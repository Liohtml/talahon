//! Lanes and per-lane SSE writer bookkeeping.
//!
//! SSE writers are tracked per lane. A single global FIFO cannot correlate a
//! response with the request that produced it: concurrent callers, or an
//! investigation firing while an analyst has the chat open, would have their
//! output written to whichever writer happened to be current.
//!
//! Life of a writer (one per `POST /message`):
//! 1. queued on its lane (`pending`) before the message reaches the host;
//! 2. promoted to the lane's `active` writer when the host signals a turn
//!    start (`set_typing(jid, true)`);
//! 3. receives every `send_message(jid, ..)` chunk while active;
//! 4. closed with a `done` event on `on_turn_complete` (or, as a safety net,
//!    `set_typing(jid, false)` when the container exits);
//! 5. removed whenever the client disconnects.
//!
//! A writer whose container exited before its turn produced any text was
//! not answered: its turn failed and the host runs it again. It goes back to
//! the front of the queue (at most [`MAX_REQUEUES`] times) instead of
//! receiving an empty `done`, so the retry's answer reaches the request that
//! asked for it rather than the next caller's stream.
//!
//! A turn start that arrives while the lane still has an active writer (a
//! follow-up piped into a running container) never replaces it mid-answer;
//! it is remembered and the next queued writer is promoted when the current
//! turn completes.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

/// Session/IPC key prefix of a per-user lane
/// (`copilot-u-<id prefix>-<hash>`, see [`UserId::session_key`]).
pub const USER_SESSION_KEY_PREFIX: &str = "copilot-u-";
/// Session/IPC key of the investigation lane. Its state directory
/// (`<data_dir>/sessions/copilot-investigate`, `/home/agent/.talon` inside
/// the container) is private to that lane and holds the eval records
/// served by `GET /evals/{alert_id}`.
pub const INVESTIGATE_SESSION_KEY: &str = "copilot-investigate";
/// Max characters of a CoPilot user id (`^[A-Za-z0-9_-]{1,48}$`).
pub const MAX_USER_ID_CHARS: usize = 48;
/// Characters of the lowercased user id kept in a per-user session/IPC key
/// (a readable hint only; uniqueness comes from the hash).
pub const USER_KEY_ID_CHARS: usize = 20;
/// Hex digits of `sha256(exact user id)` appended to a per-user key:
/// 32 hex = 128 bits, so finding an id that shares another user's key is a
/// second-preimage attack on (truncated) SHA-256, not a 2^32 search (N-8).
pub const USER_KEY_HASH_HEX: usize = 32;
/// Max length of a group folder / lane key (`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`).
const MAX_LANE_KEY_CHARS: usize = 64;

// A per-user key must always be a valid group folder.
const _: () = assert!(
    USER_SESSION_KEY_PREFIX.len() + USER_KEY_ID_CHARS + 1 + USER_KEY_HASH_HEX <= MAX_LANE_KEY_CHARS
);
const _: () = assert!(USER_KEY_HASH_HEX % 2 == 0 && USER_KEY_HASH_HEX <= 64);
/// Frames buffered per SSE writer before chunks are dropped.
pub(crate) const WRITER_BUFFER: usize = 256;
/// How often an unanswered writer waits for another turn before it is
/// closed anyway (the host retries a failed turn a few times, then tells
/// the user).
pub(crate) const MAX_REQUEUES: u8 = 10;

/// The JIDs this channel hands out, derived from the base JID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneIds {
    /// Shared chat lane (`http:copilot`); also the anonymous lane.
    pub base: String,
    /// Investigation lane (`http:copilot:investigate`).
    pub investigate: String,
    /// Prefix of per-user lanes (`http:copilot:u:`).
    pub user_prefix: String,
}

impl LaneIds {
    /// Derive the lane JIDs from the base JID.
    pub fn new(base: &str) -> Self {
        Self {
            base: base.to_string(),
            investigate: format!("{base}:investigate"),
            user_prefix: format!("{base}:u:"),
        }
    }

    /// JID of the lane owned by a CoPilot user id (the exact id).
    pub fn user_lane(&self, user_id: &str) -> String {
        format!("{}{user_id}", self.user_prefix)
    }

    /// Whether `jid` is a per-user lane.
    pub fn is_user_lane(&self, jid: &str) -> bool {
        jid.len() > self.user_prefix.len() && jid.starts_with(&self.user_prefix)
    }

    /// The base lane and every `<base>:` sub-lane.
    pub fn owns(&self, jid: &str) -> bool {
        jid == self.base
            || (jid.len() > self.base.len()
                && jid.starts_with(&self.base)
                && jid.as_bytes()[self.base.len()] == b':')
    }
}

/// JID of the lane owned by `user_id` under the default base JID
/// (`http:copilot:u:<id>`).
pub fn lane_jid_for_user(user_id: &str) -> String {
    LaneIds::new(crate::config::DEFAULT_BASE_JID).user_lane(user_id)
}

/// Whether `id` is an acceptable CoPilot user id: 1-48 characters from
/// `[A-Za-z0-9_-]`.
pub fn is_valid_user_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_USER_ID_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A request named a `user_id` that is not acceptable. Ids are never
/// "cleaned up": stripping characters would merge distinct users
/// (`bob.smith` and `bobsmith`) into one lane (MYTH-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("user_id must be a string or integer matching ^[A-Za-z0-9_-]{{1,48}}$")]
pub struct InvalidUserId;

/// A validated CoPilot user id, kept exactly as sent (case included).
///
/// The lane JID embeds the exact id (`http:copilot:u:<id>`); the session and
/// IPC key ([`Self::session_key`]) is derived so that ids differing only in
/// case cannot share a directory on a case-insensitive filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl UserId {
    /// Validate a user id string (no trimming, no stripping).
    pub fn parse(raw: &str) -> Result<Self, InvalidUserId> {
        if is_valid_user_id(raw) {
            Ok(Self(raw.to_string()))
        } else {
            Err(InvalidUserId)
        }
    }

    /// The `user_id` field of a request body: missing, `null` or `""` mean
    /// "no user" (the shared anonymous lane); a valid string or integer is
    /// accepted; anything else is rejected.
    pub fn from_json(raw: Option<&Value>) -> Result<Option<Self>, InvalidUserId> {
        match raw {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.is_empty() => Ok(None),
            Some(Value::String(s)) => Self::parse(s).map(Some),
            Some(Value::Number(n)) if n.is_i64() || n.is_u64() => {
                Self::parse(&n.to_string()).map(Some)
            }
            Some(_) => Err(InvalidUserId),
        }
    }

    /// The exact id.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Session/IPC key of this user's lane:
    /// `copilot-u-<lowercased id, first 20 chars>-<first 32 hex of sha256(exact id)>`,
    /// e.g. `copilot-u-bob-81b637d8fcd2c6da6359e6963113a117`.
    ///
    /// At most 63 characters of `[a-z0-9_-]`, so always a valid group
    /// folder. The 128-bit hash of the *exact* id keeps `Bob` and `bob` (and
    /// ids sharing a 20-char prefix) apart even where the filesystem folds
    /// case, and makes it infeasible to pick an id whose key collides with
    /// another user's (and so share their session, IPC namespace and lane).
    pub fn session_key(&self) -> String {
        let prefix: String = self
            .0
            .chars()
            .take(USER_KEY_ID_CHARS)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        let digest = Sha256::digest(self.0.as_bytes());
        let hash: String = digest
            .iter()
            .take(USER_KEY_HASH_HEX / 2)
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{USER_SESSION_KEY_PREFIX}{prefix}-{hash}")
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One frame on an SSE stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SseFrame {
    /// `{"type":"text","content":...}`
    Text(String),
    /// `{"type":"done"}` — the turn finished; the stream closes after it.
    Done,
}

impl SseFrame {
    /// JSON payload of the `data:` line. Keys are always ordered `type`
    /// first, regardless of serde_json's map-ordering feature.
    pub(crate) fn to_json(&self) -> String {
        match self {
            SseFrame::Text(content) => format!(
                r#"{{"type":"text","content":{}}}"#,
                Value::String(content.clone())
            ),
            SseFrame::Done => r#"{"type":"done"}"#.to_string(),
        }
    }
}

struct Writer {
    id: u64,
    tx: mpsc::Sender<SseFrame>,
    /// Text was written to it.
    answered: bool,
    /// Times it went back to the queue unanswered.
    requeues: u8,
}

#[derive(Default)]
struct LaneStreams {
    pending: VecDeque<Writer>,
    active: Option<Writer>,
    /// Turn starts signalled while a writer was still active; each one
    /// promotes the next pending writer when the current turn completes.
    owed: usize,
    /// A turn is in progress on this lane.
    in_turn: bool,
}

impl LaneStreams {
    fn writer_count(&self) -> usize {
        self.pending.len() + usize::from(self.active.is_some())
    }

    fn is_idle(&self) -> bool {
        self.writer_count() == 0 && !self.in_turn && self.owed == 0
    }

    fn clamp_owed(&mut self) {
        self.owed = self.owed.min(self.pending.len());
    }
}

#[derive(Default)]
struct RegistryInner {
    lanes: HashMap<String, LaneStreams>,
    total_writers: usize,
}

/// Why a stream could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// Too many requests already queued on this lane.
    LaneBusy,
    /// Too many streams open across all lanes.
    TooManyStreams,
}

/// What happened to a text chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    /// Queued on the active writer.
    Delivered,
    /// The lane has no active writer; the chunk was dropped.
    NoWriter,
    /// The active writer's buffer is full; the chunk was dropped.
    Overflow,
    /// The client went away; the writer was removed.
    ClientGone,
}

/// Counts for `/status` and `/metrics`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StreamCounts {
    pub pending: usize,
    pub active: usize,
    pub lanes_in_turn: usize,
}

/// Per-lane SSE writer registry. All operations are synchronous and hold the
/// lock briefly; no `.await` happens under it.
#[derive(Default)]
pub(crate) struct StreamRegistry {
    inner: Mutex<RegistryInner>,
    next_id: AtomicU64,
}

impl StreamRegistry {
    fn lock(&self) -> MutexGuard<'_, RegistryInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue a new writer on `jid`.
    pub(crate) fn open(
        &self,
        jid: &str,
        max_per_lane: usize,
        max_total: usize,
    ) -> Result<(u64, mpsc::Receiver<SseFrame>), OpenError> {
        let mut inner = self.lock();
        if inner.total_writers >= max_total {
            return Err(OpenError::TooManyStreams);
        }
        let lane = inner.lanes.entry(jid.to_string()).or_default();
        if lane.writer_count() >= max_per_lane {
            return Err(OpenError::LaneBusy);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(WRITER_BUFFER);
        lane.pending.push_back(Writer {
            id,
            tx,
            answered: false,
            requeues: 0,
        });
        inner.total_writers += 1;
        Ok((id, rx))
    }

    /// Forget writer `id` (client disconnected or stream finished).
    pub(crate) fn remove(&self, jid: &str, id: u64) {
        let mut inner = self.lock();
        let mut removed = 0;
        if let Some(lane) = inner.lanes.get_mut(jid) {
            let before = lane.pending.len();
            lane.pending.retain(|w| w.id != id);
            removed += before - lane.pending.len();
            if lane.active.as_ref().is_some_and(|w| w.id == id) {
                lane.active = None;
                removed += 1;
            }
            lane.clamp_owed();
            if lane.is_idle() {
                inner.lanes.remove(jid);
            }
        }
        inner.total_writers = inner.total_writers.saturating_sub(removed);
    }

    /// `set_typing(jid, true)`: a turn starts (or a follow-up was piped into
    /// the running container). Returns true if a writer was promoted.
    pub(crate) fn turn_started(&self, jid: &str) -> bool {
        let mut inner = self.lock();
        let lane = inner.lanes.entry(jid.to_string()).or_default();
        lane.in_turn = true;
        if lane.active.is_some() {
            if lane.owed < lane.pending.len() {
                lane.owed += 1;
            }
            return false;
        }
        match lane.pending.pop_front() {
            Some(w) => {
                lane.active = Some(w);
                lane.clamp_owed();
                true
            }
            None => false,
        }
    }

    /// `on_turn_complete(jid)`: close the active writer; promote the next
    /// one if a follow-up turn was already signalled. Returns true if a
    /// writer was closed.
    pub(crate) fn turn_complete(&self, jid: &str) -> bool {
        let mut inner = self.lock();
        let mut closed = false;
        if let Some(lane) = inner.lanes.get_mut(jid) {
            if let Some(w) = lane.active.take() {
                let _ = w.tx.try_send(SseFrame::Done);
                closed = true;
            }
            if lane.owed > 0 && !lane.pending.is_empty() {
                lane.owed -= 1;
                lane.active = lane.pending.pop_front();
            } else {
                lane.owed = 0;
                lane.in_turn = false;
            }
            if lane.is_idle() {
                inner.lanes.remove(jid);
            }
        }
        if closed {
            inner.total_writers = inner.total_writers.saturating_sub(1);
        }
        closed
    }

    /// `set_typing(jid, false)`: the container exited. Safety net that
    /// closes a still-active writer — unless it got no text, which means its
    /// turn failed and will be run again: then it waits at the front of the
    /// queue (see the module docs). Returns true if a writer was closed.
    pub(crate) fn turn_ended(&self, jid: &str) -> bool {
        let mut inner = self.lock();
        let mut closed = false;
        if let Some(lane) = inner.lanes.get_mut(jid) {
            if let Some(mut w) = lane.active.take() {
                if !w.answered && w.requeues < MAX_REQUEUES {
                    w.requeues += 1;
                    lane.pending.push_front(w);
                } else {
                    let _ = w.tx.try_send(SseFrame::Done);
                    closed = true;
                }
            }
            lane.owed = 0;
            lane.in_turn = false;
            if lane.is_idle() {
                inner.lanes.remove(jid);
            }
        }
        if closed {
            inner.total_writers = inner.total_writers.saturating_sub(1);
        }
        closed
    }

    /// Write a text chunk to the lane's active writer. Never falls back to
    /// another lane's writer.
    pub(crate) fn send_text(&self, jid: &str, text: &str) -> SendOutcome {
        let mut inner = self.lock();
        let Some(lane) = inner.lanes.get_mut(jid) else {
            return SendOutcome::NoWriter;
        };
        let Some(w) = lane.active.as_mut() else {
            return SendOutcome::NoWriter;
        };
        w.answered = true;
        match w.tx.try_send(SseFrame::Text(text.to_string())) {
            Ok(()) => SendOutcome::Delivered,
            Err(mpsc::error::TrySendError::Full(_)) => SendOutcome::Overflow,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                lane.active = None;
                inner.total_writers = inner.total_writers.saturating_sub(1);
                SendOutcome::ClientGone
            }
        }
    }

    /// Whether the lane has an active or queued writer (an open stream).
    pub(crate) fn has_streams(&self, jid: &str) -> bool {
        self.lock()
            .lanes
            .get(jid)
            .is_some_and(|l| l.writer_count() > 0)
    }

    /// Writers queued (not yet active) on `jid`.
    pub(crate) fn pending_len(&self, jid: &str) -> usize {
        self.lock().lanes.get(jid).map_or(0, |l| l.pending.len())
    }

    /// Whether `jid` has an active writer.
    #[cfg(test)]
    pub(crate) fn has_active(&self, jid: &str) -> bool {
        self.lock()
            .lanes
            .get(jid)
            .is_some_and(|l| l.active.is_some())
    }

    /// Aggregate counts.
    pub(crate) fn counts(&self) -> StreamCounts {
        let inner = self.lock();
        let mut c = StreamCounts::default();
        for lane in inner.lanes.values() {
            c.pending += lane.pending.len();
            c.active += usize::from(lane.active.is_some());
            c.lanes_in_turn += usize::from(lane.in_turn);
        }
        c
    }

    /// Drop a lane's bookkeeping (idle sweep). Open writers are dropped, which
    /// ends their streams.
    pub(crate) fn forget_lane(&self, jid: &str) {
        let mut inner = self.lock();
        if let Some(lane) = inner.lanes.remove(jid) {
            let n = lane.writer_count();
            inner.total_writers = inner.total_writers.saturating_sub(n);
        }
    }

    /// Close every stream (shutdown). Active writers get a `done` frame.
    pub(crate) fn close_all(&self) {
        let mut inner = self.lock();
        for (_, lane) in inner.lanes.drain() {
            if let Some(w) = lane.active {
                let _ = w.tx.try_send(SseFrame::Done);
            }
        }
        inner.total_writers = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const COPILOT_JID: &str = "http:copilot";
    const INVESTIGATE_JID: &str = "http:copilot:investigate";

    fn ids() -> LaneIds {
        LaneIds::new(COPILOT_JID)
    }

    struct Enqueued {
        id: u64,
        rx: mpsc::Receiver<SseFrame>,
    }

    impl Enqueued {
        /// Text payloads received so far.
        fn texts(&mut self) -> Vec<String> {
            self.drain()
                .into_iter()
                .filter_map(|f| match f {
                    SseFrame::Text(t) => Some(t),
                    SseFrame::Done => None,
                })
                .collect()
        }

        fn drain(&mut self) -> Vec<SseFrame> {
            let mut out = Vec::new();
            while let Ok(f) = self.rx.try_recv() {
                out.push(f);
            }
            out
        }

        /// Whether the stream was ended (sender dropped, buffer drained).
        fn ended(&mut self) -> bool {
            matches!(
                self.rx.try_recv(),
                Err(mpsc::error::TryRecvError::Disconnected)
            )
        }
    }

    fn enqueue(reg: &StreamRegistry, jid: &str) -> Enqueued {
        let (id, rx) = reg.open(jid, 16, 1024).unwrap();
        Enqueued { id, rx }
    }

    // ---- writer isolation ----------------------------------------------------

    #[test]
    fn writes_a_lane_response_only_to_that_lanes_writer() {
        let reg = StreamRegistry::default();
        let mut chat = enqueue(&reg, COPILOT_JID);
        let mut investigate = enqueue(&reg, INVESTIGATE_JID);
        reg.turn_started(COPILOT_JID);
        reg.turn_started(INVESTIGATE_JID);
        reg.send_text(COPILOT_JID, "answer for the analyst");
        reg.send_text(INVESTIGATE_JID, "investigation report");
        assert_eq!(chat.texts(), vec!["answer for the analyst"]);
        assert_eq!(investigate.texts(), vec!["investigation report"]);
    }

    #[test]
    fn drops_output_for_a_lane_with_no_writer_instead_of_borrowing_another() {
        let reg = StreamRegistry::default();
        let mut chat = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        assert_eq!(
            reg.send_text(INVESTIGATE_JID, "investigation report"),
            SendOutcome::NoWriter
        );
        assert!(chat.texts().is_empty());
        assert!(!chat.ended());
    }

    #[test]
    fn one_lanes_turn_start_does_not_steal_another_lanes_queued_writer() {
        let reg = StreamRegistry::default();
        let mut chat = enqueue(&reg, COPILOT_JID);
        reg.turn_started(INVESTIGATE_JID);
        reg.send_text(COPILOT_JID, "still waiting");
        assert!(chat.texts().is_empty());
        reg.turn_started(COPILOT_JID);
        reg.send_text(COPILOT_JID, "answer for the analyst");
        assert_eq!(chat.texts(), vec!["answer for the analyst"]);
    }

    #[test]
    fn closes_only_the_completing_lanes_stream() {
        let reg = StreamRegistry::default();
        let mut chat = enqueue(&reg, COPILOT_JID);
        let mut investigate = enqueue(&reg, INVESTIGATE_JID);
        reg.turn_started(COPILOT_JID);
        reg.turn_started(INVESTIGATE_JID);
        assert!(reg.turn_complete(INVESTIGATE_JID));
        assert_eq!(investigate.drain(), vec![SseFrame::Done]);
        assert!(investigate.ended());
        assert!(chat.drain().is_empty());
        assert!(!chat.ended());
    }

    #[test]
    fn serialises_two_callers_on_the_same_lane() {
        let reg = StreamRegistry::default();
        let mut first = enqueue(&reg, COPILOT_JID);
        let mut second = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        reg.send_text(COPILOT_JID, "first answer");
        reg.turn_complete(COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        reg.send_text(COPILOT_JID, "second answer");
        assert_eq!(first.texts(), vec!["first answer"]);
        assert_eq!(second.texts(), vec!["second answer"]);
    }

    // ---- new behaviour -------------------------------------------------------

    #[test]
    fn follow_up_turn_start_does_not_hijack_the_active_writer() {
        // Replacing the active writer when a piped follow-up signals a new
        // turn would land the rest of answer #1 in caller #2's stream.
        let reg = StreamRegistry::default();
        let mut first = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        let mut second = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID); // follow-up piped into the container
        reg.send_text(COPILOT_JID, "rest of first answer");
        reg.turn_complete(COPILOT_JID);
        reg.send_text(COPILOT_JID, "second answer");
        reg.turn_complete(COPILOT_JID);
        assert_eq!(first.texts(), vec!["rest of first answer"]);
        assert!(first.ended());
        assert_eq!(second.texts(), vec!["second answer"]);
        assert!(second.ended());
        assert_eq!(reg.counts(), StreamCounts::default());
    }

    #[test]
    fn container_exit_closes_the_active_writer_as_a_safety_net() {
        let reg = StreamRegistry::default();
        let mut w = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        reg.send_text(COPILOT_JID, "partial answer");
        assert!(reg.turn_ended(COPILOT_JID));
        assert_eq!(
            w.drain(),
            vec![SseFrame::Text("partial answer".into()), SseFrame::Done]
        );
        assert!(w.ended());
        assert!(!reg.turn_ended(COPILOT_JID));
    }

    #[test]
    fn an_unanswered_writer_gets_the_retry_not_the_next_caller() {
        let reg = StreamRegistry::default();
        let mut first = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        let mut second = enqueue(&reg, COPILOT_JID);
        // The turn fails: no text, the container exits.
        assert!(!reg.turn_ended(COPILOT_JID));
        assert!(first.drain().is_empty());
        assert_eq!(reg.pending_len(COPILOT_JID), 2);
        // The host's retry answers the first request in its own stream.
        reg.turn_started(COPILOT_JID);
        reg.send_text(COPILOT_JID, "first answer");
        reg.turn_complete(COPILOT_JID);
        reg.turn_ended(COPILOT_JID);
        assert_eq!(first.texts(), vec!["first answer"]);
        assert!(first.ended());
        assert!(second.drain().is_empty());
        assert_eq!(reg.pending_len(COPILOT_JID), 1);
    }

    #[test]
    fn an_unanswered_writer_is_closed_after_too_many_failed_turns() {
        let reg = StreamRegistry::default();
        let mut w = enqueue(&reg, COPILOT_JID);
        for _ in 0..MAX_REQUEUES {
            reg.turn_started(COPILOT_JID);
            assert!(!reg.turn_ended(COPILOT_JID));
        }
        reg.turn_started(COPILOT_JID);
        assert!(reg.turn_ended(COPILOT_JID));
        assert_eq!(w.drain(), vec![SseFrame::Done]);
        assert_eq!(reg.counts(), StreamCounts::default());
    }

    #[test]
    fn disconnect_removes_pending_and_active_writers() {
        let reg = StreamRegistry::default();
        let a = enqueue(&reg, COPILOT_JID);
        let b = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        assert!(reg.has_active(COPILOT_JID));
        reg.remove(COPILOT_JID, a.id);
        assert!(!reg.has_active(COPILOT_JID));
        assert_eq!(reg.pending_len(COPILOT_JID), 1);
        reg.remove(COPILOT_JID, b.id);
        assert!(!reg.has_streams(COPILOT_JID));
        // A dropped receiver is detected on the next write.
        let c = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        drop(c);
        assert_eq!(reg.send_text(COPILOT_JID, "x"), SendOutcome::ClientGone);
        reg.turn_ended(COPILOT_JID);
        assert_eq!(reg.counts(), StreamCounts::default());
    }

    #[test]
    fn caps_are_enforced() {
        let reg = StreamRegistry::default();
        assert!(reg.open(COPILOT_JID, 1, 10).is_ok());
        assert_eq!(
            reg.open(COPILOT_JID, 1, 10).err(),
            Some(OpenError::LaneBusy)
        );
        assert!(reg.open("http:copilot:u:1", 1, 2).is_ok());
        assert_eq!(
            reg.open("http:copilot:u:2", 1, 2).err(),
            Some(OpenError::TooManyStreams)
        );
    }

    #[test]
    fn full_buffer_drops_chunks_without_blocking() {
        let reg = StreamRegistry::default();
        let mut w = enqueue(&reg, COPILOT_JID);
        reg.turn_started(COPILOT_JID);
        for _ in 0..WRITER_BUFFER {
            assert_eq!(reg.send_text(COPILOT_JID, "x"), SendOutcome::Delivered);
        }
        assert_eq!(reg.send_text(COPILOT_JID, "x"), SendOutcome::Overflow);
        assert_eq!(w.texts().len(), WRITER_BUFFER);
    }

    #[test]
    fn close_all_ends_every_stream() {
        let reg = StreamRegistry::default();
        let mut a = enqueue(&reg, COPILOT_JID);
        let mut b = enqueue(&reg, INVESTIGATE_JID);
        reg.turn_started(COPILOT_JID);
        reg.close_all();
        assert_eq!(a.drain(), vec![SseFrame::Done]);
        assert!(a.ended());
        assert!(b.ended());
        assert_eq!(reg.counts(), StreamCounts::default());
    }

    #[test]
    fn frames_serialize_like_the_ts_channel() {
        assert_eq!(
            SseFrame::Text("hi \"x\"\n".into()).to_json(),
            r#"{"type":"text","content":"hi \"x\"\n"}"#
        );
        assert_eq!(SseFrame::Done.to_json(), r#"{"type":"done"}"#);
    }

    // ---- lane ownership + user id validation -------------------------------

    #[test]
    fn owns_the_chat_lane_and_every_sub_lane() {
        let l = ids();
        assert!(l.owns(COPILOT_JID));
        assert!(l.owns(INVESTIGATE_JID));
        assert!(l.owns("http:copilot:u:42"));
    }

    #[test]
    fn does_not_own_another_channels_jid() {
        let l = ids();
        assert!(!l.owns("webhook:copilot"));
        assert!(!l.owns("telegram:123"));
        assert!(!l.owns("http:copilotx"));
        assert!(!l.owns("http:copilo"));
    }

    fn parse(v: Value) -> Result<Option<String>, InvalidUserId> {
        UserId::from_json(Some(&v)).map(|o| o.map(|u| u.as_str().to_string()))
    }

    #[test]
    fn accepts_ids_copilot_actually_issues() {
        assert_eq!(parse(json!(42)).unwrap().as_deref(), Some("42"));
        assert_eq!(
            parse(json!("analyst-7")).unwrap().as_deref(),
            Some("analyst-7")
        );
        assert_eq!(parse(json!("a_b-C9")).unwrap().as_deref(), Some("a_b-C9"));
        let max = "x".repeat(MAX_USER_ID_CHARS);
        assert_eq!(parse(json!(max.clone())).unwrap(), Some(max));
    }

    #[test]
    fn rejects_ids_instead_of_stripping_them_into_a_neighbour() {
        // Stripping these instead would let `bob.smith` and `bobsmith` share
        // a lane.
        for raw in [
            "bob.smith",
            "../../etc/passwd",
            "a:b",
            " bob",
            "bob ",
            "ünïcödé-1",
            "a/b",
            "///",
        ] {
            assert_eq!(parse(json!(raw)), Err(InvalidUserId), "{raw:?}");
        }
        assert_eq!(
            parse(json!("x".repeat(MAX_USER_ID_CHARS + 1))),
            Err(InvalidUserId)
        );
        for v in [json!({ "id": 1 }), json!(true), json!(["1"]), json!(1.5)] {
            assert_eq!(parse(v.clone()), Err(InvalidUserId), "{v}");
        }
        assert!(UserId::parse("bob.smith").is_err());
        assert!(is_valid_user_id("bobsmith"));
    }

    #[test]
    fn absent_ids_map_to_the_anon_lane() {
        assert_eq!(UserId::from_json(None), Ok(None));
        assert_eq!(parse(Value::Null), Ok(None));
        assert_eq!(parse(json!("")), Ok(None));
    }

    #[test]
    fn session_key_has_the_documented_format() {
        let bob = UserId::parse("bob").unwrap();
        // sha256("bob") = 81b637d8fcd2c6da6359e6963113a117...
        assert_eq!(
            bob.session_key(),
            "copilot-u-bob-81b637d8fcd2c6da6359e6963113a117"
        );
        let upper = UserId::parse("Bob").unwrap();
        // sha256("Bob") = cd9fb1e148ccd8442e5aa74904cc73bf...
        assert_eq!(
            upper.session_key(),
            "copilot-u-bob-cd9fb1e148ccd8442e5aa74904cc73bf"
        );
        assert_eq!(
            UserId::parse("42").unwrap().session_key(),
            "copilot-u-42-73475cb40a568e8da8a045ced110137e"
        );
    }

    #[test]
    fn session_key_carries_a_128_bit_hash_of_the_exact_id() {
        // N-8: a 32-bit suffix let a caller grind an id (~2^32 tries) whose
        // key equals a victim's whenever both shared the truncated prefix.
        for raw in ["bob", "Bob", "42", &"Q".repeat(MAX_USER_ID_CHARS)] {
            let id = UserId::parse(raw).unwrap();
            let key = id.session_key();
            let (head, hash) = key.rsplit_once('-').unwrap();
            assert_eq!(hash.len(), USER_KEY_HASH_HEX, "{key}");
            assert!(hash.len() * 4 >= 128, "{key}");
            assert!(
                hash.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            let digest = Sha256::digest(raw.as_bytes());
            let full: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hash, &full[..USER_KEY_HASH_HEX]);
            let prefix = head.strip_prefix(USER_SESSION_KEY_PREFIX).unwrap();
            assert!(prefix.len() <= USER_KEY_ID_CHARS, "{key}");
            assert!(raw.to_ascii_lowercase().starts_with(prefix), "{key}");
        }
    }

    #[test]
    fn ids_sharing_a_long_prefix_get_distinct_full_hash_keys() {
        // Ids longer than the readable prefix are told apart by the hash
        // alone (the old format kept 40 characters + 32 bits).
        let base = "victim-account-with-a-long-identifier-00";
        let victim = UserId::parse(&format!("{base}zz")).unwrap().session_key();
        assert_eq!(
            victim.len(),
            USER_SESSION_KEY_PREFIX.len() + USER_KEY_ID_CHARS + 1 + USER_KEY_HASH_HEX
        );
        let mut seen = std::collections::HashSet::new();
        seen.insert(victim.clone());
        for i in 0..2_000u32 {
            let k = UserId::parse(&format!("{base}{i:x}"))
                .unwrap()
                .session_key();
            assert_eq!(k.len(), victim.len());
            assert!(seen.insert(k), "duplicate key for suffix {i:x}");
        }
    }

    #[test]
    fn session_keys_never_collide_on_case_insensitive_filesystems() {
        let ids = [
            "bob",
            "Bob",
            "BOB",
            "bOb",
            "bobsmith",
            "bob_smith",
            "bob-smith",
        ];
        let mut keys: Vec<String> = ids
            .iter()
            .map(|i| UserId::parse(i).unwrap().session_key().to_ascii_lowercase())
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), ids.len(), "{keys:?}");
        // Ids sharing the readable prefix still get distinct keys.
        let base = "a".repeat(USER_KEY_ID_CHARS);
        let k1 = UserId::parse(&format!("{base}1")).unwrap().session_key();
        let k2 = UserId::parse(&format!("{base}2")).unwrap().session_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn every_accepted_id_yields_a_valid_lane_key() {
        for raw in [
            "42".to_string(),
            "analyst-7".to_string(),
            "-leading-dash".to_string(),
            "Z".repeat(MAX_USER_ID_CHARS),
            "_".repeat(MAX_USER_ID_CHARS),
            "-".repeat(MAX_USER_ID_CHARS),
            "9".repeat(USER_KEY_ID_CHARS + 1),
        ] {
            let key = UserId::parse(&raw).unwrap().session_key();
            assert!(key.len() <= MAX_LANE_KEY_CHARS, "{key}");
            assert_eq!(
                key.len(),
                USER_SESSION_KEY_PREFIX.len()
                    + raw.len().min(USER_KEY_ID_CHARS)
                    + 1
                    + USER_KEY_HASH_HEX
            );
            assert!(key.starts_with(USER_SESSION_KEY_PREFIX));
            assert!(talon_core::paths::is_valid_group_folder(&key), "{key}");
            assert_eq!(key, key.to_ascii_lowercase());
        }
    }

    #[test]
    fn lane_jid_helpers() {
        assert_eq!(lane_jid_for_user("42"), "http:copilot:u:42");
        let l = ids();
        assert!(l.is_user_lane("http:copilot:u:42"));
        assert!(!l.is_user_lane("http:copilot:u:"));
        assert!(!l.is_user_lane(INVESTIGATE_JID));
        assert_eq!(l.investigate, INVESTIGATE_JID);
    }
}
