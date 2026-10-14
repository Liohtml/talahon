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
//! Hardening over the TS release: a turn start that arrives while the lane
//! still has an active writer (a follow-up piped into a running container)
//! no longer replaces it mid-answer; it is remembered and the next queued
//! writer is promoted when the current turn completes.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use serde_json::Value;
use tokio::sync::mpsc;

/// Session/IPC key prefix of a per-user lane (`copilot-u-<id>`).
pub const USER_SESSION_KEY_PREFIX: &str = "copilot-u-";
/// Session/IPC key of the investigation lane.
pub const INVESTIGATE_SESSION_KEY: &str = "copilot-investigate";
/// Max characters kept from a CoPilot user id. `copilot-u-<id>` must stay a
/// valid (<= 64 character) group folder for the session/IPC resolvers.
pub const MAX_USER_ID_CHARS: usize = 48;
/// Frames buffered per SSE writer before chunks are dropped.
pub(crate) const WRITER_BUFFER: usize = 256;

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

    /// JID of the lane owned by a (normalized) CoPilot user id.
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
/// (`http:copilot:u:<id>`), mirroring the TS `laneJidForUser`.
pub fn lane_jid_for_user(user_id: &str) -> String {
    LaneIds::new(crate::config::DEFAULT_BASE_JID).user_lane(user_id)
}

/// Reduce a CoPilot user id to something safe to embed in a JID, a session
/// key and a filesystem path. Strings and numbers are accepted; anything
/// else, or anything that is empty after stripping characters outside
/// `[A-Za-z0-9_-]`, maps to `None` (the anonymous lane) rather than being
/// silently mangled into a neighbouring user's key.
pub fn normalize_user_id(raw: &Value) -> Option<String> {
    let text = match raw {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    normalize_user_id_str(&text)
}

/// String form of [`normalize_user_id`].
pub fn normalize_user_id_str(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(MAX_USER_ID_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
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
    /// JSON payload of the `data:` line. Key order matches the TS channel
    /// (`type` first) regardless of serde_json's map-ordering feature.
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
        lane.pending.push_back(Writer { id, tx });
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
    /// closes a still-active writer. Returns true if one was closed.
    pub(crate) fn turn_ended(&self, jid: &str) -> bool {
        let mut inner = self.lock();
        let mut closed = false;
        if let Some(lane) = inner.lanes.get_mut(jid) {
            if let Some(w) = lane.active.take() {
                let _ = w.tx.try_send(SseFrame::Done);
                closed = true;
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
        let Some(w) = lane.active.as_ref() else {
            return SendOutcome::NoWriter;
        };
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
        /// Text payloads received so far (TS `textEvents`).
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

    // ---- ports of `HttpChannel writer isolation` ---------------------------

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
        // TS replaced the active writer when a piped follow-up signalled a new
        // turn, so the rest of answer #1 landed in caller #2's stream.
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
        assert!(reg.turn_ended(COPILOT_JID));
        assert_eq!(w.drain(), vec![SseFrame::Done]);
        assert!(w.ended());
        assert!(!reg.turn_ended(COPILOT_JID));
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

    // ---- ports of `HttpChannel lane ownership` + `normalizeUserId` ----------

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

    #[test]
    fn accepts_ids_copilot_actually_issues() {
        assert_eq!(normalize_user_id(&json!(42)).as_deref(), Some("42"));
        assert_eq!(
            normalize_user_id(&json!("analyst-7")).as_deref(),
            Some("analyst-7")
        );
        assert_eq!(
            normalize_user_id(&json!("a_b-C9")).as_deref(),
            Some("a_b-C9")
        );
    }

    #[test]
    fn strips_characters_that_would_escape_the_key_or_path() {
        assert_eq!(
            normalize_user_id(&json!("../../etc/passwd")).as_deref(),
            Some("etcpasswd")
        );
        assert_eq!(normalize_user_id(&json!("a:b")).as_deref(), Some("ab"));
    }

    #[test]
    fn falls_back_to_the_anon_lane_rather_than_mangling_into_a_neighbour() {
        assert_eq!(normalize_user_id(&json!("")), None);
        assert_eq!(normalize_user_id(&json!("   ")), None);
        assert_eq!(normalize_user_id(&json!("///")), None);
        assert_eq!(normalize_user_id(&Value::Null), None);
        assert_eq!(normalize_user_id(&json!({ "id": 1 })), None);
        assert_eq!(normalize_user_id(&json!(true)), None);
        assert_eq!(normalize_user_id(&json!(["1"])), None);
    }

    #[test]
    fn bounds_the_length_so_the_derived_lane_key_stays_a_valid_folder() {
        let id = normalize_user_id(&json!("x".repeat(200))).unwrap();
        assert!(talon_core::paths::is_valid_group_folder(&format!(
            "{USER_SESSION_KEY_PREFIX}{id}"
        )));
    }

    #[test]
    fn keeps_every_accepted_id_inside_a_valid_lane_key() {
        for raw in ["42", "analyst-7", "a_b-C9", &"z".repeat(300), "ünïcödé-1"] {
            let id = normalize_user_id(&json!(raw)).unwrap();
            assert!(talon_core::paths::is_valid_group_folder(&format!(
                "{USER_SESSION_KEY_PREFIX}{id}"
            )));
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
