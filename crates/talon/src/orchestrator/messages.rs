//! Message pipeline: per-lane message processing, the message loop and
//! recovery of pending messages at startup.
//!
//! The loop is event-driven: `ChannelHost::on_message` stores the message
//! and wakes it through a `Notify`; a poll interval remains as a fallback
//! (messages written to the database by something else, missed wake-ups).
//! Semantics:
//!
//! - the "seen" cursor (`last_timestamp`) advances as soon as messages are
//!   fetched; the per-lane agent cursor only when they are handed to the
//!   agent;
//! - a missing agent cursor is recovered from the last bot reply;
//! - non-main lanes need the trigger word from an allowed sender;
//!   non-trigger messages accumulate and are sent as context later;
//! - follow-ups are piped into the lane's running container (IPC input)
//!   instead of starting a new one;
//! - a run's ledger records what it was handed and which of it its turns
//!   answered (the agent names the input files each turn consumed); what a
//!   run leaves unanswered — its turn died, or the container closed before
//!   reading a follow-up — runs again from the committed cursor, which is
//!   also what is persisted while the run is in flight (crash recovery).
//!   An error after everything was answered is not retried (no duplicates);
//! - session commands close an active container (authorized senders only)
//!   and are handled by a fresh run;
//! - when the queue gives up retrying, the user is told.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use talon_core::channel::Channel;
use talon_core::protocol::{ContainerOutput, OutputStatus};
use talon_core::types::{NewMessage, RegisteredGroup};
use talon_router::{
    AgentOutputHandler, SessionCommandOutcome, SessionCommandRequest, extract_session_command,
    format_messages, handle_session_command, is_session_command_allowed, strip_internal_tags,
    trigger_pattern_for,
};
use talon_scheduler::CloseTimer;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::Orchestrator;
use super::commands::LaneCommandDeps;
use super::ledger::LaneLedger;
use super::run::RunOptions;

/// Extra headroom (on top of the idle timeout) a running container's LLM
/// token must have left before a follow-up is piped into it.
const PIPE_TOKEN_HEADROOM: std::time::Duration = std::time::Duration::from_secs(90);

/// How many pending messages a trigger-gated lane searches for its trigger
/// when the trigger is older than the prompt window.
const TRIGGER_SCAN_LIMIT: usize = talon_db::DEFAULT_MESSAGE_LIMIT;

/// What one poll of the message loop did (tests / debugging).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PollSummary {
    /// New messages fetched.
    pub fetched: usize,
    /// Lanes whose messages were piped into a running container.
    pub piped: Vec<String>,
    /// Lanes enqueued for a new container run.
    pub enqueued: Vec<String>,
}

/// Streaming handler of a chat run.
struct ChatSink<'a> {
    host: &'a Orchestrator,
    jid: &'a str,
    group_name: &'a str,
    channel: Arc<dyn Channel>,
    idle: CloseTimer,
    ledger: Arc<Mutex<LaneLedger>>,
    had_error: bool,
}

#[async_trait]
impl AgentOutputHandler for ChatSink<'_> {
    async fn on_output(&mut self, output: &ContainerOutput) {
        if let Some(raw) = output.result.as_deref().filter(|r| !r.is_empty()) {
            let text = strip_internal_tags(raw);
            tracing::info!(group = %self.group_name, chars = raw.len(), "Agent output");
            if !text.is_empty() {
                if let Err(e) = self.host.send_outbound(self.jid, &text).await {
                    tracing::warn!(chat_jid = %self.jid, error = %e, "failed to deliver agent output");
                }
            }
        }
        match output.status {
            OutputStatus::Success => {
                // Every success frame ends a turn, an empty answer too: the
                // container now waits for input, so the idle countdown runs.
                self.idle.reset();
                let (completions, committed) = {
                    let mut ledger = lock_ledger(&self.ledger);
                    let n = ledger.turn_answered(output.consumed_inputs.as_deref());
                    (n, ledger.committed().to_string())
                };
                self.host.commit_cursor(self.jid, &committed);
                self.host.queue.notify_idle(self.jid);
                for _ in 0..completions {
                    if let Err(e) = self.channel.on_turn_complete(self.jid).await {
                        tracing::debug!(chat_jid = %self.jid, error = %e, "on_turn_complete failed");
                    }
                }
            }
            OutputStatus::Error => self.had_error = true,
        }
    }
}

fn lock_ledger(ledger: &Mutex<LaneLedger>) -> MutexGuard<'_, LaneLedger> {
    ledger.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Notice sent when a lane's messages failed every retry.
pub const RETRIES_EXHAUSTED_NOTICE: &str = "⚠️ Your last message could not be processed: the \
     agent failed several times in a row. It will be picked up again with your next message.";

/// Whether `msg` may wake the agent in a trigger-gated lane.
pub(crate) fn trigger_ok(
    jid: &str,
    pattern: &regex::Regex,
    allowlist: &talon_security::senders::SenderAllowlist,
    msg: &NewMessage,
) -> bool {
    pattern.is_match(msg.content.trim())
        && (msg.is_from_me || allowlist.is_trigger_allowed(jid, &msg.sender))
}

impl Orchestrator {
    async fn set_typing(&self, channel: &Arc<dyn Channel>, jid: &str, typing: bool) {
        if let Err(e) = channel.set_typing(jid, typing).await {
            tracing::debug!(chat_jid = jid, error = %e, "Failed to set typing indicator");
        }
    }

    fn pending_messages(&self, jid: &str) -> Vec<NewMessage> {
        self.pending_messages_up_to(jid, self.config.max_messages_per_prompt)
    }

    /// The `limit` most recent messages after the lane's cursor.
    fn pending_messages_up_to(&self, jid: &str, limit: usize) -> Vec<NewMessage> {
        let cursor = self.get_or_recover_cursor(jid);
        match self
            .db
            .get_messages_since(jid, &cursor, &self.config.assistant_name, limit)
        {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(chat_jid = jid, error = %e, "failed to load pending messages");
                Vec::new()
            }
        }
    }

    /// The prompt of a trigger-gated lane, from `window` (its latest
    /// pending messages): `window` itself when it holds an allowed trigger.
    /// When more than `MAX_MESSAGES_PER_PROMPT` messages followed the
    /// trigger, it is no longer in `window`; the prompt then starts at the
    /// oldest pending trigger instead, and `true` says that messages after
    /// it are still pending. `None`: no trigger is pending.
    fn trigger_window(
        &self,
        jid: &str,
        pattern: &regex::Regex,
        allowlist: &talon_security::senders::SenderAllowlist,
        window: Vec<NewMessage>,
    ) -> Option<(Vec<NewMessage>, bool)> {
        if window
            .iter()
            .any(|m| trigger_ok(jid, pattern, allowlist, m))
        {
            return Some((window, false));
        }
        let all = self.pending_messages_up_to(jid, TRIGGER_SCAN_LIMIT);
        let first = all
            .iter()
            .position(|m| trigger_ok(jid, pattern, allowlist, m))?;
        let end = all
            .len()
            .min(first.saturating_add(self.config.max_messages_per_prompt.max(1)));
        tracing::info!(
            chat_jid = jid,
            later = all.len() - first - 1,
            "trigger is older than the prompt window; answering it first"
        );
        Some((all[first..end].to_vec(), end < all.len()))
    }

    /// Process all pending messages of a lane.
    /// Called by the queue when it is the lane's turn. `false` asks the
    /// queue to retry with backoff.
    pub async fn process_group_messages(&self, chat_jid: &str) -> bool {
        let Some(group) = self.group(chat_jid) else {
            return true;
        };
        let Some(channel) = self.find_channel(chat_jid) else {
            tracing::warn!(chat_jid, "No channel owns JID, skipping messages");
            return true;
        };
        let is_main = group.is_main;

        let mut missed = self.pending_messages(chat_jid);
        if missed.is_empty() {
            return true;
        }

        // --- Session command interception (before the trigger check) ---
        let pattern = trigger_pattern_for(&group, &self.config.assistant_name);
        let deps = LaneCommandDeps {
            host: self,
            jid: chat_jid,
            group: &group,
            channel: Arc::clone(&channel),
            pattern: &pattern,
        };
        let request = SessionCommandRequest {
            missed_messages: &missed,
            is_main_group: is_main,
            group_name: &group.name,
            trigger_pattern: &pattern,
            timezone: &self.config.timezone_name,
            is_trusted_channel: group.trusted_session_commands,
        };
        match handle_session_command(request, &deps).await {
            Ok(SessionCommandOutcome::Handled { success }) => {
                // Messages after the command stay pending; they get their
                // own run now instead of waiting for the next message.
                if success && !self.pending_messages(chat_jid).is_empty() {
                    self.queue.enqueue_message_check(chat_jid);
                }
                return success;
            }
            Ok(SessionCommandOutcome::NotHandled) => {}
            Err(e) => {
                tracing::warn!(chat_jid, error = %e, "session command failed; will retry");
                return false;
            }
        }

        // --- Trigger gating for non-main lanes ---
        let mut more_pending = false;
        if group.needs_trigger() {
            let allowlist = self.allowlist.current();
            match self.trigger_window(chat_jid, &pattern, &allowlist, missed) {
                Some((window, more)) => {
                    missed = window;
                    more_pending = more;
                }
                None => return true,
            }
        }

        let prompt = format_messages(&missed, &self.config.timezone_name);
        let Some(last) = missed.last() else {
            return true;
        };

        // Advance the cursor so the piping path won't re-fetch these
        // messages; until they are answered the committed cursor (the old
        // one) is what is persisted and what an error rolls back to.
        let previous_cursor = self.cursor(chat_jid);
        let ledger = Arc::new(Mutex::new(LaneLedger::new(
            previous_cursor.clone(),
            last.timestamp.clone(),
        )));
        {
            let mut st = self.lock();
            st.last_agent_timestamp
                .insert(chat_jid.to_string(), last.timestamp.clone());
            st.committed
                .insert(chat_jid.to_string(), previous_cursor.clone());
            st.ledgers.insert(chat_jid.to_string(), Arc::clone(&ledger));
        }
        self.save_state();
        tracing::info!(group = %group.name, message_count = missed.len(), "Processing messages");

        self.set_typing(&channel, chat_jid, true).await;
        let mut sink = ChatSink {
            host: self,
            jid: chat_jid,
            group_name: &group.name,
            channel: Arc::clone(&channel),
            idle: self.queue.close_timer(chat_jid, self.config.idle_timeout),
            ledger: Arc::clone(&ledger),
            had_error: false,
        };
        let outcome = self
            .run_agent(&group, &prompt, chat_jid, RunOptions::message(), &mut sink)
            .await;
        sink.idle.cancel();
        let failed = !outcome.is_success() || sink.had_error;
        drop(sink);

        // Seal the run: nothing more is piped into it. Whatever it did not
        // answer (the prompt or follow-ups) runs again from the committed
        // cursor.
        let (all_answered, committed) = {
            let mut ledger = lock_ledger(&ledger);
            ledger.finish(!failed);
            (ledger.all_answered(), ledger.committed().to_string())
        };
        {
            let mut st = self.lock();
            st.ledgers.remove(chat_jid);
            st.committed.remove(chat_jid);
            if !all_answered {
                st.last_agent_timestamp
                    .insert(chat_jid.to_string(), committed);
            }
        }
        self.save_state();
        self.set_typing(&channel, chat_jid, false).await;

        if failed {
            if all_answered {
                tracing::warn!(
                    group = %group.name,
                    "Agent error after every message was answered; nothing to retry"
                );
                return true;
            }
            tracing::warn!(group = %group.name, "Agent error, rolled back message cursor for retry");
            return false;
        }
        if !all_answered {
            // Follow-ups the container closed before reading.
            tracing::info!(group = %group.name, "Follow-ups were not answered by the run; running them again");
            self.queue.enqueue_message_check(chat_jid);
        } else if more_pending {
            // Messages after the answered trigger: the lane runs again.
            self.queue.enqueue_message_check(chat_jid);
        }
        true
    }

    /// Record the cursor through which the lane's running container has
    /// answered (persisted while the run is in flight).
    pub(crate) fn commit_cursor(&self, jid: &str, committed: &str) {
        {
            let mut st = self.lock();
            match st.committed.get_mut(jid) {
                Some(c) if c != committed => committed.clone_into(c),
                _ => return,
            }
        }
        self.save_state();
    }

    /// Tell the user that the lane's messages failed every retry (see
    /// [`talon_scheduler::LaneProcessor::retries_exhausted`]). The cursor
    /// stays put, so they are picked up again with the next message.
    pub async fn notify_retries_exhausted(&self, chat_jid: &str) {
        let Some(channel) = self.find_channel(chat_jid) else {
            return;
        };
        self.set_typing(&channel, chat_jid, true).await;
        if let Err(e) = self.send_outbound(chat_jid, RETRIES_EXHAUSTED_NOTICE).await {
            tracing::warn!(chat_jid, error = %e, "cannot tell the user that their message failed");
        }
        if let Err(e) = channel.on_turn_complete(chat_jid).await {
            tracing::debug!(chat_jid, error = %e, "on_turn_complete failed");
        }
        self.set_typing(&channel, chat_jid, false).await;
    }

    /// Whether a follow-up may be piped into the lane's running container:
    /// its LLM token must outlive another idle period. A token about to run
    /// out is extended through the gateway first; only when that fails is
    /// the container recycled.
    fn may_pipe(&self, jid: &str) -> bool {
        let (deadline, run_token) = {
            let st = self.lock();
            (
                st.token_deadlines.get(jid).copied(),
                st.run_tokens.get(jid).cloned(),
            )
        };
        let Some(deadline) = deadline else {
            return true;
        };
        let needed = self.config.idle_timeout + PIPE_TOKEN_HEADROOM;
        if Instant::now() + needed < deadline {
            return true;
        }
        let (Some((token, ttl)), Some(llm)) = (run_token, self.llm.clone()) else {
            return false;
        };
        let ttl = ttl.max(needed);
        if !llm.extend(&token, ttl) {
            return false;
        }
        let mut st = self.lock();
        // The run may have ended while the gateway call was in flight.
        if st.run_tokens.get(jid).is_some_and(|(t, _)| *t == token) {
            st.token_deadlines
                .insert(jid.to_string(), Instant::now() + ttl);
            true
        } else {
            false
        }
    }

    /// One iteration of the message loop.
    pub async fn poll_once(&self) -> PollSummary {
        let mut summary = PollSummary::default();
        let (jids, since) = {
            let st = self.lock();
            (
                st.groups.keys().cloned().collect::<Vec<_>>(),
                st.last_timestamp.clone(),
            )
        };
        let (messages, new_ts) =
            match self
                .db
                .get_new_messages(&jids, &since, &self.config.assistant_name)
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "Error in message loop");
                    return summary;
                }
            };
        if messages.is_empty() {
            return summary;
        }
        summary.fetched = messages.len();
        tracing::info!(count = messages.len(), "New messages");

        // Advance the "seen" cursor for all messages immediately.
        self.lock().last_timestamp = new_ts;
        self.save_state();

        // Group by lane, preserving first-seen order.
        let mut order: Vec<String> = Vec::new();
        let mut by_lane: HashMap<String, Vec<NewMessage>> = HashMap::new();
        for msg in messages {
            if !by_lane.contains_key(&msg.chat_jid) {
                order.push(msg.chat_jid.clone());
            }
            by_lane.entry(msg.chat_jid.clone()).or_default().push(msg);
        }

        for jid in order {
            let Some(lane_messages) = by_lane.remove(&jid) else {
                continue;
            };
            let Some(group) = self.group(&jid) else {
                continue;
            };
            let Some(channel) = self.find_channel(&jid) else {
                tracing::warn!(chat_jid = %jid, "No channel owns JID, skipping messages");
                continue;
            };
            match self
                .route_lane(&jid, &group, &channel, &lane_messages)
                .await
            {
                LaneRoute::Piped => summary.piped.push(jid),
                LaneRoute::Enqueued => summary.enqueued.push(jid),
                LaneRoute::Skipped => {}
            }
        }
        summary
    }

    async fn route_lane(
        &self,
        jid: &str,
        group: &RegisteredGroup,
        channel: &Arc<dyn Channel>,
        lane_messages: &[NewMessage],
    ) -> LaneRoute {
        let pattern = trigger_pattern_for(group, &self.config.assistant_name);

        // --- Session command interception (message loop) ---
        if let Some(cmd_msg) = lane_messages
            .iter()
            .find(|m| extract_session_command(&m.content, &pattern).is_some())
        {
            // Only an authorized sender may close the active container —
            // otherwise anyone could kill in-flight work with /compact.
            if is_session_command_allowed(
                group.is_main,
                cmd_msg.is_from_me,
                group.trusted_session_commands,
            ) {
                self.queue.close_stdin(jid);
            }
            // processGroupMessages handles auth + cursor; never pipe a
            // slash command into a running session.
            self.queue.enqueue_message_check(jid);
            return LaneRoute::Enqueued;
        }

        // Non-main lanes only act on (allowed) trigger messages; others
        // accumulate and are pulled in as context later.
        let allowlist = self.allowlist.current();
        if group.needs_trigger()
            && !lane_messages
                .iter()
                .any(|m| trigger_ok(jid, &pattern, &allowlist, m))
        {
            return LaneRoute::Skipped;
        }

        // Everything since the lane cursor, so accumulated context goes too.
        let mut more_pending = false;
        let mut all_pending = self.pending_messages(jid);
        if group.needs_trigger() && !all_pending.is_empty() {
            (all_pending, more_pending) = self
                .trigger_window(jid, &pattern, &allowlist, all_pending)
                .unwrap_or_default();
        }
        let to_send: &[NewMessage] = if all_pending.is_empty() {
            lane_messages
        } else {
            &all_pending
        };
        let Some(last) = to_send.last() else {
            return LaneRoute::Skipped;
        };
        let formatted = format_messages(to_send, &self.config.timezone_name);

        if self.may_pipe(jid) {
            if let Some((ledger, file)) = self.pipe_into_run(jid, &formatted, &last.timestamp) {
                tracing::debug!(
                    chat_jid = jid,
                    count = to_send.len(),
                    "Piped messages to active container"
                );
                if more_pending {
                    // The rest gets its own run once this container is done.
                    self.queue.enqueue_message_check(jid);
                }
                // A turn starts for the follow-up (typing indicator; the
                // HTTP channel moves on to this request's stream). Its
                // completion is reported only after this, see
                // `LaneLedger::signalled`.
                let channel = Arc::clone(channel);
                let jid_owned = jid.to_string();
                tokio::spawn(async move {
                    if let Err(e) = channel.set_typing(&jid_owned, true).await {
                        tracing::warn!(chat_jid = %jid_owned, error = %e, "Failed to set typing indicator");
                    }
                    if lock_ledger(&ledger).signalled(&file) {
                        if let Err(e) = channel.on_turn_complete(&jid_owned).await {
                            tracing::debug!(chat_jid = %jid_owned, error = %e, "on_turn_complete failed");
                        }
                    }
                });
                return LaneRoute::Piped;
            }
        } else {
            // The running container's LLM token would expire mid-turn: let
            // it finish and handle the follow-up in a fresh run.
            tracing::info!(
                chat_jid = jid,
                "container token near expiry; follow-up goes to a new run"
            );
            self.queue.close_stdin(jid);
        }
        // No active container — enqueue for a new one.
        self.queue.enqueue_message_check(jid);
        LaneRoute::Enqueued
    }

    /// Pipe `text` into the lane's running message container, if it still
    /// takes input, and advance the lane cursor to `cursor` (its newest
    /// message). Returns the run's ledger and the input file written.
    fn pipe_into_run(
        &self,
        jid: &str,
        text: &str,
        cursor: &str,
    ) -> Option<(Arc<Mutex<LaneLedger>>, String)> {
        let ledger = self.lock().ledgers.get(jid).cloned()?;
        // The ledger stays locked until the cursor moved, so the run cannot
        // be sealed (and roll the cursor back) in between.
        let mut guard = lock_ledger(&ledger);
        if guard.is_sealed() {
            return None;
        }
        let file = self.queue.pipe_message(jid, text)?;
        guard.record_pipe(file.clone(), cursor.to_string());
        self.set_cursor(jid, cursor);
        drop(guard);
        Some((ledger, file))
    }

    /// The message loop: poll, then wait for a wake-up (new message) or
    /// the poll interval, until `cancel` fires or shutdown begins.
    pub async fn message_loop(self: Arc<Self>, cancel: CancellationToken) {
        if self.loop_running.swap(true, Ordering::SeqCst) {
            tracing::debug!("Message loop already running, skipping duplicate start");
            return;
        }
        tracing::info!(
            default_trigger = %self.config.default_trigger,
            "Talon running"
        );
        while !cancel.is_cancelled() && self.is_accepting() {
            self.poll_once().await;
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }
        self.loop_running.store(false, Ordering::SeqCst);
        tracing::info!("Message loop stopped");
    }

    /// Startup recovery: enqueue lanes with unprocessed messages (crash
    /// between advancing `last_timestamp` and processing). Returns the
    /// enqueued JIDs.
    pub fn recover_pending_messages(&self) -> Vec<String> {
        let mut groups: Vec<(String, String)> = self
            .groups_snapshot()
            .into_iter()
            .map(|(jid, g)| (jid, g.name))
            .collect();
        groups.sort();
        let mut enqueued = Vec::new();
        for (jid, name) in groups {
            let pending = self.pending_messages(&jid);
            if !pending.is_empty() {
                tracing::info!(group = %name, pending_count = pending.len(), "Recovery: found unprocessed messages");
                self.queue.enqueue_message_check(&jid);
                enqueued.push(jid);
            }
        }
        enqueued
    }
}

/// How the loop routed one lane's new messages.
enum LaneRoute {
    Piped,
    Enqueued,
    Skipped,
}
