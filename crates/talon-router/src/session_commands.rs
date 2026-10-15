//! Session slash commands (`/compact`, `/new` and its aliases) intercepted
//! by the orchestrator before a batch reaches the agent (port of
//! `src/session-commands.ts`).
//!
//! The host implements [`SessionCommandDeps`]; [`handle_session_command`]
//! drives authorization, the pre-command flush and the command itself.

use async_trait::async_trait;
use regex::Regex;
use talon_core::Result;
use talon_core::protocol::{ContainerOutput, OutputStatus};
use talon_core::types::NewMessage;

use crate::outbound::strip_internal_tags;

/// A session command the orchestrator understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionCommand {
    /// `/compact`: summarise the session context (runs the agent).
    Compact,
    /// `/new` (aliases `/reset`, `/clear`): drop the stored session.
    New,
}

impl SessionCommand {
    /// The canonical slash command, e.g. `"/compact"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionCommand::Compact => "/compact",
            SessionCommand::New => "/new",
        }
    }

    /// Parse a canonical command or alias. Case-sensitive, exact match.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "/compact" => Some(SessionCommand::Compact),
            "/new" | "/reset" | "/clear" => Some(SessionCommand::New),
            _ => None,
        }
    }
}

impl std::fmt::Display for SessionCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extract a session command from a message, stripping a leading trigger
/// (`@Andy /compact`). Returns `None` for anything that is not exactly a
/// known command — `/compact now` or `/deploy` fall through as prompts.
pub fn extract_session_command(content: &str, trigger_pattern: &Regex) -> Option<SessionCommand> {
    let text = content.trim();
    let text = trigger_pattern.replace(text, "");
    SessionCommand::parse(text.trim())
}

/// Whether a session-command sender is authorized.
///
/// Allowed: the main group (any sender), a trusted/admin sender
/// (`is_from_me`) in any group, or any sender on a channel that
/// authenticates its own callers (`RegisteredGroup::trusted_session_commands`,
/// e.g. the CoPilot HTTP API). The last case is its own flag rather than
/// `is_main` so it does not also grant main-group privileges.
pub fn is_session_command_allowed(
    is_main_group: bool,
    is_from_me: bool,
    is_trusted_channel: bool,
) -> bool {
    is_main_group || is_from_me || is_trusted_channel
}

/// Receives streamed agent outputs during [`SessionCommandDeps::run_agent`].
#[async_trait]
pub trait AgentOutputHandler: Send {
    /// Called for every output frame the agent run produces, in order.
    async fn on_output(&mut self, output: &ContainerOutput);
}

/// Orchestrator callbacks used by [`handle_session_command`].
#[async_trait]
pub trait SessionCommandDeps: Send + Sync {
    /// Send `text` to the lane's chat (already plain text; the host applies
    /// channel formatting).
    async fn send_message(&self, text: &str) -> Result<()>;

    /// Toggle the typing indicator. Failures are the host's to log.
    async fn set_typing(&self, typing: bool);

    /// Run the agent on `prompt`, streaming every output to `on_output`.
    /// Returns the overall run status.
    async fn run_agent(&self, prompt: &str, on_output: &mut dyn AgentOutputHandler)
    -> OutputStatus;

    /// Close the running container's stdin (`_close` sentinel).
    fn close_stdin(&self);

    /// Advance the lane's message cursor to `timestamp`.
    fn advance_cursor(&self, timestamp: &str);

    /// Format messages as an agent prompt (normally
    /// [`crate::format_messages`]).
    fn format_messages(&self, messages: &[NewMessage], timezone: &str) -> String {
        crate::format::format_messages(messages, timezone)
    }

    /// Whether the (denied) sender may normally talk to the agent; decides
    /// whether a denial message is sent or the command is consumed silently.
    fn can_sender_interact(&self, message: &NewMessage) -> bool;

    /// Drop the lane's stored session so the next run starts fresh.
    fn clear_session(&self);
}

/// Inputs to [`handle_session_command`].
#[derive(Debug, Clone, Copy)]
pub struct SessionCommandRequest<'a> {
    /// Messages pending for the lane, oldest first.
    pub missed_messages: &'a [NewMessage],
    /// Whether the lane is the main control group.
    pub is_main_group: bool,
    /// Group name (logging only).
    pub group_name: &'a str,
    /// The lane's trigger pattern (stripped before matching).
    pub trigger_pattern: &'a Regex,
    /// IANA timezone for prompt formatting.
    pub timezone: &'a str,
    /// The channel authenticates its own callers.
    pub is_trusted_channel: bool,
}

/// Result of [`handle_session_command`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCommandOutcome {
    /// No session command in the batch — process normally.
    NotHandled,
    /// A command was found and handled. `success == false` means the caller
    /// should retry later (the cursor was not advanced).
    Handled {
        /// Whether the batch was consumed.
        success: bool,
    },
}

impl SessionCommandOutcome {
    /// `true` unless [`SessionCommandOutcome::NotHandled`].
    pub fn handled(&self) -> bool {
        matches!(self, SessionCommandOutcome::Handled { .. })
    }
}

/// Message sent to a sender that may chat but not run session commands.
pub const DENIED_MESSAGE: &str = "Session commands require admin access.";
/// Confirmation sent after `/new`.
pub const NEW_SESSION_MESSAGE: &str = "New session started. Previous context cleared.";

fn result_to_text(output: &ContainerOutput) -> String {
    match output.result.as_deref() {
        Some(r) if !r.is_empty() => strip_internal_tags(r),
        _ => String::new(),
    }
}

struct PreCommandHandler<'a> {
    deps: &'a dyn SessionCommandDeps,
    had_error: bool,
    output_sent: bool,
}

#[async_trait]
impl AgentOutputHandler for PreCommandHandler<'_> {
    async fn on_output(&mut self, output: &ContainerOutput) {
        if output.status == OutputStatus::Error {
            self.had_error = true;
        }
        let text = result_to_text(output);
        if !text.is_empty() {
            match self.deps.send_message(&text).await {
                Ok(()) => self.output_sent = true,
                Err(e) => tracing::warn!(error = %e, "failed to deliver pre-command output"),
            }
        }
        // Session-update marker (success with no result): emitted after the
        // query completes, so every result is already written — close stdin.
        if output.status == OutputStatus::Success && output.result.is_none() {
            self.deps.close_stdin();
        }
    }
}

struct CommandHandler<'a> {
    deps: &'a dyn SessionCommandDeps,
    had_error: bool,
}

#[async_trait]
impl AgentOutputHandler for CommandHandler<'_> {
    async fn on_output(&mut self, output: &ContainerOutput) {
        if output.status == OutputStatus::Error {
            self.had_error = true;
        }
        let text = result_to_text(output);
        if !text.is_empty() {
            if let Err(e) = self.deps.send_message(&text).await {
                tracing::warn!(error = %e, "failed to deliver session command output");
            }
        }
    }
}

/// Intercept a session command in `req.missed_messages`.
///
/// - No command: [`SessionCommandOutcome::NotHandled`].
/// - Unauthorized: a denial is sent (only if the sender may otherwise
///   interact), the cursor advances past the command, `success = true`.
/// - `/new`: the session is cleared without running the agent.
/// - `/compact`: messages before the command are flushed to the agent first
///   (so they are part of the compacted context), then the literal command
///   is sent as the prompt. Messages after the command stay pending.
///
/// # Errors
/// Propagates [`SessionCommandDeps::send_message`] failures on the
/// denial / confirmation / failure notices (the cursor is then not
/// advanced past an unacknowledged command, so the caller retries).
pub async fn handle_session_command(
    req: SessionCommandRequest<'_>,
    deps: &dyn SessionCommandDeps,
) -> Result<SessionCommandOutcome> {
    let found = req.missed_messages.iter().enumerate().find_map(|(idx, m)| {
        extract_session_command(&m.content, req.trigger_pattern).map(|cmd| (idx, m, cmd))
    });
    let Some((cmd_index, cmd_msg, command)) = found else {
        return Ok(SessionCommandOutcome::NotHandled);
    };

    if !is_session_command_allowed(
        req.is_main_group,
        cmd_msg.is_from_me,
        req.is_trusted_channel,
    ) {
        // Denied: tell the sender if they could normally interact, then
        // consume the command (the cursor is a high-water mark, so other
        // messages in the batch are consumed too — acceptable edge case).
        if deps.can_sender_interact(cmd_msg) {
            deps.send_message(DENIED_MESSAGE).await?;
        }
        deps.advance_cursor(&cmd_msg.timestamp);
        return Ok(SessionCommandOutcome::Handled { success: true });
    }

    tracing::info!(group = %req.group_name, command = %command, "Session command");

    // /new needs no container: dropping the stored session IS the operation.
    // Handled before the flush below — feeding messages into a context that
    // is about to be discarded would cost a full turn for nothing.
    if command == SessionCommand::New {
        deps.clear_session();
        deps.advance_cursor(&cmd_msg.timestamp);
        deps.send_message(NEW_SESSION_MESSAGE).await?;
        return Ok(SessionCommandOutcome::Handled { success: true });
    }

    // Authorized /compact: flush earlier messages into the session first.
    let pre = &req.missed_messages[..cmd_index];
    if let Some(last_pre) = pre.last() {
        let prompt = deps.format_messages(pre, req.timezone);
        let mut handler = PreCommandHandler {
            deps,
            had_error: false,
            output_sent: false,
        };
        let status = deps.run_agent(&prompt, &mut handler).await;
        if status == OutputStatus::Error || handler.had_error {
            tracing::warn!(group = %req.group_name, "Pre-compact processing failed, aborting session command");
            deps.send_message(&format!(
                "Failed to process messages before {command}. Try again."
            ))
            .await?;
            if handler.output_sent {
                // Output already delivered — retrying would duplicate it.
                // Advance past the flushed messages, leave the command pending.
                deps.advance_cursor(&last_pre.timestamp);
                return Ok(SessionCommandOutcome::Handled { success: true });
            }
            return Ok(SessionCommandOutcome::Handled { success: false });
        }
    }

    // Forward the literal slash command as the prompt (no XML envelope).
    deps.set_typing(true).await;
    let mut handler = CommandHandler {
        deps,
        had_error: false,
    };
    let status = deps.run_agent(command.as_str(), &mut handler).await;

    // Messages after the command remain pending for the next poll.
    deps.advance_cursor(&cmd_msg.timestamp);
    deps.set_typing(false).await;

    if status == OutputStatus::Error || handler.had_error {
        deps.send_message(&format!("{command} failed. The session is unchanged."))
            .await?;
    }

    Ok(SessionCommandOutcome::Handled { success: true })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn trigger() -> Regex {
        talon_core::trigger::build_trigger_pattern("@Andy", "Andy")
    }

    // --- extract_session_command --------------------------------------------

    #[test]
    fn detects_bare_compact() {
        assert_eq!(
            extract_session_command("/compact", &trigger()),
            Some(SessionCommand::Compact)
        );
    }

    #[test]
    fn detects_compact_with_trigger_prefix() {
        assert_eq!(
            extract_session_command("@Andy /compact", &trigger()),
            Some(SessionCommand::Compact)
        );
    }

    #[test]
    fn rejects_compact_with_extra_text() {
        assert_eq!(
            extract_session_command("/compact now please", &trigger()),
            None
        );
    }

    #[test]
    fn rejects_partial_matches() {
        assert_eq!(extract_session_command("/compaction", &trigger()), None);
    }

    #[test]
    fn rejects_regular_messages() {
        assert_eq!(
            extract_session_command("please compact the conversation", &trigger()),
            None
        );
    }

    #[test]
    fn handles_whitespace() {
        assert_eq!(
            extract_session_command("  /compact  ", &trigger()),
            Some(SessionCommand::Compact)
        );
    }

    #[test]
    fn command_is_case_sensitive() {
        assert_eq!(extract_session_command("/Compact", &trigger()), None);
    }

    #[test]
    fn detects_bare_new() {
        assert_eq!(
            extract_session_command("/new", &trigger()),
            Some(SessionCommand::New)
        );
    }

    #[test]
    fn detects_new_with_trigger_prefix() {
        assert_eq!(
            extract_session_command("@Andy /new", &trigger()),
            Some(SessionCommand::New)
        );
    }

    #[test]
    fn canonicalises_reset_and_clear() {
        assert_eq!(
            extract_session_command("/reset", &trigger()),
            Some(SessionCommand::New)
        );
        assert_eq!(
            extract_session_command("/clear", &trigger()),
            Some(SessionCommand::New)
        );
        assert_eq!(SessionCommand::New.as_str(), "/new");
    }

    #[test]
    fn rejects_unknown_slash_command() {
        assert_eq!(extract_session_command("/deploy", &trigger()), None);
    }

    #[test]
    fn trigger_is_case_insensitive() {
        assert_eq!(
            extract_session_command("@andy /new", &trigger()),
            Some(SessionCommand::New)
        );
    }

    // --- is_session_command_allowed -----------------------------------------

    #[test]
    fn allows_main_group_regardless_of_sender() {
        assert!(is_session_command_allowed(true, false, false));
    }

    #[test]
    fn allows_admin_sender_in_non_main_group() {
        assert!(is_session_command_allowed(false, true, false));
    }

    #[test]
    fn denies_untrusted_sender_in_non_main_group() {
        assert!(!is_session_command_allowed(false, false, false));
    }

    #[test]
    fn allows_trusted_sender_in_main_group() {
        assert!(is_session_command_allowed(true, true, false));
    }

    #[test]
    fn allows_authenticated_channel_in_non_main_group() {
        assert!(is_session_command_allowed(false, false, true));
    }

    // --- handle_session_command ---------------------------------------------

    fn make_msg(content: &str) -> NewMessage {
        NewMessage {
            id: "msg-1".into(),
            chat_jid: "group@test".into(),
            sender: "user@test".into(),
            sender_name: "User".into(),
            content: content.into(),
            timestamp: "100".into(),
            ..Default::default()
        }
    }

    fn msg_at(content: &str, ts: &str) -> NewMessage {
        NewMessage {
            timestamp: ts.into(),
            ..make_msg(content)
        }
    }

    fn from_me(content: &str, is_from_me: bool) -> NewMessage {
        NewMessage {
            is_from_me,
            ..make_msg(content)
        }
    }

    /// Scripted run: outputs streamed to the handler, then the final status.
    type Script = (Vec<ContainerOutput>, OutputStatus);

    #[derive(Default)]
    struct MockDeps {
        sent: Mutex<Vec<String>>,
        typing: Mutex<Vec<bool>>,
        prompts: Mutex<Vec<String>>,
        scripts: Mutex<Vec<Script>>,
        closed: Mutex<u32>,
        cursor: Mutex<Vec<String>>,
        formatted: Mutex<Vec<Vec<NewMessage>>>,
        cleared: Mutex<u32>,
        deny_interaction: bool,
        fail_send: bool,
    }

    impl MockDeps {
        fn with_scripts(scripts: Vec<Script>) -> Self {
            Self {
                scripts: Mutex::new(scripts),
                ..Default::default()
            }
        }
        fn sent(&self) -> Vec<String> {
            self.sent.lock().unwrap().clone()
        }
        fn prompts(&self) -> Vec<String> {
            self.prompts.lock().unwrap().clone()
        }
        fn cursor(&self) -> Vec<String> {
            self.cursor.lock().unwrap().clone()
        }
        fn cleared(&self) -> u32 {
            *self.cleared.lock().unwrap()
        }
    }

    #[async_trait]
    impl SessionCommandDeps for MockDeps {
        async fn send_message(&self, text: &str) -> Result<()> {
            if self.fail_send {
                return Err(talon_core::Error::Channel("down".into()));
            }
            self.sent.lock().unwrap().push(text.to_string());
            Ok(())
        }
        async fn set_typing(&self, typing: bool) {
            self.typing.lock().unwrap().push(typing);
        }
        async fn run_agent(
            &self,
            prompt: &str,
            on_output: &mut dyn AgentOutputHandler,
        ) -> OutputStatus {
            self.prompts.lock().unwrap().push(prompt.to_string());
            let script = {
                let mut scripts = self.scripts.lock().unwrap();
                if scripts.is_empty() {
                    (Vec::new(), OutputStatus::Success)
                } else {
                    scripts.remove(0)
                }
            };
            for out in &script.0 {
                on_output.on_output(out).await;
            }
            script.1
        }
        fn close_stdin(&self) {
            *self.closed.lock().unwrap() += 1;
        }
        fn advance_cursor(&self, timestamp: &str) {
            self.cursor.lock().unwrap().push(timestamp.to_string());
        }
        fn format_messages(&self, messages: &[NewMessage], _timezone: &str) -> String {
            self.formatted.lock().unwrap().push(messages.to_vec());
            "<formatted>".to_string()
        }
        fn can_sender_interact(&self, _message: &NewMessage) -> bool {
            !self.deny_interaction
        }
        fn clear_session(&self) {
            *self.cleared.lock().unwrap() += 1;
        }
    }

    fn req<'a>(msgs: &'a [NewMessage], is_main: bool, re: &'a Regex) -> SessionCommandRequest<'a> {
        SessionCommandRequest {
            missed_messages: msgs,
            is_main_group: is_main,
            group_name: "test",
            trigger_pattern: re,
            timezone: "UTC",
            is_trusted_channel: false,
        }
    }

    #[tokio::test]
    async fn not_handled_without_command() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [make_msg("hello")];
        let out = handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::NotHandled);
        assert!(!out.handled());
    }

    #[tokio::test]
    async fn authorized_compact_in_main_group() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [make_msg("/compact")];
        let out = handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert_eq!(deps.prompts(), vec!["/compact"]);
        assert_eq!(deps.cursor(), vec!["100"]);
        assert_eq!(*deps.typing.lock().unwrap(), vec![true, false]);
    }

    #[tokio::test]
    async fn new_does_not_run_agent() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [make_msg("/new")];
        let out = handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert_eq!(deps.cleared(), 1);
        assert!(deps.prompts().is_empty());
        assert_eq!(deps.cursor(), vec!["100"]);
        assert_eq!(deps.sent(), vec![NEW_SESSION_MESSAGE]);
    }

    #[tokio::test]
    async fn new_does_not_flush_earlier_messages() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [msg_at("some earlier chatter", "50"), msg_at("/new", "100")];
        handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert!(deps.prompts().is_empty());
        assert!(deps.formatted.lock().unwrap().is_empty());
        assert_eq!(deps.cleared(), 1);
    }

    #[tokio::test]
    async fn reset_is_alias_for_new() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [make_msg("/reset")];
        let out = handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert_eq!(deps.cleared(), 1);
    }

    #[tokio::test]
    async fn trusted_channel_may_run_new_in_non_main_group() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [from_me("/new", false)];
        let mut r = req(&msgs, false, &re);
        r.group_name = "copilot";
        r.is_trusted_channel = true;
        let out = handle_session_command(r, &deps).await.unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert_eq!(deps.cleared(), 1);
        assert_eq!(deps.sent(), vec![NEW_SESSION_MESSAGE]);
    }

    #[tokio::test]
    async fn untrusted_channel_new_is_denied() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [from_me("/new", false)];
        handle_session_command(req(&msgs, false, &re), &deps)
            .await
            .unwrap();
        assert_eq!(deps.cleared(), 0);
        assert_eq!(deps.sent(), vec![DENIED_MESSAGE]);
    }

    #[tokio::test]
    async fn denial_sent_to_interactable_sender() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [from_me("/compact", false)];
        let out = handle_session_command(req(&msgs, false, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert_eq!(deps.sent(), vec![DENIED_MESSAGE]);
        assert!(deps.prompts().is_empty());
        assert_eq!(deps.cursor(), vec!["100"]);
    }

    #[tokio::test]
    async fn denied_command_consumed_silently_when_sender_cannot_interact() {
        let deps = MockDeps {
            deny_interaction: true,
            ..Default::default()
        };
        let re = trigger();
        let msgs = [from_me("/compact", false)];
        let out = handle_session_command(req(&msgs, false, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert!(deps.sent().is_empty());
        assert_eq!(deps.cursor(), vec!["100"]);
    }

    #[tokio::test]
    async fn flushes_pre_compact_messages_first() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [msg_at("summarize this", "99"), msg_at("/compact", "100")];
        let out = handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert_eq!(
            deps.formatted.lock().unwrap().clone(),
            vec![vec![msgs[0].clone()]]
        );
        assert_eq!(deps.prompts(), vec!["<formatted>", "/compact"]);
    }

    #[tokio::test]
    async fn pre_compact_output_is_delivered_and_stdin_closed() {
        let deps = MockDeps::with_scripts(vec![
            (
                vec![
                    ContainerOutput::success(Some("<internal>x</internal>Summary".into()), None),
                    ContainerOutput::success(None, Some("sess".into())),
                ],
                OutputStatus::Success,
            ),
            (
                vec![ContainerOutput::success(Some("Compacted.".into()), None)],
                OutputStatus::Success,
            ),
        ]);
        let re = trigger();
        let msgs = [msg_at("summarize this", "99"), msg_at("/compact", "100")];
        handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(deps.sent(), vec!["Summary", "Compacted."]);
        assert_eq!(*deps.closed.lock().unwrap(), 1);
        assert_eq!(deps.cursor(), vec!["100"]);
    }

    #[tokio::test]
    async fn admin_sender_in_non_main_group() {
        let deps = MockDeps::default();
        let re = trigger();
        let msgs = [from_me("/compact", true)];
        let out = handle_session_command(req(&msgs, false, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert_eq!(deps.prompts(), vec!["/compact"]);
    }

    #[tokio::test]
    async fn reports_failure_when_run_errors_without_streamed_error() {
        let deps = MockDeps::with_scripts(vec![(
            vec![ContainerOutput::success(None, None)],
            OutputStatus::Error,
        )]);
        let re = trigger();
        let msgs = [make_msg("/compact")];
        let out = handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert!(deps.sent().iter().any(|m| m.contains("failed")));
        assert_eq!(deps.cursor(), vec!["100"]);
    }

    #[tokio::test]
    async fn reports_failure_on_streamed_error() {
        let deps = MockDeps::with_scripts(vec![(
            vec![ContainerOutput::error("boom")],
            OutputStatus::Success,
        )]);
        let re = trigger();
        let msgs = [make_msg("/compact")];
        handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(
            deps.sent(),
            vec!["/compact failed. The session is unchanged."]
        );
    }

    #[tokio::test]
    async fn pre_compact_failure_without_output_requests_retry() {
        let deps = MockDeps::with_scripts(vec![(Vec::new(), OutputStatus::Error)]);
        let re = trigger();
        let msgs = [msg_at("summarize this", "99"), msg_at("/compact", "100")];
        let out = handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: false });
        assert!(deps.sent().iter().any(|m| m.contains("Failed to process")));
        assert!(deps.cursor().is_empty());
        assert_eq!(
            deps.prompts().len(),
            1,
            "command must not run after a failed flush"
        );
    }

    #[tokio::test]
    async fn pre_compact_failure_after_output_advances_past_flushed_messages() {
        let deps = MockDeps::with_scripts(vec![(
            vec![
                ContainerOutput::success(Some("partial".into()), None),
                ContainerOutput::error("boom"),
            ],
            OutputStatus::Error,
        )]);
        let re = trigger();
        let msgs = [
            msg_at("a", "98"),
            msg_at("b", "99"),
            msg_at("/compact", "100"),
        ];
        let out = handle_session_command(req(&msgs, true, &re), &deps)
            .await
            .unwrap();
        assert_eq!(out, SessionCommandOutcome::Handled { success: true });
        assert_eq!(deps.cursor(), vec!["99"]);
        assert_eq!(deps.sent()[0], "partial");
    }

    #[tokio::test]
    async fn denial_send_failure_propagates_without_advancing() {
        let deps = MockDeps {
            fail_send: true,
            ..Default::default()
        };
        let re = trigger();
        let msgs = [from_me("/compact", false)];
        assert!(
            handle_session_command(req(&msgs, false, &re), &deps)
                .await
                .is_err()
        );
        assert!(deps.cursor().is_empty());
    }
}
