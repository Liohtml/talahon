//! [`SessionCommandDeps`] for one lane (built while processing the lane's
//! pending messages).

use std::sync::Arc;

use async_trait::async_trait;
use regex::Regex;
use talon_core::Result;
use talon_core::channel::Channel;
use talon_core::protocol::{ContainerOutput, OutputStatus};
use talon_core::types::{NewMessage, RegisteredGroup};
use talon_router::{AgentOutputHandler, SessionCommandDeps};
use talon_scheduler::CloseTimer;

use super::Orchestrator;
use super::messages::trigger_ok;
use super::run::RunOptions;

/// Session-command callbacks bound to one lane.
pub struct LaneCommandDeps<'a> {
    /// The orchestrator.
    pub host: &'a Orchestrator,
    /// Lane JID.
    pub jid: &'a str,
    /// The lane's group.
    pub group: &'a RegisteredGroup,
    /// The channel owning the lane.
    pub channel: Arc<dyn Channel>,
    /// The lane's trigger pattern.
    pub pattern: &'a Regex,
}

/// Forwards outputs to the router's handler and closes the container
/// shortly after a successful turn: a session-command run is single-shot,
/// so its container must not idle until the idle timeout.
struct CommandSink<'a> {
    inner: &'a mut dyn AgentOutputHandler,
    close: CloseTimer,
}

#[async_trait]
impl AgentOutputHandler for CommandSink<'_> {
    async fn on_output(&mut self, output: &ContainerOutput) {
        self.inner.on_output(output).await;
        if output.status == OutputStatus::Success {
            self.close.arm_once();
        }
    }
}

#[async_trait]
impl SessionCommandDeps for LaneCommandDeps<'_> {
    async fn send_message(&self, text: &str) -> Result<()> {
        self.host.send_outbound(self.jid, text).await.map(|_| ())
    }

    async fn set_typing(&self, typing: bool) {
        if let Err(e) = self.channel.set_typing(self.jid, typing).await {
            tracing::debug!(chat_jid = %self.jid, error = %e, "Failed to set typing indicator");
        }
    }

    async fn run_agent(
        &self,
        prompt: &str,
        on_output: &mut dyn AgentOutputHandler,
    ) -> OutputStatus {
        let mut sink = CommandSink {
            inner: on_output,
            close: self
                .host
                .queue
                .close_timer(self.jid, self.host.settings.command_close_delay),
        };
        let outcome = self
            .host
            .run_agent(
                self.group,
                prompt,
                self.jid,
                RunOptions::message(),
                &mut sink,
            )
            .await;
        sink.close.cancel();
        outcome.status
    }

    fn close_stdin(&self) {
        self.host.queue.close_stdin(self.jid);
    }

    fn advance_cursor(&self, timestamp: &str) {
        self.host.set_cursor(self.jid, timestamp);
    }

    fn can_sender_interact(&self, message: &NewMessage) -> bool {
        let is_main = self.group.is_main;
        let requires_trigger = !is_main && self.group.requires_trigger != Some(false);
        if is_main || !requires_trigger {
            return true;
        }
        let allowlist = self.host.allowlist.current();
        trigger_ok(self.jid, self.pattern, &allowlist, message)
    }

    fn clear_session(&self) {
        self.host.clear_session_for(self.group);
        tracing::info!(chat_jid = %self.jid, group = %self.group.name, "Session cleared");
    }
}
