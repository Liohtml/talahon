//! Messaging channel abstraction.
//!
//! A channel (HTTP/CoPilot, Telegram, webhook, Emacs, ...) owns a set of JIDs,
//! delivers inbound messages to the host through [`ChannelHost`], and sends
//! outbound text. Channels are constructed by the host with an
//! `Arc<dyn ChannelHost>` and must keep any background tasks they spawn
//! (servers, pollers) tied to their own lifetime (`disconnect` stops them).

use std::collections::HashMap;

use async_trait::async_trait;

use crate::Result;
use crate::types::{ChatMetadata, NewMessage, RegisteredGroup};

/// Text dialect a channel renders. Drives Markdown -> native conversion in
/// `talon-router`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelType {
    /// Passthrough Markdown (HTTP API, Discord, Emacs).
    Markdown,
    Telegram,
    WhatsApp,
    Slack,
    Signal,
    /// Plain text, all markup stripped (webhook payloads).
    Plain,
}

#[async_trait]
pub trait Channel: Send + Sync {
    /// Stable short name (`"http"`, `"telegram"`, ...).
    fn name(&self) -> &str;

    /// Dialect for outbound formatting.
    fn channel_type(&self) -> ChannelType {
        ChannelType::Markdown
    }

    /// Start the channel (bind servers, start polling). Must return once the
    /// channel is ready; long-running work goes into spawned tasks.
    async fn connect(&self) -> Result<()>;

    /// Deliver `text` to `jid`. Text is already formatted for `channel_type`.
    async fn send_message(&self, jid: &str, text: &str) -> Result<()>;

    fn is_connected(&self) -> bool;

    /// Whether this channel is responsible for `jid`.
    fn owns_jid(&self, jid: &str) -> bool;

    /// Stop background tasks and release sockets.
    async fn disconnect(&self) -> Result<()>;

    /// Optional typing indicator.
    async fn set_typing(&self, _jid: &str, _is_typing: bool) -> Result<()> {
        Ok(())
    }

    /// Called when the agent finishes a turn successfully, before the
    /// container goes idle (lets streaming channels close their streams).
    async fn on_turn_complete(&self, _jid: &str) -> Result<()> {
        Ok(())
    }

    /// Optional: refresh chat names from the platform.
    async fn sync_groups(&self, _force: bool) -> Result<()> {
        Ok(())
    }
}

/// Callbacks a channel uses to talk back to the host orchestrator.
/// Implemented by the `talon` binary.
#[async_trait]
pub trait ChannelHost: Send + Sync {
    /// Deliver an inbound message. The host applies the sender allowlist,
    /// persists it, and wakes the message loop. Never blocks on the agent.
    async fn on_message(&self, chat_jid: &str, message: NewMessage);

    /// Report chat metadata discovered by the channel.
    async fn on_chat_metadata(&self, metadata: ChatMetadata);

    /// Snapshot of all registered groups keyed by JID.
    fn registered_groups(&self) -> HashMap<String, RegisteredGroup>;

    /// Register (or update) a lane. In-memory lanes (per-user HTTP lanes)
    /// pass `persist = false`.
    async fn register_group(&self, jid: &str, group: RegisteredGroup, persist: bool);

    /// Drop an in-memory lane registration. Never removes a persisted group.
    async fn unregister_group(&self, jid: &str) -> bool;

    /// Drop a lane's stored session so its next run starts fresh.
    /// Returns false for an unknown JID.
    async fn clear_session(&self, jid: &str) -> bool;

    /// Scheduled tasks were created/changed out of band (e.g. by the HTTP
    /// API); wake the scheduler.
    fn notify_tasks_changed(&self);

    /// Live queue / container status for observability endpoints.
    fn queue_status(&self) -> QueueStatus {
        QueueStatus::default()
    }
}

/// Snapshot of the group queue for `/status`-style endpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QueueStatus {
    pub active_containers: usize,
    pub max_containers: usize,
    pub waiting_groups: usize,
    /// JIDs with a running container.
    pub active_jids: Vec<String>,
}
