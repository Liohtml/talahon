//! Host callback traits implemented by the [`Orchestrator`]:
//! [`ChannelHost`] (channels), [`IpcHost`] (IPC watcher),
//! [`LaneProcessor`] (group queue) and [`GroupDirectory`] (scheduler).

use std::collections::{BTreeSet, HashMap, HashSet};

use async_trait::async_trait;
use talon_core::channel::{ChannelHost, QueueStatus};
use talon_core::types::{AvailableGroup, ChatMetadata, NewMessage, RegisteredGroup};
use talon_core::{Error, Result};
use talon_ipc::{IpcHost, SourceIdentity};
use talon_scheduler::{GroupDirectory, LaneProcessor};

use super::Orchestrator;

impl Orchestrator {
    /// Inbound message: sender-allowlist drop
    /// check, store, wake the message loop. Never blocks on the agent.
    /// Returns whether the message was stored.
    pub fn accept_message(&self, chat_jid: &str, mut message: NewMessage) -> bool {
        // The channel's JID is authoritative for where the message lives.
        if message.chat_jid != chat_jid {
            message.chat_jid = chat_jid.to_string();
        }
        let group = self.group(chat_jid);
        if let Some(group) = group
            .as_ref()
            .filter(|_| !message.is_from_me && !message.is_bot_message)
        {
            let allowlist = self.allowlist.current();
            if allowlist.should_drop_message(chat_jid, &message.sender) {
                if allowlist.log_denied() {
                    tracing::debug!(chat_jid, sender = %message.sender, "sender-allowlist: dropping message (drop mode)");
                }
                return false;
            }
            // Chat text from non-main lanes is untrusted (§3.4): record
            // high-risk injection attempts. Detection only: the agent fences
            // the content, and dropping here would also discard legitimate
            // messages that quote attack text (alert payloads, phishing).
            if !group.is_main {
                let report = talon_security::injection::scan(&message.content);
                if let Some(ev) = talon_security::injection::audit_event(
                    &group.folder,
                    &format!("chat:{chat_jid}"),
                    &report,
                ) {
                    tracing::warn!(chat_jid, rules = ?report.rule_ids(), "possible prompt injection in inbound message");
                    self.audit.record(ev);
                }
            }
        }
        self.store_message(&message);
        if self.is_accepting() {
            self.wake.notify_one();
        }
        true
    }

    /// Rewrite `current_tasks.json` for every IPC namespace (one write
    /// each), filtered to the namespace's own lanes (MYTH-03); non-main
    /// namespaces load only their own tasks (N-3).
    pub fn refresh_task_snapshots(&self) {
        let groups = self.groups_snapshot();
        let keys: BTreeSet<String> = groups.values().map(|g| g.ipc_key().to_string()).collect();
        for key in keys {
            self.write_lane_tasks_snapshot_for(&key, &groups, None);
        }
    }
}

#[async_trait]
impl ChannelHost for Orchestrator {
    async fn on_message(&self, chat_jid: &str, message: NewMessage) {
        self.accept_message(chat_jid, message);
    }

    async fn on_chat_metadata(&self, metadata: ChatMetadata) {
        if let Err(e) = self.db.store_chat_metadata(&metadata) {
            tracing::warn!(chat_jid = %metadata.chat_jid, error = %e, "failed to store chat metadata");
        }
    }

    fn registered_groups(&self) -> HashMap<String, RegisteredGroup> {
        self.groups_snapshot()
    }

    async fn register_group(&self, jid: &str, group: RegisteredGroup, persist: bool) {
        // Errors are logged inside; channels have no way to react.
        let _ = self.register_group_inner(jid, group, persist, false);
    }

    async fn unregister_group(&self, jid: &str) -> bool {
        self.unregister_lane(jid)
    }

    async fn clear_session(&self, jid: &str) -> bool {
        let Some(group) = self.group(jid) else {
            return false;
        };
        self.clear_session_for(&group);
        // A running container still holds the old conversation: let it
        // finish its turn and exit, so the next message starts fresh.
        self.queue.close_stdin(jid);
        tracing::info!(jid, group = %group.name, "Session cleared");
        true
    }

    fn notify_tasks_changed(&self) {
        self.wake_scheduler();
    }

    fn queue_status(&self) -> QueueStatus {
        self.queue.status()
    }
}

#[async_trait]
impl IpcHost for Orchestrator {
    async fn send_message(&self, jid: &str, text: &str) -> Result<()> {
        if self.find_channel(jid).is_none() {
            return Err(Error::Channel(format!("No channel for JID: {jid}")));
        }
        self.send_outbound(jid, text).await.map(|_| ())
    }

    fn registered_groups(&self) -> HashMap<String, RegisteredGroup> {
        self.groups_snapshot()
    }

    async fn register_group(&self, jid: &str, mut group: RegisteredGroup) -> Result<()> {
        // Defense in depth on top of the watcher (MYTH-04), against the
        // host's current registry: IPC never changes the main group, never
        // grants main, and never sets operator-only container options.
        let existing = self.group(jid);
        if existing.as_ref().is_some_and(|g| g.is_main) {
            return Err(Error::InvalidInput(
                "the main group's registration cannot be changed via IPC".into(),
            ));
        }
        group.is_main = false;
        group.container_config = existing.and_then(|g| g.container_config);
        self.register_group_inner(jid, group, true, true)
    }

    async fn sync_groups(&self, force: bool) -> Result<()> {
        let channels = self.channels();
        let results = futures::future::join_all(
            channels
                .iter()
                .map(|c| async move { (c.name().to_string(), c.sync_groups(force).await) }),
        )
        .await;
        for (name, result) in results {
            if let Err(e) = result {
                tracing::warn!(channel = %name, error = %e, "group sync failed");
            }
        }
        Ok(())
    }

    fn available_groups(&self) -> Vec<AvailableGroup> {
        Orchestrator::available_groups(self)
    }

    async fn write_groups_snapshot(
        &self,
        source: &SourceIdentity,
        available: &[AvailableGroup],
        _registered_jids: &HashSet<String>,
    ) -> Result<()> {
        talon_container::write_groups_snapshot(
            &self.config.data_dir,
            &source.folder,
            source.is_main,
            available,
            Some(&source.ipc_key),
        )
        .map(|_| ())
    }

    fn on_tasks_changed(&self) {
        self.refresh_task_snapshots();
        self.wake_scheduler();
    }
}

#[async_trait]
impl LaneProcessor for Orchestrator {
    async fn process_messages(&self, chat_jid: &str) -> bool {
        self.process_group_messages(chat_jid).await
    }

    async fn run_task(&self, chat_jid: &str, task_id: &str) {
        match self.scheduler() {
            Some(scheduler) => {
                let outcome = scheduler.run_task(chat_jid, task_id).await;
                tracing::debug!(chat_jid, task_id, ?outcome, "task run finished");
            }
            None => tracing::error!(chat_jid, task_id, "task scheduler not installed"),
        }
    }

    async fn retries_exhausted(&self, chat_jid: &str) {
        self.notify_retries_exhausted(chat_jid).await;
    }
}

impl GroupDirectory for Orchestrator {
    fn registered_groups(&self) -> HashMap<String, RegisteredGroup> {
        self.groups_snapshot()
    }
}
