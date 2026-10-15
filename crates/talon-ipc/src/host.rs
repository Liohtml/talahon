//! Host callbacks used by the watcher, and the directory-derived identity of
//! a requesting container.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use talon_core::Result;
use talon_core::types::{AvailableGroup, RegisteredGroup};
use talon_security::ipc_authz::IpcIdentity;

/// Identity of the container that wrote an IPC file.
///
/// Derived **only** from the namespace directory the file was found in
/// (`data/ipc/<ipc_key>/`) and the registered group that owns that key —
/// never from anything inside the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIdentity {
    /// The namespace directory name (`RegisteredGroup::ipc_key()`).
    pub ipc_key: String,
    /// Group folder of the owning lane(s).
    pub folder: String,
    /// Whether the owning group is the main control group.
    pub is_main: bool,
}

impl SourceIdentity {
    /// Identity of `group`'s IPC namespace.
    pub fn of_group(group: &RegisteredGroup) -> Self {
        Self {
            ipc_key: group.ipc_key().to_string(),
            folder: group.folder.clone(),
            is_main: group.is_main,
        }
    }

    /// Borrowed view for the policy engine. The IPC key is the principal
    /// of every per-lane rule.
    pub fn as_ipc_identity(&self) -> IpcIdentity<'_> {
        IpcIdentity {
            source_folder: &self.folder,
            ipc_key: &self.ipc_key,
            is_main: self.is_main,
        }
    }
}

/// Callbacks into the host orchestrator (`talon`).
///
/// Async callbacks are bounded by
/// [`IpcWatcherConfig::host_call_timeout`](crate::IpcWatcherConfig::host_call_timeout).
/// Synchronous callbacks must be cheap (in-memory snapshots or short SQLite
/// reads).
#[async_trait]
pub trait IpcHost: Send + Sync {
    /// Deliver an authorized outbound message. The host picks the channel
    /// owning `jid`, formats `text` for it, and redacts as configured.
    async fn send_message(&self, jid: &str, text: &str) -> Result<()>;

    /// Snapshot of all registered groups (persisted and in-memory lanes)
    /// keyed by JID. Used for identity resolution and authorization.
    fn registered_groups(&self) -> HashMap<String, RegisteredGroup>;

    /// Persist and activate a group registration requested by the main
    /// group. The watcher has already validated the folder and forced
    /// `is_main = false`; the host creates the group directory.
    async fn register_group(&self, jid: &str, group: RegisteredGroup) -> Result<()>;

    /// Refresh chat metadata from every channel (`force` bypasses caches).
    async fn sync_groups(&self, force: bool) -> Result<()>;

    /// Groups the agent may see in `available_groups.json`.
    fn available_groups(&self) -> Vec<AvailableGroup>;

    /// (Re)write `available_groups.json` into `source`'s IPC namespace
    /// (`source.ipc_key`). Main sees every group, others see none.
    async fn write_groups_snapshot(
        &self,
        source: &SourceIdentity,
        available: &[AvailableGroup],
        registered_jids: &HashSet<String>,
    ) -> Result<()>;

    /// Scheduled tasks changed: rewrite `current_tasks.json` snapshots and
    /// wake the scheduler.
    fn on_tasks_changed(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(folder: &str, ipc_key: Option<&str>, is_main: bool) -> RegisteredGroup {
        RegisteredGroup {
            name: folder.into(),
            folder: folder.into(),
            trigger: "@Talon".into(),
            added_at: "2024-01-01T00:00:00.000Z".into(),
            container_config: None,
            requires_trigger: None,
            is_main,
            session_key: None,
            ipc_key: ipc_key.map(str::to_string),
            ephemeral_session: false,
            trusted_session_commands: false,
        }
    }

    #[test]
    fn identity_uses_ipc_key_and_folder() {
        let id = SourceIdentity::of_group(&group("copilot", Some("copilot-u-7"), false));
        assert_eq!(id.ipc_key, "copilot-u-7");
        assert_eq!(id.folder, "copilot");
        assert!(!id.is_main);
        let v = id.as_ipc_identity();
        assert_eq!(v.source_folder, "copilot");
        assert_eq!(v.ipc_key, "copilot-u-7");
        assert!(!v.is_main);
    }

    #[test]
    fn identity_defaults_key_to_folder() {
        let id = SourceIdentity::of_group(&group("main", None, true));
        assert_eq!(id.ipc_key, "main");
        assert!(id.is_main);
    }
}
