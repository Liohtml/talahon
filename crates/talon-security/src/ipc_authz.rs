//! Authorization of container -> host IPC requests.
//!
//! Identity is the *directory* the IPC file was found in (`source_folder`),
//! never a field inside the file. Rules (from `src/ipc.ts`, tightened):
//! - outbound message: main may message any registered JID; others only
//!   JIDs whose group folder == source folder.
//! - schedule_task: non-main may only target JIDs of its own folder.
//! - pause/resume/cancel/update: non-main only for tasks of its own folder.
//! - refresh_groups / register_group: main only; register_group can never
//!   set `is_main` and folder must pass `is_valid_group_folder`.

use std::collections::HashMap;

use talon_core::protocol::IpcTask;
use talon_core::types::RegisteredGroup;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcDecision {
    Allow,
    Deny(String),
}

impl IpcDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, IpcDecision::Allow)
    }
}

/// Identity of the requesting container, derived from its IPC directory.
#[derive(Debug, Clone, Copy)]
pub struct IpcIdentity<'a> {
    /// Group folder owning the IPC namespace.
    pub source_folder: &'a str,
    pub is_main: bool,
}

#[allow(unused_variables, clippy::todo)]
pub fn authorize_outbound_message(
    who: IpcIdentity<'_>,
    target_jid: &str,
    groups: &HashMap<String, RegisteredGroup>,
) -> IpcDecision {
    todo!()
}

/// `existing_task_folder`: group folder of the task referenced by
/// pause/resume/cancel/update (None if it doesn't exist).
#[allow(unused_variables, clippy::todo)]
pub fn authorize_task(
    who: IpcIdentity<'_>,
    task: &IpcTask,
    groups: &HashMap<String, RegisteredGroup>,
    existing_task_folder: Option<&str>,
) -> IpcDecision {
    todo!()
}
