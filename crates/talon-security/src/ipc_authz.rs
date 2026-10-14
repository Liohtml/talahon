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
//!
//! Additional hardening over the TypeScript release:
//! - the caller-supplied `is_main` flag is cross-checked against the
//!   registry: an identity only counts as main when a registered group with
//!   `is_main` actually owns `source_folder` (a stale/forged flag degrades to
//!   non-main, never the other way round);
//! - an invalid `source_folder` is denied outright;
//! - main may no longer message *unregistered* JIDs;
//! - a caller-chosen `taskId` must be a sane identifier and must not collide
//!   with an existing task;
//! - `register_group` may not attach a new JID to a main group's folder
//!   (which would hand a non-main chat the main workspace), and its text
//!   fields are length/charset bounded.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use talon_core::paths::is_valid_group_folder;
use talon_core::protocol::IpcTask;
use talon_core::types::RegisteredGroup;

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcDecision {
    /// The request may proceed.
    Allow,
    /// The request is refused; the string is a short, log-safe reason.
    Deny(String),
}

impl IpcDecision {
    /// `true` for [`IpcDecision::Allow`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, IpcDecision::Allow)
    }

    /// The denial reason, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            IpcDecision::Allow => None,
            IpcDecision::Deny(r) => Some(r),
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        IpcDecision::Deny(reason.into())
    }
}

/// Identity of the requesting container, derived from its IPC directory.
#[derive(Debug, Clone, Copy)]
pub struct IpcIdentity<'a> {
    /// Group folder owning the IPC namespace.
    pub source_folder: &'a str,
    /// Whether the owning group is the main group (re-verified against the
    /// registry by every check in this module).
    pub is_main: bool,
}

/// Maximum length of free-text identifiers (`jid`, `name`, `trigger`).
pub const MAX_FIELD_LEN: usize = 256;

/// Caller-chosen task ids: `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.
static TASK_ID: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$").expect("static task id regex")
});

/// Is `task_id` an acceptable caller-chosen task identifier?
pub fn is_valid_task_id(task_id: &str) -> bool {
    TASK_ID.is_match(task_id)
}

/// Effective main status: the flag must be backed by the registry.
fn effective_main(who: IpcIdentity<'_>, groups: &HashMap<String, RegisteredGroup>) -> bool {
    who.is_main
        && groups
            .values()
            .any(|g| g.is_main && g.folder == who.source_folder)
}

fn check_source(who: IpcIdentity<'_>) -> Option<IpcDecision> {
    (!is_valid_group_folder(who.source_folder)).then(|| IpcDecision::deny("invalid source folder"))
}

fn sane_field(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty() && value.len() <= MAX_FIELD_LEN && !value.chars().any(char::is_control)
}

/// May `who` send a chat message to `target_jid`?
pub fn authorize_outbound_message(
    who: IpcIdentity<'_>,
    target_jid: &str,
    groups: &HashMap<String, RegisteredGroup>,
) -> IpcDecision {
    if let Some(d) = check_source(who) {
        return d;
    }
    if target_jid.trim().is_empty() {
        return IpcDecision::deny("empty target jid");
    }
    let Some(target) = groups.get(target_jid) else {
        return IpcDecision::deny("target jid is not registered");
    };
    if effective_main(who, groups) || target.folder == who.source_folder {
        IpcDecision::Allow
    } else {
        IpcDecision::deny("non-main group may only message its own chats")
    }
}

/// `existing_task_folder`: group folder of the task referenced by
/// pause/resume/cancel/update (None if it doesn't exist).
///
/// For `schedule_task` with an explicit `taskId`, callers should pass the
/// folder of an already existing task with that id (if any): a collision is
/// denied so a caller can never overwrite someone else's task.
pub fn authorize_task(
    who: IpcIdentity<'_>,
    task: &IpcTask,
    groups: &HashMap<String, RegisteredGroup>,
    existing_task_folder: Option<&str>,
) -> IpcDecision {
    if let Some(d) = check_source(who) {
        return d;
    }
    let is_main = effective_main(who, groups);

    match task {
        IpcTask::ScheduleTask {
            task_id,
            prompt,
            schedule_value,
            target_jid,
            ..
        } => {
            if prompt.trim().is_empty() || schedule_value.trim().is_empty() {
                return IpcDecision::deny("schedule_task: missing prompt or schedule");
            }
            if let Some(id) = task_id {
                if !is_valid_task_id(id) {
                    return IpcDecision::deny("schedule_task: invalid taskId");
                }
                if existing_task_folder.is_some() {
                    return IpcDecision::deny("schedule_task: taskId already exists");
                }
            }
            let Some(target) = groups.get(target_jid.as_str()) else {
                return IpcDecision::deny("schedule_task: target jid is not registered");
            };
            if !is_main && target.folder != who.source_folder {
                return IpcDecision::deny(
                    "schedule_task: non-main group may only schedule for itself",
                );
            }
            IpcDecision::Allow
        }
        IpcTask::PauseTask { task_id, .. }
        | IpcTask::ResumeTask { task_id, .. }
        | IpcTask::CancelTask { task_id, .. }
        | IpcTask::UpdateTask { task_id, .. } => {
            if task_id.trim().is_empty() {
                return IpcDecision::deny("missing taskId");
            }
            let Some(owner) = existing_task_folder else {
                return IpcDecision::deny("task not found");
            };
            if is_main || owner == who.source_folder {
                IpcDecision::Allow
            } else {
                IpcDecision::deny("non-main group may only manage its own tasks")
            }
        }
        IpcTask::RefreshGroups { .. } => {
            if is_main {
                IpcDecision::Allow
            } else {
                IpcDecision::deny("refresh_groups: main only")
            }
        }
        IpcTask::RegisterGroup {
            jid,
            name,
            folder,
            trigger,
            ..
        } => {
            if !is_main {
                return IpcDecision::deny("register_group: main only");
            }
            if !sane_field(jid) || !sane_field(name) || !sane_field(trigger) {
                return IpcDecision::deny("register_group: missing or invalid fields");
            }
            if !is_valid_group_folder(folder) {
                return IpcDecision::deny("register_group: unsafe folder name");
            }
            // A new JID must not be bound to a main group's workspace.
            let hijacks_main = groups
                .iter()
                .any(|(gjid, g)| g.is_main && g.folder == *folder && gjid != jid);
            if hijacks_main {
                return IpcDecision::deny("register_group: folder belongs to the main group");
            }
            IpcDecision::Allow
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use talon_core::types::ScheduleType;

    fn group(name: &str, folder: &str, is_main: bool) -> RegisteredGroup {
        RegisteredGroup {
            name: name.into(),
            folder: folder.into(),
            trigger: "@Andy".into(),
            added_at: "2024-01-01T00:00:00.000Z".into(),
            container_config: None,
            requires_trigger: None,
            is_main,
            session_key: None,
            ipc_key: None,
            ephemeral_session: false,
            trusted_session_commands: false,
        }
    }

    fn groups() -> HashMap<String, RegisteredGroup> {
        HashMap::from([
            (
                "main@g.us".to_string(),
                group("Main", "whatsapp_main", true),
            ),
            (
                "other@g.us".to_string(),
                group("Other", "other-group", false),
            ),
            (
                "third@g.us".to_string(),
                group("Third", "third-group", false),
            ),
        ])
    }

    const MAIN: IpcIdentity<'static> = IpcIdentity {
        source_folder: "whatsapp_main",
        is_main: true,
    };
    const OTHER: IpcIdentity<'static> = IpcIdentity {
        source_folder: "other-group",
        is_main: false,
    };
    const THIRD: IpcIdentity<'static> = IpcIdentity {
        source_folder: "third-group",
        is_main: false,
    };

    fn schedule(target: &str) -> IpcTask {
        IpcTask::ScheduleTask {
            task_id: None,
            prompt: "do something".into(),
            script: None,
            schedule_type: ScheduleType::Once,
            schedule_value: "2025-06-01T00:00:00".into(),
            context_mode: None,
            target_jid: target.into(),
            created_by: None,
            timestamp: None,
        }
    }

    fn register(jid: &str, folder: &str) -> IpcTask {
        IpcTask::RegisterGroup {
            jid: jid.into(),
            name: "New Group".into(),
            folder: folder.into(),
            trigger: "@Andy".into(),
            requires_trigger: None,
            container_config: None,
            timestamp: None,
        }
    }

    fn pause(id: &str) -> IpcTask {
        IpcTask::PauseTask {
            task_id: id.into(),
            timestamp: None,
        }
    }

    // --- schedule_task (ported from ipc-auth.test.ts) ---

    #[test]
    fn main_can_schedule_for_another_group() {
        assert!(authorize_task(MAIN, &schedule("other@g.us"), &groups(), None).is_allowed());
    }

    #[test]
    fn non_main_can_schedule_for_itself() {
        assert!(authorize_task(OTHER, &schedule("other@g.us"), &groups(), None).is_allowed());
    }

    #[test]
    fn non_main_cannot_schedule_for_another_group() {
        assert!(!authorize_task(OTHER, &schedule("main@g.us"), &groups(), None).is_allowed());
        assert!(!authorize_task(OTHER, &schedule("third@g.us"), &groups(), None).is_allowed());
    }

    #[test]
    fn schedule_for_unregistered_target_is_denied_even_for_main() {
        assert!(!authorize_task(MAIN, &schedule("unknown@g.us"), &groups(), None).is_allowed());
    }

    #[test]
    fn schedule_requires_prompt_and_value() {
        let mut t = schedule("other@g.us");
        if let IpcTask::ScheduleTask { prompt, .. } = &mut t {
            *prompt = "  ".into();
        }
        assert!(!authorize_task(MAIN, &t, &groups(), None).is_allowed());
    }

    #[test]
    fn schedule_task_id_must_be_sane_and_fresh() {
        let mut t = schedule("other@g.us");
        if let IpcTask::ScheduleTask { task_id, .. } = &mut t {
            *task_id = Some("task-1700000000000-abc123".into());
        }
        assert!(authorize_task(OTHER, &t, &groups(), None).is_allowed());
        // collision with an existing task (possibly another group's)
        assert!(!authorize_task(OTHER, &t, &groups(), Some("whatsapp_main")).is_allowed());
        for bad in ["", "../x", "a b", "-lead", &"a".repeat(129), "id\n"] {
            if let IpcTask::ScheduleTask { task_id, .. } = &mut t {
                *task_id = Some(bad.to_string());
            }
            assert!(
                !authorize_task(MAIN, &t, &groups(), None).is_allowed(),
                "{bad:?}"
            );
        }
    }

    // --- pause / resume / cancel / update ---

    #[test]
    fn main_can_manage_any_task() {
        for t in [
            pause("t"),
            IpcTask::ResumeTask {
                task_id: "t".into(),
                timestamp: None,
            },
            IpcTask::CancelTask {
                task_id: "t".into(),
                timestamp: None,
            },
            IpcTask::UpdateTask {
                task_id: "t".into(),
                prompt: Some("p".into()),
                script: None,
                schedule_type: None,
                schedule_value: None,
                timestamp: None,
            },
        ] {
            assert!(authorize_task(MAIN, &t, &groups(), Some("other-group")).is_allowed());
        }
    }

    #[test]
    fn non_main_can_manage_own_task_only() {
        assert!(authorize_task(OTHER, &pause("t"), &groups(), Some("other-group")).is_allowed());
        assert!(!authorize_task(OTHER, &pause("t"), &groups(), Some("whatsapp_main")).is_allowed());
        let resume = IpcTask::ResumeTask {
            task_id: "t".into(),
            timestamp: None,
        };
        assert!(!authorize_task(THIRD, &resume, &groups(), Some("other-group")).is_allowed());
        let cancel = IpcTask::CancelTask {
            task_id: "t".into(),
            timestamp: None,
        };
        assert!(authorize_task(OTHER, &cancel, &groups(), Some("other-group")).is_allowed());
        assert!(!authorize_task(OTHER, &cancel, &groups(), Some("whatsapp_main")).is_allowed());
    }

    #[test]
    fn missing_task_is_denied() {
        let d = authorize_task(MAIN, &pause("nope"), &groups(), None);
        assert_eq!(d.reason(), Some("task not found"));
        assert!(!authorize_task(MAIN, &pause(" "), &groups(), Some("x")).is_allowed());
    }

    // --- refresh_groups / register_group ---

    #[test]
    fn refresh_groups_main_only() {
        let t = IpcTask::RefreshGroups { timestamp: None };
        assert!(authorize_task(MAIN, &t, &groups(), None).is_allowed());
        assert!(!authorize_task(OTHER, &t, &groups(), None).is_allowed());
    }

    #[test]
    fn non_main_cannot_register_group() {
        assert!(
            !authorize_task(OTHER, &register("new@g.us", "new-group"), &groups(), None)
                .is_allowed()
        );
    }

    #[test]
    fn main_can_register_group() {
        assert!(
            authorize_task(MAIN, &register("new@g.us", "new-group"), &groups(), None).is_allowed()
        );
    }

    #[test]
    fn register_rejects_unsafe_folder() {
        for bad in ["../../outside", "", "global", "errors", "a/b", " x", "-x"] {
            assert!(
                !authorize_task(MAIN, &register("new@g.us", bad), &groups(), None).is_allowed(),
                "{bad}"
            );
        }
    }

    #[test]
    fn register_rejects_missing_fields() {
        let t = IpcTask::RegisterGroup {
            jid: "partial@g.us".into(),
            name: "Partial".into(),
            folder: "".into(),
            trigger: "".into(),
            requires_trigger: None,
            container_config: None,
            timestamp: None,
        };
        assert!(!authorize_task(MAIN, &t, &groups(), None).is_allowed());
        let t = IpcTask::RegisterGroup {
            jid: "x@g.us".into(),
            name: "bad\nname".into(),
            folder: "ok".into(),
            trigger: "@A".into(),
            requires_trigger: None,
            container_config: None,
            timestamp: None,
        };
        assert!(!authorize_task(MAIN, &t, &groups(), None).is_allowed());
    }

    #[test]
    fn register_cannot_attach_new_jid_to_main_folder() {
        assert!(
            !authorize_task(
                MAIN,
                &register("evil@g.us", "whatsapp_main"),
                &groups(),
                None
            )
            .is_allowed()
        );
        // re-registering main itself (config update) stays possible
        assert!(
            authorize_task(
                MAIN,
                &register("main@g.us", "whatsapp_main"),
                &groups(),
                None
            )
            .is_allowed()
        );
    }

    // --- outbound messages ---

    #[test]
    fn main_can_message_any_registered_group() {
        let g = groups();
        assert!(authorize_outbound_message(MAIN, "other@g.us", &g).is_allowed());
        assert!(authorize_outbound_message(MAIN, "third@g.us", &g).is_allowed());
    }

    #[test]
    fn non_main_can_message_own_chat_only() {
        let g = groups();
        assert!(authorize_outbound_message(OTHER, "other@g.us", &g).is_allowed());
        assert!(!authorize_outbound_message(OTHER, "main@g.us", &g).is_allowed());
        assert!(!authorize_outbound_message(OTHER, "third@g.us", &g).is_allowed());
        assert!(!authorize_outbound_message(OTHER, "unknown@g.us", &g).is_allowed());
    }

    #[test]
    fn main_cannot_message_unregistered_jid() {
        // tightened vs. TS (which allowed it)
        assert!(!authorize_outbound_message(MAIN, "unknown@g.us", &groups()).is_allowed());
        assert!(!authorize_outbound_message(MAIN, "", &groups()).is_allowed());
    }

    #[test]
    fn forged_main_flag_is_not_trusted() {
        let forged = IpcIdentity {
            source_folder: "other-group",
            is_main: true,
        };
        let g = groups();
        assert!(!authorize_outbound_message(forged, "main@g.us", &g).is_allowed());
        assert!(!authorize_task(forged, &schedule("main@g.us"), &g, None).is_allowed());
        assert!(!authorize_task(forged, &register("n@g.us", "n"), &g, None).is_allowed());
        assert!(
            !authorize_task(
                forged,
                &IpcTask::RefreshGroups { timestamp: None },
                &g,
                None
            )
            .is_allowed()
        );
        // ...but it keeps its own non-main rights
        assert!(authorize_outbound_message(forged, "other@g.us", &g).is_allowed());
    }

    #[test]
    fn invalid_source_folder_is_denied() {
        let bad = IpcIdentity {
            source_folder: "../whatsapp_main",
            is_main: false,
        };
        assert!(!authorize_outbound_message(bad, "other@g.us", &groups()).is_allowed());
        assert!(
            !authorize_task(bad, &pause("t"), &groups(), Some("../whatsapp_main")).is_allowed()
        );
        let empty = IpcIdentity {
            source_folder: "",
            is_main: false,
        };
        assert!(!authorize_task(empty, &pause("t"), &groups(), Some("")).is_allowed());
    }

    #[test]
    fn lane_jids_sharing_a_folder_may_message_each_other() {
        let mut g = groups();
        g.insert(
            "http:copilot:u:1".into(),
            group("Copilot", "copilot", false),
        );
        g.insert(
            "http:copilot:u:2".into(),
            group("Copilot", "copilot", false),
        );
        let who = IpcIdentity {
            source_folder: "copilot",
            is_main: false,
        };
        assert!(authorize_outbound_message(who, "http:copilot:u:2", &g).is_allowed());
        assert!(!authorize_outbound_message(who, "other@g.us", &g).is_allowed());
    }
}
