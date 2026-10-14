//! Authorization seam.
//!
//! Every IPC request is authorized by an [`IpcAuthorizer`] — in production
//! [`FnAuthorizer::security_policy`], i.e. `talon_security::ipc_authz` — and
//! **additionally** by the built-in [`BaselineAuthorizer`], which encodes the
//! original TypeScript rules from `src/ipc.ts`. The effective decision is the
//! conjunction of both: the baseline can only ever *deny*, so a bug in (or a
//! permissive replacement of) the policy engine can never widen what a
//! container may do. A policy that panics fails closed.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use talon_core::paths::is_valid_group_folder;
use talon_core::protocol::IpcTask;
use talon_core::types::RegisteredGroup;
use talon_security::ipc_authz::{IpcDecision, IpcIdentity};

/// Pluggable authorization for container -> host IPC requests.
///
/// `who` is the directory-derived identity of the requester.
pub trait IpcAuthorizer: Send + Sync {
    /// May `who` send a chat message to `target_jid`?
    fn authorize_message(
        &self,
        who: IpcIdentity<'_>,
        target_jid: &str,
        groups: &HashMap<String, RegisteredGroup>,
    ) -> IpcDecision;

    /// May `who` perform `task`? `existing_task_folder` is the group folder
    /// of the task referenced by pause/resume/cancel/update (`None` if it
    /// does not exist or the variant references no task).
    fn authorize_task(
        &self,
        who: IpcIdentity<'_>,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        existing_task_folder: Option<&str>,
    ) -> IpcDecision;
}

/// Function-pointer signature of an outbound-message policy.
pub type MessageAuthzFn =
    fn(IpcIdentity<'_>, &str, &HashMap<String, RegisteredGroup>) -> IpcDecision;

/// Function-pointer signature of a task policy.
pub type TaskAuthzFn =
    fn(IpcIdentity<'_>, &IpcTask, &HashMap<String, RegisteredGroup>, Option<&str>) -> IpcDecision;

/// An [`IpcAuthorizer`] made of two plain functions.
#[derive(Debug, Clone, Copy)]
pub struct FnAuthorizer {
    /// Outbound message policy.
    pub message: MessageAuthzFn,
    /// Task policy.
    pub task: TaskAuthzFn,
}

impl FnAuthorizer {
    /// The production policy engine: `talon_security::ipc_authz`.
    pub fn security_policy() -> Self {
        Self {
            message: talon_security::ipc_authz::authorize_outbound_message,
            task: talon_security::ipc_authz::authorize_task,
        }
    }
}

impl IpcAuthorizer for FnAuthorizer {
    fn authorize_message(
        &self,
        who: IpcIdentity<'_>,
        target_jid: &str,
        groups: &HashMap<String, RegisteredGroup>,
    ) -> IpcDecision {
        (self.message)(who, target_jid, groups)
    }

    fn authorize_task(
        &self,
        who: IpcIdentity<'_>,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        existing_task_folder: Option<&str>,
    ) -> IpcDecision {
        (self.task)(who, task, groups, existing_task_folder)
    }
}

/// The TypeScript authorization rules (`src/ipc.ts`), always enforced in
/// addition to the configured policy.
///
/// - message: main may message any JID; others only JIDs registered to their
///   own folder.
/// - `schedule_task`: target JID must be registered; non-main only for its
///   own folder.
/// - pause/resume/cancel/update: task must exist; non-main only its own.
/// - `refresh_groups`: main only.
/// - `register_group`: main only, folder must be a valid group folder.
#[derive(Debug, Clone, Copy, Default)]
pub struct BaselineAuthorizer;

impl IpcAuthorizer for BaselineAuthorizer {
    fn authorize_message(
        &self,
        who: IpcIdentity<'_>,
        target_jid: &str,
        groups: &HashMap<String, RegisteredGroup>,
    ) -> IpcDecision {
        if who.is_main {
            return IpcDecision::Allow;
        }
        match groups.get(target_jid) {
            Some(g) if g.folder == who.source_folder => IpcDecision::Allow,
            Some(_) => IpcDecision::Deny("target chat belongs to another group".into()),
            None => IpcDecision::Deny("target chat is not registered".into()),
        }
    }

    fn authorize_task(
        &self,
        who: IpcIdentity<'_>,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        existing_task_folder: Option<&str>,
    ) -> IpcDecision {
        match task {
            IpcTask::ScheduleTask { target_jid, .. } => match groups.get(target_jid) {
                None => IpcDecision::Deny("target group not registered".into()),
                Some(g) if !who.is_main && g.folder != who.source_folder => {
                    IpcDecision::Deny("non-main group may only schedule tasks for itself".into())
                }
                Some(_) => IpcDecision::Allow,
            },
            IpcTask::PauseTask { .. }
            | IpcTask::ResumeTask { .. }
            | IpcTask::CancelTask { .. }
            | IpcTask::UpdateTask { .. } => match existing_task_folder {
                None => IpcDecision::Deny("task not found".into()),
                Some(f) if !who.is_main && f != who.source_folder => {
                    IpcDecision::Deny("non-main group may only manage its own tasks".into())
                }
                Some(_) => IpcDecision::Allow,
            },
            IpcTask::RefreshGroups { .. } => {
                if who.is_main {
                    IpcDecision::Allow
                } else {
                    IpcDecision::Deny("only the main group may refresh groups".into())
                }
            }
            IpcTask::RegisterGroup { folder, .. } => {
                if !who.is_main {
                    IpcDecision::Deny("only the main group may register groups".into())
                } else if !is_valid_group_folder(folder) {
                    IpcDecision::Deny("invalid group folder".into())
                } else {
                    IpcDecision::Allow
                }
            }
        }
    }
}

/// Run a policy call, converting a panic into a fail-closed denial.
fn guarded(f: impl FnOnce() -> IpcDecision) -> IpcDecision {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(d) => d,
        Err(_) => {
            tracing::error!("IPC authorization policy panicked; failing closed");
            IpcDecision::Deny("authorization policy failed; request denied".into())
        }
    }
}

fn combine(policy: IpcDecision, baseline: impl FnOnce() -> IpcDecision) -> IpcDecision {
    match policy {
        IpcDecision::Deny(r) => IpcDecision::Deny(r),
        IpcDecision::Allow => match baseline() {
            IpcDecision::Allow => IpcDecision::Allow,
            IpcDecision::Deny(r) => {
                tracing::warn!(reason = %r, "IPC policy allowed a request the baseline denies");
                IpcDecision::Deny(format!("baseline policy: {r}"))
            }
        },
    }
}

/// Effective decision for an outbound message (policy AND baseline).
pub(crate) fn decide_message(
    policy: &dyn IpcAuthorizer,
    who: IpcIdentity<'_>,
    target_jid: &str,
    groups: &HashMap<String, RegisteredGroup>,
) -> IpcDecision {
    combine(
        guarded(|| policy.authorize_message(who, target_jid, groups)),
        || BaselineAuthorizer.authorize_message(who, target_jid, groups),
    )
}

/// Effective decision for a task operation (policy AND baseline).
pub(crate) fn decide_task(
    policy: &dyn IpcAuthorizer,
    who: IpcIdentity<'_>,
    task: &IpcTask,
    groups: &HashMap<String, RegisteredGroup>,
    existing_task_folder: Option<&str>,
) -> IpcDecision {
    combine(
        guarded(|| policy.authorize_task(who, task, groups, existing_task_folder)),
        || BaselineAuthorizer.authorize_task(who, task, groups, existing_task_folder),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{group, groups_fixture};

    fn allow_msg(_: IpcIdentity<'_>, _: &str, _: &HashMap<String, RegisteredGroup>) -> IpcDecision {
        IpcDecision::Allow
    }
    fn allow_task(
        _: IpcIdentity<'_>,
        _: &IpcTask,
        _: &HashMap<String, RegisteredGroup>,
        _: Option<&str>,
    ) -> IpcDecision {
        IpcDecision::Allow
    }
    fn deny_msg(_: IpcIdentity<'_>, _: &str, _: &HashMap<String, RegisteredGroup>) -> IpcDecision {
        IpcDecision::Deny("policy says no".into())
    }
    fn panic_task(
        _: IpcIdentity<'_>,
        _: &IpcTask,
        _: &HashMap<String, RegisteredGroup>,
        _: Option<&str>,
    ) -> IpcDecision {
        panic!("not yet implemented")
    }

    const MAIN: IpcIdentity<'static> = IpcIdentity {
        source_folder: "whatsapp_main",
        is_main: true,
    };
    const OTHER: IpcIdentity<'static> = IpcIdentity {
        source_folder: "other-group",
        is_main: false,
    };

    fn is_msg_authorized(who: IpcIdentity<'_>, jid: &str) -> bool {
        BaselineAuthorizer
            .authorize_message(who, jid, &groups_fixture())
            .is_allowed()
    }

    // Port of the "IPC message authorization" block of ipc-auth.test.ts.
    #[test]
    fn main_group_can_send_to_any_group() {
        assert!(is_msg_authorized(MAIN, "other@g.us"));
        assert!(is_msg_authorized(MAIN, "third@g.us"));
    }

    #[test]
    fn non_main_group_can_send_to_its_own_chat() {
        assert!(is_msg_authorized(OTHER, "other@g.us"));
    }

    #[test]
    fn non_main_group_cannot_send_to_another_groups_chat() {
        assert!(!is_msg_authorized(OTHER, "main@g.us"));
        assert!(!is_msg_authorized(OTHER, "third@g.us"));
    }

    #[test]
    fn non_main_group_cannot_send_to_unregistered_jid() {
        assert!(!is_msg_authorized(OTHER, "unknown@g.us"));
    }

    #[test]
    fn main_group_can_send_to_unregistered_jid() {
        assert!(is_msg_authorized(MAIN, "unknown@g.us"));
    }

    #[test]
    fn baseline_task_rules() {
        let g = groups_fixture();
        let b = BaselineAuthorizer;
        let pause = IpcTask::PauseTask {
            task_id: "t".into(),
            timestamp: None,
        };
        assert!(
            b.authorize_task(MAIN, &pause, &g, Some("other-group"))
                .is_allowed()
        );
        assert!(
            b.authorize_task(OTHER, &pause, &g, Some("other-group"))
                .is_allowed()
        );
        assert!(
            !b.authorize_task(OTHER, &pause, &g, Some("whatsapp_main"))
                .is_allowed()
        );
        assert!(!b.authorize_task(MAIN, &pause, &g, None).is_allowed());

        let refresh = IpcTask::RefreshGroups { timestamp: None };
        assert!(b.authorize_task(MAIN, &refresh, &g, None).is_allowed());
        assert!(!b.authorize_task(OTHER, &refresh, &g, None).is_allowed());

        let reg = |folder: &str| IpcTask::RegisterGroup {
            jid: "new@g.us".into(),
            name: "New".into(),
            folder: folder.into(),
            trigger: "@Andy".into(),
            requires_trigger: None,
            container_config: None,
            timestamp: None,
        };
        assert!(
            b.authorize_task(MAIN, &reg("new-group"), &g, None)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(MAIN, &reg("../../outside"), &g, None)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(MAIN, &reg("errors"), &g, None)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(OTHER, &reg("new-group"), &g, None)
                .is_allowed()
        );
    }

    #[test]
    fn baseline_denies_even_when_policy_allows() {
        let permissive = FnAuthorizer {
            message: allow_msg,
            task: allow_task,
        };
        let g = groups_fixture();
        assert!(!decide_message(&permissive, OTHER, "main@g.us", &g).is_allowed());
        assert!(decide_message(&permissive, OTHER, "other@g.us", &g).is_allowed());
        let refresh = IpcTask::RefreshGroups { timestamp: None };
        let d = decide_task(&permissive, OTHER, &refresh, &g, None);
        assert!(matches!(d, IpcDecision::Deny(r) if r.starts_with("baseline policy")));
    }

    #[test]
    fn policy_denial_wins_over_baseline_allow() {
        let strict = FnAuthorizer {
            message: deny_msg,
            task: allow_task,
        };
        let d = decide_message(&strict, MAIN, "other@g.us", &groups_fixture());
        assert_eq!(d, IpcDecision::Deny("policy says no".into()));
    }

    #[test]
    fn panicking_policy_fails_closed() {
        let broken = FnAuthorizer {
            message: allow_msg,
            task: panic_task,
        };
        let refresh = IpcTask::RefreshGroups { timestamp: None };
        let d = decide_task(&broken, MAIN, &refresh, &groups_fixture(), None);
        assert!(!d.is_allowed());
    }

    #[test]
    fn schedule_task_baseline() {
        let mut g = groups_fixture();
        g.insert(
            "lane@x".into(),
            group("copilot", Some("copilot-u-1"), false),
        );
        let sched = |jid: &str| IpcTask::ScheduleTask {
            task_id: None,
            prompt: "p".into(),
            script: None,
            schedule_type: talon_core::types::ScheduleType::Once,
            schedule_value: "2026-01-01T00:00:00".into(),
            context_mode: None,
            target_jid: jid.into(),
            created_by: None,
            timestamp: None,
        };
        let b = BaselineAuthorizer;
        assert!(
            b.authorize_task(MAIN, &sched("other@g.us"), &g, None)
                .is_allowed()
        );
        assert!(
            b.authorize_task(OTHER, &sched("other@g.us"), &g, None)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(OTHER, &sched("main@g.us"), &g, None)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(MAIN, &sched("unknown@g.us"), &g, None)
                .is_allowed()
        );
        let copilot = IpcIdentity {
            source_folder: "copilot",
            is_main: false,
        };
        assert!(
            b.authorize_task(copilot, &sched("lane@x"), &g, None)
                .is_allowed()
        );
    }
}
