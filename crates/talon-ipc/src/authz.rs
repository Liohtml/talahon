//! Authorization seam.
//!
//! Every IPC request is authorized by an [`IpcAuthorizer`] — in production
//! [`FnAuthorizer::security_policy`], i.e. `talon_security::ipc_authz` — and
//! **additionally** by the built-in [`BaselineAuthorizer`], which encodes the
//! original TypeScript rules from `src/ipc.ts` tightened to per-lane
//! isolation (MYTH-03). The effective decision is the conjunction of both:
//! the baseline can only ever *deny*, so a bug in (or a permissive
//! replacement of) the policy engine can never widen what a container may
//! do. A policy that panics fails closed.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use talon_core::paths::is_valid_group_folder;
use talon_core::protocol::IpcTask;
use talon_core::types::RegisteredGroup;
use talon_security::ipc_authz::{IpcDecision, IpcIdentity, TaskOwner};

/// Pluggable authorization for container -> host IPC requests.
///
/// `who` is the directory-derived identity of the requester; its
/// [`IpcIdentity::ipc_key`] is the principal.
pub trait IpcAuthorizer: Send + Sync {
    /// May `who` send a chat message to `target_jid`?
    fn authorize_message(
        &self,
        who: IpcIdentity<'_>,
        target_jid: &str,
        groups: &HashMap<String, RegisteredGroup>,
    ) -> IpcDecision;

    /// May `who` perform `task`? `existing_task_owner` is the recorded owner
    /// of the task referenced by pause/resume/cancel/update, or of an
    /// existing task whose id a `schedule_task` reuses (`None` if no such
    /// task exists; tasks without an owner record are [`TaskOwner::Host`]).
    fn authorize_task(
        &self,
        who: IpcIdentity<'_>,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        existing_task_owner: Option<TaskOwner<'_>>,
    ) -> IpcDecision;
}

/// Function-pointer signature of an outbound-message policy.
pub type MessageAuthzFn =
    fn(IpcIdentity<'_>, &str, &HashMap<String, RegisteredGroup>) -> IpcDecision;

/// Function-pointer signature of a task policy.
pub type TaskAuthzFn = fn(
    IpcIdentity<'_>,
    &IpcTask,
    &HashMap<String, RegisteredGroup>,
    Option<TaskOwner<'_>>,
) -> IpcDecision;

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
        existing_task_owner: Option<TaskOwner<'_>>,
    ) -> IpcDecision {
        (self.task)(who, task, groups, existing_task_owner)
    }
}

/// Is `g` a lane of the requesting namespace (same IPC key and folder)?
fn own_lane(who: IpcIdentity<'_>, g: &RegisteredGroup) -> bool {
    g.ipc_key() == who.ipc_key && g.folder == who.source_folder
}

/// The TypeScript authorization rules (`src/ipc.ts`), tightened to per-lane
/// isolation, always enforced in addition to the configured policy.
///
/// - message: main may message any JID; others only JIDs registered to
///   their own lane (same IPC key *and* folder).
/// - `schedule_task`: target JID must be registered; non-main only for its
///   own lane and never with a `script`.
/// - pause/resume/cancel/update: task must exist; non-main only tasks it
///   created (owner == its IPC key; host-owned tasks are immutable) and
///   `update_task` may not set a script; main may not change the script of
///   a host-owned task.
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
            Some(g) if own_lane(who, g) => IpcDecision::Allow,
            Some(_) => IpcDecision::Deny("target chat belongs to another lane".into()),
            None => IpcDecision::Deny("target chat is not registered".into()),
        }
    }

    fn authorize_task(
        &self,
        who: IpcIdentity<'_>,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        existing_task_owner: Option<TaskOwner<'_>>,
    ) -> IpcDecision {
        match task {
            IpcTask::ScheduleTask {
                target_jid, script, ..
            } => match groups.get(target_jid) {
                None => IpcDecision::Deny("target group not registered".into()),
                Some(g) if !who.is_main && !own_lane(who, g) => {
                    IpcDecision::Deny("non-main lane may only schedule tasks for itself".into())
                }
                Some(_) if !who.is_main && script.as_deref().is_some_and(|s| !s.is_empty()) => {
                    IpcDecision::Deny("only the main group may schedule scripts".into())
                }
                Some(_) => IpcDecision::Allow,
            },
            IpcTask::PauseTask { .. }
            | IpcTask::ResumeTask { .. }
            | IpcTask::CancelTask { .. }
            | IpcTask::UpdateTask { .. } => {
                let Some(owner) = existing_task_owner else {
                    return IpcDecision::Deny("task not found".into());
                };
                let script = match task {
                    IpcTask::UpdateTask { script, .. } => script.as_deref(),
                    _ => None,
                };
                if who.is_main {
                    if owner.is_host() && script.is_some() {
                        return IpcDecision::Deny(
                            "the script of a host-owned task is operator-only".into(),
                        );
                    }
                    return IpcDecision::Allow;
                }
                if !owner.is_lane(who.ipc_key) {
                    return IpcDecision::Deny(
                        "non-main lane may only manage tasks it created".into(),
                    );
                }
                if script.is_some_and(|s| !s.is_empty()) {
                    return IpcDecision::Deny("only the main group may set a script".into());
                }
                IpcDecision::Allow
            }
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
    existing_task_owner: Option<TaskOwner<'_>>,
) -> IpcDecision {
    combine(
        guarded(|| policy.authorize_task(who, task, groups, existing_task_owner)),
        || BaselineAuthorizer.authorize_task(who, task, groups, existing_task_owner),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{copilot_groups, group, groups_fixture};

    fn allow_msg(_: IpcIdentity<'_>, _: &str, _: &HashMap<String, RegisteredGroup>) -> IpcDecision {
        IpcDecision::Allow
    }
    fn allow_task(
        _: IpcIdentity<'_>,
        _: &IpcTask,
        _: &HashMap<String, RegisteredGroup>,
        _: Option<TaskOwner<'_>>,
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
        _: Option<TaskOwner<'_>>,
    ) -> IpcDecision {
        panic!("not yet implemented")
    }

    const MAIN: IpcIdentity<'static> = IpcIdentity {
        source_folder: "whatsapp_main",
        ipc_key: "whatsapp_main",
        is_main: true,
    };
    const OTHER: IpcIdentity<'static> = IpcIdentity {
        source_folder: "other-group",
        ipc_key: "other-group",
        is_main: false,
    };
    const ALICE: IpcIdentity<'static> = IpcIdentity {
        source_folder: "copilot",
        ipc_key: "copilot-u-alice",
        is_main: false,
    };

    fn is_msg_authorized(who: IpcIdentity<'_>, jid: &str) -> bool {
        BaselineAuthorizer
            .authorize_message(who, jid, &groups_fixture())
            .is_allowed()
    }

    fn sched(jid: &str, script: Option<&str>) -> IpcTask {
        IpcTask::ScheduleTask {
            task_id: None,
            prompt: "p".into(),
            script: script.map(str::to_string),
            schedule_type: talon_core::types::ScheduleType::Once,
            schedule_value: "2026-01-01T00:00:00".into(),
            context_mode: None,
            target_jid: jid.into(),
            created_by: None,
            timestamp: None,
        }
    }

    fn pause() -> IpcTask {
        IpcTask::PauseTask {
            task_id: "t".into(),
            timestamp: None,
        }
    }

    fn update_script(script: &str) -> IpcTask {
        IpcTask::UpdateTask {
            task_id: "t".into(),
            prompt: None,
            script: Some(script.into()),
            schedule_type: None,
            schedule_value: None,
            timestamp: None,
        }
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
    fn baseline_messages_are_per_lane() {
        let g = copilot_groups();
        let b = BaselineAuthorizer;
        assert!(
            b.authorize_message(ALICE, "http:copilot:u:alice", &g)
                .is_allowed()
        );
        for jid in [
            "http:copilot:u:bob",
            "http:copilot:investigate",
            "http:copilot",
            "webhook:copilot",
        ] {
            assert!(!b.authorize_message(ALICE, jid, &g).is_allowed(), "{jid}");
        }
    }

    #[test]
    fn baseline_task_rules() {
        let g = groups_fixture();
        let b = BaselineAuthorizer;
        let own = Some(TaskOwner::Lane("other-group"));
        let mains = Some(TaskOwner::Lane("whatsapp_main"));
        let host = Some(TaskOwner::Host);
        assert!(b.authorize_task(MAIN, &pause(), &g, own).is_allowed());
        assert!(b.authorize_task(MAIN, &pause(), &g, host).is_allowed());
        assert!(b.authorize_task(OTHER, &pause(), &g, own).is_allowed());
        assert!(!b.authorize_task(OTHER, &pause(), &g, mains).is_allowed());
        assert!(!b.authorize_task(OTHER, &pause(), &g, host).is_allowed());
        assert!(!b.authorize_task(MAIN, &pause(), &g, None).is_allowed());

        // scripts: never from non-main, never onto host tasks
        assert!(
            !b.authorize_task(OTHER, &update_script("x"), &g, own)
                .is_allowed()
        );
        assert!(
            b.authorize_task(OTHER, &update_script(""), &g, own)
                .is_allowed()
        );
        assert!(
            b.authorize_task(MAIN, &update_script("x"), &g, own)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(MAIN, &update_script("x"), &g, host)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(MAIN, &update_script(""), &g, host)
                .is_allowed()
        );

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
    fn baseline_keeps_lanes_apart_under_a_permissive_policy() {
        let permissive = FnAuthorizer {
            message: allow_msg,
            task: allow_task,
        };
        let g = copilot_groups();
        assert!(!decide_message(&permissive, ALICE, "http:copilot:u:bob", &g).is_allowed());
        assert!(!decide_message(&permissive, ALICE, "webhook:copilot", &g).is_allowed());
        assert!(
            !decide_task(
                &permissive,
                ALICE,
                &sched("http:copilot:u:alice", Some("id")),
                &g,
                None
            )
            .is_allowed()
        );
        assert!(
            !decide_task(
                &permissive,
                ALICE,
                &pause(),
                &g,
                Some(TaskOwner::Lane("copilot-u-bob"))
            )
            .is_allowed()
        );
        assert!(!decide_task(&permissive, ALICE, &pause(), &g, Some(TaskOwner::Host)).is_allowed());
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
    fn production_policy_and_baseline_agree_on_the_copilot_lanes() {
        let policy = FnAuthorizer::security_policy();
        let g = copilot_groups();
        assert!(decide_message(&policy, ALICE, "http:copilot:u:alice", &g).is_allowed());
        assert!(!decide_message(&policy, ALICE, "http:copilot:u:bob", &g).is_allowed());
        assert!(
            decide_task(
                &policy,
                ALICE,
                &sched("http:copilot:u:alice", None),
                &g,
                None
            )
            .is_allowed()
        );
        assert!(
            !decide_task(&policy, ALICE, &sched("http:copilot:u:bob", None), &g, None).is_allowed()
        );
    }

    #[test]
    fn schedule_task_baseline() {
        let mut g = groups_fixture();
        g.insert(
            "lane@x".into(),
            group("copilot", Some("copilot-u-1"), false),
        );
        g.insert("base@x".into(), group("copilot", None, false));
        let b = BaselineAuthorizer;
        assert!(
            b.authorize_task(MAIN, &sched("other@g.us", None), &g, None)
                .is_allowed()
        );
        assert!(
            b.authorize_task(MAIN, &sched("other@g.us", Some("echo")), &g, None)
                .is_allowed()
        );
        assert!(
            b.authorize_task(OTHER, &sched("other@g.us", None), &g, None)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(OTHER, &sched("other@g.us", Some("echo")), &g, None)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(OTHER, &sched("main@g.us", None), &g, None)
                .is_allowed()
        );
        assert!(
            !b.authorize_task(MAIN, &sched("unknown@g.us", None), &g, None)
                .is_allowed()
        );
        let lane = IpcIdentity {
            source_folder: "copilot",
            ipc_key: "copilot-u-1",
            is_main: false,
        };
        assert!(
            b.authorize_task(lane, &sched("lane@x", None), &g, None)
                .is_allowed()
        );
        // same folder, different namespace
        assert!(
            !b.authorize_task(lane, &sched("base@x", None), &g, None)
                .is_allowed()
        );
    }
}
