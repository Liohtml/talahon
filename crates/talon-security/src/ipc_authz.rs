//! Authorization of container -> host IPC requests.
//!
//! ## Principal
//!
//! The principal is the **IPC namespace** the request was found in
//! ([`IpcIdentity::ipc_key`], i.e. the `data/ipc/<ipc_key>/` directory) —
//! never a field inside the file, and no longer the group *folder*: several
//! lanes share one folder (all CoPilot lanes live in `copilot`: the
//! per-analyst lanes `http:copilot:u:<id>` with key `copilot-u-<id>`, the
//! investigation lane, the base lane and the webhook lane), so a
//! folder-keyed check would let analyst *alice* act on analyst *bob*'s lane
//! (MYTH-03).
//!
//! ## Rules for non-main sources
//! - outbound message: the target JID must be a registered lane whose
//!   [`RegisteredGroup::ipc_key`] equals the source `ipc_key` (and whose
//!   folder equals the source folder);
//! - `schedule_task`: `targetJid` must be such a lane; a `script` is
//!   **forbidden** (scripts run on the host side of the task runner with the
//!   target lane's mounts — only main may schedule them);
//! - pause/resume/cancel/update: only tasks whose recorded owner
//!   ([`TaskOwner`]) is the source `ipc_key`. Tasks without an owner record
//!   (created by the host: HTTP investigations, the seeded alert digest,
//!   rows that predate ownership records) are [`TaskOwner::Host`] and
//!   immutable; `update_task` may not set a script;
//! - `refresh_groups` / `register_group`: denied (main only).
//!
//! ## Rules for main
//! - may message any *registered* JID (unregistered JIDs are denied);
//! - may schedule for any registered lane, including scripts;
//! - may pause/resume/cancel/update any task, but `update_task` may not
//!   change the script of a host-owned task (script injection into host
//!   tasks is operator-only);
//! - `register_group` can never set `is_main`, its folder must pass
//!   `is_valid_group_folder`, it may not attach a new JID to a main group's
//!   folder, and its text fields are length/charset bounded. Its
//!   `containerConfig` is never honoured (additional mounts, env, network
//!   are operator-only; the IPC watcher strips the field).
//!
//! ## General hardening
//! - the caller-supplied `is_main` flag is cross-checked against the
//!   registry: an identity only counts as main when a registered main group
//!   owns both `source_folder` and `ipc_key` (a stale/forged flag degrades
//!   to non-main, never the other way round);
//! - an invalid `source_folder` / `ipc_key`, or a namespace that no
//!   registered lane owns, is denied outright;
//! - a caller-chosen `taskId` must be a sane identifier and must not collide
//!   with an existing task (of any owner).

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
    /// Group folder of the lane(s) owning the IPC namespace.
    pub source_folder: &'a str,
    /// The IPC namespace (directory name, [`RegisteredGroup::ipc_key`]) the
    /// request was found in. This is the principal for every per-lane rule.
    pub ipc_key: &'a str,
    /// Whether the owning group is the main group (re-verified against the
    /// registry by every check in this module).
    pub is_main: bool,
}

/// Textual owner recorded for tasks created by the host itself (and the
/// implied owner of every task without an owner record).
pub const HOST_TASK_OWNER: &str = "host";

/// Recorded owner of an existing scheduled task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOwner<'a> {
    /// Created by the host (HTTP investigations, the seeded alert digest,
    /// rows that predate ownership records). Immutable for non-main lanes;
    /// its script can only be changed by the operator.
    Host,
    /// Created over IPC by the namespace with this `ipc_key`.
    Lane(&'a str),
}

impl<'a> TaskOwner<'a> {
    /// Interpret a stored owner record. No record, an empty record and the
    /// literal [`HOST_TASK_OWNER`] all mean [`TaskOwner::Host`] — so a lane
    /// whose IPC key happens to be `host` can never claim host tasks.
    pub fn from_record(record: Option<&'a str>) -> Self {
        match record {
            Some(owner) if !owner.trim().is_empty() && owner != HOST_TASK_OWNER => {
                TaskOwner::Lane(owner)
            }
            _ => TaskOwner::Host,
        }
    }

    /// The textual form stored in the database / written to the audit log.
    pub fn as_str(&self) -> &'a str {
        match self {
            TaskOwner::Host => HOST_TASK_OWNER,
            TaskOwner::Lane(key) => key,
        }
    }

    /// `true` for [`TaskOwner::Host`].
    pub fn is_host(&self) -> bool {
        matches!(self, TaskOwner::Host)
    }

    /// Whether the task was created by the namespace `ipc_key`.
    pub fn is_lane(&self, ipc_key: &str) -> bool {
        matches!(self, TaskOwner::Lane(k) if *k == ipc_key)
    }
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

/// Does `group` belong to the source namespace (same IPC key *and* folder)?
fn is_own_lane(who: IpcIdentity<'_>, group: &RegisteredGroup) -> bool {
    group.ipc_key() == who.ipc_key && group.folder == who.source_folder
}

/// Effective main status: the flag must be backed by a registered main
/// group owning both the folder and the namespace.
fn effective_main(who: IpcIdentity<'_>, groups: &HashMap<String, RegisteredGroup>) -> bool {
    who.is_main && groups.values().any(|g| g.is_main && is_own_lane(who, g))
}

/// Validate the identity itself: sane names, backed by a registered lane.
fn check_source(
    who: IpcIdentity<'_>,
    groups: &HashMap<String, RegisteredGroup>,
) -> Option<IpcDecision> {
    if !is_valid_group_folder(who.source_folder) || !is_valid_group_folder(who.ipc_key) {
        return Some(IpcDecision::deny("invalid source identity"));
    }
    if !groups.values().any(|g| is_own_lane(who, g)) {
        return Some(IpcDecision::deny(
            "source namespace is not owned by a registered lane",
        ));
    }
    None
}

fn sane_field(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty() && value.len() <= MAX_FIELD_LEN && !value.chars().any(char::is_control)
}

/// A script that would actually be stored (empty means "none").
fn sets_script(script: Option<&String>) -> bool {
    script.is_some_and(|s| !s.is_empty())
}

/// May `who` send a chat message to `target_jid`?
pub fn authorize_outbound_message(
    who: IpcIdentity<'_>,
    target_jid: &str,
    groups: &HashMap<String, RegisteredGroup>,
) -> IpcDecision {
    if let Some(d) = check_source(who, groups) {
        return d;
    }
    if target_jid.trim().is_empty() {
        return IpcDecision::deny("empty target jid");
    }
    let Some(target) = groups.get(target_jid) else {
        return IpcDecision::deny("target jid is not registered");
    };
    if effective_main(who, groups) || is_own_lane(who, target) {
        IpcDecision::Allow
    } else {
        IpcDecision::deny("non-main lane may only message its own lane")
    }
}

/// May `who` perform `task`?
///
/// `existing_task_owner`: recorded owner of the task referenced by
/// pause/resume/cancel/update (`None` if the task does not exist; a task
/// without an owner record is [`TaskOwner::Host`], see
/// [`TaskOwner::from_record`]).
///
/// For `schedule_task` with an explicit `taskId`, callers pass the owner of
/// an already existing task with that id (if any): a collision is denied so
/// a caller can never overwrite someone else's task.
pub fn authorize_task(
    who: IpcIdentity<'_>,
    task: &IpcTask,
    groups: &HashMap<String, RegisteredGroup>,
    existing_task_owner: Option<TaskOwner<'_>>,
) -> IpcDecision {
    if let Some(d) = check_source(who, groups) {
        return d;
    }
    let is_main = effective_main(who, groups);

    match task {
        IpcTask::ScheduleTask {
            task_id,
            prompt,
            script,
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
                if existing_task_owner.is_some() {
                    return IpcDecision::deny("schedule_task: taskId already exists");
                }
            }
            let Some(target) = groups.get(target_jid.as_str()) else {
                return IpcDecision::deny("schedule_task: target jid is not registered");
            };
            if is_main {
                return IpcDecision::Allow;
            }
            if !is_own_lane(who, target) {
                return IpcDecision::deny(
                    "schedule_task: non-main lane may only schedule for its own lane",
                );
            }
            if sets_script(script.as_ref()) {
                return IpcDecision::deny(
                    "schedule_task: only the main group may schedule scripts",
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
            let Some(owner) = existing_task_owner else {
                return IpcDecision::deny("task not found");
            };
            let script = match task {
                IpcTask::UpdateTask { script, .. } => script.as_ref(),
                _ => None,
            };
            if is_main {
                if owner.is_host() && script.is_some() {
                    return IpcDecision::deny(
                        "update_task: the script of a host-owned task can only be changed by the operator",
                    );
                }
                return IpcDecision::Allow;
            }
            if owner.is_host() {
                return IpcDecision::deny("host-owned tasks cannot be changed by a non-main lane");
            }
            if !owner.is_lane(who.ipc_key) {
                return IpcDecision::deny("non-main lane may only manage tasks it created");
            }
            if sets_script(script) {
                return IpcDecision::deny("update_task: only the main group may set a script");
            }
            IpcDecision::Allow
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
            trigger: "@Talon".into(),
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

    fn lane(folder: &str, ipc_key: &str) -> RegisteredGroup {
        RegisteredGroup {
            session_key: Some(ipc_key.into()),
            ipc_key: Some(ipc_key.into()),
            ..group("Copilot", folder, false)
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

    /// The CoPilot lanes: all share the folder `copilot`.
    fn copilot_groups() -> HashMap<String, RegisteredGroup> {
        let mut g = groups();
        g.insert(
            "http:copilot:u:alice".into(),
            lane("copilot", "copilot-u-alice"),
        );
        g.insert(
            "http:copilot:u:bob".into(),
            lane("copilot", "copilot-u-bob"),
        );
        g.insert(
            "http:copilot:investigate".into(),
            lane("copilot", "copilot-investigate"),
        );
        g.insert("http:copilot".into(), group("Copilot", "copilot", false));
        g.insert("webhook:copilot".into(), lane("copilot", "copilot-webhook"));
        g
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
    const THIRD: IpcIdentity<'static> = IpcIdentity {
        source_folder: "third-group",
        ipc_key: "third-group",
        is_main: false,
    };
    const ALICE: IpcIdentity<'static> = IpcIdentity {
        source_folder: "copilot",
        ipc_key: "copilot-u-alice",
        is_main: false,
    };
    const BOB: IpcIdentity<'static> = IpcIdentity {
        source_folder: "copilot",
        ipc_key: "copilot-u-bob",
        is_main: false,
    };
    const BASE: IpcIdentity<'static> = IpcIdentity {
        source_folder: "copilot",
        ipc_key: "copilot",
        is_main: false,
    };
    const INVESTIGATE: IpcIdentity<'static> = IpcIdentity {
        source_folder: "copilot",
        ipc_key: "copilot-investigate",
        is_main: false,
    };

    const DIGEST: &str = "copilot-alert-digest-15m";

    fn lane_owner(key: &str) -> Option<TaskOwner<'_>> {
        Some(TaskOwner::Lane(key))
    }

    const HOST: Option<TaskOwner<'static>> = Some(TaskOwner::Host);

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

    fn schedule_script(target: &str, script: &str) -> IpcTask {
        let mut t = schedule(target);
        if let IpcTask::ScheduleTask { script: s, .. } = &mut t {
            *s = Some(script.into());
        }
        t
    }

    fn register(jid: &str, folder: &str) -> IpcTask {
        IpcTask::RegisterGroup {
            jid: jid.into(),
            name: "New Group".into(),
            folder: folder.into(),
            trigger: "@Talon".into(),
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

    fn resume(id: &str) -> IpcTask {
        IpcTask::ResumeTask {
            task_id: id.into(),
            timestamp: None,
        }
    }

    fn cancel(id: &str) -> IpcTask {
        IpcTask::CancelTask {
            task_id: id.into(),
            timestamp: None,
        }
    }

    fn update(id: &str, prompt: Option<&str>, script: Option<&str>) -> IpcTask {
        IpcTask::UpdateTask {
            task_id: id.into(),
            prompt: prompt.map(str::to_string),
            script: script.map(str::to_string),
            schedule_type: None,
            schedule_value: None,
            timestamp: None,
        }
    }

    fn all_ops(id: &str) -> [IpcTask; 4] {
        [
            pause(id),
            resume(id),
            cancel(id),
            update(id, Some("p"), None),
        ]
    }

    // --- TaskOwner ---

    #[test]
    fn task_owner_records() {
        assert_eq!(TaskOwner::from_record(None), TaskOwner::Host);
        assert_eq!(TaskOwner::from_record(Some("host")), TaskOwner::Host);
        assert_eq!(TaskOwner::from_record(Some("")), TaskOwner::Host);
        assert_eq!(TaskOwner::from_record(Some("  ")), TaskOwner::Host);
        assert_eq!(
            TaskOwner::from_record(Some("copilot-u-alice")),
            TaskOwner::Lane("copilot-u-alice")
        );
        assert_eq!(TaskOwner::Host.as_str(), HOST_TASK_OWNER);
        assert_eq!(TaskOwner::Lane("k").as_str(), "k");
        assert!(TaskOwner::Lane("k").is_lane("k"));
        assert!(!TaskOwner::Lane("k").is_lane("j"));
        assert!(!TaskOwner::Host.is_lane("host"));
    }

    // --- schedule_task ---

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
        // collision with an existing task (of any owner)
        assert!(!authorize_task(OTHER, &t, &groups(), lane_owner("whatsapp_main")).is_allowed());
        assert!(!authorize_task(OTHER, &t, &groups(), HOST).is_allowed());
        assert!(!authorize_task(MAIN, &t, &groups(), lane_owner("other-group")).is_allowed());
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

    #[test]
    fn scripts_are_main_only() {
        let g = groups();
        let t = schedule_script("other@g.us", "echo pwned");
        let d = authorize_task(OTHER, &t, &g, None);
        assert_eq!(
            d.reason(),
            Some("schedule_task: only the main group may schedule scripts")
        );
        assert!(authorize_task(MAIN, &t, &g, None).is_allowed());
        // an empty script means "none" and is fine
        assert!(authorize_task(OTHER, &schedule_script("other@g.us", ""), &g, None).is_allowed());
    }

    // --- MYTH-03: lanes sharing a folder ---

    #[test]
    fn alice_cannot_message_bobs_lane() {
        let g = copilot_groups();
        assert!(authorize_outbound_message(ALICE, "http:copilot:u:alice", &g).is_allowed());
        for target in [
            "http:copilot:u:bob",
            "http:copilot:investigate",
            "http:copilot",
        ] {
            assert!(
                !authorize_outbound_message(ALICE, target, &g).is_allowed(),
                "{target}"
            );
        }
        assert!(!authorize_outbound_message(BOB, "http:copilot:u:alice", &g).is_allowed());
    }

    #[test]
    fn alice_cannot_message_the_webhook() {
        let g = copilot_groups();
        let d = authorize_outbound_message(ALICE, "webhook:copilot", &g);
        assert_eq!(
            d.reason(),
            Some("non-main lane may only message its own lane")
        );
        assert!(!authorize_outbound_message(INVESTIGATE, "webhook:copilot", &g).is_allowed());
        assert!(!authorize_outbound_message(BASE, "webhook:copilot", &g).is_allowed());
        // main still can
        assert!(authorize_outbound_message(MAIN, "webhook:copilot", &g).is_allowed());
    }

    #[test]
    fn lanes_sharing_an_ipc_key_but_not_the_folder_are_not_the_same_lane() {
        let mut g = copilot_groups();
        g.insert("odd@x".into(), lane("elsewhere", "copilot-u-alice"));
        assert!(!authorize_outbound_message(ALICE, "odd@x", &g).is_allowed());
    }

    #[test]
    fn alice_cannot_schedule_into_bobs_lane() {
        let g = copilot_groups();
        assert!(authorize_task(ALICE, &schedule("http:copilot:u:alice"), &g, None).is_allowed());
        for target in [
            "http:copilot:u:bob",
            "http:copilot:investigate",
            "webhook:copilot",
            "http:copilot",
        ] {
            assert!(
                !authorize_task(ALICE, &schedule(target), &g, None).is_allowed(),
                "{target}"
            );
        }
        // ...and never with a script, not even into her own lane
        assert!(
            !authorize_task(
                ALICE,
                &schedule_script("http:copilot:u:bob", "cat /workspace/sessions/*"),
                &g,
                None
            )
            .is_allowed()
        );
        assert!(
            !authorize_task(
                ALICE,
                &schedule_script("http:copilot:u:alice", "id"),
                &g,
                None
            )
            .is_allowed()
        );
    }

    #[test]
    fn digest_task_is_immutable_for_non_main_lanes() {
        let g = copilot_groups();
        for who in [ALICE, BOB, BASE, INVESTIGATE, OTHER] {
            for t in all_ops(DIGEST) {
                assert!(
                    !authorize_task(who, &t, &g, HOST).is_allowed(),
                    "{} {t:?}",
                    who.ipc_key
                );
            }
        }
        let d = authorize_task(ALICE, &resume(DIGEST), &g, HOST);
        assert_eq!(
            d.reason(),
            Some("host-owned tasks cannot be changed by a non-main lane")
        );
    }

    #[test]
    fn lane_cannot_touch_tasks_of_another_lane_in_the_same_folder() {
        let g = copilot_groups();
        for t in all_ops("task-bob") {
            assert!(
                !authorize_task(ALICE, &t, &g, lane_owner("copilot-u-bob")).is_allowed(),
                "{t:?}"
            );
            // the base lane shares the folder but not the namespace
            assert!(!authorize_task(BASE, &t, &g, lane_owner("copilot-u-bob")).is_allowed());
        }
    }

    #[test]
    fn own_lane_operations_are_still_allowed() {
        let g = copilot_groups();
        for t in all_ops("task-alice") {
            assert!(
                authorize_task(ALICE, &t, &g, lane_owner("copilot-u-alice")).is_allowed(),
                "{t:?}"
            );
        }
        // own task, but no script injection
        let set_script = update("task-alice", None, Some("curl evil"));
        assert_eq!(
            authorize_task(ALICE, &set_script, &g, lane_owner("copilot-u-alice")).reason(),
            Some("update_task: only the main group may set a script")
        );
        // clearing a script is harmless
        let clear = update("task-alice", None, Some(""));
        assert!(authorize_task(ALICE, &clear, &g, lane_owner("copilot-u-alice")).is_allowed());
    }

    #[test]
    fn a_lane_named_host_cannot_claim_host_tasks() {
        let mut g = groups();
        g.insert("h@x".into(), group("Host", "host", false));
        let who = IpcIdentity {
            source_folder: "host",
            ipc_key: "host",
            is_main: false,
        };
        let owner = Some(TaskOwner::from_record(Some("host")));
        assert!(!authorize_task(who, &pause(DIGEST), &g, owner).is_allowed());
        assert!(!authorize_task(who, &pause(DIGEST), &g, HOST).is_allowed());
    }

    // --- pause / resume / cancel / update ---

    #[test]
    fn main_can_manage_any_task() {
        let g = copilot_groups();
        for owner in [lane_owner("other-group"), lane_owner("copilot-u-bob"), HOST] {
            for t in all_ops("t") {
                assert!(authorize_task(MAIN, &t, &g, owner).is_allowed(), "{t:?}");
            }
        }
        // main may set scripts on lane-owned tasks...
        let set_script = update("t", None, Some("echo hi"));
        assert!(authorize_task(MAIN, &set_script, &g, lane_owner("copilot-u-bob")).is_allowed());
        // ...but never change the script of a host-owned task
        for script in ["echo hi", ""] {
            let t = update(DIGEST, None, Some(script));
            assert_eq!(
                authorize_task(MAIN, &t, &g, HOST).reason(),
                Some(
                    "update_task: the script of a host-owned task can only be changed by the operator"
                ),
                "{script:?}"
            );
        }
    }

    #[test]
    fn non_main_can_manage_own_task_only() {
        assert!(
            authorize_task(OTHER, &pause("t"), &groups(), lane_owner("other-group")).is_allowed()
        );
        assert!(
            !authorize_task(OTHER, &pause("t"), &groups(), lane_owner("whatsapp_main"))
                .is_allowed()
        );
        assert!(
            !authorize_task(THIRD, &resume("t"), &groups(), lane_owner("other-group")).is_allowed()
        );
        assert!(
            authorize_task(OTHER, &cancel("t"), &groups(), lane_owner("other-group")).is_allowed()
        );
        assert!(
            !authorize_task(OTHER, &cancel("t"), &groups(), lane_owner("whatsapp_main"))
                .is_allowed()
        );
        // pre-existing rows without an owner record are host-owned
        assert!(!authorize_task(OTHER, &cancel("t"), &groups(), HOST).is_allowed());
    }

    #[test]
    fn missing_task_is_denied() {
        let d = authorize_task(MAIN, &pause("nope"), &groups(), None);
        assert_eq!(d.reason(), Some("task not found"));
        assert!(!authorize_task(MAIN, &pause(" "), &groups(), HOST).is_allowed());
    }

    // --- refresh_groups / register_group ---

    #[test]
    fn refresh_groups_main_only() {
        let t = IpcTask::RefreshGroups { timestamp: None };
        assert!(authorize_task(MAIN, &t, &groups(), None).is_allowed());
        assert!(!authorize_task(OTHER, &t, &groups(), None).is_allowed());
        assert!(!authorize_task(ALICE, &t, &copilot_groups(), None).is_allowed());
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
        assert!(!authorize_outbound_message(MAIN, "unknown@g.us", &groups()).is_allowed());
        assert!(!authorize_outbound_message(MAIN, "", &groups()).is_allowed());
    }

    #[test]
    fn forged_main_flag_is_not_trusted() {
        let forged = IpcIdentity {
            source_folder: "other-group",
            ipc_key: "other-group",
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
    fn main_flag_requires_the_main_namespace() {
        // main's folder, but a different namespace (e.g. a lane registered
        // into the main folder under another key) is not main
        let mut g = groups();
        let mut side = group("Side", "whatsapp_main", false);
        side.ipc_key = Some("side-key".into());
        g.insert("side@x".into(), side);
        let who = IpcIdentity {
            source_folder: "whatsapp_main",
            ipc_key: "side-key",
            is_main: true,
        };
        assert!(!authorize_outbound_message(who, "other@g.us", &g).is_allowed());
        assert!(!authorize_task(who, &pause("t"), &g, lane_owner("whatsapp_main")).is_allowed());
    }

    #[test]
    fn invalid_or_unregistered_source_is_denied() {
        let bad = IpcIdentity {
            source_folder: "../whatsapp_main",
            ipc_key: "../whatsapp_main",
            is_main: false,
        };
        assert!(!authorize_outbound_message(bad, "other@g.us", &groups()).is_allowed());
        assert!(
            !authorize_task(bad, &pause("t"), &groups(), lane_owner("../whatsapp_main"))
                .is_allowed()
        );
        let empty = IpcIdentity {
            source_folder: "",
            ipc_key: "",
            is_main: false,
        };
        assert!(!authorize_task(empty, &pause("t"), &groups(), lane_owner("")).is_allowed());
        let bad_key = IpcIdentity {
            source_folder: "other-group",
            ipc_key: "../x",
            is_main: false,
        };
        assert!(!authorize_outbound_message(bad_key, "other@g.us", &groups()).is_allowed());
        // a valid name that no registered lane owns
        let stranger = IpcIdentity {
            source_folder: "other-group",
            ipc_key: "stranger",
            is_main: false,
        };
        let d = authorize_task(stranger, &pause("t"), &groups(), lane_owner("stranger"));
        assert_eq!(
            d.reason(),
            Some("source namespace is not owned by a registered lane")
        );
    }
}
