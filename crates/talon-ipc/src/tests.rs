//! Behavioural tests: a port of `src/ipc-auth.test.ts` (driven through
//! `process_task` / `process_message`, like the TS suite drives
//! `processTaskIpc`) plus end-to-end scans over a temporary IPC tree.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use talon_core::protocol::{IpcOutbound, IpcTask};
use talon_core::time::parse_iso;
use talon_core::types::{AdditionalMount, ContainerConfig, ContextMode, ScheduleType, TaskStatus};
use tokio_util::sync::CancellationToken;

use crate::process::IpcOutcome;
use crate::testutil::*;

fn sched(target: &str, ty: ScheduleType, value: &str) -> IpcTask {
    IpcTask::ScheduleTask {
        task_id: None,
        prompt: "do something".into(),
        script: None,
        schedule_type: ty,
        schedule_value: value.into(),
        context_mode: None,
        target_jid: target.into(),
        created_by: None,
        timestamp: None,
    }
}

fn once(target: &str) -> IpcTask {
    sched(target, ScheduleType::Once, "2025-06-01T00:00:00")
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

fn message(jid: &str, text: &str) -> IpcOutbound {
    IpcOutbound::Message {
        chat_jid: jid.into(),
        text: text.into(),
        group_folder: None,
        timestamp: None,
    }
}

// ---------------------------------------------------------------------------
// schedule_task authorization (ipc-auth.test.ts)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn main_group_can_schedule_for_another_group() {
    let h = harness();
    let o = h.watcher.process_task(&main_id(), once("other@g.us")).await;
    assert_eq!(o, IpcOutcome::Applied);
    let all = h.store.all();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].group_folder, "other-group");
    assert_eq!(all[0].chat_jid, "other@g.us");
    assert_eq!(all[0].status, TaskStatus::Active);
    assert_eq!(h.host.tasks_changed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn non_main_group_can_schedule_for_itself() {
    let h = harness();
    let o = h
        .watcher
        .process_task(&other_id(), once("other@g.us"))
        .await;
    assert!(o.is_applied());
    let all = h.store.all();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].group_folder, "other-group");
}

#[tokio::test]
async fn non_main_group_cannot_schedule_for_another_group() {
    let h = harness();
    let o = h.watcher.process_task(&other_id(), once("main@g.us")).await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    assert!(h.store.all().is_empty());
    assert_eq!(h.host.tasks_changed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejects_schedule_task_for_unregistered_target_jid() {
    let h = harness();
    let o = h
        .watcher
        .process_task(&main_id(), once("unknown@g.us"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    assert!(h.store.all().is_empty());
}

// ---------------------------------------------------------------------------
// pause / resume / cancel authorization
// ---------------------------------------------------------------------------

fn seed_pause_fixture(h: &Harness) {
    h.store.insert_owned(
        task(
            "task-main",
            "whatsapp_main",
            "main@g.us",
            TaskStatus::Active,
        ),
        "whatsapp_main",
    );
    h.store.insert_owned(
        task(
            "task-other",
            "other-group",
            "other@g.us",
            TaskStatus::Active,
        ),
        "other-group",
    );
}

#[tokio::test]
async fn main_group_can_pause_any_task() {
    let h = harness();
    seed_pause_fixture(&h);
    assert!(
        h.watcher
            .process_task(&main_id(), pause("task-other"))
            .await
            .is_applied()
    );
    assert_eq!(
        h.store.get("task-other").unwrap().status,
        TaskStatus::Paused
    );
}

#[tokio::test]
async fn non_main_group_can_pause_its_own_task() {
    let h = harness();
    seed_pause_fixture(&h);
    assert!(
        h.watcher
            .process_task(&other_id(), pause("task-other"))
            .await
            .is_applied()
    );
    assert_eq!(
        h.store.get("task-other").unwrap().status,
        TaskStatus::Paused
    );
}

#[tokio::test]
async fn non_main_group_cannot_pause_another_groups_task() {
    let h = harness();
    seed_pause_fixture(&h);
    let o = h
        .watcher
        .process_task(&other_id(), pause("task-main"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    assert_eq!(h.store.get("task-main").unwrap().status, TaskStatus::Active);
}

#[tokio::test]
async fn pausing_a_missing_task_is_denied() {
    let h = harness();
    let o = h.watcher.process_task(&main_id(), pause("nope")).await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
}

#[tokio::test]
async fn resume_rules() {
    let h = harness();
    h.store.insert_owned(
        task(
            "task-paused",
            "other-group",
            "other@g.us",
            TaskStatus::Paused,
        ),
        "other-group",
    );
    // third group cannot
    let o = h
        .watcher
        .process_task(&third_id(), resume("task-paused"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    assert_eq!(
        h.store.get("task-paused").unwrap().status,
        TaskStatus::Paused
    );
    // own group can
    assert!(
        h.watcher
            .process_task(&other_id(), resume("task-paused"))
            .await
            .is_applied()
    );
    assert_eq!(
        h.store.get("task-paused").unwrap().status,
        TaskStatus::Active
    );
    // main can
    h.store.insert_owned(
        task(
            "task-paused",
            "other-group",
            "other@g.us",
            TaskStatus::Paused,
        ),
        "other-group",
    );
    assert!(
        h.watcher
            .process_task(&main_id(), resume("task-paused"))
            .await
            .is_applied()
    );
    assert_eq!(
        h.store.get("task-paused").unwrap().status,
        TaskStatus::Active
    );
}

#[tokio::test]
async fn cancel_rules() {
    let h = harness();
    h.store.insert_owned(
        task(
            "task-to-cancel",
            "other-group",
            "other@g.us",
            TaskStatus::Active,
        ),
        "other-group",
    );
    assert!(
        h.watcher
            .process_task(&main_id(), cancel("task-to-cancel"))
            .await
            .is_applied()
    );
    assert!(h.store.get("task-to-cancel").is_none());

    h.store.insert_owned(
        task("task-own", "other-group", "other@g.us", TaskStatus::Active),
        "other-group",
    );
    assert!(
        h.watcher
            .process_task(&other_id(), cancel("task-own"))
            .await
            .is_applied()
    );
    assert!(h.store.get("task-own").is_none());

    h.store.insert_owned(
        task(
            "task-foreign",
            "whatsapp_main",
            "main@g.us",
            TaskStatus::Active,
        ),
        "whatsapp_main",
    );
    let o = h
        .watcher
        .process_task(&other_id(), cancel("task-foreign"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    assert!(h.store.get("task-foreign").is_some());
}

// ---------------------------------------------------------------------------
// register_group / refresh_groups
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_main_group_cannot_register_a_group() {
    let h = harness();
    let o = h
        .watcher
        .process_task(&other_id(), register("new@g.us", "new-group"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    assert!(!h.host.registered_groups_snapshot().contains_key("new@g.us"));
}

#[tokio::test]
async fn main_group_cannot_register_with_unsafe_folder_path() {
    let h = harness();
    for folder in ["../../outside", "errors", "global", "a/b", ""] {
        let o = h
            .watcher
            .process_task(&main_id(), register("new@g.us", folder))
            .await;
        assert!(!o.is_applied(), "{folder}");
    }
    assert!(h.host.registered.lock().unwrap().is_empty());
}

#[tokio::test]
async fn main_group_can_register_a_new_group() {
    let h = harness();
    let o = h
        .watcher
        .process_task(&main_id(), register("new@g.us", "new-group"))
        .await;
    assert_eq!(o, IpcOutcome::Applied);
    let g = h
        .host
        .registered_groups_snapshot()
        .remove("new@g.us")
        .unwrap();
    assert_eq!(g.name, "New Group");
    assert_eq!(g.folder, "new-group");
    assert_eq!(g.trigger, "@Andy");
    assert!(!g.is_main);
    let ev = h.audit.snapshot();
    assert!(
        ev.iter()
            .any(|e| e.kind == "ipc.register_group" && e.outcome == "allowed")
    );
}

#[tokio::test]
async fn register_group_never_touches_the_main_group() {
    let h = harness();
    // re-registering the main JID is refused (no demotion, no folder swap)
    let o = h
        .watcher
        .process_task(&main_id(), register("main@g.us", "whatsapp_main"))
        .await;
    assert!(matches!(o, IpcOutcome::Rejected(_)));
    // binding another JID to the main folder is refused
    let o = h
        .watcher
        .process_task(&main_id(), register("x@g.us", "whatsapp_main"))
        .await;
    assert!(matches!(o, IpcOutcome::Rejected(_)));
    assert!(h.host.registered.lock().unwrap().is_empty());
    assert!(h.host.registered_groups_snapshot()["main@g.us"].is_main);
}

#[tokio::test]
async fn register_group_preserves_lane_fields_and_strips_container_config() {
    let h = harness();
    let operator_cfg = ContainerConfig {
        network: Some("talon-net".into()),
        ..ContainerConfig::default()
    };
    {
        let mut groups = h.host.groups.lock().unwrap();
        let other = groups.get_mut("other@g.us").unwrap();
        other.container_config = Some(operator_cfg.clone());
        other.trusted_session_commands = true;
    }
    let req = |cfg: ContainerConfig| IpcTask::RegisterGroup {
        jid: "other@g.us".into(),
        name: "Other renamed".into(),
        folder: "other-group".into(),
        trigger: "@Andy".into(),
        requires_trigger: Some(true),
        container_config: Some(cfg),
        timestamp: None,
    };
    let mount = AdditionalMount {
        host_path: "/srv/talon".into(),
        container_path: Some("project".into()),
        readonly: false,
    };
    for cfg in [
        ContainerConfig {
            network: Some("host".into()),
            ..ContainerConfig::default()
        },
        ContainerConfig {
            additional_mounts: vec![mount.clone()],
            timeout: Some(120_000),
            ..ContainerConfig::default()
        },
        ContainerConfig {
            env: [("HTTP_PROXY".to_string(), "x".to_string())].into(),
            ..ContainerConfig::default()
        },
    ] {
        let o = h.watcher.process_task(&main_id(), req(cfg)).await;
        assert_eq!(o, IpcOutcome::Applied);
        let g = h
            .host
            .registered_groups_snapshot()
            .remove("other@g.us")
            .unwrap();
        assert_eq!(g.name, "Other renamed");
        assert_eq!(g.added_at, "2024-01-01T00:00:00.000Z");
        assert!(g.trusted_session_commands);
        assert_eq!(g.requires_trigger, Some(true));
        // the operator's configuration is kept verbatim
        assert_eq!(g.container_config.as_ref(), Some(&operator_cfg));
    }
    let ev = h.audit.snapshot();
    let regs: Vec<_> = ev
        .iter()
        .filter(|e| e.kind == "ipc.register_group")
        .collect();
    assert_eq!(regs.len(), 3);
    assert!(
        regs.iter()
            .all(|e| e.outcome == "allowed" && e.details["containerConfigIgnored"] == true)
    );
}

#[tokio::test]
async fn register_group_never_applies_container_config_to_new_groups() {
    let h = harness();
    let o = h
        .watcher
        .process_task(
            &main_id(),
            IpcTask::RegisterGroup {
                jid: "new@g.us".into(),
                name: "New".into(),
                folder: "new-group".into(),
                trigger: "@Andy".into(),
                requires_trigger: None,
                container_config: Some(ContainerConfig {
                    additional_mounts: vec![AdditionalMount {
                        host_path: "/".into(),
                        container_path: Some("root".into()),
                        readonly: false,
                    }],
                    ..ContainerConfig::default()
                }),
                timestamp: None,
            },
        )
        .await;
    assert_eq!(o, IpcOutcome::Applied);
    let g = h
        .host
        .registered_groups_snapshot()
        .remove("new@g.us")
        .unwrap();
    assert_eq!(g.container_config, None);
    // without a containerConfig there is no note
    h.watcher
        .process_task(&main_id(), register("new2@g.us", "new-group-2"))
        .await;
    let ev = h.audit.snapshot();
    let last = ev.last().unwrap();
    assert!(last.details.get("containerConfigIgnored").is_none());
}

#[tokio::test]
async fn register_group_cannot_hijack_another_lanes_namespace() {
    let h = harness();
    h.host
        .groups
        .lock()
        .unwrap()
        .insert("lane@x".into(), group("copilot", Some("new-group"), false));
    let o = h
        .watcher
        .process_task(&main_id(), register("new@g.us", "new-group"))
        .await;
    assert!(matches!(o, IpcOutcome::Rejected(_)));
}

#[tokio::test]
async fn non_main_group_cannot_trigger_refresh() {
    let h = harness();
    let o = h
        .watcher
        .process_task(&other_id(), IpcTask::RefreshGroups { timestamp: None })
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    assert_eq!(h.host.syncs.load(Ordering::SeqCst), 0);
    assert!(h.host.snapshots.lock().unwrap().is_empty());
}

#[tokio::test]
async fn main_refresh_syncs_and_writes_snapshot_for_its_namespace() {
    let h = harness();
    let o = h
        .watcher
        .process_task(&main_id(), IpcTask::RefreshGroups { timestamp: None })
        .await;
    assert_eq!(o, IpcOutcome::Applied);
    assert_eq!(h.host.syncs.load(Ordering::SeqCst), 1);
    let snaps = h.host.snapshots.lock().unwrap().clone();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].0, main_id());
    assert_eq!(snaps[0].2, 3);
}

// ---------------------------------------------------------------------------
// IPC message authorization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn message_authorization_end_to_end() {
    let h = harness();
    assert!(
        h.watcher
            .process_message(&main_id(), message("third@g.us", "a"))
            .await
            .is_applied()
    );
    assert!(
        h.watcher
            .process_message(&main_id(), message("unknown@g.us", "b"))
            .await
            .is_applied()
    );
    assert!(
        h.watcher
            .process_message(&other_id(), message("other@g.us", "c"))
            .await
            .is_applied()
    );
    for jid in ["main@g.us", "third@g.us", "unknown@g.us"] {
        let o = h
            .watcher
            .process_message(&other_id(), message(jid, "x"))
            .await;
        assert!(matches!(o, IpcOutcome::Denied(_)), "{jid}");
    }
    let sent = h.host.sent();
    assert_eq!(
        sent.iter().map(|(j, _)| j.as_str()).collect::<Vec<_>>(),
        ["third@g.us", "unknown@g.us", "other@g.us"]
    );
    let ev = h.audit.snapshot();
    assert_eq!(
        ev.iter().filter(|e| e.kind == "ipc.message.denied").count(),
        3
    );
    assert_eq!(
        ev.iter()
            .filter(|e| e.kind == "ipc.message.allowed")
            .count(),
        3
    );
    // message text never reaches the audit log
    assert!(ev.iter().all(|e| !e.details.to_string().contains("\"x\"")));
}

#[tokio::test]
async fn failed_delivery_is_reported() {
    let h = harness();
    h.host.fail_send.store(true, Ordering::SeqCst);
    let o = h
        .watcher
        .process_message(&main_id(), message("other@g.us", "x"))
        .await;
    assert!(matches!(o, IpcOutcome::Failed(_)));
    assert!(
        h.audit
            .snapshot()
            .iter()
            .any(|e| e.kind == "ipc.message.failed" && e.outcome == "error")
    );
}

#[tokio::test]
async fn slow_host_calls_time_out() {
    let h = harness_with(|c| c.host_call_timeout = Duration::from_millis(50));
    *h.host.send_delay.lock().unwrap() = Some(Duration::from_secs(5));
    let o = h
        .watcher
        .process_message(&main_id(), message("other@g.us", "x"))
        .await;
    assert!(
        matches!(o, IpcOutcome::Failed(ref e) if e.contains("timed out")),
        "{o:?}"
    );
}

// ---------------------------------------------------------------------------
// schedule types / context_mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn creates_task_with_cron_schedule_and_computes_next_run() {
    let h = harness();
    let o = h
        .watcher
        .process_task(
            &main_id(),
            sched("other@g.us", ScheduleType::Cron, "0 9 * * *"),
        )
        .await;
    assert!(o.is_applied());
    let t = &h.store.all()[0];
    assert_eq!(t.schedule_type, ScheduleType::Cron);
    let next = parse_iso(t.next_run.as_deref().unwrap()).unwrap();
    assert!(next > chrono::Utc::now() - chrono::Duration::seconds(60));
}

#[tokio::test]
async fn cron_is_evaluated_in_the_configured_timezone() {
    let h = harness_with(|c| c.timezone = chrono_tz::Europe::Berlin);
    let o = h
        .watcher
        .process_task(
            &main_id(),
            sched("other@g.us", ScheduleType::Cron, "0 9 * * *"),
        )
        .await;
    assert!(o.is_applied());
    let next = parse_iso(h.store.all()[0].next_run.as_deref().unwrap()).unwrap();
    let local = next.with_timezone(&chrono_tz::Europe::Berlin);
    assert_eq!(chrono::Timelike::hour(&local), 9);
}

#[tokio::test]
async fn creates_task_with_interval_schedule() {
    let h = harness();
    let before = chrono::Utc::now();
    let o = h
        .watcher
        .process_task(
            &main_id(),
            sched("other@g.us", ScheduleType::Interval, "3600000"),
        )
        .await;
    assert!(o.is_applied());
    let next = parse_iso(h.store.all()[0].next_run.as_deref().unwrap()).unwrap();
    assert!(next >= before + chrono::Duration::milliseconds(3_600_000 - 1_000));
    assert!(next <= chrono::Utc::now() + chrono::Duration::milliseconds(3_600_000 + 1_000));
}

#[tokio::test]
async fn invalid_schedules_are_rejected() {
    let h = harness();
    for (ty, v) in [
        (ScheduleType::Cron, "not a cron"),
        (ScheduleType::Interval, "abc"),
        (ScheduleType::Interval, "0"),
        (ScheduleType::Interval, "5"),
        (ScheduleType::Once, "not-a-date"),
        (ScheduleType::Once, "2026-02-01T15:30:00Z"),
    ] {
        let o = h
            .watcher
            .process_task(&main_id(), sched("other@g.us", ty, v))
            .await;
        assert!(matches!(o, IpcOutcome::Rejected(_)), "{ty:?} {v}");
    }
    assert!(h.store.all().is_empty());
    let ev = h.audit.snapshot();
    assert!(
        ev.iter()
            .all(|e| e.kind == "ipc.task.denied" && e.details["stage"] == "validation")
    );
}

#[tokio::test]
async fn context_mode_handling() {
    let h = harness();
    for (mode, expect) in [
        (Some(ContextMode::Group), ContextMode::Group),
        (Some(ContextMode::Isolated), ContextMode::Isolated),
        (None, ContextMode::Isolated),
    ] {
        let mut t = once("other@g.us");
        if let IpcTask::ScheduleTask { context_mode, .. } = &mut t {
            *context_mode = mode;
        }
        assert!(h.watcher.process_task(&main_id(), t).await.is_applied());
        let created = h.store.all();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].context_mode, expect);
        h.store.tasks.lock().unwrap().clear();
    }
}

#[tokio::test]
async fn duplicate_task_ids_are_rejected() {
    let h = harness();
    h.store.insert(task(
        "task-main",
        "whatsapp_main",
        "main@g.us",
        TaskStatus::Active,
    ));
    let mut t = once("other@g.us");
    if let IpcTask::ScheduleTask {
        task_id, prompt, ..
    } = &mut t
    {
        *task_id = Some("task-main".into());
        *prompt = "overwrite attempt".into();
    }
    let o = h.watcher.process_task(&other_id(), t).await;
    assert!(
        matches!(o, IpcOutcome::Rejected(ref r) if r.contains("duplicate")),
        "{o:?}"
    );
    let existing = h.store.get("task-main").unwrap();
    assert_eq!(existing.group_folder, "whatsapp_main");
    assert_eq!(existing.prompt, "p");
}

#[tokio::test]
async fn container_chosen_task_id_is_kept() {
    let h = harness();
    let mut t = once("other@g.us");
    if let IpcTask::ScheduleTask { task_id, .. } = &mut t {
        *task_id = Some("task-1700000000000-abc123".into());
    }
    assert!(h.watcher.process_task(&other_id(), t).await.is_applied());
    assert!(h.store.get("task-1700000000000-abc123").is_some());
}

#[tokio::test]
async fn db_failure_is_reported_not_panicked() {
    let h = harness();
    h.store.fail.store(true, Ordering::SeqCst);
    let o = h.watcher.process_task(&main_id(), pause("x")).await;
    assert!(matches!(o, IpcOutcome::Failed(_)));
    let o = h.watcher.process_task(&main_id(), once("other@g.us")).await;
    assert!(matches!(o, IpcOutcome::Failed(_)));
    assert!(
        h.audit
            .snapshot()
            .iter()
            .any(|e| e.kind == "ipc.task.failed")
    );
}

// ---------------------------------------------------------------------------
// update_task
// ---------------------------------------------------------------------------

fn update(id: &str) -> IpcTask {
    IpcTask::UpdateTask {
        task_id: id.into(),
        prompt: None,
        script: None,
        schedule_type: None,
        schedule_value: None,
        timestamp: None,
    }
}

#[tokio::test]
async fn update_task_rules() {
    let h = harness();
    let mut t = task("t-other", "other-group", "other@g.us", TaskStatus::Active);
    t.script = Some("echo hi".into());
    h.store.insert_owned(t, "other-group");
    h.store.insert_owned(
        task("t-main", "whatsapp_main", "main@g.us", TaskStatus::Active),
        "whatsapp_main",
    );

    // non-main cannot touch main's task
    let mut u = update("t-main");
    if let IpcTask::UpdateTask { prompt, .. } = &mut u {
        *prompt = Some("pwned".into());
    }
    assert!(matches!(
        h.watcher.process_task(&other_id(), u).await,
        IpcOutcome::Denied(_)
    ));
    assert_eq!(h.store.get("t-main").unwrap().prompt, "p");

    // own task: a schedule below the lane's minimum frequency is a quota
    // violation (N-3) and changes nothing
    let mut u = update("t-other");
    if let IpcTask::UpdateTask {
        schedule_type,
        schedule_value,
        script,
        ..
    } = &mut u
    {
        *schedule_type = Some(ScheduleType::Interval);
        *schedule_value = Some("60000".into());
        *script = Some(String::new());
    }
    let o = h.watcher.process_task(&other_id(), u).await;
    assert!(
        matches!(o, IpcOutcome::Denied(ref r) if r.contains("minimum")),
        "{o:?}"
    );
    assert_eq!(
        h.store.get("t-other").unwrap().schedule_type,
        ScheduleType::Once
    );
    assert!(h.store.get("t-other").unwrap().script.is_some());

    // own task: schedule change recomputes next_run, empty script clears
    let mut u = update("t-other");
    if let IpcTask::UpdateTask {
        schedule_type,
        schedule_value,
        script,
        ..
    } = &mut u
    {
        *schedule_type = Some(ScheduleType::Interval);
        *schedule_value = Some("600000".into());
        *script = Some(String::new());
    }
    assert!(h.watcher.process_task(&other_id(), u).await.is_applied());
    let t = h.store.get("t-other").unwrap();
    assert_eq!(t.schedule_type, ScheduleType::Interval);
    assert!(t.script.is_none());
    let next = parse_iso(t.next_run.as_deref().unwrap()).unwrap();
    assert!(next > chrono::Utc::now());

    // invalid schedule leaves the task untouched
    let mut u = update("t-other");
    if let IpcTask::UpdateTask {
        schedule_type,
        schedule_value,
        ..
    } = &mut u
    {
        *schedule_type = Some(ScheduleType::Cron);
        *schedule_value = Some("bogus".into());
    }
    assert!(matches!(
        h.watcher.process_task(&other_id(), u).await,
        IpcOutcome::Rejected(_)
    ));
    assert_eq!(
        h.store.get("t-other").unwrap().schedule_type,
        ScheduleType::Interval
    );

    // missing task
    assert!(matches!(
        h.watcher.process_task(&main_id(), update("ghost")).await,
        IpcOutcome::Denied(_)
    ));
}

// ---------------------------------------------------------------------------
// End-to-end scans over a real directory tree
// ---------------------------------------------------------------------------

fn ns_dir(h: &Harness, key: &str, kind: &str) -> std::path::PathBuf {
    let d = h.dir.path().join("ipc").join(key).join(kind);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &std::path::Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

fn count(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).map(|r| r.count()).unwrap_or(0)
}

fn errors_dir(h: &Harness) -> std::path::PathBuf {
    h.dir.path().join("ipc").join("errors")
}

fn error_records(h: &Harness) -> Vec<serde_json::Value> {
    let mut v: Vec<_> = std::fs::read_dir(errors_dir(h))
        .map(|r| {
            r.map(|e| {
                serde_json::from_slice::<serde_json::Value>(
                    &std::fs::read(e.unwrap().path()).unwrap(),
                )
                .unwrap()
            })
            .collect()
        })
        .unwrap_or_default();
    v.sort_by_key(|r| r["file"].as_str().unwrap_or_default().to_string());
    v
}

#[tokio::test]
async fn scan_processes_messages_and_tasks_in_name_order() {
    let h = harness();
    let m = ns_dir(&h, "other-group", "messages");
    write(
        &m,
        "1700000000002-bbbbbb.json",
        r#"{"type":"message","chatJid":"other@g.us","text":"second"}"#,
    );
    write(
        &m,
        "1700000000001-aaaaaa.json",
        r#"{"type":"message","chatJid":"other@g.us","text":"first"}"#,
    );
    write(
        &m,
        "1700000000003-cccccc.json",
        r#"{"type":"message","chatJid":"main@g.us","text":"sneaky"}"#,
    );
    write(
        &m,
        "1700000000004-dddddd.json.tmp",
        r#"{"type":"message","chatJid":"other@g.us","text":"partial"}"#,
    );
    let t = ns_dir(&h, "other-group", "tasks");
    write(
        &t,
        "1700000000001-aaaaaa.json",
        r#"{"type":"schedule_task","taskId":"task-1","prompt":"p","schedule_type":"interval","schedule_value":"600000","context_mode":"group","targetJid":"other@g.us","createdBy":"whatsapp_main"}"#,
    );

    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.messages_sent, 2);
    assert_eq!(stats.tasks_applied, 1);
    assert_eq!(stats.denied, 1);
    assert_eq!(stats.files, 4);
    let texts: Vec<_> = h.host.sent().into_iter().map(|(_, t)| t).collect();
    assert_eq!(texts, ["first", "second"]);
    // processed files are gone, the in-progress tmp file is untouched
    let left: Vec<_> = std::fs::read_dir(&m)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left, ["1700000000004-dddddd.json.tmp"]);
    assert_eq!(count(&t), 0);
    let created = h.store.get("task-1").unwrap();
    assert_eq!(created.group_folder, "other-group");
    assert_eq!(created.context_mode, ContextMode::Group);
    // denial left an audit trail but no quarantine record
    assert!(
        h.audit
            .snapshot()
            .iter()
            .any(|e| e.kind == "ipc.message.denied" && e.actor == "other-group")
    );
    assert!(error_records(&h).is_empty());
}

#[tokio::test]
async fn identity_comes_from_the_directory_not_the_payload() {
    let h = harness();
    let t = ns_dir(&h, "other-group", "tasks");
    // claims to be main in every way the payload can
    write(
        &t,
        "1.json",
        r#"{"type":"refresh_groups","groupFolder":"whatsapp_main","isMain":true}"#,
    );
    write(
        &t,
        "2.json",
        r#"{"type":"register_group","jid":"evil@g.us","name":"Evil","folder":"evil","trigger":"@x","isMain":true,"groupFolder":"whatsapp_main"}"#,
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.denied, 2);
    assert_eq!(h.host.syncs.load(Ordering::SeqCst), 0);
    assert!(h.host.registered.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_namespaces_are_ignored() {
    let h = harness();
    let m = ns_dir(&h, "stranger", "messages");
    write(
        &m,
        "1.json",
        r#"{"type":"message","chatJid":"main@g.us","text":"hi"}"#,
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.files, 0);
    assert_eq!(count(&m), 1);
    assert!(h.host.sent().is_empty());
}

#[tokio::test]
async fn lanes_with_custom_ipc_keys_are_their_own_principal() {
    let h = harness();
    h.host.groups.lock().unwrap().insert(
        "http:copilot:u:7".into(),
        group("copilot", Some("copilot-u-7"), false),
    );
    h.host
        .groups
        .lock()
        .unwrap()
        .insert("http:copilot".into(), group("copilot", None, false));
    let m = ns_dir(&h, "copilot-u-7", "messages");
    write(
        &m,
        "1.json",
        r#"{"type":"message","chatJid":"http:copilot:u:7","text":"own lane"}"#,
    );
    write(
        &m,
        "2.json",
        r#"{"type":"message","chatJid":"http:copilot","text":"same folder, other lane"}"#,
    );
    write(
        &m,
        "3.json",
        r#"{"type":"message","chatJid":"other@g.us","text":"other folder"}"#,
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.messages_sent, 1);
    assert_eq!(stats.denied, 2);
    assert_eq!(h.host.sent()[0].0, "http:copilot:u:7");
    let denied: Vec<_> = h
        .audit
        .snapshot()
        .into_iter()
        .filter(|e| e.kind == "ipc.message.denied")
        .collect();
    assert!(
        denied
            .iter()
            .all(|e| e.actor == "copilot" && e.details["ipcKey"] == "copilot-u-7")
    );
}

#[tokio::test]
async fn conflicting_namespace_is_not_processed() {
    let h = harness();
    // a non-main lane registered with the main group's IPC key
    h.host.groups.lock().unwrap().insert(
        "evil@x".into(),
        group("other-group", Some("whatsapp_main"), false),
    );
    let m = ns_dir(&h, "whatsapp_main", "messages");
    write(
        &m,
        "1.json",
        r#"{"type":"message","chatJid":"third@g.us","text":"hi"}"#,
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.files, 0);
    assert_eq!(count(&m), 1);
}

#[tokio::test]
async fn malformed_files_are_quarantined_with_bounded_records() {
    let h = harness_with(|c| {
        c.max_file_bytes = 1024;
        c.max_error_content_bytes = 64;
    });
    let m = ns_dir(&h, "other-group", "messages");
    let t = ns_dir(&h, "other-group", "tasks");
    write(&m, "a-badjson.json", "{not json");
    write(
        &m,
        "b-big.json",
        &format!(
            r#"{{"type":"message","chatJid":"other@g.us","text":"{}"}}"#,
            "x".repeat(4096)
        ),
    );
    write(
        &m,
        "c-deep.json",
        &format!(
            r#"{{"type":"message","chatJid":"other@g.us","text":"t","x":{}{}}}"#,
            "[".repeat(64),
            "]".repeat(64)
        ),
    );
    write(&t, "d-unknown.json", r#"{"type":"format_disk"}"#);
    write(
        &t,
        "e-missing.json",
        r#"{"type":"register_group","jid":"partial@g.us","name":"Partial"}"#,
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.quarantined, 5);
    assert_eq!(count(&m) + count(&t), 0);
    let recs = error_records(&h);
    assert_eq!(recs.len(), 5);
    let by_file = |f: &str| recs.iter().find(|r| r["file"] == f).unwrap().clone();
    assert!(
        by_file("a-badjson.json")["reason"]
            .as_str()
            .unwrap()
            .contains("invalid JSON")
    );
    assert_eq!(by_file("a-badjson.json")["content"], "{not json");
    assert!(
        by_file("b-big.json")["reason"]
            .as_str()
            .unwrap()
            .contains("too large")
    );
    assert!(by_file("b-big.json")["content"].is_null());
    assert!(
        by_file("c-deep.json")["reason"]
            .as_str()
            .unwrap()
            .contains("depth")
    );
    assert_eq!(by_file("c-deep.json")["contentTruncated"], true);
    assert!(
        by_file("d-unknown.json")["reason"]
            .as_str()
            .unwrap()
            .contains("unknown task type")
    );
    assert_eq!(by_file("e-missing.json")["groupFolder"], "other-group");
    assert!(
        !h.host
            .registered_groups_snapshot()
            .contains_key("partial@g.us")
    );
    let rejected = h
        .audit
        .snapshot()
        .into_iter()
        .filter(|e| e.kind == "ipc.file.rejected")
        .count();
    assert_eq!(rejected, 5);
}

#[tokio::test]
async fn quarantine_retention_is_bounded() {
    let h = harness_with(|c| c.max_error_files = 3);
    let m = ns_dir(&h, "other-group", "messages");
    for i in 0..10 {
        write(&m, &format!("{i:02}.json"), "garbage");
    }
    h.watcher.scan_once().await;
    assert_eq!(count(&errors_dir(&h)), 3);
    let files: Vec<_> = error_records(&h)
        .iter()
        .map(|r| r["file"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(files, ["07.json", "08.json", "09.json"]);
}

#[tokio::test]
async fn symlinked_ipc_file_is_never_followed() {
    let h = harness();
    let secret = h.dir.path().join("host-secret.txt");
    std::fs::write(
        &secret,
        r#"{"type":"message","chatJid":"other@g.us","text":"LEAK"}"#,
    )
    .unwrap();
    let m = ns_dir(&h, "other-group", "messages");
    std::os::unix::fs::symlink(&secret, m.join("1.json")).unwrap();
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.quarantined, 1);
    assert!(h.host.sent().is_empty());
    assert_eq!(count(&m), 0);
    assert!(secret.exists(), "symlink target must not be touched");
    let recs = error_records(&h);
    assert!(
        recs[0]["reason"]
            .as_str()
            .unwrap()
            .contains("symbolic link")
    );
    assert!(recs[0]["content"].is_null());
}

#[tokio::test]
async fn symlinked_messages_dir_is_never_followed() {
    let h = harness();
    // host directory the attacker wants us to process (and delete from)
    let victim = h.dir.path().join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    write(
        &victim,
        "important.json",
        r#"{"type":"message","chatJid":"other@g.us","text":"x"}"#,
    );
    let ns = h.dir.path().join("ipc").join("other-group");
    std::fs::create_dir_all(&ns).unwrap();
    std::os::unix::fs::symlink(&victim, ns.join("messages")).unwrap();
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.files, 0);
    assert!(victim.join("important.json").exists());
    assert!(h.host.sent().is_empty());
    let ev = h.audit.snapshot();
    assert_eq!(
        ev.iter().filter(|e| e.kind == "ipc.file.rejected").count(),
        1
    );
    // reported once, not on every scan
    h.watcher.scan_once().await;
    let ev = h.audit.snapshot();
    assert_eq!(
        ev.iter().filter(|e| e.kind == "ipc.file.rejected").count(),
        1
    );
}

#[tokio::test]
async fn hardlinked_and_special_files_are_rejected() {
    let h = harness();
    let m = ns_dir(&h, "other-group", "messages");
    let outside = h.dir.path().join("outside.json");
    std::fs::write(
        &outside,
        r#"{"type":"message","chatJid":"other@g.us","text":"x"}"#,
    )
    .unwrap();
    std::fs::hard_link(&outside, m.join("1.json")).unwrap();
    std::fs::create_dir(m.join("2.json")).unwrap();
    std::fs::write(m.join("2.json").join("inner"), "x").unwrap();
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.quarantined, 2);
    assert!(h.host.sent().is_empty());
    assert!(outside.exists());
    assert!(!m.join("1.json").exists());
    assert!(!m.join("2.json").exists());
}

#[tokio::test]
async fn per_scan_limit_defers_the_rest() {
    let h = harness_with(|c| c.max_messages_per_scan = 5);
    let m = ns_dir(&h, "other-group", "messages");
    for i in 0..12 {
        write(
            &m,
            &format!("{i:02}.json"),
            &format!(r#"{{"type":"message","chatJid":"other@g.us","text":"{i}"}}"#),
        );
    }
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.messages_sent, 5);
    assert_eq!(stats.deferred, 7);
    assert_eq!(count(&m), 7);
    h.watcher.scan_once().await;
    h.watcher.scan_once().await;
    assert_eq!(count(&m), 0);
    let texts: Vec<_> = h.host.sent().into_iter().map(|(_, t)| t).collect();
    let expected: Vec<String> = (0..12).map(|i| i.to_string()).collect();
    assert_eq!(texts, expected);
}

#[tokio::test]
async fn failed_dispatch_is_dead_lettered_and_not_replayed() {
    let h = harness();
    h.host.fail_send.store(true, Ordering::SeqCst);
    let m = ns_dir(&h, "other-group", "messages");
    write(
        &m,
        "1.json",
        r#"{"type":"message","chatJid":"other@g.us","text":"hello"}"#,
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.failed, 1);
    assert_eq!(count(&m), 0);
    let recs = error_records(&h);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["deadLetter"], true);
    h.host.fail_send.store(false, Ordering::SeqCst);
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.files, 0);
    assert!(h.host.sent().is_empty());
}

#[tokio::test]
async fn run_loop_processes_until_cancelled_and_rejects_duplicate_runs() {
    let h = harness();
    let watcher = Arc::new(h.watcher);
    let token = CancellationToken::new();
    let w = Arc::clone(&watcher);
    let t2 = token.clone();
    let task = tokio::spawn(async move { w.run(t2).await });
    let m = h
        .dir
        .path()
        .join("ipc")
        .join("other-group")
        .join("messages");
    std::fs::create_dir_all(&m).unwrap();
    write(
        &m,
        "1.json",
        r#"{"type":"message","chatJid":"other@g.us","text":"live"}"#,
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while h.host.sent().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(h.host.sent().len(), 1);
    // the loop is running now: a second run on the same watcher returns
    // immediately instead of starting a competing poller
    tokio::time::timeout(Duration::from_secs(1), watcher.run(token.clone()))
        .await
        .unwrap();
    token.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn panicking_policy_denies_everything() {
    use talon_security::ipc_authz::IpcDecision;
    let h = harness();
    let watcher = h.watcher.with_authorizer(Arc::new(crate::FnAuthorizer {
        message: |_, _, _| -> IpcDecision { unimplemented!("policy not ready") },
        task: |_, _, _, _| -> IpcDecision { unimplemented!("policy not ready") },
    }));
    let o = watcher
        .process_message(&main_id(), message("other@g.us", "x"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    let o = watcher.process_task(&main_id(), once("other@g.us")).await;
    assert!(matches!(o, IpcOutcome::Denied(_)));
    assert!(h.store.all().is_empty());
    assert!(h.host.sent().is_empty());
}

// ---------------------------------------------------------------------------
// MYTH-03: lanes sharing a folder (all CoPilot lanes live in `copilot`).
// Driven through the production policy *and* the baseline.
// ---------------------------------------------------------------------------

const ALICE_JID: &str = "http:copilot:u:alice";
const BOB_JID: &str = "http:copilot:u:bob";
const WEBHOOK_JID: &str = "webhook:copilot";
const INVESTIGATE_JID: &str = "http:copilot:investigate";
const DIGEST_ID: &str = "copilot-alert-digest-15m";

fn alice() -> crate::host::SourceIdentity {
    copilot_id("copilot-u-alice")
}

fn bob() -> crate::host::SourceIdentity {
    copilot_id("copilot-u-bob")
}

fn with_task_id(mut t: IpcTask, id: &str) -> IpcTask {
    if let IpcTask::ScheduleTask { task_id, .. } = &mut t {
        *task_id = Some(id.into());
    }
    t
}

fn with_script(mut t: IpcTask, s: &str) -> IpcTask {
    match &mut t {
        IpcTask::ScheduleTask { script, .. } | IpcTask::UpdateTask { script, .. } => {
            *script = Some(s.into());
        }
        _ => {}
    }
    t
}

fn with_prompt(mut t: IpcTask, p: &str) -> IpcTask {
    if let IpcTask::UpdateTask { prompt, .. } = &mut t {
        *prompt = Some(p.into());
    }
    t
}

/// The host-seeded, paused digest task and a running investigation.
fn seed_host_tasks(h: &Harness) {
    let mut digest = task(DIGEST_ID, "copilot", WEBHOOK_JID, TaskStatus::Paused);
    digest.schedule_type = ScheduleType::Cron;
    digest.schedule_value = "*/15 * * * *".into();
    h.store.insert(digest);
    h.store.insert(task(
        "copilot-inv-42-1700000000000",
        "copilot",
        INVESTIGATE_JID,
        TaskStatus::Active,
    ));
}

#[tokio::test]
async fn alice_cannot_message_bobs_lane() {
    let h = copilot_harness();
    let o = h
        .watcher
        .process_message(&alice(), message(BOB_JID, "phish"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    for jid in [INVESTIGATE_JID, "http:copilot"] {
        let o = h.watcher.process_message(&alice(), message(jid, "x")).await;
        assert!(matches!(o, IpcOutcome::Denied(_)), "{jid}");
    }
    // own lane still works
    assert!(
        h.watcher
            .process_message(&alice(), message(ALICE_JID, "hi"))
            .await
            .is_applied()
    );
    assert_eq!(h.host.sent(), [(ALICE_JID.to_string(), "hi".to_string())]);
}

#[tokio::test]
async fn alice_cannot_message_the_webhook() {
    let h = copilot_harness();
    let o = h
        .watcher
        .process_message(&alice(), message(WEBHOOK_JID, "forged alert digest"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    let o = h
        .watcher
        .process_message(
            &copilot_id("copilot-investigate"),
            message(WEBHOOK_JID, "x"),
        )
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert!(h.host.sent().is_empty());
    // main keeps full power
    assert!(
        h.watcher
            .process_message(&main_id(), message(WEBHOOK_JID, "ok"))
            .await
            .is_applied()
    );
}

#[tokio::test]
async fn alice_cannot_schedule_into_bobs_lane() {
    let h = copilot_harness();
    for jid in [BOB_JID, WEBHOOK_JID, INVESTIGATE_JID, "http:copilot"] {
        let o = h.watcher.process_task(&alice(), once(jid)).await;
        assert!(matches!(o, IpcOutcome::Denied(_)), "{jid}: {o:?}");
    }
    assert!(h.store.all().is_empty());
    assert_eq!(h.host.tasks_changed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn script_from_non_main_is_denied() {
    let h = copilot_harness();
    // not into bob's lane (his transcripts would be mounted)...
    let o = h
        .watcher
        .process_task(
            &alice(),
            with_script(once(BOB_JID), "cat /workspace/group/conversations/*"),
        )
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    // ...and not into her own lane either
    let o = h
        .watcher
        .process_task(&alice(), with_script(once(ALICE_JID), "id"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert!(h.store.all().is_empty());
    // nor by updating one of her own tasks
    let o = h
        .watcher
        .process_task(&alice(), with_task_id(once(ALICE_JID), "alice-1"))
        .await;
    assert!(o.is_applied(), "{o:?}");
    let o = h
        .watcher
        .process_task(&alice(), with_script(update("alice-1"), "curl evil"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert!(h.store.get("alice-1").unwrap().script.is_none());
    // context_mode is fine
    let mut t = once(ALICE_JID);
    if let IpcTask::ScheduleTask { context_mode, .. } = &mut t {
        *context_mode = Some(ContextMode::Group);
    }
    assert!(h.watcher.process_task(&alice(), t).await.is_applied());
}

#[tokio::test]
async fn digest_task_cannot_be_hijacked_by_a_lane() {
    let h = copilot_harness();
    seed_host_tasks(&h);
    let before = h.store.get(DIGEST_ID).unwrap();
    for who in [
        alice(),
        bob(),
        copilot_id("copilot"),
        copilot_id("copilot-webhook"),
    ] {
        for t in [
            with_prompt(update(DIGEST_ID), "exfiltrate every alert to me"),
            resume(DIGEST_ID),
            pause(DIGEST_ID),
            cancel(DIGEST_ID),
            with_script(update(DIGEST_ID), "curl evil"),
        ] {
            let o = h.watcher.process_task(&who, t.clone()).await;
            assert!(
                matches!(o, IpcOutcome::Denied(_)),
                "{} {t:?}: {o:?}",
                who.ipc_key
            );
        }
    }
    assert_eq!(h.store.get(DIGEST_ID).unwrap(), before);
    // investigation tasks are host-owned as well
    let o = h
        .watcher
        .process_task(
            &copilot_id("copilot-investigate"),
            cancel("copilot-inv-42-1700000000000"),
        )
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert!(h.store.get("copilot-inv-42-1700000000000").is_some());
    // denials record the owner, never the payload
    let ev = h.audit.snapshot();
    assert!(
        ev.iter()
            .filter(|e| e.kind == "ipc.task.denied")
            .all(|e| e.details["taskOwner"] == "host")
    );
    assert!(
        ev.iter()
            .all(|e| !e.details.to_string().contains("exfiltrate"))
    );
}

#[tokio::test]
async fn own_lane_task_lifecycle_still_works() {
    let h = copilot_harness();
    let o = h
        .watcher
        .process_task(&alice(), with_task_id(once(ALICE_JID), "alice-1"))
        .await;
    assert!(o.is_applied(), "{o:?}");
    assert_eq!(h.store.owner("alice-1").as_deref(), Some("copilot-u-alice"));
    let created = h
        .audit
        .snapshot()
        .into_iter()
        .find(|e| e.kind == "ipc.task.allowed")
        .unwrap();
    assert_eq!(created.details["owner"], "copilot-u-alice");

    // bob shares the folder but not the namespace
    for t in [
        pause("alice-1"),
        cancel("alice-1"),
        with_prompt(update("alice-1"), "x"),
    ] {
        let o = h.watcher.process_task(&bob(), t).await;
        assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    }
    // alice manages her own task
    for t in [
        pause("alice-1"),
        resume("alice-1"),
        with_prompt(update("alice-1"), "new prompt"),
    ] {
        let o = h.watcher.process_task(&alice(), t).await;
        assert!(o.is_applied(), "{o:?}");
    }
    assert_eq!(h.store.get("alice-1").unwrap().prompt, "new prompt");
    assert!(
        h.watcher
            .process_task(&alice(), cancel("alice-1"))
            .await
            .is_applied()
    );
    assert!(h.store.get("alice-1").is_none());
    assert!(h.store.owner("alice-1").is_none());
}

#[tokio::test]
async fn main_can_still_manage_tasks() {
    let h = copilot_harness();
    seed_host_tasks(&h);
    // host-owned tasks: status and prompt changes are fine...
    for t in [
        resume(DIGEST_ID),
        pause(DIGEST_ID),
        with_prompt(update(DIGEST_ID), "summarize"),
    ] {
        let o = h.watcher.process_task(&main_id(), t).await;
        assert!(o.is_applied(), "{o:?}");
    }
    assert_eq!(h.store.get(DIGEST_ID).unwrap().prompt, "summarize");
    // ...but script injection into a host task is operator-only
    let o = h
        .watcher
        .process_task(&main_id(), with_script(update(DIGEST_ID), "echo hi"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert!(h.store.get(DIGEST_ID).unwrap().script.is_none());

    // main may schedule (with a script) into any lane; it owns the result
    let o = h
        .watcher
        .process_task(
            &main_id(),
            with_task_id(with_script(once(BOB_JID), "echo check"), "main-1"),
        )
        .await;
    assert!(o.is_applied(), "{o:?}");
    assert_eq!(h.store.owner("main-1").as_deref(), Some("whatsapp_main"));
    assert_eq!(
        h.store.get("main-1").unwrap().script.as_deref(),
        Some("echo check")
    );
    // ...which bob cannot touch
    let o = h.watcher.process_task(&bob(), cancel("main-1")).await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    // main manages lane-owned tasks, scripts included
    h.store.insert_owned(
        task("bob-1", "copilot", BOB_JID, TaskStatus::Active),
        "copilot-u-bob",
    );
    let o = h
        .watcher
        .process_task(&main_id(), with_script(update("bob-1"), "echo ok"))
        .await;
    assert!(o.is_applied(), "{o:?}");
    assert!(
        h.watcher
            .process_task(&main_id(), cancel("bob-1"))
            .await
            .is_applied()
    );
    assert!(
        h.watcher
            .process_task(&main_id(), cancel(DIGEST_ID))
            .await
            .is_applied()
    );
}

#[tokio::test]
async fn task_id_of_a_host_task_cannot_be_reused() {
    let h = copilot_harness();
    seed_host_tasks(&h);
    let o = h
        .watcher
        .process_task(&alice(), with_task_id(once(ALICE_JID), DIGEST_ID))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert_eq!(h.store.get(DIGEST_ID).unwrap().chat_jid, WEBHOOK_JID);
    assert!(h.store.owner(DIGEST_ID).is_none());
}

#[tokio::test]
async fn owner_recording_failure_rolls_back_the_task() {
    let h = copilot_harness();
    h.store.fail_owner.store(true, Ordering::SeqCst);
    let o = h
        .watcher
        .process_task(&alice(), with_task_id(once(ALICE_JID), "alice-1"))
        .await;
    assert!(
        matches!(o, IpcOutcome::Failed(ref e) if e.contains("owner")),
        "{o:?}"
    );
    assert!(h.store.all().is_empty());
    assert_eq!(h.host.tasks_changed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn scan_enforces_lanes_by_directory() {
    let h = copilot_harness();
    seed_host_tasks(&h);
    let m = ns_dir(&h, "copilot-u-alice", "messages");
    write(
        &m,
        "1.json",
        r#"{"type":"message","chatJid":"http:copilot:u:bob","text":"x","groupFolder":"copilot"}"#,
    );
    write(
        &m,
        "2.json",
        r#"{"type":"message","chatJid":"http:copilot:u:alice","text":"mine"}"#,
    );
    let t = ns_dir(&h, "copilot-u-alice", "tasks");
    write(
        &t,
        "1.json",
        r#"{"type":"schedule_task","prompt":"p","script":"cat ~/.ssh/*","schedule_type":"interval","schedule_value":"60000","targetJid":"http:copilot:u:bob"}"#,
    );
    write(
        &t,
        "2.json",
        r#"{"type":"update_task","taskId":"copilot-alert-digest-15m","prompt":"backdoor"}"#,
    );
    write(
        &t,
        "3.json",
        r#"{"type":"resume_task","taskId":"copilot-alert-digest-15m"}"#,
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.messages_sent, 1);
    assert_eq!(stats.tasks_applied, 0);
    assert_eq!(stats.denied, 4);
    assert_eq!(h.host.sent()[0].0, ALICE_JID);
    let digest = h.store.get(DIGEST_ID).unwrap();
    assert_eq!(digest.status, TaskStatus::Paused);
    assert_eq!(digest.prompt, "p");
}

// ---------------------------------------------------------------------------
// MYTH-11: audit rate limit and log hygiene
// ---------------------------------------------------------------------------

fn count_kind(h: &Harness, kind: &str, ipc_key: &str) -> usize {
    h.audit
        .snapshot()
        .iter()
        .filter(|e| e.kind == kind && e.details["ipcKey"] == ipc_key)
        .count()
}

#[tokio::test]
async fn audit_rows_are_rate_limited_per_namespace() {
    let h = copilot_harness_with(|c| {
        c.audit_max_per_window = 5;
        c.audit_window = Duration::from_millis(800);
    });
    for i in 0..20 {
        let o = h
            .watcher
            .process_message(&alice(), message(BOB_JID, &format!("{i}")))
            .await;
        assert!(matches!(o, IpcOutcome::Denied(_)));
    }
    assert_eq!(count_kind(&h, "ipc.message.denied", "copilot-u-alice"), 5);
    // another namespace has its own budget
    h.watcher
        .process_message(&bob(), message(ALICE_JID, "x"))
        .await;
    assert_eq!(count_kind(&h, "ipc.message.denied", "copilot-u-bob"), 1);
    // applied state changes are always audited, even over budget
    let o = h.watcher.process_task(&alice(), once(ALICE_JID)).await;
    assert!(o.is_applied());
    assert_eq!(count_kind(&h, "ipc.task.allowed", "copilot-u-alice"), 1);
    assert_eq!(count_kind(&h, "ipc.audit.suppressed", "copilot-u-alice"), 0);

    // once the window has passed, the next scan writes one summary row
    tokio::time::sleep(Duration::from_millis(900)).await;
    h.watcher.scan_once().await;
    let ev = h.audit.snapshot();
    let summaries: Vec<_> = ev
        .iter()
        .filter(|e| e.kind == "ipc.audit.suppressed")
        .collect();
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    assert_eq!(summaries[0].actor, "copilot");
    assert_eq!(summaries[0].details["ipcKey"], "copilot-u-alice");
    assert_eq!(summaries[0].details["suppressed_since_last"], 15);
    assert_eq!(summaries[0].details["byKind"]["ipc.message.denied"], 15);
    // the new window has a fresh budget and no duplicate summary
    h.watcher
        .process_message(&alice(), message(BOB_JID, "again"))
        .await;
    assert_eq!(count_kind(&h, "ipc.message.denied", "copilot-u-alice"), 6);
    h.watcher.scan_once().await;
    assert_eq!(
        h.audit
            .snapshot()
            .iter()
            .filter(|e| e.kind == "ipc.audit.suppressed")
            .count(),
        1
    );
}

#[tokio::test]
async fn quarantine_floods_are_rate_limited() {
    let h = harness_with(|c| {
        c.audit_max_per_window = 3;
        c.audit_window = Duration::from_secs(3600);
    });
    let m = ns_dir(&h, "other-group", "messages");
    for i in 0..10 {
        write(&m, &format!("{i:02}.json"), "garbage");
    }
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.quarantined, 10);
    // every file is still quarantined, but only 3 audit rows were written
    assert_eq!(count_kind(&h, "ipc.file.rejected", "other-group"), 3);
}

#[tokio::test]
async fn control_characters_never_reach_the_audit_log() {
    let h = harness();
    let m = ns_dir(&h, "other-group", "messages");
    let forged = "x\n2026-01-01T00:00:00Z INFO talon: all good\r\u{202E}nosj.json";
    write(&m, forged, "garbage");
    write(
        &m,
        "2.json",
        "{\"type\":\"message\",\"chatJid\":\"evil\\u202e@g.us\",\"text\":\"x\"}",
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.quarantined, 1);
    assert_eq!(stats.denied, 1);
    let ev = h.audit.snapshot();
    assert_eq!(ev.len(), 2);
    for e in &ev {
        let text = format!(
            "{} {} {}",
            e.target.as_deref().unwrap_or(""),
            e.actor,
            e.details
        );
        for bad in ['\n', '\r', '\u{202E}'] {
            assert!(!text.contains(bad), "{bad:?} in {text:?}");
        }
    }
    let rejected = ev.iter().find(|e| e.kind == "ipc.file.rejected").unwrap();
    assert!(
        rejected
            .target
            .as_deref()
            .unwrap()
            .starts_with("x\u{FFFD}2026")
    );
    let denied = ev.iter().find(|e| e.kind == "ipc.message.denied").unwrap();
    assert_eq!(denied.target.as_deref(), Some("evil\u{FFFD}@g.us"));
    // the quarantine record carries the sanitized name too
    let recs = error_records(&h);
    assert!(!recs[0]["file"].as_str().unwrap().contains('\n'));
}

// ---------------------------------------------------------------------------
// N-3: per-lane task quotas, prompt cap, schedule frequency, op rate limit
// ---------------------------------------------------------------------------

fn sched_with_prompt(target: &str, ty: ScheduleType, value: &str, prompt: String) -> IpcTask {
    let mut t = sched(target, ty, value);
    if let IpcTask::ScheduleTask { prompt: p, .. } = &mut t {
        *p = prompt;
    }
    t
}

fn alice_once(id: &str) -> IpcTask {
    with_task_id(once(ALICE_JID), id)
}

/// Details of the most recent `ipc.task.denied` row.
fn last_denial(h: &Harness) -> serde_json::Value {
    h.audit
        .snapshot()
        .into_iter()
        .rev()
        .find(|e| e.kind == "ipc.task.denied")
        .expect("a denial row")
        .details
}

fn assert_quota_denied(h: &Harness, o: &IpcOutcome, quota: &str) {
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    let d = last_denial(h);
    assert_eq!(d["stage"], "quota", "{d}");
    assert_eq!(d["quota"], quota, "{d}");
}

fn set_status(h: &Harness, id: &str, status: TaskStatus) {
    h.store.tasks.lock().unwrap().get_mut(id).unwrap().status = status;
}

#[tokio::test]
async fn non_main_lane_task_quota_counts_active_and_paused_tasks() {
    let h = copilot_harness_with(|c| c.max_tasks_per_lane = 3);
    for i in 0..3 {
        let o = h
            .watcher
            .process_task(&alice(), alice_once(&format!("alice-{i}")))
            .await;
        assert!(o.is_applied(), "{o:?}");
    }
    // paused tasks still count
    assert!(
        h.watcher
            .process_task(&alice(), pause("alice-0"))
            .await
            .is_applied()
    );
    let o = h
        .watcher
        .process_task(&alice(), alice_once("alice-3"))
        .await;
    assert_quota_denied(&h, &o, "tasks_per_lane");
    assert!(
        matches!(o, IpcOutcome::Denied(ref r) if r.contains("limit 3")),
        "{o:?}"
    );
    assert_eq!(last_denial(&h)["ownedTasks"], 3);
    assert!(h.store.get("alice-3").is_none());

    // bob shares the folder but has his own quota
    let o = h
        .watcher
        .process_task(&bob(), with_task_id(once(BOB_JID), "bob-0"))
        .await;
    assert!(o.is_applied(), "{o:?}");

    // cancelling frees a slot
    assert!(
        h.watcher
            .process_task(&alice(), cancel("alice-1"))
            .await
            .is_applied()
    );
    assert!(
        h.watcher
            .process_task(&alice(), alice_once("alice-3"))
            .await
            .is_applied()
    );

    // completed tasks do not count, but resuming one needs a free slot
    set_status(&h, "alice-2", TaskStatus::Completed);
    assert!(
        h.watcher
            .process_task(&alice(), alice_once("alice-4"))
            .await
            .is_applied()
    );
    let o = h.watcher.process_task(&alice(), resume("alice-2")).await;
    assert_quota_denied(&h, &o, "tasks_per_lane");
    assert_eq!(
        h.store.get("alice-2").unwrap().status,
        TaskStatus::Completed
    );
    // resuming a paused task does not add one
    assert!(
        h.watcher
            .process_task(&alice(), resume("alice-0"))
            .await
            .is_applied()
    );
    assert!(
        h.watcher
            .process_task(&alice(), cancel("alice-4"))
            .await
            .is_applied()
    );
    assert!(
        h.watcher
            .process_task(&alice(), resume("alice-2"))
            .await
            .is_applied()
    );
    let live = h
        .store
        .all()
        .into_iter()
        .filter(|t| h.store.owner(&t.id).as_deref() == Some("copilot-u-alice"))
        .filter(|t| t.status != TaskStatus::Completed)
        .count();
    assert_eq!(live, 3);
}

#[tokio::test]
async fn main_is_exempt_from_task_quota_and_frequency() {
    let h = copilot_harness_with(|c| c.max_tasks_per_lane = 1);
    for i in 0..4 {
        let t = with_task_id(
            sched(ALICE_JID, ScheduleType::Cron, "* * * * *"),
            &format!("main-{i}"),
        );
        let o = h.watcher.process_task(&main_id(), t).await;
        assert!(o.is_applied(), "{o:?}");
    }
    let o = h
        .watcher
        .process_task(&main_id(), sched(BOB_JID, ScheduleType::Interval, "10000"))
        .await;
    assert!(o.is_applied(), "{o:?}");
    // tasks main scheduled into alice's lane are main's, not alice's quota
    assert!(
        h.watcher
            .process_task(&alice(), alice_once("alice-0"))
            .await
            .is_applied()
    );
    let o = h
        .watcher
        .process_task(&alice(), alice_once("alice-1"))
        .await;
    assert_quota_denied(&h, &o, "tasks_per_lane");
    // main may resume a too-frequent paused task of a lane
    set_status(&h, "main-0", TaskStatus::Paused);
    assert!(
        h.watcher
            .process_task(&main_id(), resume("main-0"))
            .await
            .is_applied()
    );
}

#[tokio::test]
async fn task_quota_can_be_disabled() {
    let h = copilot_harness_with(|c| c.max_tasks_per_lane = 0);
    for i in 0..30 {
        let o = h
            .watcher
            .process_task(&alice(), alice_once(&format!("alice-{i}")))
            .await;
        assert!(o.is_applied(), "{i}: {o:?}");
    }
}

#[tokio::test]
async fn prompt_size_is_capped_per_lane() {
    let h = copilot_harness();
    let kib = |n: usize| "x".repeat(n * 1024);
    let o = h
        .watcher
        .process_task(
            &alice(),
            sched_with_prompt(
                ALICE_JID,
                ScheduleType::Once,
                "2026-06-01T00:00:00",
                kib(16),
            ),
        )
        .await;
    assert!(o.is_applied(), "{o:?}");
    for prompt in [kib(16) + "y", "日".repeat(6000), kib(250)] {
        let o = h
            .watcher
            .process_task(
                &alice(),
                sched_with_prompt(ALICE_JID, ScheduleType::Once, "2026-06-01T00:00:00", prompt),
            )
            .await;
        assert_quota_denied(&h, &o, "prompt_bytes");
    }
    assert!(last_denial(&h)["promptBytes"].as_u64().unwrap() > 200 * 1024);
    assert_eq!(h.store.all().len(), 1);
    // update_task is capped as well
    let id = h.store.all()[0].id.clone();
    let o = h
        .watcher
        .process_task(&alice(), with_prompt(update(&id), &kib(17)))
        .await;
    assert_quota_denied(&h, &o, "prompt_bytes");
    assert_eq!(h.store.get(&id).unwrap().prompt.len(), 16 * 1024);
    // the prompt text never reaches the audit log
    assert!(
        h.audit
            .snapshot()
            .iter()
            .all(|e| !e.details.to_string().contains("xxxxxxxx"))
    );

    // main has a larger cap
    for (size, ok) in [(20, true), (64, true), (65, false)] {
        let o = h
            .watcher
            .process_task(
                &main_id(),
                sched_with_prompt(
                    BOB_JID,
                    ScheduleType::Once,
                    "2026-06-01T00:00:00",
                    kib(size),
                ),
            )
            .await;
        if ok {
            assert!(o.is_applied(), "{size} KiB: {o:?}");
        } else {
            assert_quota_denied(&h, &o, "prompt_bytes");
        }
    }
    let o = h
        .watcher
        .process_task(&main_id(), with_prompt(update(&id), &kib(64)))
        .await;
    assert!(o.is_applied(), "{o:?}");
}

#[tokio::test]
async fn prompt_caps_are_configurable() {
    let h = copilot_harness_with(|c| {
        c.max_prompt_bytes = 10;
        c.main_max_prompt_bytes = 0; // disabled
    });
    let o = h
        .watcher
        .process_task(
            &alice(),
            sched_with_prompt(
                ALICE_JID,
                ScheduleType::Once,
                "2026-06-01T00:00:00",
                "x".repeat(11),
            ),
        )
        .await;
    assert_quota_denied(&h, &o, "prompt_bytes");
    let o = h
        .watcher
        .process_task(
            &main_id(),
            sched_with_prompt(
                BOB_JID,
                ScheduleType::Once,
                "2026-06-01T00:00:00",
                "x".repeat(200 * 1024),
            ),
        )
        .await;
    assert!(o.is_applied(), "{o:?}");
}

#[tokio::test]
async fn recurring_lane_schedules_respect_the_minimum_frequency() {
    let h = copilot_harness();
    for (ty, v) in [
        (ScheduleType::Cron, "* * * * *"),
        (ScheduleType::Cron, "*/2 * * * *"),
        (ScheduleType::Cron, "*/10 * * * * *"),
        (ScheduleType::Cron, "0,3 * * * *"),
        (ScheduleType::Interval, "60000"),
        (ScheduleType::Interval, "299999"),
    ] {
        let o = h
            .watcher
            .process_task(&alice(), sched(ALICE_JID, ty, v))
            .await;
        assert_quota_denied(&h, &o, "schedule_frequency");
    }
    assert!(h.store.all().is_empty());
    for (ty, v) in [
        (ScheduleType::Cron, "*/5 * * * *"),
        (ScheduleType::Cron, "0 9 * * 1-5"),
        (ScheduleType::Interval, "300000"),
        (ScheduleType::Once, "2026-06-01T00:00:00"),
    ] {
        let o = h
            .watcher
            .process_task(&alice(), sched(ALICE_JID, ty, v))
            .await;
        assert!(o.is_applied(), "{ty:?} {v}: {o:?}");
    }
    assert_eq!(h.store.all().len(), 4);

    // rescheduling to a frequent cron is denied and changes nothing
    let id = h
        .store
        .all()
        .into_iter()
        .find(|t| t.schedule_value == "*/5 * * * *")
        .unwrap()
        .id;
    let mut u = update(&id);
    if let IpcTask::UpdateTask { schedule_value, .. } = &mut u {
        *schedule_value = Some("* * * * *".into());
    }
    let o = h.watcher.process_task(&alice(), u).await;
    assert_quota_denied(&h, &o, "schedule_frequency");
    assert_eq!(h.store.get(&id).unwrap().schedule_value, "*/5 * * * *");
    // switching an interval task to a short interval as well
    let id = h
        .store
        .all()
        .into_iter()
        .find(|t| t.schedule_type == ScheduleType::Interval)
        .unwrap()
        .id;
    let mut u = update(&id);
    if let IpcTask::UpdateTask { schedule_value, .. } = &mut u {
        *schedule_value = Some("10000".into());
    }
    let o = h.watcher.process_task(&alice(), u).await;
    assert_quota_denied(&h, &o, "schedule_frequency");

    // a paused too-frequent task (created before the limit existed) cannot
    // be resumed by its lane; pausing / cancelling it stays possible
    let mut legacy = task("legacy", "copilot", ALICE_JID, TaskStatus::Paused);
    legacy.schedule_type = ScheduleType::Cron;
    legacy.schedule_value = "* * * * *".into();
    h.store.insert_owned(legacy, "copilot-u-alice");
    let o = h.watcher.process_task(&alice(), resume("legacy")).await;
    assert_quota_denied(&h, &o, "schedule_frequency");
    assert_eq!(h.store.get("legacy").unwrap().status, TaskStatus::Paused);
    assert!(
        h.watcher
            .process_task(&alice(), cancel("legacy"))
            .await
            .is_applied()
    );
}

#[tokio::test]
async fn minimum_frequency_is_configurable() {
    let h = copilot_harness_with(|c| c.min_schedule_interval = Duration::from_secs(3600));
    let o = h
        .watcher
        .process_task(
            &alice(),
            sched(ALICE_JID, ScheduleType::Cron, "*/30 * * * *"),
        )
        .await;
    assert_quota_denied(&h, &o, "schedule_frequency");
    let h = copilot_harness_with(|c| c.min_schedule_interval = Duration::ZERO);
    let o = h
        .watcher
        .process_task(&alice(), sched(ALICE_JID, ScheduleType::Cron, "* * * * *"))
        .await;
    assert!(o.is_applied(), "{o:?}");
}

#[tokio::test]
async fn executed_task_ops_are_rate_limited_with_one_summary_row() {
    let h = copilot_harness_with(|c| {
        c.max_task_ops_per_window = 3;
        c.task_op_window = Duration::from_millis(1500);
    });
    // denied / rejected requests do not use the budget
    let o = h.watcher.process_task(&alice(), once(BOB_JID)).await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    let o = h
        .watcher
        .process_task(&alice(), sched(ALICE_JID, ScheduleType::Cron, "bogus"))
        .await;
    assert!(matches!(o, IpcOutcome::Rejected(_)), "{o:?}");
    for i in 0..3 {
        let o = h
            .watcher
            .process_task(&alice(), alice_once(&format!("alice-{i}")))
            .await;
        assert!(o.is_applied(), "{o:?}");
    }
    // over budget: denied and NOT executed
    for i in 3..10 {
        let o = h
            .watcher
            .process_task(&alice(), alice_once(&format!("alice-{i}")))
            .await;
        assert!(
            matches!(o, IpcOutcome::Denied(ref r) if r.contains("rate limit")),
            "{o:?}"
        );
    }
    let o = h.watcher.process_task(&alice(), pause("alice-0")).await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert_eq!(h.store.all().len(), 3);
    assert_eq!(h.store.get("alice-0").unwrap().status, TaskStatus::Active);
    assert_eq!(h.host.tasks_changed.load(Ordering::SeqCst), 3);
    // every executed operation is audited; throttled ones are not, one by one
    assert_eq!(count_kind(&h, "ipc.task.allowed", "copilot-u-alice"), 3);
    assert_eq!(count_kind(&h, "ipc.task.denied", "copilot-u-alice"), 2);
    assert_eq!(count_kind(&h, "ipc.task.throttled", "copilot-u-alice"), 0);

    // other namespaces have their own budgets
    let o = h.watcher.process_task(&bob(), once(BOB_JID)).await;
    assert!(o.is_applied(), "{o:?}");
    let o = h.watcher.process_task(&main_id(), pause("alice-0")).await;
    assert!(o.is_applied(), "{o:?}");

    // once the window has passed, the next scan writes one summary row
    tokio::time::sleep(Duration::from_millis(1600)).await;
    h.watcher.scan_once().await;
    let summaries: Vec<_> = h
        .audit
        .snapshot()
        .into_iter()
        .filter(|e| e.kind == "ipc.task.throttled")
        .collect();
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    let s = &summaries[0];
    assert_eq!(s.actor, "copilot");
    assert_eq!(s.outcome, "denied");
    assert_eq!(s.details["ipcKey"], "copilot-u-alice");
    assert_eq!(s.details["isMain"], false);
    assert_eq!(s.details["throttled_since_last"], 8);
    assert_eq!(s.details["byType"]["schedule_task"], 7);
    assert_eq!(s.details["byType"]["pause_task"], 1);
    assert_eq!(s.details["limit"], 3);

    // the new window has a fresh budget and no duplicate summary
    let o = h.watcher.process_task(&alice(), resume("alice-0")).await;
    assert!(o.is_applied(), "{o:?}");
    h.watcher.scan_once().await;
    assert_eq!(
        h.audit
            .snapshot()
            .iter()
            .filter(|e| e.kind == "ipc.task.throttled")
            .count(),
        1
    );
}

#[tokio::test]
async fn main_has_a_higher_task_op_budget_and_limits_can_be_disabled() {
    let h = copilot_harness_with(|c| {
        c.max_task_ops_per_window = 2;
        c.main_max_task_ops_per_window = 4;
        c.task_op_window = Duration::from_secs(3600);
    });
    for i in 0..6 {
        let o = h
            .watcher
            .process_task(&main_id(), with_task_id(once(BOB_JID), &format!("m-{i}")))
            .await;
        assert_eq!(o.is_applied(), i < 4, "{i}: {o:?}");
    }
    for i in 0..3 {
        let o = h
            .watcher
            .process_task(&alice(), alice_once(&format!("a-{i}")))
            .await;
        assert_eq!(o.is_applied(), i < 2, "{i}: {o:?}");
    }
    // main's no-op update and refresh are operations too
    let o = h.watcher.process_task(&main_id(), update("m-0")).await;
    assert!(
        matches!(o, IpcOutcome::Denied(ref r) if r.contains("rate limit")),
        "{o:?}"
    );
    let o = h
        .watcher
        .process_task(&main_id(), IpcTask::RefreshGroups { timestamp: None })
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert_eq!(h.host.syncs.load(Ordering::SeqCst), 0);

    let h = copilot_harness_with(|c| {
        c.main_max_task_ops_per_window = 0;
        c.task_op_window = Duration::from_secs(3600);
    });
    for i in 0..150 {
        let o = h
            .watcher
            .process_task(&main_id(), with_task_id(once(BOB_JID), &format!("m-{i}")))
            .await;
        assert!(o.is_applied(), "{i}: {o:?}");
    }
}

#[tokio::test]
async fn executed_ops_are_audited_even_over_the_audit_budget() {
    let h = copilot_harness_with(|c| {
        c.audit_max_per_window = 2;
        c.audit_window = Duration::from_secs(3600);
        c.max_task_ops_per_window = 5;
        c.task_op_window = Duration::from_secs(3600);
    });
    // use up the audit budget with denials
    for _ in 0..3 {
        h.watcher.process_task(&alice(), once(BOB_JID)).await;
    }
    assert_eq!(count_kind(&h, "ipc.task.denied", "copilot-u-alice"), 2);
    for i in 0..4 {
        assert!(
            h.watcher
                .process_task(&alice(), alice_once(&format!("alice-{i}")))
                .await
                .is_applied()
        );
    }
    assert_eq!(count_kind(&h, "ipc.task.allowed", "copilot-u-alice"), 4);
    // a quota denial is an ordinary (rate-limited) audit row
    let o = h
        .watcher
        .process_task(&alice(), sched(ALICE_JID, ScheduleType::Cron, "* * * * *"))
        .await;
    assert!(matches!(o, IpcOutcome::Denied(_)), "{o:?}");
    assert_eq!(count_kind(&h, "ipc.task.denied", "copilot-u-alice"), 2);
    // an operation that failed after it started executing is audited too
    h.store.fail_owner.store(true, Ordering::SeqCst);
    let o = h
        .watcher
        .process_task(&alice(), alice_once("alice-x"))
        .await;
    assert!(matches!(o, IpcOutcome::Failed(_)), "{o:?}");
    assert_eq!(count_kind(&h, "ipc.task.failed", "copilot-u-alice"), 1);
    h.store.fail_owner.store(false, Ordering::SeqCst);
    // the budget (5) is now used up: further operations are not executed
    let o = h
        .watcher
        .process_task(&alice(), alice_once("alice-y"))
        .await;
    assert!(
        matches!(o, IpcOutcome::Denied(ref r) if r.contains("rate limit")),
        "{o:?}"
    );
    assert!(h.store.get("alice-y").is_none());
}

#[tokio::test]
async fn pending_throttle_summary_is_written_on_shutdown() {
    let h = copilot_harness_with(|c| {
        c.max_task_ops_per_window = 1;
        c.task_op_window = Duration::from_secs(3600);
    });
    let t = ns_dir(&h, "copilot-u-alice", "tasks");
    for i in 0..3 {
        write(
            &t,
            &format!("{i}.json"),
            &format!(
                r#"{{"type":"schedule_task","taskId":"alice-{i}","prompt":"p","schedule_type":"once","schedule_value":"2026-06-01T00:00:00","targetJid":"{ALICE_JID}"}}"#
            ),
        );
    }
    let watcher = Arc::new(h.watcher);
    let token = CancellationToken::new();
    let (w, t2) = (Arc::clone(&watcher), token.clone());
    let run = tokio::spawn(async move { w.run(t2).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while count(&t) > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(count(&t), 0);
    assert_eq!(h.store.all().len(), 1);
    assert!(
        h.audit
            .snapshot()
            .iter()
            .all(|e| e.kind != "ipc.task.throttled")
    );
    token.cancel();
    run.await.unwrap();
    let s: Vec<_> = h
        .audit
        .snapshot()
        .into_iter()
        .filter(|e| e.kind == "ipc.task.throttled")
        .collect();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].details["throttled_since_last"], 2);
}

/// The N-3 proof of concept: one lane drops 320 every-minute cron tasks
/// with 250 KiB prompts (and the same with small prompts and with
/// acceptable schedules).
#[tokio::test]
async fn mass_task_creation_from_one_lane_is_contained() {
    let h = copilot_harness();
    let big = "A".repeat(250 * 1024);
    for _ in 0..320 {
        let t = sched_with_prompt(ALICE_JID, ScheduleType::Cron, "* * * * *", big.clone());
        assert!(!h.watcher.process_task(&alice(), t).await.is_applied());
    }
    for _ in 0..320 {
        let t = sched(ALICE_JID, ScheduleType::Cron, "* * * * *");
        assert!(!h.watcher.process_task(&alice(), t).await.is_applied());
    }
    assert!(h.store.all().is_empty());
    let mut applied = 0;
    for _ in 0..320 {
        let t = sched(ALICE_JID, ScheduleType::Cron, "*/5 * * * *");
        if h.watcher.process_task(&alice(), t).await.is_applied() {
            applied += 1;
        }
    }
    assert_eq!(applied, 25);
    assert_eq!(h.store.all().len(), 25);
    // audit rows stay bounded: the executed operations plus the budget
    let rows = h
        .audit
        .snapshot()
        .iter()
        .filter(|e| e.details["ipcKey"] == "copilot-u-alice")
        .count();
    assert!(rows <= 25 + 60, "{rows}");
}
