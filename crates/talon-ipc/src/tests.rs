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
    h.store.insert(task(
        "task-main",
        "whatsapp_main",
        "main@g.us",
        TaskStatus::Active,
    ));
    h.store.insert(task(
        "task-other",
        "other-group",
        "other@g.us",
        TaskStatus::Active,
    ));
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
    h.store.insert(task(
        "task-paused",
        "other-group",
        "other@g.us",
        TaskStatus::Paused,
    ));
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
    h.store.insert(task(
        "task-paused",
        "other-group",
        "other@g.us",
        TaskStatus::Paused,
    ));
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
    h.store.insert(task(
        "task-to-cancel",
        "other-group",
        "other@g.us",
        TaskStatus::Active,
    ));
    assert!(
        h.watcher
            .process_task(&main_id(), cancel("task-to-cancel"))
            .await
            .is_applied()
    );
    assert!(h.store.get("task-to-cancel").is_none());

    h.store.insert(task(
        "task-own",
        "other-group",
        "other@g.us",
        TaskStatus::Active,
    ));
    assert!(
        h.watcher
            .process_task(&other_id(), cancel("task-own"))
            .await
            .is_applied()
    );
    assert!(h.store.get("task-own").is_none());

    h.store.insert(task(
        "task-foreign",
        "whatsapp_main",
        "main@g.us",
        TaskStatus::Active,
    ));
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
async fn register_group_preserves_lane_fields_and_limits_container_config() {
    let h = harness();
    {
        let mut groups = h.host.groups.lock().unwrap();
        let other = groups.get_mut("other@g.us").unwrap();
        other.container_config = Some(ContainerConfig {
            network: Some("talon-net".into()),
            ..ContainerConfig::default()
        });
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
    // privileged container option refused
    let o = h
        .watcher
        .process_task(
            &main_id(),
            req(ContainerConfig {
                network: Some("host".into()),
                ..ContainerConfig::default()
            }),
        )
        .await;
    assert!(matches!(o, IpcOutcome::Rejected(_)));
    // mounts accepted; operator fields preserved
    let mount = AdditionalMount {
        host_path: "/srv/logs".into(),
        container_path: None,
        readonly: true,
    };
    let o = h
        .watcher
        .process_task(
            &main_id(),
            req(ContainerConfig {
                additional_mounts: vec![mount.clone()],
                ..ContainerConfig::default()
            }),
        )
        .await;
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
    let cfg = g.container_config.unwrap();
    assert_eq!(cfg.network.as_deref(), Some("talon-net"));
    assert_eq!(cfg.additional_mounts, vec![mount]);
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
    h.store.insert(t);
    h.store.insert(task(
        "t-main",
        "whatsapp_main",
        "main@g.us",
        TaskStatus::Active,
    ));

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
        *schedule_value = Some("60000".into());
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
        r#"{"type":"schedule_task","taskId":"task-1","prompt":"p","schedule_type":"interval","schedule_value":"60000","context_mode":"group","targetJid":"other@g.us","createdBy":"whatsapp_main"}"#,
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
async fn lanes_with_custom_ipc_keys_map_to_their_folder() {
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
        r#"{"type":"message","chatJid":"http:copilot","text":"same folder"}"#,
    );
    write(
        &m,
        "2.json",
        r#"{"type":"message","chatJid":"other@g.us","text":"other folder"}"#,
    );
    let stats = h.watcher.scan_once().await;
    assert_eq!(stats.messages_sent, 1);
    assert_eq!(stats.denied, 1);
    assert_eq!(h.host.sent()[0].0, "http:copilot");
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
