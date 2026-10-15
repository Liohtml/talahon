//! Integration tests against the real `talon-db` (in-memory SQLite, hash-
//! chained audit log) and the real `talon_security::ipc_authz` policy (the
//! watcher's default authorizer).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use talon_core::protocol::{IpcOutbound, IpcTask};
use talon_core::types::{
    AvailableGroup, ContextMode, RegisteredGroup, ScheduleType, ScheduledTask, TaskStatus,
};
use talon_db::{Db, DbAuditSink};
use talon_ipc::{IpcHost, IpcOutcome, IpcWatcher, IpcWatcherConfig, SourceIdentity};

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

/// Host backed by the real database for registrations (like the
/// orchestrator).
struct DbHost {
    db: Db,
    groups: Mutex<HashMap<String, RegisteredGroup>>,
    sent: Mutex<Vec<(String, String)>>,
    tasks_changed: AtomicUsize,
    snapshots: AtomicUsize,
}

impl DbHost {
    fn new(db: Db) -> Self {
        let groups = HashMap::from([
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
        ]);
        for (jid, g) in &groups {
            db.set_registered_group(jid, g).unwrap();
        }
        Self {
            db,
            groups: Mutex::new(groups),
            sent: Mutex::default(),
            tasks_changed: AtomicUsize::new(0),
            snapshots: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl IpcHost for DbHost {
    async fn send_message(&self, jid: &str, text: &str) -> talon_core::Result<()> {
        self.sent.lock().unwrap().push((jid.into(), text.into()));
        Ok(())
    }
    fn registered_groups(&self) -> HashMap<String, RegisteredGroup> {
        self.groups.lock().unwrap().clone()
    }
    async fn register_group(&self, jid: &str, group: RegisteredGroup) -> talon_core::Result<()> {
        self.db.set_registered_group(jid, &group)?;
        self.groups.lock().unwrap().insert(jid.into(), group);
        Ok(())
    }
    async fn sync_groups(&self, _force: bool) -> talon_core::Result<()> {
        Ok(())
    }
    fn available_groups(&self) -> Vec<AvailableGroup> {
        Vec::new()
    }
    async fn write_groups_snapshot(
        &self,
        _source: &SourceIdentity,
        _available: &[AvailableGroup],
        _registered_jids: &HashSet<String>,
    ) -> talon_core::Result<()> {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_tasks_changed(&self) {
        self.tasks_changed.fetch_add(1, Ordering::SeqCst);
    }
}

struct Env {
    watcher: IpcWatcher,
    db: Db,
    host: Arc<DbHost>,
    dir: tempfile::TempDir,
}

fn env() -> Env {
    env_with(|_| {})
}

fn env_with(tune: impl FnOnce(&mut IpcWatcherConfig)) -> Env {
    let db = Db::open_in_memory().expect("in-memory db");
    let host = Arc::new(DbHost::new(db.clone()));
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = IpcWatcherConfig::new(dir.path(), chrono_tz::UTC);
    cfg.poll_interval = Duration::from_millis(20);
    tune(&mut cfg);
    // default authorizer == talon_security::ipc_authz
    let watcher = IpcWatcher::new(
        cfg,
        db.clone(),
        host.clone(),
        Arc::new(DbAuditSink::new(db.clone())),
    );
    Env {
        watcher,
        db,
        host,
        dir,
    }
}

fn id(folder: &str, is_main: bool) -> SourceIdentity {
    SourceIdentity {
        ipc_key: folder.into(),
        folder: folder.into(),
        is_main,
    }
}

fn once(target: &str) -> IpcTask {
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

fn seed(db: &Db, id: &str, folder: &str, jid: &str) {
    db.create_task(&ScheduledTask {
        id: id.into(),
        group_folder: folder.into(),
        chat_jid: jid.into(),
        prompt: "p".into(),
        script: None,
        schedule_type: ScheduleType::Once,
        schedule_value: "2025-06-01T00:00:00".into(),
        context_mode: ContextMode::Isolated,
        next_run: Some("2025-06-01T00:00:00.000Z".into()),
        last_run: None,
        last_result: None,
        status: TaskStatus::Active,
        created_at: "2024-01-01T00:00:00.000Z".into(),
    })
    .unwrap();
}

#[tokio::test]
async fn schedule_task_authorization_with_real_policy_and_db() {
    let e = env();
    let main = id("whatsapp_main", true);
    let other = id("other-group", false);
    assert!(
        e.watcher
            .process_task(&main, once("other@g.us"))
            .await
            .is_applied()
    );
    assert!(
        e.watcher
            .process_task(&other, once("other@g.us"))
            .await
            .is_applied()
    );
    assert!(matches!(
        e.watcher.process_task(&other, once("main@g.us")).await,
        IpcOutcome::Denied(_)
    ));
    assert!(matches!(
        e.watcher.process_task(&main, once("unknown@g.us")).await,
        IpcOutcome::Denied(_)
    ));
    let tasks = e.db.get_all_tasks().unwrap();
    assert_eq!(tasks.len(), 2);
    assert!(tasks.iter().all(|t| t.group_folder == "other-group"));
    assert!(
        tasks
            .iter()
            .all(|t| t.context_mode == ContextMode::Isolated)
    );
    assert_eq!(e.host.tasks_changed.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn forged_main_flag_is_not_trusted_by_the_policy() {
    let e = env();
    // identity claims main for a folder that is not the registered main group
    let forged = id("other-group", true);
    assert!(matches!(
        e.watcher.process_task(&forged, once("third@g.us")).await,
        IpcOutcome::Denied(_)
    ));
    assert!(e.db.get_all_tasks().unwrap().is_empty());
}

#[tokio::test]
async fn duplicate_task_id_never_overwrites_with_real_db() {
    let e = env();
    seed(&e.db, "task-main", "whatsapp_main", "main@g.us");
    let mut t = once("other@g.us");
    if let IpcTask::ScheduleTask { task_id, .. } = &mut t {
        *task_id = Some("task-main".into());
    }
    let o = e.watcher.process_task(&id("other-group", false), t).await;
    assert!(!o.is_applied(), "{o:?}");
    assert_eq!(
        e.db.get_task_by_id("task-main")
            .unwrap()
            .unwrap()
            .group_folder,
        "whatsapp_main"
    );
}

#[tokio::test]
async fn pause_resume_cancel_with_real_policy_and_db() {
    let e = env();
    seed(&e.db, "task-main", "whatsapp_main", "main@g.us");
    e.db.set_task_owner("task-main", "whatsapp_main").unwrap();
    seed(&e.db, "task-other", "other-group", "other@g.us");
    e.db.set_task_owner("task-other", "other-group").unwrap();
    let other = id("other-group", false);
    let main = id("whatsapp_main", true);

    let pause = |id: &str| IpcTask::PauseTask {
        task_id: id.into(),
        timestamp: None,
    };
    assert!(
        e.watcher
            .process_task(&other, pause("task-other"))
            .await
            .is_applied()
    );
    assert_eq!(
        e.db.get_task_by_id("task-other").unwrap().unwrap().status,
        TaskStatus::Paused
    );
    assert!(
        !e.watcher
            .process_task(&other, pause("task-main"))
            .await
            .is_applied()
    );
    assert_eq!(
        e.db.get_task_by_id("task-main").unwrap().unwrap().status,
        TaskStatus::Active
    );
    let resume = IpcTask::ResumeTask {
        task_id: "task-other".into(),
        timestamp: None,
    };
    assert!(e.watcher.process_task(&main, resume).await.is_applied());
    assert_eq!(
        e.db.get_task_by_id("task-other").unwrap().unwrap().status,
        TaskStatus::Active
    );
    let cancel = IpcTask::CancelTask {
        task_id: "task-main".into(),
        timestamp: None,
    };
    assert!(
        !e.watcher
            .process_task(&other, cancel.clone())
            .await
            .is_applied()
    );
    assert!(e.db.get_task_by_id("task-main").unwrap().is_some());
    assert!(e.watcher.process_task(&main, cancel).await.is_applied());
    assert!(e.db.get_task_by_id("task-main").unwrap().is_none());
}

#[tokio::test]
async fn register_and_refresh_with_real_policy_and_db() {
    let e = env();
    let reg = |folder: &str| IpcTask::RegisterGroup {
        jid: "new@g.us".into(),
        name: "New Group".into(),
        folder: folder.into(),
        trigger: "@Talon".into(),
        requires_trigger: None,
        container_config: None,
        timestamp: None,
    };
    let other = id("other-group", false);
    let main = id("whatsapp_main", true);
    assert!(
        !e.watcher
            .process_task(&other, reg("new-group"))
            .await
            .is_applied()
    );
    assert!(
        !e.watcher
            .process_task(&main, reg("../../outside"))
            .await
            .is_applied()
    );
    assert!(e.db.get_registered_group("new@g.us").unwrap().is_none());
    assert!(
        e.watcher
            .process_task(&main, reg("new-group"))
            .await
            .is_applied()
    );
    let g = e.db.get_registered_group("new@g.us").unwrap().unwrap();
    assert_eq!(g.folder, "new-group");
    assert!(!g.is_main);

    let refresh = IpcTask::RefreshGroups { timestamp: None };
    assert!(
        !e.watcher
            .process_task(&other, refresh.clone())
            .await
            .is_applied()
    );
    assert!(e.watcher.process_task(&main, refresh).await.is_applied());
    assert_eq!(e.host.snapshots.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn messages_with_real_policy() {
    let e = env();
    let msg = |jid: &str| IpcOutbound::Message {
        chat_jid: jid.into(),
        text: "hi".into(),
        group_folder: None,
        timestamp: None,
    };
    let main = id("whatsapp_main", true);
    let other = id("other-group", false);
    assert!(
        e.watcher
            .process_message(&main, msg("third@g.us"))
            .await
            .is_applied()
    );
    assert!(
        e.watcher
            .process_message(&other, msg("other@g.us"))
            .await
            .is_applied()
    );
    assert!(
        !e.watcher
            .process_message(&other, msg("main@g.us"))
            .await
            .is_applied()
    );
    assert!(
        !e.watcher
            .process_message(&other, msg("unknown@g.us"))
            .await
            .is_applied()
    );
    assert_eq!(e.host.sent.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn end_to_end_scan_with_hash_chained_audit() {
    let e = env();
    let ns = e.dir.path().join("ipc").join("other-group");
    let m = ns.join("messages");
    let t = ns.join("tasks");
    std::fs::create_dir_all(&m).unwrap();
    std::fs::create_dir_all(&t).unwrap();
    std::fs::write(
        m.join("1700000000001-aaaaaa.json"),
        r#"{"type":"message","chatJid":"other@g.us","text":"progress"}"#,
    )
    .unwrap();
    std::fs::write(
        m.join("1700000000002-bbbbbb.json"),
        r#"{"type":"message","chatJid":"main@g.us","text":"escalate?"}"#,
    )
    .unwrap();
    std::fs::write(
        t.join("1700000000003-cccccc.json"),
        r#"{"type":"schedule_task","taskId":"task-1700000000003-cccccc","prompt":"sweep","schedule_type":"cron","schedule_value":"*/15 * * * *","context_mode":"group","targetJid":"other@g.us","createdBy":"other-group"}"#,
    )
    .unwrap();
    std::fs::write(t.join("1700000000004-dddddd.json"), "{garbage").unwrap();

    let stats = e.watcher.scan_once().await;
    assert_eq!(stats.messages_sent, 1);
    assert_eq!(stats.tasks_applied, 1);
    assert_eq!(stats.denied, 1);
    assert_eq!(stats.quarantined, 1);

    let task =
        e.db.get_task_by_id("task-1700000000003-cccccc")
            .unwrap()
            .unwrap();
    assert_eq!(task.group_folder, "other-group");
    assert_eq!(task.context_mode, ContextMode::Group);
    assert!(task.next_run.is_some());

    let audit = e.db.recent_audit(50, Some("ipc.")).unwrap();
    let kinds: Vec<_> = audit.iter().map(|a| a.kind.as_str()).collect();
    assert!(kinds.contains(&"ipc.message.allowed"), "{kinds:?}");
    assert!(kinds.contains(&"ipc.message.denied"), "{kinds:?}");
    assert!(kinds.contains(&"ipc.task.allowed"), "{kinds:?}");
    assert!(kinds.contains(&"ipc.file.rejected"), "{kinds:?}");
    assert!(audit.iter().all(|a| a.actor == "other-group"));
    assert_eq!(e.db.verify_audit_chain().unwrap(), None);
    assert!(
        std::fs::read_dir(e.dir.path().join("ipc").join("errors"))
            .unwrap()
            .next()
            .is_some()
    );
}

fn lane(folder: &str, ipc_key: &str) -> RegisteredGroup {
    RegisteredGroup {
        session_key: Some(ipc_key.into()),
        ipc_key: Some(ipc_key.into()),
        ..group("Copilot", folder, false)
    }
}

fn lane_id(ipc_key: &str) -> SourceIdentity {
    SourceIdentity {
        ipc_key: ipc_key.into(),
        folder: "copilot".into(),
        is_main: false,
    }
}

/// Env with the CoPilot lanes (in-memory, like the HTTP channel keeps them).
fn copilot_env() -> Env {
    copilot_env_with(|_| {})
}

fn copilot_env_with(tune: impl FnOnce(&mut IpcWatcherConfig)) -> Env {
    let e = env_with(tune);
    {
        let mut g = e.host.groups.lock().unwrap();
        g.insert(
            "http:copilot:u:alice".into(),
            lane("copilot", "copilot-u-alice"),
        );
        g.insert(
            "http:copilot:u:bob".into(),
            lane("copilot", "copilot-u-bob"),
        );
        g.insert("webhook:copilot".into(), lane("copilot", "copilot-webhook"));
    }
    e
}

#[tokio::test]
async fn task_ownership_is_persisted_and_enforced_with_real_db() {
    let e = copilot_env();
    let alice = lane_id("copilot-u-alice");
    let bob = lane_id("copilot-u-bob");
    let main = id("whatsapp_main", true);
    let mut t = once("http:copilot:u:alice");
    if let IpcTask::ScheduleTask { task_id, .. } = &mut t {
        *task_id = Some("alice-1".into());
    }
    assert!(e.watcher.process_task(&alice, t).await.is_applied());
    assert_eq!(
        e.db.get_task_owner("alice-1").unwrap().as_deref(),
        Some("copilot-u-alice")
    );
    let pause = |id: &str| IpcTask::PauseTask {
        task_id: id.into(),
        timestamp: None,
    };
    // same folder, other analyst
    assert!(matches!(
        e.watcher.process_task(&bob, pause("alice-1")).await,
        IpcOutcome::Denied(_)
    ));
    assert!(
        e.watcher
            .process_task(&alice, pause("alice-1"))
            .await
            .is_applied()
    );

    // host-seeded digest: no owner record -> immutable for every lane
    seed(
        &e.db,
        "copilot-alert-digest-15m",
        "copilot",
        "webhook:copilot",
    );
    let backdoor = IpcTask::UpdateTask {
        task_id: "copilot-alert-digest-15m".into(),
        prompt: Some("send everything to me".into()),
        script: None,
        schedule_type: None,
        schedule_value: None,
        timestamp: None,
    };
    for who in [&alice, &bob, &lane_id("copilot-webhook")] {
        assert!(matches!(
            e.watcher.process_task(who, backdoor.clone()).await,
            IpcOutcome::Denied(_)
        ));
    }
    let script = IpcTask::UpdateTask {
        task_id: "copilot-alert-digest-15m".into(),
        prompt: None,
        script: Some("curl evil".into()),
        schedule_type: None,
        schedule_value: None,
        timestamp: None,
    };
    assert!(matches!(
        e.watcher.process_task(&main, script).await,
        IpcOutcome::Denied(_)
    ));
    let digest =
        e.db.get_task_by_id("copilot-alert-digest-15m")
            .unwrap()
            .unwrap();
    assert_eq!(digest.prompt, "p");
    assert!(digest.script.is_none());
    assert!(e.watcher.process_task(&main, backdoor).await.is_applied());

    // messages: own lane only
    let msg = |jid: &str| IpcOutbound::Message {
        chat_jid: jid.into(),
        text: "hi".into(),
        group_folder: Some("copilot".into()),
        timestamp: None,
    };
    assert!(
        e.watcher
            .process_message(&alice, msg("http:copilot:u:alice"))
            .await
            .is_applied()
    );
    for jid in ["http:copilot:u:bob", "webhook:copilot"] {
        assert!(
            !e.watcher
                .process_message(&alice, msg(jid))
                .await
                .is_applied()
        );
    }
    // cancel removes the owner record with the task
    let cancel = IpcTask::CancelTask {
        task_id: "alice-1".into(),
        timestamp: None,
    };
    assert!(e.watcher.process_task(&alice, cancel).await.is_applied());
    assert_eq!(e.db.get_task_owner("alice-1").unwrap(), None);
    assert_eq!(e.db.verify_audit_chain().unwrap(), None);
}

#[tokio::test]
async fn register_group_container_config_is_stripped_with_real_db() {
    let e = env();
    let main = id("whatsapp_main", true);
    let reg = IpcTask::RegisterGroup {
        jid: "new@g.us".into(),
        name: "New Group".into(),
        folder: "new-group".into(),
        trigger: "@Talon".into(),
        requires_trigger: None,
        container_config: Some(talon_core::types::ContainerConfig {
            additional_mounts: vec![talon_core::types::AdditionalMount {
                host_path: "/srv/talon".into(),
                container_path: Some("project".into()),
                readonly: false,
            }],
            ..Default::default()
        }),
        timestamp: None,
    };
    assert!(e.watcher.process_task(&main, reg).await.is_applied());
    let g = e.db.get_registered_group("new@g.us").unwrap().unwrap();
    assert_eq!(g.container_config, None);
    let audit = e.db.recent_audit(10, Some("ipc.register_group")).unwrap();
    assert_eq!(audit[0].details["containerConfigIgnored"], true);
}

/// N-3 with the real database: owner-based task quota, prompt cap, minimum
/// frequency, the executed-operation rate limit with its summary row (in
/// the hash-chained audit log), and the per-lane snapshot query.
#[tokio::test]
async fn lane_task_quotas_with_real_db() {
    let e = copilot_env_with(|c| {
        c.max_tasks_per_lane = 3;
        c.max_task_ops_per_window = 5;
        c.task_op_window = Duration::from_secs(3600);
    });
    let alice = lane_id("copilot-u-alice");
    let bob = lane_id("copilot-u-bob");
    let sched = |target: &str, id: &str, ty: ScheduleType, value: &str, prompt: String| {
        IpcTask::ScheduleTask {
            task_id: Some(id.into()),
            prompt,
            script: None,
            schedule_type: ty,
            schedule_value: value.into(),
            context_mode: None,
            target_jid: target.into(),
            created_by: None,
            timestamp: None,
        }
    };
    const ALICE: &str = "http:copilot:u:alice";
    // the reviewer's payload: every-minute cron, 250 KiB prompt
    let o = e
        .watcher
        .process_task(
            &alice,
            sched(
                ALICE,
                "flood",
                ScheduleType::Cron,
                "* * * * *",
                "A".repeat(250 * 1024),
            ),
        )
        .await;
    assert!(
        matches!(o, IpcOutcome::Denied(ref r) if r.contains("prompt")),
        "{o:?}"
    );
    let o = e
        .watcher
        .process_task(
            &alice,
            sched(ALICE, "flood", ScheduleType::Cron, "* * * * *", "p".into()),
        )
        .await;
    assert!(
        matches!(o, IpcOutcome::Denied(ref r) if r.contains("minimum")),
        "{o:?}"
    );
    for i in 0..3 {
        let id = format!("alice-{i}");
        let o = e
            .watcher
            .process_task(
                &alice,
                sched(ALICE, &id, ScheduleType::Cron, "*/15 * * * *", "p".into()),
            )
            .await;
        assert!(o.is_applied(), "{o:?}");
    }
    assert_eq!(e.db.count_tasks_owned_by("copilot-u-alice").unwrap(), 3);
    let o = e
        .watcher
        .process_task(
            &alice,
            sched(
                ALICE,
                "alice-3",
                ScheduleType::Once,
                "2026-06-01T00:00:00",
                "p".into(),
            ),
        )
        .await;
    assert!(
        matches!(o, IpcOutcome::Denied(ref r) if r.contains("limit 3")),
        "{o:?}"
    );
    assert!(e.db.get_task_by_id("alice-3").unwrap().is_none());

    // bob's lane is independent; the snapshot query separates the lanes
    let o = e
        .watcher
        .process_task(
            &bob,
            sched(
                "http:copilot:u:bob",
                "bob-0",
                ScheduleType::Interval,
                "900000",
                "p".into(),
            ),
        )
        .await;
    assert!(o.is_applied(), "{o:?}");
    let alice_tasks = e.db.get_tasks_for_jids(&[ALICE.to_string()]).unwrap();
    assert_eq!(alice_tasks.len(), 3);
    assert!(alice_tasks.iter().all(|t| t.chat_jid == ALICE));
    assert_eq!(
        e.db.get_tasks_for_jids(&["http:copilot:u:bob".to_string()])
            .unwrap()
            .len(),
        1
    );

    // executed operations: 3 creates so far; 2 more pass, then throttled
    for (i, expect) in [(0, true), (1, true), (2, false), (0, false)] {
        let o = e
            .watcher
            .process_task(
                &alice,
                IpcTask::PauseTask {
                    task_id: format!("alice-{i}"),
                    timestamp: None,
                },
            )
            .await;
        assert_eq!(o.is_applied(), expect, "{i}: {o:?}");
    }
    assert_eq!(
        e.db.get_task_by_id("alice-2").unwrap().unwrap().status,
        TaskStatus::Active
    );
    // shutting the watcher down writes the pending summary row
    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();
    e.watcher.run(token).await;
    let rows = e.db.recent_audit(200, Some("ipc.")).unwrap();
    let throttled: Vec<_> = rows
        .iter()
        .filter(|r| r.kind == "ipc.task.throttled")
        .collect();
    assert_eq!(throttled.len(), 1, "{throttled:?}");
    assert_eq!(throttled[0].details["ipcKey"], "copilot-u-alice");
    assert_eq!(throttled[0].details["throttled_since_last"], 2);
    let quota_denials = rows
        .iter()
        .filter(|r| r.kind == "ipc.task.denied" && r.details["stage"] == "quota")
        .count();
    assert_eq!(quota_denials, 3);
    assert_eq!(e.db.verify_audit_chain().unwrap(), None);
}
