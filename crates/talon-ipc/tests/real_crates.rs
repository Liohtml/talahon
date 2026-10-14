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

/// Host backed by the real database for registrations (like `index.ts`).
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
    let db = Db::open_in_memory().expect("in-memory db");
    let host = Arc::new(DbHost::new(db.clone()));
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = IpcWatcherConfig::new(dir.path(), chrono_tz::UTC);
    cfg.poll_interval = Duration::from_millis(20);
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
    seed(&e.db, "task-other", "other-group", "other@g.us");
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
        trigger: "@Andy".into(),
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
