//! Test fakes: in-memory task store, recording host, fixtures.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use talon_core::audit::MemoryAuditSink;
use talon_core::types::{
    AvailableGroup, ContextMode, RegisteredGroup, ScheduleType, ScheduledTask, TaskStatus,
    TaskUpdate,
};
use talon_core::{Error, Result};

use crate::authz::FnAuthorizer;
use crate::config::IpcWatcherConfig;
use crate::host::{IpcHost, SourceIdentity};
use crate::store::TaskStore;
use crate::watcher::IpcWatcher;

pub(crate) fn group(folder: &str, ipc_key: Option<&str>, is_main: bool) -> RegisteredGroup {
    RegisteredGroup {
        name: folder.into(),
        folder: folder.into(),
        trigger: "@Andy".into(),
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

/// The three groups of `ipc-auth.test.ts`.
pub(crate) fn groups_fixture() -> HashMap<String, RegisteredGroup> {
    let mut main = group("whatsapp_main", None, true);
    main.name = "Main".into();
    main.trigger = "always".into();
    let mut other = group("other-group", None, false);
    other.name = "Other".into();
    let mut third = group("third-group", None, false);
    third.name = "Third".into();
    HashMap::from([
        ("main@g.us".to_string(), main),
        ("other@g.us".to_string(), other),
        ("third@g.us".to_string(), third),
    ])
}

pub(crate) fn task(id: &str, folder: &str, jid: &str, status: TaskStatus) -> ScheduledTask {
    ScheduledTask {
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
        status,
        created_at: "2024-01-01T00:00:00.000Z".into(),
    }
}

#[derive(Debug, Default)]
pub(crate) struct MemoryTaskStore {
    pub tasks: Mutex<BTreeMap<String, ScheduledTask>>,
    pub fail: AtomicBool,
}

impl MemoryTaskStore {
    pub fn all(&self) -> Vec<ScheduledTask> {
        self.tasks.lock().unwrap().values().cloned().collect()
    }
    pub fn get(&self, id: &str) -> Option<ScheduledTask> {
        self.tasks.lock().unwrap().get(id).cloned()
    }
    pub fn insert(&self, t: ScheduledTask) {
        self.tasks.lock().unwrap().insert(t.id.clone(), t);
    }
    fn check(&self) -> Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            Err(Error::Db("disk on fire".into()))
        } else {
            Ok(())
        }
    }
}

impl TaskStore for MemoryTaskStore {
    fn create_task(&self, task: &ScheduledTask) -> Result<()> {
        self.check()?;
        let mut m = self.tasks.lock().unwrap();
        if m.contains_key(&task.id) {
            return Err(Error::Db("UNIQUE constraint failed".into()));
        }
        m.insert(task.id.clone(), task.clone());
        Ok(())
    }
    fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        self.check()?;
        Ok(self.get(id))
    }
    fn update_task(&self, id: &str, u: &TaskUpdate) -> Result<()> {
        self.check()?;
        let mut m = self.tasks.lock().unwrap();
        let Some(t) = m.get_mut(id) else {
            return Ok(());
        };
        if let Some(p) = &u.prompt {
            t.prompt = p.clone();
        }
        if let Some(s) = &u.script {
            t.script = s.clone();
        }
        if let Some(st) = u.schedule_type {
            t.schedule_type = st;
        }
        if let Some(v) = &u.schedule_value {
            t.schedule_value = v.clone();
        }
        if let Some(c) = u.context_mode {
            t.context_mode = c;
        }
        if let Some(n) = &u.next_run {
            t.next_run = n.clone();
        }
        if let Some(s) = u.status {
            t.status = s;
        }
        Ok(())
    }
    fn delete_task(&self, id: &str) -> Result<()> {
        self.check()?;
        self.tasks.lock().unwrap().remove(id);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(crate) struct FakeHost {
    pub groups: Mutex<HashMap<String, RegisteredGroup>>,
    pub sent: Mutex<Vec<(String, String)>>,
    pub registered: Mutex<Vec<(String, RegisteredGroup)>>,
    pub syncs: AtomicUsize,
    pub snapshots: Mutex<Vec<(SourceIdentity, usize, usize)>>,
    pub tasks_changed: AtomicUsize,
    pub fail_send: AtomicBool,
    pub send_delay: Mutex<Option<Duration>>,
    pub available: Mutex<Vec<AvailableGroup>>,
}

impl FakeHost {
    pub fn with_groups(groups: HashMap<String, RegisteredGroup>) -> Self {
        Self {
            groups: Mutex::new(groups),
            ..Self::default()
        }
    }
    pub fn sent(&self) -> Vec<(String, String)> {
        self.sent.lock().unwrap().clone()
    }
    pub fn registered_groups_snapshot(&self) -> HashMap<String, RegisteredGroup> {
        self.groups.lock().unwrap().clone()
    }
}

#[async_trait]
impl IpcHost for FakeHost {
    async fn send_message(&self, jid: &str, text: &str) -> Result<()> {
        let delay = *self.send_delay.lock().unwrap();
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        if self.fail_send.load(Ordering::SeqCst) {
            return Err(Error::Channel(format!("no channel for JID: {jid}")));
        }
        self.sent.lock().unwrap().push((jid.into(), text.into()));
        Ok(())
    }
    fn registered_groups(&self) -> HashMap<String, RegisteredGroup> {
        self.groups.lock().unwrap().clone()
    }
    async fn register_group(&self, jid: &str, group: RegisteredGroup) -> Result<()> {
        self.groups
            .lock()
            .unwrap()
            .insert(jid.into(), group.clone());
        self.registered.lock().unwrap().push((jid.into(), group));
        Ok(())
    }
    async fn sync_groups(&self, _force: bool) -> Result<()> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn available_groups(&self) -> Vec<AvailableGroup> {
        self.available.lock().unwrap().clone()
    }
    async fn write_groups_snapshot(
        &self,
        source: &SourceIdentity,
        available: &[AvailableGroup],
        registered_jids: &HashSet<String>,
    ) -> Result<()> {
        self.snapshots.lock().unwrap().push((
            source.clone(),
            available.len(),
            registered_jids.len(),
        ));
        Ok(())
    }
    fn on_tasks_changed(&self) {
        self.tasks_changed.fetch_add(1, Ordering::SeqCst);
    }
}

/// Watcher wired to fakes. The policy slot gets a permissive authorizer, so
/// every test exercises the baseline (TypeScript) rules.
pub(crate) struct Harness {
    pub watcher: IpcWatcher,
    pub host: Arc<FakeHost>,
    pub store: Arc<MemoryTaskStore>,
    pub audit: MemoryAuditSink,
    pub dir: tempfile::TempDir,
}

pub(crate) fn allow_all() -> FnAuthorizer {
    FnAuthorizer {
        message: |_, _, _| talon_security::ipc_authz::IpcDecision::Allow,
        task: |_, _, _, _| talon_security::ipc_authz::IpcDecision::Allow,
    }
}

pub(crate) fn harness_with(tune: impl FnOnce(&mut IpcWatcherConfig)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = IpcWatcherConfig::new(dir.path(), chrono_tz::UTC);
    cfg.poll_interval = Duration::from_millis(20);
    tune(&mut cfg);
    let host = Arc::new(FakeHost::with_groups(groups_fixture()));
    let store = Arc::new(MemoryTaskStore::default());
    let audit = MemoryAuditSink::default();
    let watcher = IpcWatcher::new(
        cfg,
        Arc::clone(&store),
        host.clone(),
        Arc::new(audit.clone()),
    )
    .with_authorizer(Arc::new(allow_all()));
    Harness {
        watcher,
        host,
        store,
        audit,
        dir,
    }
}

pub(crate) fn harness() -> Harness {
    harness_with(|_| {})
}

pub(crate) fn main_id() -> SourceIdentity {
    SourceIdentity {
        ipc_key: "whatsapp_main".into(),
        folder: "whatsapp_main".into(),
        is_main: true,
    }
}

pub(crate) fn other_id() -> SourceIdentity {
    SourceIdentity {
        ipc_key: "other-group".into(),
        folder: "other-group".into(),
        is_main: false,
    }
}

pub(crate) fn third_id() -> SourceIdentity {
    SourceIdentity {
        ipc_key: "third-group".into(),
        folder: "third-group".into(),
        is_main: false,
    }
}
