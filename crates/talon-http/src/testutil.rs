//! Test doubles: a recording [`ChannelHost`], an in-memory [`HttpStore`],
//! a scripted [`PalaceRunner`] and request helpers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response};
use serde_json::Value;
use talon_core::audit::MemoryAuditSink;
use talon_core::channel::{ChannelHost, QueueStatus};
use talon_core::types::{ChatMetadata, NewMessage, RegisteredGroup, ScheduledTask, SessionRow};
use talon_core::{Error, Result};
use talon_db::Investigation;
use tower::ServiceExt;

use crate::auth::test_support::LocalVerifier;
use crate::config::{ApiKey, HttpConfig};
use crate::palace::{PalaceError, PalaceRunner};
use crate::server::{HttpDeps, HttpState, router};
use crate::store::HttpStore;

pub(crate) const KEY: &str = "test-key-0123456789abcdef";

/// Recording host with a live registry.
#[derive(Default)]
pub(crate) struct FakeHost {
    pub groups: Mutex<HashMap<String, RegisteredGroup>>,
    pub messages: Mutex<Vec<(String, NewMessage)>>,
    pub metadata: Mutex<Vec<ChatMetadata>>,
    pub registrations: Mutex<Vec<(String, bool)>>,
    pub unregistered: Mutex<Vec<String>>,
    pub cleared: Mutex<Vec<String>>,
    pub notified: AtomicUsize,
    /// When true, `clear_session` only succeeds for registered JIDs.
    pub strict_clear: bool,
}

impl FakeHost {
    pub fn registrations(&self) -> Vec<(String, bool)> {
        self.registrations.lock().unwrap().clone()
    }
    pub fn cleared(&self) -> Vec<String> {
        self.cleared.lock().unwrap().clone()
    }
    pub fn unregistered(&self) -> Vec<String> {
        self.unregistered.lock().unwrap().clone()
    }
    pub fn metadata(&self) -> Vec<ChatMetadata> {
        self.metadata.lock().unwrap().clone()
    }
    pub fn messages(&self) -> Vec<(String, NewMessage)> {
        self.messages.lock().unwrap().clone()
    }
    pub fn group(&self, jid: &str) -> Option<RegisteredGroup> {
        self.groups.lock().unwrap().get(jid).cloned()
    }
}

#[async_trait]
impl ChannelHost for FakeHost {
    async fn on_message(&self, chat_jid: &str, message: NewMessage) {
        self.messages
            .lock()
            .unwrap()
            .push((chat_jid.to_string(), message));
    }
    async fn on_chat_metadata(&self, metadata: ChatMetadata) {
        self.metadata.lock().unwrap().push(metadata);
    }
    fn registered_groups(&self) -> HashMap<String, RegisteredGroup> {
        self.groups.lock().unwrap().clone()
    }
    async fn register_group(&self, jid: &str, group: RegisteredGroup, persist: bool) {
        self.groups.lock().unwrap().insert(jid.to_string(), group);
        self.registrations
            .lock()
            .unwrap()
            .push((jid.to_string(), persist));
    }
    async fn unregister_group(&self, jid: &str) -> bool {
        self.unregistered.lock().unwrap().push(jid.to_string());
        self.groups.lock().unwrap().remove(jid).is_some()
    }
    async fn clear_session(&self, jid: &str) -> bool {
        self.cleared.lock().unwrap().push(jid.to_string());
        !self.strict_clear || self.groups.lock().unwrap().contains_key(jid)
    }
    fn notify_tasks_changed(&self) {
        self.notified.fetch_add(1, Ordering::SeqCst);
    }
    fn queue_status(&self) -> QueueStatus {
        QueueStatus {
            active_containers: 1,
            max_containers: 5,
            waiting_groups: 0,
            active_jids: vec!["http:copilot".into()],
        }
    }
}

/// In-memory store; `fail_investigations` makes investigation writes fail.
#[derive(Default)]
pub(crate) struct MemoryStore {
    pub tasks: Mutex<Vec<ScheduledTask>>,
    pub sessions: Mutex<Vec<SessionRow>>,
    pub investigations: Mutex<Vec<Investigation>>,
    pub fail_investigations: bool,
}

impl MemoryStore {
    pub fn get_investigation_sync(&self, id: &str) -> Option<Investigation> {
        HttpStore::get_investigation(self, id).unwrap()
    }
    pub fn get_task_by_id_sync(&self, id: &str) -> Option<ScheduledTask> {
        HttpStore::get_task_by_id(self, id).unwrap()
    }
}

impl HttpStore for MemoryStore {
    fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        Ok(self
            .tasks
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.id == id)
            .cloned())
    }
    fn create_task(&self, task: &ScheduledTask) -> Result<()> {
        let mut tasks = self.tasks.lock().unwrap();
        if tasks.iter().any(|t| t.id == task.id) {
            return Err(Error::Db("UNIQUE constraint failed".into()));
        }
        tasks.push(task.clone());
        Ok(())
    }
    fn delete_task(&self, id: &str) -> Result<()> {
        self.tasks.lock().unwrap().retain(|t| t.id != id);
        Ok(())
    }
    fn get_tasks_for_group(&self, group_folder: &str) -> Result<Vec<ScheduledTask>> {
        Ok(self
            .tasks
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.group_folder == group_folder)
            .cloned()
            .collect())
    }
    fn get_session_rows(&self) -> Result<Vec<SessionRow>> {
        Ok(self.sessions.lock().unwrap().clone())
    }
    fn upsert_investigation(&self, inv: &Investigation) -> Result<()> {
        if self.fail_investigations {
            return Err(Error::Db("disk full".into()));
        }
        let mut list = self.investigations.lock().unwrap();
        list.retain(|i| i.id != inv.id);
        list.push(inv.clone());
        Ok(())
    }
    fn get_investigation(&self, id: &str) -> Result<Option<Investigation>> {
        Ok(self
            .investigations
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.id == id)
            .cloned())
    }
    fn list_investigations(&self, limit: usize) -> Result<Vec<Investigation>> {
        let mut list = self.investigations.lock().unwrap().clone();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        list.truncate(limit);
        Ok(list)
    }
    fn latest_investigation_for_alert(&self, alert_id: &str) -> Result<Option<Investigation>> {
        Ok(self
            .list_investigations(usize::MAX)?
            .into_iter()
            .find(|i| i.alert_id == alert_id))
    }
}

/// Palace runner returning a canned response and recording requests.
pub(crate) struct FakePalace {
    pub requests: Mutex<Vec<Value>>,
    pub response: Mutex<Option<std::result::Result<Value, PalaceError>>>,
}

impl Default for FakePalace {
    fn default() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(None),
        }
    }
}

impl FakePalace {
    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl PalaceRunner for FakePalace {
    async fn call(&self, request: Value) -> std::result::Result<Value, PalaceError> {
        self.requests.lock().unwrap().push(request.clone());
        match self.response.lock().unwrap().take() {
            Some(r) => r,
            None => Ok(serde_json::json!({ "ok": true, "op": request["op"] })),
        }
    }
}

/// A fully wired test harness.
pub(crate) struct Harness {
    pub state: HttpState,
    pub host: Arc<FakeHost>,
    pub store: Arc<MemoryStore>,
    pub palace: Arc<FakePalace>,
    pub audit: MemoryAuditSink,
    pub _dir: tempfile::TempDir,
}

pub(crate) fn config_in(root: &Path) -> HttpConfig {
    let mut cfg = HttpConfig::new(root);
    cfg.api_key = ApiKey::new(KEY);
    cfg.port = 0;
    cfg.bind = "127.0.0.1".parse().unwrap();
    cfg
}

impl Harness {
    pub fn new() -> Self {
        Self::with(|_| {}, MemoryStore::default(), FakeHost::default())
    }

    pub fn with_config(f: impl FnOnce(&mut HttpConfig)) -> Self {
        Self::with(f, MemoryStore::default(), FakeHost::default())
    }

    pub fn with(f: impl FnOnce(&mut HttpConfig), store: MemoryStore, host: FakeHost) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config_in(dir.path());
        f(&mut cfg);
        let host = Arc::new(host);
        let store = Arc::new(store);
        let palace = Arc::new(FakePalace::default());
        let audit = MemoryAuditSink::default();
        let deps = HttpDeps {
            host: host.clone(),
            store: store.clone(),
            audit: Arc::new(audit.clone()),
            verifier: Arc::new(LocalVerifier),
            palace: palace.clone(),
        };
        Self {
            state: HttpState::new(cfg, deps),
            host,
            store,
            palace,
            audit,
            _dir: dir,
        }
    }

    pub fn root(&self) -> &Path {
        self._dir.path()
    }

    pub fn router(&self) -> Router {
        router(self.state.clone())
    }

    pub async fn send(&self, req: Request<Body>) -> Response<Body> {
        self.router().oneshot(req).await.unwrap()
    }

    pub fn audit_kinds(&self) -> Vec<String> {
        self.audit.snapshot().into_iter().map(|e| e.kind).collect()
    }
}

/// Request builder with a peer address and (optionally) the API key.
pub(crate) fn request(
    method: &str,
    uri: &str,
    body: Option<&str>,
    key: Option<&str>,
) -> Request<Body> {
    request_from(method, uri, body, key, "198.51.100.7:40000")
}

pub(crate) fn request_from(
    method: &str,
    uri: &str,
    body: Option<&str>,
    key: Option<&str>,
    peer: &str,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(k) = key {
        b = b.header("x-api-key", k);
    }
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    let mut req = b
        .body(body.map_or_else(Body::empty, |s| Body::from(s.to_string())))
        .unwrap();
    let addr: SocketAddr = peer.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

pub(crate) fn authed(method: &str, uri: &str, body: Option<&str>) -> Request<Body> {
    request(method, uri, body, Some(KEY))
}

pub(crate) async fn body_json(res: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(&bytes)))
}

pub(crate) async fn body_text(res: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}
