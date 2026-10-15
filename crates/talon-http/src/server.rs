//! The axum application: shared state, middleware and request handlers.
//!
//! Middleware, outermost first: response counting, security headers,
//! panic containment, CORS (answers preflights before authentication),
//! API-key authentication (everything except `GET /health`), body limit.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, QueryRejection};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use futures::FutureExt;
use serde_json::{Map, Value, json};
use talon_core::audit::{SharedAuditSink, event};
use talon_core::channel::ChannelHost;
use talon_core::time::now_iso;
use talon_core::types::{
    AdditionalMount, ChatMetadata, ContainerConfig, NewMessage, RegisteredGroup,
};
use tokio::sync::Mutex as AsyncMutex;

use crate::auth::{AuthThrottle, KeyVerifier, SecurityKeyVerifier};
use crate::config::HttpConfig;
use crate::files;
use crate::investigate::{
    self, InvestigationRequest, investigation_prompt, investigation_record, investigation_task,
    is_duplicate, job_id,
};
use crate::lanes::{LaneIds, OpenError, StreamRegistry, USER_SESSION_KEY_PREFIX, UserId};
use crate::metrics::{self, Gauges, Metrics};
use crate::palace::{
    DisabledPalaceRunner, PalaceError, PalaceRunner, ScriptPalaceRunner, add_lesson_request,
    forget_request, search_request,
};
use crate::sse::{WriterGuard, WriterStream};
use crate::store::{HttpStore, run_blocking};
use crate::validate::{
    LESSON_TYPES, MAX_LESSON_CHARS, MAX_QUERY_CHARS, is_valid_customer_code, is_valid_drawer_id,
    is_valid_investigation_id, is_valid_lesson_type, is_valid_template_name, is_valid_triggered_by,
    parse_alert_id, sanitize_label, truncate_chars,
};

/// Mounts every CoPilot lane gets (`(directory under project root, read-only)`).
/// `mempalace-data` stays read-write for the `mcp-palace` MCP server: the
/// container entrypoint chowns it to `mcp-palace`, so the agent uid cannot
/// reach it, and the host never runs palace code against it by default
/// (MYTH-01, see [`crate::palace`]).
const COPILOT_MOUNTS: &[(&str, bool)] = &[
    ("siem", true),
    ("mysql", true),
    ("copilot-mcp", true),
    ("wazuh-mcp", true),
    ("velociraptor-mcp", true),
    ("mempalace", true),
    ("mempalace-data", false),
    ("shuffle-mcp", true),
    ("cve-mcp", true),
];
/// Max characters of a user display name kept in a lane name.
const MAX_LABEL_CHARS: usize = 64;
/// Default/maximum page size of `GET /investigations`.
const DEFAULT_INVESTIGATIONS_LIMIT: usize = 50;
const MAX_INVESTIGATIONS_LIMIT: usize = 500;
/// Investigations sampled for the `/metrics` status gauge.
const METRICS_INVESTIGATION_WINDOW: usize = 1_000;
/// Max characters of a request path recorded in an audit event.
const MAX_AUDIT_PATH_CHARS: usize = 256;

/// Everything the HTTP channel talks to.
pub struct HttpDeps {
    /// Host orchestrator callbacks.
    pub host: Arc<dyn ChannelHost>,
    /// Persistence (normally a [`talon_db::Db`]).
    pub store: Arc<dyn HttpStore>,
    /// Audit sink for security-relevant decisions.
    pub audit: SharedAuditSink,
    /// API key verification backend.
    pub verifier: Arc<dyn KeyVerifier>,
    /// MemPalace bridge ([`DisabledPalaceRunner`] unless one is supplied).
    pub palace: Arc<dyn PalaceRunner>,
}

impl HttpDeps {
    /// Production wiring: the given store and [`SecurityKeyVerifier`].
    ///
    /// The palace is **disabled** (`/palace/*` answers 503) until a runner is
    /// supplied with [`Self::with_palace`] — normally a
    /// [`crate::CommandPalaceRunner`] that runs the palace in a hardened
    /// container. Only if the operator set `TALON_PALACE_HOST_EXEC=unsafe`
    /// ([`HttpConfig::palace_host_exec`]) does the default become a
    /// [`ScriptPalaceRunner`] executing `palace-call.sh` on the host
    /// (dangerous, MYTH-01).
    pub fn new(
        config: &HttpConfig,
        host: Arc<dyn ChannelHost>,
        store: Arc<dyn HttpStore>,
        audit: SharedAuditSink,
    ) -> Self {
        Self {
            host,
            store,
            audit,
            verifier: Arc::new(SecurityKeyVerifier),
            palace: default_palace_runner(config),
        }
    }

    /// Use `palace` for the `/palace/*` endpoints (replaces the default,
    /// including the `TALON_PALACE_HOST_EXEC=unsafe` script runner).
    pub fn with_palace(mut self, palace: Arc<dyn PalaceRunner>) -> Self {
        self.palace = palace;
        self
    }
}

/// [`DisabledPalaceRunner`], or the host script runner when the operator
/// explicitly opted into host execution.
fn default_palace_runner(config: &HttpConfig) -> Arc<dyn PalaceRunner> {
    if !config.palace_host_exec {
        return Arc::new(DisabledPalaceRunner);
    }
    tracing::warn!(
        script = %config.palace_script.display(),
        "TALON_PALACE_HOST_EXEC=unsafe: MemPalace calls run palace-call.sh ON THE HOST against \
         agent-writable mempalace-data; a compromised agent can get code executed as this user. \
         Use a containerized palace runner instead"
    );
    Arc::new(ScriptPalaceRunner::new(
        config.palace_script.clone(),
        config.palace_timeout,
        config.palace_max_output_bytes,
        config.palace_max_concurrency,
    ))
}

impl fmt::Debug for HttpDeps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpDeps").finish_non_exhaustive()
    }
}

/// A user lane could not be created because the lane cap was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneLimitReached;

pub(crate) struct Shared {
    pub config: HttpConfig,
    pub lanes: LaneIds,
    pub host: Arc<dyn ChannelHost>,
    pub store: Arc<dyn HttpStore>,
    pub audit: SharedAuditSink,
    pub verifier: Arc<dyn KeyVerifier>,
    pub palace: Arc<dyn PalaceRunner>,
    pub streams: Arc<StreamRegistry>,
    pub throttle: AuthThrottle,
    pub metrics: Metrics,
    pub started_at: Instant,
    base_group: Mutex<Option<RegisteredGroup>>,
    last_seen: Mutex<HashMap<String, Instant>>,
    lane_lock: AsyncMutex<()>,
    investigate_lock: AsyncMutex<()>,
    last_job_millis: AtomicI64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Cloneable handle to the channel's state. Build the server with
/// [`router`]; the [`crate::HttpChannel`] shares the same state.
#[derive(Clone)]
pub struct HttpState(pub(crate) Arc<Shared>);

impl fmt::Debug for HttpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpState")
            .field("config", &self.0.config)
            .finish_non_exhaustive()
    }
}

impl HttpState {
    /// Assemble the state from configuration and dependencies.
    pub fn new(config: HttpConfig, deps: HttpDeps) -> Self {
        let throttle = AuthThrottle::new(config.auth_max_failures, config.auth_window);
        Self(Arc::new(Shared {
            lanes: LaneIds::new(&config.base_jid),
            throttle,
            config,
            host: deps.host,
            store: deps.store,
            audit: deps.audit,
            verifier: deps.verifier,
            palace: deps.palace,
            streams: Arc::new(StreamRegistry::default()),
            metrics: Metrics::default(),
            started_at: Instant::now(),
            base_group: Mutex::new(None),
            last_seen: Mutex::new(HashMap::new()),
            lane_lock: AsyncMutex::new(()),
            investigate_lock: AsyncMutex::new(()),
            last_job_millis: AtomicI64::new(0),
        }))
    }

    /// The channel configuration.
    pub fn config(&self) -> &HttpConfig {
        &self.0.config
    }

    /// The lane JIDs.
    pub fn lanes(&self) -> &LaneIds {
        &self.0.lanes
    }

    /// Register the chat and investigation lanes (persisted) and capture the
    /// template per-user lanes are cloned from.
    pub async fn register_base_lanes(&self) {
        let s = &self.0;
        let group = base_group(&s.config);
        // trusted_session_commands is safe on the chat lanes because every
        // request to this server is authenticated with the API key.
        let chat = RegisteredGroup {
            trusted_session_commands: true,
            ..group.clone()
        };
        *lock(&s.base_group) = Some(chat.clone());
        s.register_lane(&s.lanes.base, chat, true).await;
        // Investigation lane: same folder and mounts, separate ephemeral
        // session; nothing types slash commands at it. Its state directory
        // (keyed by this session key) is where `GET /evals` reads from.
        let key = s.config.investigation_session_key();
        let investigate = RegisteredGroup {
            name: "CoPilot Investigations".to_string(),
            session_key: Some(key.to_string()),
            ipc_key: Some(key.to_string()),
            ephemeral_session: true,
            ..group
        };
        s.register_lane(&s.lanes.investigate, investigate, true)
            .await;
    }

    /// Set the template per-user lanes are cloned from (normally captured by
    /// [`Self::register_base_lanes`]).
    pub fn set_base_group(&self, group: RegisteredGroup) {
        *lock(&self.0.base_group) = Some(group);
    }

    /// Resolve (registering on first use) the lane for a validated CoPilot
    /// user id. `None` maps to the shared base lane.
    pub async fn ensure_user_lane(
        &self,
        user_id: Option<&UserId>,
        user_name: Option<&str>,
    ) -> Result<String, LaneLimitReached> {
        self.0.ensure_user_lane(user_id, user_name).await
    }

    /// Every registered per-user lane JID.
    pub fn user_lane_jids(&self) -> Vec<String> {
        self.0.user_lane_jids()
    }

    /// Drop per-user lanes idle for longer than `lane_idle`. Returns the
    /// swept JIDs.
    pub async fn sweep_idle_lanes(&self) -> Vec<String> {
        match Instant::now().checked_sub(self.0.config.lane_idle) {
            Some(cutoff) => self.0.sweep_idle_lanes_before(cutoff).await,
            None => Vec::new(),
        }
    }

    /// Drop per-user lanes whose last traffic is older than `cutoff`.
    pub async fn sweep_idle_lanes_before(&self, cutoff: Instant) -> Vec<String> {
        self.0.sweep_idle_lanes_before(cutoff).await
    }

    /// Seed the paused alert digest task if it does not exist yet.
    pub async fn seed_digest_task(&self) -> talon_core::Result<bool> {
        let folder = self.0.config.group_folder.clone();
        let tz = self.0.config.timezone;
        run_blocking(&self.0.store, move |st| {
            investigate::seed_digest_task(st, &folder, tz, Utc::now())
        })
        .await
    }

    #[cfg(test)]
    pub(crate) fn set_last_seen(&self, jid: &str, at: Instant) {
        lock(&self.0.last_seen).insert(jid.to_string(), at);
    }
}

/// The CoPilot group template the base lanes are registered with.
fn base_group(config: &HttpConfig) -> RegisteredGroup {
    let additional_mounts = COPILOT_MOUNTS
        .iter()
        .map(|(dir, readonly)| AdditionalMount {
            host_path: config.project_root.join(dir).to_string_lossy().into_owned(),
            container_path: Some((*dir).to_string()),
            readonly: *readonly,
        })
        .collect();
    RegisteredGroup {
        name: "CoPilot".to_string(),
        folder: config.group_folder.clone(),
        trigger: String::new(),
        added_at: now_iso(),
        container_config: Some(ContainerConfig {
            additional_mounts,
            ..ContainerConfig::default()
        }),
        requires_trigger: Some(false),
        is_main: false,
        session_key: None,
        ipc_key: None,
        ephemeral_session: false,
        trusted_session_commands: false,
    }
}

impl Shared {
    /// Register a lane: its group entry AND its chat row, always together
    /// (a lane without a chat row cannot store inbound messages — the
    /// `messages.chat_jid` foreign key rejects them). `is_group = false`
    /// keeps lanes out of the main group's activatable-group list.
    pub(crate) async fn register_lane(&self, jid: &str, group: RegisteredGroup, persist: bool) {
        let name = group.name.clone();
        self.host.register_group(jid, group, persist).await;
        self.host
            .on_chat_metadata(ChatMetadata {
                chat_jid: jid.to_string(),
                timestamp: now_iso(),
                name: Some(name),
                channel: Some("http".to_string()),
                is_group: Some(false),
            })
            .await;
    }

    /// Session key -> exact user id of every registered per-user lane (the
    /// key itself is one-way: lowercased, truncated and hashed).
    fn user_ids_by_session_key(&self) -> HashMap<String, String> {
        self.host
            .registered_groups()
            .into_iter()
            .filter_map(|(jid, group)| {
                let user = jid.strip_prefix(self.lanes.user_prefix.as_str())?;
                if user.is_empty() {
                    return None;
                }
                Some((group.session_key?, user.to_string()))
            })
            .collect()
    }

    pub(crate) fn user_lane_jids(&self) -> Vec<String> {
        let mut jids: Vec<String> = self
            .host
            .registered_groups()
            .into_keys()
            .filter(|jid| self.lanes.is_user_lane(jid))
            .collect();
        jids.sort();
        jids
    }

    async fn ensure_user_lane(
        &self,
        user_id: Option<&UserId>,
        user_name: Option<&str>,
    ) -> Result<String, LaneLimitReached> {
        let Some(user_id) = user_id else {
            return Ok(self.lanes.base.clone());
        };
        let jid = self.lanes.user_lane(user_id.as_str());
        let _guard = self.lane_lock.lock().await;

        if self.host.registered_groups().contains_key(&jid) {
            lock(&self.last_seen).insert(jid.clone(), Instant::now());
            return Ok(jid);
        }
        let Some(base) = lock(&self.base_group).clone() else {
            // connect() hasn't run: nothing to clone from. Fall back rather
            // than registering a half-built lane with no mounts.
            tracing::warn!(%jid, "HTTP channel: no base group, using anon lane");
            return Ok(self.lanes.base.clone());
        };
        if self.user_lane_jids().len() >= self.config.max_user_lanes {
            tracing::warn!(
                limit = self.config.max_user_lanes,
                "HTTP channel: user lane limit reached"
            );
            return Err(LaneLimitReached);
        }

        let label = user_name
            .map(|n| sanitize_label(n, MAX_LABEL_CHARS))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| user_id.to_string());
        // Collision-proof on case-insensitive filesystems (MYTH-12); the JID
        // keeps the exact id.
        let key = user_id.session_key();
        let group = RegisteredGroup {
            name: format!("CoPilot — {label}"),
            session_key: Some(key.clone()),
            ipc_key: Some(key),
            trusted_session_commands: true,
            ..base
        };
        lock(&self.last_seen).insert(jid.clone(), Instant::now());
        self.register_lane(&jid, group, false).await;
        tracing::info!(%jid, %user_id, "HTTP channel: registered user lane");
        Ok(jid)
    }

    /// Drop lanes with no traffic since `cutoff`, releasing their stored
    /// session and the transcript it pins. A lane with an open SSE stream is
    /// never swept; the anon and investigation lanes are never touched.
    async fn sweep_idle_lanes_before(&self, cutoff: Instant) -> Vec<String> {
        let _guard = self.lane_lock.lock().await;
        let mut swept = Vec::new();
        for jid in self.user_lane_jids() {
            let last_seen = lock(&self.last_seen).get(&jid).copied();
            if last_seen.is_some_and(|t| t > cutoff) {
                continue;
            }
            if self.streams.has_streams(&jid) {
                continue;
            }
            self.host.clear_session(&jid).await;
            self.host.unregister_group(&jid).await;
            lock(&self.last_seen).remove(&jid);
            self.streams.forget_lane(&jid);
            tracing::info!(%jid, "HTTP channel: swept idle user lane");
            swept.push(jid);
        }
        swept
    }

    fn next_job_millis(&self, now: DateTime<Utc>) -> i64 {
        let now_ms = now.timestamp_millis();
        let mut prev = self.last_job_millis.load(Ordering::SeqCst);
        loop {
            let next = now_ms.max(prev.saturating_add(1));
            match self.last_job_millis.compare_exchange(
                prev,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return next,
                Err(actual) => prev = actual,
            }
        }
    }

    fn audit(&self, kind: &str, actor: &str, target: Option<&str>, outcome: &str, details: Value) {
        self.audit
            .record(event(kind, actor, target, outcome, details));
    }
}

// ---------------------------------------------------------------------------
// Errors and helpers
// ---------------------------------------------------------------------------

/// A JSON error response: `{"error": "..."}`.
#[derive(Debug, Clone)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

type ApiResult = Result<Response, ApiError>;

fn body_error(e: BytesRejection) -> ApiError {
    let status = e.status();
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::new(status, "request body too large")
    } else {
        ApiError::new(status, "invalid request body")
    }
}

fn query_error(_: QueryRejection) -> ApiError {
    ApiError::bad_request("invalid query string")
}

/// Parse a JSON object body. `allow_empty` treats a blank body as `{}`.
fn parse_object(body: &[u8], allow_empty: bool) -> Result<Map<String, Value>, ApiError> {
    if allow_empty && body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Map::new());
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(ApiError::bad_request("JSON body must be an object")),
        Err(_) => Err(ApiError::bad_request("Invalid JSON")),
    }
}

/// JavaScript truthiness of an optional JSON value.
fn is_falsy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(Value::Number(n)) => n.as_f64() == Some(0.0),
        _ => false,
    }
}

/// Optional string field: missing/null/empty => `None`; non-string => error.
fn optional_str<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, ()> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(()),
    }
}

fn lesson_types_message(field: &str) -> String {
    format!("{field} must be one of: {}", LESSON_TYPES.join(", "))
}

pub(crate) fn ip_from_extensions(ext: &axum::http::Extensions) -> IpAddr {
    ext.get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_canonical())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

/// The peer address of the connection (`0.0.0.0` when unknown, e.g. in
/// tests driving the router directly).
pub(crate) struct ClientIp(pub IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(ip_from_extensions(&parts.extensions)))
    }
}

// ---------------------------------------------------------------------------
// Router + middleware
// ---------------------------------------------------------------------------

/// Build the complete HTTP API around `state`.
pub fn router(state: HttpState) -> Router {
    let limit = state.0.config.max_body_bytes;
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/metrics", get(metrics_handler))
        .route("/session/reset", post(session_reset))
        .route("/investigate", post(investigate_handler))
        .route("/investigations", get(list_investigations))
        .route("/investigations/{id}", get(get_investigation))
        .route("/evals/{alert_id}", get(evals))
        .route("/templates", get(templates))
        .route("/palace/lesson", post(palace_lesson))
        .route("/palace/search", get(palace_search))
        .route("/palace/forget", post(palace_forget))
        .route("/message", post(message))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(limit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), cors))
        .layer(middleware::from_fn(catch_panic))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            count_responses,
        ))
        .with_state(state)
}

async fn count_responses(State(st): State<HttpState>, req: Request, next: Next) -> Response {
    let res = next.run(req).await;
    st.0.metrics.record_response(res.status().as_u16());
    res
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}

/// Turn a panic anywhere below into a 500 instead of a dropped connection.
async fn catch_panic(req: Request, next: Next) -> Response {
    match AssertUnwindSafe(next.run(req)).catch_unwind().await {
        Ok(res) => res,
        Err(_) => {
            tracing::error!("HTTP channel: request handler panicked");
            ApiError::internal("internal error").into_response()
        }
    }
}

fn allowed_origin(allowed: &[String], origin: &str) -> Option<HeaderValue> {
    if allowed.iter().any(|o| o == "*") {
        return Some(HeaderValue::from_static("*"));
    }
    allowed
        .iter()
        .any(|o| o.eq_ignore_ascii_case(origin))
        .then(|| HeaderValue::from_str(origin).ok())
        .flatten()
}

/// Allowlist CORS. Preflights are answered here, before authentication
/// (browsers never attach credentials to them); other responses get
/// `Access-Control-Allow-Origin` only for configured origins.
async fn cors(State(st): State<HttpState>, req: Request, next: Next) -> Response {
    let allow = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(|o| allowed_origin(&st.0.config.cors_origins, o));
    if req.method() == Method::OPTIONS {
        let mut res = StatusCode::NO_CONTENT.into_response();
        let h = res.headers_mut();
        if let Some(origin) = allow {
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            h.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, OPTIONS"),
            );
            h.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("Authorization, Content-Type, X-Api-Key"),
            );
            h.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("600"),
            );
        }
        h.insert(header::VARY, HeaderValue::from_static("Origin"));
        return res;
    }
    let mut res = next.run(req).await;
    if let Some(origin) = allow {
        let h = res.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        h.append(header::VARY, HeaderValue::from_static("Origin"));
    }
    res
}

/// Fail-closed API key check for everything but `GET /health`, with per-IP
/// throttling of repeated failures. Keys are never logged or audited.
async fn require_api_key(State(st): State<HttpState>, req: Request, next: Next) -> Response {
    if req.method() == Method::GET && req.uri().path() == "/health" {
        return next.run(req).await;
    }
    let s = &st.0;
    let ip = ip_from_extensions(req.extensions());

    if let Some(retry_after) = s.throttle.blocked(ip) {
        Metrics::inc(&s.metrics.auth_throttled);
        let mut res = ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed authentication attempts",
        )
        .into_response();
        res.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from(retry_after.as_secs().max(1)),
        );
        return res;
    }

    let headers = req.headers();
    let x_api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok());
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let provided = s.verifier.extract(x_api_key, authorization);
    let configured = s.config.api_key.is_configured();
    if configured
        && s.verifier
            .verify(provided.as_deref(), s.config.api_key.expose())
    {
        s.throttle.record_success(ip);
        return next.run(req).await;
    }

    let reason = if !configured {
        "api_key_unset"
    } else if provided.is_none() {
        "missing_credentials"
    } else {
        "invalid_credentials"
    };
    Metrics::inc(&s.metrics.auth_failures);
    let record = s.throttle.record_failure(ip);
    let path = truncate_chars(req.uri().path(), MAX_AUDIT_PATH_CHARS);
    s.audit(
        "http.auth.failed",
        &ip.to_string(),
        Some(path),
        "denied",
        json!({
            "reason": reason,
            "method": req.method().as_str(),
            "failures": record.failures,
            "throttled": record.now_throttled,
        }),
    );
    if record.now_throttled {
        tracing::warn!(%ip, failures = record.failures, "HTTP channel: throttling client after repeated auth failures");
    }
    ApiError::new(StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not found")
}

async fn health() -> Response {
    Json(json!({ "status": "ok", "channel": "http" })).into_response()
}

async fn status(State(st): State<HttpState>) -> ApiResult {
    let s = &st.0;
    let folder = s.config.group_folder.clone();
    let (tasks, rows) = run_blocking(&s.store, move |store| {
        Ok((
            store.get_tasks_for_group(&folder)?,
            store.get_session_rows()?,
        ))
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "GET /status failed");
        ApiError::internal("failed to read status")
    })?;

    // Lane context sizes, so CoPilot can show a session growing before it
    // starts costing minutes per reply. The investigation lane is ephemeral
    // and so never has a stored session.
    let folder = &s.config.group_folder;
    let user_ids = s.user_ids_by_session_key();
    let sessions: Vec<Value> = rows
        .into_iter()
        .filter(|r| {
            r.group_folder.starts_with(folder.as_str())
                || r.group_folder.starts_with(USER_SESSION_KEY_PREFIX)
        })
        .map(|r| {
            // Only registered lanes can be mapped back to their exact id; a
            // session left over from before a restart reports `null`.
            let user_id = user_ids.get(&r.group_folder).cloned();
            json!({
                "lane": r.group_folder,
                "user_id": user_id,
                "session_id": r.session_id,
                "input_tokens": r.input_tokens,
                "updated_at": r.updated_at,
            })
        })
        .collect();
    let scheduled_tasks: Vec<Value> = tasks
        .iter()
        .map(|t| {
            json!({
                "id": t.id,
                "status": t.status.as_str(),
                "schedule_type": t.schedule_type.as_str(),
                "schedule_value": t.schedule_value,
                "next_run": t.next_run,
                "last_run": t.last_run,
            })
        })
        .collect();
    let counts = s.streams.counts();
    let queue = s.host.queue_status();
    Ok(Json(json!({
        "status": "ok",
        "uptime_seconds": s.started_at.elapsed().as_secs(),
        "active_investigations": counts.lanes_in_turn,
        "pending_queue_depth": s.streams.pending_len(&s.lanes.base),
        "sessions": sessions,
        "scheduled_tasks": scheduled_tasks,
        "user_lanes": s.user_lane_jids().len(),
        "queue": {
            "active_containers": queue.active_containers,
            "max_containers": queue.max_containers,
            "waiting_groups": queue.waiting_groups,
        },
    }))
    .into_response())
}

async fn metrics_handler(State(st): State<HttpState>) -> Response {
    let s = &st.0;
    let by_status = match run_blocking(&s.store, |store| {
        store.list_investigations(METRICS_INVESTIGATION_WINDOW)
    })
    .await
    {
        Ok(list) => {
            let mut map = BTreeMap::new();
            for inv in list {
                *map.entry(inv.status).or_insert(0u64) += 1;
            }
            Some(map)
        }
        Err(e) => {
            tracing::debug!(err = %e, "metrics: investigation lookup failed");
            None
        }
    };
    let counts = s.streams.counts();
    let gauges = Gauges {
        uptime_seconds: s.started_at.elapsed().as_secs(),
        queue: s.host.queue_status(),
        sse_pending: counts.pending,
        sse_active: counts.active,
        lanes_in_turn: counts.lanes_in_turn,
        user_lanes: s.user_lane_jids().len(),
        investigations_by_status: by_status,
        investigations_window: METRICS_INVESTIGATION_WINDOW,
    };
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        metrics::render(&s.metrics, &gauges),
    )
        .into_response()
}

async fn session_reset(
    State(st): State<HttpState>,
    ClientIp(ip): ClientIp,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    let s = &st.0;
    let body = body.map_err(body_error)?;
    let obj = parse_object(&body, true)?;
    let scope = match optional_str(&obj, "scope") {
        Ok(v) => v.unwrap_or("chat"),
        Err(()) => "",
    };
    let user_id =
        UserId::from_json(obj.get("user_id")).map_err(|e| ApiError::bad_request(e.to_string()))?;

    // 'chat' resets the caller's own lane: an analyst clearing their
    // conversation must not clear a colleague's. Without a user_id it falls
    // back to the shared anonymous lane.
    let targets: Vec<String> = match scope {
        "all" => {
            let mut t = vec![s.lanes.base.clone(), s.lanes.investigate.clone()];
            t.extend(s.user_lane_jids());
            t
        }
        "investigate" => vec![s.lanes.investigate.clone()],
        "chat" => vec![
            user_id
                .as_ref()
                .map_or_else(|| s.lanes.base.clone(), |u| s.lanes.user_lane(u.as_str())),
        ],
        _ => {
            return Err(ApiError::bad_request(
                "scope must be one of 'chat', 'investigate', 'all'",
            ));
        }
    };

    let mut cleared = Vec::new();
    for jid in targets {
        if s.host.clear_session(&jid).await {
            cleared.push(jid);
        }
    }
    let user_id = user_id.as_ref().map(UserId::as_str);
    tracing::info!(scope, user_id = ?user_id, cleared = ?cleared, "HTTP channel: session reset");
    s.audit(
        "http.session.reset",
        &ip.to_string(),
        None,
        "info",
        json!({ "scope": scope, "user_id": user_id, "lanes": cleared }),
    );
    Ok(Json(json!({ "cleared": cleared.len(), "lanes": cleared })).into_response())
}

/// Validate the `/investigate` body. Template existence is checked by the
/// caller (filesystem access).
fn parse_investigation_request(obj: &Map<String, Value>) -> Result<InvestigationRequest, ApiError> {
    if is_falsy(obj.get("alert_id")) || is_falsy(obj.get("customer_code")) {
        return Err(ApiError::bad_request("alert_id and customer_code required"));
    }
    let alert_id = obj
        .get("alert_id")
        .and_then(parse_alert_id)
        .ok_or_else(|| ApiError::bad_request("alert_id must be a positive integer"))?;
    let customer_code = obj
        .get("customer_code")
        .and_then(Value::as_str)
        .filter(|c| is_valid_customer_code(c))
        .ok_or_else(|| ApiError::bad_request("customer_code must match ^[A-Za-z0-9_-]{1,64}$"))?
        .to_string();
    let triggered_by = match optional_str(obj, "triggered_by") {
        Ok(None) => "webhook".to_string(),
        Ok(Some(t)) if is_valid_triggered_by(t) => t.to_string(),
        _ => {
            return Err(ApiError::bad_request(
                "triggered_by must be one of: manual, scheduled, webhook",
            ));
        }
    };
    let template_override = match optional_str(obj, "template_override") {
        Ok(None) => None,
        Ok(Some(t)) if is_valid_template_name(t) => Some(t.to_string()),
        _ => {
            return Err(ApiError::bad_request(
                "template_override must be a plain .txt filename (no path separators)",
            ));
        }
    };
    Ok(InvestigationRequest {
        alert_id,
        customer_code,
        triggered_by,
        template_override,
    })
}

async fn investigate_handler(
    State(st): State<HttpState>,
    ClientIp(ip): ClientIp,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    let s = &st.0;
    let actor = ip.to_string();
    let body = body.map_err(body_error)?;
    let obj = parse_object(&body, false)?;
    let req = match parse_investigation_request(&obj) {
        Ok(r) => r,
        Err(e) => {
            s.audit(
                "http.investigate",
                &actor,
                None,
                "denied",
                json!({ "reason": e.message }),
            );
            return Err(e);
        }
    };

    // Validate the override against the on-disk prompts directory (regular
    // files only) before queuing anything.
    if let Some(template) = req.template_override.clone() {
        let dir = s.config.group_dir();
        let exists = tokio::task::spawn_blocking(move || files::template_exists(&dir, &template))
            .await
            .unwrap_or(false);
        if !exists {
            let name = req.template_override.as_deref().unwrap_or_default();
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                format!("template_override not found: {name}"),
            ));
        }
    }

    // Serialize dedup check + creation so two identical triggers racing each
    // other cannot both start a job.
    let guard = s.investigate_lock.lock().await;
    let now = Utc::now();
    let window = s.config.dedup_window;
    if !window.is_zero() {
        let alert = req.alert_id.to_string();
        match run_blocking(&s.store, move |st| {
            st.latest_investigation_for_alert(&alert)
        })
        .await
        {
            Ok(Some(existing)) if is_duplicate(&existing, &req, window, now) => {
                Metrics::inc(&s.metrics.investigations_deduplicated);
                s.audit(
                    "http.investigate",
                    &actor,
                    Some(&existing.id),
                    "info",
                    json!({
                        "alert_id": req.alert_id,
                        "customer_code": req.customer_code,
                        "deduplicated": true,
                    }),
                );
                tracing::info!(alert_id = req.alert_id, job_id = %existing.id, "HTTP channel: duplicate investigation trigger");
                return Ok((
                    StatusCode::OK,
                    Json(json!({
                        "job_id": existing.id,
                        "status": existing.status,
                        "template_override": existing.template,
                        "deduplicated": true,
                    })),
                )
                    .into_response());
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(err = %e, "investigation dedup lookup failed"),
        }
    }

    let id = job_id(req.alert_id, s.next_job_millis(now));
    let prompt = investigation_prompt(&req, &id);
    let task = investigation_task(
        &id,
        &s.config.group_folder,
        &s.lanes.investigate,
        prompt,
        s.config.timezone,
        now,
    )
    .map_err(|e| {
        tracing::error!(err = %e, "failed to build investigation task");
        ApiError::internal("failed to queue investigation")
    })?;
    let inv = investigation_record(&id, &req, now);
    run_blocking(&s.store, move |st| {
        investigate::persist_investigation(st, &task, &inv)
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "failed to persist investigation");
        ApiError::internal("failed to queue investigation")
    })?;
    drop(guard);

    s.host.notify_tasks_changed();
    Metrics::inc(&s.metrics.investigations_created);
    s.audit(
        "http.investigate",
        &actor,
        Some(&id),
        "allowed",
        json!({
            "alert_id": req.alert_id,
            "customer_code": req.customer_code,
            "triggered_by": req.triggered_by,
            "template_override": req.template_override,
        }),
    );
    tracing::info!(
        alert_id = req.alert_id,
        customer_code = %req.customer_code,
        job_id = %id,
        triggered_by = %req.triggered_by,
        template_override = ?req.template_override,
        "HTTP channel: investigation queued"
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "job_id": id,
            "status": investigate::STATUS_QUEUED,
            "template_override": req.template_override,
            "deduplicated": false,
        })),
    )
        .into_response())
}

async fn list_investigations(
    State(st): State<HttpState>,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> ApiResult {
    let Query(params) = query.map_err(query_error)?;
    let limit = match params.get("limit").map(|l| l.trim()) {
        None | Some("") => DEFAULT_INVESTIGATIONS_LIMIT,
        Some(l) => l
            .parse::<usize>()
            .map_err(|_| ApiError::bad_request("limit must be a positive integer"))?
            .clamp(1, MAX_INVESTIGATIONS_LIMIT),
    };
    let list = run_blocking(&st.0.store, move |s| s.list_investigations(limit))
        .await
        .map_err(|e| {
            tracing::error!(err = %e, "GET /investigations failed");
            ApiError::internal("failed to list investigations")
        })?;
    Ok(Json(json!({ "investigations": list })).into_response())
}

async fn get_investigation(State(st): State<HttpState>, Path(id): Path<String>) -> ApiResult {
    if !is_valid_investigation_id(&id) {
        return Err(ApiError::bad_request("invalid investigation id"));
    }
    let found = run_blocking(&st.0.store, move |s| s.get_investigation(&id))
        .await
        .map_err(|e| {
            tracing::error!(err = %e, "GET /investigations/{{id}} failed");
            ApiError::internal("failed to read investigation")
        })?;
    match found {
        Some(inv) => Ok(Json(inv).into_response()),
        None => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "investigation not found",
        )),
    }
}

/// `GET /evals/{alert_id}` — eval JSON written by the investigation agent
/// at the end of an investigation; replays are returned in descending job-id
/// order.
///
/// Records are read from the investigation lane's private state directory
/// (`<data_dir>/sessions/<investigation session key>/evals/`), which no other
/// lane can write; the shared `groups/<folder>/evals/` is consulted only when
/// the operator enabled `COPILOT_EVALS_LEGACY_GROUP_DIR` (N-2).
async fn evals(State(st): State<HttpState>, Path(alert_id): Path<String>) -> ApiResult {
    if alert_id.is_empty()
        || alert_id.len() > crate::validate::MAX_ALERT_ID_DIGITS
        || !alert_id.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ApiError::bad_request("invalid alert_id"));
    }
    let numeric: u64 = alert_id
        .parse()
        .map_err(|_| ApiError::bad_request("invalid alert_id"))?;
    let config = &st.0.config;
    let sources = files::EvalSources {
        sessions_dir: config.sessions_dir(),
        lane_key: config.investigation_session_key().to_string(),
        legacy_group_dir: config.evals_legacy_group_dir.then(|| config.group_dir()),
    };
    let evals =
        tokio::task::spawn_blocking(move || files::read_investigation_evals(&sources, &alert_id))
            .await
            .map_err(|_| ApiError::internal("failed to read evals"))?
            .map_err(|e| {
                tracing::error!(err = %e, "GET /evals failed");
                ApiError::internal("failed to read evals")
            })?;
    Ok(Json(json!({ "alert_id": numeric, "evals": evals })).into_response())
}

/// `GET /templates` — template filenames + previews; bodies are never
/// exposed (the agent is the only consumer of the full content).
async fn templates(State(st): State<HttpState>) -> ApiResult {
    let dir = st.0.config.group_dir();
    let templates = tokio::task::spawn_blocking(move || files::list_templates(&dir))
        .await
        .map_err(|_| ApiError::internal("failed to list templates"))?
        .map_err(|e| {
            tracing::error!(err = %e, "GET /templates failed");
            ApiError::internal("failed to list templates")
        })?;
    Ok(Json(json!({ "templates": templates })).into_response())
}

fn palace_response(s: &Shared, op: &str, result: Result<Value, PalaceError>) -> ApiResult {
    match result {
        Ok(v) => {
            Metrics::inc(&s.metrics.palace_ok);
            Ok(Json(v).into_response())
        }
        Err(PalaceError::Disabled) => {
            Metrics::inc(&s.metrics.palace_failed);
            tracing::debug!(op, "palace call refused: no palace runner configured");
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                PalaceError::Disabled.to_string(),
            ))
        }
        Err(e) => {
            Metrics::inc(&s.metrics.palace_failed);
            tracing::error!(op, err = %e, "palace call failed");
            let status = match e {
                PalaceError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
                PalaceError::Busy => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err(ApiError::new(status, e.to_string()))
        }
    }
}

/// `POST /palace/lesson` — CoPilot's drainer ingests teach-the-palace
/// lessons (wraps `mempalace_add_drawer`).
async fn palace_lesson(
    State(st): State<HttpState>,
    ClientIp(ip): ClientIp,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    let s = &st.0;
    let body = body.map_err(body_error)?;
    let obj = parse_object(&body, false)?;
    if is_falsy(obj.get("customer_code"))
        || is_falsy(obj.get("lesson_type"))
        || is_falsy(obj.get("lesson_text"))
    {
        return Err(ApiError::bad_request(
            "customer_code, lesson_type, and lesson_text are required",
        ));
    }
    let lesson_type = obj
        .get("lesson_type")
        .and_then(Value::as_str)
        .filter(|t| is_valid_lesson_type(t))
        .ok_or_else(|| ApiError::bad_request(lesson_types_message("lesson_type")))?;
    let customer_code = obj
        .get("customer_code")
        .and_then(Value::as_str)
        .filter(|c| is_valid_customer_code(c))
        .ok_or_else(|| ApiError::bad_request("customer_code must match ^[A-Za-z0-9_-]{1,64}$"))?;
    let lesson_text = obj
        .get("lesson_text")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("lesson_text must be a string"))?;
    if lesson_text.chars().count() > MAX_LESSON_CHARS {
        return Err(ApiError::bad_request(format!(
            "lesson_text exceeds {MAX_LESSON_CHARS} characters"
        )));
    }
    let durability = if obj.get("durability").and_then(Value::as_str) == Some("one_off") {
        "one_off"
    } else {
        "durable"
    };

    // Lessons are recalled into future investigation prompts: audit every
    // write (metadata only, never the text).
    s.audit(
        "http.palace.lesson",
        &ip.to_string(),
        Some(customer_code),
        "info",
        json!({
            "lesson_type": lesson_type,
            "durability": durability,
            "length": lesson_text.chars().count(),
        }),
    );
    let result = s
        .palace
        .call(add_lesson_request(
            customer_code,
            lesson_type,
            lesson_text,
            durability,
        ))
        .await;
    palace_response(s, "add_drawer", result)
}

/// `GET /palace/search` — similar-lessons preview (wraps `mempalace_search`).
async fn palace_search(
    State(st): State<HttpState>,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> ApiResult {
    let s = &st.0;
    let Query(params) = query.map_err(query_error)?;
    let customer_code = params
        .get("customer_code")
        .map(String::as_str)
        .unwrap_or("");
    let q = params.get("query").map(String::as_str).unwrap_or("");
    if customer_code.is_empty() || q.is_empty() {
        return Err(ApiError::bad_request(
            "customer_code and query are required",
        ));
    }
    if !is_valid_customer_code(customer_code) {
        return Err(ApiError::bad_request(
            "customer_code must match ^[A-Za-z0-9_-]{1,64}$",
        ));
    }
    if q.chars().count() > MAX_QUERY_CHARS {
        return Err(ApiError::bad_request(format!(
            "query exceeds {MAX_QUERY_CHARS} characters"
        )));
    }
    let room = params
        .get("room")
        .map(String::as_str)
        .filter(|r| !r.is_empty());
    if room.is_some_and(|r| !is_valid_lesson_type(r)) {
        return Err(ApiError::bad_request(lesson_types_message("room")));
    }
    let limit = match params
        .get("limit")
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
    {
        None => 5,
        Some(l) => l
            .parse::<i64>()
            .map_err(|_| ApiError::bad_request("limit must be an integer"))?
            .clamp(1, 25) as u32,
    };
    let result = s
        .palace
        .call(search_request(customer_code, room, q, limit))
        .await;
    palace_response(s, "search", result)
}

/// `POST /palace/forget` — CoPilot's durability sweeper removes an expired
/// one-off lesson (wraps `mempalace_delete_drawer`). A missing drawer is
/// reported by MemPalace as `success: false`, not as an HTTP error.
async fn palace_forget(
    State(st): State<HttpState>,
    ClientIp(ip): ClientIp,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    let s = &st.0;
    let body = body.map_err(body_error)?;
    let obj = parse_object(&body, false)?;
    let drawer_id = match obj.get("drawer_id") {
        Some(Value::String(d)) if !d.is_empty() => d.as_str(),
        _ => return Err(ApiError::bad_request("drawer_id (string) is required")),
    };
    if !is_valid_drawer_id(drawer_id) {
        return Err(ApiError::bad_request(
            "drawer_id contains invalid characters",
        ));
    }
    s.audit(
        "http.palace.forget",
        &ip.to_string(),
        Some(drawer_id),
        "info",
        json!({}),
    );
    let result = s.palace.call(forget_request(drawer_id)).await;
    palace_response(s, "delete_drawer", result)
}

/// `POST /message` — route an analyst prompt into the caller's lane and
/// stream the answer back as SSE (`data: {"type":"text"|"done"}`), with a
/// keepalive comment every `sse_keepalive`.
async fn message(State(st): State<HttpState>, body: Result<Bytes, BytesRejection>) -> ApiResult {
    let s = &st.0;
    let body = body.map_err(body_error)?;
    let obj = parse_object(&body, false)?;
    let text = match obj.get("message") {
        Some(Value::String(m)) => m.trim(),
        _ => "",
    };
    if text.is_empty() {
        return Err(ApiError::bad_request("message field required"));
    }
    let sender = obj
        .get("sender")
        .and_then(Value::as_str)
        .map(|v| sanitize_label(v, MAX_LABEL_CHARS))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "copilot".to_string());
    // Invalid ids are rejected, never stripped into a neighbour's lane.
    let user_id =
        UserId::from_json(obj.get("user_id")).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let user_name = obj.get("user_name").and_then(Value::as_str);

    // Resolve the caller's lane before opening the stream, so the writer is
    // queued against the same JID the reply will be written to.
    let lane = s
        .ensure_user_lane(user_id.as_ref(), user_name)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many active user lanes",
            )
        })?;
    let (writer_id, rx) = s
        .streams
        .open(&lane, s.config.max_pending_per_lane, s.config.max_streams)
        .map_err(|e| match e {
            OpenError::LaneBusy => ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests queued on this lane",
            ),
            OpenError::TooManyStreams => {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "too many open streams")
            }
        })?;
    let stream = WriterStream::new(
        rx,
        WriterGuard {
            registry: Arc::clone(&s.streams),
            jid: lane.clone(),
            id: writer_id,
        },
    );

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let msg = NewMessage {
        id: format!(
            "http-{}-{}",
            Utc::now().timestamp_millis(),
            suffix.get(..8).unwrap_or(&suffix)
        ),
        chat_jid: lane.clone(),
        sender: sender.clone(),
        sender_name: sender.clone(),
        content: text.to_string(),
        timestamp: now_iso(),
        is_from_me: false,
        ..NewMessage::default()
    };
    s.host.on_message(&lane, msg).await;
    Metrics::inc(&s.metrics.messages);
    tracing::info!(lane = %lane, sender = %sender, length = text.len(), "HTTP channel: message received");

    let keepalive = KeepAlive::new()
        .interval(s.config.sse_keepalive.max(Duration::from_millis(10)))
        .text("keepalive");
    let mut res = Sse::new(stream).keep_alive(keepalive).into_response();
    res.headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(res)
}
