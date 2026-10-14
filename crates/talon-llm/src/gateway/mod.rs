//! Host-side LLM gateway: an authenticated reverse proxy in front of vLLM.
//!
//! Containers never see the vLLM API key. The host starts one gateway,
//! issues a short-lived token per container run ([`GatewayHandle::issue_token`]),
//! hands it to the container inside `ContainerInput.llm` (stdin, never env)
//! and revokes it when the run ends.
//!
//! ```text
//! container ──Bearer tlgw_…──▶ gateway ──Bearer <TALON_VLLM_API_KEY>──▶ vLLM
//!                              │ talon-net: header-read timeout, connection caps
//!                              │ token digest lookup + TTL
//!                              │ per-token rate limit + in-flight cap (429)
//!                              │ global in-flight cap across tokens (503)
//!                              │ body size (413) and JSON value budget
//!                              │ parameter allowlist (unknown fields dropped,
//!                              │   media parts / grammar forms refused)
//!                              │ model pinned to the allow-list
//!                              │ max_tokens clamped / inserted, n = 1
//!                              │ per-label cache_salt (no shared prefix cache)
//!                              │ SSE passed through, usage counted per label
//!                              └ audit: gateway.auth.failed / gateway.request
//! ```
//!
//! Routes: `POST /v1/chat/completions` (JSON or SSE), `GET /v1/models`
//! (filtered to allowed models), `POST /tokenize`. Everything else is 404.
//! Client headers are never forwarded; the upstream request is built fresh
//! from the allowlisted fields (see [`CHAT_ALLOWED_FIELDS`] and
//! [`TOKENIZE_ALLOWED_FIELDS`]).

mod policy;
mod stats;
mod tokens;

use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER,
    WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use futures::Stream;
use serde::Deserialize;
use serde_json::{Value, json};
use talon_core::audit::{SharedAuditSink, event};
use talon_core::protocol::LlmEndpoint;
use talon_core::provider::DEFAULT_MAX_CONTEXT_TOKENS;
use talon_core::types::VllmConfig;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard, WaitForCancellationFutureOwned};

use crate::client::{BaseUrls, normalize_base_url, read_body_capped};
use crate::error::LlmError;
use crate::sse::SseDecoder;
use crate::types::Usage;

pub use policy::{
    CHAT_ALLOWED_FIELDS, MAX_JSON_NODES, MAX_SCHEMA_BYTES, MAX_TOOL_DEFINITION_BYTES, MAX_TOOLS,
    TOKENIZE_ALLOWED_FIELDS,
};
pub use stats::{GatewayStats, LabelStats, MAX_LABELS, OVERFLOW_LABEL};
/// Connection limits of the gateway's HTTP server (re-exported from
/// `talon-net` so hosts can tune them without depending on it).
pub use talon_net::ServerLimits;
pub use tokens::TOKEN_PREFIX;

use policy::{CacheSaltKey, PolicyOutcome, RequestPolicy};
use stats::StatsRecorder;
use tokens::{AuthDecision, InFlightGuard, TokenStore, extract_token};

/// Default gateway port (`TALON_LLM_GATEWAY_PORT`).
pub const DEFAULT_GATEWAY_PORT: u16 = 3001;
/// Default request body limit. 4 MiB is roughly a million tokens of text —
/// far beyond any served context window — including 100+ tool schemas, and
/// keeps `bodies x concurrency` bounded on the host.
pub const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Default `max_tokens` cap.
pub const DEFAULT_MAX_OUTPUT_TOKENS_CAP: u32 = 16_384;
/// Default per-token request budget.
pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 120;
/// Default per-token cap on simultaneous requests.
pub const DEFAULT_MAX_CONCURRENT_PER_TOKEN: u32 = 8;
/// Default cap on simultaneous requests across all tokens.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: u32 = 32;
/// Default cap on open connections (see [`ServerLimits`]).
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// Default cap on open connections from one peer IP (one container
/// normally has one IP on the docker bridge).
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 64;
/// A client must deliver its request body within this time (slow-trickle
/// clients would otherwise hold a connection and request slots). 4 MiB
/// over the docker bridge takes milliseconds.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// `Retry-After` (seconds) when the global concurrency cap is reached.
const OVERLOAD_RETRY_AFTER: &str = "2";
/// A streamed response may outlive `request_timeout` by this much before
/// its slots are reclaimed (covers a client that stopped reading).
const STREAM_DEADLINE_SLACK: Duration = Duration::from_secs(30);
/// Audit records for auth failures / denials per minute (the rest are
/// counted and reported in the next record as `suppressed_since_last`).
const AUDIT_DENIALS_PER_MINUTE: u32 = 60;
/// Interval of the expired-token sweep.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// `/v1/models` and `/tokenize` should be quick.
const AUX_TIMEOUT: Duration = Duration::from_secs(30);

/// Gateway configuration.
#[derive(Clone)]
pub struct GatewayConfig {
    /// Listen address (default `127.0.0.1:3001`; on Linux docker bind the
    /// bridge address so `host.docker.internal` reaches it).
    pub bind: SocketAddr,
    /// vLLM base URL, with or without `/v1`.
    pub upstream_base_url: String,
    /// vLLM `--api-key` (`TALON_VLLM_API_KEY`). Injected upstream; never
    /// visible to containers.
    pub upstream_api_key: Option<String>,
    /// Models containers may use (in addition to `default_model`).
    pub allowed_models: Vec<String>,
    /// Model substituted for any model not on the allow-list.
    pub default_model: String,
    /// Request body limit in bytes (413 above).
    pub max_body_bytes: usize,
    /// `max_tokens` / `max_completion_tokens` are clamped to this, and
    /// `max_tokens` is inserted when the client sent neither. `None`
    /// disables both.
    pub max_output_tokens_cap: Option<u32>,
    /// Per-token request budget (token bucket, burst = one minute's worth).
    /// `0` disables rate limiting.
    pub requests_per_minute: u32,
    /// Per-token cap on simultaneous requests (streams count until they
    /// end). `0` disables the cap.
    pub max_concurrent_per_token: u32,
    /// Cap on simultaneous requests across **all** tokens (streams count
    /// until they end; request bodies are buffered under it, so it also
    /// bounds host memory at about `max_concurrent_requests x
    /// max_body_bytes`). Excess requests get `503` + `Retry-After`. `0`
    /// disables the cap.
    pub max_concurrent_requests: u32,
    /// Send a per-label `cache_salt` (derived from a random per-gateway
    /// secret) with every chat request, so lanes never share vLLM
    /// prefix-cache blocks — otherwise one lane could learn from response
    /// timing whether another lane's prompt starts with a guessed prefix.
    /// Needs vLLM >= 0.9 (V1 engine). Older vLLM releases and other
    /// OpenAI-compatible servers may reject (or warn about) the unknown
    /// field; set this to `false` for them. Client-supplied salts are
    /// always discarded.
    pub cache_salt: bool,
    /// Connection limits for the HTTP server (header-read timeout, global
    /// and per-IP connection caps, shutdown grace). Defaults:
    /// [`DEFAULT_MAX_CONNECTIONS`], [`DEFAULT_MAX_CONNECTIONS_PER_IP`] and
    /// the `talon-net` defaults for the rest.
    pub server_limits: ServerLimits,
    /// Upstream request timeout (whole request, including a streamed body).
    pub request_timeout: Duration,
    /// Upper bound for a buffered (non-streaming) upstream response body.
    pub max_response_bytes: usize,
    /// Also audit every successful request (`gateway.request`, outcome
    /// `allowed`, with label/model/token counts). Denials are always audited.
    pub audit_requests: bool,
    /// Honour `HTTP(S)_PROXY` for the upstream connection (off by default:
    /// the API key should go straight to vLLM).
    pub use_system_proxy: bool,
}

impl fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("bind", &self.bind)
            .field("upstream_base_url", &self.upstream_base_url)
            .field(
                "upstream_api_key",
                &self.upstream_api_key.as_ref().map(|_| "<redacted>"),
            )
            .field("allowed_models", &self.allowed_models)
            .field("default_model", &self.default_model)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_output_tokens_cap", &self.max_output_tokens_cap)
            .field("requests_per_minute", &self.requests_per_minute)
            .field("max_concurrent_per_token", &self.max_concurrent_per_token)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("cache_salt", &self.cache_salt)
            .field("server_limits", &self.server_limits)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl GatewayConfig {
    /// Defaults: `127.0.0.1:3001`, 4 MiB bodies, 16384 output-token cap,
    /// 120 requests/minute and 8 in flight per token, 32 in flight overall,
    /// per-label `cache_salt`, 256 connections (64 per IP), 600 s timeout.
    pub fn new(upstream_base_url: impl Into<String>, default_model: impl Into<String>) -> Self {
        Self {
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_GATEWAY_PORT)),
            upstream_base_url: upstream_base_url.into(),
            upstream_api_key: None,
            allowed_models: Vec::new(),
            default_model: default_model.into(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_output_tokens_cap: Some(DEFAULT_MAX_OUTPUT_TOKENS_CAP),
            requests_per_minute: DEFAULT_REQUESTS_PER_MINUTE,
            max_concurrent_per_token: DEFAULT_MAX_CONCURRENT_PER_TOKEN,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            cache_salt: true,
            server_limits: default_server_limits(),
            request_timeout: crate::client::DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: crate::client::DEFAULT_MAX_RESPONSE_BYTES,
            audit_requests: false,
            use_system_proxy: false,
        }
    }

    /// From the host's vLLM provider settings: allows `model` and
    /// `fast_model`, caps output at `max_output_tokens` (or the default).
    pub fn from_vllm(vllm: &VllmConfig, upstream_api_key: Option<String>) -> Self {
        let mut cfg = Self::new(vllm.base_url.clone(), vllm.model.clone());
        cfg.upstream_api_key = upstream_api_key.filter(|k| !k.trim().is_empty());
        cfg.allowed_models.push(vllm.model.clone());
        if let Some(fast) = &vllm.fast_model {
            cfg.allowed_models.push(fast.clone());
        }
        if let Some(cap) = vllm.max_output_tokens {
            cfg.max_output_tokens_cap = Some(cap);
        }
        if let Some(secs) = vllm.request_timeout_secs.filter(|s| *s > 0) {
            cfg.request_timeout = Duration::from_secs(secs);
        }
        cfg
    }

    /// Allow an additional model (e.g. a per-group override).
    pub fn allow_model(mut self, model: impl Into<String>) -> Self {
        let model = model.into();
        if !self.allowed_models.contains(&model) {
            self.allowed_models.push(model);
        }
        self
    }

    fn validate(&self) -> Result<(), LlmError> {
        if self.default_model.trim().is_empty() {
            return Err(LlmError::Config("gateway default_model is empty".into()));
        }
        if self.max_body_bytes == 0 {
            return Err(LlmError::Config(
                "gateway max_body_bytes must be > 0".into(),
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(LlmError::Config(
                "gateway request_timeout must be > 0".into(),
            ));
        }
        let limits = &self.server_limits;
        if limits.max_connections == 0 || limits.max_connections_per_ip == 0 {
            return Err(LlmError::Config(
                "gateway connection limits must be > 0".into(),
            ));
        }
        if limits.header_read_timeout.is_zero() {
            return Err(LlmError::Config(
                "gateway header_read_timeout must be > 0".into(),
            ));
        }
        Ok(())
    }
}

/// The gateway's default [`ServerLimits`]: [`DEFAULT_MAX_CONNECTIONS`],
/// [`DEFAULT_MAX_CONNECTIONS_PER_IP`], `talon-net` defaults otherwise
/// (15 s header-read timeout, 10 s shutdown grace).
pub fn default_server_limits() -> ServerLimits {
    ServerLimits {
        max_connections: DEFAULT_MAX_CONNECTIONS,
        max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
        ..ServerLimits::default()
    }
}

/// Entry point: `LlmGateway::start(config, audit)`.
#[derive(Debug)]
pub struct LlmGateway {
    _private: (),
}

impl LlmGateway {
    /// Validate the config, bind the listener and serve in the background.
    pub async fn start(
        config: GatewayConfig,
        audit: SharedAuditSink,
    ) -> Result<GatewayHandle, LlmError> {
        config.validate()?;
        let upstream = normalize_base_url(&config.upstream_base_url)?;
        let upstream_auth = match config.upstream_api_key.as_deref().map(str::trim) {
            Some(key) if !key.is_empty() => {
                let mut v = HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| {
                    LlmError::Config("upstream API key contains invalid characters".into())
                })?;
                v.set_sensitive(true);
                Some(v)
            }
            _ => None,
        };
        let mut builder = reqwest::Client::builder()
            .user_agent(concat!("talon-llm-gateway/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90));
        if !config.use_system_proxy {
            builder = builder.no_proxy();
        }
        let http = builder
            .build()
            .map_err(|e| LlmError::Config(format!("cannot build upstream HTTP client: {e}")))?;

        let policy = RequestPolicy {
            allowed_models: config.allowed_models.clone(),
            default_model: config.default_model.clone(),
            max_output_tokens_cap: config.max_output_tokens_cap,
            cache_salt: config.cache_salt.then(CacheSaltKey::random),
        };
        let global = (config.max_concurrent_requests > 0).then(|| {
            Arc::new(Semaphore::new(
                usize::try_from(config.max_concurrent_requests)
                    .unwrap_or(usize::MAX)
                    .min(Semaphore::MAX_PERMITS),
            ))
        });
        let state = Arc::new(GatewayState {
            tokens: TokenStore::new(config.requests_per_minute, config.max_concurrent_per_token),
            stats: StatsRecorder::new(),
            throttle: AuditThrottle::new(AUDIT_DENIALS_PER_MINUTE, Duration::from_secs(60)),
            upstream,
            upstream_auth,
            http,
            policy,
            global,
            kill: CancellationToken::new(),
            audit,
            config,
        });

        let listener = tokio::net::TcpListener::bind(state.config.bind)
            .await
            .map_err(|e| {
                LlmError::Config(format!(
                    "cannot bind LLM gateway on {}: {e}",
                    state.config.bind
                ))
            })?;
        let addr = listener
            .local_addr()
            .map_err(|e| LlmError::Config(format!("gateway listener has no address: {e}")))?;

        let app = Router::new()
            .route("/v1/chat/completions", post(chat_completions))
            .route("/v1/models", get(list_models))
            .route("/tokenize", post(tokenize))
            .fallback(not_found)
            .with_state(state.clone());

        // talon-net instead of `axum::serve`: header-read timeout and
        // connection caps against slowloris FD exhaustion; it inserts
        // `ConnectInfo<SocketAddr>` for the handlers.
        let cancel = CancellationToken::new();
        let task = tokio::spawn(talon_net::serve(
            listener,
            app,
            state.config.server_limits,
            cancel.clone(),
        ));
        let sweep_state = state.clone();
        let sweep_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = sweep_cancel.cancelled() => break,
                    _ = tick.tick() => {
                        let n = sweep_state.tokens.purge_expired();
                        if n > 0 {
                            tracing::debug!(expired = n, "LLM gateway purged expired tokens");
                        }
                    }
                }
            }
        });

        tracing::info!(
            %addr,
            upstream = %state.upstream.api,
            default_model = %state.config.default_model,
            max_concurrent_requests = state.config.max_concurrent_requests,
            max_connections = state.config.server_limits.max_connections,
            cache_salt = state.config.cache_salt,
            "LLM gateway listening"
        );
        Ok(GatewayHandle {
            inner: Arc::new(HandleInner {
                addr,
                state,
                cancel,
                task: Mutex::new(Some(task)),
            }),
        })
    }
}

/// Control handle for a running gateway. Cheap to clone; the server stops
/// when [`GatewayHandle::shutdown`] is called or the last clone is dropped.
#[derive(Clone)]
pub struct GatewayHandle {
    inner: Arc<HandleInner>,
}

struct HandleInner {
    addr: SocketAddr,
    state: Arc<GatewayState>,
    cancel: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for HandleInner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl fmt::Debug for GatewayHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayHandle")
            .field("addr", &self.inner.addr)
            .finish_non_exhaustive()
    }
}

impl GatewayHandle {
    /// The bound address (useful with port 0).
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// The bound port.
    pub fn port(&self) -> u16 {
        self.inner.addr.port()
    }

    /// Issue a token for one container run. `label` (e.g. the group folder)
    /// is used for usage accounting and audit; `ttl` should be the
    /// container timeout. Only the token's SHA-256 digest is stored.
    pub fn issue_token(&self, label: &str, ttl: Duration) -> String {
        let token = self.inner.state.tokens.issue(label, ttl);
        tracing::debug!(label, ttl_secs = ttl.as_secs(), "LLM gateway token issued");
        token
    }

    /// Revoke a token (call when the run ends). Returns whether it existed.
    pub fn revoke(&self, token: &str) -> bool {
        self.inner.state.tokens.revoke(token)
    }

    /// Extend a live token so it stays valid for another `ttl` from now
    /// (e.g. when a follow-up message is piped into a long-running chat
    /// container). Never shortens a token and never revives an expired or
    /// revoked one. Returns whether the token was live.
    pub fn extend(&self, token: &str, ttl: Duration) -> bool {
        self.inner.state.tokens.extend(token, ttl)
    }

    /// Revoke every token issued for `label`. Returns how many were removed.
    pub fn revoke_label(&self, label: &str) -> usize {
        self.inner.state.tokens.revoke_label(label)
    }

    /// Counters and per-label usage.
    pub fn stats(&self) -> GatewayStats {
        self.inner
            .state
            .stats
            .snapshot(self.inner.state.tokens.active())
    }

    /// The base URL a container uses: `http://<host>:<port>/v1`
    /// (`host` is normally `host.docker.internal`).
    pub fn container_base_url(&self, host: &str) -> String {
        format!("http://{host}:{}/v1", self.port())
    }

    /// Build the [`LlmEndpoint`] for `ContainerInput.llm` from a freshly
    /// issued token and the run's effective vLLM settings. The model must be
    /// on the gateway's allow-list (else the gateway substitutes the default).
    pub fn endpoint(&self, token: String, host: &str, vllm: &VllmConfig) -> LlmEndpoint {
        let cap = self.inner.state.config.max_output_tokens_cap;
        let max_output_tokens = match (vllm.max_output_tokens, cap) {
            (Some(n), Some(c)) => Some(n.min(c)),
            (n, c) => n.or(c),
        };
        LlmEndpoint {
            base_url: self.container_base_url(host),
            token,
            model: vllm.model.clone(),
            fast_model: vllm.fast_model.clone(),
            max_context_tokens: vllm
                .max_context_tokens
                .unwrap_or(DEFAULT_MAX_CONTEXT_TOKENS),
            max_output_tokens,
            temperature: vllm.temperature,
            top_p: vllm.top_p,
            enable_thinking: vllm.enable_thinking,
            request_timeout_secs: vllm.request_timeout_secs,
        }
    }

    /// Stop accepting connections and wait (up to the configured
    /// `server_limits.shutdown_grace`) for in-flight requests; streams
    /// still running after that are ended.
    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        let task = {
            let mut guard = self.inner.task.lock().unwrap_or_else(|p| p.into_inner());
            guard.take()
        };
        if let Some(task) = task {
            let grace = self
                .inner
                .state
                .config
                .server_limits
                .shutdown_grace
                .saturating_add(Duration::from_secs(1));
            let abort = task.abort_handle();
            if tokio::time::timeout(grace, task).await.is_err() {
                abort.abort();
            }
        }
        self.inner.state.kill.cancel();
        tracing::info!(addr = %self.inner.addr, "LLM gateway stopped");
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct GatewayState {
    config: GatewayConfig,
    upstream: BaseUrls,
    upstream_auth: Option<HeaderValue>,
    http: reqwest::Client,
    tokens: TokenStore,
    stats: StatsRecorder,
    policy: RequestPolicy,
    /// Global in-flight cap (`None` = disabled).
    global: Option<Arc<Semaphore>>,
    /// Cancelled at the end of `shutdown`: ends streams still running.
    kill: CancellationToken,
    audit: SharedAuditSink,
    throttle: AuditThrottle,
}

impl GatewayState {
    /// Audit a denial, rate-limited so a flood cannot swamp the audit log.
    fn audit_denial(&self, kind: &str, actor: &str, target: &str, mut details: Value) {
        let Some(suppressed) = self.throttle.admit() else {
            return;
        };
        if suppressed > 0 {
            details["suppressed_since_last"] = json!(suppressed);
        }
        self.audit
            .record(event(kind, actor, Some(target), "denied", details));
    }

    fn audit_request(&self, label: &str, route: &str, outcome: &str, details: Value) {
        if self.config.audit_requests {
            self.audit.record(event(
                "gateway.request",
                label,
                Some(route),
                outcome,
                details,
            ));
        }
    }

    fn upstream_request(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.upstream_auth {
            Some(auth) => builder.header(AUTHORIZATION, auth.clone()),
            None => builder,
        }
    }
}

/// Fixed-window limiter for audit records.
struct AuditThrottle {
    max_per_window: u32,
    window: Duration,
    state: Mutex<ThrottleState>,
}

struct ThrottleState {
    window_start: Instant,
    count: u32,
    suppressed: u64,
}

impl AuditThrottle {
    fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            state: Mutex::new(ThrottleState {
                window_start: Instant::now(),
                count: 0,
                suppressed: 0,
            }),
        }
    }

    /// `Some(n)` = record now (n events were suppressed since the last
    /// record); `None` = suppress.
    fn admit(&self) -> Option<u64> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if now.saturating_duration_since(s.window_start) >= self.window {
            s.window_start = now;
            s.count = 0;
        }
        if s.count < self.max_per_window {
            s.count += 1;
            Some(std::mem::take(&mut s.suppressed))
        } else {
            s.suppressed += 1;
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

type SharedState = Arc<GatewayState>;

const ROUTE_CHAT: &str = "/v1/chat/completions";
const ROUTE_MODELS: &str = "/v1/models";
const ROUTE_TOKENIZE: &str = "/tokenize";

fn error_response(status: StatusCode, kind: &str, message: &str) -> Response {
    let body = json!({"error": {"message": message, "type": kind, "code": status.as_u16()}});
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Slots a request holds while it runs: the token's in-flight slot and a
/// global permit. Dropping it releases both.
struct AdmissionGuard {
    _slot: InFlightGuard,
    _permit: Option<OwnedSemaphorePermit>,
}

/// An authenticated request that got its slots.
struct Admission {
    label: String,
    guard: AdmissionGuard,
}

/// Authenticate, rate-limit, take the token's in-flight slot, then a global
/// permit. Keep the returned guard alive until the response is done.
fn admit(
    state: &GatewayState,
    headers: &HeaderMap,
    remote: SocketAddr,
    route: &str,
) -> Result<Admission, Box<Response>> {
    let (label, slot) = authenticate(state, headers, remote, route)?;
    let permit = match &state.global {
        None => None,
        Some(sem) => match Arc::clone(sem).try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                state.stats.overloaded();
                tracing::debug!(label, route, "LLM gateway at its global concurrency cap");
                state.audit_denial(
                    "gateway.request",
                    &label,
                    route,
                    json!({"reason": "overloaded", "remote": remote.ip().to_string()}),
                );
                let mut resp = error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "overloaded_error",
                    "LLM gateway is at its concurrency limit; retry later",
                );
                resp.headers_mut()
                    .insert(RETRY_AFTER, HeaderValue::from_static(OVERLOAD_RETRY_AFTER));
                return Err(Box::new(resp));
            }
        },
    };
    state.stats.request(&label);
    Ok(Admission {
        label,
        guard: AdmissionGuard {
            _slot: slot,
            _permit: permit,
        },
    })
}

/// Authenticate, rate-limit and take an in-flight slot. Returns the token's
/// label and the slot guard (keep it alive until the response is done).
fn authenticate(
    state: &GatewayState,
    headers: &HeaderMap,
    remote: SocketAddr,
    route: &str,
) -> Result<(String, InFlightGuard), Box<Response>> {
    let presented = extract_token(
        header_str(headers, AUTHORIZATION.as_str()),
        header_str(headers, "x-api-key"),
    );
    let decision = state.tokens.authorize(presented.as_deref());
    match decision {
        AuthDecision::Allowed { label, guard } => Ok((label, guard)),
        AuthDecision::TooManyConcurrent { label } => {
            state.stats.rate_limited(&label);
            state.audit_denial(
                "gateway.request",
                &label,
                route,
                json!({"reason": "too_many_concurrent", "remote": remote.ip().to_string()}),
            );
            let mut resp = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                "too many concurrent requests for this gateway token",
            );
            resp.headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("1"));
            Err(Box::new(resp))
        }
        AuthDecision::RateLimited { label, retry_after } => {
            state.stats.rate_limited(&label);
            state.audit_denial(
                "gateway.request",
                &label,
                route,
                json!({"reason": "rate_limited", "remote": remote.ip().to_string()}),
            );
            let secs = retry_after.as_secs_f64().ceil().max(1.0);
            let mut resp = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                "gateway token request budget exceeded",
            );
            if let Ok(v) = HeaderValue::from_str(&format!("{secs:.0}")) {
                resp.headers_mut().insert(RETRY_AFTER, v);
            }
            Err(Box::new(resp))
        }
        other => {
            state.stats.auth_failure();
            let label = match &other {
                AuthDecision::Expired { label } => Some(label.clone()),
                _ => None,
            };
            tracing::debug!(remote = %remote, route, reason = other.reason(), "LLM gateway auth failed");
            state.audit_denial(
                "gateway.auth.failed",
                &remote.ip().to_string(),
                route,
                json!({"reason": other.reason(), "label": label}),
            );
            let mut resp = error_response(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "missing, invalid or expired gateway token",
            );
            resp.headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            Err(Box::new(resp))
        }
    }
}

/// Refuse a request on policy grounds (counted + audited).
fn reject(
    state: &GatewayState,
    label: &str,
    route: &str,
    status: StatusCode,
    reason: &str,
    message: &str,
) -> Response {
    state.stats.rejected();
    state.audit_denial(
        "gateway.request",
        label,
        route,
        json!({"reason": reason, "status": status.as_u16()}),
    );
    error_response(status, "invalid_request_error", message)
}

async fn read_request_body(
    state: &GatewayState,
    headers: &HeaderMap,
    body: Body,
    label: &str,
    route: &str,
) -> Result<Bytes, Box<Response>> {
    let limit = state.config.max_body_bytes;
    let declared =
        header_str(headers, CONTENT_LENGTH.as_str()).and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|len| usize::try_from(len).map_or(true, |l| l > limit)) {
        return Err(Box::new(reject(
            state,
            label,
            route,
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "request body too large",
        )));
    }
    match tokio::time::timeout(BODY_READ_TIMEOUT, axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(Box::new(reject(
            state,
            label,
            route,
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "request body too large or unreadable",
        ))),
        Err(_) => Err(Box::new(reject(
            state,
            label,
            route,
            StatusCode::REQUEST_TIMEOUT,
            "body_timeout",
            "request body not received in time",
        ))),
    }
}

/// Read the body and parse it once. The raw bytes are dropped as soon as
/// the value exists; bodies with more than [`MAX_JSON_NODES`] values are
/// refused before parsing (bounds the `Value` blow-up per request).
async fn read_json_body(
    state: &GatewayState,
    headers: &HeaderMap,
    body: Body,
    label: &str,
    route: &str,
) -> Result<Value, Box<Response>> {
    let bytes = read_request_body(state, headers, body, label, route).await?;
    if !policy::json_nodes_within(&bytes, MAX_JSON_NODES) {
        return Err(Box::new(reject(
            state,
            label,
            route,
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_complex",
            "request body has too many JSON values",
        )));
    }
    serde_json::from_slice(&bytes).map_err(|_| {
        Box::new(reject(
            state,
            label,
            route,
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "request body is not valid JSON",
        ))
    })
}

/// Count and log what the policy changed (field names are client-chosen:
/// truncated, and `?`-formatted so control characters are escaped).
fn note_policy(state: &GatewayState, label: &str, route: &str, outcome: &PolicyOutcome) {
    if outcome.dropped_count > 0 {
        state.stats.dropped_fields(label, outcome.dropped_count);
    }
    if outcome.model_rewritten || outcome.dropped_count > 0 {
        tracing::debug!(
            label,
            route,
            model = %outcome.model,
            model_rewritten = outcome.model_rewritten,
            dropped = ?outcome.dropped,
            dropped_count = outcome.dropped_count,
            "LLM gateway rewrote request"
        );
    }
}

/// Serialize the filtered body once (consuming it) for the upstream.
fn encode_payload(json: Value) -> Result<Vec<u8>, Box<Response>> {
    serde_json::to_vec(&json).map_err(|_| {
        Box::new(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "cannot encode request",
        ))
    })
}

fn upstream_failure(state: &GatewayState, label: &str, route: &str, err: &LlmError) -> Response {
    state.stats.upstream_error(label);
    tracing::warn!(route, label, error = %err, "LLM gateway upstream request failed");
    state.audit_request(label, route, "error", json!({"error": err.to_string()}));
    match err {
        LlmError::Timeout(_) => error_response(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream_timeout",
            "upstream LLM server timed out",
        ),
        LlmError::ResponseTooLarge { .. } => error_response(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "upstream response too large",
        ),
        _ => error_response(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "upstream LLM server unavailable",
        ),
    }
}

fn upstream_auth_failure(
    state: &GatewayState,
    label: &str,
    route: &str,
    status: StatusCode,
) -> Response {
    state.stats.upstream_error(label);
    tracing::error!(
        route,
        status = status.as_u16(),
        "LLM gateway: upstream rejected the gateway's API key — check TALON_VLLM_API_KEY"
    );
    state.audit_request(
        label,
        route,
        "error",
        json!({"reason": "upstream_auth", "status": status.as_u16()}),
    );
    error_response(
        StatusCode::BAD_GATEWAY,
        "upstream_error",
        "upstream rejected the gateway's credentials",
    )
}

/// Copy status, content type and retry hints from an upstream response.
fn passthrough(status: StatusCode, upstream_headers: &HeaderMap, body: Vec<u8>) -> Response {
    let mut builder = Response::builder().status(status);
    let content_type = upstream_headers
        .get(CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));
    builder = builder.header(CONTENT_TYPE, content_type);
    if let Some(v) = upstream_headers.get(RETRY_AFTER) {
        builder = builder.header(RETRY_AFTER, v.clone());
    }
    builder.body(Body::from(body)).unwrap_or_else(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "cannot build response",
        )
    })
}

fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
}

/// Only the `usage` member is materialized; the rest of the response is
/// skipped by the deserializer without building a `Value` tree.
#[derive(Deserialize)]
struct UsageEnvelope {
    #[serde(default)]
    usage: Option<Usage>,
}

fn usage_from_json(bytes: &[u8]) -> Option<Usage> {
    serde_json::from_slice::<UsageEnvelope>(bytes).ok()?.usage
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn chat_completions(
    State(state): State<SharedState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Admission { label, guard } = match admit(&state, &headers, remote, ROUTE_CHAT) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    let mut json = match read_json_body(&state, &headers, body, &label, ROUTE_CHAT).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let outcome = match state.policy.apply_chat(&mut json, &label) {
        Ok(o) => o,
        Err(msg) => {
            return reject(
                &state,
                &label,
                ROUTE_CHAT,
                StatusCode::BAD_REQUEST,
                "policy",
                &msg,
            );
        }
    };
    note_policy(&state, &label, ROUTE_CHAT, &outcome);
    let payload = match encode_payload(json) {
        Ok(p) => p,
        Err(r) => return *r,
    };

    let started = Instant::now();
    let url = format!("{}/chat/completions", state.upstream.api);
    let accept = if outcome.stream {
        "text/event-stream"
    } else {
        "application/json"
    };
    let request = state.upstream_request(
        state
            .http
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, accept)
            .timeout(state.config.request_timeout)
            .body(payload),
    );
    let upstream = match request.send().await {
        Ok(r) => r,
        Err(e) => return upstream_failure(&state, &label, ROUTE_CHAT, &LlmError::from_reqwest(&e)),
    };
    let status = upstream.status();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return upstream_auth_failure(&state, &label, ROUTE_CHAT, status);
    }

    if outcome.stream && status.is_success() && is_event_stream(upstream.headers()) {
        // The stream's lifetime is bounded independently of the client:
        // a watchdog owns the slots and releases them at the deadline even
        // if the client stopped reading (hyper then never polls the body).
        let stop = state.kill.child_token();
        spawn_stream_watchdog(
            guard,
            stop.clone(),
            state
                .config
                .request_timeout
                .saturating_add(STREAM_DEADLINE_SLACK),
            label.clone(),
        );
        let tap = UsageTap {
            inner: Box::pin(upstream.bytes_stream()),
            decoder: Some(SseDecoder::default()),
            usage: None,
            state: state.clone(),
            label,
            model: outcome.model,
            started,
            completed: false,
            failed: false,
            stopped: false,
            stop: Box::pin(stop.clone().cancelled_owned()),
            _done: stop.drop_guard(),
        };
        return Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "text/event-stream")
            .header(CACHE_CONTROL, "no-cache")
            .header("x-accel-buffering", "no")
            .body(Body::from_stream(tap))
            .unwrap_or_else(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "cannot build response",
                )
            });
    }

    let upstream_headers = upstream.headers().clone();
    let body = match read_body_capped(upstream, state.config.max_response_bytes).await {
        Ok(b) => b,
        Err(e) => return upstream_failure(&state, &label, ROUTE_CHAT, &e),
    };
    drop(guard);
    if status.is_success() {
        let usage = usage_from_json(&body);
        state.stats.completion(&label, usage.as_ref(), false);
        state.audit_request(
            &label,
            ROUTE_CHAT,
            "allowed",
            request_details(&outcome.model, false, status, usage.as_ref(), started),
        );
    } else {
        state.stats.error(&label);
        tracing::debug!(
            label,
            status = status.as_u16(),
            "LLM gateway upstream returned an error"
        );
    }
    passthrough(status, &upstream_headers, body)
}

/// Own a streaming request's slots until the stream ends (`stop` is
/// cancelled by the stream's drop guard), the gateway shuts down (parent
/// token), or `deadline` passes — then cancel `stop` (the stream ends the
/// next time it is polled) and release the slots.
fn spawn_stream_watchdog(
    guard: AdmissionGuard,
    stop: CancellationToken,
    deadline: Duration,
    label: String,
) {
    tokio::spawn(async move {
        tokio::select! {
            () = stop.cancelled() => {}
            () = tokio::time::sleep(deadline) => {
                tracing::warn!(label, "LLM gateway stream exceeded its deadline; releasing its slots");
                stop.cancel();
            }
        }
        drop(guard);
    });
}

fn request_details(
    model: &str,
    stream: bool,
    status: StatusCode,
    usage: Option<&Usage>,
    started: Instant,
) -> Value {
    json!({
        "model": model,
        "stream": stream,
        "status": status.as_u16(),
        "prompt_tokens": usage.map(|u| u.prompt_tokens),
        "completion_tokens": usage.map(|u| u.completion_tokens),
        "cached_tokens": usage.map(|u| u.cached_tokens),
        "duration_ms": elapsed_ms(started),
    })
}

async fn list_models(
    State(state): State<SharedState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Admission {
        label,
        guard: _guard,
    } = match admit(&state, &headers, remote, ROUTE_MODELS) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    let url = format!("{}/models", state.upstream.api);
    let request = state.upstream_request(
        state
            .http
            .get(&url)
            .header(ACCEPT, "application/json")
            .timeout(AUX_TIMEOUT.min(state.config.request_timeout)),
    );
    let upstream = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            return upstream_failure(&state, &label, ROUTE_MODELS, &LlmError::from_reqwest(&e));
        }
    };
    let status = upstream.status();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return upstream_auth_failure(&state, &label, ROUTE_MODELS, status);
    }
    let upstream_headers = upstream.headers().clone();
    let body = match read_body_capped(upstream, 4 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return upstream_failure(&state, &label, ROUTE_MODELS, &e),
    };
    if !status.is_success() {
        state.stats.error(&label);
        return passthrough(status, &upstream_headers, body);
    }
    match serde_json::from_slice::<Value>(&body) {
        Ok(mut v) => {
            state.policy.filter_models(&mut v);
            (status, axum::Json(v)).into_response()
        }
        Err(_) => upstream_failure(
            &state,
            &label,
            ROUTE_MODELS,
            &LlmError::Decode("invalid /v1/models response".into()),
        ),
    }
}

async fn tokenize(
    State(state): State<SharedState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Admission {
        label,
        guard: _guard,
    } = match admit(&state, &headers, remote, ROUTE_TOKENIZE) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    let mut json = match read_json_body(&state, &headers, body, &label, ROUTE_TOKENIZE).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let outcome = match state.policy.apply_tokenize(&mut json) {
        Ok(o) => o,
        Err(msg) => {
            return reject(
                &state,
                &label,
                ROUTE_TOKENIZE,
                StatusCode::BAD_REQUEST,
                "policy",
                &msg,
            );
        }
    };
    note_policy(&state, &label, ROUTE_TOKENIZE, &outcome);
    let payload = match encode_payload(json) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let url = format!("{}/tokenize", state.upstream.root);
    let request = state.upstream_request(
        state
            .http
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .timeout(AUX_TIMEOUT.min(state.config.request_timeout))
            .body(payload),
    );
    let upstream = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            return upstream_failure(&state, &label, ROUTE_TOKENIZE, &LlmError::from_reqwest(&e));
        }
    };
    let status = upstream.status();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return upstream_auth_failure(&state, &label, ROUTE_TOKENIZE, status);
    }
    let upstream_headers = upstream.headers().clone();
    match read_body_capped(upstream, state.config.max_response_bytes).await {
        Ok(b) => passthrough(status, &upstream_headers, b),
        Err(e) => upstream_failure(&state, &label, ROUTE_TOKENIZE, &e),
    }
}

async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found_error", "not found")
}

// ---------------------------------------------------------------------------
// SSE passthrough with usage accounting
// ---------------------------------------------------------------------------

type UpstreamBytes = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

/// Passes upstream SSE bytes through unchanged while watching for the
/// usage chunk; records stats/audit when the stream ends or is dropped
/// (client disconnect). Ends early when `stop` fires (deadline/shutdown).
struct UsageTap {
    inner: UpstreamBytes,
    decoder: Option<SseDecoder>,
    usage: Option<Usage>,
    state: SharedState,
    label: String,
    model: String,
    started: Instant,
    completed: bool,
    failed: bool,
    /// `stop` fired; the stream has ended.
    stopped: bool,
    /// Deadline / shutdown signal (see [`spawn_stream_watchdog`]).
    stop: Pin<Box<WaitForCancellationFutureOwned>>,
    /// Cancels `stop` on drop, which makes the watchdog release the
    /// request's slots.
    _done: DropGuard,
}

impl UsageTap {
    fn inspect(&mut self, bytes: &[u8]) {
        let Some(decoder) = self.decoder.as_mut() else {
            return;
        };
        match decoder.push(bytes) {
            Ok(events) => {
                for ev in events {
                    if ev.data.contains("\"usage\"") {
                        if let Some(u) = usage_from_json(ev.data.as_bytes()) {
                            self.usage = Some(u);
                        }
                    }
                }
            }
            // Malformed / oversized SSE: stop inspecting, keep forwarding.
            Err(_) => self.decoder = None,
        }
    }
}

impl Stream for UsageTap {
    type Item = Result<Bytes, reqwest::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.stopped {
            return Poll::Ready(None);
        }
        if this.stop.as_mut().poll(cx).is_ready() {
            this.stopped = true;
            this.failed = true;
            tracing::debug!(label = %this.label, "LLM gateway stream ended by deadline or shutdown");
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                this.inspect(&bytes);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.failed = true;
                tracing::warn!(label = %this.label, error = %e, "LLM gateway upstream stream failed");
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.completed = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for UsageTap {
    fn drop(&mut self) {
        let ok = self.completed && !self.failed;
        if ok {
            self.state
                .stats
                .completion(&self.label, self.usage.as_ref(), true);
        } else {
            self.state.stats.error(&self.label);
        }
        self.state.audit_request(
            &self.label,
            ROUTE_CHAT,
            if ok { "allowed" } else { "error" },
            request_details(
                &self.model,
                true,
                StatusCode::OK,
                self.usage.as_ref(),
                self.started,
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_debug_redacts_key_and_from_vllm() {
        let vllm = VllmConfig {
            base_url: "http://vllm:8000".into(),
            model: "big".into(),
            fast_model: Some("small".into()),
            max_context_tokens: Some(65536),
            max_output_tokens: Some(4096),
            temperature: None,
            top_p: None,
            enable_thinking: None,
            request_timeout_secs: Some(120),
        };
        let cfg = GatewayConfig::from_vllm(&vllm, Some("sk-very-secret".into())).allow_model("big");
        assert_eq!(
            cfg.allowed_models,
            vec!["big".to_string(), "small".to_string()]
        );
        assert_eq!(cfg.max_output_tokens_cap, Some(4096));
        assert_eq!(cfg.request_timeout, Duration::from_secs(120));
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("sk-very-secret"), "{dbg}");
        assert!(
            GatewayConfig::from_vllm(&vllm, Some("  ".into()))
                .upstream_api_key
                .is_none()
        );
    }

    #[test]
    fn config_validation() {
        assert!(GatewayConfig::new("http://x", "").validate().is_err());
        let mut c = GatewayConfig::new("http://x", "m");
        c.max_body_bytes = 0;
        assert!(c.validate().is_err());
        let mut c = GatewayConfig::new("http://x", "m");
        c.server_limits.max_connections = 0;
        assert!(c.validate().is_err());
        let mut c = GatewayConfig::new("http://x", "m");
        c.server_limits.max_connections_per_ip = 0;
        assert!(c.validate().is_err());
        let mut c = GatewayConfig::new("http://x", "m");
        c.server_limits.header_read_timeout = Duration::ZERO;
        assert!(c.validate().is_err());
        assert!(GatewayConfig::new("http://x", "m").validate().is_ok());
    }

    #[test]
    fn hardened_defaults() {
        let vllm = VllmConfig {
            base_url: "http://vllm:8000".into(),
            model: "big".into(),
            fast_model: None,
            max_context_tokens: None,
            max_output_tokens: None,
            temperature: None,
            top_p: None,
            enable_thinking: None,
            request_timeout_secs: None,
        };
        for cfg in [
            GatewayConfig::new("http://x", "m"),
            GatewayConfig::from_vllm(&vllm, None),
        ] {
            assert_eq!(cfg.max_body_bytes, 4 * 1024 * 1024);
            assert_eq!(cfg.max_concurrent_requests, 32);
            assert_eq!(cfg.max_concurrent_per_token, 8);
            assert!(cfg.cache_salt);
            assert_eq!(cfg.server_limits.max_connections, 256);
            assert_eq!(cfg.server_limits.max_connections_per_ip, 64);
            assert!(!cfg.server_limits.header_read_timeout.is_zero());
            let dbg = format!("{cfg:?}");
            assert!(dbg.contains("max_concurrent_requests: 32"), "{dbg}");
        }
    }

    fn held_admission(store: &TokenStore, token: &str, sem: &Arc<Semaphore>) -> AdmissionGuard {
        let AuthDecision::Allowed { guard, .. } = store.authorize(Some(token)) else {
            panic!("token must be allowed");
        };
        AdmissionGuard {
            _slot: guard,
            _permit: Some(Arc::clone(sem).try_acquire_owned().unwrap()),
        }
    }

    /// A client that stops reading a stream never lets hyper poll the body
    /// again; the watchdog still gives the slots back at the deadline.
    #[tokio::test]
    async fn stream_watchdog_releases_slots_at_deadline_or_when_the_stream_ends() {
        let store = TokenStore::new(0, 1);
        let token = store.issue("lane", Duration::from_secs(60));
        let sem = Arc::new(Semaphore::new(1));

        let stop = CancellationToken::new();
        let guard = held_admission(&store, &token, &sem);
        spawn_stream_watchdog(
            guard,
            stop.clone(),
            Duration::from_millis(50),
            "lane".into(),
        );
        assert_eq!(sem.available_permits(), 0);
        assert!(matches!(
            store.authorize(Some(&token)),
            AuthDecision::TooManyConcurrent { .. }
        ));
        tokio::time::timeout(Duration::from_secs(5), stop.cancelled())
            .await
            .expect("deadline cancels the stream");
        for _ in 0..200 {
            if sem.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(sem.available_permits(), 1);
        assert!(matches!(
            store.authorize(Some(&token)),
            AuthDecision::Allowed { .. }
        ));

        // Normal end: the stream's drop guard cancels `stop` long before
        // the deadline.
        let stop = CancellationToken::new();
        let guard = held_admission(&store, &token, &sem);
        spawn_stream_watchdog(
            guard,
            stop.clone(),
            Duration::from_secs(3600),
            "lane".into(),
        );
        drop(stop.clone().drop_guard());
        for _ in 0..200 {
            if sem.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(sem.available_permits(), 1);
    }

    #[test]
    fn usage_is_read_without_materializing_the_body() {
        let body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],
            "usage":{"prompt_tokens":5,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":4}}}"#;
        let u = usage_from_json(body).unwrap();
        assert_eq!(
            (u.prompt_tokens, u.completion_tokens, u.cached_tokens),
            (5, 2, 4)
        );
        assert!(usage_from_json(br#"{"usage":null}"#).is_none());
        assert!(usage_from_json(br#"{"choices":[]}"#).is_none());
        assert!(usage_from_json(b"not json").is_none());
    }

    #[test]
    fn audit_throttle_counts_suppressed() {
        let t = AuditThrottle::new(2, Duration::from_secs(3600));
        assert_eq!(t.admit(), Some(0));
        assert_eq!(t.admit(), Some(0));
        assert_eq!(t.admit(), None);
        assert_eq!(t.admit(), None);
        let t2 = AuditThrottle::new(1, Duration::ZERO);
        assert_eq!(t2.admit(), Some(0));
        assert_eq!(t2.admit(), Some(0), "zero window resets every time");
    }
}
