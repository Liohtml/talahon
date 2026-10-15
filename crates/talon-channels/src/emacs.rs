//! Emacs bridge: a tiny HTTP API on `127.0.0.1` that `emacs/talon.el`
//! talks to.
//!
//! - `POST /api/message {"text": ".."}` -> `{"messageId", "timestamp"}` and
//!   the text is delivered to the host as a message on `emacs:default`
//!   (chat metadata first, then the message).
//! - `GET /api/messages?since=<epoch ms>` -> `{"messages": [{"text",
//!   "timestamp"}]}` with every buffered reply newer than `since`.
//! - Outbound replies are buffered (newest 200).
//! - On connect the `emacs:default` group is auto-registered (persisted)
//!   and a Markdown-formatting `CLAUDE.md` is bootstrapped in its folder.
//!
//! Hardened: the listener is bound to loopback only, a bearer token is
//! **required** (the bridge stays disabled without `EMACS_AUTH_TOKEN`)
//! and compared in constant time, failures are audited
//! (`http.auth.failed`), bodies are capped, reply timestamps and message ids
//! are strictly increasing (no message lost or overwritten when two land in
//! the same millisecond). The server runs on [`talon_net::serve`]
//! (header-read timeout, global and per-IP connection caps), so a local
//! slowloris client cannot exhaust the host's file descriptors.
//!
//! **Own folder.** The lane runs in its own real `groups/emacs` directory,
//! never a link to the main group's folder (a non-main lane writing there
//! could rewrite the `CLAUDE.md` that becomes main's system prompt). A leftover legacy symlink is never
//! followed or deleted: the bridge refuses to start and tells the operator
//! how to replace it. `CLAUDE.md` is created with `O_CREAT | O_EXCL`, so a
//! planted (even dangling) symlink can never redirect the write to a host
//! file.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, RawQuery, Request, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use serde_json::{Value, json};
use talon_core::audit::{SharedAuditSink, event};
use talon_core::channel::{Channel, ChannelHost, ChannelType};
use talon_core::env::EnvFile;
use talon_core::time::now_iso;
use talon_core::types::{ChatMetadata, NewMessage, RegisteredGroup};
use talon_core::{Error, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::security::{ConstantTimeEqFn, default_constant_time_eq};
use crate::util::{MonotonicMillis, project_root, secret_value, setting};

/// The single JID the bridge owns.
pub const EMACS_JID: &str = "emacs:default";
/// Group folder the Emacs lane runs in: its own real directory under
/// `groups/`, never a link to another group's folder.
pub const EMACS_GROUP_FOLDER: &str = "emacs";
/// Default listen port.
pub const DEFAULT_EMACS_PORT: u16 = 8766;
/// Env var: listen port.
pub const EMACS_CHANNEL_PORT_ENV: &str = "EMACS_CHANNEL_PORT";
/// Env var: bearer token (required to enable the bridge).
pub const EMACS_AUTH_TOKEN_ENV: &str = "EMACS_AUTH_TOKEN";
/// Replies kept for polling.
pub const MAX_BUFFERED_REPLIES: usize = 200;
/// Largest accepted request body.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// Simultaneous connections the bridge accepts (one local Emacs client).
pub const MAX_CONNECTIONS: usize = 32;
/// Simultaneous connections the bridge accepts from one peer IP.
pub const MAX_CONNECTIONS_PER_IP: usize = 16;

/// Connection limits of the bridge's HTTP server.
pub fn server_limits() -> talon_net::ServerLimits {
    talon_net::ServerLimits {
        max_connections: MAX_CONNECTIONS,
        max_connections_per_ip: MAX_CONNECTIONS_PER_IP,
        ..Default::default()
    }
}

const CLAUDE_MD: &str = "## Message Formatting

This is an Emacs channel. Responses are automatically converted from markdown
to org-mode by the bridge before display.

**Always format responses in standard markdown:**
- `**bold**` not `*bold*`
- `*italic*` not `/italic/`
- `~~strikethrough~~` not `+strikethrough+`
- `` `code` `` not `~code~`
- ` ```lang ` fenced code blocks
- `- ` for bullet points

Do NOT output org-mode syntax directly. The bridge handles conversion.
";

/// Emacs bridge configuration.
#[derive(Clone)]
pub struct EmacsConfig {
    /// TCP port on 127.0.0.1 (0 = ephemeral, for tests).
    pub port: u16,
    /// Bearer token the Emacs client must present. Required; never logged.
    pub auth_token: String,
    /// `groups/` directory holding the lane's own `emacs` folder and its
    /// `CLAUDE.md`. `None` skips the filesystem bootstrap.
    pub groups_dir: Option<PathBuf>,
}

impl std::fmt::Debug for EmacsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmacsConfig")
            .field("port", &self.port)
            .field("auth_token", &"<redacted>")
            .field("groups_dir", &self.groups_dir)
            .finish()
    }
}

impl EmacsConfig {
    /// From `EMACS_AUTH_TOKEN` (required) and `EMACS_CHANNEL_PORT`
    /// (default 8766); `groups_dir` is `<project root>/groups`. `None` when
    /// no token is configured or the port is invalid.
    pub fn from_env(env: &EnvFile) -> Option<Self> {
        let port_setting = setting(env, EMACS_CHANNEL_PORT_ENV);
        let Some(auth_token) = secret_value(env, EMACS_AUTH_TOKEN_ENV) else {
            if port_setting.is_some() {
                warn!(
                    "Emacs bridge disabled: EMACS_CHANNEL_PORT is set but EMACS_AUTH_TOKEN is not (a token is now required)"
                );
            }
            return None;
        };
        let port = match port_setting {
            None => DEFAULT_EMACS_PORT,
            Some(raw) => match raw.parse::<u16>() {
                Ok(port) => port,
                Err(_) => {
                    warn!(value = %raw, "Emacs bridge disabled: invalid EMACS_CHANNEL_PORT");
                    return None;
                }
            },
        };
        Some(Self {
            port,
            auth_token,
            groups_dir: project_root(env).map(|root| root.join("groups")),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct BufferedReply {
    text: String,
    timestamp: i64,
}

struct Shared {
    host: Arc<dyn ChannelHost>,
    audit: SharedAuditSink,
    token: String,
    buffer: Mutex<VecDeque<BufferedReply>>,
    reply_clock: MonotonicMillis,
    id_clock: MonotonicMillis,
}

#[derive(Clone)]
struct AppState {
    shared: Arc<Shared>,
    ct_eq: ConstantTimeEqFn,
}

struct Server {
    addr: SocketAddr,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// Emacs bridge channel (owns [`EMACS_JID`]).
pub struct EmacsBridgeChannel {
    port: u16,
    groups_dir: Option<PathBuf>,
    shared: Arc<Shared>,
    ct_eq: ConstantTimeEqFn,
    listening: Arc<AtomicBool>,
    server: tokio::sync::Mutex<Option<Server>>,
}

impl std::fmt::Debug for EmacsBridgeChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmacsBridgeChannel")
            .field("port", &self.port)
            .field("listening", &self.listening.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl EmacsBridgeChannel {
    /// Build the bridge. Fails when the token is empty (fail closed).
    pub fn new(
        config: EmacsConfig,
        host: Arc<dyn ChannelHost>,
        audit: SharedAuditSink,
    ) -> Result<Self> {
        let token = config.auth_token.trim().to_string();
        if token.is_empty() {
            return Err(Error::Config(
                "Emacs bridge requires a non-empty EMACS_AUTH_TOKEN".to_string(),
            ));
        }
        if token.len() < 16 {
            warn!("EMACS_AUTH_TOKEN is shorter than 16 characters; use a long random token");
        }
        Ok(Self {
            port: config.port,
            groups_dir: config.groups_dir,
            shared: Arc::new(Shared {
                host,
                audit,
                token,
                buffer: Mutex::new(VecDeque::new()),
                reply_clock: MonotonicMillis::default(),
                id_clock: MonotonicMillis::default(),
            }),
            ct_eq: default_constant_time_eq(),
            listening: Arc::new(AtomicBool::new(false)),
            server: tokio::sync::Mutex::new(None),
        })
    }

    /// Replace the constant-time comparison (tests).
    pub fn with_constant_time_eq(mut self, ct_eq: ConstantTimeEqFn) -> Self {
        self.ct_eq = ct_eq;
        self
    }

    /// Bound address while connected (useful with port 0).
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.server.lock().await.as_ref().map(|s| s.addr)
    }

    fn router(&self) -> Router {
        let state = AppState {
            shared: Arc::clone(&self.shared),
            ct_eq: self.ct_eq,
        };
        Router::new()
            .route("/api/message", post(handle_post))
            .route("/api/messages", get(handle_poll))
            .fallback(not_found)
            .method_not_allowed_fallback(not_found)
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_bearer,
            ))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .with_state(state)
    }

    async fn ensure_group_registered(&self) {
        if let Some(existing) = self.shared.host.registered_groups().get(EMACS_JID) {
            if existing.folder != EMACS_GROUP_FOLDER {
                // An operator choice; the bridge does not rewrite it, but
                // the lane then does not use the folder prepared here.
                warn!(
                    folder = %existing.folder,
                    "Emacs lane is registered on a folder other than groups/emacs; it shares that folder's files and CLAUDE.md"
                );
            }
            return;
        }
        let group = RegisteredGroup {
            name: "emacs".to_string(),
            folder: EMACS_GROUP_FOLDER.to_string(),
            trigger: String::new(),
            added_at: now_iso(),
            container_config: None,
            requires_trigger: Some(false),
            is_main: false,
            session_key: None,
            ipc_key: None,
            ephemeral_session: false,
            trusted_session_commands: false,
        };
        self.shared
            .host
            .register_group(EMACS_JID, group, true)
            .await;
        info!("Emacs group auto-registered");
    }
}

/// Make sure `<groups_dir>/emacs` is the lane's own real directory and
/// return its path.
///
/// # Errors
/// The entry is a symlink (the legacy layout linked it to the main group's
/// folder) or anything else that is not a directory, or it cannot be
/// created. The entry is never followed, replaced or deleted: the operator
/// decides what to keep.
fn prepare_group_dir(groups_dir: &Path) -> Result<PathBuf> {
    let dir = talon_core::paths::group_folder_path(groups_dir, EMACS_GROUP_FOLDER)?;
    std::fs::create_dir_all(groups_dir).map_err(|e| {
        Error::Channel(format!(
            "Emacs bridge cannot create {}: {e}",
            groups_dir.display()
        ))
    })?;
    // `mkdir` never follows a symlink in the last component: an existing
    // entry of any kind is reported as `AlreadyExists` and inspected below.
    match std::fs::create_dir(&dir) {
        Ok(()) => info!(dir = %dir.display(), "Emacs channel: created group folder"),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(Error::Channel(format!(
                "Emacs bridge cannot create {}: {e}",
                dir.display()
            )));
        }
    }
    let meta = std::fs::symlink_metadata(&dir)
        .map_err(|e| Error::Channel(format!("Emacs bridge cannot stat {}: {e}", dir.display())))?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&dir)
            .map(|t| t.display().to_string())
            .unwrap_or_else(|_| "?".to_string());
        return Err(Error::Config(format!(
            "Emacs bridge not started: {dir} is a symlink to {target} (legacy layout that let \
             the non-main Emacs lane write another group's folder and CLAUDE.md). Replace it \
             with a real directory: `rm {dir}` (removes only the link, not its target), copy \
             any instructions the Emacs lane should keep into {dir}/CLAUDE.md, then restart \
             Talon. The bridge creates the folder itself when it is missing.",
            dir = dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(Error::Config(format!(
            "Emacs bridge not started: {} exists but is not a directory; move it away and \
             restart Talon",
            dir.display()
        )));
    }
    Ok(dir)
}

/// Bootstrap `<dir>/CLAUDE.md` with the Emacs formatting instructions.
///
/// The file is opened with `create_new` (`O_CREAT | O_EXCL`), which fails on
/// any existing entry, including a dangling symlink: an agent-planted link
/// can never redirect the write to a host file, and an existing file is
/// left untouched.
fn ensure_claude_md(dir: &Path) {
    let path = dir.join("CLAUDE.md");
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, CLAUDE_MD.as_bytes()));
    match written {
        Ok(()) => info!("Emacs channel: wrote CLAUDE.md"),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let is_link = std::fs::symlink_metadata(&path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if is_link {
                warn!(
                    path = %path.display(),
                    "Emacs channel: CLAUDE.md is a symlink; left untouched (never written through)"
                );
            } else {
                debug!("Emacs channel: CLAUDE.md already exists");
            }
        }
        Err(e) => warn!(err = %e, "Emacs channel: could not write CLAUDE.md"),
    }
}

#[async_trait]
impl Channel for EmacsBridgeChannel {
    fn name(&self) -> &str {
        "emacs"
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Markdown
    }

    async fn connect(&self) -> Result<()> {
        let mut server = self.server.lock().await;
        if server.is_some() {
            return Ok(());
        }
        // Filesystem first: a legacy `groups/emacs` symlink stops the
        // bridge before the lane is registered (the host's registration
        // would otherwise create directories through the link). The host
        // logs the returned error and keeps running without the bridge.
        if let Some(groups_dir) = &self.groups_dir {
            let dir = prepare_group_dir(groups_dir)?;
            ensure_claude_md(&dir);
        }
        self.ensure_group_registered().await;

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, self.port))
            .await
            .map_err(|e| {
                Error::Channel(format!(
                    "Emacs bridge cannot bind 127.0.0.1:{}: {e}",
                    self.port
                ))
            })?;
        let addr = listener.local_addr()?;
        let app = self.router();
        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let listening = Arc::clone(&self.listening);
        listening.store(true, Ordering::SeqCst);
        let handle = tokio::spawn(async move {
            // Header-read timeout and connection caps: no slowloris FD
            // exhaustion through the bridge.
            talon_net::serve(listener, app, server_limits(), shutdown).await;
            listening.store(false, Ordering::SeqCst);
        });
        info!(
            port = addr.port(),
            "Emacs channel listening — load emacs/talon.el to connect"
        );
        *server = Some(Server {
            addr,
            cancel,
            handle,
        });
        Ok(())
    }

    async fn send_message(&self, _jid: &str, text: &str) -> Result<()> {
        let mut buffer = self.shared.buffer.lock().unwrap_or_else(|e| e.into_inner());
        buffer.push_back(BufferedReply {
            text: text.to_string(),
            timestamp: self.shared.reply_clock.next(),
        });
        while buffer.len() > MAX_BUFFERED_REPLIES {
            buffer.pop_front();
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.listening.load(Ordering::SeqCst)
    }

    fn owns_jid(&self, jid: &str) -> bool {
        jid == EMACS_JID
    }

    async fn disconnect(&self) -> Result<()> {
        let Some(server) = self.server.lock().await.take() else {
            return Ok(());
        };
        server.cancel.cancel();
        let mut handle = server.handle;
        // `serve` drains open connections for at most `shutdown_grace`.
        let wait = server_limits().shutdown_grace + Duration::from_secs(2);
        if tokio::time::timeout(wait, &mut handle).await.is_err() {
            handle.abort();
        }
        self.listening.store(false, Ordering::SeqCst);
        info!("Emacs channel stopped");
        Ok(())
    }
}

// ---- HTTP handlers -----------------------------------------------------------

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// `Bearer <token>` (scheme case-insensitive).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    Some(token.trim()).filter(|t| !t.is_empty())
}

async fn require_bearer(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let authorized = bearer_token(request.headers())
        .is_some_and(|token| (state.ct_eq)(token.as_bytes(), state.shared.token.as_bytes()));
    if authorized {
        return next.run(request).await;
    }
    let path = request.uri().path().to_string();
    state.shared.audit.record(event(
        "http.auth.failed",
        "channel:emacs",
        Some(&path),
        "denied",
        json!({
            "method": request.method().as_str(),
            "has_credentials": request.headers().contains_key(AUTHORIZATION),
        }),
    ));
    warn!(path, "Emacs bridge: unauthorized request");
    json_error(StatusCode::UNAUTHORIZED, "Unauthorized")
}

async fn not_found() -> Response {
    json_error(StatusCode::NOT_FOUND, "Not found")
}

async fn handle_post(State(state): State<AppState>, body: Bytes) -> Response {
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };
    let Some(text) = parsed
        .get("text")
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty())
    else {
        return json_error(StatusCode::BAD_REQUEST, "text required");
    };

    let shared = &state.shared;
    let id_ms = shared.id_clock.next();
    let timestamp = now_iso();
    let message_id = format!("emacs-{id_ms}");

    shared
        .host
        .on_chat_metadata(ChatMetadata {
            chat_jid: EMACS_JID.to_string(),
            timestamp: timestamp.clone(),
            name: Some("Emacs".to_string()),
            channel: Some("emacs".to_string()),
            is_group: Some(false),
        })
        .await;
    shared
        .host
        .on_message(
            EMACS_JID,
            NewMessage {
                id: message_id.clone(),
                chat_jid: EMACS_JID.to_string(),
                sender: "emacs".to_string(),
                sender_name: "Emacs".to_string(),
                content: text.to_string(),
                timestamp,
                is_from_me: false,
                ..NewMessage::default()
            },
        )
        .await;
    info!(length = text.chars().count(), "Emacs message received");
    (
        StatusCode::OK,
        Json(json!({ "messageId": message_id, "timestamp": id_ms })),
    )
        .into_response()
}

async fn handle_poll(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let mut since: i64 = 0;
    if let Some(query) = query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if key == "since" {
                match value.trim().parse::<i64>() {
                    Ok(v) => since = v,
                    Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid since"),
                }
            }
        }
    }
    let messages: Vec<BufferedReply> = state
        .shared
        .buffer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|m| m.timestamp > since)
        .cloned()
        .collect();
    (StatusCode::OK, Json(json!({ "messages": messages }))).into_response()
}

#[cfg(test)]
mod tests;
