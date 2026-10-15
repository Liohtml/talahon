//! MCP client over any newline-delimited JSON-RPC transport.
//!
//! An [`McpClient`] owns three background tasks: a writer (single ordered
//! queue to the server), a reader (dispatches responses to pending
//! requests, answers server->client requests, handles notifications) and,
//! for spawned servers, a stderr logger plus a process supervisor. All
//! methods take `&self`, so a client is normally shared as `Arc<McpClient>`.
//!
//! Failure semantics:
//! - malformed lines and invalid messages are logged and skipped;
//! - responses with unknown ids are ignored;
//! - when the server dies (EOF, write error, process exit) every pending
//!   and future request fails promptly with [`McpError::Closed`];
//! - timeouts and caller cancellation send `notifications/cancelled`;
//! - dropping the client kills a spawned server's process group.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::config::ServerConfig;
use crate::error::{MAX_REMOTE_MESSAGE_CHARS, McpError, truncate_chars};
use crate::jsonrpc::{self, Message, RequestId, RpcError, codes};
use crate::process::{self, ProcessControl, SpawnOptions};
use crate::transport::{
    BoxedReader, BoxedWriter, DEFAULT_MAX_MESSAGE_BYTES, Frame, LineReader, write_loop,
};
use crate::types::{
    CallToolResult, Implementation, InitializeResult, LATEST_PROTOCOL_VERSION, McpTool,
    SUPPORTED_PROTOCOL_VERSIONS, is_supported_protocol_version,
};

/// Capacity of the outgoing message queue.
const OUTGOING_QUEUE: usize = 256;
/// Max bytes of one stderr line kept/logged.
const STDERR_LINE_BYTES: usize = 8 * 1024;
/// Max chars of one stderr line stored in the tail buffer / logs.
const STDERR_LINE_CHARS: usize = 2000;
/// After the process exits, give the reader this long to drain the pipe
/// before failing pending requests.
const EXIT_DRAIN_GRACE: Duration = Duration::from_millis(1000);
/// On EOF / write failure, wait this long for the exit status to produce a
/// better close reason.
const EXIT_STATUS_WAIT: Duration = Duration::from_millis(500);

/// Tunables of an [`McpClient`].
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// `clientInfo` sent in `initialize` (default `talon-mcp/<version>`).
    pub client_info: Implementation,
    /// Protocol revision requested first (default [`LATEST_PROTOCOL_VERSION`]).
    pub protocol_version: String,
    /// Client capabilities sent in `initialize` (default `{}`).
    pub capabilities: Value,
    /// Timeout for `initialize` (default 30 s).
    pub init_timeout: Duration,
    /// Default timeout for other requests such as `tools/list` and `ping`
    /// (default 30 s).
    pub request_timeout: Duration,
    /// Default timeout for `tools/call` (default 300 s).
    pub tool_call_timeout: Duration,
    /// Maximum size of one message in either direction (default 16 MiB).
    pub max_message_bytes: usize,
    /// Maximum number of `tools/list` pages followed (default 100).
    pub max_tool_pages: usize,
    /// Number of stderr lines retained for diagnostics (default 50).
    pub stderr_tail_lines: usize,
    /// Grace period per shutdown phase (stdin EOF, then SIGTERM; default 2 s).
    pub shutdown_grace: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            client_info: Implementation::new("talon-mcp", env!("CARGO_PKG_VERSION")),
            protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
            capabilities: json!({}),
            init_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
            tool_call_timeout: Duration::from_secs(300),
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_tool_pages: 100,
            stderr_tail_lines: 50,
            shutdown_grace: Duration::from_secs(2),
        }
    }
}

type PendingTx = oneshot::Sender<Result<Value, McpError>>;

#[derive(Default)]
struct State {
    pending: HashMap<i64, PendingTx>,
    closed: Option<String>,
}

/// State shared between the client handle and its background tasks.
struct Shared {
    server: String,
    state: Mutex<State>,
    tools_generation: watch::Sender<u64>,
    stderr_tail: Mutex<VecDeque<String>>,
    stderr_tail_lines: usize,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Shared {
    fn register(&self, id: i64) -> Result<oneshot::Receiver<Result<Value, McpError>>, McpError> {
        let mut st = lock(&self.state);
        if let Some(reason) = &st.closed {
            return Err(McpError::Closed {
                server: self.server.clone(),
                reason: reason.clone(),
            });
        }
        let (tx, rx) = oneshot::channel();
        st.pending.insert(id, tx);
        Ok(rx)
    }

    fn complete(&self, id: i64, result: Result<Value, McpError>) -> bool {
        let tx = lock(&self.state).pending.remove(&id);
        match tx {
            Some(tx) => {
                let _ = tx.send(result);
                true
            }
            None => false,
        }
    }

    fn forget(&self, id: i64) {
        lock(&self.state).pending.remove(&id);
    }

    /// Mark closed and fail all pending requests. Returns true for the
    /// first call.
    fn close(&self, reason: impl Into<String>) -> bool {
        let reason = reason.into();
        let drained: Vec<PendingTx> = {
            let mut st = lock(&self.state);
            if st.closed.is_some() {
                return false;
            }
            st.closed = Some(reason.clone());
            st.pending.drain().map(|(_, tx)| tx).collect()
        };
        if reason != SHUTDOWN_REASON && reason != DROPPED_REASON {
            tracing::warn!(server = %self.server, reason = %reason, failed_requests = drained.len(), "MCP connection closed");
        }
        for tx in drained {
            let _ = tx.send(Err(McpError::Closed {
                server: self.server.clone(),
                reason: reason.clone(),
            }));
        }
        true
    }

    fn closed_reason(&self) -> Option<String> {
        lock(&self.state).closed.clone()
    }

    fn closed_error(&self) -> McpError {
        McpError::Closed {
            server: self.server.clone(),
            reason: self
                .closed_reason()
                .unwrap_or_else(|| "connection closed".to_string()),
        }
    }

    fn push_stderr(&self, line: String) {
        if self.stderr_tail_lines == 0 {
            return;
        }
        let mut tail = lock(&self.stderr_tail);
        if tail.len() >= self.stderr_tail_lines {
            tail.pop_front();
        }
        tail.push_back(line);
    }
}

const SHUTDOWN_REASON: &str = "client shut down";
const DROPPED_REASON: &str = "client dropped";

/// A connection to one MCP server.
pub struct McpClient {
    name: String,
    options: ClientOptions,
    shared: Arc<Shared>,
    outgoing: mpsc::Sender<Vec<u8>>,
    next_id: AtomicI64,
    init: OnceLock<InitializeResult>,
    init_lock: tokio::sync::Mutex<()>,
    process: Option<ProcessControl>,
    writer_stop: CancellationToken,
    lifetime: CancellationToken,
    _kill_on_drop: DropGuard,
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("name", &self.name)
            .field("pid", &self.pid())
            .field("initialized", &self.init.get().is_some())
            .field("closed", &self.shared.closed_reason())
            .finish()
    }
}

impl McpClient {
    /// Connect over an arbitrary transport (e.g. `tokio::io::duplex`
    /// halves, a socket split, or pipes). Does not send anything; call
    /// [`Self::initialize`] next.
    pub async fn connect<R, W>(
        name: impl Into<String>,
        reader: R,
        writer: W,
        options: ClientOptions,
    ) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Self::assemble(
            name.into(),
            Box::new(reader),
            Box::new(writer),
            options,
            CancellationToken::new(),
            None,
        )
    }

    /// Connect to a server exposed on a unix socket by the supervisor
    /// (see [`crate::config::socket_path`]).
    #[cfg(unix)]
    pub async fn connect_unix(
        name: impl Into<String>,
        path: impl AsRef<Path>,
        options: ClientOptions,
    ) -> Result<Self, McpError> {
        let name = name.into();
        let path = path.as_ref();
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .map_err(|source| McpError::Connect {
                server: name.clone(),
                path: path.to_path_buf(),
                source,
            })?;
        let (r, w) = stream.into_split();
        Ok(Self::connect(name, r, w, options).await)
    }

    /// Spawn a stdio server with default [`SpawnOptions`] and
    /// [`ClientOptions`].
    pub async fn spawn(name: &str, config: &ServerConfig) -> Result<Self, McpError> {
        Self::spawn_with(
            name,
            config,
            &SpawnOptions::default(),
            ClientOptions::default(),
        )
        .await
    }

    /// Spawn a stdio server. Its stderr is logged via `tracing` (target
    /// `talon::mcp::stderr`, level debug) and the last lines are kept (see
    /// [`Self::stderr_tail`]).
    pub async fn spawn_with(
        name: &str,
        config: &ServerConfig,
        spawn: &SpawnOptions,
        options: ClientOptions,
    ) -> Result<Self, McpError> {
        let mut cmd = process::build_command(name, config, spawn)?;
        let mut child = cmd.spawn().map_err(|source| McpError::Spawn {
            server: name.to_string(),
            source,
        })?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
            let _ = child.start_kill();
            return Err(McpError::Spawn {
                server: name.to_string(),
                source: std::io::Error::other("child stdio pipes unavailable"),
            });
        };
        tracing::debug!(server = %name, pid = ?child.id(), command = %config.command, "spawned MCP server");
        let lifetime = CancellationToken::new();
        let (exit_tx, exit_rx) = watch::channel(None);
        let group = cfg!(unix) && spawn.new_process_group;
        let control = process::supervise(name.to_string(), child, group, lifetime.clone(), exit_tx);
        let mut client = Self::assemble(
            name.to_string(),
            Box::new(stdout),
            Box::new(stdin),
            options,
            lifetime,
            Some(exit_rx),
        );
        client.process = Some(control);
        if let Some(stderr) = stderr {
            tokio::spawn(stderr_loop(
                stderr,
                Arc::clone(&client.shared),
                client.lifetime.clone(),
            ));
        }
        Ok(client)
    }

    fn assemble(
        name: String,
        reader: BoxedReader,
        writer: BoxedWriter,
        options: ClientOptions,
        lifetime: CancellationToken,
        exited: Option<watch::Receiver<Option<String>>>,
    ) -> Self {
        let (tools_generation, _) = watch::channel(0u64);
        let shared = Arc::new(Shared {
            server: name.clone(),
            state: Mutex::new(State::default()),
            tools_generation,
            stderr_tail: Mutex::new(VecDeque::new()),
            stderr_tail_lines: options.stderr_tail_lines,
        });
        let (out_tx, out_rx) = mpsc::channel(OUTGOING_QUEUE);
        let writer_stop = lifetime.child_token();
        {
            let shared = Arc::clone(&shared);
            let stop = writer_stop.clone();
            let exited = exited.clone();
            tokio::spawn(async move {
                if let Err(e) = write_loop(writer, out_rx, stop).await {
                    // A write usually fails because the process died; prefer
                    // its exit status as the reason.
                    let reason =
                        exit_reason_or(exited, format!("write to server failed: {e}")).await;
                    shared.close(reason);
                }
            });
        }
        tokio::spawn(read_loop(
            reader,
            Arc::clone(&shared),
            out_tx.clone(),
            lifetime.clone(),
            options.max_message_bytes,
            exited.clone(),
        ));
        if let Some(rx) = exited {
            tokio::spawn(exit_watch(rx, Arc::clone(&shared), lifetime.clone()));
        }
        Self {
            name,
            options,
            shared,
            outgoing: out_tx,
            next_id: AtomicI64::new(1),
            init: OnceLock::new(),
            init_lock: tokio::sync::Mutex::new(()),
            process: None,
            writer_stop,
            _kill_on_drop: lifetime.clone().drop_guard(),
            lifetime,
        }
    }

    /// Server name (from `.mcp.json`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Options in effect.
    pub fn options(&self) -> &ClientOptions {
        &self.options
    }

    /// PID of a spawned server process.
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().and_then(|p| p.pid)
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.shared.closed_reason().is_some()
    }

    /// Why the connection closed, if it did.
    pub fn closed_reason(&self) -> Option<String> {
        self.shared.closed_reason()
    }

    /// Result of a successful [`Self::initialize`].
    pub fn initialize_result(&self) -> Option<&InitializeResult> {
        self.init.get()
    }

    /// Negotiated protocol revision.
    pub fn protocol_version(&self) -> Option<&str> {
        self.init.get().map(|r| r.protocol_version.as_str())
    }

    /// Server-provided instructions (untrusted text).
    pub fn instructions(&self) -> Option<&str> {
        self.init.get().and_then(|r| r.instructions.as_deref())
    }

    /// Generation counter bumped on every
    /// `notifications/tools/list_changed`.
    pub fn tools_generation(&self) -> u64 {
        *self.shared.tools_generation.borrow()
    }

    /// Subscribe to `notifications/tools/list_changed` (the value is the
    /// generation counter).
    pub fn subscribe_tools_changed(&self) -> watch::Receiver<u64> {
        self.shared.tools_generation.subscribe()
    }

    /// The last stderr lines of a spawned server (may contain sensitive
    /// data; do not show to the model).
    pub fn stderr_tail(&self) -> Vec<String> {
        lock(&self.shared.stderr_tail).iter().cloned().collect()
    }

    /// Perform the `initialize` handshake and send
    /// `notifications/initialized`.
    ///
    /// Version negotiation: the client proposes
    /// [`ClientOptions::protocol_version`]; any revision in
    /// [`SUPPORTED_PROTOCOL_VERSIONS`] returned by the server is accepted.
    /// If the server rejects the request with an error whose `data.supported`
    /// lists a revision we support, the handshake is retried once with it.
    /// Calling this again after success returns the cached result.
    pub async fn initialize(&self) -> Result<InitializeResult, McpError> {
        // Serialize concurrent callers: only one handshake goes out.
        let _guard = self.init_lock.lock().await;
        if let Some(r) = self.init.get() {
            return Ok(r.clone());
        }
        let mut version = self.options.protocol_version.clone();
        let mut retried = false;
        loop {
            let params = json!({
                "protocolVersion": version,
                "capabilities": self.options.capabilities,
                "clientInfo": self.options.client_info,
            });
            let value = match self
                .request_inner(
                    "initialize",
                    Some(params),
                    self.options.init_timeout,
                    None,
                    false,
                )
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    if let McpError::Rpc {
                        data: Some(data), ..
                    } = &e
                    {
                        if let Some(alt) = pick_supported_version(data) {
                            if !retried && alt != version {
                                tracing::info!(server = %self.name, from = %version, to = %alt, "retrying MCP initialize with server-supported version");
                                version = alt;
                                retried = true;
                                continue;
                            }
                        }
                    }
                    return Err(e);
                }
            };
            let result: InitializeResult =
                serde_json::from_value(value).map_err(|e| McpError::Protocol {
                    server: self.name.clone(),
                    message: format!("invalid initialize result: {e}"),
                })?;
            if !is_supported_protocol_version(&result.protocol_version) {
                return Err(McpError::UnsupportedVersion {
                    server: self.name.clone(),
                    version: truncate_chars(&result.protocol_version, 64),
                });
            }
            self.notify("notifications/initialized", None).await?;
            tracing::info!(
                server = %self.name,
                protocol = %result.protocol_version,
                server_name = %truncate_chars(&result.server_info.name, 64),
                server_version = %truncate_chars(&result.server_info.version, 32),
                "MCP server initialized"
            );
            let _ = self.init.set(result.clone());
            return Ok(result);
        }
    }

    /// `ping`; succeeds if the server answers within the request timeout.
    pub async fn ping(&self) -> Result<(), McpError> {
        self.request("ping", None, None).await.map(|_| ())
    }

    /// `tools/list`, following `nextCursor` pagination. Malformed or
    /// duplicate tool entries are skipped with a warning; a server without
    /// tool support (method not found) yields an empty list.
    pub async fn list_tools(&self) -> Result<Vec<McpTool>, McpError> {
        self.ensure_initialized()?;
        let mut tools = Vec::new();
        let mut names = HashSet::new();
        let mut cursors = HashSet::new();
        let mut cursor: Option<String> = None;
        for _ in 0..self.options.max_tool_pages.max(1) {
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let page = match self.request("tools/list", params, None).await {
                Ok(v) => v,
                Err(e) if cursor.is_none() && e.rpc_code() == Some(codes::METHOD_NOT_FOUND) => {
                    return Ok(Vec::new());
                }
                Err(e) => return Err(e),
            };
            let Some(items) = page.get("tools").and_then(Value::as_array) else {
                return Err(McpError::Protocol {
                    server: self.name.clone(),
                    message: "tools/list result has no 'tools' array".into(),
                });
            };
            for item in items {
                match serde_json::from_value::<McpTool>(item.clone()) {
                    Ok(tool) if tool.name.is_empty() => {
                        tracing::warn!(server = %self.name, "skipping MCP tool with empty name");
                    }
                    Ok(tool) => {
                        if names.insert(tool.name.clone()) {
                            tools.push(tool);
                        } else {
                            tracing::warn!(server = %self.name, tool = %truncate_chars(&tool.name, 128), "skipping duplicate MCP tool");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(server = %self.name, error = %e, "skipping malformed MCP tool definition");
                    }
                }
            }
            match page.get("nextCursor").and_then(Value::as_str) {
                Some(next) if !next.is_empty() => {
                    if !cursors.insert(next.to_string()) {
                        tracing::warn!(server = %self.name, "MCP server repeated a tools/list cursor; stopping pagination");
                        return Ok(tools);
                    }
                    cursor = Some(next.to_string());
                }
                _ => return Ok(tools),
            }
        }
        tracing::warn!(server = %self.name, pages = self.options.max_tool_pages, "tools/list pagination limit reached");
        Ok(tools)
    }

    /// `tools/call`. `arguments` must be a JSON object (`null` is treated
    /// as `{}`). `timeout` defaults to [`ClientOptions::tool_call_timeout`].
    /// A tool-level failure is a successful call with
    /// [`CallToolResult::is_error`] set; protocol failures are `Err`.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
        timeout: Option<Duration>,
    ) -> Result<CallToolResult, McpError> {
        self.call_tool_inner(name, arguments, timeout, None).await
    }

    /// Like [`Self::call_tool`] but aborts (and notifies the server) when
    /// `cancel` fires.
    pub async fn call_tool_cancellable(
        &self,
        name: &str,
        arguments: Value,
        timeout: Option<Duration>,
        cancel: &CancellationToken,
    ) -> Result<CallToolResult, McpError> {
        self.call_tool_inner(name, arguments, timeout, Some(cancel))
            .await
    }

    async fn call_tool_inner(
        &self,
        name: &str,
        arguments: Value,
        timeout: Option<Duration>,
        cancel: Option<&CancellationToken>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_initialized()?;
        let arguments = match arguments {
            Value::Null => json!({}),
            Value::Object(_) => arguments,
            other => {
                return Err(McpError::InvalidArgument(format!(
                    "tool arguments must be a JSON object, got {}",
                    json_type_name(&other)
                )));
            }
        };
        let timeout = timeout.unwrap_or(self.options.tool_call_timeout);
        let value = self
            .request_inner(
                "tools/call",
                Some(json!({ "name": name, "arguments": arguments })),
                timeout,
                cancel,
                true,
            )
            .await?;
        if !value.is_object() {
            return Err(McpError::Protocol {
                server: self.name.clone(),
                message: "tools/call result is not an object".into(),
            });
        }
        serde_json::from_value(value).map_err(|e| McpError::Protocol {
            server: self.name.clone(),
            message: format!("invalid tools/call result: {e}"),
        })
    }

    /// Send an arbitrary request. `timeout` defaults to
    /// [`ClientOptions::request_timeout`].
    pub async fn request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Option<Duration>,
    ) -> Result<Value, McpError> {
        let timeout = timeout.unwrap_or(self.options.request_timeout);
        self.request_inner(method, params, timeout, None, true)
            .await
    }

    /// Send an arbitrary request that can be cancelled.
    pub async fn request_cancellable(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Option<Duration>,
        cancel: &CancellationToken,
    ) -> Result<Value, McpError> {
        let timeout = timeout.unwrap_or(self.options.request_timeout);
        self.request_inner(method, params, timeout, Some(cancel), true)
            .await
    }

    /// Send a notification.
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        if self.is_closed() {
            return Err(self.shared.closed_error());
        }
        let line = Message::notification(method, params).to_line()?;
        self.check_size(&line)?;
        match tokio::time::timeout(self.options.request_timeout, self.outgoing.send(line)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(self.shared.closed_error()),
            Err(_) => Err(McpError::Timeout {
                server: self.name.clone(),
                method: method.to_string(),
                timeout: self.options.request_timeout,
            }),
        }
    }

    async fn request_inner(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
        cancel: Option<&CancellationToken>,
        send_cancel: bool,
    ) -> Result<Value, McpError> {
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            return Err(McpError::Cancelled {
                server: self.name.clone(),
                method: method.to_string(),
            });
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let line = Message::request(id, method, params).to_line()?;
        self.check_size(&line)?;
        let rx = self.shared.register(id)?;
        let exchange = async {
            self.outgoing
                .send(line)
                .await
                .map_err(|_| self.shared.closed_error())?;
            rx.await.unwrap_or_else(|_| Err(self.shared.closed_error()))
        };
        let (outcome, reason) = tokio::select! {
            r = tokio::time::timeout(timeout, exchange) => match r {
                Ok(r) => return r,
                Err(_) => (
                    McpError::Timeout {
                        server: self.name.clone(),
                        method: method.to_string(),
                        timeout,
                    },
                    "request timed out",
                ),
            },
            _ = wait_cancelled(cancel) => (
                McpError::Cancelled {
                    server: self.name.clone(),
                    method: method.to_string(),
                },
                "request cancelled by client",
            ),
        };
        self.shared.forget(id);
        if send_cancel && !self.is_closed() {
            tracing::debug!(server = %self.name, method, id, reason, "abandoning MCP request");
            send_nowait(
                &self.shared,
                &self.outgoing,
                &jsonrpc::cancelled_notification(&RequestId::Number(id), reason),
            );
        }
        Err(outcome)
    }

    fn check_size(&self, line: &[u8]) -> Result<(), McpError> {
        if line.len() > self.options.max_message_bytes {
            return Err(McpError::MessageTooLarge {
                size: line.len(),
                limit: self.options.max_message_bytes,
            });
        }
        Ok(())
    }

    fn ensure_initialized(&self) -> Result<(), McpError> {
        if self.is_closed() {
            return Err(self.shared.closed_error());
        }
        if self.init.get().is_none() {
            return Err(McpError::NotInitialized {
                server: self.name.clone(),
            });
        }
        Ok(())
    }

    /// Graceful shutdown: fail pending requests, close the server's input
    /// (stdin / socket write half), then for spawned servers wait
    /// [`ClientOptions::shutdown_grace`], send `SIGTERM` to the process
    /// group, wait again and finally `SIGKILL`. Idempotent.
    pub async fn shutdown(&self) {
        self.shared.close(SHUTDOWN_REASON);
        self.writer_stop.cancel();
        if let Some(p) = &self.process {
            p.stop(self.options.shutdown_grace).await;
        }
        self.lifetime.cancel();
        tracing::debug!(server = %self.name, "MCP client shut down");
    }
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn pick_supported_version(data: &Value) -> Option<String> {
    let supported = data.get("supported")?.as_array()?;
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|v| supported.iter().any(|s| s.as_str() == Some(**v)))
        .map(|v| (*v).to_string())
}

async fn wait_cancelled(cancel: Option<&CancellationToken>) {
    match cancel {
        Some(c) => c.cancelled().await,
        None => std::future::pending().await,
    }
}

/// Queue a message without waiting; drops it (with a warning) when the
/// queue is full so the reader task can never deadlock on the writer.
fn send_nowait(shared: &Shared, out: &mpsc::Sender<Vec<u8>>, msg: &Message) {
    match msg.to_line() {
        Ok(line) => {
            if let Err(mpsc::error::TrySendError::Full(_)) = out.try_send(line) {
                tracing::warn!(server = %shared.server, "MCP outgoing queue full; dropping message");
            }
        }
        Err(e) => {
            tracing::warn!(server = %shared.server, error = %e, "failed to serialize MCP message")
        }
    }
}

/// Replace control characters and cap the length of untrusted text before
/// it reaches the logs.
pub(crate) fn sanitize_for_log(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_control() && c != '\t' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect();
    truncate_chars(&cleaned, STDERR_LINE_CHARS)
}

async fn read_loop(
    reader: BoxedReader,
    shared: Arc<Shared>,
    out: mpsc::Sender<Vec<u8>>,
    lifetime: CancellationToken,
    max_message_bytes: usize,
    exited: Option<watch::Receiver<Option<String>>>,
) {
    let mut lines = LineReader::new(reader, max_message_bytes);
    let reason = loop {
        let frame = tokio::select! {
            _ = lifetime.cancelled() => break DROPPED_REASON.to_string(),
            frame = lines.next_frame() => frame,
        };
        match frame {
            Ok(Some(Frame::Line(line))) => handle_line(&shared, &out, &line),
            Ok(Some(Frame::Oversize {
                len,
                prefix,
                suffix,
            })) => {
                handle_oversize(&shared, &out, len, max_message_bytes, &prefix, &suffix);
            }
            Ok(None) => {
                break exit_reason_or(exited, "server closed the connection (EOF)".to_string())
                    .await;
            }
            Err(e) => break format!("read from server failed: {e}"),
        }
    };
    shared.close(reason);
}

/// For spawned servers, wait briefly for the process exit description and
/// use it as the close reason; otherwise use `fallback`.
async fn exit_reason_or(
    exited: Option<watch::Receiver<Option<String>>>,
    fallback: String,
) -> String {
    if let Some(mut rx) = exited {
        if let Ok(Ok(status)) =
            tokio::time::timeout(EXIT_STATUS_WAIT, rx.wait_for(Option::is_some)).await
        {
            if let Some(s) = status.as_ref() {
                return s.clone();
            }
        }
    }
    fallback
}

/// Fails pending requests if the process exits while something (e.g. a
/// grandchild) keeps its stdout open.
async fn exit_watch(
    mut rx: watch::Receiver<Option<String>>,
    shared: Arc<Shared>,
    lifetime: CancellationToken,
) {
    let status = tokio::select! {
        _ = lifetime.cancelled() => return,
        s = rx.wait_for(Option::is_some) => match s {
            Ok(s) => s.clone().unwrap_or_default(),
            Err(_) => return,
        },
    };
    tokio::select! {
        _ = lifetime.cancelled() => {}
        _ = tokio::time::sleep(EXIT_DRAIN_GRACE) => {
            shared.close(status);
        }
    }
}

fn handle_line(shared: &Shared, out: &mpsc::Sender<Vec<u8>>, line: &[u8]) {
    let messages = match jsonrpc::parse_line(line) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(server = %shared.server, error = %e, len = line.len(), "skipping malformed line from MCP server");
            tracing::debug!(server = %shared.server, line = %sanitize_for_log(&String::from_utf8_lossy(line)), "malformed line");
            return;
        }
    };
    for msg in messages {
        match msg {
            Ok(Message::Response { id, result }) => handle_response(shared, id, result),
            Ok(Message::Request { id, method, params }) => {
                handle_server_request(shared, out, id, &method, params);
            }
            Ok(Message::Notification { method, params }) => {
                handle_notification(shared, &method, params);
            }
            Err(invalid) => {
                tracing::warn!(server = %shared.server, reason = %invalid.reason, "skipping invalid JSON-RPC message from MCP server");
                if let Some(id) = invalid.id {
                    // Best effort: it may have been a request.
                    tracing::debug!(server = %shared.server, id = %id, "invalid message carried an id");
                }
            }
        }
    }
}

fn handle_response(shared: &Shared, id: Option<RequestId>, result: Result<Value, RpcError>) {
    let Some(num) = id.as_ref().and_then(RequestId::as_i64) else {
        match &result {
            Err(e) => tracing::warn!(
                server = %shared.server,
                code = e.code,
                message = %sanitize_for_log(&e.message),
                "MCP server reported an error without a usable request id"
            ),
            Ok(_) => {
                tracing::debug!(server = %shared.server, id = ?id, "ignoring response with unknown id")
            }
        }
        return;
    };
    let outcome = result.map_err(|e| McpError::Rpc {
        server: shared.server.clone(),
        code: e.code,
        message: truncate_chars(&e.message, MAX_REMOTE_MESSAGE_CHARS),
        data: e.data,
    });
    if !shared.complete(num, outcome) {
        tracing::debug!(server = %shared.server, id = num, "ignoring response for unknown or abandoned request");
    }
}

fn handle_server_request(
    shared: &Shared,
    out: &mpsc::Sender<Vec<u8>>,
    id: RequestId,
    method: &str,
    _params: Option<Value>,
) {
    let result = match method {
        "ping" => Ok(json!({})),
        "roots/list" => Ok(json!({ "roots": [] })),
        other => {
            tracing::debug!(server = %shared.server, method = %sanitize_for_log(other), "rejecting unsupported server->client request");
            Err(RpcError::method_not_found(other))
        }
    };
    send_nowait(
        shared,
        out,
        &Message::Response {
            id: Some(id),
            result,
        },
    );
}

fn handle_notification(shared: &Shared, method: &str, params: Option<Value>) {
    match method {
        "notifications/tools/list_changed" => {
            shared.tools_generation.send_modify(|g| *g += 1);
            tracing::info!(server = %shared.server, "MCP server tool list changed");
        }
        "notifications/message" => {
            let params = params.unwrap_or(Value::Null);
            let level = params
                .get("level")
                .and_then(Value::as_str)
                .unwrap_or("info");
            let data = match params.get("data") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            let data = sanitize_for_log(&data);
            match level {
                "debug" | "info" | "notice" => {
                    tracing::debug!(target: "talon::mcp::server_log", server = %shared.server, level, "{data}");
                }
                "warning" => {
                    tracing::info!(target: "talon::mcp::server_log", server = %shared.server, level, "{data}");
                }
                _ => {
                    tracing::warn!(target: "talon::mcp::server_log", server = %shared.server, level = %sanitize_for_log(level), "{data}");
                }
            }
        }
        "notifications/progress" => {
            tracing::trace!(server = %shared.server, "MCP progress notification");
        }
        other => {
            tracing::debug!(server = %shared.server, method = %sanitize_for_log(other), "ignoring MCP notification");
        }
    }
}

fn handle_oversize(
    shared: &Shared,
    out: &mpsc::Sender<Vec<u8>>,
    len: usize,
    limit: usize,
    prefix: &[u8],
    suffix: &[u8],
) {
    let info = jsonrpc::scan_oversize(prefix, suffix);
    tracing::warn!(server = %shared.server, len, limit, id = ?info.id, "discarding oversized message from MCP server");
    let Some(id) = info.id else {
        return;
    };
    if info.has_method {
        send_nowait(
            shared,
            out,
            &Message::error_response(
                Some(id),
                RpcError::invalid_request(format!(
                    "message of {len} bytes exceeds the limit of {limit} bytes"
                )),
            ),
        );
    } else if let Some(num) = id.as_i64() {
        shared.complete(num, Err(McpError::MessageTooLarge { size: len, limit }));
    }
}

async fn stderr_loop<R: AsyncRead + Unpin>(
    stderr: R,
    shared: Arc<Shared>,
    lifetime: CancellationToken,
) {
    let mut lines = LineReader::new(stderr, STDERR_LINE_BYTES);
    loop {
        let frame = tokio::select! {
            _ = lifetime.cancelled() => break,
            f = lines.next_frame() => f,
        };
        let text = match frame {
            Ok(Some(Frame::Line(l))) => sanitize_for_log(&String::from_utf8_lossy(&l)),
            Ok(Some(Frame::Oversize { len, prefix, .. })) => format!(
                "{} [... line of {len} bytes truncated]",
                sanitize_for_log(&String::from_utf8_lossy(&prefix))
            ),
            Ok(None) | Err(_) => break,
        };
        tracing::debug!(target: "talon::mcp::stderr", server = %shared.server, "{text}");
        shared.push_stderr(text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_highest_common_version() {
        assert_eq!(
            pick_supported_version(&json!({"supported": ["2024-11-05", "2025-03-26"]})),
            Some("2025-03-26".to_string())
        );
        assert_eq!(
            pick_supported_version(&json!({"supported": ["1999"]})),
            None
        );
        assert_eq!(pick_supported_version(&json!({"supported": "x"})), None);
        assert_eq!(pick_supported_version(&json!({})), None);
    }

    #[test]
    fn sanitizes_log_text() {
        assert_eq!(sanitize_for_log("a\u{1b}[31mb\r"), "a\u{FFFD}[31mb\u{FFFD}");
        assert_eq!(sanitize_for_log("tab\tok"), "tab\tok");
        assert!(sanitize_for_log(&"x".repeat(5000)).chars().count() <= STDERR_LINE_CHARS + 1);
    }

    #[test]
    fn json_type_names() {
        assert_eq!(json_type_name(&json!([])), "array");
        assert_eq!(json_type_name(&json!("s")), "string");
        assert_eq!(json_type_name(&json!(1)), "number");
        assert_eq!(json_type_name(&json!(true)), "boolean");
        assert_eq!(json_type_name(&json!(null)), "null");
        assert_eq!(json_type_name(&json!({})), "object");
    }

    #[test]
    fn shared_close_fails_pending_and_rejects_new() {
        let (gen_tx, _) = watch::channel(0);
        let shared = Shared {
            server: "s".into(),
            state: Mutex::new(State::default()),
            tools_generation: gen_tx,
            stderr_tail: Mutex::new(VecDeque::new()),
            stderr_tail_lines: 2,
        };
        let mut rx = shared.register(1).unwrap();
        assert!(shared.close("gone"));
        assert!(!shared.close("again"));
        match rx.try_recv().unwrap() {
            Err(McpError::Closed { reason, .. }) => assert_eq!(reason, "gone"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(shared.register(2).is_err());
        assert!(!shared.complete(1, Ok(json!(1))));
        shared.push_stderr("a".into());
        shared.push_stderr("b".into());
        shared.push_stderr("c".into());
        assert_eq!(lock(&shared.stderr_tail).len(), 2);
    }
}
