//! The anonymizing MCP proxy: line-delimited JSON-RPC between a client
//! (the agent, on our stdin/stdout) and an upstream MCP server (a child
//! process).
//!
//! Client -> upstream:
//! - `tools/call` for `deanonymize` is answered locally (never forwarded);
//! - other `tools/call` arguments are de-anonymized before forwarding (the
//!   model can search for `USER_1`; the SIEM receives `john.doe`), and
//!   OpenSearch aggregation names are remembered as field hints;
//! - every request id is tracked so responses can be matched to methods;
//! - unparseable lines get a `-32700` reply; oversize lines are dropped
//!   with an error reply when their id can be recovered.
//!
//! Upstream -> client:
//! - `tools/list` results get the `deanonymize` tool appended (last page);
//! - `tools/call` results are anonymized (content blocks incl. JSON in text,
//!   `structuredContent`, everything else); error objects, responses to
//!   unknown ids, and server-initiated requests/notifications are
//!   anonymized generically; `initialize`/`ping`/list results pass through;
//! - non-JSON output (stray prints) is dropped, never forwarded raw;
//! - oversize responses become a JSON-RPC error for the pending request;
//! - when the upstream exits, every pending request gets a JSON-RPC error
//!   and the proxy shuts down. When the client closes its input, the
//!   upstream's stdin is closed and its remaining output is relayed for a
//!   grace period.
//!
//! Anonymization runs on the blocking pool; per direction, message order is
//! preserved.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::engine::{Anonymizer, FieldHints};
use crate::jsonrpc::{
    DEANONYMIZE_TOOL_NAME, INTERNAL_ERROR, INVALID_REQUEST, MessageKind, PARSE_ERROR,
    RESPONSE_TOO_LARGE, TOO_MANY_PENDING, UPSTREAM_EXITED, classify, deanonymize_tool,
    error_response, extract_id, id_key, result_response, to_line,
};
use crate::session::{SharedSession, lock_session};

/// Bytes of an oversize line kept for id recovery.
const HEAD_KEEP: usize = 64 * 1024;
/// Queue depth per direction.
const CHANNEL_CAPACITY: usize = 256;
/// Responses whose results pass through untouched.
const PASSTHROUGH_METHODS: &[&str] = &[
    "initialize",
    "ping",
    "prompts/list",
    "resources/list",
    "resources/templates/list",
    "logging/setLevel",
];

/// Proxy tuning.
#[derive(Debug, Clone)]
pub struct ProxyOptions {
    /// Maximum size of one JSON-RPC line (either direction).
    pub max_line_bytes: usize,
    /// How long to wait for the upstream after the client closed its input
    /// (or after cancellation) before giving up on it.
    pub shutdown_grace: Duration,
    /// De-anonymize `tools/call` arguments before forwarding them upstream.
    pub deanonymize_arguments: bool,
    /// Maximum requests waiting for the upstream.
    pub max_pending: usize,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            max_line_bytes: 32 * 1024 * 1024,
            shutdown_grace: Duration::from_secs(10),
            deanonymize_arguments: true,
            max_pending: 4096,
        }
    }
}

/// Why [`run_proxy`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyOutcome {
    /// The client closed its input (normal shutdown).
    ClientClosed,
    /// The upstream closed its output / exited.
    UpstreamClosed,
    /// Writing to the client failed (client gone).
    ClientOutputClosed,
    /// The cancellation token fired (signal).
    Cancelled,
}

// ---------------------------------------------------------------------------
// Line reader
// ---------------------------------------------------------------------------

/// One line read by [`LineReader`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A complete line without the trailing `\n` / `\r\n`.
    Complete(Vec<u8>),
    /// A line longer than the limit: its first bytes and its total length.
    Oversize {
        /// The first (up to 64 KiB) bytes.
        head: Vec<u8>,
        /// Total length in bytes.
        len: usize,
    },
}

/// Newline-delimited reader with a hard per-line limit (oversize lines are
/// consumed without being buffered). A final line without `\n` is returned
/// at EOF.
pub struct LineReader<R> {
    inner: BufReader<R>,
    max: usize,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    /// Wrap `reader`; lines longer than `max` bytes are reported as
    /// [`Line::Oversize`].
    pub fn new(reader: R, max: usize) -> Self {
        Self {
            inner: BufReader::with_capacity(64 * 1024, reader),
            max: max.max(1),
        }
    }

    /// Next line, or `None` at EOF.
    pub async fn next_line(&mut self) -> io::Result<Option<Line>> {
        let mut buf: Vec<u8> = Vec::new();
        let mut total = 0usize;
        let mut oversize = false;
        let mut saw_any = false;
        loop {
            let (consumed, done) = {
                let avail = self.inner.fill_buf().await?;
                if avail.is_empty() {
                    if !saw_any {
                        return Ok(None);
                    }
                    break;
                }
                saw_any = true;
                let (chunk, found) = match avail.iter().position(|&b| b == b'\n') {
                    Some(i) => (&avail[..i], true),
                    None => (avail, false),
                };
                total = total.saturating_add(chunk.len());
                if !oversize && buf.len() + chunk.len() > self.max {
                    oversize = true;
                    buf.truncate(HEAD_KEEP);
                }
                if oversize {
                    let room = HEAD_KEEP.saturating_sub(buf.len());
                    buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
                } else {
                    buf.extend_from_slice(chunk);
                }
                (chunk.len() + usize::from(found), found)
            };
            self.inner.consume(consumed);
            if done {
                break;
            }
        }
        if oversize {
            return Ok(Some(Line::Oversize {
                head: buf,
                len: total,
            }));
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        Ok(Some(Line::Complete(buf)))
    }
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &b[start..end]
}

fn raw_line(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(b'\n');
    v
}

// ---------------------------------------------------------------------------
// Message routing (synchronous; runs on the blocking pool)
// ---------------------------------------------------------------------------

struct Pending {
    id: Value,
    method: String,
    hints: FieldHints,
}

/// Lines produced for one client message.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClientOut {
    /// Line to forward to the upstream.
    pub upstream: Option<Vec<u8>>,
    /// Line to answer the client with directly.
    pub client: Option<Vec<u8>>,
}

enum Single {
    Forward(Value, bool),
    Reply(Value),
}

/// Stateful message router shared by both directions.
pub struct Router {
    session: SharedSession,
    pending: Mutex<HashMap<String, Pending>>,
    opts: ProxyOptions,
}

impl Router {
    /// New router over `session`.
    pub fn new(session: SharedSession, opts: ProxyOptions) -> Self {
        Self {
            session,
            pending: Mutex::new(HashMap::new()),
            opts,
        }
    }

    fn pending(&self) -> MutexGuard<'_, HashMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of requests waiting for the upstream.
    pub fn pending_count(&self) -> usize {
        self.pending().len()
    }

    fn with_tx<R>(&self, f: impl FnOnce(&mut Anonymizer) -> R) -> R {
        lock_session(&self.session).transaction(f)
    }

    /// Dispatch one line read from the client.
    pub fn on_client(&self, line: Line) -> ClientOut {
        match line {
            Line::Complete(l) => self.handle_client_line(&l),
            Line::Oversize { head, len } => self.handle_client_oversize(&head, len),
        }
    }

    /// Dispatch one line read from the upstream.
    pub fn on_upstream(&self, line: Line) -> Option<Vec<u8>> {
        match line {
            Line::Complete(l) => self.handle_upstream_line(&l),
            Line::Oversize { head, len } => self.handle_upstream_oversize(&head, len),
        }
    }

    /// Handle one complete client line.
    pub fn handle_client_line(&self, line: &[u8]) -> ClientOut {
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() {
            return ClientOut::default();
        }
        let value: Value = match serde_json::from_slice(trimmed) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(bytes = trimmed.len(), "client sent invalid JSON");
                return ClientOut {
                    client: Some(to_line(&error_response(
                        Value::Null,
                        PARSE_ERROR,
                        "Parse error",
                    ))),
                    upstream: None,
                };
            }
        };
        match value {
            Value::Array(items) => {
                if items.is_empty() {
                    return ClientOut {
                        client: Some(to_line(&error_response(
                            Value::Null,
                            INVALID_REQUEST,
                            "Invalid Request",
                        ))),
                        upstream: None,
                    };
                }
                let (mut fwd, mut local) = (Vec::new(), Vec::new());
                for item in items {
                    match self.client_single(item) {
                        Single::Forward(v, _) => fwd.push(v),
                        Single::Reply(v) => local.push(v),
                    }
                }
                ClientOut {
                    upstream: (!fwd.is_empty()).then(|| to_line(&Value::Array(fwd))),
                    client: (!local.is_empty()).then(|| to_line(&Value::Array(local))),
                }
            }
            v => match self.client_single(v) {
                Single::Forward(v, modified) => ClientOut {
                    upstream: Some(if modified {
                        to_line(&v)
                    } else {
                        raw_line(trimmed)
                    }),
                    client: None,
                },
                Single::Reply(v) => ClientOut {
                    client: Some(to_line(&v)),
                    upstream: None,
                },
            },
        }
    }

    fn client_single(&self, mut v: Value) -> Single {
        match classify(&v) {
            MessageKind::Request { id, method } => {
                if method == "tools/call" {
                    let name = v
                        .get("params")
                        .and_then(|p| p.get("name"))
                        .and_then(Value::as_str);
                    if name == Some(DEANONYMIZE_TOOL_NAME) {
                        return Single::Reply(self.local_deanonymize(id, &v));
                    }
                    let hints = v
                        .get("params")
                        .and_then(|p| p.get("arguments"))
                        .map(FieldHints::from_arguments)
                        .unwrap_or_default();
                    let mut modified = false;
                    if self.opts.deanonymize_arguments {
                        if let Some(args) = v.get_mut("params").and_then(|p| p.get_mut("arguments"))
                        {
                            modified =
                                lock_session(&self.session).read(|a| a.deanonymize_json(args));
                        }
                    }
                    if let Err(reply) = self.track(id, method, hints) {
                        return Single::Reply(reply);
                    }
                    return Single::Forward(v, modified);
                }
                if let Err(reply) = self.track(id, method, FieldHints::default()) {
                    return Single::Reply(reply);
                }
                Single::Forward(v, false)
            }
            MessageKind::Notification { method } => {
                if method == "notifications/cancelled" {
                    if let Some(rid) = v.get("params").and_then(|p| p.get("requestId")) {
                        self.pending().remove(&id_key(rid));
                    }
                }
                Single::Forward(v, false)
            }
            // A reply to a server-initiated request: pass through.
            MessageKind::Response { .. } => Single::Forward(v, false),
            MessageKind::Invalid => {
                let id = v.get("id").cloned().unwrap_or(Value::Null);
                Single::Reply(error_response(id, INVALID_REQUEST, "Invalid Request"))
            }
        }
    }

    fn track(&self, id: Value, method: String, hints: FieldHints) -> Result<(), Value> {
        let mut p = self.pending();
        let key = id_key(&id);
        if !p.contains_key(&key) && p.len() >= self.opts.max_pending {
            tracing::warn!(pending = p.len(), "too many requests in flight; rejecting");
            return Err(error_response(
                id,
                TOO_MANY_PENDING,
                "too many requests in flight",
            ));
        }
        p.insert(key, Pending { id, method, hints });
        Ok(())
    }

    fn local_deanonymize(&self, id: Value, req: &Value) -> Value {
        let text = req
            .get("params")
            .and_then(|p| p.get("arguments"))
            .and_then(|a| a.get("text"))
            .and_then(Value::as_str);
        match text {
            Some(t) => {
                let restored = lock_session(&self.session).read(|a| a.deanonymize_text(t));
                tracing::info!(
                    chars = t.chars().count(),
                    "deanonymize tool answered locally"
                );
                result_response(id, json!({"content": [{"type": "text", "text": restored}]}))
            }
            None => result_response(
                id,
                json!({
                    "content": [{"type": "text", "text": "deanonymize: missing required string argument `text`"}],
                    "isError": true
                }),
            ),
        }
    }

    /// Handle an oversize client line: dropped, answered with an error if
    /// its id can be recovered.
    pub fn handle_client_oversize(&self, head: &[u8], len: usize) -> ClientOut {
        tracing::warn!(
            bytes = len,
            limit = self.opts.max_line_bytes,
            "client message exceeds the line limit; dropped"
        );
        let client = extract_id(head).map(|id| {
            to_line(&error_response(
                id,
                INVALID_REQUEST,
                &format!(
                    "request exceeds the proxy limit of {} bytes",
                    self.opts.max_line_bytes
                ),
            ))
        });
        ClientOut {
            client,
            upstream: None,
        }
    }

    /// Handle one complete upstream line; returns the line for the client.
    pub fn handle_upstream_line(&self, line: &[u8]) -> Option<Vec<u8>> {
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() {
            return None;
        }
        let value: Value = match serde_json::from_slice(trimmed) {
            Ok(v) => v,
            Err(_) => {
                return self.unprocessable_upstream(
                    trimmed,
                    INTERNAL_ERROR,
                    "upstream response could not be parsed",
                );
            }
        };
        match value {
            Value::Array(items) => {
                let out: Vec<Value> = items
                    .into_iter()
                    .filter_map(|i| self.upstream_single(i).map(|(v, _)| v))
                    .collect();
                (!out.is_empty()).then(|| to_line(&Value::Array(out)))
            }
            v => {
                let (v, passthrough) = self.upstream_single(v)?;
                Some(if passthrough {
                    raw_line(trimmed)
                } else {
                    to_line(&v)
                })
            }
        }
    }

    /// Returns the message for the client and whether the original bytes
    /// may be forwarded unchanged.
    fn upstream_single(&self, mut v: Value) -> Option<(Value, bool)> {
        match classify(&v) {
            MessageKind::Request { .. } | MessageKind::Notification { .. } => {
                // Server-initiated traffic (logging, progress, sampling) can
                // carry data too.
                if let Some(params) = v.get_mut("params") {
                    self.with_tx(|a| a.anonymize_json(params));
                }
                Some((v, false))
            }
            MessageKind::Response { id } => {
                let pending = self.pending().remove(&id_key(&id));
                if let Some(err) = v.get_mut("error") {
                    self.with_tx(|a| {
                        if let Some(Value::String(m)) = err.get_mut("message") {
                            *m = a.anonymize_text(m);
                        }
                        if let Some(d) = err.get_mut("data") {
                            a.anonymize_json(d);
                        }
                    });
                    return Some((v, false));
                }
                let (method, hints) = match pending {
                    Some(p) => (Some(p.method), p.hints),
                    None => (None, FieldHints::default()),
                };
                match method.as_deref() {
                    Some("tools/list") => {
                        append_deanonymize_tool(&mut v);
                        Some((v, false))
                    }
                    Some(m) if PASSTHROUGH_METHODS.contains(&m) => Some((v, true)),
                    Some("tools/call") => {
                        if let Some(r) = v.get_mut("result") {
                            self.with_tx(|a| a.anonymize_tool_result(r, &hints));
                        }
                        Some((v, false))
                    }
                    other => {
                        if other.is_none() {
                            tracing::debug!(
                                "response for an untracked id; anonymizing generically"
                            );
                        }
                        if let Some(r) = v.get_mut("result") {
                            self.with_tx(|a| {
                                if r.get("content").is_some_and(Value::is_array) {
                                    a.anonymize_tool_result(r, &hints)
                                } else {
                                    a.anonymize_json_with_hints(r, &hints)
                                }
                            });
                        }
                        Some((v, false))
                    }
                }
            }
            MessageKind::Invalid => {
                tracing::warn!("upstream sent an invalid JSON-RPC message; dropped");
                None
            }
        }
    }

    fn unprocessable_upstream(&self, bytes: &[u8], code: i64, message: &str) -> Option<Vec<u8>> {
        tracing::warn!(
            bytes = bytes.len(),
            reason = message,
            "upstream output dropped"
        );
        let head = &bytes[..bytes.len().min(HEAD_KEEP)];
        let id = extract_id(head)?;
        let p = self.pending().remove(&id_key(&id))?;
        Some(to_line(&error_response(p.id, code, message)))
    }

    /// Handle an oversize upstream line: never forwarded; the pending
    /// request (if its id can be recovered) gets an error.
    pub fn handle_upstream_oversize(&self, head: &[u8], len: usize) -> Option<Vec<u8>> {
        let msg = format!(
            "upstream response exceeded the proxy limit of {} bytes ({len} bytes)",
            self.opts.max_line_bytes
        );
        self.unprocessable_upstream(head, RESPONSE_TOO_LARGE, &msg)
    }

    /// Error responses for every request still waiting for the upstream.
    pub fn drain_pending(&self, message: &str) -> Vec<Vec<u8>> {
        let drained: Vec<Pending> = self.pending().drain().map(|(_, p)| p).collect();
        if !drained.is_empty() {
            tracing::warn!(
                count = drained.len(),
                reason = message,
                "failing pending requests"
            );
        }
        drained
            .into_iter()
            .map(|p| to_line(&error_response(p.id, UPSTREAM_EXITED, message)))
            .collect()
    }
}

/// Append the `deanonymize` tool to a `tools/list` response (last page only,
/// once).
fn append_deanonymize_tool(v: &mut Value) {
    let Some(result) = v.get_mut("result").and_then(Value::as_object_mut) else {
        return;
    };
    if result.get("nextCursor").is_some_and(|c| !c.is_null()) {
        return;
    }
    let tools = result
        .entry("tools")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(list) = tools {
        if !list
            .iter()
            .any(|t| t.get("name").and_then(Value::as_str) == Some(DEANONYMIZE_TOOL_NAME))
        {
            list.push(deanonymize_tool());
        }
    }
}

// ---------------------------------------------------------------------------
// Async plumbing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientEnd {
    Eof,
    UpstreamGone,
    ClientOutputGone,
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut w: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    while let Some(line) = rx.recv().await {
        w.write_all(&line).await?;
        if rx.is_empty() {
            w.flush().await?;
        }
    }
    w.flush().await?;
    let _ = w.shutdown().await;
    Ok(())
}

async fn client_loop<R: AsyncRead + Unpin>(
    router: Arc<Router>,
    input: R,
    to_upstream: mpsc::Sender<Vec<u8>>,
    to_client: mpsc::Sender<Vec<u8>>,
) -> ClientEnd {
    let mut reader = LineReader::new(input, router.opts.max_line_bytes);
    loop {
        let line = match reader.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => return ClientEnd::Eof,
            Err(e) => {
                tracing::warn!(error = %e, "reading from the client failed");
                return ClientEnd::Eof;
            }
        };
        let r = Arc::clone(&router);
        let out = match tokio::task::spawn_blocking(move || r.on_client(line)).await {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(error = %e, "client message handler failed");
                continue;
            }
        };
        if let Some(l) = out.client {
            if to_client.send(l).await.is_err() {
                return ClientEnd::ClientOutputGone;
            }
        }
        if let Some(l) = out.upstream {
            if to_upstream.send(l).await.is_err() {
                tracing::warn!("upstream input closed");
                return ClientEnd::UpstreamGone;
            }
        }
    }
}

async fn upstream_loop<R: AsyncRead + Unpin>(
    router: Arc<Router>,
    input: R,
    to_client: mpsc::Sender<Vec<u8>>,
) {
    let mut reader = LineReader::new(input, router.opts.max_line_bytes);
    loop {
        let line = match reader.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => {
                tracing::info!("upstream closed its output");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "reading from the upstream failed");
                return;
            }
        };
        let r = Arc::clone(&router);
        let out = match tokio::task::spawn_blocking(move || r.on_upstream(line)).await {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(error = %e, "upstream message handler failed");
                continue;
            }
        };
        if let Some(l) = out {
            if to_client.send(l).await.is_err() {
                return;
            }
        }
    }
}

async fn wait_or_abort<T>(handle: &mut JoinHandle<T>, grace: Duration) -> bool {
    if tokio::time::timeout(grace, &mut *handle).await.is_ok() {
        true
    } else {
        handle.abort();
        false
    }
}

/// Run the proxy until either side closes (or `cancel` fires).
///
/// `client_in`/`client_out` are the agent side (normally our stdin/stdout);
/// `upstream_stdin`/`upstream_stdout` are the child's pipes. The upstream's
/// stdin is closed (dropped) before this returns.
pub async fn run_proxy<CI, CO, UW, UR>(
    session: SharedSession,
    opts: ProxyOptions,
    client_in: CI,
    client_out: CO,
    upstream_stdin: UW,
    upstream_stdout: UR,
    cancel: CancellationToken,
) -> ProxyOutcome
where
    CI: AsyncRead + Unpin + Send + 'static,
    CO: AsyncWrite + Unpin + Send + 'static,
    UW: AsyncWrite + Unpin + Send + 'static,
    UR: AsyncRead + Unpin + Send + 'static,
{
    let grace = opts.shutdown_grace;
    let router = Arc::new(Router::new(session, opts));
    let (cl_tx, cl_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    let (up_tx, up_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    let mut client_writer = tokio::spawn(write_loop(client_out, cl_rx));
    let mut upstream_writer = tokio::spawn(write_loop(upstream_stdin, up_rx));
    let mut client_reader = tokio::spawn(client_loop(
        Arc::clone(&router),
        client_in,
        up_tx,
        cl_tx.clone(),
    ));
    let mut upstream_reader = tokio::spawn(upstream_loop(
        Arc::clone(&router),
        upstream_stdout,
        cl_tx.clone(),
    ));

    let mut writer_done = false;
    let mut upstream_writer_done = false;
    let outcome = tokio::select! {
        end = &mut client_reader => match end {
            Ok(ClientEnd::ClientOutputGone) => {
                upstream_reader.abort();
                ProxyOutcome::ClientOutputClosed
            }
            Ok(ClientEnd::UpstreamGone) => {
                wait_or_abort(&mut upstream_reader, grace).await;
                ProxyOutcome::UpstreamClosed
            }
            _ => {
                // The client is done; the upstream's stdin closes once the
                // queued lines are written. Relay what it still sends.
                if !wait_or_abort(&mut upstream_reader, grace).await {
                    tracing::warn!("upstream did not finish within the grace period after the client closed");
                }
                ProxyOutcome::ClientClosed
            }
        },
        _ = &mut upstream_reader => {
            client_reader.abort();
            ProxyOutcome::UpstreamClosed
        }
        _ = &mut client_writer => {
            writer_done = true;
            client_reader.abort();
            upstream_reader.abort();
            ProxyOutcome::ClientOutputClosed
        }
        _ = cancel.cancelled() => {
            // Dropping the client reader drops the last upstream sender: the
            // writer flushes and closes the upstream's stdin.
            client_reader.abort();
            wait_or_abort(&mut upstream_writer, Duration::from_millis(500)).await;
            upstream_writer_done = true;
            wait_or_abort(&mut upstream_reader, grace).await;
            ProxyOutcome::Cancelled
        }
    };

    if outcome != ProxyOutcome::ClientOutputClosed {
        let reason = match outcome {
            ProxyOutcome::UpstreamClosed => "upstream MCP server exited before responding",
            _ => "proxy shut down before the upstream MCP server responded",
        };
        for line in router.drain_pending(reason) {
            if cl_tx.send(line).await.is_err() {
                break;
            }
        }
    }
    drop(cl_tx);
    if !writer_done
        && tokio::time::timeout(Duration::from_secs(5), &mut client_writer)
            .await
            .is_err()
    {
        client_writer.abort();
    }
    if !upstream_writer_done {
        wait_or_abort(&mut upstream_writer, Duration::from_millis(500)).await;
    }
    outcome
}

#[cfg(test)]
mod tests;
