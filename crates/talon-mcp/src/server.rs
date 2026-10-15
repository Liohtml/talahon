//! Minimal MCP server serving a set of [`talon_core::tool::Tool`]s over
//! any newline-delimited transport (stdio, unix socket, `duplex`).
//!
//! Supports `initialize` (with version negotiation), `ping`, `tools/list`
//! (optionally paginated), `tools/call` (concurrent, cancellable via
//! `notifications/cancelled`), and answers everything else with
//! `-32601 Method not found`.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::FutureExt;
use serde_json::{Value, json};
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolSpec};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::error::McpError;
use crate::jsonrpc::{self, InvalidMessage, Message, RequestId, RpcError};
use crate::transport::{DEFAULT_MAX_MESSAGE_BYTES, Frame, LineReader, write_loop};
use crate::types::{
    CallToolResult, ContentBlock, Implementation, LATEST_PROTOCOL_VERSION,
    is_supported_protocol_version,
};

type InFlight = Arc<Mutex<HashMap<RequestId, CancellationToken>>>;

/// Builder for [`McpServer`].
pub struct McpServerBuilder {
    info: Implementation,
    instructions: Option<String>,
    tools: Vec<Arc<dyn Tool>>,
    context: Option<ToolContext>,
    page_size: usize,
    max_message_bytes: usize,
    drain_timeout: Duration,
}

impl McpServerBuilder {
    /// Add a tool. Tools are listed in insertion order; a later tool with
    /// the same name as an earlier one is ignored.
    pub fn tool(mut self, tool: Arc<dyn Tool>) -> Self {
        self.tools.push(tool);
        self
    }

    /// Add several tools.
    pub fn tools(mut self, tools: impl IntoIterator<Item = Arc<dyn Tool>>) -> Self {
        self.tools.extend(tools);
        self
    }

    /// Instructions returned from `initialize`.
    pub fn instructions(mut self, text: impl Into<String>) -> Self {
        self.instructions = Some(text.into());
        self
    }

    /// Context passed to every tool call. Its `cancel` token stops the
    /// server; each call gets a child token. Default: current directory as
    /// `cwd`, **no** allowed roots, not main.
    pub fn context(mut self, ctx: ToolContext) -> Self {
        self.context = Some(ctx);
        self
    }

    /// Tools per `tools/list` page (0 = all in one page, the default).
    pub fn page_size(mut self, n: usize) -> Self {
        self.page_size = n;
        self
    }

    /// Maximum incoming message size (default 16 MiB).
    pub fn max_message_bytes(mut self, n: usize) -> Self {
        self.max_message_bytes = n;
        self
    }

    /// How long in-flight calls may finish after the client disconnects
    /// (default 5 s); afterwards they are cancelled.
    pub fn drain_timeout(mut self, d: Duration) -> Self {
        self.drain_timeout = d;
        self
    }

    /// Finish.
    pub fn build(self) -> McpServer {
        let mut entries: Vec<(ToolSpec, Arc<dyn Tool>)> = Vec::new();
        let mut index = HashMap::new();
        for tool in self.tools {
            let spec = tool.spec();
            if index.contains_key(&spec.name) {
                tracing::warn!(tool = %spec.name, "duplicate tool name; ignoring later definition");
                continue;
            }
            index.insert(spec.name.clone(), entries.len());
            entries.push((spec, tool));
        }
        McpServer {
            inner: Arc::new(ServerInner {
                info: self.info,
                instructions: self.instructions,
                entries,
                index,
                context: self.context.unwrap_or_else(default_context),
                page_size: self.page_size,
                max_message_bytes: self.max_message_bytes,
                drain_timeout: self.drain_timeout,
            }),
        }
    }
}

fn default_context() -> ToolContext {
    ToolContext {
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        allowed_roots: Vec::new(),
        read_only_roots: Vec::new(),
        group_folder: String::new(),
        chat_jid: String::new(),
        is_main: false,
        ipc_dir: PathBuf::new(),
        cancel: CancellationToken::new(),
    }
}

struct ServerInner {
    info: Implementation,
    instructions: Option<String>,
    entries: Vec<(ToolSpec, Arc<dyn Tool>)>,
    index: HashMap<String, usize>,
    context: ToolContext,
    page_size: usize,
    max_message_bytes: usize,
    drain_timeout: Duration,
}

/// An MCP server exposing [`Tool`]s. Cheap to clone; one instance can
/// serve many connections.
#[derive(Clone)]
pub struct McpServer {
    inner: Arc<ServerInner>,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("info", &self.inner.info)
            .field("tools", &self.inner.index.len())
            .finish()
    }
}

impl McpServer {
    /// Start building a server named `name`/`version`.
    pub fn builder(name: impl Into<String>, version: impl Into<String>) -> McpServerBuilder {
        McpServerBuilder {
            info: Implementation::new(name, version),
            instructions: None,
            tools: Vec::new(),
            context: None,
            page_size: 0,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            drain_timeout: Duration::from_secs(5),
        }
    }

    /// Specs of the served tools, in listing order.
    pub fn tool_specs(&self) -> Vec<ToolSpec> {
        self.inner.entries.iter().map(|(s, _)| s.clone()).collect()
    }

    /// Serve this process's stdin/stdout until EOF.
    pub async fn serve_stdio(&self) -> Result<(), McpError> {
        self.serve(tokio::io::stdin(), tokio::io::stdout()).await
    }

    /// Serve one accepted unix-socket connection until EOF.
    #[cfg(unix)]
    pub async fn serve_unix(&self, stream: tokio::net::UnixStream) -> Result<(), McpError> {
        let (r, w) = stream.into_split();
        self.serve(r, w).await
    }

    /// Serve one connection until the reader hits EOF (or the context's
    /// cancel token fires). In-flight calls get
    /// [`McpServerBuilder::drain_timeout`] to finish; queued responses are
    /// flushed before returning.
    pub async fn serve<R, W>(&self, reader: R, writer: W) -> Result<(), McpError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let conn_cancel = self.inner.context.cancel.child_token();
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
        let writer_task = tokio::spawn(write_loop(writer, out_rx, CancellationToken::new()));
        let in_flight: InFlight = Arc::new(Mutex::new(HashMap::new()));
        let mut tasks: JoinSet<()> = JoinSet::new();
        let mut lines = LineReader::new(reader, self.inner.max_message_bytes);

        let read_result = loop {
            let frame = tokio::select! {
                _ = conn_cancel.cancelled() => break Ok(()),
                Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
                frame = lines.next_frame() => frame,
            };
            match frame {
                Ok(None) => break Ok(()),
                Err(e) => break Err(McpError::Io(e)),
                Ok(Some(Frame::Oversize {
                    len,
                    prefix,
                    suffix,
                })) => {
                    let info = jsonrpc::scan_oversize(&prefix, &suffix);
                    tracing::warn!(
                        len,
                        limit = self.inner.max_message_bytes,
                        "discarding oversized MCP request"
                    );
                    if let (Some(id), true) = (info.id, info.has_method) {
                        let err = RpcError::invalid_request(format!(
                            "message of {len} bytes exceeds the limit of {} bytes",
                            self.inner.max_message_bytes
                        ));
                        send(&out_tx, Message::error_response(Some(id), err)).await;
                    }
                }
                Ok(Some(Frame::Line(line))) => match jsonrpc::parse_line(&line) {
                    Ok(messages) => {
                        for msg in messages {
                            self.dispatch(msg, &out_tx, &mut tasks, &in_flight, &conn_cancel)
                                .await;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "MCP server received malformed JSON");
                        send(
                            &out_tx,
                            Message::error_response(
                                None,
                                RpcError::parse_error(format!("Parse error: {e}")),
                            ),
                        )
                        .await;
                    }
                },
            }
        };

        // Let in-flight calls finish, then cancel the stragglers.
        let drained = tokio::time::timeout(self.inner.drain_timeout, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        if !drained {
            conn_cancel.cancel();
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        drop(out_tx);
        match writer_task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!(error = %e, "MCP server write failed"),
            Err(e) => tracing::debug!(error = %e, "MCP server writer task failed"),
        }
        read_result
    }

    async fn dispatch(
        &self,
        msg: Result<Message, InvalidMessage>,
        out: &mpsc::Sender<Vec<u8>>,
        tasks: &mut JoinSet<()>,
        in_flight: &InFlight,
        conn_cancel: &CancellationToken,
    ) {
        match msg {
            Err(invalid) => {
                send(
                    out,
                    Message::error_response(invalid.id, RpcError::invalid_request(invalid.reason)),
                )
                .await;
            }
            Ok(Message::Response { .. }) => {
                tracing::debug!("MCP server ignoring unexpected response");
            }
            Ok(Message::Notification { method, params }) => {
                if method == "notifications/cancelled" {
                    let id = params
                        .as_ref()
                        .and_then(|p| p.get("requestId"))
                        .and_then(RequestId::from_value);
                    if let Some(id) = id {
                        let token = in_flight
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .get(&id)
                            .cloned();
                        if let Some(token) = token {
                            tracing::debug!(id = %id, "MCP request cancelled by client");
                            token.cancel();
                        }
                    }
                }
            }
            Ok(Message::Request { id, method, params }) => {
                let result = match method.as_str() {
                    "initialize" => self.initialize(params.as_ref()),
                    "ping" => Ok(json!({})),
                    "tools/list" => self.list_tools(params.as_ref()),
                    "tools/call" => {
                        self.spawn_call(id, params, out, tasks, in_flight, conn_cancel)
                            .await;
                        return;
                    }
                    other => Err(RpcError::method_not_found(other)),
                };
                send(
                    out,
                    Message::Response {
                        id: Some(id),
                        result,
                    },
                )
                .await;
            }
        }
    }

    fn initialize(&self, params: Option<&Value>) -> Result<Value, RpcError> {
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("missing protocolVersion"))?;
        let version = if is_supported_protocol_version(requested) {
            requested
        } else {
            LATEST_PROTOCOL_VERSION
        };
        let mut result = json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": self.inner.info,
        });
        if let Some(i) = &self.inner.instructions {
            result["instructions"] = json!(i);
        }
        Ok(result)
    }

    fn list_tools(&self, params: Option<&Value>) -> Result<Value, RpcError> {
        let total = self.inner.entries.len();
        let start = match params.and_then(|p| p.get("cursor")) {
            None | Some(Value::Null) => 0,
            Some(Value::String(c)) => c
                .parse::<usize>()
                .ok()
                .filter(|n| *n <= total)
                .ok_or_else(|| RpcError::invalid_params("invalid cursor"))?,
            Some(_) => return Err(RpcError::invalid_params("invalid cursor")),
        };
        let end = if self.inner.page_size == 0 {
            total
        } else {
            start.saturating_add(self.inner.page_size).min(total)
        };
        let tools: Vec<Value> = self.inner.entries[start..end]
            .iter()
            .map(|(spec, tool)| {
                let mut t = json!({
                    "name": spec.name,
                    "description": spec.description,
                    "inputSchema": spec.parameters,
                });
                if tool.concurrency() == ToolConcurrency::ReadOnly {
                    t["annotations"] = json!({ "readOnlyHint": true });
                }
                t
            })
            .collect();
        let mut result = json!({ "tools": tools });
        if end < total {
            result["nextCursor"] = json!(end.to_string());
        }
        Ok(result)
    }

    async fn spawn_call(
        &self,
        id: RequestId,
        params: Option<Value>,
        out: &mpsc::Sender<Vec<u8>>,
        tasks: &mut JoinSet<()>,
        in_flight: &InFlight,
        conn_cancel: &CancellationToken,
    ) {
        let params = params.unwrap_or_else(|| json!({}));
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            let err = RpcError::invalid_params("missing tool name");
            send(out, Message::error_response(Some(id), err)).await;
            return;
        };
        let args = match params.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(v @ Value::Object(_)) => v.clone(),
            Some(_) => {
                let err = RpcError::invalid_params("arguments must be an object");
                send(out, Message::error_response(Some(id), err)).await;
                return;
            }
        };
        let Some(&idx) = self.inner.index.get(name) else {
            let err = RpcError::invalid_params(format!("Unknown tool: {name}"));
            send(out, Message::error_response(Some(id), err)).await;
            return;
        };
        let tool = Arc::clone(&self.inner.entries[idx].1);
        let token = conn_cancel.child_token();
        in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id.clone(), token.clone());
        let mut ctx = self.inner.context.clone();
        ctx.cancel = token.clone();
        let out = out.clone();
        let in_flight = Arc::clone(in_flight);
        let tool_name = name.to_string();
        tasks.spawn(async move {
            let call = AssertUnwindSafe(tool.call(args, &ctx)).catch_unwind();
            let outcome = tokio::select! {
                r = call => Some(r),
                _ = token.cancelled() => None,
            };
            in_flight
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            let result = match outcome {
                // Cancelled requests get no response (spec).
                None => return,
                Some(Ok(output)) => {
                    let r = CallToolResult {
                        content: vec![ContentBlock::text(output.content)],
                        is_error: output.is_error,
                        ..CallToolResult::default()
                    };
                    serde_json::to_value(r).map_err(|e| RpcError::internal(e.to_string()))
                }
                Some(Err(_)) => {
                    tracing::error!(tool = %tool_name, "tool panicked while serving MCP call");
                    Err(RpcError::internal(format!("tool '{tool_name}' panicked")))
                }
            };
            send(
                &out,
                Message::Response {
                    id: Some(id),
                    result,
                },
            )
            .await;
        });
    }
}

async fn send(out: &mpsc::Sender<Vec<u8>>, msg: Message) {
    match msg.to_line() {
        Ok(line) => {
            let _ = out.send(line).await;
        }
        Err(e) => tracing::warn!(error = %e, "failed to serialize MCP response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use talon_core::tool::ToolOutput;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    struct Echo;

    #[async_trait]
    impl Tool for Echo {
        fn spec(&self) -> ToolSpec {
            ToolSpec {
                name: "echo".into(),
                description: "echo".into(),
                parameters: json!({"type":"object"}),
            }
        }
        fn concurrency(&self) -> ToolConcurrency {
            ToolConcurrency::ReadOnly
        }
        async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
            ToolOutput::ok(args.to_string())
        }
    }

    /// Drive the server with raw lines and collect raw responses.
    async fn exchange(server: McpServer, input: &str) -> Vec<Value> {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server_side);
        let task = tokio::spawn(async move { server.serve(sr, sw).await });
        let (cr, mut cw) = tokio::io::split(client_side);
        cw.write_all(input.as_bytes()).await.unwrap();
        cw.shutdown().await.unwrap();
        drop(cw);
        let mut out = Vec::new();
        let mut lines = BufReader::new(cr).lines();
        while let Some(l) = lines.next_line().await.unwrap() {
            out.push(serde_json::from_str(&l).unwrap());
        }
        task.await.unwrap().unwrap();
        out
    }

    #[tokio::test]
    async fn raw_protocol_errors() {
        let server = McpServer::builder("t", "1")
            .tool(Arc::new(Echo))
            .tool(Arc::new(Echo))
            .build();
        assert_eq!(server.tool_specs().len(), 1);
        let input = concat!(
            "this is not json\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"nope\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"missing\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":[1]}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/list\",\"params\":{\"cursor\":\"99\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"initialize\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"a\":1}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n",
        );
        let out = exchange(server, input).await;
        let by_id = |id: i64| out.iter().find(|v| v["id"] == json!(id)).cloned();
        let parse_err = out.iter().find(|v| v["id"].is_null()).unwrap();
        assert_eq!(parse_err["error"]["code"], json!(-32700));
        assert_eq!(by_id(1).unwrap()["error"]["code"], json!(-32601));
        assert_eq!(by_id(2).unwrap()["error"]["code"], json!(-32600));
        let unknown = by_id(3).unwrap();
        assert_eq!(unknown["error"]["code"], json!(-32602));
        assert!(
            unknown["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Unknown tool")
        );
        assert_eq!(by_id(4).unwrap()["error"]["code"], json!(-32602));
        assert_eq!(by_id(5).unwrap()["error"]["code"], json!(-32602));
        assert_eq!(by_id(6).unwrap()["error"]["code"], json!(-32602));
        assert_eq!(
            by_id(7).unwrap()["result"]["protocolVersion"],
            json!(LATEST_PROTOCOL_VERSION)
        );
        let call = by_id(8).unwrap();
        assert_eq!(call["result"]["content"][0]["text"], json!("{\"a\":1}"));
        assert_eq!(call["result"]["isError"], json!(false));
        assert!(by_id(9).is_none());
    }

    #[tokio::test]
    async fn oversize_request_gets_error() {
        let server = McpServer::builder("t", "1").max_message_bytes(64).build();
        let big = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"ping\",\"params\":{{\"pad\":\"{}\"}}}}\n",
            "x".repeat(200)
        );
        let out = exchange(
            server,
            &format!("{big}{{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"ping\"}}\n"),
        )
        .await;
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["id"], json!(11));
        assert_eq!(out[0]["error"]["code"], json!(-32600));
        assert_eq!(out[1]["id"], json!(12));
        assert_eq!(out[1]["result"], json!({}));
    }

    #[tokio::test]
    async fn pagination_and_annotations() {
        let server = McpServer::builder("t", "1")
            .tool(Arc::new(Echo))
            .page_size(1)
            .build();
        let out = exchange(
            server,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{\"cursor\":\"1\"}}\n",
        )
        .await;
        let first = out.iter().find(|v| v["id"] == json!(1)).unwrap();
        assert_eq!(
            first["result"]["tools"][0]["annotations"]["readOnlyHint"],
            json!(true)
        );
        assert!(first["result"].get("nextCursor").is_none());
        let second = out.iter().find(|v| v["id"] == json!(2)).unwrap();
        assert_eq!(second["result"]["tools"], json!([]));
    }

    #[tokio::test]
    async fn context_cancel_stops_server() {
        let ctx = default_context();
        let cancel = ctx.cancel.clone();
        let server = McpServer::builder("t", "1").context(ctx).build();
        let (_client_side, server_side) = tokio::io::duplex(1024);
        let (sr, sw) = tokio::io::split(server_side);
        let task = tokio::spawn(async move { server.serve(sr, sw).await });
        cancel.cancel();
        let res = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(res.is_ok());
    }
}
