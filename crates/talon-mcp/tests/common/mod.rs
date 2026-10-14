//! Shared helpers for the integration tests.
// Test-only helpers: panicking on setup failure is the desired behaviour.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};
use talon_mcp::{ClientOptions, McpClient};
use tokio::io::{
    AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf,
};
use tokio_util::sync::CancellationToken;

pub fn ctx() -> ToolContext {
    ToolContext {
        cwd: PathBuf::from("/tmp"),
        allowed_roots: vec![],
        read_only_roots: vec![],
        group_folder: "test".into(),
        chat_jid: "test@jid".into(),
        is_main: false,
        ipc_dir: PathBuf::from("/tmp/ipc"),
        cancel: CancellationToken::new(),
    }
}

// ---------------------------------------------------------------------------
// Test tools served by `McpServer`.

pub struct Echo;

#[async_trait]
impl Tool for Echo {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "echo".into(),
            description: "Echo the 'text' argument".into(),
            parameters: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}),
        }
    }
    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }
    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        match args.get("text").and_then(Value::as_str) {
            Some(t) => ToolOutput::ok(t),
            None => ToolOutput::err("missing 'text'"),
        }
    }
}

pub struct Fail;

#[async_trait]
impl Tool for Fail {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "fail".into(),
            description: "Always fails".into(),
            parameters: json!({"type":"object","properties":{}}),
        }
    }
    async fn call(&self, _args: Value, _ctx: &ToolContext) -> ToolOutput {
        ToolOutput::err("this tool always fails")
    }
}

/// Sleeps `ms` milliseconds unless cancelled; records cancellation.
pub struct Slow {
    pub cancelled: Arc<AtomicBool>,
}

#[async_trait]
impl Tool for Slow {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "slow".into(),
            description: "Sleeps".into(),
            parameters: json!({"type":"object","properties":{"ms":{"type":"integer"}}}),
        }
    }
    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }
    async fn call(&self, args: Value, ctx: &ToolContext) -> ToolOutput {
        let ms = args.get("ms").and_then(Value::as_u64).unwrap_or(10_000);
        let flag = Arc::clone(&self.cancelled);
        // The server drops this future on cancellation; a guard records it.
        struct Guard(Arc<AtomicBool>, bool);
        impl Drop for Guard {
            fn drop(&mut self) {
                if !self.1 {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
        }
        let mut guard = Guard(flag, false);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(ms)) => {
                guard.1 = true;
                ToolOutput::ok(format!("slept {ms}ms"))
            }
            _ = ctx.cancel.cancelled() => {
                ToolOutput::err("cancelled")
            }
        }
    }
}

pub struct Panicker;

#[async_trait]
impl Tool for Panicker {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "panic".into(),
            description: "Panics".into(),
            parameters: json!({"type":"object"}),
        }
    }
    async fn call(&self, _args: Value, _ctx: &ToolContext) -> ToolOutput {
        panic!("boom");
    }
}

/// Returns `n` bytes of text.
pub struct Big;

#[async_trait]
impl Tool for Big {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "big".into(),
            description: "Returns n bytes".into(),
            parameters: json!({"type":"object","properties":{"n":{"type":"integer"}}}),
        }
    }
    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(10) as usize;
        ToolOutput::ok("z".repeat(n))
    }
}

// ---------------------------------------------------------------------------
// Scripted fake peer: drives the server side of a duplex by hand.

pub struct FakePeer {
    lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
    writer: WriteHalf<DuplexStream>,
}

impl FakePeer {
    /// Next message from the client (panics after 5 s).
    pub async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(5), self.lines.next_line())
            .await
            .expect("timed out waiting for client message")
            .expect("read error")
            .expect("client closed the connection");
        serde_json::from_str(&line).expect("client sent invalid JSON")
    }

    /// Next message, `None` on EOF or after `wait`.
    pub async fn try_recv(&mut self, wait: Duration) -> Option<Value> {
        match tokio::time::timeout(wait, self.lines.next_line()).await {
            Ok(Ok(Some(line))) => serde_json::from_str(&line).ok(),
            _ => None,
        }
    }

    /// True if the client closes its side (EOF) within `wait`, skipping
    /// any messages still in flight.
    pub async fn expect_eof(&mut self, wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, self.lines.next_line()).await {
                Ok(Ok(Some(_))) => continue,
                Ok(Ok(None)) | Ok(Err(_)) => return true,
                Err(_) => return false,
            }
        }
    }

    /// Next request with `method`, skipping notifications/other traffic.
    pub async fn recv_method(&mut self, method: &str) -> Value {
        loop {
            let v = self.recv().await;
            if v["method"] == json!(method) {
                return v;
            }
        }
    }

    pub async fn send(&mut self, v: Value) {
        self.send_raw(&v.to_string()).await;
    }

    pub async fn send_raw(&mut self, line: &str) {
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.write_all(b"\n").await.unwrap();
        self.writer.flush().await.unwrap();
    }

    pub async fn respond(&mut self, req: &Value, result: Value) {
        self.send(json!({"jsonrpc":"2.0","id":req["id"],"result":result}))
            .await;
    }

    /// Answer `initialize` (with the requested version) and swallow
    /// `notifications/initialized`.
    pub async fn handshake(&mut self) {
        let init = self.recv_method("initialize").await;
        let version = init["params"]["protocolVersion"].clone();
        self.respond(
            &init,
            json!({"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": {"name":"fake","version":"1"}}),
        )
        .await;
        let n = self.recv().await;
        assert_eq!(n["method"], json!("notifications/initialized"));
    }
}

/// Client connected to a [`FakePeer`] over an in-memory duplex.
pub async fn fake_pair(options: ClientOptions) -> (Arc<McpClient>, FakePeer) {
    let (client_side, server_side) = tokio::io::duplex(1 << 20);
    let (cr, cw) = tokio::io::split(client_side);
    let client = McpClient::connect("fake", cr, cw, options).await;
    let (sr, sw) = tokio::io::split(server_side);
    let peer = FakePeer {
        lines: BufReader::new(sr).lines(),
        writer: sw,
    };
    (Arc::new(client), peer)
}

pub fn fast_options() -> ClientOptions {
    ClientOptions {
        init_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
        tool_call_timeout: Duration::from_secs(5),
        shutdown_grace: Duration::from_millis(500),
        ..ClientOptions::default()
    }
}

// ---------------------------------------------------------------------------
// Python fake MCP server for spawn tests.

pub fn python3() -> Option<PathBuf> {
    for p in ["/usr/bin/python3", "/usr/local/bin/python3", "/bin/python3"] {
        if Path::new(p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    eprintln!("python3 not found; skipping spawn test");
    None
}

/// Whether a process is gone (missing from /proc or a zombie).
pub fn process_gone(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(')')
            .map(|(_, rest)| {
                rest.trim_start().starts_with('Z') || rest.trim_start().starts_with('X')
            })
            .unwrap_or(false),
    }
}

pub async fn wait_gone(pid: u32, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if process_gone(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    process_gone(pid)
}

pub const FAKE_SERVER_PY: &str = r#"
import json, os, subprocess, sys, time

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def text(mid, t, is_error=False):
    send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": t}], "isError": is_error}})

print("fake server starting pid=%d" % os.getpid(), file=sys.stderr, flush=True)
# Non-JSON noise on stdout must be skipped by the client.
sys.stdout.write("Starting fake MCP server (not json)\n")
sys.stdout.flush()

def schema(**props):
    return {"type": "object", "properties": {k: {"type": v} for k, v in props.items()}}

TOOLS = [
    {"name": "echo", "description": "Echo text", "inputSchema": schema(text="string"), "annotations": {"readOnlyHint": True}},
    {"name": "env", "description": "Read an env var", "inputSchema": schema(name="string")},
    {"name": "cwd", "description": "Working directory", "inputSchema": schema()},
    {"name": "structured", "description": "Structured result", "inputSchema": schema()},
    {"name": "image", "description": "Image result", "inputSchema": schema()},
    {"name": "fail", "description": "Tool error", "inputSchema": schema()},
    {"name": "die", "description": "Exit without answering", "inputSchema": schema()},
    {"name": "sleep", "description": "Sleep", "inputSchema": schema(seconds="number")},
    {"name": "big", "description": "Big output", "inputSchema": schema(n="integer")},
    {"name": "pid", "description": "Process id", "inputSchema": schema()},
    {"name": "spawn_child", "description": "Start a background child", "inputSchema": schema()},
    {"name": "cancelled", "description": "Cancelled ids seen", "inputSchema": schema()},
    {"name": "pong", "description": "Whether the client answered our ping", "inputSchema": schema()},
    {"name": "change_tools", "description": "Add a tool and notify", "inputSchema": schema()},
    {"name": "bad.name/with spaces", "description": "Needs sanitizing", "inputSchema": schema()},
]
PAGE = int(os.environ.get("FAKE_PAGE_SIZE", "0"))
cancelled = []
pong = []
children = []

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    try:
        msg = json.loads(raw)
    except Exception:
        send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
        continue
    method = msg.get("method")
    mid = msg.get("id")
    params = msg.get("params") or {}
    if method is None:
        if mid == "srv-ping":
            pong.append(msg.get("result"))
        continue
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": params.get("protocolVersion"),
            "capabilities": {"tools": {"listChanged": True}, "logging": {}},
            "serverInfo": {"name": "fake-py", "version": "0.1"},
            "instructions": "Fake server instructions"}})
    elif method == "notifications/initialized":
        send({"jsonrpc": "2.0", "id": "srv-ping", "method": "ping"})
        send({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "hello from fake"}})
    elif method == "notifications/cancelled":
        cancelled.append(params.get("requestId"))
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "tools/list":
        start = int(params.get("cursor") or 0)
        end = len(TOOLS) if PAGE == 0 else min(start + PAGE, len(TOOLS))
        result = {"tools": TOOLS[start:end]}
        if end < len(TOOLS):
            result["nextCursor"] = str(end)
        send({"jsonrpc": "2.0", "id": mid, "result": result})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "echo":
            text(mid, args.get("text", ""))
        elif name == "env":
            text(mid, str(os.environ.get(args.get("name", ""), "<unset>")))
        elif name == "cwd":
            text(mid, os.getcwd())
        elif name == "structured":
            send({"jsonrpc": "2.0", "id": mid, "result": {"content": [], "structuredContent": {"alerts": 3, "ok": True}}})
        elif name == "image":
            send({"jsonrpc": "2.0", "id": mid, "result": {"content": [
                {"type": "text", "text": "see image"},
                {"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"}]}})
        elif name == "fail":
            text(mid, "index not found", True)
        elif name == "die":
            print("dying on purpose", file=sys.stderr, flush=True)
            os._exit(3)
        elif name == "sleep":
            time.sleep(float(args.get("seconds", 1)))
            text(mid, "woke up")
        elif name == "big":
            text(mid, "x" * int(args.get("n", 10)))
        elif name == "pid":
            text(mid, str(os.getpid()))
        elif name == "spawn_child":
            p = subprocess.Popen(["sleep", "60"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(p)
            text(mid, str(p.pid))
        elif name == "cancelled":
            text(mid, json.dumps(cancelled))
        elif name == "pong":
            text(mid, json.dumps(pong))
        elif name == "change_tools":
            TOOLS.append({"name": "extra", "description": "Added later", "inputSchema": schema()})
            send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
            text(mid, "changed")
        else:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "Unknown tool: %s" % name}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}})
"#;

/// Writes the fake server (and wrapper scripts) into `dir`.
pub fn write_fake_server(dir: &Path) -> PathBuf {
    let script = dir.join("fake_server.py");
    std::fs::write(&script, FAKE_SERVER_PY).unwrap();
    script
}

#[cfg(unix)]
pub fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    let mut perm = std::fs::metadata(path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(path, perm).unwrap();
}
