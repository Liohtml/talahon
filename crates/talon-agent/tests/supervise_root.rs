//! End-to-end test of `talon-agent supervise` (privileged path): the agent
//! runs as `nobody`, an MCP server runs as a fake `mcp-echo` account behind
//! the supervisor's unix socket, the model is a wiremock fake vLLM. The
//! mount table is injected (read-only rootfs, writable `/usr/bin/env`).
//!
//! Needs root (setuid/setgid, chown) and `/usr/bin/python3`; skipped
//! otherwise.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use talon_core::protocol::{ContainerOutput, OUTPUT_END_MARKER, OUTPUT_START_MARKER, OutputStatus};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const NOBODY: u32 = 65534;
const MCP_UID: u32 = 61010;

const ECHO_SERVER: &str = r#"
import json, os, sys
def send(o):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    m = msg.get("method")
    if mid is None:
        continue
    if m == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": msg["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "echo", "version": "1"},
            "instructions": "Echo server for tests."}})
    elif m == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{
            "name": "echo", "description": "Echo test tool",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
            "annotations": {"readOnlyHint": True}}]}})
    elif m == "tools/call":
        info = "pong uid=%d home=%s safepath=%s cwd=%s" % (
            os.getuid(), os.environ.get("HOME"), os.environ.get("PYTHONSAFEPATH"), os.getcwd())
        send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": info}]}})
    elif m == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    else:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "not found"}})
"#;

fn sse(chunks: &[Value]) -> String {
    let mut body: String = chunks.iter().map(|c| format!("data: {c}\n\n")).collect();
    body.push_str("data: [DONE]\n\n");
    body
}

struct FakeVllm {
    calls: Arc<AtomicUsize>,
}

impl Respond for FakeVllm {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let body = match self.calls.fetch_add(1, Ordering::SeqCst) {
            0 => sse(&[
                json!({"id":"a","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_e","type":"function","function":{"name":"mcp__echo__echo","arguments":"{\"text\":\"ping\"}"}}]},"finish_reason":null}]}),
                json!({"id":"a","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}),
            ]),
            _ => sse(&[
                json!({"id":"b","choices":[{"index":0,"delta":{"role":"assistant","content":"MCP said pong"},"finish_reason":null}]}),
                json!({"id":"b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
            ]),
        };
        ResponseTemplate::new(200).set_body_raw(body, "text/event-stream")
    }
}

fn mkdir(p: &Path, mode: u32) {
    std::fs::create_dir_all(p).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_runs_mcp_and_agent_unprivileged() {
    if !rustix::process::geteuid().is_root() || !Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping: needs root and /usr/bin/python3");
        return;
    }
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(FakeVllm {
            calls: calls.clone(),
        })
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let root: PathBuf = dir.path().to_path_buf();
    mkdir(&root, 0o755);
    for sub in ["group", "ipc", "ipc/input", "state"] {
        mkdir(&root.join(sub), 0o777);
    }
    std::fs::write(root.join("echo_mcp.py"), ECHO_SERVER).unwrap();
    std::fs::set_permissions(
        root.join("echo_mcp.py"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::write(
        root.join("passwd"),
        format!(
            "root:x:0:0:root:/root:/bin/bash\nmcp-default:x:61009:61009::/nonexistent:/usr/sbin/nologin\nmcp-echo:x:{MCP_UID}:{MCP_UID}::/nonexistent:/usr/sbin/nologin\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("group/.mcp.json"),
        json!({"mcpServers": {
            "echo": {"command": "/usr/bin/python3", "args": [root.join("echo_mcp.py")], "runAs": "mcp-echo"},
            "evil": {"command": root.join("echo_mcp.py"), "runAs": "mcp-echo"},
            "rwbin": {"command": "/usr/bin/env", "args": ["python3", root.join("echo_mcp.py")], "runAs": "mcp-echo"}
        }})
        .to_string(),
    )
    .unwrap();
    // The supervisor only launches commands on read-only mounts. This
    // sandbox's rootfs is writable, so hand it a table shaped like a
    // `--read-only` container: read-only rootfs, with a writable file bind
    // mount over `/usr/bin/env` (refused although under an allowed root).
    let env_bin = std::fs::canonicalize("/usr/bin/env").unwrap_or_else(|_| "/usr/bin/env".into());
    std::fs::write(
        root.join("mountinfo"),
        format!(
            "1 0 0:1 / / ro,relatime - overlay overlay rw\n2 1 0:2 / /proc rw,nosuid - proc proc rw\n3 1 8:1 /x {} rw,relatime - ext4 /dev/sda1 rw\n",
            env_bin.display()
        ),
    )
    .unwrap();

    let socket_dir = root.join("run/mcp");
    let home_root = root.join("run/home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_talon-agent"))
        .arg("supervise")
        .arg("--group-dir")
        .arg(root.join("group"))
        .arg("--global-dir")
        .arg(root.join("global"))
        .arg("--project-dir")
        .arg(root.join("project"))
        .arg("--extra-dir")
        .arg(root.join("extra"))
        .arg("--ipc-dir")
        .arg(root.join("ipc"))
        .arg("--state-dir")
        .arg(root.join("state"))
        .arg("--ipc-poll-ms")
        .arg("20")
        .arg("--socket-dir")
        .arg(&socket_dir)
        .arg("--mcp-home-root")
        .arg(&home_root)
        .arg("--passwd-file")
        .arg(root.join("passwd"))
        .arg("--mountinfo-file")
        .arg(root.join("mountinfo"))
        .env("RUN_UID", NOBODY.to_string())
        .env("RUN_GID", NOBODY.to_string())
        .env("TALON_LOG", "debug")
        .env_remove("TALON_MCP_SOCKET_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let input = json!({
        "prompt": "use the echo tool",
        "groupFolder": "testgroup",
        "chatJid": "tg:1",
        "isMain": false,
        "llm": {
            "baseUrl": format!("{}/v1", server.uri()),
            "token": "tlgw-root-test-token-abcdef0123",
            "model": "m",
            "maxContextTokens": 32768
        }
    });
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&serde_json::to_vec(&input).unwrap())
        .await
        .unwrap();
    drop(stdin);

    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut buf = String::new();
    let mut inside = false;
    let frame: ContainerOutput = loop {
        let line = tokio::time::timeout(Duration::from_secs(60), lines.next_line())
            .await
            .expect("timed out waiting for a frame")
            .unwrap()
            .expect("stdout closed");
        if line == OUTPUT_START_MARKER {
            inside = true;
        } else if line == OUTPUT_END_MARKER {
            break serde_json::from_str(&buf).unwrap();
        } else if inside {
            buf.push_str(&line);
        }
    };
    assert_eq!(frame.status, OutputStatus::Success, "{frame:?}");
    assert_eq!(frame.result.as_deref(), Some("MCP said pong"));
    let id = frame.new_session_id.unwrap();

    // The socket was consumed (unlinked after the single accept).
    assert!(std::fs::symlink_metadata(socket_dir.join("echo.sock")).is_err());
    assert!(std::fs::symlink_metadata(socket_dir.join("evil.sock")).is_err());
    assert!(std::fs::symlink_metadata(socket_dir.join("rwbin.sock")).is_err());
    let meta = std::fs::metadata(&socket_dir).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o750);
    assert_eq!((meta.uid(), meta.gid()), (0, NOBODY));
    let home = std::fs::metadata(home_root.join("echo")).unwrap();
    assert_eq!(home.mode() & 0o777, 0o700);
    assert_eq!(home.uid(), MCP_UID);

    std::fs::write(root.join("ipc/input/_close"), "").unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("supervisor did not exit")
        .unwrap();
    let mut logs = String::new();
    stderr.read_to_string(&mut logs).await.unwrap();
    assert!(status.success(), "{status:?}\n{logs}");
    assert!(logs.contains("refusing MCP server"), "{logs}");
    assert!(logs.contains("is not on a read-only mount"), "{logs}");
    assert!(!logs.contains("tlgw-root-test-token-abcdef0123"));

    // The agent ran as nobody.
    let session = root.join("state/sessions").join(format!("{id}.jsonl"));
    assert_eq!(std::fs::metadata(&session).unwrap().uid(), NOBODY);
    // ... and prepared its lane-private reports/evals directories (N-2).
    for sub in ["state/reports", "state/evals"] {
        let meta = std::fs::symlink_metadata(root.join(sub)).unwrap();
        assert!(meta.is_dir(), "{sub}");
        assert_eq!(meta.mode() & 0o777, 0o700, "{sub}");
        assert_eq!(meta.uid(), NOBODY, "{sub}");
    }

    // The MCP server ran as mcp-echo with the hardened environment and
    // its result reached the model fenced.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let first: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let tools: Vec<&str> = first["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["function"]["name"].as_str().unwrap())
        .collect();
    assert!(tools.contains(&"mcp__echo__echo"));
    assert!(!tools.iter().any(|t| t.starts_with("mcp__evil")));
    assert!(!tools.iter().any(|t| t.starts_with("mcp__rwbin")));
    // Per-run notes travel in the first user message, keeping the system
    // prompt byte-stable across runs (vLLM prefix caching).
    let system = first["messages"][0]["content"].as_str().unwrap();
    assert!(!system.contains("Echo server for tests."));
    let user = first["messages"][1]["content"].as_str().unwrap();
    assert!(user.contains("Echo server for tests."));
    assert!(user.contains("Unavailable MCP servers this run: evil"));
    let second: Value = serde_json::from_slice(&requests[1].body).unwrap();
    let tool_msg = second["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "tool")
        .unwrap()["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        tool_msg.contains("<untrusted_data source=\"mcp:echo\""),
        "{tool_msg}"
    );
    assert!(
        tool_msg.contains(&format!("pong uid={MCP_UID}")),
        "{tool_msg}"
    );
    assert!(
        tool_msg.contains(&format!("home={}", home_root.join("echo").display())),
        "{tool_msg}"
    );
    assert!(tool_msg.contains("safepath=1"), "{tool_msg}");
    assert!(tool_msg.contains("cwd=/usr/bin"), "{tool_msg}");
}
