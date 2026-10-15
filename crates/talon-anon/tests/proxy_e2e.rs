//! End-to-end tests: the `talon-anon-proxy` binary driven over stdio, with a
//! fake upstream MCP server written in Python (skipped if `python3` is not
//! installed).

// Test-only crate: panicking on unexpected I/O is the desired failure mode.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const FAKE_UPSTREAM: &str = r#"
import json, os, sys

LOG = sys.argv[1]

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

DOC = {
    "_index": "wazuh-alerts-4.x-2024.01.01",
    "_id": "abc123",
    "_source": {
        "agent": {"name": "WS-FIN-01", "ip": "10.1.2.3"},
        "data": {"win": {"eventdata": {
            "targetUserName": "john.doe",
            "image": "C:\\Users\\john.doe\\AppData\\Local\\Temp\\evil.exe",
            "hashes": "SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "destinationIp": "8.8.8.8",
            "destinationHostname": "c2.evil-domain.com"
        }}},
        "rule": {"id": "92052", "level": 12, "description": "Suspicious process", "mitre": {"id": ["T1059.001"]}},
        "full_log": "Process created by john.doe on WS-FIN-01 (10.1.2.3) mail john.doe@corp-example.com"
    }
}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    with open(LOG, "a") as f:
        f.write(line + "\n")
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:
        continue
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2025-06-18",
              "capabilities": {"tools": {}}, "serverInfo": {"name": "fake-opensearch", "version": "0"}}})
    elif method == "tools/list":
        sys.stdout.write("stray debug output mentioning 10.9.9.9 and john.doe\n")
        sys.stdout.flush()
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": "get_document", "description": "Get a document", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"].get("arguments") or {}
        if name == "get_document":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": json.dumps(DOC, indent=2)}],
                "structuredContent": DOC}})
        elif name == "search":
            body = {"aggregations": {"by_user": {"buckets": [{"key": "john.doe", "doc_count": 4}]}}}
            send({"jsonrpc": "2.0", "id": mid, "result": {"content": [
                {"type": "text", "text": "Search results for " + json.dumps(args) + ": " + json.dumps(body)}]}})
        elif name == "big":
            send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": "x" * 200000}]}})
        elif name == "crash":
            os._exit(3)
        else:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool " + name}})
"#;

fn python_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn fields_yaml() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fields.yaml")
}

struct Proxy {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    stderr: thread::JoinHandle<String>,
}

impl Proxy {
    fn start(dir: &Path, map: &Path) -> Proxy {
        let script = dir.join("fake_upstream.py");
        fs::write(&script, FAKE_UPSTREAM).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_talon-anon-proxy"))
            .arg("--fields")
            .arg(fields_yaml())
            .arg("--map")
            .arg(map)
            .args(["--max-line-bytes", "65536", "--shutdown-grace-secs", "5"])
            .arg("--")
            .arg("python3")
            .arg("-I")
            .arg(&script)
            .arg(dir.join("received.log"))
            .env("TALON_ANON_LOG", "debug")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn talon-anon-proxy");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut stderr = child.stderr.take().unwrap();
        let stderr = thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            s
        });
        let stdin = child.stdin.take();
        Proxy {
            child,
            stdin,
            lines: rx,
            stderr,
        }
    }

    fn send_raw(&mut self, raw: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(raw.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn send(&mut self, v: Value) {
        self.send_raw(&v.to_string());
    }

    fn recv(&self) -> Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(20))
            .expect("no response from proxy");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("proxy wrote non-JSON {line:?}: {e}"))
    }

    fn call(&mut self, id: i64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}}));
        let r = self.recv();
        assert_eq!(r["id"], id, "{r}");
        r
    }

    fn finish(mut self) -> (ExitStatus, String) {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < deadline, "proxy did not exit");
            thread::sleep(Duration::from_millis(20));
        };
        let leftover: Vec<String> = self.lines.try_iter().collect();
        assert!(leftover.is_empty(), "unexpected output: {leftover:?}");
        (status, self.stderr.join().unwrap())
    }
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn full_session_over_stdio() {
    if !python_available() {
        eprintln!("python3 not available; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let map = dir.path().join("state").join("session_tokens.json");
    let mut p = Proxy::start(dir.path(), &map);

    p.send(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}));
    assert_eq!(p.recv()["result"]["serverInfo"]["name"], "fake-opensearch");
    p.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));

    p.send(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}));
    let list = p.recv();
    assert_eq!(list["id"], 1, "stray upstream stdout must be dropped");
    let names: Vec<_> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(names, [json!("get_document"), json!("deanonymize")]);

    // --- anonymized document
    let r = p.call(
        2,
        "get_document",
        json!({"index": "wazuh-alerts-*", "id": "abc123"}),
    );
    let all = r.to_string();
    for pii in ["john.doe", "WS-FIN-01", "10.1.2.3", "corp-example.com"] {
        assert!(!all.contains(pii), "{pii} leaked: {all}");
    }
    for kept in [
        "8.8.8.8",
        "c2.evil-domain.com",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "T1059.001",
        "92052",
    ] {
        assert!(all.contains(kept), "{kept} was altered: {all}");
    }
    let text: Value =
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, r["result"]["structuredContent"]);
    let src = &text["_source"];
    assert_eq!(src["data"]["win"]["eventdata"]["targetUserName"], "USER_1");
    assert_eq!(src["agent"]["name"], "HOST_1");
    assert_eq!(src["agent"]["ip"], "IP_INT_1");
    assert_eq!(
        src["full_log"],
        "Process created by USER_1 on HOST_1 (IP_INT_1) mail EMAIL_1"
    );

    // --- the model searches by token; upstream receives the real value; the
    // aggregation bucket comes back tokenized via the request's field hint
    let r = p.call(
        3,
        "search",
        json!({"index": "wazuh-*", "query": "data.win.eventdata.targetUserName:USER_1",
               "body": {"aggs": {"by_user": {"terms": {"field": "data.win.eventdata.targetUserName"}}}}}),
    );
    let out = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!out.contains("john.doe"), "{out}");
    assert!(out.contains("\"key\":\"USER_1\""), "{out}");
    let received = fs::read_to_string(dir.path().join("received.log")).unwrap();
    let search_req: Value =
        serde_json::from_str(received.lines().find(|l| l.contains("\"search\"")).unwrap()).unwrap();
    assert_eq!(
        search_req["params"]["arguments"]["query"],
        "data.win.eventdata.targetUserName:john.doe"
    );
    assert!(
        !received.contains("\"deanonymize\""),
        "deanonymize must never reach the upstream"
    );

    // --- local de-anonymization (USER_1 must not clobber USER_10)
    let r = p.call(
        4,
        "deanonymize",
        json!({"text": "USER_1 on HOST_1 (IP_INT_1), not USER_10; mail EMAIL_1"}),
    );
    assert_eq!(
        r["result"]["content"][0]["text"],
        "john.doe on WS-FIN-01 (10.1.2.3), not USER_10; mail john.doe@corp-example.com"
    );

    // --- oversize upstream response -> JSON-RPC error, session continues
    let r = p.call(5, "big", json!({}));
    assert_eq!(r["error"]["code"], -32001, "{r}");
    // --- upstream error messages are anonymized too
    let r = p.call(6, "nope", json!({}));
    assert_eq!(r["error"]["code"], -32602);
    // --- client garbage -> parse error
    p.send_raw("{not json");
    assert_eq!(p.recv()["error"]["code"], -32700);

    let (status, stderr) = p.finish();
    assert!(
        status.success(),
        "exit status {status:?}; stderr:\n{stderr}"
    );
    for pii in ["john.doe", "WS-FIN-01", "10.1.2.3"] {
        assert!(!stderr.contains(pii), "{pii} leaked into logs:\n{stderr}");
    }

    // --- map persisted, private, Python-compatible
    #[cfg(unix)]
    assert_eq!(mode(&map), 0o600);
    let saved: Value = serde_json::from_slice(&fs::read(&map).unwrap()).unwrap();
    assert_eq!(saved["forward"]["john.doe"], "USER_1");
    assert_eq!(saved["counters"]["USER"], 1);

    // --- a new proxy process continues the same session
    let mut p2 = Proxy::start(dir.path(), &map);
    let r = p2.call(1, "deanonymize", json!({"text": "USER_1@HOST_1"}));
    assert_eq!(r["result"]["content"][0]["text"], "john.doe@WS-FIN-01");
    let (status, _) = p2.finish();
    assert!(status.success());
}

#[test]
fn upstream_crash_answers_pending_requests_and_exits_with_its_code() {
    if !python_available() {
        eprintln!("python3 not available; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut p = Proxy::start(dir.path(), &dir.path().join("t.json"));
    let r = p.call(9, "crash", json!({}));
    assert_eq!(r["error"]["code"], -32000, "{r}");
    let (status, _) = p.finish();
    assert_eq!(status.code(), Some(3));
}

#[test]
fn bad_invocations_fail_fast() {
    let dir = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_talon-anon-proxy");
    let map = dir.path().join("t.json");

    let missing = Command::new(bin)
        .arg("--map")
        .arg(&map)
        .args(["--", "/nonexistent/talon-upstream-xyz"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(missing.code(), Some(127));

    let bad_yaml = dir.path().join("bad.yaml");
    fs::write(&bad_yaml, "categories: [nope]\n").unwrap();
    let bad = Command::new(bin)
        .arg("--fields")
        .arg(&bad_yaml)
        .arg("--map")
        .arg(&map)
        .args(["--", "true"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(bad.code(), Some(2));

    let check = Command::new(bin)
        .arg("--fields")
        .arg(fields_yaml())
        .arg("--map")
        .arg(&map)
        .arg("--check")
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(check.success());

    // --check reports a corrupt map without moving it aside
    let corrupt = dir.path().join("corrupt.json");
    fs::write(&corrupt, "{ nope").unwrap();
    let check_corrupt = Command::new(bin)
        .arg("--map")
        .arg(&corrupt)
        .arg("--check")
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(check_corrupt.code(), Some(1));
    assert_eq!(fs::read_to_string(&corrupt).unwrap(), "{ nope");

    let no_upstream = Command::new(bin)
        .arg("--map")
        .arg(&map)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!no_upstream.success());
}
