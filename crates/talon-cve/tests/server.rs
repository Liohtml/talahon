//! The MCP server in process (`McpServer` over `tokio::io::duplex`) on a
//! database built from the sample files, and the binary itself.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::build_db;
use serde_json::{Value, json};
use talon_cve::tools::{NO_DATABASE, TOOL_NAMES, WRONG_SCHEMA};
use talon_cve::{Config, SERVER_NAME, build_server};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

struct Session {
    to_server: DuplexStream,
    from_server: BufReader<DuplexStream>,
    next_id: i64,
}

impl Session {
    fn start(db: &Path, max_age_days: i64) -> Self {
        let server = build_server(&Config {
            db_path: db.to_path_buf(),
            max_age_days,
        });
        let (to_server, server_in) = tokio::io::duplex(1 << 20);
        let (server_out, from_server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move { server.serve(server_in, server_out).await });
        Self {
            to_server,
            from_server: BufReader::new(from_server),
            next_id: 0,
        }
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let mut line = serde_json::to_vec(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )
        .unwrap();
        line.push(b'\n');
        self.to_server.write_all(&line).await.unwrap();
        let mut answer = String::new();
        let n = tokio::time::timeout(
            Duration::from_secs(20),
            self.from_server.read_line(&mut answer),
        )
        .await
        .expect("server did not answer")
        .unwrap();
        assert!(n > 0, "server closed the connection");
        let response: Value = serde_json::from_str(&answer).unwrap();
        assert_eq!(response["id"], id, "{response}");
        response
    }

    /// Call a tool; returns `(text, is_error)`.
    async fn call(&mut self, name: &str, arguments: Value) -> (String, bool) {
        let response = self
            .rpc("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        let result = &response["result"];
        assert!(result.is_object(), "no result: {response}");
        let content = result["content"].as_array().unwrap();
        assert_eq!(content.len(), 1, "{response}");
        (
            content[0]["text"].as_str().unwrap().to_string(),
            result["isError"].as_bool().unwrap_or(false),
        )
    }

    async fn ok(&mut self, name: &str, arguments: Value) -> Value {
        let (text, is_error) = self.call(name, arguments).await;
        assert!(!is_error, "{name} failed: {text}");
        serde_json::from_str(&text).unwrap()
    }

    async fn err(&mut self, name: &str, arguments: Value) -> String {
        let (text, is_error) = self.call(name, arguments).await;
        assert!(is_error, "{name} should have failed: {text}");
        text
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[tokio::test]
async fn handshake_and_tool_list() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cve.sqlite");
    build_db(&db, &now());
    let mut s = Session::start(&db, 3);

    let init = s
        .rpc(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}),
        )
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], SERVER_NAME);
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("No network access")
    );

    let list = s.rpc("tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, TOOL_NAMES);
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        assert!(tool["description"].as_str().unwrap().len() > 40, "{tool}");
    }
}

#[tokio::test]
async fn every_tool_answers() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cve.sqlite");
    let synced = now();
    build_db(&db, &synced);
    let mut s = Session::start(&db, 3);

    let lookup = s
        .ok(
            "lookup_cve",
            json!({"cve_ids": ["cve-2021-44228", "CVE-2030-0001"]}),
        )
        .await;
    assert_eq!(lookup["cves"][0]["id"], "CVE-2021-44228");
    assert_eq!(lookup["cves"][0]["cvss"]["severity"], "CRITICAL");
    assert_eq!(lookup["cves"][0]["kev"]["date_added"], "2021-12-10");
    assert_eq!(lookup["cves"][1]["found"], false);
    assert_eq!(lookup["data_as_of"], synced);
    assert!(lookup.get("warning").is_none(), "{lookup}");
    // The online server's argument spelling works too.
    let single = s.ok("lookup_cve", json!({"cve_id": "CVE-2014-0160"})).await;
    assert_eq!(single["cves"][0]["products"][0]["vendor"], "openssl");

    let search = s
        .ok("search_cves", json!({"query": "log4j", "min_cvss": 9}))
        .await;
    assert_eq!(search["count"], 1);
    assert_eq!(search["more_available"], false);
    assert_eq!(search["hits"][0]["id"], "CVE-2021-44228");
    assert_eq!(search["hits"][0]["kev"], true);
    assert_eq!(search["hits"][0]["epss"], 0.94358);
    let limited = s
        .ok("search_cves", json!({"kev_only": true, "limit": 1}))
        .await;
    assert_eq!(
        (limited["count"].clone(), limited["more_available"].clone()),
        (json!(1), json!(true))
    );

    let epss = s
        .ok(
            "get_epss_score",
            json!({"cve_ids": ["CVE-2014-0160", "CVE-2030-0001"]}),
        )
        .await;
    assert_eq!(epss["scores"][0]["epss"]["percentile"], 0.99987);
    assert_eq!(epss["scores"][1]["epss"], json!(null));
    assert_eq!(epss["epss_score_date"], "2026-11-17T12:03:07Z");

    let kev = s
        .ok(
            "check_kev",
            json!({"cve_ids": ["CVE-2014-0160", "CVE-2026-0001"]}),
        )
        .await;
    assert_eq!(kev["results"][0]["in_kev"], true);
    assert_eq!(kev["results"][1]["in_kev"], false);

    let list = s.ok("list_kev", json!({"ransomware_only": true})).await;
    assert_eq!(list["count"], 1);
    assert_eq!(list["entries"][0]["cve_id"], "CVE-2021-44228");

    let status = s.ok("data_status", json!({})).await;
    assert_eq!(status["sources"]["nvd"]["cves"], 3);
    assert_eq!(status["sources"]["epss"]["scores"], 3);
    assert_eq!(status["sources"]["cisa_kev"]["entries"], 2);
    assert_eq!(status["age_days"], 0);
    assert_eq!(status["network_access"], false);
}

#[tokio::test]
async fn bad_arguments_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cve.sqlite");
    build_db(&db, &now());
    let mut s = Session::start(&db, 3);

    let text = s
        .err(
            "lookup_cve",
            json!({"cve_ids": ["CVE-2021-44228' OR 1=1 --"]}),
        )
        .await;
    assert!(text.contains("not a CVE id"), "{text}");
    let many: Vec<String> = (0..21)
        .map(|i| format!("CVE-2021-{:04}", 1000 + i))
        .collect();
    let text = s.err("lookup_cve", json!({"cve_ids": many})).await;
    assert!(text.contains("at most 20"), "{text}");
    let many: Vec<String> = (0..101)
        .map(|i| format!("CVE-2021-{:04}", 1000 + i))
        .collect();
    let text = s.err("get_epss_score", json!({"cve_ids": many})).await;
    assert!(text.contains("at most 100"), "{text}");
    assert!(s.err("lookup_cve", json!({})).await.contains("required"));
    assert!(
        s.err("search_cves", json!({}))
            .await
            .contains("at least one")
    );
    assert!(
        s.err("list_kev", json!({"added_after": "yesterday"}))
            .await
            .contains("YYYY-MM-DD")
    );
    // An unknown tool is a protocol error or a flagged result, never a crash.
    let response = s
        .rpc(
            "tools/call",
            json!({"name": "drop_database", "arguments": {}}),
        )
        .await;
    assert!(
        response.get("error").is_some() || response["result"]["isError"] == true,
        "{response}"
    );
    // The server is still there.
    assert_eq!(
        s.ok("data_status", json!({})).await["sources"]["nvd"]["cves"],
        3
    );
}

#[tokio::test]
async fn stale_data_carries_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cve.sqlite");
    let old = (chrono::Utc::now() - chrono::Duration::days(9)).to_rfc3339();
    build_db(&db, &old);
    let mut s = Session::start(&db, 3);
    for (tool, args) in [
        ("lookup_cve", json!({"cve_ids": ["CVE-2021-44228"]})),
        ("search_cves", json!({"query": "log4j"})),
        ("get_epss_score", json!({"cve_ids": ["CVE-2021-44228"]})),
        ("check_kev", json!({"cve_ids": ["CVE-2021-44228"]})),
        ("list_kev", json!({})),
        ("data_status", json!({})),
    ] {
        let answer = s.ok(tool, args).await;
        let warning = answer["warning"].as_str().unwrap_or_default();
        assert!(warning.contains("9 days old"), "{tool}: {answer}");
        assert_eq!(answer["data_as_of"], old, "{tool}");
    }
    assert_eq!(s.ok("data_status", json!({})).await["age_days"], 9);
}

#[tokio::test]
async fn missing_or_foreign_database_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Session::start(&dir.path().join("nope.sqlite"), 3);
    for (tool, args) in [
        ("lookup_cve", json!({"cve_ids": ["CVE-2021-44228"]})),
        ("search_cves", json!({"query": "log4j"})),
        ("get_epss_score", json!({"cve_ids": ["CVE-2021-44228"]})),
        ("check_kev", json!({"cve_ids": ["CVE-2021-44228"]})),
        ("list_kev", json!({})),
        ("data_status", json!({})),
    ] {
        assert_eq!(s.err(tool, args).await, NO_DATABASE, "{tool}");
    }
    // Bad arguments are still reported as such.
    assert!(s.err("lookup_cve", json!({})).await.contains("required"));

    let foreign = dir.path().join("foreign.sqlite");
    rusqlite::Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE t (x)")
        .unwrap();
    let mut s = Session::start(&foreign, 3);
    assert_eq!(s.err("data_status", json!({})).await, WRONG_SCHEMA);

    // The file appearing later is picked up without a restart.
    let late = dir.path().join("late.sqlite");
    let mut s = Session::start(&late, 3);
    assert_eq!(s.err("data_status", json!({})).await, NO_DATABASE);
    build_db(&late, &now());
    assert_eq!(
        s.ok("data_status", json!({})).await["sources"]["nvd"]["cves"],
        3
    );
}

#[tokio::test]
async fn a_swapped_file_is_read_by_the_next_call() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cve.sqlite");
    build_db(&db, "2026-11-01T00:00:00Z");
    let mut s = Session::start(&db, 10_000);
    assert_eq!(
        s.ok("data_status", json!({})).await["data_as_of"],
        "2026-11-01T00:00:00Z"
    );
    // What a sync does: build beside it, rename over it.
    let next = dir.path().join("cve.sqlite.new");
    build_db(&next, "2026-11-02T00:00:00Z");
    std::fs::rename(&next, &db).unwrap();
    assert_eq!(
        s.ok("data_status", json!({})).await["data_as_of"],
        "2026-11-02T00:00:00Z"
    );
}

#[test]
fn binary_check_and_version() {
    let bin = env!("CARGO_BIN_EXE_talahon-cve-mcp");
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cve.sqlite");

    let version = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("talahon-cve-mcp "));

    let run = |db: &Path| {
        std::process::Command::new(bin)
            .arg("--check")
            .env("TALAHON_CVE_DB", db)
            .output()
            .unwrap()
    };
    let missing = run(&db);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("does not exist"));
    build_db(&db, "2026-11-17T03:00:00Z");
    let ok = run(&db);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(String::from_utf8_lossy(&ok.stderr).contains("3 CVEs, 3 EPSS scores, 2 KEV entries"));
    assert!(ok.stdout.is_empty(), "stdout is the protocol");

    let bad = std::process::Command::new(bin)
        .arg("--serve-http")
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}
