//! Tests of the `talon-opensearch-mcp` binary itself: the stdio loop
//! (initialize → tools/list → tools/call), what it prints where, and its
//! start-up checks.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BIN: &str = env!("CARGO_BIN_EXE_talon-opensearch-mcp");
const PASSWORD: &str = "hunter2-very-secret";

/// The binary with a clean environment (nothing inherited from the test
/// runner can configure it).
fn command() -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

#[tokio::test]
async fn stdio_loop_serves_initialize_list_and_call() {
    let os = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/wazuh-alerts-4.x-*/_search"))
        // base64("admin:hunter2-very-secret")
        .and(header(
            "authorization",
            "Basic YWRtaW46aHVudGVyMi12ZXJ5LXNlY3JldA==",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"hits":{"total":{"value":0},"hits":[]}}"#,
            "application/json",
        ))
        .mount(&os)
        .await;

    let mut child = command()
        .env("OPENSEARCH_HOSTS", os.uri())
        .env("OPENSEARCH_USERNAME", "admin")
        .env("OPENSEARCH_PASSWORD", PASSWORD)
        .env("VERIFY_CERTS", "false")
        .env("TALON_OPENSEARCH_LOG", "debug")
        // A proxy from the environment must be ignored (it points nowhere).
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("http_proxy", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();

    let requests = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "search_documents",
            "arguments": {"index": "wazuh-alerts-4.x-*", "body": {"size": 0}}}}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "get_index", "arguments": {"index": "../_cluster/settings\n"}}}),
    ];
    let mut responses = Vec::new();
    for request in &requests {
        let mut line = serde_json::to_vec(request).unwrap();
        line.push(b'\n');
        stdin.write_all(&line).await.unwrap();
        if request.get("id").is_none() {
            continue;
        }
        let mut answer = String::new();
        tokio::time::timeout(Duration::from_secs(30), stdout.read_line(&mut answer))
            .await
            .expect("no response from the server")
            .unwrap();
        let answer: Value = serde_json::from_str(&answer).expect("stdout must be JSON lines only");
        assert_eq!(answer["id"], request["id"]);
        responses.push(answer);
    }

    assert_eq!(
        responses[0]["result"]["serverInfo"]["name"],
        "talon-opensearch-mcp"
    );
    assert_eq!(responses[0]["result"]["protocolVersion"], "2025-06-18");
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 10);
    assert!(tools.iter().any(|t| t["name"] == "get_document"));
    assert_eq!(
        responses[2]["result"]["content"][0]["text"],
        r#"{"hits":{"total":{"value":0},"hits":[]}}"#
    );
    assert!(
        responses[2]["result"]
            .get("isError")
            .is_none_or(|e| e == false)
    );
    assert_eq!(responses[3]["result"]["isError"], true);

    // EOF on stdin ends the server cleanly, with nothing more on stdout.
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("server did not exit on EOF")
        .unwrap();
    assert!(status.success());
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).await.unwrap();
    assert_eq!(rest, "");

    // Logs go to stderr and never contain the password or the auth header.
    let mut log = String::new();
    stderr.read_to_string(&mut log).await.unwrap();
    assert!(log.contains("talon-opensearch-mcp starting"), "{log}");
    assert!(log.contains("TLS certificates are not verified"), "{log}");
    assert!(!log.contains(PASSWORD), "{log}");
    assert!(!log.contains("YWRtaW46"), "{log}");

    assert_eq!(os.received_requests().await.unwrap().len(), 1);
}

async fn run(args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String, String) {
    let mut cmd = command();
    cmd.args(args).stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = tokio::time::timeout(Duration::from_secs(30), cmd.output())
        .await
        .expect("binary did not exit")
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn bad_configuration_fails_at_startup_without_leaking_it() {
    let cases: [(&[(&str, &str)], &str); 5] = [
        (
            &[("OPENSEARCH_HOSTS", "ftp://admin:hunter2-very-secret@host")],
            "OPENSEARCH_HOSTS",
        ),
        (&[("VERIFY_CERTS", "maybe")], "VERIFY_CERTS"),
        (
            &[("OPENSEARCH_CLUSTERS", "{\"a\":{}}")],
            "OPENSEARCH_CLUSTERS",
        ),
        (
            &[("OPENSEARCH_PROXY", "socks5h://127.0.0.1:1080")],
            "OPENSEARCH_PROXY",
        ),
        (
            &[("OPENSEARCH_CA_CERTS", "/nonexistent/ca.pem")],
            "OPENSEARCH_CA_CERTS",
        ),
    ];
    for (env, var) in cases {
        for args in [&["--check"][..], &[][..]] {
            let (code, stdout, stderr) = run(args, env).await;
            assert_eq!(code, Some(2), "{var}: {stderr}");
            assert_eq!(stdout, "", "{var}");
            assert!(
                stderr.contains("configuration error") && stderr.contains(var),
                "{stderr}"
            );
            assert!(!stderr.contains(PASSWORD), "{stderr}");
        }
    }
}

#[tokio::test]
async fn check_version_and_unknown_arguments() {
    let (code, stdout, stderr) = run(
        &["--check"],
        &[
            ("OPENSEARCH_HOSTS", "https://os.example:9200"),
            ("OPENSEARCH_USERNAME", "admin"),
            ("OPENSEARCH_PASSWORD", PASSWORD),
        ],
    )
    .await;
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(stdout, "");
    assert!(stderr.contains("configuration OK"));
    assert!(!stderr.contains(PASSWORD));

    let (code, stdout, _) = run(&["--version"], &[]).await;
    assert_eq!(code, Some(0));
    assert!(stdout.starts_with("talon-opensearch-mcp "));

    let (code, stdout, _) = run(&["--transport", "sse"], &[]).await;
    assert_eq!(code, Some(2));
    assert_eq!(stdout, "");
}
