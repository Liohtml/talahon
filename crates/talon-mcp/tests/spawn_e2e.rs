//! End-to-end tests against a real child process: a small Python MCP
//! server (and bash wrappers around it, like Talon's real wrapper scripts).
#![cfg(unix)]
// Test-only helpers: panicking on setup failure is the desired behaviour.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{ctx, fast_options, python3, wait_gone, write_executable, write_fake_server};
use serde_json::json;
use talon_core::tool::ToolConcurrency;
use talon_mcp::{
    AdapterOptions, ClientOptions, ManagerOptions, McpClient, McpConfigFile, McpError, McpManager,
    ServerConfig, SpawnOptions,
};

fn fake_config(python: &Path, script: &Path, cwd: &Path) -> ServerConfig {
    let mut cfg = ServerConfig::new(
        python.to_string_lossy(),
        [script.to_string_lossy().to_string()],
    );
    cfg.env.insert("FAKE_SECRET".into(), "s3cret".into());
    cfg.env.insert("FAKE_PAGE_SIZE".into(), "4".into());
    cfg.cwd = Some(cwd.to_path_buf());
    cfg
}

async fn start(cfg: &ServerConfig, spawn: &SpawnOptions, opts: ClientOptions) -> Arc<McpClient> {
    let client = McpClient::spawn_with("fake", cfg, spawn, opts)
        .await
        .unwrap();
    client.initialize().await.unwrap();
    Arc::new(client)
}

async fn text(client: &McpClient, tool: &str, args: serde_json::Value) -> String {
    let r = client.call_tool(tool, args, None).await.unwrap();
    assert!(!r.is_error, "{tool}: {}", r.render_text());
    r.render_text()
}

#[tokio::test]
async fn spawned_python_server_end_to_end() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    let cfg = fake_config(&py, &script, dir.path());
    let client = start(&cfg, &SpawnOptions::minimal(), fast_options()).await;
    assert!(client.pid().is_some());
    let init = client.initialize_result().unwrap();
    assert_eq!(init.server_info.name, "fake-py");
    assert!(init.capabilities.tools_list_changed());
    assert_eq!(client.instructions(), Some("Fake server instructions"));

    // Pagination (page size 4) collects every tool.
    let tools = client.list_tools().await.unwrap();
    assert_eq!(tools.len(), 15);
    assert!(tools.iter().any(|t| t.name == "bad.name/with spaces"));
    assert!(tools[0].is_read_only());

    assert_eq!(
        text(&client, "echo", json!({"text": "héllo wörld"})).await,
        "héllo wörld"
    );

    // Environment: server env applied, minimal base env, nothing inherited.
    assert_eq!(
        text(&client, "env", json!({"name": "FAKE_SECRET"})).await,
        "s3cret"
    );
    assert_eq!(text(&client, "env", json!({"name": "HOME"})).await, "/tmp");
    assert_eq!(
        text(&client, "env", json!({"name": "CARGO_MANIFEST_DIR"})).await,
        "<unset>"
    );
    let cwd = text(&client, "cwd", json!({})).await;
    assert_eq!(
        std::fs::canonicalize(cwd).unwrap(),
        std::fs::canonicalize(dir.path()).unwrap()
    );

    // Result conversion.
    let s = text(&client, "structured", json!({})).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&s).unwrap(),
        json!({"alerts": 3, "ok": true})
    );
    assert_eq!(
        text(&client, "image", json!({})).await,
        "see image\n[image content omitted: image/png, ~5 bytes]"
    );
    let r = client.call_tool("fail", json!({}), None).await.unwrap();
    assert!(r.is_error);
    assert_eq!(r.render_text(), "index not found");
    let err = client
        .call_tool("no_such_tool", json!({}), None)
        .await
        .unwrap_err();
    assert_eq!(err.rpc_code(), Some(-32602));

    // The client answered the server's ping sent after `initialized`.
    assert_eq!(text(&client, "pong", json!({})).await, "[{}]");
    client.ping().await.unwrap();

    // stderr is captured.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !client
        .stderr_tail()
        .iter()
        .any(|l| l.contains("fake server starting"))
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        client
            .stderr_tail()
            .iter()
            .any(|l| l.contains("fake server starting"))
    );

    let pid = client.pid().unwrap();
    client.shutdown().await;
    assert!(wait_gone(pid, Duration::from_secs(3)).await);
    assert!(
        client
            .call_tool("echo", json!({"text": "x"}), None)
            .await
            .unwrap_err()
            .is_closed()
    );
}

#[tokio::test]
async fn crash_fails_pending_call_promptly() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    let cfg = fake_config(&py, &script, dir.path());
    let client = start(&cfg, &SpawnOptions::default(), fast_options()).await;
    let started = Instant::now();
    let err = client
        .call_tool("die", json!({}), Some(Duration::from_secs(60)))
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    match &err {
        McpError::Closed { reason, .. } => assert!(reason.contains("exit"), "{reason}"),
        other => panic!("unexpected {other:?}"),
    }
    assert!(client.is_closed());
    let deadline = Instant::now() + Duration::from_secs(2);
    while !client
        .stderr_tail()
        .iter()
        .any(|l| l.contains("dying on purpose"))
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        client
            .stderr_tail()
            .iter()
            .any(|l| l.contains("dying on purpose"))
    );
}

#[tokio::test]
async fn timeout_sends_cancel_and_server_stays_usable() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    let cfg = fake_config(&py, &script, dir.path());
    let client = start(&cfg, &SpawnOptions::default(), fast_options()).await;
    let err = client
        .call_tool(
            "sleep",
            json!({"seconds": 0.6}),
            Some(Duration::from_millis(150)),
        )
        .await
        .unwrap_err();
    assert!(err.is_timeout());
    // The single-threaded server answers the late call (ignored) and then
    // processes the queued cancellation and this call.
    let cancelled = text(&client, "cancelled", json!({})).await;
    let ids: Vec<i64> = serde_json::from_str(&cancelled).unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        text(&client, "echo", json!({"text": "still alive"})).await,
        "still alive"
    );
}

#[tokio::test]
async fn oversized_output_fails_only_that_call() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    let cfg = fake_config(&py, &script, dir.path());
    let opts = ClientOptions {
        max_message_bytes: 64 * 1024,
        ..fast_options()
    };
    let client = start(&cfg, &SpawnOptions::default(), opts).await;
    let started = Instant::now();
    let err = client
        .call_tool("big", json!({"n": 1_000_000}), None)
        .await
        .unwrap_err();
    assert!(matches!(err, McpError::MessageTooLarge { .. }), "{err}");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(text(&client, "big", json!({"n": 1000})).await.len(), 1000);
}

#[tokio::test]
async fn drop_kills_server() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    let cfg = fake_config(&py, &script, dir.path());
    let client = start(&cfg, &SpawnOptions::default(), fast_options()).await;
    let pid: u32 = text(&client, "pid", json!({})).await.parse().unwrap();
    let child: u32 = text(&client, "spawn_child", json!({}))
        .await
        .parse()
        .unwrap();
    assert!(!common::process_gone(pid));
    drop(client);
    assert!(
        wait_gone(pid, Duration::from_secs(3)).await,
        "server survived drop"
    );
    assert!(
        wait_gone(child, Duration::from_secs(3)).await,
        "grandchild survived drop"
    );
}

#[tokio::test]
async fn shutdown_kills_process_group_behind_bash_wrapper() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    // Like the real wrappers, but without `exec`: bash stays the parent.
    let wrapper = dir.path().join("wrapper.sh");
    write_executable(
        &wrapper,
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\necho 'wrapper starting' >&2\n\"{}\" \"{}\"\n",
            py.display(),
            script.display()
        ),
    );
    let cfg = ServerConfig::new(wrapper.to_string_lossy(), Vec::<String>::new());
    let client = start(&cfg, &SpawnOptions::default(), fast_options()).await;
    let bash_pid = client.pid().unwrap();
    let py_pid: u32 = text(&client, "pid", json!({})).await.parse().unwrap();
    assert_ne!(bash_pid, py_pid);
    let child: u32 = text(&client, "spawn_child", json!({}))
        .await
        .parse()
        .unwrap();
    let started = Instant::now();
    client.shutdown().await;
    assert!(started.elapsed() < Duration::from_secs(4));
    for pid in [bash_pid, py_pid, child] {
        assert!(
            wait_gone(pid, Duration::from_secs(3)).await,
            "pid {pid} survived shutdown"
        );
    }
}

#[tokio::test]
async fn shutdown_escalates_for_stubborn_server() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    // Ignores SIGTERM and keeps running after stdin EOF.
    let stubborn = dir.path().join("stubborn.sh");
    write_executable(
        &stubborn,
        &format!(
            "#!/usr/bin/env bash\ntrap '' TERM\n\"{}\" \"{}\"\nwhile true; do sleep 0.05; done\n",
            py.display(),
            script.display()
        ),
    );
    let cfg = ServerConfig::new(stubborn.to_string_lossy(), Vec::<String>::new());
    let opts = ClientOptions {
        shutdown_grace: Duration::from_millis(200),
        ..fast_options()
    };
    let client = start(&cfg, &SpawnOptions::default(), opts).await;
    let pid = client.pid().unwrap();
    let started = Instant::now();
    client.shutdown().await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert!(wait_gone(pid, Duration::from_secs(3)).await);
}

#[tokio::test]
async fn manager_spawn_mode_isolates_failures_and_refreshes() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    let hang = dir.path().join("hang.py");
    std::fs::write(&hang, "import time\ntime.sleep(60)\n").unwrap();
    let config_json = json!({
        "mcpServers": {
            "fake": {"command": py, "args": [script], "env": {"FAKE_PAGE_SIZE": "5"}},
            "ghost": {"command": "/nonexistent/server"},
            "hang": {"command": py, "args": [hang]},
            "broken": {"command": 7}
        }
    });
    let config = McpConfigFile::parse(&config_json.to_string()).unwrap();
    assert_eq!(config.invalid.len(), 1);
    let mut options = ManagerOptions {
        start_timeout: Duration::from_millis(1500),
        client: fast_options(),
        reserved_tool_names: vec!["bash".into()],
        adapter: AdapterOptions {
            post_processor: Some(Arc::new(|server: &str, _tool: &str, text: String| {
                format!("[{server}] {text}")
            })),
            ..AdapterOptions::default()
        },
        ..ManagerOptions::default()
    };
    options.spawn = SpawnOptions::default();
    let started = Instant::now();
    let mut manager = McpManager::start(&config, options).await;
    // Concurrent start: bounded by the hang timeout, not the sum.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    let failed: Vec<_> = manager.failures().iter().map(|f| f.name.as_str()).collect();
    assert_eq!(failed, vec!["broken", "ghost", "hang"]);
    let hang_err = &manager.failures()[2].error;
    assert!(hang_err.contains("timed out"), "{hang_err}");

    let tools = manager.tools();
    assert_eq!(tools.len(), 15);
    let names: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
    assert!(names.contains(&"mcp__fake__echo".to_string()));
    assert!(names.contains(&"mcp__fake__bad_name_with_spaces".to_string()));
    for n in &names {
        assert!(talon_mcp::adapter::is_valid_tool_name(n), "{n}");
    }
    let echo = tools
        .iter()
        .find(|t| t.spec().name == "mcp__fake__echo")
        .unwrap();
    assert_eq!(echo.concurrency(), ToolConcurrency::ReadOnly);
    let out = echo.call(json!({"text": "x"}), &ctx()).await;
    assert_eq!(out.content, "[fake] x");
    assert_eq!(
        manager.instructions(),
        vec![("fake".to_string(), "Fake server instructions".to_string())]
    );

    // tools/list_changed -> refresh picks up the new tool.
    assert!(!manager.refresh_tools().await);
    let change = tools
        .iter()
        .find(|t| t.spec().name == "mcp__fake__change_tools")
        .unwrap();
    assert_eq!(
        change.call(json!({}), &ctx()).await.content,
        "[fake] changed"
    );
    let client = Arc::clone(manager.client("fake").unwrap());
    let deadline = Instant::now() + Duration::from_secs(2);
    while client.tools_generation() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(manager.refresh_tools().await);
    assert_eq!(manager.tools().len(), 16);
    assert!(
        manager
            .tools()
            .iter()
            .any(|t| t.spec().name == "mcp__fake__extra")
    );

    let pid = client.pid().unwrap();
    manager.shutdown_all().await;
    assert!(wait_gone(pid, Duration::from_secs(3)).await);
}

/// What `talon-agent supervise` does: spawn the server itself, expose its
/// stdio on `<dir>/<server>.sock` via `bridge`, and let the agent connect
/// with the manager in socket mode.
#[tokio::test]
async fn supervisor_style_socket_bridge() {
    let Some(py) = python3() else { return };
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake_server(dir.path());
    let cfg = fake_config(&py, &script, dir.path());
    let config = McpConfigFile {
        mcp_servers: [("fake".to_string(), cfg.clone())].into_iter().collect(),
        ..McpConfigFile::default()
    };

    // Supervisor side.
    let sock_dir = dir.path().join("mcp");
    std::fs::create_dir(&sock_dir).unwrap();
    let path = talon_mcp::socket_path(&sock_dir, "fake").unwrap();
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let mut cmd =
        talon_mcp::process::build_command("fake", &cfg, &SpawnOptions::minimal()).unwrap();
    let mut child = cmd.spawn().unwrap();
    let pid = child.id().unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let supervisor = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let relayed = talon_mcp::bridge::bridge(stream, stdin, stdout)
            .await
            .unwrap();
        let status = child.wait().await.unwrap();
        (relayed, status)
    });

    // Agent side.
    let options = ManagerOptions {
        client: fast_options(),
        ..ManagerOptions::default()
    }
    .with_socket_dir(Some(sock_dir.clone()));
    let manager = McpManager::start(&config, options).await;
    assert!(manager.failures().is_empty(), "{:?}", manager.failures());
    let tools = manager.tools();
    assert_eq!(tools.len(), 15);
    let env = tools
        .iter()
        .find(|t| t.spec().name == "mcp__fake__env")
        .unwrap();
    assert_eq!(
        env.call(json!({"name": "FAKE_SECRET"}), &ctx())
            .await
            .content,
        "s3cret"
    );
    manager.shutdown_all().await;

    // Closing the agent's connection closes the server's stdin: it exits.
    let ((to_server, to_client), status) = tokio::time::timeout(Duration::from_secs(5), supervisor)
        .await
        .unwrap()
        .unwrap();
    assert!(to_server > 0 && to_client > 0);
    assert!(status.success(), "{status}");
    assert!(wait_gone(pid, Duration::from_secs(2)).await);
}
