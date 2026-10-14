//! `McpClient` <-> `McpServer` round trips over in-memory and unix-socket
//! transports, plus the `Tool` adapter and the manager in socket mode.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{Big, Echo, Fail, Panicker, Slow, ctx, fast_options};
use serde_json::json;
use talon_core::tool::{Tool, ToolConcurrency};
use talon_mcp::{
    AdapterOptions, ClientOptions, LATEST_PROTOCOL_VERSION, ManagerOptions, McpClient,
    McpConfigFile, McpError, McpManager, McpServer, McpToolAdapter, ToolNameAllocator, socket_path,
};
use tokio_util::sync::CancellationToken;

struct Harness {
    client: Arc<McpClient>,
    slow_cancelled: Arc<AtomicBool>,
    server_task: tokio::task::JoinHandle<Result<(), McpError>>,
}

async fn harness(page_size: usize, options: ClientOptions) -> Harness {
    let slow_cancelled = Arc::new(AtomicBool::new(false));
    let server = McpServer::builder("talon-test", "1.0")
        .instructions("test instructions")
        .tool(Arc::new(Echo))
        .tool(Arc::new(Fail))
        .tool(Arc::new(Slow {
            cancelled: Arc::clone(&slow_cancelled),
        }))
        .tool(Arc::new(Panicker))
        .tool(Arc::new(Big))
        .page_size(page_size)
        .build();
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    let server_task = tokio::spawn(async move { server.serve(sr, sw).await });
    let (cr, cw) = tokio::io::split(client_side);
    let client = Arc::new(McpClient::connect("local", cr, cw, options).await);
    Harness {
        client,
        slow_cancelled,
        server_task,
    }
}

#[tokio::test]
async fn full_round_trip() {
    let h = harness(2, fast_options()).await;
    let client = &h.client;
    let init = client.initialize().await.unwrap();
    assert_eq!(init.protocol_version, LATEST_PROTOCOL_VERSION);
    assert_eq!(init.server_info.name, "talon-test");
    assert!(init.capabilities.has_tools());
    assert_eq!(client.instructions(), Some("test instructions"));
    client.ping().await.unwrap();

    // 5 tools, page size 2 -> 3 pages.
    let tools = client.list_tools().await.unwrap();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["echo", "fail", "slow", "panic", "big"]);
    assert!(tools[0].is_read_only());
    assert!(!tools[1].is_read_only());
    assert_eq!(tools[0].input_schema["required"], json!(["text"]));

    let r = client
        .call_tool("echo", json!({"text": "hello"}), None)
        .await
        .unwrap();
    assert_eq!(r.render_text(), "hello");
    assert!(!r.is_error);

    let r = client.call_tool("fail", json!({}), None).await.unwrap();
    assert!(r.is_error);
    assert_eq!(r.render_text(), "this tool always fails");

    let err = client.call_tool("nope", json!({}), None).await.unwrap_err();
    assert_eq!(err.rpc_code(), Some(-32602));
    assert!(err.to_string().contains("Unknown tool: nope"));

    let err = client
        .call_tool("panic", json!({}), None)
        .await
        .unwrap_err();
    assert_eq!(err.rpc_code(), Some(-32603));
    // The server survives a panicking tool.
    client.ping().await.unwrap();

    client.shutdown().await;
    let served = tokio::time::timeout(Duration::from_secs(5), h.server_task).await;
    assert!(matches!(served, Ok(Ok(Ok(())))));
}

#[tokio::test]
async fn cancellation_propagates_to_server_tool() {
    let h = harness(0, fast_options()).await;
    h.client.initialize().await.unwrap();
    let token = CancellationToken::new();
    let c = Arc::clone(&h.client);
    let t = token.clone();
    let call = tokio::spawn(async move {
        c.call_tool_cancellable("slow", json!({"ms": 10_000}), None, &t)
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    token.cancel();
    let err = call.await.unwrap().unwrap_err();
    assert!(matches!(err, McpError::Cancelled { .. }));
    // The server receives notifications/cancelled and drops the tool future.
    let deadline = Instant::now() + Duration::from_secs(3);
    while !h.slow_cancelled.load(Ordering::SeqCst) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        h.slow_cancelled.load(Ordering::SeqCst),
        "server-side tool was not cancelled"
    );
    h.client.ping().await.unwrap();
}

#[tokio::test]
async fn timeout_cancels_server_tool() {
    let h = harness(0, fast_options()).await;
    h.client.initialize().await.unwrap();
    let err = h
        .client
        .call_tool(
            "slow",
            json!({"ms": 10_000}),
            Some(Duration::from_millis(100)),
        )
        .await
        .unwrap_err();
    assert!(err.is_timeout());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !h.slow_cancelled.load(Ordering::SeqCst) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(h.slow_cancelled.load(Ordering::SeqCst));
}

#[tokio::test]
async fn calls_run_concurrently() {
    let h = harness(0, fast_options()).await;
    h.client.initialize().await.unwrap();
    let started = Instant::now();
    let mut calls = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&h.client);
        calls.push(tokio::spawn(async move {
            c.call_tool("slow", json!({"ms": 300}), None).await
        }));
    }
    for call in calls {
        assert_eq!(call.await.unwrap().unwrap().render_text(), "slept 300ms");
    }
    assert!(
        started.elapsed() < Duration::from_millis(1100),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn large_results_round_trip() {
    let h = harness(0, fast_options()).await;
    h.client.initialize().await.unwrap();
    let r = h
        .client
        .call_tool("big", json!({"n": 3_000_000}), None)
        .await
        .unwrap();
    assert_eq!(r.render_text().len(), 3_000_000);
}

#[tokio::test]
async fn adapter_exposes_tools() {
    let h = harness(0, fast_options()).await;
    h.client.initialize().await.unwrap();
    let tools = h.client.list_tools().await.unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    let options = AdapterOptions {
        max_output_bytes: 100,
        post_processor: Some(Arc::new(move |server: &str, tool: &str, text: String| {
            seen2.lock().unwrap().push(format!("{server}/{tool}"));
            format!("<untrusted source=\"{server}\">{text}</untrusted>")
        })),
        ..AdapterOptions::default()
    };
    let mut alloc = ToolNameAllocator::new();
    alloc.reserve("mcp__local__fail");
    let adapters = McpToolAdapter::wrap_all(&h.client, &tools, &mut alloc, &options);
    let names: Vec<_> = adapters
        .iter()
        .map(|a| a.exposed_name().to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "mcp__local__echo",
            "mcp__local__fail_2",
            "mcp__local__slow",
            "mcp__local__panic",
            "mcp__local__big"
        ]
    );

    let echo: Arc<dyn Tool> = adapters[0].clone();
    let spec = echo.spec();
    assert_eq!(spec.name, "mcp__local__echo");
    assert_eq!(spec.description, "Echo the 'text' argument");
    assert_eq!(spec.parameters["type"], json!("object"));
    assert_eq!(echo.concurrency(), ToolConcurrency::ReadOnly);
    assert_eq!(adapters[1].concurrency(), ToolConcurrency::Exclusive);
    assert_eq!(adapters[0].server_name(), "local");
    assert_eq!(adapters[1].tool_name(), "fail");

    let out = echo.call(json!({"text": "hi"}), &ctx()).await;
    assert!(!out.is_error);
    assert_eq!(out.content, "<untrusted source=\"local\">hi</untrusted>");

    let out = adapters[1].call(json!({}), &ctx()).await;
    assert!(out.is_error);
    assert!(out.content.contains("always fails"));

    // Non-object arguments are rejected locally (still post-processed).
    let out = echo.call(json!([1, 2]), &ctx()).await;
    assert!(out.is_error);
    assert!(out.content.contains("expected a JSON object"));

    // Truncation happens before the post-processor so the fence survives.
    let out = adapters[4].call(json!({"n": 500}), &ctx()).await;
    assert!(out.content.ends_with("</untrusted>"));
    assert!(out.content.contains("output truncated"));

    // Protocol errors become error outputs.
    let out = adapters[3].call(json!({}), &ctx()).await;
    assert!(out.is_error);
    assert!(out.content.starts_with("<untrusted"));
    assert!(out.content.contains("MCP tool call failed"));

    // Cancellation through the ToolContext.
    let c = ctx();
    let cancel = c.cancel.clone();
    let slow = adapters[2].clone();
    let call = tokio::spawn(async move { slow.call(json!({"ms": 10_000}), &c).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel.cancel();
    let out = call.await.unwrap();
    assert!(out.is_error);
    assert!(out.content.contains("cancelled"));

    let log = seen.lock().unwrap().clone();
    assert!(log.contains(&"local/echo".to_string()));
    assert!(log.contains(&"local/panic".to_string()));

    // Force-exclusive option.
    let opts = AdapterOptions {
        force_exclusive: true,
        ..AdapterOptions::default()
    };
    let a = McpToolAdapter::new(Arc::clone(&h.client), tools[0].clone(), "bad name!", opts);
    assert_eq!(a.concurrency(), ToolConcurrency::Exclusive);
    assert_eq!(a.exposed_name(), "bad_name_");
}

#[tokio::test]
async fn adapter_reports_dead_server() {
    let h = harness(0, fast_options()).await;
    h.client.initialize().await.unwrap();
    let tools = h.client.list_tools().await.unwrap();
    let mut alloc = ToolNameAllocator::new();
    let adapters =
        McpToolAdapter::wrap_all(&h.client, &tools, &mut alloc, &AdapterOptions::default());
    h.server_task.abort();
    let _ = h.server_task.await;
    let out = adapters[0].call(json!({"text": "x"}), &ctx()).await;
    assert!(out.is_error);
    assert!(out.content.contains("not available"), "{}", out.content);
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_transport_and_manager_socket_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket_path(dir.path(), "local").unwrap();
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = McpServer::builder("sock", "1").tool(Arc::new(Echo)).build();
    let accept = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let server = server.clone();
            tokio::spawn(async move { server.serve_unix(stream).await });
        }
    });

    // Direct client.
    let client = McpClient::connect_unix("local", &path, fast_options())
        .await
        .unwrap();
    client.initialize().await.unwrap();
    let r = client
        .call_tool("echo", json!({"text": "via socket"}), None)
        .await
        .unwrap();
    assert_eq!(r.render_text(), "via socket");
    client.shutdown().await;

    // Manager: one server reachable, one socket missing.
    let cfg = McpConfigFile::parse(
        r#"{"mcpServers": {"local": {"command": "ignored-in-socket-mode", "runAs": "mcp-siem"}, "absent": {"command": "x"}}}"#,
    )
    .unwrap();
    let mut opts = ManagerOptions::default().with_socket_dir(Some(dir.path().to_path_buf()));
    opts.client = fast_options();
    opts.reserved_tool_names = vec!["bash".into()];
    let manager = McpManager::start(&cfg, opts).await;
    assert_eq!(manager.servers().len(), 1);
    assert_eq!(manager.failures().len(), 1);
    assert_eq!(manager.failures()[0].name, "absent");
    let tools = manager.tools();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].spec().name, "mcp__local__echo");
    let out = tools[0].call(json!({"text": "managed"}), &ctx()).await;
    assert_eq!(out.content, "managed");
    let statuses = manager.statuses();
    assert_eq!(statuses.len(), 2);
    assert!(
        statuses
            .iter()
            .any(|s| s.name == "local" && s.connected && s.tool_count == 1)
    );
    assert!(statuses.iter().any(|s| s.name == "absent" && !s.connected));
    assert!(manager.client("local").is_some());
    manager.shutdown_all().await;
    assert!(manager.client("local").unwrap().is_closed());
    accept.abort();
}

#[tokio::test]
async fn older_client_version_is_echoed_by_server() {
    let opts = ClientOptions {
        protocol_version: "2024-11-05".into(),
        ..fast_options()
    };
    let h = harness(0, opts).await;
    let r = h.client.initialize().await.unwrap();
    assert_eq!(r.protocol_version, "2024-11-05");
}
