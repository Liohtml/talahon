//! Client behaviour against a hand-scripted (mis)behaving server.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{fake_pair, fast_options};
use serde_json::{Value, json};
use talon_mcp::{ClientOptions, LATEST_PROTOCOL_VERSION, McpError};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn handshake_sends_initialized_after_result() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    let req = peer.recv().await;
    assert_eq!(req["jsonrpc"], json!("2.0"));
    assert_eq!(req["method"], json!("initialize"));
    assert_eq!(
        req["params"]["protocolVersion"],
        json!(LATEST_PROTOCOL_VERSION)
    );
    assert_eq!(req["params"]["clientInfo"]["name"], json!("talon-mcp"));
    assert!(req["params"]["capabilities"].is_object());
    peer.respond(
        &req,
        json!({"protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": true}},
               "serverInfo": {"name": "s", "version": "9"}, "instructions": "hi"}),
    )
    .await;
    let note = peer.recv().await;
    assert_eq!(
        note,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    );
    let result = init.await.unwrap().unwrap();
    assert_eq!(result.server_info.name, "s");
    assert_eq!(client.protocol_version(), Some(LATEST_PROTOCOL_VERSION));
    assert_eq!(client.instructions(), Some("hi"));
    // Second call returns the cached result without traffic.
    let again = client.initialize().await.unwrap();
    assert_eq!(again, result);
    assert!(peer.try_recv(Duration::from_millis(50)).await.is_none());
}

#[tokio::test]
async fn malformed_lines_and_unknown_ids_are_skipped() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    let req = peer.recv().await;
    peer.send_raw("this is not json").await;
    peer.send_raw("{\"truncated\": ").await;
    peer.send_raw("[]").await;
    peer.send_raw("42").await;
    peer.send(json!({"jsonrpc":"2.0","id":999,"result":{}}))
        .await;
    peer.send(json!({"jsonrpc":"2.0","id":"1","result":{}}))
        .await;
    peer.send(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"bad"}}))
        .await;
    peer.send(json!({"jsonrpc":"1.0","id":1,"result":{}})).await;
    peer.respond(
        &req,
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name":"s","version":"1"}}),
    )
    .await;
    init.await.unwrap().unwrap();
    assert!(!client.is_closed());
}

#[tokio::test]
async fn answers_server_to_client_requests() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();

    peer.send(json!({"jsonrpc":"2.0","id":50,"method":"ping"}))
        .await;
    assert_eq!(
        peer.recv().await,
        json!({"jsonrpc":"2.0","id":50,"result":{}})
    );
    peer.send(json!({"jsonrpc":"2.0","id":"r","method":"roots/list"}))
        .await;
    assert_eq!(
        peer.recv().await,
        json!({"jsonrpc":"2.0","id":"r","result":{"roots":[]}})
    );
    peer.send(json!({"jsonrpc":"2.0","id":51,"method":"sampling/createMessage","params":{}}))
        .await;
    let resp = peer.recv().await;
    assert_eq!(resp["id"], json!(51));
    assert_eq!(resp["error"]["code"], json!(-32601));
    // Batches (legacy) are processed element by element.
    peer.send(json!([{"jsonrpc":"2.0","id":52,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/progress","params":{}}])).await;
    assert_eq!(peer.recv().await["id"], json!(52));
}

#[tokio::test]
async fn tools_list_changed_bumps_generation() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();
    let mut rx = client.subscribe_tools_changed();
    assert_eq!(client.tools_generation(), 0);
    peer.send(json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}))
        .await;
    peer.send(json!({"jsonrpc":"2.0","method":"notifications/message","params":{"level":"error","data":{"x":"\u{1b}[31mred"}}})).await;
    tokio::time::timeout(Duration::from_secs(2), rx.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*rx.borrow(), 1);
    assert_eq!(client.tools_generation(), 1);
}

#[tokio::test]
async fn list_tools_follows_cursors_and_skips_bad_entries() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();

    let c = Arc::clone(&client);
    let list = tokio::spawn(async move { c.list_tools().await });
    let req = peer.recv_method("tools/list").await;
    assert!(req.get("params").is_none() || req["params"].get("cursor").is_none());
    peer.respond(
        &req,
        json!({"tools": [
            {"name": "a", "inputSchema": {"type":"object"}},
            {"description": "no name"},
            {"name": "", "inputSchema": {}},
            {"name": "b"}
        ], "nextCursor": "page2"}),
    )
    .await;
    let req = peer.recv_method("tools/list").await;
    assert_eq!(req["params"]["cursor"], json!("page2"));
    peer.respond(
        &req,
        json!({"tools": [{"name": "c"}, {"name": "a"}], "nextCursor": ""}),
    )
    .await;
    let tools = list.await.unwrap().unwrap();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b", "c"]);

    // A server that repeats its cursor does not loop forever.
    let c = Arc::clone(&client);
    let list = tokio::spawn(async move { c.list_tools().await });
    for _ in 0..2 {
        let req = peer.recv_method("tools/list").await;
        peer.respond(
            &req,
            json!({"tools": [{"name": "x"}], "nextCursor": "same"}),
        )
        .await;
    }
    let tools = list.await.unwrap().unwrap();
    assert_eq!(tools.len(), 1);

    // Missing tools array is a protocol error.
    let c = Arc::clone(&client);
    let list = tokio::spawn(async move { c.list_tools().await });
    let req = peer.recv_method("tools/list").await;
    peer.respond(&req, json!({"items": []})).await;
    assert!(matches!(
        list.await.unwrap(),
        Err(McpError::Protocol { .. })
    ));

    // Method not found -> no tools.
    let c = Arc::clone(&client);
    let list = tokio::spawn(async move { c.list_tools().await });
    let req = peer.recv_method("tools/list").await;
    peer.send(json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32601,"message":"nope"}}))
        .await;
    assert!(list.await.unwrap().unwrap().is_empty());
}

#[tokio::test]
async fn dead_server_fails_pending_promptly() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();

    let c = Arc::clone(&client);
    let call = tokio::spawn(async move {
        c.call_tool("x", json!({}), Some(Duration::from_secs(60)))
            .await
    });
    let _req = peer.recv_method("tools/call").await;
    let started = Instant::now();
    drop(peer);
    let err = call.await.unwrap().unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    assert!(err.is_closed(), "{err}");
    assert!(err.to_string().contains("EOF"), "{err}");
    assert!(client.is_closed());
    // New requests fail immediately.
    let started = Instant::now();
    assert!(client.ping().await.unwrap_err().is_closed());
    assert!(
        client
            .call_tool("x", json!({}), None)
            .await
            .unwrap_err()
            .is_closed()
    );
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn timeout_sends_cancellation_and_ignores_late_response() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();

    let c = Arc::clone(&client);
    let call = tokio::spawn(async move {
        c.call_tool("slow", json!({"q": 1}), Some(Duration::from_millis(200)))
            .await
    });
    let req = peer.recv_method("tools/call").await;
    assert_eq!(
        req["params"],
        json!({"name": "slow", "arguments": {"q": 1}})
    );
    let err = call.await.unwrap().unwrap_err();
    assert!(err.is_timeout(), "{err}");
    let cancel = peer.recv().await;
    assert_eq!(cancel["method"], json!("notifications/cancelled"));
    assert_eq!(cancel["params"]["requestId"], req["id"]);
    // The late response is ignored; the connection stays usable.
    peer.respond(&req, json!({"content": []})).await;
    let c = Arc::clone(&client);
    let ping = tokio::spawn(async move { c.ping().await });
    let p = peer.recv_method("ping").await;
    peer.respond(&p, json!({})).await;
    ping.await.unwrap().unwrap();
    assert!(!client.is_closed());
}

#[tokio::test]
async fn caller_cancellation() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();

    let token = CancellationToken::new();
    let c = Arc::clone(&client);
    let t = token.clone();
    let call =
        tokio::spawn(async move { c.call_tool_cancellable("slow", json!({}), None, &t).await });
    let req = peer.recv_method("tools/call").await;
    token.cancel();
    let err = call.await.unwrap().unwrap_err();
    assert!(matches!(err, McpError::Cancelled { .. }), "{err}");
    let cancel = peer.recv().await;
    assert_eq!(cancel["params"]["requestId"], req["id"]);
    assert_eq!(
        cancel["params"]["reason"],
        json!("request cancelled by client")
    );
}

#[tokio::test]
async fn oversized_response_fails_only_that_call() {
    let opts = ClientOptions {
        max_message_bytes: 1024,
        ..fast_options()
    };
    let (client, mut peer) = fake_pair(opts).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();

    // Python ordering: id before result.
    let c = Arc::clone(&client);
    let call = tokio::spawn(async move { c.call_tool("big", json!({}), None).await });
    let req = peer.recv_method("tools/call").await;
    let big = "y".repeat(5000);
    peer.send_raw(&format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{big}\"}}]}}}}",
        req["id"]
    ))
    .await;
    let started = Instant::now();
    let err = call.await.unwrap().unwrap_err();
    assert!(
        matches!(err, McpError::MessageTooLarge { limit: 1024, .. }),
        "{err}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));

    // TypeScript ordering: id after result.
    let c = Arc::clone(&client);
    let call = tokio::spawn(async move { c.call_tool("big", json!({}), None).await });
    let req = peer.recv_method("tools/call").await;
    peer.send_raw(&format!(
        "{{\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{big}\"}}]}},\"jsonrpc\":\"2.0\",\"id\":{}}}",
        req["id"]
    ))
    .await;
    let err = call.await.unwrap().unwrap_err();
    assert!(matches!(err, McpError::MessageTooLarge { .. }), "{err}");

    // Too-large outgoing message is refused locally.
    let err = client
        .call_tool("x", json!({"blob": "q".repeat(4096)}), None)
        .await
        .unwrap_err();
    assert!(matches!(err, McpError::MessageTooLarge { .. }), "{err}");

    // Still usable.
    let c = Arc::clone(&client);
    let ping = tokio::spawn(async move { c.ping().await });
    let p = peer.recv_method("ping").await;
    peer.respond(&p, json!({})).await;
    ping.await.unwrap().unwrap();
}

#[tokio::test]
async fn version_negotiation_accepts_older_supported_version() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    let req = peer.recv_method("initialize").await;
    peer.respond(&req, json!({"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name":"old","version":"1"}})).await;
    let r = init.await.unwrap().unwrap();
    assert_eq!(r.protocol_version, "2024-11-05");
    assert_eq!(client.protocol_version(), Some("2024-11-05"));
}

#[tokio::test]
async fn version_negotiation_rejects_unknown_version() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    let req = peer.recv_method("initialize").await;
    peer.respond(&req, json!({"protocolVersion": "2099-01-01", "capabilities": {}, "serverInfo": {"name":"new","version":"1"}})).await;
    let err = init.await.unwrap().unwrap_err();
    assert!(
        matches!(err, McpError::UnsupportedVersion { ref version, .. } if version == "2099-01-01"),
        "{err}"
    );
    assert!(client.initialize_result().is_none());
    assert!(matches!(
        client.list_tools().await,
        Err(McpError::NotInitialized { .. })
    ));
}

#[tokio::test]
async fn version_negotiation_retries_with_supported_version_from_error() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    let req = peer.recv_method("initialize").await;
    peer.send(json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32602,"message":"Unsupported protocol version",
        "data":{"supported":["2025-03-26"],"requested":LATEST_PROTOCOL_VERSION}}})).await;
    let retry = peer.recv_method("initialize").await;
    assert_eq!(retry["params"]["protocolVersion"], json!("2025-03-26"));
    assert_ne!(retry["id"], req["id"]);
    peer.respond(&retry, json!({"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"name":"x","version":"1"}})).await;
    assert_eq!(init.await.unwrap().unwrap().protocol_version, "2025-03-26");
}

#[tokio::test]
async fn initialize_error_without_alternative_fails() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    let req = peer.recv_method("initialize").await;
    peer.send(json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32603,"message":"boom"}}))
        .await;
    let err = init.await.unwrap().unwrap_err();
    assert_eq!(err.rpc_code(), Some(-32603));
    assert!(err.to_string().contains("boom"));
}

#[tokio::test]
async fn initialize_timeout() {
    let opts = ClientOptions {
        init_timeout: Duration::from_millis(150),
        ..fast_options()
    };
    let (client, mut peer) = fake_pair(opts).await;
    let err = client.initialize().await.unwrap_err();
    assert!(err.is_timeout());
    // No cancellation is sent for initialize.
    let first = peer.recv().await;
    assert_eq!(first["method"], json!("initialize"));
    assert!(peer.try_recv(Duration::from_millis(100)).await.is_none());
}

#[tokio::test]
async fn requires_initialization_and_object_args() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    assert!(matches!(
        client.call_tool("x", json!({}), None).await,
        Err(McpError::NotInitialized { .. })
    ));
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();
    for bad in [json!([1]), json!("s"), json!(3)] {
        assert!(matches!(
            client.call_tool("x", bad, None).await,
            Err(McpError::InvalidArgument(_))
        ));
    }
    // null args become {}.
    let c = Arc::clone(&client);
    let call = tokio::spawn(async move { c.call_tool("x", Value::Null, None).await });
    let req = peer.recv_method("tools/call").await;
    assert_eq!(req["params"]["arguments"], json!({}));
    peer.respond(
        &req,
        json!({"content": [{"type":"text","text":"ok"}], "isError": false}),
    )
    .await;
    let r = call.await.unwrap().unwrap();
    assert_eq!(r.render_text(), "ok");
    // Non-object result is a protocol error.
    let c = Arc::clone(&client);
    let call = tokio::spawn(async move { c.call_tool("x", json!({}), None).await });
    let req = peer.recv_method("tools/call").await;
    peer.respond(&req, json!("nope")).await;
    assert!(matches!(
        call.await.unwrap(),
        Err(McpError::Protocol { .. })
    ));
    // Rpc errors carry code and message.
    let c = Arc::clone(&client);
    let call = tokio::spawn(async move { c.call_tool("missing", json!({}), None).await });
    let req = peer.recv_method("tools/call").await;
    peer.send(json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32602,"message":"Unknown tool: missing"}})).await;
    let err = call.await.unwrap().unwrap_err();
    assert_eq!(err.rpc_code(), Some(-32602));
}

#[tokio::test]
async fn concurrent_requests_are_matched_by_id() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();

    let mut calls = Vec::new();
    for i in 0..5 {
        let c = Arc::clone(&client);
        calls.push(tokio::spawn(async move {
            c.call_tool("t", json!({"i": i}), None).await
        }));
    }
    let mut reqs = Vec::new();
    for _ in 0..5 {
        reqs.push(peer.recv_method("tools/call").await);
    }
    // Answer in reverse order.
    for req in reqs.iter().rev() {
        let i = req["params"]["arguments"]["i"].clone();
        peer.respond(
            req,
            json!({"content": [{"type":"text","text": i.to_string()}]}),
        )
        .await;
    }
    for (i, call) in calls.into_iter().enumerate() {
        assert_eq!(call.await.unwrap().unwrap().render_text(), i.to_string());
    }
}

#[tokio::test]
async fn shutdown_closes_transport_and_fails_pending() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    let c = Arc::clone(&client);
    let init = tokio::spawn(async move { c.initialize().await });
    peer.handshake().await;
    init.await.unwrap().unwrap();
    let c = Arc::clone(&client);
    let call = tokio::spawn(async move { c.call_tool("t", json!({}), None).await });
    let _ = peer.recv_method("tools/call").await;
    client.shutdown().await;
    let err = call.await.unwrap().unwrap_err();
    assert!(err.is_closed());
    assert_eq!(client.closed_reason().as_deref(), Some("client shut down"));
    // The peer sees EOF.
    assert!(peer.expect_eof(Duration::from_secs(2)).await);
    client.shutdown().await; // idempotent
}

#[tokio::test]
async fn dropping_client_closes_transport() {
    let (client, mut peer) = fake_pair(fast_options()).await;
    drop(client);
    assert!(peer.expect_eof(Duration::from_secs(2)).await);
}
