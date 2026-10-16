use super::*;
use crate::config::CompiledConfig;
use crate::session::AnonSession;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, DuplexStream, Lines, ReadHalf, duplex};

fn router_with(opts: ProxyOptions) -> Router {
    let session =
        AnonSession::in_memory(Arc::new(CompiledConfig::builtin().unwrap())).into_shared();
    Router::new(session, opts)
}

fn router() -> Router {
    router_with(ProxyOptions::default())
}

fn line(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap()
}

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn call(id: i64, name: &str, args: Value) -> Vec<u8> {
    line(
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}}),
    )
}

fn text_result(id: i64, text: &str) -> Vec<u8> {
    line(
        json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": text}]}}),
    )
}

// ---------------------------------------------------------------------------
// Router (synchronous)
// ---------------------------------------------------------------------------

#[test]
fn tools_list_gets_deanonymize_appended_on_last_page_only() {
    let r = router();
    let out = r.handle_client_line(&line(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})));
    assert!(out.client.is_none());
    assert!(out.upstream.is_some());
    let resp = r
        .handle_upstream_line(&line(
            json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_documents"}]}}),
        ))
        .unwrap();
    let names: Vec<_> = parse(&resp)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["search_documents", "deanonymize"]);

    r.handle_client_line(&line(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})));
    let page = r
        .handle_upstream_line(&line(
            json!({"jsonrpc":"2.0","id":2,"result":{"tools":[],"nextCursor":"p2"}}),
        ))
        .unwrap();
    assert_eq!(parse(&page)["result"]["tools"], json!([]));

    r.handle_client_line(&line(json!({"jsonrpc":"2.0","id":3,"method":"tools/list"})));
    let dup = r
        .handle_upstream_line(&line(
            json!({"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"deanonymize"}]}}),
        ))
        .unwrap();
    assert_eq!(parse(&dup)["result"]["tools"].as_array().unwrap().len(), 1);
}

#[test]
fn tool_results_are_anonymized_and_deanonymize_is_local() {
    let r = router();
    let out = r.handle_client_line(&call(
        2,
        "get_document",
        json!({"index": "wazuh-*", "id": "x"}),
    ));
    assert!(out.upstream.is_some());
    let doc = json!({"agent_name": "WS-FIN-01", "data_srcip": "10.0.0.1", "data_dstip": "8.8.8.8"})
        .to_string();
    let resp = parse(&r.handle_upstream_line(&text_result(2, &doc)).unwrap());
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!text.contains("WS-FIN-01") && !text.contains("10.0.0.1"));
    assert!(text.contains("HOST_1") && text.contains("IP_INT_1") && text.contains("8.8.8.8"));

    let out = r.handle_client_line(&call(
        3,
        "deanonymize",
        json!({"text": "HOST_1 talked to IP_INT_1 (HOST_10)"}),
    ));
    assert!(
        out.upstream.is_none(),
        "deanonymize must never be forwarded"
    );
    let reply = parse(&out.client.unwrap());
    assert_eq!(reply["id"], 3);
    assert_eq!(
        reply["result"]["content"][0]["text"],
        "WS-FIN-01 talked to 10.0.0.1 (HOST_10)"
    );
    assert_eq!(r.pending_count(), 0);

    let bad = parse(
        &r.handle_client_line(&call(4, "deanonymize", json!({})))
            .client
            .unwrap(),
    );
    assert_eq!(bad["result"]["isError"], true);
}

#[test]
fn arguments_are_deanonymized_before_forwarding() {
    let r = router();
    r.handle_client_line(&call(1, "get", json!({})));
    r.handle_upstream_line(&text_result(1, &json!({"agent_name": "WS-9"}).to_string()));
    let out = r.handle_client_line(&call(
        2,
        "search",
        json!({"query": "agent.name:HOST_1", "body": "{\"q\":\"HOST_1\"}"}),
    ));
    let fwd = parse(&out.upstream.unwrap());
    assert_eq!(fwd["params"]["arguments"]["query"], "agent.name:WS-9");
    assert_eq!(fwd["params"]["arguments"]["body"], "{\"q\":\"WS-9\"}");
    // and the echo comes back tokenized
    let back = parse(
        &r.handle_upstream_line(&text_result(2, "found WS-9"))
            .unwrap(),
    );
    assert_eq!(back["result"]["content"][0]["text"], "found HOST_1");

    let raw = router_with(ProxyOptions {
        deanonymize_arguments: false,
        ..ProxyOptions::default()
    });
    raw.handle_client_line(&call(1, "get", json!({})));
    raw.handle_upstream_line(&text_result(1, &json!({"agent_name": "WS-9"}).to_string()));
    let fwd = parse(
        &raw.handle_client_line(&call(2, "search", json!({"query": "HOST_1"})))
            .upstream
            .unwrap(),
    );
    assert_eq!(fwd["params"]["arguments"]["query"], "HOST_1");
}

#[test]
fn unmodified_requests_are_forwarded_byte_identical() {
    let r = router();
    let original = br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"x","arguments":{"n":1.50}}}"#;
    let out = r.handle_client_line(original);
    let mut want = original.to_vec();
    want.push(b'\n');
    assert_eq!(out.upstream.unwrap(), want);
}

#[test]
fn invalid_client_input_gets_json_rpc_errors() {
    let r = router();
    let out = r.handle_client_line(b"this is not json");
    assert!(out.upstream.is_none());
    assert_eq!(parse(&out.client.unwrap())["error"]["code"], PARSE_ERROR);
    let out = r.handle_client_line(b"[]");
    assert_eq!(
        parse(&out.client.unwrap())["error"]["code"],
        INVALID_REQUEST
    );
    let out = r.handle_client_line(br#"{"jsonrpc":"2.0","id":5}"#);
    let e = parse(&out.client.unwrap());
    assert_eq!(
        (e["id"].clone(), e["error"]["code"].clone()),
        (json!(5), json!(INVALID_REQUEST))
    );
    assert_eq!(r.handle_client_line(b"   \r"), ClientOut::default());
    let out = r.handle_client_oversize(
        br#"{"jsonrpc":"2.0","id":"big-1","method":"tools/call","params":{"#,
        99_999_999,
    );
    let e = parse(&out.client.unwrap());
    assert_eq!(e["id"], "big-1");
    assert!(r.handle_client_oversize(b"xxxxxxxx", 10).client.is_none());
}

#[test]
fn batches_split_local_and_forwarded_parts() {
    let r = router();
    let batch = json!([
        {"jsonrpc":"2.0","id":1,"method":"tools/list"},
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"deanonymize","arguments":{"text":"x"}}},
        {"jsonrpc":"2.0","method":"notifications/initialized"}
    ]);
    let out = r.handle_client_line(&line(batch));
    assert_eq!(parse(&out.upstream.unwrap()).as_array().unwrap().len(), 2);
    assert_eq!(parse(&out.client.unwrap())[0]["id"], 2);
    let resp = r
        .handle_upstream_line(&line(
            json!([{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}]),
        ))
        .unwrap();
    assert_eq!(parse(&resp)[0]["result"]["tools"][0]["name"], "deanonymize");
}

#[test]
fn upstream_errors_unknown_ids_and_notifications_are_anonymized() {
    let r = router();
    r.handle_client_line(&call(1, "get", json!({})));
    let err = r
        .handle_upstream_line(&line(json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no data for CORP\\jsmith at 10.0.0.9","data":{"host":"10.0.0.9"}}})))
        .unwrap();
    let e = parse(&err);
    assert_eq!(
        e["error"]["message"],
        "no data for DOMAIN_INT_1\\USER_1 at IP_INT_1"
    );
    assert_eq!(e["error"]["data"]["host"], "IP_INT_1");

    let unknown = parse(
        &r.handle_upstream_line(&line(
            json!({"jsonrpc":"2.0","id":77,"result":{"x":"from 10.0.0.7"}}),
        ))
        .unwrap(),
    );
    assert_eq!(unknown["result"]["x"], "from IP_INT_2");

    let note = parse(
        &r.handle_upstream_line(&line(json!({"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"query by alice@corp.com"}})))
            .unwrap(),
    );
    assert_eq!(note["params"]["data"], "query by EMAIL_1");
}

#[test]
fn passthrough_methods_keep_bytes_and_garbage_is_dropped() {
    let r = router();
    r.handle_client_line(&line(
        json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}),
    ));
    let raw = br#"{"jsonrpc":"2.0","id":0,"result":{"serverInfo":{"name":"x","note":"10.0.0.1"},"protocolVersion":"2025-06-18"}}"#;
    let mut want = raw.to_vec();
    want.push(b'\n');
    assert_eq!(r.handle_upstream_line(raw).unwrap(), want);

    assert!(
        r.handle_upstream_line(b"DEBUG: connecting to 10.0.0.1 as jdoe")
            .is_none()
    );
    assert!(r.handle_upstream_line(br#"{"no":"id"}"#).is_none());

    r.handle_client_line(&call(7, "get", json!({})));
    let e = parse(
        &r.handle_upstream_line(br#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"te"#)
            .unwrap(),
    );
    assert_eq!(
        (e["id"].clone(), e["error"]["code"].clone()),
        (json!(7), json!(INTERNAL_ERROR))
    );
    assert_eq!(r.pending_count(), 0);

    r.handle_client_line(&call(8, "get", json!({})));
    let e = parse(
        &r.handle_upstream_oversize(br#"{"jsonrpc":"2.0","id":8,"result":{"#, 1 << 30)
            .unwrap(),
    );
    assert_eq!(e["error"]["code"], RESPONSE_TOO_LARGE);
    assert!(
        r.handle_upstream_oversize(br#"{"jsonrpc":"2.0","id":8,"#, 1 << 30)
            .is_none(),
        "not pending any more"
    );
}

#[test]
fn cancellation_pending_limits_and_draining() {
    let r = router_with(ProxyOptions {
        max_pending: 2,
        ..ProxyOptions::default()
    });
    r.handle_client_line(&call(1, "a", json!({})));
    r.handle_client_line(&call(2, "b", json!({})));
    let rejected = r.handle_client_line(&call(3, "c", json!({})));
    assert!(rejected.upstream.is_none());
    assert_eq!(
        parse(&rejected.client.unwrap())["error"]["code"],
        TOO_MANY_PENDING
    );
    r.handle_client_line(&line(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}),
    ));
    assert_eq!(r.pending_count(), 1);
    let drained = r.drain_pending("bye");
    assert_eq!(drained.len(), 1);
    let e = parse(&drained[0]);
    assert_eq!(
        (e["id"].clone(), e["error"]["code"].clone()),
        (json!(2), json!(UPSTREAM_EXITED))
    );
    assert_eq!(r.pending_count(), 0);
}

#[test]
fn a_reused_request_id_cannot_unmask_a_tool_result() {
    let r = router();
    let first = r.handle_client_line(&call(1, "search", json!({})));
    assert!(first.upstream.is_some());
    // Same id again, as a passthrough method: rejected, not forwarded.
    let reused = r.handle_client_line(&line(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})));
    assert!(reused.upstream.is_none());
    let e = parse(&reused.client.unwrap());
    assert_eq!(
        (e["id"].clone(), e["error"]["code"].clone()),
        (json!(1), json!(INVALID_REQUEST))
    );
    assert_eq!(r.pending_count(), 1);
    // The tool result is still anonymized as a `tools/call` response.
    let doc = json!({"agent_name": "WS-FIN-01", "data_srcip": "10.0.0.1"}).to_string();
    let resp = parse(&r.handle_upstream_line(&text_result(1, &doc)).unwrap());
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        !text.contains("WS-FIN-01") && !text.contains("10.0.0.1"),
        "{text}"
    );
}

#[test]
fn aggregation_hints_flow_from_request_to_response() {
    let r = router();
    let args = json!({"index": "wazuh-*", "body": {"aggs": {"by_host": {"terms": {"field": "agent.name"}}}}});
    r.handle_client_line(&call(1, "search", args));
    let body =
        json!({"aggregations": {"by_host": {"buckets": [{"key": "WS-77", "doc_count": 2}]}}})
            .to_string();
    let resp = parse(
        &r.handle_upstream_line(&text_result(1, &format!("Search results: {body}")))
            .unwrap(),
    );
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("Search results: "));
    assert!(text.contains("\"key\":\"HOST_1\""), "{text}");
}

// ---------------------------------------------------------------------------
// LineReader
// ---------------------------------------------------------------------------

#[tokio::test]
async fn line_reader_partial_crlf_oversize_and_trailing_line() {
    let (mut w, r) = duplex(64);
    let writer = tokio::spawn(async move {
        for chunk in [
            &b"ab"[..],
            b"c\r\nde",
            b"f\n",
            &[b'x'; 300],
            b"\nok\n",
            b"tail",
        ] {
            w.write_all(chunk).await.unwrap();
        }
    });
    let mut lr = LineReader::new(r, 100);
    assert_eq!(
        lr.next_line().await.unwrap(),
        Some(Line::Complete(b"abc".to_vec()))
    );
    assert_eq!(
        lr.next_line().await.unwrap(),
        Some(Line::Complete(b"def".to_vec()))
    );
    match lr.next_line().await.unwrap() {
        Some(Line::Oversize { head, len }) => {
            assert_eq!(len, 300);
            assert!(head.len() <= HEAD_KEEP && head.iter().all(|&b| b == b'x'));
        }
        other => panic!("expected oversize, got {other:?}"),
    }
    assert_eq!(
        lr.next_line().await.unwrap(),
        Some(Line::Complete(b"ok".to_vec()))
    );
    writer.await.unwrap();
    assert_eq!(
        lr.next_line().await.unwrap(),
        Some(Line::Complete(b"tail".to_vec()))
    );
    assert_eq!(lr.next_line().await.unwrap(), None);
}

// ---------------------------------------------------------------------------
// run_proxy with an in-process fake upstream
// ---------------------------------------------------------------------------

type ClientLines = Lines<BufReader<ReadHalf<DuplexStream>>>;

async fn recv(lines: &mut ClientLines) -> Value {
    let l = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("timed out waiting for the proxy")
        .unwrap()
        .expect("proxy closed its output");
    serde_json::from_str(&l).unwrap()
}

async fn send(w: &mut tokio::io::WriteHalf<DuplexStream>, v: Value) {
    let mut b = serde_json::to_vec(&v).unwrap();
    b.push(b'\n');
    w.write_all(&b).await.unwrap();
}

/// Fake MCP server: `get` returns PII, `slow` is answered only after stdin
/// closes, `crash` exits immediately, `noise` prints garbage first.
async fn fake_upstream(stream: DuplexStream, seen: Arc<Mutex<Vec<Value>>>) {
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();
    let mut held = Vec::new();
    while let Ok(Some(l)) = lines.next_line().await {
        let v: Value = serde_json::from_str(&l).unwrap();
        seen.lock().unwrap().push(v.clone());
        let id = v["id"].clone();
        let reply = match (v["method"].as_str(), v["params"]["name"].as_str()) {
            (Some("tools/list"), _) => {
                Some(json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"get"}]}}))
            }
            (Some("tools/call"), Some("get")) => Some(json!({"jsonrpc":"2.0","id":id,"result":{
                "content":[{"type":"text","text": json!({"agent_name":"WS-9","full_log":"login by WS-9 from 10.2.3.4"}).to_string()}],
                "structuredContent":{"agent_name":"WS-9"}}})),
            (Some("tools/call"), Some("noise")) => {
                w.write_all(b"warning: something on stdout from 10.2.3.4\n")
                    .await
                    .unwrap();
                Some(json!({"jsonrpc":"2.0","id":id,"result":{"content":[]}}))
            }
            (Some("tools/call"), Some("slow")) => {
                held.push(id);
                None
            }
            (Some("tools/call"), Some("crash")) => return,
            _ => None,
        };
        if let Some(reply) = reply {
            let mut b = serde_json::to_vec(&reply).unwrap();
            b.push(b'\n');
            w.write_all(&b).await.unwrap();
        }
    }
    for id in held {
        let mut b = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"late answer for 10.2.3.4"}]}})).unwrap();
        b.push(b'\n');
        w.write_all(&b).await.unwrap();
    }
}

struct Harness {
    lines: ClientLines,
    input: tokio::io::WriteHalf<DuplexStream>,
    seen: Arc<Mutex<Vec<Value>>>,
    proxy: JoinHandle<ProxyOutcome>,
    cancel: CancellationToken,
}

fn harness() -> Harness {
    let session =
        AnonSession::in_memory(Arc::new(CompiledConfig::builtin().unwrap())).into_shared();
    let (test_side, proxy_client) = duplex(1 << 20);
    let (proxy_up, fake_side) = duplex(1 << 20);
    let (pc_r, pc_w) = tokio::io::split(proxy_client);
    let (pu_r, pu_w) = tokio::io::split(proxy_up);
    let seen = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(fake_upstream(fake_side, Arc::clone(&seen)));
    let cancel = CancellationToken::new();
    let opts = ProxyOptions {
        shutdown_grace: Duration::from_secs(3),
        ..ProxyOptions::default()
    };
    let proxy = tokio::spawn(run_proxy(
        session,
        opts,
        pc_r,
        pc_w,
        pu_w,
        pu_r,
        cancel.clone(),
    ));
    let (tr, tw) = tokio::io::split(test_side);
    Harness {
        lines: BufReader::new(tr).lines(),
        input: tw,
        seen,
        proxy,
        cancel,
    }
}

#[tokio::test]
async fn proxy_round_trip_and_client_close() {
    let mut h = harness();
    send(
        &mut h.input,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    let list = recv(&mut h.lines).await;
    assert_eq!(list["result"]["tools"][1]["name"], "deanonymize");

    send(&mut h.input, json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"noise","arguments":{}}})).await;
    let r = recv(&mut h.lines).await;
    assert_eq!(
        r["id"], 2,
        "stray upstream output was dropped, not forwarded"
    );

    send(&mut h.input, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get","arguments":{}}})).await;
    let r = recv(&mut h.lines).await;
    let s = r.to_string();
    assert!(!s.contains("WS-9") && !s.contains("10.2.3.4"), "{s}");
    assert_eq!(r["result"]["structuredContent"]["agent_name"], "HOST_1");

    send(&mut h.input, json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get","arguments":{"q":"HOST_1"}}})).await;
    recv(&mut h.lines).await;
    assert_eq!(
        h.seen.lock().unwrap().last().unwrap()["params"]["arguments"]["q"],
        "WS-9"
    );

    send(&mut h.input, json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"slow","arguments":{}}})).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    h.input.shutdown().await.unwrap();
    let late = recv(&mut h.lines).await;
    assert_eq!(late["id"], 5);
    assert_eq!(
        late["result"]["content"][0]["text"],
        "late answer for IP_INT_1"
    );
    let outcome = tokio::time::timeout(Duration::from_secs(10), h.proxy)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome, ProxyOutcome::ClientClosed);
    assert!(h.lines.next_line().await.unwrap().is_none());
}

#[tokio::test]
async fn upstream_crash_fails_pending_requests() {
    let mut h = harness();
    send(&mut h.input, json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"slow","arguments":{}}})).await;
    send(&mut h.input, json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"crash","arguments":{}}})).await;
    let mut ids = vec![];
    for _ in 0..2 {
        let e = recv(&mut h.lines).await;
        assert_eq!(e["error"]["code"], UPSTREAM_EXITED);
        ids.push(e["id"].as_i64().unwrap());
    }
    ids.sort_unstable();
    assert_eq!(ids, [10, 11]);
    let outcome = tokio::time::timeout(Duration::from_secs(10), h.proxy)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome, ProxyOutcome::UpstreamClosed);
}

#[tokio::test]
async fn cancellation_shuts_down_and_answers_pending() {
    let mut h = harness();
    send(&mut h.input, json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"slow","arguments":{}}})).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    h.cancel.cancel();
    // the fake upstream answers held requests when its stdin closes
    let r = recv(&mut h.lines).await;
    assert_eq!(r["id"], 20);
    let outcome = tokio::time::timeout(Duration::from_secs(10), h.proxy)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome, ProxyOutcome::Cancelled);
}
