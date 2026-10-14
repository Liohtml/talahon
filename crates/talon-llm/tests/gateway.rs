//! `LlmGateway` with wiremock as the upstream vLLM.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use talon_core::audit::MemoryAuditSink;
use talon_core::tool::ToolSpec;
use talon_core::types::VllmConfig;
use talon_llm::gateway::{GatewayConfig, GatewayHandle, LlmGateway, TOKEN_PREFIX};
use talon_llm::types::{ChatMessage, FinishReason};
use talon_llm::{ClientConfig, LlmError, VllmClient};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UPSTREAM_KEY: &str = "sk-upstream-secret";

async fn start(
    server: &MockServer,
    tweak: impl FnOnce(&mut GatewayConfig),
) -> (GatewayHandle, MemoryAuditSink) {
    let mut cfg = GatewayConfig::new(server.uri(), "qwen").allow_model("qwen-small");
    cfg.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    cfg.upstream_api_key = Some(UPSTREAM_KEY.into());
    cfg.max_output_tokens_cap = Some(2048);
    tweak(&mut cfg);
    let audit = MemoryAuditSink::default();
    let handle = LlmGateway::start(cfg, Arc::new(audit.clone()))
        .await
        .unwrap();
    (handle, audit)
}

fn url(handle: &GatewayHandle, p: &str) -> String {
    format!("http://{}{p}", handle.addr())
}

async fn mount_completion(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header(
            "authorization",
            format!("Bearer {UPSTREAM_KEY}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion("pong")))
        .mount(server)
        .await;
}

async fn last_upstream_body(server: &MockServer) -> Value {
    server
        .received_requests()
        .await
        .unwrap()
        .last()
        .unwrap()
        .body_json()
        .unwrap()
}

#[tokio::test]
async fn missing_invalid_expired_and_revoked_tokens_are_refused_and_audited() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, audit) = start(&server, |_| {}).await;
    let http = http();
    let body = json!({"model": "qwen", "messages": [{"role": "user", "content": "x"}]});

    let r = http
        .post(url(&gw, "/v1/chat/completions"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Bearer");
    let err: Value = r.json().await.unwrap();
    assert_eq!(err["error"]["type"], "authentication_error");

    let r = http
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(format!("{TOKEN_PREFIX}{}", "0".repeat(64)))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    let expired = gw.issue_token("grp-expired", Duration::ZERO);
    let r = http
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&expired)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    let token = gw.issue_token("grp", Duration::from_secs(60));
    assert!(gw.revoke(&token));
    let r = http
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Nothing reached the upstream.
    assert!(server.received_requests().await.unwrap().is_empty());
    let events = audit.snapshot();
    let failures: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "gateway.auth.failed")
        .collect();
    assert_eq!(failures.len(), 4);
    assert!(failures.iter().all(|e| e.outcome == "denied"));
    assert_eq!(failures[0].details["reason"], "missing_token");
    assert_eq!(failures[1].details["reason"], "invalid_token");
    assert_eq!(failures[2].details["reason"], "expired_token");
    assert_eq!(failures[2].details["label"], "grp-expired");
    assert_eq!(failures[0].target.as_deref(), Some("/v1/chat/completions"));
    // Tokens never end up in the audit trail.
    let dump = serde_json::to_string(&events).unwrap();
    assert!(!dump.contains(&token) && !dump.contains(&expired));
    assert_eq!(gw.stats().auth_failures, 4);
}

#[tokio::test]
async fn forwards_with_upstream_key_pins_model_and_clamps() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("main", Duration::from_secs(60));
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .header("cookie", "session=abc")
        .header("x-forwarded-for", "10.0.0.1")
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 999999,
            "chat_template": "{% raw %}evil{% endraw %}",
            "n": 4,
            "temperature": 0.1
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let resp: Value = r.json().await.unwrap();
    assert_eq!(resp["choices"][0]["message"]["content"], "pong");

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];
    assert_eq!(
        req.headers.get("authorization").unwrap().to_str().unwrap(),
        format!("Bearer {UPSTREAM_KEY}")
    );
    assert!(
        req.headers.get("cookie").is_none(),
        "client headers must not be forwarded"
    );
    assert!(req.headers.get("x-forwarded-for").is_none());
    let sent: Value = req.body_json().unwrap();
    assert_eq!(sent["model"], "qwen", "unknown model pinned to default");
    assert_eq!(sent["max_tokens"], 2048, "max_tokens clamped");
    assert_eq!(sent["n"], 1);
    assert!(sent.get("chat_template").is_none());
    assert_eq!(sent["temperature"], json!(0.1));

    // Allowed models pass; missing max_tokens is inserted.
    http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&json!({"model": "qwen-small", "messages": []}))
        .send()
        .await
        .unwrap();
    let sent = last_upstream_body(&server).await;
    assert_eq!(sent["model"], "qwen-small");
    assert_eq!(sent["max_tokens"], 2048);

    let stats = gw.stats();
    assert_eq!(stats.requests, 2);
    assert_eq!(stats.active_tokens, 1);
    let main = &stats.labels["main"];
    assert_eq!(main.completions, 2);
    assert_eq!(main.prompt_tokens, 240);
    assert_eq!(main.cached_tokens, 192);
}

#[tokio::test]
async fn per_token_rate_limit() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, audit) = start(&server, |c| c.requests_per_minute = 2).await;
    let a = gw.issue_token("a", Duration::from_secs(60));
    let b = gw.issue_token("b", Duration::from_secs(60));
    let body = json!({"messages": []});
    let send = |t: String| {
        let body = body.clone();
        let u = url(&gw, "/v1/chat/completions");
        async move {
            http()
                .post(u)
                .bearer_auth(t)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };
    assert_eq!(send(a.clone()).await.status(), 200);
    assert_eq!(send(a.clone()).await.status(), 200);
    let limited = send(a.clone()).await;
    assert_eq!(limited.status(), 429);
    let retry_after: u64 = limited.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=30).contains(&retry_after), "{retry_after}");
    // Separate budget per token.
    assert_eq!(send(b).await.status(), 200);

    let stats = gw.stats();
    assert_eq!(stats.rate_limited, 1);
    assert_eq!(stats.labels["a"].rate_limited, 1);
    assert!(audit.snapshot().iter().any(|e| e.kind == "gateway.request"
        && e.details["reason"] == "rate_limited"
        && e.actor == "a"));
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn per_token_concurrency_cap() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(completion("slow"))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
    let (gw, audit) = start(&server, |c| c.max_concurrent_per_token = 1).await;
    let token = gw.issue_token("busy", Duration::from_secs(60));
    let send = || {
        let u = url(&gw, "/v1/chat/completions");
        let t = token.clone();
        async move {
            http()
                .post(u)
                .bearer_auth(t)
                .json(&json!({"messages": []}))
                .send()
                .await
                .unwrap()
        }
    };
    let (a, b) = tokio::join!(send(), send());
    let mut statuses = vec![a.status().as_u16(), b.status().as_u16()];
    statuses.sort_unstable();
    assert_eq!(statuses, vec![200, 429]);
    let limited = if a.status() == 429 { &a } else { &b };
    assert_eq!(limited.headers()["retry-after"], "1");
    // The slot is released once the first request finished.
    assert_eq!(send().await.status(), 200);
    assert!(
        audit
            .snapshot()
            .iter()
            .any(|e| e.details["reason"] == "too_many_concurrent")
    );
}

#[tokio::test]
async fn body_limit_and_bad_json_are_rejected_before_upstream() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, audit) = start(&server, |c| c.max_body_bytes = 1024).await;
    let token = gw.issue_token("t", Duration::from_secs(60));
    let big = json!({"messages": [{"role": "user", "content": "x".repeat(4096)}]});
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&big)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);

    // Chunked body without Content-Length is limited too.
    let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = vec![
        Ok(bytes::Bytes::from(vec![b' '; 800])),
        Ok(bytes::Bytes::from(vec![b' '; 800])),
    ];
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);

    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&json!({"messages": [], "max_tokens": "all"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(gw.stats().rejected, 4);
    let reasons: Vec<Value> = audit
        .snapshot()
        .iter()
        .filter(|e| e.kind == "gateway.request")
        .map(|e| e.details["reason"].clone())
        .collect();
    assert!(reasons.contains(&json!("body_too_large")));
    assert!(reasons.contains(&json!("invalid_json")));
}

#[tokio::test]
async fn sse_is_passed_through_and_usage_counted() {
    let server = MockServer::start().await;
    let stream_body = tool_call_stream();
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(stream_body.clone(), "text/event-stream"),
        )
        .mount(&server)
        .await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("stream-lane", Duration::from_secs(60));
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&json!({"messages": [], "stream": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    assert_eq!(r.headers()["cache-control"], "no-cache");
    let text = r.text().await.unwrap();
    assert_eq!(text, stream_body, "SSE bytes are passed through unchanged");

    let sent = last_upstream_body(&server).await;
    assert_eq!(sent["stream_options"]["include_usage"], true);

    eventually(|| {
        gw.stats()
            .labels
            .get("stream-lane")
            .is_some_and(|l| l.streamed == 1)
    })
    .await;
    let l = gw.stats().labels["stream-lane"].clone();
    assert_eq!(l.prompt_tokens, 200);
    assert_eq!(l.completion_tokens, 30);
    assert_eq!(l.cached_tokens, 150);
    assert_eq!(l.errors, 0);
}

#[tokio::test]
async fn models_are_filtered_and_tokenize_is_forwarded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", format!("Bearer {UPSTREAM_KEY}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "qwen", "max_model_len": 32768}, {"id": "internal-finetune"}, {"id": "qwen-small"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tokenize"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"count": 5, "max_model_len": 32768})),
        )
        .mount(&server)
        .await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("t", Duration::from_secs(60));

    let models: Value = http()
        .get(url(&gw, "/v1/models"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = models["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["qwen", "qwen-small"]);

    let r = http()
        .post(url(&gw, "/tokenize"))
        .bearer_auth(&token)
        .json(&json!({"model": "other", "prompt": "hello", "chat_template": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<Value>().await.unwrap()["count"], 5);
    let sent = last_upstream_body(&server).await;
    assert_eq!(sent["model"], "qwen");
    assert!(sent.get("chat_template").is_none());
}

#[tokio::test]
async fn unknown_routes_404_and_wrong_methods_405() {
    let server = MockServer::start().await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("t", Duration::from_secs(60));
    for p in [
        "/v1/completions",
        "/v1/embeddings",
        "/health",
        "/metrics",
        "/v1/chat/completions/x",
    ] {
        let r = http()
            .post(url(&gw, p))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{p}");
    }
    let r = http()
        .get(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn upstream_failures_map_to_502_and_errors_pass_through() {
    // Upstream rejects the gateway's key: the container must not see a 401
    // (it would think its own token is bad).
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string("bad key"))
        .mount(&server)
        .await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("t", Duration::from_secs(60));
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&json!({"messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 502);

    // Upstream 400 (e.g. context length) is passed through with its body.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "object": "error", "message": "This model's maximum context length is 8192 tokens.", "code": 400
        })))
        .mount(&server)
        .await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("t", Duration::from_secs(60));
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&json!({"messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("maximum context length"));
    assert_eq!(gw.stats().labels["t"].errors, 1);

    // Upstream down.
    let port = closed_port().await;
    let mut cfg = GatewayConfig::new(format!("http://127.0.0.1:{port}"), "qwen");
    cfg.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    let gw = LlmGateway::start(cfg, Arc::new(MemoryAuditSink::default()))
        .await
        .unwrap();
    let token = gw.issue_token("t", Duration::from_secs(60));
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&json!({"messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 502);
    assert_eq!(gw.stats().upstream_errors, 1);
}

#[tokio::test]
async fn upstream_timeout_maps_to_504() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(completion("late"))
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    let (gw, _audit) = start(&server, |c| c.request_timeout = Duration::from_millis(200)).await;
    let token = gw.issue_token("t", Duration::from_secs(60));
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&json!({"messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 504);
}

#[tokio::test]
async fn audit_requests_records_usage() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, audit) = start(&server, |c| c.audit_requests = true).await;
    let token = gw.issue_token("investigate", Duration::from_secs(60));
    http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .json(&json!({"messages": []}))
        .send()
        .await
        .unwrap();
    let events = audit.snapshot();
    let ev = events
        .iter()
        .find(|e| e.kind == "gateway.request" && e.outcome == "allowed")
        .expect("request audited");
    assert_eq!(ev.actor, "investigate");
    assert_eq!(ev.details["model"], "qwen");
    assert_eq!(ev.details["prompt_tokens"], 120);
    assert_eq!(ev.details["cached_tokens"], 96);
}

#[tokio::test]
async fn end_to_end_vllm_client_through_gateway() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(wiremock::matchers::body_partial_json(
            json!({"stream": true}),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(tool_call_stream(), "text/event-stream"),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(completion("<think>hm</think>final")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tokenize"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"count": 77, "max_model_len": 32768})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [{"id": "qwen"}]})))
        .mount(&server)
        .await;

    let (gw, _audit) = start(&server, |_| {}).await;
    let vllm = VllmConfig {
        base_url: server.uri(),
        model: "qwen".into(),
        fast_model: Some("qwen-small".into()),
        max_context_tokens: Some(32768),
        max_output_tokens: Some(4096),
        temperature: Some(0.3),
        top_p: None,
        enable_thinking: Some(false),
        request_timeout_secs: Some(60),
    };
    let token = gw.issue_token("main", Duration::from_secs(60));
    let ep = gw.endpoint(token.clone(), "127.0.0.1", &vllm);
    assert_eq!(ep.base_url, format!("http://127.0.0.1:{}/v1", gw.port()));
    assert_eq!(ep.max_output_tokens, Some(2048), "capped by the gateway");
    assert!(ep.token.starts_with(TOKEN_PREFIX));

    // What the container does with the endpoint from ContainerInput.llm:
    let client = VllmClient::from_endpoint(&ep).unwrap();
    let tool = ToolSpec {
        name: "get_weather".into(),
        description: "w".into(),
        parameters: json!({"type": "object"}),
    };
    let req = client.request(vec![ChatMessage::user("w")]).tools([&tool]);
    let resp = client
        .chat_stream(&req)
        .await
        .unwrap()
        .into_response()
        .await
        .unwrap();
    assert_eq!(resp.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(resp.message.tool_calls[0].name(), "get_weather");
    assert_eq!(resp.usage.cached_tokens, 150);

    let resp = client
        .chat(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap();
    assert_eq!(resp.message.text(), "final");
    assert_eq!(resp.message.reasoning_content.as_deref(), Some("hm"));

    let n = client.tokenize("anything").await;
    assert_eq!(n.count, 77);
    assert!(!n.estimated);
    assert_eq!(client.list_models().await.unwrap()[0].id, "qwen");
    // `/health` is not routed by the gateway; health() falls back to /v1/models.
    client.health().await.unwrap();

    // The upstream saw the real key and the defaults from the endpoint.
    let received = server.received_requests().await.unwrap();
    assert!(received.iter().all(|r| {
        r.headers
            .get("authorization")
            .is_some_and(|v| v.to_str().unwrap() == format!("Bearer {UPSTREAM_KEY}"))
    }));
    let chat: Value = received[0].body_json().unwrap();
    assert_eq!(chat["chat_template_kwargs"]["enable_thinking"], false);
    assert_eq!(chat["max_tokens"], 2048);

    // After revocation the container is locked out.
    assert!(gw.revoke(&token));
    let err = client.list_models().await.unwrap_err();
    assert!(
        matches!(err, LlmError::Unauthorized { status: 401, .. }),
        "{err:?}"
    );

    // The streamed completion is accounted when the passthrough body is dropped.
    eventually(|| {
        gw.stats()
            .labels
            .get("main")
            .is_some_and(|m| m.completions == 2 && m.streamed == 1)
    })
    .await;
}

#[tokio::test]
async fn shutdown_stops_serving() {
    let server = MockServer::start().await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let addr = gw.addr();
    gw.shutdown().await;
    let mut cfg = ClientConfig::new(format!("http://{addr}"), "qwen");
    cfg.retry = fast_retry(0);
    let client = VllmClient::new(cfg).unwrap();
    let err = client.list_models().await.unwrap_err();
    assert!(matches!(err, LlmError::Connect(_)), "{err:?}");
}

#[tokio::test]
async fn bind_conflict_is_a_config_error() {
    let server = MockServer::start().await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let taken = gw.addr();
    let mut cfg = GatewayConfig::new(server.uri(), "qwen");
    cfg.bind = taken;
    let err = LlmGateway::start(cfg, Arc::new(MemoryAuditSink::default()))
        .await
        .unwrap_err();
    assert!(matches!(err, LlmError::Config(_)), "{err:?}");
    let mut bad = GatewayConfig::new("not a url", "qwen");
    bad.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    assert!(
        LlmGateway::start(bad, Arc::new(MemoryAuditSink::default()))
            .await
            .is_err()
    );
}
