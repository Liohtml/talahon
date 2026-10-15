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

// ---------------------------------------------------------------------------
// Mythos hardening: MYTH-06 (talon-net serving), MYTH-07 (memory/concurrency
// bounds), MYTH-08 (parameter allowlist, cache_salt).
// ---------------------------------------------------------------------------

async fn post_chat(gw: &GatewayHandle, token: &str, body: &Value) -> reqwest::Response {
    http()
        .post(url(gw, "/v1/chat/completions"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap()
}

fn sorted_keys(v: &Value) -> Vec<String> {
    let mut keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

#[tokio::test]
async fn allowlist_drops_vllm_extensions_and_keeps_allowed_fields() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("lane", Duration::from_secs(60));
    let tools = json!([{"type": "function", "function": {
        "name": "get_weather", "description": "w",
        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
    }}]);
    let response_format = json!({"type": "json_schema", "json_schema": {
        "name": "verdict", "strict": true, "schema": {"type": "object"}
    }});
    let mut body = json!({
        "model": "qwen",
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": [
                {"type": "text", "text": "hi", "image_url": {"url": "http://169.254.169.254/latest/meta-data/"}}
            ]}
        ],
        "tools": tools,
        "tool_choice": "auto",
        "parallel_tool_calls": true,
        "temperature": 0.2, "top_p": 0.9, "top_k": 20, "min_p": 0.05,
        "presence_penalty": 0.1, "frequency_penalty": 0.2, "repetition_penalty": 1.05,
        "seed": 7, "stop": ["END"], "max_completion_tokens": 100,
        "response_format": response_format,
        "chat_template_kwargs": {
            "enable_thinking": false,
            "chat_template": "{% for i in range(999999999) %}x{% endfor %}",
            "tokenize": true
        }
    });
    let blocked = [
        ("chat_template", json!("{{ evil }}")),
        ("guided_regex", json!("(a|aa)+$")),
        ("guided_grammar", json!("root ::= \"a\"*")),
        ("guided_json", json!({"type": "object"})),
        ("guided_choice", json!(["a"])),
        ("structured_outputs", json!({"grammar": "root ::= \"a\"*"})),
        ("ignore_eos", json!(true)),
        ("min_tokens", json!(16000)),
        ("request_id", json!("other-lanes-request")),
        ("logits_processors", json!(["os.system"])),
        ("priority", json!(-1000)),
        ("best_of", json!(16)),
        ("use_beam_search", json!(true)),
        ("prompt_logprobs", json!(20)),
        ("logprobs", json!(true)),
        ("top_logprobs", json!(20)),
        ("user", json!("analyst\nforged log line")),
        ("mm_processor_kwargs", json!({"num_crops": 100})),
        ("documents", json!([{"title": "x", "text": "y"}])),
        ("vllm_xargs", json!({"k": 1})),
        ("kv_transfer_params", json!({"do_remote_decode": true})),
        ("continue_final_message", json!(true)),
    ];
    for (k, v) in &blocked {
        body[*k] = v.clone();
    }
    let r = post_chat(&gw, &token, &body).await;
    assert_eq!(r.status(), 200);

    let sent = last_upstream_body(&server).await;
    for (k, _) in &blocked {
        assert!(sent.get(*k).is_none(), "{k} reached vLLM");
    }
    assert_eq!(
        sorted_keys(&sent),
        vec![
            "cache_salt",
            "chat_template_kwargs",
            "frequency_penalty",
            "max_completion_tokens",
            "messages",
            "min_p",
            "model",
            "parallel_tool_calls",
            "presence_penalty",
            "repetition_penalty",
            "response_format",
            "seed",
            "stop",
            "temperature",
            "tool_choice",
            "tools",
            "top_k",
            "top_p",
        ]
    );
    assert_eq!(
        sent["chat_template_kwargs"],
        json!({"enable_thinking": false})
    );
    assert_eq!(
        sent["messages"][1]["content"],
        json!([{"type": "text", "text": "hi"}])
    );
    assert_eq!(sent["tools"], body["tools"]);
    assert_eq!(sent["response_format"], body["response_format"]);
    for k in [
        "temperature",
        "top_p",
        "top_k",
        "min_p",
        "seed",
        "stop",
        "max_completion_tokens",
    ] {
        assert_eq!(sent[k], body[k], "{k}");
    }
    // Dropped fields are counted (22 top-level + 2 kwargs), per label too.
    let stats = gw.stats();
    assert_eq!(stats.dropped_fields, 24);
    assert_eq!(stats.labels["lane"].dropped_fields, 24);
}

#[tokio::test]
async fn media_parts_grammar_forms_and_bad_shapes_are_rejected_before_upstream() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("lane", Duration::from_secs(60));
    let with_part = |part: Value| json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "look"}, part]}]});
    let msgs = json!([{"role": "user", "content": "x"}]);
    let bad = [
        with_part(
            json!({"type": "image_url", "image_url": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}),
        ),
        with_part(
            json!({"type": "input_audio", "input_audio": {"data": "UklGRg==", "format": "wav"}}),
        ),
        with_part(
            json!({"type": "audio_url", "audio_url": {"url": "http://10.0.0.5:9200/_cat/indices"}}),
        ),
        with_part(
            json!({"type": "video_url", "video_url": {"url": "http://127.0.0.1:3001/v1/models"}}),
        ),
        with_part(json!({"type": "image_embeds", "image_embeds": "AAAA"})),
        with_part(json!({"type": "file", "file": {"file_data": "AAAA"}})),
        json!({"messages": msgs, "response_format": {"type": "grammar", "grammar": "root ::= \"a\""}}),
        json!({"messages": msgs, "response_format": {"type": "regex", "regex": "(a+)+$"}}),
        json!({"messages": msgs, "response_format": {"type": "structural_tag", "structures": [], "triggers": []}}),
        json!({"messages": msgs, "response_format": {"type": "json_schema", "json_schema": {
            "name": "big", "schema": {"type": "object", "description": "x".repeat(70 * 1024)}}}}),
        json!({"messages": msgs, "tools": [{"type": "code_interpreter"}]}),
        json!({"messages": [{"role": "developer", "content": "x"}]}),
        json!({"messages": [{"role": "user", "content": {"type": "image_url"}}]}),
        json!({"messages": msgs, "chat_template_kwargs": {"enable_thinking": "please"}}),
    ];
    for body in &bad {
        let r = post_chat(&gw, &token, body).await;
        assert_eq!(r.status(), 400, "{body}");
        let err: Value = r.json().await.unwrap();
        assert_eq!(err["error"]["type"], "invalid_request_error");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(gw.stats().rejected, bad.len() as u64);
    assert!(
        audit
            .snapshot()
            .iter()
            .any(|e| e.kind == "gateway.request" && e.details["reason"] == "policy")
    );
}

#[tokio::test]
async fn tokenize_allowlist() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tokenize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"count": 3})))
        .mount(&server)
        .await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("t", Duration::from_secs(60));
    let send = |body: Value| {
        let u = url(&gw, "/tokenize");
        let t = token.clone();
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
    let r = send(json!({
        "model": "qwen", "prompt": "hello", "add_special_tokens": false,
        "chat_template": "{{ x }}", "return_token_strs": true, "mm_processor_kwargs": {}
    }))
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        last_upstream_body(&server).await,
        json!({"model": "qwen", "prompt": "hello", "add_special_tokens": false})
    );

    let r = send(json!({
        "messages": [{"role": "user", "content": "hi"}], "add_generation_prompt": true,
        "tools": [{"type": "function", "function": {"name": "f"}}],
        "chat_template_kwargs": {"enable_thinking": true, "chat_template": "x"},
        "continue_final_message": true
    }))
    .await;
    assert_eq!(r.status(), 200);
    let sent = last_upstream_body(&server).await;
    assert_eq!(
        sorted_keys(&sent),
        vec![
            "add_generation_prompt",
            "chat_template_kwargs",
            "messages",
            "model",
            "tools"
        ]
    );
    assert_eq!(
        sent["chat_template_kwargs"],
        json!({"enable_thinking": true})
    );

    for bad in [
        json!({"messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "http://169.254.169.254/"}}]}]}),
        json!({"prompt": "a", "messages": [{"role": "user", "content": "b"}]}),
        json!({"prompt": [1, 2, 3]}),
        json!({"model": "qwen"}),
    ] {
        assert_eq!(send(bad.clone()).await.status(), 400, "{bad}");
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    assert_eq!(gw.stats().dropped_fields, 5);
}

#[tokio::test]
async fn cache_salt_is_per_label_and_can_be_disabled() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, _audit) = start(&server, |_| {}).await;
    let body = json!({"messages": [], "cache_salt": "shared-by-attacker"});
    let mut salt_for = Vec::new();
    for label in ["lane-a", "lane-a", "lane-b"] {
        let token = gw.issue_token(label, Duration::from_secs(60));
        assert_eq!(post_chat(&gw, &token, &body).await.status(), 200);
        let sent = last_upstream_body(&server).await;
        let salt = sent["cache_salt"].as_str().unwrap().to_string();
        assert_eq!(salt.len(), 64);
        assert!(salt.bytes().all(|b| b.is_ascii_hexdigit()), "{salt}");
        salt_for.push(salt);
    }
    assert_eq!(
        salt_for[0], salt_for[1],
        "same label, same salt (cache reuse)"
    );
    assert_ne!(
        salt_for[0], salt_for[2],
        "different labels never share the cache"
    );
    assert!(salt_for.iter().all(|s| s != "shared-by-attacker"));
    assert_eq!(gw.stats().dropped_fields, 0, "a client salt is not a probe");

    // Another gateway (another secret) derives other salts for the same label.
    let (gw2, _audit) = start(&server, |_| {}).await;
    let token = gw2.issue_token("lane-a", Duration::from_secs(60));
    post_chat(&gw2, &token, &body).await;
    assert_ne!(
        last_upstream_body(&server).await["cache_salt"],
        json!(salt_for[0])
    );

    // Disabled (older vLLM): no salt at all, client salts are still discarded.
    let (gw3, _audit) = start(&server, |c| c.cache_salt = false).await;
    let token = gw3.issue_token("lane-a", Duration::from_secs(60));
    assert_eq!(post_chat(&gw3, &token, &body).await.status(), 200);
    assert!(
        last_upstream_body(&server)
            .await
            .get("cache_salt")
            .is_none()
    );
}

#[tokio::test]
async fn global_concurrency_cap_spans_tokens() {
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
    let (gw, audit) = start(&server, |c| c.max_concurrent_requests = 1).await;
    let a = gw.issue_token("a", Duration::from_secs(60));
    let b = gw.issue_token("b", Duration::from_secs(60));
    let body = json!({"messages": []});
    let (ra, rb) = tokio::join!(post_chat(&gw, &a, &body), post_chat(&gw, &b, &body));
    let mut statuses = vec![ra.status().as_u16(), rb.status().as_u16()];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        vec![200, 503],
        "per-token caps alone would allow both"
    );
    let limited = if ra.status() == 503 { ra } else { rb };
    assert_eq!(limited.headers()["retry-after"], "2");
    let err: Value = limited.json().await.unwrap();
    assert_eq!(err["error"]["type"], "overloaded_error");
    assert_eq!(gw.stats().overloaded, 1);
    assert!(
        audit
            .snapshot()
            .iter()
            .any(|e| e.kind == "gateway.request" && e.details["reason"] == "overloaded")
    );
    // The permit is released with the response.
    assert_eq!(post_chat(&gw, &b, &body).await.status(), 200);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

/// An upstream that sends one SSE event and then never finishes.
async fn hanging_sse_upstream() -> String {
    use axum::response::IntoResponse;
    use futures::StreamExt;
    async fn handler() -> axum::response::Response {
        let first = futures::stream::once(async {
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\n",
            ))
        });
        let body = axum::body::Body::from_stream(first.chain(futures::stream::pending()));
        ([("content-type", "text/event-stream")], body).into_response()
    }
    let app = axum::Router::new().route("/v1/chat/completions", axum::routing::post(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn open_streams_hold_a_global_permit_until_they_end_and_shutdown_ends_them() {
    let upstream = hanging_sse_upstream().await;
    let mut cfg = GatewayConfig::new(upstream, "qwen");
    cfg.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    cfg.max_concurrent_requests = 1;
    cfg.server_limits.shutdown_grace = Duration::from_millis(300);
    let gw = LlmGateway::start(cfg, Arc::new(MemoryAuditSink::default()))
        .await
        .unwrap();
    let a = gw.issue_token("a", Duration::from_secs(60));
    let b = gw.issue_token("b", Duration::from_secs(60));
    let stream_body = json!({"messages": [], "stream": true});

    let mut held = post_chat(&gw, &a, &stream_body).await;
    assert_eq!(held.status(), 200);
    assert!(held.chunk().await.unwrap().is_some());
    // While the stream is open, the only permit is taken.
    assert_eq!(post_chat(&gw, &b, &stream_body).await.status(), 503);

    // Client disconnect ends the stream and frees the permit.
    drop(held);
    let mut next = None;
    for _ in 0..100 {
        let r = post_chat(&gw, &b, &stream_body).await;
        if r.status() == 200 {
            next = Some(r);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut held = next.expect("permit released after client disconnect");
    assert!(held.chunk().await.unwrap().is_some());

    // Shutdown waits out the grace period, then ends streams still open.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        gw.shutdown().await;
        while let Ok(Some(_)) = held.chunk().await {}
    })
    .await;
    assert!(ended.is_ok(), "stream must end after the shutdown grace");
    assert!(
        gw.stats().labels["b"].errors >= 1,
        "cut-off stream counted as error"
    );
}

#[tokio::test]
async fn default_body_limit_is_4_mib() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, audit) = start(&server, |_| {}).await;
    assert_eq!(talon_llm::gateway::DEFAULT_MAX_BODY_BYTES, 4 * 1024 * 1024);
    let token = gw.issue_token("t", Duration::from_secs(60));
    let big = json!({"messages": [{"role": "user", "content": "x".repeat(4 * 1024 * 1024)}]});
    assert_eq!(post_chat(&gw, &token, &big).await.status(), 413);
    let fits = json!({"messages": [{"role": "user", "content": "x".repeat(3 * 1024 * 1024)}]});
    assert_eq!(post_chat(&gw, &token, &fits).await.status(), 200);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert!(
        audit
            .snapshot()
            .iter()
            .any(|e| e.details["reason"] == "body_too_large")
    );
}

#[tokio::test]
async fn json_value_budget_is_enforced_before_parsing() {
    let server = MockServer::start().await;
    mount_completion(&server).await;
    let (gw, audit) = start(&server, |_| {}).await;
    let token = gw.issue_token("t", Duration::from_secs(60));
    // ~400 KB of `0,` — small on the wire, ~10x that as a Value tree.
    let raw = format!(
        "{{\"messages\":[],\"pad\":[{}0]}}",
        "0,".repeat(talon_llm::gateway::MAX_JSON_NODES + 10)
    );
    let r = http()
        .post(url(&gw, "/v1/chat/completions"))
        .bearer_auth(&token)
        .header("content-type", "application/json")
        .body(raw)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(
        audit
            .snapshot()
            .iter()
            .any(|e| e.details["reason"] == "body_too_complex")
    );
}

#[tokio::test]
async fn slow_header_clients_are_disconnected() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = MockServer::start().await;
    let (gw, _audit) = start(&server, |c| {
        c.server_limits.header_read_timeout = Duration::from_millis(300);
    })
    .await;
    let mut s = tokio::net::TcpStream::connect(gw.addr()).await.unwrap();
    s.write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nX-Slow: ")
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "gateway must close a connection with incomplete headers"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    // Normal clients are unaffected.
    let token = gw.issue_token("t", Duration::from_secs(60));
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    let r = http()
        .get(url(&gw, "/v1/models"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn per_ip_connection_cap_closes_excess_connections() {
    use tokio::io::AsyncReadExt;
    let server = MockServer::start().await;
    let (gw, _audit) = start(&server, |c| {
        c.server_limits.max_connections_per_ip = 2;
        c.server_limits.header_read_timeout = Duration::from_secs(30);
    })
    .await;
    let _a = tokio::net::TcpStream::connect(gw.addr()).await.unwrap();
    let _b = tokio::net::TcpStream::connect(gw.addr()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c = tokio::net::TcpStream::connect(gw.addr()).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
        .await
        .expect("excess connection must be closed promptly")
        .unwrap_or(0);
    assert_eq!(n, 0);
}
