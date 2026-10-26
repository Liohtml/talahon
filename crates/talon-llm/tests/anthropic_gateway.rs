//! `LlmGateway` with `UpstreamKind::Anthropic`, wiremock playing the
//! Messages API. The agent side is the unchanged `VllmClient`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use talon_core::audit::MemoryAuditSink;
use talon_core::tool::ToolSpec;
use talon_core::types::{ProviderKind, VllmConfig};
use talon_llm::gateway::{GatewayConfig, GatewayHandle, LlmGateway, UpstreamKind};
use talon_llm::types::{ChatMessage, FinishReason};
use talon_llm::{ClientConfig, VllmClient};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const KEY: &str = "sk-ant-test-key";
const MODEL: &str = "claude-sonnet-5-5";

fn provider_config(server: &MockServer, thinking: bool) -> VllmConfig {
    VllmConfig {
        base_url: server.uri(),
        model: MODEL.into(),
        fast_model: None,
        max_context_tokens: Some(200_000),
        max_output_tokens: Some(2048),
        temperature: None,
        top_p: None,
        enable_thinking: Some(thinking),
        request_timeout_secs: None,
    }
}

async fn start(server: &MockServer, thinking: bool) -> (GatewayHandle, VllmClient) {
    let cfg = provider_config(server, thinking);
    let mut gw = GatewayConfig::from_provider(ProviderKind::Anthropic, &cfg, Some(KEY.into()));
    assert_eq!(gw.upstream_kind, UpstreamKind::Anthropic);
    assert!(!gw.cache_salt);
    gw.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    let handle = LlmGateway::start(gw, Arc::new(MemoryAuditSink::default()))
        .await
        .unwrap();
    let token = handle.issue_token("lane", Duration::from_secs(60));
    let endpoint = handle.endpoint(token, "127.0.0.1", &cfg);
    let client = VllmClient::new(ClientConfig::from_endpoint(&endpoint)).unwrap();
    (handle, client)
}

fn anthropic_message(blocks: Value, stop_reason: &str) -> Value {
    json!({
        "id": "msg_01", "type": "message", "role": "assistant", "model": MODEL,
        "content": blocks, "stop_reason": stop_reason, "stop_sequence": null,
        "usage": {"input_tokens": 20, "cache_read_input_tokens": 80, "cache_creation_input_tokens": 0, "output_tokens": 5}
    })
}

fn sse(events: &[(&str, Value)]) -> String {
    events
        .iter()
        .map(|(name, data)| format!("event: {name}\ndata: {data}\n\n"))
        .collect()
}

async fn requests(server: &MockServer) -> Vec<Request> {
    server.received_requests().await.unwrap()
}

#[tokio::test]
async fn non_streaming_chat_is_translated_both_ways_with_the_api_key_on_the_host() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", KEY))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_message(
            json!([
                {"type": "text", "text": "Looking it up."},
                {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {"q": 7}}
            ]),
            "tool_use",
        )))
        .mount(&server)
        .await;
    let (gw, client) = start(&server, false).await;

    let spec = ToolSpec {
        name: "lookup".into(),
        description: "look things up".into(),
        parameters: json!({"type": "object", "properties": {"q": {"type": "integer"}}}),
    };
    let req = client
        .request(vec![
            ChatMessage::system("You are Talon."),
            ChatMessage::user("alert 7"),
        ])
        .tools([&spec]);
    let resp = client.chat(&req).await.unwrap();
    assert_eq!(resp.message.text(), "Looking it up.");
    assert_eq!(resp.message.tool_calls.len(), 1);
    assert_eq!(resp.message.tool_calls[0].function.name, "lookup");
    assert_eq!(resp.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(resp.usage.prompt_tokens, 100);
    assert_eq!(resp.usage.cached_tokens, 80);
    assert_eq!(resp.usage.completion_tokens, 5);

    let sent = requests(&server).await;
    assert_eq!(sent.len(), 1);
    // The container's gateway token never reaches the upstream.
    assert!(sent[0].headers.get("authorization").is_none());
    let body: Value = sent[0].body_json().unwrap();
    assert_eq!(body["model"], MODEL);
    assert_eq!(body["system"][0]["text"], "You are Talon.");
    assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["tools"][0]["name"], "lookup");
    assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
    assert_eq!(
        body["max_tokens"], 2048,
        "the gateway cap is forwarded as max_tokens"
    );
    assert!(body.get("thinking").is_none());
    assert!(body.get("cache_salt").is_none());
    assert!(body.get("stream_options").is_none());
    gw.shutdown().await;
}

#[tokio::test]
async fn streaming_chat_is_translated_to_openai_chunks() {
    let server = MockServer::start().await;
    let stream = sse(&[
        (
            "message_start",
            json!({"type":"message_start","message":{"id":"msg_s","model":MODEL,"usage":{"input_tokens":3,"output_tokens":1}}}),
        ),
        (
            "content_block_start",
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        ),
        (
            "content_block_delta",
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"All "}}),
        ),
        (
            "content_block_delta",
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"clear."}}),
        ),
        (
            "content_block_stop",
            json!({"type":"content_block_stop","index":0}),
        ),
        (
            "message_delta",
            json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}),
        ),
        ("message_stop", json!({"type":"message_stop"})),
    ]);
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_raw(stream, "text/event-stream"))
        .mount(&server)
        .await;
    let (gw, client) = start(&server, true).await;

    let req = client.request(vec![ChatMessage::user("status?")]);
    let mut seen = Vec::new();
    let resp = client
        .chat_streaming(&req, |ev| seen.push(format!("{ev:?}")))
        .await
        .unwrap();
    assert_eq!(resp.message.text(), "All clear.");
    assert_eq!(resp.finish_reason, Some(FinishReason::Stop));
    assert_eq!(resp.usage.prompt_tokens, 3);
    assert_eq!(resp.usage.completion_tokens, 4);
    assert!(seen.iter().any(|e| e.contains("Content")));

    let body: Value = requests(&server).await[0].body_json().unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(
        body["thinking"]["type"], "adaptive",
        "host opt-in via enable_thinking"
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn models_are_listed_locally_and_tokenize_uses_count_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages/count_tokens"))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"input_tokens": 42})))
        .mount(&server)
        .await;
    let (gw, client) = start(&server, false).await;

    let models = client.list_models().await.unwrap();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].id, MODEL);

    let count = client
        .tokenize_messages(&[ChatMessage::user("count me")], &[])
        .await;
    assert!(!count.estimated);
    assert_eq!(count.count, 42);
    let sent = requests(&server).await;
    assert_eq!(
        sent.len(),
        1,
        "models came from the allow-list, not upstream"
    );
    let body: Value = sent[0].body_json().unwrap();
    assert_eq!(body["messages"][0]["content"][0]["text"], "count me");
    assert!(body.get("max_tokens").is_none());
    gw.shutdown().await;
}

#[tokio::test]
async fn upstream_errors_keep_their_status_in_openai_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}
        })))
        .mount(&server)
        .await;
    let (gw, client) = start(&server, false).await;
    let req = client.request(vec![ChatMessage::user("x")]);
    let err = client.chat(&req).await.unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("429") || text.to_lowercase().contains("rate"),
        "{text}"
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn gateway_refuses_to_start_without_an_anthropic_key() {
    let server = MockServer::start().await;
    let cfg = provider_config(&server, false);
    let mut gw = GatewayConfig::from_provider(ProviderKind::Anthropic, &cfg, None);
    gw.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    let err = LlmGateway::start(gw, Arc::new(MemoryAuditSink::default()))
        .await
        .expect_err("must not start");
    assert!(err.to_string().contains("TALON_ANTHROPIC_API_KEY"));
}
