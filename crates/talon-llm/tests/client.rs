//! `VllmClient` against a fake vLLM (wiremock).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use futures::StreamExt;
use serde_json::{Value, json};
use talon_core::protocol::SessionUsage;
use talon_core::tool::ToolSpec;
use talon_llm::stream::StreamEvent;
use talon_llm::types::{ChatMessage, FinishReason, ToolCallFormat, ToolChoice};
use talon_llm::{ClientConfig, LlmError, VllmClient};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(server: &MockServer, retries: u32) -> VllmClient {
    let mut cfg = ClientConfig::new(format!("{}/v1", server.uri()), "qwen").with_api_key("sk-test");
    cfg.retry = fast_retry(retries);
    VllmClient::new(cfg).unwrap()
}

fn weather_tool() -> ToolSpec {
    ToolSpec {
        name: "get_weather".into(),
        description: "Weather for a city".into(),
        parameters: json!({"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}),
    }
}

#[tokio::test]
async fn chat_sends_auth_and_parses_usage() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer sk-test"))
        .and(body_partial_json(json!({
            "model": "qwen",
            "messages": [{"role": "user", "content": "hi"}],
            "chat_template_kwargs": {"enable_thinking": false}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion("hello")))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server, 0);
    let req = client
        .request(vec![ChatMessage::user("hi")])
        .enable_thinking(false);
    let resp = client.chat(&req).await.unwrap();
    assert_eq!(resp.message.text(), "hello");
    assert_eq!(resp.finish_reason, Some(FinishReason::Stop));
    assert_eq!(resp.usage.prompt_tokens, 120);
    assert_eq!(resp.usage.cached_tokens, 96);
    let su: SessionUsage = resp.session_usage();
    assert_eq!(su.input_tokens, Some(24));
    assert_eq!(su.cache_read_input_tokens, Some(96));
    assert_eq!(su.output_tokens, Some(8));

    let sent: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    assert!(
        sent.get("stream").is_none(),
        "non-streaming request: {sent}"
    );
    assert!(sent.get("stream_options").is_none());
}

#[tokio::test]
async fn chat_with_tools_and_guided_decoding_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({
            "tools": [{"type": "function", "function": {"name": "get_weather"}}],
            "tool_choice": "required",
            "parallel_tool_calls": true
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(tool_call_completion(
                "get_weather",
                "{\"city\": \"Bremen\"}",
            )),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({
            "response_format": {"type": "json_schema", "json_schema": {"name": "verdict", "strict": true}}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion("{\"verdict\":\"benign\"}")))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server, 0);
    let tool = weather_tool();
    let req = client
        .request(vec![ChatMessage::user("weather?")])
        .tools([&tool])
        .tool_choice(ToolChoice::Required)
        .parallel_tool_calls(true);
    let resp = client.chat(&req).await.unwrap();
    assert_eq!(resp.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(resp.message.tool_calls.len(), 1);
    assert_eq!(resp.message.tool_calls[0].id, "chatcmpl-tool-1");
    assert_eq!(
        resp.message.tool_calls[0].parse_arguments().unwrap(),
        json!({"city": "Bremen"})
    );
    assert!(resp.postprocess.recovered_format.is_none());

    let schema = json!({"type": "object", "properties": {"verdict": {"type": "string"}}});
    let req = client
        .request(vec![ChatMessage::user("triage")])
        .json_schema("verdict", schema, true);
    let resp = client.chat(&req).await.unwrap();
    assert_eq!(resp.content_json().unwrap()["verdict"], "benign");
}

#[tokio::test]
async fn chat_recovers_text_tool_calls_and_think() {
    let server = MockServer::start().await;
    let text = "<think>The user wants weather.</think>\n<tool_call>\n{\"name\": \"get_weather\", \"arguments\": {\"city\": \"Kiel\"}}\n</tool_call>";
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion(text)))
        .mount(&server)
        .await;
    let client = client_for(&server, 0);
    let tool = weather_tool();
    let req = client.request(vec![ChatMessage::user("w")]).tools([&tool]);
    let resp = client.chat(&req).await.unwrap();
    assert_eq!(resp.message.tool_calls.len(), 1);
    assert_eq!(resp.message.tool_calls[0].name(), "get_weather");
    assert!(resp.message.tool_calls[0].id.starts_with("call_"));
    assert_eq!(resp.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(
        resp.message.reasoning_content.as_deref(),
        Some("The user wants weather.")
    );
    assert!(resp.message.content.is_none());
    assert_eq!(
        resp.postprocess.recovered_format,
        Some(ToolCallFormat::Hermes)
    );

    // Without tools offered nothing is recovered (but think is still split).
    let req = client.request(vec![ChatMessage::user("w")]);
    let resp = client.chat(&req).await.unwrap();
    assert!(resp.message.tool_calls.is_empty());
    assert!(resp.message.text().contains("<tool_call>"));
    assert!(resp.postprocess.reasoning_extracted);
}

#[tokio::test]
async fn retries_5xx_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("overloaded"))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion("ok")))
        .mount(&server)
        .await;
    let client = client_for(&server, 3);
    let resp = client
        .chat(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap();
    assert_eq!(resp.message.text(), "ok");
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn retry_after_is_honoured_on_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1")
                .set_body_json(json!({"error": {"message": "slow down"}})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion("ok")))
        .mount(&server)
        .await;
    let client = client_for(&server, 2);
    let started = Instant::now();
    client
        .chat(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(950),
        "Retry-After not honoured: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn exhausted_retries_return_last_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(502)
                .set_body_json(json!({"object": "error", "message": "bad gateway"})),
        )
        .mount(&server)
        .await;
    let client = client_for(&server, 2);
    let err = client
        .chat(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap_err();
    match err {
        LlmError::Http {
            status, message, ..
        } => {
            assert_eq!(status, 502);
            assert_eq!(message, "bad gateway");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn client_errors_are_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "object": "error",
            "message": "This model's maximum context length is 32768 tokens. However, you requested 40000 tokens (39000 in the messages, 1000 in the completion).",
            "type": "BadRequestError", "code": 400
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(401).set_body_string("bad key"))
        .mount(&server)
        .await;
    let client = client_for(&server, 3);
    let err = client
        .chat(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap_err();
    assert!(matches!(err, LlmError::ContextLengthExceeded(_)), "{err:?}");
    let err = client.list_models().await.unwrap_err();
    assert!(
        matches!(err, LlmError::Unauthorized { status: 401, .. }),
        "{err:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn connect_errors_are_retried_then_reported() {
    let port = closed_port().await;
    let mut cfg = ClientConfig::new(format!("http://127.0.0.1:{port}"), "m");
    cfg.retry = fast_retry(2);
    let client = VllmClient::new(cfg).unwrap();
    let err = client
        .chat(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap_err();
    assert!(matches!(err, LlmError::Connect(_)), "{err:?}");
    assert!(err.is_retryable());
}

#[tokio::test]
async fn request_timeout_is_enforced() {
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
    let mut cfg = ClientConfig::new(server.uri(), "m");
    cfg.retry = fast_retry(0);
    cfg.request_timeout = Duration::from_millis(200);
    let client = VllmClient::new(cfg).unwrap();
    let started = Instant::now();
    let err = client
        .chat(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap_err();
    assert!(matches!(err, LlmError::Timeout(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn oversized_responses_are_refused() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion(&"x".repeat(10_000))))
        .mount(&server)
        .await;
    let mut cfg = ClientConfig::new(server.uri(), "m");
    cfg.max_response_bytes = 1024;
    let client = VllmClient::new(cfg).unwrap();
    let err = client
        .chat(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LlmError::ResponseTooLarge { limit: 1024 }),
        "{err:?}"
    );
}

#[tokio::test]
async fn streaming_assembles_tool_calls_and_usage() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("accept", "text/event-stream"))
        .and(body_partial_json(
            json!({"stream": true, "stream_options": {"include_usage": true}}),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(tool_call_stream(), "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = client_for(&server, 0);
    let tool = weather_tool();
    let req = client.request(vec![ChatMessage::user("w")]).tools([&tool]);
    let mut stream = client.chat_stream(&req).await.unwrap();
    let mut content = String::new();
    let mut reasoning = String::new();
    let mut starts = Vec::new();
    let mut usage_events = 0;
    let mut done = None;
    while let Some(ev) = stream.next().await {
        match ev.unwrap() {
            StreamEvent::Content(c) => content.push_str(&c),
            StreamEvent::Reasoning(r) => reasoning.push_str(&r),
            StreamEvent::ToolCallStart { name, id, .. } => starts.push((name, id)),
            StreamEvent::ToolCallArguments { .. } => {}
            StreamEvent::Usage(_) => usage_events += 1,
            StreamEvent::Done(resp) => done = Some(*resp),
        }
    }
    assert_eq!(content, "Checking now.");
    assert_eq!(reasoning, "Need weather.");
    assert_eq!(
        starts,
        vec![("get_weather".to_string(), "chatcmpl-tool-9".to_string())]
    );
    assert_eq!(usage_events, 1);
    let resp = done.expect("Done event");
    assert_eq!(resp.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(resp.message.text(), "Checking now.");
    assert_eq!(
        resp.message.reasoning_content.as_deref(),
        Some("Need weather.")
    );
    assert_eq!(
        resp.message.tool_calls[0].parse_arguments().unwrap(),
        json!({"city": "Hamburg"})
    );
    assert_eq!(resp.usage.prompt_tokens, 200);
    assert_eq!(resp.usage.cached_tokens, 150);
}

#[tokio::test]
async fn chat_streaming_callback_and_json_fallback() {
    let server = MockServer::start().await;
    // A server that ignores `stream: true` and answers with plain JSON.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion("whole answer")))
        .mount(&server)
        .await;
    let client = client_for(&server, 0);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let resp = client
        .chat_streaming(&client.request(vec![ChatMessage::user("x")]), move |ev| {
            sink.lock().unwrap().push(ev.clone());
        })
        .await
        .unwrap();
    assert_eq!(resp.message.text(), "whole answer");
    let seen = seen.lock().unwrap();
    assert!(seen.contains(&StreamEvent::Content("whole answer".into())));
    assert!(!seen.iter().any(|e| matches!(e, StreamEvent::Done(_))));
}

#[tokio::test]
async fn streaming_error_status_is_retried_before_first_byte() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(tool_call_stream(), "text/event-stream"),
        )
        .mount(&server)
        .await;
    let client = client_for(&server, 1);
    let resp = client
        .chat_stream(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap()
        .into_response()
        .await
        .unwrap();
    assert_eq!(resp.message.tool_calls.len(), 1);
}

#[tokio::test]
async fn truncated_stream_is_an_error() {
    let server = MockServer::start().await;
    let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n";
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
        .mount(&server)
        .await;
    let client = client_for(&server, 0);
    let err = client
        .chat_stream(&client.request(vec![ChatMessage::user("x")]))
        .await
        .unwrap()
        .into_response()
        .await
        .unwrap_err();
    assert!(matches!(err, LlmError::Stream(_)), "{err:?}");
}

#[tokio::test]
async fn models_health_and_tokenize() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "qwen", "object": "model", "owned_by": "vllm", "root": "/models/qwen", "max_model_len": 32768}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tokenize"))
        .and(body_partial_json(
            json!({"model": "qwen", "prompt": "hello world"}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"count": 2, "max_model_len": 32768, "tokens": [1, 2]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tokenize"))
        .and(body_partial_json(json!({"add_generation_prompt": true})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"count": 42, "max_model_len": 32768})),
        )
        .mount(&server)
        .await;

    let client = client_for(&server, 0);
    let models = client.list_models().await.unwrap();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].id, "qwen");
    assert_eq!(models[0].max_model_len, Some(32768));
    client.health().await.unwrap();

    let n = client.tokenize("hello world").await;
    assert_eq!(n.count, 2);
    assert!(!n.estimated);
    assert_eq!(n.max_model_len, Some(32768));

    let n = client
        .tokenize_messages(&[ChatMessage::system("s"), ChatMessage::user("u")], &[])
        .await;
    assert_eq!(n.count, 42);
    assert!(!n.estimated);
}

#[tokio::test]
async fn health_falls_back_to_models_and_tokenize_to_estimate() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    // /health and /tokenize are not served (404 by default).
    let client = client_for(&server, 0);
    client.health().await.unwrap();

    let n = client.tokenize(&"a".repeat(40)).await;
    assert!(n.estimated);
    assert_eq!(n.count, 10);
    let before = server.received_requests().await.unwrap().len();
    // The endpoint is remembered as unavailable: no further requests.
    let n = client.tokenize("abcd").await;
    assert!(n.estimated);
    assert_eq!(server.received_requests().await.unwrap().len(), before);
}

#[tokio::test]
async fn health_reports_server_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let client = client_for(&server, 0);
    let err = client.health().await.unwrap_err();
    assert_eq!(err.status(), Some(503));
}
