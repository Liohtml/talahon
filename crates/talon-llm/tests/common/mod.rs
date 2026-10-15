//! Shared helpers for the wiremock-based integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use serde_json::{Value, json};
use talon_llm::retry::RetryPolicy;

/// A `chat.completion` body with plain text content.
pub fn completion(content: &str) -> Value {
    json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": "qwen",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 8,
            "total_tokens": 128,
            "prompt_tokens_details": {"cached_tokens": 96}
        }
    })
}

/// A `chat.completion` body with a server-parsed tool call.
pub fn tool_call_completion(name: &str, arguments: &str) -> Value {
    json!({
        "id": "chatcmpl-tool",
        "object": "chat.completion",
        "model": "qwen",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "chatcmpl-tool-1",
                    "type": "function",
                    "function": {"name": name, "arguments": arguments}
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60}
    })
}

/// Render chunks as an SSE body terminated by `[DONE]`.
pub fn sse_body(chunks: &[Value]) -> String {
    let mut s = String::new();
    for c in chunks {
        s.push_str("data: ");
        s.push_str(&c.to_string());
        s.push_str("\n\n");
    }
    s.push_str("data: [DONE]\n\n");
    s
}

/// A realistic vLLM stream: role chunk, reasoning, content, a streamed tool
/// call, finish, and the usage chunk.
pub fn tool_call_stream() -> String {
    let base = |delta: Value, finish: Value| {
        json!({
            "id": "chatcmpl-s", "object": "chat.completion.chunk", "created": 1, "model": "qwen",
            "choices": [{"index": 0, "delta": delta, "logprobs": null, "finish_reason": finish}]
        })
    };
    sse_body(&[
        base(json!({"role": "assistant", "content": ""}), Value::Null),
        base(json!({"reasoning_content": "Need weather."}), Value::Null),
        base(json!({"content": "Checking "}), Value::Null),
        base(json!({"content": "now."}), Value::Null),
        base(
            json!({"tool_calls": [{"index": 0, "id": "chatcmpl-tool-9", "type": "function",
                "function": {"name": "get_weather", "arguments": ""}}]}),
            Value::Null,
        ),
        base(
            json!({"tool_calls": [{"index": 0, "function": {"arguments": "{\"city\": "}}]}),
            Value::Null,
        ),
        base(
            json!({"tool_calls": [{"index": 0, "function": {"arguments": "\"Hamburg\"}"}}]}),
            Value::Null,
        ),
        base(json!({"content": ""}), json!("tool_calls")),
        json!({"id": "chatcmpl-s", "object": "chat.completion.chunk", "model": "qwen", "choices": [],
            "usage": {"prompt_tokens": 200, "completion_tokens": 30, "total_tokens": 230,
                      "prompt_tokens_details": {"cached_tokens": 150}}}),
    ])
}

/// Retries without meaningful delays.
pub fn fast_retry(max_retries: u32) -> RetryPolicy {
    RetryPolicy {
        max_retries,
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(20),
        max_retry_after: Duration::from_secs(5),
    }
}

/// A local port with nothing listening on it.
pub async fn closed_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// A plain HTTP client that ignores proxy environment variables.
pub fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// Poll `f` until it returns true (or panic after ~2 s).
pub async fn eventually(mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached in time");
}
