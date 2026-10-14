//! Typed errors for the vLLM client and the gateway.

use std::time::Duration;

use thiserror::Error;

/// Maximum length of an upstream error message kept in an [`LlmError`].
/// Longer messages are truncated so a misbehaving server cannot blow up logs.
pub(crate) const MAX_ERROR_MESSAGE_CHARS: usize = 2_000;

/// Everything that can go wrong talking to vLLM (directly or via the gateway).
#[derive(Debug, Clone, Error)]
pub enum LlmError {
    /// Invalid client/gateway configuration (bad URL, missing model, ...).
    #[error("LLM configuration error: {0}")]
    Config(String),

    /// The server could not be reached (DNS, TCP connect, TLS). Retryable.
    #[error("cannot connect to LLM server: {0}")]
    Connect(String),

    /// The request (or a streaming read) exceeded its time budget.
    #[error("LLM request timed out: {0}")]
    Timeout(String),

    /// HTTP 401/403 — the gateway token (or upstream key) was rejected.
    #[error("LLM server rejected credentials (HTTP {status}): {message}")]
    Unauthorized {
        /// HTTP status code (401 or 403).
        status: u16,
        /// Server-provided message.
        message: String,
    },

    /// HTTP 429 — rate limited. `retry_after` comes from the `Retry-After`
    /// header when the server sent one.
    #[error("LLM server rate limited the request: {message}")]
    RateLimited {
        /// Server-requested delay before retrying, if any.
        retry_after: Option<Duration>,
        /// Server-provided message.
        message: String,
    },

    /// The prompt (plus `max_tokens`) does not fit the model's context
    /// window. The agent loop should compact the conversation and retry.
    #[error("context length exceeded: {0}")]
    ContextLengthExceeded(String),

    /// Any other non-success HTTP status.
    #[error("LLM server returned HTTP {status}: {message}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Server-provided message (truncated).
        message: String,
        /// `Retry-After` from the response, if present.
        retry_after: Option<Duration>,
    },

    /// The server answered with something that is not the expected JSON.
    #[error("cannot decode LLM response: {0}")]
    Decode(String),

    /// The SSE stream was malformed, interrupted, or carried an error event.
    #[error("LLM stream error: {0}")]
    Stream(String),

    /// The response body exceeded the configured size limit.
    #[error("LLM response too large (limit {limit} bytes)")]
    ResponseTooLarge {
        /// The configured limit in bytes.
        limit: usize,
    },

    /// Any other transport-level failure.
    #[error("LLM request failed: {0}")]
    Request(String),
}

impl LlmError {
    /// Whether retrying the same request may succeed (connect errors,
    /// timeouts before a response, 408/429/5xx).
    pub fn is_retryable(&self) -> bool {
        match self {
            LlmError::Connect(_) | LlmError::Timeout(_) | LlmError::RateLimited { .. } => true,
            LlmError::Http { status, .. } => is_retryable_status(*status),
            _ => false,
        }
    }

    /// Short, content-free name of the error variant (safe for logs/metrics).
    pub fn kind(&self) -> &'static str {
        match self {
            LlmError::Config(_) => "config",
            LlmError::Connect(_) => "connect",
            LlmError::Timeout(_) => "timeout",
            LlmError::Unauthorized { .. } => "unauthorized",
            LlmError::RateLimited { .. } => "rate_limited",
            LlmError::ContextLengthExceeded(_) => "context_length_exceeded",
            LlmError::Http { .. } => "http",
            LlmError::Decode(_) => "decode",
            LlmError::Stream(_) => "stream",
            LlmError::ResponseTooLarge { .. } => "response_too_large",
            LlmError::Request(_) => "request",
        }
    }

    /// The HTTP status this error corresponds to, if any.
    pub fn status(&self) -> Option<u16> {
        match self {
            LlmError::Unauthorized { status, .. } | LlmError::Http { status, .. } => Some(*status),
            LlmError::RateLimited { .. } => Some(429),
            LlmError::ContextLengthExceeded(_) => Some(400),
            _ => None,
        }
    }

    /// The server-requested retry delay, if any.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            LlmError::RateLimited { retry_after, .. } | LlmError::Http { retry_after, .. } => {
                *retry_after
            }
            _ => None,
        }
    }

    /// Classify a non-success HTTP response.
    pub(crate) fn from_status(status: u16, body: &[u8], retry_after: Option<Duration>) -> Self {
        let message = extract_error_message(body);
        match status {
            401 | 403 => LlmError::Unauthorized { status, message },
            429 => LlmError::RateLimited {
                retry_after,
                message,
            },
            // 413 = the gateway's body limit: the conversation is too big,
            // so the caller should compact it just like a context overflow.
            413 => LlmError::ContextLengthExceeded(message),
            400 | 422 if looks_like_context_overflow(&message) => {
                LlmError::ContextLengthExceeded(message)
            }
            _ => LlmError::Http {
                status,
                message,
                retry_after,
            },
        }
    }

    /// Map a reqwest transport error.
    pub(crate) fn from_reqwest(err: &reqwest::Error) -> Self {
        // Never include the URL query or headers; reqwest's Display only
        // contains the URL (no credentials, we never put secrets in URLs).
        let msg = truncate(&err.to_string(), MAX_ERROR_MESSAGE_CHARS);
        if err.is_timeout() {
            LlmError::Timeout(msg)
        } else if err.is_connect() {
            LlmError::Connect(msg)
        } else if err.is_decode() {
            LlmError::Decode(msg)
        } else if err.is_builder() {
            LlmError::Config(msg)
        } else if err.is_request() || err.is_body() {
            // Request-phase failures (connection reset before a response,
            // incomplete message) are transient in practice.
            LlmError::Connect(msg)
        } else {
            LlmError::Request(msg)
        }
    }
}

impl From<LlmError> for talon_core::Error {
    fn from(err: LlmError) -> Self {
        match err {
            LlmError::Timeout(m) => talon_core::Error::Timeout(m),
            LlmError::Config(m) => talon_core::Error::Config(m),
            LlmError::Unauthorized { message, .. } => talon_core::Error::Unauthorized(message),
            other => talon_core::Error::Llm(other.to_string()),
        }
    }
}

/// HTTP statuses worth retrying.
pub(crate) fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

/// Heuristic for vLLM / OpenAI "prompt too long" errors.
pub(crate) fn looks_like_context_overflow(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("maximum context length")
        || m.contains("context length")
        || m.contains("context_length_exceeded")
        || m.contains("prompt is too long")
        || m.contains("too many tokens")
        || (m.contains("max_tokens") && m.contains("too large"))
        || (m.contains("input") && m.contains("tokens") && m.contains("exceed"))
}

/// Pull a human-readable message out of an OpenAI-style (`{"error":{...}}`)
/// or vLLM-style (`{"object":"error","message":...}`) error body.
pub(crate) fn extract_error_message(body: &[u8]) -> String {
    let fallback = || {
        let text = String::from_utf8_lossy(body);
        let text = text.trim();
        if text.is_empty() {
            "(empty response body)".to_string()
        } else {
            truncate(text, MAX_ERROR_MESSAGE_CHARS)
        }
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return fallback();
    };
    error_message_from_value(&value).unwrap_or_else(fallback)
}

/// Extract an error message from an already-parsed JSON value, if the value
/// looks like an error object.
pub(crate) fn error_message_from_value(value: &serde_json::Value) -> Option<String> {
    let candidates = [
        value.pointer("/error/message"),
        value.get("error").filter(|e| e.is_string()),
        value
            .get("message")
            .filter(|_| value.get("object").and_then(|o| o.as_str()) == Some("error")),
        value.get("detail").filter(|d| d.is_string()),
        value.get("message"),
    ];
    candidates
        .into_iter()
        .flatten()
        .find_map(|v| v.as_str())
        .map(|s| truncate(s, MAX_ERROR_MESSAGE_CHARS))
}

/// Truncate to at most `max` characters (on a char boundary), appending an
/// ellipsis marker when something was cut.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push_str("…[truncated]");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vllm_error_body_is_parsed() {
        let body = br#"{"object":"error","message":"This model's maximum context length is 32768 tokens. However, you requested 40000 tokens","type":"BadRequestError","param":null,"code":400}"#;
        let err = LlmError::from_status(400, body, None);
        assert!(matches!(err, LlmError::ContextLengthExceeded(_)), "{err:?}");
        assert_eq!(err.status(), Some(400));
        assert!(!err.is_retryable());
    }

    #[test]
    fn openai_error_body_is_parsed() {
        let body = br#"{"error":{"message":"model not found","type":"invalid_request_error"}}"#;
        match LlmError::from_status(404, body, None) {
            LlmError::Http {
                status, message, ..
            } => {
                assert_eq!(status, 404);
                assert_eq!(message, "model not found");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn payload_too_large_means_compact() {
        let err = LlmError::from_status(
            413,
            br#"{"error":{"message":"request body too large"}}"#,
            None,
        );
        assert!(matches!(err, LlmError::ContextLengthExceeded(_)), "{err:?}");
    }

    #[test]
    fn status_classification() {
        assert!(matches!(
            LlmError::from_status(401, b"nope", None),
            LlmError::Unauthorized { status: 401, .. }
        ));
        let rl = LlmError::from_status(429, b"{}", Some(Duration::from_secs(3)));
        assert!(rl.is_retryable());
        assert_eq!(rl.retry_after(), Some(Duration::from_secs(3)));
        assert!(LlmError::from_status(503, b"", None).is_retryable());
        assert!(!LlmError::from_status(400, b"bad", None).is_retryable());
        assert_eq!(
            extract_error_message(b""),
            "(empty response body)".to_string()
        );
    }

    #[test]
    fn long_messages_are_truncated() {
        let long = "x".repeat(10_000);
        let msg = extract_error_message(long.as_bytes());
        assert!(msg.len() < 2_100);
        assert!(msg.ends_with("[truncated]"));
    }

    #[test]
    fn converts_into_core_error() {
        let e: talon_core::Error = LlmError::Timeout("t".into()).into();
        assert!(matches!(e, talon_core::Error::Timeout(_)));
        let e: talon_core::Error = LlmError::Stream("s".into()).into();
        assert!(matches!(e, talon_core::Error::Llm(_)));
    }
}
