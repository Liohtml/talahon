//! Tool errors and the caller-safe messages built from them.
//!
//! The wording follows `opensearch-mcp-server` (`src/clients/error_report.py`):
//! `"<tool> failed: <what>"`, with OpenSearch's structured `error` reasons
//! for request errors and a bare `"<status> not authorized"` for anything
//! that may name users or roles. Raw response bodies, URLs and credentials
//! are never part of a message.

use serde_json::Value;

use crate::path::PathError;

/// Longest message returned to the caller, in characters.
pub const MAX_CALLER_CHARS: usize = 2000;
const TRUNCATED: &str = "... (truncated)";
const MAX_DEPTH: usize = 20;
const CHILD_KEYS: [&str; 4] = ["root_cause", "caused_by", "failed_shards", "reason"];
const IDENTITY_WORDS: [&str; 5] = [
    "security",
    "authorization",
    "authenticat",
    "unauthori",
    "forbidden",
];

/// Why a tool call failed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ToolError {
    /// The arguments were rejected before any request was made.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The `cluster` argument names a cluster that is not configured.
    #[error("Unknown cluster '{0}'. Available clusters: default")]
    UnknownCluster(String),
    /// The request did not finish within the configured timeout.
    #[error("timed out")]
    Timeout,
    /// No configured host could be reached (DNS, TCP, TLS).
    #[error("connection failed")]
    Connection,
    /// OpenSearch answered with a non-2xx status.
    #[error("HTTP {status}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// The parsed JSON error body, when there was a small enough one.
        body: Option<Value>,
    },
    /// The response body is larger than the configured limit.
    #[error("response exceeds the limit of {limit} bytes")]
    TooLarge {
        /// The limit in bytes.
        limit: usize,
    },
    /// A 2xx response that is not what the tool expects (not UTF-8 / JSON).
    #[error("invalid response from OpenSearch")]
    InvalidResponse,
    /// Anything else (a bug or an unexpected client failure).
    #[error("internal error")]
    Internal,
}

impl From<PathError> for ToolError {
    fn from(e: PathError) -> Self {
        Self::InvalidArgument(e.to_string())
    }
}

impl ToolError {
    /// The message returned to the model for a failed call of `tool`.
    pub fn caller_message(&self, tool: &str) -> String {
        let text = match self {
            Self::Status { status, body } => status_message(tool, *status, body.as_ref()),
            Self::TooLarge { limit } => format!(
                "{tool} failed: response exceeds the limit of {limit} bytes; narrow the request \
                 (smaller \"size\", \"_source\" filtering, a tighter time range or a more specific index)"
            ),
            other => format!("{tool} failed: {other}"),
        };
        cap(&sanitize(&text))
    }

    /// A short line for the server log (no reasons, no argument values).
    pub fn log_line(&self, tool: &str) -> String {
        match self {
            Self::Status { status, body } => {
                let etype = body
                    .as_ref()
                    .and_then(top_error_type)
                    .filter(|t| is_safe_type(t))
                    .map(|t| format!(" {t}"))
                    .unwrap_or_default();
                format!("{tool} failed: {status}{etype}")
            }
            Self::InvalidArgument(_) => format!("{tool} failed: invalid argument"),
            Self::UnknownCluster(_) => format!("{tool} failed: unknown cluster"),
            other => format!("{tool} failed: {other}"),
        }
    }
}

fn status_message(tool: &str, status: u16, body: Option<&Value>) -> String {
    if is_identity_bearing(status, body) {
        return format!("{tool} failed: {status} not authorized");
    }
    let reasons = body.map(extract_reasons).unwrap_or_default();
    if !reasons.is_empty() {
        return format!("{tool} failed: {status}\n{}", reasons.join("\n"));
    }
    let phrase = reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    format!("{tool} failed: {status} {phrase}")
        .trim_end()
        .to_string()
}

/// Drop control characters except newline (reasons are joined by `\n`).
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect()
}

fn cap(text: &str) -> String {
    if text.chars().count() <= MAX_CALLER_CHARS {
        return text.to_string();
    }
    let keep = MAX_CALLER_CHARS - TRUNCATED.len();
    let mut out: String = text.chars().take(keep).collect();
    out.push_str(TRUNCATED);
    out
}

fn is_safe_type(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 80
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

fn top_error_type(body: &Value) -> Option<&str> {
    body.get("error")?.as_object()?.get("type")?.as_str()
}

/// Collect `(type, reason)` pairs from an OpenSearch error object. Returns
/// `true` when the depth cap cut the walk short (callers fail closed).
fn walk<'a>(node: &'a Value, out: &mut Vec<(&'a str, Option<&'a str>)>, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return node.is_object() || node.is_array();
    }
    match node {
        Value::Array(items) => {
            let mut truncated = false;
            for item in items {
                truncated |= walk(item, out, depth + 1);
            }
            truncated
        }
        Value::Object(map) => {
            if let Some(etype) = map.get("type").and_then(Value::as_str) {
                out.push((etype, map.get("reason").and_then(Value::as_str)));
            }
            let mut truncated = false;
            for key in CHILD_KEYS {
                if let Some(child) = map.get(key).filter(|c| c.is_object() || c.is_array()) {
                    truncated |= walk(child, out, depth + 1);
                }
            }
            truncated
        }
        _ => false,
    }
}

fn entries(body: &Value) -> (Vec<(&str, Option<&str>)>, bool) {
    let mut out = Vec::new();
    let truncated = body
        .as_object()
        .and_then(|b| b.get("error"))
        .is_some_and(|error| walk(error, &mut out, 0));
    (out, truncated)
}

/// `"<type>: <reason>"` strings from the structured `error` object, in
/// order of first appearance and without duplicates. Only `error` is read.
fn extract_reasons(body: &Value) -> Vec<String> {
    if let Some(error) = body.get("error").and_then(Value::as_str) {
        return vec![format!("error: {error}")];
    }
    let mut reasons: Vec<String> = Vec::new();
    for (etype, reason) in entries(body).0 {
        let Some(reason) = reason else { continue };
        let item = format!("{etype}: {reason}");
        if !reasons.contains(&item) {
            reasons.push(item);
        }
    }
    reasons
}

/// True when the error may reveal user or role details: 401/403, or a
/// security-flavoured error type anywhere in the cause chain.
fn is_identity_bearing(status: u16, body: Option<&Value>) -> bool {
    if matches!(status, 401 | 403) {
        return true;
    }
    let Some(body) = body else { return false };
    let (entries, truncated) = entries(body);
    truncated
        || entries.iter().any(|(etype, _)| {
            let lower = etype.to_lowercase();
            IDENTITY_WORDS.iter().any(|word| lower.contains(word))
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn status(status: u16, body: Value) -> ToolError {
        ToolError::Status {
            status,
            body: Some(body),
        }
    }

    #[test]
    fn request_errors_carry_structured_reasons() {
        let e = status(
            404,
            json!({"error": {
                "root_cause": [{"type": "index_not_found_exception", "reason": "no such index [missing]"}],
                "type": "index_not_found_exception",
                "reason": "no such index [missing]"
            }, "status": 404}),
        );
        // Byte-identical to opensearch-mcp-server 2.1.9 for the same body.
        assert_eq!(
            e.caller_message("get_index"),
            "get_index failed: 404\nindex_not_found_exception: no such index [missing]"
        );
        assert_eq!(
            e.log_line("get_index"),
            "get_index failed: 404 index_not_found_exception"
        );
    }

    #[test]
    fn nested_causes_are_listed_once_in_order() {
        let e = status(
            400,
            json!({"error": {
                "type": "search_phase_execution_exception",
                "reason": "all shards failed",
                "root_cause": [{"type": "parsing_exception", "reason": "bad query"}],
                "failed_shards": [{"shard": 0, "reason": {"type": "parsing_exception", "reason": "bad query"}}],
                "caused_by": {"type": "x_content_parse_exception", "reason": "line 1"}
            }}),
        );
        assert_eq!(
            e.caller_message("search_documents"),
            "search_documents failed: 400\n\
             search_phase_execution_exception: all shards failed\n\
             parsing_exception: bad query\n\
             x_content_parse_exception: line 1"
        );
    }

    #[test]
    fn identity_bearing_errors_are_reduced() {
        let body = json!({"error": {"type": "security_exception",
            "reason": "no permissions for [x] and User [name=admin, roles=[soc]]"}});
        for code in [401, 403, 500] {
            let msg = status(code, body.clone()).caller_message("get_index");
            assert_eq!(msg, format!("get_index failed: {code} not authorized"));
        }
        let plain = ToolError::Status {
            status: 403,
            body: None,
        };
        assert_eq!(
            plain.caller_message("get_index"),
            "get_index failed: 403 not authorized"
        );
    }

    #[test]
    fn overly_deep_error_chains_fail_closed() {
        let mut node = json!({"type": "leaf", "reason": "deep"});
        for _ in 0..30 {
            node = json!({"type": "wrap", "reason": "r", "caused_by": node});
        }
        let msg = status(500, json!({"error": node})).caller_message("t");
        assert_eq!(msg, "t failed: 500 not authorized");
    }

    #[test]
    fn bodies_without_structure_fall_back_to_the_status_phrase() {
        let none = ToolError::Status {
            status: 502,
            body: None,
        };
        assert_eq!(none.caller_message("t"), "t failed: 502 Bad Gateway");
        assert_eq!(
            status(400, json!({"error": "plain text"})).caller_message("t"),
            "t failed: 400\nerror: plain text"
        );
        assert_eq!(
            status(599, json!({"message": "secret detail"})).caller_message("t"),
            "t failed: 599"
        );
        assert_eq!(
            status(404, json!({"_index": "i", "_id": "1", "found": false})).caller_message("t"),
            "t failed: 404 Not Found"
        );
    }

    #[test]
    fn messages_are_capped_and_stripped_of_control_characters() {
        let long = "x".repeat(5000);
        let msg = status(400, json!({"error": {"type": "t", "reason": long}})).caller_message("t");
        assert_eq!(msg.chars().count(), MAX_CALLER_CHARS);
        assert!(msg.ends_with(TRUNCATED));
        let ctl = status(
            400,
            json!({"error": {"type": "t", "reason": "a\u{1b}[31mb\rc"}}),
        );
        assert_eq!(ctl.caller_message("t"), "t failed: 400\nt: a[31mbc");
    }

    #[test]
    fn non_http_errors_use_fixed_phrases() {
        assert_eq!(
            ToolError::Timeout.caller_message("t"),
            "t failed: timed out"
        );
        assert_eq!(
            ToolError::Connection.caller_message("t"),
            "t failed: connection failed"
        );
        assert_eq!(
            ToolError::UnknownCluster("other".into()).caller_message("get_index"),
            "get_index failed: Unknown cluster 'other'. Available clusters: default"
        );
        assert!(
            ToolError::TooLarge { limit: 10 }
                .caller_message("t")
                .starts_with("t failed: response exceeds the limit of 10 bytes")
        );
        assert_eq!(
            ToolError::InvalidArgument("secret value".into()).log_line("t"),
            "t failed: invalid argument"
        );
    }
}
