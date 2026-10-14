//! Minimal JSON-RPC 2.0 helpers on `serde_json::Value` (the proxy does not
//! depend on `talon-mcp`; it only needs to classify and synthesize
//! messages).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

/// Invalid JSON was received.
pub const PARSE_ERROR: i64 = -32700;
/// The JSON sent is not a valid request object.
pub const INVALID_REQUEST: i64 = -32600;
/// Internal error.
pub const INTERNAL_ERROR: i64 = -32603;
/// The upstream MCP server exited before answering.
pub const UPSTREAM_EXITED: i64 = -32000;
/// The upstream response exceeded the proxy's size limit.
pub const RESPONSE_TOO_LARGE: i64 = -32001;
/// Too many requests are waiting for the upstream.
pub const TOO_MANY_PENDING: i64 = -32002;

/// Name of the locally answered tool.
pub const DEANONYMIZE_TOOL_NAME: &str = "deanonymize";

static ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Static pattern, verified by tests: cannot fail.
    Regex::new(r#""id"\s*:\s*(-?[0-9]{1,19}|"(?:[^"\\]|\\.){0,256}")"#).expect("static regex")
});

/// What a message is.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageKind {
    /// Has `method` and `id`.
    Request {
        /// Request id (number or string).
        id: Value,
        /// Method name.
        method: String,
    },
    /// Has `method`, no `id`.
    Notification {
        /// Method name.
        method: String,
    },
    /// Has `id` and `result` or `error`, no `method`.
    Response {
        /// Id of the request being answered.
        id: Value,
    },
    /// Anything else.
    Invalid,
}

/// Classify a single (non-batch) message.
pub fn classify(v: &Value) -> MessageKind {
    let Value::Object(m) = v else {
        return MessageKind::Invalid;
    };
    match m.get("method") {
        Some(Value::String(method)) => match m.get("id") {
            Some(id) => MessageKind::Request {
                id: id.clone(),
                method: method.clone(),
            },
            None => MessageKind::Notification {
                method: method.clone(),
            },
        },
        Some(_) => MessageKind::Invalid,
        None => match m.get("id") {
            Some(id) if m.contains_key("result") || m.contains_key("error") => {
                MessageKind::Response { id: id.clone() }
            }
            _ => MessageKind::Invalid,
        },
    }
}

/// Canonical map key for an id (`1` and `"1"` stay distinct).
pub fn id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

/// `{"jsonrpc":"2.0","id":..,"error":{"code":..,"message":..}}`
pub fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// `{"jsonrpc":"2.0","id":..,"result":..}`
pub fn result_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// Serialize as one protocol line (JSON + `\n`).
pub fn to_line(v: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec(v).unwrap_or_else(|_| b"null".to_vec());
    out.push(b'\n');
    out
}

/// Best-effort id extraction from the head of a message that could not be
/// parsed (oversize or malformed), so the requester can still be answered.
pub fn extract_id(head: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(head);
    let raw = ID_RE.captures(&text)?.get(1)?.as_str().to_string();
    serde_json::from_str(&raw).ok()
}

/// The `deanonymize` tool definition appended to `tools/list`.
pub fn deanonymize_tool() -> Value {
    json!({
        "name": DEANONYMIZE_TOOL_NAME,
        "description": "Reverse the anonymization applied to SIEM data during this session. \
    Pass any text containing tokens like USER_1, HOST_2, IP_INT_3, EMAIL_1, DOMAIN_INT_1, SID_1, MAC_1, etc., \
    and receive the original values substituted back in. \
    Always call this before writing the final analyst report so that usernames, \
    hostnames, and internal IPs are accurate and meaningful to the analyst.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text containing anonymization tokens to de-anonymize."
                }
            },
            "required": ["text"]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})),
            MessageKind::Request {
                id: json!(1),
                method: "tools/list".into()
            }
        );
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
            MessageKind::Notification {
                method: "notifications/initialized".into()
            }
        );
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","id":"a","result":{}})),
            MessageKind::Response { id: json!("a") }
        );
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","id":2,"error":{"code":1}})),
            MessageKind::Response { id: json!(2) }
        );
        assert_eq!(classify(&json!({"id":3})), MessageKind::Invalid);
        assert_eq!(classify(&json!({"method":5})), MessageKind::Invalid);
        assert_eq!(classify(&json!([1])), MessageKind::Invalid);
    }

    #[test]
    fn ids_and_lines() {
        assert_ne!(id_key(&json!(1)), id_key(&json!("1")));
        let line = to_line(&error_response(json!(7), PARSE_ERROR, "Parse error"));
        assert!(line.ends_with(b"\n"));
        let v: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(v["error"]["code"], PARSE_ERROR);
        assert_eq!(result_response(json!("x"), json!({}))["id"], "x");
    }

    #[test]
    fn id_extraction_from_heads() {
        assert_eq!(
            extract_id(br#"{"jsonrpc":"2.0","id":42,"result":{"content":[{"te"#),
            Some(json!(42))
        );
        assert_eq!(
            extract_id(br#"{"id": "req-\"7\"", "method":"x""#),
            Some(json!("req-\"7\""))
        );
        assert_eq!(extract_id(br#"{"jsonrpc":"2.0","result":"#), None);
        assert_eq!(extract_id(b"\xff\xfe garbage"), None);
    }

    #[test]
    fn tool_definition_shape() {
        let t = deanonymize_tool();
        assert_eq!(t["name"], "deanonymize");
        assert_eq!(t["inputSchema"]["required"], json!(["text"]));
    }
}
