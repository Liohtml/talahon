//! JSON-RPC 2.0 message model shared by the MCP client and server.
//!
//! MCP (spec 2025-06-18) frames every message as one line of compact JSON.
//! Parsing is deliberately lenient (a missing `"jsonrpc":"2.0"` member is
//! tolerated) but classification is strict: anything that is neither a
//! request, a notification nor a response is reported as
//! [`InvalidMessage`] so the caller can log and skip it.

use std::fmt;

use serde_json::{Map, Value, json};

/// The only JSON-RPC version MCP speaks.
pub const JSONRPC_VERSION: &str = "2.0";

/// Standard JSON-RPC (and MCP-specific) error codes.
pub mod codes {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON sent is not a valid request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist / is not available.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Invalid method parameters (also used by MCP for unknown tools).
    pub const INVALID_PARAMS: i64 = -32602;
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i64 = -32603;
    /// MCP: resource not found.
    pub const RESOURCE_NOT_FOUND: i64 = -32002;
}

/// A JSON-RPC request id. MCP forbids `null` ids.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestId {
    /// Integer id (what this crate generates).
    Number(i64),
    /// String id.
    String(String),
}

impl RequestId {
    /// Parse an id from JSON. Only integers representable as `i64` and
    /// strings are accepted.
    pub fn from_value(v: &Value) -> Option<Self> {
        match v {
            Value::Number(n) => n.as_i64().map(Self::Number),
            Value::String(s) => Some(Self::String(s.clone())),
            _ => None,
        }
    }

    /// JSON representation.
    pub fn to_value(&self) -> Value {
        match self {
            Self::Number(n) => Value::from(*n),
            Self::String(s) => Value::String(s.clone()),
        }
    }

    /// The integer value, if numeric.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::String(_) => None,
        }
    }
}

impl From<i64> for RequestId {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<&str> for RequestId {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "{s:?}"),
        }
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    /// Error code (see [`codes`]).
    pub code: i64,
    /// Human readable message.
    pub message: String,
    /// Optional structured data.
    pub data: Option<Value>,
}

impl RpcError {
    /// New error without data.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Attach `data`.
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// `-32601 Method not found`.
    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            codes::METHOD_NOT_FOUND,
            format!("Method not found: {method}"),
        )
    }

    /// `-32602 Invalid params`.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_PARAMS, message)
    }

    /// `-32600 Invalid request`.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_REQUEST, message)
    }

    /// `-32700 Parse error`.
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::new(codes::PARSE_ERROR, message)
    }

    /// `-32603 Internal error`.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(codes::INTERNAL_ERROR, message)
    }

    /// Lenient parse of an `error` member (missing fields get defaults).
    pub fn from_value(v: &Value) -> Self {
        let code = v
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or(codes::INTERNAL_ERROR);
        let message = match v.get("message") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::from("(no message)"),
        };
        Self {
            code,
            message,
            data: v.get("data").cloned(),
        }
    }

    /// JSON representation.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("code".into(), Value::from(self.code));
        m.insert("message".into(), Value::String(self.message.clone()));
        if let Some(d) = &self.data {
            m.insert("data".into(), d.clone());
        }
        Value::Object(m)
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

/// A classified JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A request expecting a response.
    Request {
        /// Request id.
        id: RequestId,
        /// Method name.
        method: String,
        /// Optional params (object or array).
        params: Option<Value>,
    },
    /// A one-way notification.
    Notification {
        /// Method name.
        method: String,
        /// Optional params.
        params: Option<Value>,
    },
    /// A response (success or error). `id` is `None` only for error
    /// responses to unparseable requests.
    Response {
        /// Id of the request this answers.
        id: Option<RequestId>,
        /// `result` or `error`.
        result: Result<Value, RpcError>,
    },
}

/// A JSON value that is not a valid JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub struct InvalidMessage {
    /// The id, if one could be recovered (so an error response can be sent).
    pub id: Option<RequestId>,
    /// Why it was rejected.
    pub reason: String,
}

impl Message {
    /// Build a request.
    pub fn request(
        id: impl Into<RequestId>,
        method: impl Into<String>,
        params: Option<Value>,
    ) -> Self {
        Self::Request {
            id: id.into(),
            method: method.into(),
            params,
        }
    }

    /// Build a notification.
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self::Notification {
            method: method.into(),
            params,
        }
    }

    /// Build a success response.
    pub fn response(id: RequestId, result: Value) -> Self {
        Self::Response {
            id: Some(id),
            result: Ok(result),
        }
    }

    /// Build an error response.
    pub fn error_response(id: Option<RequestId>, error: RpcError) -> Self {
        Self::Response {
            id,
            result: Err(error),
        }
    }

    /// Method name for requests and notifications.
    pub fn method(&self) -> Option<&str> {
        match self {
            Self::Request { method, .. } | Self::Notification { method, .. } => Some(method),
            Self::Response { .. } => None,
        }
    }

    /// JSON representation (always includes `"jsonrpc":"2.0"`).
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("jsonrpc".into(), Value::String(JSONRPC_VERSION.into()));
        match self {
            Self::Request { id, method, params } => {
                m.insert("id".into(), id.to_value());
                m.insert("method".into(), Value::String(method.clone()));
                if let Some(p) = params {
                    m.insert("params".into(), p.clone());
                }
            }
            Self::Notification { method, params } => {
                m.insert("method".into(), Value::String(method.clone()));
                if let Some(p) = params {
                    m.insert("params".into(), p.clone());
                }
            }
            Self::Response { id, result } => {
                m.insert(
                    "id".into(),
                    id.as_ref().map(RequestId::to_value).unwrap_or(Value::Null),
                );
                match result {
                    Ok(v) => {
                        m.insert("result".into(), v.clone());
                    }
                    Err(e) => {
                        m.insert("error".into(), e.to_value());
                    }
                }
            }
        }
        Value::Object(m)
    }

    /// Compact JSON terminated by `\n`, ready to be written to the wire.
    /// (`serde_json` escapes control characters, so the line never contains
    /// an embedded newline.)
    pub fn to_line(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec(&self.to_value())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Classify one JSON value.
    pub fn from_value(v: Value) -> Result<Self, InvalidMessage> {
        let Value::Object(mut obj) = v else {
            return Err(InvalidMessage {
                id: None,
                reason: "message is not a JSON object".into(),
            });
        };
        let raw_id = obj.remove("id");
        let id = raw_id.as_ref().and_then(RequestId::from_value);
        if let Some(version) = obj.get("jsonrpc") {
            if version.as_str() != Some(JSONRPC_VERSION) {
                return Err(InvalidMessage {
                    id,
                    reason: format!("unsupported jsonrpc version {version}"),
                });
            }
        }
        if let Some(method) = obj.remove("method") {
            let Value::String(method) = method else {
                return Err(InvalidMessage {
                    id,
                    reason: "method is not a string".into(),
                });
            };
            let params = obj.remove("params").filter(|p| !p.is_null());
            return match raw_id {
                None => Ok(Self::Notification { method, params }),
                Some(raw) => match id {
                    Some(id) => Ok(Self::Request { id, method, params }),
                    None => Err(InvalidMessage {
                        id: None,
                        reason: format!("invalid request id {raw}"),
                    }),
                },
            };
        }
        if let Some(err) = obj.remove("error") {
            return Ok(Self::Response {
                id,
                result: Err(RpcError::from_value(&err)),
            });
        }
        if let Some(result) = obj.remove("result") {
            return match id {
                Some(id) => Ok(Self::Response {
                    id: Some(id),
                    result: Ok(result),
                }),
                None => Err(InvalidMessage {
                    id: None,
                    reason: "response without a valid id".into(),
                }),
            };
        }
        Err(InvalidMessage {
            id,
            reason: "neither a request, a notification nor a response".into(),
        })
    }
}

/// Parse one wire line. A JSON array (legacy batch) yields one entry per
/// element; an empty batch yields a single invalid entry. Returns `Err` only
/// when the line is not JSON at all.
pub fn parse_line(line: &[u8]) -> Result<Vec<Result<Message, InvalidMessage>>, serde_json::Error> {
    let value: Value = serde_json::from_slice(line)?;
    Ok(match value {
        Value::Array(items) if items.is_empty() => vec![Err(InvalidMessage {
            id: None,
            reason: "empty batch".into(),
        })],
        Value::Array(items) => items.into_iter().map(Message::from_value).collect(),
        other => vec![Message::from_value(other)],
    })
}

/// Build `{"jsonrpc":"2.0","method":"notifications/cancelled",...}` for a
/// request that is being abandoned.
pub fn cancelled_notification(id: &RequestId, reason: &str) -> Message {
    Message::notification(
        "notifications/cancelled",
        Some(json!({ "requestId": id.to_value(), "reason": reason })),
    )
}

/// What could be recovered from the head and tail of a message that was too
/// large to buffer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OversizeInfo {
    /// The top-level `id`, if found.
    pub id: Option<RequestId>,
    /// Whether a top-level `method` member was seen (request/notification).
    pub has_method: bool,
}

/// Recover the top-level `id` (and whether a `method` member exists) from
/// the first and last bytes of an oversized JSON-RPC message, without
/// buffering it. The head is scanned with a small tokenizer that tracks
/// nesting and strings; the tail is checked for a trailing
/// `"id":<value>}` member, which (being the last member before the final
/// brace) is always top-level. Used to fail the matching pending request
/// promptly instead of letting it time out.
pub fn scan_oversize(prefix: &[u8], suffix: &[u8]) -> OversizeInfo {
    let mut info = scan_prefix(prefix);
    if info.id.is_none() {
        info.id = scan_suffix_id(suffix);
    }
    info
}

fn scan_prefix(s: &[u8]) -> OversizeInfo {
    let mut info = OversizeInfo::default();
    let mut p = Cursor { s, i: 0 };
    p.ws();
    if !p.eat(b'{') {
        return info;
    }
    loop {
        p.ws();
        let Some(key) = p.string() else {
            return info;
        };
        p.ws();
        if !p.eat(b':') {
            return info;
        }
        p.ws();
        if key == "id" {
            info.id = p.scalar_id();
            if info.id.is_none() {
                return info;
            }
        } else {
            if key == "method" {
                info.has_method = true;
            }
            if !p.skip_value() {
                return info;
            }
        }
        p.ws();
        if !p.eat(b',') {
            return info;
        }
    }
}

fn scan_suffix_id(s: &[u8]) -> Option<RequestId> {
    let mut end = s.len();
    while end > 0 && s[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 || s[end - 1] != b'}' {
        return None;
    }
    end -= 1;
    while end > 0 && s[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    // Value: integer or simple string, ending at `end`.
    let value_start;
    let id;
    if end > 0 && s[end - 1] == b'"' {
        let close = end - 1;
        let mut i = close;
        loop {
            if i == 0 {
                return None;
            }
            i -= 1;
            if s[i] == b'"' && (i == 0 || s[i - 1] != b'\\') {
                break;
            }
        }
        let text = std::str::from_utf8(&s[i + 1..close]).ok()?;
        if text.contains('\\') {
            return None;
        }
        id = RequestId::String(text.to_string());
        value_start = i;
    } else {
        let mut i = end;
        while i > 0 && (s[i - 1].is_ascii_digit() || s[i - 1] == b'-') {
            i -= 1;
        }
        if i == end {
            return None;
        }
        let n: i64 = std::str::from_utf8(&s[i..end]).ok()?.parse().ok()?;
        id = RequestId::Number(n);
        value_start = i;
    }
    let mut i = value_start;
    while i > 0 && s[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 || s[i - 1] != b':' {
        return None;
    }
    i -= 1;
    while i > 0 && s[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i < 4 || &s[i - 4..i] != b"\"id\"" {
        return None;
    }
    i -= 4;
    while i > 0 && s[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    // Must be preceded by a member separator or the opening brace.
    if i == 0 || matches!(s[i - 1], b',' | b'{') {
        Some(id)
    } else {
        None
    }
}

struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// Parse a JSON string, returning its raw (unescaped-ish) content.
    fn string(&mut self) -> Option<String> {
        if !self.eat(b'"') {
            return None;
        }
        let start = self.i;
        let mut escaped = false;
        while let Some(c) = self.peek() {
            self.i += 1;
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                let raw = &self.s[start..self.i - 1];
                return serde_json::from_slice::<String>(&self.s[start - 1..self.i])
                    .ok()
                    .or_else(|| std::str::from_utf8(raw).ok().map(str::to_string));
            }
        }
        None
    }

    fn scalar_id(&mut self) -> Option<RequestId> {
        match self.peek()? {
            b'"' => self.string().map(RequestId::String),
            b'-' | b'0'..=b'9' => {
                let start = self.i;
                while matches!(self.peek(), Some(b'-' | b'0'..=b'9')) {
                    self.i += 1;
                }
                // Reject fractional/exponent ids and ids cut off by the prefix.
                match self.peek() {
                    Some(b',' | b'}' | b' ' | b'\t' | b'\r' | b'\n') => {}
                    _ => return None,
                }
                std::str::from_utf8(&self.s[start..self.i])
                    .ok()?
                    .parse()
                    .ok()
                    .map(RequestId::Number)
            }
            _ => None,
        }
    }

    /// Skip one JSON value; false when the input ends first.
    fn skip_value(&mut self) -> bool {
        match self.peek() {
            None => false,
            Some(b'"') => self.string().is_some(),
            Some(b'{' | b'[') => {
                let mut depth = 0usize;
                while let Some(c) = self.peek() {
                    match c {
                        b'"' => {
                            if self.string().is_none() {
                                return false;
                            }
                            continue;
                        }
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                self.i += 1;
                                return true;
                            }
                        }
                        _ => {}
                    }
                    self.i += 1;
                }
                false
            }
            Some(_) => {
                while let Some(c) = self.peek() {
                    if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                        return true;
                    }
                    self.i += 1;
                }
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Result<Message, InvalidMessage> {
        let mut v = parse_line(line.as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        v.remove(0)
    }

    #[test]
    fn classifies_request_notification_response() {
        assert_eq!(
            one(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
            Ok(Message::request(1, "ping", None))
        );
        assert_eq!(
            one(r#"{"jsonrpc":"2.0","id":"a","method":"x","params":{"k":1}}"#),
            Ok(Message::request("a", "x", Some(json!({"k":1}))))
        );
        assert_eq!(
            one(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Ok(Message::notification("notifications/initialized", None))
        );
        assert_eq!(
            one(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#),
            Ok(Message::response(RequestId::Number(7), json!({})))
        );
        let err = one(r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"nope"}}"#);
        assert_eq!(
            err,
            Ok(Message::error_response(
                Some(RequestId::Number(7)),
                RpcError::new(-32601, "nope")
            ))
        );
        // null id on error response (parse error reply)
        let err = one(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"bad"}}"#);
        assert!(matches!(
            err,
            Ok(Message::Response {
                id: None,
                result: Err(_)
            })
        ));
        // missing jsonrpc tolerated
        assert!(one(r#"{"id":1,"result":true}"#).is_ok());
    }

    #[test]
    fn rejects_invalid_messages() {
        assert!(one(r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#).is_err());
        assert!(one(r#"{"jsonrpc":"2.0","id":1,"method":5}"#).is_err());
        assert!(one(r#"{"jsonrpc":"2.0","id":{"x":1},"method":"x"}"#).is_err());
        assert!(one(r#"{"jsonrpc":"2.0","result":1}"#).is_err());
        assert!(one(r#"{"jsonrpc":"2.0","id":3}"#).is_err());
        assert!(one(r#"42"#).is_err());
        let e = one(r#"{"jsonrpc":"2.0","id":3}"#).unwrap_err();
        assert_eq!(e.id, Some(RequestId::Number(3)));
        assert!(parse_line(b"{not json").is_err());
        assert!(parse_line(b"[]").unwrap()[0].is_err());
    }

    #[test]
    fn batches_are_split() {
        let v = parse_line(
            br#"[{"jsonrpc":"2.0","method":"a"},{"jsonrpc":"2.0","id":2,"result":1},3]"#,
        )
        .unwrap();
        assert_eq!(v.len(), 3);
        assert!(v[0].is_ok());
        assert!(v[1].is_ok());
        assert!(v[2].is_err());
    }

    #[test]
    fn serializes_round_trip() {
        let msgs = vec![
            Message::request(5, "tools/call", Some(json!({"name":"x"}))),
            Message::notification("n", None),
            Message::response(RequestId::String("s".into()), json!([1, 2])),
            Message::error_response(None, RpcError::parse_error("bad").with_data(json!({"a":1}))),
        ];
        for m in msgs {
            let line = m.to_line().unwrap();
            assert_eq!(*line.last().unwrap(), b'\n');
            assert!(!line[..line.len() - 1].contains(&b'\n'));
            let back = parse_line(&line[..line.len() - 1])
                .unwrap()
                .remove(0)
                .unwrap();
            assert_eq!(back, m);
        }
        // Embedded newlines are escaped.
        let m = Message::response(RequestId::Number(1), json!("a\nb"));
        let line = m.to_line().unwrap();
        assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn rpc_error_lenient_parse() {
        let e = RpcError::from_value(&json!({"message": 5}));
        assert_eq!(e.code, codes::INTERNAL_ERROR);
        assert_eq!(e.message, "5");
        let e = RpcError::from_value(&json!({}));
        assert_eq!(e.message, "(no message)");
        assert_eq!(
            RpcError::method_not_found("x").code,
            codes::METHOD_NOT_FOUND
        );
        assert_eq!(RpcError::invalid_request("x").code, codes::INVALID_REQUEST);
        assert_eq!(RpcError::internal("x").code, codes::INTERNAL_ERROR);
        assert_eq!(RpcError::invalid_params("x").to_string(), "x (-32602)");
    }

    #[test]
    fn request_id_helpers() {
        assert_eq!(RequestId::from_value(&json!(3)), Some(RequestId::Number(3)));
        assert_eq!(RequestId::from_value(&json!(1.5)), None);
        assert_eq!(RequestId::from_value(&json!(null)), None);
        assert_eq!(RequestId::Number(4).as_i64(), Some(4));
        assert_eq!(RequestId::from("x").as_i64(), None);
        assert_eq!(RequestId::from("x").to_string(), "\"x\"");
        let c = cancelled_notification(&RequestId::Number(9), "timeout");
        assert_eq!(c.to_value()["params"]["requestId"], json!(9));
        assert_eq!(c.method(), Some("notifications/cancelled"));
    }

    #[test]
    fn oversize_scan_prefix_python_order() {
        let head = br#"{"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"text","text":"aaaa"#;
        let info = scan_oversize(head, b"aaaa\"}]}}");
        assert_eq!(info.id, Some(RequestId::Number(42)));
        assert!(!info.has_method);
    }

    #[test]
    fn oversize_scan_suffix_typescript_order() {
        let head = br#"{"result":{"content":[{"type":"text","text":"aaaa"#;
        let tail = br#"aaaa"}]},"jsonrpc":"2.0","id":17}"#;
        let info = scan_oversize(head, tail);
        assert_eq!(info.id, Some(RequestId::Number(17)));
        let tail = br#"aaa"}]},"jsonrpc":"2.0","id": "req-1" } "#;
        assert_eq!(
            scan_oversize(head, tail).id,
            Some(RequestId::String("req-1".into()))
        );
    }

    #[test]
    fn oversize_scan_ignores_nested_ids() {
        // The id inside the result must not be taken for the top-level id.
        let head = br#"{"result":{"items":[{"id":5,"x":"#;
        let tail = br#"x"},{"id":6}]}}"#;
        assert_eq!(scan_oversize(head, tail).id, None);
        // Nested object ending in "id" right before two closing braces.
        let tail = br#"{"id":6}}"#;
        assert_eq!(scan_suffix_id(tail), None);
        // String containing an "id" key-like sequence in the prefix.
        let head = br#"{"result":"\"id\":9 aaaa"#;
        assert_eq!(scan_prefix(head).id, None);
    }

    #[test]
    fn oversize_scan_detects_method() {
        let head = br#"{"jsonrpc":"2.0","id":3,"method":"sampling/createMessage","params":{"x":"#;
        let info = scan_oversize(head, b"");
        assert_eq!(info.id, Some(RequestId::Number(3)));
        assert!(info.has_method);
        let head = br#"{"method":"x","params":{"a":"#;
        let info = scan_oversize(head, br#""b"},"jsonrpc":"2.0","id":4}"#);
        assert!(info.has_method);
        assert_eq!(info.id, Some(RequestId::Number(4)));
    }

    #[test]
    fn oversize_scan_garbage_is_harmless() {
        for junk in [
            &b""[..],
            b"x",
            b"{",
            b"{\"id\":",
            b"{\"id\":12",
            b"[1,2",
            b"{\"a\":[[[[\"",
        ] {
            let info = scan_oversize(junk, junk);
            assert_eq!(info.id, None, "{:?}", String::from_utf8_lossy(junk));
        }
        assert_eq!(scan_suffix_id(b"\"id\":1}"), Some(RequestId::Number(1)));
        assert_eq!(scan_suffix_id(b"x\"id\":1}"), None);
        assert_eq!(
            scan_suffix_id(br#",  "id" : -2 }"#),
            Some(RequestId::Number(-2))
        );
    }
}
