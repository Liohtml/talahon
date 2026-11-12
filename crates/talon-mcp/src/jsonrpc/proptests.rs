//! Property tests for the JSON-RPC wire parsing (input comes from MCP
//! servers, i.e. from outside the trust boundary).

use proptest::prelude::*;

use super::*;

/// `cases` per property, kept small for `cargo test --workspace`; set
/// `PROPTEST_CASES` for a deeper run.
fn config(cases: u32) -> ProptestConfig {
    let default = ProptestConfig::default();
    ProptestConfig {
        cases: if std::env::var_os("PROPTEST_CASES").is_some() {
            default.cases
        } else {
            cases
        },
        failure_persistence: None,
        ..default
    }
}

/// Strings that look like JSON-RPC syntax, to put inside values.
const TRICKY: &[&str] = &[
    "\"id\":7}",
    ",\"id\":\"evil\"}",
    "{\"id\":1,\"method\":\"x\"}",
    "\\",
    "\\\"",
    "\"",
    "}",
    "]",
    "\n",
    "\u{0}",
    "id",
    "method",
    "jsonrpc",
    "ä\u{1F600}",
];

fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => any::<String>(),
        2 => "[ -~]{0,12}",
        3 => prop::collection::vec(prop::sample::select(TRICKY), 0..4)
            .prop_map(|parts| parts.concat()),
    ]
}

/// Arbitrary JSON without floats (integers, strings, bools, null, nesting).
fn json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        text().prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 24, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::vec((text(), inner), 0..5)
                .prop_map(|members| Value::Object(members.into_iter().collect())),
        ]
    })
}

fn request_id() -> impl Strategy<Value = RequestId> {
    prop_oneof![
        any::<i64>().prop_map(RequestId::Number),
        text().prop_map(RequestId::String),
    ]
}

fn rpc_error() -> impl Strategy<Value = RpcError> {
    (any::<i64>(), text(), prop::option::of(json())).prop_map(|(code, message, data)| RpcError {
        code,
        message,
        data,
    })
}

/// Every message this crate can put on the wire. (`params: null` is the
/// same message as no params, so it is not generated.)
fn message() -> impl Strategy<Value = Message> {
    let params = || prop::option::of(json().prop_filter("params: null", |v| !v.is_null()));
    prop_oneof![
        (request_id(), text(), params()).prop_map(|(id, method, params)| Message::Request {
            id,
            method,
            params
        }),
        (text(), params()).prop_map(|(method, params)| Message::Notification { method, params }),
        (request_id(), json()).prop_map(|(id, result)| Message::response(id, result)),
        (prop::option::of(request_id()), rpc_error())
            .prop_map(|(id, error)| Message::error_response(id, error)),
    ]
}

/// A JSON object with an arbitrary subset of the JSON-RPC members, each
/// holding an arbitrary (mostly wrong-typed) value.
fn rpc_shaped() -> impl Strategy<Value = Value> {
    let member = |name: &'static str, likely: BoxedStrategy<Value>| {
        prop::option::of(prop_oneof![2 => likely, 1 => json()])
            .prop_map(move |v| v.map(|v| (name.to_string(), v)))
    };
    (
        member("jsonrpc", Just(Value::from(JSONRPC_VERSION)).boxed()),
        member("id", request_id().prop_map(|id| id.to_value()).boxed()),
        member("method", text().prop_map(Value::from).boxed()),
        member("params", json().boxed()),
        member("result", json().boxed()),
        member("error", rpc_error().prop_map(|e| e.to_value()).boxed()),
        prop::collection::vec((text(), json()), 0..2),
    )
        .prop_map(|(a, b, c, d, e, f, extra)| {
            let named = [a, b, c, d, e, f].into_iter().flatten();
            Value::Object(named.chain(extra).collect())
        })
}

/// Bytes that are JSON-ish often enough to get past the first token.
fn wire_bytes() -> impl Strategy<Value = Vec<u8>> {
    let fragment = prop_oneof![
        3 => prop::collection::vec(any::<u8>(), 0..16),
        6 => prop::sample::select(
            &[
                "{", "}", "[", "]", ":", ",", "\"", "\\", "\\u", "\\ud800", " ", "\n", "\r",
                "\"id\"", "\"method\"", "\"jsonrpc\"", "\"2.0\"", "\"params\"", "\"result\"",
                "\"error\"", "null", "true", "-", "0", "9223372036854775808", "1e999", "1.5",
                "-0", "{\"id\":", "\"id\":1}", "\"id\":\"a\"}",
            ][..]
        )
        .prop_map(|s| s.as_bytes().to_vec()),
        1 => message().prop_map(|m| m.to_line().unwrap()),
    ];
    prop::collection::vec(fragment, 0..12).prop_map(|parts| parts.concat())
}

proptest! {
    #![proptest_config(config(256))]

    /// Arbitrary bytes never panic; a line that parses yields at least one
    /// entry, and `Err` means the line is not JSON at all.
    #[test]
    fn parse_line_never_panics(line in wire_bytes()) {
        match parse_line(&line) {
            Ok(entries) => {
                prop_assert!(!entries.is_empty());
                prop_assert!(serde_json::from_slice::<Value>(&line).is_ok());
            }
            Err(_) => prop_assert!(serde_json::from_slice::<Value>(&line).is_err()),
        }
    }

    /// Deeply nested input is rejected, not a stack overflow.
    #[test]
    fn deep_nesting_is_an_error_not_a_crash(depth in 1usize..20_000, open in "[\\[{]") {
        let line = open.repeat(depth);
        prop_assert!(parse_line(line.as_bytes()).is_err());
        let _ = scan_oversize(line.as_bytes(), line.as_bytes());
    }

    /// Every message survives the wire: one line, no embedded newline, and
    /// parsing it gives the same message back.
    #[test]
    fn messages_round_trip(msg in message()) {
        let line = msg.to_line().unwrap();
        prop_assert_eq!(line.last(), Some(&b'\n'));
        prop_assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
        let parsed = parse_line(&line).unwrap();
        prop_assert_eq!(parsed, vec![Ok(msg.clone())]);
        // And through the JSON value.
        prop_assert_eq!(Message::from_value(msg.to_value()), Ok(msg));
    }

    /// A batch line yields its messages in order.
    #[test]
    fn batches_round_trip(msgs in prop::collection::vec(message(), 1..5)) {
        let batch = Value::Array(msgs.iter().map(Message::to_value).collect());
        let parsed = parse_line(batch.to_string().as_bytes()).unwrap();
        prop_assert_eq!(parsed, msgs.into_iter().map(Ok).collect::<Vec<_>>());
    }

    /// Anything object-shaped is classified without panicking; what is
    /// accepted serializes back to the same message, and a rejection only
    /// ever names the id the value really carried.
    #[test]
    fn classification_is_stable(value in prop_oneof![3 => rpc_shaped(), 1 => json()]) {
        let carried_id = value.get("id").and_then(RequestId::from_value);
        match Message::from_value(value) {
            Ok(msg) => prop_assert_eq!(Message::from_value(msg.to_value()), Ok(msg)),
            Err(invalid) => {
                prop_assert!(invalid.id.is_none() || invalid.id == carried_id);
                prop_assert!(!invalid.reason.is_empty());
            }
        }
    }

    /// The oversize scanner never panics on arbitrary head/tail bytes.
    #[test]
    fn scan_oversize_never_panics(prefix in wire_bytes(), suffix in wire_bytes()) {
        let _ = scan_oversize(&prefix, &suffix);
    }

    /// For a real message cut down to its first and last bytes, the scanner
    /// recovers the top-level id or nothing — never an id from inside
    /// `params` / `result` (that would fail somebody else's request).
    #[test]
    fn scan_oversize_never_reports_a_foreign_id(
        msg in message(),
        head in any::<prop::sample::Index>(),
        tail in any::<prop::sample::Index>(),
    ) {
        let line = msg.to_line().unwrap();
        let head = head.index(line.len() + 1);
        let tail = tail.index(line.len() + 1);
        let info = scan_oversize(&line[..head], &line[line.len() - tail..]);
        let (true_id, has_method) = match &msg {
            Message::Request { id, .. } => (Some(id), true),
            Message::Notification { .. } => (None, true),
            Message::Response { id, .. } => (id.as_ref(), false),
        };
        if let Some(found) = &info.id {
            prop_assert_eq!(Some(found), true_id, "line {:?}", String::from_utf8_lossy(&line));
        }
        prop_assert!(!info.has_method || has_method);
        // With the whole line in view the id is always recovered.
        let whole = scan_oversize(&line, &line);
        prop_assert_eq!(whole.id.as_ref(), true_id);
        prop_assert_eq!(whole.has_method, has_method);
    }
}
