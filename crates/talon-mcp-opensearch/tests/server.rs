//! End-to-end tests of the MCP server against a mock OpenSearch: the
//! JSON-RPC protocol in process (`McpServer` over `tokio::io::duplex`) and
//! every tool's HTTP request, result and error mapping.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use talon_mcp_opensearch::tools::TOOL_NAMES;
use talon_mcp_opensearch::{Config, build_server};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::net::TcpListener;
use wiremock::matchers::{any, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const USER: &str = "admin";
const PASSWORD: &str = "s3cr3t pass";
/// `base64("admin:s3cr3t pass")`.
const BASIC: &str = "Basic YWRtaW46czNjcjN0IHBhc3M=";
const DOC: &str =
    r#"{"zeta":1,"alpha":{"b":[1,2.50,"x y"],"a":null},"big":12345678901234567890,"u":"é中"}"#;

fn config(vars: &[(&str, String)]) -> Config {
    let vars: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    Config::from_lookup(move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
        .unwrap()
}

fn authed(hosts: &str) -> Vec<(&'static str, String)> {
    vec![
        ("OPENSEARCH_HOSTS", hosts.to_string()),
        ("OPENSEARCH_USERNAME", USER.to_string()),
        ("OPENSEARCH_PASSWORD", PASSWORD.to_string()),
    ]
}

/// An MCP client talking to an in-process server.
struct Session {
    to_server: DuplexStream,
    from_server: BufReader<DuplexStream>,
    next_id: i64,
}

impl Session {
    fn start(config: &Config) -> Self {
        let server = build_server(config).unwrap();
        let (to_server, server_in) = tokio::io::duplex(1 << 20);
        let (server_out, from_server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move { server.serve(server_in, server_out).await });
        Self {
            to_server,
            from_server: BufReader::new(from_server),
            next_id: 0,
        }
    }

    async fn for_hosts(hosts: &str) -> Self {
        Self::start(&config(&authed(hosts)))
    }

    async fn send(&mut self, message: Value) {
        let mut line = serde_json::to_vec(&message).unwrap();
        line.push(b'\n');
        self.to_server.write_all(&line).await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        let n = tokio::time::timeout(
            Duration::from_secs(20),
            self.from_server.read_line(&mut line),
        )
        .await
        .expect("server did not answer")
        .unwrap();
        assert!(n > 0, "server closed the connection");
        serde_json::from_str(&line).unwrap()
    }

    /// Send a request and return the whole response message.
    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        let response = self.recv().await;
        assert_eq!(response["id"], id, "{response}");
        assert_eq!(response["jsonrpc"], "2.0");
        response
    }

    /// Call a tool; returns `(text, is_error)`.
    async fn call(&mut self, name: &str, arguments: Value) -> (String, bool) {
        let response = self
            .rpc("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        let result = &response["result"];
        assert!(result.is_object(), "no result: {response}");
        let content = result["content"].as_array().unwrap();
        assert_eq!(content.len(), 1, "{response}");
        assert_eq!(content[0]["type"], "text");
        (
            content[0]["text"].as_str().unwrap().to_string(),
            result["isError"].as_bool().unwrap_or(false),
        )
    }

    async fn ok(&mut self, name: &str, arguments: Value) -> String {
        let (text, is_error) = self.call(name, arguments).await;
        assert!(!is_error, "{name} failed: {text}");
        text
    }

    async fn err(&mut self, name: &str, arguments: Value) -> String {
        let (text, is_error) = self.call(name, arguments).await;
        assert!(is_error, "{name} unexpectedly succeeded: {text}");
        text
    }
}

fn json_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(DOC, "application/json; charset=UTF-8")
}

async fn mock_json() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(json_ok())
        .mount(&server)
        .await;
    server
}

/// The single request the mock received, as `(method, raw path, query, body)`.
async fn only_request(server: &MockServer) -> Request {
    let mut requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "expected exactly one request");
    requests.remove(0)
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request.headers.get(name).and_then(|v| v.to_str().ok())
}

/// A port on localhost that refuses connections.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// --- protocol ---------------------------------------------------------------

#[tokio::test]
async fn protocol_initialize_list_call() {
    let os = mock_json().await;
    let mut s = Session::for_hosts(&os.uri()).await;

    let init = s
        .rpc(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}
            }),
        )
        .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "talon-opensearch-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    // Notifications get no response; the next response must be the ping's.
    s.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    s.send(json!({"jsonrpc": "2.0", "method": "notifications/whatever", "params": {}}))
        .await;
    assert_eq!(s.rpc("ping", json!({})).await["result"], json!({}));

    let list = s.rpc("tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, TOOL_NAMES);
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
        assert!(!tool["description"].as_str().unwrap().is_empty());
    }
    let get_document = tools.iter().find(|t| t["name"] == "get_document").unwrap();
    assert_eq!(
        get_document["inputSchema"],
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "index": {"type": "string", "description": "Name of the index"},
                "id": {"type": "string", "description": "Document ID"},
                "cluster": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "default": null,
                    "description": "Optional cluster name. Uses the default cluster if omitted."
                }
            },
            "required": ["index", "id"]
        })
    );

    let text = s
        .ok(
            "get_document",
            json!({"index": "wazuh-alerts-4.x-2026.11.12", "id": "AbC_-1"}),
        )
        .await;
    assert_eq!(text, DOC);

    // Write tools of the Python server do not exist here.
    for name in [
        "delete_index",
        "create_index",
        "index_document",
        "delete_document",
        "delete_by_query",
        "put_alias",
        "delete_alias",
        "create_data_stream",
        "delete_data_stream",
        "general_api_request",
    ] {
        let r = s
            .rpc(
                "tools/call",
                json!({"name": name, "arguments": {"index": "x"}}),
            )
            .await;
        assert!(
            r["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Unknown tool"),
            "{r}"
        );
    }

    let unknown = s.rpc("resources/list", json!({})).await;
    assert_eq!(unknown["error"]["code"], -32601);

    s.send(json!("not a request")).await;
    s.to_server
        .write_all(b"{ this is not json\n")
        .await
        .unwrap();
    assert_eq!(s.recv().await["error"]["code"], -32600);
    assert_eq!(s.recv().await["error"]["code"], -32700);
    // ... and the server is still alive.
    assert_eq!(s.rpc("ping", json!({})).await["result"], json!({}));

    // Only the one successful tool call reached OpenSearch.
    assert_eq!(os.received_requests().await.unwrap().len(), 1);
}

// --- requests ---------------------------------------------------------------

#[tokio::test]
async fn every_tool_sends_the_python_servers_request() {
    // (tool, arguments, method, raw path, body) — the paths and bodies are
    // what opensearch-mcp-server 2.1.9 (opensearch-py 2.8) puts on the wire
    // for the same arguments.
    let cases: Vec<(&str, Value, &str, &str, Option<Value>)> = vec![
        (
            "get_index",
            json!({"index": "wazuh-alerts-4.x-*"}),
            "GET",
            "/wazuh-alerts-4.x-*",
            None,
        ),
        (
            "get_index",
            json!({"index": "a,b", "cluster": null}),
            "GET",
            "/a,b",
            None,
        ),
        (
            "get_index",
            json!({"index": "_all", "cluster": "default"}),
            "GET",
            "/_all",
            None,
        ),
        (
            "search_documents",
            json!({"index": "wazuh-alerts-4.x-*", "body": {"size": 1, "query": {"match_all": {}}}}),
            "POST",
            "/wazuh-alerts-4.x-*/_search",
            Some(json!({"size": 1, "query": {"match_all": {}}})),
        ),
        (
            "search_documents",
            json!({"index": "wazuh-*", "body": "{\"size\": 2, \"aggs\": {}}"}),
            "POST",
            "/wazuh-*/_search",
            Some(json!({"size": 2, "aggs": {}})),
        ),
        (
            "get_document",
            json!({"index": "wazuh-alerts-4.x-2026.11.12", "id": "AbC_-1"}),
            "GET",
            "/wazuh-alerts-4.x-2026.11.12/_doc/AbC_-1",
            None,
        ),
        (
            "get_document",
            json!({"index": "idx", "id": "a/b c?d"}),
            "GET",
            "/idx/_doc/a%2Fb%20c%3Fd",
            None,
        ),
        (
            "get_cluster_health",
            json!({}),
            "GET",
            "/_cluster/health",
            None,
        ),
        (
            "get_cluster_stats",
            json!({"cluster": null}),
            "GET",
            "/_cluster/stats",
            None,
        ),
        (
            "get_alias",
            json!({"index": "wazuh-*"}),
            "GET",
            "/wazuh-*/_alias",
            None,
        ),
        ("get_data_stream", json!({}), "GET", "/_data_stream", None),
        (
            "get_data_stream",
            json!({"name": null}),
            "GET",
            "/_data_stream",
            None,
        ),
        (
            "get_data_stream",
            json!({"name": ""}),
            "GET",
            "/_data_stream",
            None,
        ),
        (
            "get_data_stream",
            json!({"name": "logs-*"}),
            "GET",
            "/_data_stream/logs-*",
            None,
        ),
        (
            "analyze_text",
            json!({"text": "Hello World"}),
            "POST",
            "/_analyze",
            Some(json!({"text": "Hello World"})),
        ),
        (
            "analyze_text",
            json!({"text": "Hello", "index": "idx", "analyzer": "standard", "explain": true,
                   "filter": ["lowercase"], "tokenizer": null, "char_filter": [], "attributes": null}),
            "POST",
            "/idx/_analyze",
            Some(
                json!({"text": "Hello", "analyzer": "standard", "filter": ["lowercase"], "explain": true}),
            ),
        ),
        (
            "analyze_text",
            json!({"text": "x", "index": "", "tokenizer": "keyword", "explain": false,
                   "char_filter": ["html_strip"], "attributes": ["keyword"]}),
            "POST",
            "/_analyze",
            Some(
                json!({"text": "x", "tokenizer": "keyword", "char_filter": ["html_strip"],
                        "attributes": ["keyword"]}),
            ),
        ),
    ];

    for (tool, arguments, want_method, want_path, want_body) in cases {
        let os = mock_json().await;
        let mut s = Session::for_hosts(&os.uri()).await;
        let text = s.ok(tool, arguments.clone()).await;
        assert_eq!(text, DOC, "{tool} {arguments}");

        let request = only_request(&os).await;
        assert_eq!(request.method.as_str(), want_method, "{tool} {arguments}");
        assert_eq!(request.url.path(), want_path, "{tool} {arguments}");
        assert_eq!(request.url.query(), None, "{tool} {arguments}");
        assert_eq!(header(&request, "authorization"), Some(BASIC), "{tool}");
        assert_eq!(
            header(&request, "accept"),
            Some("application/json"),
            "{tool}"
        );
        match want_body {
            Some(body) => {
                assert_eq!(header(&request, "content-type"), Some("application/json"));
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    body,
                    "{tool}"
                );
            }
            None => assert!(request.body.is_empty(), "{tool} sent a body"),
        }
    }
}

#[tokio::test]
async fn cat_tools_return_the_text_table() {
    let table = "green open wazuh-alerts-4.x-2026.11.12 abc 1 0 10 0 1mb 1mb\n";
    for (tool, want_path) in [
        ("list_indices", "/_cat/indices"),
        ("list_aliases", "/_cat/aliases"),
    ] {
        let os = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(want_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(table, "text/plain; charset=UTF-8"),
            )
            .mount(&os)
            .await;
        let mut s = Session::for_hosts(&os.uri()).await;
        assert_eq!(s.ok(tool, json!({})).await, table);
        let request = only_request(&os).await;
        assert_eq!(request.url.path(), want_path);
        assert_eq!(header(&request, "authorization"), Some(BASIC));
        assert!(request.body.is_empty());
    }
}

#[tokio::test]
async fn base_path_prefix_is_kept_and_auth_is_optional() {
    let os = mock_json().await;
    let hosts = format!("{}/os-prefix/", os.uri());
    let mut s = Session::start(&config(&[("OPENSEARCH_HOSTS", hosts)]));
    s.ok("get_document", json!({"index": "idx", "id": "1"}))
        .await;
    let request = only_request(&os).await;
    assert_eq!(request.url.path(), "/os-prefix/idx/_doc/1");
    assert_eq!(header(&request, "authorization"), None);
}

#[tokio::test]
async fn credentials_in_the_host_url_are_used_but_not_sent_in_the_url() {
    let os = mock_json().await;
    let hosts = os.uri().replace("http://", "http://admin:s3cr3t%20pass@");
    let mut s = Session::start(&config(&[("OPENSEARCH_HOSTS", hosts)]));
    s.ok("get_cluster_health", json!({})).await;
    let request = only_request(&os).await;
    assert_eq!(header(&request, "authorization"), Some(BASIC));
    assert_eq!(request.url.username(), "");
}

// --- argument validation and path injection ---------------------------------

#[tokio::test]
async fn invalid_arguments_never_reach_opensearch() {
    let os = mock_json().await;
    let mut s = Session::for_hosts(&os.uri()).await;
    let long = "a".repeat(5000);
    let cases: Vec<(&str, Value, &str)> = vec![
        ("get_index", json!({}), "missing required argument 'index'"),
        (
            "get_index",
            json!({"index": null}),
            "missing required argument 'index'",
        ),
        ("get_index", json!({"index": 5}), "'index' must be a string"),
        ("get_index", json!({"index": ""}), "index must not be empty"),
        (
            "get_index",
            json!({"index": "x", "bogus": 1}),
            "unexpected argument 'bogus'",
        ),
        ("get_index", json!({"index": long}), "index is longer than"),
        (
            "list_indices",
            json!({"index": "x"}),
            "unexpected argument 'index'",
        ),
        (
            "search_documents",
            json!({"index": "x"}),
            "missing required argument 'body'",
        ),
        (
            "search_documents",
            json!({"index": "x", "body": "not json"}),
            "'body' must be a JSON object",
        ),
        (
            "search_documents",
            json!({"index": "x", "body": [1]}),
            "'body' must be a JSON object",
        ),
        (
            "search_documents",
            json!({"index": "x", "body": "[1]"}),
            "'body' must be a JSON object",
        ),
        (
            "get_document",
            json!({"index": "x"}),
            "missing required argument 'id'",
        ),
        (
            "get_document",
            json!({"index": "x", "id": ""}),
            "id must not be empty",
        ),
        (
            "get_document",
            json!({"index": "x", "id": ".."}),
            "id must not be '.' or '..'",
        ),
        (
            "get_document",
            json!({"index": "x", "id": "a\nb"}),
            "control characters",
        ),
        (
            "get_data_stream",
            json!({"name": "_x"}),
            "name must not start with '_'",
        ),
        (
            "analyze_text",
            json!({}),
            "missing required argument 'text'",
        ),
        (
            "analyze_text",
            json!({"text": "x", "filter": "lowercase"}),
            "'filter' must be a list of strings",
        ),
        (
            "analyze_text",
            json!({"text": "x", "explain": "yes"}),
            "'explain' must be a boolean",
        ),
        (
            "analyze_text",
            json!({"text": "x", "index": "_cluster"}),
            "index must not start with '_'",
        ),
        // Index values that would address an API endpoint or step out of the segment.
        (
            "get_index",
            json!({"index": "_cat"}),
            "index must not start with '_'",
        ),
        (
            "get_index",
            json!({"index": "_cluster"}),
            "index must not start with '_'",
        ),
        (
            "get_index",
            json!({"index": "_plugins"}),
            "index must not start with '_'",
        ),
        (
            "get_index",
            json!({"index": "wazuh-*,_nodes"}),
            "index must not start with '_'",
        ),
        (
            "search_documents",
            json!({"index": "_search", "body": {}}),
            "index must not start with '_'",
        ),
        (
            "get_index",
            json!({"index": ".."}),
            "index must not be '.' or '..'",
        ),
        (
            "get_index",
            json!({"index": "."}),
            "index must not be '.' or '..'",
        ),
        (
            "get_index",
            json!({"index": "a,,b"}),
            "index must not be empty",
        ),
        (
            "get_index",
            json!({"index": "a\r\nX-Injected: 1"}),
            "control characters",
        ),
        (
            "get_index",
            json!({"index": "a\u{0}b"}),
            "control characters",
        ),
    ];
    for (tool, arguments, want) in cases {
        let text = s.err(tool, arguments.clone()).await;
        assert!(
            text.starts_with(&format!("{tool} failed: invalid argument: ")) && text.contains(want),
            "{tool} {arguments}: {text}"
        );
    }
    let text = s
        .err("get_index", json!({"index": "x", "cluster": "other"}))
        .await;
    assert_eq!(
        text,
        "get_index failed: Unknown cluster 'other'. Available clusters: default"
    );

    assert!(os.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn hostile_values_stay_inside_one_path_segment() {
    let hostile = [
        "../_cluster/settings",
        "idx/_delete_by_query",
        "idx/../../_plugins/_security/api/internalusers",
        "a?pretty&filter_path=*",
        "a#fragment",
        "a%2F..%2F_cat",
        "%2e%2e",
        "a\\..\\b",
        "//evil.example/x",
        "@evil.example",
        "a;b=c",
        "a b",
        "<logs-{now/d}>",
        "idx:8080",
    ];
    for value in hostile {
        // As an index: /{index}, /{index}/_search and /{index}/_alias.
        for (tool, arguments, segments, tail) in [
            ("get_index", json!({"index": value}), 1, ""),
            (
                "search_documents",
                json!({"index": value, "body": {}}),
                2,
                "/_search",
            ),
            ("get_alias", json!({"index": value}), 2, "/_alias"),
            ("get_data_stream", json!({"name": value}), 2, ""),
            (
                "analyze_text",
                json!({"text": "x", "index": value}),
                2,
                "/_analyze",
            ),
            // As a document id: /idx/_doc/{id}.
            ("get_document", json!({"index": "idx", "id": value}), 3, ""),
            (
                "get_document",
                json!({"index": value, "id": "1"}),
                3,
                "/_doc/1",
            ),
        ] {
            let os = mock_json().await;
            let mut s = Session::for_hosts(&os.uri()).await;
            s.ok(tool, arguments).await;
            let request = only_request(&os).await;
            let raw = request.url.path();
            assert_eq!(
                request.url.path_segments().unwrap().count(),
                segments,
                "{tool} {value:?} -> {raw}"
            );
            assert!(raw.ends_with(tail), "{tool} {value:?} -> {raw}");
            assert_eq!(request.url.query(), None, "{tool} {value:?} -> {raw}");
            assert!(
                matches!(request.method.as_str(), "GET" | "POST"),
                "{tool} {value:?}"
            );
            // The encoded segment decodes back to exactly the given value.
            let encoded = match tool {
                "get_document" if segments == 3 && tail.is_empty() => {
                    raw.rsplit('/').next().unwrap()
                }
                "get_data_stream" => raw.rsplit('/').next().unwrap(),
                _ => raw.split('/').nth(1).unwrap(),
            };
            assert!(
                !encoded.contains(['/', '?', '#', '\\', ' ', ';', '@']),
                "{tool} {value:?} -> {raw}"
            );
            assert_eq!(percent_decode(encoded), value, "{tool} -> {raw}");
        }
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

// --- errors -----------------------------------------------------------------

async fn mock_status(status: u16, body: &str, content_type: &str) -> MockServer {
    let os = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(status).set_body_raw(body, content_type))
        .mount(&os)
        .await;
    os
}

#[tokio::test]
async fn http_errors_are_mapped_like_the_python_server() {
    let not_found = r#"{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index [missing]"}],"type":"index_not_found_exception","reason":"no such index [missing]"},"status":404}"#;
    let denied = r#"{"error":{"type":"security_exception","reason":"no permissions for [indices:admin/get] and User [name=admin, backend_roles=[soc]]"},"status":403}"#;
    let cases = [
        (
            404,
            not_found,
            "application/json; charset=UTF-8",
            "get_index failed: 404\nindex_not_found_exception: no such index [missing]",
        ),
        (
            403,
            denied,
            "application/json",
            "get_index failed: 403 not authorized",
        ),
        (
            401,
            "Unauthorized",
            "text/plain",
            "get_index failed: 401 not authorized",
        ),
        (
            502,
            "<html>upstream secret-internal-hostname down</html>",
            "text/html",
            "get_index failed: 502 Bad Gateway",
        ),
        (
            400,
            r#"{"error":"Incorrect HTTP method"}"#,
            "application/json",
            "get_index failed: 400\nerror: Incorrect HTTP method",
        ),
        (
            429,
            r#"{"message":"slow down"}"#,
            "application/json",
            "get_index failed: 429 Too Many Requests",
        ),
    ];
    for (status, body, content_type, want) in cases {
        let os = mock_status(status, body, content_type).await;
        let mut s = Session::for_hosts(&os.uri()).await;
        let text = s.err("get_index", json!({"index": "missing"})).await;
        assert_eq!(text, want);
        assert!(!text.contains("secret-internal-hostname") && !text.contains("backend_roles"));
    }
}

#[tokio::test]
async fn missing_document_is_a_tool_error() {
    let os = mock_status(
        404,
        r#"{"_index":"idx","_id":"nope","found":false}"#,
        "application/json",
    )
    .await;
    let mut s = Session::for_hosts(&os.uri()).await;
    let text = s
        .err("get_document", json!({"index": "idx", "id": "nope"}))
        .await;
    assert_eq!(text, "get_document failed: 404 Not Found");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let target = mock_json().await;
    let os = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/stolen", target.uri())),
        )
        .mount(&os)
        .await;
    let mut s = Session::for_hosts(&os.uri()).await;
    let text = s.err("get_cluster_health", json!({})).await;
    assert_eq!(text, "get_cluster_health failed: 302 Found");
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn non_json_success_is_rejected_for_json_tools() {
    let os = mock_status(200, "<html>login</html>", "text/html").await;
    let mut s = Session::for_hosts(&os.uri()).await;
    let text = s.err("get_cluster_health", json!({})).await;
    assert_eq!(
        text,
        "get_cluster_health failed: invalid response from OpenSearch"
    );
}

#[tokio::test]
async fn timeouts_are_bounded_and_reported() {
    let os = MockServer::start().await;
    Mock::given(any())
        .respond_with(json_ok().set_delay(Duration::from_secs(30)))
        .mount(&os)
        .await;
    let mut vars = authed(&os.uri());
    vars.push(("REQUEST_TIMEOUT", "0.3".to_string()));
    let mut s = Session::start(&config(&vars));
    let started = Instant::now();
    let text = s
        .err("search_documents", json!({"index": "x", "body": {}}))
        .await;
    assert_eq!(text, "search_documents failed: timed out");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn unreachable_host_is_a_connection_error() {
    let hosts = format!("http://127.0.0.1:{}", closed_port().await);
    let mut s = Session::for_hosts(&hosts).await;
    let text = s.err("get_cluster_health", json!({})).await;
    assert_eq!(text, "get_cluster_health failed: connection failed");
    assert!(!text.contains("127.0.0.1"));
}

#[tokio::test]
async fn second_host_is_used_when_the_first_is_down() {
    let os = mock_json().await;
    let hosts = format!("http://127.0.0.1:{}, {}", closed_port().await, os.uri());
    let mut s = Session::for_hosts(&hosts).await;
    assert_eq!(s.ok("get_cluster_health", json!({})).await, DOC);
    assert_eq!(s.ok("get_cluster_stats", json!({})).await, DOC);
    assert_eq!(os.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn http_error_does_not_fail_over() {
    let first = mock_status(500, "{}", "application/json").await;
    let second = mock_json().await;
    let mut s = Session::for_hosts(&format!("{},{}", first.uri(), second.uri())).await;
    let text = s.err("get_cluster_health", json!({})).await;
    assert_eq!(text, "get_cluster_health failed: 500 Internal Server Error");
    assert!(second.received_requests().await.unwrap().is_empty());
}

// --- response size ----------------------------------------------------------

#[tokio::test]
async fn announced_oversize_response_is_refused() {
    let os = MockServer::start().await;
    let big = format!(r#"{{"pad":"{}"}}"#, "x".repeat(8192));
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_raw(big, "application/json"))
        .mount(&os)
        .await;
    let mut vars = authed(&os.uri());
    vars.push(("TALON_OPENSEARCH_MAX_RESPONSE_BYTES", "4096".to_string()));
    let mut s = Session::start(&config(&vars));
    let text = s
        .err("search_documents", json!({"index": "x", "body": {}}))
        .await;
    assert!(
        text.starts_with("search_documents failed: response exceeds the limit of 4096 bytes"),
        "{text}"
    );
    // A response within the same limit is returned.
    let small = mock_json().await;
    let mut vars = authed(&small.uri());
    vars.push(("TALON_OPENSEARCH_MAX_RESPONSE_BYTES", "4096".to_string()));
    let mut s = Session::start(&config(&vars));
    assert_eq!(s.ok("get_cluster_health", json!({})).await, DOC);
}

/// A server that streams an endless chunked JSON body (no Content-Length).
/// Returns its URL and a counter of the bytes it managed to send.
async fn endless_chunked_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let sent = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&sent);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counter = std::sync::Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                // Read the request head (the test requests have no large body).
                let mut head = Vec::new();
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let start = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                             transfer-encoding: chunked\r\n\r\n2\r\n[0\r\n";
                if stream.write_all(start.as_bytes()).await.is_err() {
                    return;
                }
                let chunk = format!("{:x}\r\n{}\r\n", 1024, ",0".repeat(512));
                // Would be 64 MiB if nobody stopped reading.
                for _ in 0..65536 {
                    if stream.write_all(chunk.as_bytes()).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1024, Ordering::Relaxed);
                }
            });
        }
    });
    (url, sent)
}

#[tokio::test]
async fn streamed_oversize_response_is_cut_off_without_buffering_it() {
    let (url, sent) = endless_chunked_server().await;
    let mut vars = authed(&url);
    vars.push(("TALON_OPENSEARCH_MAX_RESPONSE_BYTES", "65536".to_string()));
    let mut s = Session::start(&config(&vars));
    let text = s
        .err("search_documents", json!({"index": "x", "body": {}}))
        .await;
    assert!(
        text.starts_with("search_documents failed: response exceeds the limit of 65536 bytes"),
        "{text}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let sent = sent.load(std::sync::atomic::Ordering::Relaxed);
    assert!(sent < 16 * 1024 * 1024, "server could send {sent} bytes");
}
