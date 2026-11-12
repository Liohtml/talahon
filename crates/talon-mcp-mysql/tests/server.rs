//! Tests of the MCP server without a database: the JSON-RPC protocol in
//! process (`McpServer` over `tokio::io::duplex`) on a recording backend,
//! and the real backend against sockets that are not a MySQL server.
//!
//! The expected texts are those `mysql-mcp-server` 0.4.5 returned for the
//! same calls on MySQL 8.0 (see `tests/live.rs` for the comparison on a
//! real server).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Value, json};
use talon_mcp_mysql::tools::{SINGLE_STATEMENT_ONLY, TOOL_NAMES};
use talon_mcp_mysql::{
    Backend, Config, DbError, MySqlBackend, Outcome, Rows, Truncation, build_server_with,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::net::TcpListener;

const PASSWORD: &str = "hunter2-very-secret";

type Reply = Box<dyn Fn(&str) -> Result<Outcome, DbError> + Send + Sync>;

/// A backend that records the statements it is given.
struct Recording {
    database: Option<String>,
    statements: Mutex<Vec<String>>,
    reply: Reply,
}

impl Recording {
    fn new(reply: impl Fn(&str) -> Result<Outcome, DbError> + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            database: Some("copilot".to_string()),
            statements: Mutex::new(Vec::new()),
            reply: Box::new(reply),
        })
    }

    fn statements(&self) -> Vec<String> {
        self.statements.lock().unwrap().clone()
    }
}

#[async_trait]
impl Backend for Recording {
    async fn run(&self, sql: &str) -> Result<Outcome, DbError> {
        self.statements.lock().unwrap().push(sql.to_string());
        (self.reply)(sql)
    }

    fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }
}

fn rows(columns: &[&str], data: &[&[Option<&str>]]) -> Outcome {
    Outcome::Rows(Rows {
        columns: columns.iter().map(|c| c.to_string()).collect(),
        rows: data
            .iter()
            .map(|r| r.iter().map(|c| c.map(str::to_string)).collect())
            .collect(),
        truncated: None,
    })
}

/// An MCP client talking to an in-process server.
struct Session {
    to_server: DuplexStream,
    from_server: BufReader<DuplexStream>,
    next_id: i64,
}

impl Session {
    fn start(backend: Arc<dyn Backend>) -> Self {
        let server = build_server_with(backend);
        let (to_server, server_in) = tokio::io::duplex(1 << 20);
        let (server_out, from_server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move { server.serve(server_in, server_out).await });
        Self {
            to_server,
            from_server: BufReader::new(from_server),
            next_id: 0,
        }
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

    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        let response = self.recv().await;
        assert_eq!(response["id"], id, "{response}");
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

    async fn sql(&mut self, query: &str) -> String {
        self.ok("execute_sql", json!({"query": query})).await
    }
}

#[tokio::test]
async fn protocol_initialize_list_call() {
    let backend = Recording::new(|_| Ok(rows(&["1"], &[&[Some("1")]])));
    let mut s = Session::start(backend.clone());

    let init = s
        .rpc(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}),
        )
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "talon-mysql-mcp");
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    // Tools only: no resources, no prompts.
    assert!(init["result"]["capabilities"].get("resources").is_none());
    assert!(init["result"]["capabilities"].get("prompts").is_none());
    s.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;

    let list = s.rpc("tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, TOOL_NAMES);
    assert_eq!(
        names,
        ["execute_sql", "get_schema_info", "get_table_sample"]
    );
    // execute_sql can change data; the two helpers only read.
    assert!(tools[0].get("annotations").is_none());
    assert_eq!(tools[1]["annotations"]["readOnlyHint"], true);
    assert_eq!(tools[2]["annotations"]["readOnlyHint"], true);
    assert_eq!(
        tools[0]["inputSchema"],
        json!({"type": "object", "required": ["query"], "properties": {"query": {
            "type": "string",
            "description": "The SQL statement to execute. Single statements only."}}})
    );
    assert_eq!(tools[2]["inputSchema"]["required"], json!(["table_name"]));
    assert_eq!(
        tools[2]["inputSchema"]["properties"]["limit"]["type"],
        "integer"
    );
    assert!(tools[1]["inputSchema"].get("required").is_none());

    assert_eq!(s.rpc("ping", json!({})).await["result"], json!({}));
    assert_eq!(s.sql("SELECT 1").await, "1\n1");

    for method in ["resources/list", "resources/read", "prompts/list"] {
        let response = s.rpc(method, json!({})).await;
        assert_eq!(response["error"]["code"], -32601, "{method}");
    }
    // The name used in older prompts is not a tool of either server.
    let unknown = s
        .rpc(
            "tools/call",
            json!({"name": "query", "arguments": {"query": "SELECT 1"}}),
        )
        .await;
    assert_eq!(unknown["error"]["code"], -32602);
    assert_eq!(backend.statements(), ["SELECT 1"]);
}

#[tokio::test]
async fn execute_sql_passes_the_statement_through_unchanged() {
    let backend = Recording::new(|sql| {
        Ok(if sql.to_ascii_uppercase().contains("SELECT") {
            rows(
                &["id", "alert_name", "customer_code"],
                &[
                    &[Some("1"), Some("Malware, detected"), Some("lab")],
                    &[Some("2"), Some("Line\nbreak"), None],
                ],
            )
        } else {
            Outcome::Affected(2)
        })
    });
    let mut s = Session::start(backend.clone());

    assert_eq!(
        s.sql("  SELECT id, alert_name, customer_code FROM alerts;  ")
            .await,
        "id,alert_name,customer_code\n1,Malware, detected,lab\n2,Line\nbreak,"
    );
    // Writes and DDL are not restricted here (the account's grants decide).
    let writes = [
        "INSERT INTO ai_analyst_job (alert_id, status) VALUES (7, 'running')",
        "UPDATE ai_analyst_job SET status = 'completed' WHERE alert_id = 7",
        "DELETE FROM scratch WHERE id = 1",
        "CREATE TABLE t (id INT)",
        "DROP TABLE t",
        "SET @x = 1",
        "CALL refresh_stats()",
    ];
    for statement in writes {
        assert_eq!(
            s.sql(statement).await,
            "Query executed successfully. Rows affected: 2",
            "{statement}"
        );
    }
    let mut expected = vec!["  SELECT id, alert_name, customer_code FROM alerts;  ".to_string()];
    expected.extend(writes.iter().map(|w| w.to_string()));
    assert_eq!(backend.statements(), expected);
}

#[tokio::test]
async fn result_shapes_follow_the_statement() {
    let backend = Recording::new(|sql| {
        let upper = sql.trim().to_ascii_uppercase();
        Ok(if upper.starts_with("SHOW TABLES") {
            rows(&["Tables_in_other"], &[&[Some("alerts")], &[Some("cases")]])
        } else if upper.starts_with("DESC") || upper.starts_with("SHOW FULL") {
            rows(
                &["Field", "Type", "Default"],
                &[&[Some("id"), Some("int"), None]],
            )
        } else if upper.contains("EMPTY") {
            rows(&["id"], &[])
        } else {
            rows(&["NULL"], &[&[None]])
        })
    });
    let mut s = Session::start(backend);
    // The header names the configured database, whatever was asked.
    assert_eq!(
        s.sql("show tables from other").await,
        "Tables_in_copilot\nalerts\ncases"
    );
    assert_eq!(
        s.sql("DESCRIBE alerts").await,
        "Field,Type,Default\nid,int,NULL"
    );
    assert_eq!(
        s.sql("desc alerts").await,
        "Field,Type,Default\nid,int,NULL"
    );
    assert_eq!(
        s.sql("SHOW FULL COLUMNS FROM alerts").await,
        "Field,Type,Default\nid,int,"
    );
    assert_eq!(
        s.sql("SELECT * FROM empty").await,
        "Query executed successfully. No results returned."
    );
    assert_eq!(s.sql("SELECT NULL").await, "NULL\n");
}

#[tokio::test]
async fn several_statements_are_refused_before_the_database() {
    let backend = Recording::new(|_| Ok(Outcome::Affected(0)));
    let mut s = Session::start(backend.clone());
    for query in [
        "SELECT 1; SELECT 2",
        "SELECT 1; DROP TABLE alerts",
        "; SELECT 1",
        "SELECT 1; ;",
        "USE other; SELECT 1;",
        // The Python server's check is textual: these are refused as well.
        "SELECT ';'",
        "SELECT 1 /* ; */",
        "INSERT INTO t (v) VALUES ('a;b')",
    ] {
        assert_eq!(
            s.err("execute_sql", json!({"query": query})).await,
            SINGLE_STATEMENT_ONLY,
            "{query}"
        );
    }
    assert_eq!(
        SINGLE_STATEMENT_ONLY,
        "Only single statements are supported. Instead of USE statements, use fully \
         qualified names: database.table"
    );
    assert_eq!(backend.statements(), Vec::<String>::new());

    // Trailing semicolons and whitespace are fine and are sent as they are.
    for query in ["SELECT 1;", "SELECT 1;;", "SELECT 1 ;  ", ";", "   "] {
        s.sql(query).await;
    }
    assert_eq!(
        backend.statements(),
        ["SELECT 1;", "SELECT 1;;", "SELECT 1 ;  ", ";", "   "]
    );
}

#[tokio::test]
async fn invalid_arguments_never_reach_the_database() {
    let backend = Recording::new(|_| Ok(Outcome::Affected(0)));
    let mut s = Session::start(backend.clone());
    let cases = [
        (
            "execute_sql",
            json!({}),
            "Input validation error: 'query' is a required property",
        ),
        (
            "execute_sql",
            json!({"sql": "SELECT 1"}),
            "Input validation error: 'query' is a required property",
        ),
        (
            "execute_sql",
            json!({"query": 123}),
            "Input validation error: 123 is not of type 'string'",
        ),
        (
            "execute_sql",
            json!({"query": null}),
            "Input validation error: None is not of type 'string'",
        ),
        (
            "execute_sql",
            json!({"query": ""}),
            "Error calling tool execute_sql: Query is required",
        ),
        (
            "get_schema_info",
            json!({"table_name": ["alerts"]}),
            "Input validation error: ['alerts'] is not of type 'string'",
        ),
        (
            "get_schema_info",
            json!({"table_name": "a;b"}),
            "Error calling tool get_schema_info: Invalid identifier: only alphanumeric, \
             underscore, and $ are allowed",
        ),
        (
            "get_schema_info",
            json!({"table_name": "x' OR '1'='1"}),
            "Error calling tool get_schema_info: Invalid identifier: only alphanumeric, \
             underscore, and $ are allowed",
        ),
        (
            "get_table_sample",
            json!({}),
            "Input validation error: 'table_name' is a required property",
        ),
        (
            "get_table_sample",
            json!({"table_name": "alerts", "limit": "3"}),
            "Input validation error: '3' is not of type 'integer'",
        ),
        (
            "get_table_sample",
            json!({"table_name": "alerts", "limit": 2.5}),
            "Input validation error: 2.5 is not of type 'integer'",
        ),
        (
            "get_table_sample",
            json!({"table_name": "alerts`; DROP TABLE alerts; --"}),
            "Error calling tool get_table_sample: Invalid identifier: only alphanumeric, \
             underscore, and $ are allowed",
        ),
        (
            "get_table_sample",
            json!({"table_name": "a.b.c"}),
            "Error calling tool get_table_sample: Invalid identifier: only alphanumeric, \
             underscore, and $ are allowed",
        ),
        (
            "get_table_sample",
            json!({"table_name": ""}),
            "Error calling tool get_table_sample: Invalid identifier: only alphanumeric, \
             underscore, and $ are allowed",
        ),
    ];
    for (tool, args, expected) in cases {
        assert_eq!(s.err(tool, args.clone()).await, expected, "{tool} {args}");
    }
    assert_eq!(backend.statements(), Vec::<String>::new());

    // Arguments of the wrong JSON type for `arguments` itself.
    let response = s
        .rpc(
            "tools/call",
            json!({"name": "execute_sql", "arguments": ["SELECT 1"]}),
        )
        .await;
    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(backend.statements(), Vec::<String>::new());
}

#[tokio::test]
async fn helper_tools_send_the_python_servers_statements() {
    let backend = Recording::new(|_| Ok(rows(&["COLUMN_NAME"], &[&[Some("id")]])));
    let mut s = Session::start(backend.clone());
    s.ok("get_schema_info", json!({})).await;
    s.ok("get_schema_info", json!({"table_name": ""})).await;
    s.ok("get_schema_info", json!({"table_name": "alerts"}))
        .await;
    s.ok(
        "get_schema_info",
        json!({"table_name": "copilot.alerts", "junk": 1}),
    )
    .await;
    s.ok("get_table_sample", json!({"table_name": "alerts"}))
        .await;
    s.ok(
        "get_table_sample",
        json!({"table_name": "copilot.alerts", "limit": 3}),
    )
    .await;
    s.ok(
        "get_table_sample",
        json!({"table_name": "alerts", "limit": 500}),
    )
    .await;
    s.ok(
        "get_table_sample",
        json!({"table_name": "alerts", "limit": 0}),
    )
    .await;
    let all = "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE FROM \
               information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME, \
               ORDINAL_POSITION";
    assert_eq!(
        backend.statements(),
        [
            all,
            all,
            "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT FROM \
             information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = \
             'alerts' ORDER BY ORDINAL_POSITION",
            "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT FROM \
             information_schema.COLUMNS WHERE TABLE_SCHEMA = 'copilot' AND TABLE_NAME = \
             'alerts' ORDER BY ORDINAL_POSITION",
            "SELECT * FROM `alerts` LIMIT 5",
            "SELECT * FROM `copilot`.`alerts` LIMIT 3",
            "SELECT * FROM `alerts` LIMIT 20",
            "SELECT * FROM `alerts` LIMIT 0",
        ]
    );
}

#[tokio::test]
async fn database_errors_are_tool_errors_with_the_python_wording() {
    let backend = Recording::new(|sql| {
        Err(if sql.contains("slow") {
            DbError::Timeout { secs: 120 }
        } else {
            DbError::Server("Table 'copilot.nosuch' doesn't exist".to_string())
        })
    });
    let mut s = Session::start(backend);
    assert_eq!(
        s.err("execute_sql", json!({"query": "SELECT * FROM nosuch"}))
            .await,
        "Error executing query: Table 'copilot.nosuch' doesn't exist"
    );
    assert_eq!(
        s.err("get_table_sample", json!({"table_name": "nosuch"}))
            .await,
        "Error executing query: Table 'copilot.nosuch' doesn't exist"
    );
    let text = s
        .err("execute_sql", json!({"query": "SELECT slow()"}))
        .await;
    assert!(
        text.starts_with("Error executing query: Query timed out after 120 s and was cancelled"),
        "{text}"
    );
}

#[tokio::test]
async fn truncated_results_are_marked() {
    let backend = Recording::new(|_| {
        Ok(Outcome::Rows(Rows {
            columns: vec!["id".to_string()],
            rows: vec![vec![Some("1".to_string())], vec![Some("2".to_string())]],
            truncated: Some(Truncation::Rows(2)),
        }))
    });
    let mut s = Session::start(backend);
    let text = s.sql("SELECT id FROM incident_management_alert").await;
    let (data, marker) = text.rsplit_once('\n').unwrap();
    assert_eq!(data, "id\n1\n2");
    assert!(
        marker.starts_with("[RESULT TRUNCATED: only the first 2 rows are shown"),
        "{marker}"
    );
    assert!(marker.contains("TALAHON_MYSQL_MAX_ROWS"), "{marker}");
}

// --- the real backend against things that are not a MySQL server -----------

fn config(port: u16, extra: &[(&str, &str)]) -> Config {
    let mut vars = vec![
        ("MYSQL_HOST".to_string(), "127.0.0.1".to_string()),
        ("MYSQL_PORT".to_string(), port.to_string()),
        ("MYSQL_USER".to_string(), "talahon".to_string()),
        ("MYSQL_PASSWORD".to_string(), PASSWORD.to_string()),
        ("MYSQL_DATABASE".to_string(), "copilot".to_string()),
    ];
    vars.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    Config::from_lookup(move |name| {
        vars.iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    })
    .unwrap()
}

async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test]
async fn unreachable_server_is_a_tool_error_without_credentials() {
    let port = closed_port().await;
    let backend = Arc::new(MySqlBackend::new(&config(port, &[])));
    let mut s = Session::start(backend);
    for (tool, args) in [
        ("execute_sql", json!({"query": "SELECT 1"})),
        ("get_schema_info", json!({})),
        ("get_table_sample", json!({"table_name": "alerts"})),
    ] {
        let text = s.err(tool, args).await;
        assert!(
            text.starts_with(&format!(
                "Error executing query: Can't connect to MySQL server on '127.0.0.1:{port}' ("
            )),
            "{text}"
        );
        assert!(!text.contains(PASSWORD), "{text}");
    }
}

#[tokio::test]
async fn silent_server_hits_the_connect_timeout() {
    // Accepts the TCP connection but never sends the MySQL handshake.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    let backend = Arc::new(MySqlBackend::new(&config(
        port,
        &[("MYSQL_CONNECT_TIMEOUT", "1")],
    )));
    let mut s = Session::start(backend);
    let started = Instant::now();
    let text = s.err("execute_sql", json!({"query": "SELECT 1"})).await;
    let elapsed = started.elapsed();
    assert_eq!(
        text,
        format!(
            "Error executing query: Can't connect to MySQL server on '127.0.0.1:{port}' \
             (timed out after 1 s)"
        )
    );
    assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    hold.abort();
}

#[tokio::test]
async fn a_peer_that_is_not_mysql_is_a_tool_error() {
    // Speaks HTTP at the client, then closes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let serve = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            let mut sink = [0u8; 64];
            let _ = tokio::time::timeout(Duration::from_millis(200), socket.read(&mut sink)).await;
        }
    });
    for mode in ["PREFERRED", "DISABLED"] {
        let backend = Arc::new(MySqlBackend::new(&config(
            port,
            &[("MYSQL_SSL_MODE", mode), ("MYSQL_CONNECT_TIMEOUT", "5")],
        )));
        let mut s = Session::start(backend);
        let text = s.err("execute_sql", json!({"query": "SELECT 1"})).await;
        assert!(
            text.starts_with("Error executing query: Can't connect to MySQL server on"),
            "{mode}: {text}"
        );
        assert!(!text.contains(PASSWORD), "{text}");
    }
    serve.abort();
}

/// A fake server that sends a MySQL 8 handshake **without** the TLS
/// capability and records what each client connection sent first.
async fn handshake_without_tls() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let replies = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&replies);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut payload = vec![10u8];
            payload.extend_from_slice(b"8.0.99-fake\0");
            payload.extend_from_slice(&7u32.to_le_bytes());
            payload.extend_from_slice(b"abcdefgh\0");
            // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD
            // | CLIENT_CONNECT_WITH_DB | CLIENT_TRANSACTIONS; no CLIENT_SSL (0x0800).
            payload.extend_from_slice(&0xa209u16.to_le_bytes());
            payload.push(45);
            payload.extend_from_slice(&2u16.to_le_bytes());
            // upper capabilities: CLIENT_PLUGIN_AUTH | CLIENT_DEPRECATE_EOF
            payload.extend_from_slice(&0x0108u16.to_le_bytes());
            payload.push(21);
            payload.extend_from_slice(&[0u8; 10]);
            payload.extend_from_slice(b"ijklmnopqrst\0");
            payload.extend_from_slice(b"mysql_native_password\0");
            let mut packet = Vec::new();
            packet.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes()[..3]);
            packet.push(0);
            packet.extend_from_slice(&payload);
            let _ = socket.write_all(&packet).await;
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buf))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);
            buf.truncate(n);
            seen.lock().unwrap().push(buf);
        }
    });
    (port, replies)
}

/// Empty, or the driver's `COM_QUIT` (length 1, any sequence id, command 1).
fn is_nothing_or_quit(sent: &[u8]) -> bool {
    sent.is_empty() || (sent.len() == 5 && sent[..3] == [1, 0, 0] && sent[4] == 1)
}

#[tokio::test]
async fn verifying_modes_never_fall_back_to_plaintext() {
    for mode in ["REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY"] {
        let (port, replies) = handshake_without_tls().await;
        let backend = Arc::new(MySqlBackend::new(&config(
            port,
            &[("MYSQL_SSL_MODE", mode), ("MYSQL_CONNECT_TIMEOUT", "5")],
        )));
        let mut s = Session::start(backend);
        let text = s.err("execute_sql", json!({"query": "SELECT 1"})).await;
        assert_eq!(
            text,
            format!(
                "Error executing query: SSL connection error: the MySQL server on \
                 '127.0.0.1:{port}' does not offer TLS (MYSQL_SSL_MODE={mode})"
            )
        );
        // No login (user name, password scramble) was sent in the clear: at
        // most the driver's 5-byte COM_QUIT packet.
        tokio::time::sleep(Duration::from_millis(200)).await;
        for sent in replies.lock().unwrap().iter() {
            assert!(
                is_nothing_or_quit(sent),
                "{mode}: sent without TLS: {sent:?}"
            );
        }
    }
}

#[tokio::test]
async fn preferred_mode_falls_back_to_plaintext_when_tls_is_not_offered() {
    let (port, replies) = handshake_without_tls().await;
    let backend = Arc::new(MySqlBackend::new(&config(
        port,
        &[("MYSQL_CONNECT_TIMEOUT", "5")],
    )));
    let mut s = Session::start(backend);
    // The fake server does not finish the login, so the call fails, but only
    // after the client logged in over the plaintext connection.
    let text = s.err("execute_sql", json!({"query": "SELECT 1"})).await;
    assert!(text.starts_with("Error executing query: "), "{text}");
    assert!(!text.contains(PASSWORD), "{text}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let replies = replies.lock().unwrap().clone();
    // One connection that wanted TLS and gave up without a login, and one
    // with the plaintext login packet (which names the user).
    assert!(
        replies.iter().any(|sent| is_nothing_or_quit(sent)),
        "{replies:?}"
    );
    let logins: Vec<&Vec<u8>> = replies
        .iter()
        .filter(|sent| !is_nothing_or_quit(sent))
        .collect();
    assert_eq!(logins.len(), 1, "{replies:?}");
    assert!(logins[0].windows(7).any(|w| w == b"talahon"), "{replies:?}");
    // The password itself never travels, only a scramble of it.
    assert!(
        !logins[0]
            .windows(PASSWORD.len())
            .any(|w| w == PASSWORD.as_bytes())
    );
}
