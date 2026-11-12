//! Tests of the `talahon-mysql-mcp` binary itself: the stdio loop, what it
//! prints where, its start-up checks, and (ignored unless a server is
//! provided) an end-to-end run against a real MySQL / MariaDB.
//!
//! The live tests need a database the given user may create tables in:
//!
//! ```text
//! TALAHON_MYSQL_TEST_HOST=127.0.0.1 TALAHON_MYSQL_TEST_PORT=3306 \
//! TALAHON_MYSQL_TEST_USER=talahon TALAHON_MYSQL_TEST_PASSWORD=... \
//! TALAHON_MYSQL_TEST_DATABASE=talontest \
//!     cargo test -p talahon-mcp-mysql --test stdio -- --ignored
//! ```
//!
//! Every expected result text in them was produced by `mysql-mcp-server`
//! 0.4.5 for the same statement on MySQL 8.0.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const BIN: &str = env!("CARGO_BIN_EXE_talahon-mysql-mcp");
const PASSWORD: &str = "hunter2-very-secret";

/// The binary with a clean environment (nothing inherited from the test
/// runner can configure it).
fn command() -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

/// An MCP client on the binary's stdio.
struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl Client {
    async fn start<K: AsRef<std::ffi::OsStr>>(env: &[(K, String)]) -> Self {
        let mut cmd = command();
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut client = Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        };
        let init = client
            .rpc(
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "0"}}),
            )
            .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "talon-mysql-mcp");
        client
            .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        client
    }

    async fn send(&mut self, message: Value) {
        let mut line = serde_json::to_vec(&message).unwrap();
        line.push(b'\n');
        self.stdin.as_mut().unwrap().write_all(&line).await.unwrap();
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(60), self.stdout.read_line(&mut line))
            .await
            .expect("no response from the server")
            .unwrap();
        let answer: Value = serde_json::from_str(&line).expect("stdout must be JSON lines only");
        assert_eq!(answer["id"], id, "{answer}");
        answer
    }

    /// Call a tool; returns `(text, is_error)`.
    async fn call(&mut self, name: &str, arguments: Value) -> (String, bool) {
        let response = self
            .rpc("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        let result = &response["result"];
        assert!(result.is_object(), "no result: {response}");
        (
            result["content"][0]["text"].as_str().unwrap().to_string(),
            result["isError"].as_bool().unwrap_or(false),
        )
    }

    async fn sql(&mut self, query: &str) -> String {
        let (text, is_error) = self.call("execute_sql", json!({"query": query})).await;
        assert!(!is_error, "{query} failed: {text}");
        text
    }

    async fn sql_err(&mut self, query: &str) -> String {
        let (text, is_error) = self.call("execute_sql", json!({"query": query})).await;
        assert!(is_error, "{query} unexpectedly succeeded: {text}");
        text
    }

    /// Close stdin, wait for a clean exit and return what was logged.
    async fn finish(mut self) -> String {
        drop(self.stdin.take());
        let status = tokio::time::timeout(Duration::from_secs(30), self.child.wait())
            .await
            .expect("server did not exit on EOF")
            .unwrap();
        assert!(status.success());
        let mut rest = String::new();
        self.stdout.read_to_string(&mut rest).await.unwrap();
        assert_eq!(rest, "", "nothing but responses may be written to stdout");
        let mut log = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut log)
            .await
            .unwrap();
        log
    }
}

#[tokio::test]
async fn stdio_loop_serves_initialize_list_and_call() {
    // No database: a port nobody listens on.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut client = Client::start(&[
        ("MYSQL_HOST", "127.0.0.1".to_string()),
        ("MYSQL_PORT", port.to_string()),
        ("MYSQL_USER", "talahon".to_string()),
        ("MYSQL_PASS", PASSWORD.to_string()),
        ("MYSQL_DB", "copilot".to_string()),
        ("TALAHON_MYSQL_LOG", "trace".to_string()),
    ])
    .await;

    let list = client.rpc("tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        ["execute_sql", "get_schema_info", "get_table_sample"]
    );

    // Refused before any connection is attempted.
    let (text, is_error) = client
        .call(
            "execute_sql",
            json!({"query": "SELECT 1; DROP TABLE alerts"}),
        )
        .await;
    assert!(is_error);
    assert!(
        text.starts_with("Only single statements are supported."),
        "{text}"
    );
    let (text, is_error) = client
        .call("get_table_sample", json!({"table_name": "alerts; --"}))
        .await;
    assert!(is_error);
    assert!(
        text.starts_with("Error calling tool get_table_sample: Invalid identifier"),
        "{text}"
    );

    // The database is down: a tool error, and the server keeps serving.
    let statement = "SELECT password_hash FROM users WHERE name = 'statement-marker'";
    let (text, is_error) = client
        .call("execute_sql", json!({"query": statement}))
        .await;
    assert!(is_error);
    assert!(
        text.starts_with(&format!(
            "Error executing query: Can't connect to MySQL server on '127.0.0.1:{port}' ("
        )),
        "{text}"
    );
    assert!(!text.contains(PASSWORD));
    assert_eq!(client.rpc("ping", json!({})).await["result"], json!({}));

    // Logs go to stderr and never contain the password or statements,
    // even at trace level.
    let log = client.finish().await;
    assert!(log.contains("talahon-mysql-mcp starting"), "{log}");
    assert!(log.contains("copilot"), "{log}");
    assert!(!log.contains(PASSWORD), "{log}");
    assert!(!log.contains("statement-marker"), "{log}");
    assert!(!log.contains("password_hash"), "{log}");
}

async fn run(args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String, String) {
    let mut cmd = command();
    cmd.args(args).stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = tokio::time::timeout(Duration::from_secs(30), cmd.output())
        .await
        .expect("binary did not exit")
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn bad_configuration_fails_at_startup_without_leaking_it() {
    let base = [("MYSQL_USER", "talahon"), ("MYSQL_PASSWORD", PASSWORD)];
    let cases: [(&[(&str, &str)], &str); 9] = [
        (&[("MYSQL_USER", "")], "MYSQL_USER"),
        (&[("MYSQL_PORT", "hunter2-very-secret")], "MYSQL_PORT"),
        (
            &[("MYSQL_HOST", "talahon:hunter2-very-secret@db")],
            "MYSQL_HOST",
        ),
        (&[("MYSQL_SSL_MODE", "maybe")], "MYSQL_SSL_MODE"),
        (
            &[
                ("MYSQL_SSL_MODE", "VERIFY_CA"),
                ("MYSQL_SSL_CA", "/nonexistent/ca.pem"),
            ],
            "MYSQL_SSL_CA",
        ),
        (&[("MYSQL_SSH_ENABLE", "true")], "MYSQL_SSH_ENABLE"),
        (&[("MCP_TRANSPORT", "sse")], "MCP_TRANSPORT"),
        (&[("MYSQL_CHARSET", "latin1")], "MYSQL_CHARSET"),
        (&[("TALAHON_MYSQL_MAX_ROWS", "0")], "TALAHON_MYSQL_MAX_ROWS"),
    ];
    for (extra, var) in cases {
        let mut env = base.to_vec();
        env.extend_from_slice(extra);
        for args in [&["--check"][..], &[][..]] {
            let (code, stdout, stderr) = run(args, &env).await;
            assert_eq!(code, Some(2), "{var}: {stderr}");
            assert_eq!(stdout, "", "{var}");
            assert!(
                stderr.contains("configuration error") && stderr.contains(var),
                "{stderr}"
            );
            assert!(!stderr.contains(PASSWORD), "{stderr}");
        }
    }

    // The password is required (it may be empty), under either name.
    let (code, _, stderr) = run(&["--check"], &[("MYSQL_USER", "talahon")]).await;
    assert_eq!(code, Some(2));
    assert!(stderr.contains("MYSQL_PASSWORD is required"), "{stderr}");
    for name in ["MYSQL_PASSWORD", "MYSQL_PASS"] {
        let (code, _, stderr) = run(&["--check"], &[("MYSQL_USER", "talahon"), (name, "")]).await;
        assert_eq!(code, Some(0), "{name}: {stderr}");
    }
}

#[tokio::test]
async fn check_version_help_and_unknown_arguments() {
    let (code, stdout, stderr) = run(
        &["--check"],
        &[
            ("MYSQL_HOST", "db.example"),
            ("MYSQL_USER", "talahon"),
            ("MYSQL_PASSWORD", PASSWORD),
            ("MYSQL_SSL_MODE", "DISABLED"),
            ("MYSQL_AUTH_PLUGIN", "mysql_native_password"),
        ],
    )
    .await;
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(stdout, "");
    assert!(stderr.contains("configuration OK"));
    // A plaintext connection to another machine is called out.
    assert!(stderr.contains("MYSQL_SSL_MODE=DISABLED"), "{stderr}");
    assert!(stderr.contains("MYSQL_AUTH_PLUGIN"), "{stderr}");
    assert!(!stderr.contains(PASSWORD));

    let (code, stdout, _) = run(&["--version"], &[]).await;
    assert_eq!(code, Some(0));
    assert!(stdout.starts_with("talahon-mysql-mcp "));

    // --help needs no configuration (the image smoke test relies on it).
    let (code, stdout, stderr) = run(&["--help"], &[]).await;
    assert_eq!(code, Some(0));
    assert_eq!(stderr, "");
    for var in [
        "MYSQL_HOST",
        "MYSQL_SSL_MODE",
        "TALAHON_MYSQL_QUERY_TIMEOUT",
        "TALAHON_MYSQL_MAX_ROWS",
        "TALAHON_MYSQL_MAX_RESULT_BYTES",
    ] {
        assert!(stdout.contains(var), "{var} missing from --help");
    }

    let (code, stdout, _) = run(&["--transport", "sse"], &[]).await;
    assert_eq!(code, Some(2));
    assert_eq!(stdout, "");
}

// --- live tests -----------------------------------------------------------

const LIVE: &str = "needs a MySQL server: set TALAHON_MYSQL_TEST_HOST, _PORT, _USER, _PASSWORD \
                    and _DATABASE (a database the user may create tables in)";

/// The binary's environment for the test server.
fn live_env(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let var =
        |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set: {LIVE}"));
    let mut env = vec![
        ("MYSQL_HOST".to_string(), var("TALAHON_MYSQL_TEST_HOST")),
        (
            "MYSQL_PORT".to_string(),
            std::env::var("TALAHON_MYSQL_TEST_PORT").unwrap_or_else(|_| "3306".to_string()),
        ),
        ("MYSQL_USER".to_string(), var("TALAHON_MYSQL_TEST_USER")),
        (
            "MYSQL_PASSWORD".to_string(),
            var("TALAHON_MYSQL_TEST_PASSWORD"),
        ),
        (
            "MYSQL_DATABASE".to_string(),
            var("TALAHON_MYSQL_TEST_DATABASE"),
        ),
        ("TALAHON_MYSQL_LOG".to_string(), "debug".to_string()),
    ];
    env.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    env
}

#[tokio::test]
#[ignore = "needs a MySQL server (see the module documentation)"]
async fn live_statements_results_and_errors() {
    let env = live_env(&[]);
    let database = env[4].1.clone();
    let password = env[3].1.clone();
    let table = format!("talon_mcp_e2e_{}", std::process::id());
    let mut c = Client::start(&env).await;

    // --- session, as the Python server sets it up ---
    assert_eq!(c.sql("SELECT 1").await, "1\n1");
    assert_eq!(
        c.sql("SELECT @@autocommit, @@character_set_client, @@character_set_results")
            .await,
        "@@autocommit,@@character_set_client,@@character_set_results\n1,utf8mb4,utf8mb4"
    );
    let mode = c.sql("SELECT @@sql_mode").await;
    assert!(
        mode.contains("STRICT_ALL_TABLES") && mode.contains("TRADITIONAL"),
        "{mode}"
    );
    assert_eq!(
        c.sql("SELECT DATABASE()").await,
        format!("DATABASE()\n{database}")
    );

    // --- DDL and DML go through (the account's grants decide) ---
    c.sql(&format!("DROP TABLE IF EXISTS {table}")).await;
    assert_eq!(
        c.sql(&format!(
            "CREATE TABLE {table} (
                id INT PRIMARY KEY, name VARCHAR(40) COMMENT 'display name', n INT,
                amount DECIMAL(12,4), ratio DOUBLE, created DATETIME(6), day DATE, dur TIME,
                raw VARBINARY(16), flags BIT(8), note TEXT)"
        ))
        .await,
        "Query executed successfully. Rows affected: 0"
    );
    assert_eq!(
        c.sql(&format!(
            "INSERT INTO {table} VALUES
             (1, 'Malware, detected', 7, 12.5000, 0.1, '2025-01-02 03:04:05.120000',
              '2025-01-02', '25:00:00', X'00FF4142', b'10100101', 'line\\nbreak'),
             (2, 'Ünïcödé ✓ 日本語', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
             (3, '', -1, -0.0001, 1e20, '2025-01-02 03:04:05', '1000-01-01', '-00:00:05',
              X'', b'0', '')"
        ))
        .await,
        "Query executed successfully. Rows affected: 3"
    );
    assert_eq!(
        c.sql(&format!("UPDATE {table} SET n = n + 1 WHERE id IN (1, 3)"))
            .await,
        "Query executed successfully. Rows affected: 2"
    );
    // Rows matched but not changed are not counted.
    assert_eq!(
        c.sql(&format!("UPDATE {table} SET n = n WHERE id IN (1, 3)"))
            .await,
        "Query executed successfully. Rows affected: 0"
    );

    // --- every cell as Python's str() prints it; no quoting; NULL is empty ---
    assert_eq!(
        c.sql(&format!("SELECT * FROM {table} ORDER BY id")).await,
        "id,name,n,amount,ratio,created,day,dur,raw,flags,note\n\
         1,Malware, detected,8,12.5000,0.1,2025-01-02 03:04:05.120000,2025-01-02,\
         1 day, 1:00:00,b'\\x00\\xffAB',165,line\nbreak\n\
         2,Ünïcödé ✓ 日本語,,,,,,,,,\n\
         3,,0,-0.0001,1e+20,2025-01-02 03:04:05,1000-01-01,-1 day, 23:59:55,b'',0,"
    );
    assert_eq!(
        c.sql(&format!("SELECT id FROM {table} WHERE id > 100"))
            .await,
        "Query executed successfully. No results returned."
    );
    assert_eq!(
        c.sql("SELECT NULL, 1.50, 1/3, 0x4142, 'a,b', TRUE").await,
        "NULL,1.50,1/3,0x4142,a,b,TRUE\n,1.50,0.3333,b'AB',a,b,1"
    );

    // --- SHOW TABLES / DESCRIBE shapes ---
    let tables = c.sql(&format!("SHOW TABLES LIKE '{table}'")).await;
    assert_eq!(tables, format!("Tables_in_{database}\n{table}"));
    let described = c.sql(&format!("DESCRIBE {table}")).await;
    let mut lines = described.lines();
    assert_eq!(lines.next(), Some("Field,Type,Null,Key,Default,Extra"));
    // "int" on MySQL 8, "int(11)" on MariaDB and MySQL 5.7.
    let id = lines.next().unwrap();
    assert!(
        id.starts_with("id,int") && id.ends_with(",NO,PRI,NULL,"),
        "{id}"
    );
    assert!(described.contains("\nnote,text,YES,,NULL,"), "{described}");

    // --- the helper tools ---
    let (schema, is_error) = c
        .call("get_schema_info", json!({"table_name": table}))
        .await;
    assert!(!is_error, "{schema}");
    // (MariaDB reports the default of a nullable column as the text "NULL".)
    assert!(
        schema.starts_with(
            "COLUMN_NAME,DATA_TYPE,IS_NULLABLE,COLUMN_DEFAULT,COLUMN_COMMENT\nid,int,NO,,\n\
             name,varchar,YES,"
        ) && schema.contains(",display name\nn,int,YES,"),
        "{schema}"
    );
    let (qualified, _) = c
        .call(
            "get_schema_info",
            json!({"table_name": format!("{database}.{table}")}),
        )
        .await;
    assert_eq!(qualified, schema);
    let (all, _) = c.call("get_schema_info", json!({})).await;
    assert!(
        all.starts_with("TABLE_NAME,COLUMN_NAME,DATA_TYPE,IS_NULLABLE\n"),
        "{all}"
    );
    assert!(all.contains(&format!("\n{table},id,int,NO\n")), "{all}");
    let (sample, is_error) = c
        .call("get_table_sample", json!({"table_name": table, "limit": 1}))
        .await;
    assert!(!is_error, "{sample}");
    assert!(
        sample.starts_with("id,name,n,amount,") && sample.contains("\n1,Malware, detected,8,"),
        "{sample}"
    );
    assert!(!sample.contains("\n2,"), "more than one row: {sample}");
    let (sample, _) = c
        .call("get_table_sample", json!({"table_name": table}))
        .await;
    for row in ["\n1,Malware", "\n2,Ünïcödé", "\n3,,0,"] {
        assert!(sample.contains(row), "{row:?} missing: {sample}");
    }

    // --- errors: the server's message, flagged as an error ---
    assert_eq!(
        c.sql_err(&format!("SELECT * FROM {table}_nosuch")).await,
        format!("Error executing query: Table '{database}.{table}_nosuch' doesn't exist")
    );
    let text = c.sql_err("SELEC 1").await;
    assert!(
        text.starts_with("Error executing query: You have an error in your SQL syntax"),
        "{text}"
    );
    let text = c
        .sql_err(&format!("INSERT INTO {table} (id) VALUES (1)"))
        .await;
    assert!(
        text.starts_with("Error executing query: Duplicate entry '1' for key"),
        "{text}"
    );
    // Strict mode (TRADITIONAL): no silent truncation.
    let text = c
        .sql_err(&format!(
            "INSERT INTO {table} (id, name) VALUES (9, REPEAT('x', 100))"
        ))
        .await;
    assert!(
        text.starts_with("Error executing query: Data too long for column 'name'"),
        "{text}"
    );
    let (text, is_error) = c
        .call(
            "get_table_sample",
            json!({"table_name": table, "limit": -1}),
        )
        .await;
    assert!(
        is_error && text.starts_with("Error executing query: You have an error"),
        "{text}"
    );

    // --- one statement per call, nothing carries over ---
    let text = c.sql_err(&format!("SELECT 1; DROP TABLE {table}")).await;
    assert!(
        text.starts_with("Only single statements are supported."),
        "{text}"
    );
    assert_eq!(
        c.sql("SET @talon_e2e = 5").await,
        "Query executed successfully. Rows affected: 0"
    );
    assert_eq!(c.sql("SELECT @talon_e2e").await, "@talon_e2e\n");
    c.sql("START TRANSACTION").await;
    c.sql(&format!("DELETE FROM {table} WHERE id = 2")).await;
    c.sql("ROLLBACK").await;
    // Autocommit: the DELETE was its own transaction.
    assert_eq!(
        c.sql(&format!("SELECT COUNT(*) FROM {table}")).await,
        "COUNT(*)\n2"
    );

    // --- no file of this process can be requested by the server ---
    let text = c
        .sql_err(&format!(
            "LOAD DATA LOCAL INFILE '/etc/hostname' INTO TABLE {table} (name)"
        ))
        .await;
    assert!(text.starts_with("Error executing query: "), "{text}");
    assert_eq!(
        c.sql(&format!("SELECT COUNT(*) FROM {table}")).await,
        "COUNT(*)\n2"
    );

    assert_eq!(
        c.sql(&format!("DROP TABLE {table}")).await,
        "Query executed successfully. Rows affected: 0"
    );
    let log = c.finish().await;
    assert!(
        !log.contains(&password) || password.len() < 4,
        "password in the log"
    );
    assert!(!log.contains("Malware, detected"), "result data in the log");
    assert!(!log.contains("INSERT INTO"), "statements in the log");
}

#[tokio::test]
#[ignore = "needs a MySQL server (see the module documentation)"]
async fn live_limits_and_timeouts() {
    let table = format!("talon_mcp_e2e_big_{}", std::process::id());
    let mut setup = Client::start(&live_env(&[])).await;
    setup.sql(&format!("DROP TABLE IF EXISTS {table}")).await;
    setup
        .sql(&format!(
            "CREATE TABLE {table} (id INT PRIMARY KEY, pad VARCHAR(120))"
        ))
        .await;
    setup
        .sql(&format!(
            "INSERT INTO {table} SELECT a.n + 10 * b.n + 100 * c.n, REPEAT('x', 100) FROM
             (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION
              SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) a,
             (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION
              SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) b,
             (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION
              SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) c"
        ))
        .await;

    // Row limit: the first rows and a marker; an exact fit is not marked.
    let mut c = Client::start(&live_env(&[("TALAHON_MYSQL_MAX_ROWS", "10")])).await;
    let text = c.sql(&format!("SELECT id FROM {table} ORDER BY id")).await;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        &lines[..11],
        ["id", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    );
    assert_eq!(lines.len(), 12, "{text}");
    assert!(
        lines[11].starts_with("[RESULT TRUNCATED: only the first 10 rows are shown")
            && lines[11].contains("10 rows (TALAHON_MYSQL_MAX_ROWS)"),
        "{text}"
    );
    let text = c
        .sql(&format!("SELECT id FROM {table} ORDER BY id LIMIT 10"))
        .await;
    assert_eq!(text.lines().count(), 11, "{text}");
    assert!(!text.contains("TRUNCATED"));
    c.finish().await;

    // Byte limit: bounded output whatever the table size.
    let mut c = Client::start(&live_env(&[("TALAHON_MYSQL_MAX_RESULT_BYTES", "4096")])).await;
    let text = c.sql(&format!("SELECT * FROM {table} ORDER BY id")).await;
    assert!(text.len() < 4096 + 400, "{} bytes", text.len());
    assert!(text.starts_with("id,pad\n0,xxxx"), "{}", &text[..40]);
    let marker = text.lines().last().unwrap();
    assert!(
        marker.starts_with("[RESULT TRUNCATED:")
            && marker.contains("4096 bytes (TALAHON_MYSQL_MAX_RESULT_BYTES)"),
        "{marker}"
    );
    // The server keeps answering after a truncated result.
    assert_eq!(
        c.sql(&format!("SELECT COUNT(*) FROM {table}")).await,
        "COUNT(*)\n1000"
    );
    c.finish().await;

    // Query timeout: reported, and the statement is killed on the server.
    let mut c = Client::start(&live_env(&[("TALAHON_MYSQL_QUERY_TIMEOUT", "1")])).await;
    let started = Instant::now();
    let text = c.sql_err("SELECT SLEEP(30) AS talon_e2e_sleeper").await;
    assert!(
        text.starts_with("Error executing query: Query timed out after 1 s and was cancelled"),
        "{text}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
    let running = c
        .sql(
            "SELECT COUNT(*) FROM information_schema.processlist \
             WHERE info LIKE '%talon_e2e_sleeper%' AND info NOT LIKE '%processlist%'",
        )
        .await;
    assert_eq!(
        running, "COUNT(*)\n0",
        "the timed-out statement is still running"
    );
    // A timed-out change is rolled back, not half applied.
    let text = c
        .sql_err(&format!(
            "UPDATE {table} SET pad = CONCAT('y', SLEEP(1)) WHERE id < 5"
        ))
        .await;
    assert!(text.contains("timed out"), "{text}");
    c.finish().await;

    let mut check = Client::start(&live_env(&[])).await;
    // Wait out the server-side rollback of the killed UPDATE.
    let mut changed = String::new();
    for _ in 0..20 {
        let (text, is_error) = check
            .call(
                "execute_sql",
                json!({"query": format!("SELECT COUNT(*) FROM {table} WHERE pad LIKE 'y%'")}),
            )
            .await;
        if !is_error {
            changed = text;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(changed, "COUNT(*)\n0");
    check.sql(&format!("DROP TABLE {table}")).await;
    check.finish().await;
    setup.finish().await;
}
