//! The MCP tools of `mysql-mcp-server` 0.4.5.
//!
//! Tool names, descriptions, input schemas, the SQL each tool sends and the
//! text it returns are those of the Python server (read from its source and
//! its `tools/list`, and compared against it on a live MySQL 8.0), so
//! prompts work with either server:
//!
//! | Tool | What it runs |
//! |---|---|
//! | `execute_sql` | the statement in `query`, as is |
//! | `get_schema_info` | a query on `information_schema.COLUMNS` |
//! | `get_table_sample` | `SELECT * FROM <table> LIMIT <n>` (5 by default, 20 at most) |
//!
//! `execute_sql` runs **any** single statement the database account may run,
//! including `INSERT`/`UPDATE`/`DELETE` and DDL, exactly like the Python
//! server; what the agent can change is decided by the account's grants.
//! The only check is the Python server's: a `;` anywhere but at the end is
//! refused (also inside a string literal or a comment), because the
//! connection would accept several statements.
//!
//! Result text: a header line of column names and one line per row, cells
//! joined with `,` without quoting, each cell as Python's `str()` prints it
//! (see [`crate::pyfmt`]); `NULL` is an empty cell, or `NULL` for
//! `DESCRIBE` / `SHOW COLUMNS`.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};

use crate::db::{Backend, Outcome, Rows, Truncation};
use crate::pyfmt;

/// Names of the served tools, in `tools/list` order.
pub const TOOL_NAMES: [&str; 3] = ["execute_sql", "get_schema_info", "get_table_sample"];

/// Answer to a statement with a `;` that is not at the end.
pub const SINGLE_STATEMENT_ONLY: &str = "Only single statements are supported. \
     Instead of USE statements, use fully qualified names: database.table";
const NO_RESULTS: &str = "Query executed successfully. No results returned.";
const INVALID_IDENTIFIER: &str =
    "Invalid identifier: only alphanumeric, underscore, and $ are allowed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    ExecuteSql,
    GetSchemaInfo,
    GetTableSample,
}

const KINDS: [Kind; 3] = [Kind::ExecuteSql, Kind::GetSchemaInfo, Kind::GetTableSample];

/// JSON type of an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgType {
    String,
    Integer,
}

impl ArgType {
    fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
        }
    }

    /// JSON Schema typing as Python's `jsonschema` applies it: booleans are
    /// not integers, floats without a fraction are.
    fn matches(self, value: &Value) -> bool {
        match (self, value) {
            (Self::String, Value::String(_)) => true,
            (Self::Integer, Value::Number(n)) => {
                n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0)
            }
            _ => false,
        }
    }
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::ExecuteSql => "execute_sql",
            Self::GetSchemaInfo => "get_schema_info",
            Self::GetTableSample => "get_table_sample",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::ExecuteSql => {
                "Execute a SQL statement against the MySQL server. \
                 Use for SELECT, DML (INSERT/UPDATE/DELETE), SHOW, DESCRIBE, and ad-hoc queries. \
                 Supports cross-database queries using database.table notation. \
                 Single statements only — use fully qualified names instead of USE statements."
            }
            Self::GetSchemaInfo => {
                "Get column metadata for a table or all tables in the configured database: \
                 column names, data types, nullability, default values, and comments. \
                 Call this before querying an unfamiliar table. \
                 Omit table_name to see all tables at once. \
                 Accepts bare table names (uses MYSQL_DATABASE) or database.table for \
                 cross-database lookups."
            }
            Self::GetTableSample => {
                "Fetch a small sample of rows from a table to understand its data format and \
                 content. Use alongside get_schema_info before writing complex queries. \
                 Accepts bare table names (uses MYSQL_DATABASE) or database.table for \
                 cross-database lookups."
            }
        }
    }

    /// `(name, type, description)` of each argument, in schema order.
    fn properties(self) -> &'static [(&'static str, ArgType, &'static str)] {
        match self {
            Self::ExecuteSql => &[(
                "query",
                ArgType::String,
                "The SQL statement to execute. Single statements only.",
            )],
            Self::GetSchemaInfo => &[(
                "table_name",
                ArgType::String,
                "Optional: bare table name, or database.table for a cross-database lookup.",
            )],
            Self::GetTableSample => &[
                (
                    "table_name",
                    ArgType::String,
                    "Table to sample. Use database.table notation for cross-database queries.",
                ),
                (
                    "limit",
                    ArgType::Integer,
                    "Number of rows to return (default 5, max 20).",
                ),
            ],
        }
    }

    fn required(self) -> &'static [&'static str] {
        match self {
            Self::ExecuteSql => &["query"],
            Self::GetSchemaInfo => &[],
            Self::GetTableSample => &["table_name"],
        }
    }

    fn parameters(self) -> Value {
        let mut properties = serde_json::Map::new();
        for (name, ty, description) in self.properties() {
            properties.insert(
                (*name).to_string(),
                json!({"type": ty.name(), "description": description}),
            );
        }
        let mut schema = json!({"type": "object", "properties": properties});
        if !self.required().is_empty() {
            schema["required"] = json!(self.required());
        }
        schema
    }

    /// Check `args` against the input schema. The message is the one the
    /// Python MCP SDK returns (`jsonschema`'s best match: a missing required
    /// argument before a wrongly typed one).
    fn validate(self, args: &Value) -> Result<(), String> {
        for name in self.required() {
            if args.get(name).is_none() {
                return Err(format!(
                    "Input validation error: '{name}' is a required property"
                ));
            }
        }
        for (name, ty, _) in self.properties() {
            if let Some(value) = args.get(name)
                && !ty.matches(value)
            {
                return Err(format!(
                    "Input validation error: {} is not of type '{}'",
                    pyfmt::json_repr(value),
                    ty.name()
                ));
            }
        }
        Ok(())
    }
}

/// One MySQL tool bound to a backend.
pub struct MySqlTool {
    kind: Kind,
    backend: Arc<dyn Backend>,
}

impl std::fmt::Debug for MySqlTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySqlTool")
            .field("name", &self.kind.name())
            .finish()
    }
}

/// All tools, in `tools/list` order, sharing `backend`.
pub fn all_tools(backend: Arc<dyn Backend>) -> Vec<Arc<dyn Tool>> {
    KINDS
        .iter()
        .map(|&kind| {
            Arc::new(MySqlTool {
                kind,
                backend: Arc::clone(&backend),
            }) as Arc<dyn Tool>
        })
        .collect()
}

/// `validate_identifier`: `[a-zA-Z0-9_$]+`.
fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

/// `parse_table_arg`: an optional `database.` prefix and a table name, both
/// plain identifiers (so they can be placed in SQL).
fn parse_table_arg(name: &str) -> Result<(Option<&str>, &str), &'static str> {
    let (db, table) = match name.split_once('.') {
        Some((db, table)) => (Some(db), table),
        None => (None, name),
    };
    if db.is_some_and(|d| !is_identifier(d)) || !is_identifier(table) {
        return Err(INVALID_IDENTIFIER);
    }
    Ok((db, table))
}

/// The statement of `get_schema_info`.
fn schema_info_sql(table_name: Option<&str>) -> Result<String, &'static str> {
    // Python: `if table_name:`; an empty string means "all tables".
    let Some(table_name) = table_name.filter(|t| !t.is_empty()) else {
        return Ok("SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE \
             FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() \
             ORDER BY TABLE_NAME, ORDINAL_POSITION"
            .to_string());
    };
    let (db, table) = parse_table_arg(table_name)?;
    let schema_filter = match db {
        Some(db) => format!("TABLE_SCHEMA = '{db}'"),
        None => "TABLE_SCHEMA = DATABASE()".to_string(),
    };
    Ok(format!(
        "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT \
         FROM information_schema.COLUMNS WHERE {schema_filter} AND TABLE_NAME = '{table}' \
         ORDER BY ORDINAL_POSITION"
    ))
}

/// `min(limit, 20)` as Python prints it into the statement. A negative or
/// fractional-looking number (`-1`, `2.0`) is passed on and rejected by
/// the server, as with the Python server.
fn sample_limit(limit: Option<&Value>) -> String {
    let Some(Value::Number(n)) = limit else {
        return "5".to_string();
    };
    if let Some(i) = n.as_i64() {
        i.min(20).to_string()
    } else if n.is_u64() {
        "20".to_string()
    } else {
        match n.as_f64() {
            Some(f) if f > 20.0 => "20".to_string(),
            Some(f) => pyfmt::float_repr(f),
            None => "5".to_string(),
        }
    }
}

/// The statement of `get_table_sample`.
fn table_sample_sql(table_name: &str, limit: Option<&Value>) -> Result<String, &'static str> {
    let (db, table) = parse_table_arg(table_name)?;
    let table_ref = match db {
        Some(db) => format!("`{db}`.`{table}`"),
        None => format!("`{table}`"),
    };
    Ok(format!(
        "SELECT * FROM {table_ref} LIMIT {}",
        sample_limit(limit)
    ))
}

/// Which of the Python server's three output shapes a statement gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `SHOW TABLES...`: a `Tables_in_<db>` header and the first column.
    ShowTables,
    /// `DESCRIBE` and friends: `NULL` is spelled out.
    Describe,
    /// Everything else: `NULL` is an empty cell.
    Generic,
}

fn shape_of(query: &str) -> Shape {
    let upper = pyfmt::strip(query).to_uppercase();
    if upper.starts_with("SHOW TABLES") {
        Shape::ShowTables
    } else if [
        "DESCRIBE ",
        "DESC ",
        "SHOW COLUMNS FROM ",
        "SHOW FIELDS FROM ",
    ]
    .iter()
    .any(|prefix| upper.starts_with(prefix))
    {
        Shape::Describe
    } else {
        Shape::Generic
    }
}

fn truncation_note(rows: &Rows) -> Option<String> {
    let limit = match rows.truncated? {
        Truncation::Rows(n) => format!("{n} rows (TALON_MYSQL_MAX_ROWS)"),
        Truncation::Bytes(n) => format!("{n} bytes (TALON_MYSQL_MAX_RESULT_BYTES)"),
    };
    Some(format!(
        "[RESULT TRUNCATED: only the first {} rows are shown; the result exceeds the limit of \
         {limit}. Narrow the query with WHERE or LIMIT, or select fewer columns.]",
        rows.rows.len()
    ))
}

fn join_row(row: &[Option<String>], null: &str) -> String {
    row.iter()
        .map(|cell| cell.as_deref().unwrap_or(null))
        .collect::<Vec<_>>()
        .join(",")
}

/// Format a statement's outcome as the Python server's `run_query` does.
fn format_outcome(query: &str, outcome: &Outcome, database: Option<&str>) -> String {
    let rows = match outcome {
        Outcome::Affected(n) => return format!("Query executed successfully. Rows affected: {n}"),
        Outcome::Rows(rows) => rows,
    };
    let note = truncation_note(rows);
    let mut lines: Vec<String> = Vec::with_capacity(rows.rows.len() + 2);
    match shape_of(query) {
        Shape::ShowTables => {
            lines.push(format!("Tables_in_{}", database.unwrap_or("all databases")));
            lines.extend(
                rows.rows
                    .iter()
                    .map(|row| row.first().cloned().flatten().unwrap_or_default()),
            );
        }
        Shape::Describe => {
            lines.push(rows.columns.join(","));
            lines.extend(rows.rows.iter().map(|row| join_row(row, "NULL")));
        }
        Shape::Generic => {
            if rows.rows.is_empty() && note.is_none() {
                return NO_RESULTS.to_string();
            }
            lines.push(rows.columns.join(","));
            lines.extend(rows.rows.iter().map(|row| join_row(row, "")));
        }
    }
    lines.extend(note);
    lines.join("\n")
}

impl MySqlTool {
    async fn run_query(&self, query: &str) -> ToolOutput {
        match self.backend.run(query).await {
            Ok(outcome) => ToolOutput::ok(format_outcome(query, &outcome, self.backend.database())),
            Err(e) => ToolOutput::err(format!("Error executing query: {e}")),
        }
    }

    fn tool_error(&self, message: &str) -> ToolOutput {
        ToolOutput::err(format!(
            "Error calling tool {}: {message}",
            self.kind.name()
        ))
    }
}

#[async_trait]
impl Tool for MySqlTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.kind.name().to_string(),
            description: self.kind.description().to_string(),
            parameters: self.kind.parameters(),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        match self.kind {
            // Runs whatever statement it is given.
            Kind::ExecuteSql => ToolConcurrency::Exclusive,
            Kind::GetSchemaInfo | Kind::GetTableSample => ToolConcurrency::ReadOnly,
        }
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        if let Err(message) = self.kind.validate(&args) {
            return ToolOutput::err(message);
        }
        let text = |name: &str| args.get(name).and_then(Value::as_str);
        match self.kind {
            Kind::ExecuteSql => {
                let query = text("query").unwrap_or_default();
                if query.is_empty() {
                    return self.tool_error("Query is required");
                }
                if pyfmt::strip(query).trim_end_matches(';').contains(';') {
                    return ToolOutput::err(SINGLE_STATEMENT_ONLY);
                }
                self.run_query(query).await
            }
            Kind::GetSchemaInfo => match schema_info_sql(text("table_name")) {
                Ok(sql) => self.run_query(&sql).await,
                Err(message) => self.tool_error(message),
            },
            Kind::GetTableSample => {
                match table_sample_sql(text("table_name").unwrap_or_default(), args.get("limit")) {
                    Ok(sql) => self.run_query(&sql).await,
                    Err(message) => self.tool_error(message),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(columns: &[&str], data: &[&[Option<&str>]]) -> Rows {
        Rows {
            columns: columns.iter().map(|c| c.to_string()).collect(),
            rows: data
                .iter()
                .map(|r| r.iter().map(|c| c.map(str::to_string)).collect())
                .collect(),
            truncated: None,
        }
    }

    #[test]
    fn identifiers() {
        for ok in ["alerts", "a_b", "A1", "$x", "x$y", "9lives"] {
            assert!(is_identifier(ok), "{ok}");
        }
        for bad in [
            "", "a b", "a;b", "a-b", "a`b", "a'b", "tablé", "alerts\n", "a.b", "a\"b", "a\\b",
            "a/*", "a\0",
        ] {
            assert!(!is_identifier(bad), "{bad:?}");
        }
        assert_eq!(parse_table_arg("alerts"), Ok((None, "alerts")));
        assert_eq!(parse_table_arg("db.alerts"), Ok((Some("db"), "alerts")));
        for bad in [
            "",
            ".alerts",
            "db.",
            "a.b.c",
            "db.a b",
            "d b.a",
            "db.alerts\n",
            ".",
        ] {
            assert_eq!(parse_table_arg(bad), Err(INVALID_IDENTIFIER), "{bad:?}");
        }
    }

    #[test]
    fn schema_info_statements_are_the_python_servers() {
        let all = "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE FROM \
                   information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() ORDER BY \
                   TABLE_NAME, ORDINAL_POSITION";
        assert_eq!(schema_info_sql(None).unwrap(), all);
        assert_eq!(schema_info_sql(Some("")).unwrap(), all);
        assert_eq!(
            schema_info_sql(Some("alerts")).unwrap(),
            "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT FROM \
             information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = \
             'alerts' ORDER BY ORDINAL_POSITION"
        );
        assert_eq!(
            schema_info_sql(Some("copilot.alerts")).unwrap(),
            "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT FROM \
             information_schema.COLUMNS WHERE TABLE_SCHEMA = 'copilot' AND TABLE_NAME = \
             'alerts' ORDER BY ORDINAL_POSITION"
        );
        assert_eq!(
            schema_info_sql(Some("x' OR '1'='1")),
            Err(INVALID_IDENTIFIER)
        );
    }

    #[test]
    fn table_sample_statements_and_limits() {
        assert_eq!(
            table_sample_sql("alerts", None).unwrap(),
            "SELECT * FROM `alerts` LIMIT 5"
        );
        assert_eq!(
            table_sample_sql("db.alerts", Some(&json!(3))).unwrap(),
            "SELECT * FROM `db`.`alerts` LIMIT 3"
        );
        for (limit, expected) in [
            (json!(0), "0"),
            (json!(20), "20"),
            (json!(21), "20"),
            (json!(50), "20"),
            (json!(u64::MAX), "20"),
            (json!(1e30), "20"),
            // Passed through; the server rejects them (as with Python).
            (json!(-1), "-1"),
            (json!(2.0), "2.0"),
            (json!(20.0), "20.0"),
        ] {
            assert_eq!(sample_limit(Some(&limit)), expected, "{limit}");
        }
        assert_eq!(sample_limit(None), "5");
        assert_eq!(
            table_sample_sql("a`; DROP TABLE x; --", None),
            Err(INVALID_IDENTIFIER)
        );
    }

    #[test]
    fn validation_messages_are_jsonschemas() {
        let v = |kind: Kind, args: Value| kind.validate(&args).unwrap_err();
        assert_eq!(
            v(Kind::ExecuteSql, json!({})),
            "Input validation error: 'query' is a required property"
        );
        assert_eq!(
            v(Kind::ExecuteSql, json!({"sql": "SELECT 1"})),
            "Input validation error: 'query' is a required property"
        );
        assert_eq!(
            v(Kind::ExecuteSql, json!({"query": null})),
            "Input validation error: None is not of type 'string'"
        );
        assert_eq!(
            v(Kind::ExecuteSql, json!({"query": 123})),
            "Input validation error: 123 is not of type 'string'"
        );
        assert_eq!(
            v(Kind::ExecuteSql, json!({"query": ["SELECT 1"]})),
            "Input validation error: ['SELECT 1'] is not of type 'string'"
        );
        assert_eq!(
            v(Kind::ExecuteSql, json!({"query": true})),
            "Input validation error: True is not of type 'string'"
        );
        assert_eq!(
            v(Kind::GetTableSample, json!({"limit": 3})),
            "Input validation error: 'table_name' is a required property"
        );
        assert_eq!(
            v(
                Kind::GetTableSample,
                json!({"table_name": "a", "limit": "3"})
            ),
            "Input validation error: '3' is not of type 'integer'"
        );
        assert_eq!(
            v(
                Kind::GetTableSample,
                json!({"table_name": "a", "limit": 2.5})
            ),
            "Input validation error: 2.5 is not of type 'integer'"
        );
        assert_eq!(
            v(
                Kind::GetTableSample,
                json!({"table_name": "a", "limit": true})
            ),
            "Input validation error: True is not of type 'integer'"
        );
        assert_eq!(
            v(
                Kind::GetTableSample,
                json!({"table_name": "a", "limit": null})
            ),
            "Input validation error: None is not of type 'integer'"
        );
        // The first wrongly typed argument in schema order.
        assert_eq!(
            v(Kind::GetTableSample, json!({"limit": "x", "table_name": 7})),
            "Input validation error: 7 is not of type 'string'"
        );
        assert_eq!(
            v(Kind::GetSchemaInfo, json!({"table_name": 5})),
            "Input validation error: 5 is not of type 'string'"
        );
        // Accepted: unknown arguments, integral floats, no arguments.
        assert!(
            Kind::ExecuteSql
                .validate(&json!({"query": "x", "extra": 1}))
                .is_ok()
        );
        assert!(
            Kind::GetTableSample
                .validate(&json!({"table_name": "a", "limit": 2.0}))
                .is_ok()
        );
        assert!(Kind::GetSchemaInfo.validate(&json!({})).is_ok());
    }

    #[test]
    fn statement_shapes() {
        for q in [
            "SHOW TABLES",
            "show tables",
            "  \n show tables  ",
            "SHOW TABLES LIKE 'a%'",
            "Show Tables FROM other",
        ] {
            assert_eq!(shape_of(q), Shape::ShowTables, "{q}");
        }
        for q in [
            "DESCRIBE alerts",
            "desc alerts",
            "SHOW COLUMNS FROM alerts",
            "show fields from x",
            "DESCRIBE SELECT 1",
        ] {
            assert_eq!(shape_of(q), Shape::Describe, "{q}");
        }
        for q in [
            "SELECT 1",
            "SHOW FULL TABLES",
            "DESCRIBE\talerts",
            "SHOW FULL COLUMNS FROM alerts",
            "# comment\nSHOW TABLES",
            "EXPLAIN SELECT 1",
            "",
        ] {
            assert_eq!(shape_of(q), Shape::Generic, "{q}");
        }
    }

    #[test]
    fn generic_results() {
        let r = rows(
            &["id", "name", "note"],
            &[
                &[Some("1"), Some("a,b"), None],
                &[Some("2"), Some("x\ny"), Some("")],
            ],
        );
        assert_eq!(
            format_outcome("SELECT * FROM t", &Outcome::Rows(r), Some("db")),
            "id,name,note\n1,a,b,\n2,x\ny,"
        );
        assert_eq!(
            format_outcome(
                "SELECT 1 FROM t WHERE 0",
                &Outcome::Rows(rows(&["1"], &[])),
                None
            ),
            NO_RESULTS
        );
        assert_eq!(
            format_outcome(
                "SELECT NULL",
                &Outcome::Rows(rows(&["NULL"], &[&[None]])),
                None
            ),
            "NULL\n"
        );
        assert_eq!(
            format_outcome("UPDATE t SET a = 1", &Outcome::Affected(3), None),
            "Query executed successfully. Rows affected: 3"
        );
    }

    #[test]
    fn show_tables_and_describe_results() {
        let tables = rows(&["Tables_in_other"], &[&[Some("alerts")], &[Some("cases")]]);
        assert_eq!(
            format_outcome(
                "SHOW TABLES FROM other",
                &Outcome::Rows(tables.clone()),
                Some("copilot")
            ),
            "Tables_in_copilot\nalerts\ncases"
        );
        assert_eq!(
            format_outcome("show tables", &Outcome::Rows(tables), None),
            "Tables_in_all databases\nalerts\ncases"
        );
        assert_eq!(
            format_outcome(
                "SHOW TABLES LIKE 'zz%'",
                &Outcome::Rows(rows(&["Tables_in_x (zz%)"], &[])),
                Some("x")
            ),
            "Tables_in_x"
        );
        let described = rows(
            &["Field", "Type", "Null", "Key", "Default", "Extra"],
            &[&[
                Some("id"),
                Some("int"),
                Some("NO"),
                Some("PRI"),
                None,
                Some("auto_increment"),
            ]],
        );
        assert_eq!(
            format_outcome("DESCRIBE alerts", &Outcome::Rows(described.clone()), None),
            "Field,Type,Null,Key,Default,Extra\nid,int,NO,PRI,NULL,auto_increment"
        );
        // Not one of the special prefixes: NULL is an empty cell.
        assert_eq!(
            format_outcome(
                "SHOW FULL COLUMNS FROM alerts",
                &Outcome::Rows(described),
                None
            ),
            "Field,Type,Null,Key,Default,Extra\nid,int,NO,PRI,,auto_increment"
        );
        assert_eq!(
            format_outcome("DESC empty", &Outcome::Rows(rows(&["Field"], &[])), None),
            "Field"
        );
    }

    #[test]
    fn truncated_results_end_with_a_marker() {
        let mut r = rows(&["id"], &[&[Some("1")], &[Some("2")]]);
        r.truncated = Some(Truncation::Rows(2));
        let text = format_outcome("SELECT id FROM big", &Outcome::Rows(r.clone()), None);
        assert_eq!(
            text,
            "id\n1\n2\n[RESULT TRUNCATED: only the first 2 rows are shown; the result exceeds \
             the limit of 2 rows (TALON_MYSQL_MAX_ROWS). Narrow the query with WHERE or LIMIT, \
             or select fewer columns.]"
        );
        r.truncated = Some(Truncation::Bytes(4096));
        let text = format_outcome("SHOW TABLES", &Outcome::Rows(r.clone()), Some("d"));
        assert!(text.starts_with("Tables_in_d\n1\n2\n[RESULT TRUNCATED: only the first 2 rows"));
        assert!(text.contains("4096 bytes (TALON_MYSQL_MAX_RESULT_BYTES)"));
        // No row fitted: still the header and the marker, not "No results".
        r.rows.clear();
        let text = format_outcome("SELECT blob FROM t", &Outcome::Rows(r), None);
        assert!(
            text.starts_with("id\n[RESULT TRUNCATED: only the first 0 rows"),
            "{text}"
        );
    }

    #[test]
    fn specs_match_the_python_server() {
        // `tools/list` of mysql-mcp-server 0.4.5 (name, description, inputSchema).
        let expected = json!([
            {
                "name": "execute_sql",
                "description": "Execute a SQL statement against the MySQL server. Use for SELECT, DML (INSERT/UPDATE/DELETE), SHOW, DESCRIBE, and ad-hoc queries. Supports cross-database queries using database.table notation. Single statements only — use fully qualified names instead of USE statements.",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "The SQL statement to execute. Single statements only."}}, "required": ["query"]}
            },
            {
                "name": "get_schema_info",
                "description": "Get column metadata for a table or all tables in the configured database: column names, data types, nullability, default values, and comments. Call this before querying an unfamiliar table. Omit table_name to see all tables at once. Accepts bare table names (uses MYSQL_DATABASE) or database.table for cross-database lookups.",
                "inputSchema": {"type": "object", "properties": {"table_name": {"type": "string", "description": "Optional: bare table name, or database.table for a cross-database lookup."}}}
            },
            {
                "name": "get_table_sample",
                "description": "Fetch a small sample of rows from a table to understand its data format and content. Use alongside get_schema_info before writing complex queries. Accepts bare table names (uses MYSQL_DATABASE) or database.table for cross-database lookups.",
                "inputSchema": {"type": "object", "properties": {"table_name": {"type": "string", "description": "Table to sample. Use database.table notation for cross-database queries."}, "limit": {"type": "integer", "description": "Number of rows to return (default 5, max 20)."}}, "required": ["table_name"]}
            }
        ]);
        let actual: Vec<Value> = KINDS
            .iter()
            .map(|k| {
                json!({
                    "name": k.name(),
                    "description": k.description(),
                    "inputSchema": k.parameters(),
                })
            })
            .collect();
        assert_eq!(Value::Array(actual), expected);
        assert_eq!(KINDS.map(Kind::name), TOOL_NAMES);
    }
}
