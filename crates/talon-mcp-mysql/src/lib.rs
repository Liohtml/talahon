//! # talon-mcp-mysql — native MySQL MCP server
//!
//! A stdio MCP server (`talon-mysql-mcp`) that gives the agent the CoPilot
//! MySQL database. It is a drop-in for the tools of the Python
//! `mysql-mcp-server` 0.4.5 (same tool names, argument names, input schemas,
//! statements and result text) without a Python interpreter to cold-start
//! in every agent container. See `docs/RUST_ARCHITECTURE.md` §3.3 for how
//! MCP servers run under privilege separation.
//!
//! It is **opt-in**: `mysql/mysql-mcp.sh` starts it only when
//! `TALON_MYSQL_MCP=rust` is set; the Python server stays the default.
//!
//! Module map:
//! - [`config`] — environment variables (`MYSQL_HOST`, `MYSQL_SSL_MODE`, ...)
//! - [`db`]     — one bounded statement per connection (`mysql_async`, rustls)
//! - [`pyfmt`]  — cell text as the Python server prints it
//! - [`tools`]  — the MCP tools
//!
//! Deliberate differences to the Python server:
//! - statements are bounded: connect and query timeouts, a row and a byte
//!   limit with a marked truncation ([`db`]);
//! - failures (`Error executing query: ...`, argument errors, the
//!   single-statement refusal) are flagged `isError`; the text is the same;
//! - MCP resources and prompts, the SSH tunnel and the SSE transport are
//!   not implemented, and configuration errors stop the server at start-up
//!   instead of failing every call;
//! - TLS is rustls (TLS 1.2/1.3); `REQUIRED`, `VERIFY_CA` and
//!   `VERIFY_IDENTITY` all verify chain and host name ([`config::TlsMode`]);
//! - a `SET` cell lists its members in definition order (Python's order
//!   is random).
//!
//! The protocol itself (JSON-RPC framing, `initialize`, `ping`,
//! `tools/list`, `tools/call`, cancellation, message size limits) is
//! [`talon_mcp::McpServer`].
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let config = talon_mcp_mysql::Config::from_env()?;
//! let server = talon_mcp_mysql::build_server(&config);
//! server.serve_stdio().await?;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

pub mod config;
pub mod db;
pub mod pyfmt;
pub mod tools;

use std::sync::Arc;

pub use config::{Config, ConfigError, TlsMode};
pub use db::{Backend, DbError, MySqlBackend, Outcome, Rows, Truncation};
use talon_mcp::McpServer;

/// Name reported as `serverInfo.name` in `initialize`.
pub const SERVER_NAME: &str = "talon-mysql-mcp";

/// Build the MCP server for `config`. No connection is made until a tool
/// is called, so this succeeds while the database is unreachable.
///
/// Embedders that exit right after serving should build the
/// [`MySqlBackend`] themselves, pass it to [`build_server_with`] and call
/// [`MySqlBackend::settle`] before exiting.
pub fn build_server(config: &Config) -> McpServer {
    build_server_with(Arc::new(MySqlBackend::new(config)))
}

/// Build the MCP server on any [`Backend`] (tests, embedding).
pub fn build_server_with(backend: Arc<dyn Backend>) -> McpServer {
    McpServer::builder(SERVER_NAME, env!("CARGO_PKG_VERSION"))
        .tools(tools::all_tools(backend))
        .build()
}
