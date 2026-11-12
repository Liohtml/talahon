//! # talon-mcp-opensearch — native OpenSearch MCP server
//!
//! A stdio MCP server (`talon-opensearch-mcp`) that gives the agent
//! read-only access to an OpenSearch / Wazuh-indexer cluster. It is a
//! drop-in for the read-only tools of the Python `opensearch-mcp-server`
//! (same tool names, argument names, input schemas, result text and error
//! wording) without a Python interpreter to cold-start in every agent
//! container. See `docs/RUST_ARCHITECTURE.md` §3.3 for how MCP servers run
//! under privilege separation.
//!
//! It is **opt-in**: `siem/opensearch-mcp.sh` starts it only when
//! `TALON_OPENSEARCH_MCP=rust` is set; the Python server stays the default.
//!
//! Module map:
//! - [`config`] — environment variables (`OPENSEARCH_HOSTS`, `VERIFY_CERTS`, ...)
//! - [`client`] — bounded, read-only HTTP client
//! - [`path`]   — validation and encoding of model-supplied path segments
//! - [`tools`]  — the MCP tools
//! - [`error`]  — tool errors and caller-safe messages
//!
//! The protocol itself (JSON-RPC framing, `initialize`, `ping`,
//! `tools/list`, `tools/call`, cancellation, message size limits) is
//! [`talon_mcp::McpServer`].
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let config = talon_mcp_opensearch::Config::from_env()?;
//! let server = talon_mcp_opensearch::build_server(&config)?;
//! server.serve_stdio().await?;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

pub mod client;
pub mod config;
pub mod error;
pub mod path;
pub mod tools;

use std::sync::Arc;

pub use client::OpenSearchClient;
pub use config::{Config, ConfigError};
pub use error::ToolError;
use talon_mcp::McpServer;

/// Name reported as `serverInfo.name` in `initialize`.
pub const SERVER_NAME: &str = "talon-opensearch-mcp";

/// Build the MCP server for `config`. No request is made until a tool is
/// called, so this succeeds while the cluster is unreachable.
pub fn build_server(config: &Config) -> Result<McpServer, ConfigError> {
    let client = Arc::new(OpenSearchClient::new(config)?);
    Ok(McpServer::builder(SERVER_NAME, env!("CARGO_PKG_VERSION"))
        .tools(tools::all_tools(client))
        .build())
}
