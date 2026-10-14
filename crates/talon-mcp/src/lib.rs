//! # talon-mcp — Model Context Protocol over stdio
//!
//! **Owner: agent A03.** See `docs/RUST_ARCHITECTURE.md` §A03.
//!
//! A native (SDK-free) implementation of MCP revision `2025-06-18`:
//! JSON-RPC 2.0, one message per line, over any `AsyncRead`/`AsyncWrite`
//! pair — child-process stdio, `tokio::net::UnixStream` (the privileged
//! supervisor exposes every server on `/run/talon/mcp/<server>.sock`) or
//! `tokio::io::duplex` in tests.
//!
//! Module map:
//! - [`config`]    — `.mcp.json` parsing/validation, socket paths, `runAs`
//! - [`client`]    — [`McpClient`]: spawn / connect, handshake, tools, ping
//! - [`adapter`]   — [`McpToolAdapter`]: remote tools as `talon_core::tool::Tool`
//! - [`manager`]   — [`McpManager`]: start all servers, aggregate tools
//! - [`server`]    — [`McpServer`]: serve `Tool`s over any transport
//! - [`process`]   — child process spawning, process groups, shutdown
//! - [`bridge`]    — stdio <-> socket relay for the privileged supervisor
//! - [`transport`] — bounded, cancel-safe line framing and writer loop
//! - [`jsonrpc`]   — JSON-RPC message model
//! - [`types`]     — MCP protocol types (tools, results, content blocks)
//! - [`error`]     — [`McpError`]
//!
//! Typical agent usage:
//!
//! ```no_run
//! # async fn demo() -> Result<(), talon_mcp::McpError> {
//! use std::sync::Arc;
//! use talon_mcp::{McpConfigFile, McpManager, ManagerOptions};
//!
//! let config = McpConfigFile::load_optional("/workspace/group/.mcp.json".as_ref())?
//!     .unwrap_or_default();
//! let mut options = ManagerOptions::default()
//!     .with_socket_dir(std::env::var_os("TALON_MCP_SOCKET_DIR").map(Into::into));
//! options.reserved_tool_names = vec!["bash".into(), "read_file".into()];
//! options.adapter.post_processor = Some(Arc::new(|server, _tool, text| {
//!     format!("<untrusted_data source=\"mcp:{server}\">\n{text}\n</untrusted_data>")
//! }));
//! let manager = McpManager::start(&config, options).await;
//! let tools = manager.tools(); // Vec<Arc<dyn talon_core::tool::Tool>>
//! # drop(tools);
//! manager.shutdown_all().await;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

pub mod adapter;
pub mod bridge;
pub mod client;
pub mod config;
pub mod error;
pub mod jsonrpc;
pub mod manager;
pub mod process;
pub mod server;
pub mod transport;
pub mod types;

pub use adapter::{AdapterOptions, McpToolAdapter, ResultPostProcessor, ToolNameAllocator};
pub use client::{ClientOptions, McpClient};
pub use config::{McpConfigFile, ServerConfig, socket_path};
pub use error::McpError;
pub use manager::{LaunchMode, ManagerOptions, McpManager, ServerFailure, ServerStatus};
pub use process::SpawnOptions;
pub use server::{McpServer, McpServerBuilder};
pub use types::{CallToolResult, ContentBlock, InitializeResult, LATEST_PROTOCOL_VERSION, McpTool};
