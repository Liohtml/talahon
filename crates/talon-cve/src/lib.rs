//! # talon-cve — offline CVE, EPSS and KEV data for the agent
//!
//! The agent container has no route to the internet (see
//! `docs/RUST_ARCHITECTURE.md` §3.3 and the egress firewall). This crate
//! lets it answer vulnerability questions anyway:
//!
//! - the **host** downloads the NVD data feeds, the EPSS scores and the CISA
//!   KEV catalogue once a day (`talahon cve sync`) and builds one SQLite
//!   file from them ([`import`], [`store::Writer`]);
//! - the **container** gets that file on a read-only mount, and the MCP
//!   server `talahon-cve-mcp` ([`tools`], [`store::Reader`]) answers from it.
//!   The server opens no socket: it links no HTTP client and no resolver.
//!
//! Module map:
//! - [`model`]  — the records
//! - [`import`] — parsers of the three sources (streaming, size-capped,
//!   checksum-verified where the source publishes one)
//! - [`store`]  — the SQLite schema, the writer and the read-only queries
//! - [`tools`]  — the MCP tools
//!
//! The download itself (which hosts, redirects, limits, the atomic swap of
//! the file) lives in the host binary (`talahon cve sync`), so that nothing
//! in this crate can reach the network.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let config = talon_cve::Config::from_env();
//! let server = talon_cve::build_server(&config);
//! server.serve_stdio().await?;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

pub mod import;
pub mod model;
pub mod store;
pub mod tools;

use std::path::PathBuf;

use talon_mcp::McpServer;

/// Name reported as `serverInfo.name` in `initialize`.
pub const SERVER_NAME: &str = "talahon-cve-mcp";

/// File name of the database inside its directory.
pub const DB_FILE_NAME: &str = "cve.sqlite";
/// Directory of the database below the Talahon project root. `cve-mcp/` is
/// the folder the agent container already mounts read-only for the CVE
/// server's wrapper, so the file needs no mount of its own.
pub const DB_DIR: &str = "cve-mcp/data";
/// Setting: path of the database file (host: `.env`; server: environment).
pub const DB_PATH_ENV: &str = "TALAHON_CVE_DB";
/// Setting: age in days from which the tools warn that the data is stale.
pub const MAX_AGE_ENV: &str = "TALAHON_CVE_MAX_AGE_DAYS";
/// Default of [`MAX_AGE_ENV`]: the sync runs daily, so three days means it
/// failed at least twice.
pub const DEFAULT_MAX_AGE_DAYS: i64 = 3;

/// Default database path below `project_root`.
pub fn default_db_path(project_root: &std::path::Path) -> PathBuf {
    project_root.join(DB_DIR).join(DB_FILE_NAME)
}

/// Configuration of the MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The database file.
    pub db_path: PathBuf,
    /// Age in days from which answers carry a staleness warning.
    pub max_age_days: i64,
}

impl Config {
    /// Read [`DB_PATH_ENV`] and [`MAX_AGE_ENV`] from the process
    /// environment (the `TALON_*` spellings are accepted). Without a path
    /// the file is expected in the working directory.
    pub fn from_env() -> Self {
        let db_path = talon_core::env::process_var(DB_PATH_ENV)
            .filter(|v| !v.trim().is_empty())
            .map_or_else(|| PathBuf::from(DB_FILE_NAME), PathBuf::from);
        let max_age_days = talon_core::env::process_var(MAX_AGE_ENV)
            .and_then(|v| v.trim().parse::<i64>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or(DEFAULT_MAX_AGE_DAYS);
        Self {
            db_path,
            max_age_days,
        }
    }
}

/// Build the MCP server. The database is opened per call, so this succeeds
/// while the file does not exist yet.
pub fn build_server(config: &Config) -> McpServer {
    McpServer::builder(SERVER_NAME, env!("CARGO_PKG_VERSION"))
        .tools(tools::all_tools(config))
        .instructions(tools::INSTRUCTIONS)
        .build()
}
