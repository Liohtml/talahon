//! Shared error type. Crates are free to use `anyhow` internally, but public
//! APIs that cross crate boundaries should return [`Result`].

use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// A security policy rejected the operation (mount allowlist, path
    /// traversal, IPC authorization, injection guard, ...).
    #[error("security policy violation: {0}")]
    Security(String),

    #[error("database error: {0}")]
    Db(String),

    #[error("container error: {0}")]
    Container(String),

    #[error("LLM provider error: {0}")]
    Llm(String),

    #[error("MCP error: {0}")]
    Mcp(String),

    #[error("channel error: {0}")]
    Channel(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }
    pub fn security(msg: impl Into<String>) -> Self {
        Self::Security(msg.into())
    }
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
