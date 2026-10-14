//! Error type of the MCP client/server.

use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

/// Maximum number of characters of a server-provided error message kept in
/// [`McpError::Rpc`] (server output is untrusted and may be huge).
pub(crate) const MAX_REMOTE_MESSAGE_CHARS: usize = 2000;

/// Everything that can go wrong while talking MCP.
#[derive(Debug, Error)]
pub enum McpError {
    /// The `.mcp.json` file or a server entry is invalid.
    #[error("invalid MCP configuration: {0}")]
    Config(String),

    /// The server process could not be started.
    #[error("failed to start MCP server '{server}': {source}")]
    Spawn {
        /// Server name from `.mcp.json`.
        server: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// Connecting to the server's unix socket failed.
    #[error("failed to connect to MCP server '{server}' at {}: {source}", path.display())]
    Connect {
        /// Server name.
        server: String,
        /// Socket path.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// Generic I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The connection is gone (process exited, socket closed, client shut
    /// down). Pending and future requests fail with this error.
    #[error("MCP server '{server}' is not available: {reason}")]
    Closed {
        /// Server name.
        server: String,
        /// Why the connection closed.
        reason: String,
    },

    /// No response arrived within the timeout. A
    /// `notifications/cancelled` was sent to the server.
    #[error("MCP request '{method}' to server '{server}' timed out after {}", fmt_duration(*timeout))]
    Timeout {
        /// Server name.
        server: String,
        /// JSON-RPC method (or `startup` for the manager's start budget).
        method: String,
        /// The timeout that elapsed.
        timeout: Duration,
    },

    /// The caller cancelled the request (e.g. the agent turn was aborted).
    #[error("MCP request '{method}' to server '{server}' was cancelled")]
    Cancelled {
        /// Server name.
        server: String,
        /// JSON-RPC method.
        method: String,
    },

    /// The server answered with a JSON-RPC error object.
    #[error("MCP server '{server}' returned error {code}: {message}")]
    Rpc {
        /// Server name.
        server: String,
        /// JSON-RPC error code.
        code: i64,
        /// Error message (truncated to a sane length).
        message: String,
        /// Optional `data` member.
        data: Option<serde_json::Value>,
    },

    /// The server violated the protocol (malformed result, ...).
    #[error("MCP protocol error from server '{server}': {message}")]
    Protocol {
        /// Server name.
        server: String,
        /// Description of the violation.
        message: String,
    },

    /// Version negotiation failed.
    #[error("MCP server '{server}' uses unsupported protocol version '{version}'")]
    UnsupportedVersion {
        /// Server name.
        server: String,
        /// Version the server proposed.
        version: String,
    },

    /// A request that needs an initialized session was issued before
    /// [`crate::McpClient::initialize`] succeeded.
    #[error("MCP server '{server}' has not been initialized")]
    NotInitialized {
        /// Server name.
        server: String,
    },

    /// A message exceeded the configured size limit.
    #[error("MCP message of {size} bytes exceeds the limit of {limit} bytes")]
    MessageTooLarge {
        /// Actual (or lower bound of the) size in bytes.
        size: usize,
        /// Configured limit.
        limit: usize,
    },

    /// A caller-supplied argument was invalid (e.g. non-object tool args).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl McpError {
    /// True for [`McpError::Closed`].
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }

    /// True for [`McpError::Timeout`].
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }

    /// JSON-RPC error code if this is an [`McpError::Rpc`].
    pub fn rpc_code(&self) -> Option<i64> {
        match self {
            Self::Rpc { code, .. } => Some(*code),
            _ => None,
        }
    }
}

impl From<McpError> for talon_core::Error {
    fn from(e: McpError) -> Self {
        match e {
            McpError::Timeout { .. } => talon_core::Error::Timeout(e.to_string()),
            McpError::Config(msg) => talon_core::Error::Config(msg),
            McpError::InvalidArgument(msg) => talon_core::Error::InvalidInput(msg),
            McpError::Io(io) => talon_core::Error::Io(io),
            other => talon_core::Error::Mcp(other.to_string()),
        }
    }
}

/// Truncate untrusted text to `max` characters, appending an ellipsis.
pub(crate) fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s.to_string(),
    }
}

fn fmt_duration(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        let e = McpError::Timeout {
            server: "siem".into(),
            method: "tools/call".into(),
            timeout: Duration::from_secs(5),
        };
        assert_eq!(
            e.to_string(),
            "MCP request 'tools/call' to server 'siem' timed out after 5s"
        );
        assert!(e.is_timeout());
        let e = McpError::Timeout {
            server: "siem".into(),
            method: "ping".into(),
            timeout: Duration::from_millis(250),
        };
        assert!(e.to_string().ends_with("250ms"));

        let e = McpError::Closed {
            server: "x".into(),
            reason: "EOF".into(),
        };
        assert!(e.is_closed());
        assert_eq!(e.to_string(), "MCP server 'x' is not available: EOF");
    }

    #[test]
    fn converts_to_core_error() {
        let core: talon_core::Error = McpError::Timeout {
            server: "a".into(),
            method: "m".into(),
            timeout: Duration::from_secs(1),
        }
        .into();
        assert!(matches!(core, talon_core::Error::Timeout(_)));
        let core: talon_core::Error = McpError::Rpc {
            server: "a".into(),
            code: -32601,
            message: "nope".into(),
            data: None,
        }
        .into();
        assert!(matches!(core, talon_core::Error::Mcp(_)));
        let core: talon_core::Error = McpError::Config("bad".into()).into();
        assert!(matches!(core, talon_core::Error::Config(_)));
    }

    #[test]
    fn rpc_code_accessor() {
        let e = McpError::Rpc {
            server: "a".into(),
            code: -32602,
            message: String::new(),
            data: None,
        };
        assert_eq!(e.rpc_code(), Some(-32602));
        assert_eq!(McpError::InvalidArgument("x".into()).rpc_code(), None);
    }

    #[test]
    fn truncation_is_char_safe() {
        assert_eq!(truncate_chars("abc", 5), "abc");
        assert_eq!(truncate_chars("äöüß", 2), "äö…");
        assert_eq!(truncate_chars("", 0), "");
    }
}
