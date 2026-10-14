//! The tool abstraction used by the in-container agent loop.
//!
//! Built-in tools (`talon-tools`), threat-intel tools (`talon-intel`) and
//! remote MCP tools (wrapped by `talon-agent`) all implement [`Tool`], so the
//! agent loop treats them uniformly.

use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// JSON-schema described tool, as advertised to the model in the OpenAI
/// `tools` array (`{"type":"function","function":{name,description,parameters}}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    /// `^[a-zA-Z0-9_-]{1,64}$`. MCP tools are exposed as `mcp__<server>__<tool>`.
    pub name: String,
    pub description: String,
    /// JSON Schema (`{"type":"object","properties":{...},"required":[...]}`).
    pub parameters: serde_json::Value,
}

/// Result of a tool invocation, fed back to the model as a `tool` message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolOutput {
    pub content: String,
    pub is_error: bool,
}

impl ToolOutput {
    pub fn ok(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_error: false,
        }
    }

    pub fn err(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_error: true,
        }
    }
}

/// How a tool may be scheduled by the agent loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolConcurrency {
    /// No side effects; may run in parallel with other read-only tools.
    ReadOnly,
    /// Mutates state; runs alone, in call order.
    Exclusive,
}

/// Per-call execution context.
#[derive(Debug, Clone)]
pub struct ToolContext {
    /// Working directory (normally `/workspace/group`).
    pub cwd: PathBuf,
    /// Directories the file tools may touch (cwd, extra mounts, ...).
    /// Anything outside is rejected after canonicalization.
    pub allowed_roots: Vec<PathBuf>,
    /// Read-only roots (e.g. `/workspace/global`, `/workspace/project`).
    pub read_only_roots: Vec<PathBuf>,
    pub group_folder: String,
    pub chat_jid: String,
    pub is_main: bool,
    /// IPC namespace root (normally `/workspace/ipc`).
    pub ipc_dir: PathBuf,
    /// Cancelled when the turn is aborted or the container shuts down.
    pub cancel: CancellationToken,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn spec(&self) -> ToolSpec;

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::Exclusive
    }

    /// Execute. Errors the model can act on (bad args, file not found) are
    /// returned as `ToolOutput::err`, never as panics.
    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolOutput;
}
