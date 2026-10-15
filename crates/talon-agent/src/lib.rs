//! # talon-agent — in-container agent runtime
//!
//! See `docs/RUST_ARCHITECTURE.md` §3.1–3.4. Runs the agent turn inside the
//! container with a native vLLM agent loop.
//!
//! The binary has two modes:
//!
//! - **`talon-agent supervise`** ([`supervise`]) — runs as root (PID 1 of the
//!   container), LLM-free: validates the stdin input, starts each MCP server
//!   of `.mcp.json` as its `mcp-*` account behind a unix socket, then runs
//!   `talon-agent run` as `RUN_UID:RUN_GID` and tears everything down when
//!   it exits. Without root it falls back to `run`.
//! - **`talon-agent run`** ([`run`]) — the unprivileged agent: reads the
//!   `ContainerInput`, resumes/creates the session, and drives the
//!   [`agent::Agent`] loop against the host LLM gateway (vLLM), emitting
//!   `ContainerOutput` frames on stdout.
//!
//! Module map:
//! - [`config`]   — paths, loop limits, CLI/env interface
//! - [`wire`]     — stdin input (bounded) and stdout frames
//! - [`logging`]  — stderr-only, secret-redacting `tracing` setup
//! - [`model`]    — model settings + request builders over `ChatBackend`
//! - [`session`]  — JSONL transcripts under `<state>/sessions/<uuid>.jsonl`
//! - [`ipc`]      — follow-up input files and the `_close` sentinel
//! - [`prompt`]   — system prompt (byte-stable, read-only `CLAUDE.md`) and
//!   turn messages (fenced `MEMORY.md`, run notes)
//! - [`tools`]    — tool registry, parallel execution, truncation, loop guard,
//!   untrusted-output fencing
//! - [`mcp`]      — `.mcp.json` loading and MCP manager setup
//! - [`compact`]  — compaction cut points, summaries, lane-private Markdown
//!   archives under `<state>/conversations/`
//! - [`script`]   — scheduled-task pre-flight scripts
//! - [`agent`]    — the turn / session loop
//! - [`run`]      — `talon-agent run` (lane-private triage reports under
//!   `<state>/reports/`, eval records under `<state>/evals/`)
//! - [`supervise`]— `talon-agent supervise`
//! - [`mountinfo`]— read-only mount check for privileged MCP commands
//! - [`error`]    — [`AgentError`]
//!
//! ## Testing the loop without HTTP
//!
//! The loop depends only on [`talon_llm::ChatBackend`]; tests drive it with
//! [`talon_llm::ScriptedBackend`] and an in-memory [`wire::MemorySink`]:
//!
//! ```no_run
//! # async fn demo() -> Result<(), talon_agent::AgentError> {
//! use std::sync::Arc;
//! use talon_agent::config::RunConfig;
//! use talon_agent::wire::MemorySink;
//! use talon_llm::{ChatMessage, ChatResponse, ScriptedBackend};
//!
//! let backend = Arc::new(ScriptedBackend::new([Ok(ChatResponse::from_message(
//!     ChatMessage::assistant("hello"),
//! ))]));
//! let input = serde_json::from_str(
//!     r#"{"prompt":"hi","groupFolder":"main","chatJid":"tg:1","isMain":true}"#,
//! )
//! .map_err(|e| talon_agent::AgentError::Input(e.to_string()))?;
//! let sink = Arc::new(MemorySink::new());
//! talon_agent::run::execute(
//!     input,
//!     &RunConfig::default(),
//!     Some(backend),
//!     sink.clone(),
//!     tokio_util::sync::CancellationToken::new(),
//! )
//! .await?;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod agent;
pub mod compact;
pub mod config;
pub mod error;
pub mod ipc;
pub mod logging;
pub mod mcp;
pub mod model;
pub mod mountinfo;
pub mod prompt;
pub mod run;
pub mod script;
pub mod session;
pub mod supervise;
pub mod tools;
pub mod wire;

pub use agent::{Agent, AgentParts, TurnOutcome};
pub use config::{AgentPaths, LoopSettings, RunConfig};
pub use error::AgentError;
