//! # talon — host orchestrator and CLI
//!
//! The `talahon` binary is the long-running host process plus the operator
//! CLI:
//!
//! | command | purpose |
//! |---|---|
//! | `talahon run` (default) | orchestrator: channels, message loop, queue, scheduler, IPC watcher, LLM gateway |
//! | `talahon setup <step> [args]` | setup steps from `talon-setup` (machine-readable status blocks) |
//! | `talahon doctor` | environment, vLLM, container runtime and LLM gateway diagnostics |
//! | `talahon audit verify` | recompute the hash-chained audit log |
//! | `talahon audit tail [-n N] [--kind prefix]` | recent audit events as JSON lines |
//! | `talahon eval score --reports DIR` | score saved reports against the golden set (`evals/golden/`) |
//! | `talahon eval run` | investigate every golden case through a running Talahon, then score |
//! | `talahon version` | print the version |
//!
//! ## Architecture of `talahon run`
//!
//! ```text
//!  channels (http, telegram, emacs, webhook)
//!     │ ChannelHost::on_message ── sender allowlist (drop) ── store ── Notify
//!     ▼
//!  message loop (event-driven, poll fallback) ── trigger gating ── session commands
//!     │ pipe follow-up into the lane's container (IPC input)  or  enqueue a lane run
//!     ▼
//!  GroupQueue (per-lane serialization, global limit) ◀── TaskScheduler (due tasks)
//!     │ LaneProcessor::process_messages / run_task
//!     ▼
//!  Orchestrator::run_agent ── session/provider fingerprint ── snapshots
//!     │ LLM gateway token (stdin only) ── ContainerRunner ── output frames
//!     ▼
//!  outbound: redact ── format per channel dialect ── Channel::send_message
//! ```
//!
//! Everything that needs the outside world (container runtime, LLM gateway,
//! channels) sits behind a trait ([`agent::ContainerLauncher`],
//! [`agent::LlmAccess`], `talon_core::channel::Channel`) so the orchestrator
//! logic is unit-tested with fakes and an in-memory database.

#![warn(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod agent;
pub mod allowlist;
pub mod app;
pub mod audit_cmd;
pub mod cli;
pub mod doctor;
pub mod entry;
pub mod eval_cmd;
pub mod investigation;
pub mod logging;
pub mod orchestrator;
pub mod output_limits;
pub mod palace;
pub mod safe_fs;
pub mod secrets;

#[cfg(test)]
mod testutil;

/// Version of the `talahon` package (`CARGO_PKG_VERSION`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
