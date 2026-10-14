//! # talon — host orchestrator and CLI
//!
//! **Owner: agent A15.** See `docs/RUST_ARCHITECTURE.md` §A15.
//!
//! The `talon` binary is the long-running host process (port of
//! `src/index.ts`) plus the operator CLI:
//!
//! | command | purpose |
//! |---|---|
//! | `talon run` (default) | orchestrator: channels, message loop, queue, scheduler, IPC watcher, LLM gateway |
//! | `talon setup <step> [args]` | setup steps from `talon-setup` (machine-readable status blocks) |
//! | `talon doctor` | environment, vLLM, container runtime and LLM gateway diagnostics |
//! | `talon audit verify` | recompute the hash-chained audit log |
//! | `talon audit tail [-n N] [--kind prefix]` | recent audit events as JSON lines |
//! | `talon version` | print the version |
//!
//! ## Architecture of `talon run`
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
pub mod investigation;
pub mod logging;
pub mod orchestrator;
pub mod secrets;

#[cfg(test)]
mod testutil;

/// Version of the `talon` package (`CARGO_PKG_VERSION`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
