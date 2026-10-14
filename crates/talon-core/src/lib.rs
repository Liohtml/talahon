//! # talon-core
//!
//! The contract every other Talon crate builds against. Everything in here is
//! **frozen** for the duration of the Rust rewrite: crates may add their own
//! types, but must not change the shapes defined here without coordinating,
//! because the host (`talon`) and the in-container runtime (`talon-agent`)
//! exchange these types across a process and container boundary.
//!
//! Module map:
//! - [`types`]    — domain model (groups, messages, tasks, container config)
//! - [`protocol`] — host <-> container wire protocol (stdin/stdout + IPC files)
//! - [`channel`]  — the `Channel` trait and the host callbacks channels use
//! - [`tool`]     — the `Tool` trait every agent tool implements
//! - [`config`]   — process-wide configuration resolved from env / `.env`
//! - [`env`]      — `.env` reader that never pollutes `std::env`
//! - [`provider`] — vLLM provider defaults and per-group merging
//! - [`paths`]    — group-folder validation and traversal-safe path resolution
//! - [`schedule`] — cron / interval / once next-run computation
//! - [`trigger`]  — trigger-word regex construction
//! - [`time`]     — timestamp helpers (JS `toISOString` compatible)
//! - [`audit`]    — audit sink trait for security-relevant decisions
//! - [`error`]    — the shared error type

pub mod audit;
pub mod channel;
pub mod config;
pub mod env;
pub mod error;
pub mod paths;
pub mod protocol;
pub mod provider;
pub mod schedule;
pub mod time;
pub mod tool;
pub mod trigger;
pub mod types;

pub use error::{Error, Result};
