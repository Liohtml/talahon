//! # talon-security — the policy engine
//!
//! **Owner: agent A07.** The module layout and public signatures below are the
//! contract consumed by talon-container, talon-ipc, talon-http, talon-tools,
//! talon-agent and the host. Implement every `todo!()`; you may add items,
//! but do not change/remove the listed signatures without coordinating.
//!
//! Design rules: fail closed, never panic on attacker input, no regex
//! catastrophic backtracking (the `regex` crate is linear-time — keep it),
//! bounded work on unbounded input (cap scanned length), unit tests for every
//! bypass you can think of.

pub mod auth;
pub mod egress;
pub mod injection;
pub mod ipc_authz;
pub mod mounts;
pub mod redact;
pub mod senders;
