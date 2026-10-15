//! # talon-http — CoPilot HTTP API channel
//!
//! See `docs/RUST_ARCHITECTURE.md` §3.4 (untrusted data) and §3.5 (audit).
//!
//! An axum server that CoPilot talks to (plus the MemPalace bridge), exposed
//! to the host as a [`talon_core::channel::Channel`] owning every
//! `http:copilot*` JID.
//!
//! ## Lanes
//! - `http:copilot` — the shared chat lane (callers that name no user).
//! - `http:copilot:investigate` — investigations; ephemeral session, its
//!   output reaches CoPilot through the MCP write-back tools, not SSE.
//! - `http:copilot:u:<id>` — one in-memory lane per CoPilot user, cloned
//!   from the base group (same folder/mounts, own session + IPC namespace
//!   `copilot-u-<lowercased id, ≤ 20 chars>-<32 hex of sha256(exact id)>`,
//!   e.g. `copilot-u-bob-81b637d8fcd2c6da6359e6963113a117`), dropped again
//!   by the idle-lane sweep. Ids must match `^[A-Za-z0-9_-]{1,48}$`; anything
//!   else is rejected with 400 rather than stripped into another user's lane.
//!   The 128-bit hash makes it infeasible to choose an id whose key collides
//!   with another user's (N-8).
//!
//! ## Endpoints
//! | Method | Path | Notes |
//! |---|---|---|
//! | GET  | `/health` | unauthenticated liveness |
//! | GET  | `/status` | uptime, lanes, sessions, scheduled tasks, queue |
//! | GET  | `/metrics` | Prometheus text exposition |
//! | POST | `/session/reset` | `{scope: chat\|investigate\|all, user_id?}` |
//! | POST | `/investigate` | `{alert_id, customer_code, triggered_by?, template_override?}` |
//! | GET  | `/investigations` | `?limit=` recent investigation jobs |
//! | GET  | `/investigations/{id}` | one job |
//! | GET  | `/evals/{alert_id}` | eval JSON written by the investigation lane (`<data_dir>/sessions/copilot-investigate/evals/`) |
//! | GET  | `/templates` | prompt templates available for overrides |
//! | POST | `/palace/lesson` | MemPalace `add_drawer` (503 unless a palace runner is configured) |
//! | GET  | `/palace/search` | MemPalace `search` (503 unless configured) |
//! | POST | `/palace/forget` | MemPalace `delete_drawer` (503 unless configured) |
//! | POST | `/message` | chat; answers stream back as SSE |
//!
//! ## Security
//! Fail-closed API key (an unset `HTTP_API_KEY` rejects every request but
//! `/health`), constant-time comparison via [`talon_security::auth`],
//! per-IP auth-failure throttling, request body limit, strict input
//! validation, security headers, allowlist-based CORS, audit events and
//! investigation de-duplication. Served with [`talon_net::serve`]
//! (header-read timeout, connection caps), bound to `127.0.0.1` unless
//! configured otherwise. MemPalace code never runs on the host by default
//! (see [`palace`]); agent-writable `evals/` and `prompts/` are read without
//! following symlinks. Eval records come from the investigation lane's
//! private state directory, so no other CoPilot lane can forge them (N-2);
//! the shared `groups/<folder>/evals/` is read only with
//! `COPILOT_EVALS_LEGACY_GROUP_DIR=true` (migration).
//!
//! ## Testing
//! [`router`] builds the full axum [`axum::Router`] from an [`HttpState`];
//! drive it with `tower::ServiceExt::oneshot`. The database and key
//! verification are reached through the [`HttpStore`] and [`KeyVerifier`]
//! seams so the server can be exercised without the real backends.

#![warn(missing_docs)]

pub mod auth;
pub mod channel;
pub mod config;
mod files;
pub mod investigate;
pub mod lanes;
mod metrics;
pub mod palace;
pub mod server;
mod sse;
pub mod store;
pub mod validate;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod testutil;

pub use auth::{KeyVerifier, SecurityKeyVerifier};
pub use channel::HttpChannel;
pub use config::{ApiKey, HttpConfig};
pub use lanes::{InvalidUserId, LaneIds, UserId, is_valid_user_id, lane_jid_for_user};
pub use palace::{
    CommandPalaceRunner, DisabledPalaceRunner, PalaceError, PalaceRunner, ScriptPalaceRunner,
};
pub use server::{HttpDeps, HttpState, router};
pub use store::HttpStore;
