//! # talon-http — CoPilot HTTP API channel
//!
//! **Owner: agent A13.** See `docs/RUST_ARCHITECTURE.md` §A13.
//!
//! Rust port of `src/channels/http.ts` (+ `src/palace-client.ts`): an axum
//! server that SOCFortress CoPilot talks to, exposed to the host as a
//! [`talon_core::channel::Channel`] owning every `http:copilot*` JID.
//!
//! ## Lanes
//! - `http:copilot` — the shared chat lane (callers that name no user).
//! - `http:copilot:investigate` — investigations; ephemeral session, its
//!   output reaches CoPilot through the MCP write-back tools, not SSE.
//! - `http:copilot:u:<id>` — one in-memory lane per CoPilot user, cloned
//!   from the base group (same folder/mounts, own session + IPC namespace),
//!   dropped again by the idle-lane sweep.
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
//! | GET  | `/evals/{alert_id}` | eval JSON files written by the agent |
//! | GET  | `/templates` | prompt templates available for overrides |
//! | POST | `/palace/lesson` | MemPalace `add_drawer` |
//! | GET  | `/palace/search` | MemPalace `search` |
//! | POST | `/palace/forget` | MemPalace `delete_drawer` |
//! | POST | `/message` | chat; answers stream back as SSE |
//!
//! ## Security
//! Fail-closed API key (an unset `HTTP_API_KEY` rejects every request but
//! `/health`), constant-time comparison via [`talon_security::auth`],
//! per-IP auth-failure throttling, request body limit, strict input
//! validation, security headers, allowlist-based CORS, audit events and
//! investigation de-duplication.
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
pub use lanes::{LaneIds, lane_jid_for_user, normalize_user_id};
pub use palace::{PalaceError, PalaceRunner, ScriptPalaceRunner};
pub use server::{HttpDeps, HttpState, router};
pub use store::HttpStore;
