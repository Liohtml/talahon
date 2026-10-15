//! # talon-anon — PII anonymization engine and anonymizing MCP proxy
//!
//! SIEM tool results are rewritten before they reach the model: user names, host names, internal
//! IPs, e-mail addresses, internal domains, SIDs and MAC addresses become
//! consistent session tokens (`USER_1`, `HOST_2`, `IP_INT_3`, `EMAIL_1`,
//! `DOMAIN_INT_1`, `SID_1`, `MAC_1`), while hashes, public IPs/domains and
//! rule metadata pass through untouched. A local `deanonymize` tool restores
//! the originals for the final report.
//!
//! Library layout:
//! - [`config`] — `fields.yaml` (Python-compatible, with optional extensions)
//! - [`tokens`] — the token map (Python-compatible `session_tokens.json`)
//! - [`store`] — atomic `0600` persistence, cross-process lock + merge
//! - [`engine`] — [`Anonymizer`]: field-aware JSON walking, free-text
//!   detectors, known-value sweep, de-anonymization
//! - [`session`] — [`AnonSession`]: anonymizer + store, transactional
//! - [`detect`] — IP classification helpers
//! - [`jsonrpc`] — JSON-RPC 2.0 helpers on `serde_json::Value`
//! - [`proxy`] — the line-delimited JSON-RPC proxy used by the
//!   `talon-anon-proxy` binary
//!
//! ```
//! use std::sync::Arc;
//! use talon_anon::{Anonymizer, CompiledConfig};
//!
//! let cfg = CompiledConfig::from_yaml_str(
//!     "categories:\n  user:\n    token_prefix: USER\n    fields: [data_win_eventdata_user]\n",
//! )
//! .unwrap();
//! let mut anon = Anonymizer::new(Arc::new(cfg));
//! let mut doc = serde_json::json!({
//!     "data": {"win": {"eventdata": {"user": "john.doe"}}},
//!     "full_log": "john.doe logged on from 10.0.0.5"
//! });
//! anon.anonymize_json(&mut doc);
//! assert_eq!(doc["data"]["win"]["eventdata"]["user"], "USER_1");
//! assert_eq!(doc["full_log"], "USER_1 logged on from IP_INT_1");
//! assert_eq!(anon.deanonymize_text("USER_1 / IP_INT_1"), "john.doe / 10.0.0.5");
//! ```

pub mod config;
pub mod detect;
pub mod engine;
pub mod jsonrpc;
pub mod proxy;
pub mod session;
pub mod store;
mod text;
pub mod tokens;

pub use config::{Category, CompiledConfig, FieldDisposition, FieldsConfig};
pub use engine::{Anonymizer, FieldHints};
pub use proxy::{ProxyOptions, ProxyOutcome, run_proxy};
pub use session::{AnonSession, SharedSession};
pub use store::MapStore;
pub use tokens::{TokenEntry, TokenMap};
