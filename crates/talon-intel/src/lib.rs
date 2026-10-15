//! # talon-intel — SOC intelligence engine
//!
//! See `docs/RUST_ARCHITECTURE.md` §3.4 (untrusted data).
//!
//! Pure, offline and deterministic: no network, no clock-dependent logic
//! (except report file names), no model calls. Everything is available as a
//! library API and as `talon_core::tool::Tool`s via [`intel_tools`].
//!
//! | module | purpose |
//! |---|---|
//! | [`alert`] | normalised view of raw Wazuh / Graylog / OpenSearch alerts |
//! | [`ioc`] | IOC extraction, refanging, classification, dedup |
//! | [`mitre`] | embedded ATT&CK table + mappings with explanations |
//! | [`cmdline`] | suspicious command-line / process-tree analysis |
//! | [`triage`] | explainable, monotonic 0–100 risk prior |
//! | [`correlate`] | clustering of related alerts |
//! | [`report`] | `TriageReport`, strict JSON schema, validation, Markdown |
//! | [`hints`] | per-alert-type investigation guidance (prompt templates) |
//! | [`analysis`] | one-shot [`analyze_alert`] combining all of the above |
//! | [`tools`] | the agent tools |
//!
//! Quick start:
//!
//! ```
//! use talon_intel::{analyze_alert, triage::TriageContext};
//! let alert = serde_json::json!({
//!     "rule": {"level": 12, "groups": ["sysmon", "sysmon_eid1_detections"]},
//!     "data": {"win": {"system": {"eventID": "1"}, "eventdata": {
//!         "commandLine": "vssadmin.exe delete shadows /all /quiet"}}}
//! });
//! let a = analyze_alert(&alert, &TriageContext::default());
//! assert_eq!(a.mitre[0].technique_id, "T1490");
//! assert!(a.triage.score >= 60);
//! ```

#![warn(missing_docs)]

pub mod alert;
pub mod analysis;
pub mod cmdline;
mod common;
pub mod correlate;
pub mod hints;
pub mod ioc;
pub mod mitre;
pub mod report;
mod tld;
pub mod tools;
pub mod triage;

pub use analysis::{AlertAnalysis, analyze_alert};
pub use common::{Confidence, Severity};
pub use hints::{investigation_hints, template_candidates};
pub use ioc::{Ioc, IocReport, IocType, Scope, extract_from_json, extract_from_text};
pub use mitre::{MitreMapping, Tactic, Technique};
pub use report::{TriageReport, Verdict};
pub use tools::{IntelToolOptions, intel_tools};
