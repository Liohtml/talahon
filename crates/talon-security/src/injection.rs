//! Prompt-injection defence for untrusted content (SIEM events, web pages,
//! MCP tool results, alert fields an attacker controls).
//!
//! Two layers:
//! 1. **Fencing** — untrusted text is wrapped in a randomly-nonced envelope the
//!    model is told never to obey; any occurrence of the envelope delimiters
//!    inside the content is neutralized so content can't "close" the fence.
//! 2. **Detection** — heuristic scoring of instruction-like patterns
//!    ("ignore previous instructions", role tags, tool-call JSON, base64
//!    blobs that decode to instructions, zero-width / bidi control chars,
//!    "you are now", exfiltration URLs with secrets, ...). Findings are
//!    reported, and high-risk content is flagged to the model and audited.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InjectionFinding {
    /// Rule id, e.g. `override-instructions`, `role-tag`, `hidden-unicode`.
    pub rule: String,
    /// Short excerpt (<= 120 chars) around the match.
    pub excerpt: String,
    pub weight: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InjectionReport {
    pub risk: RiskLevel,
    pub score: f32,
    pub findings: Vec<InjectionFinding>,
}

/// Scan text (only the first ~256 KiB is examined).
#[allow(unused_variables, clippy::todo)]
pub fn scan(text: &str) -> InjectionReport {
    todo!()
}

/// Remove zero-width and bidi-override characters, normalize newlines.
#[allow(unused_variables, clippy::todo)]
pub fn sanitize_invisible(text: &str) -> String {
    todo!()
}

/// Wrap untrusted content for inclusion in a model prompt / tool result:
///
/// ```text
/// <untrusted_data source="opensearch" nonce="k3J9..">
/// ...content (delimiters neutralized, invisible chars stripped)...
/// </untrusted_data nonce="k3J9..">
/// ```
///
/// When `report.risk >= Medium`, a one-line warning naming the rules is
/// prepended inside the envelope.
#[allow(unused_variables, clippy::todo)]
pub fn fence_untrusted(source: &str, content: &str) -> String {
    todo!()
}

/// System-prompt paragraph explaining the fencing contract to the model.
#[allow(clippy::todo)]
pub fn fencing_instructions() -> &'static str {
    todo!()
}
