//! Shared enums and small helpers used across the intel modules.

use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Severity scale shared by triage scoring and reports.
///
/// Mirrors CoPilot's `severity_assessment` values
/// (`Critical|High|Medium|Low|Informational`); serialized in lowercase,
/// deserialization also accepts the capitalised CoPilot spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// No action needed; context only.
    #[serde(
        alias = "Informational",
        alias = "INFORMATIONAL",
        alias = "info",
        alias = "Info"
    )]
    Informational,
    /// Low risk.
    #[serde(alias = "Low", alias = "LOW")]
    Low,
    /// Medium risk.
    #[serde(alias = "Medium", alias = "MEDIUM")]
    Medium,
    /// High risk.
    #[serde(alias = "High", alias = "HIGH")]
    High,
    /// Critical risk; immediate response.
    #[serde(alias = "Critical", alias = "CRITICAL")]
    Critical,
}

impl Severity {
    /// All severities, lowest first.
    pub const ALL: [Severity; 5] = [
        Severity::Informational,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Lowercase wire name (`"high"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Informational => "informational",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// CoPilot label (`"High"`), as expected by `SubmitAiAnalystReportTool`.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Informational => "Informational",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    /// Severity band for a 0–100 risk score
    /// (`<20` informational, `<40` low, `<60` medium, `<80` high, else critical).
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Severity::Informational,
            20..=39 => Severity::Low,
            40..=59 => Severity::Medium,
            60..=79 => Severity::High,
            _ => Severity::Critical,
        }
    }

    /// Wazuh rule-level band (0–3 informational, 4–7 low, 8–11 medium,
    /// 12–14 high, 15 critical).
    pub fn from_rule_level(level: u8) -> Self {
        match level {
            0..=3 => Severity::Informational,
            4..=7 => Severity::Low,
            8..=11 => Severity::Medium,
            12..=14 => Severity::High,
            _ => Severity::Critical,
        }
    }

    /// Case-insensitive parse of a wire name or label (`info` accepted).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "informational" | "info" | "none" => Some(Severity::Informational),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Qualitative confidence of a derived mapping or prior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Weak signal; a candidate worth checking.
    Low,
    /// Plausible; supported by specific evidence.
    Medium,
    /// Strong; explicit tag or unambiguous evidence.
    High,
}

impl Confidence {
    /// Lowercase wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compile a static regex.
///
/// Only called from `LazyLock` initialisers with string literals. Every such
/// pattern is force-compiled by the unit tests, so a failure here is a
/// programming error caught by `cargo test`, never a condition driven by
/// external input.
#[allow(clippy::expect_used)]
pub(crate) fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static regex must compile")
}

/// Truncate to at most `max` characters (not bytes), appending `…` when cut.
pub(crate) fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Remove ASCII control characters except `\n`, `\r` and `\t`
/// (CoPilot rejects them in `report_markdown`).
pub(crate) fn strip_control_chars(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_bands() {
        assert_eq!(Severity::from_score(0), Severity::Informational);
        assert_eq!(Severity::from_score(19), Severity::Informational);
        assert_eq!(Severity::from_score(20), Severity::Low);
        assert_eq!(Severity::from_score(59), Severity::Medium);
        assert_eq!(Severity::from_score(60), Severity::High);
        assert_eq!(Severity::from_score(100), Severity::Critical);
        assert_eq!(Severity::from_rule_level(3), Severity::Informational);
        assert_eq!(Severity::from_rule_level(7), Severity::Low);
        assert_eq!(Severity::from_rule_level(10), Severity::Medium);
        assert_eq!(Severity::from_rule_level(12), Severity::High);
        assert_eq!(Severity::from_rule_level(15), Severity::Critical);
    }

    #[test]
    fn severity_serde_accepts_copilot_labels() {
        let s: Severity = serde_json::from_str("\"High\"").unwrap();
        assert_eq!(s, Severity::High);
        let s: Severity = serde_json::from_str("\"informational\"").unwrap();
        assert_eq!(s, Severity::Informational);
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(Severity::parse(" MEDIUM "), Some(Severity::Medium));
        assert_eq!(Severity::parse("bogus"), None);
        assert!(Severity::Critical > Severity::High);
    }

    #[test]
    fn helpers() {
        assert_eq!(truncate_chars("abcdef", 4), "abc…");
        assert_eq!(truncate_chars("abc", 4), "abc");
        assert_eq!(strip_control_chars("a\u{0}b\nc\u{1b}d\t"), "ab\ncd\t");
    }
}
