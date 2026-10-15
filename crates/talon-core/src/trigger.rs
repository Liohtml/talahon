//! Trigger-word matching (`@Andy hello`).

use regex::{Regex, RegexBuilder};

/// `^<escaped trigger>\b`, case-insensitive. An empty trigger falls back to
/// `@<assistant_name>`.
pub fn build_trigger_pattern(trigger: &str, assistant_name: &str) -> Regex {
    let t = trigger.trim();
    let t = if t.is_empty() {
        format!("@{assistant_name}")
    } else {
        t.to_string()
    };
    RegexBuilder::new(&format!(r"^{}\b", regex::escape(&t)))
        .case_insensitive(true)
        .build()
        // An escaped literal followed by \b always compiles.
        .unwrap_or_else(|_| Regex::new("$^").expect("static regex"))
}

/// Default trigger for an assistant name.
pub fn default_trigger(assistant_name: &str) -> String {
    format!("@{assistant_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_case_insensitively_at_start() {
        let re = build_trigger_pattern("@Andy", "Andy");
        assert!(re.is_match("@andy what's up"));
        assert!(!re.is_match("hey @Andy"));
        assert!(!re.is_match("@Andyx"));
    }

    #[test]
    fn empty_trigger_uses_assistant_name() {
        let re = build_trigger_pattern("  ", "Talon");
        assert!(re.is_match("@Talon go"));
    }

    #[test]
    fn regex_metacharacters_are_escaped() {
        let re = build_trigger_pattern("a.b", "x");
        assert!(re.is_match("a.b hi"));
        assert!(!re.is_match("axb hi"));
    }
}
