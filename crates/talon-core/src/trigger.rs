//! Trigger-word matching (`@Talahon hello`).
//!
//! The assistant's default name changed from `Talon` to `Talahon`. Chats
//! that have always addressed `@Talon` keep working: while `ASSISTANT_NAME`
//! is **not** set, a default trigger (none, `@Talahon` or `@Talon`) matches
//! both names ([`trigger_pattern`]). With `ASSISTANT_NAME` set, and for any
//! other trigger, matching is exactly what is configured.

use regex::{Regex, RegexBuilder};

/// The assistant's name when `ASSISTANT_NAME` is not set.
pub const DEFAULT_ASSISTANT_NAME: &str = "Talahon";

/// The default name up to 2.x, see the module docs.
pub const LEGACY_ASSISTANT_NAME: &str = "Talon";

fn compile(alternatives: &[&str]) -> Regex {
    let escaped: Vec<String> = alternatives.iter().map(|t| regex::escape(t)).collect();
    RegexBuilder::new(&format!(r"^(?:{})\b", escaped.join("|")))
        .case_insensitive(true)
        .build()
        // Escaped literals followed by \b always compile.
        .unwrap_or_else(|_| Regex::new("$^").expect("static regex"))
}

/// `^<escaped trigger>\b`, case-insensitive. An empty trigger falls back to
/// `@<assistant_name>`.
pub fn build_trigger_pattern(trigger: &str, assistant_name: &str) -> Regex {
    trigger_pattern(trigger, assistant_name, false)
}

/// Whether `trigger` is one of the triggers the product ships with: none,
/// `@Talahon` or the pre-rename `@Talon` (case-insensitive).
pub fn is_shipped_default_trigger(trigger: &str) -> bool {
    let t = trigger.trim();
    t.is_empty()
        || [DEFAULT_ASSISTANT_NAME, LEGACY_ASSISTANT_NAME]
            .iter()
            .any(|name| t.eq_ignore_ascii_case(&default_trigger(name)))
}

/// [`build_trigger_pattern`] that knows whether the assistant name is the
/// built-in default (`name_is_default`: `ASSISTANT_NAME` is not set).
///
/// With the default name, a shipped default trigger
/// ([`is_shipped_default_trigger`]) matches `@Talahon` **and** `@Talon`.
/// Otherwise this is [`build_trigger_pattern`].
pub fn trigger_pattern(trigger: &str, assistant_name: &str, name_is_default: bool) -> Regex {
    if name_is_default && is_shipped_default_trigger(trigger) {
        return compile(&[
            &default_trigger(DEFAULT_ASSISTANT_NAME),
            &default_trigger(LEGACY_ASSISTANT_NAME),
        ]);
    }
    let t = trigger.trim();
    if t.is_empty() {
        compile(&[&default_trigger(assistant_name)])
    } else {
        compile(&[t])
    }
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
        let re = build_trigger_pattern("@Talahon", "Talahon");
        assert!(re.is_match("@talahon what's up"));
        assert!(!re.is_match("hey @Talahon"));
        assert!(!re.is_match("@Talahonx"));
    }

    #[test]
    fn unset_assistant_name_accepts_the_old_and_the_new_default() {
        // ASSISTANT_NAME not set: no trigger, `@Talahon` and `@Talon` are
        // all "the default trigger" and match both names.
        for trigger in ["", "  ", "@Talahon", "@Talon", "@talon"] {
            let re = trigger_pattern(trigger, DEFAULT_ASSISTANT_NAME, true);
            assert!(re.is_match("@Talahon status"), "{trigger:?}");
            assert!(re.is_match("@Talon status"), "{trigger:?}");
            assert!(re.is_match("@TALON"), "{trigger:?}");
            assert!(!re.is_match("@Talonx status"), "{trigger:?}");
            assert!(!re.is_match("@Talahonx status"), "{trigger:?}");
            assert!(!re.is_match("hey @Talon"), "{trigger:?}");
        }
        // A group's own trigger is never widened.
        let re = trigger_pattern("@Claw", DEFAULT_ASSISTANT_NAME, true);
        assert!(re.is_match("@claw hi"));
        assert!(!re.is_match("@Talon hi"));
        assert!(!re.is_match("@Talahon hi"));
    }

    #[test]
    fn an_explicit_assistant_name_is_matched_exactly_as_before() {
        // ASSISTANT_NAME=Talahon, set explicitly: only that name.
        let re = trigger_pattern("", "Talahon", false);
        assert!(re.is_match("@Talahon go"));
        assert!(!re.is_match("@Talon go"));
        // ASSISTANT_NAME=Talon kept on purpose: only that name.
        let re = trigger_pattern("", "Talon", false);
        assert!(re.is_match("@Talon go"));
        assert!(!re.is_match("@Talahon go"));
        // ASSISTANT_NAME=Nova with a group still registered as `@Talon`.
        let re = trigger_pattern("@Talon", "Nova", false);
        assert!(re.is_match("@Talon go"));
        assert!(!re.is_match("@Talahon go"));
        assert!(!re.is_match("@Nova go"));
        // Same result as the two-argument builder.
        for (trigger, name) in [("", "Nova"), ("@Talon", "Nova"), ("a.b", "x")] {
            assert_eq!(
                trigger_pattern(trigger, name, false).as_str(),
                build_trigger_pattern(trigger, name).as_str()
            );
        }
    }

    #[test]
    fn empty_trigger_uses_assistant_name() {
        let re = build_trigger_pattern("  ", "Talahon");
        assert!(re.is_match("@Talahon go"));
    }

    #[test]
    fn regex_metacharacters_are_escaped() {
        let re = build_trigger_pattern("a.b", "x");
        assert!(re.is_match("a.b hi"));
        assert!(!re.is_match("axb hi"));
    }
}
