//! Machine-readable status blocks.
//!
//! Every setup step ends by printing one block that the setup skill parses:
//!
//! ```text
//! === TALON SETUP: CHECK_ENVIRONMENT ===
//! PLATFORM: linux
//! STATUS: success
//! === END ===
//! ```
//!
//! Skill instructions and scripts that parse the output match on the
//! `=== TALON SETUP: <STEP> ===` header line.

use std::fmt;

/// First part of a block header line.
pub const STATUS_HEADER_PREFIX: &str = "=== TALON SETUP: ";
/// Last part of a block header line.
pub const STATUS_HEADER_SUFFIX: &str = " ===";
/// Block terminator line.
pub const STATUS_END: &str = "=== END ===";

/// One `KEY: value` status block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusBlock {
    step: String,
    fields: Vec<(String, String)>,
}

/// Make a value safe for the line-oriented format: no line breaks or other
/// control characters can forge extra fields or terminate the block.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

impl StatusBlock {
    /// New empty block for `step` (e.g. `"CHECK_ENVIRONMENT"`).
    pub fn new(step: impl Into<String>) -> Self {
        Self {
            step: sanitize(&step.into()),
            fields: Vec::new(),
        }
    }

    /// Builder form of [`StatusBlock::set`].
    #[must_use]
    pub fn field(mut self, key: &str, value: impl fmt::Display) -> Self {
        self.set(key, value);
        self
    }

    /// Set `key` to `value`, replacing an existing value in place (field
    /// order is insertion order).
    pub fn set(&mut self, key: &str, value: impl fmt::Display) {
        let key = sanitize(key);
        let value = sanitize(&value.to_string());
        if let Some(slot) = self.fields.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.fields.push((key, value));
        }
    }

    /// Value of `key`, if set.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The step name in the header.
    pub fn step(&self) -> &str {
        &self.step
    }

    /// All fields in order.
    pub fn fields(&self) -> &[(String, String)] {
        &self.fields
    }

    /// The `STATUS` field, if set.
    pub fn status(&self) -> Option<&str> {
        self.get("STATUS")
    }

    /// Render the block (no trailing newline).
    pub fn render(&self) -> String {
        let mut lines = Vec::with_capacity(self.fields.len() + 2);
        lines.push(format!(
            "{STATUS_HEADER_PREFIX}{}{STATUS_HEADER_SUFFIX}",
            self.step
        ));
        for (k, v) in &self.fields {
            lines.push(format!("{k}: {v}"));
        }
        lines.push(STATUS_END.to_string());
        lines.join("\n")
    }
}

impl fmt::Display for StatusBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Parse every status block in `text` (other lines are ignored).
pub fn parse_status_blocks(text: &str) -> Vec<StatusBlock> {
    let mut out = Vec::new();
    let mut current: Option<StatusBlock> = None;
    for line in text.lines() {
        if let Some(step) = line
            .strip_prefix(STATUS_HEADER_PREFIX)
            .and_then(|rest| rest.strip_suffix(STATUS_HEADER_SUFFIX))
        {
            current = Some(StatusBlock::new(step));
        } else if line == STATUS_END {
            if let Some(block) = current.take() {
                out.push(block);
            }
        } else if let Some(block) = current.as_mut() {
            if let Some((k, v)) = line.split_once(": ") {
                block.set(k, v);
            } else if let Some(k) = line.strip_suffix(':') {
                block.set(k, "");
            }
        }
    }
    out
}

/// What a step produced: optional free-form lines (printed first, e.g.
/// `groups --list`), an optional status block and the process exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutcome {
    /// Plain output lines printed before the block.
    pub lines: Vec<String>,
    /// The status block, if the step emits one.
    pub block: Option<StatusBlock>,
    /// Exit code (0 success, 1 failure, 2 runtime unavailable, 4 bad input
    /// — the same codes for every step).
    pub exit_code: i32,
}

impl StepOutcome {
    /// Outcome with a block and exit code 0.
    pub fn ok(block: StatusBlock) -> Self {
        Self::with_code(block, 0)
    }

    /// Outcome with a block and an explicit exit code.
    pub fn with_code(block: StatusBlock, exit_code: i32) -> Self {
        Self {
            lines: Vec::new(),
            block: Some(block),
            exit_code,
        }
    }

    /// Outcome made only of plain lines.
    pub fn lines(lines: Vec<String>, exit_code: i32) -> Self {
        Self {
            lines,
            block: None,
            exit_code,
        }
    }

    /// Whether the step succeeded (exit code 0).
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    /// Everything the CLI should print to stdout.
    pub fn render(&self) -> String {
        let mut parts: Vec<String> = self.lines.clone();
        if let Some(block) = &self.block {
            parts.push(block.render());
        }
        parts.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_like_typescript() {
        let block = StatusBlock::new("TIMEZONE")
            .field("RESOLVED_TZ", "Europe/Berlin")
            .field("NEEDS_USER_INPUT", false)
            .field("COUNT", 3)
            .field("STATUS", "success");
        assert_eq!(
            block.render(),
            "=== TALON SETUP: TIMEZONE ===\nRESOLVED_TZ: Europe/Berlin\nNEEDS_USER_INPUT: false\nCOUNT: 3\nSTATUS: success\n=== END ==="
        );
    }

    #[test]
    fn set_replaces_in_place() {
        let mut b = StatusBlock::new("X").field("A", 1).field("B", 2);
        b.set("A", 9);
        assert_eq!(b.fields()[0], ("A".to_string(), "9".to_string()));
        assert_eq!(b.get("B"), Some("2"));
    }

    #[test]
    fn values_cannot_inject_lines() {
        let b = StatusBlock::new("X").field("ERROR", "bad\n=== END ===\nSTATUS: success");
        let rendered = b.render();
        assert_eq!(rendered.lines().count(), 3);
        let parsed = parse_status_blocks(&rendered);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].status(), None);
    }

    #[test]
    fn parse_round_trip_and_noise() {
        let a = StatusBlock::new("A")
            .field("STATUS", "success")
            .field("EMPTY", "");
        let b = StatusBlock::new("B").field("URL", "http://x:1/a: b");
        let text = format!("noise\n{a}\nmore noise\n{b}\n");
        let parsed = parse_status_blocks(&text);
        assert_eq!(parsed, vec![a, b]);
        assert_eq!(parsed[1].get("URL"), Some("http://x:1/a: b"));
    }

    #[test]
    fn outcome_render_puts_lines_first() {
        let mut o = StepOutcome::ok(StatusBlock::new("S").field("STATUS", "success"));
        o.lines = vec!["a|b".into()];
        assert!(o.render().starts_with("a|b\n=== TALON SETUP: S ==="));
        assert!(o.is_success());
        assert!(!StepOutcome::lines(vec![], 1).is_success());
    }
}
