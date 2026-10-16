//! `.env` reader.
//!
//! Values are returned to the caller and never loaded into `std::env`, so
//! secrets don't leak into child processes (containers, MCP servers, tools).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Parsed `.env` file plus a view of the real process environment.
#[derive(Debug, Clone, Default)]
pub struct EnvFile {
    path: Option<PathBuf>,
    values: HashMap<String, String>,
}

impl EnvFile {
    /// Load `<project_root>/.env`. A missing file yields an empty set.
    pub fn load(project_root: &Path) -> Self {
        let path = project_root.join(".env");
        match std::fs::read_to_string(&path) {
            Ok(content) => Self {
                path: Some(path),
                values: parse_env(&content),
            },
            Err(_) => Self::default(),
        }
    }

    /// Build from literal content (tests).
    pub fn from_str_content(content: &str) -> Self {
        Self {
            path: None,
            values: parse_env(content),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Value from the `.env` file only. Use this for secrets.
    pub fn file_value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// Process environment first, then `.env`. Use this for non-secret
    /// settings an operator may override per-process.
    pub fn get(&self, key: &str) -> Option<String> {
        std::env::var(key)
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| self.values.get(key).cloned())
    }

    /// Parsed integer setting with a default and lower bound.
    pub fn get_u64(&self, key: &str, default: u64, min: u64) -> u64 {
        self.get(key)
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default)
            .max(min)
    }

    pub fn get_bool(&self, key: &str) -> bool {
        matches!(
            self.get(key).as_deref().map(str::trim),
            Some("1" | "true" | "TRUE" | "True" | "yes" | "on")
        )
    }
}

/// Parse `KEY=VALUE` lines. Supports comments, blank lines, `export KEY=...`,
/// single/double quoted values and inline comments (` # …` after an unquoted
/// value, anything after a quoted one). Empty values are dropped.
pub fn parse_env(content: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let key = trimmed[..eq].trim();
        if key.is_empty() {
            continue;
        }
        let value = value_of(&trimmed[eq + 1..]);
        if !value.is_empty() {
            out.insert(key.to_string(), value.to_string());
        }
    }
    out
}

/// The value of a `KEY=VALUE` line from the text after `=`: a quoted value
/// without its quotes (text after the closing quote, e.g. a comment, is
/// ignored); an unquoted value up to a `#` that follows whitespace, as in
/// `MAX_CONTEXT=131072  # tokens` (`a#b` keeps its `#`).
fn value_of(raw: &str) -> &str {
    let value = raw.trim();
    if let Some(quote) = value.chars().next().filter(|c| matches!(c, '"' | '\'')) {
        if value.len() >= 2 && value.ends_with(quote) {
            return &value[1..value.len() - 1];
        }
        return match value[1..].find(quote) {
            Some(end) => &value[1..=end],
            // Unterminated quote: keep the text as written.
            None => value,
        };
    }
    let comment = raw
        .char_indices()
        .find(|&(i, c)| c == '#' && raw[..i].ends_with(char::is_whitespace))
        .map_or(raw.len(), |(i, _)| i);
    raw[..comment].trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_comments_and_export() {
        let env = EnvFile::from_str_content(
            "# c\nA=1\nexport B=\"two words\"\nC='x'\nEMPTY=\n  D = spaced \n",
        );
        assert_eq!(env.file_value("A"), Some("1"));
        assert_eq!(env.file_value("B"), Some("two words"));
        assert_eq!(env.file_value("C"), Some("x"));
        assert_eq!(env.file_value("EMPTY"), None);
        assert_eq!(env.file_value("D"), Some("spaced"));
    }

    #[test]
    fn inline_comments_are_not_part_of_the_value() {
        // The provider guide's example uses inline comments.
        let env = EnvFile::from_str_content(concat!(
            "TALON_VLLM_FAST_MODEL=Qwen/Qwen3-8B        # optional: compaction\n",
            "TALON_VLLM_MAX_CONTEXT=131072\t# tokens\n",
            "REQUIRED=true # strict\n",
            "QUOTED=\"a # b\"   # comment\n",
            "SINGLE='x y' # c\n",
            "HASH=abc#123\n",
            "URL=http://h/#frag\n",
            "ONLY= # nothing here\n",
        ));
        assert_eq!(
            env.file_value("TALON_VLLM_FAST_MODEL"),
            Some("Qwen/Qwen3-8B")
        );
        assert_eq!(env.file_value("TALON_VLLM_MAX_CONTEXT"), Some("131072"));
        assert_eq!(env.file_value("REQUIRED"), Some("true"));
        assert_eq!(env.file_value("QUOTED"), Some("a # b"));
        assert_eq!(env.file_value("SINGLE"), Some("x y"));
        assert_eq!(env.file_value("HASH"), Some("abc#123"));
        assert_eq!(env.file_value("URL"), Some("http://h/#frag"));
        assert_eq!(env.file_value("ONLY"), None);
    }

    #[test]
    fn byte_order_mark_does_not_hide_the_first_key() {
        let env = EnvFile::from_str_content("\u{feff}TZ=Europe/Berlin\nA=1\n");
        assert_eq!(env.file_value("TZ"), Some("Europe/Berlin"));
    }
}
