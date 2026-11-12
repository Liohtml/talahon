//! `.env` reader and the one place environment keys are resolved.
//!
//! Values are returned to the caller and never loaded into `std::env`, so
//! secrets don't leak into child processes (containers, MCP servers, tools).
//!
//! # `TALAHON_*` keys and their `TALON_*` aliases
//!
//! Every setting of this project is spelled `TALAHON_<NAME>`. Up to 2.x the
//! prefix was `TALON_`; that spelling is still read for one major version so
//! an existing installation keeps running after the upgrade:
//!
//! - the new name is looked up first (process environment, then `.env`),
//!   then the old name (process environment, then `.env`), so when both are
//!   set the new one wins, whatever the source;
//! - an old name that supplies a value is recorded and warned about once per
//!   process ([`note_legacy_key`]), never once per read;
//! - [`EnvFile::legacy_keys`] lists the old spellings and conflicts for
//!   `talahon doctor`.
//!
//! Keys with any other prefix are looked up exactly as written.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

/// Prefix of every setting of this project.
pub const ENV_PREFIX: &str = "TALAHON_";

/// The prefix used up to 2.x, still read as an alias of [`ENV_PREFIX`].
pub const LEGACY_ENV_PREFIX: &str = "TALON_";

/// The pre-rename spelling of a `TALAHON_*` key (`None` for any other key).
pub fn legacy_key(key: &str) -> Option<String> {
    key.strip_prefix(ENV_PREFIX)
        .filter(|rest| !rest.is_empty())
        .map(|rest| format!("{LEGACY_ENV_PREFIX}{rest}"))
}

/// The current spelling of a pre-rename `TALON_*` key (`None` for any other
/// key).
pub fn current_key(key: &str) -> Option<String> {
    key.strip_prefix(LEGACY_ENV_PREFIX)
        .filter(|rest| !rest.is_empty())
        .map(|rest| format!("{ENV_PREFIX}{rest}"))
}

/// Both spellings a secret may be stored under: the key itself and, for a
/// `TALAHON_*` key, its `TALON_*` alias. Redaction and env scrubbing iterate
/// this so a value under the old name is treated exactly like the new one.
pub fn key_spellings(key: &str) -> Vec<String> {
    let mut out = vec![key.to_string()];
    out.extend(legacy_key(key));
    out
}

/// Which old keys have been used ([`LegacyKeyLog::note`] is true exactly once
/// per key) and which of them still wait for a logger.
#[derive(Debug, Default)]
pub struct LegacyKeyLog {
    seen: BTreeSet<String>,
    pending: Vec<String>,
}

impl LegacyKeyLog {
    /// Record a use of `legacy`; true the first time only.
    pub fn note(&mut self, legacy: &str) -> bool {
        self.seen.insert(legacy.to_string())
    }

    /// Every old key used so far, sorted.
    pub fn seen(&self) -> Vec<String> {
        self.seen.iter().cloned().collect()
    }
}

fn legacy_log() -> &'static Mutex<LegacyKeyLog> {
    static LOG: OnceLock<Mutex<LegacyKeyLog>> = OnceLock::new();
    LOG.get_or_init(Mutex::default)
}

fn warn_legacy_key(legacy: &str) {
    let current = current_key(legacy).unwrap_or_default();
    tracing::warn!(
        deprecated = legacy,
        replacement = %current,
        "{legacy} is deprecated: rename it to {current} (the old name is removed in the next major version)"
    );
}

/// Record that the old spelling `legacy` supplied a value and warn about it,
/// once per process and key. Before a logger is installed the warning is
/// held back until [`flush_legacy_key_warnings`]. Returns true the first time.
pub fn note_legacy_key(legacy: &str) -> bool {
    let logger = tracing::dispatcher::has_been_set();
    let mut due = Vec::new();
    let first = {
        let mut log = legacy_log().lock().unwrap_or_else(PoisonError::into_inner);
        let first = log.note(legacy);
        if first {
            log.pending.push(legacy.to_string());
        }
        if logger {
            due = std::mem::take(&mut log.pending);
        }
        first
    };
    for key in due {
        warn_legacy_key(&key);
    }
    first
}

/// Emit the warnings for old keys that were read before logging was set up
/// (the log filter itself is such a key). Binaries call this once after
/// installing their logger.
pub fn flush_legacy_key_warnings() {
    let due = {
        let mut log = legacy_log().lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut log.pending)
    };
    for key in due {
        warn_legacy_key(&key);
    }
}

/// The old keys this process has taken a value from so far, sorted.
pub fn legacy_keys_used() -> Vec<String> {
    legacy_log()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .seen()
}

/// Resolve `key` through `lookup`: the key itself, then its `TALON_*` alias
/// (recorded via [`note_legacy_key`] when it supplies the value).
pub fn resolve_with(key: &str, lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    if let Some(value) = lookup(key) {
        return Some(value);
    }
    let legacy = legacy_key(key)?;
    let value = lookup(&legacy)?;
    note_legacy_key(&legacy);
    Some(value)
}

/// `std::env::var(key).ok()` with the `TALON_*` alias: the variable under its
/// current name, else under its old name. Use this instead of
/// `std::env::var("TALAHON_…")`.
pub fn process_var(key: &str) -> Option<String> {
    resolve_with(key, |k| std::env::var(k).ok())
}

/// [`process_var`] for callers that only ask whether a variable is set.
pub fn process_var_is_set(key: &str) -> bool {
    std::env::var_os(key).is_some()
        || legacy_key(key).is_some_and(|k| std::env::var_os(k).is_some())
}

/// The old name a `clap` argument reading `key` must read instead: `Some`
/// when `key` is unset in the process environment and its `TALON_*` alias is
/// set (the use is recorded). `clap` has no notion of an alias for `env`, so
/// the binaries swap the name on the built command with this.
pub fn legacy_process_key_in_use(key: &str) -> Option<String> {
    if std::env::var_os(key).is_some() {
        return None;
    }
    let legacy = legacy_key(key)?;
    std::env::var_os(&legacy)?;
    note_legacy_key(&legacy);
    Some(legacy)
}

/// Where a deprecated key was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnvSource {
    /// The process environment.
    Process,
    /// The `.env` file.
    File,
}

/// A `TALON_*` key found in the `.env` file or the process environment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LegacyKey {
    /// The old spelling as found.
    pub legacy: String,
    /// The spelling it must be renamed to.
    pub current: String,
    /// Where it was found.
    pub source: EnvSource,
    /// True when the current spelling is set too, to a different value: the
    /// current one wins and this value is ignored.
    pub conflict: bool,
}

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

    /// The `.env` file the values came from, if one was read.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Value from the `.env` file only. Use this for secrets. A `TALAHON_*`
    /// key falls back to its `TALON_*` alias (see the module docs).
    pub fn file_value(&self, key: &str) -> Option<&str> {
        if let Some(value) = self.values.get(key) {
            return Some(value.as_str());
        }
        let legacy = legacy_key(key)?;
        let value = self.values.get(&legacy)?;
        note_legacy_key(&legacy);
        Some(value.as_str())
    }

    /// Process environment first, then `.env`. Use this for non-secret
    /// settings an operator may override per-process. A `TALAHON_*` key that
    /// is set in neither falls back to its `TALON_*` alias, looked up the
    /// same way (see the module docs).
    pub fn get(&self, key: &str) -> Option<String> {
        let lookup = |k: &str| {
            std::env::var(k)
                .ok()
                .filter(|v| !v.is_empty())
                .or_else(|| self.values.get(k).cloned())
        };
        resolve_with(key, lookup)
    }

    /// Every `TALON_*` key in the `.env` file and the process environment,
    /// sorted, with the spelling to rename it to and whether it conflicts
    /// with an already present `TALAHON_*` value (for `talahon doctor`).
    pub fn legacy_keys(&self) -> Vec<LegacyKey> {
        let process: HashMap<String, String> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .filter(|(_, v)| !v.is_empty())
            .collect();
        self.legacy_keys_in(&process)
    }

    /// [`Self::legacy_keys`] against an explicit process environment.
    pub fn legacy_keys_in(&self, process: &HashMap<String, String>) -> Vec<LegacyKey> {
        let current_value = |current: &str| {
            process
                .get(current)
                .or_else(|| self.values.get(current))
                .map(String::as_str)
        };
        let mut out = Vec::new();
        for (source, map) in [
            (EnvSource::Process, process),
            (EnvSource::File, &self.values),
        ] {
            for (key, value) in map {
                let Some(current) = current_key(key) else {
                    continue;
                };
                let conflict = current_value(&current).is_some_and(|v| v != value);
                out.push(LegacyKey {
                    legacy: key.clone(),
                    current,
                    source,
                    conflict,
                });
            }
        }
        out.sort();
        out
    }

    /// Parsed integer setting with a default and lower bound.
    pub fn get_u64(&self, key: &str, default: u64, min: u64) -> u64 {
        self.get(key)
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default)
            .max(min)
    }

    /// Boolean setting: `1`, `true`, `yes` and `on` are true.
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
    fn new_key_falls_back_to_the_old_spelling_in_the_file() {
        let env = EnvFile::from_str_content("TALON_ENVTEST_ONLY_OLD=legacy\nOTHER=1\n");
        assert_eq!(env.file_value("TALAHON_ENVTEST_ONLY_OLD"), Some("legacy"));
        assert_eq!(
            env.get("TALAHON_ENVTEST_ONLY_OLD").as_deref(),
            Some("legacy")
        );
        // Still readable under the name it was written with.
        assert_eq!(env.file_value("TALON_ENVTEST_ONLY_OLD"), Some("legacy"));
        // Other prefixes have no alias.
        assert_eq!(env.file_value("TALAHON_OTHER"), None);
        assert!(legacy_keys_used().contains(&"TALON_ENVTEST_ONLY_OLD".to_string()));
    }

    #[test]
    fn new_key_wins_over_the_old_one_and_is_not_reported_as_used() {
        let env = EnvFile::from_str_content("TALON_ENVTEST_BOTH=old\nTALAHON_ENVTEST_BOTH=new\n");
        assert_eq!(env.file_value("TALAHON_ENVTEST_BOTH"), Some("new"));
        assert_eq!(env.get("TALAHON_ENVTEST_BOTH").as_deref(), Some("new"));
        assert!(!legacy_keys_used().contains(&"TALON_ENVTEST_BOTH".to_string()));
    }

    #[test]
    fn an_old_key_is_noted_once_however_often_it_is_read() {
        let mut log = LegacyKeyLog::default();
        assert!(log.note("TALON_A"));
        assert!(!log.note("TALON_A"));
        assert!(log.note("TALON_B"));
        assert_eq!(log.seen(), ["TALON_A", "TALON_B"]);

        // The process-wide log behaves the same through repeated reads.
        let env = EnvFile::from_str_content("TALON_ENVTEST_ONCE=v\n");
        assert_eq!(env.file_value("TALAHON_ENVTEST_ONCE"), Some("v"));
        assert!(!note_legacy_key("TALON_ENVTEST_ONCE"));
        assert_eq!(env.get("TALAHON_ENVTEST_ONCE").as_deref(), Some("v"));
        assert_eq!(
            legacy_keys_used()
                .iter()
                .filter(|k| *k == "TALON_ENVTEST_ONCE")
                .count(),
            1
        );
    }

    #[test]
    fn resolve_with_prefers_new_then_old_and_ignores_foreign_prefixes() {
        let vars: HashMap<&str, &str> = [
            ("TALON_ENVTEST_R1", "old"),
            ("TALAHON_ENVTEST_R2", "new"),
            ("TALON_ENVTEST_R2", "old"),
            ("COPILOT_X", "c"),
        ]
        .into();
        let lookup = |k: &str| vars.get(k).map(ToString::to_string);
        assert_eq!(
            resolve_with("TALAHON_ENVTEST_R1", lookup).as_deref(),
            Some("old")
        );
        assert_eq!(
            resolve_with("TALAHON_ENVTEST_R2", lookup).as_deref(),
            Some("new")
        );
        assert_eq!(resolve_with("COPILOT_X", lookup).as_deref(), Some("c"));
        assert_eq!(resolve_with("TALAHON_ENVTEST_R3", lookup), None);
    }

    #[test]
    fn key_spellings_and_conversions() {
        assert_eq!(legacy_key("TALAHON_LOG").as_deref(), Some("TALON_LOG"));
        assert_eq!(legacy_key("TALON_LOG"), None);
        assert_eq!(legacy_key("TALAHON_"), None);
        assert_eq!(current_key("TALON_LOG").as_deref(), Some("TALAHON_LOG"));
        assert_eq!(current_key("TALAHON_LOG"), None);
        assert_eq!(current_key("HTTP_API_KEY"), None);
        assert_eq!(
            key_spellings("TALAHON_VLLM_API_KEY"),
            ["TALAHON_VLLM_API_KEY", "TALON_VLLM_API_KEY"]
        );
        assert_eq!(key_spellings("HTTP_API_KEY"), ["HTTP_API_KEY"]);
    }

    #[test]
    fn legacy_keys_lists_old_spellings_and_conflicts() {
        let env = EnvFile::from_str_content(concat!(
            "TALON_VLLM_MODEL=old-model\n",
            "TALAHON_VLLM_MODEL=new-model\n",
            "TALON_AUDIT_KEY=k\n",
            "TALAHON_AUDIT_KEY=k\n",
            "TALON_LOG=debug\n",
            "HTTP_API_KEY=x\n",
        ));
        let process: HashMap<String, String> = [
            ("TALON_PROVIDER".to_string(), "vllm".to_string()),
            ("TALAHON_LOG".to_string(), "info".to_string()),
        ]
        .into();
        let found = env.legacy_keys_in(&process);
        let brief: Vec<(&str, &str, EnvSource, bool)> = found
            .iter()
            .map(|k| (k.legacy.as_str(), k.current.as_str(), k.source, k.conflict))
            .collect();
        assert_eq!(
            brief,
            [
                (
                    "TALON_AUDIT_KEY",
                    "TALAHON_AUDIT_KEY",
                    EnvSource::File,
                    false
                ),
                // The process sets the new name to another value: it wins.
                ("TALON_LOG", "TALAHON_LOG", EnvSource::File, true),
                (
                    "TALON_PROVIDER",
                    "TALAHON_PROVIDER",
                    EnvSource::Process,
                    false
                ),
                (
                    "TALON_VLLM_MODEL",
                    "TALAHON_VLLM_MODEL",
                    EnvSource::File,
                    true
                ),
            ]
        );
    }

    #[test]
    fn byte_order_mark_does_not_hide_the_first_key() {
        let env = EnvFile::from_str_content("\u{feff}TZ=Europe/Berlin\nA=1\n");
        assert_eq!(env.file_value("TZ"), Some("Europe/Berlin"));
    }
}
