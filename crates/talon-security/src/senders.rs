//! Per-chat sender allowlist (port of `src/sender-allowlist.ts`).
//! File: `~/.config/talon/sender-allowlist.json`. Missing file => everyone
//! allowed (legacy behaviour) unless `TALON_SENDER_ALLOWLIST_REQUIRED=true`.
//!
//! File format (identical to the TypeScript release):
//!
//! ```json
//! {
//!   "default": { "allow": "*", "mode": "trigger" },
//!   "chats": { "tg:-100123": { "allow": ["12345", "67890"], "mode": "drop" } },
//!   "logDenied": true
//! }
//! ```
//!
//! - `allow`: `"*"` (everyone) or an exact list of sender ids.
//! - `mode`: `trigger` (messages are stored, but only allowed senders can
//!   wake the agent) or `drop` (messages from other senders are discarded
//!   before they are stored).
//!
//! Load semantics match TS: a missing, unreadable or invalid file (or an
//! invalid `default` entry) yields the allow-all default; invalid per-chat
//! entries are skipped. When the allowlist is *required*
//! ([`SenderAllowlist::load_with_policy`] with `required = true`, or
//! `TALON_SENDER_ALLOWLIST_REQUIRED` set in the process environment for
//! [`SenderAllowlist::load`]), those cases fail closed instead: nobody may
//! trigger the agent (messages are still stored, `trigger` mode).

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Environment variable that makes the sender allowlist mandatory.
pub const REQUIRED_ENV: &str = "TALON_SENDER_ALLOWLIST_REQUIRED";

/// Maximum size of the allowlist file.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Allow {
    All,
    List(HashSet<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Trigger,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    allow: Allow,
    mode: Mode,
}

impl Entry {
    const fn allow_all() -> Self {
        Entry {
            allow: Allow::All,
            mode: Mode::Trigger,
        }
    }

    fn allows(&self, sender: &str) -> bool {
        match &self.allow {
            Allow::All => true,
            Allow::List(list) => list.contains(sender),
        }
    }

    /// TS `isValidEntry`: `allow` is `"*"` or an array of strings, `mode` is
    /// `trigger` | `drop`.
    fn parse(value: &serde_json::Value) -> Option<Self> {
        let obj = value.as_object()?;
        let allow = match obj.get("allow")? {
            serde_json::Value::String(s) if s == "*" => Allow::All,
            serde_json::Value::Array(items) => {
                let mut set = HashSet::with_capacity(items.len());
                for item in items {
                    set.insert(item.as_str()?.to_string());
                }
                Allow::List(set)
            }
            _ => return None,
        };
        let mode = match obj.get("mode")?.as_str()? {
            "trigger" => Mode::Trigger,
            "drop" => Mode::Drop,
            _ => return None,
        };
        Some(Entry { allow, mode })
    }
}

/// Parsed sender allowlist. `Default` is the TS default: everyone allowed,
/// `trigger` mode, `logDenied: true`.
#[derive(Debug, Clone)]
pub struct SenderAllowlist {
    default: Entry,
    chats: HashMap<String, Entry>,
    log_denied: bool,
}

impl Default for SenderAllowlist {
    fn default() -> Self {
        Self {
            default: Entry::allow_all(),
            chats: HashMap::new(),
            log_denied: true,
        }
    }
}

impl SenderAllowlist {
    /// Load the allowlist; whether it is mandatory is taken from the process
    /// environment ([`REQUIRED_ENV`]). Hosts that read settings from `.env`
    /// should call [`SenderAllowlist::load_with_policy`] instead.
    pub fn load(path: &Path) -> Self {
        let required = std::env::var(REQUIRED_ENV)
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        Self::load_with_policy(path, required)
    }

    /// Load the allowlist. With `required`, a missing/invalid file denies
    /// every sender (fail closed) instead of allowing everyone.
    pub fn load_with_policy(path: &Path, required: bool) -> Self {
        let fallback = || {
            if required {
                Self::deny_all()
            } else {
                Self::default()
            }
        };
        let md = match std::fs::metadata(path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if required {
                    tracing::warn!(path = %path.display(), "sender-allowlist: required but missing; denying all senders");
                }
                return fallback();
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "sender-allowlist: cannot read config");
                return fallback();
            }
        };
        if !md.is_file() || md.len() > MAX_FILE_BYTES {
            tracing::warn!(path = %path.display(), "sender-allowlist: not a regular file or too large");
            return fallback();
        }
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "sender-allowlist: cannot read config");
                return fallback();
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(path = %path.display(), "sender-allowlist: invalid JSON");
                return fallback();
            }
        };
        match Self::parse(&value) {
            Some(list) => list,
            None => {
                tracing::warn!(path = %path.display(), "sender-allowlist: invalid or missing default entry");
                fallback()
            }
        }
    }

    /// Build from an already parsed JSON document (TS semantics: an invalid
    /// `default` yields the allow-all default).
    pub fn from_json(value: serde_json::Value) -> Self {
        Self::parse(&value).unwrap_or_default()
    }

    /// An allowlist nobody passes (`allow: []`, `trigger` mode).
    pub fn deny_all() -> Self {
        Self {
            default: Entry {
                allow: Allow::List(HashSet::new()),
                mode: Mode::Trigger,
            },
            chats: HashMap::new(),
            log_denied: true,
        }
    }

    fn parse(value: &serde_json::Value) -> Option<Self> {
        let obj = value.as_object()?;
        let default = Entry::parse(obj.get("default")?)?;
        let mut chats = HashMap::new();
        if let Some(map) = obj.get("chats").and_then(serde_json::Value::as_object) {
            for (jid, entry) in map {
                match Entry::parse(entry) {
                    Some(e) => {
                        chats.insert(jid.clone(), e);
                    }
                    None => {
                        tracing::warn!(jid = %jid, "sender-allowlist: skipping invalid chat entry");
                    }
                }
            }
        }
        let log_denied = obj.get("logDenied") != Some(&serde_json::Value::Bool(false));
        Some(Self {
            default,
            chats,
            log_denied,
        })
    }

    fn entry(&self, chat_jid: &str) -> &Entry {
        self.chats.get(chat_jid).unwrap_or(&self.default)
    }

    /// Whether denied senders should be logged.
    pub fn log_denied(&self) -> bool {
        self.log_denied
    }

    /// May this sender's messages be processed at all?
    pub fn is_sender_allowed(&self, chat_jid: &str, sender: &str) -> bool {
        self.entry(chat_jid).allows(sender)
    }

    /// Drop the message before it is stored (drop mode entries).
    ///
    /// True when the chat's entry is in `drop` mode **and** the sender is not
    /// allowed (TS: `shouldDropMessage(chat) && !isSenderAllowed(chat, sender)`).
    pub fn should_drop_message(&self, chat_jid: &str, sender: &str) -> bool {
        let entry = self.entry(chat_jid);
        let drop = entry.mode == Mode::Drop && !entry.allows(sender);
        if drop && self.log_denied {
            tracing::debug!(chat_jid = %chat_jid, sender = %sender, "sender-allowlist: dropping message (drop mode)");
        }
        drop
    }

    /// Whether the chat's entry is in `drop` mode (TS `shouldDropMessage`).
    pub fn is_drop_mode(&self, chat_jid: &str) -> bool {
        self.entry(chat_jid).mode == Mode::Drop
    }

    /// May this sender wake the agent with the trigger word?
    pub fn is_trigger_allowed(&self, chat_jid: &str, sender: &str) -> bool {
        let allowed = self.is_sender_allowed(chat_jid, sender);
        if !allowed && self.log_denied {
            tracing::debug!(chat_jid = %chat_jid, sender = %sender, "sender-allowlist: trigger denied for sender");
        }
        allowed
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write(dir: &tempfile::TempDir, value: &serde_json::Value) -> std::path::PathBuf {
        let p = dir.path().join("sender-allowlist.json");
        std::fs::write(&p, value.to_string()).unwrap();
        p
    }

    // --- loadSenderAllowlist (ported) ---

    #[test]
    fn missing_file_allows_all() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = SenderAllowlist::load_with_policy(&dir.path().join("nope.json"), false);
        assert!(cfg.is_sender_allowed("g1", "anyone"));
        assert!(!cfg.is_drop_mode("g1"));
        assert!(cfg.log_denied());
    }

    #[test]
    fn loads_allow_star() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": "*", "mode": "trigger"}, "chats": {}, "logDenied": false}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, false);
        assert!(cfg.is_sender_allowed("g", "x"));
        assert!(!cfg.log_denied());
    }

    #[test]
    fn loads_empty_list_as_deny_all() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": [], "mode": "trigger"}, "chats": {}}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, false);
        assert!(!cfg.is_sender_allowed("g", "x"));
    }

    #[test]
    fn loads_list_and_drop_mode() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": ["alice", "bob"], "mode": "drop"}, "chats": {}}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, false);
        assert!(cfg.is_sender_allowed("g", "alice"));
        assert!(cfg.is_sender_allowed("g", "bob"));
        assert!(!cfg.is_sender_allowed("g", "eve"));
        assert!(cfg.is_drop_mode("g"));
    }

    #[test]
    fn per_chat_override_beats_default_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": "*", "mode": "trigger"}, "chats": {"group-a": {"allow": ["alice"], "mode": "drop"}}}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, false);
        assert!(cfg.is_drop_mode("group-a"));
        assert!(cfg.is_sender_allowed("group-a", "alice"));
        assert!(!cfg.is_sender_allowed("group-a", "bob"));
    }

    #[test]
    fn invalid_json_allows_all() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.json");
        std::fs::write(&p, "{ not valid json }}}").unwrap();
        assert!(SenderAllowlist::load_with_policy(&p, false).is_sender_allowed("g", "x"));
    }

    #[test]
    fn invalid_schema_allows_all() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, &json!({"default": {"oops": true}}));
        assert!(SenderAllowlist::load_with_policy(&p, false).is_sender_allowed("g", "x"));
    }

    #[test]
    fn non_string_allow_items_fall_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": [123, null, true], "mode": "trigger"}, "chats": {}}),
        );
        assert!(SenderAllowlist::load_with_policy(&p, false).is_sender_allowed("g", "x"));
    }

    #[test]
    fn invalid_chat_entries_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": "*", "mode": "trigger"}, "chats": {"good": {"allow": ["alice"], "mode": "trigger"}, "bad": {"allow": 123}}}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, false);
        assert!(!cfg.is_sender_allowed("good", "bob"));
        // "bad" fell back to the default entry
        assert!(cfg.is_sender_allowed("bad", "bob"));
    }

    #[test]
    fn required_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = SenderAllowlist::load_with_policy(&dir.path().join("nope.json"), true);
        assert!(!cfg.is_sender_allowed("g", "x"));
        assert!(!cfg.is_trigger_allowed("g", "x"));
        // trigger mode: messages are still stored
        assert!(!cfg.should_drop_message("g", "x"));
        let p = dir.path().join("bad.json");
        std::fs::write(&p, "nope").unwrap();
        assert!(!SenderAllowlist::load_with_policy(&p, true).is_sender_allowed("g", "x"));
        // a valid file is honoured as-is when required
        let p = write(
            &dir,
            &json!({"default": {"allow": ["alice"], "mode": "trigger"}}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, true);
        assert!(cfg.is_sender_allowed("g", "alice"));
    }

    #[test]
    fn directory_instead_of_file_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        assert!(SenderAllowlist::load_with_policy(dir.path(), false).is_sender_allowed("g", "x"));
        assert!(!SenderAllowlist::load_with_policy(dir.path(), true).is_sender_allowed("g", "x"));
    }

    // --- isSenderAllowed (ported) ---

    #[test]
    fn allow_star_allows_any() {
        let cfg = SenderAllowlist::from_json(
            json!({"default": {"allow": "*", "mode": "trigger"}, "chats": {}, "logDenied": true}),
        );
        assert!(cfg.is_sender_allowed("g1", "anyone"));
    }

    #[test]
    fn allow_empty_denies_any() {
        let cfg = SenderAllowlist::from_json(
            json!({"default": {"allow": [], "mode": "trigger"}, "chats": {}}),
        );
        assert!(!cfg.is_sender_allowed("g1", "anyone"));
    }

    #[test]
    fn exact_match_only() {
        let cfg = SenderAllowlist::from_json(
            json!({"default": {"allow": ["alice", "bob"], "mode": "trigger"}}),
        );
        assert!(cfg.is_sender_allowed("g1", "alice"));
        assert!(!cfg.is_sender_allowed("g1", "eve"));
        assert!(!cfg.is_sender_allowed("g1", "Alice"));
        assert!(!cfg.is_sender_allowed("g1", "alice "));
        assert!(!cfg.is_sender_allowed("g1", ""));
    }

    #[test]
    fn per_chat_entry_over_default() {
        let cfg = SenderAllowlist::from_json(
            json!({"default": {"allow": "*", "mode": "trigger"}, "chats": {"g1": {"allow": ["alice"], "mode": "trigger"}}}),
        );
        assert!(!cfg.is_sender_allowed("g1", "bob"));
        assert!(cfg.is_sender_allowed("g2", "bob"));
    }

    #[test]
    fn from_json_invalid_is_default() {
        let cfg = SenderAllowlist::from_json(json!([1, 2, 3]));
        assert!(cfg.is_sender_allowed("g", "x"));
        let cfg =
            SenderAllowlist::from_json(json!({"default": {"allow": "all", "mode": "trigger"}}));
        assert!(cfg.is_sender_allowed("g", "x"));
        let cfg = SenderAllowlist::from_json(json!({"default": {"allow": "*", "mode": "block"}}));
        assert!(!cfg.is_drop_mode("g"));
    }

    // --- shouldDropMessage (ported, with sender) ---

    #[test]
    fn trigger_mode_never_drops() {
        let cfg = SenderAllowlist::from_json(json!({"default": {"allow": [], "mode": "trigger"}}));
        assert!(!cfg.should_drop_message("g1", "eve"));
    }

    #[test]
    fn drop_mode_drops_only_denied_senders() {
        let cfg =
            SenderAllowlist::from_json(json!({"default": {"allow": ["alice"], "mode": "drop"}}));
        assert!(cfg.should_drop_message("g1", "eve"));
        assert!(!cfg.should_drop_message("g1", "alice"));
        let star = SenderAllowlist::from_json(json!({"default": {"allow": "*", "mode": "drop"}}));
        assert!(star.is_drop_mode("g1"));
        assert!(!star.should_drop_message("g1", "anyone"));
    }

    #[test]
    fn per_chat_mode_override() {
        let cfg = SenderAllowlist::from_json(
            json!({"default": {"allow": "*", "mode": "trigger"}, "chats": {"g1": {"allow": [], "mode": "drop"}}}),
        );
        assert!(cfg.should_drop_message("g1", "x"));
        assert!(!cfg.should_drop_message("g2", "x"));
        assert!(cfg.is_drop_mode("g1"));
        assert!(!cfg.is_drop_mode("g2"));
    }

    // --- isTriggerAllowed (ported) ---

    #[test]
    fn trigger_allowed_follows_sender_allowlist() {
        let cfg = SenderAllowlist::from_json(
            json!({"default": {"allow": ["alice"], "mode": "trigger"}, "logDenied": false}),
        );
        assert!(cfg.is_trigger_allowed("g1", "alice"));
        assert!(!cfg.is_trigger_allowed("g1", "eve"));
        let logging = SenderAllowlist::from_json(
            json!({"default": {"allow": ["alice"], "mode": "trigger"}, "logDenied": true}),
        );
        assert!(!logging.is_trigger_allowed("g1", "eve"));
    }

    #[test]
    fn default_and_deny_all() {
        assert!(SenderAllowlist::default().is_trigger_allowed("g", "x"));
        let d = SenderAllowlist::deny_all();
        assert!(!d.is_trigger_allowed("g", "x"));
        assert!(!d.should_drop_message("g", "x"));
    }
}
