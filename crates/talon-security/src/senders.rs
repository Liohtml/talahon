//! Per-chat sender allowlist.
//! File: `~/.config/talon/sender-allowlist.json`. Missing file => everyone
//! allowed (legacy behaviour) unless `TALON_SENDER_ALLOWLIST_REQUIRED=true`.
//!
//! File format:
//!
//! ```json
//! {
//!   "default": { "allow": "*", "mode": "trigger" },
//!   "chats": { "tg:-100123": { "allow": ["12345", "67890"], "mode": "drop" } },
//!   "logDenied": true
//! }
//! ```
//!
//! - `allow`: `"*"` (everyone) or an exact list of sender ids (strings or
//!   numbers: Telegram ids are often written as numbers).
//! - `mode`: `trigger` (messages are stored, but only allowed senders can
//!   wake the agent) or `drop` (messages from other senders are discarded
//!   before they are stored).
//!
//! Load semantics: a missing file yields the allow-all default unless the
//! allowlist is *required* ([`SenderAllowlist::load_with_policy`] with
//! `required = true`, or `TALON_SENDER_ALLOWLIST_REQUIRED` set in the
//! process environment for [`SenderAllowlist::load`]). A file that exists
//! but cannot be used (unreadable, invalid JSON, invalid `default` entry)
//! always fails closed, and so does an invalid per-chat entry for its chat:
//! nobody may trigger the agent there (messages are still stored, `trigger`
//! mode). An operator who wrote a file meant to restrict senders; a typo in
//! it must not let everyone in.

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
    fn deny_all() -> Self {
        Entry {
            allow: Allow::List(HashSet::new()),
            mode: Mode::Trigger,
        }
    }

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

    /// Valid entry: `allow` is `"*"` or an array of strings or numbers,
    /// `mode` is `trigger` | `drop`.
    fn parse(value: &serde_json::Value) -> Option<Self> {
        let obj = value.as_object()?;
        let allow = match obj.get("allow")? {
            serde_json::Value::String(s) if s == "*" => Allow::All,
            serde_json::Value::Array(items) => {
                let mut set = HashSet::with_capacity(items.len());
                for item in items {
                    let id = match item {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => return None,
                    };
                    set.insert(id);
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

/// Parsed sender allowlist. `Default` allows everyone, in `trigger` mode,
/// with `logDenied: true`.
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

    /// Load the allowlist. A missing file allows everyone, or nobody with
    /// `required`; a file that exists but cannot be used denies everyone
    /// (see the module docs).
    pub fn load_with_policy(path: &Path, required: bool) -> Self {
        let unusable = |reason: &str| {
            tracing::error!(path = %path.display(), reason, "sender-allowlist: unusable file; nobody may trigger the agent until it is fixed");
            Self::deny_all()
        };
        let md = match std::fs::metadata(path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if required {
                    tracing::warn!(path = %path.display(), "sender-allowlist: required but missing; denying all senders");
                    return Self::deny_all();
                }
                return Self::default();
            }
            Err(e) => return unusable(&e.to_string()),
        };
        if !md.is_file() || md.len() > MAX_FILE_BYTES {
            return unusable("not a regular file or too large");
        }
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) => return unusable(&e.to_string()),
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return unusable("invalid JSON");
        };
        Self::parse(&value).unwrap_or_else(|| unusable("invalid or missing default entry"))
    }

    /// Build from an already parsed JSON document (an invalid `default`
    /// denies everyone, as for a file).
    pub fn from_json(value: serde_json::Value) -> Self {
        Self::parse(&value).unwrap_or_else(Self::deny_all)
    }

    /// An allowlist nobody passes (`allow: []`, `trigger` mode).
    pub fn deny_all() -> Self {
        Self {
            default: Entry::deny_all(),
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
                        tracing::error!(jid = %jid, "sender-allowlist: invalid chat entry; nobody may trigger the agent in this chat");
                        chats.insert(jid.clone(), Entry::deny_all());
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
    /// allowed.
    pub fn should_drop_message(&self, chat_jid: &str, sender: &str) -> bool {
        let entry = self.entry(chat_jid);
        let drop = entry.mode == Mode::Drop && !entry.allows(sender);
        if drop && self.log_denied {
            tracing::debug!(chat_jid = %chat_jid, sender = %sender, "sender-allowlist: dropping message (drop mode)");
        }
        drop
    }

    /// Whether the chat's entry is in `drop` mode.
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
    fn invalid_json_denies_all() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.json");
        std::fs::write(&p, "{ not valid json }}}").unwrap();
        assert!(!SenderAllowlist::load_with_policy(&p, false).is_sender_allowed("g", "x"));
    }

    #[test]
    fn invalid_schema_denies_all() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, &json!({"default": {"oops": true}}));
        assert!(!SenderAllowlist::load_with_policy(&p, false).is_sender_allowed("g", "x"));
    }

    #[test]
    fn numeric_ids_are_accepted() {
        // Telegram user ids are numbers; writing them unquoted is the
        // natural mistake and must not invalidate the file.
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": [123456789, "alice"], "mode": "trigger"}}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, false);
        assert!(cfg.is_sender_allowed("g", "123456789"));
        assert!(cfg.is_sender_allowed("g", "alice"));
        assert!(!cfg.is_sender_allowed("g", "mallory"));
    }

    #[test]
    fn invalid_default_denies_everyone() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": [null, true], "mode": "trigger"}, "chats": {}}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, false);
        assert!(!cfg.is_sender_allowed("g", "x"));
        assert!(!cfg.is_trigger_allowed("g", "x"));
        // trigger mode: messages are still stored
        assert!(!cfg.should_drop_message("g", "x"));
    }

    #[test]
    fn invalid_chat_entry_denies_that_chat() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            &json!({"default": {"allow": "*", "mode": "trigger"}, "chats": {"good": {"allow": ["alice"], "mode": "trigger"}, "bad": {"allow": ["bob"], "mode": "trgger"}}}),
        );
        let cfg = SenderAllowlist::load_with_policy(&p, false);
        assert!(!cfg.is_sender_allowed("good", "bob"));
        assert!(cfg.is_sender_allowed("good", "alice"));
        // "bad" does not fall back to the allow-all default
        assert!(!cfg.is_trigger_allowed("bad", "bob"));
        assert!(cfg.is_sender_allowed("other", "anyone"));
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
    fn unusable_file_denies_everyone() {
        let dir = tempfile::tempdir().unwrap();
        for required in [false, true] {
            assert!(
                !SenderAllowlist::load_with_policy(dir.path(), required)
                    .is_sender_allowed("g", "x")
            );
        }
        let p = dir.path().join("broken.json");
        std::fs::write(&p, "{ not json").unwrap();
        assert!(!SenderAllowlist::load_with_policy(&p, false).is_sender_allowed("g", "x"));
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
    fn from_json_invalid_denies_all() {
        let cfg = SenderAllowlist::from_json(json!([1, 2, 3]));
        assert!(!cfg.is_sender_allowed("g", "x"));
        let cfg =
            SenderAllowlist::from_json(json!({"default": {"allow": "all", "mode": "trigger"}}));
        assert!(!cfg.is_sender_allowed("g", "x"));
        let cfg = SenderAllowlist::from_json(json!({"default": {"allow": "*", "mode": "block"}}));
        assert!(!cfg.is_drop_mode("g"));
        assert!(!cfg.is_trigger_allowed("g", "x"));
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
