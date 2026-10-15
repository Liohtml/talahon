//! Live view of the sender allowlist.
//!
//! An operator can edit `sender-allowlist.json` without a restart:
//! [`AllowlistSource`] picks up changes on the next check, but only
//! re-parses when the file's modification time or size changed.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use talon_security::senders::SenderAllowlist;

/// File identity used to detect edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
}

enum Mode {
    File {
        path: PathBuf,
        required: bool,
        cache: Mutex<Option<(Option<Stamp>, Arc<SenderAllowlist>)>>,
    },
    Fixed(Arc<SenderAllowlist>),
}

/// Source of the current [`SenderAllowlist`].
pub struct AllowlistSource {
    mode: Mode,
}

impl std::fmt::Debug for AllowlistSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.mode {
            Mode::File { path, required, .. } => f
                .debug_struct("AllowlistSource")
                .field("path", path)
                .field("required", required)
                .finish(),
            Mode::Fixed(_) => f.write_str("AllowlistSource(fixed)"),
        }
    }
}

impl AllowlistSource {
    /// Read `path`; with `required`, a missing or invalid file denies every
    /// sender (`TALON_SENDER_ALLOWLIST_REQUIRED`).
    pub fn from_file(path: PathBuf, required: bool) -> Self {
        Self {
            mode: Mode::File {
                path,
                required,
                cache: Mutex::new(None),
            },
        }
    }

    /// Always the given allowlist (tests).
    pub fn fixed(list: SenderAllowlist) -> Self {
        Self {
            mode: Mode::Fixed(Arc::new(list)),
        }
    }

    /// The allowlist as currently on disk.
    pub fn current(&self) -> Arc<SenderAllowlist> {
        match &self.mode {
            Mode::Fixed(list) => Arc::clone(list),
            Mode::File {
                path,
                required,
                cache,
            } => {
                let stamp = std::fs::metadata(path).ok().map(|m| Stamp {
                    modified: m.modified().ok(),
                    len: m.len(),
                });
                let mut cache = cache.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some((cached, list)) = cache.as_ref() {
                    if *cached == stamp {
                        return Arc::clone(list);
                    }
                }
                let list = Arc::new(SenderAllowlist::load_with_policy(path, *required));
                *cache = Some((stamp, Arc::clone(&list)));
                list
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_allows_everyone_unless_required() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sender-allowlist.json");
        let open = AllowlistSource::from_file(path.clone(), false);
        assert!(open.current().is_trigger_allowed("tg:1", "alice"));
        let closed = AllowlistSource::from_file(path, true);
        assert!(!closed.current().is_trigger_allowed("tg:1", "alice"));
    }

    #[test]
    fn edits_are_picked_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sender-allowlist.json");
        let src = AllowlistSource::from_file(path.clone(), false);
        assert!(!src.current().should_drop_message("tg:1", "mallory"));
        std::fs::write(
            &path,
            r#"{"default":{"allow":"*","mode":"trigger"},"chats":{"tg:1":{"allow":["alice"],"mode":"drop"}}}"#,
        )
        .unwrap();
        let list = src.current();
        assert!(list.should_drop_message("tg:1", "mallory"));
        assert!(!list.should_drop_message("tg:1", "alice"));
    }
}
