//! An anonymization session: an [`Anonymizer`] plus (optionally) its
//! persistent map file, with transactional access.
//!
//! Every mutation runs inside [`AnonSession::transaction`]: take the lock
//! file, re-sync the map from disk (other proxies may have added tokens),
//! run the closure, and write the map back atomically if it changed — so
//! tokens are on disk *before* the anonymized output that contains them is
//! released to the client.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use talon_core::Result;

use crate::config::CompiledConfig;
use crate::engine::Anonymizer;
use crate::store::MapStore;

/// Shared handle used by the proxy (both directions use one session).
pub type SharedSession = Arc<Mutex<AnonSession>>;

/// Anonymizer + optional persistent store.
#[derive(Debug)]
pub struct AnonSession {
    anonymizer: Anonymizer,
    store: Option<MapStore>,
}

impl AnonSession {
    /// Open a session backed by `map_path` (loaded now; created on first
    /// write).
    pub fn open(config: Arc<CompiledConfig>, map_path: impl Into<PathBuf>) -> Self {
        let mut store = MapStore::new(map_path);
        let map = store.load();
        tracing::info!(entries = map.len(), path = %store.path().display(), "token map loaded");
        Self {
            anonymizer: Anonymizer::with_map(config, map),
            store: Some(store),
        }
    }

    /// A session that is never persisted (tests, one-shot use).
    pub fn in_memory(config: Arc<CompiledConfig>) -> Self {
        Self {
            anonymizer: Anonymizer::new(config),
            store: None,
        }
    }

    /// Wrap into a [`SharedSession`].
    pub fn into_shared(self) -> SharedSession {
        Arc::new(Mutex::new(self))
    }

    /// Read-only access to the anonymizer (no disk sync).
    pub fn anonymizer(&self) -> &Anonymizer {
        &self.anonymizer
    }

    /// Lock, re-sync from disk, run `f`, persist if the map changed, unlock.
    pub fn transaction<R>(&mut self, f: impl FnOnce(&mut Anonymizer) -> R) -> R {
        let Some(store) = self.store.as_mut() else {
            return f(&mut self.anonymizer);
        };
        let _lock = store.lock();
        store.sync_into(self.anonymizer.map_mut());
        let out = f(&mut self.anonymizer);
        if self.anonymizer.map().is_dirty() {
            if let Err(e) = store.save(self.anonymizer.map_mut()) {
                // Keep working in memory; warn on the first failure and then
                // only occasionally.
                let n = store.write_failures();
                if n == 1 || n % 100 == 0 {
                    tracing::warn!(error = %e, failures = n, "token map could not be persisted; keeping it in memory");
                }
            }
        }
        out
    }

    /// Re-sync from disk (no lock needed: writers rename atomically), then
    /// run a read-only closure. Used for de-anonymization so tokens issued
    /// by a sibling proxy are resolvable.
    pub fn read<R>(&mut self, f: impl FnOnce(&Anonymizer) -> R) -> R {
        if let Some(store) = self.store.as_mut() {
            store.sync_into(self.anonymizer.map_mut());
        }
        f(&self.anonymizer)
    }

    /// Persist the map now if it has unsaved changes.
    pub fn flush(&mut self) -> Result<()> {
        if let Some(store) = self.store.as_mut() {
            if self.anonymizer.map().is_dirty() {
                let _lock = store.lock();
                store.sync_into(self.anonymizer.map_mut());
                store.save(self.anonymizer.map_mut())?;
            }
        }
        Ok(())
    }
}

/// Lock a shared session, recovering from poisoning (the session holds no
/// invariants a panic could break half-way that matter more than staying
/// available).
pub fn lock_session(session: &SharedSession) -> std::sync::MutexGuard<'_, AnonSession> {
    session.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Arc<CompiledConfig> {
        Arc::new(
            CompiledConfig::from_yaml_str(
                "categories:\n  user:\n    token_prefix: USER\n    fields: [user]\n",
            )
            .unwrap(),
        )
    }

    #[test]
    fn transactions_persist_and_sessions_share_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("session_tokens.json");
        let mut a = AnonSession::open(cfg(), &p);
        let mut b = AnonSession::open(cfg(), &p);
        let t = a.transaction(|an| an.anonymize_field("user", "alice"));
        assert_eq!(t, "USER_1");
        assert!(p.exists());
        let t = b.transaction(|an| an.anonymize_field("user", "bob"));
        assert_eq!(t, "USER_2", "b saw a's token before allocating");
        let restored = a.read(|an| an.deanonymize_text("USER_1 USER_2"));
        assert_eq!(restored, "alice bob");
        // a fresh session continues the numbering
        let mut c = AnonSession::open(cfg(), &p);
        assert_eq!(
            c.transaction(|an| an.anonymize_field("user", "carol")),
            "USER_3"
        );
        assert!(c.flush().is_ok());
    }

    #[test]
    fn in_memory_sessions_never_touch_disk() {
        let mut s = AnonSession::in_memory(cfg());
        assert_eq!(
            s.transaction(|an| an.anonymize_field("user", "x")),
            "USER_1"
        );
        assert!(s.flush().is_ok());
        let shared = s.into_shared();
        assert_eq!(lock_session(&shared).anonymizer().map().len(), 1);
    }
}
