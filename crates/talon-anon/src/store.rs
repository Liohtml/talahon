//! Persistence of the token map (`session_tokens.json`).
//!
//! - **Atomic, private writes**: the map holds real PII, so it is written to
//!   a `0600` temporary file in the same directory, fsynced and renamed over
//!   the target (a pre-existing `0644` file written by the Python proxy is
//!   replaced by a `0600` one).
//! - **Cross-process safety**: several proxies (one per concurrent agent
//!   container of the same group) may share one map file. Every change runs
//!   under an advisory lock file (`<map>.lock`, created with `O_EXCL`,
//!   broken when stale) and starts by re-reading the file and rebasing the
//!   in-memory map onto it, so two proxies never hand out the same token for
//!   different values.
//! - **Corruption**: an unparseable map is moved aside to
//!   `<map>.corrupt-<unix-seconds>` (never silently overwritten).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use talon_core::{Error, Result};

use crate::tokens::TokenMap;

/// A lock file older than this is considered abandoned.
pub const LOCK_STALE_AFTER: Duration = Duration::from_secs(15);
/// Give up waiting (and break the lock) after this long.
pub const LOCK_WAIT_MAX: Duration = Duration::from_secs(15);

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
fn private_options(opts: &mut OpenOptions) -> &mut OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600)
}

#[cfg(not(unix))]
fn private_options(opts: &mut OpenOptions) -> &mut OpenOptions {
    opts
}

fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Write `bytes` to `path` atomically with mode `0600` (temp file in the
/// same directory + fsync + rename + best-effort directory fsync).
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = parent_dir(path);
    create_private_dir_all(dir)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("tokens");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp = dir.join(format!(
        ".{name}.{}.{}.{nanos}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut f = private_options(OpenOptions::new().write(true).create_new(true)).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Held advisory lock; the lock file is removed on drop.
#[derive(Debug)]
pub struct MapLock {
    path: PathBuf,
}

impl Drop for MapLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_is_stale(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age > LOCK_STALE_AFTER)
}

/// File-backed token map storage.
#[derive(Debug)]
pub struct MapStore {
    path: PathBuf,
    lock_path: PathBuf,
    last_synced: Option<Vec<u8>>,
    locking: bool,
    write_failures: u64,
}

impl MapStore {
    /// Storage at `path` (the file does not need to exist yet).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut lock_name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        lock_name.push(".lock");
        let lock_path = path.with_file_name(lock_name);
        Self {
            path,
            lock_path,
            last_synced: None,
            locking: true,
            write_failures: 0,
        }
    }

    /// The map file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the map. A missing file yields an empty map; an unreadable file
    /// yields an empty in-memory map (logged); a corrupt file is quarantined.
    pub fn load(&mut self) -> TokenMap {
        match self.read_disk() {
            Ok(Some(map)) => map,
            Ok(None) => TokenMap::new(),
            Err(e) => {
                tracing::warn!(path = %self.path.display(), error = %e, "token map unreadable; starting with an empty in-memory map");
                TokenMap::new()
            }
        }
    }

    /// Read the file; `Ok(None)` if it does not exist. Corrupt content is
    /// re-read once (a concurrent non-atomic writer may be mid-write) and
    /// then quarantined.
    fn read_disk(&mut self) -> io::Result<Option<TokenMap>> {
        let mut attempt = 0;
        loop {
            let bytes = match fs::read(&self.path) {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    self.last_synced = Some(Vec::new());
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            if bytes.iter().all(u8::is_ascii_whitespace) {
                self.last_synced = Some(bytes);
                return Ok(None);
            }
            match TokenMap::from_json_slice(&bytes) {
                Ok(map) => {
                    self.last_synced = Some(bytes);
                    return Ok(Some(map));
                }
                Err(e) if attempt == 0 => {
                    tracing::debug!(error = %e, "token map did not parse; retrying once");
                    attempt += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    self.quarantine(&e);
                    self.last_synced = Some(Vec::new());
                    return Ok(None);
                }
            }
        }
    }

    fn quarantine(&self, err: &Error) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut name = self
            .path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(".corrupt-{secs}"));
        let target = self.path.with_file_name(name);
        match fs::rename(&self.path, &target) {
            Ok(()) => {
                tracing::warn!(error = %err, moved_to = %target.display(), "token map was corrupt; moved aside")
            }
            Err(e) => {
                tracing::warn!(error = %err, rename_error = %e, "token map is corrupt and could not be moved aside")
            }
        }
    }

    /// Re-read the file if it changed since the last load/save and rebase
    /// `map` onto it. Returns `true` if the map was replaced.
    pub fn sync_into(&mut self, map: &mut TokenMap) -> bool {
        let current = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                tracing::debug!(error = %e, "token map not re-read");
                return false;
            }
        };
        if self.last_synced.as_deref() == Some(current.as_slice()) {
            return false;
        }
        let disk = if current.iter().all(u8::is_ascii_whitespace) {
            self.last_synced = Some(current);
            TokenMap::new()
        } else {
            match self.read_disk() {
                Ok(Some(m)) => m,
                Ok(None) => TokenMap::new(),
                Err(e) => {
                    tracing::debug!(error = %e, "token map not re-read");
                    return false;
                }
            }
        };
        let report = map.rebase_onto(disk);
        if report.conflicts > 0 {
            tracing::warn!(
                conflicts = report.conflicts,
                "token map changed on disk with conflicting entries; disk entries kept"
            );
        }
        tracing::debug!(
            added = report.added,
            entries = map.len(),
            "token map re-synced from disk"
        );
        true
    }

    /// Persist `map` atomically (0600) and mark it clean.
    pub fn save(&mut self, map: &mut TokenMap) -> Result<()> {
        let json = map.to_json_string()?;
        match write_private_atomic(&self.path, json.as_bytes()) {
            Ok(()) => {
                self.last_synced = Some(json.into_bytes());
                map.mark_clean();
                self.write_failures = 0;
                Ok(())
            }
            Err(e) => {
                self.write_failures += 1;
                Err(Error::Io(e))
            }
        }
    }

    /// Consecutive failed writes (for rate-limited warnings).
    pub fn write_failures(&self) -> u64 {
        self.write_failures
    }

    /// Acquire the advisory lock (best effort). Returns `None` when locking
    /// is unavailable (e.g. read-only directory), in which case the caller
    /// proceeds unlocked.
    pub fn lock(&mut self) -> Option<MapLock> {
        if !self.locking {
            return None;
        }
        let started = Instant::now();
        let mut backoff = Duration::from_millis(2);
        let mut created_dir = false;
        loop {
            match private_options(OpenOptions::new().write(true).create_new(true))
                .open(&self.lock_path)
            {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", std::process::id());
                    return Some(MapLock {
                        path: self.lock_path.clone(),
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(&self.lock_path) || started.elapsed() > LOCK_WAIT_MAX {
                        tracing::warn!(lock = %self.lock_path.display(), "breaking stale token map lock");
                        let _ = fs::remove_file(&self.lock_path);
                        continue;
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_millis(50));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && !created_dir => {
                    created_dir = true;
                    if create_private_dir_all(parent_dir(&self.lock_path)).is_err() {
                        self.disable_locking(&e);
                        return None;
                    }
                }
                Err(e) => {
                    self.disable_locking(&e);
                    return None;
                }
            }
        }
    }

    fn disable_locking(&mut self, e: &io::Error) {
        tracing::warn!(error = %e, "token map lock unavailable; continuing without cross-process locking");
        self.locking = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn atomic_write_is_private_and_replaces_public_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nested").join("session_tokens.json");
        write_private_atomic(&p, b"one").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(mode(&p), 0o600);
            fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
            write_private_atomic(&p, b"two").unwrap();
            assert_eq!(mode(&p), 0o600);
        }
        let leftovers: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn load_save_round_trip_python_format() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("session_tokens.json");
        fs::write(
            &p,
            r#"{"forward": {"john.doe": "USER_1"}, "counters": {"USER": 1}}"#,
        )
        .unwrap();
        let mut store = MapStore::new(&p);
        let mut map = store.load();
        assert_eq!(map.token_for("john.doe"), Some("USER_1"));
        map.get_or_create("jane", "USER");
        store.save(&mut map).unwrap();
        assert!(!map.is_dirty());
        let v: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["forward"]["jane"], "USER_2");
        assert_eq!(v["counters"]["USER"], 2);
    }

    #[test]
    fn missing_and_empty_files_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = MapStore::new(dir.path().join("none.json"));
        assert!(store.load().is_empty());
        let p = dir.path().join("empty.json");
        fs::write(&p, "\n").unwrap();
        assert!(MapStore::new(&p).load().is_empty());
    }

    #[test]
    fn corrupt_file_is_quarantined_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("session_tokens.json");
        fs::write(&p, "{ this is not json").unwrap();
        let mut store = MapStore::new(&p);
        assert!(store.load().is_empty());
        assert!(!p.exists());
        let quarantined: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .collect();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(
            fs::read_to_string(quarantined[0].path()).unwrap(),
            "{ this is not json"
        );
    }

    #[test]
    fn two_stores_share_one_file_without_token_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("session_tokens.json");
        let (mut s1, mut s2) = (MapStore::new(&p), MapStore::new(&p));
        let (mut m1, mut m2) = (s1.load(), s2.load());

        let _l = s1.lock().unwrap();
        s1.sync_into(&mut m1);
        assert_eq!(m1.get_or_create("alice", "USER"), "USER_1");
        s1.save(&mut m1).unwrap();
        drop(_l);

        let _l = s2.lock().unwrap();
        assert!(s2.sync_into(&mut m2));
        assert_eq!(m2.get_or_create("bob", "USER"), "USER_2");
        assert_eq!(m2.get_or_create("alice", "USER"), "USER_1");
        s2.save(&mut m2).unwrap();
        drop(_l);

        assert!(s1.sync_into(&mut m1));
        assert_eq!(m1.original_for("USER_2"), Some("bob"));
        assert!(!s1.sync_into(&mut m1), "unchanged file is not re-read");
    }

    #[test]
    fn deleted_file_is_rewritten_from_memory() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.json");
        let mut s = MapStore::new(&p);
        let mut m = s.load();
        m.get_or_create("alice", "USER");
        s.save(&mut m).unwrap();
        fs::remove_file(&p).unwrap();
        assert!(s.sync_into(&mut m));
        assert!(m.is_dirty());
        assert_eq!(m.token_for("alice"), Some("USER_1"));
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.json");
        let mut s = MapStore::new(&p);
        let lock = s.lock().unwrap();
        let lock_file = dir.path().join("t.json.lock");
        assert!(lock_file.exists());
        drop(lock);
        assert!(!lock_file.exists());
    }

    #[test]
    fn stale_lock_is_broken() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.json");
        let lock_file = dir.path().join("t.json.lock");
        fs::write(&lock_file, "99999").unwrap();
        let old = SystemTime::now() - Duration::from_secs(3600);
        File::options()
            .write(true)
            .open(&lock_file)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let mut s = MapStore::new(&p);
        let started = Instant::now();
        assert!(s.lock().is_some());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_directory_degrades_gracefully() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        fs::create_dir(&ro).unwrap();
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o500)).unwrap();
        let probe = ro.join("probe");
        if fs::write(&probe, "x").is_ok() {
            // running as root: permissions are not enforced, nothing to test
            return;
        }
        let mut s = MapStore::new(ro.join("t.json"));
        assert!(s.lock().is_none());
        let mut m = s.load();
        m.get_or_create("a", "USER");
        assert!(s.save(&mut m).is_err());
        assert!(m.is_dirty());
        assert_eq!(s.write_failures(), 1);
    }
}
