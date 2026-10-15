//! Atomic file writes (temp file in the same directory + fsync + rename).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos:x}-{n}", std::process::id())
}

/// Write `data` to `tmp` (which must not exist), fsync, then rename to `dest`.
/// The temp file is removed on failure.
fn write_then_rename(
    tmp: &Path,
    dest: &Path,
    data: &[u8],
    mode_from: Option<&Path>,
) -> io::Result<()> {
    let result = (|| {
        // `create_new` = O_CREAT|O_EXCL: never follows a pre-planted symlink.
        let mut f = OpenOptions::new().write(true).create_new(true).open(tmp)?;
        if let Some(src) = mode_from {
            if let Ok(meta) = fs::metadata(src) {
                // Best effort: keep the permissions of the file being replaced.
                let _ = f.set_permissions(meta.permissions());
            }
        }
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(tmp, dest)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

/// Atomically replace (or create) `path` with `data`. The parent directory
/// must exist. Readers never observe a partially written file.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        unique_suffix()
    ));
    write_then_rename(&tmp, path, data, Some(path))
}

/// Write an IPC file into `dir` as `<ipc_file_name>` via `<name>.tmp`
/// (`*.json.tmp` + rename, see `talon_core::protocol`). Returns the final
/// file name.
pub(crate) fn write_ipc_file(dir: &Path, data: &[u8]) -> io::Result<String> {
    fs::create_dir_all(dir)?;
    let mut last_err = None;
    for _ in 0..3 {
        let name = talon_core::protocol::ipc_file_name();
        let dest: PathBuf = dir.join(&name);
        let tmp = dir.join(format!("{name}.tmp"));
        match write_then_rename(&tmp, &dest, data, None) {
            Ok(()) => return Ok(name),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("could not allocate IPC file name")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        write_atomic(&p, b"one").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "one");
        write_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "two");
        // No temp files left behind.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn atomic_write_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.sh");
        fs::write(&p, "x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o750)).unwrap();
        write_atomic(&p, b"y").unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[test]
    fn ipc_file_written_with_json_name() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("tasks");
        let name = write_ipc_file(&sub, b"{}").unwrap();
        assert!(name.ends_with(".json"));
        assert_eq!(fs::read_to_string(sub.join(&name)).unwrap(), "{}");
        let leftovers: Vec<_> = fs::read_dir(&sub)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
