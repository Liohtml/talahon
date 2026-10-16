//! Filesystem helpers shared by the steps: atomic writes, `.env` updates and
//! symlink-safe checks.
//!
//! Group folders are mounted read-write into agent containers, so a
//! compromised agent can plant symlinks there. Every helper that writes
//! into a location an agent could have touched refuses to follow symlinks
//! (checks use `symlink_metadata`, writes go through a temp file + rename,
//! which replaces a symlink instead of writing through it).

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use talon_core::env::parse_env;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `path` exists (without following a final symlink).
pub fn exists_nofollow(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// `path` is a regular file and not a symlink.
pub fn is_regular_file_nofollow(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// `path` is a real directory and not a symlink.
pub fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false)
}

fn tmp_path_for(path: &Path) -> io::Result<PathBuf> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_string_lossy();
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(dir.join(format!(".{name}.tmp-{}-{n}", std::process::id())))
}

/// Write `content` to `path` atomically (temp file in the same directory,
/// fsync, rename). `mode` sets the Unix permissions of the new file.
pub fn write_atomic(path: &Path, content: &[u8], mode: Option<u32>) -> io::Result<()> {
    let tmp = tmp_path_for(path)?;
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode.unwrap_or(0o644));
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(content)?;
        f.sync_all()?;
        #[cfg(unix)]
        if let Some(mode) = mode {
            // Apply exactly (the open() mode is filtered by the umask).
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Unix permission bits of an existing regular file.
pub fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Whether `key` is a sane `.env` key (`[A-Za-z_][A-Za-z0-9_]*`).
pub fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Insert or replace `KEY=<raw_value>` in the `.env` file at `path`.
///
/// `raw_value` is written verbatim (callers add quotes if they want them)
/// and must not contain line breaks or NUL — otherwise a value could smuggle
/// extra settings into `.env`. The first existing `KEY=` (or `export KEY=`)
/// line is replaced; otherwise the line is appended. The file keeps its
/// permissions (new files are created `0600`).
pub fn upsert_env_line(path: &Path, key: &str, raw_value: &str) -> io::Result<()> {
    if !is_valid_env_key(key) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid env key {key:?}"),
        ));
    }
    if raw_value.contains(['\n', '\r', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "env value contains a line break",
        ));
    }
    let new_line = format!("{key}={raw_value}");
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let content = match existing.as_deref() {
        None | Some("") => format!("{new_line}\n"),
        Some(text) => {
            let prefix = format!("{key}=");
            let export_prefix = format!("export {key}=");
            let mut replaced = false;
            let mut lines: Vec<String> = Vec::new();
            for line in text.lines() {
                // A byte-order mark may precede the first key.
                let t = line.trim_start_matches('\u{feff}').trim_start();
                if t.starts_with(&prefix) || t.starts_with(&export_prefix) {
                    // Every earlier definition goes: the last one would win.
                    if !replaced {
                        lines.push(new_line.clone());
                        replaced = true;
                    }
                } else {
                    lines.push(line.to_string());
                }
            }
            if replaced {
                let mut out = lines.join("\n");
                if text.ends_with('\n') {
                    out.push('\n');
                }
                out
            } else {
                format!("{}\n{new_line}\n", text.trim_end())
            }
        }
    };
    let mode = file_mode(path).unwrap_or(0o600);
    write_atomic(path, content.as_bytes(), Some(mode))
}

/// Value of `key` in the `.env` file at `path` (quotes stripped).
pub fn read_env_value(path: &Path, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_env(&content).get(key).cloned()
}

/// Create `dir` (and parents) and verify it is writable by creating and
/// removing a probe file.
pub fn ensure_writable_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let probe = dir.join(format!(".talon-write-probe-{}", std::process::id()));
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|mut f| f.write_all(b"ok"));
    let _ = std::fs::remove_file(&probe);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_sets_mode_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.json");
        write_atomic(&p, b"one", Some(0o600)).unwrap();
        write_atomic(&p, b"two", Some(0o600)).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two");
        assert_eq!(file_mode(&p), Some(0o600));
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn atomic_write_replaces_symlink_instead_of_following() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "precious").unwrap();
        let link = dir.path().join("CLAUDE.md");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomic(&link, b"new", None).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
        assert!(is_regular_file_nofollow(&link));
    }

    #[test]
    fn upsert_creates_file_0600() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".env");
        upsert_env_line(&p, "TZ", "Europe/Berlin").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "TZ=Europe/Berlin\n");
        assert_eq!(file_mode(&p), Some(0o600));
    }

    #[test]
    fn upsert_replaces_first_occurrence_and_keeps_rest() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(&p, "SOME_KEY=value\nASSISTANT_NAME=\"Talon\"\nOTHER=test\n").unwrap();
        upsert_env_line(&p, "ASSISTANT_NAME", "\"Nova\"").unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "SOME_KEY=value\nASSISTANT_NAME=\"Nova\"\nOTHER=test\n"
        );
    }

    #[test]
    fn upsert_replaces_every_definition_even_after_a_bom() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(&p, "\u{feff}TZ=UTC\nA=1\nTZ=Asia/Tokyo\n").unwrap();
        upsert_env_line(&p, "TZ", "Europe/Berlin").unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "TZ=Europe/Berlin\nA=1\n"
        );
        assert_eq!(read_env_value(&p, "TZ").as_deref(), Some("Europe/Berlin"));
    }

    #[test]
    fn upsert_appends_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(&p, "SOME_KEY=value\n\n").unwrap();
        upsert_env_line(&p, "ASSISTANT_NAME", "\"Nova\"").unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "SOME_KEY=value\nASSISTANT_NAME=\"Nova\"\n"
        );
        assert_eq!(
            read_env_value(&p, "ASSISTANT_NAME").as_deref(),
            Some("Nova")
        );
    }

    #[test]
    fn upsert_handles_export_prefix_and_keeps_mode() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(&p, "export TZ=UTC\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        upsert_env_line(&p, "TZ", "Asia/Tokyo").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "TZ=Asia/Tokyo\n");
        assert_eq!(file_mode(&p), Some(0o640));
    }

    #[test]
    fn upsert_rejects_injection() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".env");
        assert!(upsert_env_line(&p, "TZ", "UTC\nTALON_VLLM_BASE_URL=http://evil").is_err());
        assert!(upsert_env_line(&p, "BAD KEY", "x").is_err());
        assert!(upsert_env_line(&p, "1X", "x").is_err());
        assert!(!p.exists());
    }

    #[test]
    fn writable_dir_probe() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b");
        ensure_writable_dir(&sub).unwrap();
        assert!(is_real_dir(&sub));
        assert_eq!(std::fs::read_dir(&sub).unwrap().count(), 0);
    }

    #[test]
    fn nofollow_checks() {
        let dir = tempfile::tempdir().unwrap();
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(exists_nofollow(&dangling));
        assert!(!dangling.exists());
        assert!(!is_regular_file_nofollow(&dangling));
    }
}
