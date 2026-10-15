//! Hardened, descriptor-relative filesystem access for IPC directories.
//!
//! Everything below `data/ipc/<ipc_key>/` is writable by a (potentially
//! compromised) container, so path-based APIs are unsafe there: a container
//! can swap `messages/` for a symlink to a host directory between a check
//! and a use, or plant `x.json -> /home/user/.ssh/id_rsa`. This module
//! therefore:
//!
//! - opens every container-controlled directory with
//!   `O_DIRECTORY | O_NOFOLLOW` relative to an already-open parent and then
//!   works only through that descriptor (`openat`, `unlinkat`, `renameat`),
//!   so later path swaps cannot redirect host-side reads or deletes;
//! - opens files with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY` (symlinks fail,
//!   FIFOs cannot block, no controlling tty) and decides on the *opened*
//!   inode via `fstat`: regular file, single hard link, size within limit;
//! - reads at most `limit + 1` bytes;
//! - never moves container-created inodes into host-owned directories:
//!   quarantine records in `errors/` are new files the host writes itself
//!   (mode 0600) and the offending entry is unlinked in place.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde_json::json;

use crate::config::ERRORS_DIR_NAME;

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn file_read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC
}

fn is_symlink_errno(e: Errno) -> bool {
    // Linux/macOS report O_NOFOLLOW on a symlink as ELOOP, FreeBSD as EMLINK.
    e == Errno::LOOP || e == Errno::MLINK
}

/// Open (creating if needed) the IPC root. The root itself is operator
/// controlled, so it may legitimately be a symlink (e.g. data on another
/// volume); everything *below* it is opened with `O_NOFOLLOW`.
pub(crate) fn open_base(path: &Path) -> io::Result<OwnedFd> {
    std::fs::create_dir_all(path)?;
    Ok(rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Result of opening a container-controlled sub-directory.
#[derive(Debug)]
pub(crate) enum SubDir {
    /// A real directory, pinned by descriptor.
    Opened(OwnedFd),
    /// Does not exist (nothing to do).
    Missing,
    /// Exists but is a symlink or not a directory — never followed.
    Unsafe(String),
}

/// Open `name` below `parent` as a directory without following symlinks.
pub(crate) fn open_subdir(parent: BorrowedFd<'_>, name: &str) -> io::Result<SubDir> {
    match rfs::openat(parent, name, dir_flags(), Mode::empty()) {
        Ok(fd) => Ok(SubDir::Opened(fd)),
        Err(e) if e == Errno::NOENT => Ok(SubDir::Missing),
        Err(e) if is_symlink_errno(e) || e == Errno::NOTDIR => Ok(SubDir::Unsafe(format!(
            "{name:?} is a symlink or not a directory; refusing to follow it"
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Sorted `*.json` names of a directory.
#[derive(Debug, Default)]
pub(crate) struct Listing {
    /// Candidate names in byte (== lexical) order.
    pub names: Vec<CString>,
    /// The directory had more than `max_entries` entries; only the first
    /// `max_entries` (in readdir order) were considered.
    pub truncated: bool,
}

/// List `*.json` entries (in-progress `*.json.tmp` writes are skipped).
pub(crate) fn list_json(dir: BorrowedFd<'_>, max_entries: usize) -> io::Result<Listing> {
    let reader = rfs::Dir::read_from(dir)?;
    let mut listing = Listing::default();
    let mut seen = 0usize;
    for entry in reader {
        let entry = entry?;
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        seen += 1;
        if seen > max_entries {
            listing.truncated = true;
            break;
        }
        if bytes.ends_with(b".json") {
            listing.names.push(name.to_owned());
        }
    }
    listing.names.sort();
    Ok(listing)
}

/// Outcome of reading one candidate entry.
#[derive(Debug)]
pub(crate) enum ReadOutcome {
    /// A regular, singly-linked file within the size limit.
    Ok(Vec<u8>),
    /// Disappeared before it could be opened.
    Vanished,
    /// Unsafe or unreadable; must be removed and quarantined.
    Rejected {
        reason: String,
        content: Option<Vec<u8>>,
    },
}

fn describe(ft: std::fs::FileType) -> &'static str {
    if ft.is_dir() {
        "directory"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_fifo() {
        "fifo"
    } else if ft.is_socket() {
        "socket"
    } else if ft.is_block_device() || ft.is_char_device() {
        "device"
    } else {
        "special file"
    }
}

fn rejected(reason: impl Into<String>) -> ReadOutcome {
    ReadOutcome::Rejected {
        reason: reason.into(),
        content: None,
    }
}

/// Safely read the entry `name` of `dir`, capped at `max_bytes`.
pub(crate) fn read_entry(dir: BorrowedFd<'_>, name: &CStr, max_bytes: u64) -> ReadOutcome {
    let fd = match rfs::openat(dir, name, file_read_flags(), Mode::empty()) {
        Ok(fd) => fd,
        Err(e) if e == Errno::NOENT => return ReadOutcome::Vanished,
        Err(e) if is_symlink_errno(e) => return rejected("symbolic link"),
        Err(e) => return rejected(format!("cannot open: {e}")),
    };
    let file = File::from(fd);
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return rejected(format!("cannot stat: {e}")),
    };
    let ft = meta.file_type();
    if !ft.is_file() {
        return rejected(format!("not a regular file ({})", describe(ft)));
    }
    if meta.nlink() > 1 {
        return rejected(format!("regular file with {} hard links", meta.nlink()));
    }
    if meta.len() > max_bytes {
        return rejected(format!(
            "file too large ({} bytes > {max_bytes} byte limit)",
            meta.len()
        ));
    }
    let mut buf = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    if let Err(e) = file.take(max_bytes.saturating_add(1)).read_to_end(&mut buf) {
        return rejected(format!("read failed: {e}"));
    }
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
        return rejected(format!(
            "file grew beyond the {max_bytes} byte limit while reading"
        ));
    }
    ReadOutcome::Ok(buf)
}

/// Result of [`remove_entry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Removal {
    /// Unlinked (or, for a non-empty directory, renamed aside).
    Removed,
    /// Someone else removed it first — treat as not claimed.
    Vanished,
}

fn aside_name() -> CString {
    let millis = chrono::Utc::now().timestamp_millis();
    let rand: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect();
    // Only ASCII digits, letters and '-' / '.': no interior NUL possible.
    CString::new(format!(".rejected-{millis}-{rand}")).unwrap_or_default()
}

/// Remove `name` from `dir` without following symlinks. Symlinks, FIFOs and
/// sockets are unlinked (the link itself, never its target); an empty
/// directory is removed; a non-empty directory is renamed aside within the
/// same (container-owned) directory so it no longer matches `*.json`.
pub(crate) fn remove_entry(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<Removal> {
    match rfs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) => Ok(Removal::Removed),
        Err(e) if e == Errno::NOENT => Ok(Removal::Vanished),
        Err(e) if e == Errno::ISDIR || e == Errno::PERM => {
            match rfs::unlinkat(dir, name, AtFlags::REMOVEDIR) {
                Ok(()) => Ok(Removal::Removed),
                Err(e2) if e2 == Errno::NOENT => Ok(Removal::Vanished),
                Err(e2) if e2 == Errno::NOTEMPTY || e2 == Errno::EXIST => {
                    rfs::renameat(dir, name, dir, aside_name().as_c_str())?;
                    Ok(Removal::Removed)
                }
                Err(_) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// One rejected or dead-lettered IPC file, written to `errors/`.
#[derive(Debug, Clone)]
pub(crate) struct QuarantineRecord {
    pub ipc_key: String,
    pub folder: String,
    /// `messages` | `tasks`
    pub dir: &'static str,
    /// Original file name (lossy UTF-8).
    pub file: String,
    pub reason: String,
    /// Original bytes, if they were read.
    pub content: Option<Vec<u8>>,
    /// Parsed and authorized but the host/db failed (vs. malformed input).
    pub dead_letter: bool,
}

/// Open (creating with mode 0700 if needed) the host-owned quarantine dir.
pub(crate) fn open_errors_dir(base: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    match rfs::mkdirat(base, ERRORS_DIR_NAME, Mode::RWXU) {
        Ok(()) => {}
        Err(e) if e == Errno::EXIST => {}
        Err(e) => return Err(e.into()),
    }
    Ok(rfs::openat(
        base,
        ERRORS_DIR_NAME,
        dir_flags(),
        Mode::empty(),
    )?)
}

/// Restrict a name to `[A-Za-z0-9._-]`, at most 80 chars, minus `.json`.
fn sanitize_component(name: &str) -> String {
    let stem = name.strip_suffix(".json").unwrap_or(name);
    let s: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    if s.is_empty() { "unnamed".into() } else { s }
}

/// Write `rec` as a JSON envelope `<millis>-<unique>-<key>-<dir>-<name>.json`
/// (mode 0600, `O_EXCL`). Returns the file name.
pub(crate) fn write_quarantine(
    errors: BorrowedFd<'_>,
    rec: &QuarantineRecord,
    unique: u64,
    max_content: usize,
) -> io::Result<String> {
    let now = chrono::Utc::now();
    let name = format!(
        "{:013}-{unique:06}-{}-{}-{}.json",
        now.timestamp_millis().max(0),
        sanitize_component(&rec.ipc_key),
        rec.dir,
        sanitize_component(&rec.file)
    );
    let (content, truncated, size) = match &rec.content {
        Some(bytes) => {
            let keep = &bytes[..bytes.len().min(max_content)];
            (
                Some(String::from_utf8_lossy(keep).into_owned()),
                bytes.len() > keep.len(),
                Some(bytes.len()),
            )
        }
        None => (None, false, None),
    };
    let envelope = json!({
        "quarantinedAt": talon_core::time::to_iso(now),
        "ipcKey": rec.ipc_key,
        "groupFolder": rec.folder,
        "dir": rec.dir,
        "file": rec.file,
        "reason": rec.reason,
        "deadLetter": rec.dead_letter,
        "size": size,
        "contentTruncated": truncated,
        "content": content,
    });
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(io::Error::other)?;
    let fd = rfs::openat(
        errors,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    let mut f = File::from(fd);
    f.write_all(&bytes)?;
    Ok(name)
}

/// Records written by this module start with a 13-digit millisecond stamp.
fn is_timestamped(name: &CStr) -> bool {
    let b = name.to_bytes();
    b.len() > 14
        && b.get(..13)
            .is_some_and(|p| p.iter().all(u8::is_ascii_digit))
        && b.get(13) == Some(&b'-')
}

/// Keep at most `max_files` entries in the quarantine directory. Legacy
/// (non-timestamped, written by earlier releases) entries are pruned first,
/// then the oldest records. Returns how many entries were removed.
pub(crate) fn prune_quarantine(errors: BorrowedFd<'_>, max_files: usize) -> io::Result<usize> {
    let reader = rfs::Dir::read_from(errors)?;
    let mut names = Vec::new();
    for entry in reader {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(entry.file_name().to_owned());
        }
    }
    if names.len() <= max_files {
        return Ok(0);
    }
    names.sort_by(|a, b| (is_timestamped(a), a).cmp(&(is_timestamped(b), b)));
    let excess = names.len() - max_files;
    let mut removed = 0;
    for name in names.iter().take(excess) {
        if rfs::unlinkat(errors, name.as_c_str(), AtFlags::empty()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn subdir_refuses_symlinks_and_files() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("real")).unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("link")).unwrap();
        std::fs::write(tmp.path().join("file"), b"x").unwrap();
        let base = open_base(tmp.path()).unwrap();
        assert!(matches!(
            open_subdir(base.as_fd(), "real").unwrap(),
            SubDir::Opened(_)
        ));
        assert!(matches!(
            open_subdir(base.as_fd(), "link").unwrap(),
            SubDir::Unsafe(_)
        ));
        assert!(matches!(
            open_subdir(base.as_fd(), "file").unwrap(),
            SubDir::Unsafe(_)
        ));
        assert!(matches!(
            open_subdir(base.as_fd(), "nope").unwrap(),
            SubDir::Missing
        ));
    }

    #[test]
    fn listing_is_sorted_filtered_and_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        for n in ["b.json", "a.json", "c.json.tmp", "notes.txt", "0.json"] {
            std::fs::write(tmp.path().join(n), b"{}").unwrap();
        }
        let base = open_base(tmp.path()).unwrap();
        let l = list_json(base.as_fd(), 100).unwrap();
        let names: Vec<_> = l.names.iter().map(|n| n.to_str().unwrap()).collect();
        assert_eq!(names, ["0.json", "a.json", "b.json"]);
        assert!(!l.truncated);
        let l = list_json(base.as_fd(), 2).unwrap();
        assert!(l.truncated);
        assert!(l.names.len() <= 2);
    }

    #[test]
    fn read_rejects_symlink_without_touching_target() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret.txt");
        std::fs::write(&secret, b"TOP SECRET").unwrap();
        let dir = tmp.path().join("messages");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&secret, dir.join("x.json")).unwrap();
        let fd = open_base(&dir).unwrap();
        match read_entry(fd.as_fd(), &cstr("x.json"), 1024) {
            ReadOutcome::Rejected { reason, content } => {
                assert!(reason.contains("symbolic link"));
                assert!(content.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            remove_entry(fd.as_fd(), &cstr("x.json")).unwrap(),
            Removal::Removed
        );
        assert!(!dir.join("x.json").exists());
        assert_eq!(std::fs::read(&secret).unwrap(), b"TOP SECRET");
    }

    #[test]
    fn read_enforces_size_and_links() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("big.json"), vec![b' '; 2048]).unwrap();
        std::fs::write(tmp.path().join("ok.json"), b"{\"a\":1}").unwrap();
        std::fs::write(tmp.path().join("orig.json"), b"{}").unwrap();
        std::fs::hard_link(tmp.path().join("orig.json"), tmp.path().join("hl.json")).unwrap();
        let fd = open_base(tmp.path()).unwrap();
        assert!(matches!(
            read_entry(fd.as_fd(), &cstr("big.json"), 1024),
            ReadOutcome::Rejected { .. }
        ));
        match read_entry(fd.as_fd(), &cstr("ok.json"), 1024) {
            ReadOutcome::Ok(b) => assert_eq!(b, b"{\"a\":1}"),
            other => panic!("unexpected {other:?}"),
        }
        match read_entry(fd.as_fd(), &cstr("hl.json"), 1024) {
            ReadOutcome::Rejected { reason, .. } => assert!(reason.contains("hard links")),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            read_entry(fd.as_fd(), &cstr("missing.json"), 1024),
            ReadOutcome::Vanished
        ));
    }

    #[test]
    fn directories_are_rejected_and_removed_or_renamed() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("empty.json")).unwrap();
        std::fs::create_dir(tmp.path().join("full.json")).unwrap();
        std::fs::write(tmp.path().join("full.json").join("inner"), b"x").unwrap();
        let fd = open_base(tmp.path()).unwrap();
        assert!(matches!(
            read_entry(fd.as_fd(), &cstr("empty.json"), 1024),
            ReadOutcome::Rejected { .. }
        ));
        assert_eq!(
            remove_entry(fd.as_fd(), &cstr("empty.json")).unwrap(),
            Removal::Removed
        );
        assert_eq!(
            remove_entry(fd.as_fd(), &cstr("full.json")).unwrap(),
            Removal::Removed
        );
        assert!(!tmp.path().join("empty.json").exists());
        assert!(!tmp.path().join("full.json").exists());
        let l = list_json(fd.as_fd(), 100).unwrap();
        assert!(l.names.is_empty());
        assert_eq!(
            remove_entry(fd.as_fd(), &cstr("gone.json")).unwrap(),
            Removal::Vanished
        );
    }

    #[test]
    fn fifo_does_not_block() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("pipe.json");
        let status = std::process::Command::new("mkfifo").arg(&path).status();
        if !matches!(status, Ok(s) if s.success()) {
            eprintln!("mkfifo unavailable; skipping");
            return;
        }
        let fd = open_base(tmp.path()).unwrap();
        match read_entry(fd.as_fd(), &cstr("pipe.json"), 1024) {
            ReadOutcome::Rejected { reason, .. } => assert!(reason.contains("fifo"), "{reason}"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            remove_entry(fd.as_fd(), &cstr("pipe.json")).unwrap(),
            Removal::Removed
        );
    }

    #[test]
    fn quarantine_records_and_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let base = open_base(tmp.path()).unwrap();
        let errors = open_errors_dir(base.as_fd()).unwrap();
        // legacy (non-timestamped) entry is pruned first
        std::fs::write(tmp.path().join("errors").join("main-1.json"), b"{}").unwrap();
        let rec = QuarantineRecord {
            ipc_key: "main".into(),
            folder: "main".into(),
            dir: "tasks",
            file: "../../weird name.json".into(),
            reason: "invalid JSON".into(),
            content: Some(b"{not json".to_vec()),
            dead_letter: false,
        };
        let mut names = Vec::new();
        for i in 0..4 {
            names.push(write_quarantine(errors.as_fd(), &rec, i, 4).unwrap());
        }
        for n in &names {
            assert!(!n.contains('/') && !n.contains(' '), "{n}");
        }
        let body: serde_json::Value = serde_json::from_slice(
            &std::fs::read(tmp.path().join("errors").join(&names[0])).unwrap(),
        )
        .unwrap();
        assert_eq!(body["content"], "{not");
        assert_eq!(body["contentTruncated"], true);
        assert_eq!(body["reason"], "invalid JSON");
        let mode = std::fs::metadata(tmp.path().join("errors").join(&names[0]))
            .unwrap()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let removed = prune_quarantine(errors.as_fd(), 2).unwrap();
        assert_eq!(removed, 3);
        let mut left: Vec<_> = std::fs::read_dir(tmp.path().join("errors"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, vec![names[2].clone(), names[3].clone()]);
    }

    #[test]
    fn sanitizes_components() {
        assert_eq!(sanitize_component("../a b.json"), ".._a_b");
        assert_eq!(sanitize_component(""), "unnamed");
        assert_eq!(sanitize_component(&"x".repeat(500)).len(), 80);
    }
}
