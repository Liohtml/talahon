//! Descriptor-relative, symlink-safe access to agent-writable directories
//! (MYTH-10).
//!
//! Everything below `groups/<folder>/` can be changed by the lane's
//! (potentially compromised) container at any time, so path-based reads
//! there are racy: `reports/` can be swapped for a symlink to a host
//! directory between a check and the open, and a file checked with
//! `lstat` can be replaced by a FIFO that blocks the reading thread
//! forever. The helpers here therefore
//!
//! - open the operator-controlled root (`groups/`) normally and every
//!   directory below it with `O_DIRECTORY | O_NOFOLLOW`, relative to the
//!   already-open parent (`openat`), so later path swaps cannot redirect
//!   the host;
//! - open files with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`
//!   (symlinks fail, FIFOs cannot block) and decide on the *opened* inode
//!   via `fstat`: regular file, single hard link, size within the limit;
//! - read at most `limit + 1` bytes;
//! - create files only with `O_CREAT | O_EXCL | O_NOFOLLOW`, so an existing
//!   entry (including a dangling symlink) is never written through.
//!
//! Reference pattern: `crates/talon-ipc/src/fsio.rs` (not a dependency).

use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use rustix::io::Errno;

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

fn unsafe_entry(name: &str, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{name:?} is {what}; refusing to follow it"),
    )
}

/// Open an operator-controlled directory (e.g. `groups/`). It may
/// legitimately be a symlink (data on another volume); everything *below*
/// it is opened with [`open_dir_at`].
///
/// # Errors
/// The directory cannot be opened.
pub fn open_root(path: &Path) -> io::Result<OwnedFd> {
    Ok(rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Open the sub-directory `name` of `parent` without following symlinks.
///
/// # Errors
/// `NotFound` when missing; `InvalidData` when it is a symlink or not a
/// directory; other I/O errors as reported.
pub fn open_dir_at(parent: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
    match rfs::openat(parent, name, dir_flags(), Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(e) if is_symlink_errno(e) || e == Errno::NOTDIR => {
            Err(unsafe_entry(name, "a symlink or not a directory"))
        }
        Err(e) => Err(e.into()),
    }
}

/// Create the sub-directory `name` of `parent` (mode `0o755` before umask)
/// unless it exists, then open it without following symlinks.
///
/// # Errors
/// See [`open_dir_at`]; `mkdirat` failures other than "exists".
pub fn ensure_dir_at(parent: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
    match rfs::mkdirat(parent, name, Mode::from_raw_mode(0o755)) {
        Ok(()) => {}
        Err(e) if e == Errno::EXIST => {}
        Err(e) => return Err(e.into()),
    }
    open_dir_at(parent, name)
}

/// Whether `name` exists in `dir` (any type; a symlink is not followed).
///
/// # Errors
/// `fstatat` failures other than "not found".
pub fn entry_exists_at(dir: BorrowedFd<'_>, name: &str) -> io::Result<bool> {
    match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(e) if e == Errno::NOENT => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Why [`open_regular_at`] refused an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenRefusal {
    /// The entry does not exist.
    Missing,
    /// The entry exists but must not be read (symlink, FIFO, directory,
    /// hard-linked, too large, unreadable). The text says why.
    Rejected(String),
}

fn describe(ft: std::fs::FileType) -> &'static str {
    if ft.is_dir() {
        "a directory"
    } else if ft.is_symlink() {
        "a symlink"
    } else if ft.is_fifo() {
        "a fifo"
    } else if ft.is_socket() {
        "a socket"
    } else if ft.is_block_device() || ft.is_char_device() {
        "a device"
    } else {
        "a special file"
    }
}

/// Open `name` in `dir` for reading: no symlinks, non-blocking (a FIFO can
/// neither block the open nor the read), and — checked on the opened inode
/// — a regular file with a single link of at most `max_bytes`.
///
/// # Errors
/// [`OpenRefusal`] describing why the entry was not opened.
pub fn open_regular_at(
    dir: BorrowedFd<'_>,
    name: &str,
    max_bytes: u64,
) -> Result<(File, Metadata), OpenRefusal> {
    let fd = match rfs::openat(dir, name, file_read_flags(), Mode::empty()) {
        Ok(fd) => fd,
        Err(e) if e == Errno::NOENT => return Err(OpenRefusal::Missing),
        Err(e) if is_symlink_errno(e) => {
            return Err(OpenRefusal::Rejected("symbolic link".into()));
        }
        Err(e) => return Err(OpenRefusal::Rejected(format!("cannot open: {e}"))),
    };
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| OpenRefusal::Rejected(format!("cannot stat: {e}")))?;
    let ft = meta.file_type();
    if !ft.is_file() {
        return Err(OpenRefusal::Rejected(format!(
            "not a regular file ({})",
            describe(ft)
        )));
    }
    if meta.nlink() > 1 {
        return Err(OpenRefusal::Rejected(format!(
            "regular file with {} hard links",
            meta.nlink()
        )));
    }
    if meta.len() > max_bytes {
        return Err(OpenRefusal::Rejected(format!(
            "file too large ({} bytes > {max_bytes} byte limit)",
            meta.len()
        )));
    }
    Ok((file, meta))
}

/// Read at most `max_bytes` from `file`.
///
/// # Errors
/// Read failures, or `InvalidData` when the file holds more than
/// `max_bytes` (it grew after the size check).
pub fn read_capped(file: File, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file grew beyond the {max_bytes} byte limit while reading"),
        ));
    }
    Ok(buf)
}

/// Create the new file `name` in `dir` (mode `0o644` before umask) and
/// write `content`. Never opens an existing entry: a file, directory or
/// (even dangling) symlink at `name` makes this fail with `AlreadyExists`.
///
/// # Errors
/// `AlreadyExists`, or any create/write failure.
pub fn create_new_at(dir: BorrowedFd<'_>, name: &str, content: &[u8]) -> io::Result<()> {
    let fd = rfs::openat(
        dir,
        name,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NOCTTY
            | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )?;
    let mut file = File::from(fd);
    file.write_all(content)?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn dirs_below_the_root_are_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("groups");
        std::fs::create_dir_all(root.join("real")).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        symlink(&elsewhere, root.join("link")).unwrap();
        std::fs::write(root.join("file"), "x").unwrap();

        let fd = open_root(&root).unwrap();
        assert!(open_dir_at(fd.as_fd(), "real").is_ok());
        let err = open_dir_at(fd.as_fd(), "link").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = open_dir_at(fd.as_fd(), "file").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = open_dir_at(fd.as_fd(), "missing").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // ensure_dir_at creates, re-opens, and refuses a symlink.
        assert!(ensure_dir_at(fd.as_fd(), "new").is_ok());
        assert!(root.join("new").is_dir());
        assert!(ensure_dir_at(fd.as_fd(), "new").is_ok());
        assert!(ensure_dir_at(fd.as_fd(), "link").is_err());
    }

    #[test]
    fn root_may_be_an_operator_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("real")).unwrap();
        symlink(tmp.path().join("real"), tmp.path().join("alias")).unwrap();
        assert!(open_root(&tmp.path().join("alias")).is_ok());
    }

    #[test]
    fn regular_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("ok"), "hello").unwrap();
        std::fs::write(dir.join("target"), "secret").unwrap();
        symlink(dir.join("target"), dir.join("sym")).unwrap();
        std::fs::hard_link(dir.join("target"), dir.join("hard")).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("big"), vec![b'a'; 64]).unwrap();
        let fifo = dir.join("fifo");
        rfs::mkfifoat(rfs::CWD, &fifo, Mode::from_raw_mode(0o600)).unwrap();

        let fd = open_root(dir).unwrap();
        let (file, meta) = open_regular_at(fd.as_fd(), "ok", 1024).unwrap();
        assert_eq!(meta.len(), 5);
        assert_eq!(read_capped(file, 1024).unwrap(), b"hello");

        assert_eq!(
            open_regular_at(fd.as_fd(), "missing", 1024).unwrap_err(),
            OpenRefusal::Missing
        );
        for name in ["sym", "hard", "sub", "big", "fifo"] {
            assert!(
                matches!(
                    open_regular_at(fd.as_fd(), name, 32),
                    Err(OpenRefusal::Rejected(_))
                ),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn read_capped_detects_growth() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), "0123456789").unwrap();
        let file = File::open(tmp.path().join("f")).unwrap();
        assert!(read_capped(file, 4).is_err());
    }

    #[test]
    fn create_new_never_writes_through_existing_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, "original").unwrap();
        symlink(&victim, dir.join("live-link")).unwrap();
        symlink(tmp.path().join("nowhere"), dir.join("dangling")).unwrap();

        let fd = open_root(&dir).unwrap();
        assert!(entry_exists_at(fd.as_fd(), "dangling").unwrap());
        assert!(!entry_exists_at(fd.as_fd(), "fresh").unwrap());
        create_new_at(fd.as_fd(), "fresh", b"content").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("fresh")).unwrap(),
            "content"
        );
        assert_eq!(
            create_new_at(fd.as_fd(), "fresh", b"again")
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(create_new_at(fd.as_fd(), "live-link", b"pwned").is_err());
        assert!(create_new_at(fd.as_fd(), "dangling", b"pwned").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "original");
        assert!(!tmp.path().join("nowhere").exists());
    }
}
