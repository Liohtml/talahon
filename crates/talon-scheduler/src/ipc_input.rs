//! Host -> container IPC writes into `<data_dir>/ipc/<ipc_key>/input/`.
//!
//! `<data_dir>/ipc/<ipc_key>/` is bind-mounted read-write into the lane's
//! container, so every entry *inside* it is attacker-controlled once the
//! container is compromised: an agent can swap `input` for a symlink to
//! another lane's `input/` at any moment (e.g. `RENAME_EXCHANGE` in a loop).
//! Resolving `input/<file>` by path after an `lstat` check is therefore a
//! TOCTOU race that lets a non-main lane plant follow-up messages or
//! `_close` sentinels in main's inbox (MYTH-02).
//!
//! Every write therefore works on directory descriptors only:
//! - the lane key is validated through [`talon_core::paths::group_ipc_path`]
//!   (no traversal, single component);
//! - the operator-controlled IPC root `<data_dir>/ipc` is opened (it may
//!   legitimately be a symlink to another volume; containers never see it);
//! - the lane directory and then `input` are opened relative to their
//!   parent descriptor with `O_DIRECTORY | O_NOFOLLOW` (created with
//!   `mkdirat` and re-opened the same way when missing). A symlink or
//!   non-directory is refused and left alone — nothing is deleted or
//!   replaced by path;
//! - the temp file is created with `openat(input_fd, tmp, O_CREAT | O_EXCL |
//!   O_NOFOLLOW, 0600)`, written, `fsync`ed and `renameat`ed onto its final
//!   name within the same pinned directory. Swapping `input` afterwards can
//!   only move the lane's own directory around; it can no longer redirect
//!   the write. The rename replaces a planted symlink at the destination
//!   instead of writing through it (fixed-name `_close` sentinel).

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use talon_core::paths::group_ipc_path;
use talon_core::protocol::{IPC_CLOSE_SENTINEL, IpcInput, ipc_file_name};
use talon_core::{Error, Result};
use tracing::warn;

/// Name of the host -> container inbox below the lane's IPC directory.
const INPUT_DIR: &str = "input";

/// `<data_dir>/ipc/<ipc_key>/input` (validated, not created).
pub fn input_dir(data_dir: &Path, ipc_key: &str) -> Result<PathBuf> {
    Ok(group_ipc_path(data_dir, ipc_key)?.join(INPUT_DIR))
}

/// Write a follow-up [`IpcInput::Message`] for the lane's running container.
/// Returns the final path of the written file.
pub fn write_message(data_dir: &Path, ipc_key: &str, text: &str) -> Result<PathBuf> {
    let body = serde_json::to_vec(&IpcInput::Message {
        text: text.to_string(),
    })?;
    let dir = open_input_dir(data_dir, ipc_key)?;
    let name = ipc_file_name();
    write_atomic(&dir, &name, &format!("{name}.tmp"), &body)?;
    Ok(dir.path.join(name))
}

/// Write the `_close` sentinel that tells the container to finish its
/// current turn and exit. Returns the sentinel path.
pub fn write_close_sentinel(data_dir: &Path, ipc_key: &str) -> Result<PathBuf> {
    let dir = open_input_dir(data_dir, ipc_key)?;
    // The temp name must not end in `.json` (the agent would treat it as a
    // message) and must be unpredictable.
    let tmp = format!("{IPC_CLOSE_SENTINEL}.{}.tmp", ipc_file_name());
    write_atomic(&dir, IPC_CLOSE_SENTINEL, &tmp, b"")?;
    Ok(dir.path.join(IPC_CLOSE_SENTINEL))
}

/// Most directory entries [`clear_inbox`] looks at (the directory is
/// writable by the container).
const MAX_CLEAR_ENTRIES: usize = 10_000;

/// Empty the lane's inbox before a container starts: follow-up messages
/// (`*.json`) left by an earlier container and a stale `_close`. A leftover
/// message was never answered; the host sends it again from the message
/// store, so the next container must not also read the old file (and a
/// stale `_close` would end it after its first turn). Entries are unlinked
/// descriptor-relatively and never followed. Returns how many were removed.
pub fn clear_inbox(data_dir: &Path, ipc_key: &str) -> Result<usize> {
    let dir = open_input_dir(data_dir, ipc_key)?;
    let reader = rfs::Dir::read_from(dir.fd.as_fd()).map_err(io::Error::from)?;
    let mut names = Vec::new();
    for entry in reader.take(MAX_CLEAR_ENTRIES) {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name();
        let bytes = name.to_bytes();
        let stale = bytes == IPC_CLOSE_SENTINEL.as_bytes()
            || (bytes.ends_with(b".json") && !bytes.starts_with(b"."));
        if stale {
            names.push(name.to_owned());
        }
    }
    Ok(names
        .iter()
        .filter(|name| rfs::unlinkat(dir.fd.as_fd(), name.as_c_str(), AtFlags::empty()).is_ok())
        .count())
}

/// A lane's `input/` directory, pinned by descriptor.
struct InputDir {
    fd: OwnedFd,
    /// For return values and logs only; never re-resolved for I/O.
    path: PathBuf,
}

/// Open `<ipc>/<key>/input` as a real directory (creating missing levels)
/// without ever following a symlink below the IPC root.
fn open_input_dir(data_dir: &Path, ipc_key: &str) -> Result<InputDir> {
    // Validates the key: a single safe path component.
    let lane_path = group_ipc_path(data_dir, ipc_key)?;
    let root_path = data_dir.join("ipc");
    // Operator controlled and never mounted into a container: may be a
    // symlink (data on another volume), so it is opened normally.
    fs::create_dir_all(&root_path)?;
    let root = rfs::open(
        &root_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    // The lane directory is host-created (it is the container's bind-mount
    // source), but is opened without following symlinks all the same.
    let lane = open_or_create_dir(root.as_fd(), ipc_key, &lane_path)?;
    let path = lane_path.join(INPUT_DIR);
    let fd = open_or_create_dir(lane.as_fd(), INPUT_DIR, &path)?;
    Ok(InputDir { fd, path })
}

/// `openat(parent, name, O_DIRECTORY | O_NOFOLLOW)`; when missing,
/// `mkdirat` and open again the same way. A symlink or non-directory is
/// refused with [`Error::Security`] and left untouched.
fn open_or_create_dir(parent: BorrowedFd<'_>, name: &str, shown: &Path) -> Result<OwnedFd> {
    let opened = match open_dir_nofollow(parent, name) {
        Err(e) if e == Errno::NOENT => {
            match rfs::mkdirat(parent, name, Mode::RWXU | Mode::RWXG | Mode::RWXO) {
                // EEXIST: created concurrently (or replaced by something
                // else) — the re-open below decides.
                Ok(()) => {}
                Err(e) if e == Errno::EXIST => {}
                Err(e) => return Err(io::Error::from(e).into()),
            }
            open_dir_nofollow(parent, name)
        }
        other => other,
    };
    opened.map_err(|e| {
        if is_symlink_errno(e) || e == Errno::NOTDIR {
            warn!(
                path = %shown.display(),
                "refusing IPC input write: path is a symlink or not a directory"
            );
            Error::security(format!(
                "IPC path {} is a symlink or not a directory; refusing to write through it",
                shown.display()
            ))
        } else {
            io::Error::from(e).into()
        }
    })
}

fn open_dir_nofollow(parent: BorrowedFd<'_>, name: &str) -> rustix::io::Result<OwnedFd> {
    rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

fn is_symlink_errno(e: Errno) -> bool {
    // Linux/macOS report O_NOFOLLOW on a symlink as ELOOP, FreeBSD as EMLINK.
    e == Errno::LOOP || e == Errno::MLINK
}

/// Create `tmp_name` (`O_EXCL | O_NOFOLLOW`, 0600) in the pinned directory,
/// write and `fsync` it, then `renameat` it onto `final_name` in the same
/// directory. On failure the temp entry is unlinked from that directory.
fn write_atomic(dir: &InputDir, final_name: &str, tmp_name: &str, body: &[u8]) -> Result<()> {
    let fd = rfs::openat(
        dir.fd.as_fd(),
        tmp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(io::Error::from)?;
    let mut file = File::from(fd);
    let result = (|| -> io::Result<()> {
        give_to_dir_owner(&file, dir.fd.as_fd())?;
        file.write_all(body)?;
        file.sync_all()?;
        rfs::renameat(dir.fd.as_fd(), tmp_name, dir.fd.as_fd(), final_name)?;
        Ok(())
    })();
    drop(file);
    if let Err(e) = result {
        // Descriptor-relative and never follows a symlink; at worst it
        // removes whatever the container put at our temp name in its own
        // directory.
        let _ = rfs::unlinkat(dir.fd.as_fd(), tmp_name, AtFlags::empty());
        return Err(e.into());
    }
    Ok(())
}

/// The file is 0600, so the in-container agent can read it only if it owns
/// it. A root host chowns `input/` to the agent's `RUN_UID`
/// (talon-container), so hand the new file to the owner of the *pinned*
/// directory; `fchown` on our own descriptor never follows anything. A
/// non-root host normally owns both already; if it cannot match a foreign
/// owner the write fails (and the caller falls back) instead of leaving an
/// unreadable message behind.
fn give_to_dir_owner(file: &File, dir: BorrowedFd<'_>) -> io::Result<()> {
    let dir_stat = rfs::fstat(dir)?;
    let (uid, gid) = (dir_stat.st_uid, dir_stat.st_gid);
    if file.metadata()?.uid() == uid {
        return Ok(());
    }
    std::os::unix::fs::fchown(file, Some(uid), Some(gid))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn message_is_written_atomically_with_protocol_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_message(tmp.path(), "lane-1", "hello \"world\"").unwrap();
        assert_eq!(path.parent().unwrap(), tmp.path().join("ipc/lane-1/input"));
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with(".json"));
        let parsed: IpcInput = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            parsed,
            IpcInput::Message {
                text: "hello \"world\"".into()
            }
        );
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["type"], "message");
        // No temp files left behind.
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn close_sentinel_is_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_close_sentinel(tmp.path(), "g").unwrap();
        assert_eq!(path, tmp.path().join("ipc/g/input/_close"));
        assert_eq!(fs::read(&path).unwrap().len(), 0);
        // Idempotent.
        write_close_sentinel(tmp.path(), "g").unwrap();
        let entries = fs::read_dir(tmp.path().join("ipc/g/input"))
            .unwrap()
            .count();
        assert_eq!(entries, 1);
    }

    #[test]
    fn clear_inbox_removes_leftovers_only() {
        let tmp = tempfile::tempdir().unwrap();
        write_message(tmp.path(), "g", "old").unwrap();
        write_close_sentinel(tmp.path(), "g").unwrap();
        let input = tmp.path().join("ipc/g/input");
        fs::write(input.join("partial.json.tmp"), b"").unwrap();
        let outside = tmp.path().join("outside.json");
        fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, input.join("link.json")).unwrap();
        assert_eq!(clear_inbox(tmp.path(), "g").unwrap(), 3);
        let left: Vec<String> = fs::read_dir(&input)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left, vec!["partial.json.tmp".to_string()]);
        // The symlink itself went, never its target.
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        // A lane without an inbox yet is fine.
        assert_eq!(clear_inbox(tmp.path(), "fresh").unwrap(), 0);
    }

    #[test]
    fn invalid_ipc_keys_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        for key in ["../escape", "a/b", "", "global", ".hidden"] {
            assert!(write_message(tmp.path(), key, "x").is_err(), "{key}");
            assert!(write_close_sentinel(tmp.path(), key).is_err(), "{key}");
        }
        assert!(!tmp.path().join("escape").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_input_dir_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let lane = tmp.path().join("ipc/g");
        fs::create_dir_all(&lane).unwrap();
        std::os::unix::fs::symlink(&outside, lane.join("input")).unwrap();
        let err = write_message(tmp.path(), "g", "x").unwrap_err();
        assert!(matches!(err, Error::Security(_)), "{err:?}");
        assert!(write_close_sentinel(tmp.path(), "g").is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn planted_close_symlink_is_replaced_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim.txt");
        fs::write(&victim, "precious").unwrap();
        let input = tmp.path().join("ipc/g/input");
        fs::create_dir_all(&input).unwrap();
        std::os::unix::fs::symlink(&victim, input.join("_close")).unwrap();

        write_close_sentinel(tmp.path(), "g").unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        let meta = fs::symlink_metadata(input.join("_close")).unwrap();
        assert!(meta.is_file() && !meta.file_type().is_symlink());
    }

    #[test]
    fn input_dir_that_is_a_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let lane = tmp.path().join("ipc/g");
        fs::create_dir_all(&lane).unwrap();
        fs::write(lane.join("input"), "not a dir").unwrap();
        assert!(write_message(tmp.path(), "g", "x").is_err());
        assert!(write_close_sentinel(tmp.path(), "g").is_err());
        assert_eq!(fs::read_to_string(lane.join("input")).unwrap(), "not a dir");
    }

    /// Every non-symlink file below `dir` (symlinks are never followed).
    #[cfg(unix)]
    fn files_below(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = fs::read_dir(&d) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    /// Lane `evil` plus the victim lane `main`, whose `input/` is the target.
    #[cfg(unix)]
    fn two_lanes() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("ipc/main/input");
        fs::create_dir_all(&victim).unwrap();
        let lane = tmp.path().join("ipc/evil");
        fs::create_dir_all(lane.join("input")).unwrap();
        (tmp, lane, victim)
    }

    /// Hammer lane `evil` with follow-ups and `_close` sentinels while
    /// `swap` runs in a loop on another thread; returns
    /// `(messages written, writes refused, swapper iterations)`.
    #[cfg(unix)]
    fn race_writes<F>(data_dir: &Path, writes: usize, mut swap: F) -> (usize, usize, u64)
    where
        F: FnMut(u64) + Send + 'static,
    {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let stop = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let swapper = {
            let (stop, started) = (Arc::clone(&stop), Arc::clone(&started));
            std::thread::spawn(move || {
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    swap(i);
                    i += 1;
                    started.store(true, Ordering::Relaxed);
                }
                i
            })
        };
        while !started.load(Ordering::Relaxed) {
            std::thread::yield_now();
        }
        let (mut written, mut refused) = (0, 0);
        for n in 0..writes {
            match write_message(data_dir, "evil", &format!("attacker text {n}")) {
                Ok(_) => written += 1,
                Err(_) => refused += 1,
            }
            if n % 4 == 0 {
                let _ = write_close_sentinel(data_dir, "evil");
            }
        }
        stop.store(true, Ordering::Relaxed);
        let iterations = swapper.join().unwrap();
        (written, refused, iterations)
    }

    /// Nothing reached the victim; every accepted message is a complete
    /// file somewhere inside the attacker's own lane; no temp files remain.
    #[cfg(unix)]
    fn assert_contained(lane: &Path, victim: &Path, written: usize) {
        let leaked = files_below(victim);
        assert!(
            leaked.is_empty(),
            "{} host writes landed in another lane's input/: {leaked:?}",
            leaked.len()
        );
        let own = files_below(lane);
        let temps: Vec<_> = own
            .iter()
            .filter(|p| p.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(temps.is_empty(), "temp files left behind: {temps:?}");
        let messages: Vec<_> = own
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        assert_eq!(messages.len(), written);
        for path in messages {
            let parsed: IpcInput = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert!(matches!(parsed, IpcInput::Message { .. }));
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_other_lane_input_is_refused_without_writing() {
        let (tmp, lane, victim) = two_lanes();
        fs::remove_dir(lane.join("input")).unwrap();
        std::os::unix::fs::symlink(&victim, lane.join("input")).unwrap();

        let err = write_message(tmp.path(), "evil", "attacker text").unwrap_err();
        assert!(matches!(err, Error::Security(_)), "{err:?}");
        let err = write_close_sentinel(tmp.path(), "evil").unwrap_err();
        assert!(matches!(err, Error::Security(_)), "{err:?}");

        assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
        // The planted link is left alone (not deleted/replaced by path).
        assert!(
            fs::symlink_metadata(lane.join("input"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_lane_dir_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(outside.join("input")).unwrap();
        fs::create_dir_all(tmp.path().join("ipc")).unwrap();
        std::os::unix::fs::symlink(&outside, tmp.path().join("ipc/g")).unwrap();
        let err = write_message(tmp.path(), "g", "x").unwrap_err();
        assert!(matches!(err, Error::Security(_)), "{err:?}");
        assert!(write_close_sentinel(tmp.path(), "g").is_err());
        assert!(files_below(&outside).is_empty());
    }

    /// MYTH-02 regression: the swapper flips `input` between the lane's real
    /// directory and a symlink to main's `input/` using plain renames.
    #[cfg(unix)]
    #[test]
    fn racing_rename_swap_never_reaches_other_lane() {
        let (tmp, lane, victim) = two_lanes();
        let (sw_lane, sw_victim) = (lane.clone(), victim.clone());
        let (written, refused, iterations) = race_writes(tmp.path(), 400, move |i| {
            let input = sw_lane.join("input");
            let aside = sw_lane.join(format!("aside-{i}"));
            let _ = fs::rename(&input, &aside);
            let _ = std::os::unix::fs::symlink(&sw_victim, &input);
            std::thread::yield_now();
            match fs::symlink_metadata(&input) {
                Ok(m) if m.file_type().is_symlink() => {
                    let _ = fs::remove_file(&input);
                }
                // The host re-created `input` while it was missing.
                Ok(_) => {
                    let _ = fs::rename(&input, sw_lane.join(format!("gone-{i}")));
                }
                Err(_) => {}
            }
            let _ = fs::rename(&aside, &input);
        });
        eprintln!("written={written} refused={refused} swaps={iterations}");
        assert!(iterations > 0);
        assert_contained(&lane, &victim, written);
    }

    /// MYTH-02 regression with the reviewer's primitive: atomic
    /// `RENAME_EXCHANGE` of the real `input` and a symlink to main's.
    #[cfg(target_os = "linux")]
    #[test]
    fn rename_exchange_race_never_reaches_other_lane() {
        use rustix::fs::{Mode, OFlags, RenameFlags, open, renameat_with};

        let (tmp, lane, victim) = two_lanes();
        std::os::unix::fs::symlink(&victim, lane.join("swap")).unwrap();
        let lane_fd = open(
            &lane,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let exchange =
            move || renameat_with(&lane_fd, "input", &lane_fd, "swap", RenameFlags::EXCHANGE);
        if let Err(e) = exchange() {
            eprintln!("RENAME_EXCHANGE unsupported here ({e}); skipping");
            return;
        }
        let (written, refused, iterations) = race_writes(tmp.path(), 400, move |_| {
            let _ = exchange();
        });
        eprintln!("written={written} refused={refused} swaps={iterations}");
        assert!(iterations > 0);
        assert_contained(&lane, &victim, written);
    }

    #[cfg(unix)]
    #[test]
    fn missing_input_is_created_and_writes_are_private_and_atomic() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("ipc/g")).unwrap();
        let mut paths = Vec::new();
        for n in 0..50 {
            paths.push(write_message(tmp.path(), "g", &format!("m{n}")).unwrap());
        }
        write_close_sentinel(tmp.path(), "g").unwrap();
        let input = tmp.path().join("ipc/g/input");
        let meta = fs::symlink_metadata(&input).unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink());
        let names: Vec<String> = fs::read_dir(&input)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 51, "{names:?}");
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
        for (n, path) in paths.iter().enumerate() {
            assert_eq!(path.parent().unwrap(), input);
            let parsed: IpcInput = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(
                parsed,
                IpcInput::Message {
                    text: format!("m{n}")
                }
            );
            let mode = fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A root host gives the 0600 files to the agent uid that owns `input/`.
    #[cfg(unix)]
    #[test]
    fn root_host_hands_files_to_the_input_dir_owner() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let probe = tmp.path().join("probe");
        fs::write(&probe, b"").unwrap();
        if fs::metadata(&probe).unwrap().uid() != 0 {
            eprintln!("not running as root; skipping");
            return;
        }
        let input = tmp.path().join("ipc/g/input");
        fs::create_dir_all(&input).unwrap();
        if let Err(e) = std::os::unix::fs::chown(&input, Some(4242), Some(4243)) {
            eprintln!("cannot chown here ({e}); skipping");
            return;
        }
        let message = write_message(tmp.path(), "g", "hi").unwrap();
        let close = write_close_sentinel(tmp.path(), "g").unwrap();
        for path in [message, close] {
            let meta = fs::metadata(&path).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (4242, 4243), "{path:?}");
            assert_eq!(meta.mode() & 0o777, 0o600, "{path:?}");
        }
    }
}
