//! Copies of a group's `MEMORY.md` from before each run.
//!
//! `groups/<folder>/MEMORY.md` is the agent's notebook and the agent may
//! rewrite it whole (`write_file`), so one bad turn can lose every earlier
//! note. Before a container starts, the host therefore copies the file to
//! `<data_dir>/memory-history/<folder>/MEMORY-<UTC time>.md` when it differs
//! from the newest copy there. It keeps the newest [`KEEP_NEWEST`] copies
//! and, in addition, the newest copy of each UTC day of the last
//! [`KEEP_DAILY_DAYS`] days, so a busy folder still has a copy from before
//! a wipe nobody noticed for a while.
//!
//! Runs of one folder can start at the same moment (the CoPilot lanes share
//! the `copilot` folder), so every call writes its own temp file and claims
//! the final name with a hard link, which never replaces an existing copy.
//!
//! No container mounts the history writable, so no agent can change or
//! delete a copy. The main group mounts the project root read-only and,
//! with the default `data_dir` (`<project>/data`), can read every group's
//! history like the rest of the project. A secret removed from `MEMORY.md`
//! stays in the older copies until they are pruned.
//!
//! The source is agent-writable and is read through [`crate::safe_fs`] (no
//! symlink, no FIFO, single link, size-capped). To restore, copy a file from
//! the history back over `MEMORY.md` while no run of that group is active.

use std::fs;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

use crate::safe_fs::{self, OpenRefusal};

/// The file that is copied.
pub const MEMORY_FILE: &str = "MEMORY.md";
/// Directory under `data_dir` holding one sub-directory per group folder.
pub const HISTORY_DIR: &str = "memory-history";
/// The newest copies of a group, always kept.
pub const KEEP_NEWEST: usize = 50;
/// Beyond [`KEEP_NEWEST`], the newest copy of each UTC calendar day is kept
/// for this many days (today included); older copies are deleted.
pub const KEEP_DAILY_DAYS: i64 = 30;
/// A larger `MEMORY.md` is not copied (the agent reads far less of it).
pub const MAX_BYTES: u64 = 1024 * 1024;

const PREFIX: &str = "MEMORY-";
const SUFFIX: &str = ".md";
/// The time in a copy's name, UTC.
const STAMP: &str = "%Y%m%dT%H%M%SZ";
/// Copies made in one second: the plain name, then `_001` … `_999`.
const MAX_SAME_SECOND: u32 = 1000;
/// Temp files are `.MEMORY-<pid>-<seq>.tmp`; the dot keeps them apart from
/// the copies.
const TMP_PREFIX: &str = ".MEMORY-";
const TMP_SUFFIX: &str = ".tmp";
/// A temp file this old was left by a crash between write and claim.
const STALE_TMP_AGE: Duration = Duration::from_secs(60 * 60);

/// Makes each temp file name of this process unique.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Copy `groups/<folder>/MEMORY.md` into the history when it changed since
/// the newest copy. Returns the new copy's path, or `None` when there was
/// nothing to do (no file, an empty file, or no change). Blocking disk work.
///
/// # Errors
/// An invalid folder name, a source that must not be read (symlink, special
/// file, too large) or a failing read or write.
pub fn snapshot(
    groups_dir: &Path,
    data_dir: &Path,
    folder: &str,
    now: DateTime<Utc>,
) -> io::Result<Option<PathBuf>> {
    talon_core::paths::assert_valid_group_folder(folder)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let groups = safe_fs::open_root(groups_dir)?;
    let group = match safe_fs::open_dir_at(groups.as_fd(), folder) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let content = match safe_fs::open_regular_at(group.as_fd(), MEMORY_FILE, MAX_BYTES) {
        Ok((file, _)) => safe_fs::read_capped(file, MAX_BYTES)?,
        Err(OpenRefusal::Missing) => return Ok(None),
        Err(OpenRefusal::Rejected(why)) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, why));
        }
    };
    if content.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }

    let dir = data_dir.join(HISTORY_DIR).join(folder);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    if let Some(newest) = copies(&dir)?.last()
        && fs::read(&newest.path)? == content
    {
        return Ok(None);
    }

    let tmp = write_tmp(&dir, &content)?;
    let claimed = claim(&dir, &tmp, now);
    // Claimed or not, the temp name goes; a claimed copy keeps the inode.
    remove(&tmp, "a MEMORY.md temp file");
    let target = claimed?;
    prune(&dir, now.date_naive());
    Ok(Some(target))
}

/// A copy in the history; sorts by the time and counter in its name.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Saved {
    at: NaiveDateTime,
    n: u32,
    path: PathBuf,
}

/// The copies in `dir`, oldest first. Other files are ignored.
fn copies(dir: &Path) -> io::Result<Vec<Saved>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Some((at, n)) = entry.file_name().to_str().and_then(parse_name) else {
            continue;
        };
        if entry.file_type()?.is_file() {
            found.push(Saved {
                at,
                n,
                path: entry.path(),
            });
        }
    }
    found.sort();
    Ok(found)
}

/// The time and counter of `MEMORY-<stamp>[_NNN].md`.
fn parse_name(name: &str) -> Option<(NaiveDateTime, u32)> {
    let stem = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    let (stamp, n) = match stem.split_once('_') {
        Some((stamp, n)) if all_digits(n) => (stamp, n.parse().ok()?),
        Some(_) => return None,
        None => (stem, 0),
    };
    let at = NaiveDateTime::parse_from_str(stamp, STAMP).ok()?;
    Some((at, n))
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Write `content` to a temp file in `dir` that no other call uses
/// (mode `0600`, synced to disk).
fn write_tmp(dir: &Path, content: &[u8]) -> io::Result<PathBuf> {
    loop {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(
            "{TMP_PREFIX}{}-{seq}{TMP_SUFFIX}",
            std::process::id()
        ));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => file,
            // Left by an earlier process with the same pid.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        if let Err(e) = file.write_all(content).and_then(|()| file.sync_all()) {
            remove(&tmp, "a MEMORY.md temp file");
            return Err(e);
        }
        return Ok(tmp);
    }
}

/// Link `tmp` as `MEMORY-<now>.md`, or with the first free counter when
/// another copy holds that name. A hard link never replaces an existing
/// entry, so concurrent snapshots cannot overwrite each other's copy.
fn claim(dir: &Path, tmp: &Path, now: DateTime<Utc>) -> io::Result<PathBuf> {
    let stamp = now.format(STAMP).to_string();
    for n in 0..MAX_SAME_SECOND {
        let target = if n == 0 {
            dir.join(format!("{PREFIX}{stamp}{SUFFIX}"))
        } else {
            dir.join(format!("{PREFIX}{stamp}_{n:03}{SUFFIX}"))
        };
        match fs::hard_link(tmp, &target) {
            Ok(()) => return Ok(target),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("{MAX_SAME_SECOND} copies of MEMORY.md in one second"),
    ))
}

/// Delete the copies the retention no longer keeps (see [`expired`]) and
/// temp files a crash left behind. Failures are only logged.
fn prune(dir: &Path, today: NaiveDate) {
    match copies(dir) {
        Ok(all) => {
            for old in expired(&all, today) {
                remove(old, "an old MEMORY.md copy");
            }
        }
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "cannot list the MEMORY.md copies");
        }
    }
    remove_stale_tmps(dir, SystemTime::now());
}

/// The copies to delete from `all` (oldest first): every copy except the
/// newest [`KEEP_NEWEST`] and the newest copy of each UTC day of the last
/// [`KEEP_DAILY_DAYS`] days up to `today`.
fn expired(all: &[Saved], today: NaiveDate) -> Vec<&Path> {
    let newest_from = all.len().saturating_sub(KEEP_NEWEST);
    all.iter()
        .enumerate()
        .filter(|&(i, saved)| {
            let day = saved.at.date();
            let last_of_day = all
                .get(i.saturating_add(1))
                .is_none_or(|next| next.at.date() != day);
            let recent = today.signed_duration_since(day).num_days() < KEEP_DAILY_DAYS;
            i < newest_from && !(last_of_day && recent)
        })
        .map(|(_, saved)| saved.path.as_path())
        .collect()
}

/// Delete `.MEMORY-<pid>-<seq>.tmp` files older than [`STALE_TMP_AGE`];
/// younger ones may belong to a snapshot in progress.
fn remove_stale_tmps(dir: &Path, now: SystemTime) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "cannot list the MEMORY.md copies");
            return;
        }
    };
    for entry in entries.flatten() {
        let is_tmp = entry.file_name().to_str().is_some_and(|name| {
            name.strip_prefix(TMP_PREFIX)
                .and_then(|rest| rest.strip_suffix(TMP_SUFFIX))
                .and_then(|rest| rest.split_once('-'))
                .is_some_and(|(pid, seq)| all_digits(pid) && all_digits(seq))
        });
        if !is_tmp {
            continue;
        }
        let stale = entry.metadata().is_ok_and(|meta| {
            meta.is_file()
                && meta
                    .modified()
                    .ok()
                    .and_then(|modified| now.duration_since(modified).ok())
                    .is_some_and(|age| age > STALE_TMP_AGE)
        });
        if stale {
            remove(&entry.path(), "a leftover MEMORY.md temp file");
        }
    }
}

/// Delete `path`; already gone (a concurrent run pruned it) is fine.
fn remove(path: &Path, what: &str) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(path = %path.display(), error = %e, "cannot delete {what}"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier, mpsc};

    use chrono::TimeZone;

    use super::*;

    struct Fixture {
        _tmp: tempfile::TempDir,
        groups: PathBuf,
        data: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let groups = tmp.path().join("groups");
        let data = tmp.path().join("data");
        fs::create_dir_all(groups.join("copilot")).unwrap();
        fs::create_dir_all(&data).unwrap();
        Fixture {
            _tmp: tmp,
            groups,
            data,
        }
    }

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, second).unwrap()
    }

    fn write_memory(f: &Fixture, text: &str) {
        fs::write(f.groups.join("copilot").join(MEMORY_FILE), text).unwrap();
    }

    fn history_dir(f: &Fixture) -> PathBuf {
        f.data.join(HISTORY_DIR).join("copilot")
    }

    fn history(f: &Fixture) -> Vec<PathBuf> {
        copies(&history_dir(f))
            .unwrap_or_default()
            .into_iter()
            .map(|saved| saved.path)
            .collect()
    }

    fn contents(f: &Fixture) -> Vec<String> {
        history(f)
            .iter()
            .map(|p| fs::read_to_string(p).unwrap())
            .collect()
    }

    fn names_in(dir: &Path) -> BTreeSet<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn copies_the_file_once_per_change() {
        let f = fixture();
        write_memory(&f, "first notes\n");
        let copy = snapshot(&f.groups, &f.data, "copilot", at(1))
            .unwrap()
            .unwrap();
        assert_eq!(
            copy.file_name().unwrap().to_string_lossy(),
            "MEMORY-20260102T030401Z.md"
        );
        assert_eq!(fs::read_to_string(&copy).unwrap(), "first notes\n");
        let meta = fs::metadata(&copy).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // The temp name is gone; the copy is the only link.
        assert_eq!(std::os::unix::fs::MetadataExt::nlink(&meta), 1);
        assert_eq!(
            fs::metadata(history_dir(&f)).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // Unchanged: no second copy.
        assert!(
            snapshot(&f.groups, &f.data, "copilot", at(2))
                .unwrap()
                .is_none()
        );
        assert_eq!(history(&f).len(), 1);

        // The overwrite the history exists for: the earlier text survives.
        write_memory(&f, "everything replaced\n");
        snapshot(&f.groups, &f.data, "copilot", at(3))
            .unwrap()
            .unwrap();
        let all = history(&f);
        assert_eq!(all.len(), 2);
        assert_eq!(fs::read_to_string(&all[0]).unwrap(), "first notes\n");
        assert_eq!(names_in(&history_dir(&f)).len(), 2, "no temp file left");
    }

    #[test]
    fn nothing_to_copy_is_not_an_error() {
        let f = fixture();
        assert!(
            snapshot(&f.groups, &f.data, "copilot", at(1))
                .unwrap()
                .is_none()
        );
        write_memory(&f, " \n\n");
        assert!(
            snapshot(&f.groups, &f.data, "copilot", at(1))
                .unwrap()
                .is_none()
        );
        assert!(
            snapshot(&f.groups, &f.data, "unknown-group", at(1))
                .unwrap()
                .is_none()
        );
        assert!(history(&f).is_empty());
    }

    #[test]
    fn two_runs_in_one_second_get_two_names() {
        let f = fixture();
        write_memory(&f, "a\n");
        snapshot(&f.groups, &f.data, "copilot", at(1)).unwrap();
        write_memory(&f, "b\n");
        let second = snapshot(&f.groups, &f.data, "copilot", at(1))
            .unwrap()
            .unwrap();
        assert_eq!(
            second.file_name().unwrap().to_string_lossy(),
            "MEMORY-20260102T030401Z_001.md"
        );
        // The second copy sorts after the first, so it is the "newest".
        let all = history(&f);
        assert_eq!(all.len(), 2);
        assert_eq!(fs::read_to_string(&all[1]).unwrap(), "b\n");
    }

    #[test]
    fn concurrent_snapshots_of_one_folder_keep_every_version() {
        const RUNS: usize = 24;
        for round in 0..10 {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path().join("data");
            // One groups root per run, so each run sees a different
            // MEMORY.md for the same folder at the same moment.
            let roots: Vec<PathBuf> = (0..RUNS)
                .map(|i| {
                    let root = tmp.path().join(format!("groups-{i}"));
                    fs::create_dir_all(root.join("copilot")).unwrap();
                    fs::write(
                        root.join("copilot").join(MEMORY_FILE),
                        format!("round {round} version {i}\n"),
                    )
                    .unwrap();
                    root
                })
                .collect();
            let start = Arc::new(Barrier::new(RUNS));
            let handles: Vec<_> = roots
                .into_iter()
                .map(|root| {
                    let (data, start) = (data.clone(), Arc::clone(&start));
                    std::thread::spawn(move || {
                        start.wait();
                        snapshot(&root, &data, "copilot", at(1)).unwrap()
                    })
                })
                .collect();
            for handle in handles {
                assert!(handle.join().unwrap().is_some());
            }

            let dir = data.join(HISTORY_DIR).join("copilot");
            let kept: BTreeSet<String> = copies(&dir)
                .unwrap()
                .iter()
                .map(|saved| fs::read_to_string(&saved.path).unwrap())
                .collect();
            let expected: BTreeSet<String> = (0..RUNS)
                .map(|i| format!("round {round} version {i}\n"))
                .collect();
            assert_eq!(kept, expected, "round {round}");
            assert_eq!(names_in(&dir).len(), RUNS, "round {round}: no temp left");
        }
    }

    #[test]
    fn keeps_only_the_newest_copies_of_one_day() {
        let f = fixture();
        let start = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        for i in 0..(KEEP_NEWEST + 30) {
            write_memory(&f, &format!("version {i}\n"));
            let now = start + chrono::Duration::seconds(i64::try_from(i).unwrap());
            snapshot(&f.groups, &f.data, "copilot", now).unwrap();
        }
        let all = contents(&f);
        assert_eq!(all.len(), KEEP_NEWEST);
        assert_eq!(all[0], "version 30\n");
        assert_eq!(
            all.last().unwrap(),
            &format!("version {}\n", KEEP_NEWEST + 29)
        );
    }

    #[test]
    fn keeps_the_last_copy_of_each_recent_day() {
        let f = fixture();
        let first = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let days = 40;
        // Two versions a day for 40 days ...
        for day in 0..days {
            for version in 0..2 {
                write_memory(&f, &format!("day {day} version {version}\n"));
                let now =
                    first + chrono::Duration::days(day) + chrono::Duration::hours(version + 1);
                snapshot(&f.groups, &f.data, "copilot", now).unwrap();
            }
        }
        // ... then a busy last day that alone fills the newest copies.
        let last = first + chrono::Duration::days(days - 1);
        for i in 0..(KEEP_NEWEST + 10) {
            write_memory(&f, &format!("busy {i}\n"));
            let now = last
                + chrono::Duration::hours(12)
                + chrono::Duration::seconds(i64::try_from(i).unwrap());
            snapshot(&f.groups, &f.data, "copilot", now).unwrap();
        }

        let all = contents(&f);
        // The newest copy of each of the 29 earlier days inside the window
        // (days 10..=38; day 39 is today), then the newest copies.
        let daily: Vec<String> = (days - KEEP_DAILY_DAYS..days - 1)
            .map(|day| format!("day {day} version 1\n"))
            .collect();
        let busy: Vec<String> = (10..KEEP_NEWEST + 10)
            .map(|i| format!("busy {i}\n"))
            .collect();
        assert_eq!(all, [daily, busy].concat());
    }

    #[test]
    fn copy_names_carry_time_and_counter() {
        let name = |s: &str| parse_name(s).unwrap();
        let (time, n) = name("MEMORY-20260102T030405Z_007.md");
        assert_eq!(
            time,
            NaiveDate::from_ymd_opt(2026, 1, 2)
                .unwrap()
                .and_hms_opt(3, 4, 5)
                .unwrap()
        );
        assert_eq!(n, 7);
        // Within one second: the plain name, then the counter in order.
        assert!(name("MEMORY-20260102T030405Z.md") < name("MEMORY-20260102T030405Z_001.md"));
        assert!(name("MEMORY-20260102T030405Z_009.md") < name("MEMORY-20260102T030405Z_010.md"));
        assert!(name("MEMORY-20260102T030405Z_999.md") < name("MEMORY-20260102T030406Z.md"));
        for bad in [
            "MEMORY-.md",
            "MEMORY-backup.md",
            "MEMORY-20260101T090000Z_.md",
            "MEMORY-20260101T090000Z_x1.md",
            "MEMORY-20260101T090000Z.md.bak",
            ".MEMORY-1-1.tmp",
        ] {
            assert!(parse_name(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn prunes_stale_temp_files_only() {
        let f = fixture();
        write_memory(&f, "first\n");
        snapshot(&f.groups, &f.data, "copilot", at(1)).unwrap();
        let dir = history_dir(&f);
        let two_hours_ago = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
        let plant = |name: &str, modified: SystemTime| {
            let path = dir.join(name);
            fs::write(&path, "x").unwrap();
            fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(modified)
                .unwrap();
        };
        plant(".MEMORY-123-4.tmp", two_hours_ago);
        plant(".MEMORY-123-5.tmp", SystemTime::now());
        plant(".other.tmp", two_hours_ago);
        plant("notes.txt", two_hours_ago);
        // A directory with a temp name is not ours to delete.
        fs::create_dir(dir.join(".MEMORY-123-6.tmp")).unwrap();
        fs::File::open(dir.join(".MEMORY-123-6.tmp"))
            .unwrap()
            .set_modified(two_hours_ago)
            .unwrap();

        write_memory(&f, "second\n");
        snapshot(&f.groups, &f.data, "copilot", at(2))
            .unwrap()
            .unwrap();
        let names = names_in(&dir);
        assert!(!names.contains(".MEMORY-123-4.tmp"), "{names:?}");
        for kept in [
            ".MEMORY-123-5.tmp",
            ".MEMORY-123-6.tmp",
            ".other.tmp",
            "notes.txt",
        ] {
            assert!(names.contains(kept), "{kept} must stay: {names:?}");
        }
        assert_eq!(contents(&f), ["first\n", "second\n"]);
    }

    #[test]
    fn refuses_a_symlink_and_an_oversized_file() {
        let f = fixture();
        let secret = f.data.join("secret");
        fs::write(&secret, "host secret").unwrap();
        symlink(&secret, f.groups.join("copilot").join(MEMORY_FILE)).unwrap();
        assert!(snapshot(&f.groups, &f.data, "copilot", at(1)).is_err());
        assert!(history(&f).is_empty());

        fs::remove_file(f.groups.join("copilot").join(MEMORY_FILE)).unwrap();
        let big = vec![b'x'; usize::try_from(MAX_BYTES).unwrap() + 1];
        fs::write(f.groups.join("copilot").join(MEMORY_FILE), big).unwrap();
        assert!(snapshot(&f.groups, &f.data, "copilot", at(1)).is_err());
        assert!(history(&f).is_empty());
    }

    #[test]
    fn refuses_a_directory_and_a_fifo_without_blocking() {
        let f = fixture();
        let memory = f.groups.join("copilot").join(MEMORY_FILE);
        fs::create_dir(&memory).unwrap();
        assert!(snapshot(&f.groups, &f.data, "copilot", at(1)).is_err());
        assert!(history(&f).is_empty());

        fs::remove_dir(&memory).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &memory,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        // Without O_NONBLOCK the open would wait for a writer forever.
        let (tx, rx) = mpsc::channel();
        let (groups, data) = (f.groups.clone(), f.data.clone());
        std::thread::spawn(move || {
            let _ = tx.send(snapshot(&groups, &data, "copilot", at(1)).is_err());
        });
        let refused = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a FIFO must not block the snapshot");
        assert!(refused);
        assert!(history(&f).is_empty());
    }

    #[test]
    fn refuses_a_folder_name_that_leaves_the_groups_directory() {
        let f = fixture();
        assert!(snapshot(&f.groups, &f.data, "../data", at(1)).is_err());
        assert!(snapshot(&f.groups, &f.data, "a/b", at(1)).is_err());
    }
}
