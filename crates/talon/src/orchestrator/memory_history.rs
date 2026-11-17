//! Copies of a group's `MEMORY.md` from before each run.
//!
//! `groups/<folder>/MEMORY.md` is the agent's notebook and the agent may
//! rewrite it whole (`write_file`), so one bad turn can lose every earlier
//! note. Before a container starts, the host therefore copies the file to
//! `<data_dir>/memory-history/<folder>/MEMORY-<UTC time>.md` when it differs
//! from the newest copy there, and keeps the newest [`KEEP`] copies.
//!
//! The history lives under `data_dir`, which no container mounts, so an
//! agent can neither read nor destroy it. The source is agent-writable and
//! is read through [`crate::safe_fs`] (no symlink, no FIFO, single link,
//! size-capped). To restore, copy a file from the history back over
//! `MEMORY.md` while no run of that group is active.

use std::fs;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::safe_fs::{self, OpenRefusal};

/// The file that is copied.
pub const MEMORY_FILE: &str = "MEMORY.md";
/// Directory under `data_dir` holding one sub-directory per group folder.
pub const HISTORY_DIR: &str = "memory-history";
/// Copies kept per group; older ones are deleted.
pub const KEEP: usize = 50;
/// A larger `MEMORY.md` is not copied (the agent reads far less of it).
pub const MAX_BYTES: u64 = 1024 * 1024;

const PREFIX: &str = "MEMORY-";
const SUFFIX: &str = ".md";

/// Copy `groups/<folder>/MEMORY.md` into the history when it changed since
/// the newest copy. Returns the new copy's path, or `None` when there was
/// nothing to do (no file, an empty file, or no change).
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
    let mut copies = copies(&dir)?;
    if let Some(newest) = copies.last()
        && fs::read(newest)? == content
    {
        return Ok(None);
    }

    let target = free_name(&dir, now);
    let tmp = dir.join(format!(".{}.tmp", std::process::id()));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&content)?;
        file.sync_all()?;
        fs::rename(&tmp, &target)
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    copies.push(target.clone());
    let excess = copies.len().saturating_sub(KEEP);
    for old in copies.iter().take(excess) {
        if let Err(e) = fs::remove_file(old) {
            tracing::warn!(path = %old.display(), error = %e, "cannot delete an old MEMORY.md copy");
        }
    }
    Ok(Some(target))
}

/// The copies in `dir`, oldest first (the names sort by time).
fn copies(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(PREFIX) && name.ends_with(SUFFIX) && entry.file_type()?.is_file() {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

/// `MEMORY-<time>.md`, with a counter when two runs start in one second.
fn free_name(dir: &Path, now: DateTime<Utc>) -> PathBuf {
    let stamp = now.format("%Y%m%dT%H%M%SZ");
    let mut path = dir.join(format!("{PREFIX}{stamp}{SUFFIX}"));
    let mut n = 1u32;
    while path.exists() {
        path = dir.join(format!("{PREFIX}{stamp}_{n:03}{SUFFIX}"));
        n = n.saturating_add(1);
    }
    path
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

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

    fn history(f: &Fixture) -> Vec<PathBuf> {
        copies(&f.data.join(HISTORY_DIR).join("copilot")).unwrap_or_default()
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
        assert_eq!(
            fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
            0o600
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
    fn keeps_only_the_newest_copies() {
        let f = fixture();
        let start = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        for i in 0..(KEEP + 3) {
            write_memory(&f, &format!("version {i}\n"));
            let now = start + chrono::Duration::seconds(i64::try_from(i).unwrap());
            snapshot(&f.groups, &f.data, "copilot", now).unwrap();
        }
        let all = history(&f);
        assert_eq!(all.len(), KEEP);
        assert_eq!(fs::read_to_string(&all[0]).unwrap(), "version 3\n");
        assert_eq!(
            fs::read_to_string(all.last().unwrap()).unwrap(),
            format!("version {}\n", KEEP + 2)
        );
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
    fn refuses_a_folder_name_that_leaves_the_groups_directory() {
        let f = fixture();
        assert!(snapshot(&f.groups, &f.data, "../data", at(1)).is_err());
        assert!(snapshot(&f.groups, &f.data, "a/b", at(1)).is_err());
    }
}
