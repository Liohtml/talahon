//! Read-only filesystem views: eval JSON files and prompt templates.
//!
//! `groups/<folder>/evals` and `groups/<folder>/prompts` sit inside the
//! group folder agent containers mount read-write, so both their files *and
//! the directory entries themselves* are attacker-controlled (MYTH-10). A
//! path-based check-then-read can be raced (swap `evals/` for a symlink to
//! a host directory, or a file for a FIFO that blocks the reader forever).
//! Therefore:
//!
//! - the group directory is operator-controlled and opened normally; the
//!   `evals`/`prompts` sub-directory is opened relative to it with
//!   `O_DIRECTORY | O_NOFOLLOW` (a directory symlink is refused) and every
//!   later access goes through that descriptor;
//! - files are opened relative to the directory descriptor with
//!   `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY` (symlinks fail, FIFOs cannot
//!   block) and judged on the opened inode via `fstat`: regular files only,
//!   size-capped, reads bounded;
//! - everything here is blocking; callers run it inside `spawn_blocking`.

use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use chrono::{DateTime, Utc};
use rustix::fs::{self as rfs, Mode, OFlags};
use rustix::io::Errno;
use serde::Serialize;
use serde_json::Value;

use crate::validate::{is_valid_template_name, truncate_chars};

/// Agent-written eval JSON files, below the group directory.
pub(crate) const EVALS_DIR: &str = "evals";
/// Prompt templates, below the group directory.
pub(crate) const PROMPTS_DIR: &str = "prompts";
/// Max eval files returned for one alert.
pub(crate) const MAX_EVALS: usize = 100;
/// Max size of one eval file.
pub(crate) const MAX_EVAL_BYTES: u64 = 1024 * 1024;
/// Max templates listed.
pub(crate) const MAX_TEMPLATES: usize = 1_000;
/// Bytes read from a template to find its preview line.
const TEMPLATE_PREVIEW_BYTES: u64 = 64 * 1024;
/// Max characters of a template preview line.
const TEMPLATE_PREVIEW_CHARS: usize = 200;
/// Directory entries scanned per request (bounds the work an agent can
/// cause by flooding a directory).
const MAX_DIR_ENTRIES: usize = 1_000_000;

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn file_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC
}

fn is_symlink_errno(e: Errno) -> bool {
    // Linux/macOS report O_NOFOLLOW on a symlink as ELOOP, FreeBSD as EMLINK.
    e == Errno::LOOP || e == Errno::MLINK
}

/// Open `<group_dir>/<name>` as a directory without following a symlink at
/// `name`. `Ok(None)` when either does not exist.
fn open_agent_dir(group_dir: &Path, name: &str) -> io::Result<Option<OwnedFd>> {
    // Operator-controlled: may legitimately be a symlink (data volume).
    let base = match rfs::open(
        group_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) if e == Errno::NOENT => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    match rfs::openat(&base, name, dir_flags(), Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(e) if e == Errno::NOENT => Ok(None),
        Err(e) if is_symlink_errno(e) || e == Errno::NOTDIR => Err(io::Error::other(format!(
            "{name}/ is a symlink or not a directory; refusing to follow it"
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Sort order of [`collect_names`].
#[derive(Clone, Copy)]
enum Order {
    Ascending,
    Descending,
}

fn sort_truncate(names: &mut Vec<String>, order: Order, limit: usize) {
    match order {
        Order::Ascending => names.sort(),
        Order::Descending => names.sort_by(|a, b| b.cmp(a)),
    }
    names.truncate(limit);
}

/// The first `limit` UTF-8 entry names of `dir` (in `order`) accepted by
/// `keep`. Memory stays bounded however many entries the directory holds.
fn collect_names(
    dir: BorrowedFd<'_>,
    keep: impl Fn(&str) -> bool,
    order: Order,
    limit: usize,
) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for (scanned, entry) in rfs::Dir::read_from(dir)?.enumerate() {
        if scanned >= MAX_DIR_ENTRIES {
            tracing::warn!(
                limit = MAX_DIR_ENTRIES,
                "directory has too many entries; listing truncated"
            );
            break;
        }
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name == "." || name == ".." || !keep(name) {
            continue;
        }
        names.push(name.to_string());
        if names.len() >= limit.saturating_mul(2).max(64) {
            sort_truncate(&mut names, order, limit);
        }
    }
    sort_truncate(&mut names, order, limit);
    Ok(names)
}

/// Open the entry `name` of `dir` without following symlinks or blocking,
/// and accept it only if the opened inode is a regular file.
fn open_regular(dir: BorrowedFd<'_>, name: &str) -> Result<(File, Metadata), String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err("invalid name".to_string());
    }
    let fd = rfs::openat(dir, name, file_flags(), Mode::empty()).map_err(|e| {
        if is_symlink_errno(e) {
            "symbolic link".to_string()
        } else {
            format!("cannot open: {e}")
        }
    })?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|e| format!("cannot stat: {e}"))?;
    if !meta.file_type().is_file() {
        return Err("not a regular file".to_string());
    }
    Ok((file, meta))
}

/// Read at most `max` bytes; `None` if the file holds more.
fn read_capped(file: File, max: u64) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    Ok((u64::try_from(buf.len()).unwrap_or(u64::MAX) <= max).then_some(buf))
}

/// Eval JSON files for `alert_id` (`<group_dir>/evals/<alert_id>-*.json`),
/// newest job id first. Unsafe, unparseable or oversized files are skipped
/// with a warning; a symlinked `evals/` directory is an error.
pub(crate) fn read_evals(group_dir: &Path, alert_id: &str) -> io::Result<Vec<Value>> {
    let Some(dir) = open_agent_dir(group_dir, EVALS_DIR)? else {
        return Ok(Vec::new());
    };
    let prefix = format!("{alert_id}-");
    let names = collect_names(
        dir.as_fd(),
        |n| n.starts_with(&prefix) && n.ends_with(".json"),
        Order::Descending,
        MAX_EVALS,
    )?;

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let (file, meta) = match open_regular(dir.as_fd(), &name) {
            Ok(f) => f,
            Err(reason) => {
                tracing::warn!(file = %name, %reason, "skipping unsafe eval file");
                continue;
            }
        };
        if meta.len() > MAX_EVAL_BYTES {
            tracing::warn!(file = %name, size = meta.len(), "skipping oversized eval file");
            continue;
        }
        match read_capped(file, MAX_EVAL_BYTES) {
            Ok(Some(bytes)) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(v) => out.push(v),
                Err(e) => tracing::warn!(file = %name, err = %e, "failed to parse eval file"),
            },
            Ok(None) => tracing::warn!(file = %name, "eval file grew past the size cap; skipped"),
            Err(e) => tracing::warn!(file = %name, err = %e, "failed to read eval file"),
        }
    }
    Ok(out)
}

/// One entry of `GET /templates`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TemplateInfo {
    pub filename: String,
    pub size_bytes: u64,
    pub modified_at: Option<String>,
    pub first_line: Option<String>,
}

fn first_non_empty_line(file: File) -> Option<String> {
    let mut buf = Vec::new();
    file.take(TEMPLATE_PREVIEW_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    let text = String::from_utf8_lossy(&buf);
    text.split('\n')
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| truncate_chars(l, TEMPLATE_PREVIEW_CHARS).to_string())
}

/// Prompt templates usable as `template_override` (regular `.txt` files with
/// a valid override name in `<group_dir>/prompts`), sorted by filename.
/// Bodies are never returned; a symlinked `prompts/` directory is an error.
pub(crate) fn list_templates(group_dir: &Path) -> io::Result<Vec<TemplateInfo>> {
    let Some(dir) = open_agent_dir(group_dir, PROMPTS_DIR)? else {
        return Ok(Vec::new());
    };
    let names = collect_names(
        dir.as_fd(),
        is_valid_template_name,
        Order::Ascending,
        MAX_TEMPLATES,
    )?;

    let mut out = Vec::with_capacity(names.len());
    for filename in names {
        let Ok((file, meta)) = open_regular(dir.as_fd(), &filename) else {
            continue;
        };
        let modified_at = meta
            .modified()
            .ok()
            .map(|t| talon_core::time::to_iso(DateTime::<Utc>::from(t)));
        out.push(TemplateInfo {
            first_line: first_non_empty_line(file),
            filename,
            size_bytes: meta.len(),
            modified_at,
        });
    }
    Ok(out)
}

/// Whether `name` is a valid override name and a regular file directly
/// inside `<group_dir>/prompts` (never through a symlink).
pub(crate) fn template_exists(group_dir: &Path, name: &str) -> bool {
    if !is_valid_template_name(name) {
        return false;
    }
    match open_agent_dir(group_dir, PROMPTS_DIR) {
        Ok(Some(dir)) => open_regular(dir.as_fd(), name).is_ok(),
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(err = %e, "refusing to look up template override");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, Instant};

    /// `<tmp>/group` with an `evals` and a `prompts` directory.
    fn group() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let g = dir.path().join("group");
        fs::create_dir_all(g.join(EVALS_DIR)).unwrap();
        fs::create_dir_all(g.join(PROMPTS_DIR)).unwrap();
        (dir, g)
    }

    fn mkfifo(path: &Path) -> bool {
        std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn evals_are_filtered_by_alert_prefix_and_sorted_newest_first() {
        let (_t, g) = group();
        let d = g.join(EVALS_DIR);
        fs::write(d.join("12-copilot-inv-12-100.json"), r#"{"job":"a"}"#).unwrap();
        fs::write(d.join("12-copilot-inv-12-200.json"), r#"{"job":"b"}"#).unwrap();
        fs::write(d.join("123-copilot-inv-123-1.json"), r#"{"job":"other"}"#).unwrap();
        fs::write(d.join("12-broken.json"), "{not json").unwrap();
        fs::write(d.join("12-notes.txt"), "x").unwrap();
        let evals = read_evals(&g, "12").unwrap();
        assert_eq!(evals.len(), 2);
        assert_eq!(evals[0]["job"], "b");
        assert_eq!(evals[1]["job"], "a");
    }

    #[test]
    fn evals_are_capped_to_the_newest_max_evals() {
        let (_t, g) = group();
        let d = g.join(EVALS_DIR);
        for i in 0..(MAX_EVALS + 50) {
            fs::write(
                d.join(format!("5-job-{i:04}.json")),
                format!(r#"{{"i":{i}}}"#),
            )
            .unwrap();
        }
        let evals = read_evals(&g, "5").unwrap();
        assert_eq!(evals.len(), MAX_EVALS);
        assert_eq!(evals[0]["i"], MAX_EVALS + 49);
        assert_eq!(evals[MAX_EVALS - 1]["i"], 50);
    }

    #[test]
    fn missing_evals_dir_or_group_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_evals(&dir.path().join("nope"), "1")
                .unwrap()
                .is_empty()
        );
        assert!(read_evals(dir.path(), "1").unwrap().is_empty());
        assert!(list_templates(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn symlinked_evals_are_skipped() {
        let (_t, g) = group();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.json");
        fs::write(&secret, r#"{"secret":true}"#).unwrap();
        std::os::unix::fs::symlink(&secret, g.join(EVALS_DIR).join("7-x.json")).unwrap();
        assert!(read_evals(&g, "7").unwrap().is_empty());
    }

    #[test]
    fn symlinked_evals_dir_is_refused() {
        let (_t, g) = group();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("7-x.json"), r#"{"secret":true}"#).unwrap();
        fs::remove_dir(g.join(EVALS_DIR)).unwrap();
        std::os::unix::fs::symlink(outside.path(), g.join(EVALS_DIR)).unwrap();
        let err = read_evals(&g, "7").unwrap_err();
        assert!(err.to_string().contains("refusing to follow"), "{err}");
    }

    #[test]
    fn evals_dir_that_is_a_file_is_refused() {
        let (_t, g) = group();
        fs::remove_dir(g.join(EVALS_DIR)).unwrap();
        fs::write(g.join(EVALS_DIR), "x").unwrap();
        assert!(read_evals(&g, "7").is_err());
    }

    #[test]
    fn operator_symlinked_group_dir_is_followed() {
        let real = tempfile::tempdir().unwrap();
        fs::create_dir_all(real.path().join(EVALS_DIR)).unwrap();
        fs::write(real.path().join(EVALS_DIR).join("3-a.json"), r#"{"ok":1}"#).unwrap();
        let links = tempfile::tempdir().unwrap();
        let g = links.path().join("copilot");
        std::os::unix::fs::symlink(real.path(), &g).unwrap();
        assert_eq!(read_evals(&g, "3").unwrap().len(), 1);
    }

    #[test]
    fn fifo_and_oversized_evals_are_skipped_without_blocking() {
        let (_t, g) = group();
        let d = g.join(EVALS_DIR);
        fs::write(
            d.join("9-big.json"),
            vec![b' '; MAX_EVAL_BYTES as usize + 1],
        )
        .unwrap();
        fs::write(d.join("9-ok.json"), r#"{"ok":true}"#).unwrap();
        fs::create_dir(d.join("9-dir.json")).unwrap();
        let have_fifo = mkfifo(&d.join("9-fifo.json"));
        let started = Instant::now();
        let evals = read_evals(&g, "9").unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(evals, vec![serde_json::json!({"ok": true})]);
        if !have_fifo {
            eprintln!("mkfifo unavailable; FIFO case not exercised");
        }
    }

    #[test]
    fn templates_list_valid_regular_txt_files_with_previews() {
        let (_t, g) = group();
        let d = g.join(PROMPTS_DIR);
        fs::write(
            d.join("sysmon_event_1.txt"),
            "\n\n  # Process Creation  \nbody",
        )
        .unwrap();
        fs::write(d.join("b.txt"), "").unwrap();
        fs::write(d.join("README.md"), "# readme").unwrap();
        fs::write(d.join(".hidden.txt"), "x").unwrap();
        fs::write(d.join("long.txt"), "x".repeat(500)).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("t.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.path().join("t.txt"), d.join("link.txt")).unwrap();
        let _ = mkfifo(&d.join("fifo.txt"));

        let t = list_templates(&g).unwrap();
        let names: Vec<_> = t.iter().map(|t| t.filename.as_str()).collect();
        assert_eq!(names, vec!["b.txt", "long.txt", "sysmon_event_1.txt"]);
        assert_eq!(t[0].first_line, None);
        assert_eq!(t[1].first_line.as_ref().unwrap().len(), 200);
        assert_eq!(t[2].first_line.as_deref(), Some("# Process Creation"));
        assert!(t[2].modified_at.as_ref().unwrap().ends_with('Z'));
        assert_eq!(t[2].size_bytes, 29);
    }

    #[test]
    fn symlinked_prompts_dir_is_refused() {
        let (_t, g) = group();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("t.txt"), "secret").unwrap();
        fs::remove_dir(g.join(PROMPTS_DIR)).unwrap();
        std::os::unix::fs::symlink(outside.path(), g.join(PROMPTS_DIR)).unwrap();
        assert!(list_templates(&g).is_err());
        assert!(!template_exists(&g, "t.txt"));
    }

    #[test]
    fn template_existence_requires_a_regular_file_inside_the_dir() {
        let (_t, g) = group();
        let d = g.join(PROMPTS_DIR);
        fs::write(d.join("ok.txt"), "x").unwrap();
        fs::create_dir(d.join("dir.txt")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("t.txt"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path().join("t.txt"), d.join("link.txt")).unwrap();
        let have_fifo = mkfifo(&d.join("fifo.txt"));
        assert!(template_exists(&g, "ok.txt"));
        assert!(!template_exists(&g, "missing.txt"));
        assert!(!template_exists(&g, "dir.txt"));
        assert!(!template_exists(&g, "link.txt"));
        assert!(!template_exists(&g, "../ok.txt"));
        if have_fifo {
            assert!(!template_exists(&g, "fifo.txt"));
        }
    }

    #[test]
    fn names_are_collected_with_bounded_memory_in_order() {
        let (_t, g) = group();
        let d = g.join(PROMPTS_DIR);
        for i in 0..300 {
            fs::write(d.join(format!("t{i:03}.txt")), "x").unwrap();
        }
        let dir = open_agent_dir(&g, PROMPTS_DIR).unwrap().unwrap();
        let asc = collect_names(dir.as_fd(), |_| true, Order::Ascending, 10).unwrap();
        assert_eq!(asc.first().map(String::as_str), Some("t000.txt"));
        assert_eq!(asc.len(), 10);
        let desc = collect_names(dir.as_fd(), |_| true, Order::Descending, 3).unwrap();
        assert_eq!(desc, vec!["t299.txt", "t298.txt", "t297.txt"]);
    }
}
