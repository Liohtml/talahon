//! Read-only filesystem views: eval JSON files and prompt templates.
//!
//! Eval records live in the investigation lane's private state directory,
//! `<data_dir>/sessions/<investigation session key>/evals` (the container's
//! `/home/agent/.talon/evals`): only that lane can write them, so another
//! CoPilot lane can no longer forge an alert's evals (N-2). Prompt templates
//! (and, for migration only, legacy evals) live in `groups/<folder>/`.
//!
//! Both trees are mounted read-write into agent containers, so their files
//! *and the directory entries themselves* are attacker-controlled (MYTH-10).
//! A path-based check-then-read can be raced (swap `evals/` for a symlink
//! to a host directory, or a file for a FIFO that blocks the reader
//! forever). Therefore:
//!
//! - the root (`groups/<folder>` or `<data_dir>/sessions`) is
//!   operator-controlled and opened normally; every component below it (the
//!   lane directory, `evals`, `prompts`) is opened relative to its parent
//!   descriptor with `O_DIRECTORY | O_NOFOLLOW` (a directory symlink is
//!   refused) and every later access goes through the final descriptor;
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

use talon_core::paths::is_valid_group_folder;

use crate::validate::{is_valid_template_name, truncate_chars};

/// Agent-written eval JSON files, below the investigation lane's state
/// directory (legacy: below the group directory).
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

/// Open `<root>/<components...>` as a directory. `root` is
/// operator-controlled and opened normally (it may legitimately be a
/// symlink, e.g. to a data volume); each component is opened relative to
/// its parent's descriptor without following a symlink. `Ok(None)` when
/// anything along the way does not exist.
fn open_dir_below(root: &Path, components: &[&str]) -> io::Result<Option<OwnedFd>> {
    let mut dir = match rfs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) if e == Errno::NOENT => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    for name in components {
        if name.is_empty() || name.contains('/') || *name == "." || *name == ".." {
            return Err(io::Error::other(format!(
                "invalid directory component {name:?}"
            )));
        }
        dir = match rfs::openat(&dir, *name, dir_flags(), Mode::empty()) {
            Ok(fd) => fd,
            Err(e) if e == Errno::NOENT => return Ok(None),
            Err(e) if is_symlink_errno(e) || e == Errno::NOTDIR => {
                return Err(io::Error::other(format!(
                    "{name}/ is a symlink or not a directory; refusing to follow it"
                )));
            }
            Err(e) => return Err(e.into()),
        };
    }
    Ok(Some(dir))
}

/// Open `<group_dir>/<name>` as a directory without following a symlink at
/// `name`. `Ok(None)` when either does not exist.
fn open_agent_dir(group_dir: &Path, name: &str) -> io::Result<Option<OwnedFd>> {
    open_dir_below(group_dir, &[name])
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

/// Eval JSON files for `alert_id` (`<dir>/<alert_id>-*.json`) in the
/// directory `dir` (already opened without following symlinks), newest job
/// id first, paired with their file names. Unsafe, unparseable or oversized
/// files are skipped with a warning.
fn read_evals_in(dir: BorrowedFd<'_>, alert_id: &str) -> io::Result<Vec<(String, Value)>> {
    let prefix = format!("{alert_id}-");
    let names = collect_names(
        dir,
        |n| n.starts_with(&prefix) && n.ends_with(".json"),
        Order::Descending,
        MAX_EVALS,
    )?;

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let (file, meta) = match open_regular(dir, &name) {
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
                Ok(v) => out.push((name, v)),
                Err(e) => tracing::warn!(file = %name, err = %e, "failed to parse eval file"),
            },
            Ok(None) => tracing::warn!(file = %name, "eval file grew past the size cap; skipped"),
            Err(e) => tracing::warn!(file = %name, err = %e, "failed to read eval file"),
        }
    }
    Ok(out)
}

/// Evals for `alert_id` in `<root>/<components...>/`; nothing when the
/// directory does not exist, an error when any component is a symlink.
fn read_evals_below(
    root: &Path,
    components: &[&str],
    alert_id: &str,
) -> io::Result<Vec<(String, Value)>> {
    match open_dir_below(root, components)? {
        Some(dir) => read_evals_in(dir.as_fd(), alert_id),
        None => Ok(Vec::new()),
    }
}

/// Eval JSON files for `alert_id` in `<group_dir>/evals/<alert_id>-*.json`,
/// newest job id first. Unsafe, unparseable or oversized files are skipped
/// with a warning; a symlinked `evals/` directory is an error.
#[cfg(test)]
pub(crate) fn read_evals(group_dir: &Path, alert_id: &str) -> io::Result<Vec<Value>> {
    Ok(read_evals_below(group_dir, &[EVALS_DIR], alert_id)?
        .into_iter()
        .map(|(_, v)| v)
        .collect())
}

/// Where `GET /evals` looks for eval records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvalSources {
    /// `<data_dir>/sessions` (operator-controlled; may be a symlink).
    pub sessions_dir: std::path::PathBuf,
    /// Session key of the investigation lane (its state directory below
    /// `sessions_dir`; never followed if it is a symlink).
    pub lane_key: String,
    /// The legacy shared group directory, read in addition when the
    /// operator enabled `COPILOT_EVALS_LEGACY_GROUP_DIR`.
    pub legacy_group_dir: Option<std::path::PathBuf>,
}

/// Eval records for `alert_id`, newest job id first, at most
/// [`MAX_EVALS`].
///
/// The primary source is the investigation lane's private
/// `<sessions_dir>/<lane_key>/evals/`: a symlinked lane directory or
/// `evals/` is an error. With a legacy group directory configured, records
/// found there are merged in (a file name present in both places is taken
/// from the lane-private copy); a problem with the legacy directory is
/// logged and that source skipped, so it cannot take the endpoint down.
pub(crate) fn read_investigation_evals(
    sources: &EvalSources,
    alert_id: &str,
) -> io::Result<Vec<Value>> {
    if !is_valid_group_folder(&sources.lane_key) {
        return Err(io::Error::other(format!(
            "invalid investigation lane key {:?}",
            sources.lane_key
        )));
    }
    let mut evals = read_evals_below(
        &sources.sessions_dir,
        &[sources.lane_key.as_str(), EVALS_DIR],
        alert_id,
    )?;
    if let Some(group_dir) = &sources.legacy_group_dir {
        match read_evals_below(group_dir, &[EVALS_DIR], alert_id) {
            Ok(legacy) if !legacy.is_empty() => {
                tracing::debug!(
                    count = legacy.len(),
                    "serving eval records from the legacy shared group directory"
                );
                for (name, value) in legacy {
                    if !evals.iter().any(|(n, _)| *n == name) {
                        evals.push((name, value));
                    }
                }
                evals.sort_by(|a, b| b.0.cmp(&a.0));
                evals.truncate(MAX_EVALS);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(err = %e, "skipping the legacy group evals directory");
            }
        }
    }
    Ok(evals.into_iter().map(|(_, v)| v).collect())
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

    // ---- lane-private eval records (N-2) -----------------------------------

    const LANE: &str = "copilot-investigate";

    /// `<tmp>/data/sessions/<LANE>/evals` plus a legacy `<tmp>/groups/copilot/evals`.
    struct Layout {
        _tmp: tempfile::TempDir,
        sessions: std::path::PathBuf,
        group: std::path::PathBuf,
    }

    impl Layout {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let sessions = tmp.path().join("data/sessions");
            let group = tmp.path().join("groups/copilot");
            fs::create_dir_all(sessions.join(LANE).join(EVALS_DIR)).unwrap();
            fs::create_dir_all(group.join(EVALS_DIR)).unwrap();
            Self {
                _tmp: tmp,
                sessions,
                group,
            }
        }

        fn lane_evals(&self) -> std::path::PathBuf {
            self.sessions.join(LANE).join(EVALS_DIR)
        }

        fn sources(&self, legacy: bool) -> EvalSources {
            EvalSources {
                sessions_dir: self.sessions.clone(),
                lane_key: LANE.to_string(),
                legacy_group_dir: legacy.then(|| self.group.clone()),
            }
        }
    }

    #[test]
    fn investigation_evals_come_from_the_lane_private_state_dir() {
        let l = Layout::new();
        fs::write(
            l.lane_evals().join("12-copilot-inv-12-1.json"),
            r#"{"n":1}"#,
        )
        .unwrap();
        fs::write(
            l.lane_evals().join("12-copilot-inv-12-2.json"),
            r#"{"n":2}"#,
        )
        .unwrap();
        fs::write(
            l.lane_evals().join("120-copilot-inv-120-1.json"),
            r#"{"n":3}"#,
        )
        .unwrap();
        // A forged record dropped into the shared group folder by another lane.
        fs::write(
            l.group.join(EVALS_DIR).join("12-copilot-inv-12-9.json"),
            r#"{"forged":true}"#,
        )
        .unwrap();
        let evals = read_investigation_evals(&l.sources(false), "12").unwrap();
        assert_eq!(
            evals,
            vec![serde_json::json!({"n": 2}), serde_json::json!({"n": 1})]
        );
    }

    #[test]
    fn missing_lane_or_sessions_dir_yields_no_evals() {
        let tmp = tempfile::tempdir().unwrap();
        for sessions in [tmp.path().join("nope"), tmp.path().to_path_buf()] {
            let sources = EvalSources {
                sessions_dir: sessions,
                lane_key: LANE.to_string(),
                legacy_group_dir: None,
            };
            assert!(read_investigation_evals(&sources, "1").unwrap().is_empty());
        }
        fs::create_dir_all(tmp.path().join(LANE)).unwrap();
        let sources = EvalSources {
            sessions_dir: tmp.path().to_path_buf(),
            lane_key: LANE.to_string(),
            legacy_group_dir: None,
        };
        assert!(read_investigation_evals(&sources, "1").unwrap().is_empty());
    }

    #[test]
    fn symlinked_lane_dir_is_refused() {
        let l = Layout::new();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(outside.path().join(EVALS_DIR)).unwrap();
        fs::write(
            outside.path().join(EVALS_DIR).join("7-x.json"),
            r#"{"secret":true}"#,
        )
        .unwrap();
        fs::remove_dir_all(l.sessions.join(LANE)).unwrap();
        std::os::unix::fs::symlink(outside.path(), l.sessions.join(LANE)).unwrap();
        let err = read_investigation_evals(&l.sources(false), "7").unwrap_err();
        assert!(err.to_string().contains("refusing to follow"), "{err}");
    }

    #[test]
    fn symlinked_lane_evals_dir_is_refused() {
        let l = Layout::new();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("7-x.json"), r#"{"secret":true}"#).unwrap();
        fs::remove_dir(l.lane_evals()).unwrap();
        std::os::unix::fs::symlink(outside.path(), l.lane_evals()).unwrap();
        let err = read_investigation_evals(&l.sources(false), "7").unwrap_err();
        assert!(err.to_string().contains("refusing to follow"), "{err}");
        // A file where the directory should be is refused too.
        fs::remove_file(l.lane_evals()).unwrap();
        fs::write(l.lane_evals(), "x").unwrap();
        assert!(read_investigation_evals(&l.sources(false), "7").is_err());
    }

    #[test]
    fn symlinked_and_fifo_lane_eval_files_are_skipped() {
        let l = Layout::new();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("s.json"), r#"{"secret":true}"#).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("s.json"),
            l.lane_evals().join("7-link.json"),
        )
        .unwrap();
        let _ = mkfifo(&l.lane_evals().join("7-fifo.json"));
        fs::write(l.lane_evals().join("7-ok.json"), r#"{"ok":1}"#).unwrap();
        let started = Instant::now();
        let evals = read_investigation_evals(&l.sources(false), "7").unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(evals, vec![serde_json::json!({"ok": 1})]);
    }

    #[test]
    fn operator_symlinked_sessions_root_is_followed() {
        let real = tempfile::tempdir().unwrap();
        let evals = real.path().join(LANE).join(EVALS_DIR);
        fs::create_dir_all(&evals).unwrap();
        fs::write(evals.join("3-a.json"), r#"{"ok":1}"#).unwrap();
        let links = tempfile::tempdir().unwrap();
        let sessions = links.path().join("sessions");
        std::os::unix::fs::symlink(real.path(), &sessions).unwrap();
        let sources = EvalSources {
            sessions_dir: sessions,
            lane_key: LANE.to_string(),
            legacy_group_dir: None,
        };
        assert_eq!(read_investigation_evals(&sources, "3").unwrap().len(), 1);
    }

    #[test]
    fn invalid_lane_keys_are_refused() {
        let l = Layout::new();
        for key in ["", "..", "a/b", "../copilot", "-x"] {
            let mut sources = l.sources(false);
            sources.lane_key = key.to_string();
            assert!(read_investigation_evals(&sources, "1").is_err(), "{key:?}");
        }
    }

    #[test]
    fn legacy_group_dir_is_merged_only_when_enabled() {
        let l = Layout::new();
        let legacy = l.group.join(EVALS_DIR);
        fs::write(l.lane_evals().join("5-job-2.json"), r#"{"src":"lane2"}"#).unwrap();
        fs::write(legacy.join("5-job-1.json"), r#"{"src":"legacy1"}"#).unwrap();
        fs::write(legacy.join("5-job-3.json"), r#"{"src":"legacy3"}"#).unwrap();
        // Same name in both places: the lane-private copy wins.
        fs::write(l.lane_evals().join("5-job-4.json"), r#"{"src":"lane4"}"#).unwrap();
        fs::write(legacy.join("5-job-4.json"), r#"{"src":"forged4"}"#).unwrap();

        let off = read_investigation_evals(&l.sources(false), "5").unwrap();
        assert_eq!(
            off,
            vec![
                serde_json::json!({"src": "lane4"}),
                serde_json::json!({"src": "lane2"})
            ]
        );
        let on = read_investigation_evals(&l.sources(true), "5").unwrap();
        assert_eq!(
            on,
            vec![
                serde_json::json!({"src": "lane4"}),
                serde_json::json!({"src": "legacy3"}),
                serde_json::json!({"src": "lane2"}),
                serde_json::json!({"src": "legacy1"}),
            ]
        );
    }

    #[test]
    fn merged_evals_stay_capped() {
        let l = Layout::new();
        for i in 0..MAX_EVALS {
            fs::write(
                l.lane_evals().join(format!("5-a-{i:04}.json")),
                format!(r#"{{"i":{i}}}"#),
            )
            .unwrap();
            fs::write(
                l.group.join(EVALS_DIR).join(format!("5-b-{i:04}.json")),
                format!(r#"{{"legacy":{i}}}"#),
            )
            .unwrap();
        }
        let evals = read_investigation_evals(&l.sources(true), "5").unwrap();
        assert_eq!(evals.len(), MAX_EVALS);
        assert_eq!(evals[0]["legacy"], MAX_EVALS - 1);
    }

    #[test]
    fn a_symlinked_legacy_dir_is_skipped_not_followed() {
        let l = Layout::new();
        fs::write(l.lane_evals().join("7-ok.json"), r#"{"ok":1}"#).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("7-x.json"), r#"{"secret":true}"#).unwrap();
        fs::remove_dir(l.group.join(EVALS_DIR)).unwrap();
        std::os::unix::fs::symlink(outside.path(), l.group.join(EVALS_DIR)).unwrap();
        let evals = read_investigation_evals(&l.sources(true), "7").unwrap();
        assert_eq!(evals, vec![serde_json::json!({"ok": 1})]);
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
