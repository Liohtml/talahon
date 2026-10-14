//! Read-only filesystem views: eval JSON files and prompt templates.
//!
//! Only regular files are considered (`symlink_metadata`, so a symlink
//! planted in `prompts/` or `evals/` can never point the API at a file
//! outside the group folder), and every read is size-capped.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::validate::{is_valid_template_name, truncate_chars};

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

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Eval JSON files for `alert_id` (`<alert_id>-*.json`), newest job id
/// first. Unparseable or oversized files are skipped with a warning.
pub(crate) fn read_evals(dir: &Path, alert_id: &str) -> io::Result<Vec<Value>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let prefix = format!("{alert_id}-");
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(&prefix) && n.ends_with(".json"))
        .collect();
    names.sort();
    names.reverse();
    names.truncate(MAX_EVALS);

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let path = dir.join(&name);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() {
            tracing::warn!(file = %name, "skipping non-regular eval file");
            continue;
        }
        if meta.len() > MAX_EVAL_BYTES {
            tracing::warn!(file = %name, size = meta.len(), "skipping oversized eval file");
            continue;
        }
        match fs::read(&path).map(|b| serde_json::from_slice::<Value>(&b)) {
            Ok(Ok(v)) => out.push(v),
            Ok(Err(e)) => tracing::warn!(file = %name, err = %e, "failed to parse eval file"),
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

fn first_non_empty_line(path: &Path) -> Option<String> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(TEMPLATE_PREVIEW_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    let text = String::from_utf8_lossy(&buf);
    text.split('\n')
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| truncate_chars(l, TEMPLATE_PREVIEW_CHARS).to_string())
}

/// Prompt templates usable as `template_override` (regular `.txt` files with
/// a valid override name), sorted by filename. Bodies are never returned.
pub(crate) fn list_templates(dir: &Path) -> io::Result<Vec<TemplateInfo>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_valid_template_name(n))
        .collect();
    names.sort();
    names.truncate(MAX_TEMPLATES);

    let mut out = Vec::with_capacity(names.len());
    for filename in names {
        let path = dir.join(&filename);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let modified_at = meta
            .modified()
            .ok()
            .map(|t| talon_core::time::to_iso(DateTime::<Utc>::from(t)));
        out.push(TemplateInfo {
            first_line: first_non_empty_line(&path),
            filename,
            size_bytes: meta.len(),
            modified_at,
        });
    }
    Ok(out)
}

/// Whether `name` (already validated with `is_valid_template_name`) is a
/// regular file directly inside `dir`.
pub(crate) fn template_exists(dir: &Path, name: &str) -> bool {
    is_valid_template_name(name) && is_regular_file(&dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evals_are_filtered_by_alert_prefix_and_sorted_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        fs::write(d.join("12-copilot-inv-12-100.json"), r#"{"job":"a"}"#).unwrap();
        fs::write(d.join("12-copilot-inv-12-200.json"), r#"{"job":"b"}"#).unwrap();
        fs::write(d.join("123-copilot-inv-123-1.json"), r#"{"job":"other"}"#).unwrap();
        fs::write(d.join("12-broken.json"), "{not json").unwrap();
        fs::write(d.join("12-notes.txt"), "x").unwrap();
        let evals = read_evals(d, "12").unwrap();
        assert_eq!(evals.len(), 2);
        assert_eq!(evals[0]["job"], "b");
        assert_eq!(evals[1]["job"], "a");
    }

    #[test]
    fn missing_evals_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_evals(&dir.path().join("nope"), "1")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn symlinked_evals_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.json");
        fs::write(&secret, r#"{"secret":true}"#).unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("7-x.json")).unwrap();
        assert!(read_evals(dir.path(), "7").unwrap().is_empty());
    }

    #[test]
    fn templates_list_valid_regular_txt_files_with_previews() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
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

        let t = list_templates(d).unwrap();
        let names: Vec<_> = t.iter().map(|t| t.filename.as_str()).collect();
        assert_eq!(names, vec!["b.txt", "long.txt", "sysmon_event_1.txt"]);
        assert_eq!(t[0].first_line, None);
        assert_eq!(t[1].first_line.as_ref().unwrap().len(), 200);
        assert_eq!(t[2].first_line.as_deref(), Some("# Process Creation"));
        assert!(t[2].modified_at.as_ref().unwrap().ends_with('Z'));
        assert_eq!(t[2].size_bytes, 29);
    }

    #[test]
    fn template_existence_requires_a_regular_file_inside_the_dir() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        fs::write(d.join("ok.txt"), "x").unwrap();
        fs::create_dir(d.join("dir.txt")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("t.txt"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path().join("t.txt"), d.join("link.txt")).unwrap();
        assert!(template_exists(d, "ok.txt"));
        assert!(!template_exists(d, "missing.txt"));
        assert!(!template_exists(d, "dir.txt"));
        assert!(!template_exists(d, "link.txt"));
        assert!(!template_exists(d, "../ok.txt"));
    }
}
