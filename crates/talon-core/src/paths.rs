//! Group-folder validation and traversal-safe path resolution.
//!
//! Group folders and lane keys end up in host filesystem paths and container
//! mount specs, so they are validated against a strict pattern *and* the
//! resolved path is re-checked to stay inside its base directory.

use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::{Error, Result};

static GROUP_FOLDER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$").expect("static regex"));

const RESERVED_FOLDERS: &[&str] = &["global", "errors"];

/// `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`, not reserved (`global`, `errors`).
pub fn is_valid_group_folder(folder: &str) -> bool {
    !folder.is_empty()
        && folder == folder.trim()
        && GROUP_FOLDER_PATTERN.is_match(folder)
        && !folder.contains("..")
        && !RESERVED_FOLDERS
            .iter()
            .any(|r| r.eq_ignore_ascii_case(folder))
}

pub fn assert_valid_group_folder(folder: &str) -> Result<()> {
    if is_valid_group_folder(folder) {
        Ok(())
    } else {
        Err(Error::security(format!("invalid group folder {folder:?}")))
    }
}

/// Lexically normalize a path (resolve `.` and `..`) without touching the
/// filesystem.
pub fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Ensure `candidate` (after lexical normalization) is `base` or inside it.
pub fn ensure_within(base: &Path, candidate: &Path) -> Result<PathBuf> {
    let base_n = normalize_lexically(base);
    let cand_n = normalize_lexically(candidate);
    if cand_n.starts_with(&base_n) {
        Ok(cand_n)
    } else {
        Err(Error::security(format!(
            "path {} escapes base directory {}",
            candidate.display(),
            base.display()
        )))
    }
}

fn resolve_under(base: &Path, key: &str) -> Result<PathBuf> {
    assert_valid_group_folder(key)?;
    ensure_within(base, &base.join(key))
}

/// `<groups_dir>/<folder>`
pub fn group_folder_path(groups_dir: &Path, folder: &str) -> Result<PathBuf> {
    resolve_under(groups_dir, folder)
}

/// `<data_dir>/ipc/<ipc_key>`
pub fn group_ipc_path(data_dir: &Path, ipc_key: &str) -> Result<PathBuf> {
    resolve_under(&data_dir.join("ipc"), ipc_key)
}

/// `<data_dir>/sessions/<session_key>` — the lane's persistent agent state.
pub fn group_sessions_path(data_dir: &Path, session_key: &str) -> Result<PathBuf> {
    resolve_under(&data_dir.join("sessions"), session_key)
}

/// Expand a leading `~` / `~/` using `$HOME`.
pub fn expand_home(p: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    if p == "~" {
        PathBuf::from(home)
    } else if let Some(rest) = p.strip_prefix("~/") {
        Path::new(&home).join(rest)
    } else {
        PathBuf::from(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_validation() {
        assert!(is_valid_group_folder("main"));
        assert!(is_valid_group_folder("copilot-u-42"));
        assert!(!is_valid_group_folder(""));
        assert!(!is_valid_group_folder("../etc"));
        assert!(!is_valid_group_folder("a/b"));
        assert!(!is_valid_group_folder("Global"));
        assert!(!is_valid_group_folder(" main"));
        assert!(!is_valid_group_folder("-lead"));
        assert!(!is_valid_group_folder(&"a".repeat(65)));
    }

    #[test]
    fn resolution_stays_in_base() {
        let base = Path::new("/srv/talon/groups");
        assert_eq!(
            group_folder_path(base, "main").unwrap(),
            PathBuf::from("/srv/talon/groups/main")
        );
        assert!(group_folder_path(base, "..").is_err());
        assert!(ensure_within(base, Path::new("/srv/talon/groups/../x")).is_err());
    }

    #[test]
    fn ipc_and_session_paths() {
        let data = Path::new("/d");
        assert_eq!(
            group_ipc_path(data, "g").unwrap(),
            PathBuf::from("/d/ipc/g")
        );
        assert_eq!(
            group_sessions_path(data, "g").unwrap(),
            PathBuf::from("/d/sessions/g")
        );
    }
}
