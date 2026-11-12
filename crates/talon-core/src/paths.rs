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

/// Name of the host configuration directory under `~/.config`.
pub const CONFIG_DIR_NAME: &str = "talahon";

/// Its name up to 2.x, still used when it is the only one that exists.
pub const LEGACY_CONFIG_DIR_NAME: &str = "talon";

/// Which host configuration directory is in effect, see
/// [`resolve_config_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDir {
    /// The one authoritative directory (mount and sender allowlists).
    pub path: PathBuf,
    /// True when [`Self::path`] is the pre-rename `~/.config/talon`.
    pub legacy: bool,
    /// `~/.config/talon` when it exists next to `~/.config/talahon`: it is
    /// **not** read (the two are never merged).
    pub ignored_legacy: Option<PathBuf>,
}

/// The host configuration directory for `home`.
///
/// `~/.config/talahon` when it exists; else `~/.config/talon` when that
/// exists (an installation from before the rename); else
/// `~/.config/talahon`. The allowlists in there are security decisions, so
/// exactly one directory is authoritative: nothing is ever read from the
/// other one.
pub fn resolve_config_dir(home: &Path) -> ConfigDir {
    let base = home.join(".config");
    let current = base.join(CONFIG_DIR_NAME);
    let legacy = base.join(LEGACY_CONFIG_DIR_NAME);
    let legacy_exists = legacy.is_dir();
    if current.is_dir() || !legacy_exists {
        ConfigDir {
            path: current,
            legacy: false,
            ignored_legacy: legacy_exists.then_some(legacy),
        }
    } else {
        ConfigDir {
            path: legacy,
            legacy: true,
            ignored_legacy: None,
        }
    }
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
    fn config_dir_prefers_the_new_name_and_never_merges() {
        let home = std::env::temp_dir().join(format!(
            "talahon-core-config-dir-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        let new = home.join(".config/talahon");
        let old = home.join(".config/talon");

        // Fresh install: the new name, even though nothing exists yet.
        let fresh = resolve_config_dir(&home);
        assert_eq!(fresh.path, new);
        assert!(!fresh.legacy);
        assert_eq!(fresh.ignored_legacy, None);

        // Upgraded install: only the old directory exists and is used.
        std::fs::create_dir_all(&old).unwrap();
        let upgraded = resolve_config_dir(&home);
        assert_eq!(upgraded.path, old);
        assert!(upgraded.legacy);
        assert_eq!(upgraded.ignored_legacy, None);

        // Both exist: the new one alone is authoritative, the old one is
        // reported as ignored (never merged).
        std::fs::create_dir_all(&new).unwrap();
        let both = resolve_config_dir(&home);
        assert_eq!(both.path, new);
        assert!(!both.legacy);
        assert_eq!(both.ignored_legacy, Some(old.clone()));

        // A file named like the directory does not count.
        std::fs::remove_dir_all(&new).unwrap();
        std::fs::write(&new, "x").unwrap();
        assert_eq!(resolve_config_dir(&home).path, old);
        let _ = std::fs::remove_dir_all(&home);
    }

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
        let base = Path::new("/srv/talahon/groups");
        assert_eq!(
            group_folder_path(base, "main").unwrap(),
            PathBuf::from("/srv/talahon/groups/main")
        );
        assert!(group_folder_path(base, "..").is_err());
        assert!(ensure_within(base, Path::new("/srv/talahon/groups/../x")).is_err());
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
