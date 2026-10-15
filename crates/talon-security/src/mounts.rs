//! Additional-mount validation against the tamper-proof allowlist.
//!
//! Rules: no allowlist file => every additional mount is rejected; host paths
//! are canonicalized (symlinks resolved) before matching allowed roots and
//! blocked patterns (`.ssh`, `.gnupg`, `.aws`, `.env`, `id_rsa`, `*.pem`,
//! `.docker`, `.kube`, credentials, ... are always blocked even if the file
//! omits them); container paths must be relative, without `..`, `:` or
//! control characters; non-main groups are forced read-only when
//! `non_main_read_only`; read-write requires `allow_read_write` on the root.
//!
//! Hardening:
//! - pattern matching is case-insensitive and supports globs (`*.pem`);
//! - relative or `~user` host paths and allowed roots are rejected instead
//!   of being resolved against the process cwd;
//! - an allowed root of `/` is ignored;
//! - host paths containing `:`/`,`/control characters (docker `-v`/`--mount`
//!   option injection) are rejected, as are container paths outside a
//!   conservative charset;
//! - only directories and regular files can be mounted (no sockets such as
//!   `docker.sock`, no device nodes or FIFOs);
//! - system locations (`/proc`, `/sys`, `/dev`, `/etc`, `/run`, `/var/run`,
//!   `/boot`, docker/containerd state), the user's home directory
//!   itself (or any ancestor of it) and `~/.config` are never mountable;
//! - a world-writable allowlist file is refused (it would not be
//!   tamper-proof);
//! - duplicate container paths are rejected by [`MountValidator::validate_all`].
//!
//! Known limitation: validation happens before `docker run`; a path swapped
//! for a symlink in between (TOCTOU) is only caught if the runtime resolves
//! the canonical path we return — callers must mount
//! [`ValidatedMount::host_path`], never the requested path.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};
use talon_core::paths::expand_home;
use talon_core::types::{AdditionalMount, AllowedRoot, MountAllowlist};

/// Patterns blocked regardless of the allowlist file.
pub const DEFAULT_BLOCKED_PATTERNS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".gpg",
    ".aws",
    ".azure",
    ".gcloud",
    ".kube",
    ".docker",
    ".env",
    "credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "private_key",
    ".secret",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
];

/// Container-side prefix of every additional mount.
pub const EXTRA_MOUNT_PREFIX: &str = "/workspace/extra";

/// Absolute host locations that are never mountable (nor anything below).
const SYSTEM_BLOCKED_PREFIXES: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/boot",
    "/run",
    "/var/run",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/containers",
    "/private/etc",
    "/private/var/run",
];

/// Extra file-name patterns (case-insensitive globs) always blocked on top
/// of [`DEFAULT_BLOCKED_PATTERNS`].
const EXTRA_BLOCKED_GLOBS: &[&str] = &["*.sock", "*.socket", "*.kdbx", "*.keychain*"];

/// Maximum size of the allowlist file.
const MAX_ALLOWLIST_BYTES: u64 = 1024 * 1024;

/// Maximum length of a container path.
const MAX_CONTAINER_PATH_LEN: usize = 255;

/// A mount that passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMount {
    /// Canonical host path.
    pub host_path: PathBuf,
    /// Full container path (`/workspace/extra/<name>`).
    pub container_path: String,
    /// Effective read-only flag (may be stricter than requested).
    pub readonly: bool,
}

/// Outcome of validating a single mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountDecision {
    /// The mount may be used as described.
    Allowed(ValidatedMount),
    /// The mount must not be used.
    Rejected {
        /// Human-readable reason (safe to log).
        reason: String,
    },
}

impl MountDecision {
    fn reject(reason: impl Into<String>) -> Self {
        MountDecision::Rejected {
            reason: reason.into(),
        }
    }
}

/// Validates [`AdditionalMount`]s against a [`MountAllowlist`].
#[derive(Debug, Clone)]
pub struct MountValidator {
    allowlist: Option<MountAllowlist>,
}

impl MountValidator {
    /// Load from disk. Missing/invalid file => validator that rejects all.
    pub fn load(path: &Path) -> Self {
        match read_allowlist(path) {
            Ok(list) => {
                tracing::info!(
                    path = %path.display(),
                    allowed_roots = list.allowed_roots.len(),
                    blocked_patterns = list.blocked_patterns.len() + DEFAULT_BLOCKED_PATTERNS.len(),
                    "mount allowlist loaded"
                );
                Self {
                    allowlist: Some(list),
                }
            }
            Err(LoadError::Missing) => {
                tracing::warn!(
                    path = %path.display(),
                    "mount allowlist not found - additional mounts will be BLOCKED"
                );
                Self { allowlist: None }
            }
            Err(LoadError::Invalid(reason)) => {
                tracing::error!(
                    path = %path.display(),
                    error = %reason,
                    "failed to load mount allowlist - additional mounts will be BLOCKED"
                );
                Self { allowlist: None }
            }
        }
    }

    /// Validator over an in-memory allowlist (`None` rejects everything).
    pub fn from_allowlist(allowlist: Option<MountAllowlist>) -> Self {
        Self { allowlist }
    }

    /// Whether an allowlist is configured at all.
    pub fn is_configured(&self) -> bool {
        self.allowlist.is_some()
    }

    /// Validate one mount for a group.
    pub fn validate(&self, mount: &AdditionalMount, is_main: bool) -> MountDecision {
        let Some(allowlist) = &self.allowlist else {
            return MountDecision::reject("no mount allowlist configured");
        };

        // --- host path: syntax ---------------------------------------------
        let raw = mount.host_path.as_str();
        if raw.trim().is_empty() {
            return MountDecision::reject("empty host path");
        }
        if raw.chars().any(char::is_control) {
            return MountDecision::reject("host path contains control characters");
        }
        let expanded = expand_home(raw);
        if !expanded.is_absolute() {
            return MountDecision::reject(format!(
                "host path must be absolute or start with ~/: {raw:?}"
            ));
        }

        // --- container path: syntax (cheap, before touching the fs) --------
        let container_rel = match &mount.container_path {
            Some(cp) if !cp.is_empty() => cp.clone(),
            _ => match expanded.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_string(),
                None => {
                    return MountDecision::reject("cannot derive container path from host path");
                }
            },
        };
        if let Err(reason) = check_container_path(&container_rel) {
            return MountDecision::reject(format!(
                "invalid container path {container_rel:?}: {reason}"
            ));
        }

        // --- canonicalize ---------------------------------------------------
        let real = match std::fs::canonicalize(&expanded) {
            Ok(p) => p,
            Err(_) => {
                return MountDecision::reject(format!(
                    "host path does not exist or is not accessible: {raw:?}"
                ));
            }
        };
        let Some(real_str) = real.to_str() else {
            return MountDecision::reject("host path is not valid UTF-8");
        };
        if real_str.contains(':')
            || real_str.contains(',')
            || real_str.chars().any(char::is_control)
        {
            return MountDecision::reject(format!(
                "host path contains characters unsafe for container mount specs: {real_str:?}"
            ));
        }
        match std::fs::metadata(&real) {
            Ok(md) if md.is_dir() || md.is_file() => {}
            Ok(_) => {
                return MountDecision::reject("only directories and regular files can be mounted");
            }
            Err(_) => return MountDecision::reject("cannot stat host path"),
        }

        // --- always-blocked locations ---------------------------------------
        if let Some(reason) = blocked_location(&real) {
            return MountDecision::reject(reason);
        }

        // --- blocked patterns -------------------------------------------------
        if let Some(pattern) = matches_blocked_pattern(&real, &allowlist.blocked_patterns) {
            return MountDecision::reject(format!(
                "path matches blocked pattern {pattern:?}: {real_str:?}"
            ));
        }

        // --- allowed roots ----------------------------------------------------
        let Some(root) = find_allowed_root(&real, &allowlist.allowed_roots) else {
            return MountDecision::reject(format!(
                "path {real_str:?} is not under any allowed root"
            ));
        };

        // --- read-only policy ---------------------------------------------------
        let requested_rw = !mount.readonly;
        let readonly = if !requested_rw {
            true
        } else if !is_main && allowlist.non_main_read_only {
            tracing::info!(mount = %raw, "mount forced to read-only for non-main group");
            true
        } else if !root.allow_read_write {
            tracing::info!(mount = %raw, root = %root.path, "mount forced to read-only - root does not allow read-write");
            true
        } else {
            false
        };

        MountDecision::Allowed(ValidatedMount {
            host_path: real,
            container_path: format!("{EXTRA_MOUNT_PREFIX}/{container_rel}"),
            readonly,
        })
    }

    /// Validate all; rejected mounts are logged (with reason) and dropped.
    pub fn validate_all(
        &self,
        mounts: &[AdditionalMount],
        group_name: &str,
        is_main: bool,
    ) -> Vec<ValidatedMount> {
        let mut out: Vec<ValidatedMount> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for mount in mounts {
            match self.validate(mount, is_main) {
                MountDecision::Allowed(v) => {
                    if !seen.insert(v.container_path.to_ascii_lowercase()) {
                        tracing::warn!(
                            group = %group_name,
                            requested_path = %mount.host_path,
                            container_path = %v.container_path,
                            "additional mount REJECTED: duplicate container path"
                        );
                        continue;
                    }
                    tracing::debug!(
                        group = %group_name,
                        host_path = %v.host_path.display(),
                        container_path = %v.container_path,
                        readonly = v.readonly,
                        "mount validated"
                    );
                    out.push(v);
                }
                MountDecision::Rejected { reason } => {
                    tracing::warn!(
                        group = %group_name,
                        requested_path = %mount.host_path,
                        container_path = ?mount.container_path,
                        reason = %reason,
                        "additional mount REJECTED"
                    );
                }
            }
        }
        out
    }
}

enum LoadError {
    Missing,
    Invalid(String),
}

fn read_allowlist(path: &Path) -> Result<MountAllowlist, LoadError> {
    let md = match std::fs::metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(LoadError::Missing),
        Err(e) => return Err(LoadError::Invalid(format!("cannot stat: {e}"))),
    };
    if !md.is_file() {
        return Err(LoadError::Invalid("not a regular file".into()));
    }
    if md.len() > MAX_ALLOWLIST_BYTES {
        return Err(LoadError::Invalid("file too large".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o002 != 0 {
            return Err(LoadError::Invalid(
                "file is world-writable and therefore not tamper-proof".into(),
            ));
        }
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| LoadError::Invalid(format!("cannot read: {e}")))?;
    serde_json::from_str::<MountAllowlist>(&content).map_err(|e| LoadError::Invalid(e.to_string()))
}

/// Container path rules: relative, non-empty, no `..`/`.` segments, no `:`
/// / `,` / backslash / control characters, conservative charset.
fn check_container_path(cp: &str) -> Result<(), &'static str> {
    if cp.trim().is_empty() {
        return Err("must not be empty");
    }
    if cp.len() > MAX_CONTAINER_PATH_LEN {
        return Err("too long");
    }
    if cp.starts_with('/') {
        return Err("must be relative");
    }
    if cp.contains("..") {
        return Err("must not contain \"..\"");
    }
    if cp.contains(':') {
        return Err("must not contain \":\"");
    }
    if cp.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    let charset_ok = cp
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ' ' | '@' | '+'));
    if !charset_ok {
        return Err("contains unsupported characters");
    }
    if cp != cp.trim() {
        return Err("must not start or end with whitespace");
    }
    for seg in cp.split('/') {
        if seg.is_empty() || seg == "." || seg.trim() != seg {
            return Err("contains an empty, \".\" or space-padded segment");
        }
    }
    Ok(())
}

/// System locations, the home directory (and its ancestors), `~/.config`.
fn blocked_location(real: &Path) -> Option<String> {
    if real == Path::new("/") {
        return Some("refusing to mount the filesystem root".into());
    }
    for prefix in SYSTEM_BLOCKED_PREFIXES {
        if real.starts_with(prefix) {
            return Some(format!("system location {prefix} is never mountable"));
        }
    }
    if let Some(home) = home_dir() {
        if home.starts_with(real) {
            return Some("refusing to mount the home directory or one of its ancestors".into());
        }
        let config = home.join(".config");
        if real.starts_with(&config) {
            return Some("~/.config is never mountable (holds Talon and tool credentials)".into());
        }
    }
    None
}

fn home_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let home = PathBuf::from(home);
    if !home.is_absolute() || home == Path::new("/") {
        return None;
    }
    Some(std::fs::canonicalize(&home).unwrap_or(home))
}

enum Pattern {
    /// Case-insensitive substring of a component / the whole path.
    Substring(String),
    /// Case-insensitive glob over each component.
    Glob(GlobMatcher),
}

fn compile_pattern(p: &str) -> Option<Pattern> {
    let p = p.trim();
    if p.is_empty() {
        return None;
    }
    if p.contains(['*', '?', '[', '{']) {
        match GlobBuilder::new(p)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
        {
            Ok(g) => Some(Pattern::Glob(g.compile_matcher())),
            Err(e) => {
                tracing::warn!(pattern = %p, error = %e, "invalid blocked glob; using substring match");
                Some(Pattern::Substring(p.to_lowercase()))
            }
        }
    } else {
        Some(Pattern::Substring(p.to_lowercase()))
    }
}

/// Returns the first blocked pattern matched by `real` (defaults, extras and
/// the allowlist's own patterns).
fn matches_blocked_pattern(real: &Path, extra: &[String]) -> Option<String> {
    let full = real.to_string_lossy().to_lowercase();
    let components: Vec<String> = real
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();

    let all = DEFAULT_BLOCKED_PATTERNS
        .iter()
        .copied()
        .chain(EXTRA_BLOCKED_GLOBS.iter().copied())
        .chain(extra.iter().map(String::as_str));

    for raw in all {
        let Some(pattern) = compile_pattern(raw) else {
            continue;
        };
        let hit = match &pattern {
            Pattern::Substring(s) => {
                components.iter().any(|c| c.contains(s.as_str())) || full.contains(s.as_str())
            }
            Pattern::Glob(g) => components.iter().any(|c| g.is_match(c)),
        };
        if hit {
            return Some(raw.to_string());
        }
    }
    None
}

fn find_allowed_root<'a>(real: &Path, roots: &'a [AllowedRoot]) -> Option<&'a AllowedRoot> {
    roots.iter().find(|root| {
        let expanded = expand_home(root.path.trim());
        if !expanded.is_absolute() {
            tracing::warn!(root = %root.path, "ignoring relative allowed root");
            return false;
        }
        let Ok(real_root) = std::fs::canonicalize(&expanded) else {
            return false;
        };
        if real_root == Path::new("/") {
            tracing::warn!(root = %root.path, "ignoring allowed root '/'");
            return false;
        }
        // Component-wise prefix check (`/a/b` does not contain `/a/bc`).
        real.starts_with(&real_root)
    })
}

/// Example allowlist JSON for `talon setup`.
pub fn allowlist_template() -> String {
    let template = MountAllowlist {
        allowed_roots: vec![
            AllowedRoot {
                path: "~/projects".into(),
                allow_read_write: true,
                description: Some("Development projects".into()),
            },
            AllowedRoot {
                path: "~/repos".into(),
                allow_read_write: true,
                description: Some("Git repositories".into()),
            },
            AllowedRoot {
                path: "~/Documents/work".into(),
                allow_read_write: false,
                description: Some("Work documents (read-only)".into()),
            },
        ],
        blocked_patterns: vec!["password".into(), "secret".into(), "token".into()],
        non_main_read_only: true,
    };
    serde_json::to_string_pretty(&template).unwrap_or_else(|_| TEMPLATE_FALLBACK.to_string())
}

const TEMPLATE_FALLBACK: &str = r#"{
  "allowedRoots": [],
  "blockedPatterns": [],
  "nonMainReadOnly": true
}"#;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    /// Creates `<tmp>/allowed/{project,secrets/.ssh,repo/.env,...}` and an
    /// allowlist rooted at `<tmp>/allowed`.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap().join("allowed");
        fs::create_dir_all(root.join("project/src")).unwrap();
        fs::create_dir_all(root.join("ro-only")).unwrap();
        fs::create_dir_all(root.join("home-ish/.ssh")).unwrap();
        fs::create_dir_all(root.join("home-ish/.SSH-backup")).unwrap();
        fs::create_dir_all(root.join("app/.env")).unwrap();
        fs::write(root.join("app/server.pem"), "x").unwrap();
        fs::write(root.join("app/notes.txt"), "x").unwrap();
        fs::create_dir_all(dir.path().join("outside")).unwrap();
        Fixture { _dir: dir, root }
    }

    fn allowlist(f: &Fixture) -> MountAllowlist {
        MountAllowlist {
            allowed_roots: vec![AllowedRoot {
                path: f.root.to_string_lossy().into_owned(),
                allow_read_write: true,
                description: None,
            }],
            blocked_patterns: vec!["password".into()],
            non_main_read_only: true,
        }
    }

    fn mount(host: &Path, cp: Option<&str>, readonly: bool) -> AdditionalMount {
        AdditionalMount {
            host_path: host.to_string_lossy().into_owned(),
            container_path: cp.map(str::to_string),
            readonly,
        }
    }

    fn reason(d: MountDecision) -> String {
        match d {
            MountDecision::Rejected { reason } => reason,
            MountDecision::Allowed(v) => panic!("unexpectedly allowed: {v:?}"),
        }
    }

    fn allowed(d: MountDecision) -> ValidatedMount {
        match d {
            MountDecision::Allowed(v) => v,
            MountDecision::Rejected { reason } => panic!("unexpectedly rejected: {reason}"),
        }
    }

    #[test]
    fn no_allowlist_rejects_everything() {
        let f = fixture();
        let v = MountValidator::from_allowlist(None);
        assert!(!v.is_configured());
        assert!(
            reason(v.validate(&mount(&f.root.join("project"), None, true), true))
                .contains("allowlist")
        );
    }

    #[test]
    fn missing_or_invalid_file_rejects_everything() {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        let missing = MountValidator::load(&dir.path().join("nope.json"));
        assert!(!missing.is_configured());
        let bad = dir.path().join("bad.json");
        fs::write(&bad, "{ not json").unwrap();
        assert!(!MountValidator::load(&bad).is_configured());
        let wrong_shape = dir.path().join("shape.json");
        fs::write(&wrong_shape, r#"{"allowedRoots": "nope"}"#).unwrap();
        let v = MountValidator::load(&wrong_shape);
        assert!(
            reason(v.validate(&mount(&f.root.join("project"), None, true), true))
                .contains("allowlist")
        );
    }

    #[test]
    fn loads_valid_file_with_defaults() {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mount-allowlist.json");
        fs::write(
            &p,
            format!(
                r#"{{"allowedRoots":[{{"path":{:?}}}]}}"#,
                f.root.to_string_lossy()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let v = MountValidator::load(&p);
        assert!(v.is_configured());
        let ok = allowed(v.validate(&mount(&f.root.join("project"), None, false), false));
        // nonMainReadOnly defaults to true
        assert!(ok.readonly);
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_allowlist_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mount-allowlist.json");
        fs::write(&p, r#"{"allowedRoots":[]}"#).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!MountValidator::load(&p).is_configured());
    }

    #[test]
    fn allows_path_under_root_with_basename_container_path() {
        let f = fixture();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        let ok = allowed(v.validate(&mount(&f.root.join("project"), None, true), true));
        assert_eq!(ok.container_path, "/workspace/extra/project");
        assert_eq!(ok.host_path, f.root.join("project"));
        assert!(ok.readonly);
    }

    #[test]
    fn explicit_container_path() {
        let f = fixture();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        let ok = allowed(v.validate(
            &mount(&f.root.join("project"), Some("code/main"), true),
            true,
        ));
        assert_eq!(ok.container_path, "/workspace/extra/code/main");
    }

    #[test]
    fn rejects_path_outside_roots() {
        let f = fixture();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        let outside = f.root.parent().unwrap().join("outside");
        assert!(
            reason(v.validate(&mount(&outside, None, true), true))
                .contains("not under any allowed root")
        );
        // sibling with common string prefix is not "under" the root
        let sib = f.root.parent().unwrap().join("allowed-evil");
        fs::create_dir_all(&sib).unwrap();
        assert!(
            reason(v.validate(&mount(&sib, None, true), true))
                .contains("not under any allowed root")
        );
    }

    #[test]
    fn rejects_nonexistent_and_relative_paths() {
        let f = fixture();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        assert!(
            reason(v.validate(&mount(&f.root.join("nope"), None, true), true))
                .contains("does not exist")
        );
        let rel = AdditionalMount {
            host_path: "allowed/project".into(),
            container_path: None,
            readonly: true,
        };
        assert!(reason(v.validate(&rel, true)).contains("absolute"));
        let tilde_user = AdditionalMount {
            host_path: "~root/x".into(),
            container_path: None,
            readonly: true,
        };
        assert!(reason(v.validate(&tilde_user, true)).contains("absolute"));
        let empty = AdditionalMount {
            host_path: "  ".into(),
            container_path: None,
            readonly: true,
        };
        assert!(reason(v.validate(&empty, true)).contains("empty"));
    }

    #[test]
    fn traversal_is_resolved_before_root_check() {
        let f = fixture();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        let sneaky = f.root.join("project/../../outside");
        assert!(
            reason(v.validate(&mount(&sneaky, Some("x"), true), true))
                .contains("not under any allowed root")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_resolved() {
        let f = fixture();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        let outside = f.root.parent().unwrap().join("outside");
        let link = f.root.join("link-out");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(
            reason(v.validate(&mount(&link, None, true), true))
                .contains("not under any allowed root")
        );
        // and a symlink pointing at a blocked dir inside the root
        let link2 = f.root.join("innocent");
        std::os::unix::fs::symlink(f.root.join("home-ish/.ssh"), &link2).unwrap();
        assert!(reason(v.validate(&mount(&link2, None, true), true)).contains(".ssh"));
    }

    #[test]
    fn default_blocked_patterns_apply_even_if_file_omits_them() {
        let f = fixture();
        let mut list = allowlist(&f);
        list.blocked_patterns.clear();
        let v = MountValidator::from_allowlist(Some(list));
        assert!(
            reason(v.validate(&mount(&f.root.join("home-ish/.ssh"), None, true), true))
                .contains(".ssh")
        );
        assert!(
            reason(v.validate(&mount(&f.root.join("app/.env"), None, true), true)).contains(".env")
        );
        assert!(
            reason(v.validate(&mount(&f.root.join("app/server.pem"), None, true), true))
                .contains("*.pem")
        );
        // case-insensitive
        assert!(
            reason(v.validate(
                &mount(&f.root.join("home-ish/.SSH-backup"), None, true),
                true
            ))
            .contains(".ssh")
        );
        // a plain file in an allowed dir is fine
        allowed(v.validate(&mount(&f.root.join("app/notes.txt"), None, true), true));
    }

    #[test]
    fn custom_blocked_patterns_apply() {
        let f = fixture();
        fs::create_dir_all(f.root.join("my-passwords")).unwrap();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        assert!(
            reason(v.validate(&mount(&f.root.join("my-passwords"), None, true), true))
                .contains("password")
        );
    }

    #[test]
    fn container_path_validation() {
        let f = fixture();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        let host = f.root.join("project");
        for bad in [
            "../escape",
            "a/../../b",
            "/abs",
            "repo:rw",
            "a,readonly=false",
            "a\nb",
            "a\\b",
            "a//b",
            "./a",
            "a/./b",
            " a",
            "a ",
            "a/ b",
            "$(id)",
            "a;b",
        ] {
            assert!(
                reason(v.validate(&mount(&host, Some(bad), true), true)).contains("container path"),
                "{bad:?}"
            );
        }
        let long = "a".repeat(300);
        assert!(
            reason(v.validate(&mount(&host, Some(&long), true), true)).contains("container path")
        );
        // empty container path falls back to the basename
        let ok = allowed(v.validate(&mount(&host, Some(""), true), true));
        assert_eq!(ok.container_path, "/workspace/extra/project");
        allowed(v.validate(&mount(&host, Some("My Work"), true), true));
    }

    #[test]
    fn host_path_with_mount_spec_metacharacters_is_rejected() {
        let f = fixture();
        let weird = f.root.join("a:b");
        fs::create_dir_all(&weird).unwrap();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        assert!(reason(v.validate(&mount(&weird, Some("ab"), true), true)).contains("unsafe"));
        let comma = f.root.join("a,b");
        fs::create_dir_all(&comma).unwrap();
        assert!(reason(v.validate(&mount(&comma, Some("ab"), true), true)).contains("unsafe"));
        let ctrl = AdditionalMount {
            host_path: format!("{}/pro\u{7}ject", f.root.display()),
            container_path: None,
            readonly: true,
        };
        assert!(reason(v.validate(&ctrl, true)).contains("control"));
    }

    #[test]
    fn readonly_semantics() {
        let f = fixture();
        let mut list = allowlist(&f);
        list.allowed_roots.push(AllowedRoot {
            path: f.root.join("ro-only").to_string_lossy().into_owned(),
            allow_read_write: false,
            description: Some("ro".into()),
        });
        // put the ro root first so it wins for its subtree
        list.allowed_roots.reverse();
        let v = MountValidator::from_allowlist(Some(list.clone()));
        let project = f.root.join("project");
        // main + rw root + rw requested => rw
        assert!(!allowed(v.validate(&mount(&project, None, false), true)).readonly);
        // non-main forced ro
        assert!(allowed(v.validate(&mount(&project, None, false), false)).readonly);
        // ro requested stays ro
        assert!(allowed(v.validate(&mount(&project, None, true), true)).readonly);
        // root without allowReadWrite forces ro even for main
        assert!(allowed(v.validate(&mount(&f.root.join("ro-only"), None, false), true)).readonly);
        // nonMainReadOnly=false lets non-main get rw on rw roots
        list.non_main_read_only = false;
        let v = MountValidator::from_allowlist(Some(list));
        assert!(!allowed(v.validate(&mount(&project, None, false), false)).readonly);
    }

    #[test]
    fn root_slash_and_relative_roots_are_ignored() {
        let f = fixture();
        let list = MountAllowlist {
            allowed_roots: vec![
                AllowedRoot {
                    path: "/".into(),
                    allow_read_write: true,
                    description: None,
                },
                AllowedRoot {
                    path: "relative/root".into(),
                    allow_read_write: true,
                    description: None,
                },
            ],
            blocked_patterns: vec![],
            non_main_read_only: false,
        };
        let v = MountValidator::from_allowlist(Some(list));
        assert!(
            reason(v.validate(&mount(&f.root.join("project"), None, true), true))
                .contains("not under any allowed root")
        );
    }

    #[cfg(unix)]
    #[test]
    fn system_locations_and_sockets_are_never_mountable() {
        let list = MountAllowlist {
            allowed_roots: vec![AllowedRoot {
                path: "/".into(),
                allow_read_write: true,
                description: None,
            }],
            blocked_patterns: vec![],
            non_main_read_only: false,
        };
        let v = MountValidator::from_allowlist(Some(list));
        for p in ["/", "/etc", "/proc/self", "/dev", "/sys"] {
            let m = AdditionalMount {
                host_path: p.into(),
                container_path: Some("x".into()),
                readonly: true,
            };
            assert!(
                !matches!(v.validate(&m, true), MountDecision::Allowed(_)),
                "{p}"
            );
        }
        // a unix socket is not a dir/file
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let list = MountAllowlist {
            allowed_roots: vec![AllowedRoot {
                path: dir.path().to_string_lossy().into_owned(),
                allow_read_write: true,
                description: None,
            }],
            blocked_patterns: vec![],
            non_main_read_only: false,
        };
        let v = MountValidator::from_allowlist(Some(list));
        let m = AdditionalMount {
            host_path: sock.to_string_lossy().into_owned(),
            container_path: Some("s".into()),
            readonly: true,
        };
        assert!(!matches!(v.validate(&m, true), MountDecision::Allowed(_)));
    }

    #[test]
    fn validate_all_drops_rejected_and_duplicates() {
        let f = fixture();
        let v = MountValidator::from_allowlist(Some(allowlist(&f)));
        let mounts = vec![
            mount(&f.root.join("project"), None, true),
            mount(&f.root.join("home-ish/.ssh"), None, true),
            mount(&f.root.join("ro-only"), Some("project"), true),
            mount(&f.root.join("ro-only"), None, true),
        ];
        let out = v.validate_all(&mounts, "g", true);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].container_path, "/workspace/extra/project");
        assert_eq!(out[1].container_path, "/workspace/extra/ro-only");
    }

    #[test]
    fn template_is_valid_allowlist_json() {
        let t = allowlist_template();
        let parsed: MountAllowlist = serde_json::from_str(&t).unwrap();
        assert_eq!(parsed.allowed_roots.len(), 3);
        assert!(parsed.non_main_read_only);
        assert!(t.contains("\"allowedRoots\""));
        assert!(t.contains("\"allowReadWrite\": true"));
        assert!(parsed.blocked_patterns.contains(&"token".to_string()));
    }

    #[test]
    fn pattern_matching_helpers() {
        let p = Path::new("/srv/data/Prod.KEY");
        assert_eq!(matches_blocked_pattern(p, &[]).as_deref(), Some("*.key"));
        let p = Path::new("/srv/data/report.txt");
        assert_eq!(matches_blocked_pattern(p, &[]), None);
        assert_eq!(
            matches_blocked_pattern(p, &["  ".into(), "[".into()]).as_deref(),
            None
        );
        let p = Path::new("/srv/aws-credentials-backup");
        assert_eq!(
            matches_blocked_pattern(p, &[]).as_deref(),
            Some("credentials")
        );
        let p = Path::new("/srv/run/docker.sock");
        assert_eq!(matches_blocked_pattern(p, &[]).as_deref(), Some("*.sock"));
    }
}
