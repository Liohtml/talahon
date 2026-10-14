//! Step `mounts` (port of `setup/mounts.ts`): write the mount allowlist
//! (`~/.config/talon/mount-allowlist.json`, outside the project root and
//! never mounted into a container).
//!
//! Sources, in order: `--empty` (no extra mounts), `--template` (the
//! commented example from `talon_security::mounts::allowlist_template`),
//! `--json '<json>'`, otherwise JSON on stdin. An existing file is kept
//! unless `--force` is given.
//!
//! Hardening: the JSON must deserialize as a `MountAllowlist` (the
//! TypeScript step accepted any JSON), roots must be absolute or `~/`
//! paths, and the file is written atomically with mode `0600` in a `0700`
//! directory. Extra descriptive keys are preserved.

use anyhow::Context as _;
use talon_core::types::MountAllowlist;

use super::StepArgs;
use crate::context::{SETUP_LOG, SetupContext};
use crate::fsutil::write_atomic;
use crate::status::{StatusBlock, StepOutcome};

/// Maximum accepted allowlist input size.
pub const MAX_ALLOWLIST_BYTES: usize = 256 * 1024;

/// Parse and validate allowlist JSON.
///
/// # Errors
/// `"invalid_json"` for unparsable input, `"invalid_allowlist"` for JSON
/// that is not a valid allowlist.
pub fn parse_allowlist(json: &str) -> Result<MountAllowlist, &'static str> {
    parse_allowlist_value(json).map(|(_, a)| a)
}

/// [`parse_allowlist`], also returning the raw JSON value (written back
/// as-is, so descriptive extra keys survive — like the TypeScript step).
fn parse_allowlist_value(json: &str) -> Result<(serde_json::Value, MountAllowlist), &'static str> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|_| "invalid_json")?;
    let allowlist: MountAllowlist =
        serde_json::from_value(value.clone()).map_err(|_| "invalid_allowlist")?;
    let root_ok = |p: &str| {
        let p = p.trim();
        !p.is_empty()
            && !p.contains('\0')
            && (p.starts_with('/') || p == "~" || p.starts_with("~/"))
    };
    if !allowlist.allowed_roots.iter().all(|r| root_ok(&r.path)) {
        return Err("invalid_allowlist");
    }
    Ok((value, allowlist))
}

fn block(path: &str) -> StatusBlock {
    StatusBlock::new("CONFIGURE_MOUNTS").field("PATH", path)
}

fn failed(path: &str, error: &str) -> StepOutcome {
    StepOutcome::with_code(
        block(path)
            .field("ALLOWED_ROOTS", 0)
            .field("NON_MAIN_READ_ONLY", "unknown")
            .field("STATUS", "failed")
            .field("ERROR", error)
            .field("LOG", SETUP_LOG),
        4,
    )
}

/// Run the step.
///
/// # Errors
/// Filesystem failures writing the allowlist.
pub async fn run(args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    let path = ctx.mount_allowlist_path();
    let path_str = path.display().to_string();
    if ctx.platform.is_root() {
        tracing::warn!(
            "Running as root — mount allowlist will be written to root's home directory"
        );
    }

    if path.exists() && !args.flag("--force") {
        tracing::info!(path = %path_str, "Mount allowlist already exists — skipping (use --force to overwrite)");
        return Ok(StepOutcome::ok(
            block(&path_str)
                .field("ALLOWED_ROOTS", 0)
                .field("NON_MAIN_READ_ONLY", "unknown")
                .field("STATUS", "skipped")
                .field("LOG", SETUP_LOG),
        ));
    }

    let (value, allowlist) = if args.flag("--empty") {
        let empty = MountAllowlist {
            allowed_roots: Vec::new(),
            blocked_patterns: Vec::new(),
            non_main_read_only: true,
        };
        (serde_json::to_value(&empty)?, empty)
    } else {
        let input = if args.flag("--template") {
            // Guard against a panicking implementation: report, don't abort.
            match std::panic::catch_unwind(talon_security::mounts::allowlist_template) {
                Ok(t) => t,
                Err(_) => return Ok(failed(&path_str, "template_unavailable")),
            }
        } else if let Some(json) = args.value("--json") {
            json.to_string()
        } else {
            tracing::info!("Reading mount allowlist from stdin");
            match ctx.read_stdin(MAX_ALLOWLIST_BYTES).await {
                Ok(s) => s,
                Err(_) => return Ok(failed(&path_str, "invalid_json")),
            }
        };
        if input.len() > MAX_ALLOWLIST_BYTES {
            return Ok(failed(&path_str, "invalid_json"));
        }
        match parse_allowlist_value(&input) {
            Ok(parsed) => parsed,
            Err(code) => {
                tracing::error!(error = code, "Invalid mount allowlist");
                return Ok(failed(&path_str, code));
            }
        }
    };

    let dir = path.parent().context("allowlist path has no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))?;
    }
    let mut json = serde_json::to_string_pretty(&value)?;
    json.push('\n');
    write_atomic(&path, json.as_bytes(), Some(0o600))
        .with_context(|| format!("writing {path_str}"))?;
    tracing::info!(path = %path_str, roots = allowlist.allowed_roots.len(), "Allowlist configured");

    Ok(StepOutcome::ok(
        block(&path_str)
            .field("ALLOWED_ROOTS", allowlist.allowed_roots.len())
            .field("NON_MAIN_READ_ONLY", allowlist.non_main_read_only)
            .field("STATUS", "success")
            .field("LOG", SETUP_LOG),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::context::StdinSource;
    use crate::runner::mock::MockRunner;

    fn ctx(dir: &std::path::Path) -> SetupContext {
        SetupContext::new(
            &dir.join("proj"),
            &dir.join("home"),
            Arc::new(MockRunner::new()),
        )
    }

    fn read_allowlist(c: &SetupContext) -> MountAllowlist {
        serde_json::from_str(&std::fs::read_to_string(c.mount_allowlist_path()).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn empty_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let out = run(&StepArgs::new(["--empty"]), &c).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.status(), Some("success"));
        assert_eq!(b.get("ALLOWED_ROOTS"), Some("0"));
        assert_eq!(b.get("NON_MAIN_READ_ONLY"), Some("true"));
        let a = read_allowlist(&c);
        assert!(a.allowed_roots.is_empty());
        assert!(a.non_main_read_only);
        assert_eq!(
            crate::fsutil::file_mode(&c.mount_allowlist_path()),
            Some(0o600)
        );
        assert_eq!(crate::fsutil::file_mode(&c.config_dir), Some(0o700));
    }

    #[tokio::test]
    async fn json_flag_and_skip_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let json = r#"{"allowedRoots":[{"path":"~/projects","allowReadWrite":true},{"path":"/srv/logs"}],"blockedPatterns":["password"],"nonMainReadOnly":false}"#;
        let out = run(&StepArgs::new(["--json", json]), &c).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("ALLOWED_ROOTS"), Some("2"));
        assert_eq!(b.get("NON_MAIN_READ_ONLY"), Some("false"));
        let a = read_allowlist(&c);
        assert!(a.allowed_roots[0].allow_read_write);
        assert_eq!(a.blocked_patterns, vec!["password"]);

        let out = run(&StepArgs::new(["--empty"]), &c).await.unwrap();
        assert_eq!(out.block.unwrap().status(), Some("skipped"));
        assert_eq!(read_allowlist(&c).allowed_roots.len(), 2);

        let out = run(&StepArgs::new(["--empty", "--force"]), &c)
            .await
            .unwrap();
        assert_eq!(out.block.unwrap().status(), Some("success"));
        assert!(read_allowlist(&c).allowed_roots.is_empty());
    }

    #[tokio::test]
    async fn stdin_input() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ctx(dir.path());
        c.stdin = StdinSource::Text(r#"{"allowedRoots":[{"path":"/data"}]}"#.into());
        let out = run(&StepArgs::default(), &c).await.unwrap();
        assert_eq!(out.block.unwrap().get("ALLOWED_ROOTS"), Some("1"));
        // Defaults filled in.
        assert!(read_allowlist(&c).non_main_read_only);
    }

    #[tokio::test]
    async fn invalid_inputs_exit_4() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let out = run(&StepArgs::new(["--json", "{not json"]), &c)
            .await
            .unwrap();
        assert_eq!(out.exit_code, 4);
        assert_eq!(out.block.unwrap().get("ERROR"), Some("invalid_json"));
        let out = run(&StepArgs::new(["--json", r#"{"allowedRoots":"nope"}"#]), &c)
            .await
            .unwrap();
        assert_eq!(out.block.unwrap().get("ERROR"), Some("invalid_allowlist"));
        let out = run(
            &StepArgs::new(["--json", r#"{"allowedRoots":[{"path":"relative/dir"}]}"#]),
            &c,
        )
        .await
        .unwrap();
        assert_eq!(out.block.unwrap().get("ERROR"), Some("invalid_allowlist"));
        assert!(!c.mount_allowlist_path().exists());
    }

    #[test]
    fn parse_allowlist_rules() {
        assert!(parse_allowlist(r#"{"allowedRoots":[]}"#).is_ok());
        assert!(parse_allowlist(r#"{"allowedRoots":[{"path":"~"}]}"#).is_ok());
        assert_eq!(parse_allowlist("[]").unwrap_err(), "invalid_allowlist");
        assert_eq!(
            parse_allowlist(r#"{"allowedRoots":[{"path":""}]}"#).unwrap_err(),
            "invalid_allowlist"
        );
    }

    /// Needs `talon_security::mounts::allowlist_template` (agent A07).
    #[tokio::test]
    async fn template_flag_writes_a_valid_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let out = run(&StepArgs::new(["--template"]), &c).await.unwrap();
        assert_eq!(
            out.block.unwrap().status(),
            Some("success"),
            "template must be a valid allowlist"
        );
        assert!(c.mount_allowlist_path().exists());
    }
}
