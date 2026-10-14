//! Step `timezone` (port of `setup/timezone.ts`): resolve the operator's
//! IANA timezone and persist it as `TZ` in `.env`.
//!
//! Precedence: `--tz` > `.env` `TZ` > process `TZ` > host autodetection.
//! Emits `NEEDS_USER_INPUT=true` (and `STATUS: needs_input`) when nothing
//! valid was found, so the skill can ask and re-run with `--tz`.

use anyhow::Context as _;
use talon_core::time::is_valid_timezone;

use super::StepArgs;
use crate::context::SetupContext;
use crate::fsutil::{read_env_value, upsert_env_line};
use crate::status::{StatusBlock, StepOutcome};

/// Run the step.
///
/// # Errors
/// Failing to write `.env`.
pub async fn run(args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    let env_path = ctx.env_path();
    let env_file_tz = read_env_value(&env_path, "TZ");
    let user_tz = args.value("--tz").map(str::trim).filter(|s| !s.is_empty());

    let resolved = [
        user_tz,
        env_file_tz.as_deref(),
        ctx.env_tz.as_deref(),
        ctx.system_tz.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|tz| is_valid_timezone(tz))
    .map(str::to_string);

    let needs_user_input = resolved.is_none();
    if let Some(tz) = &resolved {
        if Some(tz) != env_file_tz.as_ref() {
            upsert_env_line(&env_path, "TZ", tz)
                .with_context(|| format!("writing TZ to {}", env_path.display()))?;
            tracing::info!(timezone = %tz, "Set TZ in .env");
        }
    }

    let block = StatusBlock::new("TIMEZONE")
        .field("SYSTEM_TZ", ctx.system_tz.as_deref().unwrap_or("unknown"))
        .field("ENV_TZ", ctx.env_tz.as_deref().unwrap_or("unset"))
        .field("ENV_FILE_TZ", env_file_tz.as_deref().unwrap_or("unset"))
        .field("RESOLVED_TZ", resolved.as_deref().unwrap_or("none"))
        .field("NEEDS_USER_INPUT", needs_user_input)
        .field(
            "STATUS",
            if needs_user_input {
                "needs_input"
            } else {
                "success"
            },
        );
    Ok(StepOutcome::ok(block))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runner::mock::MockRunner;

    fn ctx(dir: &std::path::Path) -> SetupContext {
        SetupContext::new(dir, dir, Arc::new(MockRunner::new()))
    }

    #[tokio::test]
    async fn user_flag_wins_and_is_written() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "A=1\nTZ=UTC\n").unwrap();
        let mut c = ctx(dir.path());
        c.system_tz = Some("Asia/Tokyo".into());
        let out = run(&StepArgs::new(["--tz", "Europe/Berlin"]), &c)
            .await
            .unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("RESOLVED_TZ"), Some("Europe/Berlin"));
        assert_eq!(b.get("ENV_FILE_TZ"), Some("UTC"));
        assert_eq!(b.status(), Some("success"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".env")).unwrap(),
            "A=1\nTZ=Europe/Berlin\n"
        );
    }

    #[tokio::test]
    async fn invalid_flag_falls_through_to_env_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "TZ=\"America/New_York\"\n").unwrap();
        let out = run(&StepArgs::new(["--tz", "IST-2"]), &ctx(dir.path()))
            .await
            .unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("RESOLVED_TZ"), Some("America/New_York"));
        // Already persisted: file untouched.
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".env")).unwrap(),
            "TZ=\"America/New_York\"\n"
        );
    }

    #[tokio::test]
    async fn process_env_then_system() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ctx(dir.path());
        c.env_tz = Some("XYZ+3".into());
        c.system_tz = Some("Asia/Jerusalem".into());
        let out = run(&StepArgs::default(), &c).await.unwrap();
        assert_eq!(
            out.block.unwrap().get("RESOLVED_TZ"),
            Some("Asia/Jerusalem")
        );
        assert_eq!(
            read_env_value(&c.env_path(), "TZ").as_deref(),
            Some("Asia/Jerusalem")
        );
    }

    #[tokio::test]
    async fn nothing_valid_needs_input() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ctx(dir.path());
        c.env_tz = Some("IST-2".into());
        let out = run(&StepArgs::default(), &c).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("NEEDS_USER_INPUT"), Some("true"));
        assert_eq!(b.status(), Some("needs_input"));
        assert_eq!(b.get("RESOLVED_TZ"), Some("none"));
        assert_eq!(b.get("SYSTEM_TZ"), Some("unknown"));
        assert!(!dir.path().join(".env").exists());
        assert_eq!(out.exit_code, 0);
    }
}
