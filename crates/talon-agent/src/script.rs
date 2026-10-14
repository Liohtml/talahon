//! Scheduled-task pre-flight scripts.
//!
//! The script runs with `bash -c` in the group folder through the `bash`
//! tool's runner (scrubbed environment, own process group, killed on
//! timeout) with a 30 s budget. Its **last non-empty stdout line** must be
//! `{"wakeAgent": bool, "data"?: any}`. A failing script, missing output or
//! invalid JSON means "don't wake" (TypeScript parity).

use std::path::Path;
use std::time::Duration;

use talon_core::protocol::ScriptResult;
use talon_tools::{BashOptions, BashTool};
use tokio_util::sync::CancellationToken;

/// Script time budget.
pub const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Output retained from the script (stdout and stderr each).
const SCRIPT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Parse the script result from stdout (last non-empty line).
pub fn parse_script_output(stdout: &str) -> Option<ScriptResult> {
    let last = stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())?;
    match serde_json::from_str::<ScriptResult>(last) {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::warn!(error = %e, "task script output is not a valid {{\"wakeAgent\": bool}} line");
            None
        }
    }
}

/// Run `script` in `cwd`. `None` = don't wake the agent (error, timeout,
/// bad output).
pub async fn run_task_script(
    script: &str,
    cwd: &Path,
    cancel: &CancellationToken,
) -> Option<ScriptResult> {
    let tool = BashTool::new(BashOptions {
        max_output_bytes: SCRIPT_MAX_OUTPUT_BYTES,
        ..BashOptions::default()
    });
    let result = match tool.run(script, cwd, SCRIPT_TIMEOUT, cancel).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "cannot start the task script");
            return None;
        }
    };
    if !result.stderr.trim().is_empty() {
        let tail: String = result.stderr.chars().take(500).collect();
        tracing::info!(stderr = %crate::logging::redact(&tail), "task script stderr");
    }
    if !result.success() {
        tracing::warn!(
            exit_code = ?result.exit_code,
            termination = ?result.termination,
            "task script failed"
        );
        return None;
    }
    parse_script_output(&result.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_last_line() {
        let r = parse_script_output("noise\n{\"wakeAgent\":true,\"data\":{\"n\":2}}\n\n").unwrap();
        assert!(r.wake_agent);
        assert_eq!(r.data.unwrap()["n"], 2);
        assert!(parse_script_output("").is_none());
        assert!(parse_script_output("{\"wakeAgent\":\"yes\"}").is_none());
        assert!(parse_script_output("not json").is_none());
        assert!(
            !parse_script_output("{\"wakeAgent\":false}")
                .unwrap()
                .wake_agent
        );
    }

    #[tokio::test]
    async fn runs_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = CancellationToken::new();
        let r = run_task_script(
            "echo progress >&2; echo '{\"wakeAgent\": true, \"data\": [1]}'",
            dir.path(),
            &cancel,
        )
        .await
        .unwrap();
        assert!(r.wake_agent);
        assert!(
            run_task_script("exit 3", dir.path(), &cancel)
                .await
                .is_none()
        );
        assert!(
            run_task_script("echo nothing-useful", dir.path(), &cancel)
                .await
                .is_none()
        );
    }
}
