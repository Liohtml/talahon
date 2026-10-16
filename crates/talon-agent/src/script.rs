//! Scheduled-task pre-flight scripts.
//!
//! The script runs with `bash -c` in the group folder through the `bash`
//! tool's runner (scrubbed environment, own process group, killed on
//! timeout) with a 30 s budget. Its **last non-empty stdout line** must be
//! `{"wakeAgent": bool, "data"?: any}`. A script that fails, times out or
//! prints no such line is an error: the run is reported as failed (and
//! retried by the scheduler), never as a run that decided not to wake.

use std::path::Path;
use std::time::Duration;

use talon_core::protocol::ScriptResult;
use talon_tools::{BashOptions, BashTool, Termination};
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

/// Run `script` in `cwd`. `Err` says why the script failed (could not
/// start, non-zero exit, timeout, no `{"wakeAgent": ...}` line).
pub async fn run_task_script(
    script: &str,
    cwd: &Path,
    cancel: &CancellationToken,
) -> Result<ScriptResult, String> {
    let tool = BashTool::new(BashOptions {
        max_output_bytes: SCRIPT_MAX_OUTPUT_BYTES,
        ..BashOptions::default()
    });
    let result = match tool.run(script, cwd, SCRIPT_TIMEOUT, cancel).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "cannot start the task script");
            return Err(format!("cannot start: {e}"));
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
        return Err(match (result.termination, result.exit_code) {
            (Termination::TimedOut, _) => {
                format!("timed out after {} s", SCRIPT_TIMEOUT.as_secs())
            }
            (Termination::Cancelled, _) => "cancelled".to_string(),
            (Termination::Exited, Some(code)) => format!("exited with status {code}"),
            (Termination::Exited, None) => "killed by a signal".to_string(),
        });
    }
    parse_script_output(&result.stdout)
        .ok_or_else(|| "printed no {\"wakeAgent\": true|false} line".to_string())
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
        assert_eq!(
            run_task_script("exit 3", dir.path(), &cancel).await,
            Err("exited with status 3".to_string())
        );
        let err = run_task_script("echo nothing-useful", dir.path(), &cancel)
            .await
            .unwrap_err();
        assert!(err.contains("wakeAgent"), "{err}");
        let quiet = run_task_script("echo '{\"wakeAgent\": false}'", dir.path(), &cancel)
            .await
            .unwrap();
        assert!(!quiet.wake_agent);
    }
}
