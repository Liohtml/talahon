//! `bash` — run a shell command in a fresh, scrubbed, killable process group.
//!
//! - `bash -c <command>` with `stdin` closed, in `ToolContext.cwd` (or a
//!   guarded `cwd` argument).
//! - **Scrubbed environment**: only allowlisted variables (`PATH`, `HOME`,
//!   `LANG`, `LC_*`, `TZ`, `TERM`, `USER` by default) are inherited, so the
//!   runtime's own environment never leaks into commands.
//! - The child leads its own process group (`setpgid(0, 0)` via
//!   `Command::process_group`). On timeout or cancellation the whole group gets
//!   `SIGTERM`, then `SIGKILL` after a grace period; after a normal exit any
//!   leftover background jobs in the group are killed too. Signals are sent
//!   with the shell's `kill` builtin, so no `unsafe` and no extra binary.
//! - stdout and stderr are read concurrently into bounded head/tail buffers.

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::json;
use talon_core::tool::{Tool, ToolContext, ToolOutput, ToolSpec};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::args::Args;
use crate::guard::{Access, PathGuard};
use crate::output::HeadTail;

/// Tool name.
pub const NAME: &str = "bash";

/// `PATH` used when the runtime has none.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// How long to wait for the output pipes to close after the process group
/// is gone (a process that escaped the group with `setsid` may hold them).
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum accepted command length.
const MAX_COMMAND_BYTES: usize = 100_000;

/// Configuration of the [`BashTool`].
#[derive(Debug, Clone)]
pub struct BashOptions {
    /// Shell binary, invoked as `<shell> -c <command>`. Default `bash`.
    pub shell: PathBuf,
    /// Timeout when the model does not pass one. Default 120 s.
    pub default_timeout: Duration,
    /// Upper bound for a model-requested timeout. Default 600 s.
    pub max_timeout: Duration,
    /// Retained bytes per stream (stdout, stderr). Default 30 000.
    pub max_output_bytes: usize,
    /// Inherited environment variable names; a trailing `*` is a prefix match.
    pub env_allowlist: Vec<String>,
    /// Extra variables set for every command (non-secret, e.g. `PAGER=cat`).
    pub extra_env: Vec<(String, String)>,
    /// Time between `SIGTERM` and `SIGKILL` on timeout/cancel. Default 2 s.
    pub kill_grace: Duration,
}

impl Default for BashOptions {
    fn default() -> Self {
        Self {
            shell: PathBuf::from("bash"),
            default_timeout: Duration::from_secs(120),
            max_timeout: Duration::from_secs(600),
            max_output_bytes: 30_000,
            env_allowlist: ["PATH", "HOME", "LANG", "LC_*", "TZ", "TERM", "USER"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            extra_env: vec![
                ("PAGER".to_string(), "cat".to_string()),
                ("GIT_PAGER".to_string(), "cat".to_string()),
            ],
            kill_grace: Duration::from_secs(2),
        }
    }
}

/// Filter the current process environment through `allowlist`.
pub fn scrubbed_env(allowlist: &[String]) -> Vec<(OsString, OsString)> {
    let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| {
            let Some(k) = k.to_str() else {
                return false;
            };
            allowlist.iter().any(|a| match a.strip_suffix('*') {
                Some(prefix) => k.starts_with(prefix),
                None => k == a,
            })
        })
        .collect();
    if !vars.iter().any(|(k, _)| k == "PATH") {
        vars.push((OsString::from("PATH"), OsString::from(DEFAULT_PATH)));
    }
    vars
}

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// The shell exited on its own.
    Exited,
    /// The timeout elapsed; the process group was killed.
    TimedOut,
    /// The context's cancellation token fired; the process group was killed.
    Cancelled,
}

/// Outcome of [`BashTool::run`].
#[derive(Debug, Clone)]
pub struct BashResult {
    /// Captured stdout (head/tail truncated).
    pub stdout: String,
    /// Captured stderr (head/tail truncated).
    pub stderr: String,
    /// Exit code, when the shell exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal, when killed by one.
    pub signal: Option<i32>,
    /// Why the command ended.
    pub termination: Termination,
    /// Wall-clock duration.
    pub duration: Duration,
    /// The timeout that applied.
    pub timeout: Duration,
}

impl BashResult {
    /// Exited normally with status 0.
    pub fn success(&self) -> bool {
        self.termination == Termination::Exited && self.exit_code == Some(0)
    }

    /// Render for the model: stdout, `[stderr]` section, status line.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let out = self.stdout.trim_end_matches('\n');
        let err = self.stderr.trim_end_matches('\n');
        if !out.is_empty() {
            s.push_str(out);
            s.push('\n');
        }
        if !err.is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str("[stderr]\n");
            s.push_str(err);
            s.push('\n');
        }
        if s.is_empty() {
            s.push_str("(no output)\n");
        }
        let status = match self.termination {
            Termination::TimedOut => format!(
                "[timed out after {}s; the process group was killed]",
                self.timeout.as_secs()
            ),
            Termination::Cancelled => "[cancelled; the process group was killed]".to_string(),
            Termination::Exited => match (self.exit_code, self.signal) {
                (Some(c), _) => format!("[exit code: {c}]"),
                (None, Some(sig)) => format!("[terminated by signal {sig}]"),
                (None, None) => "[exit status unknown]".to_string(),
            },
        };
        s.push_str(&status);
        s
    }
}

/// Kills the process group if the run future is dropped mid-flight.
struct GroupKillGuard {
    pgid: Option<u32>,
    shell: PathBuf,
}

impl Drop for GroupKillGuard {
    fn drop(&mut self) {
        if let Some(pgid) = self.pgid.take() {
            let _ = std::process::Command::new(&self.shell)
                .arg("-c")
                .arg(kill_script("KILL", pgid))
                .env_clear()
                .env("PATH", DEFAULT_PATH)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn kill_script(sig: &str, pgid: u32) -> String {
    format!("kill -s {sig} -- -{pgid} 2>/dev/null; exit 0")
}

async fn signal_group(shell: &Path, pgid: u32, sig: &str) {
    let r = tokio::process::Command::new(shell)
        .arg("-c")
        .arg(kill_script(sig, pgid))
        .env_clear()
        .env("PATH", DEFAULT_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    if let Err(e) = r {
        tracing::warn!(pgid, sig, error = %e, "failed to signal process group");
    }
}

fn spawn_reader<R>(reader: Option<R>, buf: Arc<Mutex<HeadTail>>) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let Some(mut reader) = reader else {
            return;
        };
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            match reader.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut b) = buf.lock() {
                        b.push(&chunk[..n]);
                    }
                }
            }
        }
    })
}

fn take_rendered(buf: &Arc<Mutex<HeadTail>>) -> String {
    buf.lock().map(|b| b.render()).unwrap_or_default()
}

/// The `bash` tool.
#[derive(Debug, Clone, Default)]
pub struct BashTool {
    opts: BashOptions,
}

impl BashTool {
    /// New tool with the given options.
    pub fn new(opts: BashOptions) -> Self {
        Self { opts }
    }

    /// The configured options.
    pub fn options(&self) -> &BashOptions {
        &self.opts
    }

    /// Run `command` in `cwd` with the scrubbed environment. Also usable by
    /// the agent runtime for scheduled-task pre-flight scripts.
    pub async fn run(
        &self,
        command: &str,
        cwd: &Path,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> std::io::Result<BashResult> {
        let started = Instant::now();
        let mut cmd = tokio::process::Command::new(&self.opts.shell);
        cmd.arg("-c")
            .arg(command)
            .current_dir(cwd)
            .env_clear()
            .envs(scrubbed_env(&self.opts.env_allowlist))
            .envs(
                self.opts
                    .extra_env
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str())),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = cmd.spawn()?;
        let pgid = child.id();
        let mut guard = GroupKillGuard {
            pgid,
            shell: self.opts.shell.clone(),
        };

        let out_buf = Arc::new(Mutex::new(HeadTail::new(self.opts.max_output_bytes)));
        let err_buf = Arc::new(Mutex::new(HeadTail::new(self.opts.max_output_bytes)));
        let out_task = spawn_reader(child.stdout.take(), out_buf.clone());
        let err_task = spawn_reader(child.stderr.take(), err_buf.clone());

        let mut termination = Termination::Exited;
        let waited = tokio::select! {
            s = child.wait() => Some(s),
            _ = tokio::time::sleep(timeout) => {
                termination = Termination::TimedOut;
                None
            }
            _ = cancel.cancelled() => {
                termination = Termination::Cancelled;
                None
            }
        };
        let status = match waited {
            Some(s) => s.ok(),
            None => {
                if let Some(pg) = pgid {
                    signal_group(&self.opts.shell, pg, "TERM").await;
                }
                match tokio::time::timeout(self.opts.kill_grace, child.wait()).await {
                    Ok(Ok(s)) => Some(s),
                    _ => {
                        if let Some(pg) = pgid {
                            signal_group(&self.opts.shell, pg, "KILL").await;
                        }
                        let _ = child.start_kill();
                        tokio::time::timeout(Duration::from_secs(5), child.wait())
                            .await
                            .ok()
                            .and_then(Result::ok)
                    }
                }
            }
        };
        // Background jobs left in the group must not outlive the call.
        if let Some(pg) = pgid {
            signal_group(&self.opts.shell, pg, "KILL").await;
        }
        guard.pgid = None;

        let aborts = [out_task.abort_handle(), err_task.abort_handle()];
        let drain = async {
            let _ = out_task.await;
            let _ = err_task.await;
        };
        if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
            tracing::debug!("output pipes still open after process group exit; abandoning");
            for a in aborts {
                a.abort();
            }
        }

        Ok(BashResult {
            stdout: take_rendered(&out_buf),
            stderr: take_rendered(&err_buf),
            exit_code: status.and_then(|s| s.code()),
            signal: status.and_then(|s| s.signal()),
            termination,
            duration: started.elapsed(),
            timeout,
        })
    }
}

#[async_trait]
impl Tool for BashTool {
    fn spec(&self) -> ToolSpec {
        let default_s = self.opts.default_timeout.as_secs();
        let max_s = self.opts.max_timeout.as_secs().max(1);
        ToolSpec {
            name: NAME.to_string(),
            description: format!(
                "Run a shell command with `bash -c` and return its stdout, stderr and exit code.\n\
                 \n\
                 - Runs in the group workspace (the current working directory) unless `cwd` is given. \
                 Every call starts a fresh shell: `cd`, variables and functions do NOT persist between \
                 calls, so chain dependent steps in one command with `&&`.\n\
                 - The environment is minimal (PATH, HOME, LANG, LC_*, TZ, TERM, USER). API keys and \
                 secrets are not available to commands; do not try to find them.\n\
                 - Timeout: default {default_s} s, maximum {max_s} s (`timeout_secs`). On timeout the \
                 whole process tree is killed. Background jobs (`cmd &`) are killed when the command \
                 returns, so do not start servers or daemons.\n\
                 - stdin is closed: interactive programs (editors, pagers, password prompts) will not \
                 work; use non-interactive flags (e.g. `git --no-pager log`, `apt-get -y`).\n\
                 - stdout and stderr are each capped at about {cap} bytes; the middle of longer output \
                 is omitted. Filter with `head`, `tail`, `grep`, `jq` or `wc` to keep output small.\n\
                 - A non-zero exit code is reported as an error result.\n\
                 - Prefer the dedicated tools for files: read_file, write_file, edit_file, list_dir, \
                 glob and grep.\n\
                 \n\
                 Examples:\n\
                 {{\"command\": \"jq '.hits.hits | length' alerts/latest.json\"}}\n\
                 {{\"command\": \"python3 scripts/enrich.py --ip 203.0.113.7\", \"timeout_secs\": 300, \
                 \"description\": \"Enrich suspicious IP\"}}",
                cap = self.opts.max_output_bytes
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The bash command line to execute, e.g. \"ls -la logs/ | head -50\"."
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": max_s,
                        "description": format!("Timeout in seconds (default {default_s}, max {max_s}).")
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory (absolute, or relative to the workspace). Must be an accessible directory. Default: the workspace."
                    },
                    "description": {
                        "type": "string",
                        "description": "Short (5-10 words) description of what the command does, for logs."
                    }
                },
                "required": ["command"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolOutput {
        let args = match Args::parse(args) {
            Ok(a) => a,
            Err(e) => return ToolOutput::err(e),
        };
        let command = match args.str("command") {
            Ok(c) => c,
            Err(e) => return ToolOutput::err(e),
        };
        if command.trim().is_empty() {
            return ToolOutput::err("`command` must not be empty");
        }
        if command.len() > MAX_COMMAND_BYTES {
            return ToolOutput::err(format!(
                "`command` is longer than {MAX_COMMAND_BYTES} bytes; write a script file with write_file and run it instead"
            ));
        }
        if command.contains('\0') {
            return ToolOutput::err("`command` must not contain NUL bytes");
        }
        let mut note = String::new();
        let timeout = match args.opt_u64("timeout_secs") {
            Err(e) => return ToolOutput::err(e),
            Ok(None) | Ok(Some(0)) => self.opts.default_timeout,
            Ok(Some(s)) => {
                let req = Duration::from_secs(s);
                if req > self.opts.max_timeout {
                    note = format!(
                        "[note: timeout_secs={s} exceeds the maximum; using {}s]\n",
                        self.opts.max_timeout.as_secs()
                    );
                    self.opts.max_timeout
                } else {
                    req
                }
            }
        };
        let cwd = match args.opt_str("cwd") {
            Err(e) => return ToolOutput::err(e),
            Ok(None) => ctx.cwd.clone(),
            Ok(Some(raw)) => {
                let guard = PathGuard::from_context(ctx);
                match guard.resolve(&raw, Access::Read) {
                    Ok(g) if g.exists && g.path.is_dir() => g.path,
                    Ok(g) => {
                        return ToolOutput::err(format!(
                            "cwd {} is not an existing directory",
                            g.path.display()
                        ));
                    }
                    Err(e) => return ToolOutput::err(e),
                }
            }
        };
        if let Ok(Some(d)) = args.opt_str("description") {
            tracing::debug!(description = %d, "bash tool call");
        }

        match self.run(&command, &cwd, timeout, &ctx.cancel).await {
            Ok(res) => {
                let body = format!("{note}{}", res.render());
                if res.success() {
                    ToolOutput::ok(body)
                } else {
                    ToolOutput::err(body)
                }
            }
            Err(e) => ToolOutput::err(format!(
                "failed to start {}: {e}",
                self.opts.shell.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ctx_for;

    fn tool() -> BashTool {
        BashTool::new(BashOptions {
            kill_grace: Duration::from_millis(500),
            ..BashOptions::default()
        })
    }

    fn pid_alive(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => false,
            Ok(s) => {
                // state is the field after the parenthesized comm
                let state = s
                    .rsplit(')')
                    .next()
                    .and_then(|r| r.split_whitespace().next());
                !matches!(state, Some("Z") | Some("X"))
            }
        }
    }

    async fn wait_dead(pid: u32) -> bool {
        for _ in 0..40 {
            if !pid_alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn runs_command_and_reports_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let out = tool()
            .call(json!({"command": "echo hello; echo oops >&2"}), &ctx)
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.starts_with("hello\n"));
        assert!(out.content.contains("[stderr]\noops"));
        assert!(out.content.ends_with("[exit code: 0]"));

        let out = tool().call(json!({"command": "exit 3"}), &ctx).await;
        assert!(out.is_error);
        assert!(out.content.contains("(no output)"));
        assert!(out.content.ends_with("[exit code: 3]"));
    }

    #[tokio::test]
    async fn runs_in_cwd_and_guarded_cwd_argument() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let ctx = ctx_for(dir.path());
        let out = tool().call(json!({"command": "pwd"}), &ctx).await;
        let real = std::fs::canonicalize(dir.path()).unwrap();
        assert!(
            out.content.starts_with(real.to_str().unwrap()),
            "{}",
            out.content
        );
        let out = tool()
            .call(json!({"command": "pwd", "cwd": "sub"}), &ctx)
            .await;
        assert!(out.content.contains("/sub"), "{}", out.content);
        let out = tool()
            .call(json!({"command": "pwd", "cwd": "/etc"}), &ctx)
            .await;
        assert!(out.is_error);
        assert!(out.content.contains("access denied"));
    }

    #[tokio::test]
    async fn environment_is_scrubbed() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let out = tool().call(json!({"command": "env"}), &ctx).await;
        assert!(!out.is_error, "{}", out.content);
        let shell_vars = ["PWD", "SHLVL", "_", "OLDPWD", "PAGER", "GIT_PAGER"];
        for line in out.content.lines() {
            let Some((k, _)) = line.split_once('=') else {
                continue;
            };
            let allowed = ["PATH", "HOME", "LANG", "TZ", "TERM", "USER"].contains(&k)
                || k.starts_with("LC_")
                || shell_vars.contains(&k);
            assert!(allowed, "unexpected env var leaked: {k}");
        }
        assert!(out.content.contains("PATH="));
    }

    #[test]
    fn scrub_supports_prefix_patterns() {
        let vars = scrubbed_env(&["NO_SUCH_VAR_*".to_string()]);
        // Only the PATH fallback is present.
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].0, "PATH");
    }

    #[tokio::test]
    async fn timeout_kills_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let started = Instant::now();
        let out = tool()
            .call(
                json!({"command": "sleep 60 & echo $!; sleep 30", "timeout_secs": 1}),
                &ctx,
            )
            .await;
        assert!(out.is_error);
        assert!(
            out.content.contains("timed out after 1s"),
            "{}",
            out.content
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid: u32 = out.content.lines().next().unwrap().trim().parse().unwrap();
        assert!(wait_dead(pid).await, "background sleep {pid} survived");
    }

    #[tokio::test]
    async fn background_jobs_killed_after_exit() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let started = Instant::now();
        let out = tool()
            .call(
                json!({"command": "sleep 60 >/dev/null 2>&1 & echo $!"}),
                &ctx,
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid: u32 = out.content.lines().next().unwrap().trim().parse().unwrap();
        assert!(wait_dead(pid).await, "background sleep {pid} survived");
    }

    #[tokio::test]
    async fn background_job_holding_pipe_does_not_hang() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let started = Instant::now();
        let out = tool()
            .call(json!({"command": "sleep 30 & echo started"}), &ctx)
            .await;
        assert!(out.content.starts_with("started"), "{}", out.content);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn cancellation_kills_command() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let cancel = ctx.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            cancel.cancel();
        });
        let started = Instant::now();
        let out = tool().call(json!({"command": "sleep 30"}), &ctx).await;
        assert!(out.is_error);
        assert!(out.content.contains("cancelled"), "{}", out.content);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn output_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let t = BashTool::new(BashOptions {
            max_output_bytes: 1000,
            ..BashOptions::default()
        });
        let out = t
            .call(json!({"command": "seq 1 200000; echo END"}), &ctx)
            .await;
        assert!(!out.is_error);
        assert!(out.content.len() < 2000, "len {}", out.content.len());
        assert!(out.content.starts_with("1\n2\n"));
        assert!(out.content.contains("bytes omitted"));
        assert!(out.content.contains("END"));
    }

    #[tokio::test]
    async fn argument_validation() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        assert!(tool().call(json!({}), &ctx).await.is_error);
        assert!(tool().call(json!({"command": "  "}), &ctx).await.is_error);
        assert!(
            tool()
                .call(json!({"command": "true", "timeout_secs": "x"}), &ctx)
                .await
                .is_error
        );
        let out = tool()
            .call(json!({"command": "true", "timeout_secs": 100000}), &ctx)
            .await;
        assert!(!out.is_error);
        assert!(out.content.contains("exceeds the maximum"));
    }

    #[tokio::test]
    async fn signal_termination_reported() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let out = tool().call(json!({"command": "kill -9 $$"}), &ctx).await;
        assert!(out.is_error);
        assert!(out.content.contains("signal 9"), "{}", out.content);
    }
}
