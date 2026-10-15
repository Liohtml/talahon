//! Spawning and supervising MCP server child processes.
//!
//! Each server runs in its own process group so the whole tree (bash
//! wrapper + Python interpreter) can be signalled. Shutdown follows the MCP
//! stdio guidance: close stdin, wait, `SIGTERM`, wait, `SIGKILL`. Dropping
//! the owning client kills the group immediately.

use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::config::ServerConfig;
use crate::error::McpError;

/// Default `PATH` for [`SpawnOptions::minimal`] when the parent has none.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// How a server process is launched.
#[derive(Debug, Clone)]
pub struct SpawnOptions {
    /// Start from an empty environment instead of inheriting this
    /// process's environment.
    pub env_clear: bool,
    /// Variables set before the server's own `env` (which wins on conflict).
    pub base_env: Vec<(String, String)>,
    /// Run as this uid (requires privileges).
    pub uid: Option<u32>,
    /// Run as this gid (requires privileges).
    pub gid: Option<u32>,
    /// Put the server in its own process group (default `true`) so the
    /// whole process tree is signalled on shutdown.
    pub new_process_group: bool,
    /// Working directory when the entry has no `cwd`.
    pub default_cwd: Option<PathBuf>,
}

impl Default for SpawnOptions {
    /// Inherit the environment (Claude Code behaviour), own process group.
    fn default() -> Self {
        Self {
            env_clear: false,
            base_env: Vec::new(),
            uid: None,
            gid: None,
            new_process_group: true,
            default_cwd: None,
        }
    }
}

impl SpawnOptions {
    /// The supervisor's minimal environment (§3.3): `PATH`, `LANG`, `TZ`
    /// (copied from this process when set) and `HOME=/tmp`; everything
    /// else comes from the server's `env`.
    pub fn minimal() -> Self {
        let mut base_env = vec![(
            "PATH".to_string(),
            std::env::var("PATH").unwrap_or_else(|_| DEFAULT_PATH.to_string()),
        )];
        base_env.push((
            "LANG".to_string(),
            std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".to_string()),
        ));
        if let Ok(tz) = std::env::var("TZ") {
            base_env.push(("TZ".to_string(), tz));
        }
        base_env.push(("HOME".to_string(), "/tmp".to_string()));
        Self {
            env_clear: true,
            base_env,
            ..Self::default()
        }
    }

    /// Run the server as `uid:gid` (the caller must be privileged; the
    /// standard library drops supplementary groups when switching from root).
    pub fn with_user(mut self, uid: u32, gid: u32) -> Self {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self
    }
}

/// Build the `Command` for a server entry: piped stdio, `kill_on_drop`,
/// environment and identity per `options`. Validates the entry first.
pub fn build_command(
    name: &str,
    config: &ServerConfig,
    options: &SpawnOptions,
) -> Result<Command, McpError> {
    config.validate_for_spawn(name)?;
    let mut cmd = Command::new(&config.command);
    cmd.args(&config.args);
    if options.env_clear {
        cmd.env_clear();
    }
    for (k, v) in &options.base_env {
        cmd.env(k, v);
    }
    for (k, v) in &config.env {
        cmd.env(k, v);
    }
    if let Some(cwd) = config.cwd.as_ref().or(options.default_cwd.as_ref()) {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        if options.new_process_group {
            cmd.process_group(0);
        }
        if let Some(gid) = options.gid {
            cmd.gid(gid);
        }
        if let Some(uid) = options.uid {
            cmd.uid(uid);
        }
    }
    Ok(cmd)
}

/// Signals used during shutdown.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Sig {
    Term,
    Kill,
}

/// Send `sig` to the process (group). Errors (e.g. `ESRCH`) are ignored.
#[cfg(unix)]
pub(crate) fn send_signal(pid: u32, group: bool, sig: Sig) {
    use rustix::process::{Pid, Signal, kill_process, kill_process_group};
    let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return;
    };
    let signal = match sig {
        Sig::Term => Signal::TERM,
        Sig::Kill => Signal::KILL,
    };
    let _ = if group {
        kill_process_group(pid, signal)
    } else {
        kill_process(pid, signal)
    };
}

#[cfg(not(unix))]
pub(crate) fn send_signal(_pid: u32, _group: bool, _sig: Sig) {}

/// Request for a graceful stop.
pub(crate) struct StopRequest {
    pub grace: Duration,
    pub done: oneshot::Sender<()>,
}

/// Handle kept by the client to control the supervisor task.
#[derive(Debug)]
pub(crate) struct ProcessControl {
    pub pid: Option<u32>,
    stop_tx: mpsc::Sender<StopRequest>,
}

impl ProcessControl {
    /// Ask the supervisor task to stop the process gracefully (the caller
    /// has already closed stdin) and wait until it is gone.
    pub async fn stop(&self, grace: Duration) {
        let (done, wait) = oneshot::channel();
        if self.stop_tx.send(StopRequest { grace, done }).await.is_ok() {
            // Bounded: grace for EOF, grace after SIGTERM, then SIGKILL.
            let budget = grace.saturating_mul(2) + Duration::from_secs(2);
            let _ = tokio::time::timeout(budget, wait).await;
        }
    }
}

/// Spawn the supervisor task owning `child`. `exited` receives a
/// human-readable description once the process is gone. When `lifetime` is
/// cancelled (client dropped) the process group is killed immediately.
pub(crate) fn supervise(
    server: String,
    mut child: Child,
    group: bool,
    lifetime: CancellationToken,
    exited: watch::Sender<Option<String>>,
) -> ProcessControl {
    let pid = child.id();
    let (stop_tx, mut stop_rx) = mpsc::channel::<StopRequest>(1);
    tokio::spawn(async move {
        let status = tokio::select! {
            status = child.wait() => status,
            _ = lifetime.cancelled() => {
                hard_kill(&mut child, pid, group);
                child.wait().await
            }
            req = stop_rx.recv() => match req {
                Some(req) => {
                    let status = graceful_stop(&mut child, pid, group, req.grace).await;
                    let _ = exited.send(Some(describe(&status)));
                    let _ = req.done.send(());
                    return;
                }
                // Control handle dropped together with the client.
                None => {
                    hard_kill(&mut child, pid, group);
                    child.wait().await
                }
            },
        };
        let text = describe(&status);
        tracing::debug!(server = %server, status = %text, "MCP server process exited");
        let _ = exited.send(Some(text));
    });
    ProcessControl { pid, stop_tx }
}

fn hard_kill(child: &mut Child, pid: Option<u32>, group: bool) {
    if let Some(pid) = pid {
        if group {
            send_signal(pid, true, Sig::Kill);
        }
    }
    let _ = child.start_kill();
}

async fn graceful_stop(
    child: &mut Child,
    pid: Option<u32>,
    group: bool,
    grace: Duration,
) -> std::io::Result<ExitStatus> {
    if let Ok(status) = tokio::time::timeout(grace, child.wait()).await {
        // Sweep stragglers left in the group (e.g. a wrapper's children).
        if let (Some(pid), true) = (pid, group) {
            send_signal(pid, true, Sig::Kill);
        }
        return status;
    }
    if let Some(pid) = pid {
        send_signal(pid, group, Sig::Term);
    }
    if let Ok(status) = tokio::time::timeout(grace, child.wait()).await {
        if let (Some(pid), true) = (pid, group) {
            send_signal(pid, true, Sig::Kill);
        }
        return status;
    }
    hard_kill(child, pid, group);
    child.wait().await
}

fn describe(status: &std::io::Result<ExitStatus>) -> String {
    match status {
        Ok(s) => format!("server process exited ({s})"),
        Err(e) => format!("server process wait failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_env_contents() {
        let o = SpawnOptions::minimal();
        assert!(o.env_clear);
        let keys: Vec<_> = o.base_env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"PATH"));
        assert!(keys.contains(&"LANG"));
        assert!(keys.contains(&"HOME"));
        assert!(o.base_env.iter().any(|(k, v)| k == "HOME" && v == "/tmp"));
        let o = o.with_user(1, 2);
        assert_eq!((o.uid, o.gid), (Some(1), Some(2)));
    }

    #[test]
    fn build_command_validates() {
        let cfg = ServerConfig::new("", Vec::<String>::new());
        assert!(build_command("x", &cfg, &SpawnOptions::default()).is_err());
        let cfg = ServerConfig::new("/bin/true", Vec::<String>::new());
        assert!(build_command("bad/name", &cfg, &SpawnOptions::default()).is_err());
        assert!(build_command("ok", &cfg, &SpawnOptions::default()).is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_policy_applies() {
        // SAFETY of the assertion: cargo sets CARGO_MANIFEST_DIR for test
        // binaries; env_clear must hide it from the server.
        let mut cfg = ServerConfig::new(
            "/bin/sh",
            ["-c", "echo \"$HOME|$FOO|${CARGO_MANIFEST_DIR:-unset}\""],
        );
        cfg.env.insert("FOO".into(), "bar".into());
        let mut opts = SpawnOptions::minimal();
        opts.base_env.push(("FOO".into(), "base".into()));
        let mut cmd = build_command("envtest", &cfg, &opts).unwrap();
        let out = cmd.output().await.unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(text.trim(), "/tmp|bar|unset");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn graceful_stop_escalates_to_kill() {
        // Ignores SIGTERM and stdin EOF: must end with SIGKILL.
        let cfg = ServerConfig::new(
            "/bin/sh",
            ["-c", "trap '' TERM; while :; do sleep 0.05; done"],
        );
        let mut cmd = build_command("stubborn", &cfg, &SpawnOptions::default()).unwrap();
        let child = cmd.spawn().unwrap();
        let (tx, mut rx) = watch::channel(None);
        let ctl = supervise("stubborn".into(), child, true, CancellationToken::new(), tx);
        let start = std::time::Instant::now();
        ctl.stop(Duration::from_millis(100)).await;
        assert!(start.elapsed() < Duration::from_secs(3));
        let desc = rx.wait_for(Option::is_some).await.unwrap().clone().unwrap();
        assert!(desc.contains("exited"), "{desc}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifetime_cancel_kills() {
        let cfg = ServerConfig::new("/bin/sh", ["-c", "sleep 30"]);
        let mut cmd = build_command("sleeper", &cfg, &SpawnOptions::default()).unwrap();
        let child = cmd.spawn().unwrap();
        let (tx, mut rx) = watch::channel(None);
        let lifetime = CancellationToken::new();
        let _ctl = supervise("sleeper".into(), child, true, lifetime.clone(), tx);
        lifetime.cancel();
        let res = tokio::time::timeout(Duration::from_secs(3), rx.wait_for(Option::is_some)).await;
        assert!(res.is_ok(), "process not killed");
    }
}
