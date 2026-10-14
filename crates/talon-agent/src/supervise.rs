//! `talon-agent supervise`: the small, LLM-free root process of the
//! container (docs/RUST_ARCHITECTURE.md §3.3).
//!
//! 1. Read the whole `ContainerInput` from stdin (bounded) and validate it
//!    **before** anything is spawned.
//! 2. Take the agent identity numerically from `RUN_UID` / `RUN_GID`
//!    (non-zero, not an `mcp-*` id; the read-only rootfs has no passwd
//!    entry for a remapped uid).
//! 3. Parse `<group>/.mcp.json` (read-only mount; missing/empty = no
//!    servers). For each server: `runAs` must be a valid, existing `mcp-*`
//!    account (else `mcp-default`); the command must pass
//!    `check_privileged_launch` under [`ALLOWED_MCP_ROOTS`] **and** the
//!    canonical command and its directory must be on a read-only mount of
//!    this container (`/proc/self/mountinfo`, see [`crate::mountinfo`] and
//!    [`CommandPolicy`]) and outside [`DENIED_MCP_DIRS`] (read-only here,
//!    but agent-writable through other mounts) — else the server is
//!    refused; it runs as that
//!    account with the minimal environment,
//!    `HOME=/run/talon/home/<server>` (0700, owned by the account),
//!    `PYTHONSAFEPATH=1`, `PYTHONDONTWRITEBYTECODE=1`, in its own process
//!    group, with the **command's directory** as cwd (never the
//!    agent-writable group folder: Python puts the cwd on `sys.path`).
//! 4. Expose each server on `/run/talon/mcp/<server>.sock` (dir 0750
//!    `root:<agent gid>`, socket 0600 owned by the agent): accept exactly
//!    one connection (peer uid checked), unlink the path, then relay bytes
//!    with `talon_mcp::bridge`.
//! 5. Spawn `talon-agent run` as `RUN_UID:RUN_GID` (std `uid`/`gid`, which
//!    drops supplementary groups) with a cleared environment (`PATH`,
//!    `HOME=/home/agent`, `LANG`, `TZ`, `TALON_MCP_SOCKET_DIR`, log filter
//!    and egress policy variables), the original input on its stdin and the
//!    supervisor's stdout/stderr inherited (frames and logs pass straight
//!    through). SIGTERM/SIGINT are forwarded; the agent is killed if it does
//!    not exit within [`AGENT_STOP_GRACE`].
//! 6. When the agent exits, stop every MCP server (stdin EOF, SIGTERM, then
//!    SIGKILL to the process group) and exit with the agent's code.
//!
//! Without root privileges `supervise` falls back to `run` with a warning.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use talon_core::protocol::ContainerOutput;
use talon_mcp::config::{DEFAULT_RUN_AS, is_valid_run_as, lookup_user_in_passwd};
use talon_mcp::{ServerConfig, SpawnOptions, socket_path};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

use crate::config::{RunArgs, RunConfig};
use crate::mountinfo::{DEFAULT_MOUNTINFO, MountTable};
use crate::wire::{OutputSink, StdoutSink, parse_input, read_capped};
use crate::{logging, mcp, run};

/// Socket directory exposed to the agent.
pub const DEFAULT_SOCKET_DIR: &str = "/run/talon/mcp";
/// Parent of the per-server private home directories.
pub const DEFAULT_HOME_ROOT: &str = "/run/talon/home";
/// The agent's home (tmpfs; sessions are bind-mounted at `.talon`).
pub const AGENT_HOME: &str = "/home/agent";
/// Directories a privileged MCP command must live in (read-only mounts and
/// image directories; never the agent-writable workspace). Being under one
/// of them is not enough: [`CommandPolicy`] also requires the command to be
/// on a read-only mount (the image rootfs is mounted read-only, so the check
/// holds for the image directories too). `/workspace/project` is main's
/// read-only project mount (`groups/main/.mcp.json` points there).
pub const ALLOWED_MCP_ROOTS: [&str; 6] = [
    "/workspace/project",
    "/workspace/extra",
    "/opt",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
];
/// Directories inside [`ALLOWED_MCP_ROOTS`] a privileged MCP command (or
/// its directory) may never be in (N-10). Main's `/workspace/project` view
/// is read-only, but these parts of it are the host's `groups/`, `data/`
/// and `store/`, which agents write through other mounts (the group
/// folder, the IPC namespace, the session state, ...): read-only is not
/// immutable there.
pub const DENIED_MCP_DIRS: [&str; 3] = [
    "/workspace/project/groups",
    "/workspace/project/data",
    "/workspace/project/store",
];
/// Non-secret variables passed from the container environment to the agent.
pub const PASSTHROUGH_ENV: &[&str] = &[
    "RUST_LOG",
    "TALON_LOG",
    "TALON_EGRESS_ALLOW",
    "TALON_EGRESS_DENY",
    "TALON_EGRESS_ALLOW_PRIVATE",
];
/// How long the agent may take to exit after a forwarded signal.
pub const AGENT_STOP_GRACE: Duration = Duration::from_secs(10);
/// Grace period per stage when stopping an MCP server.
const SERVER_STOP_GRACE: Duration = Duration::from_secs(2);
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Longest MCP stderr line logged (bytes).
const MAX_STDERR_LINE: usize = 4096;

/// CLI options of `talon-agent supervise`.
#[derive(Debug, Clone, clap::Args)]
pub struct SuperviseArgs {
    /// Options forwarded to `talon-agent run` (paths, loop limits).
    #[command(flatten)]
    pub run: RunArgs,
    /// Where the per-server unix sockets are created.
    #[arg(long, default_value = DEFAULT_SOCKET_DIR)]
    pub socket_dir: PathBuf,
    /// Parent directory of the per-server private homes.
    #[arg(long, default_value = DEFAULT_HOME_ROOT)]
    pub mcp_home_root: PathBuf,
    /// Agent binary (default: this executable).
    #[arg(long)]
    pub agent_bin: Option<PathBuf>,
    /// Account database used to resolve `runAs` (tests only).
    #[arg(long, hide = true, default_value = "/etc/passwd")]
    pub passwd_file: PathBuf,
    /// Mount table used for the read-only command check (tests only).
    #[arg(long, hide = true, default_value = DEFAULT_MOUNTINFO)]
    pub mountinfo_file: PathBuf,
}

/// Resolved supervisor configuration.
#[derive(Debug, Clone)]
pub struct SuperviseConfig {
    /// Configuration of the agent (`run`).
    pub run: RunConfig,
    /// Socket directory.
    pub socket_dir: PathBuf,
    /// Per-server home parent.
    pub home_root: PathBuf,
    /// Agent binary override.
    pub agent_bin: Option<PathBuf>,
    /// Account database (`/etc/passwd`).
    pub passwd_file: PathBuf,
    /// Mount table (`/proc/self/mountinfo`).
    pub mountinfo_file: PathBuf,
}

impl SuperviseArgs {
    /// Resolve into a [`SuperviseConfig`].
    pub fn into_config(self) -> SuperviseConfig {
        SuperviseConfig {
            run: self.run.into_config(),
            socket_dir: self.socket_dir,
            home_root: self.mcp_home_root,
            agent_bin: self.agent_bin,
            passwd_file: self.passwd_file,
            mountinfo_file: self.mountinfo_file,
        }
    }
}

/// The agent's numeric identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentIds {
    /// `RUN_UID`.
    pub uid: u32,
    /// `RUN_GID`.
    pub gid: u32,
}

fn parse_id(name: &str, value: Option<&str>) -> Result<u32, String> {
    let v = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{name} is not set"))?;
    if v.len() > 10 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{name} must be a decimal number"));
    }
    let id: u32 = v.parse().map_err(|_| format!("{name} is out of range"))?;
    if id == 0 {
        return Err(format!("{name}=0 refused: the agent never runs as root"));
    }
    if id == u32::MAX {
        return Err(format!("{name} is out of range"));
    }
    Ok(id)
}

/// Validate `RUN_UID` / `RUN_GID`: numeric, non-zero, and not shared with
/// any `mcp-*` account in `passwd` (that would expose its secrets).
pub fn parse_agent_ids(
    run_uid: Option<&str>,
    run_gid: Option<&str>,
    passwd: &str,
) -> Result<AgentIds, String> {
    let ids = AgentIds {
        uid: parse_id("RUN_UID", run_uid)?,
        gid: parse_id("RUN_GID", run_gid)?,
    };
    for line in passwd.lines().filter(|l| l.starts_with("mcp-")) {
        let mut f = line.split(':');
        let name = f.next().unwrap_or_default();
        let _pw = f.next();
        let uid = f.next().and_then(|u| u.parse::<u32>().ok());
        let gid = f.next().and_then(|g| g.parse::<u32>().ok());
        if uid == Some(ids.uid)
            || gid == Some(ids.gid)
            || uid == Some(ids.gid)
            || gid == Some(ids.uid)
        {
            return Err(format!("RUN_UID/RUN_GID collide with the {name} account"));
        }
    }
    Ok(ids)
}

/// Environment of the agent process (everything else is cleared).
pub fn agent_env(socket_dir: &Path, get: impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    let clean = |v: String| (!v.contains('\0') && !v.is_empty()).then_some(v);
    let mut env = vec![
        (
            "PATH".to_string(),
            get("PATH")
                .and_then(clean)
                .unwrap_or_else(|| DEFAULT_PATH.to_string()),
        ),
        ("HOME".to_string(), AGENT_HOME.to_string()),
        (
            "LANG".to_string(),
            get("LANG")
                .and_then(clean)
                .unwrap_or_else(|| "C.UTF-8".to_string()),
        ),
    ];
    if let Some(tz) = get("TZ").and_then(clean) {
        env.push(("TZ".to_string(), tz));
    }
    env.push((
        "TALON_MCP_SOCKET_DIR".to_string(),
        socket_dir.display().to_string(),
    ));
    for key in PASSTHROUGH_ENV {
        if let Some(v) = get(key).and_then(clean) {
            env.push(((*key).to_string(), v));
        }
    }
    env
}

/// Command-line arguments that make `talon-agent run` use the same
/// configuration as this supervisor.
pub fn agent_args(cfg: &RunConfig, socket_dir: &Path) -> Vec<OsString> {
    let p = &cfg.paths;
    let s = &cfg.settings;
    let mut args: Vec<OsString> = vec!["run".into()];
    let mut flag = |name: &str, value: OsString| {
        args.push(format!("--{name}").into());
        args.push(value);
    };
    flag("group-dir", p.group.clone().into_os_string());
    flag("global-dir", p.global.clone().into_os_string());
    flag("project-dir", p.project.clone().into_os_string());
    flag("extra-dir", p.extra.clone().into_os_string());
    flag("ipc-dir", p.ipc.clone().into_os_string());
    flag("state-dir", p.state.clone().into_os_string());
    flag("mcp-config", p.mcp_config.clone().into_os_string());
    flag("mcp-socket-dir", socket_dir.as_os_str().to_owned());
    flag("max-iterations", s.max_iterations.to_string().into());
    flag("self-check", s.self_check.to_string().into());
    flag("compact-threshold", s.compact_ratio.to_string().into());
    flag("ipc-poll-ms", s.ipc_poll.as_millis().to_string().into());
    flag(
        "tool-timeout-secs",
        s.tool_timeout.as_secs().to_string().into(),
    );
    flag("max-input-bytes", cfg.max_input_bytes.to_string().into());
    args
}

/// How one MCP server will be launched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// Server name.
    pub name: String,
    /// System account.
    pub user: String,
    /// Account uid.
    pub uid: u32,
    /// Account gid.
    pub gid: u32,
    /// Socket path.
    pub socket: PathBuf,
    /// Private home.
    pub home: PathBuf,
    /// Entry to spawn: canonical command, cwd = the command's directory.
    pub config: ServerConfig,
    /// Why `runAs` was replaced by `mcp-default`, if it was.
    pub note: Option<String>,
}

/// Where a privileged MCP command may come from.
#[derive(Debug, Clone)]
pub struct CommandPolicy {
    /// The command must resolve under one of these ([`ALLOWED_MCP_ROOTS`]).
    pub roots: Vec<PathBuf>,
    /// The canonical command and its directory must not be under any of
    /// these ([`DENIED_MCP_DIRS`]), even on a read-only mount.
    pub denied: Vec<PathBuf>,
    /// The container's mount table: the canonical command and its
    /// directory must be on read-only mounts.
    pub mounts: MountTable,
}

impl CommandPolicy {
    /// [`ALLOWED_MCP_ROOTS`] minus [`DENIED_MCP_DIRS`], with `mounts`.
    pub fn container(mounts: MountTable) -> Self {
        Self {
            roots: ALLOWED_MCP_ROOTS.iter().map(PathBuf::from).collect(),
            denied: DENIED_MCP_DIRS.iter().map(PathBuf::from).collect(),
            mounts,
        }
    }

    /// The denied directory `path` (absolute, canonical) lies in, if any.
    /// Each entry is compared as configured and canonicalized (when it
    /// exists), component-wise (`/workspace/project/groupsX` is not under
    /// `/workspace/project/groups`).
    fn denied_dir_of(&self, path: &Path) -> Option<&Path> {
        self.denied
            .iter()
            .find(|d| {
                path.starts_with(d) || std::fs::canonicalize(d).is_ok_and(|c| path.starts_with(c))
            })
            .map(PathBuf::as_path)
    }

    /// Validate `cfg` for a privileged launch and return the canonical
    /// command path.
    pub fn check(&self, name: &str, cfg: &ServerConfig) -> Result<PathBuf, String> {
        let command = cfg
            .check_privileged_launch(name, &self.roots)
            .map_err(|e| e.to_string())?;
        let dir = command
            .parent()
            .ok_or_else(|| "command has no parent directory".to_string())?;
        for path in [command.as_path(), dir] {
            if let Some(denied) = self.denied_dir_of(path) {
                return Err(format!(
                    "server '{name}': {} is under {}, which agents can write through other mounts",
                    path.display(),
                    denied.display()
                ));
            }
            if !self.mounts.is_read_only(path) {
                return Err(format!(
                    "server '{name}': {} is not on a read-only mount",
                    path.display()
                ));
            }
        }
        Ok(command)
    }
}

/// Decide whether and how to launch `name` (pure apart from resolving the
/// command path). `Err` explains why the server is refused.
pub fn plan_server(
    name: &str,
    cfg: &ServerConfig,
    passwd: &str,
    policy: &CommandPolicy,
    socket_dir: &Path,
    home_root: &Path,
    agent: AgentIds,
) -> Result<LaunchPlan, String> {
    let socket = socket_path(socket_dir, name).map_err(|e| e.to_string())?;
    let (user, note) = match cfg.run_as.as_deref() {
        Some(u) if is_valid_run_as(u) && lookup_user_in_passwd(passwd, u).is_some() => {
            (u.to_string(), None)
        }
        Some(u) => (
            DEFAULT_RUN_AS.to_string(),
            Some(format!(
                "runAs {:?} is invalid or has no account; using {DEFAULT_RUN_AS}",
                u.chars().take(48).collect::<String>()
            )),
        ),
        None => (DEFAULT_RUN_AS.to_string(), None),
    };
    let account =
        lookup_user_in_passwd(passwd, &user).ok_or_else(|| format!("no system account {user}"))?;
    if account.uid == 0 || account.gid == 0 {
        return Err(format!("account {user} is privileged (uid/gid 0)"));
    }
    if account.uid == agent.uid || account.gid == agent.gid {
        return Err(format!("account {user} shares an id with the agent"));
    }
    let mut checked = cfg.clone();
    checked.run_as = Some(user.clone());
    let command = policy.check(name, &checked)?;
    let cwd = command
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "command has no parent directory".to_string())?;
    checked.command = command.display().to_string();
    checked.cwd = Some(cwd);
    Ok(LaunchPlan {
        name: name.to_string(),
        user,
        uid: account.uid,
        gid: account.gid,
        socket,
        home: home_root.join(name),
        config: checked,
        note,
    })
}

/// Variables forced on every MCP server after its own `env` (so a
/// `.mcp.json` entry cannot override them).
pub fn server_env_overrides(home: &Path) -> Vec<(String, String)> {
    vec![
        ("HOME".to_string(), home.display().to_string()),
        ("PYTHONSAFEPATH".to_string(), "1".to_string()),
        ("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string()),
    ]
}

/// Exit code for a child status: its code, or `128 + signal`.
pub fn exit_code(status: &ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

/// Create (or re-secure) a directory: no symlinks, `mode`, `uid:gid`.
pub fn prepare_dir(path: &Path, mode: u32, uid: u32, gid: u32) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(std::io::Error::other(format!(
                "{} exists and is not a directory",
                path.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    // e.g. /run/talon when the entrypoint did not create it:
                    // it must stay traversable for the agent and mcp-* users
                    // (the process umask is 077).
                    std::fs::create_dir_all(parent)?;
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
                }
            }
            std::fs::create_dir(path)?;
        }
        Err(e) => return Err(e),
    }
    std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Bind `path` (replacing a stale socket), mode 0600, owned by the agent.
pub fn bind_socket(path: &Path, agent: AgentIds) -> std::io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    std::os::unix::fs::chown(path, Some(agent.uid), Some(agent.gid))?;
    Ok(listener)
}

/// Accept exactly one connection on `listener` from the agent (or root),
/// unlink `path`, then relay it to the server's stdio until either side
/// ends.
pub async fn serve_socket<W, R>(
    listener: UnixListener,
    path: PathBuf,
    server_stdin: W,
    server_stdout: R,
    agent: AgentIds,
    name: String,
) where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let accepted = listener.accept().await;
    let _ = std::fs::remove_file(&path);
    drop(listener);
    let stream = match accepted {
        Ok((stream, _)) => stream,
        Err(e) => {
            tracing::warn!(server = %name, error = %e, "MCP socket accept failed");
            return;
        }
    };
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == agent.uid || cred.uid() == 0 => {}
        Ok(cred) => {
            tracing::warn!(server = %name, uid = cred.uid(), "refusing MCP socket connection from an unexpected uid");
            return;
        }
        Err(e) => {
            tracing::warn!(server = %name, error = %e, "cannot verify the MCP socket peer");
            return;
        }
    }
    tracing::debug!(server = %name, "agent connected to MCP socket");
    match talon_mcp::bridge::bridge(stream, server_stdin, server_stdout).await {
        Ok((up, down)) => tracing::debug!(server = %name, up, down, "MCP bridge closed"),
        Err(e) => tracing::debug!(server = %name, error = %e, "MCP bridge ended with an error"),
    }
}

/// Log a child's stderr line by line (bounded line length).
pub async fn pump_stderr<R: AsyncRead + Unpin>(name: String, mut reader: R) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=pos).collect();
            log_stderr_line(&name, &line);
        }
        if buf.len() > MAX_STDERR_LINE {
            log_stderr_line(&name, &buf);
            buf.clear();
        }
    }
    log_stderr_line(&name, &buf);
}

fn log_stderr_line(name: &str, bytes: &[u8]) {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_STDERR_LINE)]);
    let text = text.trim_end();
    if !text.is_empty() {
        tracing::info!(target: "talon_agent::mcp_stderr", server = %name, "{text}");
    }
}

/// A running MCP server.
struct RunningServer {
    name: String,
    pid: Option<u32>,
    socket: PathBuf,
    child: Child,
    bridge: JoinHandle<()>,
    stderr: Option<JoinHandle<()>>,
}

fn signal_group(pid: Option<u32>, sig: rustix::process::Signal) {
    let Some(pid) = pid
        .and_then(|p| i32::try_from(p).ok())
        .and_then(rustix::process::Pid::from_raw)
    else {
        return;
    };
    let _ = rustix::process::kill_process_group(pid, sig);
}

impl RunningServer {
    async fn shutdown(mut self) {
        // Dropping the bridge closes the server's stdin (MCP stdio shutdown).
        self.bridge.abort();
        let _ = (&mut self.bridge).await;
        let _ = std::fs::remove_file(&self.socket);
        let mut exited = tokio::time::timeout(SERVER_STOP_GRACE, self.child.wait())
            .await
            .is_ok();
        if !exited {
            signal_group(self.pid, rustix::process::Signal::TERM);
            exited = tokio::time::timeout(SERVER_STOP_GRACE, self.child.wait())
                .await
                .is_ok();
        }
        // Sweep the whole group (wrapper scripts leave children behind).
        signal_group(self.pid, rustix::process::Signal::KILL);
        if !exited {
            let _ = self.child.start_kill();
            let _ = tokio::time::timeout(SERVER_STOP_GRACE, self.child.wait()).await;
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = tokio::time::timeout(Duration::from_millis(500), stderr).await;
        }
        tracing::debug!(server = %self.name, "MCP server stopped");
    }
}

async fn launch_server(plan: LaunchPlan, agent: AgentIds) -> Result<RunningServer, String> {
    prepare_dir(&plan.home, 0o700, plan.uid, plan.gid)
        .map_err(|e| format!("cannot prepare home {}: {e}", plan.home.display()))?;
    let options = SpawnOptions::minimal().with_user(plan.uid, plan.gid);
    let mut cmd = talon_mcp::process::build_command(&plan.name, &plan.config, &options)
        .map_err(|e| e.to_string())?;
    for (k, v) in server_env_overrides(&plan.home) {
        cmd.env(k, v);
    }
    let listener = bind_socket(&plan.socket, agent)
        .map_err(|e| format!("cannot bind {}: {e}", plan.socket.display()))?;
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&plan.socket);
            return Err(format!("spawn failed: {e}"));
        }
    };
    let pid = child.id();
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.start_kill();
        let _ = std::fs::remove_file(&plan.socket);
        return Err("child stdio unavailable".into());
    };
    let stderr = child
        .stderr
        .take()
        .map(|e| tokio::spawn(pump_stderr(plan.name.clone(), e)));
    let bridge = tokio::spawn(serve_socket(
        listener,
        plan.socket.clone(),
        stdin,
        stdout,
        agent,
        plan.name.clone(),
    ));
    tracing::info!(server = %plan.name, user = %plan.user, pid = ?pid, "MCP server started");
    Ok(RunningServer {
        name: plan.name,
        pid,
        socket: plan.socket,
        child,
        bridge,
        stderr,
    })
}

async fn recv_signal(sig: &mut Option<tokio::signal::unix::Signal>) {
    match sig {
        Some(s) => {
            if s.recv().await.is_none() {
                std::future::pending::<()>().await;
            }
        }
        None => std::future::pending::<()>().await,
    }
}

/// Wait for the agent, forwarding SIGTERM/SIGINT and killing it after
/// [`AGENT_STOP_GRACE`]. Returns the status and whether a signal was
/// forwarded.
async fn wait_agent(child: &mut Child) -> (std::io::Result<ExitStatus>, bool) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).ok();
    let mut int = signal(SignalKind::interrupt()).ok();
    let pid = child
        .id()
        .and_then(|p| i32::try_from(p).ok())
        .and_then(rustix::process::Pid::from_raw);
    let mut forwarded = false;
    let deadline = tokio::time::sleep(Duration::from_secs(365 * 24 * 3600));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            status = child.wait() => return (status, forwarded),
            () = recv_signal(&mut term) => {}
            () = recv_signal(&mut int) => {}
            () = &mut deadline, if forwarded => {
                tracing::warn!("agent did not exit after the forwarded signal; killing it");
                let _ = child.start_kill();
                return (child.wait().await, forwarded);
            }
        }
        if let Some(pid) = pid {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        }
        if !forwarded {
            tracing::info!("forwarding termination signal to the agent");
            forwarded = true;
            deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + AGENT_STOP_GRACE);
        }
    }
}

/// Entry point of `talon-agent supervise`; returns the exit code.
pub async fn supervise_main(cfg: SuperviseConfig) -> i32 {
    if !rustix::process::geteuid().is_root() {
        tracing::warn!(
            "supervise needs root; falling back to `run` (MCP servers will run unprivileged as the agent)"
        );
        return run::run_main(cfg.run).await;
    }
    let output = StdoutSink;
    let fail = |msg: String| {
        tracing::error!(error = %msg, "supervisor failed");
        output.emit(&ContainerOutput::error(format!("supervisor: {msg}")));
        1
    };

    // 1. Input first, before anything is spawned.
    let bytes = match read_capped(tokio::io::stdin(), cfg.run.max_input_bytes).await {
        Ok(b) => b,
        Err(e) => return fail(e.to_string()),
    };
    match parse_input(&bytes) {
        Ok(input) => {
            if let Some(llm) = &input.llm {
                logging::register_secret(&llm.token);
            }
        }
        Err(e) => return fail(e.to_string()),
    }

    // 2. Identities.
    let passwd = std::fs::read_to_string(&cfg.passwd_file).unwrap_or_default();
    let ids = match parse_agent_ids(
        std::env::var("RUN_UID").ok().as_deref(),
        std::env::var("RUN_GID").ok().as_deref(),
        &passwd,
    ) {
        Ok(ids) => ids,
        Err(e) => return fail(e),
    };

    // 3./4. MCP servers.
    let mut servers: Vec<RunningServer> = Vec::new();
    let mcp_config = mcp::load_mcp_config(&cfg.run.paths.mcp_config);
    for (name, error) in &mcp_config.invalid {
        tracing::warn!(server = %name, %error, "invalid MCP server entry ignored");
    }
    let mounts = MountTable::load(&cfg.mountinfo_file).unwrap_or_else(|e| {
        tracing::error!(
            path = %cfg.mountinfo_file.display(),
            error = %e,
            "cannot read the mount table; every MCP server will be refused"
        );
        MountTable::default()
    });
    let policy = CommandPolicy::container(mounts);
    let dirs_ready = prepare_dir(&cfg.socket_dir, 0o750, 0, ids.gid)
        .and_then(|()| prepare_dir(&cfg.home_root, 0o711, 0, 0));
    match dirs_ready {
        Err(e) => {
            tracing::error!(error = %e, "cannot prepare MCP runtime directories; starting without MCP servers")
        }
        Ok(()) => {
            for (name, server) in mcp_config.servers() {
                let plan = match plan_server(
                    name,
                    server,
                    &passwd,
                    &policy,
                    &cfg.socket_dir,
                    &cfg.home_root,
                    ids,
                ) {
                    Ok(p) => p,
                    Err(reason) => {
                        tracing::warn!(server = %name, %reason, "refusing MCP server");
                        continue;
                    }
                };
                if let Some(note) = &plan.note {
                    tracing::warn!(server = %name, %note, "MCP runAs replaced");
                }
                match launch_server(plan, ids).await {
                    Ok(s) => servers.push(s),
                    Err(e) => {
                        tracing::warn!(server = %name, error = %e, "MCP server failed to start")
                    }
                }
            }
        }
    }

    // 5. The agent.
    let exe = match cfg.agent_bin.clone().map_or_else(std::env::current_exe, Ok) {
        Ok(p) => p,
        Err(e) => {
            stop_servers(servers).await;
            return fail(format!("cannot locate the agent binary: {e}"));
        }
    };
    let mut cmd = Command::new(&exe);
    cmd.args(agent_args(&cfg.run, &cfg.socket_dir))
        .env_clear()
        .envs(agent_env(&cfg.socket_dir, |k| std::env::var(k).ok()))
        .current_dir(&cfg.run.paths.group)
        .uid(ids.uid)
        .gid(ids.gid)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            stop_servers(servers).await;
            return fail(format!("cannot start the agent: {e}"));
        }
    };
    tracing::info!(
        uid = ids.uid,
        gid = ids.gid,
        servers = servers.len(),
        "agent started"
    );
    if let Some(mut stdin) = child.stdin.take() {
        let bytes = Arc::new(bytes);
        tokio::spawn(async move {
            if let Err(e) = stdin.write_all(&bytes).await {
                tracing::warn!(error = %e, "cannot pass the input to the agent");
            }
            let _ = stdin.shutdown().await;
        });
    }

    // 6. Wait, then tear everything down.
    let (status, forwarded) = wait_agent(&mut child).await;
    stop_servers(servers).await;
    match status {
        Ok(status) => {
            let code = exit_code(&status);
            if let (Some(sig), false) = (status.signal(), forwarded) {
                return fail(format!("agent process terminated by signal {sig}"));
            }
            tracing::info!(code, "agent exited");
            code
        }
        Err(e) => fail(format!("cannot wait for the agent: {e}")),
    }
}

async fn stop_servers(servers: Vec<RunningServer>) {
    join_all(servers.into_iter().map(RunningServer::shutdown)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash
agent:x:1000:1000::/home/agent:/bin/bash
mcp-siem:x:61001:61001::/nonexistent:/usr/sbin/nologin
mcp-default:x:61009:61009::/nonexistent:/usr/sbin/nologin
mcp-evil:x:0:0::/nonexistent:/usr/sbin/nologin
";

    fn agent() -> AgentIds {
        AgentIds {
            uid: 1000,
            gid: 1000,
        }
    }

    #[test]
    fn agent_id_validation() {
        assert_eq!(
            parse_agent_ids(Some("1000"), Some(" 1000 "), PASSWD),
            Ok(agent())
        );
        assert!(parse_agent_ids(None, Some("1000"), PASSWD).is_err());
        assert!(
            parse_agent_ids(Some("0"), Some("1000"), PASSWD)
                .unwrap_err()
                .contains("root")
        );
        assert!(parse_agent_ids(Some("-5"), Some("1000"), PASSWD).is_err());
        assert!(parse_agent_ids(Some("1e3"), Some("1000"), PASSWD).is_err());
        assert!(parse_agent_ids(Some("99999999999"), Some("1000"), PASSWD).is_err());
        assert!(parse_agent_ids(Some("4294967295"), Some("1000"), PASSWD).is_err());
        let e = parse_agent_ids(Some("61001"), Some("1000"), PASSWD).unwrap_err();
        assert!(e.contains("mcp-siem"), "{e}");
        assert!(parse_agent_ids(Some("1000"), Some("61009"), PASSWD).is_err());
    }

    #[test]
    fn agent_environment_is_minimal() {
        let env = agent_env(Path::new("/run/talon/mcp"), |k| match k {
            "PATH" => Some("/usr/bin".into()),
            "TZ" => Some("Europe/Berlin".into()),
            "RUST_LOG" => Some("debug".into()),
            "TALON_EGRESS_ALLOW" => Some("ti.example.com".into()),
            "LANG" => Some(String::new()),
            "TALON_VLLM_API_KEY" | "AWS_SECRET_ACCESS_KEY" => Some("secret".into()),
            "TALON_LOG" => Some("bad\0value".into()),
            _ => None,
        });
        let get = |k: &str| {
            env.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("PATH"), Some("/usr/bin"));
        assert_eq!(get("HOME"), Some("/home/agent"));
        assert_eq!(get("LANG"), Some("C.UTF-8"));
        assert_eq!(get("TZ"), Some("Europe/Berlin"));
        assert_eq!(get("TALON_MCP_SOCKET_DIR"), Some("/run/talon/mcp"));
        assert_eq!(get("RUST_LOG"), Some("debug"));
        assert_eq!(get("TALON_EGRESS_ALLOW"), Some("ti.example.com"));
        assert_eq!(get("TALON_VLLM_API_KEY"), None);
        assert_eq!(get("AWS_SECRET_ACCESS_KEY"), None);
        assert_eq!(get("TALON_LOG"), None);
        let default_path = agent_env(Path::new("/s"), |_| None);
        assert_eq!(default_path[0].1, DEFAULT_PATH);
    }

    #[test]
    fn agent_args_forward_the_configuration() {
        let cfg = RunConfig::default();
        let args: Vec<String> = agent_args(&cfg, Path::new("/run/talon/mcp"))
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(args[0], "run");
        let pos = |f: &str| args.iter().position(|a| a == f).unwrap();
        assert_eq!(args[pos("--group-dir") + 1], "/workspace/group");
        assert_eq!(args[pos("--mcp-socket-dir") + 1], "/run/talon/mcp");
        assert_eq!(args[pos("--self-check") + 1], "true");
        assert_eq!(args[pos("--ipc-poll-ms") + 1], "500");
        // Round trip through the real parser.
        #[derive(clap::Parser)]
        struct Cli {
            #[command(subcommand)]
            cmd: Sub,
        }
        #[derive(clap::Subcommand)]
        enum Sub {
            Run(RunArgs),
        }
        let parsed = <Cli as clap::Parser>::try_parse_from(
            std::iter::once("talon-agent".to_string()).chain(args),
        )
        .unwrap();
        let Sub::Run(run) = parsed.cmd;
        let back = run.into_config();
        assert_eq!(back.paths, cfg.paths);
        assert_eq!(back.settings, cfg.settings);
        assert_eq!(back.mcp_socket_dir, Some(PathBuf::from("/run/talon/mcp")));
    }

    fn script_in(dir: &Path) -> PathBuf {
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let script = bin.join("server.sh");
        std::fs::write(&script, "#!/bin/sh\nexec cat\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    /// A mount table with a writable rootfs and `ro_dir` (canonical)
    /// mounted read-only on top.
    fn table_with_ro(ro_dir: &Path) -> MountTable {
        MountTable::parse(&format!(
            "1 0 0:1 / / rw,relatime - ext4 /dev/a rw\n2 1 0:2 / {} ro,relatime - ext4 /dev/b rw\n",
            mount_point(ro_dir)
        ))
    }

    fn mount_point(p: &Path) -> String {
        std::fs::canonicalize(p)
            .unwrap()
            .display()
            .to_string()
            .replace('\\', "\\134")
            .replace(' ', "\\040")
    }

    #[test]
    fn server_plans_enforce_policy() {
        let dir = tempfile::tempdir().unwrap();
        let script = script_in(dir.path());
        let policy = CommandPolicy {
            roots: vec![dir.path().join("bin")],
            denied: vec![],
            mounts: table_with_ro(dir.path()),
        };
        let sock = Path::new("/run/talon/mcp");
        let home = Path::new("/run/talon/home");
        let mut cfg = ServerConfig::new(script.display().to_string(), ["--x"]);
        cfg.run_as = Some("mcp-siem".into());
        cfg.cwd = Some(PathBuf::from("/workspace/group"));
        let plan = plan_server("siem", &cfg, PASSWD, &policy, sock, home, agent()).unwrap();
        assert_eq!(plan.user, "mcp-siem");
        assert_eq!((plan.uid, plan.gid), (61001, 61001));
        assert_eq!(plan.socket, PathBuf::from("/run/talon/mcp/siem.sock"));
        assert_eq!(plan.home, PathBuf::from("/run/talon/home/siem"));
        let canonical = std::fs::canonicalize(&script).unwrap();
        assert_eq!(plan.config.command, canonical.display().to_string());
        // cwd is the command's directory, never the group folder.
        assert_eq!(plan.config.cwd.as_deref(), canonical.parent());
        assert!(plan.note.is_none());

        // Unknown / invalid runAs -> mcp-default with a note.
        cfg.run_as = Some("mcp-nobody".into());
        let plan = plan_server("siem", &cfg, PASSWD, &policy, sock, home, agent()).unwrap();
        assert_eq!(plan.user, "mcp-default");
        assert!(plan.note.is_some());
        cfg.run_as = Some("root".into());
        assert_eq!(
            plan_server("siem", &cfg, PASSWD, &policy, sock, home, agent())
                .unwrap()
                .user,
            "mcp-default"
        );
        cfg.run_as = None;
        assert_eq!(
            plan_server("siem", &cfg, PASSWD, &policy, sock, home, agent())
                .unwrap()
                .user,
            "mcp-default"
        );

        // Privileged account refused.
        cfg.run_as = Some("mcp-evil".into());
        assert!(plan_server("siem", &cfg, PASSWD, &policy, sock, home, agent()).is_err());
        // Account sharing the agent's ids refused.
        cfg.run_as = Some("mcp-siem".into());
        let clash = AgentIds { uid: 61001, gid: 5 };
        assert!(plan_server("siem", &cfg, PASSWD, &policy, sock, home, clash).is_err());
        // No mcp-default account at all.
        cfg.run_as = None;
        assert!(
            plan_server(
                "siem",
                &cfg,
                "root:x:0:0::/:/bin/sh\n",
                &policy,
                sock,
                home,
                agent()
            )
            .is_err()
        );

        // Command outside the allowed roots / relative / dangerous env.
        cfg.run_as = Some("mcp-siem".into());
        let other = tempfile::tempdir().unwrap();
        assert!(
            plan_server(
                "siem",
                &cfg,
                PASSWD,
                &CommandPolicy {
                    roots: vec![other.path().to_path_buf()],
                    denied: vec![],
                    mounts: table_with_ro(dir.path()),
                },
                sock,
                home,
                agent()
            )
            .is_err()
        );
        let mut rel = cfg.clone();
        rel.command = "server.sh".into();
        assert!(plan_server("siem", &rel, PASSWD, &policy, sock, home, agent()).is_err());
        let mut bad_env = cfg.clone();
        bad_env.env.insert("LD_PRELOAD".into(), "/tmp/x.so".into());
        assert!(plan_server("siem", &bad_env, PASSWD, &policy, sock, home, agent()).is_err());
        // Symlink escaping the root is resolved and refused.
        let link = dir.path().join("bin").join("link.sh");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        let mut linked = cfg.clone();
        linked.command = link.display().to_string();
        assert!(plan_server("siem", &linked, PASSWD, &policy, sock, home, agent()).is_err());
        // Bad server name.
        assert!(plan_server("../x", &cfg, PASSWD, &policy, sock, home, agent()).is_err());
    }

    #[test]
    fn commands_must_be_on_read_only_mounts() {
        let dir = tempfile::tempdir().unwrap();
        let script = script_in(dir.path());
        let canonical = std::fs::canonicalize(&script).unwrap();
        let sock = Path::new("/run/talon/mcp");
        let home = Path::new("/run/talon/home");
        let mut cfg = ServerConfig::new(script.display().to_string(), ["--x"]);
        cfg.run_as = Some("mcp-siem".into());
        let roots = vec![dir.path().join("bin")];
        let plan = |mounts: MountTable| {
            plan_server(
                "siem",
                &cfg,
                PASSWD,
                &CommandPolicy {
                    roots: roots.clone(),
                    denied: vec![],
                    mounts,
                },
                sock,
                home,
                agent(),
            )
        };

        // Read-only mount: allowed.
        assert!(plan(table_with_ro(dir.path())).is_ok());
        // Under an allowed root but on a writable mount: refused.
        let rw = MountTable::parse(&format!(
            "1 0 0:1 / / ro - ext4 /dev/a ro\n2 1 0:2 / {} rw,relatime - ext4 /dev/b rw\n",
            mount_point(dir.path())
        ));
        let err = plan(rw).unwrap_err();
        assert!(err.contains("is not on a read-only mount"), "{err}");
        // A writable file bind-mounted over the command: refused.
        let file_rw = MountTable::parse(&format!(
            "1 0 0:1 / / ro - ext4 /dev/a ro\n2 1 0:2 / {} rw - ext4 /dev/b rw\n",
            mount_point(&canonical)
        ));
        assert!(plan(file_rw).is_err());
        // A writable directory with a read-only command file bound into it
        // (the cwd would be writable): refused.
        let dir_rw = MountTable::parse(&format!(
            "1 0 0:1 / / rw - ext4 /dev/a rw\n2 1 0:2 / {} ro - ext4 /dev/b ro\n",
            mount_point(&canonical)
        ));
        assert!(plan(dir_rw).is_err());
        // No usable mount table: everything is refused (fail closed).
        assert!(plan(MountTable::default()).is_err());
    }

    #[test]
    fn commands_in_agent_writable_project_dirs_are_refused() {
        // Main's project view: read-only as a whole, but `groups/`, `data/`
        // and `store/` are agent-writable through other mounts (N-10).
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let write_script = |rel: &str| {
            let path = project.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "#!/bin/sh\nexec cat\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let good = write_script("mysql/mysql-mcp.sh");
        let lookalike = write_script("groupsX/server.sh");
        let planted = [
            write_script("groups/main/evil.sh"),
            write_script("data/ipc/main/evil.sh"),
            write_script("store/evil.sh"),
        ];
        let denied: Vec<PathBuf> = ["groups", "data", "store"]
            .iter()
            .map(|d| project.join(d))
            .collect();
        let policy = CommandPolicy {
            roots: vec![project.clone()],
            denied: denied.clone(),
            mounts: table_with_ro(&project),
        };
        let sock = Path::new("/run/talon/mcp");
        let home = Path::new("/run/talon/home");
        let plan = |policy: &CommandPolicy, command: &Path| {
            let mut cfg = ServerConfig::new(command.display().to_string(), Vec::<String>::new());
            cfg.run_as = Some("mcp-siem".into());
            plan_server("srv", &cfg, PASSWD, policy, sock, home, agent())
        };

        assert!(plan(&policy, &good).is_ok());
        // Component-wise: `groupsX` is not `groups`.
        assert!(plan(&policy, &lookalike).is_ok());
        for script in &planted {
            let err = plan(&policy, script).unwrap_err();
            assert!(
                err.contains("which agents can write through other mounts"),
                "{err}"
            );
        }
        // A link in an allowed directory into a denied one is resolved and
        // refused.
        let link = project.join("mysql").join("link.sh");
        std::os::unix::fs::symlink(&planted[0], &link).unwrap();
        assert!(plan(&policy, &link).is_err());
        // Denied entries are compared canonicalized too (an alias path for
        // the project still matches).
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&project, &alias).unwrap();
        let aliased = CommandPolicy {
            roots: vec![project.clone()],
            denied: vec![alias.join("groups")],
            mounts: table_with_ro(&project),
        };
        assert!(plan(&aliased, &planted[0]).is_err());
        assert!(plan(&aliased, &good).is_ok());
        // Without the denylist, only the read-only check would apply and
        // the planted script would pass: the denylist is what refuses it.
        let open = CommandPolicy {
            denied: vec![],
            ..policy.clone()
        };
        assert!(plan(&open, &planted[0]).is_ok());
    }

    #[test]
    fn container_policy_denies_agent_writable_project_dirs() {
        let policy = CommandPolicy::container(MountTable::default());
        assert_eq!(
            policy.denied,
            DENIED_MCP_DIRS
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        );
        for path in [
            "/workspace/project/groups/main/tool.sh",
            "/workspace/project/groups",
            "/workspace/project/data/sessions/x/evil.py",
            "/workspace/project/store/messages.db",
        ] {
            assert!(policy.denied_dir_of(Path::new(path)).is_some(), "{path}");
        }
        for path in [
            "/workspace/project/mysql/mysql-mcp.sh",
            "/workspace/project/groupsX/tool.sh",
            "/workspace/project/container/skills/x.sh",
            "/workspace/extra/siem/siem-mcp.sh",
            "/usr/bin/python3",
        ] {
            assert!(policy.denied_dir_of(Path::new(path)).is_none(), "{path}");
        }
        // Every denied directory lies inside an allowed root (otherwise the
        // entry would be pointless).
        assert!(
            policy
                .denied
                .iter()
                .all(|d| policy.roots.iter().any(|r| d.starts_with(r)))
        );
    }

    #[test]
    fn container_policy_allows_main_project_mount() {
        let policy = CommandPolicy::container(MountTable::default());
        assert!(policy.roots.contains(&PathBuf::from("/workspace/project")));
        assert!(policy.roots.contains(&PathBuf::from("/workspace/extra")));
        assert!(
            !policy
                .roots
                .iter()
                .any(|r| r.starts_with("/workspace/group") || r.starts_with("/tmp"))
        );
        // Shaped like main's container: the project is a read-only bind
        // mount, the group folder is writable.
        let mounts = MountTable::parse(
            "10 1 0:1 / / ro,relatime - overlay overlay rw\n\
             11 10 8:1 /srv/talon /workspace/project ro,relatime - ext4 /dev/sda1 rw\n\
             12 10 8:1 /srv/talon/groups/main /workspace/group rw,relatime - ext4 /dev/sda1 rw\n",
        );
        assert!(mounts.is_read_only(Path::new("/workspace/project/mysql/mysql-mcp.sh")));
        assert!(mounts.is_read_only(Path::new("/workspace/project/mysql")));
        assert!(mounts.is_read_only(Path::new("/usr/bin/python3")));
        assert!(!mounts.is_read_only(Path::new("/workspace/group/evil.sh")));
    }

    #[test]
    fn supervise_args_take_a_mountinfo_override() {
        use clap::Parser;
        #[derive(Debug, Parser)]
        struct Cli {
            #[command(flatten)]
            supervise: SuperviseArgs,
        }
        let cfg = Cli::try_parse_from(["t"]).unwrap().supervise.into_config();
        assert_eq!(cfg.mountinfo_file, PathBuf::from(DEFAULT_MOUNTINFO));
        let cfg = Cli::try_parse_from(["t", "--mountinfo-file", "/x/mi"])
            .unwrap()
            .supervise
            .into_config();
        assert_eq!(cfg.mountinfo_file, PathBuf::from("/x/mi"));
    }

    #[test]
    fn env_overrides_and_exit_codes() {
        let o = server_env_overrides(Path::new("/run/talon/home/siem"));
        assert!(o.contains(&("HOME".into(), "/run/talon/home/siem".into())));
        assert!(o.contains(&("PYTHONSAFEPATH".into(), "1".into())));
        assert!(o.contains(&("PYTHONDONTWRITEBYTECODE".into(), "1".into())));
        assert_eq!(exit_code(&ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(&ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(&ExitStatus::from_raw(9)), 137);
    }

    fn own_ids() -> AgentIds {
        AgentIds {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        }
    }

    #[test]
    fn prepare_dir_secures_directories() {
        let dir = tempfile::tempdir().unwrap();
        let ids = own_ids();
        let d = dir.path().join("a").join("mcp");
        prepare_dir(&d, 0o750, ids.uid, ids.gid).unwrap();
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        prepare_dir(&d, 0o700, ids.uid, ids.gid).unwrap();
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let f = dir.path().join("file");
        std::fs::write(&f, "").unwrap();
        assert!(prepare_dir(&f, 0o700, ids.uid, ids.gid).is_err());
        let l = dir.path().join("link");
        std::os::unix::fs::symlink(&d, &l).unwrap();
        assert!(prepare_dir(&l, 0o700, ids.uid, ids.gid).is_err());
    }

    #[tokio::test]
    async fn socket_accepts_one_connection_then_disappears() {
        let dir = tempfile::tempdir().unwrap();
        let ids = own_ids();
        let path = dir.path().join("siem.sock");
        std::fs::write(&path, "stale").unwrap();
        let listener = bind_socket(&path, ids).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (stdin_w, stdin_r) = tokio::io::duplex(1024);
        let (mut stdout_w, stdout_r) = tokio::io::duplex(1024);
        let task = tokio::spawn(serve_socket(
            listener,
            path.clone(),
            stdin_w,
            stdout_r,
            ids,
            "siem".into(),
        ));
        let client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (client_r, mut client_w) = client.into_split();
        client_w.write_all(b"{\"id\":1}\n").await.unwrap();
        let mut server_in = BufReader::new(stdin_r).lines();
        assert_eq!(server_in.next_line().await.unwrap().unwrap(), "{\"id\":1}");
        // Unlinked after the single accept.
        assert!(std::fs::symlink_metadata(&path).is_err());
        assert!(tokio::net::UnixStream::connect(&path).await.is_err());
        stdout_w.write_all(b"{\"result\":{}}\n").await.unwrap();
        let mut client_lines = BufReader::new(client_r).lines();
        assert_eq!(
            client_lines.next_line().await.unwrap().unwrap(),
            "{\"result\":{}}"
        );
        drop(stdout_w);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn foreign_peers_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.sock");
        let mut ids = own_ids();
        let listener = bind_socket(&path, ids).unwrap();
        // Pretend the agent is someone else (unless we are root, who is
        // always accepted).
        ids.uid = ids.uid.wrapping_add(4242);
        let (stdin_w, stdin_r) = tokio::io::duplex(64);
        let (_stdout_w, stdout_r) = tokio::io::duplex(64);
        let task = tokio::spawn(serve_socket(
            listener,
            path.clone(),
            stdin_w,
            stdout_r,
            ids,
            "x".into(),
        ));
        let _client = tokio::net::UnixStream::connect(&path).await.unwrap();
        if rustix::process::getuid().is_root() {
            task.abort();
            return;
        }
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        let mut lines = BufReader::new(stdin_r).lines();
        assert!(lines.next_line().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn stderr_pump_handles_partial_and_long_lines() {
        let data = format!("first\nsecond partial{}\nlast", "x".repeat(10_000));
        pump_stderr("srv".into(), data.as_bytes()).await;
    }
}
