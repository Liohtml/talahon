//! Container runtime abstraction.
//!
//! Everything runtime-specific lives here: which binary to call
//! (`docker` / `podman`), how to check it is up, how to find and stop
//! orphaned Talon containers (by the `talon.managed=true` label instead of a
//! name prefix), how containers reach the host, which host address the
//! LLM gateway should bind to so that `host.docker.internal` reaches it, and
//! the dedicated agent network ([`AGENT_NETWORK`], MYTH-05).
//!
//! All external commands go through the injectable [`CommandExecutor`] so the
//! behaviour is unit-testable without a container daemon. Arguments are always
//! passed as an argv vector — never through a shell.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use talon_core::{Error, Result};

/// Label every Talon-launched container carries (`--label`).
pub const MANAGED_LABEL: &str = "talon.managed=true";

/// Label key recording the owning group folder.
pub const GROUP_LABEL_KEY: &str = "talon.group";

/// Hostname containers use to reach the host machine.
pub const HOST_GATEWAY_NAME: &str = "host.docker.internal";

/// Dedicated bridge network for agent containers (MYTH-05): inter-container
/// communication disabled, fixed bridge interface [`AGENT_BRIDGE_NAME`] for
/// host egress firewall rules (`talon setup egress`).
pub const AGENT_NETWORK: &str = "talon-agents";

/// Linux bridge interface of [`AGENT_NETWORK`].
pub const AGENT_BRIDGE_NAME: &str = "br-talon";

/// Docker bridge driver option controlling inter-container communication.
pub const ICC_OPTION: &str = "com.docker.network.bridge.enable_icc";

/// Bridge driver option naming the Linux bridge interface.
pub const BRIDGE_NAME_OPTION: &str = "com.docker.network.bridge.name";

/// `docker info` timeout.
const INFO_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for short query commands (`ps`, `network inspect`, `ip`).
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
/// Grace period used when stopping orphans left behind by a previous host
/// process (nobody is listening to their output any more).
const ORPHAN_STOP_GRACE: Duration = Duration::from_secs(3);
/// Extra time on top of the stop grace before the `stop` command itself is
/// considered hung.
const STOP_COMMAND_SLACK: Duration = Duration::from_secs(15);
/// Max bytes of command output retained.
const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;

/// Which container engine the binary talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    /// Docker Engine / Docker Desktop.
    Docker,
    /// Podman (rootful or rootless).
    Podman,
}

impl RuntimeKind {
    /// Infer the engine from a binary path or name (`podman` anywhere in the
    /// file name => Podman, everything else => Docker).
    pub fn from_binary(bin: &str) -> Self {
        let name = Path::new(bin)
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if name.contains("podman") {
            RuntimeKind::Podman
        } else {
            RuntimeKind::Docker
        }
    }

    /// Name of the default bridge network for this engine.
    pub fn default_network(&self) -> &'static str {
        match self {
            RuntimeKind::Docker => "bridge",
            RuntimeKind::Podman => "podman",
        }
    }
}

/// Host operating system, which decides host-gateway handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    /// Linux: `host.docker.internal` must be added explicitly and the gateway
    /// should bind the bridge address.
    Linux,
    /// macOS: Docker Desktop provides `host.docker.internal` and forwards it
    /// to the host loopback.
    MacOs,
    /// Anything else (treated like macOS: no extra flags, loopback bind).
    Other,
}

impl HostPlatform {
    /// The platform this binary was compiled for.
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            HostPlatform::Linux
        } else if cfg!(target_os = "macos") {
            HostPlatform::MacOs
        } else {
            HostPlatform::Other
        }
    }
}

/// Captured result of an external command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit code (`None` when killed by a signal).
    pub status: Option<i32>,
    /// Captured stdout (lossy UTF-8, capped).
    pub stdout: String,
    /// Captured stderr (lossy UTF-8, capped).
    pub stderr: String,
}

impl CommandOutput {
    /// Exit code 0.
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    /// Convenience constructor for tests and fakes.
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// Convenience constructor for a failed command.
    pub fn failed(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            status: Some(code),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

/// Runs short-lived external commands (argv, no shell).
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Run `program args...` with stdin closed, capturing output. Must kill
    /// the process and return `ErrorKind::TimedOut` after `timeout`.
    async fn run(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> io::Result<CommandOutput>;
}

/// [`CommandExecutor`] backed by `tokio::process`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioCommandExecutor;

fn lossy_capped(bytes: &[u8]) -> String {
    let slice = if bytes.len() > MAX_COMMAND_OUTPUT {
        &bytes[..MAX_COMMAND_OUTPUT]
    } else {
        bytes
    };
    String::from_utf8_lossy(slice).into_owned()
}

#[async_trait]
impl CommandExecutor for TokioCommandExecutor {
    async fn run(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> io::Result<CommandOutput> {
        let child = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(out) => {
                let out = out?;
                Ok(CommandOutput {
                    status: out.status.code(),
                    stdout: lossy_capped(&out.stdout),
                    stderr: lossy_capped(&out.stderr),
                })
            }
            // Dropping the future drops the child; kill_on_drop reaps it.
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{program} timed out after {}s", timeout.as_secs()),
            )),
        }
    }
}

/// `true` when `name` is safe to pass as a container name argument
/// (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$` — never starts with `-`).
pub fn is_valid_container_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    name.len() <= 128 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Argument vector for a graceful stop (`stop -t <secs> <name>`).
pub fn stop_args(name: &str, grace: Duration) -> Vec<String> {
    vec![
        "stop".to_string(),
        "-t".to_string(),
        grace.as_secs().to_string(),
        name.to_string(),
    ]
}

/// Argument vector for a forced kill (`kill <name>`, SIGKILL).
pub fn kill_args(name: &str) -> Vec<String> {
    vec!["kill".to_string(), name.to_string()]
}

/// Argument vector listing running Talon containers by label.
pub fn list_managed_args() -> Vec<String> {
    vec![
        "ps".to_string(),
        "--filter".to_string(),
        format!("label={MANAGED_LABEL}"),
        "--format".to_string(),
        "{{.Names}}".to_string(),
    ]
}

/// Argument vector inspecting a network (`network inspect <name>`).
pub fn network_inspect_args(name: &str) -> Vec<String> {
    vec![
        "network".to_string(),
        "inspect".to_string(),
        name.to_string(),
    ]
}

/// Argument vector creating the agent network:
///
/// - docker: `network create --driver bridge --opt
///   com.docker.network.bridge.enable_icc=false --opt
///   com.docker.network.bridge.name=br-talon --label talon.managed=true <name>`
/// - podman: the same without `enable_icc` (netavark has no equivalent and
///   rejects unknown bridge options).
pub fn agent_network_create_args(kind: RuntimeKind, name: &str) -> Vec<String> {
    let mut args: Vec<String> = ["network", "create", "--driver", "bridge"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if kind == RuntimeKind::Docker {
        args.push("--opt".to_string());
        args.push(format!("{ICC_OPTION}=false"));
    }
    args.push("--opt".to_string());
    args.push(format!("{BRIDGE_NAME_OPTION}={AGENT_BRIDGE_NAME}"));
    args.push("--label".to_string());
    args.push(MANAGED_LABEL.to_string());
    args.push(name.to_string());
    args
}

/// Problems with an existing network that [`ContainerRuntime::ensure_agent_network`]
/// did not create (reported as warnings; the operator owns that network).
pub fn existing_network_warnings(kind: RuntimeKind, inspect_json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(inspect_json) else {
        return vec!["network inspect output is not JSON".to_string()];
    };
    let net = match &value {
        serde_json::Value::Array(items) => match items.first() {
            Some(first) => first,
            None => return vec!["network inspect returned no network".to_string()],
        },
        other => other,
    };
    let mut warnings = Vec::new();
    let driver = net
        .get("Driver")
        .or_else(|| net.get("driver"))
        .and_then(|d| d.as_str())
        .unwrap_or_default();
    if driver != "bridge" {
        warnings.push(format!("driver is {driver:?}, expected \"bridge\""));
    }
    if kind == RuntimeKind::Docker {
        let icc = net
            .pointer("/Options")
            .and_then(|o| o.get(ICC_OPTION))
            .and_then(|v| v.as_str());
        if icc != Some("false") {
            warnings.push(format!(
                "{ICC_OPTION} is not \"false\": agent containers can reach each other"
            ));
        }
    }
    warnings
}

fn validate_binary(bin: &str) -> Result<()> {
    let ok = !bin.is_empty()
        && bin.len() <= 4096
        && !bin.starts_with('-')
        && !bin.chars().any(|c| c.is_control() || c.is_whitespace());
    if ok {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "invalid container runtime binary {bin:?}"
        )))
    }
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Resolve `name` against `path_var` (a `PATH`-style list). Names containing
/// a `/` are checked directly.
pub fn resolve_executable(name: &str, path_var: Option<OsString>) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return is_executable_file(&p).then_some(p);
    }
    let path_var = path_var?;
    std::env::split_paths(&path_var)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable_file(candidate))
}

/// The container runtime used to launch and manage agent containers.
#[derive(Clone)]
pub struct ContainerRuntime {
    bin: String,
    kind: RuntimeKind,
    platform: HostPlatform,
    exec: Arc<dyn CommandExecutor>,
}

impl fmt::Debug for ContainerRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainerRuntime")
            .field("bin", &self.bin)
            .field("kind", &self.kind)
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

impl ContainerRuntime {
    /// Use `bin` (name or path) as-is, without checking that it exists.
    pub fn new(bin: impl Into<String>) -> Result<Self> {
        let bin = bin.into();
        validate_binary(&bin)?;
        Ok(Self {
            kind: RuntimeKind::from_binary(&bin),
            bin,
            platform: HostPlatform::current(),
            exec: Arc::new(TokioCommandExecutor),
        })
    }

    /// Find the preferred runtime (`docker` / `podman` / a path) on `PATH`,
    /// falling back to the other engine. The resolved absolute path is used
    /// afterwards so later `PATH` changes cannot redirect it.
    pub fn detect(preferred: &str) -> Result<Self> {
        Self::detect_in(preferred, std::env::var_os("PATH"))
    }

    /// [`Self::detect`] against an explicit `PATH` value (testable).
    pub fn detect_in(preferred: &str, path_var: Option<OsString>) -> Result<Self> {
        validate_binary(preferred)?;
        let mut candidates = vec![preferred.to_string()];
        if !preferred.contains('/') {
            for alt in ["docker", "podman"] {
                if !candidates.iter().any(|c| c == alt) {
                    candidates.push(alt.to_string());
                }
            }
        }
        for candidate in &candidates {
            if let Some(path) = resolve_executable(candidate, path_var.clone()) {
                let path_str = path.to_string_lossy().into_owned();
                if candidate != preferred {
                    tracing::warn!(
                        preferred,
                        using = %path_str,
                        "preferred container runtime not found, falling back"
                    );
                }
                let mut rt = Self::new(path_str)?;
                rt.kind = RuntimeKind::from_binary(candidate);
                return Ok(rt);
            }
        }
        Err(Error::Container(format!(
            "no container runtime found on PATH (tried {})",
            candidates.join(", ")
        )))
    }

    /// Replace the command executor (tests, instrumentation).
    pub fn with_executor(mut self, exec: Arc<dyn CommandExecutor>) -> Self {
        self.exec = exec;
        self
    }

    /// Override the detected host platform (tests).
    pub fn with_platform(mut self, platform: HostPlatform) -> Self {
        self.platform = platform;
        self
    }

    /// Override the engine kind (e.g. `docker` shim that is really podman).
    pub fn with_kind(mut self, kind: RuntimeKind) -> Self {
        self.kind = kind;
        self
    }

    /// Binary invoked for every runtime command.
    pub fn bin(&self) -> &str {
        &self.bin
    }

    /// Engine kind.
    pub fn kind(&self) -> RuntimeKind {
        self.kind
    }

    /// Host platform.
    pub fn platform(&self) -> HostPlatform {
        self.platform
    }

    async fn exec(&self, args: &[String], timeout: Duration) -> io::Result<CommandOutput> {
        self.exec.run(&self.bin, args, timeout).await
    }

    /// Fail unless `<bin> info` succeeds (the daemon is reachable).
    pub async fn ensure_running(&self) -> Result<()> {
        let args = vec!["info".to_string()];
        let failure = match self.exec(&args, INFO_TIMEOUT).await {
            Ok(out) if out.success() => {
                tracing::debug!("Container runtime already running");
                return Ok(());
            }
            Ok(out) => format!(
                "exit code {:?}: {}",
                out.status,
                out.stderr.trim().chars().take(500).collect::<String>()
            ),
            Err(e) => e.to_string(),
        };
        tracing::error!(bin = %self.bin, error = %failure, "Failed to reach container runtime");
        Err(Error::Container(format!(
            "Container runtime is required but failed to start ({}: {failure}). \
             Ensure the runtime is installed and running (`{} info`).",
            self.bin, self.bin
        )))
    }

    /// Stop every running container labelled `talon.managed=true` (left over
    /// from a previous host process). Never fails: problems are logged.
    /// Returns the names that were found.
    pub async fn cleanup_orphans(&self) -> Vec<String> {
        let out = match self.exec(&list_managed_args(), QUERY_TIMEOUT).await {
            Ok(out) if out.success() => out,
            Ok(out) => {
                tracing::warn!(
                    status = ?out.status,
                    stderr = %out.stderr.trim(),
                    "Failed to clean up orphaned containers"
                );
                return Vec::new();
            }
            Err(err) => {
                tracing::warn!(%err, "Failed to clean up orphaned containers");
                return Vec::new();
            }
        };
        let names: Vec<String> = out
            .stdout
            .lines()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .filter(|n| {
                let ok = is_valid_container_name(n);
                if !ok {
                    tracing::warn!(name = %n, "ignoring unexpected container name from runtime");
                }
                ok
            })
            .map(str::to_string)
            .collect();
        for name in &names {
            if let Err(err) = self.stop(name, ORPHAN_STOP_GRACE).await {
                tracing::debug!(%name, %err, "orphan already stopped");
            }
        }
        if !names.is_empty() {
            tracing::info!(count = names.len(), names = ?names, "Stopped orphaned containers");
        }
        names
    }

    /// Graceful stop: SIGTERM, then SIGKILL after `grace`.
    pub async fn stop(&self, name: &str, grace: Duration) -> Result<()> {
        if !is_valid_container_name(name) {
            return Err(Error::invalid(format!("invalid container name {name:?}")));
        }
        let out = self
            .exec(&stop_args(name, grace), grace + STOP_COMMAND_SLACK)
            .await
            .map_err(|e| Error::Container(format!("{} stop {name}: {e}", self.bin)))?;
        if out.success() {
            Ok(())
        } else {
            Err(Error::Container(format!(
                "{} stop {name} failed ({:?}): {}",
                self.bin,
                out.status,
                out.stderr.trim()
            )))
        }
    }

    /// Immediate SIGKILL.
    pub async fn kill(&self, name: &str) -> Result<()> {
        if !is_valid_container_name(name) {
            return Err(Error::invalid(format!("invalid container name {name:?}")));
        }
        let out = self
            .exec(&kill_args(name), QUERY_TIMEOUT)
            .await
            .map_err(|e| Error::Container(format!("{} kill {name}: {e}", self.bin)))?;
        if out.success() {
            Ok(())
        } else {
            Err(Error::Container(format!(
                "{} kill {name} failed ({:?}): {}",
                self.bin,
                out.status,
                out.stderr.trim()
            )))
        }
    }

    /// Create the agent network `name` (normally [`AGENT_NETWORK`]) unless it
    /// already exists: a bridge with inter-container communication disabled
    /// (docker), bridge interface [`AGENT_BRIDGE_NAME`] and the
    /// `talon.managed=true` label. On podman `enable_icc` is unsupported and
    /// skipped with a warning. An existing network is kept as-is; settings
    /// that weaken isolation are logged. Concurrent creation is tolerated.
    ///
    /// `host.docker.internal:host-gateway` keeps working on the custom
    /// network: `host-gateway` resolves to the daemon's host-gateway IP and
    /// traffic to that host address is routed to the host, not forwarded
    /// between bridges.
    pub async fn ensure_agent_network(&self, name: &str) -> Result<()> {
        crate::args::validate_network(name).map_err(|reason| {
            Error::Config(format!("invalid agent network name {name:?}: {reason}"))
        })?;
        let inspect = network_inspect_args(name);
        match self.exec(&inspect, QUERY_TIMEOUT).await {
            Ok(out) if out.success() => {
                if name != "none" {
                    for warning in existing_network_warnings(self.kind, &out.stdout) {
                        tracing::warn!(network = name, "{warning}");
                    }
                }
                tracing::debug!(network = name, "agent network already exists");
                return Ok(());
            }
            Ok(_) => {}
            Err(err) => {
                return Err(Error::Container(format!(
                    "{} network inspect {name}: {err}",
                    self.bin
                )));
            }
        }
        if self.kind == RuntimeKind::Podman {
            tracing::warn!(
                network = name,
                "podman cannot disable inter-container communication on a bridge; \
                 agent containers on this network can reach each other"
            );
        }
        let create = agent_network_create_args(self.kind, name);
        let out = self
            .exec(&create, QUERY_TIMEOUT)
            .await
            .map_err(|e| Error::Container(format!("{} network create {name}: {e}", self.bin)))?;
        if out.success() {
            tracing::info!(
                network = name,
                bridge = AGENT_BRIDGE_NAME,
                "created agent network"
            );
            return Ok(());
        }
        // Lost a creation race? Then the network exists now.
        if out.stderr.to_ascii_lowercase().contains("already exists") {
            if let Ok(again) = self.exec(&inspect, QUERY_TIMEOUT).await {
                if again.success() {
                    return Ok(());
                }
            }
        }
        Err(Error::Container(format!(
            "{} network create {name} failed ({:?}): {}",
            self.bin,
            out.status,
            out.stderr.trim().chars().take(500).collect::<String>()
        )))
    }

    /// Extra `run` arguments so the container can resolve the host. On Linux
    /// `host.docker.internal` is not built in and is mapped to the bridge
    /// gateway; Docker Desktop (macOS) provides it.
    pub fn host_gateway_args(&self) -> Vec<String> {
        match self.platform {
            HostPlatform::Linux => vec![
                "--add-host".to_string(),
                format!("{HOST_GATEWAY_NAME}:host-gateway"),
            ],
            HostPlatform::MacOs | HostPlatform::Other => Vec::new(),
        }
    }

    /// Address the host-side LLM gateway should bind so that containers can
    /// reach it as `host.docker.internal` without exposing it on every
    /// interface.
    ///
    /// - macOS / other: `127.0.0.1` (Docker Desktop forwards to loopback).
    /// - Linux: the default bridge gateway from `<bin> network inspect`
    ///   (docker: `bridge`, podman: `podman`), then the `docker0` interface
    ///   address, each only if it is actually bindable on this host; finally
    ///   `127.0.0.1` (fail closed — never `0.0.0.0`) with a warning.
    pub async fn detect_gateway_bind_addr(&self) -> IpAddr {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        if self.platform != HostPlatform::Linux {
            return loopback;
        }

        let networks = match self.kind {
            RuntimeKind::Docker => ["bridge", "podman"],
            RuntimeKind::Podman => ["podman", "bridge"],
        };
        for network in networks {
            let args = vec![
                "network".to_string(),
                "inspect".to_string(),
                network.to_string(),
            ];
            match self.exec(&args, QUERY_TIMEOUT).await {
                Ok(out) if out.success() => {
                    for ip in parse_network_gateways(&out.stdout) {
                        if is_bindable(ip) {
                            tracing::debug!(%ip, network, "gateway bind address from bridge network");
                            return ip;
                        }
                        tracing::debug!(%ip, network, "bridge gateway not bindable on this host");
                    }
                }
                Ok(out) => {
                    tracing::debug!(network, status = ?out.status, "network inspect failed");
                }
                Err(err) => tracing::debug!(network, %err, "network inspect failed"),
            }
        }

        let args: Vec<String> = ["-4", "-o", "addr", "show", "dev", "docker0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if let Ok(out) = self.exec.run("ip", &args, QUERY_TIMEOUT).await {
            if out.success() {
                if let Some(ip) = parse_ip_addr_output(&out.stdout) {
                    if is_bindable(ip) {
                        tracing::debug!(%ip, "gateway bind address from docker0");
                        return ip;
                    }
                }
            }
        }

        tracing::warn!(
            "could not detect the container bridge address; binding the LLM gateway to 127.0.0.1 \
             (containers may not reach it — set TALON_LLM_GATEWAY_BIND explicitly)"
        );
        loopback
    }
}

/// Free-function form of [`ContainerRuntime::detect_gateway_bind_addr`].
pub async fn detect_gateway_bind_addr(runtime: &ContainerRuntime) -> IpAddr {
    runtime.detect_gateway_bind_addr().await
}

/// `true` when a TCP socket can be bound to `ip` on this host.
pub fn is_bindable(ip: IpAddr) -> bool {
    TcpListener::bind(SocketAddr::new(ip, 0)).is_ok()
}

fn first_host_of_subnet(subnet: &str) -> Option<IpAddr> {
    let (addr, prefix) = subnet.split_once('/')?;
    let addr: Ipv4Addr = addr.trim().parse().ok()?;
    let prefix: u32 = prefix.trim().parse().ok()?;
    if prefix > 30 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(addr) & mask;
    Some(IpAddr::V4(Ipv4Addr::from(network.checked_add(1)?)))
}

/// Extract gateway addresses from `docker network inspect` /
/// `podman network inspect` JSON. IPv4 addresses come first.
pub fn parse_network_gateways(json: &str) -> Vec<IpAddr> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let networks: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    let mut out: Vec<IpAddr> = Vec::new();
    let mut push = |ip: IpAddr| {
        if !out.contains(&ip) {
            out.push(ip);
        }
    };
    for net in networks {
        // Docker: [{"IPAM": {"Config": [{"Subnet": "...", "Gateway": "..."}]}}]
        if let Some(configs) = net.pointer("/IPAM/Config").and_then(|c| c.as_array()) {
            for cfg in configs {
                let gw = cfg
                    .get("Gateway")
                    .and_then(|g| g.as_str())
                    .and_then(|g| g.trim().parse::<IpAddr>().ok());
                match gw {
                    Some(ip) => push(ip),
                    None => {
                        if let Some(ip) = cfg
                            .get("Subnet")
                            .and_then(|s| s.as_str())
                            .and_then(first_host_of_subnet)
                        {
                            push(ip);
                        }
                    }
                }
            }
        }
        // Podman: [{"subnets": [{"subnet": "...", "gateway": "..."}]}]
        if let Some(subnets) = net.get("subnets").and_then(|s| s.as_array()) {
            for sub in subnets {
                if let Some(ip) = sub
                    .get("gateway")
                    .and_then(|g| g.as_str())
                    .and_then(|g| g.trim().parse::<IpAddr>().ok())
                {
                    push(ip);
                }
            }
        }
    }
    out.sort_by_key(|ip| !ip.is_ipv4());
    out
}

/// Parse the first IPv4 address from `ip -4 -o addr show dev <if>` output.
pub fn parse_ip_addr_output(output: &str) -> Option<IpAddr> {
    let mut tokens = output.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "inet" {
            let cidr = tokens.next()?;
            let addr = cidr.split('/').next()?;
            return addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4);
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod testing {
    //! Scriptable [`CommandExecutor`] fake.

    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex;
    use std::time::Duration;

    use async_trait::async_trait;

    use super::{CommandExecutor, CommandOutput};

    type Hook = Box<dyn Fn(&str, &[String]) + Send + Sync>;

    /// Records every call and answers from a queue of scripted responses
    /// (default: success with empty output).
    #[derive(Default)]
    pub struct FakeExecutor {
        pub calls: Mutex<Vec<(String, Vec<String>)>>,
        pub responses: Mutex<VecDeque<io::Result<CommandOutput>>>,
        pub hook: Mutex<Option<Hook>>,
    }

    impl FakeExecutor {
        pub fn push(&self, r: io::Result<CommandOutput>) {
            self.responses.lock().unwrap().push_back(r);
        }

        pub fn set_hook(&self, hook: impl Fn(&str, &[String]) + Send + Sync + 'static) {
            *self.hook.lock().unwrap() = Some(Box::new(hook));
        }

        pub fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }

        pub fn subcommands(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .map(|(_, a)| a.first().cloned().unwrap_or_default())
                .collect()
        }
    }

    #[async_trait]
    impl CommandExecutor for FakeExecutor {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            _timeout: Duration,
        ) -> io::Result<CommandOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            if let Some(h) = self.hook.lock().unwrap().as_ref() {
                h(program, args);
            }
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(CommandOutput::ok("")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeExecutor;
    use super::*;

    fn rt(exec: &Arc<FakeExecutor>) -> ContainerRuntime {
        ContainerRuntime::new("docker")
            .unwrap()
            .with_executor(exec.clone())
            .with_platform(HostPlatform::Linux)
    }

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // --- pure functions ---

    #[test]
    fn stop_args_use_grace_and_name() {
        assert_eq!(
            stop_args("talon-test-123", Duration::from_secs(10)),
            sv(&["stop", "-t", "10", "talon-test-123"])
        );
        assert_eq!(kill_args("x1"), sv(&["kill", "x1"]));
    }

    #[test]
    fn container_name_validation() {
        assert!(is_valid_container_name("talon-main-1700000000000"));
        assert!(is_valid_container_name("a.b_c-d"));
        assert!(!is_valid_container_name("-rm"));
        assert!(!is_valid_container_name(""));
        assert!(!is_valid_container_name("a b"));
        assert!(!is_valid_container_name("a;rm"));
        assert!(!is_valid_container_name(&"a".repeat(129)));
    }

    #[test]
    fn runtime_kind_from_binary() {
        assert_eq!(RuntimeKind::from_binary("docker"), RuntimeKind::Docker);
        assert_eq!(
            RuntimeKind::from_binary("/usr/bin/podman"),
            RuntimeKind::Podman
        );
        assert_eq!(RuntimeKind::Podman.default_network(), "podman");
        assert!(ContainerRuntime::new("--privileged").is_err());
        assert!(ContainerRuntime::new("doc ker").is_err());
        assert!(ContainerRuntime::new("").is_err());
    }

    #[test]
    fn host_gateway_args_per_platform() {
        let exec = Arc::new(FakeExecutor::default());
        assert_eq!(
            rt(&exec).host_gateway_args(),
            sv(&["--add-host", "host.docker.internal:host-gateway"])
        );
        assert!(
            rt(&exec)
                .with_platform(HostPlatform::MacOs)
                .host_gateway_args()
                .is_empty()
        );
    }

    // --- ensure_running ---

    #[tokio::test]
    async fn ensure_running_ok_when_info_succeeds() {
        let exec = Arc::new(FakeExecutor::default());
        rt(&exec).ensure_running().await.unwrap();
        assert_eq!(exec.calls(), vec![("docker".to_string(), sv(&["info"]))]);
    }

    #[tokio::test]
    async fn ensure_running_errors_when_info_fails() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Cannot connect to the Docker daemon",
        )));
        let err = rt(&exec).ensure_running().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("Container runtime is required but failed to start")
        );

        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::failed(1, "daemon down")));
        assert!(rt(&exec).ensure_running().await.is_err());
    }

    // --- cleanup_orphans ---

    #[tokio::test]
    async fn cleanup_stops_orphans_by_label() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::ok(
            "talon-group1-111\ntalon-group2-222\n",
        )));
        let names = rt(&exec).cleanup_orphans().await;
        assert_eq!(names, sv(&["talon-group1-111", "talon-group2-222"]));
        let calls = exec.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1, list_managed_args());
        assert!(calls[0].1.contains(&"label=talon.managed=true".to_string()));
        assert_eq!(calls[1].1, stop_args("talon-group1-111", ORPHAN_STOP_GRACE));
        assert_eq!(calls[2].1, stop_args("talon-group2-222", ORPHAN_STOP_GRACE));
    }

    #[tokio::test]
    async fn cleanup_noop_without_orphans() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::ok("")));
        assert!(rt(&exec).cleanup_orphans().await.is_empty());
        assert_eq!(exec.calls().len(), 1);
    }

    #[tokio::test]
    async fn cleanup_warns_and_continues_when_ps_fails() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Err(io::Error::other("docker not available")));
        assert!(rt(&exec).cleanup_orphans().await.is_empty());
        assert_eq!(exec.calls().len(), 1);
    }

    #[tokio::test]
    async fn cleanup_continues_when_one_stop_fails() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::ok("talon-a-1\ntalon-b-2\n")));
        exec.push(Ok(CommandOutput::failed(1, "already stopped")));
        exec.push(Ok(CommandOutput::ok("")));
        let names = rt(&exec).cleanup_orphans().await;
        assert_eq!(names.len(), 2);
        assert_eq!(exec.calls().len(), 3);
    }

    #[tokio::test]
    async fn cleanup_ignores_hostile_names() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::ok("--all\ntalon-ok-1\n")));
        let names = rt(&exec).cleanup_orphans().await;
        assert_eq!(names, sv(&["talon-ok-1"]));
        assert_eq!(exec.calls().len(), 2);
    }

    #[tokio::test]
    async fn stop_and_kill_validate_names_and_report_failures() {
        let exec = Arc::new(FakeExecutor::default());
        let r = rt(&exec);
        assert!(r.stop("-v", Duration::from_secs(1)).await.is_err());
        assert!(r.kill("-v").await.is_err());
        assert!(exec.calls().is_empty());
        exec.push(Ok(CommandOutput::failed(1, "No such container")));
        assert!(r.stop("talon-x-1", Duration::from_secs(1)).await.is_err());
        r.kill("talon-x-1").await.unwrap();
        assert_eq!(exec.subcommands(), sv(&["stop", "kill"]));
    }

    // --- agent network (MYTH-05) ---

    #[tokio::test]
    async fn ensure_agent_network_creates_isolated_bridge() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::failed(1, "Error: No such network")));
        rt(&exec).ensure_agent_network(AGENT_NETWORK).await.unwrap();
        let calls = exec.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, sv(&["network", "inspect", "talon-agents"]));
        assert_eq!(
            calls[1].1,
            sv(&[
                "network",
                "create",
                "--driver",
                "bridge",
                "--opt",
                "com.docker.network.bridge.enable_icc=false",
                "--opt",
                "com.docker.network.bridge.name=br-talon",
                "--label",
                "talon.managed=true",
                "talon-agents",
            ])
        );
    }

    #[tokio::test]
    async fn ensure_agent_network_keeps_existing_network() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::ok(
            r#"[{"Name":"talon-agents","Driver":"bridge","Options":{"com.docker.network.bridge.enable_icc":"false"}}]"#,
        )));
        rt(&exec).ensure_agent_network(AGENT_NETWORK).await.unwrap();
        assert_eq!(exec.subcommands(), sv(&["network"]));
        assert!(
            existing_network_warnings(
                RuntimeKind::Docker,
                r#"[{"Driver":"bridge","Options":{"com.docker.network.bridge.enable_icc":"false"}}]"#
            )
            .is_empty()
        );
        let warnings = existing_network_warnings(
            RuntimeKind::Docker,
            r#"[{"Driver":"overlay","Options":{}}]"#,
        );
        assert_eq!(warnings.len(), 2);
        // Podman has no ICC switch: only the driver is checked.
        assert!(
            existing_network_warnings(RuntimeKind::Podman, r#"[{"driver":"bridge"}]"#).is_empty()
        );
        assert_eq!(existing_network_warnings(RuntimeKind::Docker, "x").len(), 1);
    }

    #[tokio::test]
    async fn ensure_agent_network_podman_skips_icc_option() {
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::failed(125, "network not found")));
        let r = ContainerRuntime::new("podman")
            .unwrap()
            .with_executor(exec.clone())
            .with_platform(HostPlatform::Linux);
        r.ensure_agent_network("talon-agents").await.unwrap();
        let create = &exec.calls()[1].1;
        assert!(!create.iter().any(|a| a.contains("enable_icc")));
        assert!(create.contains(&"com.docker.network.bridge.name=br-talon".to_string()));
        assert_eq!(create.last().map(String::as_str), Some("talon-agents"));
    }

    #[tokio::test]
    async fn ensure_agent_network_race_and_failures() {
        // Lost the creation race: the re-inspect finds it.
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::failed(1, "No such network")));
        exec.push(Ok(CommandOutput::failed(
            1,
            "Error response from daemon: network with name talon-agents already exists",
        )));
        exec.push(Ok(CommandOutput::ok("[]")));
        rt(&exec).ensure_agent_network(AGENT_NETWORK).await.unwrap();
        assert_eq!(exec.calls().len(), 3);

        // Other create failures are errors.
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Ok(CommandOutput::failed(1, "No such network")));
        exec.push(Ok(CommandOutput::failed(1, "bridge name br-talon in use")));
        let err = rt(&exec)
            .ensure_agent_network(AGENT_NETWORK)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("br-talon in use"));

        // The runtime being unreachable is an error, not a create attempt.
        let exec = Arc::new(FakeExecutor::default());
        exec.push(Err(io::Error::other("daemon down")));
        assert!(rt(&exec).ensure_agent_network(AGENT_NETWORK).await.is_err());
        assert_eq!(exec.calls().len(), 1);

        // Invalid names never reach the runtime.
        let exec = Arc::new(FakeExecutor::default());
        for bad in ["host", "-x", "container:abc", ""] {
            assert!(rt(&exec).ensure_agent_network(bad).await.is_err());
        }
        assert!(exec.calls().is_empty());
    }

    // --- detection ---

    #[test]
    fn detect_prefers_requested_then_falls_back() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let podman = dir.path().join("podman");
        std::fs::write(&podman, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&podman, std::fs::Permissions::from_mode(0o755)).unwrap();
        // non-executable docker is ignored
        std::fs::write(dir.path().join("docker"), "").unwrap();

        let path = Some(dir.path().as_os_str().to_owned());
        let rt = ContainerRuntime::detect_in("docker", path.clone()).unwrap();
        assert_eq!(rt.kind(), RuntimeKind::Podman);
        assert_eq!(rt.bin(), podman.to_string_lossy());

        let rt = ContainerRuntime::detect_in("podman", path).unwrap();
        assert_eq!(rt.kind(), RuntimeKind::Podman);

        let empty = tempfile::tempdir().unwrap();
        assert!(
            ContainerRuntime::detect_in("docker", Some(empty.path().as_os_str().to_owned()))
                .is_err()
        );
    }

    // --- gateway detection ---

    #[test]
    fn parses_docker_and_podman_network_json() {
        let docker = r#"[{"Name":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]"#;
        assert_eq!(
            parse_network_gateways(docker),
            vec!["172.17.0.1".parse::<IpAddr>().unwrap()]
        );
        let no_gw = r#"[{"IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]}}]"#;
        assert_eq!(
            parse_network_gateways(no_gw),
            vec!["172.18.0.1".parse::<IpAddr>().unwrap()]
        );
        let podman = r#"[{"name":"podman","subnets":[{"subnet":"fd00::/64","gateway":"fd00::1"},{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]}]"#;
        let gws = parse_network_gateways(podman);
        assert_eq!(gws[0], "10.88.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(gws.len(), 2);
        assert!(parse_network_gateways("not json").is_empty());
        assert!(parse_network_gateways("{}").is_empty());
    }

    #[test]
    fn parses_ip_addr_output() {
        let out = "3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever";
        assert_eq!(
            parse_ip_addr_output(out),
            Some("172.17.0.1".parse().unwrap())
        );
        assert_eq!(parse_ip_addr_output(""), None);
    }

    #[tokio::test]
    async fn gateway_bind_uses_bindable_bridge_gateway() {
        let exec = Arc::new(FakeExecutor::default());
        // 127.0.0.2 is always bindable on Linux (all of 127/8 is local).
        exec.push(Ok(CommandOutput::ok(
            r#"[{"IPAM":{"Config":[{"Subnet":"127.0.0.0/8","Gateway":"127.0.0.2"}]}}]"#,
        )));
        let ip = rt(&exec).detect_gateway_bind_addr().await;
        assert_eq!(ip, "127.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(exec.calls()[0].1, sv(&["network", "inspect", "bridge"]));
    }

    #[tokio::test]
    async fn gateway_bind_falls_back_to_loopback() {
        let exec = Arc::new(FakeExecutor::default());
        // TEST-NET-1 address is never local => not bindable.
        exec.push(Ok(CommandOutput::ok(
            r#"[{"IPAM":{"Config":[{"Gateway":"192.0.2.1"}]}}]"#,
        )));
        exec.push(Ok(CommandOutput::failed(1, "no such network")));
        exec.push(Ok(CommandOutput::failed(
            1,
            "Device \"docker0\" does not exist.",
        )));
        let ip = rt(&exec).detect_gateway_bind_addr().await;
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let calls = exec.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[1].1, sv(&["network", "inspect", "podman"]));
        assert_eq!(calls[2].0, "ip");
    }

    #[tokio::test]
    async fn gateway_bind_is_loopback_on_macos() {
        let exec = Arc::new(FakeExecutor::default());
        let ip = rt(&exec)
            .with_platform(HostPlatform::MacOs)
            .detect_gateway_bind_addr()
            .await;
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(exec.calls().is_empty());
        let ip = detect_gateway_bind_addr(&rt(&exec).with_platform(HostPlatform::Other)).await;
        assert!(ip.is_loopback());
    }

    #[tokio::test]
    async fn tokio_executor_runs_and_times_out() {
        let exec = TokioCommandExecutor;
        let out = exec
            .run(
                "sh",
                &sv(&["-c", "echo hi; echo err >&2; exit 3"]),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(out.status, Some(3));
        assert_eq!(out.stdout.trim(), "hi");
        assert_eq!(out.stderr.trim(), "err");
        let err = exec
            .run("sleep", &sv(&["5"]), Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
