//! `docker run` argument construction (port of `buildContainerArgs` /
//! `buildProviderArgs` in `src/container-runner.ts`) with the hardening of
//! `docs/RUST_ARCHITECTURE.md` §3.3.
//!
//! ```text
//! run --rm -i --init --name talon-<folder>-<millis>
//!   --label talon.managed=true --label talon.group=<folder>
//!   --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID
//!   --cap-add=FOWNER --cap-add=DAC_OVERRIDE --cap-add=KILL
//!   --security-opt=no-new-privileges --read-only
//!   --tmpfs /tmp:rw,nosuid,nodev,size=1g --tmpfs /run:rw,nosuid,nodev,size=16m
//!   --tmpfs /etc/mcp-secrets:rw,nosuid,nodev,noexec,size=1m,mode=0711
//!   --tmpfs /home/agent:rw,nosuid,nodev,size=256m
//!   --pids-limit 512 --memory 4g --memory-swap 4g --cpus 2
//!   [--network <group network | default network (talon-agents)>]
//!   -e TZ=<tz> -e RUN_UID=<uid> -e RUN_GID=<gid> [-e KEY=VALUE ...]
//!   [--add-host host.docker.internal:host-gateway]       (Linux)
//!   [--add-host <blocked>:127.0.0.1 ...]
//!   --mount type=bind,source=<host>,target=<ctr>[,readonly] ...
//!   <image>
//! ```
//!
//! No secret ever goes into the argument list: the env overlay drops keys
//! that look like credentials (and keys that could hijack the root
//! entrypoint, e.g. `LD_PRELOAD`, `BASH_ENV`, `PATH`), each drop is reported
//! as a [`ConfigRejection`] for the audit log.

use std::sync::atomic::{AtomicI64, Ordering};

use talon_core::paths::is_valid_group_folder;
use talon_core::types::ContainerConfig;
use talon_core::{Error, Result};

use crate::mounts::VolumeMount;
use crate::runtime::{GROUP_LABEL_KEY, MANAGED_LABEL, is_valid_container_name};

/// Default `--memory`.
pub const DEFAULT_MEMORY: &str = "4g";
/// Default `--cpus`.
pub const DEFAULT_CPUS: f64 = 2.0;
/// Default `--pids-limit`.
pub const DEFAULT_PIDS_LIMIT: u32 = 512;
/// Accepted `--pids-limit` range.
pub const PIDS_LIMIT_RANGE: (u32, u32) = (64, 65_536);
/// Accepted `--cpus` range.
pub const CPUS_RANGE: (f64, f64) = (0.1, 256.0);
/// Minimum memory limit (bytes) accepted from a group config.
pub const MIN_MEMORY_BYTES: u64 = 128 * 1024 * 1024;

/// Capabilities kept after `--cap-drop=ALL` (entrypoint + supervisor needs).
pub const ADDED_CAPABILITIES: &[&str] = &[
    "CHOWN",
    "SETUID",
    "SETGID",
    "FOWNER",
    "DAC_OVERRIDE",
    "KILL",
];

/// `--tmpfs` mounts (target, options).
pub const TMPFS_MOUNTS: &[(&str, &str)] = &[
    ("/tmp", "rw,nosuid,nodev,size=1g"),
    ("/run", "rw,nosuid,nodev,size=16m"),
    (
        "/etc/mcp-secrets",
        "rw,nosuid,nodev,noexec,size=1m,mode=0711",
    ),
    ("/home/agent", "rw,nosuid,nodev,size=256m"),
];

/// Fallback uid/gid when the host runs as root (the agent never runs as 0).
pub const FALLBACK_ID: u32 = 1000;

/// Max env overlay value length.
const MAX_ENV_VALUE: usize = 8192;
/// Max env overlay key length.
const MAX_ENV_KEY: usize = 128;

/// Substrings marking a key as a credential (`*KEY*`, `*TOKEN*`, ...).
const SECRET_MARKERS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE",
];
/// Suffixes marking a key as a credential (`MYSQL_PASS`, `DB_PWD`, ...).
const SECRET_SUFFIXES: &[&str] = &["_PASS", "_PWD", "_AUTH"];
/// Keys owned by the launcher or able to hijack the root entrypoint /
/// supervisor (dynamic loader, shell start-up, interpreters).
const RESERVED_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TZ",
    "RUN_UID",
    "RUN_GID",
    "TMPDIR",
    "ENV",
    "BASH_ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "IFS",
    "CDPATH",
    "GLOBIGNORE",
    "PROMPT_COMMAND",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "NODE_OPTIONS",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "RUBYLIB",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
];
/// Reserved key prefixes.
const RESERVED_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "BASH_FUNC_",
    "PYTHON",
    "TALON_",
    "MALLOC_",
    "NSS_",
];

/// uid/gid the in-container `agent` user runs as (`RUN_UID` / `RUN_GID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunAs {
    /// Numeric user id.
    pub uid: u32,
    /// Numeric group id.
    pub gid: u32,
}

impl RunAs {
    /// Normalize: root ids are replaced by [`FALLBACK_ID`] so the agent never
    /// runs as uid/gid 0.
    pub fn sanitized(uid: u32, gid: u32) -> Self {
        Self {
            uid: if uid == 0 { FALLBACK_ID } else { uid },
            gid: if gid == 0 { FALLBACK_ID } else { gid },
        }
    }

    /// The host process's ids (so bind-mounted files stay accessible),
    /// sanitized.
    pub fn current() -> Self {
        let (uid, gid) = host_ids();
        Self::sanitized(uid, gid)
    }
}

/// Raw `(uid, gid)` of the host process.
pub fn host_ids() -> (u32, u32) {
    (
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    )
}

/// `true` when the host process runs as root.
pub fn host_is_root() -> bool {
    rustix::process::getuid().is_root()
}

/// Effective docker resource limits.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceLimits {
    /// `--memory` (and `--memory-swap`, disabling swap).
    pub memory: String,
    /// `--cpus`.
    pub cpus: f64,
    /// `--pids-limit`.
    pub pids_limit: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory: DEFAULT_MEMORY.to_string(),
            cpus: DEFAULT_CPUS,
            pids_limit: DEFAULT_PIDS_LIMIT,
        }
    }
}

/// A container-config value that was refused (to be audited as
/// `container.config.rejected`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRejection {
    /// Config field (`env`, `blockedHosts`, `memory`, `cpus`, `pidsLimit`,
    /// `network`).
    pub field: &'static str,
    /// The offending key or value. For `env` this is the **key only** — the
    /// value is never recorded.
    pub value: String,
    /// Why it was refused.
    pub reason: String,
}

impl ConfigRejection {
    fn new(field: &'static str, value: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field,
            value: value.into(),
            reason: reason.into(),
        }
    }
}

/// Parse a docker memory size (`512m`, `4g`, `1073741824`) into bytes.
pub fn parse_memory_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() || s.len() > 24 {
        return None;
    }
    let (digits, mult) = match s.chars().last()? {
        'b' | 'B' => (&s[..s.len() - 1], 1u64),
        'k' | 'K' => (&s[..s.len() - 1], 1024),
        'm' | 'M' => (&s[..s.len() - 1], 1024 * 1024),
        'g' | 'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

impl ResourceLimits {
    /// Apply a group's overrides on top of `defaults`. Invalid values keep
    /// the default and are reported.
    pub fn from_config(
        cfg: &ContainerConfig,
        defaults: &ResourceLimits,
    ) -> (Self, Vec<ConfigRejection>) {
        let mut out = defaults.clone();
        let mut rejections = Vec::new();
        if let Some(mem) = &cfg.memory {
            match parse_memory_bytes(mem) {
                Some(bytes) if bytes >= MIN_MEMORY_BYTES => out.memory = mem.trim().to_string(),
                _ => rejections.push(ConfigRejection::new(
                    "memory",
                    mem.clone(),
                    "expected a size like 512m/4g, at least 128m",
                )),
            }
        }
        if let Some(cpus) = cfg.cpus {
            if cpus.is_finite() && (CPUS_RANGE.0..=CPUS_RANGE.1).contains(&cpus) {
                out.cpus = cpus;
            } else {
                rejections.push(ConfigRejection::new(
                    "cpus",
                    cpus.to_string(),
                    "out of range (0.1..=256)",
                ));
            }
        }
        if let Some(pids) = cfg.pids_limit {
            if (PIDS_LIMIT_RANGE.0..=PIDS_LIMIT_RANGE.1).contains(&pids) {
                out.pids_limit = pids;
            } else {
                rejections.push(ConfigRejection::new(
                    "pidsLimit",
                    pids.to_string(),
                    "out of range (64..=65536)",
                ));
            }
        }
        (out, rejections)
    }

    /// `--cpus` rendering (`2`, `1.5`).
    pub fn cpus_arg(&self) -> String {
        if self.cpus.fract() == 0.0 {
            format!("{}", self.cpus as u64)
        } else {
            format!("{}", self.cpus)
        }
    }
}

/// Why an env overlay key is refused, or `None` when it is acceptable.
pub fn env_key_rejection(key: &str) -> Option<&'static str> {
    let mut chars = key.chars();
    let valid = key.len() <= MAX_ENV_KEY
        && matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Some("invalid environment variable name");
    }
    let upper = key.to_ascii_uppercase();
    if SECRET_MARKERS.iter().any(|m| upper.contains(m))
        || SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s))
        || upper == "PASS"
    {
        return Some("looks like a secret; use OneCLI or per-MCP secret files");
    }
    if RESERVED_KEYS.contains(&upper.as_str())
        || RESERVED_PREFIXES.iter().any(|p| upper.starts_with(p))
    {
        return Some("reserved: controlled by the launcher or able to hijack the entrypoint");
    }
    None
}

/// Filter the env overlay. Returns accepted `(key, value)` pairs (sorted by
/// key) and the rejections (keys only).
pub fn filter_env_overlay(cfg: &ContainerConfig) -> (Vec<(String, String)>, Vec<ConfigRejection>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for (key, value) in &cfg.env {
        if let Some(reason) = env_key_rejection(key) {
            rejected.push(ConfigRejection::new("env", key.clone(), reason));
            continue;
        }
        if value.len() > MAX_ENV_VALUE || value.chars().any(|c| matches!(c, '\0' | '\n' | '\r')) {
            rejected.push(ConfigRejection::new(
                "env",
                key.clone(),
                "value too long or contains control characters",
            ));
            continue;
        }
        accepted.push((key.clone(), value.clone()));
    }
    (accepted, rejected)
}

/// `true` for a syntactically valid DNS hostname (not an IP literal).
pub fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// Normalize and validate blocked hosts (lower-case, deduplicated).
pub fn filter_blocked_hosts(cfg: &ContainerConfig) -> (Vec<String>, Vec<ConfigRejection>) {
    let mut accepted: Vec<String> = Vec::new();
    let mut rejected = Vec::new();
    for raw in &cfg.blocked_hosts {
        let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if !is_valid_hostname(&host) {
            rejected.push(ConfigRejection::new(
                "blockedHosts",
                raw.clone(),
                "not a valid hostname",
            ));
            continue;
        }
        if host == crate::runtime::HOST_GATEWAY_NAME {
            rejected.push(ConfigRejection::new(
                "blockedHosts",
                raw.clone(),
                "cannot block the host gateway (the LLM gateway is reached through it)",
            ));
            continue;
        }
        if !accepted.contains(&host) {
            accepted.push(host);
        }
    }
    (accepted, rejected)
}

/// Validate `--network`. `host` and namespace-sharing modes are refused.
pub fn validate_network(network: &str) -> std::result::Result<(), &'static str> {
    let n = network.trim();
    if n.eq_ignore_ascii_case("host") {
        return Err("host networking defeats container isolation");
    }
    if n.contains(':') {
        return Err("namespace-sharing network modes are not allowed");
    }
    if !is_valid_container_name(n) {
        return Err("invalid network name");
    }
    Ok(())
}

/// `true` when an image reference is safe as a positional argument.
pub fn is_valid_image(image: &str) -> bool {
    let mut chars = image.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && image.len() <= 512
        && chars
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@'))
}

/// `true` for an IANA-looking timezone name safe for `-e TZ=`.
pub fn is_valid_tz(tz: &str) -> bool {
    !tz.is_empty()
        && tz.len() <= 64
        && tz
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+'))
}

/// `true` when a path can be embedded in a `--mount` CSV spec without
/// changing its meaning (no `,`, `"`, control characters).
pub fn is_mount_path_safe(path: &str) -> bool {
    !path.is_empty() && !path.chars().any(|c| c == ',' || c == '"' || c.is_control())
}

/// `--mount type=bind,...` arguments for one mount.
pub fn mount_args(m: &VolumeMount) -> Result<[String; 2]> {
    let host = m.host_path.to_string_lossy();
    if !m.host_path.is_absolute() || !is_mount_path_safe(&host) {
        return Err(Error::security(format!(
            "unsafe host path in mount: {host:?}"
        )));
    }
    let target = &m.container_path;
    if !target.starts_with('/')
        || target.split('/').any(|seg| seg == ".." || seg == ".")
        || !is_mount_path_safe(target)
    {
        return Err(Error::security(format!(
            "unsafe container path in mount: {target:?}"
        )));
    }
    let mut spec = format!("type=bind,source={host},target={target}");
    if m.readonly {
        spec.push_str(",readonly");
    }
    Ok(["--mount".to_string(), spec])
}

static LAST_NAME_MILLIS: AtomicI64 = AtomicI64::new(0);

/// Strictly increasing millisecond stamp (unique per process).
fn unique_millis() -> i64 {
    let now = chrono::Utc::now().timestamp_millis();
    let mut last = LAST_NAME_MILLIS.load(Ordering::Relaxed);
    loop {
        let next = now.max(last.saturating_add(1));
        match LAST_NAME_MILLIS.compare_exchange_weak(
            last,
            next,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(actual) => last = actual,
        }
    }
}

/// `talon-<folder with [^A-Za-z0-9-] -> '-'>-<millis>` (unique per process).
pub fn container_name(group_folder: &str) -> String {
    let safe: String = group_folder
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("talon-{safe}-{}", unique_millis())
}

/// Inputs for [`build_run_args`].
#[derive(Debug, Clone)]
pub struct RunArgsInput<'a> {
    /// Container name (from [`container_name`]).
    pub name: &'a str,
    /// Owning group folder (label).
    pub group_folder: &'a str,
    /// Image reference.
    pub image: &'a str,
    /// IANA timezone passed as `TZ`.
    pub timezone: &'a str,
    /// `RUN_UID` / `RUN_GID`.
    pub run_as: RunAs,
    /// Effective (merged) container config.
    pub config: &'a ContainerConfig,
    /// Limits used when the config has no (valid) override.
    pub default_limits: &'a ResourceLimits,
    /// Bind mounts.
    pub mounts: &'a [VolumeMount],
    /// From [`crate::runtime::ContainerRuntime::host_gateway_args`].
    pub host_gateway_args: &'a [String],
    /// Network used when the config sets none (or an invalid one), normally
    /// [`crate::runtime::AGENT_NETWORK`]; `None` = the runtime default.
    pub default_network: Option<&'a str>,
}

/// Output of [`build_run_args`].
#[derive(Debug, Clone, PartialEq)]
pub struct RunArgs {
    /// Arguments after the runtime binary (starting with `run`).
    pub args: Vec<String>,
    /// Effective limits.
    pub limits: ResourceLimits,
    /// Accepted env overlay keys (values deliberately not repeated here).
    pub env_keys: Vec<String>,
    /// Hosts routed to 127.0.0.1.
    pub blocked_hosts: Vec<String>,
    /// `--network`: the config's network, else the default network;
    /// `None` = the runtime default bridge.
    pub network: Option<String>,
    /// Refused config values (to audit).
    pub rejections: Vec<ConfigRejection>,
}

/// Build the full, hardened `run` argument vector.
pub fn build_run_args(input: &RunArgsInput<'_>) -> Result<RunArgs> {
    if !is_valid_container_name(input.name) {
        return Err(Error::invalid(format!(
            "invalid container name {:?}",
            input.name
        )));
    }
    if !is_valid_group_folder(input.group_folder) {
        return Err(Error::security(format!(
            "invalid group folder {:?}",
            input.group_folder
        )));
    }
    if !is_valid_image(input.image) {
        return Err(Error::Config(format!(
            "invalid container image {:?}",
            input.image
        )));
    }
    if !is_valid_tz(input.timezone) {
        return Err(Error::Config(format!(
            "invalid timezone {:?}",
            input.timezone
        )));
    }
    if input.run_as.uid == 0 || input.run_as.gid == 0 {
        return Err(Error::security("the agent must not run as uid/gid 0"));
    }

    let mut rejections = Vec::new();
    let (limits, mut r) = ResourceLimits::from_config(input.config, input.default_limits);
    rejections.append(&mut r);
    let (env, mut r) = filter_env_overlay(input.config);
    rejections.append(&mut r);
    let (blocked_hosts, mut r) = filter_blocked_hosts(input.config);
    rejections.append(&mut r);
    let network = match input.config.network.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(n) => match validate_network(n) {
            Ok(()) => Some(n.to_string()),
            Err(reason) => {
                rejections.push(ConfigRejection::new("network", n, reason));
                None
            }
        },
    };
    // No (valid) group network: the operator default, never silently the
    // runtime's shared default bridge when a default is configured.
    let network = match network {
        Some(n) => Some(n),
        None => match input
            .default_network
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            None => None,
            Some(d) => {
                validate_network(d).map_err(|reason| {
                    Error::Config(format!("invalid default container network {d:?}: {reason}"))
                })?;
                Some(d.to_string())
            }
        },
    };

    let mut args: Vec<String> = Vec::with_capacity(64 + 2 * input.mounts.len());
    let mut push = |items: &[&str]| args.extend(items.iter().map(|s| s.to_string()));
    // `--init`: a tiny init (tini/catatonit) becomes PID 1, forwards signals
    // and reaps orphaned MCP-wrapper processes the supervisor cannot.
    push(&["run", "--rm", "-i", "--init", "--name", input.name]);
    push(&["--label", MANAGED_LABEL]);
    push(&[
        "--label",
        &format!("{GROUP_LABEL_KEY}={}", input.group_folder),
    ]);
    push(&["--cap-drop=ALL"]);
    for cap in ADDED_CAPABILITIES {
        push(&[&format!("--cap-add={cap}")]);
    }
    push(&["--security-opt=no-new-privileges", "--read-only"]);
    for (target, opts) in TMPFS_MOUNTS {
        push(&["--tmpfs", &format!("{target}:{opts}")]);
    }
    push(&["--pids-limit", &limits.pids_limit.to_string()]);
    push(&["--memory", &limits.memory, "--memory-swap", &limits.memory]);
    push(&["--cpus", &limits.cpus_arg()]);
    if let Some(net) = &network {
        push(&["--network", net]);
    }
    push(&["-e", &format!("TZ={}", input.timezone)]);
    push(&["-e", &format!("RUN_UID={}", input.run_as.uid)]);
    push(&["-e", &format!("RUN_GID={}", input.run_as.gid)]);
    for (k, v) in &env {
        push(&["-e", &format!("{k}={v}")]);
    }
    args.extend(input.host_gateway_args.iter().cloned());
    for host in &blocked_hosts {
        args.push("--add-host".to_string());
        args.push(format!("{host}:127.0.0.1"));
    }
    for m in input.mounts {
        args.extend(mount_args(m)?);
    }
    args.push(input.image.to_string());

    Ok(RunArgs {
        args,
        limits,
        env_keys: env.into_iter().map(|(k, _)| k).collect(),
        blocked_hosts,
        network,
        rejections,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn input<'a>(
        cfg: &'a ContainerConfig,
        mounts: &'a [VolumeMount],
        gw: &'a [String],
        limits: &'a ResourceLimits,
    ) -> RunArgsInput<'a> {
        RunArgsInput {
            name: "talon-team-1700000000000",
            group_folder: "team",
            image: "talon-agent:latest",
            timezone: "Europe/Berlin",
            run_as: RunAs {
                uid: 1001,
                gid: 1002,
            },
            config: cfg,
            default_limits: limits,
            mounts,
            host_gateway_args: gw,
            default_network: None,
        }
    }

    #[test]
    fn exact_hardened_args() {
        let cfg = ContainerConfig {
            blocked_hosts: vec!["api.anthropic.com".into()],
            ..Default::default()
        };
        let mounts = vec![
            VolumeMount::rw("/srv/talon/groups/team", "/workspace/group"),
            VolumeMount::shadow("/workspace/extra/siem/.env"),
        ];
        let gw = sv(&["--add-host", "host.docker.internal:host-gateway"]);
        let limits = ResourceLimits::default();
        let out = build_run_args(&input(&cfg, &mounts, &gw, &limits)).unwrap();
        assert_eq!(
            out.args,
            sv(&[
                "run",
                "--rm",
                "-i",
                "--init",
                "--name",
                "talon-team-1700000000000",
                "--label",
                "talon.managed=true",
                "--label",
                "talon.group=team",
                "--cap-drop=ALL",
                "--cap-add=CHOWN",
                "--cap-add=SETUID",
                "--cap-add=SETGID",
                "--cap-add=FOWNER",
                "--cap-add=DAC_OVERRIDE",
                "--cap-add=KILL",
                "--security-opt=no-new-privileges",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=1g",
                "--tmpfs",
                "/run:rw,nosuid,nodev,size=16m",
                "--tmpfs",
                "/etc/mcp-secrets:rw,nosuid,nodev,noexec,size=1m,mode=0711",
                "--tmpfs",
                "/home/agent:rw,nosuid,nodev,size=256m",
                "--pids-limit",
                "512",
                "--memory",
                "4g",
                "--memory-swap",
                "4g",
                "--cpus",
                "2",
                "-e",
                "TZ=Europe/Berlin",
                "-e",
                "RUN_UID=1001",
                "-e",
                "RUN_GID=1002",
                "--add-host",
                "host.docker.internal:host-gateway",
                "--add-host",
                "api.anthropic.com:127.0.0.1",
                "--mount",
                "type=bind,source=/srv/talon/groups/team,target=/workspace/group",
                "--mount",
                "type=bind,source=/dev/null,target=/workspace/extra/siem/.env,readonly",
                "talon-agent:latest",
            ])
        );
        assert!(out.rejections.is_empty());
    }

    #[test]
    fn limits_and_network_overrides() {
        let cfg = ContainerConfig {
            memory: Some("8g".into()),
            cpus: Some(1.5),
            pids_limit: Some(1024),
            network: Some("talon-net".into()),
            ..Default::default()
        };
        let limits = ResourceLimits::default();
        let out = build_run_args(&input(&cfg, &[], &[], &limits)).unwrap();
        let joined = out.args.join(" ");
        assert!(joined.contains("--memory 8g --memory-swap 8g --cpus 1.5"));
        assert!(joined.contains("--pids-limit 1024"));
        assert!(joined.contains("--network talon-net"));
        assert!(!joined.contains("host.docker.internal"));
        assert_eq!(out.network.as_deref(), Some("talon-net"));
    }

    #[test]
    fn network_selection_prefers_group_then_default() {
        let limits = ResourceLimits::default();
        let none = ContainerConfig::default();
        // Default network applies when the group sets none.
        let mut i = input(&none, &[], &[], &limits);
        i.default_network = Some(crate::runtime::AGENT_NETWORK);
        let out = build_run_args(&i).unwrap();
        assert_eq!(out.network.as_deref(), Some("talon-agents"));
        let pos = out.args.iter().position(|a| a == "--network").unwrap();
        assert_eq!(out.args[pos + 1], "talon-agents");
        // Network flag sits with the limits, before env and mounts.
        let cpus = out.args.iter().position(|a| a == "--cpus").unwrap();
        assert_eq!(pos, cpus + 2);

        // The group's network wins.
        let own = ContainerConfig {
            network: Some("lab-net".into()),
            ..Default::default()
        };
        let mut i = input(&own, &[], &[], &limits);
        i.default_network = Some("talon-agents");
        let out = build_run_args(&i).unwrap();
        assert_eq!(out.network.as_deref(), Some("lab-net"));
        assert_eq!(out.args.iter().filter(|a| *a == "--network").count(), 1);

        // An invalid group network is reported and the default used.
        let bad = ContainerConfig {
            network: Some("host".into()),
            ..Default::default()
        };
        let mut i = input(&bad, &[], &[], &limits);
        i.default_network = Some("talon-agents");
        let out = build_run_args(&i).unwrap();
        assert_eq!(out.network.as_deref(), Some("talon-agents"));
        assert_eq!(out.rejections[0].field, "network");

        // No default: runtime default bridge (no flag).
        let out = build_run_args(&input(&none, &[], &[], &limits)).unwrap();
        assert_eq!(out.network, None);
        assert!(!out.args.contains(&"--network".to_string()));
        let mut i = input(&none, &[], &[], &limits);
        i.default_network = Some("  ");
        assert_eq!(build_run_args(&i).unwrap().network, None);

        // An invalid default is a configuration error (fail closed).
        for d in ["host", "container:x", "-net"] {
            let mut i = input(&none, &[], &[], &limits);
            i.default_network = Some(d);
            assert!(build_run_args(&i).is_err(), "{d}");
        }
    }

    #[test]
    fn invalid_limits_fall_back_and_are_reported() {
        let cfg = ContainerConfig {
            memory: Some("lots".into()),
            cpus: Some(f64::NAN),
            pids_limit: Some(1),
            network: Some("host".into()),
            ..Default::default()
        };
        let limits = ResourceLimits::default();
        let out = build_run_args(&input(&cfg, &[], &[], &limits)).unwrap();
        assert_eq!(out.limits, ResourceLimits::default());
        assert_eq!(out.network, None);
        let fields: Vec<_> = out.rejections.iter().map(|r| r.field).collect();
        assert_eq!(fields, vec!["memory", "cpus", "pidsLimit", "network"]);
        assert!(!out.args.contains(&"host".to_string()));

        assert!(validate_network("container:abc").is_err());
        assert!(validate_network("-x").is_err());
        assert!(validate_network("none").is_ok());
        assert_eq!(parse_memory_bytes("512m"), Some(512 * 1024 * 1024));
        assert_eq!(parse_memory_bytes("1073741824"), Some(1 << 30));
        assert_eq!(parse_memory_bytes("1.5g"), None);
        assert_eq!(parse_memory_bytes("99999999999999999999g"), None);
        let (l, r) = ResourceLimits::from_config(
            &ContainerConfig {
                memory: Some("64m".into()),
                ..Default::default()
            },
            &ResourceLimits::default(),
        );
        assert_eq!(l.memory, "4g");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn env_overlay_drops_secrets_and_dangerous_keys() {
        // Secret-shaped fixtures are assembled at runtime so no source
        // literal matches a push-protection secret scanner.
        let openai_like = ["s", "k-", "123"].concat();
        let github_like = ["gh", "p_", "x"].concat();
        let mut env = BTreeMap::new();
        for (k, v) in [
            ("LOG_LEVEL", "debug"),
            ("HTTPS_PROXY", "http://proxy:3128"),
            ("no_proxy", "localhost"),
            ("OPENAI_API_KEY", openai_like.as_str()),
            ("GITHUB_TOKEN", github_like.as_str()),
            ("DB_PASSWORD", "x"),
            ("MYSQL_PASS", "x"),
            ("client_secret", "x"),
            ("LD_PRELOAD", "/workspace/group/evil.so"),
            ("BASH_ENV", "/workspace/group/x.sh"),
            ("BASH_FUNC_ls%%", "() { evil; }"),
            ("PATH", "/workspace/group"),
            ("TZ", "UTC"),
            ("RUN_UID", "0"),
            ("PYTHONPATH", "/workspace/group"),
            ("GLIBC_TUNABLES", "x"),
            ("TALON_MCP_SOCKET_DIR", "/tmp"),
            ("1BAD", "x"),
            ("WITH-DASH", "x"),
            ("MULTI", "a\nb"),
        ] {
            env.insert(k.to_string(), v.to_string());
        }
        let cfg = ContainerConfig {
            env,
            ..Default::default()
        };
        let limits = ResourceLimits::default();
        let out = build_run_args(&input(&cfg, &[], &[], &limits)).unwrap();
        assert_eq!(out.env_keys, sv(&["HTTPS_PROXY", "LOG_LEVEL", "no_proxy"]));
        let joined = out.args.join(" ");
        assert!(joined.contains("-e LOG_LEVEL=debug"));
        assert!(!joined.contains(&openai_like));
        assert!(!joined.contains(&github_like));
        assert!(!joined.contains("evil"));
        assert!(!joined.contains("RUN_UID=0"));
        assert_eq!(out.rejections.len(), 17);
        assert!(out.rejections.iter().all(|r| r.field == "env"));
        // Values never appear in rejections.
        assert!(
            !out.rejections
                .iter()
                .any(|r| r.value.contains(&openai_like))
        );
    }

    #[test]
    fn env_key_classification() {
        assert!(env_key_rejection("TALON_THING").is_some());
        assert!(env_key_rejection("SSH_PRIVATE_KEY_PATH").is_some());
        assert!(env_key_rejection("PASS").is_some());
        assert!(env_key_rejection("ld_preload").is_some());
        assert!(env_key_rejection("SESSION_LABEL").is_none());
        assert!(env_key_rejection("LANG").is_none());
        assert!(env_key_rejection("").is_some());
        assert!(env_key_rejection(&"A".repeat(200)).is_some());
    }

    #[test]
    fn blocked_hosts_validated() {
        let cfg = ContainerConfig {
            blocked_hosts: vec![
                "API.Anthropic.com.".into(),
                "api.anthropic.com".into(),
                "bad host".into(),
                "1.2.3.4".into(),
                "x:127.0.0.1".into(),
                "-flag".into(),
                "host.docker.internal".into(),
                "telemetry.example".into(),
            ],
            ..Default::default()
        };
        let (hosts, rejected) = filter_blocked_hosts(&cfg);
        assert_eq!(hosts, sv(&["api.anthropic.com", "telemetry.example"]));
        assert_eq!(rejected.len(), 5);
    }

    #[test]
    fn positional_injection_is_impossible() {
        let cfg = ContainerConfig::default();
        let limits = ResourceLimits::default();
        let mut i = input(&cfg, &[], &[], &limits);
        i.image = "--privileged";
        assert!(build_run_args(&i).is_err());
        let mut i = input(&cfg, &[], &[], &limits);
        i.name = "-it";
        assert!(build_run_args(&i).is_err());
        let mut i = input(&cfg, &[], &[], &limits);
        i.timezone = "UTC -e X=1";
        assert!(build_run_args(&i).is_err());
        let mut i = input(&cfg, &[], &[], &limits);
        i.group_folder = "../x";
        assert!(build_run_args(&i).is_err());
        let mut i = input(&cfg, &[], &[], &limits);
        i.run_as = RunAs { uid: 0, gid: 5 };
        assert!(build_run_args(&i).is_err());
        assert!(is_valid_image("ghcr.io/org/talon-agent@sha256:abc"));
    }

    #[test]
    fn mount_specs_reject_csv_injection() {
        assert!(mount_args(&VolumeMount::rw("/a,target=/etc", "/workspace/extra/x")).is_err());
        assert!(mount_args(&VolumeMount::rw("/a\"b", "/workspace/extra/x")).is_err());
        assert!(mount_args(&VolumeMount::rw("relative", "/workspace/extra/x")).is_err());
        assert!(mount_args(&VolumeMount::rw("/a", "/workspace/../etc")).is_err());
        assert!(mount_args(&VolumeMount::rw("/a", "relative")).is_err());
        assert!(mount_args(&VolumeMount::rw("/a\nb", "/x")).is_err());
        assert_eq!(
            mount_args(&VolumeMount::ro("/host/path", "/container/path")).unwrap(),
            [
                "--mount".to_string(),
                "type=bind,source=/host/path,target=/container/path,readonly".to_string()
            ]
        );
        // A bad mount is a hard error for the whole launch.
        let cfg = ContainerConfig::default();
        let limits = ResourceLimits::default();
        let bad = vec![VolumeMount::rw("/a,b", "/x")];
        assert!(build_run_args(&input(&cfg, &bad, &[], &limits)).is_err());
    }

    #[test]
    fn container_names_are_unique_and_sanitized() {
        let a = container_name("team_a");
        let b = container_name("team_a");
        assert!(a.starts_with("talon-team-a-"));
        assert_ne!(a, b);
        assert!(is_valid_container_name(&a));
        let ma: i64 = a.rsplit('-').next().unwrap().parse().unwrap();
        let mb: i64 = b.rsplit('-').next().unwrap().parse().unwrap();
        assert!(mb > ma);
    }

    #[test]
    fn run_as_never_root() {
        assert_eq!(
            RunAs::sanitized(0, 0),
            RunAs {
                uid: 1000,
                gid: 1000
            }
        );
        assert_eq!(RunAs::sanitized(501, 20), RunAs { uid: 501, gid: 20 });
        let cur = RunAs::current();
        assert_ne!(cur.uid, 0);
        assert_ne!(cur.gid, 0);
        let (uid, _) = host_ids();
        assert_eq!(host_is_root(), uid == 0);
    }

    #[test]
    fn cpus_rendering() {
        let mut l = ResourceLimits::default();
        assert_eq!(l.cpus_arg(), "2");
        l.cpus = 0.5;
        assert_eq!(l.cpus_arg(), "0.5");
    }
}
