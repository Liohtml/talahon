//! Step `service`: install Talahon as a
//! background service running `<talahon binary> run`.
//!
//! - **Linux + systemd**: a user unit (`~/.config/systemd/user/talahon.service`,
//!   linger enabled) or, as root, a system unit. The unit is sandboxed
//!   ([`Hardening`]) as far as is compatible with driving the container
//!   runtime; if the strict sandbox prevents the service from starting
//!   (e.g. unprivileged user namespaces disabled), it is rewritten with the
//!   basic set and restarted.
//! - **macOS**: a launchd agent (`~/Library/LaunchAgents/com.talahon.plist`).
//! - **No systemd** (WSL, containers): a `start-talahon.sh` nohup wrapper.
//!
//! Up to 2.x the service was called `talon` (`talon.service`, `com.talon`,
//! `start-talon.sh` / `talon.pid`). Installing the service under its new
//! name stops, disables and removes the old one first, so two services
//! never fight over the channels.
//!
//! Every generated file is built with proper escaping for its format
//! (systemd specifiers/quoting, XML, POSIX shell), so unusual paths cannot
//! inject directives or commands.
//!
//! Every variant raises the open-file limit to [`MAX_OPEN_FILES`]: the usual
//! soft default of 1024 descriptors is easy to exhaust with slow or idle
//! connections to the HTTP API, the LLM gateway and the Emacs bridge
//! (MYTH-06). systemd units additionally cap the task count
//! ([`MAX_TASKS`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};

use super::StepArgs;
use crate::context::{SETUP_LOG, SetupContext};
use crate::fsutil::write_atomic;
use crate::platform::{Platform, ServiceManager};
use crate::runner::{CommandOutput, CommandSpec};
use crate::status::{StatusBlock, StepOutcome};

/// systemd unit name (without `.service`).
pub const SERVICE_NAME: &str = "talahon";
/// launchd label.
pub const LAUNCHD_LABEL: &str = "com.talahon";
/// systemd unit name up to 2.x; replaced by [`SERVICE_NAME`] on install.
pub const LEGACY_SERVICE_NAME: &str = "talon";
/// launchd label up to 2.x; replaced by [`LAUNCHD_LABEL`] on install.
pub const LEGACY_LAUNCHD_LABEL: &str = "com.talon";
/// Open-file limit (soft and hard) of the service process
/// (`LimitNOFILE=`, launchd `NumberOfFiles`, `ulimit -n`).
pub const MAX_OPEN_FILES: u32 = 65536;
/// systemd `TasksMax=` of the service (threads + helper processes).
pub const MAX_TASKS: u32 = 4096;

/// systemd sandboxing level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hardening {
    /// Full sandbox: read-only system/home except Talahon's state directories,
    /// private /tmp, kernel protections, no privilege escalation. In user
    /// units this needs unprivileged user namespaces.
    Strict,
    /// Directives that work without user namespaces (no-new-privileges,
    /// seccomp-based restrictions, umask).
    Basic,
    /// No sandboxing (rootless podman needs setuid `newuidmap` and its own
    /// user namespaces).
    None,
}

impl Hardening {
    /// `strict` | `basic` | `none`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Hardening::Strict => "strict",
            Hardening::Basic => "basic",
            Hardening::None => "none",
        }
    }

    /// Parse `strict` / `basic` / `none`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "strict" => Some(Hardening::Strict),
            "basic" => Some(Hardening::Basic),
            "none" => Some(Hardening::None),
            _ => None,
        }
    }

    /// Default level for a container runtime.
    pub fn default_for_runtime(runtime: &str) -> Self {
        if runtime == "podman" {
            Hardening::None
        } else {
            Hardening::Strict
        }
    }
}

/// Inputs for the generated service definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    /// Absolute path of the `talahon` binary (`ExecStart=<binary> run`).
    pub binary: PathBuf,
    /// Talahon project directory (working directory, state, logs).
    pub project_root: PathBuf,
    /// The service user's home.
    pub home_dir: PathBuf,
    /// System unit (root) instead of a user unit.
    pub system_unit: bool,
    /// Sandboxing level.
    pub hardening: Hardening,
    /// Additional writable paths for the strict sandbox.
    pub extra_rw_paths: Vec<PathBuf>,
}

impl ServiceSpec {
    fn log_file(&self) -> PathBuf {
        self.project_root.join("logs").join("talahon.log")
    }

    fn error_log_file(&self) -> PathBuf {
        self.project_root.join("logs").join("talahon.error.log")
    }

    fn path_env(&self) -> String {
        format!(
            "/usr/local/bin:/usr/bin:/bin:{}",
            self.home_dir.join(".local").join("bin").display()
        )
    }
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

fn reject_line_breaks(s: &str) -> anyhow::Result<()> {
    if s.contains(['\n', '\r', '\0']) {
        bail!("value contains a line break or NUL: {s:?}");
    }
    Ok(())
}

/// A path value for a systemd setting that is not word-split
/// (`WorkingDirectory=`): `%` specifiers escaped.
pub fn systemd_path_value(s: &str) -> anyhow::Result<String> {
    reject_line_breaks(s)?;
    Ok(s.replace('%', "%%"))
}

/// One word of a word-split systemd setting (`ExecStart=`,
/// `Environment=`, `ReadWritePaths=`): `%` and `$` escaped, quoted when it
/// contains whitespace, quotes or backslashes.
pub fn systemd_word(s: &str) -> anyhow::Result<String> {
    reject_line_breaks(s)?;
    let escaped = s.replace('%', "%%").replace('$', "$$");
    if escaped.contains(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '\\') {
        Ok(format!(
            "\"{}\"",
            escaped.replace('\\', "\\\\").replace('"', "\\\"")
        ))
    } else {
        Ok(escaped)
    }
}

/// XML text escaping for plist values.
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// POSIX shell single-quoting.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Escape POSIX extended-regex metacharacters (for `pkill -f`).
pub fn ere_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if ".[]()*+?{}|^$\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn display(p: &Path) -> anyhow::Result<String> {
    p.to_str()
        .map(str::to_string)
        .with_context(|| format!("path is not valid UTF-8: {}", p.display()))
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// Directories the service may write under the strict sandbox.
pub fn writable_paths(spec: &ServiceSpec) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = ["store", "data", "groups", "logs"]
        .iter()
        .map(|d| spec.project_root.join(d))
        .collect();
    paths.extend(spec.extra_rw_paths.iter().cloned());
    paths
}

fn hardening_lines(spec: &ServiceSpec) -> anyhow::Result<Vec<String>> {
    let mut lines = Vec::new();
    match spec.hardening {
        Hardening::None => return Ok(lines),
        Hardening::Basic => {
            lines.push("# Hardening (basic: no user namespaces required)".into());
        }
        Hardening::Strict => {
            lines.push(
                "# Hardening (compatible with the docker CLI talking to dockerd's socket)".into(),
            );
        }
    }
    lines.push("NoNewPrivileges=yes".into());
    if spec.hardening == Hardening::Strict {
        lines.push("ProtectSystem=strict".into());
        let rw: Vec<String> = writable_paths(spec)
            .iter()
            .map(|p| display(p).and_then(|s| systemd_word(&s)))
            .collect::<anyhow::Result<_>>()?;
        lines.push(format!("ReadWritePaths={}", rw.join(" ")));
        // Optional ('-'): the docker CLI may update its config / contexts,
        // the host-side palace helper keeps its data next to the project.
        let optional = [
            spec.home_dir.join(".docker"),
            spec.project_root.join("mempalace-data"),
        ];
        let optional: Vec<String> = optional
            .iter()
            .map(|p| display(p).and_then(|s| systemd_word(&format!("-{s}"))))
            .collect::<anyhow::Result<_>>()?;
        lines.push(format!("ReadWritePaths={}", optional.join(" ")));
        lines.push("PrivateTmp=yes".into());
        lines.push("ProtectKernelTunables=yes".into());
        lines.push("ProtectKernelModules=yes".into());
        lines.push("ProtectKernelLogs=yes".into());
        lines.push("ProtectControlGroups=yes".into());
        lines.push("ProtectClock=yes".into());
        lines.push("ProtectHostname=yes".into());
    }
    lines.push("RestrictSUIDSGID=yes".into());
    lines.push("RestrictRealtime=yes".into());
    lines.push("LockPersonality=yes".into());
    lines.push("SystemCallArchitectures=native".into());
    lines.push("UMask=0027".into());
    Ok(lines)
}

/// Generate the systemd unit.
///
/// # Errors
/// Paths that cannot be represented safely (line breaks, non-UTF-8).
pub fn systemd_unit(spec: &ServiceSpec) -> anyhow::Result<String> {
    let bin = systemd_word(&display(&spec.binary)?)?;
    let root = systemd_path_value(&display(&spec.project_root)?)?;
    let home = systemd_word(&format!("HOME={}", display(&spec.home_dir)?))?;
    let path = systemd_word(&format!("PATH={}", spec.path_env()))?;

    let mut lines = vec![
        "[Unit]".to_string(),
        "Description=Talahon AI SOC Analyst".into(),
        "After=network-online.target docker.service".into(),
        "Wants=network-online.target".into(),
        String::new(),
        "[Service]".into(),
        "Type=simple".into(),
        format!("ExecStart={bin} run"),
        format!("WorkingDirectory={root}"),
        "Restart=always".into(),
        "RestartSec=5".into(),
        "# Only the host process is signalled; it stops its agent containers".into(),
        "# itself, and leftovers are reaped by label on the next start.".into(),
        "KillMode=process".into(),
        "TimeoutStopSec=45".into(),
        "# Resource limits (every hardening level): the default soft limit of".into(),
        "# 1024 open files is easy to exhaust with many slow connections.".into(),
        format!("LimitNOFILE={MAX_OPEN_FILES}"),
        format!("TasksMax={MAX_TASKS}"),
        format!("Environment={home}"),
        format!("Environment={path}"),
    ];
    let out_log = display(&spec.log_file())?;
    let err_log = display(&spec.error_log_file())?;
    if out_log.contains(char::is_whitespace) || err_log.contains(char::is_whitespace) {
        lines.push("# Project path contains whitespace: logging to the journal.".into());
    } else {
        lines.push(format!(
            "StandardOutput=append:{}",
            systemd_path_value(&out_log)?
        ));
        lines.push(format!(
            "StandardError=append:{}",
            systemd_path_value(&err_log)?
        ));
    }
    let hardening = hardening_lines(spec)?;
    if !hardening.is_empty() {
        lines.push(String::new());
        lines.extend(hardening);
    }
    lines.push(String::new());
    lines.push("[Install]".into());
    lines.push(format!(
        "WantedBy={}",
        if spec.system_unit {
            "multi-user.target"
        } else {
            "default.target"
        }
    ));
    let mut unit = lines.join("\n");
    unit.push('\n');
    Ok(unit)
}

/// Generate the launchd property list.
///
/// # Errors
/// Non-UTF-8 paths.
pub fn launchd_plist(spec: &ServiceSpec) -> anyhow::Result<String> {
    let bin = xml_escape(&display(&spec.binary)?);
    let root = xml_escape(&display(&spec.project_root)?);
    let home = xml_escape(&display(&spec.home_dir)?);
    let path = xml_escape(&format!("/opt/homebrew/bin:{}", spec.path_env()));
    let out_log = xml_escape(&display(&spec.log_file())?);
    let err_log = xml_escape(&display(&spec.error_log_file())?);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{root}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>Umask</key>
    <integer>23</integer>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>{MAX_OPEN_FILES}</integer>
    </dict>
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>{MAX_OPEN_FILES}</integer>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{path}</string>
        <key>HOME</key>
        <string>{home}</string>
    </dict>
    <key>StandardOutPath</key>
    <string>{out_log}</string>
    <key>StandardErrorPath</key>
    <string>{err_log}</string>
</dict>
</plist>
"#
    ))
}

/// `<project_root>/start-talahon.sh`
pub fn nohup_wrapper_path(project_root: &Path) -> PathBuf {
    project_root.join("start-talahon.sh")
}

/// `<project_root>/talahon.pid`
pub fn pid_file_path(project_root: &Path) -> PathBuf {
    project_root.join("talahon.pid")
}

/// `<project_root>/start-talon.sh`: the wrapper's name up to 2.x.
pub fn legacy_nohup_wrapper_path(project_root: &Path) -> PathBuf {
    project_root.join("start-talon.sh")
}

/// `<project_root>/talon.pid`: the PID file's name up to 2.x.
pub fn legacy_pid_file_path(project_root: &Path) -> PathBuf {
    project_root.join("talon.pid")
}

/// The pre-rename `talon` binary next to `binary` (an instance started
/// before the upgrade runs under that name).
pub fn legacy_binary_path(binary: &Path) -> PathBuf {
    binary.with_file_name(crate::context::LEGACY_BINARY_NAME)
}

/// Generate the nohup wrapper script used without systemd.
///
/// # Errors
/// Non-UTF-8 paths.
pub fn nohup_wrapper(spec: &ServiceSpec) -> anyhow::Result<String> {
    let root = shell_quote(&display(&spec.project_root)?);
    let bin = shell_quote(&display(&spec.binary)?);
    let pid = shell_quote(&display(&pid_file_path(&spec.project_root))?);
    let legacy_pid = shell_quote(&display(&legacy_pid_file_path(&spec.project_root))?);
    let legacy_bin = shell_quote(&display(&legacy_binary_path(&spec.binary))?);
    let out_log = shell_quote(&display(&spec.log_file())?);
    let err_log = shell_quote(&display(&spec.error_log_file())?);
    let lines = [
        "#!/bin/bash".to_string(),
        "# start-talahon.sh — start Talahon without systemd".into(),
        format!("# To stop: kill \"$(cat {pid})\""),
        String::new(),
        "set -euo pipefail".into(),
        String::new(),
        format!("cd {root}"),
        format!("PID_FILE={pid}"),
        format!("BIN={bin}"),
        "# Names used before the rename to Talahon (an instance started by".into(),
        "# start-talon.sh is stopped too, so two never run side by side).".into(),
        format!("LEGACY_PID_FILE={legacy_pid}"),
        format!("LEGACY_BIN={legacy_bin}"),
        String::new(),
        "# Stop an existing instance — only if the recorded PID still is Talahon:".into(),
        "# after a reboot or crash the number may belong to another process.".into(),
        "for FILE in \"$PID_FILE\" \"$LEGACY_PID_FILE\"; do".into(),
        "  [ -f \"$FILE\" ] || continue".into(),
        "  OLD_PID=$(cat \"$FILE\" 2>/dev/null || echo \"\")".into(),
        "  if [ -n \"$OLD_PID\" ] && ps -p \"$OLD_PID\" -o args= 2>/dev/null | grep -qF -e \"$BIN run\" -e \"$LEGACY_BIN run\"; then".into(),
        "    echo \"Stopping existing Talahon (PID $OLD_PID)...\"".into(),
        "    kill \"$OLD_PID\" 2>/dev/null || true".into(),
        "    sleep 2".into(),
        "  fi".into(),
        "done".into(),
        "rm -f \"$LEGACY_PID_FILE\"".into(),
        String::new(),
        "echo \"Starting Talahon...\"".into(),
        "umask 027".into(),
        "# Raise the open-file limit (the soft default of 1024 is easy to exhaust).".into(),
        format!(
            "ulimit -n {MAX_OPEN_FILES} 2>/dev/null || ulimit -n \"$(ulimit -Hn)\" 2>/dev/null || true"
        ),
        format!("nohup \"$BIN\" run >> {out_log} 2>> {err_log} &"),
        String::new(),
        "NEW_PID=$!".into(),
        "echo \"$NEW_PID\" > \"$PID_FILE\"".into(),
        "sleep 2".into(),
        "if ! kill -0 \"$NEW_PID\" 2>/dev/null; then".into(),
        format!("  echo \"Talahon exited right after starting; see \"{err_log} >&2"),
        "  rm -f \"$PID_FILE\"".into(),
        "  exit 1".into(),
        "fi".into(),
        "echo \"Talahon started (PID $NEW_PID)\"".into(),
        format!("echo \"Logs: tail -f \"{out_log}"),
    ];
    let mut script = lines.join("\n");
    script.push('\n');
    Ok(script)
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

fn base_block(ctx: &SetupContext, service_type: &str) -> StatusBlock {
    StatusBlock::new("SETUP_SERVICE")
        .field("SERVICE_TYPE", service_type)
        .field("BINARY_PATH", ctx.talon_binary.display())
        .field("PROJECT_PATH", ctx.project_root.display())
}

fn failed(ctx: &SetupContext, error: &str) -> StepOutcome {
    StepOutcome::with_code(
        base_block(ctx, "unknown")
            .field("STATUS", "failed")
            .field("ERROR", error)
            .field("LOG", SETUP_LOG),
        1,
    )
}

fn spec_for(ctx: &SetupContext, hardening: Hardening) -> ServiceSpec {
    ServiceSpec {
        binary: ctx.talon_binary.clone(),
        project_root: ctx.project_root.clone(),
        home_dir: ctx.home_dir.clone(),
        system_unit: ctx.platform.is_root(),
        hardening,
        extra_rw_paths: Vec::new(),
    }
}

async fn run_cmd(ctx: &SetupContext, program: &str, args: &[&str]) -> CommandOutput {
    let out = ctx
        .runner
        .run(&CommandSpec::new(program, args.iter().copied()))
        .await;
    if !out.success() {
        tracing::debug!(command = %format!("{program} {}", args.join(" ")), stderr = %out.stderr.trim(), "command failed");
    }
    out
}

async fn settle(ctx: &SetupContext) {
    if !ctx.service_settle.is_zero() {
        tokio::time::sleep(ctx.service_settle).await;
    }
}

/// Run the step.
///
/// Arguments: `--hardening strict|basic|none` overrides the default
/// (strict for docker, none for podman).
///
/// # Errors
/// Filesystem failures writing the service definition.
pub async fn run(args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    tracing::info!(platform = ctx.platform.platform.as_str(), binary = %ctx.talon_binary.display(), "Setting up service");
    if !crate::runner::is_executable(&ctx.talon_binary) || !ctx.talon_binary.is_absolute() {
        return Ok(failed(ctx, "binary_not_found"));
    }
    let hardening = match args.value("--hardening") {
        Some(h) => match Hardening::parse(h) {
            Some(h) => h,
            None => {
                return Ok(StepOutcome {
                    exit_code: 4,
                    ..failed(ctx, "invalid_hardening")
                });
            }
        },
        None => Hardening::default_for_runtime(&ctx.config.container_runtime),
    };

    // Directories must exist before the sandbox can bind them writable.
    for dir in writable_paths(&spec_for(ctx, hardening)) {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    match (ctx.platform.platform, ctx.platform.service_manager()) {
        (Platform::MacOs, _) => setup_launchd(ctx).await,
        (Platform::Linux, ServiceManager::Systemd) => setup_systemd(ctx, hardening).await,
        (Platform::Linux, _) => setup_nohup(ctx, "no_systemd"),
        _ => Ok(failed(ctx, "unsupported_platform")),
    }
}

async fn setup_launchd(ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    let plist_path = ctx
        .home_dir
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    if let Some(dir) = plist_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let plist = launchd_plist(&spec_for(ctx, Hardening::None))?;
    write_atomic(&plist_path, plist.as_bytes(), Some(0o644))?;
    tracing::info!(path = %plist_path.display(), "Wrote launchd plist");

    // The agent installed before the rename (`com.talon`) would keep running
    // next to the new one: unload and remove it first.
    let legacy_plist = plist_path.with_file_name(format!("{LEGACY_LAUNCHD_LABEL}.plist"));
    let legacy_removed = legacy_plist.is_file();
    if legacy_removed {
        let legacy_str = display(&legacy_plist)?;
        let _ = run_cmd(ctx, "launchctl", &["unload", "-w", &legacy_str]).await;
        std::fs::remove_file(&legacy_plist)
            .with_context(|| format!("removing {}", legacy_plist.display()))?;
        tracing::info!(path = %legacy_plist.display(), "Removed the pre-rename launchd agent");
    }

    let plist_str = display(&plist_path)?;
    // Reload so a changed plist takes effect (unload fails if not loaded).
    let _ = run_cmd(ctx, "launchctl", &["unload", &plist_str]).await;
    let load = run_cmd(ctx, "launchctl", &["load", "-w", &plist_str]).await;
    if !load.success() {
        tracing::warn!("launchctl load failed");
    }
    let list = run_cmd(ctx, "launchctl", &["list"]).await;
    let loaded = list.success()
        && list
            .stdout
            .lines()
            .any(|l| l.split_whitespace().nth(2) == Some(LAUNCHD_LABEL));

    Ok(started(
        base_block(ctx, "launchd")
            .field("PLIST_PATH", plist_path.display())
            .field("LEGACY_SERVICE_REMOVED", legacy_removed)
            .field("SERVICE_LOADED", loaded),
        loaded,
    ))
}

/// The step's result once the service definition is written: success only
/// when the service actually runs.
fn started(mut block: StatusBlock, running: bool) -> StepOutcome {
    if running {
        block.set("STATUS", "success");
        block.set("LOG", SETUP_LOG);
        StepOutcome::ok(block)
    } else {
        block.set("STATUS", "failed");
        block.set("ERROR", "service_not_running");
        block.set("LOG", SETUP_LOG);
        StepOutcome::with_code(block, 1)
    }
}

/// systemd's own exec-setup failure codes (`EXIT_CHDIR` = 200 …
/// `EXIT_CREDENTIALS` = 243): the service binary never ran.
pub fn is_exec_setup_failure(status: u32) -> bool {
    (200..=245).contains(&status)
}

/// Docker works from the shell but not from the systemd user session — the
/// user was added to the `docker` group after the session started.
async fn docker_group_stale(ctx: &SetupContext) -> bool {
    let in_session = ctx
        .runner
        .run(
            &CommandSpec::new(
                "systemd-run",
                ["--user", "--pipe", "--wait", "docker", "info"],
            )
            .timeout(Duration::from_secs(15)),
        )
        .await;
    if in_session.success() {
        return false;
    }
    run_cmd(ctx, "docker", &["info"]).await.success()
}

async fn setup_systemd(
    ctx: &SetupContext,
    mut hardening: Hardening,
) -> anyhow::Result<StepOutcome> {
    let as_root = ctx.platform.is_root();
    let systemctl: &[&str] = if as_root { &[] } else { &["--user"] };
    let unit_dir = if as_root {
        PathBuf::from("/etc/systemd/system")
    } else {
        if !run_cmd(ctx, "systemctl", &["--user", "daemon-reload"])
            .await
            .success()
        {
            tracing::warn!("systemd user session not available — falling back to nohup wrapper");
            return setup_nohup(ctx, "no_user_session");
        }
        ctx.home_dir.join(".config").join("systemd").join("user")
    };
    std::fs::create_dir_all(&unit_dir)
        .with_context(|| format!("creating {}", unit_dir.display()))?;
    let unit_path = unit_dir.join(format!("{SERVICE_NAME}.service"));

    let write_unit = |h: Hardening| -> anyhow::Result<()> {
        let unit = systemd_unit(&spec_for(ctx, h))?;
        write_atomic(&unit_path, unit.as_bytes(), Some(0o644))
            .with_context(|| format!("writing {}", unit_path.display()))
    };
    write_unit(hardening)?;
    tracing::info!(path = %unit_path.display(), hardening = hardening.as_str(), "Wrote systemd unit");

    let stale =
        !as_root && ctx.config.container_runtime == "docker" && docker_group_stale(ctx).await;
    if stale {
        tracing::warn!(
            "Docker group not active in the systemd session — user was likely added to the docker group mid-session"
        );
    }

    let sc = |extra: &[&'static str]| -> Vec<&str> {
        systemctl
            .iter()
            .copied()
            .chain(extra.iter().copied())
            .collect()
    };

    // The unit installed before the rename (`talon.service`) would keep
    // running next to the new one and fight over the channels: stop,
    // disable and remove it before the new unit starts.
    let legacy_unit_path = unit_dir.join(format!("{LEGACY_SERVICE_NAME}.service"));
    let legacy_removed = legacy_unit_path.is_file();
    if legacy_removed {
        let _ = run_cmd(
            ctx,
            "systemctl",
            &sc(&["disable", "--now", LEGACY_SERVICE_NAME]),
        )
        .await;
        std::fs::remove_file(&legacy_unit_path)
            .with_context(|| format!("removing {}", legacy_unit_path.display()))?;
        tracing::info!(path = %legacy_unit_path.display(), "Removed the pre-rename systemd unit");
    }

    // Stop stray manual instances that would fight over channel connections
    // (started under the current or the pre-rename binary name).
    for bin in [
        ctx.talon_binary.clone(),
        legacy_binary_path(&ctx.talon_binary),
    ] {
        if let Ok(bin) = display(&bin) {
            let pattern = format!("^{} run", ere_escape(&bin));
            let _ = run_cmd(ctx, "pkill", &["-f", &pattern]).await;
        }
    }

    let mut linger = false;
    if !as_root {
        linger = run_cmd(ctx, "loginctl", &["enable-linger"]).await.success();
        if !linger {
            tracing::warn!("loginctl enable-linger failed — service may stop on logout");
        }
    }

    let restart = || async {
        let _ = run_cmd(ctx, "systemctl", &sc(&["daemon-reload"])).await;
        let _ = run_cmd(ctx, "systemctl", &sc(&["enable", SERVICE_NAME])).await;
        let _ = run_cmd(ctx, "systemctl", &sc(&["restart", SERVICE_NAME])).await;
        settle(ctx).await;
        run_cmd(ctx, "systemctl", &sc(&["is-active", SERVICE_NAME]))
            .await
            .success()
    };
    let mut active = restart().await;
    if !active && hardening == Hardening::Strict {
        // Downgrade only when systemd itself failed to set up the sandbox
        // (exit codes 200-245 are systemd's exec-setup failures, e.g. 226
        // NAMESPACE) — not when Talahon started and then exited on its own.
        let status = run_cmd(
            ctx,
            "systemctl",
            &sc(&["show", "-p", "ExecMainStatus", "--value", SERVICE_NAME]),
        )
        .await;
        let exec_status = status.stdout.trim().parse::<u32>().ok();
        if exec_status.is_some_and(is_exec_setup_failure) {
            tracing::warn!(
                status = exec_status,
                "Service could not start inside the strict sandbox — retrying with basic hardening"
            );
            hardening = Hardening::Basic;
            write_unit(hardening)?;
            active = restart().await;
        }
    }

    let mut block = base_block(
        ctx,
        if as_root {
            "systemd-system"
        } else {
            "systemd-user"
        },
    )
    .field("UNIT_PATH", unit_path.display())
    .field("LEGACY_SERVICE_REMOVED", legacy_removed)
    .field("SERVICE_LOADED", active)
    .field("HARDENING", hardening.as_str());
    if stale {
        block.set("DOCKER_GROUP_STALE", true);
    }
    block.set("LINGER_ENABLED", linger);
    Ok(started(block, active))
}

fn setup_nohup(ctx: &SetupContext, fallback: &str) -> anyhow::Result<StepOutcome> {
    tracing::warn!("No usable systemd — generating nohup wrapper script");
    let path = nohup_wrapper_path(&ctx.project_root);
    let script = nohup_wrapper(&spec_for(ctx, Hardening::None))?;
    write_atomic(&path, script.as_bytes(), Some(0o755))?;
    tracing::info!(path = %path.display(), "Wrote nohup wrapper script");
    // The wrapper from before the rename would start a second instance; the
    // new one also stops a process recorded in the old PID file.
    let legacy = legacy_nohup_wrapper_path(&ctx.project_root);
    let legacy_removed = legacy.is_file();
    if legacy_removed {
        std::fs::remove_file(&legacy).with_context(|| format!("removing {}", legacy.display()))?;
        tracing::info!(path = %legacy.display(), "Removed the pre-rename wrapper script");
    }
    Ok(StepOutcome::ok(
        base_block(ctx, "nohup")
            .field("WRAPPER_PATH", path.display())
            .field("LEGACY_SERVICE_REMOVED", legacy_removed)
            .field("SERVICE_LOADED", false)
            .field("FALLBACK", fallback)
            .field("STATUS", "success")
            .field("LOG", SETUP_LOG),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runner::mock::MockRunner;

    fn spec(hardening: Hardening, system: bool) -> ServiceSpec {
        ServiceSpec {
            binary: PathBuf::from("/opt/talahon/bin/talahon"),
            project_root: PathBuf::from("/home/user/talahon"),
            home_dir: PathBuf::from("/home/user"),
            system_unit: system,
            hardening,
            extra_rw_paths: Vec::new(),
        }
    }

    // --- systemd unit -----------------------------------------------------------

    #[test]
    fn user_unit_uses_default_target() {
        let unit = systemd_unit(&spec(Hardening::Strict, false)).unwrap();
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn system_unit_uses_multi_user_target() {
        let unit = systemd_unit(&spec(Hardening::Strict, true)).unwrap();
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn unit_has_restart_policy_and_killmode() {
        let unit = systemd_unit(&spec(Hardening::Strict, false)).unwrap();
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RestartSec=5"));
        assert!(unit.contains("KillMode=process"));
    }

    #[test]
    fn unit_exec_start_runs_talon() {
        let unit = systemd_unit(&spec(Hardening::Strict, false)).unwrap();
        assert!(unit.contains("ExecStart=/opt/talahon/bin/talahon run\n"));
        assert!(unit.contains("WorkingDirectory=/home/user/talahon\n"));
        assert!(unit.contains("StandardOutput=append:/home/user/talahon/logs/talahon.log"));
        assert!(unit.contains("StandardError=append:/home/user/talahon/logs/talahon.error.log"));
        assert!(unit.contains("Environment=HOME=/home/user\n"));
    }

    #[test]
    fn strict_unit_is_sandboxed() {
        let unit = systemd_unit(&spec(Hardening::Strict, false)).unwrap();
        for directive in [
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ReadWritePaths=/home/user/talahon/store /home/user/talahon/data /home/user/talahon/groups /home/user/talahon/logs\n",
            "ReadWritePaths=-/home/user/.docker -/home/user/talahon/mempalace-data\n",
            "PrivateTmp=yes",
            "ProtectKernelTunables=yes",
            "ProtectControlGroups=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "UMask=0027",
        ] {
            assert!(unit.contains(directive), "missing {directive}\n{unit}");
        }
        // The mount allowlist (~/.config/talahon) must stay read-only.
        assert!(!unit.contains(".config/talahon"));
    }

    #[test]
    fn basic_and_none_hardening() {
        let basic = systemd_unit(&spec(Hardening::Basic, false)).unwrap();
        assert!(basic.contains("NoNewPrivileges=yes"));
        assert!(!basic.contains("ProtectSystem"));
        assert!(!basic.contains("PrivateTmp"));
        let none = systemd_unit(&spec(Hardening::None, false)).unwrap();
        assert!(!none.contains("NoNewPrivileges"));
        assert!(!none.contains("UMask"));
    }

    #[test]
    fn every_hardening_level_raises_fd_and_task_limits() {
        for hardening in [Hardening::Strict, Hardening::Basic, Hardening::None] {
            for system in [false, true] {
                let unit = systemd_unit(&spec(hardening, system)).unwrap();
                assert!(unit.contains("\nLimitNOFILE=65536\n"), "{unit}");
                assert!(unit.contains("\nTasksMax=4096\n"), "{unit}");
                // Limits belong to [Service], not [Install].
                let service = unit.find("[Service]").unwrap();
                let install = unit.find("[Install]").unwrap();
                let limit = unit.find("LimitNOFILE=").unwrap();
                assert!(service < limit && limit < install);
            }
        }
    }

    #[test]
    fn unit_escapes_hostile_paths() {
        let mut s = spec(Hardening::Strict, false);
        s.binary = PathBuf::from("/opt/my talahon/%h/$HOME/talahon");
        s.project_root = PathBuf::from("/srv/t%n");
        let unit = systemd_unit(&s).unwrap();
        assert!(
            unit.contains("ExecStart=\"/opt/my talahon/%%h/$$HOME/talahon\" run"),
            "{unit}"
        );
        assert!(unit.contains("WorkingDirectory=/srv/t%%n"));
        assert!(unit.contains("ReadWritePaths=/srv/t%%n/store"));

        s.project_root = PathBuf::from("/srv/x\nExecStartPre=/bin/rm -rf /");
        assert!(systemd_unit(&s).is_err());
    }

    #[test]
    fn whitespace_project_logs_to_journal() {
        let mut s = spec(Hardening::Strict, false);
        s.project_root = PathBuf::from("/srv/my talahon");
        let unit = systemd_unit(&s).unwrap();
        assert!(!unit.contains("StandardOutput=append"));
        assert!(unit.contains("ReadWritePaths=\"/srv/my talahon/store\""));
    }

    #[test]
    fn systemd_word_quoting() {
        assert_eq!(systemd_word("/a/b").unwrap(), "/a/b");
        assert_eq!(systemd_word("a b").unwrap(), "\"a b\"");
        assert_eq!(systemd_word("a\"b").unwrap(), "\"a\\\"b\"");
        assert_eq!(systemd_word("100%").unwrap(), "100%%");
        assert!(systemd_word("a\nb").is_err());
    }

    // --- launchd plist ------------------------------------------------------

    #[test]
    fn plist_contents() {
        let plist = launchd_plist(&spec(Hardening::None, false)).unwrap();
        assert!(plist.contains("<string>com.talahon</string>"));
        assert!(
            plist.contains(
                "<string>/opt/talahon/bin/talahon</string>\n        <string>run</string>"
            )
        );
        assert!(plist.contains("<string>/home/user/talahon</string>"));
        assert!(plist.contains("talahon.log"));
        assert!(plist.contains("talahon.error.log"));
        assert!(plist.contains("<key>KeepAlive</key>"));
    }

    #[test]
    fn plist_raises_open_file_limits() {
        let plist = launchd_plist(&spec(Hardening::None, false)).unwrap();
        for key in ["SoftResourceLimits", "HardResourceLimits"] {
            let expected = format!(
                "<key>{key}</key>\n    <dict>\n        <key>NumberOfFiles</key>\n        <integer>65536</integer>\n    </dict>"
            );
            assert!(plist.contains(&expected), "missing {key}\n{plist}");
        }
    }

    #[test]
    fn plist_is_well_formed_xml_shape() {
        let plist = launchd_plist(&spec(Hardening::None, false)).unwrap();
        // Every opened <dict> is closed (cheap structural sanity check).
        assert_eq!(
            plist.matches("<dict>").count(),
            plist.matches("</dict>").count()
        );
        assert_eq!(plist.matches("<dict>").count(), 4);
    }

    #[test]
    fn plist_escapes_xml() {
        let mut s = spec(Hardening::None, false);
        s.binary = PathBuf::from("/opt/a&b/</string><string>evil");
        let plist = launchd_plist(&s).unwrap();
        assert!(plist.contains("/opt/a&amp;b/&lt;/string&gt;&lt;string&gt;evil"));
        assert_eq!(plist.matches("<string>run</string>").count(), 1);
    }

    // --- nohup wrapper ------------------------------------------------------

    #[test]
    fn wrapper_script() {
        let script = nohup_wrapper(&spec(Hardening::None, false)).unwrap();
        assert!(script.starts_with("#!/bin/bash\n"));
        assert!(script.contains("BIN='/opt/talahon/bin/talahon'"));
        assert!(script.contains("nohup \"$BIN\" run >> '/home/user/talahon/logs/talahon.log'"));
        assert!(script.contains("talahon.pid"));
        // A recorded PID is only stopped while it still is Talahon.
        assert!(
            script.contains(
            "ps -p \"$OLD_PID\" -o args= 2>/dev/null | grep -qF -e \"$BIN run\" -e \"$LEGACY_BIN run\""
        )
        );
        assert!(!script.contains("kill -0 \"$OLD_PID\""));
        // An instance that dies at once is reported, not announced as started.
        assert!(script.contains("if ! kill -0 \"$NEW_PID\""));
        assert!(script.contains("set -euo pipefail"));
        // Raised before the service starts, failure-tolerant under `set -e`.
        let ulimit = script
            .find("ulimit -n 65536 2>/dev/null || ulimit -n \"$(ulimit -Hn)\" 2>/dev/null || true")
            .unwrap();
        assert!(ulimit < script.find("nohup ").unwrap());
    }

    #[test]
    fn wrapper_quotes_hostile_paths() {
        let mut s = spec(Hardening::None, false);
        s.project_root = PathBuf::from("/srv/it's $(rm -rf ~)");
        let script = nohup_wrapper(&s).unwrap();
        assert!(
            script.contains("cd '/srv/it'\\''s $(rm -rf ~)'"),
            "{script}"
        );
    }

    #[test]
    fn wrapper_is_valid_bash() {
        let mut s = spec(Hardening::None, false);
        s.project_root = PathBuf::from("/srv/it's $(x) \"q\"");
        let script = nohup_wrapper(&s).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.sh");
        std::fs::write(&p, script).unwrap();
        let status = std::process::Command::new("bash")
            .arg("-n")
            .arg(&p)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn ere_escaping() {
        assert_eq!(ere_escape("/opt/t.x/talahon+1"), "/opt/t\\.x/talahon\\+1");
    }

    #[test]
    fn hardening_defaults() {
        assert_eq!(Hardening::default_for_runtime("docker"), Hardening::Strict);
        assert_eq!(Hardening::default_for_runtime("podman"), Hardening::None);
        assert_eq!(Hardening::parse("basic"), Some(Hardening::Basic));
        assert_eq!(Hardening::parse("max"), None);
    }

    // --- installation flows -------------------------------------------------

    fn ctx_with_binary(dir: &Path, runner: Arc<MockRunner>) -> SetupContext {
        let mut ctx = SetupContext::new(&dir.join("proj"), &dir.join("home"), runner);
        let bin = dir.join("bin/talahon");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        ctx.talon_binary = bin;
        ctx.service_settle = Duration::ZERO;
        ctx.config.container_runtime = "docker".into();
        ctx
    }

    #[tokio::test]
    async fn missing_binary_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_binary(dir.path(), Arc::new(MockRunner::new()));
        ctx.talon_binary = dir.path().join("nope");
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        assert_eq!(out.block.unwrap().get("ERROR"), Some("binary_not_found"));
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn linux_without_systemd_writes_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_binary(dir.path(), Arc::new(MockRunner::new()));
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_TYPE"), Some("nohup"));
        assert_eq!(b.get("FALLBACK"), Some("no_systemd"));
        let wrapper = nohup_wrapper_path(&ctx.project_root);
        assert_eq!(crate::fsutil::file_mode(&wrapper), Some(0o755));
        for d in ["store", "data", "groups", "logs"] {
            assert!(ctx.project_root.join(d).is_dir());
        }
    }

    #[tokio::test]
    async fn systemd_user_install_flow() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl --user daemon-reload", CommandOutput::ok(""));
        runner.on("systemd-run", CommandOutput::ok("ok"));
        runner.on("loginctl enable-linger", CommandOutput::ok(""));
        runner.on("systemctl --user enable talahon", CommandOutput::ok(""));
        runner.on("systemctl --user restart talahon", CommandOutput::ok(""));
        runner.on(
            "systemctl --user is-active talahon",
            CommandOutput::ok("active"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner.clone());
        ctx.platform.has_systemd = true;
        ctx.platform.uid = Some(1000);

        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_TYPE"), Some("systemd-user"));
        assert_eq!(b.get("SERVICE_LOADED"), Some("true"));
        assert_eq!(b.get("HARDENING"), Some("strict"));
        assert_eq!(b.get("LINGER_ENABLED"), Some("true"));
        assert_eq!(b.get("DOCKER_GROUP_STALE"), None);
        let unit =
            std::fs::read_to_string(ctx.home_dir.join(".config/systemd/user/talahon.service"))
                .unwrap();
        assert!(unit.contains(&format!("ExecStart={} run", ctx.talon_binary.display())));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(runner.called("pkill -f ^"));
    }

    #[tokio::test]
    async fn strict_sandbox_failure_falls_back_to_basic() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl --user daemon-reload", CommandOutput::ok(""));
        runner.on("systemd-run", CommandOutput::failed(1, "no"));
        runner.on("docker info", CommandOutput::ok("27"));
        runner.on(
            "systemctl --user show -p ExecMainStatus",
            CommandOutput::ok("226\n"),
        );
        // is-active never succeeds (unscripted -> exit 127).
        let mut ctx = ctx_with_binary(dir.path(), runner.clone());
        ctx.platform.has_systemd = true;
        ctx.platform.uid = Some(1000);
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("HARDENING"), Some("basic"));
        assert_eq!(b.get("SERVICE_LOADED"), Some("false"));
        assert_eq!(b.get("DOCKER_GROUP_STALE"), Some("true"));
        // A service that does not run is no success.
        assert_eq!(b.get("STATUS"), Some("failed"));
        assert_eq!(b.get("ERROR"), Some("service_not_running"));
        assert_eq!(out.exit_code, 1);
        let unit =
            std::fs::read_to_string(ctx.home_dir.join(".config/systemd/user/talahon.service"))
                .unwrap();
        assert!(!unit.contains("ProtectSystem"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        // The downgraded unit keeps the resource limits.
        assert!(unit.contains("LimitNOFILE=65536"));
        assert!(unit.contains("TasksMax=4096"));
        assert_eq!(
            runner
                .calls()
                .iter()
                .filter(|c| c.contains("restart talahon"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn application_failure_keeps_strict_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl --user daemon-reload", CommandOutput::ok(""));
        runner.on("systemd-run", CommandOutput::ok(""));
        runner.on(
            "systemctl --user show -p ExecMainStatus",
            CommandOutput::ok("1\n"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner.clone());
        ctx.platform.has_systemd = true;
        ctx.platform.uid = Some(1000);
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("HARDENING"), Some("strict"));
        assert_eq!(b.get("SERVICE_LOADED"), Some("false"));
        assert_eq!(
            runner
                .calls()
                .iter()
                .filter(|c| c.contains("restart talahon"))
                .count(),
            1
        );
        assert!(is_exec_setup_failure(226));
        assert!(!is_exec_setup_failure(1));
    }

    #[tokio::test]
    async fn no_user_session_falls_back_to_nohup() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "systemctl --user daemon-reload",
            CommandOutput::failed(1, "Failed to connect to bus"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner);
        ctx.platform.has_systemd = true;
        ctx.platform.uid = Some(1000);
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_TYPE"), Some("nohup"));
        assert_eq!(b.get("FALLBACK"), Some("no_user_session"));
    }

    #[tokio::test]
    async fn podman_defaults_to_no_sandbox_and_override_works() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl --user daemon-reload", CommandOutput::ok(""));
        runner.on(
            "systemctl --user is-active talahon",
            CommandOutput::ok("active"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner);
        ctx.platform.has_systemd = true;
        ctx.platform.uid = Some(1000);
        ctx.config.container_runtime = "podman".into();
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        assert_eq!(out.block.unwrap().get("HARDENING"), Some("none"));
        let out = run(&StepArgs::new(["--hardening", "basic"]), &ctx)
            .await
            .unwrap();
        assert_eq!(out.block.unwrap().get("HARDENING"), Some("basic"));
        let out = run(&StepArgs::new(["--hardening", "max"]), &ctx)
            .await
            .unwrap();
        assert_eq!(out.exit_code, 4);
    }

    #[tokio::test]
    async fn systemd_install_replaces_the_pre_rename_unit() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl --user daemon-reload", CommandOutput::ok(""));
        runner.on("systemd-run", CommandOutput::ok("ok"));
        runner.on(
            "systemctl --user disable --now talon",
            CommandOutput::ok(""),
        );
        runner.on("systemctl --user enable talahon", CommandOutput::ok(""));
        runner.on("systemctl --user restart talahon", CommandOutput::ok(""));
        runner.on(
            "systemctl --user is-active talahon",
            CommandOutput::ok("active"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner.clone());
        ctx.platform.has_systemd = true;
        ctx.platform.uid = Some(1000);
        // The unit of a 2.x installation.
        let unit_dir = ctx.home_dir.join(".config/systemd/user");
        std::fs::create_dir_all(&unit_dir).unwrap();
        let legacy = unit_dir.join("talon.service");
        std::fs::write(&legacy, "[Service]\nExecStart=/opt/talon/bin/talon run\n").unwrap();
        assert_eq!(LEGACY_SERVICE_NAME, "talon");

        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_LOADED"), Some("true"));
        assert_eq!(b.get("LEGACY_SERVICE_REMOVED"), Some("true"));
        assert!(!legacy.exists(), "the old unit file must be gone");
        assert!(unit_dir.join("talahon.service").is_file());

        let calls = runner.calls();
        let pos = |needle: &str| {
            calls
                .iter()
                .position(|c| c == needle)
                .unwrap_or_else(|| panic!("{needle} not run: {calls:?}"))
        };
        // Stopped and disabled before the new service starts.
        assert!(
            pos("systemctl --user disable --now talon") < pos("systemctl --user restart talahon")
        );
        // A manually started instance of either binary name is stopped too.
        let dir_re = ere_escape(&dir.path().join("bin").display().to_string());
        assert!(calls.contains(&format!("pkill -f ^{dir_re}/talahon run")));
        assert!(calls.contains(&format!("pkill -f ^{dir_re}/talon run")));

        // Nothing to migrate the second time.
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        assert_eq!(
            out.block.unwrap().get("LEGACY_SERVICE_REMOVED"),
            Some("false")
        );
        assert_eq!(
            runner
                .calls()
                .iter()
                .filter(|c| c.as_str() == "systemctl --user disable --now talon")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn launchd_install_replaces_the_pre_rename_agent() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("launchctl ", CommandOutput::ok(""));
        runner.on(
            "launchctl list",
            CommandOutput::ok("PID\tStatus\tLabel\n123\t0\tcom.talahon\n"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner.clone());
        ctx.platform.platform = Platform::MacOs;
        let agents = ctx.home_dir.join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        let legacy = agents.join("com.talon.plist");
        std::fs::write(&legacy, "<plist/>").unwrap();
        assert_eq!(LEGACY_LAUNCHD_LABEL, "com.talon");

        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_LOADED"), Some("true"));
        assert_eq!(b.get("LEGACY_SERVICE_REMOVED"), Some("true"));
        assert!(!legacy.exists());
        assert!(agents.join("com.talahon.plist").is_file());
        let calls = runner.calls();
        let unload_old = calls
            .iter()
            .position(|c| c == &format!("launchctl unload -w {}", legacy.display()))
            .expect("old agent unloaded");
        let load_new = calls
            .iter()
            .position(|c| c.starts_with("launchctl load -w "))
            .expect("new agent loaded");
        assert!(unload_old < load_new);
    }

    #[tokio::test]
    async fn nohup_install_replaces_the_pre_rename_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_binary(dir.path(), Arc::new(MockRunner::new()));
        std::fs::create_dir_all(&ctx.project_root).unwrap();
        let legacy = legacy_nohup_wrapper_path(&ctx.project_root);
        assert!(legacy.ends_with("start-talon.sh"));
        std::fs::write(&legacy, "#!/bin/bash\n").unwrap();
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_TYPE"), Some("nohup"));
        assert_eq!(b.get("LEGACY_SERVICE_REMOVED"), Some("true"));
        assert!(!legacy.exists());
        // The new wrapper stops an instance recorded in the old PID file.
        let script = std::fs::read_to_string(nohup_wrapper_path(&ctx.project_root)).unwrap();
        let old_pid = legacy_pid_file_path(&ctx.project_root);
        assert!(old_pid.ends_with("talon.pid"));
        assert!(script.contains(&format!("LEGACY_PID_FILE='{}'", old_pid.display())));
        assert!(script.contains(&format!(
            "LEGACY_BIN='{}'",
            dir.path().join("bin/talon").display()
        )));
        assert!(script.contains("-e \"$BIN run\" -e \"$LEGACY_BIN run\""));
        assert!(script.contains("rm -f \"$LEGACY_PID_FILE\""));
    }

    #[tokio::test]
    async fn launchd_flow() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("launchctl load", CommandOutput::ok(""));
        runner.on(
            "launchctl list",
            CommandOutput::ok("PID\tStatus\tLabel\n123\t0\tcom.talahon\n-\t0\tcom.talahonx\n"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner);
        ctx.platform.platform = Platform::MacOs;
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_TYPE"), Some("launchd"));
        assert_eq!(b.get("SERVICE_LOADED"), Some("true"));
        assert!(
            ctx.home_dir
                .join("Library/LaunchAgents/com.talahon.plist")
                .exists()
        );
    }
}
