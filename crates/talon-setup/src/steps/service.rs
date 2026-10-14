//! Step `service` (port of `setup/service.ts`): install Talon as a
//! background service running `<talon binary> run`.
//!
//! - **Linux + systemd**: a user unit (`~/.config/systemd/user/talon.service`,
//!   linger enabled) or, as root, a system unit. The unit is sandboxed
//!   ([`Hardening`]) as far as is compatible with driving the container
//!   runtime; if the strict sandbox prevents the service from starting
//!   (e.g. unprivileged user namespaces disabled), it is rewritten with the
//!   basic set and restarted.
//! - **macOS**: a launchd agent (`~/Library/LaunchAgents/com.talon.plist`).
//! - **No systemd** (WSL, containers): a `start-talon.sh` nohup wrapper.
//!
//! Every generated file is built with proper escaping for its format
//! (systemd specifiers/quoting, XML, POSIX shell), so unusual paths cannot
//! inject directives or commands.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};

use super::StepArgs;
use crate::context::{SETUP_LOG, SetupContext};
use crate::fsutil::{exists_nofollow, write_atomic};
use crate::platform::{Platform, ServiceManager};
use crate::runner::{CommandOutput, CommandSpec};
use crate::status::{StatusBlock, StepOutcome};

/// systemd unit name (without `.service`).
pub const SERVICE_NAME: &str = "talon";
/// launchd label.
pub const LAUNCHD_LABEL: &str = "com.talon";
/// Unit name of the TypeScript release.
pub const LEGACY_SERVICE_NAME: &str = "nanoclaw";

/// systemd sandboxing level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hardening {
    /// Full sandbox: read-only system/home except Talon's state directories,
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
    /// Absolute path of the `talon` binary (`ExecStart=<binary> run`).
    pub binary: PathBuf,
    /// Talon project directory (working directory, state, logs).
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
        self.project_root.join("logs").join("talon.log")
    }

    fn error_log_file(&self) -> PathBuf {
        self.project_root.join("logs").join("talon.error.log")
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
        "Description=Talon AI SOC Analyst".into(),
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

/// `<project_root>/start-talon.sh`
pub fn nohup_wrapper_path(project_root: &Path) -> PathBuf {
    project_root.join("start-talon.sh")
}

/// `<project_root>/talon.pid`
pub fn pid_file_path(project_root: &Path) -> PathBuf {
    project_root.join("talon.pid")
}

/// Generate the nohup wrapper script used without systemd.
///
/// # Errors
/// Non-UTF-8 paths.
pub fn nohup_wrapper(spec: &ServiceSpec) -> anyhow::Result<String> {
    let root = shell_quote(&display(&spec.project_root)?);
    let bin = shell_quote(&display(&spec.binary)?);
    let pid = shell_quote(&display(&pid_file_path(&spec.project_root))?);
    let out_log = shell_quote(&display(&spec.log_file())?);
    let err_log = shell_quote(&display(&spec.error_log_file())?);
    let lines = [
        "#!/bin/bash".to_string(),
        "# start-talon.sh — start Talon without systemd".into(),
        format!("# To stop: kill \"$(cat {pid})\""),
        String::new(),
        "set -euo pipefail".into(),
        String::new(),
        format!("cd {root}"),
        format!("PID_FILE={pid}"),
        String::new(),
        "# Stop an existing instance".into(),
        "if [ -f \"$PID_FILE\" ]; then".into(),
        "  OLD_PID=$(cat \"$PID_FILE\" 2>/dev/null || echo \"\")".into(),
        "  if [ -n \"$OLD_PID\" ] && kill -0 \"$OLD_PID\" 2>/dev/null; then".into(),
        "    echo \"Stopping existing Talon (PID $OLD_PID)...\"".into(),
        "    kill \"$OLD_PID\" 2>/dev/null || true".into(),
        "    sleep 2".into(),
        "  fi".into(),
        "fi".into(),
        String::new(),
        "echo \"Starting Talon...\"".into(),
        "umask 027".into(),
        format!("nohup {bin} run >> {out_log} 2>> {err_log} &"),
        String::new(),
        "echo $! > \"$PID_FILE\"".into(),
        "echo \"Talon started (PID $!)\"".into(),
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

    Ok(StepOutcome::ok(
        base_block(ctx, "launchd")
            .field("PLIST_PATH", plist_path.display())
            .field("SERVICE_LOADED", loaded)
            .field("STATUS", "success")
            .field("LOG", SETUP_LOG),
    ))
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
    let legacy_present = exists_nofollow(&unit_dir.join(format!("{LEGACY_SERVICE_NAME}.service")));

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

    // Stop stray manual instances that would fight over channel connections.
    if let Ok(bin) = display(&ctx.talon_binary) {
        let pattern = format!("^{} run", ere_escape(&bin));
        let _ = run_cmd(ctx, "pkill", &["-f", &pattern]).await;
    }

    let mut linger = false;
    if !as_root {
        linger = run_cmd(ctx, "loginctl", &["enable-linger"]).await.success();
        if !linger {
            tracing::warn!("loginctl enable-linger failed — service may stop on logout");
        }
    }

    let sc = |extra: &[&'static str]| -> Vec<&str> {
        systemctl
            .iter()
            .copied()
            .chain(extra.iter().copied())
            .collect()
    };
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
        // NAMESPACE) — not when Talon started and then exited on its own.
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
    .field("SERVICE_LOADED", active)
    .field("HARDENING", hardening.as_str());
    if stale {
        block.set("DOCKER_GROUP_STALE", true);
    }
    if legacy_present {
        block.set("LEGACY_SERVICE", format!("{LEGACY_SERVICE_NAME}.service"));
    }
    block.set("LINGER_ENABLED", linger);
    block.set("STATUS", "success");
    block.set("LOG", SETUP_LOG);
    Ok(StepOutcome::ok(block))
}

fn setup_nohup(ctx: &SetupContext, fallback: &str) -> anyhow::Result<StepOutcome> {
    tracing::warn!("No usable systemd — generating nohup wrapper script");
    let path = nohup_wrapper_path(&ctx.project_root);
    let script = nohup_wrapper(&spec_for(ctx, Hardening::None))?;
    write_atomic(&path, script.as_bytes(), Some(0o755))?;
    tracing::info!(path = %path.display(), "Wrote nohup wrapper script");
    Ok(StepOutcome::ok(
        base_block(ctx, "nohup")
            .field("WRAPPER_PATH", path.display())
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
            binary: PathBuf::from("/opt/talon/bin/talon"),
            project_root: PathBuf::from("/home/user/talon"),
            home_dir: PathBuf::from("/home/user"),
            system_unit: system,
            hardening,
            extra_rw_paths: Vec::new(),
        }
    }

    // --- systemd unit (ports of service.test.ts) ----------------------------

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
        assert!(unit.contains("ExecStart=/opt/talon/bin/talon run\n"));
        assert!(unit.contains("WorkingDirectory=/home/user/talon\n"));
        assert!(unit.contains("StandardOutput=append:/home/user/talon/logs/talon.log"));
        assert!(unit.contains("StandardError=append:/home/user/talon/logs/talon.error.log"));
        assert!(unit.contains("Environment=HOME=/home/user\n"));
    }

    #[test]
    fn strict_unit_is_sandboxed() {
        let unit = systemd_unit(&spec(Hardening::Strict, false)).unwrap();
        for directive in [
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ReadWritePaths=/home/user/talon/store /home/user/talon/data /home/user/talon/groups /home/user/talon/logs\n",
            "ReadWritePaths=-/home/user/.docker -/home/user/talon/mempalace-data\n",
            "PrivateTmp=yes",
            "ProtectKernelTunables=yes",
            "ProtectControlGroups=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "UMask=0027",
        ] {
            assert!(unit.contains(directive), "missing {directive}\n{unit}");
        }
        // The mount allowlist (~/.config/talon) must stay read-only.
        assert!(!unit.contains(".config/talon"));
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
    fn unit_escapes_hostile_paths() {
        let mut s = spec(Hardening::Strict, false);
        s.binary = PathBuf::from("/opt/my talon/%h/$HOME/talon");
        s.project_root = PathBuf::from("/srv/t%n");
        let unit = systemd_unit(&s).unwrap();
        assert!(
            unit.contains("ExecStart=\"/opt/my talon/%%h/$$HOME/talon\" run"),
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
        s.project_root = PathBuf::from("/srv/my talon");
        let unit = systemd_unit(&s).unwrap();
        assert!(!unit.contains("StandardOutput=append"));
        assert!(unit.contains("ReadWritePaths=\"/srv/my talon/store\""));
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
        assert!(plist.contains("<string>com.talon</string>"));
        assert!(
            plist.contains("<string>/opt/talon/bin/talon</string>\n        <string>run</string>")
        );
        assert!(plist.contains("<string>/home/user/talon</string>"));
        assert!(plist.contains("talon.log"));
        assert!(plist.contains("talon.error.log"));
        assert!(plist.contains("<key>KeepAlive</key>"));
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
        assert!(
            script
                .contains("nohup '/opt/talon/bin/talon' run >> '/home/user/talon/logs/talon.log'")
        );
        assert!(script.contains("talon.pid"));
        assert!(script.contains("set -euo pipefail"));
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
        assert_eq!(ere_escape("/opt/t.x/talon+1"), "/opt/t\\.x/talon\\+1");
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
        let bin = dir.join("bin/talon");
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
        runner.on("systemctl --user enable talon", CommandOutput::ok(""));
        runner.on("systemctl --user restart talon", CommandOutput::ok(""));
        runner.on(
            "systemctl --user is-active talon",
            CommandOutput::ok("active"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner.clone());
        ctx.platform.has_systemd = true;
        ctx.platform.uid = Some(1000);
        std::fs::create_dir_all(ctx.home_dir.join(".config/systemd/user")).unwrap();
        std::fs::write(
            ctx.home_dir.join(".config/systemd/user/nanoclaw.service"),
            "",
        )
        .unwrap();

        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_TYPE"), Some("systemd-user"));
        assert_eq!(b.get("SERVICE_LOADED"), Some("true"));
        assert_eq!(b.get("HARDENING"), Some("strict"));
        assert_eq!(b.get("LINGER_ENABLED"), Some("true"));
        assert_eq!(b.get("LEGACY_SERVICE"), Some("nanoclaw.service"));
        assert_eq!(b.get("DOCKER_GROUP_STALE"), None);
        let unit = std::fs::read_to_string(ctx.home_dir.join(".config/systemd/user/talon.service"))
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
        let unit = std::fs::read_to_string(ctx.home_dir.join(".config/systemd/user/talon.service"))
            .unwrap();
        assert!(!unit.contains("ProtectSystem"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert_eq!(
            runner
                .calls()
                .iter()
                .filter(|c| c.contains("restart talon"))
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
                .filter(|c| c.contains("restart talon"))
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
            "systemctl --user is-active talon",
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
    async fn launchd_flow() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("launchctl load", CommandOutput::ok(""));
        runner.on(
            "launchctl list",
            CommandOutput::ok("PID\tStatus\tLabel\n123\t0\tcom.talon\n-\t0\tcom.talonx\n"),
        );
        let mut ctx = ctx_with_binary(dir.path(), runner);
        ctx.platform.platform = Platform::MacOs;
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SERVICE_TYPE"), Some("launchd"));
        assert_eq!(b.get("SERVICE_LOADED"), Some("true"));
        assert!(
            ctx.home_dir
                .join("Library/LaunchAgents/com.talon.plist")
                .exists()
        );
    }
}
