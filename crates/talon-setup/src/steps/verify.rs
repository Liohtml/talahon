//! Step `verify`: end-to-end health report.
//!
//! `STATUS: success` requires a running service, a reachable vLLM serving
//! the configured model, at least one configured channel and at least one
//! registered group. `CREDENTIALS` reports whether
//! `TALAHON_VLLM_BASE_URL`/`TALAHON_VLLM_MODEL` are set.
//!
//! `WARNINGS` lists settings that expose the host to agent containers
//! (`vllm_api_key_unset`, `http_bind_all_interfaces`, see
//! [`exposure_issues`]); they do not fail verification.

use std::collections::BTreeMap;

use super::StepArgs;
use super::service::{
    LAUNCHD_LABEL, LEGACY_LAUNCHD_LABEL, LEGACY_SERVICE_NAME, SERVICE_NAME, legacy_binary_path,
    legacy_pid_file_path, pid_file_path,
};
use super::vllm::add_vllm_fields;
use crate::checks::{
    VllmStatus, check_configured_vllm, detect_runtime, exposure_issues, image_present,
    legacy_image_present,
};
use crate::context::{SETUP_LOG, SetupContext};
use crate::platform::ServiceManager;
use crate::runner::CommandSpec;
use crate::status::{StatusBlock, StepOutcome};

/// Service state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Running.
    Running,
    /// Installed but not running.
    Stopped,
    /// Not installed.
    NotFound,
}

impl ServiceState {
    /// `running` | `stopped` | `not_found`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceState::Running => "running",
            ServiceState::Stopped => "stopped",
            ServiceState::NotFound => "not_found",
        }
    }
}

/// The names one installation of the service goes by.
struct ServiceNames<'a> {
    systemd: &'a str,
    launchd: &'a str,
    pid_file: std::path::PathBuf,
}

/// Determine whether the Talahon service is installed / running, under its
/// current name or the one it had up to 2.x (`talon.service`, `com.talon`,
/// `talon.pid`); see [`service_report`] to tell the two apart.
pub async fn service_state(ctx: &SetupContext) -> ServiceState {
    service_report(ctx).await.0
}

/// [`service_state`] plus whether that state belongs to the service under
/// its pre-rename name (`talahon setup service` replaces it). The current
/// name wins unless only the old one is installed or running.
pub async fn service_report(ctx: &SetupContext) -> (ServiceState, bool) {
    let current = state_of(
        ctx,
        &ServiceNames {
            systemd: SERVICE_NAME,
            launchd: LAUNCHD_LABEL,
            pid_file: pid_file_path(&ctx.project_root),
        },
    )
    .await;
    if current == ServiceState::Running {
        return (current, false);
    }
    let legacy = state_of(
        ctx,
        &ServiceNames {
            systemd: LEGACY_SERVICE_NAME,
            launchd: LEGACY_LAUNCHD_LABEL,
            pid_file: legacy_pid_file_path(&ctx.project_root),
        },
    )
    .await;
    match (current, legacy) {
        (_, ServiceState::Running) => (ServiceState::Running, true),
        (ServiceState::NotFound, ServiceState::Stopped) => (ServiceState::Stopped, true),
        (current, _) => (current, false),
    }
}

async fn state_of(ctx: &SetupContext, names: &ServiceNames<'_>) -> ServiceState {
    let runner = ctx.runner.as_ref();
    match ctx.platform.service_manager() {
        ServiceManager::Launchd => {
            let out = runner.run(&CommandSpec::new("launchctl", ["list"])).await;
            if !out.success() {
                return ServiceState::NotFound;
            }
            out.stdout
                .lines()
                .map(|l| l.split_whitespace().collect::<Vec<_>>())
                .find(|cols| cols.get(2) == Some(&names.launchd))
                .map_or(ServiceState::NotFound, |cols| match cols.first() {
                    Some(pid) if *pid != "-" => ServiceState::Running,
                    _ => ServiceState::Stopped,
                })
        }
        ServiceManager::Systemd => {
            let mut base: Vec<&str> = Vec::new();
            if !ctx.platform.is_root() {
                base.push("--user");
            }
            let with = |extra: &[&str]| -> Vec<String> {
                base.iter()
                    .chain(extra.iter())
                    .map(|s| (*s).to_string())
                    .collect()
            };
            let active = runner
                .run(&CommandSpec::new(
                    "systemctl",
                    with(&["is-active", names.systemd]),
                ))
                .await;
            if active.success() {
                return ServiceState::Running;
            }
            let files = runner
                .run(&CommandSpec::new("systemctl", with(&["list-unit-files"])))
                .await;
            let unit = format!("{}.service", names.systemd);
            if files.success()
                && files
                    .stdout
                    .lines()
                    .any(|l| l.split_whitespace().next() == Some(unit.as_str()))
            {
                ServiceState::Stopped
            } else {
                ServiceState::NotFound
            }
        }
        ServiceManager::None => {
            let Ok(raw) = std::fs::read_to_string(&names.pid_file) else {
                return ServiceState::NotFound;
            };
            match raw.trim().parse::<u32>() {
                Ok(pid) if pid > 0 => {
                    // The recorded PID may belong to another process by now
                    // (reboot, crash): it counts only while it runs Talahon.
                    let ps = runner
                        .run(&CommandSpec::new(
                            "ps",
                            [
                                "-p".to_string(),
                                pid.to_string(),
                                "-o".into(),
                                "args=".into(),
                            ],
                        ))
                        .await;
                    // Either binary name: an instance started before the
                    // upgrade still runs as `talon`.
                    let ours = format!("{} run", ctx.talon_binary.display());
                    let legacy = format!("{} run", legacy_binary_path(&ctx.talon_binary).display());
                    if ps.success() && (ps.stdout.contains(&ours) || ps.stdout.contains(&legacy)) {
                        ServiceState::Running
                    } else {
                        ServiceState::Stopped
                    }
                }
                _ => ServiceState::Stopped,
            }
        }
    }
}

/// Channels with credentials present (values are never read out).
pub fn configured_channels(ctx: &SetupContext) -> BTreeMap<&'static str, &'static str> {
    let env = &ctx.config.env;
    let has = |k: &str| env.get(k).is_some_and(|v| !v.trim().is_empty());
    let mut channels = BTreeMap::new();
    if has("HTTP_API_KEY") {
        channels.insert("http", "configured");
    }
    if has("TELEGRAM_BOT_TOKEN") {
        channels.insert("telegram", "configured");
    }
    if has("WEBHOOK_URL") {
        channels.insert("webhook", "configured");
    }
    if has("EMACS_AUTH_TOKEN") {
        channels.insert("emacs", "configured");
    }
    channels
}

/// Run the step.
///
/// # Errors
/// Never fails internally; problems are reported in the block.
pub async fn run(_args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    tracing::info!("Starting verification");
    let (service, legacy_service) = service_report(ctx).await;

    let runtimes = detect_runtime(ctx.runner.as_ref(), &ctx.config.container_runtime).await;
    let image_ok = match &runtimes.selected {
        Some(rt) => image_present(ctx.runner.as_ref(), rt, &ctx.config.container_image).await,
        None => false,
    };

    let (vllm_cfg, vllm) = check_configured_vllm(ctx).await;
    let api_key_set = ctx
        .config
        .env
        .file_value(crate::checks::api_key_env(ctx))
        .is_some();

    let channels = configured_channels(ctx);
    let channel_names: Vec<&str> = channels.keys().copied().collect();
    let channel_auth = serde_json::to_string(&channels).unwrap_or_else(|_| "{}".into());

    let registered = ctx.registered_group_count().await.unwrap_or(0);
    let allowlist = if ctx.mount_allowlist_path().exists() {
        match std::fs::read_to_string(ctx.mount_allowlist_path())
            .ok()
            .and_then(|s| serde_json::from_str::<talon_core::types::MountAllowlist>(&s).ok())
        {
            Some(_) => "configured",
            None => "invalid",
        }
    } else {
        "missing"
    };

    let ok = service == ServiceState::Running
        && vllm.status == VllmStatus::Ok
        && !channels.is_empty()
        && registered > 0;

    let mut block = StatusBlock::new("VERIFY")
        .field("SERVICE", service.as_str())
        .field(
            "CONTAINER_RUNTIME",
            runtimes.selected.as_deref().unwrap_or("none"),
        )
        .field("IMAGE", &ctx.config.container_image)
        .field("IMAGE_PRESENT", image_ok)
        .field(
            "CREDENTIALS",
            if vllm_cfg.is_some() {
                "configured"
            } else {
                "missing"
            },
        );
    if legacy_service {
        // Still `talon.service` / `com.talon` / `talon.pid`:
        // `talahon setup service` replaces it.
        block.set("SERVICE_HAS_OLD_NAME", true);
    }
    if !image_ok
        && let Some(rt) = &runtimes.selected
        && let Some(legacy) =
            legacy_image_present(ctx.runner.as_ref(), rt, &ctx.config.container_image).await
    {
        // Not used in place of the configured image: rebuild it.
        block.set("LEGACY_IMAGE", legacy);
    }
    add_vllm_fields(&mut block, vllm_cfg.as_ref(), api_key_set, &vllm);
    block.set("CONFIGURED_CHANNELS", channel_names.join(","));
    block.set("CHANNEL_AUTH", channel_auth);
    block.set("REGISTERED_GROUPS", registered);
    block.set("MOUNT_ALLOWLIST", allowlist);
    let warnings = exposure_issues(&ctx.config.env);
    if !warnings.is_empty() {
        tracing::warn!(warnings = %warnings.join(","), "Host exposed to agent containers");
    }
    block.set(
        "WARNINGS",
        if warnings.is_empty() {
            "none".to_string()
        } else {
            warnings.join(",")
        },
    );
    block.set("STATUS", if ok { "success" } else { "failed" });
    block.set("LOG", SETUP_LOG);
    tracing::info!(
        status = if ok { "success" } else { "failed" },
        "Verification complete"
    );
    Ok(StepOutcome::with_code(block, if ok { 0 } else { 1 }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::platform::Platform;
    use crate::runner::CommandOutput;
    use crate::runner::mock::MockRunner;

    fn ctx(dir: &std::path::Path, runner: Arc<MockRunner>, env: &str) -> SetupContext {
        std::fs::write(dir.join(".env"), env).unwrap();
        SetupContext::new(dir, dir, runner)
    }

    #[tokio::test]
    async fn systemd_service_states() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "systemctl --user is-active talahon",
            CommandOutput::ok("active"),
        );
        let mut c = ctx(dir.path(), runner, "");
        c.platform.has_systemd = true;
        c.platform.uid = Some(1000);
        assert_eq!(service_state(&c).await, ServiceState::Running);

        let runner = Arc::new(MockRunner::new());
        runner.on(
            "systemctl --user list-unit-files",
            CommandOutput::ok("talahon.service disabled enabled\n"),
        );
        c.runner = runner;
        assert_eq!(service_state(&c).await, ServiceState::Stopped);

        let runner = Arc::new(MockRunner::new());
        runner.on(
            "systemctl --user list-unit-files",
            CommandOutput::ok("talonx.service enabled\n"),
        );
        c.runner = runner;
        assert_eq!(service_state(&c).await, ServiceState::NotFound);

        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl is-active talahon", CommandOutput::ok("active"));
        c.runner = runner;
        c.platform.uid = Some(0);
        assert_eq!(service_state(&c).await, ServiceState::Running);
    }

    #[tokio::test]
    async fn launchd_and_pidfile_states() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "launchctl list",
            CommandOutput::ok("PID Status Label\n-\t0\tcom.talon\n"),
        );
        let mut c = ctx(dir.path(), runner, "");
        c.platform.platform = Platform::MacOs;
        assert_eq!(service_state(&c).await, ServiceState::Stopped);

        c.platform.platform = Platform::Linux;
        assert_eq!(service_state(&c).await, ServiceState::NotFound);
        std::fs::write(dir.path().join("talahon.pid"), "4242\n").unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "ps -p 4242 -o args=",
            CommandOutput::ok(&format!("{} run\n", c.talon_binary.display())),
        );
        c.runner = runner;
        assert_eq!(service_state(&c).await, ServiceState::Running);
        // A stale PID now used by another process is not Talahon.
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "ps -p 4242 -o args=",
            CommandOutput::ok("/usr/sbin/sshd -D\n"),
        );
        c.runner = runner;
        assert_eq!(service_state(&c).await, ServiceState::Stopped);
        std::fs::write(dir.path().join("talahon.pid"), "garbage").unwrap();
        assert_eq!(service_state(&c).await, ServiceState::Stopped);
    }

    #[tokio::test]
    async fn the_pre_rename_service_names_are_still_recognised() {
        let dir = tempfile::tempdir().unwrap();
        // systemd: only `talon.service` is active.
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "systemctl --user is-active talon",
            CommandOutput::ok("active"),
        );
        let mut c = ctx(dir.path(), runner, "");
        c.platform.has_systemd = true;
        c.platform.uid = Some(1000);
        assert_eq!(service_report(&c).await, (ServiceState::Running, true));
        let b = run(&StepArgs::default(), &c).await.unwrap().block.unwrap();
        assert_eq!(b.get("SERVICE"), Some("running"));
        assert_eq!(b.get("SERVICE_HAS_OLD_NAME"), Some("true"));

        // Installed under the old name, not running.
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "systemctl --user list-unit-files",
            CommandOutput::ok("talon.service enabled enabled\n"),
        );
        c.runner = runner;
        assert_eq!(service_report(&c).await, (ServiceState::Stopped, true));

        // Both installed, the new one running: that is the one reported.
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "systemctl --user is-active talahon",
            CommandOutput::ok("active"),
        );
        runner.on(
            "systemctl --user is-active talon",
            CommandOutput::ok("active"),
        );
        c.runner = runner;
        assert_eq!(service_report(&c).await, (ServiceState::Running, false));

        // launchd: `com.talon` loaded and running.
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "launchctl list",
            CommandOutput::ok("PID Status Label\n77\t0\tcom.talon\n"),
        );
        let mut c = ctx(dir.path(), runner, "");
        c.platform.platform = Platform::MacOs;
        assert_eq!(service_report(&c).await, (ServiceState::Running, true));
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "launchctl list",
            CommandOutput::ok("PID Status Label\n77\t0\tcom.talahon\n"),
        );
        c.runner = runner;
        assert_eq!(service_report(&c).await, (ServiceState::Running, false));

        // No service manager: `talon.pid` of an instance started as `talon`.
        c.platform.platform = Platform::Linux;
        std::fs::write(dir.path().join("talon.pid"), "4242\n").unwrap();
        let old_binary = c.talon_binary.with_file_name("talon");
        let runner = Arc::new(MockRunner::new());
        runner.on(
            "ps -p 4242 -o args=",
            CommandOutput::ok(&format!("{} run\n", old_binary.display())),
        );
        c.runner = runner;
        assert_eq!(service_report(&c).await, (ServiceState::Running, true));
    }

    #[tokio::test]
    async fn a_missing_image_names_the_pre_rename_one_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.install("docker");
        runner.on("docker info", CommandOutput::ok("27"));
        runner.on(
            "docker image inspect --format {{.Id}} talon-agent:latest",
            CommandOutput::ok("sha256:old"),
        );
        let c = ctx(dir.path(), runner, "");
        let b = run(&StepArgs::default(), &c).await.unwrap().block.unwrap();
        assert_eq!(b.get("IMAGE"), Some("talahon-agent:latest"));
        assert_eq!(b.get("IMAGE_PRESENT"), Some("false"));
        assert_eq!(b.get("LEGACY_IMAGE"), Some("talon-agent:latest"));
    }

    #[tokio::test]
    async fn channels_detected_without_leaking_values() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(
            dir.path(),
            Arc::new(MockRunner::new()),
            "HTTP_API_KEY=supersecret\nTELEGRAM_BOT_TOKEN=123:abc\n",
        );
        let channels = configured_channels(&c);
        assert!(channels.contains_key("http"));
        assert!(channels.contains_key("telegram"));

        let out = run(&StepArgs::default(), &c).await.unwrap();
        let text = out.render();
        assert!(!text.contains("supersecret"));
        assert!(!text.contains("123:abc"));
        let b = out.block.unwrap();
        assert_eq!(b.get("CONFIGURED_CHANNELS"), Some("http,telegram"));
        assert_eq!(
            b.get("CHANNEL_AUTH"),
            Some(r#"{"http":"configured","telegram":"configured"}"#)
        );
        // No service / vLLM / groups in a bare directory.
        assert_eq!(b.get("SERVICE"), Some("not_found"));
        assert_eq!(b.get("REGISTERED_GROUPS"), Some("0"));
        assert_eq!(b.get("MOUNT_ALLOWLIST"), Some("missing"));
        assert_eq!(b.status(), Some("failed"));
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn exposure_warnings_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(
            dir.path(),
            Arc::new(MockRunner::new()),
            "COPILOT_HTTP_BIND=::\nHTTP_API_KEY=x\n",
        );
        let b = run(&StepArgs::default(), &c).await.unwrap().block.unwrap();
        let warnings = b.get("WARNINGS").unwrap();
        assert!(warnings.contains("vllm_api_key_unset"), "{warnings}");
        if std::env::var_os("COPILOT_HTTP_BIND").is_none() {
            assert_eq!(warnings, "vllm_api_key_unset,http_bind_all_interfaces");
        }

        let dir = tempfile::tempdir().unwrap();
        let c = ctx(
            dir.path(),
            Arc::new(MockRunner::new()),
            "TALAHON_VLLM_API_KEY=secret-key\nCOPILOT_HTTP_BIND=127.0.0.1\n",
        );
        let out = run(&StepArgs::default(), &c).await.unwrap();
        assert!(!out.render().contains("secret-key"));
        if std::env::var_os("COPILOT_HTTP_BIND").is_none() {
            assert_eq!(out.block.unwrap().get("WARNINGS"), Some("none"));
        }
    }

    #[tokio::test]
    async fn invalid_allowlist_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path(), Arc::new(MockRunner::new()), "");
        std::fs::create_dir_all(&c.config_dir).unwrap();
        std::fs::write(c.mount_allowlist_path(), "{oops").unwrap();
        let out = run(&StepArgs::default(), &c).await.unwrap();
        assert_eq!(out.block.unwrap().get("MOUNT_ALLOWLIST"), Some("invalid"));
    }
}
