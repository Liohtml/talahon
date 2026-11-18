//! Step `cve-sync` (`SETUP_CVE_SYNC`): refresh the offline vulnerability
//! data once a day.
//!
//! Installs two systemd **user** units (no root needed):
//!
//! - `talahon-cve-sync.service` — a one-shot `<talahon binary> cve sync` in
//!   the project directory;
//! - `talahon-cve-sync.timer` — starts it daily at a random time between
//!   03:00 and 04:00, and after boot if a run was missed (`Persistent=`).
//!
//! The timer is enabled and started; the first download is not triggered
//! here (run `talahon cve sync` once, or wait for the timer). `--remove`
//! disables the timer and deletes both units.
//!
//! Only the host runs this. The agent containers read the resulting file
//! from a read-only mount and have no network access.
//!
//! Without a systemd user session (macOS, containers, some WSL setups) the
//! step fails with `ERROR: no_systemd_user_session`; schedule
//! `talahon cve sync` with whatever the host offers instead (cron, launchd).

use std::path::PathBuf;

use anyhow::Context as _;

use super::StepArgs;
use super::service::{systemd_path_value, systemd_word};
use crate::context::{SETUP_LOG, SetupContext};
use crate::fsutil::write_atomic;
use crate::platform::ServiceManager;
use crate::runner::{CommandOutput, CommandSpec, is_executable};
use crate::status::{StatusBlock, StepOutcome};

/// Name of the units (`<name>.service`, `<name>.timer`).
pub const UNIT_NAME: &str = "talahon-cve-sync";

/// The one-shot service unit.
///
/// # Errors
/// A path contains a line break.
pub fn service_unit(
    binary: &std::path::Path,
    project_root: &std::path::Path,
) -> anyhow::Result<String> {
    let bin = systemd_word(&binary.to_string_lossy())?;
    let root = systemd_path_value(&project_root.to_string_lossy())?;
    Ok(format!(
        "[Unit]\n\
         Description=Talahon: refresh the offline CVE data (NVD, EPSS, CISA KEV)\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         WorkingDirectory={root}\n\
         ExecStart={bin} cve sync\n\
         # A full first run downloads about 1.5 GB; later runs a few MB.\n\
         TimeoutStartSec=3h\n\
         Nice=10\n\
         IOSchedulingClass=idle\n\
         NoNewPrivileges=yes\n"
    ))
}

/// The timer unit.
pub fn timer_unit() -> String {
    format!(
        "[Unit]\n\
         Description=Talahon: daily refresh of the offline CVE data\n\
         \n\
         [Timer]\n\
         OnCalendar=*-*-* 03:00:00\n\
         RandomizedDelaySec=1h\n\
         Persistent=true\n\
         Unit={UNIT_NAME}.service\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
    )
}

fn unit_dir(ctx: &SetupContext) -> PathBuf {
    ctx.home_dir.join(".config").join("systemd").join("user")
}

async fn systemctl(ctx: &SetupContext, args: &[&str]) -> CommandOutput {
    let mut all = vec!["--user"];
    all.extend_from_slice(args);
    let out = ctx.runner.run(&CommandSpec::new("systemctl", all)).await;
    if !out.success() {
        tracing::debug!(args = %args.join(" "), stderr = %out.stderr.trim(), "systemctl failed");
    }
    out
}

fn failed(block: StatusBlock, error: &str) -> StepOutcome {
    StepOutcome::with_code(
        block
            .field("STATUS", "failed")
            .field("ERROR", error)
            .field("LOG", SETUP_LOG),
        1,
    )
}

/// Run the step.
///
/// # Errors
/// Writing the unit files failed.
pub async fn run(args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    let dir = unit_dir(ctx);
    let service_path = dir.join(format!("{UNIT_NAME}.service"));
    let timer_path = dir.join(format!("{UNIT_NAME}.timer"));
    let timer = format!("{UNIT_NAME}.timer");
    let block = StatusBlock::new("SETUP_CVE_SYNC")
        .field("TIMER", &timer)
        .field("UNIT_DIR", dir.display());

    if ctx.platform.service_manager() != ServiceManager::Systemd
        || !systemctl(ctx, &["daemon-reload"]).await.success()
    {
        return Ok(failed(block, "no_systemd_user_session"));
    }

    if args.flag("--remove") {
        let _ = systemctl(ctx, &["disable", "--now", &timer]).await;
        for path in [&service_path, &timer_path] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
            }
        }
        let _ = systemctl(ctx, &["daemon-reload"]).await;
        return Ok(StepOutcome::ok(
            block.field("STATUS", "success").field("ACTION", "removed"),
        ));
    }

    if !ctx.talon_binary.is_absolute() || !is_executable(&ctx.talon_binary) {
        return Ok(failed(block, "binary_not_found"));
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let service = service_unit(&ctx.talon_binary, &ctx.project_root)?;
    write_atomic(&service_path, service.as_bytes(), Some(0o644))
        .with_context(|| format!("writing {}", service_path.display()))?;
    write_atomic(&timer_path, timer_unit().as_bytes(), Some(0o644))
        .with_context(|| format!("writing {}", timer_path.display()))?;
    ctx.append_log("cve-sync", &format!("installed {}", timer_path.display()));

    let _ = systemctl(ctx, &["daemon-reload"]).await;
    if !systemctl(ctx, &["enable", "--now", &timer]).await.success() {
        return Ok(failed(block, "timer_not_enabled"));
    }
    // Without linger a user timer only runs while the user is logged in.
    let linger = ctx
        .runner
        .run(&CommandSpec::new("loginctl", ["enable-linger"]))
        .await
        .success();
    let active = systemctl(ctx, &["is-active", &timer]).await.success();
    let block = block
        .field("ACTION", "installed")
        .field("SCHEDULE", "daily 03:00 + up to 1h")
        .field("LINGER_ENABLED", linger)
        .field("TIMER_ACTIVE", active)
        .field("NEXT", "run `talahon cve sync` once for the first download");
    if active {
        Ok(StepOutcome::ok(
            block.field("STATUS", "success").field("LOG", SETUP_LOG),
        ))
    } else {
        Ok(failed(block, "timer_not_active"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use super::*;
    use crate::runner::mock::MockRunner;

    fn ctx(dir: &Path, runner: Arc<MockRunner>) -> SetupContext {
        let mut ctx = SetupContext::new(&dir.join("my proj"), &dir.join("home"), runner);
        let bin = dir.join("bin/talahon");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        ctx.talon_binary = bin;
        ctx.platform.platform = crate::platform::Platform::Linux;
        ctx.platform.has_systemd = true;
        ctx.platform.uid = Some(1000);
        ctx
    }

    #[test]
    fn units_are_well_formed() {
        let unit = service_unit(Path::new("/opt/t/talahon"), Path::new("/srv/my %h proj")).unwrap();
        assert!(unit.contains("ExecStart=/opt/t/talahon cve sync\n"));
        assert!(unit.contains("WorkingDirectory=/srv/my %%h proj\n"));
        assert!(unit.contains("Type=oneshot"));
        assert!(!unit.contains("User="), "a user unit");
        // A path cannot smuggle in another directive.
        assert!(service_unit(Path::new("/x\nExecStartPre=/bin/evil"), Path::new("/p")).is_err());
        let unit = service_unit(Path::new("/opt/my bin/talahon"), Path::new("/p")).unwrap();
        assert!(unit.contains("ExecStart=\"/opt/my bin/talahon\" cve sync\n"));
        let timer = timer_unit();
        assert!(timer.contains("OnCalendar=*-*-* 03:00:00"));
        assert!(timer.contains("Persistent=true"));
        assert!(timer.contains("Unit=talahon-cve-sync.service"));
        assert!(timer.contains("WantedBy=timers.target"));
    }

    #[tokio::test]
    async fn installs_and_enables_the_user_timer() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl --user daemon-reload", CommandOutput::ok(""));
        runner.on(
            "systemctl --user enable --now talahon-cve-sync.timer",
            CommandOutput::ok(""),
        );
        runner.on(
            "systemctl --user is-active talahon-cve-sync.timer",
            CommandOutput::ok("active"),
        );
        runner.on("loginctl enable-linger", CommandOutput::ok(""));
        let ctx = ctx(dir.path(), runner.clone());

        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        assert_eq!(out.exit_code, 0);
        let b = out.block.unwrap();
        assert_eq!(b.get("STATUS"), Some("success"));
        assert_eq!(b.get("TIMER_ACTIVE"), Some("true"));
        let units = ctx.home_dir.join(".config/systemd/user");
        let service = std::fs::read_to_string(units.join("talahon-cve-sync.service")).unwrap();
        assert!(service.contains(&format!(
            "ExecStart={} cve sync",
            ctx.talon_binary.display()
        )));
        assert!(service.contains(&format!("WorkingDirectory={}", ctx.project_root.display())));
        assert!(units.join("talahon-cve-sync.timer").is_file());
        // Never root, never a download from the setup step itself.
        for call in runner.calls() {
            assert!(!call.starts_with("sudo"), "{call}");
            assert!(!call.contains("start talahon-cve-sync.service"), "{call}");
            if call.starts_with("systemctl") {
                assert!(call.starts_with("systemctl --user"), "{call}");
            }
        }

        // --remove takes both units away again.
        runner.on(
            "systemctl --user disable --now talahon-cve-sync.timer",
            CommandOutput::ok(""),
        );
        let out = run(&StepArgs::new(["--remove"]), &ctx).await.unwrap();
        assert_eq!(out.block.unwrap().get("ACTION"), Some("removed"));
        assert!(!units.join("talahon-cve-sync.service").exists());
        assert!(!units.join("talahon-cve-sync.timer").exists());
        // Removing twice is fine.
        assert_eq!(
            run(&StepArgs::new(["--remove"]), &ctx)
                .await
                .unwrap()
                .exit_code,
            0
        );
    }

    #[tokio::test]
    async fn fails_clearly_without_a_user_session_or_binary() {
        let dir = tempfile::tempdir().unwrap();
        // systemctl --user fails (MockRunner answers unknown commands with a failure).
        let c = ctx(dir.path(), Arc::new(MockRunner::new()));
        let out = run(&StepArgs::default(), &c).await.unwrap();
        assert_eq!(out.exit_code, 1);
        assert_eq!(
            out.block.unwrap().get("ERROR"),
            Some("no_systemd_user_session")
        );
        assert!(
            !c.home_dir
                .join(".config/systemd/user/talahon-cve-sync.timer")
                .exists()
        );

        // No systemd at all.
        let mut c = ctx(dir.path(), Arc::new(MockRunner::new()));
        c.platform.has_systemd = false;
        let out = run(&StepArgs::default(), &c).await.unwrap();
        assert_eq!(
            out.block.unwrap().get("ERROR"),
            Some("no_systemd_user_session")
        );

        // Session there, binary gone.
        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl --user daemon-reload", CommandOutput::ok(""));
        let mut c = ctx(dir.path(), runner);
        c.talon_binary = dir.path().join("nope");
        let out = run(&StepArgs::default(), &c).await.unwrap();
        assert_eq!(out.block.unwrap().get("ERROR"), Some("binary_not_found"));

        // Timer could not be enabled.
        let runner = Arc::new(MockRunner::new());
        runner.on("systemctl --user daemon-reload", CommandOutput::ok(""));
        let c = ctx(dir.path(), runner);
        let out = run(&StepArgs::default(), &c).await.unwrap();
        assert_eq!(out.exit_code, 1);
        assert_eq!(out.block.unwrap().get("ERROR"), Some("timer_not_enabled"));
    }
}
