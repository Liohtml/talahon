//! Step `environment` (port of `setup/environment.ts`): report everything
//! the remaining steps depend on. Purely informational — `STATUS` is
//! `success` whenever the probes ran; problems are listed in `ISSUES`.
//!
//! Probes: platform/WSL/headless, docker + podman state, agent image
//! present, vLLM reachable with the model served, LLM gateway port free,
//! runtime directories writable, free disk space, existing `.env` and
//! registered groups.

use super::StepArgs;
use super::vllm::add_vllm_fields;
use crate::checks::{
    MIN_FREE_DISK_MB, PortStatus, RuntimeState, VllmStatus, check_configured_vllm, check_port,
    check_writable_dirs, detect_runtime, disk_free_mb, image_present, runtime_dirs,
};
use crate::context::{SETUP_LOG, SetupContext};
use crate::status::{StatusBlock, StepOutcome};

/// Run the step.
///
/// # Errors
/// Never fails internally; problems are reported in the block.
pub async fn run(_args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    tracing::info!("Starting environment check");
    let mut issues: Vec<String> = Vec::new();
    let mut block = StatusBlock::new("CHECK_ENVIRONMENT")
        .field("PLATFORM", ctx.platform.platform.as_str())
        .field("IS_WSL", ctx.platform.is_wsl)
        .field("IS_HEADLESS", ctx.platform.is_headless)
        .field("IS_ROOT", ctx.platform.is_root())
        .field("SERVICE_MANAGER", ctx.platform.service_manager().as_str());

    // Container runtime + image.
    let runtimes = detect_runtime(ctx.runner.as_ref(), &ctx.config.container_runtime).await;
    let docker = runtimes.state("docker");
    let podman = runtimes.state("podman");
    block.set("DOCKER", docker.as_str());
    block.set("PODMAN", podman.as_str());
    block.set("CONFIGURED_RUNTIME", &ctx.config.container_runtime);
    block.set(
        "CONTAINER_RUNTIME",
        runtimes.selected.as_deref().unwrap_or("none"),
    );
    match &runtimes.selected {
        None => {
            let state = runtimes.state(&ctx.config.container_runtime);
            issues.push(if state == RuntimeState::InstalledNotRunning {
                "container_runtime_not_running".into()
            } else {
                "container_runtime_missing".into()
            });
        }
        Some(rt) if *rt != ctx.config.container_runtime => {
            issues.push("configured_runtime_unavailable".into());
        }
        Some(_) => {}
    }
    block.set("IMAGE", &ctx.config.container_image);
    let image_ok = match &runtimes.selected {
        Some(rt) => image_present(ctx.runner.as_ref(), rt, &ctx.config.container_image).await,
        None => false,
    };
    block.set("IMAGE_PRESENT", image_ok);
    if !image_ok {
        issues.push("image_missing".into());
    }

    // vLLM.
    let (vllm_cfg, vllm) = check_configured_vllm(ctx).await;
    let api_key_set = ctx.config.env.file_value("TALON_VLLM_API_KEY").is_some();
    add_vllm_fields(&mut block, vllm_cfg.as_ref(), api_key_set, &vllm);
    if vllm.status != VllmStatus::Ok {
        issues.push(format!("vllm_{}", vllm.status.as_str()));
    }

    // LLM gateway port.
    let port = check_port(&ctx.config.llm_gateway_bind, ctx.config.llm_gateway_port).await;
    block.set("GATEWAY_BIND", &ctx.config.llm_gateway_bind);
    block.set("GATEWAY_PORT", ctx.config.llm_gateway_port);
    block.set("GATEWAY_PORT_FREE", port == PortStatus::Free);
    block.set("GATEWAY_PORT_STATUS", port.as_str());
    if port != PortStatus::Free {
        issues.push(format!("gateway_port_{}", port.as_str()));
    }

    // Writable runtime directories.
    let failures = check_writable_dirs(&runtime_dirs(ctx));
    if failures.is_empty() {
        block.set("WRITABLE_DIRS", "ok");
    } else {
        let names: Vec<String> = failures
            .iter()
            .map(|(p, _)| {
                p.strip_prefix(&ctx.project_root)
                    .unwrap_or(p)
                    .display()
                    .to_string()
            })
            .collect();
        block.set("WRITABLE_DIRS", format!("failed:{}", names.join(",")));
        issues.push("dirs_not_writable".into());
    }

    // Disk space.
    match disk_free_mb(ctx.runner.as_ref(), &ctx.project_root).await {
        Some(mb) => {
            block.set("DISK_FREE_MB", mb);
            block.set("DISK_OK", mb >= MIN_FREE_DISK_MB);
            if mb < MIN_FREE_DISK_MB {
                issues.push("low_disk_space".into());
            }
        }
        None => {
            block.set("DISK_FREE_MB", "unknown");
            block.set("DISK_OK", "unknown");
        }
    }

    // Existing configuration.
    block.set("HAS_ENV", ctx.env_path().exists());
    let legacy_json = ctx.config.data_dir.join("registered_groups.json").exists();
    let registered = ctx.registered_group_count().await.unwrap_or(0);
    block.set("HAS_REGISTERED_GROUPS", legacy_json || registered > 0);
    block.set(
        "MOUNT_ALLOWLIST",
        if ctx.mount_allowlist_path().exists() {
            "configured"
        } else {
            "missing"
        },
    );

    block.set(
        "ISSUES",
        if issues.is_empty() {
            "none".to_string()
        } else {
            issues.join(",")
        },
    );
    block.set("STATUS", "success");
    block.set("LOG", SETUP_LOG);
    tracing::info!(issues = %issues.join(","), "Environment check complete");
    Ok(StepOutcome::ok(block))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runner::CommandOutput;
    use crate::runner::mock::MockRunner;

    #[tokio::test]
    async fn reports_runtime_image_disk_and_issues() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.install("docker");
        runner.on("docker info", CommandOutput::ok("27.1.1"));
        runner.on("docker image inspect", CommandOutput::ok("sha256:1"));
        runner.on(
            "df -Pk",
            CommandOutput::ok("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 100 50 1048576 50% /\n"),
        );
        let mut ctx = SetupContext::new(dir.path(), dir.path(), runner.clone());
        // Port 0 always binds (a concrete free port could be raced).
        ctx.config.llm_gateway_port = 0;
        ctx.config.llm_gateway_bind = "127.0.0.1".into();
        ctx.config.container_runtime = "docker".into();

        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("DOCKER"), Some("running"));
        assert_eq!(b.get("PODMAN"), Some("not_found"));
        assert_eq!(b.get("CONTAINER_RUNTIME"), Some("docker"));
        assert_eq!(b.get("IMAGE_PRESENT"), Some("true"));
        assert_eq!(b.get("GATEWAY_PORT_FREE"), Some("true"));
        assert_eq!(b.get("WRITABLE_DIRS"), Some("ok"));
        assert_eq!(b.get("DISK_FREE_MB"), Some("1024"));
        assert_eq!(b.get("DISK_OK"), Some("false"));
        assert_eq!(b.get("HAS_ENV"), Some("false"));
        assert_eq!(b.get("HAS_REGISTERED_GROUPS"), Some("false"));
        assert_eq!(b.status(), Some("success"));
        let issues = b.get("ISSUES").unwrap();
        assert!(issues.contains("low_disk_space"), "{issues}");
        assert!(!issues.contains("image_missing"), "{issues}");
        // Runtime directories were created.
        for d in ["store", "data", "groups", "logs"] {
            assert!(dir.path().join(d).is_dir(), "{d}");
        }
    }

    #[tokio::test]
    async fn missing_runtime_and_busy_port_are_issues() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut ctx = SetupContext::new(dir.path(), dir.path(), runner);
        ctx.config.llm_gateway_port = listener.local_addr().unwrap().port();
        ctx.config.llm_gateway_bind = "127.0.0.1".into();
        ctx.config.container_runtime = "docker".into();
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("CONTAINER_RUNTIME"), Some("none"));
        assert_eq!(b.get("GATEWAY_PORT_FREE"), Some("false"));
        let issues = b.get("ISSUES").unwrap();
        assert!(issues.contains("container_runtime_missing"));
        assert!(issues.contains("image_missing"));
        assert!(issues.contains("gateway_port_in_use"));
        assert_eq!(b.get("DISK_FREE_MB"), Some("unknown"));
    }
}
