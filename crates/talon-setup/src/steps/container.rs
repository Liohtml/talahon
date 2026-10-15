//! Step `container`: build the agent image
//! and smoke-test it.
//!
//! `--runtime docker|podman` (default: `CONTAINER_RUNTIME`, else `docker`),
//! `--skip-build` (only test an existing image). The build uses
//! `container/build.sh` when present (build context = repo root, see
//! `talon-container`), otherwise `<runtime> build -f container/Dockerfile .`.
//! Build output goes to `logs/setup.log`.

use std::time::Duration;

use super::StepArgs;
use crate::checks::{RuntimeState, SUPPORTED_RUNTIMES, image_present, runtime_state};
use crate::context::{SETUP_LOG, SetupContext};
use crate::runner::{CommandOutput, CommandSpec};
use crate::status::{StatusBlock, StepOutcome};

/// Image builds compile Rust from source: allow a generous timeout.
pub const BUILD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Smoke-test timeout.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Image repository the build script tags.
const DEFAULT_IMAGE_REPO: &str = "talon-agent";

fn base_block(runtime: &str, image: &str) -> StatusBlock {
    StatusBlock::new("SETUP_CONTAINER")
        .field("RUNTIME", runtime)
        .field("IMAGE", image)
}

fn failed(runtime: &str, image: &str, error: &str, code: i32) -> StepOutcome {
    StepOutcome::with_code(
        base_block(runtime, image)
            .field("BUILD_OK", false)
            .field("TEST_OK", false)
            .field("STATUS", "failed")
            .field("ERROR", error)
            .field("LOG", SETUP_LOG),
        code,
    )
}

fn log_output(ctx: &SetupContext, title: &str, out: &CommandOutput) {
    let mut body = String::new();
    if let Some(code) = out.exit_code {
        body.push_str(&format!("exit code: {code}\n"));
    }
    if out.timed_out {
        body.push_str("timed out\n");
    }
    if let Some(e) = &out.spawn_error {
        body.push_str(&format!("spawn error: {e}\n"));
    }
    body.push_str(&out.stdout);
    body.push_str(&out.stderr);
    ctx.append_log(title, &body);
}

/// The build command for `image` with `runtime`.
pub fn build_command(ctx: &SetupContext, runtime: &str, image: &str) -> CommandSpec {
    let script = ctx.project_root.join("container").join("build.sh");
    let (repo, tag) = match image.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => (repo, tag),
        _ => (image, "latest"),
    };
    if script.is_file() && repo == DEFAULT_IMAGE_REPO {
        CommandSpec::new(
            "bash",
            [script.to_string_lossy().into_owned(), tag.to_string()],
        )
        .cwd(&ctx.project_root)
        .env("CONTAINER_RUNTIME", runtime)
        .timeout(BUILD_TIMEOUT)
    } else {
        CommandSpec::new(
            runtime,
            ["build", "-t", image, "-f", "container/Dockerfile", "."],
        )
        .cwd(&ctx.project_root)
        .timeout(BUILD_TIMEOUT)
    }
}

/// Run the step.
///
/// # Errors
/// Never fails internally; problems are reported in the block.
pub async fn run(args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    let image = ctx.config.container_image.clone();
    let runtime = args
        .value("--runtime")
        .map(str::to_string)
        .unwrap_or_else(|| ctx.config.container_runtime.clone());
    if runtime.is_empty() {
        return Ok(failed("unknown", &image, "missing_runtime_flag", 4));
    }
    if !SUPPORTED_RUNTIMES.contains(&runtime.as_str()) {
        return Ok(failed(&runtime, &image, "unknown_runtime", 4));
    }
    if runtime_state(ctx.runner.as_ref(), &runtime).await != RuntimeState::Running {
        return Ok(failed(&runtime, &image, "runtime_not_available", 2));
    }

    let skip_build = args.flag("--skip-build");
    let build_ok = if skip_build {
        image_present(ctx.runner.as_ref(), &runtime, &image).await
    } else {
        let cmd = build_command(ctx, &runtime, &image);
        tracing::info!(command = %cmd.display(), "Building container image");
        let out = ctx.runner.run(&cmd).await;
        log_output(ctx, &format!("container build ({})", cmd.display()), &out);
        out.success() && image_present(ctx.runner.as_ref(), &runtime, &image).await
    };

    let mut test_ok = false;
    if build_ok {
        let cmd = CommandSpec::new(
            &runtime,
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--entrypoint",
                "/bin/echo",
                image.as_str(),
                "Container OK",
            ],
        )
        .timeout(TEST_TIMEOUT);
        let out = ctx.runner.run(&cmd).await;
        test_ok = out.success() && out.stdout.contains("Container OK");
        if !test_ok {
            log_output(ctx, "container smoke test", &out);
        }
    }

    let ok = build_ok && test_ok;
    let mut block = base_block(&runtime, &image)
        .field("BUILD_OK", build_ok)
        .field("TEST_OK", test_ok);
    if skip_build {
        block.set("BUILD", "skipped");
    }
    block.set("STATUS", if ok { "success" } else { "failed" });
    if !ok {
        block.set(
            "ERROR",
            if !build_ok {
                if skip_build {
                    "image_missing"
                } else {
                    "build_failed"
                }
            } else {
                "test_failed"
            },
        );
    }
    block.set("LOG", SETUP_LOG);
    Ok(StepOutcome::with_code(block, if ok { 0 } else { 1 }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runner::mock::MockRunner;

    fn ctx(dir: &std::path::Path, runner: Arc<MockRunner>) -> SetupContext {
        let mut c = SetupContext::new(dir, dir, runner);
        c.config.container_image = "talon-agent:latest".into();
        c.config.container_runtime = "docker".into();
        c
    }

    fn running_docker() -> Arc<MockRunner> {
        let r = Arc::new(MockRunner::new());
        r.install("docker");
        r.on("docker info", CommandOutput::ok("27"));
        r
    }

    #[tokio::test]
    async fn unknown_runtime_exits_4() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(
            &StepArgs::new(["--runtime", "lxc"]),
            &ctx(dir.path(), running_docker()),
        )
        .await
        .unwrap();
        assert_eq!(out.exit_code, 4);
        assert_eq!(out.block.unwrap().get("ERROR"), Some("unknown_runtime"));
    }

    #[tokio::test]
    async fn unavailable_runtime_exits_2() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(MockRunner::new());
        runner.install("docker");
        runner.on("docker info", CommandOutput::failed(1, "permission denied"));
        let out = run(&StepArgs::default(), &ctx(dir.path(), runner))
            .await
            .unwrap();
        assert_eq!(out.exit_code, 2);
        assert_eq!(
            out.block.unwrap().get("ERROR"),
            Some("runtime_not_available")
        );
    }

    #[tokio::test]
    async fn builds_with_script_and_tests() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("container")).unwrap();
        std::fs::write(dir.path().join("container/build.sh"), "#!/bin/bash\n").unwrap();
        let runner = running_docker();
        runner.on("bash", CommandOutput::ok("built"));
        runner.on("docker image inspect", CommandOutput::ok("sha256:1"));
        runner.on("docker run", CommandOutput::ok("Container OK\n"));
        let c = ctx(dir.path(), runner.clone());
        let out = run(&StepArgs::default(), &c).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.status(), Some("success"));
        assert_eq!(b.get("BUILD_OK"), Some("true"));
        assert_eq!(b.get("TEST_OK"), Some("true"));
        assert_eq!(out.exit_code, 0);
        let calls = runner.calls.lock().unwrap().clone();
        let build = calls.iter().find(|c| c.program == "bash").unwrap();
        assert!(build.args[0].ends_with("container/build.sh"));
        assert_eq!(build.args[1], "latest");
        assert!(
            build
                .env
                .contains(&("CONTAINER_RUNTIME".into(), "docker".into()))
        );
        assert!(runner.called("docker run --rm --network none --cap-drop=ALL"));
        assert!(
            std::fs::read_to_string(dir.path().join("logs/setup.log"))
                .unwrap()
                .contains("built")
        );
    }

    #[tokio::test]
    async fn custom_image_builds_directly() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ctx(dir.path(), running_docker());
        c.config.container_image = "registry.local:5000/soc/agent:v2".into();
        let cmd = build_command(&c, "podman", &c.config.container_image);
        assert_eq!(
            cmd.display(),
            "podman build -t registry.local:5000/soc/agent:v2 -f container/Dockerfile ."
        );
    }

    #[tokio::test]
    async fn build_failure_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let runner = running_docker();
        runner.on("docker build", CommandOutput::failed(1, "boom"));
        let out = run(&StepArgs::default(), &ctx(dir.path(), runner.clone()))
            .await
            .unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("ERROR"), Some("build_failed"));
        assert_eq!(b.get("TEST_OK"), Some("false"));
        assert_eq!(out.exit_code, 1);
        assert!(!runner.called("docker run"));
    }

    #[tokio::test]
    async fn skip_build_tests_existing_image() {
        let dir = tempfile::tempdir().unwrap();
        let runner = running_docker();
        runner.on("docker image inspect", CommandOutput::ok("sha256:1"));
        runner.on("docker run", CommandOutput::ok("nope"));
        let out = run(
            &StepArgs::new(["--skip-build"]),
            &ctx(dir.path(), runner.clone()),
        )
        .await
        .unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("BUILD"), Some("skipped"));
        assert_eq!(b.get("ERROR"), Some("test_failed"));
        assert!(!runner.called("docker build"));
    }
}
