//! Containerized MemPalace runner for the CoPilot `/palace/*` endpoints
//! (MYTH-01).
//!
//! Palace data (`mempalace-data/`, ChromaDB with pickled index metadata) has
//! been writable by agent containers, so palace code must never run on the
//! host against it. Every `/palace/*` call therefore starts a throw-away,
//! hardened container (`talon_container::build_palace_run_args`: no
//! capabilities, read-only root, `mcp-palace` uid, tight limits, palace
//! code mounted read-only) through `talon_http::CommandPalaceRunner`.
//!
//! `CommandPalaceRunner` takes a fixed argument vector, but every container
//! needs its own `--name` (concurrent calls would collide, and the name is
//! what lets the host kill a container whose client timed out). So
//! [`ContainerPalaceRunner`] builds fresh arguments with a unique name per
//! call and runs them through a single-use `CommandPalaceRunner`, keeping
//! the concurrency limit, output cap and timeout itself. When a call does
//! not succeed (timeout, error exit, oversized or non-JSON output, request
//! dropped), the container is killed by name, best effort and
//! asynchronously (`--rm` then removes it), because killing the
//! `docker run` client does not stop the container.
//!
//! The host-executed `ScriptPalaceRunner` is never used.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use talon_container::{ContainerRuntime, PalaceRunSpec, build_palace_run_args};
use talon_core::config::TalonConfig;
use talon_http::{
    CommandPalaceRunner, DisabledPalaceRunner, HttpConfig, PalaceError, PalaceRunner,
};
use tokio::sync::Semaphore;

/// Name prefix of palace one-shot containers.
pub const PALACE_NAME_PREFIX: &str = "talon-palace";
/// Process environment passed through to the runtime client (socket
/// location, rootless engines, CLI contexts). None of these are secrets.
const RUNTIME_ENV_PASSTHROUGH: &[&str] = &[
    "HOME",
    "XDG_RUNTIME_DIR",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
];

/// Settings of a [`ContainerPalaceRunner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PalaceContainerConfig {
    /// Absolute path of the container runtime binary (`docker` / `podman`).
    pub runtime_bin: PathBuf,
    /// Agent image (holds the palace venv).
    pub image: String,
    /// Absolute Talon checkout holding `mempalace/` and `mempalace-data/`.
    pub project_root: PathBuf,
    /// `--network` of the palace containers (`None` = runtime default).
    pub network: Option<String>,
    /// Per-call timeout (container start included).
    pub timeout: Duration,
    /// Stdout cap per call (bytes).
    pub max_output_bytes: usize,
    /// Concurrent calls; excess callers wait up to `timeout`.
    pub max_concurrency: usize,
}

/// A palace runner that runs every call in its own hardened container (see
/// the module docs).
pub struct ContainerPalaceRunner {
    config: PalaceContainerConfig,
    permits: Arc<Semaphore>,
    seq: AtomicU64,
    env: Vec<(OsString, OsString)>,
    /// Used to kill containers whose client did not finish on its own.
    cleanup: Option<Arc<ContainerRuntime>>,
}

impl std::fmt::Debug for ContainerPalaceRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerPalaceRunner")
            .field("config", &self.config)
            .field("cleanup", &self.cleanup.is_some())
            .finish_non_exhaustive()
    }
}

impl ContainerPalaceRunner {
    /// Build the runner. Validates the configuration by building the run
    /// arguments once (image, network, `mempalace/palace-call.sh`,
    /// `mempalace-data/`).
    ///
    /// # Errors
    /// A relative runtime path or project root, or arguments that
    /// `build_palace_run_args` refuses (e.g. MemPalace not installed).
    pub fn new(config: PalaceContainerConfig) -> talon_core::Result<Self> {
        if !config.runtime_bin.is_absolute() {
            return Err(talon_core::Error::Config(format!(
                "container runtime path must be absolute: {}",
                config.runtime_bin.display()
            )));
        }
        let runner = Self {
            permits: Arc::new(Semaphore::new(config.max_concurrency.max(1))),
            seq: AtomicU64::new(0),
            env: RUNTIME_ENV_PASSTHROUGH
                .iter()
                .filter_map(|k| std::env::var_os(k).map(|v| (OsString::from(k), v)))
                .collect(),
            cleanup: None,
            config,
        };
        runner.args_for(&runner.next_name())?;
        Ok(runner)
    }

    /// Kill containers through `runtime` when a call is abandoned.
    pub fn with_cleanup(mut self, runtime: Arc<ContainerRuntime>) -> Self {
        self.cleanup = Some(runtime);
        self
    }

    /// The configuration.
    pub fn config(&self) -> &PalaceContainerConfig {
        &self.config
    }

    /// A fresh container name: `talon-palace-<millis>-<seq>`.
    pub fn next_name(&self) -> String {
        let millis = chrono::Utc::now().timestamp_millis();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("{PALACE_NAME_PREFIX}-{millis}-{seq}")
    }

    /// The `run` arguments for a container called `name`.
    ///
    /// # Errors
    /// See [`build_palace_run_args`].
    pub fn args_for(&self, name: &str) -> talon_core::Result<Vec<String>> {
        build_palace_run_args(&PalaceRunSpec {
            image: self.config.image.clone(),
            project_root: self.config.project_root.clone(),
            name: name.to_string(),
            network: self.config.network.clone(),
        })
    }

    /// The single-use client runner for one call.
    fn command(&self, args: Vec<String>) -> CommandPalaceRunner {
        let mut runner =
            CommandPalaceRunner::new(self.config.runtime_bin.clone(), args, self.config.timeout)
                .with_max_output(self.config.max_output_bytes)
                .with_max_concurrency(1);
        for (k, v) in &self.env {
            runner = runner.with_env(k.clone(), v.clone());
        }
        runner
    }
}

/// Kills the named container on drop unless disarmed (abandoned calls).
struct KillOnDrop {
    runtime: Option<Arc<ContainerRuntime>>,
    name: String,
}

impl KillOnDrop {
    fn disarm(&mut self) {
        self.runtime = None;
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let name = std::mem::take(&mut self.name);
        handle.spawn(async move {
            // Fails harmlessly when the container already exited (--rm).
            match runtime.kill(&name).await {
                Ok(()) => tracing::info!(container = %name, "killed abandoned palace container"),
                Err(e) => tracing::debug!(container = %name, error = %e, "palace container kill"),
            }
        });
    }
}

#[async_trait]
impl PalaceRunner for ContainerPalaceRunner {
    async fn call(&self, request: Value) -> Result<Value, PalaceError> {
        let permit =
            tokio::time::timeout(self.config.timeout, self.permits.clone().acquire_owned())
                .await
                .map_err(|_| PalaceError::Busy)?
                .map_err(|_| PalaceError::Busy)?;
        let name = self.next_name();
        let args = self.args_for(&name).map_err(|e| {
            tracing::error!(error = %e, "cannot build palace container arguments");
            PalaceError::Spawn("palace container configuration is invalid".into())
        })?;
        let mut guard = KillOnDrop {
            runtime: self.cleanup.clone(),
            name: name.clone(),
        };
        let result = self.command(args).call(request).await;
        match &result {
            // Success, or the client never started: nothing left running.
            Ok(_) | Err(PalaceError::Spawn(_)) => guard.disarm(),
            // Any other failure may leave the container behind (a killed
            // or failed client does not stop it): kill it, best effort.
            Err(e) => {
                tracing::warn!(container = %name, error = %e, "palace call failed; killing its container")
            }
        }
        drop(guard);
        drop(permit);
        result
    }

    fn mode(&self) -> &'static str {
        "container"
    }
}

/// The palace runner `talon run` hands to the CoPilot HTTP channel: a
/// [`ContainerPalaceRunner`] on `network` (the agent network) using the
/// agent image, the HTTP config's timeout / output cap / concurrency, and
/// `runtime` to kill abandoned containers. When it cannot be built (e.g.
/// MemPalace is not installed) the palace is disabled (`503`) — the
/// host-executed script runner is never used, whatever
/// `TALON_PALACE_HOST_EXEC` says.
pub fn host_palace_runner(
    config: &TalonConfig,
    http: &HttpConfig,
    runtime: &Arc<ContainerRuntime>,
    network: Option<String>,
) -> Arc<dyn PalaceRunner> {
    if http.palace_host_exec {
        tracing::warn!(
            "TALON_PALACE_HOST_EXEC=unsafe is ignored: MemPalace calls always run in a hardened \
             container (host execution would unpickle agent-writable data on the host)"
        );
    }
    let Some(runtime_bin) = absolute_runtime_bin(runtime.bin()) else {
        tracing::warn!(
            bin = runtime.bin(),
            "container runtime path cannot be resolved; MemPalace endpoints disabled"
        );
        return Arc::new(DisabledPalaceRunner);
    };
    let project_root = match std::fs::canonicalize(&config.project_root) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "cannot resolve the project root; MemPalace endpoints disabled");
            return Arc::new(DisabledPalaceRunner);
        }
    };
    let built = ContainerPalaceRunner::new(PalaceContainerConfig {
        runtime_bin,
        image: config.container_image.clone(),
        project_root,
        network,
        timeout: http.palace_timeout,
        max_output_bytes: http.palace_max_output_bytes,
        max_concurrency: http.palace_max_concurrency,
    });
    match built {
        Ok(runner) => {
            tracing::info!(
                image = %runner.config().image,
                network = runner.config().network.as_deref().unwrap_or("default"),
                "MemPalace calls run in hardened one-shot containers"
            );
            Arc::new(runner.with_cleanup(runtime.clone()))
        }
        Err(e) => {
            tracing::warn!(error = %e, "MemPalace endpoints disabled (palace container cannot be configured)");
            Arc::new(DisabledPalaceRunner)
        }
    }
}

/// Absolute path of the runtime binary `bin` (as resolved by
/// `ContainerRuntime::detect`, or looked up on `PATH`).
pub fn absolute_runtime_bin(bin: &str) -> Option<PathBuf> {
    let path = Path::new(bin);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    talon_container::runtime::resolve_executable(bin, std::env::var_os("PATH"))
        .filter(|p| p.is_absolute())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;

    use super::*;

    struct Fx {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        runtime: PathBuf,
    }

    /// A project with MemPalace installed and a fake runtime binary that
    /// echoes its arguments as JSON.
    fn fixture(fake_runtime_body: &str) -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir_all(root.join("mempalace-data")).unwrap();
        std::fs::create_dir_all(root.join("mempalace")).unwrap();
        std::fs::write(root.join("mempalace/palace-call.sh"), "#!/bin/sh\n").unwrap();
        let runtime = root.join("fake-docker");
        std::fs::write(&runtime, format!("#!/bin/sh\n{fake_runtime_body}\n")).unwrap();
        let mut perm = std::fs::metadata(&runtime).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&runtime, perm).unwrap();
        Fx {
            _tmp: tmp,
            root,
            runtime,
        }
    }

    fn config(fx: &Fx) -> PalaceContainerConfig {
        PalaceContainerConfig {
            runtime_bin: fx.runtime.clone(),
            image: "talon-agent:latest".into(),
            project_root: fx.root.clone(),
            network: Some("talon-agents".into()),
            timeout: Duration::from_secs(10),
            max_output_bytes: 64 * 1024,
            max_concurrency: 2,
        }
    }

    const ECHO_ARGS: &str = r#"read -r line; printf '{"argv":"%s","request":%s}\n' "$*" "$line""#;

    #[test]
    fn construction_validates_and_builds_hardened_args() {
        let fx = fixture(ECHO_ARGS);
        let runner = ContainerPalaceRunner::new(config(&fx)).unwrap();
        assert_eq!(runner.mode(), "container");
        let name = runner.next_name();
        assert!(name.starts_with("talon-palace-"));
        let args = runner.args_for(&name).unwrap();
        let joined = args.join(" ");
        assert_eq!(args[0], "run");
        assert!(joined.contains(&format!("--name {name}")));
        assert!(joined.contains("--network talon-agents"));
        assert!(joined.contains("--cap-drop=ALL"));
        assert!(joined.contains("--read-only"));
        assert!(joined.contains("--user 61008:61008"));
        assert_eq!(args.last().map(String::as_str), Some("talon-agent:latest"));
        // Names are unique per call.
        assert_ne!(runner.next_name(), runner.next_name());
    }

    #[test]
    fn construction_refuses_bad_configuration() {
        let fx = fixture(ECHO_ARGS);
        let mut relative = config(&fx);
        relative.runtime_bin = PathBuf::from("docker");
        assert!(ContainerPalaceRunner::new(relative).is_err());

        let mut bad_image = config(&fx);
        bad_image.image = "--privileged".into();
        assert!(ContainerPalaceRunner::new(bad_image).is_err());

        let mut bad_net = config(&fx);
        bad_net.network = Some("host".into());
        assert!(ContainerPalaceRunner::new(bad_net).is_err());

        std::fs::remove_file(fx.root.join("mempalace/palace-call.sh")).unwrap();
        assert!(ContainerPalaceRunner::new(config(&fx)).is_err());
    }

    #[tokio::test]
    async fn every_call_runs_the_runtime_with_a_fresh_container_name() {
        let fx = fixture(ECHO_ARGS);
        let runner = ContainerPalaceRunner::new(config(&fx)).unwrap();
        let first = runner.call(json!({"op": "status"})).await.unwrap();
        let second = runner.call(json!({"op": "status"})).await.unwrap();
        assert_eq!(first["request"]["op"], "status");
        let argv1 = first["argv"].as_str().unwrap();
        let argv2 = second["argv"].as_str().unwrap();
        assert!(argv1.starts_with("run "), "{argv1}");
        assert!(argv1.contains("--name talon-palace-"));
        assert!(argv1.contains("--entrypoint /workspace/extra/mempalace/palace-call.sh"));
        assert_ne!(argv1, argv2, "container names must differ per call");
    }

    #[tokio::test]
    async fn runtime_failures_and_timeouts_are_reported() {
        let fx = fixture("cat >/dev/null; exit 3");
        let runner = ContainerPalaceRunner::new(config(&fx)).unwrap();
        assert!(matches!(
            runner.call(json!({"op": "status"})).await,
            Err(PalaceError::Exit(_))
        ));

        let fx = fixture("exec sleep 5");
        let mut cfg = config(&fx);
        cfg.timeout = Duration::from_millis(200);
        let runner = ContainerPalaceRunner::new(cfg).unwrap();
        assert!(matches!(
            runner.call(json!({"op": "status"})).await,
            Err(PalaceError::Timeout(_))
        ));
    }

    #[test]
    fn host_wiring_uses_the_container_runner_or_disables_the_palace() {
        let fx = fixture(ECHO_ARGS);
        let config = TalonConfig::from_env(
            &fx.root,
            talon_core::env::EnvFile::from_str_content("TALON_PALACE_HOST_EXEC=unsafe\n"),
        );
        let mut http = HttpConfig::new(&fx.root);
        http.palace_host_exec = true;
        let runtime = Arc::new(ContainerRuntime::new(fx.runtime.to_string_lossy()).unwrap());
        let runner = host_palace_runner(&config, &http, &runtime, Some("talon-agents".into()));
        // Never the host-script runner, even with the unsafe opt-in.
        assert_eq!(runner.mode(), "container");

        // MemPalace not installed: disabled, not host execution.
        std::fs::remove_dir_all(fx.root.join("mempalace")).unwrap();
        let runner = host_palace_runner(&config, &http, &runtime, None);
        assert_eq!(runner.mode(), DisabledPalaceRunner.mode());
    }

    #[test]
    fn runtime_bin_resolution() {
        assert_eq!(
            absolute_runtime_bin("/usr/bin/docker"),
            Some(PathBuf::from("/usr/bin/docker"))
        );
        if let Some(sh) = absolute_runtime_bin("sh") {
            assert!(sh.is_absolute());
        }
        assert_eq!(absolute_runtime_bin("definitely-not-a-runtime-xyz"), None);
    }
}
