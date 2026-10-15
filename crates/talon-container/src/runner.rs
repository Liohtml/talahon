//! Container runner (port of `runContainerAgent` in
//! `src/container-runner.ts`).
//!
//! Lifecycle of one run:
//!
//! 1. [`ContainerRunner::prepare`]: build mounts (creating the lane's
//!    directories) and the hardened `run` arguments.
//! 2. Spawn `<runtime> run ...` through the injectable
//!    [`crate::process::ProcessSpawner`]; audit `container.launch`.
//! 3. Write the [`ContainerInput`] JSON to stdin, then close it (the LLM
//!    gateway token travels only this way — never env, never logs).
//! 4. Stream-parse stdout frames ([`crate::parser::OutputParser`]); each
//!    frame resets the hard timeout and is delivered, in order, to the
//!    [`OutputHandler`] (on its own task, so a slow handler never stalls
//!    timeout handling). stderr lines go to `tracing` after redaction.
//!    The frame path is bounded end to end (MYTH-07): parser -> run loop ->
//!    handler use bounded queues ([`RunnerConfig::frame_queue_capacity`]),
//!    so a slow handler stops stdout from being read and the container
//!    blocks on its own writes instead of the host buffering without limit.
//!    More than [`RunnerConfig::max_frames_per_run`] frames or
//!    [`RunnerConfig::max_result_bytes_per_run`] bytes of results stop the
//!    container and end the run with [`RunOutcome::OutputLimitExceeded`].
//! 5. Hard timeout = `max(group timeout || CONTAINER_TIMEOUT, IDLE_TIMEOUT +
//!    30 s)`, reset by every frame — but never beyond the absolute cap
//!    `hard timeout × max_run_time_factor` from the start of the run. On
//!    timeout (or [`ContainerHandle::stop`]) the container gets `<runtime>
//!    stop -t <grace>`; if it is still alive after the grace period it is
//!    `kill`ed and the CLI process SIGKILLed.
//! 6. Exit mapping (TS parity): output limit exceeded => error; timeout
//!    after output => success (idle cleanup); timeout without output =>
//!    error; exit 0 => success; exit 137 after output => success; anything
//!    else => error with the (redacted) stderr tail. The run waits for the
//!    handler to drain, writes a run log, audits `container.exit` and
//!    returns a [`RunResult`].

use std::fmt;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use talon_core::audit::{AuditSink, SharedAuditSink, event};
use talon_core::config::TalonConfig;
use talon_core::paths::is_valid_group_folder;
use talon_core::protocol::{ContainerInput, ContainerOutput, OutputStatus, SessionUsage};
use talon_core::types::{ContainerConfig, RegisteredGroup};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::args::{
    ConfigRejection, ResourceLimits, RunArgsInput, RunAs, build_run_args, container_name,
    host_is_root,
};
use crate::mounts::{MountLayout, MountOptions, MountRequest, VolumeMount, build_mounts};
use crate::parser::ParseEvent;
use crate::policy::{LogRedactor, MountPolicy};
use crate::process::{
    BoxedReader, ExitInfo, ProcessCommand, ProcessControl, ProcessSpawner, SpawnedProcess,
    TokioProcessSpawner,
};
use crate::runtime::{AGENT_NETWORK, ContainerRuntime};

/// Grace added to the idle timeout so the `_close` sentinel can act before
/// the hard kill (TS: 30 s).
pub const DEFAULT_IDLE_GRACE: Duration = Duration::from_secs(30);
/// `docker stop -t` grace.
pub const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(10);
/// Extra wait after the stop grace before force-killing.
pub const DEFAULT_KILL_AFTER: Duration = Duration::from_secs(5);
/// How long to wait for the streams to close once the process exited.
pub const DEFAULT_EXIT_DRAIN: Duration = Duration::from_secs(5);
/// Upper bound for any configured timeout.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 3600);
/// Run logs kept per group.
pub const DEFAULT_RUN_LOG_KEEP: usize = 50;
/// Capacity of each bounded frame queue (parser -> loop -> handler).
pub const DEFAULT_FRAME_QUEUE_CAPACITY: usize = 8;
/// Valid output frames accepted per run.
pub const DEFAULT_MAX_FRAMES_PER_RUN: usize = 1000;
/// Cumulative `result` + `error` bytes accepted per run (8 MiB).
pub const DEFAULT_MAX_RESULT_BYTES_PER_RUN: usize = 8 * 1024 * 1024;
/// Frames may extend the hard timeout up to this multiple of it.
pub const DEFAULT_MAX_RUN_TIME_FACTOR: u32 = 4;
/// Env / `.env` key selecting the agent network (`default` or empty: the
/// runtime's default bridge; unset: [`AGENT_NETWORK`]).
pub const CONTAINER_NETWORK_ENV: &str = "TALON_CONTAINER_NETWORK";
/// Longest session id accepted from a container frame (N-5). The agent
/// reports a UUID (36 bytes); the id is persisted, logged and sent back to
/// the container on the next run, so anything longer is dropped.
pub const MAX_SESSION_ID_BYTES: usize = 128;

/// `true` for a session id accepted from a container frame: 1 to
/// [`MAX_SESSION_ID_BYTES`] bytes of `[A-Za-z0-9_-]` (a UUID in practice).
/// Frames carrying anything else have the id removed before delivery (with a
/// warning that never quotes it).
pub fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SESSION_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Interpret a [`CONTAINER_NETWORK_ENV`] value: unset => [`AGENT_NETWORK`];
/// empty or `default` => `None` (the runtime's default bridge); anything
/// else is used as-is (validated at launch).
pub fn network_setting(raw: Option<&str>) -> Option<String> {
    match raw.map(str::trim) {
        None => Some(AGENT_NETWORK.to_string()),
        Some(v) if v.is_empty() || v.eq_ignore_ascii_case("default") => None,
        Some(v) => Some(v.to_string()),
    }
}

/// Bytes of stdout / stderr retained for diagnostics.
const TAIL_BYTES: usize = 16 * 1024;
/// Longest stderr line logged as-is.
const MAX_STDERR_LINE: usize = 8 * 1024;
/// Characters of stderr quoted in error messages (TS: 200).
const ERROR_TAIL_CHARS: usize = 200;
/// Audit kind for refused container-config values.
pub const AUDIT_CONFIG_REJECTED: &str = "container.config.rejected";

/// Static configuration of the runner.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Image reference (`CONTAINER_IMAGE`).
    pub image: String,
    /// Host directory layout.
    pub layout: MountLayout,
    /// IANA timezone passed as `TZ`.
    pub timezone: String,
    /// Default hard timeout (`CONTAINER_TIMEOUT`).
    pub container_timeout: Duration,
    /// `IDLE_TIMEOUT`.
    pub idle_timeout: Duration,
    /// Added to the idle timeout to form the minimum hard timeout.
    pub idle_grace: Duration,
    /// `docker stop -t`.
    pub stop_grace: Duration,
    /// Extra wait before force-kill.
    pub kill_after: Duration,
    /// Stream drain wait after exit / kill.
    pub exit_drain: Duration,
    /// Max size of one output frame (`CONTAINER_MAX_OUTPUT_SIZE`).
    pub max_output_bytes: usize,
    /// Limits used when a group has no override.
    pub default_limits: ResourceLimits,
    /// Override `RUN_UID`/`RUN_GID` (default: host ids, never root).
    pub run_as: Option<RunAs>,
    /// Chown writable dirs to `run_as` (default: when the host is root).
    pub chown_dirs: Option<bool>,
    /// Mount behaviour knobs.
    pub mount_options: MountOptions,
    /// Directory for per-run logs (`<dir>/<folder>/container-*.log`).
    /// Kept outside the group folder so the agent cannot plant symlinks.
    pub run_log_dir: Option<PathBuf>,
    /// Run logs kept per group.
    pub run_log_keep: usize,
    /// `--network` when the group config sets none: normally
    /// [`AGENT_NETWORK`]; `None` = the runtime's default bridge.
    pub default_network: Option<String>,
    /// Capacity of each bounded frame queue (backpressure to the container).
    pub frame_queue_capacity: usize,
    /// Valid frames accepted per run before the container is stopped.
    pub max_frames_per_run: usize,
    /// Cumulative `result` + `error` bytes accepted per run before the
    /// container is stopped.
    pub max_result_bytes_per_run: usize,
    /// Frames extend the hard timeout up to `hard timeout × this` (min 1).
    pub max_run_time_factor: u32,
}

impl RunnerConfig {
    /// Defaults for `image` under `layout`.
    pub fn new(image: impl Into<String>, layout: MountLayout) -> Self {
        Self {
            image: image.into(),
            run_log_dir: Some(layout.data_dir.join("logs").join("containers")),
            layout,
            timezone: "UTC".to_string(),
            container_timeout: Duration::from_secs(1800),
            idle_timeout: Duration::from_secs(1800),
            idle_grace: DEFAULT_IDLE_GRACE,
            stop_grace: DEFAULT_STOP_GRACE,
            kill_after: DEFAULT_KILL_AFTER,
            exit_drain: DEFAULT_EXIT_DRAIN,
            max_output_bytes: 10 * 1024 * 1024,
            default_limits: ResourceLimits::default(),
            run_as: None,
            chown_dirs: None,
            mount_options: MountOptions::default(),
            run_log_keep: DEFAULT_RUN_LOG_KEEP,
            default_network: Some(AGENT_NETWORK.to_string()),
            frame_queue_capacity: DEFAULT_FRAME_QUEUE_CAPACITY,
            max_frames_per_run: DEFAULT_MAX_FRAMES_PER_RUN,
            max_result_bytes_per_run: DEFAULT_MAX_RESULT_BYTES_PER_RUN,
            max_run_time_factor: DEFAULT_MAX_RUN_TIME_FACTOR,
        }
    }

    /// From the resolved host configuration. The agent network comes from
    /// [`CONTAINER_NETWORK_ENV`] (process env first, then `.env`; see
    /// [`network_setting`]); the host config directory (mount / sender
    /// allowlists) and `store/` are protected from additional mounts.
    pub fn from_talon_config(cfg: &TalonConfig) -> Self {
        let mut out = Self::new(cfg.container_image.clone(), MountLayout::from_config(cfg));
        out.timezone = cfg.timezone_name.clone();
        out.container_timeout = cfg.container_timeout;
        out.idle_timeout = cfg.idle_timeout;
        out.max_output_bytes = cfg.container_max_output_bytes;
        // `EnvFile::get` cannot tell "set but empty" from "unset".
        let raw = std::env::var(CONTAINER_NETWORK_ENV).ok().or_else(|| {
            cfg.env
                .file_value(CONTAINER_NETWORK_ENV)
                .map(str::to_string)
        });
        out.default_network = network_setting(raw.as_deref());
        out.mount_options.protected_paths = vec![
            cfg.config_dir.clone(),
            cfg.mount_allowlist_path.clone(),
            cfg.sender_allowlist_path.clone(),
            cfg.store_dir.clone(),
        ];
        out
    }

    /// Timeout configured for a group (ms in `ContainerConfig.timeout`; 0 or
    /// absent => default), capped at [`MAX_TIMEOUT`].
    pub fn config_timeout(&self, cfg: &ContainerConfig) -> Duration {
        cfg.timeout
            .filter(|ms| *ms > 0)
            .map(Duration::from_millis)
            .unwrap_or(self.container_timeout)
            .min(MAX_TIMEOUT)
    }

    /// `max(config_timeout, idle_timeout + idle_grace)`.
    pub fn hard_timeout(&self, cfg: &ContainerConfig) -> Duration {
        self.config_timeout(cfg)
            .max(self.idle_timeout.saturating_add(self.idle_grace))
            .min(MAX_TIMEOUT)
    }

    /// Absolute cap on a run: frames may push the hard timeout out, but
    /// never past `hard_timeout × max_run_time_factor` (min 1×) from the
    /// start, capped at [`MAX_TIMEOUT`].
    pub fn max_run_time(&self, cfg: &ContainerConfig) -> Duration {
        self.hard_timeout(cfg)
            .saturating_mul(self.max_run_time_factor.max(1))
            .min(MAX_TIMEOUT)
    }
}

/// One container run request.
#[derive(Clone)]
pub struct RunSpec {
    /// The group (folder, lane keys, container config).
    pub group: RegisteredGroup,
    /// Written to the container's stdin. Contains the gateway token: never
    /// logged.
    pub input: ContainerInput,
    /// Effective container config (`.env` defaults merged with the group's,
    /// see `talon_core::provider::merge_container_config`).
    pub config: ContainerConfig,
}

impl fmt::Debug for RunSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunSpec")
            .field("group", &self.group.folder)
            .field("is_main", &self.input.is_main)
            .field("prompt_len", &self.input.prompt.len())
            .field("has_llm", &self.input.llm.is_some())
            .finish_non_exhaustive()
    }
}

impl RunSpec {
    /// Spec using the group's own container config.
    pub fn new(group: RegisteredGroup, input: ContainerInput) -> Self {
        let config = group.container_config.clone().unwrap_or_default();
        Self {
            group,
            input,
            config,
        }
    }

    /// Use an explicit effective container config.
    pub fn with_config(mut self, config: ContainerConfig) -> Self {
        self.config = config;
        self
    }
}

/// Everything decided before spawning.
#[derive(Debug, Clone, PartialEq)]
pub struct PreparedRun {
    /// Container name.
    pub name: String,
    /// Arguments after the runtime binary.
    pub args: Vec<String>,
    /// Bind mounts.
    pub mounts: Vec<VolumeMount>,
    /// `RUN_UID`/`RUN_GID`.
    pub run_as: RunAs,
    /// Effective limits.
    pub limits: ResourceLimits,
    /// Accepted env overlay keys.
    pub env_keys: Vec<String>,
    /// Blocked hosts.
    pub blocked_hosts: Vec<String>,
    /// Network override.
    pub network: Option<String>,
    /// Refused config values.
    pub rejections: Vec<ConfigRejection>,
    /// Configured timeout (reported in timeout errors).
    pub config_timeout: Duration,
    /// Effective hard timeout.
    pub hard_timeout: Duration,
    /// Absolute cap the hard timeout can be extended to by frames.
    pub max_run_time: Duration,
}

/// Why a run could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Mounts / arguments could not be prepared.
    #[error("Container setup error: {0}")]
    Setup(talon_core::Error),
    /// The runtime process could not be spawned.
    #[error("Container spawn error: {0}")]
    Spawn(io::Error),
}

impl From<StartError> for talon_core::Error {
    fn from(e: StartError) -> Self {
        talon_core::Error::Container(e.to_string())
    }
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    /// The process exited on its own.
    Exited,
    /// The hard timeout fired and the container was stopped.
    TimedOut,
    /// Stopped through [`ContainerHandle::stop`].
    Stopped,
    /// The process did not confirm its exit even after SIGKILL.
    Abandoned,
    /// Preparing mounts / arguments failed.
    SetupFailed,
    /// Spawning the runtime failed.
    SpawnFailed,
    /// Too many frames or result bytes: the container was stopped.
    OutputLimitExceeded,
}

/// Final result of a run (TS `ContainerOutput` + diagnostics).
#[derive(Debug, Clone, PartialEq)]
pub struct RunResult {
    /// Success / error.
    pub status: OutputStatus,
    /// Error message (TS-compatible wording).
    pub error: Option<String>,
    /// Last non-empty session id seen in a frame.
    pub new_session_id: Option<String>,
    /// Last usage block seen in a frame.
    pub usage: Option<SessionUsage>,
    /// Last non-null `result` seen in a frame.
    pub last_result: Option<String>,
    /// Number of valid frames.
    pub outputs: usize,
    /// Exit code (or 128 + signal).
    pub exit_code: Option<i32>,
    /// How the run ended.
    pub outcome: RunOutcome,
    /// Wall-clock duration.
    pub duration: Duration,
    /// Container name (empty if setup failed before naming).
    pub container_name: String,
}

impl RunResult {
    /// `status == Success`.
    pub fn is_success(&self) -> bool {
        self.status == OutputStatus::Success
    }

    /// The TS-shaped final output (`result` is null in streaming mode).
    pub fn to_container_output(&self) -> ContainerOutput {
        ContainerOutput {
            status: self.status,
            result: None,
            new_session_id: self.new_session_id.clone(),
            error: self.error.clone(),
            usage: self.usage,
        }
    }

    fn failed_to_start(err: &StartError, name: String) -> Self {
        Self {
            status: OutputStatus::Error,
            error: Some(err.to_string()),
            new_session_id: None,
            usage: None,
            last_result: None,
            outputs: 0,
            exit_code: None,
            outcome: match err {
                StartError::Setup(_) => RunOutcome::SetupFailed,
                StartError::Spawn(_) => RunOutcome::SpawnFailed,
            },
            duration: Duration::ZERO,
            container_name: name,
        }
    }
}

/// Receives every parsed output frame, in order.
#[async_trait]
pub trait OutputHandler: Send + 'static {
    /// Called once per frame (including frames with a null result).
    async fn on_output(&mut self, output: ContainerOutput);
}

#[async_trait]
impl<F, Fut> OutputHandler for F
where
    F: FnMut(ContainerOutput) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    async fn on_output(&mut self, output: ContainerOutput) {
        (self)(output).await
    }
}

/// A handler that ignores every frame.
pub fn noop_handler() -> impl OutputHandler {
    |_output: ContainerOutput| async {}
}

struct HandleInner {
    name: String,
    group_folder: String,
    cancel: CancellationToken,
    exited: watch::Receiver<bool>,
    max_stop_wait: Duration,
}

/// Handle to a running container, for the group queue.
#[derive(Clone)]
pub struct ContainerHandle {
    inner: Arc<HandleInner>,
}

impl fmt::Debug for ContainerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainerHandle")
            .field("name", &self.inner.name)
            .field("running", &self.is_running())
            .finish()
    }
}

impl ContainerHandle {
    /// Container name (`talon-<folder>-<millis>`).
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Owning group folder.
    pub fn group_folder(&self) -> &str {
        &self.inner.group_folder
    }

    /// `false` once the run finished.
    pub fn is_running(&self) -> bool {
        !*self.inner.exited.borrow() && self.inner.exited.has_changed().is_ok()
    }

    /// `true` after [`Self::stop`] / [`Self::request_stop`].
    pub fn is_stop_requested(&self) -> bool {
        self.inner.cancel.is_cancelled()
    }

    /// Ask the run loop to stop the container (non-blocking).
    pub fn request_stop(&self) {
        self.inner.cancel.cancel();
    }

    /// Gracefully stop (then kill) the container and wait until the run
    /// finished (bounded).
    pub async fn stop(&self) {
        self.request_stop();
        if tokio::time::timeout(self.inner.max_stop_wait, self.wait_exited())
            .await
            .is_err()
        {
            tracing::warn!(container = %self.inner.name, "container did not finish after stop");
        }
    }

    /// Wait until the run finished.
    pub async fn wait_exited(&self) {
        let mut rx = self.inner.exited.clone();
        let _ = rx.wait_for(|exited| *exited).await;
    }
}

/// A started run: a handle plus the task producing the [`RunResult`].
pub struct StartedContainer {
    handle: ContainerHandle,
    task: tokio::task::JoinHandle<RunResult>,
    name: String,
}

impl StartedContainer {
    /// Handle for the queue (`name()`, `stop()`).
    pub fn handle(&self) -> ContainerHandle {
        self.handle.clone()
    }

    /// Wait for the run to finish.
    pub async fn wait(self) -> RunResult {
        match self.task.await {
            Ok(result) => result,
            Err(err) => {
                tracing::error!(container = %self.name, %err, "container run task failed");
                RunResult {
                    status: OutputStatus::Error,
                    error: Some(format!("Container run task failed: {err}")),
                    new_session_id: None,
                    usage: None,
                    last_result: None,
                    outputs: 0,
                    exit_code: None,
                    outcome: RunOutcome::Abandoned,
                    duration: Duration::ZERO,
                    container_name: self.name,
                }
            }
        }
    }
}

/// Launches agent containers.
pub struct ContainerRunner {
    config: RunnerConfig,
    runtime: Arc<ContainerRuntime>,
    spawner: Arc<dyn ProcessSpawner>,
    mount_policy: Arc<dyn MountPolicy>,
    redactor: Arc<dyn LogRedactor>,
    audit: SharedAuditSink,
}

impl fmt::Debug for ContainerRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainerRunner")
            .field("config", &self.config)
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl ContainerRunner {
    /// New runner. `mount_policy` is normally
    /// `talon_security::mounts::MountValidator`, `redactor` a
    /// `talon_security::redact::Redactor` primed with the host's secrets.
    pub fn new(
        config: RunnerConfig,
        runtime: Arc<ContainerRuntime>,
        mount_policy: Arc<dyn MountPolicy>,
        redactor: Arc<dyn LogRedactor>,
        audit: SharedAuditSink,
    ) -> Self {
        Self {
            config,
            runtime,
            spawner: Arc::new(TokioProcessSpawner),
            mount_policy,
            redactor,
            audit,
        }
    }

    /// Replace the process spawner (tests).
    pub fn with_spawner(mut self, spawner: Arc<dyn ProcessSpawner>) -> Self {
        self.spawner = spawner;
        self
    }

    /// Runner configuration.
    pub fn config(&self) -> &RunnerConfig {
        &self.config
    }

    /// Container runtime.
    pub fn runtime(&self) -> &Arc<ContainerRuntime> {
        &self.runtime
    }

    /// Build mounts and arguments without launching (creates the lane's
    /// directories). Does not record audit events.
    pub fn prepare(&self, spec: &RunSpec) -> talon_core::Result<PreparedRun> {
        self.prepare_inner(spec, None)
    }

    fn prepare_inner(
        &self,
        spec: &RunSpec,
        audit: Option<&dyn AuditSink>,
    ) -> talon_core::Result<PreparedRun> {
        let group = &spec.group;
        if !is_valid_group_folder(&group.folder) {
            return Err(talon_core::Error::security(format!(
                "invalid group folder {:?}",
                group.folder
            )));
        }
        if spec.input.group_folder != group.folder {
            tracing::warn!(
                group = %group.folder,
                input_folder = %spec.input.group_folder,
                "ContainerInput.group_folder differs from the group; using the group"
            );
        }
        let run_as = self.config.run_as.unwrap_or_else(RunAs::current);
        let chown = self.config.chown_dirs.unwrap_or_else(host_is_root);
        let mounts = build_mounts(&MountRequest {
            layout: &self.config.layout,
            group,
            is_main: spec.input.is_main,
            policy: self.mount_policy.as_ref(),
            chown_to: chown.then_some(run_as),
            options: &self.config.mount_options,
            audit,
        })?;
        let name = container_name(&group.folder);
        let gateway = self.runtime.host_gateway_args();
        let built = build_run_args(&RunArgsInput {
            name: &name,
            group_folder: &group.folder,
            image: &self.config.image,
            timezone: &self.config.timezone,
            run_as,
            config: &spec.config,
            default_limits: &self.config.default_limits,
            mounts: &mounts,
            host_gateway_args: &gateway,
            default_network: self.config.default_network.as_deref(),
        })?;
        Ok(PreparedRun {
            name,
            args: built.args,
            mounts,
            run_as,
            limits: built.limits,
            env_keys: built.env_keys,
            blocked_hosts: built.blocked_hosts,
            network: built.network,
            rejections: built.rejections,
            config_timeout: self.config.config_timeout(&spec.config),
            hard_timeout: self.config.hard_timeout(&spec.config),
            max_run_time: self.config.max_run_time(&spec.config),
        })
    }

    /// Spawn the container and return immediately with a handle; the run
    /// continues on a background task (see [`StartedContainer::wait`]).
    pub async fn start<H: OutputHandler>(
        &self,
        spec: RunSpec,
        handler: H,
    ) -> Result<StartedContainer, StartError> {
        let group = &spec.group;
        let prepared = match self.prepare_inner(&spec, Some(self.audit.as_ref())) {
            Ok(p) => p,
            Err(e) => {
                let err = StartError::Setup(e);
                self.audit_launch_failure(group, None, &err);
                tracing::error!(group = %group.name, error = %err, "container setup failed");
                return Err(err);
            }
        };
        for r in &prepared.rejections {
            tracing::warn!(
                group = %group.name,
                field = r.field,
                value = %r.value,
                reason = %r.reason,
                "container config value rejected"
            );
            self.audit.record(event(
                AUDIT_CONFIG_REJECTED,
                &group.folder,
                Some(&r.value),
                "denied",
                serde_json::json!({ "field": r.field, "reason": r.reason }),
            ));
        }

        let input_json = match serde_json::to_vec(&spec.input) {
            Ok(v) => v,
            Err(e) => {
                let err = StartError::Setup(e.into());
                self.audit_launch_failure(group, Some(&prepared.name), &err);
                return Err(err);
            }
        };

        let args_redacted = self
            .redactor
            .redact_text(&prepared.args.join(" "))
            .into_owned();
        tracing::debug!(
            group = %group.name,
            container = %prepared.name,
            mounts = ?prepared.mounts.iter().map(VolumeMount::describe).collect::<Vec<_>>(),
            args = %args_redacted,
            "Container mount configuration"
        );
        tracing::info!(
            group = %group.name,
            container = %prepared.name,
            mount_count = prepared.mounts.len(),
            is_main = spec.input.is_main,
            "Spawning container agent"
        );

        let command = ProcessCommand {
            program: self.runtime.bin().to_string(),
            args: prepared.args.clone(),
        };
        let process = match self.spawner.spawn(&command) {
            Ok(p) => p,
            Err(e) => {
                let err = StartError::Spawn(e);
                tracing::error!(group = %group.name, container = %prepared.name, error = %err, "Container spawn error");
                self.audit_launch_failure(group, Some(&prepared.name), &err);
                return Err(err);
            }
        };

        self.audit.record(event(
            "container.launch",
            &group.folder,
            Some(&prepared.name),
            "allowed",
            serde_json::json!({
                "image": self.config.image,
                "isMain": spec.input.is_main,
                "scheduledTask": spec.input.is_scheduled_task,
                "resumedSession": spec.input.session_id.is_some(),
                "runAs": { "uid": prepared.run_as.uid, "gid": prepared.run_as.gid },
                "limits": {
                    "memory": prepared.limits.memory,
                    "cpus": prepared.limits.cpus,
                    "pidsLimit": prepared.limits.pids_limit,
                },
                "network": prepared.network,
                "envKeys": prepared.env_keys,
                "blockedHosts": prepared.blocked_hosts,
                "mounts": prepared.mounts.iter().map(|m| serde_json::json!({
                    "host": m.host_path.to_string_lossy(),
                    "container": m.container_path,
                    "readonly": m.readonly,
                })).collect::<Vec<_>>(),
                "timeoutMs": prepared.hard_timeout.as_millis() as u64,
                "maxRunTimeMs": prepared.max_run_time.as_millis() as u64,
            }),
        ));

        let cancel = CancellationToken::new();
        let (exited_tx, exited_rx) = watch::channel(false);
        let cfg = &self.config;
        let handle = ContainerHandle {
            inner: Arc::new(HandleInner {
                name: prepared.name.clone(),
                group_folder: group.folder.clone(),
                cancel: cancel.clone(),
                exited: exited_rx,
                max_stop_wait: cfg
                    .stop_grace
                    .saturating_add(cfg.kill_after)
                    .saturating_add(cfg.exit_drain.saturating_mul(3))
                    .saturating_add(Duration::from_secs(5)),
            }),
        };

        let ctx = RunContext {
            name: prepared.name.clone(),
            group_name: group.name.clone(),
            group_folder: group.folder.clone(),
            is_main: spec.input.is_main,
            prompt_len: spec.input.prompt.chars().count(),
            resumed_session: spec.input.session_id.is_some(),
            config_timeout: prepared.config_timeout,
            hard_timeout: prepared.hard_timeout,
            max_run_time: prepared.max_run_time,
            frame_queue_capacity: cfg.frame_queue_capacity.max(1),
            max_frames: cfg.max_frames_per_run,
            max_result_bytes: cfg.max_result_bytes_per_run,
            stop_grace: cfg.stop_grace,
            kill_after: cfg.kill_after,
            exit_drain: cfg.exit_drain,
            max_output_bytes: cfg.max_output_bytes,
            runtime: self.runtime.clone(),
            redactor: self.redactor.clone(),
            audit: self.audit.clone(),
            run_log: cfg
                .run_log_dir
                .as_ref()
                .map(|d| (d.join(&group.folder), cfg.run_log_keep)),
            args_redacted,
            mounts: prepared.mounts,
            started: Instant::now(),
        };
        let task = tokio::spawn(run_loop(
            ctx, process, input_json, handler, cancel, exited_tx,
        ));
        Ok(StartedContainer {
            handle,
            task,
            name: prepared.name,
        })
    }

    /// Run to completion. `on_start` receives the handle right after the
    /// container was spawned (TS `onProcess`), e.g. to register it with the
    /// group queue. Never fails: problems are reported in the result.
    pub async fn run<H, F>(&self, spec: RunSpec, handler: H, on_start: F) -> RunResult
    where
        H: OutputHandler,
        F: FnOnce(ContainerHandle) + Send,
    {
        match self.start(spec, handler).await {
            Ok(started) => {
                on_start(started.handle());
                started.wait().await
            }
            Err(err) => RunResult::failed_to_start(&err, String::new()),
        }
    }

    fn audit_launch_failure(&self, group: &RegisteredGroup, name: Option<&str>, err: &StartError) {
        self.audit.record(event(
            "container.launch",
            &group.folder,
            name,
            "error",
            serde_json::json!({ "error": self.redactor.redact_text(&err.to_string()) }),
        ));
    }
}

/// Bounded buffer keeping the last bytes of a stream.
#[derive(Debug, Default)]
struct TailBuffer {
    buf: Vec<u8>,
    total: u64,
}

impl TailBuffer {
    fn push(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > 2 * TAIL_BYTES {
            let cut = self.buf.len() - TAIL_BYTES;
            self.buf.drain(..cut);
        }
    }

    fn truncated(&self) -> bool {
        self.total > TAIL_BYTES as u64
    }

    fn text(&self) -> String {
        let start = self.buf.len().saturating_sub(TAIL_BYTES);
        String::from_utf8_lossy(&self.buf[start..]).into_owned()
    }
}

#[derive(Debug, Default)]
struct StreamSummary {
    tail: TailBuffer,
}

/// Read and parse stdout. `tx` is bounded: while the run loop is not
/// accepting events, stdout is not read and the container blocks on its own
/// writes (backpressure instead of host-side buffering).
async fn read_stdout(
    mut stdout: BoxedReader,
    max_frame_bytes: usize,
    tx: mpsc::Sender<ParseEvent>,
) -> StreamSummary {
    let mut parser = crate::parser::OutputParser::new(max_frame_bytes);
    let mut summary = StreamSummary::default();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match stdout.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                summary.tail.push(&buf[..n]);
                for ev in parser.push(&buf[..n]) {
                    if tx.send(ev).await.is_err() {
                        // The run loop is gone; nobody wants more output.
                        return summary;
                    }
                }
            }
            Err(err) => {
                tracing::warn!(%err, "error reading container stdout");
                break;
            }
        }
    }
    for ev in parser.finish() {
        if tx.send(ev).await.is_err() {
            break;
        }
    }
    summary
}

async fn read_stderr(
    mut stderr: BoxedReader,
    container: String,
    redactor: Arc<dyn LogRedactor>,
) -> StreamSummary {
    let mut summary = StreamSummary::default();
    let mut buf = vec![0u8; 8 * 1024];
    let mut line: Vec<u8> = Vec::new();
    let mut discarding = false;
    let emit = |line: &[u8], truncated: bool, summary: &mut StreamSummary| {
        let raw = String::from_utf8_lossy(line);
        let text = raw.trim_end();
        if text.is_empty() {
            return;
        }
        let redacted = redactor.redact_text(text);
        // Don't reset any timeout on stderr: runtimes log continuously.
        tracing::debug!(target: "talon::container", container = %container, truncated, "{redacted}");
        summary.tail.push(redacted.as_bytes());
        summary.tail.push(b"\n");
    };
    loop {
        let n = match stderr.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => {
                tracing::warn!(%err, "error reading container stderr");
                break;
            }
        };
        let mut rest = &buf[..n];
        while !rest.is_empty() {
            let (piece, newline) = match rest.iter().position(|&b| b == b'\n') {
                Some(pos) => (&rest[..pos], true),
                None => (rest, false),
            };
            rest = if newline {
                &rest[piece.len() + 1..]
            } else {
                &[]
            };
            if !discarding {
                line.extend_from_slice(piece);
                if line.len() > MAX_STDERR_LINE {
                    line.truncate(MAX_STDERR_LINE);
                    emit(&line, true, &mut summary);
                    line.clear();
                    discarding = true;
                }
            }
            if newline {
                if !discarding {
                    emit(&line, false, &mut summary);
                }
                line.clear();
                discarding = false;
            }
        }
    }
    if !line.is_empty() && !discarding {
        emit(&line, false, &mut summary);
    }
    summary
}

struct RunContext {
    name: String,
    group_name: String,
    group_folder: String,
    is_main: bool,
    prompt_len: usize,
    resumed_session: bool,
    config_timeout: Duration,
    hard_timeout: Duration,
    max_run_time: Duration,
    frame_queue_capacity: usize,
    max_frames: usize,
    max_result_bytes: usize,
    stop_grace: Duration,
    kill_after: Duration,
    exit_drain: Duration,
    max_output_bytes: usize,
    runtime: Arc<ContainerRuntime>,
    redactor: Arc<dyn LogRedactor>,
    audit: SharedAuditSink,
    run_log: Option<(PathBuf, usize)>,
    args_redacted: String,
    mounts: Vec<VolumeMount>,
    started: Instant,
}

/// Which per-run output budget was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputLimit {
    Frames,
    ResultBytes,
}

impl OutputLimit {
    fn as_str(self) -> &'static str {
        match self {
            OutputLimit::Frames => "frames",
            OutputLimit::ResultBytes => "resultBytes",
        }
    }
}

/// Bytes a frame adds to the per-run result budget.
fn payload_bytes(output: &ContainerOutput) -> usize {
    output
        .result
        .as_ref()
        .map_or(0, String::len)
        .saturating_add(output.error.as_ref().map_or(0, String::len))
}

#[derive(Default)]
struct LoopState {
    exit: Option<io::Result<ExitInfo>>,
    had_output: bool,
    outputs: usize,
    malformed: usize,
    oversize: usize,
    result_bytes: usize,
    limit: Option<OutputLimit>,
    discarded: usize,
    run_cap_reached: bool,
    new_session_id: Option<String>,
    usage: Option<SessionUsage>,
    last_result: Option<String>,
    timed_out: bool,
    stop_requested: bool,
    kill_at: Option<Instant>,
    killed_at: Option<Instant>,
    drain_until: Option<Instant>,
}

fn after(base: Instant, d: Duration) -> Instant {
    base.checked_add(d)
        .unwrap_or_else(|| base + Duration::from_secs(365 * 24 * 3600))
}

fn begin_stop(
    ctx: &RunContext,
    st: &mut LoopState,
    stop_tx: &mpsc::UnboundedSender<talon_core::Result<()>>,
) {
    if st.kill_at.is_some() || st.killed_at.is_some() {
        return;
    }
    let runtime = ctx.runtime.clone();
    let name = ctx.name.clone();
    let grace = ctx.stop_grace;
    let tx = stop_tx.clone();
    tokio::spawn(async move {
        let _ = tx.send(runtime.stop(&name, grace).await);
    });
    st.kill_at = Some(after(
        Instant::now(),
        ctx.stop_grace.saturating_add(ctx.kill_after),
    ));
}

fn force_kill(ctx: &RunContext, st: &mut LoopState, control: &mut dyn ProcessControl) {
    tracing::warn!(group = %ctx.group_name, container = %ctx.name, "force killing container");
    let runtime = ctx.runtime.clone();
    let name = ctx.name.clone();
    tokio::spawn(async move {
        if let Err(err) = runtime.kill(&name).await {
            tracing::debug!(container = %name, %err, "kill failed (already gone?)");
        }
    });
    if let Err(err) = control.start_kill() {
        tracing::debug!(container = %ctx.name, %err, "failed to SIGKILL runtime client");
    }
    st.killed_at = Some(Instant::now());
}

fn exit_hint(code: i32) -> &'static str {
    match code {
        125 => " (container runtime failed to start the container)",
        126 => " (entrypoint not executable)",
        127 => " (entrypoint not found)",
        137 => " (SIGKILL: killed or out of memory)",
        143 => " (SIGTERM)",
        _ => "",
    }
}

fn last_chars(s: &str, n: usize) -> String {
    let count = s.chars().count();
    s.chars().skip(count.saturating_sub(n)).collect()
}

async fn run_loop<H: OutputHandler>(
    ctx: RunContext,
    process: SpawnedProcess,
    input_json: Vec<u8>,
    handler: H,
    cancel: CancellationToken,
    exited_tx: watch::Sender<bool>,
) -> RunResult {
    let SpawnedProcess {
        stdin,
        stdout,
        stderr,
        mut control,
    } = process;

    // stdin: input JSON, then EOF.
    let stdin_task = stdin.map(|mut writer| {
        tokio::spawn(async move {
            let res = writer.write_all(&input_json).await;
            let _ = writer.shutdown().await;
            res
        })
    });

    // Bounded queues end to end (MYTH-07): parser -> loop -> handler. The
    // loop holds at most one frame (`pending`) while the handler queue is
    // full and stops taking events meanwhile, so stdout stops being read.
    let (ev_tx, mut ev_rx) = mpsc::channel::<ParseEvent>(ctx.frame_queue_capacity);
    let stdout_task = tokio::spawn(read_stdout(stdout, ctx.max_output_bytes, ev_tx));
    let mut stderr_task = tokio::spawn(read_stderr(stderr, ctx.name.clone(), ctx.redactor.clone()));

    // Frames are handled sequentially on their own task (TS `outputChain`).
    let (out_tx, mut out_rx) = mpsc::channel::<ContainerOutput>(ctx.frame_queue_capacity);
    let handler_task = tokio::spawn(async move {
        let mut handler = handler;
        while let Some(output) = out_rx.recv().await {
            handler.on_output(output).await;
        }
    });

    let (stop_tx, mut stop_rx) = mpsc::unbounded_channel::<talon_core::Result<()>>();
    let mut st = LoopState::default();
    let mut events_open = true;
    let mut pending: Option<ContainerOutput> = None;
    // Frames extend the hard timeout, but never past this absolute cap.
    let cap_at = after(ctx.started, ctx.max_run_time);
    let mut deadline = after(Instant::now(), ctx.hard_timeout).min(cap_at);
    let far = after(Instant::now(), MAX_TIMEOUT);

    loop {
        if st.exit.is_some() && !events_open {
            break;
        }
        let stopping = st.kill_at.is_some() && st.killed_at.is_none();
        let kill_at = st.kill_at.unwrap_or(far);
        let give_up_at = st
            .killed_at
            .map(|t| after(t, ctx.exit_drain))
            .unwrap_or(far);
        let drain_until = st.drain_until.unwrap_or(far);
        tokio::select! {
            biased;
            permit = out_tx.reserve(), if pending.is_some() => match permit {
                Ok(permit) => {
                    if let Some(output) = pending.take() {
                        permit.send(output);
                    }
                }
                Err(_) => {
                    tracing::error!(group = %ctx.group_name, container = %ctx.name, "output handler is gone; dropping frame");
                    pending = None;
                }
            },
            ev = ev_rx.recv(), if events_open && pending.is_none() => match ev {
                Some(ParseEvent::Output(mut output)) => {
                    let bytes = payload_bytes(&output);
                    let exceeded = if st.limit.is_some() {
                        None
                    } else if st.outputs >= ctx.max_frames {
                        Some(OutputLimit::Frames)
                    } else if st.result_bytes.saturating_add(bytes) > ctx.max_result_bytes {
                        Some(OutputLimit::ResultBytes)
                    } else {
                        None
                    };
                    if let Some(limit) = exceeded {
                        st.limit = Some(limit);
                        tracing::error!(
                            group = %ctx.group_name,
                            container = %ctx.name,
                            limit = limit.as_str(),
                            frames = st.outputs,
                            result_bytes = st.result_bytes,
                            "Container output limit exceeded, stopping"
                        );
                        if st.exit.is_none() {
                            begin_stop(&ctx, &mut st, &stop_tx);
                        }
                    }
                    if st.limit.is_some() {
                        // Over budget: drained, never delivered.
                        st.discarded += 1;
                    } else {
                        st.had_output = true;
                        st.outputs += 1;
                        st.result_bytes = st.result_bytes.saturating_add(bytes);
                        // N-5: the id is persisted, logged and sent back to the
                        // container; anything but a short token is dropped
                        // (from the run result and the delivered frame alike).
                        match output.new_session_id.as_deref() {
                            None | Some("") => {}
                            Some(id) if is_valid_session_id(id) => {
                                st.new_session_id = Some(id.to_string());
                            }
                            Some(id) => {
                                tracing::warn!(group = %ctx.group_name, container = %ctx.name, bytes = id.len(), max_bytes = MAX_SESSION_ID_BYTES, "Container reported an invalid session id; ignored");
                                output.new_session_id = None;
                            }
                        }
                        if output.usage.is_some() {
                            st.usage = output.usage;
                        }
                        if output.result.is_some() {
                            st.last_result = output.result.clone();
                        }
                        // Activity: extend the hard timeout (up to the cap).
                        deadline = after(Instant::now(), ctx.hard_timeout).min(cap_at);
                        if st.exit.is_some() {
                            // Delivering a backlog after exit: keep draining
                            // while it makes progress (bounded by the frame
                            // budget; discarded frames never extend it).
                            st.drain_until = Some(after(Instant::now(), ctx.exit_drain));
                        }
                        pending = Some(output);
                    }
                }
                Some(ParseEvent::Malformed { reason, bytes }) => {
                    st.malformed += 1;
                    tracing::warn!(group = %ctx.group_name, container = %ctx.name, %reason, bytes, "Failed to parse streamed output chunk");
                }
                Some(ParseEvent::Oversize { bytes }) => {
                    st.oversize += 1;
                    tracing::warn!(group = %ctx.group_name, container = %ctx.name, bytes, limit = ctx.max_output_bytes, "Container output frame exceeded the size limit and was dropped");
                }
                None => events_open = false,
            },
            res = control.wait(), if st.exit.is_none() => {
                st.exit = Some(res);
                st.drain_until = Some(after(Instant::now(), ctx.exit_drain));
            }
            _ = sleep_until(deadline), if st.exit.is_none() && !st.timed_out && !st.stop_requested && st.limit.is_none() => {
                st.timed_out = true;
                if deadline >= cap_at {
                    st.run_cap_reached = true;
                    tracing::error!(group = %ctx.group_name, container = %ctx.name, max_run_time_ms = ctx.max_run_time.as_millis() as u64, "Container reached its absolute run-time cap, stopping gracefully");
                } else {
                    tracing::error!(group = %ctx.group_name, container = %ctx.name, "Container timeout, stopping gracefully");
                }
                begin_stop(&ctx, &mut st, &stop_tx);
            }
            _ = cancel.cancelled(), if st.exit.is_none() && !st.stop_requested && !st.timed_out && st.limit.is_none() => {
                st.stop_requested = true;
                tracing::info!(group = %ctx.group_name, container = %ctx.name, "Container stop requested");
                begin_stop(&ctx, &mut st, &stop_tx);
            }
            Some(res) = stop_rx.recv(), if stopping => {
                if let Err(err) = res {
                    tracing::warn!(group = %ctx.group_name, container = %ctx.name, %err, "Graceful stop failed, force killing");
                    st.kill_at = Some(Instant::now());
                }
            }
            _ = sleep_until(kill_at), if st.exit.is_none() && stopping => {
                force_kill(&ctx, &mut st, control.as_mut());
            }
            _ = sleep_until(give_up_at), if st.exit.is_none() && st.killed_at.is_some() => {
                tracing::error!(group = %ctx.group_name, container = %ctx.name, "Container process did not exit after SIGKILL; abandoning");
                break;
            }
            _ = sleep_until(drain_until), if st.exit.is_some() && events_open && pending.is_none() => {
                tracing::warn!(group = %ctx.group_name, container = %ctx.name, "stdout still open after exit; abandoning remaining output");
                break;
            }
        }
    }

    // Let the handler finish every accepted frame (TS waits for outputChain).
    if let Some(output) = pending.take() {
        if out_tx.send(output).await.is_err() {
            tracing::error!(group = %ctx.group_name, container = %ctx.name, "output handler is gone; dropping frame");
        }
    }
    drop(out_tx);
    if let Err(err) = handler_task.await {
        tracing::error!(group = %ctx.group_name, container = %ctx.name, %err, "output handler failed");
    }

    let stdout_summary = if events_open {
        stdout_task.abort();
        StreamSummary::default()
    } else {
        stdout_task.await.unwrap_or_default()
    };
    let stderr_summary = match tokio::time::timeout(ctx.exit_drain, &mut stderr_task).await {
        Ok(Ok(s)) => s,
        _ => {
            stderr_task.abort();
            StreamSummary::default()
        }
    };
    if let Some(task) = stdin_task {
        if task.is_finished() {
            if let Ok(Err(err)) = task.await {
                tracing::debug!(container = %ctx.name, %err, "writing container stdin failed");
            }
        } else {
            task.abort();
            tracing::warn!(container = %ctx.name, "container never consumed its input");
        }
    }

    let duration = ctx.started.elapsed();
    let exit_info = match &st.exit {
        Some(Ok(info)) => Some(*info),
        _ => None,
    };
    let code = exit_info.and_then(|i| i.shell_code());
    let stderr_text = stderr_summary.tail.text();

    let (status, error, outcome) = if let Some(limit) = st.limit {
        let what = match limit {
            OutputLimit::Frames => format!("more than {} frames", ctx.max_frames),
            OutputLimit::ResultBytes => {
                format!("more than {} bytes of results", ctx.max_result_bytes)
            }
        };
        (
            OutputStatus::Error,
            Some(format!("Container output limit exceeded: {what}")),
            RunOutcome::OutputLimitExceeded,
        )
    } else if st.timed_out {
        if st.had_output {
            tracing::info!(group = %ctx.group_name, container = %ctx.name, duration_ms = duration.as_millis() as u64, ?code, "Container timed out after output (idle cleanup)");
            (OutputStatus::Success, None, RunOutcome::TimedOut)
        } else {
            tracing::error!(group = %ctx.group_name, container = %ctx.name, duration_ms = duration.as_millis() as u64, ?code, "Container timed out with no output");
            (
                OutputStatus::Error,
                Some(format!(
                    "Container timed out after {}ms",
                    ctx.config_timeout.as_millis()
                )),
                RunOutcome::TimedOut,
            )
        }
    } else if st.stop_requested {
        if st.had_output || code == Some(0) {
            (OutputStatus::Success, None, RunOutcome::Stopped)
        } else {
            (
                OutputStatus::Error,
                Some("Container was stopped before producing output".to_string()),
                RunOutcome::Stopped,
            )
        }
    } else if let Some(Err(err)) = &st.exit {
        (
            OutputStatus::Error,
            Some(format!("Container process error: {err}")),
            RunOutcome::Abandoned,
        )
    } else if exit_info.is_none() {
        (
            OutputStatus::Error,
            Some("Container did not exit cleanly".to_string()),
            RunOutcome::Abandoned,
        )
    } else if code == Some(0) {
        tracing::info!(group = %ctx.group_name, container = %ctx.name, duration_ms = duration.as_millis() as u64, session = ?st.new_session_id, "Container completed (streaming mode)");
        (OutputStatus::Success, None, RunOutcome::Exited)
    } else if code == Some(137) && st.had_output {
        // Output already arrived: the agent completed; don't trigger retries.
        tracing::info!(group = %ctx.group_name, container = %ctx.name, "Container killed after output was received — treating as success");
        (OutputStatus::Success, None, RunOutcome::Exited)
    } else {
        let code_text = code.map_or_else(|| "unknown".to_string(), |c| c.to_string());
        let hint = code.map(exit_hint).unwrap_or_default();
        tracing::error!(group = %ctx.group_name, container = %ctx.name, code = %code_text, duration_ms = duration.as_millis() as u64, "Container exited with error");
        (
            OutputStatus::Error,
            Some(format!(
                "Container exited with code {code_text}{hint}: {}",
                last_chars(stderr_text.trim_end(), ERROR_TAIL_CHARS)
            )),
            RunOutcome::Exited,
        )
    };

    let result = RunResult {
        status,
        error,
        new_session_id: st.new_session_id.clone(),
        usage: st.usage,
        last_result: st.last_result.clone(),
        outputs: st.outputs,
        exit_code: code,
        outcome,
        duration,
        container_name: ctx.name.clone(),
    };

    if let Some((dir, keep)) = &ctx.run_log {
        let log = render_run_log(&ctx, &st, &result, &stdout_summary, &stderr_summary);
        match write_run_log(dir, &log, *keep) {
            Ok(path) => tracing::debug!(log_file = %path.display(), "Container log written"),
            Err(err) => {
                tracing::warn!(dir = %dir.display(), %err, "failed to write container run log")
            }
        }
    }

    ctx.audit.record(event(
        "container.exit",
        &ctx.group_folder,
        Some(&ctx.name),
        if result.is_success() { "info" } else { "error" },
        serde_json::json!({
            "outcome": result.outcome,
            "exitCode": result.exit_code,
            "signal": exit_info.and_then(|i| i.signal),
            "durationMs": duration.as_millis() as u64,
            "timedOut": st.timed_out,
            "runTimeCapReached": st.run_cap_reached,
            "stopRequested": st.stop_requested,
            "outputs": st.outputs,
            "malformedFrames": st.malformed,
            "oversizeFrames": st.oversize,
            "resultBytes": st.result_bytes,
            "limitExceeded": st.limit.map(OutputLimit::as_str),
            "discardedFrames": st.discarded,
            "stdoutBytes": stdout_summary.tail.total,
            "stderrBytes": stderr_summary.tail.total,
            "error": result.error.as_deref().map(|e| ctx.redactor.redact_text(e).into_owned()),
        }),
    ));

    exited_tx.send_replace(true);
    result
}

fn render_run_log(
    ctx: &RunContext,
    st: &LoopState,
    result: &RunResult,
    stdout: &StreamSummary,
    stderr: &StreamSummary,
) -> String {
    let is_error = !result.is_success();
    let mut lines: Vec<String> = vec![
        format!(
            "=== Container Run Log{} ===",
            if st.timed_out { " (TIMEOUT)" } else { "" }
        ),
        format!("Timestamp: {}", talon_core::time::now_iso()),
        format!("Group: {}", ctx.group_name),
        format!("Container: {}", ctx.name),
        format!("IsMain: {}", ctx.is_main),
        format!("Duration: {}ms", result.duration.as_millis()),
        format!(
            "Exit Code: {}",
            result
                .exit_code
                .map_or_else(|| "none".to_string(), |c| c.to_string())
        ),
        format!("Outcome: {:?}", result.outcome),
        format!("Had Streaming Output: {}", st.had_output),
        format!(
            "Frames: {} (malformed {}, oversize {}, discarded {})",
            st.outputs, st.malformed, st.oversize, st.discarded
        ),
        format!(
            "Result Bytes: {}{}",
            st.result_bytes,
            st.limit
                .map(|l| format!(" (limit exceeded: {})", l.as_str()))
                .unwrap_or_default()
        ),
        format!("Stdout Truncated: {}", stdout.tail.truncated()),
        format!("Stderr Truncated: {}", stderr.tail.truncated()),
        String::new(),
        "=== Input Summary ===".to_string(),
        format!("Prompt length: {} chars", ctx.prompt_len),
        format!(
            "Session: {}",
            if ctx.resumed_session {
                "resumed"
            } else {
                "new"
            }
        ),
        String::new(),
        "=== Mounts ===".to_string(),
    ];
    for m in &ctx.mounts {
        lines.push(if is_error {
            m.describe()
        } else {
            format!(
                "{}{}",
                m.container_path,
                if m.readonly { " (ro)" } else { "" }
            )
        });
    }
    lines.push(String::new());
    if is_error {
        if let Some(e) = &result.error {
            lines.push("=== Error ===".to_string());
            lines.push(ctx.redactor.redact_text(e).into_owned());
            lines.push(String::new());
        }
        lines.push("=== Container Args ===".to_string());
        lines.push(ctx.args_redacted.clone());
        lines.push(String::new());
        lines.push(format!(
            "=== Stderr{} ===",
            if stderr.tail.truncated() {
                " (TAIL)"
            } else {
                ""
            }
        ));
        // Already redacted line by line.
        lines.push(stderr.tail.text());
        lines.push(format!(
            "=== Stdout{} ===",
            if stdout.tail.truncated() {
                " (TAIL)"
            } else {
                ""
            }
        ));
        lines.push(ctx.redactor.redact_text(&stdout.tail.text()).into_owned());
    }
    lines.join("\n")
}

/// Write `content` to a new `container-<ts>.log` in `dir` (created 0700)
/// and prune old logs beyond `keep`.
fn write_run_log(dir: &Path, content: &str, keep: usize) -> io::Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let ts = talon_core::time::now_iso().replace([':', '.'], "-");
    let mut path = dir.join(format!("container-{ts}.log"));
    let mut attempt = 0u32;
    let mut file = loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => break f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 100 => {
                attempt += 1;
                path = dir.join(format!("container-{ts}-{attempt}.log"));
            }
            Err(e) => return Err(e),
        }
    };
    file.write_all(content.as_bytes())?;
    prune_run_logs(dir, keep);
    Ok(path)
}

fn prune_run_logs(dir: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut logs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("container-") && n.ends_with(".log"))
        })
        .collect();
    if logs.len() <= keep {
        return;
    }
    logs.sort();
    let excess = logs.len() - keep;
    for old in logs.into_iter().take(excess) {
        let _ = std::fs::remove_file(old);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use talon_core::audit::MemoryAuditSink;
    use talon_core::protocol::OUTPUT_START_MARKER;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::policy::DenyAllMounts;
    use crate::policy::testing::RecordingRedactor;
    use crate::process::testing::{BashSpawner, FailingSpawner, FakeSpawner};
    use crate::runtime::testing::FakeExecutor;
    use crate::runtime::{CommandOutput, HostPlatform};

    struct Harness {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        exec: Arc<FakeExecutor>,
        audit: MemoryAuditSink,
        redactor: Arc<RecordingRedactor>,
    }

    fn harness() -> Harness {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        Harness {
            _tmp: tmp,
            root,
            exec: Arc::new(FakeExecutor::default()),
            audit: MemoryAuditSink::default(),
            redactor: Arc::new(RecordingRedactor::default()),
        }
    }

    impl Harness {
        fn config(&self) -> RunnerConfig {
            let mut cfg = RunnerConfig::new("talon-agent:latest", MountLayout::new(&self.root));
            cfg.timezone = "America/Los_Angeles".into();
            cfg.run_as = Some(RunAs {
                uid: 1000,
                gid: 1000,
            });
            cfg.chown_dirs = Some(false);
            cfg
        }

        fn runner(&self, cfg: RunnerConfig, spawner: Arc<dyn ProcessSpawner>) -> ContainerRunner {
            let runtime = ContainerRuntime::new("docker")
                .unwrap()
                .with_executor(self.exec.clone())
                .with_platform(HostPlatform::Linux);
            ContainerRunner::new(
                cfg,
                Arc::new(runtime),
                Arc::new(DenyAllMounts),
                self.redactor.clone(),
                Arc::new(self.audit.clone()),
            )
            .with_spawner(spawner)
        }

        fn kinds(&self) -> Vec<String> {
            self.audit.snapshot().into_iter().map(|e| e.kind).collect()
        }
    }

    fn test_group() -> RegisteredGroup {
        RegisteredGroup {
            name: "Test Group".into(),
            folder: "test-group".into(),
            trigger: "@Andy".into(),
            added_at: "2026-01-01T00:00:00.000Z".into(),
            container_config: None,
            requires_trigger: None,
            is_main: false,
            session_key: None,
            ipc_key: None,
            ephemeral_session: false,
            trusted_session_commands: false,
        }
    }

    fn test_input() -> ContainerInput {
        ContainerInput {
            prompt: "Hello".into(),
            session_id: None,
            group_folder: "test-group".into(),
            chat_jid: "test@g.us".into(),
            is_main: false,
            is_scheduled_task: false,
            assistant_name: None,
            script: None,
            llm: None,
            ephemeral: false,
            timezone: None,
        }
    }

    type Seen = Arc<Mutex<Vec<ContainerOutput>>>;

    fn recording_handler() -> (Seen, impl OutputHandler) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let handler = move |o: ContainerOutput| {
            let s = s.clone();
            async move {
                s.lock().unwrap().push(o);
            }
        };
        (seen, handler)
    }

    fn framed(result: &str, session: &str) -> Vec<u8> {
        ContainerOutput::success(Some(result.into()), Some(session.into()))
            .to_framed()
            .into_bytes()
    }

    // --- ports of container-runner.test.ts (timeout behaviour) ---

    #[tokio::test(start_paused = true)]
    async fn timeout_after_output_resolves_as_success() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner.clone());
        let (seen, handler) = recording_handler();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();

        proc.stdout
            .write_all(&framed("Here is my response", "session-123"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Hard timeout = IDLE_TIMEOUT + 30 s = 1830 s.
        tokio::time::sleep(Duration::from_millis(1_830_000)).await;
        assert_eq!(h.exec.subcommands(), vec!["stop".to_string()]);
        proc.exit(137);
        drop(proc.stdout);

        let result = started.wait().await;
        assert_eq!(result.status, OutputStatus::Success);
        assert_eq!(result.new_session_id.as_deref(), Some("session-123"));
        assert_eq!(result.outcome, RunOutcome::TimedOut);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].result.as_deref(), Some("Here is my response"));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_with_no_output_resolves_as_error() {
        let h = harness();
        let (spawner, proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner);
        let (seen, handler) = recording_handler();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1_830_010)).await;
        assert_eq!(h.exec.subcommands(), vec!["stop".to_string()]);
        proc.exit(137);
        drop(proc);
        let result = started.wait().await;
        assert_eq!(result.status, OutputStatus::Error);
        assert!(result.error.as_deref().unwrap().contains("timed out"));
        assert_eq!(
            result.error.as_deref(),
            Some("Container timed out after 1800000ms")
        );
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn normal_exit_after_output_resolves_as_success() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner);
        let (seen, handler) = recording_handler();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        proc.stdout
            .write_all(&framed("Done", "session-456"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        proc.exit(0);
        drop(proc.stdout);
        let result = started.wait().await;
        assert_eq!(result.status, OutputStatus::Success);
        assert_eq!(result.new_session_id.as_deref(), Some("session-456"));
        assert_eq!(result.outcome, RunOutcome::Exited);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(h.exec.calls().is_empty(), "no stop on a clean exit");
    }

    // --- N-5: session ids from container frames ---

    #[test]
    fn session_id_validation() {
        assert!(is_valid_session_id("3f2504e0-4f89-41d3-9a0c-0305e82c3301"));
        assert!(is_valid_session_id("session-123"));
        assert!(is_valid_session_id("s_1"));
        assert!(is_valid_session_id(&"a".repeat(MAX_SESSION_ID_BYTES)));
        assert!(!is_valid_session_id(&"a".repeat(MAX_SESSION_ID_BYTES + 1)));
        for bad in [
            "",
            "a b",
            "../etc",
            "a/b",
            "a.b",
            "a:b",
            "id\nforged log line",
            "id\u{1b}[31m",
            "s\u{e9}ssion",
            "\u{0}",
        ] {
            assert!(!is_valid_session_id(bad), "{bad:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_session_ids_are_dropped() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner);
        let (seen, handler) = recording_handler();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        let huge = "x".repeat(64 * 1024);
        for (result, session) in [
            ("one", "valid-1"),
            ("two", huge.as_str()),
            ("three", "bad id\nforged log line"),
            ("four", ""),
        ] {
            proc.stdout
                .write_all(&framed(result, session))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        proc.exit(0);
        drop(proc.stdout);
        let result = started.wait().await;
        assert_eq!(result.status, OutputStatus::Success);
        assert_eq!(result.outputs, 4);
        // The last *valid* id wins; invalid ones never replace or extend it.
        assert_eq!(result.new_session_id.as_deref(), Some("valid-1"));
        assert_eq!(
            result.to_container_output().new_session_id.as_deref(),
            Some("valid-1")
        );
        let seen = seen.lock().unwrap();
        let delivered: Vec<(Option<&str>, Option<&str>)> = seen
            .iter()
            .map(|o| (o.result.as_deref(), o.new_session_id.as_deref()))
            .collect();
        assert_eq!(
            delivered,
            vec![
                (Some("one"), Some("valid-1")),
                // Invalid ids are removed from the delivered frame as well.
                (Some("two"), None),
                (Some("three"), None),
                // An empty id is "no id", passed through unchanged.
                (Some("four"), Some("")),
            ]
        );
    }

    // --- additional behaviour ---

    #[tokio::test(start_paused = true)]
    async fn frames_reset_the_hard_timeout() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let mut cfg = h.config();
        cfg.idle_timeout = Duration::from_secs(60);
        cfg.idle_grace = Duration::from_secs(0);
        cfg.container_timeout = Duration::from_secs(60);
        // Keep the absolute cap (here 600 s) out of the way.
        cfg.max_run_time_factor = 10;
        let runner = h.runner(cfg, spawner);
        let (seen, handler) = recording_handler();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        // 5 frames, 50 s apart: 250 s total, never 60 s of silence.
        for i in 0..5 {
            tokio::time::sleep(Duration::from_secs(50)).await;
            proc.stdout
                .write_all(&framed(&format!("r{i}"), "s"))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(h.exec.calls().is_empty(), "timeout must not have fired");
        proc.exit(0);
        drop(proc.stdout);
        let result = started.wait().await;
        assert!(result.is_success());
        assert_eq!(result.outputs, 5);
        assert_eq!(result.last_result.as_deref(), Some("r4"));
        let order: Vec<_> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|o| o.result.clone().unwrap())
            .collect();
        assert_eq!(order, vec!["r0", "r1", "r2", "r3", "r4"]);
    }

    // --- MYTH-07: bounded output path ---

    #[tokio::test(start_paused = true)]
    async fn frames_extend_timeout_only_up_to_absolute_cap() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let exit = proc.exit_sender();
        h.exec.set_hook(move |_, args| {
            if args.first().map(String::as_str) == Some("stop") {
                let _ = exit.send(Some(ExitInfo::code(143)));
            }
        });
        let mut cfg = h.config();
        cfg.idle_timeout = Duration::from_secs(60);
        cfg.idle_grace = Duration::ZERO;
        cfg.container_timeout = Duration::from_secs(60);
        assert_eq!(cfg.max_run_time_factor, DEFAULT_MAX_RUN_TIME_FACTOR);
        assert_eq!(
            cfg.max_run_time(&ContainerConfig::default()),
            Duration::from_secs(240)
        );
        let runner = h.runner(cfg, spawner);
        let (seen, handler) = recording_handler();
        let t0 = Instant::now();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        // A frame every 50 s would keep a resetting timeout alive forever.
        for i in 0..4 {
            tokio::time::sleep(Duration::from_secs(50)).await;
            proc.stdout
                .write_all(&framed(&format!("r{i}"), "s"))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_secs(30)).await; // t = 230 s
        assert!(h.exec.calls().is_empty(), "no stop before the cap");
        tokio::time::sleep(Duration::from_secs(15)).await; // t = 245 s
        assert_eq!(h.exec.subcommands(), vec!["stop"]);
        drop(proc.stdout);
        let result = started.wait().await;
        assert!(t0.elapsed() < Duration::from_secs(260));
        // Like any timeout after output: success, 4 frames delivered.
        assert_eq!(result.outcome, RunOutcome::TimedOut);
        assert!(result.is_success());
        assert_eq!(seen.lock().unwrap().len(), 4);
        let exit_ev = h
            .audit
            .snapshot()
            .into_iter()
            .find(|e| e.kind == "container.exit")
            .unwrap();
        assert_eq!(exit_ev.details["runTimeCapReached"], true);
        let launch = h
            .audit
            .snapshot()
            .into_iter()
            .find(|e| e.kind == "container.launch")
            .unwrap();
        assert_eq!(launch.details["maxRunTimeMs"], 240_000);
    }

    #[tokio::test(start_paused = true)]
    async fn frame_count_limit_stops_container_with_error() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let exit = proc.exit_sender();
        h.exec.set_hook(move |_, args| {
            if args.first().map(String::as_str) == Some("stop") {
                let _ = exit.send(Some(ExitInfo::code(143)));
            }
        });
        let mut cfg = h.config();
        cfg.max_frames_per_run = 3;
        let runner = h.runner(cfg, spawner);
        let (seen, handler) = recording_handler();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        for i in 0..6 {
            proc.stdout
                .write_all(&framed(&format!("r{i}"), "s"))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(h.exec.subcommands(), vec!["stop"]);
        drop(proc.stdout);
        let result = started.wait().await;
        assert_eq!(result.status, OutputStatus::Error);
        assert_eq!(result.outcome, RunOutcome::OutputLimitExceeded);
        assert_eq!(
            result.error.as_deref(),
            Some("Container output limit exceeded: more than 3 frames")
        );
        assert_eq!(result.outputs, 3);
        let delivered: Vec<_> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|o| o.result.clone().unwrap())
            .collect();
        assert_eq!(delivered, vec!["r0", "r1", "r2"]);
        let exit_ev = h
            .audit
            .snapshot()
            .into_iter()
            .find(|e| e.kind == "container.exit")
            .unwrap();
        assert_eq!(exit_ev.outcome, "error");
        assert_eq!(exit_ev.details["limitExceeded"], "frames");
        assert_eq!(exit_ev.details["discardedFrames"], 3);
    }

    #[tokio::test(start_paused = true)]
    async fn result_byte_budget_stops_container_with_error() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let runner = {
            let mut cfg = h.config();
            cfg.max_result_bytes_per_run = 100;
            h.runner(cfg, spawner.clone())
        };
        let (seen, handler) = recording_handler();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        // 60 + 60 > 100: the second frame breaks the budget.
        proc.stdout
            .write_all(&framed(&"a".repeat(60), "s"))
            .await
            .unwrap();
        proc.stdout
            .write_all(&framed(&"b".repeat(60), "s"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        // The container ignores the stop: escalation still ends the run.
        drop(proc);
        let result = started.wait().await;
        assert_eq!(result.outcome, RunOutcome::OutputLimitExceeded);
        assert_eq!(
            result.error.as_deref(),
            Some("Container output limit exceeded: more than 100 bytes of results")
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(h.exec.subcommands(), vec!["stop", "kill"]);
        assert_eq!(spawner.kill_count(), 1);
        let exit_ev = h
            .audit
            .snapshot()
            .into_iter()
            .find(|e| e.kind == "container.exit")
            .unwrap();
        assert_eq!(exit_ev.details["limitExceeded"], "resultBytes");
        assert_eq!(exit_ev.details["resultBytes"], 60);
        assert_eq!(payload_bytes(&ContainerOutput::error("xyz")), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_handler_applies_backpressure_to_stdout() {
        let h = harness();
        let (spawner, proc) = FakeSpawner::new();
        let mut cfg = h.config();
        cfg.frame_queue_capacity = 2;
        let runner = h.runner(cfg, spawner);
        // The handler takes one permit per frame; none are available yet.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (g, s) = (gate.clone(), seen.clone());
        let handler = move |o: ContainerOutput| {
            let (g, s) = (g.clone(), s.clone());
            async move {
                g.acquire().await.unwrap().forget();
                s.lock().unwrap().push(o.result.unwrap_or_default());
            }
        };
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        // 100 frames of ~8 KiB (800 KiB) through a 64 KiB pipe.
        let exit = proc.exit_sender();
        let mut stdout = proc.stdout;
        let writer = tokio::spawn(async move {
            for i in 0..100 {
                let body = format!("{i:03}-{}", "x".repeat(8 * 1024));
                stdout.write_all(&framed(&body, "s")).await.unwrap();
            }
            stdout
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            !writer.is_finished(),
            "the host must stop reading stdout while the handler is stuck"
        );
        assert!(seen.lock().unwrap().is_empty());
        // Release the handler: everything flows, in order.
        gate.add_permits(1000);
        let stdout = writer.await.unwrap();
        drop(stdout);
        let _ = exit.send(Some(ExitInfo::code(0)));
        let result = started.wait().await;
        assert!(result.is_success(), "{:?}", result.error);
        assert_eq!(result.outputs, 100);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 100);
        assert!(
            seen.iter()
                .enumerate()
                .all(|(i, r)| r.starts_with(&format!("{i:03}-")))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backlog_after_exit_is_delivered_while_it_drains() {
        // The container wrote its last frames and exited; a slow handler
        // must still get all of them (no abandon while making progress).
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let mut cfg = h.config();
        cfg.frame_queue_capacity = 1;
        cfg.exit_drain = Duration::from_secs(5);
        let runner = h.runner(cfg, spawner);
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let handler = move |o: ContainerOutput| {
            let s = s.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                s.lock().unwrap().push(o.result.unwrap_or_default());
            }
        };
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        for i in 0..6 {
            proc.stdout
                .write_all(&framed(&format!("r{i}"), "s"))
                .await
                .unwrap();
        }
        proc.exit(0);
        drop(proc.stdout);
        let result = started.wait().await;
        assert!(result.is_success());
        assert_eq!(result.outputs, 6);
        assert_eq!(seen.lock().unwrap().len(), 6);
    }

    #[tokio::test(start_paused = true)]
    async fn per_group_timeout_is_reported() {
        let h = harness();
        let (spawner, proc) = FakeSpawner::new();
        let mut cfg = h.config();
        cfg.idle_timeout = Duration::from_secs(1);
        cfg.idle_grace = Duration::from_secs(1);
        let runner = h.runner(cfg, spawner);
        let spec = RunSpec::new(test_group(), test_input()).with_config(ContainerConfig {
            timeout: Some(10_000),
            ..Default::default()
        });
        let started = runner.start(spec, noop_handler()).await.unwrap();
        // Stop is accepted by the runtime and the container then exits.
        let exit = proc.exit_sender();
        h.exec.set_hook(move |_, args| {
            if args.first().map(String::as_str) == Some("stop") {
                let _ = exit.send(Some(ExitInfo::code(143)));
            }
        });
        drop(proc);
        let result = started.wait().await;
        assert_eq!(
            result.error.as_deref(),
            Some("Container timed out after 10000ms")
        );
        assert_eq!(result.exit_code, Some(143));
    }

    #[tokio::test(start_paused = true)]
    async fn nonzero_exit_reports_redacted_stderr_tail() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner);
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), noop_handler())
            .await
            .unwrap();
        proc.stderr
            .write_all(b"booting\nfatal: password=hunter2 rejected\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        proc.exit(1);
        drop(proc);
        let result = started.wait().await;
        assert_eq!(result.status, OutputStatus::Error);
        let err = result.error.unwrap();
        assert!(err.starts_with("Container exited with code 1: "), "{err}");
        assert!(err.contains("[REDACTED] rejected"));
        assert!(!err.contains("hunter2"));
        // Every stderr line went through the redactor.
        let seen = h.redactor.seen.lock().unwrap().clone();
        assert!(seen.iter().any(|l| l == "booting"));
    }

    #[tokio::test(start_paused = true)]
    async fn exit_137_after_output_is_success_but_without_output_is_error() {
        for (emit, expect_ok) in [(true, true), (false, false)] {
            let h = harness();
            let (spawner, mut proc) = FakeSpawner::new();
            let runner = h.runner(h.config(), spawner);
            let started = runner
                .start(RunSpec::new(test_group(), test_input()), noop_handler())
                .await
                .unwrap();
            if emit {
                proc.stdout.write_all(&framed("x", "s")).await.unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            proc.exit(137);
            drop(proc);
            let result = started.wait().await;
            assert_eq!(result.is_success(), expect_ok);
            if !expect_ok {
                assert!(result.error.unwrap().contains("code 137 (SIGKILL"));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stdin_receives_input_json_then_eof() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner);
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), noop_handler())
            .await
            .unwrap();
        let stdin = proc.read_stdin().await;
        let parsed: ContainerInput = serde_json::from_str(&stdin).unwrap();
        assert_eq!(parsed, test_input());
        proc.exit(0);
        drop(proc);
        assert!(started.wait().await.is_success());
    }

    #[tokio::test(start_paused = true)]
    async fn handle_stop_runs_graceful_stop() {
        let h = harness();
        let (spawner, proc) = FakeSpawner::new();
        let exit = proc.exit_sender();
        h.exec.set_hook(move |_, args| {
            if args.first().map(String::as_str) == Some("stop") {
                let _ = exit.send(Some(ExitInfo::code(143)));
            }
        });
        let runner = h.runner(h.config(), spawner.clone());
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), noop_handler())
            .await
            .unwrap();
        let handle = started.handle();
        assert!(handle.name().starts_with("talon-test-group-"));
        assert_eq!(handle.group_folder(), "test-group");
        assert!(handle.is_running());
        drop(proc);
        handle.stop().await;
        assert!(!handle.is_running());
        assert!(handle.is_stop_requested());
        let result = started.wait().await;
        assert_eq!(result.outcome, RunOutcome::Stopped);
        assert_eq!(
            result.error.as_deref(),
            Some("Container was stopped before producing output")
        );
        let calls = h.exec.calls();
        assert_eq!(calls[0].1, vec!["stop", "-t", "10", handle.name()]);
        assert_eq!(spawner.kill_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn stop_escalates_to_kill() {
        let h = harness();
        let (spawner, proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner.clone());
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), noop_handler())
            .await
            .unwrap();
        drop(proc);
        let handle = started.handle();
        handle.request_stop();
        let result = started.wait().await;
        assert_eq!(h.exec.subcommands(), vec!["stop", "kill"]);
        assert_eq!(spawner.kill_count(), 1);
        assert_eq!(result.exit_code, Some(137));
        assert_eq!(result.outcome, RunOutcome::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_stop_command_kills_immediately() {
        let h = harness();
        h.exec.push(Ok(CommandOutput::failed(1, "daemon error")));
        let (spawner, proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner.clone());
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), noop_handler())
            .await
            .unwrap();
        drop(proc);
        let t0 = Instant::now();
        started.handle().request_stop();
        let result = started.wait().await;
        assert!(t0.elapsed() < DEFAULT_STOP_GRACE);
        assert_eq!(spawner.kill_count(), 1);
        assert!(!result.is_success());
    }

    #[tokio::test(start_paused = true)]
    async fn unkillable_process_is_abandoned() {
        let h = harness();
        let (spawner, proc) = FakeSpawner::with_options(true);
        let runner = h.runner(h.config(), spawner);
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), noop_handler())
            .await
            .unwrap();
        drop(proc);
        started.handle().request_stop();
        let result = started.wait().await;
        assert_eq!(result.exit_code, None);
        assert!(!result.is_success());
    }

    #[tokio::test(start_paused = true)]
    async fn slow_handler_does_not_block_timeouts_and_is_awaited() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let mut cfg = h.config();
        cfg.idle_timeout = Duration::from_secs(10);
        cfg.idle_grace = Duration::ZERO;
        cfg.container_timeout = Duration::from_secs(10);
        let runner = h.runner(cfg, spawner);
        let done = Arc::new(Mutex::new(0));
        let d = done.clone();
        let handler = move |_o: ContainerOutput| {
            let d = d.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                *d.lock().unwrap() += 1;
            }
        };
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        proc.stdout.write_all(&framed("a", "s")).await.unwrap();
        // Timeout fires at ~10 s although the handler is still busy.
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(h.exec.subcommands(), vec!["stop"]);
        proc.exit(143);
        drop(proc.stdout);
        let result = started.wait().await;
        assert!(result.is_success());
        assert_eq!(*done.lock().unwrap(), 1, "run waits for the handler");
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_and_oversize_frames_are_counted_not_fatal() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let mut cfg = h.config();
        cfg.max_output_bytes = 1024;
        let runner = h.runner(cfg, spawner);
        let (seen, handler) = recording_handler();
        let started = runner
            .start(RunSpec::new(test_group(), test_input()), handler)
            .await
            .unwrap();
        let big = ContainerOutput::success(Some("x".repeat(5000)), None).to_framed();
        let bad = format!("{OUTPUT_START_MARKER}\nnot json\n---TALON_OUTPUT_END---\n");
        proc.stdout.write_all(big.as_bytes()).await.unwrap();
        proc.stdout.write_all(bad.as_bytes()).await.unwrap();
        proc.stdout.write_all(&framed("good", "s")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        proc.exit(0);
        drop(proc);
        let result = started.wait().await;
        assert!(result.is_success());
        assert_eq!(result.outputs, 1);
        assert_eq!(seen.lock().unwrap()[0].result.as_deref(), Some("good"));
        let exit = h
            .audit
            .snapshot()
            .into_iter()
            .find(|e| e.kind == "container.exit")
            .unwrap();
        assert_eq!(exit.details["malformedFrames"], 1);
        assert_eq!(exit.details["oversizeFrames"], 1);
    }

    #[tokio::test(start_paused = true)]
    async fn audit_events_and_run_log() {
        let h = harness();
        let (spawner, mut proc) = FakeSpawner::new();
        let runner = h.runner(h.config(), spawner.clone());
        let mut spec = RunSpec::new(test_group(), test_input());
        spec.config.env.insert("API_TOKEN".into(), "x".into());
        spec.config.env.insert("LOG_LEVEL".into(), "debug".into());
        let started = runner.start(spec, noop_handler()).await.unwrap();
        proc.stdout.write_all(&framed("ok", "s")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        proc.exit(0);
        drop(proc);
        let result = started.wait().await;
        assert!(result.is_success());

        assert_eq!(
            h.kinds(),
            vec![AUDIT_CONFIG_REJECTED, "container.launch", "container.exit"]
        );
        let events = h.audit.snapshot();
        assert_eq!(events[0].target.as_deref(), Some("API_TOKEN"));
        let launch = &events[1];
        assert_eq!(launch.outcome, "allowed");
        assert_eq!(
            launch.target.as_deref(),
            Some(result.container_name.as_str())
        );
        assert_eq!(launch.details["envKeys"], serde_json::json!(["LOG_LEVEL"]));
        assert_eq!(events[2].outcome, "info");

        // The spawned command is `docker run ... talon-agent:latest`.
        let seen = spawner.seen.lock().unwrap().clone();
        assert_eq!(seen[0].program, "docker");
        assert_eq!(seen[0].args[0], "run");
        assert_eq!(seen[0].args.last().unwrap(), "talon-agent:latest");
        assert!(seen[0].args.contains(&"--read-only".to_string()));
        assert!(!seen[0].args.iter().any(|a| a.contains("API_TOKEN")));

        let log_dir = h.root.join("data/logs/containers/test-group");
        let logs: Vec<_> = std::fs::read_dir(&log_dir).unwrap().collect();
        assert_eq!(logs.len(), 1);
        let text = std::fs::read_to_string(logs[0].as_ref().unwrap().path()).unwrap();
        assert!(text.contains("Prompt length: 5 chars"));
        assert!(!text.contains("Hello"), "the prompt is never logged");
    }

    #[tokio::test]
    async fn spawn_failure_is_reported() {
        let h = harness();
        let runner = h.runner(h.config(), Arc::new(FailingSpawner));
        let mut handle_seen = false;
        let result = runner
            .run(
                RunSpec::new(test_group(), test_input()),
                noop_handler(),
                |_| handle_seen = true,
            )
            .await;
        assert!(!handle_seen);
        assert_eq!(result.outcome, RunOutcome::SpawnFailed);
        assert!(
            result
                .error
                .unwrap()
                .starts_with("Container spawn error: docker: not found")
        );
        let events = h.audit.snapshot();
        assert_eq!(events.last().unwrap().kind, "container.launch");
        assert_eq!(events.last().unwrap().outcome, "error");
    }

    #[tokio::test]
    async fn setup_failure_is_reported() {
        let h = harness();
        let mut cfg = h.config();
        cfg.image = "--privileged".into();
        let runner = h.runner(cfg, Arc::new(FailingSpawner));
        let result = runner
            .run(
                RunSpec::new(test_group(), test_input()),
                noop_handler(),
                |_| {},
            )
            .await;
        assert_eq!(result.outcome, RunOutcome::SetupFailed);
        assert!(result.error.unwrap().starts_with("Container setup error"));
        let out = RunResult::failed_to_start(&StartError::Spawn(io::Error::other("x")), "n".into())
            .to_container_output();
        assert_eq!(out.status, OutputStatus::Error);
        assert!(out.result.is_none());
    }

    #[tokio::test]
    async fn bash_process_end_to_end() {
        let h = harness();
        let script = r#"
            input=$(cat)
            echo "[agent] starting" >&2
            echo "noise before frames"
            printf -- '---TALON_OUTPUT_START---\n{"status":"success","result":"first","newSessionId":"s-1"}\n---TALON_OUTPUT_END---\n'
            echo "interleaved log line"
            len=${#input}
            printf -- '---TALON_OUTPUT_START---\n{"status":"success","result":"len=%s"}\n---TALON_OUTPUT_END---\n' "$len"
            echo "token=hunter2 done" >&2
            exit 0
        "#;
        let spawner = Arc::new(BashSpawner::new(script));
        let runner = h.runner(h.config(), spawner.clone());
        let (seen, handler) = recording_handler();
        let mut handle_name = String::new();
        let input = test_input();
        let expected_len = serde_json::to_string(&input).unwrap().len();
        let result = runner
            .run(RunSpec::new(test_group(), input), handler, |h| {
                handle_name = h.name().to_string()
            })
            .await;
        assert!(result.is_success(), "{:?}", result.error);
        assert_eq!(result.new_session_id.as_deref(), Some("s-1"));
        assert_eq!(handle_name, result.container_name);
        let results: Vec<_> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|o| o.result.clone().unwrap())
            .collect();
        assert_eq!(
            results,
            vec!["first".to_string(), format!("len={expected_len}")]
        );
        assert!(
            h.redactor
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("hunter2"))
        );
        let cmd = &spawner.seen.lock().unwrap()[0];
        assert!(cmd.args.contains(&"--cap-drop=ALL".to_string()));
    }

    #[tokio::test]
    async fn bash_process_failure_exit_code() {
        let h = harness();
        let spawner = Arc::new(BashSpawner::new("cat >/dev/null; echo 'boom' >&2; exit 3"));
        let runner = h.runner(h.config(), spawner);
        let result = runner
            .run(
                RunSpec::new(test_group(), test_input()),
                noop_handler(),
                |_| {},
            )
            .await;
        assert_eq!(result.exit_code, Some(3));
        assert_eq!(
            result.error.as_deref(),
            Some("Container exited with code 3: boom")
        );
    }

    #[test]
    fn network_setting_and_runner_defaults() {
        assert_eq!(network_setting(None).as_deref(), Some(AGENT_NETWORK));
        assert_eq!(network_setting(Some("")), None);
        assert_eq!(network_setting(Some("  ")), None);
        assert_eq!(network_setting(Some("default")), None);
        assert_eq!(network_setting(Some("DEFAULT")), None);
        assert_eq!(network_setting(Some(" lab ")).as_deref(), Some("lab"));

        let h = harness();
        let cfg = RunnerConfig::new("img", MountLayout::new(&h.root));
        assert_eq!(cfg.default_network.as_deref(), Some("talon-agents"));
        assert_eq!(cfg.frame_queue_capacity, DEFAULT_FRAME_QUEUE_CAPACITY);
        assert_eq!(cfg.max_frames_per_run, 1000);
        assert_eq!(cfg.max_result_bytes_per_run, 8 * 1024 * 1024);
        assert_eq!(cfg.max_run_time_factor, 4);

        // From the host configuration (.env values; the process env is
        // only consulted when it sets the key, which tests never do).
        if std::env::var_os(CONTAINER_NETWORK_ENV).is_none() {
            let load = |content: &str| {
                let env = talon_core::env::EnvFile::from_str_content(content);
                RunnerConfig::from_talon_config(&TalonConfig::from_env(&h.root, env))
            };
            assert_eq!(load("").default_network.as_deref(), Some("talon-agents"));
            assert_eq!(
                load("TALON_CONTAINER_NETWORK=default").default_network,
                None
            );
            assert_eq!(
                load("TALON_CONTAINER_NETWORK=soc-net")
                    .default_network
                    .as_deref(),
                Some("soc-net")
            );
            let cfg = load("");
            assert!(
                cfg.mount_options
                    .protected_paths
                    .contains(&h.root.join("store"))
            );
            assert!(
                cfg.mount_options
                    .protected_paths
                    .iter()
                    .any(|p| p.ends_with("mount-allowlist.json"))
            );
        }
    }

    #[test]
    fn prepare_uses_default_network_and_group_override() {
        let h = harness();
        let runner = h.runner(h.config(), Arc::new(FailingSpawner));
        let prepared = runner
            .prepare(&RunSpec::new(test_group(), test_input()))
            .unwrap();
        assert_eq!(prepared.network.as_deref(), Some("talon-agents"));
        let i = prepared.args.iter().position(|a| a == "--network").unwrap();
        assert_eq!(prepared.args[i + 1], "talon-agents");
        // host.docker.internal stays mapped on the custom network.
        assert!(
            prepared
                .args
                .contains(&"host.docker.internal:host-gateway".to_string())
        );

        let spec = RunSpec::new(test_group(), test_input()).with_config(ContainerConfig {
            network: Some("lab-net".into()),
            ..Default::default()
        });
        assert_eq!(
            runner.prepare(&spec).unwrap().network.as_deref(),
            Some("lab-net")
        );

        let mut cfg = h.config();
        cfg.default_network = None;
        let runner = h.runner(cfg, Arc::new(FailingSpawner));
        let prepared = runner
            .prepare(&RunSpec::new(test_group(), test_input()))
            .unwrap();
        assert!(!prepared.args.contains(&"--network".to_string()));

        let mut cfg = h.config();
        cfg.default_network = Some("host".into());
        let runner = h.runner(cfg, Arc::new(FailingSpawner));
        assert!(
            runner
                .prepare(&RunSpec::new(test_group(), test_input()))
                .is_err()
        );
    }

    #[test]
    fn timeouts_follow_ts_rules() {
        let h = harness();
        let cfg = h.config();
        let none = ContainerConfig::default();
        assert_eq!(cfg.config_timeout(&none), Duration::from_secs(1800));
        assert_eq!(cfg.hard_timeout(&none), Duration::from_secs(1830));
        let zero = ContainerConfig {
            timeout: Some(0),
            ..Default::default()
        };
        assert_eq!(cfg.config_timeout(&zero), Duration::from_secs(1800));
        let long = ContainerConfig {
            timeout: Some(3_600_000),
            ..Default::default()
        };
        assert_eq!(cfg.hard_timeout(&long), Duration::from_secs(3600));
        let huge = ContainerConfig {
            timeout: Some(u64::MAX),
            ..Default::default()
        };
        assert_eq!(cfg.hard_timeout(&huge), MAX_TIMEOUT);
    }

    #[test]
    fn prepare_builds_expected_run() {
        let h = harness();
        let runner = h.runner(h.config(), Arc::new(FailingSpawner));
        let prepared = runner
            .prepare(&RunSpec::new(test_group(), test_input()))
            .unwrap();
        assert!(prepared.name.starts_with("talon-test-group-"));
        assert!(
            prepared
                .args
                .contains(&"TZ=America/Los_Angeles".to_string())
        );
        assert!(prepared.args.contains(&"RUN_UID=1000".to_string()));
        assert!(
            prepared
                .args
                .contains(&"host.docker.internal:host-gateway".to_string())
        );
        assert!(
            prepared
                .mounts
                .iter()
                .any(|m| m.container_path == "/workspace/ipc")
        );
        assert!(h.audit.snapshot().is_empty(), "prepare does not audit");
        let dbg = format!("{:?}", RunSpec::new(test_group(), test_input()));
        assert!(!dbg.contains("Hello"));
    }

    #[test]
    fn run_logs_are_pruned() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..5 {
            write_run_log(tmp.path(), &format!("log {i}"), 3).unwrap();
        }
        let count = std::fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 3);
    }

    #[test]
    fn tail_buffer_keeps_the_end() {
        let mut t = TailBuffer::default();
        for _ in 0..10 {
            t.push(&[b'a'; TAIL_BYTES / 2]);
        }
        t.push(b"END");
        assert!(t.truncated());
        assert!(t.text().ends_with("END"));
        assert!(t.text().len() <= TAIL_BYTES);
        assert_eq!(last_chars("héllo", 3), "llo");
        assert_eq!(last_chars("ab", 5), "ab");
    }
}
