//! Seams between the orchestrator and the outside world: launching agent
//! containers ([`ContainerLauncher`]) and handing out model credentials
//! ([`LlmAccess`]). Production wires `talon-container`'s
//! [`ContainerRunner`] and `talon-llm`'s [`GatewayHandle`]; tests use fakes.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use talon_container::{ContainerHandle, ContainerRunner, RunResult, RunSpec};
use talon_core::protocol::{ContainerOutput, LlmEndpoint, OutputStatus, SessionUsage};
use talon_core::types::{ContainerConfig, VllmConfig};
use talon_llm::GatewayHandle;
use talon_scheduler::RunningContainer;
use tokio::sync::mpsc;

/// Called once with the started container (register it with the queue).
pub type StartHook = Box<dyn FnOnce(Arc<dyn RunningContainer>) + Send>;

/// Launches one agent container run.
#[async_trait]
pub trait ContainerLauncher: Send + Sync {
    /// Run `spec` to completion. Every output frame is sent, in order, to
    /// `outputs` (the sender is dropped when the run is over); `on_start`
    /// receives the container right after it was spawned. Never fails:
    /// problems are reported in the [`RunResult`].
    async fn launch(
        &self,
        spec: RunSpec,
        outputs: mpsc::UnboundedSender<ContainerOutput>,
        on_start: StartHook,
    ) -> RunResult;

    /// Longest a run with `config` may live without producing output (used
    /// to size the per-run LLM token TTL).
    fn hard_timeout(&self, config: &ContainerConfig) -> Duration;
}

/// Per-run model credentials.
pub trait LlmAccess: Send + Sync {
    /// Issue a credential for one run (`label` = group folder, used for
    /// usage accounting) and the endpoint description for
    /// `ContainerInput.llm`. Returns `(token, endpoint)`.
    fn issue(&self, label: &str, ttl: Duration, vllm: &VllmConfig) -> (String, LlmEndpoint);

    /// Revoke a credential when its run is over.
    fn revoke(&self, token: &str);
}

/// [`RunningContainer`] adapter over a `talon-container` handle.
pub struct QueueContainer(pub ContainerHandle);

impl fmt::Debug for QueueContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("QueueContainer").field(&self.0).finish()
    }
}

#[async_trait]
impl RunningContainer for QueueContainer {
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn stop(&self) -> talon_core::Result<()> {
        self.0.stop().await;
        Ok(())
    }
}

/// Production [`ContainerLauncher`] over [`ContainerRunner`].
pub struct RunnerLauncher {
    runner: ContainerRunner,
}

impl fmt::Debug for RunnerLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerLauncher")
            .field("runner", &self.runner)
            .finish()
    }
}

impl RunnerLauncher {
    /// Wrap a configured runner.
    pub fn new(runner: ContainerRunner) -> Self {
        Self { runner }
    }
}

#[async_trait]
impl ContainerLauncher for RunnerLauncher {
    async fn launch(
        &self,
        spec: RunSpec,
        outputs: mpsc::UnboundedSender<ContainerOutput>,
        on_start: StartHook,
    ) -> RunResult {
        let handler = move |output: ContainerOutput| {
            // The receiver only disappears when the orchestrator stopped
            // listening; dropping frames is then the right thing to do.
            let _ = outputs.send(output);
            async {}
        };
        self.runner
            .run(spec, handler, move |handle: ContainerHandle| {
                on_start(Arc::new(QueueContainer(handle)));
            })
            .await
    }

    fn hard_timeout(&self, config: &ContainerConfig) -> Duration {
        self.runner.config().hard_timeout(config)
    }
}

/// Production [`LlmAccess`] over the host LLM gateway.
#[derive(Debug, Clone)]
pub struct GatewayLlm {
    gateway: GatewayHandle,
    /// Host name containers use to reach the gateway
    /// (`host.docker.internal`).
    container_host: String,
}

impl GatewayLlm {
    /// Tokens from `gateway`; containers reach it as `container_host`.
    pub fn new(gateway: GatewayHandle, container_host: impl Into<String>) -> Self {
        Self {
            gateway,
            container_host: container_host.into(),
        }
    }
}

impl LlmAccess for GatewayLlm {
    fn issue(&self, label: &str, ttl: Duration, vllm: &VllmConfig) -> (String, LlmEndpoint) {
        let token = self.gateway.issue_token(label, ttl);
        let endpoint = self
            .gateway
            .endpoint(token.clone(), &self.container_host, vllm);
        (token, endpoint)
    }

    fn revoke(&self, token: &str) {
        self.gateway.revoke(token);
    }
}

/// What the orchestrator learned from one agent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOutcome {
    /// Overall status (TS `'success' | 'error'`).
    pub status: OutputStatus,
    /// Error message when `status == Error`.
    pub error: Option<String>,
    /// Last non-null result streamed by the agent.
    pub last_result: Option<String>,
    /// Session id reported by the agent.
    pub new_session_id: Option<String>,
    /// Usage reported with the last frame.
    pub usage: Option<SessionUsage>,
    /// Whether a container was actually started.
    pub launched: bool,
}

impl AgentOutcome {
    /// A run that failed before any container started.
    pub fn not_started(error: impl Into<String>) -> Self {
        Self {
            status: OutputStatus::Error,
            error: Some(error.into()),
            last_result: None,
            new_session_id: None,
            usage: None,
            launched: false,
        }
    }

    /// `status == Success`.
    pub fn is_success(&self) -> bool {
        self.status == OutputStatus::Success
    }
}
