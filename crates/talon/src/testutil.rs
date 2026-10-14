//! Fakes for orchestrator tests: a recording channel, a scripted container
//! launcher, a fake LLM gateway and a harness wiring them to an in-memory
//! database.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use talon_container::{RunOutcome, RunResult, RunSpec};
use talon_core::audit::MemoryAuditSink;
use talon_core::channel::{Channel, ChannelType};
use talon_core::config::TalonConfig;
use talon_core::env::EnvFile;
use talon_core::protocol::{ContainerOutput, LlmEndpoint, OutputStatus};
use talon_core::types::{ContainerConfig, NewMessage, RegisteredGroup, VllmConfig};
use talon_db::Db;
use talon_scheduler::{GroupQueue, QueueConfig, RunningContainer};
use talon_security::redact::Redactor;
use talon_security::senders::SenderAllowlist;
use tempfile::TempDir;
use tokio::sync::{Notify, mpsc};

use crate::agent::{ContainerLauncher, LlmAccess, StartHook};
use crate::allowlist::AllowlistSource;
use crate::orchestrator::{Orchestrator, OrchestratorDeps, Settings};

/// Default vLLM settings for the harness.
pub const VLLM_ENV: &str = "TALON_VLLM_BASE_URL=http://vllm.test:8000\nTALON_VLLM_MODEL=qwen\n";

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

/// Channel owning every JID that starts with `fake:`.
#[derive(Default)]
pub struct FakeChannel {
    pub sent: Mutex<Vec<(String, String)>>,
    pub typing: Mutex<Vec<(String, bool)>>,
    pub turns: Mutex<Vec<String>>,
    pub notify: Notify,
}

impl FakeChannel {
    pub fn sent_texts(&self) -> Vec<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, t)| t.clone())
            .collect()
    }
}

#[async_trait]
impl Channel for FakeChannel {
    fn name(&self) -> &str {
        "fake"
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Markdown
    }

    async fn connect(&self) -> talon_core::Result<()> {
        Ok(())
    }

    async fn send_message(&self, jid: &str, text: &str) -> talon_core::Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((jid.to_string(), text.to_string()));
        self.notify.notify_waiters();
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn owns_jid(&self, jid: &str) -> bool {
        jid.starts_with("fake:")
    }

    async fn disconnect(&self) -> talon_core::Result<()> {
        Ok(())
    }

    async fn set_typing(&self, jid: &str, is_typing: bool) -> talon_core::Result<()> {
        self.typing
            .lock()
            .unwrap()
            .push((jid.to_string(), is_typing));
        Ok(())
    }

    async fn on_turn_complete(&self, jid: &str) -> talon_core::Result<()> {
        self.turns.lock().unwrap().push(jid.to_string());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Container launcher
// ---------------------------------------------------------------------------

/// What one fake run does.
#[derive(Clone, Default)]
pub struct Script {
    pub outputs: Vec<ContainerOutput>,
    pub error: Option<String>,
    pub new_session_id: Option<String>,
    /// Block after `on_start` until notified.
    pub gate: Option<Arc<Notify>>,
}

impl Script {
    pub fn reply(text: &str) -> Self {
        Self {
            outputs: vec![
                ContainerOutput::success(Some(text.to_string()), None),
                ContainerOutput::success(None, None),
            ],
            ..Self::default()
        }
    }

    pub fn failing(error: &str) -> Self {
        Self {
            error: Some(error.to_string()),
            ..Self::default()
        }
    }
}

struct FakeContainer(String);

#[async_trait]
impl RunningContainer for FakeContainer {
    fn name(&self) -> &str {
        &self.0
    }

    async fn stop(&self) -> talon_core::Result<()> {
        Ok(())
    }
}

type Probe = Box<dyn Fn(&RunSpec) -> String + Send + Sync>;

/// Scripted launcher; records every spec.
pub struct FakeLauncher {
    pub scripts: Mutex<VecDeque<Script>>,
    pub calls: Mutex<Vec<RunSpec>>,
    pub started: AtomicUsize,
    pub hard_timeout: Mutex<Duration>,
    probe: Mutex<Option<Probe>>,
    pub probes: Mutex<Vec<String>>,
}

impl Default for FakeLauncher {
    fn default() -> Self {
        Self {
            scripts: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
            started: AtomicUsize::new(0),
            hard_timeout: Mutex::new(Duration::from_secs(30 * 60)),
            probe: Mutex::new(None),
            probes: Mutex::new(Vec::new()),
        }
    }
}

impl FakeLauncher {
    pub fn push(&self, script: Script) {
        self.scripts.lock().unwrap().push_back(script);
    }

    pub fn calls(&self) -> Vec<RunSpec> {
        self.calls.lock().unwrap().clone()
    }

    pub fn prompts(&self) -> Vec<String> {
        self.calls().into_iter().map(|s| s.input.prompt).collect()
    }

    /// Run `probe` at launch time and record its answer.
    pub fn set_probe(&self, probe: impl Fn(&RunSpec) -> String + Send + Sync + 'static) {
        *self.probe.lock().unwrap() = Some(Box::new(probe));
    }

    pub async fn wait_started(&self, n: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.started.load(Ordering::SeqCst) < n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("container did not start");
    }
}

#[async_trait]
impl ContainerLauncher for FakeLauncher {
    async fn launch(
        &self,
        spec: RunSpec,
        outputs: mpsc::UnboundedSender<ContainerOutput>,
        on_start: StartHook,
    ) -> RunResult {
        self.calls.lock().unwrap().push(spec.clone());
        if let Some(probe) = self.probe.lock().unwrap().as_ref() {
            let answer = probe(&spec);
            self.probes.lock().unwrap().push(answer);
        }
        let script = self.scripts.lock().unwrap().pop_front().unwrap_or_default();
        let name = format!("talon-{}-test", spec.group.folder);
        on_start(Arc::new(FakeContainer(name.clone())));
        self.started.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &script.gate {
            gate.notified().await;
        }
        let count = script.outputs.len();
        let last_session = script
            .outputs
            .iter()
            .rev()
            .find_map(|o| o.new_session_id.clone())
            .or(script.new_session_id.clone());
        for o in script.outputs {
            let _ = outputs.send(o);
        }
        drop(outputs);
        RunResult {
            status: if script.error.is_some() {
                OutputStatus::Error
            } else {
                OutputStatus::Success
            },
            error: script.error,
            new_session_id: last_session,
            usage: None,
            last_result: None,
            outputs: count,
            exit_code: Some(0),
            outcome: RunOutcome::Exited,
            duration: Duration::ZERO,
            container_name: name,
        }
    }

    fn hard_timeout(&self, _config: &ContainerConfig) -> Duration {
        *self.hard_timeout.lock().unwrap()
    }
}

// ---------------------------------------------------------------------------
// LLM access
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct FakeLlm {
    pub issued: Mutex<Vec<(String, String, Duration)>>,
    pub revoked: Mutex<Vec<String>>,
}

impl LlmAccess for FakeLlm {
    fn issue(&self, label: &str, ttl: Duration, vllm: &VllmConfig) -> (String, LlmEndpoint) {
        let mut issued = self.issued.lock().unwrap();
        let token = format!("tok-{}", issued.len() + 1);
        issued.push((token.clone(), label.to_string(), ttl));
        (
            token.clone(),
            LlmEndpoint {
                base_url: "http://host.docker.internal:3001/v1".into(),
                token,
                model: vllm.model.clone(),
                fast_model: vllm.fast_model.clone(),
                max_context_tokens: 32_768,
                max_output_tokens: None,
                temperature: None,
                top_p: None,
                enable_thinking: None,
                request_timeout_secs: None,
            },
        )
    }

    fn revoke(&self, token: &str) {
        self.revoked.lock().unwrap().push(token.to_string());
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

pub struct Harness {
    pub orch: Arc<Orchestrator>,
    pub db: Db,
    pub channel: Arc<FakeChannel>,
    pub launcher: Arc<FakeLauncher>,
    pub llm: Arc<FakeLlm>,
    pub audit: MemoryAuditSink,
    pub queue: GroupQueue,
    pub dir: TempDir,
}

impl Harness {
    pub fn root(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }
}

pub struct HarnessOptions {
    pub env: String,
    pub allowlist: SenderAllowlist,
    pub settings: Settings,
    pub with_llm: bool,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            env: VLLM_ENV.to_string(),
            allowlist: SenderAllowlist::default(),
            settings: Settings::default(),
            with_llm: true,
        }
    }
}

pub fn harness() -> Harness {
    harness_with(HarnessOptions::default())
}

pub fn harness_with(opts: HarnessOptions) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("groups")).unwrap();
    let config = Arc::new(TalonConfig::from_env(
        dir.path(),
        EnvFile::from_str_content(&opts.env),
    ));
    let db = Db::open_in_memory().unwrap();
    let queue = GroupQueue::new(QueueConfig::new(config.data_dir.clone(), 4));
    let launcher = Arc::new(FakeLauncher::default());
    let llm = Arc::new(FakeLlm::default());
    let audit = MemoryAuditSink::default();
    let channel = Arc::new(FakeChannel::default());
    let orch = Orchestrator::new(OrchestratorDeps {
        config,
        db: db.clone(),
        queue: queue.clone(),
        launcher: launcher.clone(),
        llm: opts.with_llm.then(|| llm.clone() as Arc<dyn LlmAccess>),
        allowlist: AllowlistSource::fixed(opts.allowlist),
        redactor: Arc::new(Redactor::with_secrets(
            &["harness-secret-value".to_string()],
        )),
        audit: Arc::new(audit.clone()),
        settings: opts.settings,
    })
    .unwrap();
    orch.set_channels(vec![channel.clone() as Arc<dyn Channel>]);
    queue.set_processor(orch.clone());
    Harness {
        orch,
        db,
        channel,
        launcher,
        llm,
        audit,
        queue,
        dir,
    }
}

pub fn group(name: &str, folder: &str, is_main: bool) -> RegisteredGroup {
    RegisteredGroup {
        name: name.into(),
        folder: folder.into(),
        trigger: "@Andy".into(),
        added_at: "2026-01-01T00:00:00.000Z".into(),
        container_config: None,
        requires_trigger: None,
        is_main,
        session_key: None,
        ipc_key: None,
        ephemeral_session: false,
        trusted_session_commands: false,
    }
}

pub fn msg(jid: &str, id: &str, sender: &str, content: &str, ts: &str) -> NewMessage {
    NewMessage {
        id: id.into(),
        chat_jid: jid.into(),
        sender: sender.into(),
        sender_name: sender.into(),
        content: content.into(),
        timestamp: ts.into(),
        ..NewMessage::default()
    }
}

/// `2026-01-01T00:00:<sec>.000Z`
pub fn ts(sec: u32) -> String {
    format!("2026-01-01T00:00:{sec:02}.000Z")
}
