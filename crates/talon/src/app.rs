//! `talon run`: startup and graceful shutdown.
//!
//! Startup:
//! 1. container runtime: detect, `ensure_running`, clean up orphans,
//!    create the dedicated agent network (`talon-agents`, inter-container
//!    traffic off; MYTH-05) unless the operator chose the runtime default —
//!    fatal when it cannot be created;
//! 2. database: open + migrate, import legacy JSON state, hash-chained audit
//!    sink, log the audit chain head;
//! 3. LLM gateway (when vLLM is configured *and* `TALON_VLLM_API_KEY` is
//!    set — without a key containers could call vLLM directly and bypass
//!    the gateway, so it is refused unless `TALON_VLLM_ALLOW_NO_API_KEY=true`;
//!    MYTH-05): bind address from `TALON_LLM_GATEWAY_BIND` or the container
//!    bridge, allow every group's model;
//! 4. container runner (mount allowlist, redactor), group queue,
//!    orchestrator (loads state), task scheduler, queue processor;
//! 5. channels: CoPilot HTTP API (its `/palace/*` calls run in throw-away
//!    hardened containers — never on the host; MYTH-01) + Telegram / Emacs /
//!    webhook when configured; at least one must connect;
//! 6. scheduler loop, IPC watcher, startup recovery, message loop.
//!
//! Shutdown (SIGTERM / SIGINT; a second signal exits immediately):
//! stop accepting work and stop the loops, `queue.shutdown(grace)` (closes
//! containers, stops stragglers), disconnect channels, stop the gateway,
//! final audit record and chain head.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use talon_container::{ContainerRunner, ContainerRuntime, LogRedactor, MountPolicy, RunnerConfig};
use talon_core::audit::{SharedAuditSink, event};
use talon_core::channel::{Channel, ChannelHost};
use talon_core::config::TalonConfig;
use talon_core::provider::{effective_vllm, merge_container_config};
use talon_core::types::RegisteredGroup;
use talon_db::{Db, DbAuditSink, DbOptions, default_db_path};
use talon_http::{HttpChannel, HttpConfig};
use talon_ipc::{IpcHost, IpcWatcher, IpcWatcherConfig};
use talon_llm::gateway::{GatewayConfig, GatewayHandle, LlmGateway};
use talon_scheduler::{GroupQueue, QueueConfig, SchedulerConfig, TaskScheduler};
use talon_security::mounts::MountValidator;
use talon_security::redact::Redactor;
use talon_security::senders::REQUIRED_ENV;
use tokio_util::sync::CancellationToken;

use crate::agent::{GatewayLlm, LlmAccess, RunnerLauncher};
use crate::allowlist::AllowlistSource;
use crate::orchestrator::{Orchestrator, OrchestratorDeps, Settings};
use crate::palace::host_palace_runner;

/// Host name containers use for the host (Docker Desktop built-in; mapped
/// to the bridge gateway on Linux by `talon-container`).
pub const DEFAULT_CONTAINER_HOST: &str = "host.docker.internal";
/// Explicit opt-out of the vLLM API key requirement (MYTH-05).
pub const ALLOW_NO_API_KEY_ENV: &str = "TALON_VLLM_ALLOW_NO_API_KEY";
/// Logged when the gateway is refused for lack of an upstream API key.
pub const VLLM_API_KEY_REQUIRED: &str = "TALON_VLLM_API_KEY is not set: refusing to start the LLM \
     gateway. Without an API key vLLM serves anyone who can reach it, so agent containers could \
     call it directly and bypass the gateway (per-run tokens, model allowlist, request filtering). \
     Set TALON_VLLM_API_KEY in .env to vLLM's --api-key; only if containers provably cannot reach \
     vLLM, set TALON_VLLM_ALLOW_NO_API_KEY=true. Every agent run fails until then — run `talon doctor`";
/// How long a channel gets to disconnect at shutdown.
const CHANNEL_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long background loops get to stop at shutdown.
const LOOP_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Log the audit chain head (anchors the chain outside the database).
pub fn log_audit_head(db: &Db, phase: &str) {
    match (db.audit_chain_head(), db.audit_count()) {
        (Ok(Some((id, hash))), Ok(count)) => {
            tracing::info!(phase, head_id = id, head_hash = %hash, events = count, "audit chain head");
        }
        (Ok(None), _) => tracing::info!(phase, "audit chain empty"),
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(phase, error = %e, "cannot read audit chain head")
        }
    }
}

/// Whether the upstream vLLM API key requirement is met (MYTH-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyPolicy {
    /// `TALON_VLLM_API_KEY` is set (non-blank) in `.env`.
    Present,
    /// No key, but the operator opted out (`TALON_VLLM_ALLOW_NO_API_KEY=true`).
    MissingAllowed,
    /// No key and no opt-out: the gateway must not start.
    Missing,
}

/// Evaluate the vLLM API key requirement for `config`.
pub fn api_key_policy(config: &TalonConfig) -> ApiKeyPolicy {
    let present = config
        .env
        .file_value("TALON_VLLM_API_KEY")
        .is_some_and(|k| !k.trim().is_empty());
    if present {
        ApiKeyPolicy::Present
    } else if config.env.get_bool(ALLOW_NO_API_KEY_ENV) {
        ApiKeyPolicy::MissingAllowed
    } else {
        ApiKeyPolicy::Missing
    }
}

/// `true`/`false` (also `1/0`, `yes/no`, `on/off`, any case).
fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn normalize_base(url: &str) -> String {
    let u = url.trim().trim_end_matches('/');
    u.strip_suffix("/v1").unwrap_or(u).to_ascii_lowercase()
}

/// Gateway configuration for the host's vLLM defaults, allowing every
/// model a registered group may use. `None` when vLLM is not configured.
pub fn gateway_config(
    config: &TalonConfig,
    groups: &HashMap<String, RegisteredGroup>,
    bind: SocketAddr,
) -> Option<GatewayConfig> {
    let vllm = effective_vllm(&config.provider_defaults)?;
    let api_key = config
        .env
        .file_value("TALON_VLLM_API_KEY")
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string);
    let mut gw = GatewayConfig::from_vllm(vllm, api_key);
    gw.bind = bind;
    if let Some(rpm) = config
        .env
        .get("TALON_LLM_GATEWAY_RPM")
        .and_then(|v| v.trim().parse::<u32>().ok())
    {
        gw.requests_per_minute = rpm;
    }
    gw.audit_requests = config.env.get_bool("TALON_LLM_GATEWAY_AUDIT_REQUESTS");
    if let Some(raw) = config.env.get("TALON_LLM_GATEWAY_MAX_CONCURRENT") {
        match raw.trim().parse::<u32>() {
            Ok(n) => gw.max_concurrent_requests = n,
            Err(_) => tracing::warn!(
                value = %raw,
                default = gw.max_concurrent_requests,
                "TALON_LLM_GATEWAY_MAX_CONCURRENT is not a number; using the default"
            ),
        }
    }
    if let Some(raw) = config.env.get("TALON_LLM_GATEWAY_CACHE_SALT") {
        match parse_bool(&raw) {
            Some(on) => gw.cache_salt = on,
            None => tracing::warn!(
                value = %raw,
                default = gw.cache_salt,
                "TALON_LLM_GATEWAY_CACHE_SALT is not true/false; using the default"
            ),
        }
    }

    let upstream = normalize_base(&vllm.base_url);
    let mut jids: Vec<&String> = groups.keys().collect();
    jids.sort();
    for jid in jids {
        let group = &groups[jid];
        let merged =
            merge_container_config(&config.provider_defaults, group.container_config.as_ref());
        let Some(v) = effective_vllm(&merged) else {
            continue;
        };
        if normalize_base(&v.base_url) != upstream {
            tracing::warn!(
                jid = %jid,
                group = %group.name,
                "group overrides the vLLM base URL; the LLM gateway only proxies to the host \
                 upstream (TALON_VLLM_BASE_URL), so its requests go there"
            );
        }
        gw = gw.allow_model(v.model.clone());
        if let Some(fast) = &v.fast_model {
            gw = gw.allow_model(fast.clone());
        }
    }
    Some(gw)
}

/// Address the gateway binds: `TALON_LLM_GATEWAY_BIND` when set, else the
/// container bridge address detected by `talon-container`.
///
/// # Errors
/// An explicit bind value that is not an IP address.
pub async fn gateway_bind_ip(
    config: &TalonConfig,
    runtime: &ContainerRuntime,
) -> anyhow::Result<IpAddr> {
    match config.env.get("TALON_LLM_GATEWAY_BIND") {
        Some(raw) => raw
            .trim()
            .parse::<IpAddr>()
            .with_context(|| format!("TALON_LLM_GATEWAY_BIND {raw:?} is not an IP address")),
        None => Ok(talon_container::detect_gateway_bind_addr(runtime).await),
    }
}

async fn start_gateway(
    config: &TalonConfig,
    runtime: &ContainerRuntime,
    groups: &HashMap<String, RegisteredGroup>,
    audit: SharedAuditSink,
) -> anyhow::Result<Option<GatewayHandle>> {
    if effective_vllm(&config.provider_defaults).is_none() {
        tracing::error!(
            "vLLM is not configured (TALON_VLLM_BASE_URL / TALON_VLLM_MODEL): the LLM gateway is \
             not started and every agent run will fail until it is — run `talon doctor`"
        );
        return Ok(None);
    }
    match api_key_policy(config) {
        ApiKeyPolicy::Present => {}
        ApiKeyPolicy::MissingAllowed => tracing::warn!(
            "TALON_VLLM_API_KEY is not set and {ALLOW_NO_API_KEY_ENV}=true: the gateway calls vLLM \
             without an API key; make sure agent containers cannot reach vLLM directly"
        ),
        ApiKeyPolicy::Missing => {
            tracing::error!("{VLLM_API_KEY_REQUIRED}");
            return Ok(None);
        }
    }
    let ip = gateway_bind_ip(config, runtime).await?;
    let bind = SocketAddr::new(ip, config.llm_gateway_port);
    let Some(gw) = gateway_config(config, groups, bind) else {
        return Ok(None);
    };
    let handle = LlmGateway::start(gw, audit)
        .await
        .map_err(|e| anyhow!("cannot start the LLM gateway on {bind}: {e}"))?;
    Ok(Some(handle))
}

/// Create (or verify) the network agent containers run on (MYTH-05):
/// `RunnerConfig::default_network`, normally
/// [`talon_container::AGENT_NETWORK`]. Nothing to do when the operator
/// chose the runtime's default bridge.
///
/// # Errors
/// The network cannot be inspected or created — fatal, because the runner
/// would otherwise fail every launch (or fall back to a weaker network).
pub async fn ensure_agent_network(
    runtime: &ContainerRuntime,
    runner_config: &RunnerConfig,
) -> anyhow::Result<()> {
    let Some(network) = runner_config.default_network.as_deref() else {
        tracing::warn!(
            "agent containers use the runtime's default bridge network (no dedicated \
             talon-agents network): containers can reach each other and egress is not \
             restricted by `talon setup egress`"
        );
        return Ok(());
    };
    runtime.ensure_agent_network(network).await.map_err(|e| {
        anyhow!(
            "cannot prepare the agent container network {network:?}: {e}. Run `talon setup \
             egress` (creates the network and its egress firewall rules), or check that the \
             container runtime can create networks"
        )
    })?;
    tracing::info!(network, "agent network ready");
    Ok(())
}

async fn wait_for_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "cannot install SIGTERM handler");
            None
        }
    };
    tokio::select! {
        r = tokio::signal::ctrl_c() => {
            if let Err(e) = r {
                tracing::warn!(error = %e, "cannot listen for SIGINT");
                std::future::pending::<()>().await;
            }
            "SIGINT"
        }
        () = async {
            match term.as_mut() {
                Some(t) => { t.recv().await; }
                None => std::future::pending::<()>().await,
            }
        } => "SIGTERM",
    }
}

async fn connect_channels(candidates: Vec<Arc<dyn Channel>>) -> Vec<Arc<dyn Channel>> {
    let mut connected = Vec::new();
    for channel in candidates {
        match channel.connect().await {
            Ok(()) => {
                tracing::info!(channel = channel.name(), "channel connected");
                connected.push(channel);
            }
            Err(e) => {
                tracing::error!(channel = channel.name(), error = %e, "channel failed to connect")
            }
        }
    }
    connected
}

async fn join_with_timeout(name: &str, handle: tokio::task::JoinHandle<()>) {
    let abort = handle.abort_handle();
    match tokio::time::timeout(LOOP_STOP_TIMEOUT, handle).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(task = name, error = %e, "background task ended abnormally"),
        Err(_) => {
            tracing::warn!(
                task = name,
                "background task did not stop in time; aborting"
            );
            abort.abort();
        }
    }
}

/// Run the orchestrator until SIGTERM / SIGINT.
///
/// # Errors
/// Fatal startup problems (container runtime unavailable, database, gateway
/// bind failure, invalid HTTP configuration, no channel connected).
pub async fn run(config: Arc<TalonConfig>, redactor: Arc<Redactor>) -> anyhow::Result<()> {
    tracing::info!(version = crate::VERSION, root = %config.project_root.display(), "Talon starting");

    // 1. Container runtime.
    let runtime = Arc::new(
        ContainerRuntime::detect(&config.container_runtime)
            .map_err(|e| anyhow!("container runtime: {e}"))?,
    );
    runtime.ensure_running().await.map_err(|e| anyhow!("{e}"))?;
    let orphans = runtime.cleanup_orphans().await;
    if !orphans.is_empty() {
        tracing::info!(count = orphans.len(), names = ?orphans, "Stopped orphaned containers");
    }
    let runner_config = RunnerConfig::from_talon_config(&config);
    ensure_agent_network(&runtime, &runner_config).await?;

    // 2. Database + audit.
    let db = Db::open_with_options(
        &default_db_path(&config.store_dir),
        &DbOptions {
            assistant_name: config.assistant_name.clone(),
        },
    )
    .map_err(|e| anyhow!("cannot open database: {e}"))?;
    tracing::info!("Database initialized");
    if let Err(e) = db.migrate_json_state(&config.data_dir) {
        tracing::warn!(error = %e, "legacy JSON state import failed");
    }
    let audit: SharedAuditSink = Arc::new(DbAuditSink::new(db.clone()));
    log_audit_head(&db, "startup");
    audit.record(event(
        "talon.start",
        "talon",
        None,
        "info",
        serde_json::json!({ "version": crate::VERSION, "pid": std::process::id() }),
    ));

    // 3. LLM gateway.
    let persisted_groups = db
        .get_all_registered_groups()
        .map_err(|e| anyhow!("cannot load registered groups: {e}"))?;
    let gateway = start_gateway(&config, &runtime, &persisted_groups, audit.clone()).await?;
    let container_host = config
        .env
        .get("TALON_LLM_GATEWAY_HOST")
        .unwrap_or_else(|| DEFAULT_CONTAINER_HOST.to_string());
    let llm: Option<Arc<dyn LlmAccess>> = gateway
        .clone()
        .map(|g| Arc::new(GatewayLlm::new(g, container_host)) as Arc<dyn LlmAccess>);

    // 4. Runner, queue, orchestrator, scheduler.
    let mounts: Arc<dyn MountPolicy> = Arc::new(MountValidator::load(&config.mount_allowlist_path));
    let log_redactor: Arc<dyn LogRedactor> = redactor.clone();
    let agent_network = runner_config.default_network.clone();
    let runner = ContainerRunner::new(
        runner_config,
        runtime.clone(),
        mounts,
        log_redactor,
        audit.clone(),
    );
    let mut queue_config = QueueConfig::from_talon_config(&config);
    // The gateway goes down after the queue: containers still running after
    // the grace period could not reach the model anyway.
    queue_config.stop_on_shutdown = true;
    let queue = GroupQueue::new(queue_config);
    let settings = Settings::default();
    let shutdown_grace = settings.shutdown_grace;
    let orch = Orchestrator::new(OrchestratorDeps {
        config: config.clone(),
        db: db.clone(),
        queue: queue.clone(),
        launcher: Arc::new(RunnerLauncher::new(runner)),
        llm,
        allowlist: AllowlistSource::from_file(
            config.sender_allowlist_path.clone(),
            config.env.get_bool(REQUIRED_ENV),
        ),
        redactor: redactor.clone(),
        audit: audit.clone(),
        settings,
    })
    .map_err(|e| anyhow!("cannot load state: {e}"))?;
    let scheduler = Arc::new(TaskScheduler::new(
        SchedulerConfig::from_talon_config(&config),
        Arc::new(db.clone()),
        queue.clone(),
        orch.clone(),
        orch.clone(),
    ));
    orch.set_scheduler(scheduler.clone());
    queue.set_processor(orch.clone());

    // 5. Channels.
    let host: Arc<dyn ChannelHost> = orch.clone();
    let http_config =
        HttpConfig::from_talon_config(&config).map_err(|e| anyhow!("HTTP channel: {e}"))?;
    let palace = host_palace_runner(&config, &http_config, &runtime, agent_network);
    let mut candidates: Vec<Arc<dyn Channel>> = vec![Arc::new(HttpChannel::with_palace(
        http_config,
        host.clone(),
        db.clone(),
        audit.clone(),
        palace,
    ))];
    candidates.extend(talon_channels::build_channels(
        host.clone(),
        &config.env,
        audit.clone(),
    ));
    let channels = connect_channels(candidates).await;
    if channels.is_empty() {
        bail!("No channels connected");
    }
    orch.set_channels(channels.clone());

    // 6. Background loops.
    let cancel = CancellationToken::new();
    let scheduler_task = tokio::spawn({
        let scheduler = scheduler.clone();
        let cancel = cancel.clone();
        async move { scheduler.run(cancel).await }
    });
    let ipc_host: Arc<dyn IpcHost> = orch.clone();
    let watcher = IpcWatcher::new(
        IpcWatcherConfig::from_talon_config(&config),
        db.clone(),
        ipc_host,
        audit.clone(),
    );
    let ipc_task = tokio::spawn({
        let cancel = cancel.clone();
        async move { watcher.run(cancel).await }
    });
    let recovered = orch.recover_pending_messages();
    if !recovered.is_empty() {
        tracing::info!(lanes = recovered.len(), "Recovery: lanes enqueued");
    }
    let loop_task = tokio::spawn(orch.clone().message_loop(cancel.clone()));

    // Wait for a signal.
    let signal = wait_for_signal().await;
    tracing::info!(signal, "Shutdown signal received");
    tokio::spawn(async {
        let second = wait_for_signal().await;
        tracing::warn!(signal = second, "second signal: exiting immediately");
        std::process::exit(130);
    });

    // Shutdown.
    orch.stop_accepting();
    cancel.cancel();
    let report = queue.shutdown(shutdown_grace).await;
    tracing::info!(
        drained = report.drained,
        still_active = ?report.still_active,
        stopped = ?report.stopped_containers,
        dropped_pending = report.dropped_pending,
        "Group queue shut down"
    );
    for channel in &channels {
        match tokio::time::timeout(CHANNEL_DISCONNECT_TIMEOUT, channel.disconnect()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(channel = channel.name(), error = %e, "channel disconnect failed")
            }
            Err(_) => tracing::warn!(channel = channel.name(), "channel disconnect timed out"),
        }
    }
    join_with_timeout("message-loop", loop_task).await;
    join_with_timeout("scheduler", scheduler_task).await;
    join_with_timeout("ipc-watcher", ipc_task).await;
    if let Some(gateway) = &gateway {
        gateway.shutdown().await;
    }
    audit.record(event(
        "talon.stop",
        "talon",
        None,
        "info",
        serde_json::json!({ "signal": signal, "drained": report.drained }),
    ));
    log_audit_head(&db, "shutdown");
    tracing::info!("Talon stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use talon_core::env::EnvFile;
    use talon_core::types::{ContainerConfig, ProviderKind, VllmConfig};

    use super::*;

    fn cfg(content: &str) -> TalonConfig {
        TalonConfig::from_env(
            Path::new("/tmp/talon-test"),
            EnvFile::from_str_content(content),
        )
    }

    fn group_with_model(model: &str, base: &str) -> RegisteredGroup {
        RegisteredGroup {
            name: model.into(),
            folder: model.into(),
            trigger: "@Talon".into(),
            added_at: "2026-01-01T00:00:00.000Z".into(),
            container_config: Some(ContainerConfig {
                provider: Some(ProviderKind::Vllm),
                vllm: Some(VllmConfig {
                    base_url: base.into(),
                    model: model.into(),
                    fast_model: Some(format!("{model}-fast")),
                    max_context_tokens: None,
                    max_output_tokens: None,
                    temperature: None,
                    top_p: None,
                    enable_thinking: None,
                    request_timeout_secs: None,
                }),
                ..ContainerConfig::default()
            }),
            requires_trigger: None,
            is_main: false,
            session_key: None,
            ipc_key: None,
            ephemeral_session: false,
            trusted_session_commands: false,
        }
    }

    #[test]
    fn no_gateway_without_vllm() {
        let c = cfg("");
        if std::env::var("TALON_VLLM_BASE_URL").is_ok() {
            return; // process env overrides .env in CI shells
        }
        assert!(gateway_config(&c, &HashMap::new(), "127.0.0.1:0".parse().unwrap()).is_none());
    }

    #[test]
    fn gateway_allows_group_models_and_keeps_key_secret() {
        let c = cfg(
            "TALON_VLLM_BASE_URL=http://vllm:8000/v1\nTALON_VLLM_MODEL=qwen\n\
             TALON_VLLM_FAST_MODEL=qwen-small\nTALON_VLLM_API_KEY=sekret-key-123\n",
        );
        if effective_vllm(&c.provider_defaults).map(|v| v.model.as_str()) != Some("qwen") {
            return; // overridden by the process environment
        }
        let mut groups = HashMap::new();
        groups.insert(
            "g1".to_string(),
            group_with_model("llama", "http://vllm:8000"),
        );
        groups.insert(
            "g2".to_string(),
            group_with_model("other", "http://elsewhere:8000"),
        );
        let bind: SocketAddr = "127.0.0.1:3999".parse().unwrap();
        let gw = gateway_config(&c, &groups, bind).unwrap();
        assert_eq!(gw.bind, bind);
        assert_eq!(gw.default_model, "qwen");
        for m in ["qwen", "qwen-small", "llama", "llama-fast", "other"] {
            assert!(gw.allowed_models.iter().any(|a| a == m), "{m} not allowed");
        }
        assert_eq!(gw.upstream_api_key.as_deref(), Some("sekret-key-123"));
        assert!(!format!("{gw:?}").contains("sekret-key-123"));
    }

    #[test]
    fn api_key_is_required_unless_explicitly_waived() {
        if std::env::var(ALLOW_NO_API_KEY_ENV).is_ok() {
            return; // process env overrides .env in CI shells
        }
        assert_eq!(
            api_key_policy(&cfg("TALON_VLLM_API_KEY=abc\n")),
            ApiKeyPolicy::Present
        );
        assert_eq!(api_key_policy(&cfg("")), ApiKeyPolicy::Missing);
        assert_eq!(
            api_key_policy(&cfg("TALON_VLLM_API_KEY=\"   \"\n")),
            ApiKeyPolicy::Missing
        );
        assert_eq!(
            api_key_policy(&cfg("TALON_VLLM_ALLOW_NO_API_KEY=false\n")),
            ApiKeyPolicy::Missing
        );
        assert_eq!(
            api_key_policy(&cfg("TALON_VLLM_ALLOW_NO_API_KEY=true\n")),
            ApiKeyPolicy::MissingAllowed
        );
        // A key always wins over the waiver.
        assert_eq!(
            api_key_policy(&cfg(
                "TALON_VLLM_API_KEY=k\nTALON_VLLM_ALLOW_NO_API_KEY=true\n"
            )),
            ApiKeyPolicy::Present
        );
    }

    #[test]
    fn gateway_concurrency_and_cache_salt_settings() {
        let base = "TALON_VLLM_BASE_URL=http://vllm:8000/v1\nTALON_VLLM_MODEL=qwen\n";
        if [
            "TALON_VLLM_BASE_URL",
            "TALON_VLLM_MODEL",
            "TALON_LLM_GATEWAY_MAX_CONCURRENT",
            "TALON_LLM_GATEWAY_CACHE_SALT",
        ]
        .iter()
        .any(|k| std::env::var(k).is_ok())
        {
            return; // process env overrides .env in CI shells
        }
        let bind: SocketAddr = "127.0.0.1:3999".parse().unwrap();
        let defaults = gateway_config(&cfg(base), &HashMap::new(), bind).unwrap();
        assert!(defaults.cache_salt);
        let gw = gateway_config(
            &cfg(&format!(
                "{base}TALON_LLM_GATEWAY_MAX_CONCURRENT=7\nTALON_LLM_GATEWAY_CACHE_SALT=false\n"
            )),
            &HashMap::new(),
            bind,
        )
        .unwrap();
        assert_eq!(gw.max_concurrent_requests, 7);
        assert!(!gw.cache_salt);
        let gw = gateway_config(
            &cfg(&format!(
                "{base}TALON_LLM_GATEWAY_MAX_CONCURRENT=lots\nTALON_LLM_GATEWAY_CACHE_SALT=maybe\n"
            )),
            &HashMap::new(),
            bind,
        )
        .unwrap();
        assert_eq!(gw.max_concurrent_requests, defaults.max_concurrent_requests);
        assert!(gw.cache_salt);
        assert_eq!(parse_bool(" Off "), Some(false));
        assert_eq!(parse_bool("YES"), Some(true));
    }

    #[test]
    fn base_url_normalization() {
        assert_eq!(normalize_base("http://V:8000/v1/"), "http://v:8000");
        assert_eq!(normalize_base("http://v:8000"), "http://v:8000");
    }
}
