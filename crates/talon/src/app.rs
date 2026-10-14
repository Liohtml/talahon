//! `talon run`: startup and graceful shutdown (port of `main()` in
//! `src/index.ts`).
//!
//! Startup:
//! 1. container runtime: detect, `ensure_running`, clean up orphans;
//! 2. database: open + migrate, import legacy JSON state, hash-chained audit
//!    sink, log the audit chain head;
//! 3. LLM gateway (when vLLM is configured): bind address from
//!    `TALON_LLM_GATEWAY_BIND` or the container bridge, allow every
//!    group's model;
//! 4. container runner (mount allowlist, redactor), group queue,
//!    orchestrator (loads state), task scheduler, queue processor;
//! 5. channels: CoPilot HTTP API + Telegram / Emacs / webhook when
//!    configured; at least one must connect;
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

/// Host name containers use for the host (Docker Desktop built-in; mapped
/// to the bridge gateway on Linux by `talon-container`).
pub const DEFAULT_CONTAINER_HOST: &str = "host.docker.internal";
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
    let ip = gateway_bind_ip(config, runtime).await?;
    let bind = SocketAddr::new(ip, config.llm_gateway_port);
    let Some(gw) = gateway_config(config, groups, bind) else {
        return Ok(None);
    };
    if gw.upstream_api_key.is_none() {
        tracing::warn!("TALON_VLLM_API_KEY is not set: the gateway calls vLLM without an API key");
    }
    let handle = LlmGateway::start(gw, audit)
        .await
        .map_err(|e| anyhow!("cannot start the LLM gateway on {bind}: {e}"))?;
    Ok(Some(handle))
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
    let runner = ContainerRunner::new(
        RunnerConfig::from_talon_config(&config),
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
    let mut candidates: Vec<Arc<dyn Channel>> = vec![Arc::new(HttpChannel::new(
        http_config,
        host.clone(),
        db.clone(),
        audit.clone(),
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
            trigger: "@Andy".into(),
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
    fn base_url_normalization() {
        assert_eq!(normalize_base("http://V:8000/v1/"), "http://v:8000");
        assert_eq!(normalize_base("http://v:8000"), "http://v:8000");
    }
}
