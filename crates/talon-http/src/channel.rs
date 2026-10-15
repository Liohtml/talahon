//! [`HttpChannel`]: the CoPilot HTTP API as a [`Channel`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use talon_core::audit::SharedAuditSink;
use talon_core::channel::{Channel, ChannelHost};
use talon_core::{Error, Result};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{HttpConfig, MIN_RECOMMENDED_KEY_LEN};
use crate::lanes::SendOutcome;
use crate::metrics::Metrics;
use crate::palace::PalaceRunner;
use crate::server::{HttpDeps, HttpState, router};
use crate::store::HttpStore;

/// How long open connections may drain after shutdown starts.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Extra time `disconnect` gives the server task beyond [`SHUTDOWN_GRACE`]
/// before aborting it.
const SHUTDOWN_SLACK: Duration = Duration::from_secs(2);
/// HTTP/2 keep-alive ping interval (dead peers are dropped).
const HTTP2_KEEP_ALIVE: Duration = Duration::from_secs(30);

/// Connection limits for [`talon_net::serve`] (MYTH-06): header-read
/// timeout and connection caps. Established requests — SSE streams in
/// particular — have no idle timeout.
fn server_limits(cfg: &HttpConfig) -> talon_net::ServerLimits {
    talon_net::ServerLimits {
        max_connections: cfg.max_connections.max(1),
        max_connections_per_ip: cfg.max_connections_per_ip.max(1),
        header_read_timeout: cfg.header_read_timeout,
        http2_keep_alive_interval: HTTP2_KEEP_ALIVE,
        shutdown_grace: SHUTDOWN_GRACE,
    }
}

struct Running {
    cancel: CancellationToken,
    server: JoinHandle<()>,
    sweeper: JoinHandle<()>,
    addr: SocketAddr,
}

/// The CoPilot HTTP channel. Owns `http:copilot` and every `http:copilot:*`
/// sub-lane.
pub struct HttpChannel {
    state: HttpState,
    running: AsyncMutex<Option<Running>>,
    connected: std::sync::atomic::AtomicBool,
    local_addr: std::sync::Mutex<Option<SocketAddr>>,
}

impl std::fmt::Debug for HttpChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpChannel")
            .field("state", &self.state)
            .field("connected", &self.is_connected())
            .finish_non_exhaustive()
    }
}

impl HttpChannel {
    /// Production constructor: `db` is the shared `talon_db::Db`.
    ///
    /// The `/palace/*` endpoints are disabled (503) — see [`HttpDeps::new`];
    /// use [`Self::with_palace`] to supply a (containerized) palace runner.
    pub fn new(
        config: HttpConfig,
        host: Arc<dyn ChannelHost>,
        db: talon_db::Db,
        audit: SharedAuditSink,
    ) -> Self {
        let store: Arc<dyn HttpStore> = Arc::new(db);
        let deps = HttpDeps::new(&config, host, store, audit);
        Self::from_state(HttpState::new(config, deps))
    }

    /// Like [`Self::new`], serving `/palace/*` through `palace` (normally a
    /// [`crate::CommandPalaceRunner`] running the palace in a hardened
    /// container).
    pub fn with_palace(
        config: HttpConfig,
        host: Arc<dyn ChannelHost>,
        db: talon_db::Db,
        audit: SharedAuditSink,
        palace: Arc<dyn PalaceRunner>,
    ) -> Self {
        let store: Arc<dyn HttpStore> = Arc::new(db);
        let deps = HttpDeps::new(&config, host, store, audit).with_palace(palace);
        Self::from_state(HttpState::new(config, deps))
    }

    /// Build around an existing state (custom dependencies, tests).
    pub fn from_state(state: HttpState) -> Self {
        Self {
            state,
            running: AsyncMutex::new(None),
            connected: std::sync::atomic::AtomicBool::new(false),
            local_addr: std::sync::Mutex::new(None),
        }
    }

    /// The shared state (e.g. to build a [`router`] for tests).
    pub fn state(&self) -> &HttpState {
        &self.state
    }

    /// The bound address once connected (useful with port `0`).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn warn_about_key(&self) {
        let key = &self.state.config().api_key;
        if !key.is_configured() {
            tracing::error!(
                "HTTP_API_KEY is not set in .env: the CoPilot HTTP API will reject EVERY request \
                 except GET /health with 401 until a key is configured"
            );
        } else if key.len() < MIN_RECOMMENDED_KEY_LEN {
            tracing::warn!(
                min_len = MIN_RECOMMENDED_KEY_LEN,
                "HTTP_API_KEY is short; use a long random key (e.g. `openssl rand -hex 32`)"
            );
        }
        if let Some(warning) = self.state.config().exposure_warning() {
            tracing::warn!("{warning}");
        }
        if self.state.config().evals_legacy_group_dir {
            tracing::warn!(
                "COPILOT_EVALS_LEGACY_GROUP_DIR is enabled: GET /evals also serves records from \
                 the shared group folder, which every CoPilot lane can write (forgeable). Disable \
                 it once old evals are no longer needed"
            );
        }
    }
}

async fn sweep_loop(state: HttpState, cancel: CancellationToken) {
    let period = state
        .config()
        .lane_sweep_interval
        .max(Duration::from_secs(1));
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tick.tick() => {
                let swept = state.sweep_idle_lanes().await;
                if !swept.is_empty() {
                    tracing::info!(count = swept.len(), "HTTP channel: idle lane sweep");
                }
            }
        }
    }
}

#[async_trait]
impl Channel for HttpChannel {
    fn name(&self) -> &str {
        "http"
    }

    async fn connect(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        if running.is_some() {
            return Ok(());
        }
        self.warn_about_key();

        let cfg = self.state.config();
        let bind = SocketAddr::new(cfg.bind, cfg.port);
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|e| Error::Channel(format!("HTTP channel: cannot bind {bind}: {e}")))?;
        let addr = listener.local_addr()?;

        self.state.register_base_lanes().await;
        if cfg.seed_digest_task {
            match self.state.seed_digest_task().await {
                Ok(true) => tracing::info!(
                    task_id = crate::investigate::DIGEST_TASK_ID,
                    "Seeded CoPilot alert digest scheduled task (paused)"
                ),
                Ok(false) => {}
                Err(e) => tracing::warn!(err = %e, "failed to seed the alert digest task"),
            }
        }

        let cancel = CancellationToken::new();
        let app = router(self.state.clone());
        // talon_net::serve inserts ConnectInfo<SocketAddr> per request, so
        // per-IP auth throttling and audit actors keep working.
        let server = tokio::spawn(talon_net::serve(
            listener,
            app,
            server_limits(cfg),
            cancel.clone(),
        ));
        let sweeper = tokio::spawn(sweep_loop(self.state.clone(), cancel.clone()));

        tracing::info!(%addr, palace = self.state.0.palace.mode(), "HTTP channel listening");
        tracing::info!(
            "HTTP channel endpoints: POST /message, POST /investigate, GET /investigations[/{{id}}], \
             GET /evals/{{alert_id}}, GET /templates, POST /palace/lesson, GET /palace/search, \
             POST /palace/forget, GET /status, GET /metrics, POST /session/reset, GET /health"
        );
        *self.local_addr.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
        *running = Some(Running {
            cancel,
            server,
            sweeper,
            addr,
        });
        self.connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn send_message(&self, jid: &str, text: &str) -> Result<()> {
        let s = &self.state.0;
        match s.streams.send_text(jid, text) {
            SendOutcome::Delivered => {
                tracing::info!(
                    jid,
                    length = text.len(),
                    "HTTP channel: wrote SSE text chunk"
                );
            }
            SendOutcome::NoWriter => {
                // Expected on the investigation lane: its results reach
                // CoPilot through the MCP write-back tools. Never fall back
                // to another lane's writer.
                tracing::debug!(
                    jid,
                    length = text.len(),
                    "HTTP channel: no SSE writer for lane, dropping chunk"
                );
            }
            SendOutcome::Overflow => {
                Metrics::inc(&s.metrics.sse_dropped_chunks);
                tracing::warn!(
                    jid,
                    length = text.len(),
                    "HTTP channel: SSE buffer full, dropping chunk"
                );
            }
            SendOutcome::ClientGone => {
                tracing::info!(jid, "HTTP channel: SSE client disconnected, dropping chunk");
            }
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn owns_jid(&self, jid: &str) -> bool {
        self.state.lanes().owns(jid)
    }

    async fn disconnect(&self) -> Result<()> {
        let taken = self.running.lock().await.take();
        self.connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let Some(mut r) = taken else {
            return Ok(());
        };
        r.cancel.cancel();
        // Open SSE streams would otherwise hold graceful shutdown forever.
        self.state.0.streams.close_all();
        if tokio::time::timeout(SHUTDOWN_GRACE + SHUTDOWN_SLACK, &mut r.server)
            .await
            .is_err()
        {
            tracing::warn!("HTTP channel: graceful shutdown timed out; aborting");
            r.server.abort();
        }
        r.sweeper.abort();
        *self.local_addr.lock().unwrap_or_else(|e| e.into_inner()) = None;
        tracing::info!(addr = %r.addr, "HTTP channel stopped");
        Ok(())
    }

    async fn set_typing(&self, jid: &str, is_typing: bool) -> Result<()> {
        let streams = &self.state.0.streams;
        if is_typing {
            // Agent is starting a turn: promote the next writer on THIS lane.
            if streams.turn_started(jid) {
                tracing::info!(
                    jid,
                    remaining = streams.pending_len(jid),
                    "HTTP channel: dequeued SSE writer"
                );
            } else {
                tracing::debug!(jid, "HTTP channel: turn start without a new SSE writer");
            }
        } else if streams.turn_ended(jid) {
            // Container exited. on_turn_complete normally closed the stream
            // already; this is the safety net.
            tracing::warn!(
                jid,
                "HTTP channel: container stopped with an active writer; closed via safety net"
            );
        }
        Ok(())
    }

    async fn on_turn_complete(&self, jid: &str) -> Result<()> {
        if self.state.0.streams.turn_complete(jid) {
            tracing::info!(
                jid,
                reason = "turn-complete",
                "HTTP channel: SSE stream closed"
            );
        }
        Ok(())
    }
}
