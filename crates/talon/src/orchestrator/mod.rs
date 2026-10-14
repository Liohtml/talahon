//! The host orchestrator (port of `src/index.ts`).
//!
//! [`Orchestrator`] owns the in-memory state the TypeScript module kept in
//! globals (registered lanes, session ids, message cursors) and implements
//! every host-side callback trait:
//!
//! - `talon_core::channel::ChannelHost` — inbound messages, lane
//!   registration, session reset, queue status ([`host`]);
//! - `talon_ipc::IpcHost` — authorized container requests ([`host`]);
//! - `talon_scheduler::LaneProcessor` / `TaskExecutor` / `GroupDirectory`
//!   — lane jobs and scheduled tasks ([`host`], [`tasks`]);
//! - `talon_router::SessionCommandDeps` — `/new`, `/compact` ([`commands`]).
//!
//! The message pipeline lives in [`messages`], agent runs (sessions, LLM
//! tokens, snapshots) in [`run`].

pub mod commands;
pub mod host;
pub mod messages;
pub mod run;
pub mod tasks;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock};
use std::time::Duration;

use talon_core::audit::SharedAuditSink;
use talon_core::channel::Channel;
use talon_core::config::TalonConfig;
use talon_core::paths::group_folder_path;
use talon_core::protocol::SessionUsage;
use talon_core::types::{ChatMetadata, NewMessage, RegisteredGroup};
use talon_core::{Error, Result};
use talon_db::Db;
use talon_scheduler::{GroupQueue, TaskScheduler};
use talon_security::redact::Redactor;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::agent::{ContainerLauncher, LlmAccess};
use crate::allowlist::AllowlistSource;

/// Router-state key of the global "seen" cursor.
pub const LAST_TIMESTAMP_KEY: &str = "last_timestamp";
/// Router-state key of the per-lane agent cursors (JSON object).
pub const LAST_AGENT_TIMESTAMP_KEY: &str = "last_agent_timestamp";

/// Tunables that are not part of `TalonConfig`.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Close a scheduled task's container this long after its result
    /// (TS `TASK_CLOSE_DELAY_MS`).
    pub task_close_delay: Duration,
    /// Close a `/compact` container this long after it finished.
    pub command_close_delay: Duration,
    /// Added to the run's lifetime when sizing the LLM token TTL.
    pub token_ttl_margin: Duration,
    /// Shutdown grace for running lane jobs.
    pub shutdown_grace: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            task_close_delay: Duration::from_secs(10),
            command_close_delay: Duration::from_secs(10),
            token_ttl_margin: Duration::from_secs(5 * 60),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

/// Everything [`Orchestrator::new`] needs.
pub struct OrchestratorDeps {
    /// Resolved host configuration.
    pub config: Arc<TalonConfig>,
    /// Database handle.
    pub db: Db,
    /// The lane queue (processor is set by the caller afterwards).
    pub queue: GroupQueue,
    /// Container launcher.
    pub launcher: Arc<dyn ContainerLauncher>,
    /// LLM credentials; `None` when vLLM is not configured.
    pub llm: Option<Arc<dyn LlmAccess>>,
    /// Sender allowlist.
    pub allowlist: AllowlistSource,
    /// Redactor for outbound text and stored error messages.
    pub redactor: Arc<Redactor>,
    /// Audit sink.
    pub audit: SharedAuditSink,
    /// Tunables.
    pub settings: Settings,
}

/// Mutable orchestrator state (TS module globals).
#[derive(Debug, Default)]
pub(crate) struct State {
    /// Registered lanes (persisted + in-memory), by JID.
    pub(crate) groups: HashMap<String, RegisteredGroup>,
    /// JIDs whose registration lives in the database.
    pub(crate) persisted: HashSet<String>,
    /// Session key -> session id.
    pub(crate) sessions: HashMap<String, String>,
    /// High-water mark of messages seen by the message loop.
    pub(crate) last_timestamp: String,
    /// Per-lane cursor: newest message handed to the agent.
    pub(crate) last_agent_timestamp: BTreeMap<String, String>,
    /// Lanes with a running message container: when its LLM token expires.
    pub(crate) token_deadlines: HashMap<String, Instant>,
    /// Lanes with a running message container: its LLM token and TTL, so a
    /// piped follow-up can extend the token instead of recycling the run.
    pub(crate) run_tokens: HashMap<String, (String, Duration)>,
}

/// The host orchestrator. Share it as `Arc<Orchestrator>`.
pub struct Orchestrator {
    pub(crate) config: Arc<TalonConfig>,
    pub(crate) settings: Settings,
    pub(crate) db: Db,
    pub(crate) queue: GroupQueue,
    pub(crate) launcher: Arc<dyn ContainerLauncher>,
    pub(crate) llm: Option<Arc<dyn LlmAccess>>,
    pub(crate) allowlist: AllowlistSource,
    pub(crate) redactor: Arc<Redactor>,
    pub(crate) audit: SharedAuditSink,
    pub(crate) state: Mutex<State>,
    channels: RwLock<Vec<Arc<dyn Channel>>>,
    scheduler: OnceLock<Arc<TaskScheduler>>,
    pub(crate) wake: Notify,
    accepting: AtomicBool,
    pub(crate) loop_running: AtomicBool,
}

impl std::fmt::Debug for Orchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Orchestrator")
            .field("assistant", &self.config.assistant_name)
            .field("queue", &self.queue)
            .finish_non_exhaustive()
    }
}

impl Orchestrator {
    /// Build the orchestrator and load its state from the database (TS
    /// `loadState`).
    ///
    /// # Errors
    /// Database read failures.
    pub fn new(deps: OrchestratorDeps) -> Result<Arc<Self>> {
        let state = load_state(&deps.db)?;
        tracing::info!(group_count = state.groups.len(), "State loaded");
        Ok(Arc::new(Self {
            config: deps.config,
            settings: deps.settings,
            db: deps.db,
            queue: deps.queue,
            launcher: deps.launcher,
            llm: deps.llm,
            allowlist: deps.allowlist,
            redactor: deps.redactor,
            audit: deps.audit,
            state: Mutex::new(state),
            channels: RwLock::new(Vec::new()),
            scheduler: OnceLock::new(),
            wake: Notify::new(),
            accepting: AtomicBool::new(true),
            loop_running: AtomicBool::new(false),
        }))
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        // Critical sections never call foreign code; keep serving after a
        // panic elsewhere rather than cascading.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The host configuration.
    pub fn config(&self) -> &TalonConfig {
        &self.config
    }

    /// The lane queue.
    pub fn queue(&self) -> &GroupQueue {
        &self.queue
    }

    /// The database handle.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Install the connected channels (they need the host to be built
    /// first, hence the late binding).
    pub fn set_channels(&self, channels: Vec<Arc<dyn Channel>>) {
        *self
            .channels
            .write()
            .unwrap_or_else(PoisonError::into_inner) = channels;
    }

    /// Snapshot of the channels.
    pub fn channels(&self) -> Vec<Arc<dyn Channel>> {
        self.channels
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The first channel owning `jid` (TS `findChannel`).
    pub fn find_channel(&self, jid: &str) -> Option<Arc<dyn Channel>> {
        let channels = self.channels.read().unwrap_or_else(PoisonError::into_inner);
        talon_router::find_channel(&channels, jid).cloned()
    }

    /// Install the task scheduler (built after the orchestrator because the
    /// orchestrator is its executor).
    pub fn set_scheduler(&self, scheduler: Arc<TaskScheduler>) {
        if self.scheduler.set(scheduler).is_err() {
            tracing::warn!("task scheduler already installed; ignoring");
        }
    }

    /// The task scheduler, once installed.
    pub fn scheduler(&self) -> Option<&Arc<TaskScheduler>> {
        self.scheduler.get()
    }

    /// Wake the scheduler (tasks changed out of band).
    pub fn wake_scheduler(&self) {
        if let Some(s) = self.scheduler.get() {
            s.wake();
        }
    }

    /// Wake the message loop.
    pub fn wake_message_loop(&self) {
        self.wake.notify_one();
    }

    /// Stop starting new work (shutdown). Inbound messages are still stored
    /// so they are recovered on the next start.
    pub fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::SeqCst);
        self.wake.notify_one();
    }

    /// Whether new work is accepted.
    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::SeqCst)
    }

    /// Snapshot of all registered lanes keyed by JID.
    pub fn groups_snapshot(&self) -> HashMap<String, RegisteredGroup> {
        self.lock().groups.clone()
    }

    /// The lane registered for `jid`.
    pub fn group(&self, jid: &str) -> Option<RegisteredGroup> {
        self.lock().groups.get(jid).cloned()
    }

    /// Current session id stored for `key`.
    pub fn session_for_key(&self, key: &str) -> Option<String> {
        self.lock().sessions.get(key).cloned()
    }

    // ---- persistence -----------------------------------------------------

    /// Persist both cursors (TS `saveState`). Failures are logged.
    pub(crate) fn save_state(&self) {
        let (last, agent) = {
            let st = self.lock();
            (
                st.last_timestamp.clone(),
                serde_json::to_string(&st.last_agent_timestamp),
            )
        };
        if let Err(e) = self.db.set_router_state(LAST_TIMESTAMP_KEY, &last) {
            tracing::error!(error = %e, "failed to save last_timestamp");
        }
        match agent {
            Ok(json) => {
                if let Err(e) = self.db.set_router_state(LAST_AGENT_TIMESTAMP_KEY, &json) {
                    tracing::error!(error = %e, "failed to save last_agent_timestamp");
                }
            }
            Err(e) => tracing::error!(error = %e, "failed to encode last_agent_timestamp"),
        }
    }

    /// The lane's agent cursor without recovery (`''` when unset).
    pub fn cursor(&self, jid: &str) -> String {
        self.lock()
            .last_agent_timestamp
            .get(jid)
            .cloned()
            .unwrap_or_default()
    }

    /// Set the lane's agent cursor and persist.
    pub(crate) fn set_cursor(&self, jid: &str, ts: &str) {
        self.lock()
            .last_agent_timestamp
            .insert(jid.to_string(), ts.to_string());
        self.save_state();
    }

    /// The lane's cursor, recovering it from the last bot reply when it is
    /// missing (new lane, corrupted state, restart) — TS `getOrRecoverCursor`.
    pub(crate) fn get_or_recover_cursor(&self, jid: &str) -> String {
        let existing = self.cursor(jid);
        if !existing.is_empty() {
            return existing;
        }
        match self
            .db
            .get_last_bot_message_timestamp(jid, &self.config.assistant_name)
        {
            Ok(Some(bot_ts)) if !bot_ts.is_empty() => {
                tracing::info!(chat_jid = jid, recovered_from = %bot_ts, "Recovered message cursor from last bot reply");
                self.set_cursor(jid, &bot_ts);
                bot_ts
            }
            Ok(_) => String::new(),
            Err(e) => {
                tracing::warn!(chat_jid = jid, error = %e, "cursor recovery failed");
                String::new()
            }
        }
    }

    /// Record a lane's session (TS `persistSession`). Ephemeral lanes keep
    /// nothing.
    pub(crate) fn persist_session(
        &self,
        group: &RegisteredGroup,
        session_id: &str,
        fingerprint: &str,
        usage: Option<&SessionUsage>,
    ) {
        if !group.should_persist_session() || session_id.is_empty() {
            return;
        }
        let key = group.session_key().to_string();
        self.lock()
            .sessions
            .insert(key.clone(), session_id.to_string());
        if let Err(e) = self.db.set_session(&key, session_id, Some(fingerprint)) {
            tracing::error!(group = %group.name, error = %e, "failed to persist session");
            return;
        }
        // Advisory: a bad usage write never fails the turn.
        let context = usage.map(SessionUsage::context_size).unwrap_or(0);
        if context > 0 {
            if let Err(e) = self.db.record_session_usage(&key, context) {
                tracing::warn!(group = %group.name, error = %e, "Failed to record session usage");
            }
        }
    }

    /// Drop a lane's session in memory *and* in the database (TS
    /// `clearSessionFor`).
    pub(crate) fn clear_session_for(&self, group: &RegisteredGroup) {
        let key = group.session_key().to_string();
        let had = self.lock().sessions.remove(&key).is_some();
        if let Err(e) = self.db.delete_session(&key) {
            tracing::error!(group = %group.name, error = %e, "failed to delete session");
        }
        if had {
            self.audit.record(talon_core::audit::event(
                "session.cleared",
                &group.folder,
                Some(&key),
                "info",
                serde_json::json!({ "group": group.name }),
            ));
        }
    }

    /// Store an inbound message, creating a minimal chat row if the
    /// channel never reported the chat (foreign key).
    pub(crate) fn store_message(&self, msg: &NewMessage) {
        if self.db.store_message(msg).is_ok() {
            return;
        }
        let meta = ChatMetadata {
            chat_jid: msg.chat_jid.clone(),
            timestamp: msg.timestamp.clone(),
            name: None,
            channel: None,
            is_group: None,
        };
        let result = self
            .db
            .store_chat_metadata(&meta)
            .and_then(|()| self.db.store_message(msg));
        if let Err(e) = result {
            tracing::error!(chat_jid = %msg.chat_jid, error = %e, "failed to store message");
        }
    }

    /// Register (or update) a lane.
    ///
    /// - The folder must be valid (else the registration is refused).
    /// - `persist`: write to `registered_groups`; when another JID already
    ///   owns the folder (lanes sharing a folder, e.g. `http:copilot:*`) the
    ///   lane stays in memory.
    /// - `create_template`: create `logs/` and copy the `CLAUDE.md` template
    ///   (TS `registerGroup`, used for IPC registrations).
    pub(crate) fn register_group_inner(
        &self,
        jid: &str,
        group: RegisteredGroup,
        persist: bool,
        create_template: bool,
    ) -> Result<()> {
        let group_dir = match group_folder_path(&self.config.groups_dir, &group.folder) {
            Ok(dir) => dir,
            Err(e) => {
                tracing::warn!(jid, folder = %group.folder, error = %e, "Rejecting group registration with invalid folder");
                return Err(e);
            }
        };
        for key in [group.session_key.as_deref(), group.ipc_key.as_deref()]
            .into_iter()
            .flatten()
        {
            talon_core::paths::assert_valid_group_folder(key)?;
        }

        let mut persisted = false;
        if persist {
            match self.db.set_registered_group(jid, &group) {
                Ok(()) => persisted = true,
                Err(Error::InvalidInput(reason)) => {
                    tracing::debug!(jid, %reason, "lane shares its folder; keeping it in memory");
                }
                Err(e) => {
                    tracing::error!(jid, error = %e, "failed to persist group registration");
                    return Err(e);
                }
            }
        }
        {
            let mut st = self.lock();
            if persisted {
                st.persisted.insert(jid.to_string());
            }
            st.groups.insert(jid.to_string(), group.clone());
        }

        if let Err(e) = std::fs::create_dir_all(group_dir.join("logs")) {
            tracing::warn!(jid, folder = %group.folder, error = %e, "cannot create group folder");
        }
        if create_template {
            self.install_claude_md(&group_dir, &group);
        }
        tracing::info!(jid, name = %group.name, folder = %group.folder, persisted, "Group registered");
        Ok(())
    }

    /// Copy the `CLAUDE.md` template into a new group folder (fixes #1391
    /// in TS). Never follows or replaces an existing entry (the folder is
    /// agent-writable, so a planted symlink must not redirect the write).
    fn install_claude_md(&self, group_dir: &Path, group: &RegisteredGroup) {
        let target = group_dir.join("CLAUDE.md");
        if std::fs::symlink_metadata(&target).is_ok() {
            return;
        }
        let template = self
            .config
            .groups_dir
            .join(if group.is_main { "main" } else { "global" })
            .join("CLAUDE.md");
        let Ok(mut content) = std::fs::read_to_string(&template) else {
            return;
        };
        let name = &self.config.assistant_name;
        if name != "Andy" {
            content = content
                .lines()
                .map(|l| {
                    if l == "# Andy" {
                        format!("# {name}")
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + if content.ends_with('\n') { "\n" } else { "" };
            content = content.replace("You are Andy", &format!("You are {name}"));
        }
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .and_then(|mut f| std::io::Write::write_all(&mut f, content.as_bytes()));
        match written {
            Ok(()) => tracing::info!(folder = %group.folder, "Created CLAUDE.md from template"),
            Err(e) => tracing::warn!(folder = %group.folder, error = %e, "cannot create CLAUDE.md"),
        }
    }

    /// Drop an in-memory lane (never a persisted one).
    pub(crate) fn unregister_lane(&self, jid: &str) -> bool {
        {
            let mut st = self.lock();
            if st.persisted.contains(jid) || st.groups.remove(jid).is_none() {
                return false;
            }
            st.last_agent_timestamp.remove(jid);
        }
        self.save_state();
        true
    }

    /// Redact, format for the owning channel's dialect and send. Returns
    /// whether anything was sent (empty after stripping `<internal>`).
    ///
    /// # Errors
    /// No connected channel owns `jid`, or the channel failed.
    pub async fn send_outbound(&self, jid: &str, raw: &str) -> Result<bool> {
        let redacted = self.redactor.redact(raw);
        let channels = self.channels();
        talon_router::send_formatted(&channels, jid, &redacted).await
    }
}

/// TS `loadState`: cursors, sessions and registered groups.
fn load_state(db: &Db) -> Result<State> {
    let last_timestamp = db.get_router_state(LAST_TIMESTAMP_KEY)?.unwrap_or_default();
    let last_agent_timestamp = match db.get_router_state(LAST_AGENT_TIMESTAMP_KEY)? {
        None => BTreeMap::new(),
        Some(raw) if raw.trim().is_empty() => BTreeMap::new(),
        Some(raw) => match serde_json::from_str::<BTreeMap<String, String>>(&raw) {
            Ok(map) => map,
            Err(_) => {
                tracing::warn!("Corrupted last_agent_timestamp in DB, resetting");
                BTreeMap::new()
            }
        },
    };
    let sessions = db.get_all_sessions()?;
    let groups = db.get_all_registered_groups()?;
    let persisted = groups.keys().cloned().collect();
    Ok(State {
        groups,
        persisted,
        sessions,
        last_timestamp,
        last_agent_timestamp,
        token_deadlines: HashMap::new(),
        run_tokens: HashMap::new(),
    })
}
