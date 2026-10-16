//! The host orchestrator.
//!
//! [`Orchestrator`] owns the host's in-memory state (registered lanes,
//! session ids, message cursors) and implements
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
use std::os::fd::{AsFd, BorrowedFd};
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
use crate::output_limits::OutputLimits;
use crate::safe_fs;

/// Router-state key of the global "seen" cursor.
pub const LAST_TIMESTAMP_KEY: &str = "last_timestamp";
/// Router-state key of the per-lane agent cursors (JSON object).
pub const LAST_AGENT_TIMESTAMP_KEY: &str = "last_agent_timestamp";
/// Per-group memory file bootstrapped from the `main` / `global` template.
const CLAUDE_MD: &str = "CLAUDE.md";
/// Largest `CLAUDE.md` template the host copies.
const MAX_TEMPLATE_BYTES: u64 = 256 * 1024;

/// Tunables that are not part of `TalonConfig`.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Close a scheduled task's container this long after its result.
    pub task_close_delay: Duration,
    /// Close a `/compact` container this long after it finished.
    pub command_close_delay: Duration,
    /// Added to the run's lifetime when sizing the LLM token TTL.
    pub token_ttl_margin: Duration,
    /// Shutdown grace for running lane jobs.
    pub shutdown_grace: Duration,
    /// Caps on agent output (MYTH-07).
    pub output_limits: OutputLimits,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            task_close_delay: Duration::from_secs(10),
            command_close_delay: Duration::from_secs(10),
            token_ttl_margin: Duration::from_secs(5 * 60),
            shutdown_grace: Duration::from_secs(10),
            output_limits: OutputLimits::default(),
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

/// Mutable orchestrator state.
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
    /// Session key -> number of times its session was cleared. A run keeps
    /// the session it ends with only if no reset happened meanwhile.
    pub(crate) session_epochs: HashMap<String, u64>,
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
    /// Build the orchestrator and load its state from the database.
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

    /// The first channel owning `jid`.
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

    /// Persist both cursors. Failures are logged.
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
    /// missing (new lane, corrupted state, restart).
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

    /// Record a lane's session. Ephemeral lanes keep nothing.
    #[cfg(test)]
    pub(crate) fn persist_session(
        &self,
        group: &RegisteredGroup,
        session_id: &str,
        fingerprint: &str,
        usage: Option<&SessionUsage>,
    ) {
        self.store_session(group, session_id, fingerprint, usage, None);
    }

    /// How often the session under `key` has been cleared so far.
    pub(crate) fn session_epoch(&self, key: &str) -> u64 {
        self.lock().session_epochs.get(key).copied().unwrap_or(0)
    }

    /// [`Self::persist_session`] for a run that started at session `epoch`:
    /// when the lane's session was cleared during the run (`/session/reset`,
    /// `/reset`), the run's session is not kept, so the reset sticks.
    pub(crate) fn persist_run_session(
        &self,
        group: &RegisteredGroup,
        session_id: &str,
        fingerprint: &str,
        usage: Option<&SessionUsage>,
        epoch: u64,
    ) {
        self.store_session(group, session_id, fingerprint, usage, Some(epoch));
    }

    fn store_session(
        &self,
        group: &RegisteredGroup,
        session_id: &str,
        fingerprint: &str,
        usage: Option<&SessionUsage>,
        epoch: Option<u64>,
    ) {
        if !group.should_persist_session() || session_id.is_empty() {
            return;
        }
        let key = group.session_key().to_string();
        {
            let mut st = self.lock();
            let current = st.session_epochs.get(&key).copied().unwrap_or(0);
            if epoch.is_some_and(|e| e != current) {
                tracing::info!(group = %group.name, "Session was cleared during the run; not keeping the run's session");
                return;
            }
            st.sessions.insert(key.clone(), session_id.to_string());
        }
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

    /// Drop a lane's session in memory *and* in the database.
    pub(crate) fn clear_session_for(&self, group: &RegisteredGroup) {
        let key = group.session_key().to_string();
        let had = {
            let mut st = self.lock();
            *st.session_epochs.entry(key.clone()).or_default() += 1;
            st.sessions.remove(&key).is_some()
        };
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
    ///   (used for IPC registrations).
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

        self.prepare_group_dir(&group_dir, &group, create_template);
        tracing::info!(jid, name = %group.name, folder = %group.folder, persisted, "Group registered");
        Ok(())
    }

    /// Create `groups/<folder>/logs` and, with `create_template`, bootstrap
    /// `CLAUDE.md`. Group folders are agent-writable, so everything below
    /// `groups/` is handled descriptor-relatively without following
    /// symlinks (MYTH-10): a planted `groups/<folder>` or `logs` symlink is
    /// refused instead of redirecting the host's writes.
    fn prepare_group_dir(&self, group_dir: &Path, group: &RegisteredGroup, create_template: bool) {
        let groups_dir = &self.config.groups_dir;
        let prepared = std::fs::create_dir_all(groups_dir)
            .and_then(|()| safe_fs::open_root(groups_dir))
            .and_then(|groups| {
                let dir = safe_fs::ensure_dir_at(groups.as_fd(), &group.folder)?;
                Ok((groups, dir))
            });
        let (groups, dir) = match prepared {
            Ok(fds) => fds,
            Err(e) => {
                tracing::warn!(folder = %group.folder, dir = %group_dir.display(), error = %e, "cannot create group folder");
                return;
            }
        };
        if let Err(e) = safe_fs::ensure_dir_at(dir.as_fd(), "logs") {
            tracing::warn!(folder = %group.folder, error = %e, "cannot create group logs folder");
        }
        if create_template {
            self.install_claude_md(groups.as_fd(), dir.as_fd(), group);
        }
    }

    /// Copy the `CLAUDE.md` template into a new group folder. Never follows or replaces an existing entry (the folder is
    /// agent-writable, so a planted symlink must not redirect the write:
    /// the file is created with `O_CREAT | O_EXCL | O_NOFOLLOW`), and the
    /// template itself (`groups/main` is writable by the main agent) is
    /// read only when it is a regular, size-capped file.
    fn install_claude_md(
        &self,
        groups: BorrowedFd<'_>,
        dir: BorrowedFd<'_>,
        group: &RegisteredGroup,
    ) {
        match safe_fs::entry_exists_at(dir, CLAUDE_MD) {
            Ok(false) => {}
            Ok(true) => return,
            Err(e) => {
                tracing::warn!(folder = %group.folder, error = %e, "cannot inspect CLAUDE.md");
                return;
            }
        }
        let template_folder = if group.is_main { "main" } else { "global" };
        let Some(mut content) = read_template(groups, template_folder) else {
            return;
        };
        let name = &self.config.assistant_name;
        if name != "Talon" {
            content = content
                .lines()
                .map(|l| {
                    if l == "# Talon" {
                        format!("# {name}")
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + if content.ends_with('\n') { "\n" } else { "" };
            content = content.replace("You are Talon", &format!("You are {name}"));
        }
        match safe_fs::create_new_at(dir, CLAUDE_MD, content.as_bytes()) {
            Ok(()) => tracing::info!(folder = %group.folder, "Created CLAUDE.md from template"),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                tracing::debug!(folder = %group.folder, "CLAUDE.md appeared concurrently; kept");
            }
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

/// Read `groups/<template_folder>/CLAUDE.md`: neither the folder nor the
/// file may be a symlink, the file must be a regular, size-capped UTF-8
/// file (a FIFO cannot block the open). Missing templates are silent.
fn read_template(groups: BorrowedFd<'_>, template_folder: &str) -> Option<String> {
    let folder = match safe_fs::open_dir_at(groups, template_folder) {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(template = template_folder, error = %e, "unsafe CLAUDE.md template folder; not copied");
            return None;
        }
    };
    let file = match safe_fs::open_regular_at(folder.as_fd(), CLAUDE_MD, MAX_TEMPLATE_BYTES) {
        Ok((file, _)) => file,
        Err(safe_fs::OpenRefusal::Missing) => return None,
        Err(safe_fs::OpenRefusal::Rejected(reason)) => {
            tracing::warn!(template = template_folder, %reason, "unsafe CLAUDE.md template; not copied");
            return None;
        }
    };
    match safe_fs::read_capped(file, MAX_TEMPLATE_BYTES).map(String::from_utf8) {
        Ok(Ok(text)) => Some(text),
        Ok(Err(_)) => {
            tracing::warn!(
                template = template_folder,
                "CLAUDE.md template is not UTF-8; not copied"
            );
            None
        }
        Err(e) => {
            tracing::warn!(template = template_folder, error = %e, "cannot read CLAUDE.md template");
            None
        }
    }
}

/// Load cursors, sessions and registered groups from the database.
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
        session_epochs: HashMap::new(),
        token_deadlines: HashMap::new(),
        run_tokens: HashMap::new(),
    })
}
