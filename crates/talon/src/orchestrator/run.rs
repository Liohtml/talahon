//! One agent run (message runs and the container part of scheduled-task
//! runs).
//!
//! 1. Effective provider: `.env` defaults merged with the group's config.
//!    Without vLLM (or without the LLM gateway) the run fails before any
//!    container starts, with an error that says what to configure.
//! 2. Session: resume the lane's session unless the provider fingerprint
//!    stored with it differs (a transcript produced by another model is
//!    not resumed — the session is dropped instead).
//! 3. Snapshots: `current_tasks.json` / `available_groups.json` in the
//!    lane's IPC namespace. Tasks are filtered per lane (MYTH-03): a
//!    non-main namespace only sees tasks whose chat JID belongs to one of
//!    its own lanes, never those of other lanes sharing the group folder,
//!    and only those are loaded from the database (N-3).
//! 4. A per-run gateway token (TTL = the run's maximum lifetime + margin)
//!    goes into `ContainerInput.llm` — stdin only — and is revoked when the
//!    run ends. Its label is the lane's IPC key (per-lane prefix-cache salt
//!    and usage accounting in the gateway; N-6).
//! 5. Output frames stream to the caller's handler in order over a
//!    bounded channel (backpressure); every frame passes the run's
//!    [`OutputGuard`] first (result text capped per frame, run aborted —
//!    container stopped, rest dropped — when it exceeds its per-run caps;
//!    MYTH-07). Session ids are persisted as they arrive, and only when
//!    they are valid (at most 128 bytes of `[A-Za-z0-9_-]`; N-5).
//! 6. Errors that say the stored session is gone clear it so the queue's
//!    retry starts fresh.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

use regex::Regex;
use talon_container::{RunOutcome, RunSpec};
use talon_core::protocol::{ContainerInput, ContainerOutput, OutputStatus};
use talon_core::provider::{effective_vllm, merge_container_config, provider_fingerprint};
use talon_core::types::{AvailableGroup, RegisteredGroup, ScheduledTask};
use talon_router::AgentOutputHandler;
use talon_scheduler::RunningContainer;
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::Orchestrator;
use crate::agent::{AgentOutcome, StartHook};
use crate::output_limits::{
    Admission, OUTPUT_CHANNEL_CAPACITY, OutputGuard, cap_text, sanitize_session_id,
};

/// How long an aborted run's container gets to stop before the run is left
/// to the runner's own timeout handling.
const ABORT_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// The container of the current run, once started (stopped on abort).
type ContainerSlot = Arc<Mutex<Option<Arc<dyn RunningContainer>>>>;

/// Error reported when no vLLM provider is configured.
pub const VLLM_NOT_CONFIGURED: &str = "vLLM provider is not configured: set TALON_VLLM_BASE_URL and \
     TALON_VLLM_MODEL in .env (run `talon doctor`)";
/// Error reported when the LLM gateway is not running.
pub const GATEWAY_NOT_RUNNING: &str =
    "LLM gateway is not running, so containers cannot reach vLLM (run `talon doctor`)";

/// Errors meaning the stored session no longer exists
/// (`/no conversation found|ENOENT.*\.jsonl|session.*not found/i`).
static STALE_SESSION: LazyLock<Regex> = LazyLock::new(|| {
    // Static pattern: compiling it cannot fail.
    #[allow(clippy::expect_used)]
    Regex::new(r"(?i)no conversation found|ENOENT.*\.jsonl|session.*not found")
        .expect("static stale-session regex")
});

/// Whether `error` says the resumed session is stale/corrupt.
pub fn is_stale_session_error(error: &str) -> bool {
    STALE_SESSION.is_match(error)
}

/// How a run treats sessions and what it tells the container.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// `ContainerInput.is_scheduled_task`.
    pub scheduled_task: bool,
    /// Pre-flight script of a scheduled task.
    pub script: Option<String>,
    /// Resume the lane's stored session (if any).
    pub resume_session: bool,
    /// Persist new session ids and clear stale / foreign-provider sessions
    /// (message runs; scheduled tasks only borrow the session).
    pub manage_session: bool,
}

impl RunOptions {
    /// A chat (message-lane) run.
    pub fn message() -> Self {
        Self {
            scheduled_task: false,
            script: None,
            resume_session: true,
            manage_session: true,
        }
    }

    /// A scheduled-task run.
    pub fn task(script: Option<String>, resume_group_session: bool) -> Self {
        Self {
            scheduled_task: true,
            script: script.filter(|s| !s.trim().is_empty()),
            resume_session: resume_group_session,
            manage_session: false,
        }
    }
}

impl Orchestrator {
    /// Groups the agent may see (`available_groups.json`).
    pub fn available_groups(&self) -> Vec<AvailableGroup> {
        let groups = self.groups_snapshot();
        match self.db.get_all_chats() {
            Ok(chats) => talon_router::available_groups(&chats, &groups),
            Err(e) => {
                tracing::warn!(error = %e, "cannot list chats for available_groups");
                Vec::new()
            }
        }
    }

    /// The tasks a namespace's snapshot shows, loaded with the narrowest
    /// query (see [`snapshot_task_query`]). A database error yields an
    /// empty list (logged).
    pub(crate) fn snapshot_tasks(&self, query: &TaskQuery) -> Vec<ScheduledTask> {
        let loaded = match query {
            TaskQuery::All => self.db.get_all_tasks(),
            TaskQuery::ForJids(jids) => self.db.get_tasks_for_jids(jids),
        };
        match loaded {
            Ok(tasks) => tasks,
            Err(e) => {
                tracing::warn!(error = %e, "cannot list tasks for snapshot");
                Vec::new()
            }
        }
    }

    /// Write `current_tasks.json` into IPC namespace `ipc_key`. A main
    /// namespace sees every task; any other only the tasks of its own lanes
    /// (`extra_jid`: the running lane, in case it is not registered), and
    /// only those are loaded from the database (N-3: a container start of
    /// a non-main lane never loads the whole task table).
    pub(crate) fn write_lane_tasks_snapshot_for(
        &self,
        ipc_key: &str,
        groups: &HashMap<String, RegisteredGroup>,
        extra_jid: Option<&str>,
    ) {
        // Main-ness comes from the registry only, never from `extra_jid`.
        let (mut jids, is_main) = lane_namespace(groups, ipc_key);
        if let Some(jid) = extra_jid {
            if !jids.iter().any(|j| j == jid) {
                jids.push(jid.to_string());
            }
        }
        let tasks = self.snapshot_tasks(&snapshot_task_query(is_main, &jids));
        if let Err(e) = talon_container::write_lane_tasks_snapshot(
            &self.config.data_dir,
            ipc_key,
            is_main,
            &jids,
            &tasks,
        ) {
            tracing::warn!(ipc_key, error = %e, "failed to write tasks snapshot");
        }
    }

    /// Write both snapshots for a run of `group` in lane `chat_jid`.
    fn write_snapshots(&self, group: &RegisteredGroup, chat_jid: &str) {
        let groups = self.groups_snapshot();
        let extra = (groups.get(chat_jid).map(RegisteredGroup::ipc_key) != Some(group.ipc_key()))
            .then_some(chat_jid);
        self.write_lane_tasks_snapshot_for(group.ipc_key(), &groups, extra);
        let available = self.available_groups();
        if let Err(e) = talon_container::write_groups_snapshot(
            &self.config.data_dir,
            &group.folder,
            group.is_main,
            &available,
            Some(group.ipc_key()),
        ) {
            tracing::warn!(group = %group.name, error = %e, "failed to write groups snapshot");
        }
    }

    /// Stop a run whose output exceeded its caps (MYTH-07): log, audit and
    /// stop the container (bounded by [`ABORT_STOP_TIMEOUT`]).
    async fn abort_run(
        &self,
        group: &RegisteredGroup,
        chat_jid: &str,
        slot: &ContainerSlot,
        reason: &str,
        guard: &OutputGuard,
    ) {
        tracing::error!(
            group = %group.name,
            chat_jid,
            frames = guard.frames(),
            result_bytes = guard.result_bytes(),
            %reason,
            "agent output limit exceeded; stopping the container"
        );
        self.audit.record(talon_core::audit::event(
            "container.output_limit",
            &group.folder,
            Some(chat_jid),
            "warn",
            serde_json::json!({
                "reason": reason,
                "frames": guard.frames(),
                "resultBytes": guard.result_bytes(),
            }),
        ));
        let container = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
        match container {
            Some(container) => {
                match tokio::time::timeout(ABORT_STOP_TIMEOUT, container.stop()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(container = container.name(), error = %e, "cannot stop container")
                    }
                    Err(_) => {
                        tracing::warn!(container = container.name(), "container stop timed out")
                    }
                }
            }
            None => tracing::warn!(chat_jid, "aborted run has no registered container"),
        }
    }

    /// The session a run should resume (including the provider check).
    fn resolve_session(
        &self,
        group: &RegisteredGroup,
        fingerprint: &str,
        opts: &RunOptions,
    ) -> Option<String> {
        if !opts.resume_session || !group.should_persist_session() {
            return None;
        }
        let key = group.session_key();
        let session_id = self.session_for_key(key)?;
        match self.db.get_session_provider(key) {
            Ok(Some(stored)) if stored != fingerprint => {
                tracing::warn!(
                    group = %group.name,
                    session_provider = %stored,
                    provider = %fingerprint,
                    "Provider changed since session was created — starting a fresh session"
                );
                if opts.manage_session {
                    self.clear_session_for(group);
                }
                None
            }
            Ok(_) => Some(session_id),
            Err(e) => {
                tracing::warn!(group = %group.name, error = %e, "cannot read session provider; starting fresh");
                None
            }
        }
    }

    /// Run the agent for `group` in lane `chat_jid`, streaming every output
    /// frame to `sink`. Never fails; see [`AgentOutcome`].
    pub async fn run_agent(
        &self,
        group: &RegisteredGroup,
        prompt: &str,
        chat_jid: &str,
        opts: RunOptions,
        sink: &mut dyn AgentOutputHandler,
    ) -> AgentOutcome {
        let merged = merge_container_config(
            &self.config.provider_defaults,
            group.container_config.as_ref(),
        );
        let Some(vllm) = effective_vllm(&merged).cloned() else {
            tracing::error!(group = %group.name, "{VLLM_NOT_CONFIGURED}");
            return AgentOutcome::not_started(VLLM_NOT_CONFIGURED);
        };
        let Some(llm) = self.llm.clone() else {
            tracing::error!(group = %group.name, "{GATEWAY_NOT_RUNNING}");
            return AgentOutcome::not_started(GATEWAY_NOT_RUNNING);
        };
        let fingerprint = provider_fingerprint(&merged);
        let session_id = self.resolve_session(group, &fingerprint, &opts);
        let session_epoch = self.session_epoch(group.session_key());

        self.write_snapshots(group, chat_jid);
        // Follow-ups an earlier container left unread are sent again from
        // the message store (the lane cursor never moved past them), and a
        // stale `_close` would end this container after its first turn.
        match talon_scheduler::ipc_input::clear_inbox(&self.config.data_dir, group.ipc_key()) {
            Ok(0) => {}
            Ok(n) => tracing::info!(group = %group.name, removed = n, "cleared leftover IPC input"),
            Err(e) => tracing::warn!(group = %group.name, error = %e, "cannot clear the IPC inbox"),
        }

        let ttl = self
            .launcher
            .hard_timeout(&merged)
            .saturating_add(self.config.idle_timeout)
            .saturating_add(self.settings.token_ttl_margin);
        // Label = the lane's IPC key, not the folder: the gateway derives
        // the per-label prefix-cache salt and usage stats from it, so lanes
        // sharing a folder (CoPilot analysts) get separate caches (N-6).
        let (token, endpoint) = llm.issue(group.ipc_key(), ttl, &vllm);
        let input = ContainerInput {
            prompt: prompt.to_string(),
            session_id: session_id.clone(),
            group_folder: group.folder.clone(),
            chat_jid: chat_jid.to_string(),
            is_main: group.is_main,
            is_scheduled_task: opts.scheduled_task,
            assistant_name: Some(self.config.assistant_name.clone()),
            script: opts.script.clone(),
            llm: Some(endpoint),
            ephemeral: group.ephemeral_session,
            timezone: Some(self.config.timezone_name.clone()),
        };
        let spec = RunSpec::new(group.clone(), input).with_config(merged);

        if !opts.scheduled_task {
            let mut st = self.lock();
            st.token_deadlines
                .insert(chat_jid.to_string(), Instant::now() + ttl);
            st.run_tokens
                .insert(chat_jid.to_string(), (token.clone(), ttl));
        }
        let slot: ContainerSlot = Arc::new(Mutex::new(None));
        let hook: StartHook = {
            let queue = self.queue.clone();
            let jid = chat_jid.to_string();
            let ipc_key = group.ipc_key().to_string();
            let slot = slot.clone();
            Box::new(move |container| {
                *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(container.clone());
                queue.register_process(&jid, container, &ipc_key);
            })
        };

        let limits = self.settings.output_limits;
        let (tx, rx) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
        let launch = self.launcher.launch(spec, tx, hook);
        let consume = async {
            let mut rx = rx;
            let mut guard = OutputGuard::new(limits);
            let mut last_result: Option<String> = None;
            let mut frame_error: Option<String> = None;
            let mut aborted: Option<String> = None;
            while let Some(output) = rx.recv().await {
                let output = match guard.admit(output) {
                    Admission::Deliver(output) => output,
                    Admission::Abort(reason) => {
                        aborted = Some(reason);
                        break;
                    }
                };
                if opts.manage_session {
                    if let Some(id) = output.new_session_id.as_deref().filter(|s| !s.is_empty()) {
                        self.persist_run_session(
                            group,
                            id,
                            &fingerprint,
                            output.usage.as_ref(),
                            session_epoch,
                        );
                    }
                }
                if let Some(result) = output.result.as_ref().filter(|r| !r.is_empty()) {
                    last_result = Some(result.clone());
                }
                if output.status == OutputStatus::Error {
                    frame_error.clone_from(&output.error);
                }
                sink.on_output(&output).await;
            }
            // Dropping the receiver makes every further send fail: the
            // launcher discards the rest of an aborted run's frames.
            drop(rx);
            if let Some(reason) = &aborted {
                self.abort_run(group, chat_jid, &slot, reason, &guard).await;
                sink.on_output(&ContainerOutput::error(reason.clone()))
                    .await;
            }
            (last_result, frame_error, aborted)
        };
        let (mut result, (streamed_result, frame_error, aborted)) = tokio::join!(launch, consume);
        if let Some(reason) = aborted {
            result.status = OutputStatus::Error;
            result.error = Some(reason);
        }
        // The runner's own copies are as untrusted as the frames: the
        // session id is validated again before it is persisted (N-5).
        result.new_session_id = sanitize_session_id(result.new_session_id.take());
        result.error = result
            .error
            .as_deref()
            .map(|e| cap_text(e, limits.max_error_bytes));
        result.last_result = result
            .last_result
            .as_deref()
            .map(|r| cap_text(r, limits.max_result_bytes));

        llm.revoke(&token);
        if !opts.scheduled_task {
            let mut st = self.lock();
            st.token_deadlines.remove(chat_jid);
            st.run_tokens.remove(chat_jid);
        }

        if opts.manage_session {
            // Usually already persisted from the streamed frame; rewriting
            // it would reset the usage recorded with it.
            if let Some(id) = result
                .new_session_id
                .as_deref()
                .filter(|id| self.session_for_key(group.session_key()).as_deref() != Some(*id))
            {
                self.persist_run_session(
                    group,
                    id,
                    &fingerprint,
                    result.usage.as_ref(),
                    session_epoch,
                );
            }
        }

        if result.status == OutputStatus::Error {
            let error = result
                .error
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());
            // The agent says so in its error frame; the runner's own error
            // only quotes the end of stderr, where later log lines may have
            // pushed the reason out.
            let stale = is_stale_session_error(&error)
                || frame_error.as_deref().is_some_and(is_stale_session_error);
            if opts.manage_session && session_id.is_some() && stale {
                tracing::warn!(
                    group = %group.name,
                    error = %error,
                    "Stale session detected — clearing for next retry"
                );
                self.clear_session_for(group);
            }
            tracing::error!(group = %group.name, error = %error, "Container agent error");
        }

        AgentOutcome {
            status: result.status,
            error: result.error.clone(),
            last_result: streamed_result.or_else(|| result.last_result.clone()),
            new_session_id: result.new_session_id.clone(),
            usage: result.usage,
            launched: !matches!(
                result.outcome,
                RunOutcome::SetupFailed | RunOutcome::SpawnFailed
            ),
        }
    }
}

/// Which tasks a `current_tasks.json` snapshot loads from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskQuery {
    /// Every task (main namespaces only).
    All,
    /// Only the tasks whose chat JID is one of these (a non-main
    /// namespace's own lanes; empty = none, no database access).
    ForJids(Vec<String>),
}

/// The snapshot query of a namespace with lanes `jids`: [`TaskQuery::All`]
/// for main, otherwise a query filtered to `jids` (N-3) — never the whole
/// table, so a lane with many tasks of its own cannot make every other
/// lane's container start load them.
pub fn snapshot_task_query(is_main: bool, jids: &[String]) -> TaskQuery {
    if is_main {
        TaskQuery::All
    } else {
        TaskQuery::ForJids(jids.to_vec())
    }
}

/// The lanes of IPC namespace `ipc_key`: every registered JID whose
/// `ipc_key()` equals it (sorted), and whether the namespace counts as main.
/// It does only when every lane in it is main: lanes that disagree get the
/// restricted view (the IPC watcher refuses such a namespace altogether).
pub fn lane_namespace(
    groups: &HashMap<String, RegisteredGroup>,
    ipc_key: &str,
) -> (Vec<String>, bool) {
    let mut jids: Vec<String> = Vec::new();
    let mut all_main = true;
    for (jid, group) in groups {
        if group.ipc_key() == ipc_key {
            all_main &= group.is_main;
            jids.push(jid.clone());
        }
    }
    jids.sort();
    let is_main = all_main && !jids.is_empty();
    (jids, is_main)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_session_patterns_match_ts() {
        assert!(is_stale_session_error(
            "No conversation found with session ID abc"
        ));
        assert!(is_stale_session_error(
            "ENOENT: no such file or directory, open '/home/agent/.talon/sessions/x.jsonl'"
        ));
        assert!(is_stale_session_error("session 1234 not found"));
        assert!(is_stale_session_error("Session Not Found"));
        assert!(!is_stale_session_error("Container exited with code 1"));
        assert!(!is_stale_session_error("not found: model"));
    }

    fn lane(folder: &str, ipc_key: Option<&str>, is_main: bool) -> RegisteredGroup {
        RegisteredGroup {
            name: folder.into(),
            folder: folder.into(),
            trigger: "@Talon".into(),
            added_at: "2026-01-01T00:00:00.000Z".into(),
            container_config: None,
            requires_trigger: None,
            is_main,
            session_key: None,
            ipc_key: ipc_key.map(str::to_string),
            ephemeral_session: false,
            trusted_session_commands: false,
        }
    }

    #[test]
    fn lane_jids_are_the_registered_jids_of_one_namespace() {
        let mut groups = HashMap::new();
        groups.insert("tg:main".to_string(), lane("main", None, true));
        groups.insert("http:copilot".to_string(), lane("copilot", None, false));
        groups.insert(
            "http:copilot:u:alice".to_string(),
            lane("copilot", Some("copilot-u-alice"), false),
        );
        groups.insert(
            "http:copilot:u:bob".to_string(),
            lane("copilot", Some("copilot-u-bob"), false),
        );
        groups.insert(
            "http:copilot:investigate".to_string(),
            lane("copilot", Some("copilot-investigate"), false),
        );
        groups.insert(
            "http:copilot:investigate:2".to_string(),
            lane("copilot", Some("copilot-investigate"), false),
        );

        assert_eq!(
            lane_namespace(&groups, "copilot-u-alice"),
            (vec!["http:copilot:u:alice".to_string()], false)
        );
        // The shared folder does not merge lanes: only the base lane uses
        // the folder as its key.
        assert_eq!(
            lane_namespace(&groups, "copilot"),
            (vec!["http:copilot".to_string()], false)
        );
        assert_eq!(
            lane_namespace(&groups, "copilot-investigate"),
            (
                vec![
                    "http:copilot:investigate".to_string(),
                    "http:copilot:investigate:2".to_string()
                ],
                false
            )
        );
        assert_eq!(
            lane_namespace(&groups, "main"),
            (vec!["tg:main".to_string()], true)
        );
        assert_eq!(lane_namespace(&groups, "nobody"), (Vec::new(), false));

        // A non-main lane sharing main's namespace demotes it.
        groups.insert("tg:intruder".to_string(), lane("main", None, false));
        let (jids, is_main) = lane_namespace(&groups, "main");
        assert_eq!(jids.len(), 2);
        assert!(!is_main);
    }

    #[test]
    fn non_main_snapshots_query_only_their_own_lanes() {
        let jids = vec!["http:copilot:u:alice".to_string()];
        assert_eq!(snapshot_task_query(true, &jids), TaskQuery::All);
        assert_eq!(
            snapshot_task_query(false, &jids),
            TaskQuery::ForJids(jids.clone())
        );
        assert_eq!(
            snapshot_task_query(false, &[]),
            TaskQuery::ForJids(Vec::new())
        );
    }

    #[test]
    fn run_options() {
        let m = RunOptions::message();
        assert!(m.resume_session && m.manage_session && !m.scheduled_task);
        let t = RunOptions::task(Some("  ".into()), true);
        assert!(t.scheduled_task && t.resume_session && !t.manage_session);
        assert_eq!(t.script, None);
    }
}
