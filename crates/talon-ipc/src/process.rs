//! Request handling: authorization (policy AND baseline), semantic
//! validation, execution through the store / host, and auditing.
//!
//! Audit kinds (one event per request):
//!
//! | request          | allowed               | denied / rejected     | host or db failure    |
//! |------------------|-----------------------|-----------------------|-----------------------|
//! | message          | `ipc.message.allowed`*| `ipc.message.denied`  | `ipc.message.failed`  |
//! | task operations  | `ipc.task.allowed`    | `ipc.task.denied`     | `ipc.task.failed`     |
//! | register_group   | `ipc.register_group`  | `ipc.register_group`  | `ipc.register_group`  |
//!
//! (*) when [`IpcWatcherConfig::audit_allowed_messages`](crate::IpcWatcherConfig)
//! is set. Outcomes are `allowed`, `denied` or `error`; denials carry
//! `details.stage = "authorization" | "validation"`. Message text and task
//! prompts are never written to the audit log (only their lengths).
//! Rows are subject to the per-namespace audit rate limit (see
//! `ratelimit`); applied task operations are always written. Targets and
//! reasons are passed through `sanitize_for_log` first.
//!
//! Task ownership (MYTH-03): every task created over IPC gets an owner
//! record — the source namespace's IPC key — and pause/resume/cancel/update
//! are authorized against that owner, not the task's folder.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use serde_json::{Map, Value, json};
use talon_core::audit::event;
use talon_core::protocol::{IpcOutbound, IpcTask};
use talon_core::schedule::first_run;
use talon_core::time::{now_iso, to_iso};
use talon_core::types::{RegisteredGroup, ScheduledTask, TaskStatus, TaskUpdate};
use talon_security::ipc_authz::{IpcDecision, TaskOwner};

use crate::authz::{decide_message, decide_task};
use crate::host::SourceIdentity;
use crate::json::{
    sanitize_for_log, task_type_name, truncate_reason, validate_outbound_shape, validate_task_shape,
};
use crate::watcher::IpcWatcher;

/// Result of handling one IPC request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcOutcome {
    /// Authorized, valid and carried out.
    Applied,
    /// Refused by authorization (policy engine or baseline).
    Denied(String),
    /// Authorized but semantically invalid (bad schedule, duplicate task id,
    /// forbidden container config, malformed fields, ...).
    Rejected(String),
    /// Authorized and valid, but the host or the database failed.
    Failed(String),
}

impl IpcOutcome {
    /// True for [`IpcOutcome::Applied`].
    pub fn is_applied(&self) -> bool {
        matches!(self, IpcOutcome::Applied)
    }
}

struct Kinds {
    allowed: &'static str,
    denied: &'static str,
    failed: &'static str,
    /// Applied requests of this family change state and are always
    /// audited, regardless of the rate limit.
    applied_is_priority: bool,
}

const MESSAGE_KINDS: Kinds = Kinds {
    allowed: "ipc.message.allowed",
    denied: "ipc.message.denied",
    failed: "ipc.message.failed",
    applied_is_priority: false,
};
const TASK_KINDS: Kinds = Kinds {
    allowed: "ipc.task.allowed",
    denied: "ipc.task.denied",
    failed: "ipc.task.failed",
    applied_is_priority: true,
};
const REGISTER_KINDS: Kinds = Kinds {
    allowed: "ipc.register_group",
    denied: "ipc.register_group",
    failed: "ipc.register_group",
    applied_is_priority: true,
};

/// An existing task and its recorded owner.
type OwnedTask = (ScheduledTask, Option<String>);

#[derive(Debug, Clone, Copy)]
enum StatusOp {
    Pause,
    Resume,
    Cancel,
}

impl StatusOp {
    fn as_str(self) -> &'static str {
        match self {
            StatusOp::Pause => "pause",
            StatusOp::Resume => "resume",
            StatusOp::Cancel => "cancel",
        }
    }
}

fn generate_task_id() -> String {
    let millis = chrono::Utc::now().timestamp_millis();
    let rand: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(6)
        .collect();
    format!("task-{millis}-{rand}")
}

impl IpcWatcher {
    fn record(
        &self,
        kinds: &Kinds,
        source: &SourceIdentity,
        target: Option<&str>,
        outcome: &IpcOutcome,
        mut details: Map<String, Value>,
    ) {
        details.insert("ipcKey".into(), json!(source.ipc_key));
        details.insert("isMain".into(), json!(source.is_main));
        let (kind, result) = match outcome {
            IpcOutcome::Applied => (kinds.allowed, "allowed"),
            IpcOutcome::Denied(r) => {
                details.insert("stage".into(), json!("authorization"));
                details.insert("reason".into(), json!(truncate_reason(r)));
                (kinds.denied, "denied")
            }
            IpcOutcome::Rejected(r) => {
                details.insert("stage".into(), json!("validation"));
                details.insert("reason".into(), json!(truncate_reason(r)));
                (kinds.denied, "denied")
            }
            IpcOutcome::Failed(e) => {
                details.insert("error".into(), json!(truncate_reason(e)));
                (kinds.failed, "error")
            }
        };
        let ty = details
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        // JIDs may carry bidi / control characters: neutralize before they
        // reach the audit log or a log line.
        let target = target.map(sanitize_for_log);
        let priority = kinds.applied_is_priority && outcome.is_applied();
        let ev = event(
            kind,
            &source.folder,
            target.as_deref(),
            result,
            Value::Object(details),
        );
        let written = self.audit_event(&source.ipc_key, &source.folder, ev, priority);
        if !written {
            // Over the namespace's audit budget: keep the logs quiet too.
            tracing::debug!(
                source = %source.folder, ipc_key = %source.ipc_key, kind = ty, target = ?target,
                result, "IPC request (audit suppressed by rate limit)"
            );
            return;
        }
        match outcome {
            IpcOutcome::Applied => tracing::info!(
                source = %source.folder, ipc_key = %source.ipc_key, kind = ty, target = ?target,
                "IPC request applied"
            ),
            IpcOutcome::Denied(r) | IpcOutcome::Rejected(r) => tracing::warn!(
                source = %source.folder, ipc_key = %source.ipc_key, kind = ty, target = ?target,
                reason = %truncate_reason(r), "IPC request denied"
            ),
            IpcOutcome::Failed(e) => tracing::error!(
                source = %source.folder, ipc_key = %source.ipc_key, kind = ty, target = ?target,
                error = %truncate_reason(e), "IPC request failed"
            ),
        }
    }

    /// Look up task `id` and its recorded owner.
    fn lookup_task(&self, id: &str) -> Result<Option<OwnedTask>, String> {
        let task = self
            .store
            .get_task_by_id(id)
            .map_err(|e| format!("task lookup failed: {e}"))?;
        let Some(task) = task else {
            return Ok(None);
        };
        let owner = self
            .store
            .get_task_owner(id)
            .map_err(|e| format!("task owner lookup failed: {e}"))?;
        Ok(Some((task, owner)))
    }

    async fn host_call<T>(
        &self,
        what: &str,
        fut: impl Future<Output = talon_core::Result<T>>,
    ) -> Result<T, String> {
        match tokio::time::timeout(self.config.host_call_timeout, fut).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(truncate_reason(&format!("{what} failed: {e}"))),
            Err(_) => Err(format!(
                "{what} timed out after {:?}",
                self.config.host_call_timeout
            )),
        }
    }

    /// Authorize and deliver one outbound chat message written by the
    /// container owning `source`.
    pub async fn process_message(&self, source: &SourceIdentity, msg: IpcOutbound) -> IpcOutcome {
        let IpcOutbound::Message {
            chat_jid,
            text,
            group_folder,
            ..
        } = &msg;
        let mut details = Map::new();
        details.insert("type".into(), json!("message"));
        details.insert("textLength".into(), json!(text.chars().count()));
        if let Some(claimed) = group_folder {
            if claimed != &source.folder {
                // Identity comes from the directory; a mismatching claim is
                // ignored but worth flagging.
                details.insert("claimedFolderMismatch".into(), json!(true));
            }
        }
        let target = Some(chat_jid.as_str());

        if let Err(reason) = validate_outbound_shape(&msg) {
            let outcome = IpcOutcome::Rejected(reason);
            self.record(&MESSAGE_KINDS, source, target, &outcome, details);
            return outcome;
        }

        let groups = self.host.registered_groups();
        let decision = decide_message(
            self.authorizer.as_ref(),
            source.as_ipc_identity(),
            chat_jid,
            &groups,
        );
        if let IpcDecision::Deny(reason) = decision {
            let outcome = IpcOutcome::Denied(reason);
            self.record(&MESSAGE_KINDS, source, target, &outcome, details);
            return outcome;
        }

        let outcome = match self
            .host_call("send_message", self.host.send_message(chat_jid, text))
            .await
        {
            Ok(()) => IpcOutcome::Applied,
            Err(e) => IpcOutcome::Failed(e),
        };
        if !outcome.is_applied() || self.config.audit_allowed_messages {
            self.record(&MESSAGE_KINDS, source, target, &outcome, details);
        } else {
            tracing::info!(source = %source.folder, chat_jid = %sanitize_for_log(chat_jid), "IPC message sent");
        }
        outcome
    }

    /// Authorize and perform one task operation written by the container
    /// owning `source`.
    pub async fn process_task(&self, source: &SourceIdentity, task: IpcTask) -> IpcOutcome {
        let ty = task_type_name(&task);
        let kinds = if matches!(task, IpcTask::RegisterGroup { .. }) {
            &REGISTER_KINDS
        } else {
            &TASK_KINDS
        };
        let mut details = Map::new();
        details.insert("type".into(), json!(ty));

        if let Err(reason) = validate_task_shape(&task) {
            let outcome = IpcOutcome::Rejected(reason);
            self.record(kinds, source, None, &outcome, details);
            return outcome;
        }

        let groups = self.host.registered_groups();
        let (target, outcome) = match &task {
            IpcTask::ScheduleTask { target_jid, .. } => (
                Some(target_jid.clone()),
                self.schedule_task(source, &task, &groups, &mut details),
            ),
            IpcTask::PauseTask { task_id, .. } => (
                Some(task_id.clone()),
                self.status_op(
                    source,
                    &task,
                    task_id,
                    StatusOp::Pause,
                    &groups,
                    &mut details,
                ),
            ),
            IpcTask::ResumeTask { task_id, .. } => (
                Some(task_id.clone()),
                self.status_op(
                    source,
                    &task,
                    task_id,
                    StatusOp::Resume,
                    &groups,
                    &mut details,
                ),
            ),
            IpcTask::CancelTask { task_id, .. } => (
                Some(task_id.clone()),
                self.status_op(
                    source,
                    &task,
                    task_id,
                    StatusOp::Cancel,
                    &groups,
                    &mut details,
                ),
            ),
            IpcTask::UpdateTask { task_id, .. } => (
                Some(task_id.clone()),
                self.update_task(source, &task, &groups, &mut details),
            ),
            IpcTask::RefreshGroups { .. } => (
                None,
                self.refresh_groups(source, &task, &groups, &mut details)
                    .await,
            ),
            IpcTask::RegisterGroup { jid, .. } => (
                Some(jid.clone()),
                self.register_group(source, &task, &groups, &mut details)
                    .await,
            ),
        };
        self.record(kinds, source, target.as_deref(), &outcome, details);
        outcome
    }

    fn schedule_task(
        &self,
        source: &SourceIdentity,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        details: &mut Map<String, Value>,
    ) -> IpcOutcome {
        let IpcTask::ScheduleTask {
            task_id,
            prompt,
            script,
            schedule_type,
            schedule_value,
            context_mode,
            target_jid,
            ..
        } = task
        else {
            return IpcOutcome::Failed("internal: request variant mismatch".into());
        };

        // A caller-chosen id may collide with an existing task (possibly of
        // another lane or the host): the policy sees the collision, and
        // duplicates are never upserted.
        let existing = match task_id {
            Some(id) => match self.lookup_task(id) {
                Ok(t) => t,
                Err(e) => return IpcOutcome::Failed(e),
            },
            None => None,
        };
        if let Some(id) = task_id {
            details.insert("taskId".into(), json!(id));
        }
        if let IpcDecision::Deny(r) = decide_task(
            self.authorizer.as_ref(),
            source.as_ipc_identity(),
            task,
            groups,
            existing
                .as_ref()
                .map(|(_, owner)| TaskOwner::from_record(owner.as_deref())),
        ) {
            return IpcOutcome::Denied(r);
        }
        let Some(target) = groups.get(target_jid) else {
            return IpcOutcome::Rejected("target group not registered".into());
        };
        if let (Some(id), Some(_)) = (task_id, &existing) {
            return IpcOutcome::Rejected(format!("duplicate task id {id:?}"));
        }

        let now = chrono::Utc::now();
        let next_run = match first_run(*schedule_type, schedule_value, self.config.timezone, now) {
            Ok(n) => n,
            Err(e) => return IpcOutcome::Rejected(format!("invalid schedule: {e}")),
        };
        let id = task_id.clone().unwrap_or_else(generate_task_id);
        let context_mode = context_mode.unwrap_or_default();
        let record = ScheduledTask {
            id: id.clone(),
            group_folder: target.folder.clone(),
            chat_jid: target_jid.clone(),
            prompt: prompt.clone(),
            script: script.clone().filter(|s| !s.is_empty()),
            schedule_type: *schedule_type,
            schedule_value: schedule_value.clone(),
            context_mode,
            next_run: Some(next_run.clone()),
            last_run: None,
            last_result: None,
            status: TaskStatus::Active,
            created_at: to_iso(now),
        };
        details.insert("taskId".into(), json!(id));
        details.insert("targetFolder".into(), json!(target.folder));
        details.insert("scheduleType".into(), json!(schedule_type.as_str()));
        details.insert("contextMode".into(), json!(context_mode.as_str()));
        details.insert("nextRun".into(), json!(next_run));
        details.insert("promptLength".into(), json!(prompt.chars().count()));
        details.insert("hasScript".into(), json!(record.script.is_some()));
        details.insert("owner".into(), json!(source.ipc_key));
        if let Err(e) = self.store.create_task(&record) {
            return IpcOutcome::Failed(format!("create task failed: {e}"));
        }
        // The creating namespace owns the task (MYTH-03). Without the record
        // the task would count as host-owned, so roll the creation back
        // rather than leave a task its creator cannot manage.
        if let Err(e) = self.store.set_task_owner(&id, &source.ipc_key) {
            if let Err(del) = self.store.delete_task(&id) {
                tracing::error!(task_id = %id, error = %del, "could not roll back IPC task without owner record");
            }
            return IpcOutcome::Failed(format!("recording task owner failed: {e}"));
        }
        self.host.on_tasks_changed();
        IpcOutcome::Applied
    }

    /// Look up the task referenced by pause/resume/cancel/update and
    /// authorize `task` against its recorded owner. Returns the task, or the
    /// outcome to report.
    fn authorize_existing(
        &self,
        source: &SourceIdentity,
        task: &IpcTask,
        task_id: &str,
        groups: &HashMap<String, RegisteredGroup>,
        details: &mut Map<String, Value>,
    ) -> Result<ScheduledTask, IpcOutcome> {
        let existing = self.lookup_task(task_id).map_err(IpcOutcome::Failed)?;
        let owner = existing
            .as_ref()
            .map(|(_, owner)| TaskOwner::from_record(owner.as_deref()));
        if let (Some((t, _)), Some(o)) = (&existing, owner) {
            details.insert("taskFolder".into(), json!(t.group_folder));
            details.insert("taskOwner".into(), json!(sanitize_for_log(o.as_str())));
        }
        if let IpcDecision::Deny(r) = decide_task(
            self.authorizer.as_ref(),
            source.as_ipc_identity(),
            task,
            groups,
            owner,
        ) {
            return Err(IpcOutcome::Denied(r));
        }
        match existing {
            Some((t, _)) => Ok(t),
            None => Err(IpcOutcome::Rejected("task not found".into())),
        }
    }

    fn status_op(
        &self,
        source: &SourceIdentity,
        task: &IpcTask,
        task_id: &str,
        op: StatusOp,
        groups: &HashMap<String, RegisteredGroup>,
        details: &mut Map<String, Value>,
    ) -> IpcOutcome {
        if let Err(outcome) = self.authorize_existing(source, task, task_id, groups, details) {
            return outcome;
        }
        let result = match op {
            StatusOp::Pause => self.store.update_task(
                task_id,
                &TaskUpdate {
                    status: Some(TaskStatus::Paused),
                    ..TaskUpdate::default()
                },
            ),
            StatusOp::Resume => self.store.update_task(
                task_id,
                &TaskUpdate {
                    status: Some(TaskStatus::Active),
                    ..TaskUpdate::default()
                },
            ),
            StatusOp::Cancel => self.store.delete_task(task_id),
        };
        if let Err(e) = result {
            return IpcOutcome::Failed(format!("{} task failed: {e}", op.as_str()));
        }
        self.host.on_tasks_changed();
        IpcOutcome::Applied
    }

    fn update_task(
        &self,
        source: &SourceIdentity,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        details: &mut Map<String, Value>,
    ) -> IpcOutcome {
        let IpcTask::UpdateTask {
            task_id,
            prompt,
            script,
            schedule_type,
            schedule_value,
            ..
        } = task
        else {
            return IpcOutcome::Failed("internal: request variant mismatch".into());
        };
        let current = match self.authorize_existing(source, task, task_id, groups, details) {
            Ok(t) => t,
            Err(outcome) => return outcome,
        };

        let mut update = TaskUpdate::default();
        if let Some(p) = prompt {
            if p.trim().is_empty() {
                return IpcOutcome::Rejected("prompt must not be empty".into());
            }
            update.prompt = Some(p.clone());
        }
        if let Some(s) = script {
            update.script = Some(if s.is_empty() { None } else { Some(s.clone()) });
        }
        if let Some(t) = schedule_type {
            update.schedule_type = Some(*t);
        }
        if let Some(v) = schedule_value {
            update.schedule_value = Some(v.clone());
        }
        if schedule_type.is_some() || schedule_value.is_some() {
            let ty = schedule_type.unwrap_or(current.schedule_type);
            let value = schedule_value.as_deref().unwrap_or(&current.schedule_value);
            match first_run(ty, value, self.config.timezone, chrono::Utc::now()) {
                Ok(next) => {
                    details.insert("nextRun".into(), json!(next));
                    update.next_run = Some(Some(next));
                }
                Err(e) => return IpcOutcome::Rejected(format!("invalid schedule: {e}")),
            }
        }
        let mut fields = Vec::new();
        if update.prompt.is_some() {
            fields.push("prompt");
        }
        if update.script.is_some() {
            fields.push("script");
        }
        if update.schedule_type.is_some() {
            fields.push("schedule_type");
        }
        if update.schedule_value.is_some() {
            fields.push("schedule_value");
        }
        details.insert("fields".into(), json!(fields));
        if update.is_empty() {
            details.insert("noop".into(), json!(true));
            return IpcOutcome::Applied;
        }
        if let Err(e) = self.store.update_task(task_id, &update) {
            return IpcOutcome::Failed(format!("update task failed: {e}"));
        }
        self.host.on_tasks_changed();
        IpcOutcome::Applied
    }

    async fn refresh_groups(
        &self,
        source: &SourceIdentity,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        details: &mut Map<String, Value>,
    ) -> IpcOutcome {
        if let IpcDecision::Deny(r) = decide_task(
            self.authorizer.as_ref(),
            source.as_ipc_identity(),
            task,
            groups,
            None,
        ) {
            return IpcOutcome::Denied(r);
        }
        if let Err(e) = self
            .host_call("sync_groups", self.host.sync_groups(true))
            .await
        {
            return IpcOutcome::Failed(e);
        }
        let available = self.host.available_groups();
        let registered: HashSet<String> = self.host.registered_groups().into_keys().collect();
        details.insert("availableGroups".into(), json!(available.len()));
        match self
            .host_call(
                "write_groups_snapshot",
                self.host
                    .write_groups_snapshot(source, &available, &registered),
            )
            .await
        {
            Ok(()) => IpcOutcome::Applied,
            Err(e) => IpcOutcome::Failed(e),
        }
    }

    async fn register_group(
        &self,
        source: &SourceIdentity,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        details: &mut Map<String, Value>,
    ) -> IpcOutcome {
        let IpcTask::RegisterGroup {
            jid,
            name,
            folder,
            trigger,
            requires_trigger,
            container_config,
            ..
        } = task
        else {
            return IpcOutcome::Failed("internal: request variant mismatch".into());
        };
        details.insert("folder".into(), json!(truncate_reason(folder)));
        // Container options (additional mounts, env, network, limits) are
        // operator-only (MYTH-04): a requested `containerConfig` is never
        // applied; the existing configuration of the JID is kept as is.
        if container_config.is_some() {
            details.insert("containerConfigIgnored".into(), json!(true));
        }
        if let IpcDecision::Deny(r) = decide_task(
            self.authorizer.as_ref(),
            source.as_ipc_identity(),
            task,
            groups,
            None,
        ) {
            return IpcOutcome::Denied(r);
        }
        if container_config.is_some() {
            tracing::warn!(
                source = %source.folder,
                ipc_key = %source.ipc_key,
                "register_group: containerConfig is operator-only and was ignored"
            );
        }
        // Defense in depth on top of the policy: never create, modify or
        // impersonate the main group through IPC.
        if !talon_core::paths::is_valid_group_folder(folder) {
            return IpcOutcome::Rejected("invalid group folder".into());
        }
        let existing = groups.get(jid);
        details.insert("new".into(), json!(existing.is_none()));
        if existing.is_some_and(|g| g.is_main) {
            return IpcOutcome::Rejected(
                "the main group's registration cannot be changed via IPC".into(),
            );
        }
        if groups.values().any(|g| g.is_main && g.folder == *folder) {
            return IpcOutcome::Rejected("folder belongs to the main group".into());
        }
        let ipc_key = existing
            .and_then(|g| g.ipc_key.clone())
            .unwrap_or_else(|| folder.clone());
        if groups
            .iter()
            .any(|(j, g)| j != jid && g.ipc_key() == ipc_key && g.folder != *folder)
        {
            return IpcOutcome::Rejected(
                "IPC namespace already used by a lane of another folder".into(),
            );
        }
        let group = RegisteredGroup {
            name: name.clone(),
            folder: folder.clone(),
            trigger: trigger.clone(),
            added_at: existing.map_or_else(now_iso, |g| g.added_at.clone()),
            // Never taken from the request (see above).
            container_config: existing.and_then(|g| g.container_config.clone()),
            requires_trigger: requires_trigger.or(existing.and_then(|g| g.requires_trigger)),
            // Forced: IPC can never grant main privileges.
            is_main: false,
            session_key: existing.and_then(|g| g.session_key.clone()),
            ipc_key: existing.and_then(|g| g.ipc_key.clone()),
            ephemeral_session: existing.is_some_and(|g| g.ephemeral_session),
            trusted_session_commands: existing.is_some_and(|g| g.trusted_session_commands),
        };
        match self
            .host_call("register_group", self.host.register_group(jid, group))
            .await
        {
            Ok(()) => IpcOutcome::Applied,
            Err(e) => IpcOutcome::Failed(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_task_ids_are_valid() {
        let id = generate_task_id();
        assert!(id.starts_with("task-"));
        assert!(crate::json::is_valid_task_id(&id));
        assert_ne!(id, generate_task_id());
    }
}
