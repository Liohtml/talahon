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
//! `details.stage = "authorization" | "validation" | "quota"` (quota
//! denials also name the `quota`: `prompt_bytes`, `schedule_frequency` or
//! `tasks_per_lane`). Message text and task prompts are never written to
//! the audit log (only their lengths). Rows are subject to the
//! per-namespace audit rate limit (see `ratelimit`); task operations that
//! were *executed* (applied, or failed after execution started) are always
//! written. Targets and reasons are passed through `sanitize_for_log`
//! first.
//!
//! Task ownership (MYTH-03): every task created over IPC gets an owner
//! record — the source namespace's IPC key — and pause/resume/cancel/update
//! are authorized against that owner, not the task's folder.
//!
//! Task quotas (N-3), checked after authorization and validation:
//! - prompt size (`schedule_task`, `update_task`): every namespace, with a
//!   larger cap for main;
//! - schedule frequency (`schedule_task`, `update_task` changing the
//!   schedule, `resume_task`): non-main only;
//! - tasks owned per namespace (`schedule_task`, `resume_task` of a
//!   completed task): non-main only.
//!
//! Finally every operation passes the execution gate: one unit of the
//! namespace's task-operation budget is taken right before state changes.
//! Over budget, the request is denied without executing and counted into
//! the namespace's `ipc.task.throttled` summary row instead of being
//! audited on its own.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use serde_json::{Map, Value, json};
use talon_core::audit::event;
use talon_core::protocol::{IpcOutbound, IpcTask};
use talon_core::schedule::{ensure_not_past, first_run};
use talon_core::time::{now_iso, to_iso};
use talon_core::types::{RegisteredGroup, ScheduleType, ScheduledTask, TaskStatus, TaskUpdate};
use talon_security::ipc_authz::{IpcDecision, TaskOwner};

use crate::authz::{decide_message, decide_task};
use crate::host::SourceIdentity;
use crate::json::{
    sanitize_for_log, task_type_name, truncate_reason, validate_outbound_shape, validate_task_shape,
};
use crate::quota::{check_prompt_bytes, check_schedule_frequency};
use crate::ratelimit::OpPermit;
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
    /// Executed requests of this family change state and are always
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

/// Execution gate of one task request (N-3): holds the task-operation
/// permit taken right before the request changes state.
#[derive(Debug, Default)]
struct OpGate {
    permit: Option<OpPermit>,
    /// The request was refused by the task-operation rate limit.
    throttled: bool,
}

/// Per-request state threaded through the task handlers.
#[derive(Debug)]
struct Req {
    /// Audit details.
    details: Map<String, Value>,
    /// Execution gate.
    gate: OpGate,
}

/// A per-lane quota violation (N-3): denied and audited with
/// `stage = "quota"` and the quota's name.
fn quota_denied(
    details: &mut Map<String, Value>,
    quota: &'static str,
    reason: String,
) -> IpcOutcome {
    details.insert("stage".into(), json!("quota"));
    details.insert("quota".into(), json!(quota));
    IpcOutcome::Denied(reason)
}

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
    /// Audit one request. `executed`: the request passed the execution
    /// gate (it changed, or tried to change, state).
    fn record(
        &self,
        kinds: &Kinds,
        source: &SourceIdentity,
        target: Option<&str>,
        outcome: &IpcOutcome,
        mut details: Map<String, Value>,
        executed: bool,
    ) {
        details.insert("ipcKey".into(), json!(source.ipc_key));
        details.insert("isMain".into(), json!(source.is_main));
        let (kind, result) = match outcome {
            IpcOutcome::Applied => (kinds.allowed, "allowed"),
            IpcOutcome::Denied(r) => {
                // Quota denials set their own stage.
                details
                    .entry("stage")
                    .or_insert_with(|| json!("authorization"));
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
        // Every executed state change is audited, even over the audit
        // budget; the task-operation rate limit bounds how many there are.
        let priority = kinds.applied_is_priority
            && executed
            && matches!(outcome, IpcOutcome::Applied | IpcOutcome::Failed(_));
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
            self.record(&MESSAGE_KINDS, source, target, &outcome, details, false);
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
            self.record(&MESSAGE_KINDS, source, target, &outcome, details, false);
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
            self.record(&MESSAGE_KINDS, source, target, &outcome, details, false);
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
            self.record(kinds, source, None, &outcome, details, false);
            return outcome;
        }

        let groups = self.host.registered_groups();
        let mut req = Req {
            details,
            gate: OpGate::default(),
        };
        let (target, outcome) = match &task {
            IpcTask::ScheduleTask { target_jid, .. } => (
                Some(target_jid.clone()),
                self.schedule_task(source, &task, &groups, &mut req),
            ),
            IpcTask::PauseTask { task_id, .. } => (
                Some(task_id.clone()),
                self.status_op(source, &task, task_id, StatusOp::Pause, &groups, &mut req),
            ),
            IpcTask::ResumeTask { task_id, .. } => (
                Some(task_id.clone()),
                self.status_op(source, &task, task_id, StatusOp::Resume, &groups, &mut req),
            ),
            IpcTask::CancelTask { task_id, .. } => (
                Some(task_id.clone()),
                self.status_op(source, &task, task_id, StatusOp::Cancel, &groups, &mut req),
            ),
            IpcTask::UpdateTask { task_id, .. } => (
                Some(task_id.clone()),
                self.update_task(source, &task, &groups, &mut req),
            ),
            IpcTask::RefreshGroups { .. } => (
                None,
                self.refresh_groups(source, &task, &groups, &mut req).await,
            ),
            IpcTask::RegisterGroup { jid, .. } => (
                Some(jid.clone()),
                self.register_group(source, &task, &groups, &mut req).await,
            ),
        };
        let Req { details, gate } = req;
        if gate.throttled {
            // Not executed. Counted into the namespace's
            // `ipc.task.throttled` summary row instead of a row per request.
            tracing::debug!(
                source = %source.folder, ipc_key = %source.ipc_key, kind = ty,
                target = ?target.as_deref().map(sanitize_for_log),
                "IPC task operation throttled"
            );
            return outcome;
        }
        let mut executed = false;
        if let Some(permit) = gate.permit {
            if matches!(outcome, IpcOutcome::Denied(_) | IpcOutcome::Rejected(_)) {
                // Refused after the gate: the budget unit was not used.
                self.release_task_op(permit);
            } else {
                executed = true;
            }
        }
        self.record(
            kinds,
            source,
            target.as_deref(),
            &outcome,
            details,
            executed,
        );
        outcome
    }

    /// The execution gate (N-3): take one unit of `source`'s task-operation
    /// budget right before `task` changes state. Over budget, the request
    /// is refused (and marked as throttled).
    fn pass_gate(
        &self,
        source: &SourceIdentity,
        task: &IpcTask,
        gate: &mut OpGate,
    ) -> Result<(), IpcOutcome> {
        match self.acquire_task_op(source, task_type_name(task)) {
            Ok(permit) => {
                gate.permit = Some(permit);
                Ok(())
            }
            Err(outcome) => {
                gate.throttled = true;
                Err(outcome)
            }
        }
    }

    /// Prompt size quota (every namespace; main has a larger cap).
    fn check_prompt(
        &self,
        source: &SourceIdentity,
        prompt: &str,
        details: &mut Map<String, Value>,
    ) -> Result<(), IpcOutcome> {
        check_prompt_bytes(prompt, self.config.prompt_limit(source.is_main)).map_err(|r| {
            details.insert("promptBytes".into(), json!(prompt.len()));
            quota_denied(details, "prompt_bytes", r)
        })
    }

    /// Schedule frequency quota (non-main only).
    fn check_frequency(
        &self,
        source: &SourceIdentity,
        schedule_type: ScheduleType,
        value: &str,
        details: &mut Map<String, Value>,
    ) -> Result<(), IpcOutcome> {
        if source.is_main {
            return Ok(());
        }
        check_schedule_frequency(
            schedule_type,
            value,
            self.config.timezone,
            chrono::Utc::now(),
            self.config.min_schedule_interval,
        )
        .map_err(|r| quota_denied(details, "schedule_frequency", r))
    }

    /// Owned-task quota (non-main only): one more active task must fit.
    fn check_task_quota(
        &self,
        source: &SourceIdentity,
        details: &mut Map<String, Value>,
    ) -> Result<(), IpcOutcome> {
        let max = self.config.max_tasks_per_lane;
        if source.is_main || max == 0 {
            return Ok(());
        }
        let owned = self
            .store
            .count_tasks_owned_by(&source.ipc_key)
            .map_err(|e| IpcOutcome::Failed(format!("task quota lookup failed: {e}")))?;
        details.insert("ownedTasks".into(), json!(owned));
        if owned >= u64::try_from(max).unwrap_or(u64::MAX) {
            return Err(quota_denied(
                details,
                "tasks_per_lane",
                format!(
                    "this lane already owns {owned} active or paused tasks (limit {max}); cancel one first"
                ),
            ));
        }
        Ok(())
    }

    fn schedule_task(
        &self,
        source: &SourceIdentity,
        task: &IpcTask,
        groups: &HashMap<String, RegisteredGroup>,
        req: &mut Req,
    ) -> IpcOutcome {
        let Req { details, gate } = req;
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
        let next_run = match first_run(*schedule_type, schedule_value, self.config.timezone, now)
            .and_then(|n| {
                ensure_not_past(*schedule_type, schedule_value, self.config.timezone, now)
                    .map(|()| n)
            }) {
            Ok(n) => n,
            Err(e) => return IpcOutcome::Rejected(format!("invalid schedule: {e}")),
        };
        // Per-lane quotas (N-3); the cron sampling of the frequency check is
        // the most expensive, so it runs last.
        if let Err(o) = self
            .check_prompt(source, prompt, details)
            .and_then(|()| self.check_task_quota(source, details))
            .and_then(|()| self.check_frequency(source, *schedule_type, schedule_value, details))
        {
            return o;
        }
        if let Err(o) = self.pass_gate(source, task, gate) {
            return o;
        }
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
        req: &mut Req,
    ) -> IpcOutcome {
        let Req { details, gate } = req;
        let current = match self.authorize_existing(source, task, task_id, groups, details) {
            Ok(t) => t,
            Err(outcome) => return outcome,
        };
        // A resumed task needs a time to run at: a completed task has none
        // left, and a `once` task whose time has passed would run at once.
        let mut resume_at = None;
        if matches!(op, StatusOp::Resume) && current.status != TaskStatus::Active {
            let now = chrono::Utc::now();
            let tz = self.config.timezone;
            if let Err(e) = ensure_not_past(current.schedule_type, &current.schedule_value, tz, now)
            {
                return IpcOutcome::Rejected(format!(
                    "cannot resume: {e}; update the task's schedule instead"
                ));
            }
            if current.status == TaskStatus::Completed || current.next_run.is_none() {
                match first_run(current.schedule_type, &current.schedule_value, tz, now) {
                    Ok(next) => {
                        details.insert("nextRun".into(), json!(next));
                        resume_at = Some(next);
                    }
                    Err(e) => {
                        return IpcOutcome::Rejected(format!(
                            "cannot resume: invalid schedule: {e}"
                        ));
                    }
                }
            }
        }
        // Re-activating a task is held to the same quotas as creating one
        // (N-3): its schedule must respect the lane's minimum frequency, and
        // a completed task needs a free slot (completed tasks do not count).
        if matches!(op, StatusOp::Resume) && current.status != TaskStatus::Active {
            let slot = if current.status == TaskStatus::Completed {
                self.check_task_quota(source, details)
            } else {
                Ok(())
            };
            if let Err(o) = slot.and_then(|()| {
                self.check_frequency(
                    source,
                    current.schedule_type,
                    &current.schedule_value,
                    details,
                )
            }) {
                return o;
            }
        }
        if let Err(o) = self.pass_gate(source, task, gate) {
            return o;
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
                    next_run: resume_at.map(Some),
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
        req: &mut Req,
    ) -> IpcOutcome {
        let Req { details, gate } = req;
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
            if let Err(o) = self.check_prompt(source, p, details) {
                return o;
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
            let (tz, now) = (self.config.timezone, chrono::Utc::now());
            match first_run(ty, value, tz, now)
                .and_then(|next| ensure_not_past(ty, value, tz, now).map(|()| next))
            {
                Ok(next) => {
                    details.insert("nextRun".into(), json!(next));
                    update.next_run = Some(Some(next));
                }
                Err(e) => return IpcOutcome::Rejected(format!("invalid schedule: {e}")),
            }
            if let Err(o) = self.check_frequency(source, ty, value, details) {
                return o;
            }
            // A new schedule for a finished task means it should run again;
            // like a resume, that takes a free slot.
            if current.status == TaskStatus::Completed {
                if let Err(o) = self.check_task_quota(source, details) {
                    return o;
                }
                update.status = Some(TaskStatus::Active);
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
        if update.status.is_some() {
            fields.push("status");
        }
        details.insert("fields".into(), json!(fields));
        // A no-op update is still an applied (and always audited) request,
        // so it takes a budget unit too.
        if let Err(o) = self.pass_gate(source, task, gate) {
            return o;
        }
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
        req: &mut Req,
    ) -> IpcOutcome {
        let Req { details, gate } = req;
        if let IpcDecision::Deny(r) = decide_task(
            self.authorizer.as_ref(),
            source.as_ipc_identity(),
            task,
            groups,
            None,
        ) {
            return IpcOutcome::Denied(r);
        }
        if let Err(o) = self.pass_gate(source, task, gate) {
            return o;
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
        req: &mut Req,
    ) -> IpcOutcome {
        let Req { details, gate } = req;
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
        if let Err(o) = self.pass_gate(source, task, gate) {
            return o;
        }
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
