//! Scheduled-task execution (the container half of TS `runTask`) and
//! investigation bookkeeping.
//!
//! The scheduler resolves the task's group (by the task's chat JID first,
//! so the investigation lane `http:copilot:investigate` — which shares the
//! `copilot` folder with the chat lanes — runs as itself), holds the lane in
//! the queue and calls [`TaskExecutor::execute`]. This module runs the
//! container, forwards results to the chat, closes the container shortly
//! after its result, and — when the task is an investigation job (task id
//! == investigation id) — moves the `investigations` row through
//! `running` -> `completed` / `failed`, attaches the agent's structured
//! verdict and records its IOC sightings.

use std::time::SystemTime;

use async_trait::async_trait;
use talon_core::protocol::{ContainerOutput, OutputStatus};
use talon_core::time::now_iso;
use talon_core::types::{RegisteredGroup, ScheduledTask};
use talon_db::Investigation;
use talon_router::AgentOutputHandler;
use talon_scheduler::{CloseTimer, TaskExecution, TaskExecutor, TaskRunContext};
use tokio::time::Instant;

use super::Orchestrator;
use super::run::RunOptions;
use crate::investigation::{
    STATUS_COMPLETED, STATUS_FAILED, STATUS_RUNNING, load_verdict_async, sightings_from_verdict,
    truncate_error,
};

/// Streaming handler of a task run.
struct TaskSink<'a> {
    host: &'a Orchestrator,
    jid: &'a str,
    task_id: &'a str,
    close: CloseTimer,
    result: Option<String>,
    error: Option<String>,
}

#[async_trait]
impl AgentOutputHandler for TaskSink<'_> {
    async fn on_output(&mut self, output: &ContainerOutput) {
        if let Some(result) = output.result.as_deref().filter(|r| !r.is_empty()) {
            self.result = Some(result.to_string());
            // Forward to the chat (send_outbound formats + redacts).
            if let Err(e) = self.host.send_outbound(self.jid, result).await {
                tracing::warn!(task_id = %self.task_id, chat_jid = %self.jid, error = %e, "cannot deliver task result");
            }
            self.close.arm_once();
        }
        match output.status {
            OutputStatus::Success => {
                self.host.queue.notify_idle(self.jid);
                // Close promptly even when the result is null (IPC-only tasks).
                self.close.arm_once();
            }
            OutputStatus::Error => {
                self.error = Some(
                    output
                        .error
                        .clone()
                        .filter(|e| !e.trim().is_empty())
                        .unwrap_or_else(|| "Unknown error".to_string()),
                );
            }
        }
    }
}

impl Orchestrator {
    /// Load the investigation tracked under `task_id`, if any.
    fn investigation_for(&self, task_id: &str) -> Option<Investigation> {
        match self.db.get_investigation(task_id) {
            Ok(inv) => inv,
            Err(e) => {
                tracing::warn!(task_id, error = %e, "cannot read investigation");
                None
            }
        }
    }

    fn save_investigation(&self, inv: &Investigation) {
        if let Err(e) = self.db.upsert_investigation(inv) {
            tracing::error!(investigation = %inv.id, error = %e, "failed to update investigation");
        }
    }

    /// Mark an investigation `running`.
    pub(crate) fn investigation_started(&self, mut inv: Investigation) -> Investigation {
        inv.status = STATUS_RUNNING.to_string();
        inv.updated_at = now_iso();
        inv.error = None;
        self.save_investigation(&inv);
        tracing::info!(investigation = %inv.id, alert_id = %inv.alert_id, "Investigation running");
        inv
    }

    /// Record the end of an investigation run: status, error, verdict and
    /// IOC sightings. The agent-written report is read on the blocking
    /// pool without following symlinks (MYTH-10).
    pub(crate) async fn investigation_finished(
        &self,
        mut inv: Investigation,
        group: &RegisteredGroup,
        error: Option<&str>,
        run_started: SystemTime,
    ) {
        let verdict = load_verdict_async(
            self.config.groups_dir.clone(),
            group.folder.clone(),
            inv.id.clone(),
            inv.alert_id.clone(),
            run_started,
        )
        .await;
        let now = now_iso();
        inv.updated_at = now.clone();
        match error {
            Some(e) => {
                inv.status = STATUS_FAILED.to_string();
                inv.error = Some(truncate_error(&self.redactor.redact(e)));
            }
            None => {
                inv.status = STATUS_COMPLETED.to_string();
                inv.error = None;
            }
        }
        if let Some(verdict) = &verdict {
            let sightings = sightings_from_verdict(
                verdict,
                &inv.alert_id,
                Some(inv.customer_code.as_str()).filter(|c| !c.is_empty()),
                &now,
            );
            if !sightings.is_empty() {
                match self.db.record_ioc_sightings(&sightings) {
                    Ok(()) => {
                        tracing::info!(investigation = %inv.id, count = sightings.len(), "Recorded IOC sightings")
                    }
                    Err(e) => {
                        tracing::warn!(investigation = %inv.id, error = %e, "failed to record IOC sightings")
                    }
                }
            }
        }
        if verdict.is_some() {
            inv.verdict = verdict;
        }
        self.save_investigation(&inv);
        self.audit.record(talon_core::audit::event(
            "investigation.finished",
            &group.folder,
            Some(&inv.id),
            if inv.status == STATUS_COMPLETED {
                "info"
            } else {
                "error"
            },
            serde_json::json!({
                "alertId": inv.alert_id,
                "customerCode": inv.customer_code,
                "status": inv.status,
                "verdict": inv.verdict.as_ref().and_then(|v| v.get("verdict")).cloned(),
            }),
        ));
        tracing::info!(
            investigation = %inv.id,
            status = %inv.status,
            has_verdict = inv.verdict.is_some(),
            "Investigation finished"
        );
    }

    /// Execute one scheduled task (see the module docs).
    pub async fn execute_task(
        &self,
        task: &ScheduledTask,
        group: &RegisteredGroup,
        ctx: &TaskRunContext,
    ) -> TaskExecution {
        let started = Instant::now();
        let started_wall = SystemTime::now();
        let investigation = self
            .investigation_for(&task.id)
            .map(|inv| self.investigation_started(inv));

        let group_dir = self.config.groups_dir.join(&group.folder);
        if let Err(e) = std::fs::create_dir_all(&group_dir) {
            tracing::warn!(task_id = %task.id, error = %e, "cannot create group folder");
        }
        tracing::info!(task_id = %task.id, group = %task.group_folder, "Running scheduled task");

        let mut sink = TaskSink {
            host: self,
            jid: &ctx.chat_jid,
            task_id: &task.id,
            close: self
                .queue
                .close_timer(&ctx.chat_jid, self.settings.task_close_delay),
            result: None,
            error: None,
        };
        let opts = RunOptions::task(task.script.clone(), ctx.uses_group_session());
        let outcome = self
            .run_agent(group, &task.prompt, &ctx.chat_jid, opts, &mut sink)
            .await;
        sink.close.cancel();
        let mut result = sink.result.take();
        let mut error = sink.error.take();
        drop(sink);

        if outcome.is_success() {
            if let Some(r) = outcome.last_result.clone() {
                result = Some(r);
            }
        } else {
            error = Some(
                outcome
                    .error
                    .clone()
                    .filter(|e| !e.trim().is_empty())
                    .unwrap_or_else(|| "Unknown error".to_string()),
            );
        }

        if let Some(inv) = investigation {
            self.investigation_finished(inv, group, error.as_deref(), started_wall)
                .await;
        }

        TaskExecution {
            result,
            error,
            duration: Some(started.elapsed()),
        }
    }
}

#[async_trait]
impl TaskExecutor for Orchestrator {
    async fn execute(
        &self,
        task: &ScheduledTask,
        group: &RegisteredGroup,
        ctx: &TaskRunContext,
    ) -> TaskExecution {
        self.execute_task(task, group, ctx).await
    }
}
