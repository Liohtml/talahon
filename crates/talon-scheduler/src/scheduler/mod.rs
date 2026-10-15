//! Scheduled-task runner (port of `src/task-scheduler.ts`).
//!
//! The poll loop finds due tasks and enqueues them into the [`GroupQueue`];
//! when the queue gives the task's lane a slot, the host's
//! [`LaneProcessor::run_task`](crate::LaneProcessor::run_task) calls
//! [`TaskScheduler::run_task`], which re-reads the task, resolves its group,
//! runs it through the host's [`TaskExecutor`] under a timeout, records the
//! run log and computes the next run.
//!
//! Catch-up policy: a task that missed one or more runs (host downtime, busy
//! lane) runs **once** and is then rescheduled from the time it finished —
//! cron tasks to the next occurrence after now, interval tasks to the next
//! grid point after now. Missed runs are never replayed in a burst.
//!
//! Lane policy (N-1): a task only ever runs in the lane it was created for —
//! the group registered at its own `chat_jid` with its own folder. Lanes of
//! the same folder are *not* interchangeable: each carries its own session
//! key, IPC namespace and output stream (per-user CoPilot lanes all share
//! the `copilot` folder). When the task's lane is not registered (in-memory
//! lanes after a host restart or an idle sweep) or is registered for another
//! folder, the run is deferred with capped backoff and never completed, so it
//! runs in its own lane once that lane is registered again. Unlike the TS
//! port there is no fallback to another JID of the same folder.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::Serialize;
use talon_core::config::TalonConfig;
use talon_core::paths::is_valid_group_folder;
use talon_core::schedule::compute_next_run;
use talon_core::time::{parse_iso, to_iso};
use talon_core::types::{
    ContextMode, RegisteredGroup, ScheduleType, ScheduledTask, TaskRunLog, TaskRunStatus,
    TaskStatus,
};
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backoff::{JitterRng, RetryPolicy};
use crate::clock::{Clock, SystemClock};
use crate::queue::{EnqueueOutcome, GroupQueue};
use crate::store::TaskStore;

#[cfg(test)]
mod tests;

/// A task whose `next_run` is further in the future than this when it
/// reaches the front of its lane was rescheduled while queued and is skipped.
const NOT_DUE_TOLERANCE: chrono::Duration = chrono::Duration::seconds(1);

/// Scheduler configuration.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// How often due tasks are polled (TS `SCHEDULER_POLL_INTERVAL`, 60 s).
    pub poll_interval: Duration,
    /// Timezone for cron evaluation.
    pub timezone: Tz,
    /// Run timeout for groups without `containerConfig.timeout`.
    pub default_run_timeout: Duration,
    /// Slack added to the run timeout before the scheduler intervenes, and
    /// how long it then waits for the executor after stopping the container.
    pub timeout_grace: Duration,
    /// Backoff for failed runs. `max_retries` failed runs in a row are
    /// retried early; after that the task falls back to its regular
    /// schedule (`once` tasks complete).
    pub retry: RetryPolicy,
    /// `last_result` keeps this many characters of the result (TS: 200).
    pub result_summary_chars: usize,
    /// Results stored in the run log are truncated to this many characters.
    pub max_logged_result_chars: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(60),
            timezone: chrono_tz::UTC,
            default_run_timeout: Duration::from_secs(30 * 60),
            timeout_grace: Duration::from_secs(60),
            retry: RetryPolicy {
                max_retries: 3,
                base_delay: Duration::from_secs(60),
                max_delay: Duration::from_secs(30 * 60),
                jitter: 0.2,
            },
            result_summary_chars: 200,
            max_logged_result_chars: 64 * 1024,
        }
    }
}

impl SchedulerConfig {
    /// Build from the host configuration (`SCHEDULER_POLL_INTERVAL`, `TZ`,
    /// `CONTAINER_TIMEOUT`).
    pub fn from_talon_config(config: &TalonConfig) -> Self {
        Self {
            poll_interval: config.scheduler_poll_interval,
            timezone: config.timezone,
            default_run_timeout: config.container_timeout,
            ..Self::default()
        }
    }
}

/// Everything the executor needs besides the task and its group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunContext {
    /// Lane the run occupies; register the container under this JID.
    pub chat_jid: String,
    /// The group is the main control group.
    pub is_main: bool,
    /// `group`: resume the group's session; `isolated`: fresh session.
    pub context_mode: ContextMode,
    /// Container timeout to apply. The scheduler stops the container after
    /// `timeout + timeout_grace`.
    pub timeout: Duration,
    /// The `next_run` value the task was due at.
    pub scheduled_for: Option<String>,
    /// When this run started (ISO).
    pub started_at: String,
    /// How late the run starts relative to `scheduled_for`.
    pub late_by: Duration,
    /// Consecutive failed attempts before this one (0 = first try).
    pub attempt: u32,
}

impl TaskRunContext {
    /// Whether the run should resume the group's current session.
    pub fn uses_group_session(&self) -> bool {
        self.context_mode == ContextMode::Group
    }
}

/// What the executor reports back for one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskExecution {
    /// Final agent result (already forwarded to the chat by the executor).
    pub result: Option<String>,
    /// Error message; `Some` marks the run as failed.
    pub error: Option<String>,
    /// Executor-measured duration. When `None` the scheduler's wall-clock
    /// measurement is logged.
    pub duration: Option<Duration>,
}

impl TaskExecution {
    /// A successful run.
    pub fn success(result: Option<String>) -> Self {
        Self {
            result,
            ..Self::default()
        }
    }

    /// A failed run.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            error: Some(error.into()),
            ..Self::default()
        }
    }

    /// Attach an executor-measured duration.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }
}

/// Host side of a task run (TS `runTask` minus the bookkeeping): write the
/// tasks snapshot, resolve the session when
/// [`TaskRunContext::uses_group_session`], run the container with
/// `is_scheduled_task = true` and the task's `script`, register it with
/// [`GroupQueue::register_process`] under `ctx.chat_jid`, forward results to
/// the chat, call [`GroupQueue::notify_idle`] on success output and close
/// the container shortly after the result (see [`GroupQueue::close_timer`]).
///
/// Runs in its own task: a panic is recorded as a failed run, and the future
/// is dropped if it outlives the timeout plus grace.
#[async_trait]
pub trait TaskExecutor: Send + Sync {
    /// Execute one run of `task` in `group`.
    async fn execute(
        &self,
        task: &ScheduledTask,
        group: &RegisteredGroup,
        ctx: &TaskRunContext,
    ) -> TaskExecution;
}

/// Source of the registered groups (JID -> group).
pub trait GroupDirectory: Send + Sync {
    /// Snapshot of all registered groups.
    fn registered_groups(&self) -> HashMap<String, RegisteredGroup>;
}

impl<F> GroupDirectory for F
where
    F: Fn() -> HashMap<String, RegisteredGroup> + Send + Sync,
{
    fn registered_groups(&self) -> HashMap<String, RegisteredGroup> {
        self()
    }
}

/// Result of one poll.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PollReport {
    /// Due tasks returned by the store.
    pub due: usize,
    /// Newly started or queued.
    pub enqueued: usize,
    /// Already running or queued in their lane (not duplicated).
    pub already_queued: usize,
    /// Refused (queue shutting down) or not active.
    pub skipped: usize,
}

/// Why [`TaskScheduler::run_task`] did not run a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Deleted while queued.
    NotFound,
    /// Paused or completed while queued.
    NotActive,
    /// Rescheduled into the future while queued.
    NotDue,
    /// The host handed the task to a lane other than its own `chat_jid`.
    /// Nothing is changed, so the next poll enqueues it in its own lane.
    WrongLane,
    /// The store could not be read.
    StoreError(String),
}

/// A finished run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskRunReport {
    /// Task id.
    pub task_id: String,
    /// Logged status.
    pub status: TaskRunStatus,
    /// Logged duration.
    pub duration_ms: i64,
    /// The run hit the scheduler's timeout.
    pub timed_out: bool,
    /// Stored `last_result`.
    pub summary: String,
    /// Stored `next_run` (`None` = completed or paused).
    pub next_run: Option<String>,
    /// `Some(n)`: `next_run` is the n-th backoff retry after a failure.
    pub retry_attempt: Option<u32>,
    /// The task was paused because its schedule is invalid.
    pub paused: bool,
}

/// Outcome of [`TaskScheduler::run_task`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TaskRunOutcome {
    /// Nothing ran.
    Skipped {
        /// Why.
        reason: SkipReason,
    },
    /// The task has an invalid group folder and was paused (TS behaviour).
    Paused {
        /// Logged error.
        error: String,
    },
    /// The task's own lane is not registered (yet) for its folder; retried
    /// later with backoff. The task never runs in another lane meanwhile.
    Deferred {
        /// Logged error.
        error: String,
        /// New `next_run`.
        next_run: String,
    },
    /// The executor ran.
    Finished(TaskRunReport),
}

/// The task scheduler. Share it as `Arc<TaskScheduler>`.
pub struct TaskScheduler {
    config: SchedulerConfig,
    store: Arc<dyn TaskStore>,
    queue: GroupQueue,
    executor: Arc<dyn TaskExecutor>,
    groups: Arc<dyn GroupDirectory>,
    clock: Arc<dyn Clock>,
    wake: Notify,
    running: AtomicBool,
    failures: Mutex<HashMap<String, u32>>,
    rng: JitterRng,
}

impl fmt::Debug for TaskScheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskScheduler")
            .field("config", &self.config)
            .field("queue", &self.queue)
            .field("clock", &self.clock)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

struct RunningGuard<'a>(&'a AtomicBool);

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl TaskScheduler {
    /// Create a scheduler using the system clock.
    pub fn new(
        config: SchedulerConfig,
        store: Arc<dyn TaskStore>,
        queue: GroupQueue,
        executor: Arc<dyn TaskExecutor>,
        groups: Arc<dyn GroupDirectory>,
    ) -> Self {
        Self {
            config,
            store,
            queue,
            executor,
            groups,
            clock: Arc::new(SystemClock),
            wake: Notify::new(),
            running: AtomicBool::new(false),
            failures: Mutex::new(HashMap::new()),
            rng: JitterRng::new(),
        }
    }

    /// Replace the wall clock (tests: [`TokioClock`](crate::TokioClock)).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The configuration.
    pub fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    /// The queue tasks are enqueued into.
    pub fn queue(&self) -> &GroupQueue {
        &self.queue
    }

    /// Poll again right away (tasks were created/changed out of band;
    /// `ChannelHost::notify_tasks_changed`). Coalesces.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Poll loop: poll, then sleep `poll_interval` or until [`wake`](Self::wake),
    /// until `cancel` fires. A second concurrent call returns immediately.
    pub async fn run(&self, cancel: CancellationToken) {
        if self.running.swap(true, Ordering::SeqCst) {
            debug!("scheduler loop already running, skipping duplicate start");
            return;
        }
        let _guard = RunningGuard(&self.running);
        info!(
            poll_interval_ms = duration_ms(self.config.poll_interval),
            "scheduler loop started"
        );
        while !cancel.is_cancelled() {
            self.poll_once().await;
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                () = self.wake.notified() => debug!("scheduler woken"),
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }
        info!("scheduler loop stopped");
    }

    /// Enqueue every due task once (idempotent per lane).
    pub async fn poll_once(&self) -> PollReport {
        let now = to_iso(self.clock.now());
        let due = match self.store.get_due_tasks(&now).await {
            Ok(due) => due,
            Err(e) => {
                error!(error = %e, "error in scheduler loop: failed to load due tasks");
                return PollReport::default();
            }
        };
        let mut report = PollReport {
            due: due.len(),
            ..PollReport::default()
        };
        if due.is_empty() {
            return report;
        }
        info!(count = due.len(), "found due tasks");
        for task in due {
            if task.status != TaskStatus::Active {
                report.skipped += 1;
                continue;
            }
            match self.queue.enqueue_task(&task.chat_jid, &task.id) {
                EnqueueOutcome::Started | EnqueueOutcome::Queued => report.enqueued += 1,
                EnqueueOutcome::AlreadyRunning | EnqueueOutcome::AlreadyQueued => {
                    report.already_queued += 1;
                }
                EnqueueOutcome::ShuttingDown => report.skipped += 1,
            }
        }
        report
    }

    /// Run one task now (called from the host's `LaneProcessor::run_task`
    /// while the lane is held). Re-reads the task, so tasks paused,
    /// deleted or rescheduled while queued are skipped. The task only runs
    /// in its own lane (`chat_jid == task.chat_jid`, registered for the
    /// task's folder); otherwise it is skipped or deferred, never run in
    /// another lane of the same folder (see the module docs).
    pub async fn run_task(&self, chat_jid: &str, task_id: &str) -> TaskRunOutcome {
        let started = Instant::now();
        let now = self.clock.now();

        let task = match self.store.get_task_by_id(task_id).await {
            Ok(Some(task)) => task,
            Ok(None) => {
                debug!(task_id, "task no longer exists; skipping");
                self.clear_failures(task_id);
                return skipped(SkipReason::NotFound);
            }
            Err(e) => {
                error!(task_id, error = %e, "failed to load task");
                return skipped(SkipReason::StoreError(e.to_string()));
            }
        };
        if task.status != TaskStatus::Active {
            debug!(
                task_id,
                status = task.status.as_str(),
                "task no longer active; skipping"
            );
            self.clear_failures(task_id);
            return skipped(SkipReason::NotActive);
        }
        let scheduled_for = task.next_run.as_deref().and_then(parse_iso);
        if scheduled_for.is_some_and(|due| due > now + NOT_DUE_TOLERANCE) {
            debug!(task_id, next_run = ?task.next_run, "task was rescheduled while queued; skipping");
            return skipped(SkipReason::NotDue);
        }

        if !is_valid_group_folder(&task.group_folder) {
            let error = format!("invalid group folder {:?}", task.group_folder);
            error!(task_id, group_folder = ?task.group_folder, "task has invalid group folder; pausing");
            // Stop retry churn for malformed legacy rows.
            if let Err(e) = self.store.pause_task(&task.id).await {
                error!(task_id, error = %e, "failed to pause task");
            }
            self.log_run(&task.id, now, started.elapsed(), None, Some(error.clone()))
                .await;
            return TaskRunOutcome::Paused { error };
        }

        // The lane the queue holds must be the task's own: the container is
        // registered under `chat_jid` while the group (session, IPC
        // namespace) comes from `task.chat_jid`. Never mix two lanes.
        if chat_jid != task.chat_jid {
            warn!(
                task_id,
                lane = chat_jid,
                task_lane = %task.chat_jid,
                "task was handed to a lane other than its own; skipping"
            );
            return skipped(SkipReason::WrongLane);
        }

        let groups = self.groups.registered_groups();
        let group = match resolve_group(&groups, &task) {
            Ok(group) => group,
            Err(unresolved) => {
                return self
                    .defer_unresolved_lane(&task, &unresolved, now, started)
                    .await;
            }
        };

        let attempt = self.failure_count(&task.id);
        let late_by = scheduled_for
            .and_then(|due| (now - due).to_std().ok())
            .unwrap_or_default();
        if late_by > self.config.poll_interval.saturating_mul(2) {
            info!(
                task_id,
                late_by_secs = late_by.as_secs(),
                "task missed its scheduled time; running once and rescheduling from now"
            );
        }
        let ctx = TaskRunContext {
            chat_jid: task.chat_jid.clone(),
            is_main: group.is_main,
            context_mode: task.context_mode,
            timeout: self.run_timeout_for(&group),
            scheduled_for: task.next_run.clone(),
            started_at: to_iso(now),
            late_by,
            attempt,
        };
        info!(task_id, group = %task.group_folder, attempt, "running scheduled task");

        let (execution, timed_out) = self.execute(&task, &group, &ctx).await;
        let duration = execution.duration.unwrap_or_else(|| started.elapsed());
        let error = execution.error.map(|e| {
            if e.trim().is_empty() {
                "Unknown error".to_string()
            } else {
                e
            }
        });
        let result = execution.result;
        self.log_run(&task.id, now, duration, result.clone(), error.clone())
            .await;

        let finished = self.clock.now();
        let summary = match (&error, &result) {
            (Some(e), _) => format!("Error: {e}"),
            (None, Some(r)) if !r.is_empty() => truncate_chars(r, self.config.result_summary_chars),
            _ => "Completed".to_string(),
        };

        let regular = compute_next_run(
            task.schedule_type,
            &task.schedule_value,
            task.next_run.as_deref(),
            self.config.timezone,
            finished,
        );
        let mut paused = false;
        let mut retry_attempt = None;
        let next_run = match regular {
            Err(e) => {
                error!(task_id, error = %e, "task has an invalid schedule; pausing");
                paused = true;
                task.next_run.clone()
            }
            Ok(regular) if error.is_some() => {
                let failures = self.record_failure(&task.id);
                if failures <= self.config.retry.max_retries {
                    retry_attempt = Some(failures);
                    let retry_at = finished + self.backoff(failures);
                    let next = match regular.as_deref().and_then(parse_iso) {
                        Some(r) if task.schedule_type != ScheduleType::Once => r.min(retry_at),
                        _ => retry_at,
                    };
                    Some(to_iso(next))
                } else {
                    warn!(
                        task_id,
                        failures, "task keeps failing; back to its regular schedule"
                    );
                    self.clear_failures(&task.id);
                    regular
                }
            }
            Ok(regular) => {
                self.clear_failures(&task.id);
                regular
            }
        };
        let next_run = next_run.map(|n| ensure_after(n, finished));

        if let Err(e) = self
            .store
            .update_task_after_run(&task.id, next_run.as_deref(), &summary)
            .await
        {
            error!(task_id, error = %e, "failed to update task after run");
        }
        if paused {
            if let Err(e) = self.store.pause_task(&task.id).await {
                error!(task_id, error = %e, "failed to pause task");
            }
        }

        let status = if error.is_some() {
            TaskRunStatus::Error
        } else {
            TaskRunStatus::Success
        };
        info!(
            task_id,
            status = status.as_str(),
            duration_ms = duration_ms(duration),
            timed_out,
            next_run = next_run.as_deref().unwrap_or("none"),
            "task completed"
        );
        TaskRunOutcome::Finished(TaskRunReport {
            task_id: task.id,
            status,
            duration_ms: duration_ms(duration),
            timed_out,
            summary,
            next_run: if paused { None } else { next_run },
            retry_attempt,
            paused,
        })
    }

    /// The task's own lane is not registered for its folder: log, then retry
    /// later with backoff (capped) instead of re-running it on every poll.
    /// Never completes the task and never runs it in another lane, so it runs
    /// in its own lane once that lane is registered again.
    async fn defer_unresolved_lane(
        &self,
        task: &ScheduledTask,
        unresolved: &UnresolvedLane,
        now: DateTime<Utc>,
        started: Instant,
    ) -> TaskRunOutcome {
        let error = match unresolved {
            UnresolvedLane::FolderMismatch { registered_folder } => {
                error!(
                    task_id = %task.id,
                    lane = %task.chat_jid,
                    group_folder = %task.group_folder,
                    registered_folder = %registered_folder,
                    "task's lane is registered for another folder; deferring"
                );
                format!(
                    "Group not found: {} (lane {:?} is registered for folder {:?})",
                    task.group_folder, task.chat_jid, registered_folder
                )
            }
            UnresolvedLane::NotRegistered => {
                // Expected for in-memory lanes after a restart or idle sweep.
                warn!(
                    task_id = %task.id,
                    lane = %task.chat_jid,
                    group_folder = %task.group_folder,
                    "task's lane is not registered; deferring"
                );
                format!(
                    "Group not found: {} (lane {:?} is not registered)",
                    task.group_folder, task.chat_jid
                )
            }
        };
        self.log_run(&task.id, now, started.elapsed(), None, Some(error.clone()))
            .await;
        let failures = self.record_failure(&task.id);
        let retry_at = now + self.backoff(failures);
        let regular = if task.schedule_type == ScheduleType::Once {
            None
        } else {
            compute_next_run(
                task.schedule_type,
                &task.schedule_value,
                task.next_run.as_deref(),
                self.config.timezone,
                now,
            )
            .ok()
            .flatten()
            .as_deref()
            .and_then(parse_iso)
        };
        let next = to_iso(regular.map_or(retry_at, |r| r.min(retry_at)));
        let next = ensure_after(next, now);
        if let Err(e) = self.store.reschedule_task(&task.id, &next).await {
            error!(task_id = %task.id, error = %e, "failed to reschedule task");
        }
        TaskRunOutcome::Deferred {
            error,
            next_run: next,
        }
    }

    /// Run the executor in its own task under `timeout + grace`. On timeout,
    /// stop the lane's container, give the executor `grace` to return, then
    /// abort it.
    async fn execute(
        &self,
        task: &ScheduledTask,
        group: &RegisteredGroup,
        ctx: &TaskRunContext,
    ) -> (TaskExecution, bool) {
        let executor = Arc::clone(&self.executor);
        let (t, g, c) = (task.clone(), group.clone(), ctx.clone());
        let mut handle = tokio::spawn(async move { executor.execute(&t, &g, &c).await });
        let deadline = ctx.timeout.saturating_add(self.config.timeout_grace);

        let joined = tokio::select! {
            joined = &mut handle => Some(joined),
            () = tokio::time::sleep(deadline) => None,
        };
        match joined {
            Some(Ok(execution)) => (execution, false),
            Some(Err(e)) => {
                error!(task_id = %task.id, error = %e, "task executor failed");
                let message = if e.is_panic() {
                    "task executor panicked"
                } else {
                    "task executor was cancelled"
                };
                (TaskExecution::failure(message), false)
            }
            None => {
                warn!(
                    task_id = %task.id,
                    timeout_ms = duration_ms(deadline),
                    "scheduled task exceeded its run timeout; stopping its container"
                );
                if !self.queue.stop_container(&ctx.chat_jid).await {
                    self.queue.close_stdin(&ctx.chat_jid);
                }
                let late = match tokio::time::timeout(self.config.timeout_grace, &mut handle).await
                {
                    Ok(Ok(execution)) => Some(execution),
                    Ok(Err(_)) => None,
                    Err(_) => {
                        handle.abort();
                        None
                    }
                };
                let message = format!("task timed out after {}", human_duration(deadline));
                let mut execution = late.unwrap_or_default();
                execution.error = Some(match execution.error.take() {
                    Some(e) if !e.trim().is_empty() => format!("{message}: {e}"),
                    _ => message,
                });
                execution.duration = None;
                (execution, true)
            }
        }
    }

    fn run_timeout_for(&self, group: &RegisteredGroup) -> Duration {
        group
            .container_config
            .as_ref()
            .and_then(|c| c.timeout)
            .filter(|ms| *ms > 0)
            .map_or(self.config.default_run_timeout, Duration::from_millis)
    }

    fn backoff(&self, attempt: u32) -> chrono::Duration {
        let delay = self.config.retry.delay_for(attempt, self.rng.next_unit());
        chrono::Duration::from_std(delay).unwrap_or(chrono::Duration::MAX)
    }

    async fn log_run(
        &self,
        task_id: &str,
        run_at: DateTime<Utc>,
        duration: Duration,
        result: Option<String>,
        error: Option<String>,
    ) {
        let log = TaskRunLog {
            task_id: task_id.to_string(),
            run_at: to_iso(run_at),
            duration_ms: duration_ms(duration),
            status: if error.is_some() {
                TaskRunStatus::Error
            } else {
                TaskRunStatus::Success
            },
            result: result.map(|r| truncate_marked(&r, self.config.max_logged_result_chars)),
            error,
        };
        if let Err(e) = self.store.log_task_run(&log).await {
            error!(task_id, error = %e, "failed to record task run");
        }
    }

    fn failures(&self) -> MutexGuard<'_, HashMap<String, u32>> {
        self.failures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn failure_count(&self, task_id: &str) -> u32 {
        self.failures().get(task_id).copied().unwrap_or(0)
    }

    fn record_failure(&self, task_id: &str) -> u32 {
        let mut failures = self.failures();
        let count = failures.entry(task_id.to_string()).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    fn clear_failures(&self, task_id: &str) {
        self.failures().remove(task_id);
    }
}

fn skipped(reason: SkipReason) -> TaskRunOutcome {
    TaskRunOutcome::Skipped { reason }
}

/// Why a task's own lane could not be resolved (the run is deferred).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnresolvedLane {
    /// Nothing is registered at the task's `chat_jid`.
    NotRegistered,
    /// The task's `chat_jid` is registered, but for another folder.
    FolderMismatch {
        /// The folder the JID is registered for.
        registered_folder: String,
    },
}

/// The group the task runs in: the group registered at the task's own JID,
/// and only if its folder matches the task's.
///
/// Deliberately no fallback to another JID with the same folder (the TS
/// `find(g => g.folder === task.group_folder)`, N-1): lanes sharing a folder
/// have distinct session keys, IPC namespaces and output streams, so running
/// a per-user lane's task in, e.g., the base lane would hand it that lane's
/// session and IPC identity.
pub(crate) fn resolve_group(
    groups: &HashMap<String, RegisteredGroup>,
    task: &ScheduledTask,
) -> Result<RegisteredGroup, UnresolvedLane> {
    match groups.get(&task.chat_jid) {
        Some(group) if group.folder == task.group_folder => Ok(group.clone()),
        Some(group) => Err(UnresolvedLane::FolderMismatch {
            registered_folder: group.folder.clone(),
        }),
        None => Err(UnresolvedLane::NotRegistered),
    }
}

/// Keep `next` strictly after `now` (defensive; schedules already are).
fn ensure_after(next: String, now: DateTime<Utc>) -> String {
    match parse_iso(&next) {
        Some(t) if t <= now => to_iso(now + chrono::Duration::seconds(1)),
        _ => next,
    }
}

fn duration_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

fn human_duration(d: Duration) -> String {
    if d >= Duration::from_secs(1) {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// First `max` characters (TS `slice(0, 200)` on the summary).
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// First `max` characters plus a marker when something was cut.
fn truncate_marked(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => format!("{}\n[... truncated]", &s[..idx]),
        None => s.to_string(),
    }
}
