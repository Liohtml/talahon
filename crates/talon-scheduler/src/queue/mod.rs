//! Per-lane serialization with a global container limit.
//!
//! A *lane* is a chat JID. At most one job (a message run or a scheduled
//! task) runs per lane, and at most [`QueueConfig::max_concurrent`] jobs run
//! in total. Lanes that cannot start because the limit is reached wait in a
//! FIFO list. When a job finishes, the lane's own pending work runs next —
//! tasks before messages, because messages are re-discovered from the
//! database but queued tasks are not — unless other lanes are already
//! waiting, in which case the lane queues behind them (fairness).
//!
//! The queue never calls into the host while holding its lock: jobs run in
//! spawned tasks that call [`LaneProcessor`] without any lock held, and
//! every state transition happens in short synchronous critical sections.
//! The state lock is a `std::sync::Mutex` on purpose: it is never held across
//! an `.await`, and it lets [`GroupQueue::status`] stay synchronous for
//! `ChannelHost::queue_status`.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use talon_core::channel::QueueStatus;
use talon_core::config::TalonConfig;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::backoff::{JitterRng, RetryPolicy};
use crate::ipc_input;

#[cfg(test)]
mod tests;

/// Host callbacks the queue invokes when a lane gets its turn.
///
/// Implementations are called from a spawned task with no queue lock held,
/// so they may freely call back into the [`GroupQueue`] (`register_process`,
/// `notify_idle`, `close_stdin`, ...). A panic inside a callback is caught
/// and treated as a failure.
#[async_trait]
pub trait LaneProcessor: Send + Sync {
    /// Process all pending messages for `chat_jid`. Return `false` to have
    /// the queue retry with backoff (e.g. the agent failed and the cursor
    /// was rolled back).
    async fn process_messages(&self, chat_jid: &str) -> bool;

    /// Run the scheduled task `task_id` in the lane `chat_jid`. Hosts
    /// normally delegate to [`TaskScheduler::run_task`](crate::TaskScheduler::run_task).
    async fn run_task(&self, chat_jid: &str, task_id: &str);
}

/// Handle to a lane's running agent container, registered by the host via
/// [`GroupQueue::register_process`]. Keeps the queue independent of the
/// container crate.
#[async_trait]
pub trait RunningContainer: Send + Sync {
    /// Runtime container name (e.g. `talon-main-1700000000000`).
    fn name(&self) -> &str;

    /// Stop the container (graceful stop, then kill).
    async fn stop(&self) -> talon_core::Result<()>;
}

/// Queue configuration.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Global limit of concurrently running lane jobs (min 1).
    pub max_concurrent: usize,
    /// Talon `data/` directory; IPC input files go to
    /// `<data_dir>/ipc/<ipc_key>/input/`.
    pub data_dir: PathBuf,
    /// Backoff for failed message runs.
    pub retry: RetryPolicy,
    /// After the shutdown grace period, stop containers that are still
    /// running. `false` (the default) leaves them detached to finish on
    /// their own.
    pub stop_on_shutdown: bool,
    /// Upper bound for a single [`RunningContainer::stop`] call.
    pub stop_timeout: Duration,
}

impl QueueConfig {
    /// Defaults: [`RetryPolicy::default`] (capped, jittered), containers
    /// detached on shutdown, 15 s stop timeout.
    pub fn new(data_dir: impl Into<PathBuf>, max_concurrent: usize) -> Self {
        Self {
            max_concurrent,
            data_dir: data_dir.into(),
            retry: RetryPolicy::default(),
            stop_on_shutdown: false,
            stop_timeout: Duration::from_secs(15),
        }
    }

    /// Build from the host configuration (`MAX_CONCURRENT_CONTAINERS`,
    /// `data/`).
    pub fn from_talon_config(config: &TalonConfig) -> Self {
        Self::new(config.data_dir.clone(), config.max_concurrent_containers)
    }
}

/// Result of an enqueue call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnqueueOutcome {
    /// A job was started immediately.
    Started,
    /// The work was recorded and will run when the lane / a slot frees up.
    Queued,
    /// The task is the one currently running in this lane (dropped).
    AlreadyRunning,
    /// The task is already waiting in this lane (dropped).
    AlreadyQueued,
    /// The queue is shutting down (dropped).
    ShuttingDown,
}

/// What a lane is currently running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LaneJob {
    /// A message run (`process_messages`).
    Messages,
    /// A scheduled task run.
    Task {
        /// The task's id.
        task_id: String,
    },
}

/// Per-lane detail for `/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaneSnapshot {
    /// Lane (chat JID).
    pub jid: String,
    /// The running job, if any.
    pub running: Option<LaneJob>,
    /// The container finished its turn and waits for IPC input.
    pub idle_waiting: bool,
    /// Registered container name, if any.
    pub container_name: Option<String>,
    /// Registered IPC namespace, if any.
    pub ipc_key: Option<String>,
    /// How long the current job has been running, in milliseconds.
    pub running_for_ms: Option<u64>,
    /// A message check is pending.
    pub pending_messages: bool,
    /// Queued task ids, in run order.
    pub pending_tasks: Vec<String>,
    /// Consecutive failed message runs.
    pub retry_count: u32,
    /// A backoff retry timer is armed.
    pub retry_scheduled: bool,
    /// The lane waits for a global slot.
    pub waiting: bool,
}

/// Detailed queue state for `/status`-style endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueSnapshot {
    /// Running lane jobs.
    pub active: usize,
    /// Global limit.
    pub max_concurrent: usize,
    /// Lanes waiting for a slot, in FIFO order.
    pub waiting: Vec<String>,
    /// `shutdown` was called.
    pub shutting_down: bool,
    /// Known lanes, sorted by JID.
    pub lanes: Vec<LaneSnapshot>,
}

/// Outcome of [`GroupQueue::shutdown`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShutdownReport {
    /// Every lane job finished (within the grace period or after stopping).
    pub drained: bool,
    /// Lanes still running when `shutdown` returned (detached).
    pub still_active: Vec<String>,
    /// Containers stopped after the grace period (`stop_on_shutdown`).
    pub stopped_containers: Vec<String>,
    /// Pending message checks / tasks that were dropped.
    pub dropped_pending: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RunKind {
    Messages,
    Task(String),
}

struct ActiveRun {
    id: u64,
    kind: RunKind,
    idle_waiting: bool,
    /// The `_close` sentinel was written: the container exits after its
    /// current turn without reading further input, so nothing more may be
    /// piped into it.
    closing: bool,
    container: Option<Arc<dyn RunningContainer>>,
    ipc_key: Option<String>,
    started: Instant,
}

impl ActiveRun {
    fn task_id(&self) -> Option<&str> {
        match &self.kind {
            RunKind::Task(id) => Some(id),
            RunKind::Messages => None,
        }
    }

    fn is_task(&self) -> bool {
        matches!(self.kind, RunKind::Task(_))
    }
}

#[derive(Default)]
struct Lane {
    active: Option<ActiveRun>,
    pending_messages: bool,
    pending_tasks: VecDeque<String>,
    retry_count: u32,
    retry_scheduled: bool,
}

impl Lane {
    fn has_pending(&self) -> bool {
        self.pending_messages || !self.pending_tasks.is_empty()
    }

    fn is_disposable(&self) -> bool {
        self.active.is_none()
            && !self.has_pending()
            && self.retry_count == 0
            && !self.retry_scheduled
    }
}

#[derive(Default)]
struct State {
    lanes: HashMap<String, Lane>,
    active_count: usize,
    waiting: VecDeque<String>,
    shutting_down: bool,
}

impl State {
    fn push_waiting(&mut self, jid: &str) {
        if !self.waiting.iter().any(|w| w == jid) {
            self.waiting.push_back(jid.to_string());
        }
    }

    /// Drop idle lane state (per-user lanes would otherwise accumulate).
    fn gc_lane(&mut self, jid: &str) {
        let disposable = self.lanes.get(jid).is_some_and(Lane::is_disposable);
        if disposable && !self.waiting.iter().any(|w| w == jid) {
            self.lanes.remove(jid);
        }
    }
}

struct Inner {
    config: QueueConfig,
    state: Mutex<State>,
    processor: RwLock<Option<Arc<dyn LaneProcessor>>>,
    tracker: TaskTracker,
    cancel: CancellationToken,
    rng: JitterRng,
    next_run_id: AtomicU64,
}

/// The per-lane job queue. Cheap to clone (shared state).
#[derive(Clone)]
pub struct GroupQueue {
    inner: Arc<Inner>,
}

impl fmt::Debug for GroupQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = self.status();
        f.debug_struct("GroupQueue")
            .field("active", &status.active_containers)
            .field("max", &status.max_containers)
            .field("waiting", &status.waiting_groups)
            .finish_non_exhaustive()
    }
}

impl GroupQueue {
    /// Create a queue without a processor; set one with
    /// [`set_processor`](Self::set_processor) before enqueueing work.
    pub fn new(config: QueueConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                state: Mutex::new(State::default()),
                processor: RwLock::new(None),
                tracker: TaskTracker::new(),
                cancel: CancellationToken::new(),
                rng: JitterRng::new(),
                next_run_id: AtomicU64::new(1),
            }),
        }
    }

    /// Create a queue with its processor.
    pub fn with_processor(config: QueueConfig, processor: Arc<dyn LaneProcessor>) -> Self {
        let queue = Self::new(config);
        queue.set_processor(processor);
        queue
    }

    /// Install (or replace) the host callbacks.
    /// Jobs started before this call run without a processor and count as
    /// successful no-ops.
    pub fn set_processor(&self, processor: Arc<dyn LaneProcessor>) {
        *self
            .inner
            .processor
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(processor);
    }

    /// The configuration the queue was built with.
    pub fn config(&self) -> &QueueConfig {
        &self.inner.config
    }

    /// New messages arrived for `chat_jid`: run a message check now, or
    /// remember it for when the lane / a slot is free.
    pub fn enqueue_message_check(&self, chat_jid: &str) -> EnqueueOutcome {
        let inner = &self.inner;
        let mut st = inner.lock();
        if st.shutting_down {
            return EnqueueOutcome::ShuttingDown;
        }
        let at_limit = st.active_count >= inner.max_concurrent();
        let lane = st.lanes.entry(chat_jid.to_string()).or_default();
        if lane.active.is_some() {
            lane.pending_messages = true;
            debug!(jid = chat_jid, "container active, message check queued");
            return EnqueueOutcome::Queued;
        }
        if at_limit {
            lane.pending_messages = true;
            st.push_waiting(chat_jid);
            debug!(
                jid = chat_jid,
                active = st.active_count,
                "at concurrency limit, message check queued"
            );
            return EnqueueOutcome::Queued;
        }
        inner.start_job(&mut st, chat_jid, RunKind::Messages);
        EnqueueOutcome::Started
    }

    /// Queue scheduled task `task_id` for lane `chat_jid`. Idempotent: a task
    /// that is already running or queued in the lane is not queued again.
    /// If the lane's container is idle-waiting it is asked to close so the
    /// task can start.
    pub fn enqueue_task(&self, chat_jid: &str, task_id: &str) -> EnqueueOutcome {
        let inner = &self.inner;
        let preempt = {
            let mut st = inner.lock();
            if st.shutting_down {
                return EnqueueOutcome::ShuttingDown;
            }
            let at_limit = st.active_count >= inner.max_concurrent();
            let lane = st.lanes.entry(chat_jid.to_string()).or_default();
            if lane.active.as_ref().and_then(ActiveRun::task_id) == Some(task_id) {
                debug!(jid = chat_jid, task_id, "task already running, skipping");
                return EnqueueOutcome::AlreadyRunning;
            }
            if lane.pending_tasks.iter().any(|t| t == task_id) {
                debug!(jid = chat_jid, task_id, "task already queued, skipping");
                return EnqueueOutcome::AlreadyQueued;
            }
            if let Some(active) = &lane.active {
                let idle = active.idle_waiting;
                lane.pending_tasks.push_back(task_id.to_string());
                debug!(jid = chat_jid, task_id, "container active, task queued");
                idle
            } else if at_limit {
                lane.pending_tasks.push_back(task_id.to_string());
                st.push_waiting(chat_jid);
                debug!(
                    jid = chat_jid,
                    task_id,
                    active = st.active_count,
                    "at concurrency limit, task queued"
                );
                false
            } else {
                inner.start_job(&mut st, chat_jid, RunKind::Task(task_id.to_string()));
                return EnqueueOutcome::Started;
            }
        };
        if preempt {
            debug!(
                jid = chat_jid,
                task_id, "preempting idle container for task"
            );
            self.close_stdin(chat_jid);
        }
        EnqueueOutcome::Queued
    }

    /// Record the container serving the lane's current job. Returns `false`
    /// when the lane has no running job
    /// (nothing is recorded) or `ipc_key` is invalid (the container is
    /// recorded for `stop`, but IPC writes stay disabled).
    pub fn register_process(
        &self,
        chat_jid: &str,
        container: Arc<dyn RunningContainer>,
        ipc_key: &str,
    ) -> bool {
        let key_ok = talon_core::paths::is_valid_group_folder(ipc_key);
        let mut st = self.inner.lock();
        let Some(active) = st.lanes.get_mut(chat_jid).and_then(|l| l.active.as_mut()) else {
            warn!(
                jid = chat_jid,
                container = container.name(),
                "register_process for a lane without a running job; ignored"
            );
            return false;
        };
        debug!(
            jid = chat_jid,
            container = container.name(),
            ipc_key,
            "container registered"
        );
        active.container = Some(container);
        if key_ok {
            active.ipc_key = Some(ipc_key.to_string());
        } else {
            warn!(
                jid = chat_jid,
                ipc_key, "invalid IPC key; follow-up messages disabled"
            );
            active.ipc_key = None;
        }
        key_ok
    }

    /// The lane's container finished a turn and is waiting for IPC input.
    /// If tasks are pending it is asked to close right away (preemption).
    pub fn notify_idle(&self, chat_jid: &str) {
        let preempt = {
            let mut st = self.inner.lock();
            let Some(lane) = st.lanes.get_mut(chat_jid) else {
                return;
            };
            let Some(active) = lane.active.as_mut() else {
                return;
            };
            active.idle_waiting = true;
            !lane.pending_tasks.is_empty()
        };
        if preempt {
            debug!(jid = chat_jid, "idle with pending tasks, closing container");
            self.close_stdin(chat_jid);
        }
    }

    /// Pipe a follow-up message into the lane's running container via an IPC
    /// input file. Returns `false` when there is no message container to
    /// receive it (no running job, a task container, nothing registered yet,
    /// a container that was asked to close, or the write failed) — the caller
    /// should then
    /// [`enqueue_message_check`](Self::enqueue_message_check).
    pub fn send_message(&self, chat_jid: &str, text: &str) -> bool {
        let (run_id, ipc_key, was_idle) = {
            let mut st = self.inner.lock();
            let Some(active) = st.lanes.get_mut(chat_jid).and_then(|l| l.active.as_mut()) else {
                return false;
            };
            // A closing container takes `_close` before any input file and
            // exits: a message piped now would sit unread in its input
            // directory while the cursor already moved past it.
            if active.is_task() || active.closing {
                return false;
            }
            let Some(key) = active.ipc_key.clone() else {
                return false;
            };
            // The agent is about to receive work: no longer idle, so a task
            // enqueued meanwhile must not preempt it.
            let was_idle = std::mem::replace(&mut active.idle_waiting, false);
            (active.id, key, was_idle)
        };
        match ipc_input::write_message(&self.inner.config.data_dir, &ipc_key, text) {
            Ok(path) => {
                debug!(jid = chat_jid, file = %path.display(), chars = text.len(), "follow-up piped to container");
                true
            }
            Err(e) => {
                warn!(jid = chat_jid, error = %e, "failed to write IPC input message");
                let mut st = self.inner.lock();
                if let Some(active) = st.lanes.get_mut(chat_jid).and_then(|l| l.active.as_mut()) {
                    if active.id == run_id {
                        active.idle_waiting = was_idle;
                    }
                }
                false
            }
        }
    }

    /// Ask the lane's container to wind down by writing the `_close`
    /// sentinel. Returns whether the sentinel was written. From then on
    /// [`send_message`](Self::send_message) refuses the lane, so follow-ups
    /// wait for the next run instead of being lost.
    pub fn close_stdin(&self, chat_jid: &str) -> bool {
        let (run_id, ipc_key) = {
            let st = self.inner.lock();
            match st.lanes.get(chat_jid).and_then(|l| l.active.as_ref()) {
                Some(ActiveRun {
                    id,
                    ipc_key: Some(key),
                    ..
                }) => (*id, key.clone()),
                _ => return false,
            }
        };
        match ipc_input::write_close_sentinel(&self.inner.config.data_dir, &ipc_key) {
            Ok(_) => {
                debug!(jid = chat_jid, "close sentinel written");
                let mut st = self.inner.lock();
                if let Some(active) = st.lanes.get_mut(chat_jid).and_then(|l| l.active.as_mut()) {
                    if active.id == run_id {
                        active.closing = true;
                    }
                }
                true
            }
            Err(e) => {
                warn!(jid = chat_jid, error = %e, "failed to write close sentinel");
                false
            }
        }
    }

    /// Stop the lane's registered container (bounded by
    /// [`QueueConfig::stop_timeout`]). Returns whether a container was
    /// stopped successfully.
    pub async fn stop_container(&self, chat_jid: &str) -> bool {
        let container = {
            let st = self.inner.lock();
            st.lanes
                .get(chat_jid)
                .and_then(|l| l.active.as_ref())
                .and_then(|a| a.container.clone())
        };
        match container {
            Some(c) => stop_with_timeout(c, self.inner.config.stop_timeout).await,
            None => false,
        }
    }

    /// A timer that writes the `_close` sentinel for `chat_jid` after
    /// `delay` (idle timer / task close timer). Dropping it cancels it.
    pub fn close_timer(&self, chat_jid: &str, delay: Duration) -> CloseTimer {
        CloseTimer {
            queue: self.clone(),
            jid: chat_jid.to_string(),
            delay,
            handle: None,
        }
    }

    /// Whether the lane currently runs a job.
    pub fn is_active(&self, chat_jid: &str) -> bool {
        self.inner
            .lock()
            .lanes
            .get(chat_jid)
            .is_some_and(|l| l.active.is_some())
    }

    /// Whether [`shutdown`](Self::shutdown) was called.
    pub fn is_shutting_down(&self) -> bool {
        self.inner.lock().shutting_down
    }

    /// Summary for `ChannelHost::queue_status` / `/status`.
    pub fn status(&self) -> QueueStatus {
        let st = self.inner.lock();
        let mut active_jids: Vec<String> = st
            .lanes
            .iter()
            .filter(|(_, l)| l.active.is_some())
            .map(|(jid, _)| jid.clone())
            .collect();
        active_jids.sort();
        QueueStatus {
            active_containers: st.active_count,
            max_containers: self.inner.max_concurrent(),
            waiting_groups: st.waiting.len(),
            active_jids,
        }
    }

    /// Detailed per-lane state.
    pub fn snapshot(&self) -> QueueSnapshot {
        let st = self.inner.lock();
        let now = Instant::now();
        let mut lanes: Vec<LaneSnapshot> = st
            .lanes
            .iter()
            .map(|(jid, lane)| {
                let active = lane.active.as_ref();
                LaneSnapshot {
                    jid: jid.clone(),
                    running: active.map(|a| match &a.kind {
                        RunKind::Messages => LaneJob::Messages,
                        RunKind::Task(id) => LaneJob::Task {
                            task_id: id.clone(),
                        },
                    }),
                    idle_waiting: active.is_some_and(|a| a.idle_waiting),
                    container_name: active
                        .and_then(|a| a.container.as_ref())
                        .map(|c| c.name().to_string()),
                    ipc_key: active.and_then(|a| a.ipc_key.clone()),
                    running_for_ms: active.map(|a| {
                        u64::try_from(now.saturating_duration_since(a.started).as_millis())
                            .unwrap_or(u64::MAX)
                    }),
                    pending_messages: lane.pending_messages,
                    pending_tasks: lane.pending_tasks.iter().cloned().collect(),
                    retry_count: lane.retry_count,
                    retry_scheduled: lane.retry_scheduled,
                    waiting: st.waiting.iter().any(|w| w == jid),
                }
            })
            .collect();
        lanes.sort_by(|a, b| a.jid.cmp(&b.jid));
        QueueSnapshot {
            active: st.active_count,
            max_concurrent: self.inner.max_concurrent(),
            waiting: st.waiting.iter().cloned().collect(),
            shutting_down: st.shutting_down,
            lanes,
        }
    }

    /// Graceful, bounded shutdown:
    /// 1. refuse new work, drop pending checks/tasks (messages are
    ///    re-discovered from the database on restart, tasks are still due),
    ///    cancel retry timers;
    /// 2. write `_close` to every running container so it finishes its
    ///    current turn and exits;
    /// 3. wait up to `grace` for running jobs;
    /// 4. if [`QueueConfig::stop_on_shutdown`], stop containers that are
    ///    still running and wait up to `stop_timeout` more.
    ///
    /// Remaining jobs are reported as detached. No new job starts after this
    /// is called, and the processor is released (breaking `Arc` cycles).
    pub async fn shutdown(&self, grace: Duration) -> ShutdownReport {
        let inner = &self.inner;
        let (to_close, dropped_pending) = {
            let mut st = inner.lock();
            st.shutting_down = true;
            st.waiting.clear();
            let mut dropped = 0;
            let mut to_close = Vec::new();
            for (jid, lane) in &mut st.lanes {
                dropped += usize::from(lane.pending_messages) + lane.pending_tasks.len();
                lane.pending_messages = false;
                lane.pending_tasks.clear();
                lane.retry_scheduled = false;
                if lane.active.is_some() {
                    to_close.push(jid.clone());
                }
            }
            (to_close, dropped)
        };
        inner.cancel.cancel();
        info!(
            active = to_close.len(),
            dropped_pending, "group queue shutting down"
        );
        for jid in &to_close {
            self.close_stdin(jid);
        }

        inner.tracker.close();
        let mut drained = tokio::time::timeout(grace, inner.tracker.wait())
            .await
            .is_ok();

        let mut stopped_containers = Vec::new();
        if !drained && inner.config.stop_on_shutdown {
            let containers: Vec<Arc<dyn RunningContainer>> = {
                let st = inner.lock();
                st.lanes
                    .values()
                    .filter_map(|l| l.active.as_ref().and_then(|a| a.container.clone()))
                    .collect()
            };
            let mut stops = JoinSet::new();
            for container in containers {
                let timeout = inner.config.stop_timeout;
                stops.spawn(async move {
                    let name = container.name().to_string();
                    (name, stop_with_timeout(container, timeout).await)
                });
            }
            while let Some(joined) = stops.join_next().await {
                if let Ok((name, true)) = joined {
                    stopped_containers.push(name);
                }
            }
            stopped_containers.sort();
            drained = tokio::time::timeout(inner.config.stop_timeout, inner.tracker.wait())
                .await
                .is_ok();
        }

        let still_active = self.status().active_jids;
        if drained {
            info!("group queue drained");
        } else {
            info!(detached = ?still_active, "group queue shut down with containers still running (detached)");
        }
        *inner
            .processor
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        ShutdownReport {
            drained: drained && still_active.is_empty(),
            still_active,
            stopped_containers,
            dropped_pending,
        }
    }
}

async fn stop_with_timeout(container: Arc<dyn RunningContainer>, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, container.stop()).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            warn!(container = container.name(), error = %e, "failed to stop container");
            false
        }
        Err(_) => {
            warn!(container = container.name(), "timed out stopping container");
            false
        }
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Critical sections never call foreign code, so poisoning can only
        // come from an internal bug; keep serving rather than cascading.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn max_concurrent(&self) -> usize {
        self.config.max_concurrent.max(1)
    }

    fn processor(&self) -> Option<Arc<dyn LaneProcessor>> {
        self.processor
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Mark the lane active and spawn its job. Caller holds the lock.
    fn start_job(self: &Arc<Self>, st: &mut State, jid: &str, kind: RunKind) {
        let lane = st.lanes.entry(jid.to_string()).or_default();
        if kind == RunKind::Messages {
            lane.pending_messages = false;
        }
        lane.active = Some(ActiveRun {
            id: self.next_run_id.fetch_add(1, Ordering::Relaxed),
            kind: kind.clone(),
            idle_waiting: false,
            closing: false,
            container: None,
            ipc_key: None,
            started: Instant::now(),
        });
        st.active_count += 1;
        debug!(jid, job = ?kind, active = st.active_count, "starting lane job");
        let inner = Arc::clone(self);
        let jid = jid.to_string();
        self.tracker
            .spawn(async move { inner.run_job(jid, kind).await });
    }

    async fn run_job(self: Arc<Self>, jid: String, kind: RunKind) {
        let processor = self.processor();
        let success = match (&kind, processor) {
            (_, None) => {
                warn!(jid, "no lane processor configured; job skipped");
                true
            }
            (RunKind::Messages, Some(p)) => {
                let lane = jid.clone();
                match tokio::spawn(async move { p.process_messages(&lane).await }).await {
                    Ok(ok) => ok,
                    Err(e) => {
                        error!(jid, error = %e, "message processing panicked");
                        false
                    }
                }
            }
            (RunKind::Task(task_id), Some(p)) => {
                let (lane, id) = (jid.clone(), task_id.clone());
                if let Err(e) = tokio::spawn(async move { p.run_task(&lane, &id).await }).await {
                    error!(jid, task_id, error = %e, "task run panicked");
                }
                true
            }
        };
        self.finish_job(&jid, &kind, success);
    }

    fn finish_job(self: &Arc<Self>, jid: &str, kind: &RunKind, success: bool) {
        let mut st = self.lock();
        st.active_count = st.active_count.saturating_sub(1);
        if let Some(lane) = st.lanes.get_mut(jid) {
            lane.active = None;
        }
        if *kind == RunKind::Messages {
            if success {
                if let Some(lane) = st.lanes.get_mut(jid) {
                    lane.retry_count = 0;
                }
            } else if !st.shutting_down {
                self.schedule_retry(&mut st, jid);
            }
        }
        debug!(jid, job = ?kind, success, active = st.active_count, "lane job finished");
        self.drain_lane(&mut st, jid);
        st.gc_lane(jid);
    }

    fn schedule_retry(self: &Arc<Self>, st: &mut State, jid: &str) {
        let policy = &self.config.retry;
        let lane = st.lanes.entry(jid.to_string()).or_default();
        lane.retry_count += 1;
        if lane.retry_count > policy.max_retries {
            error!(
                jid,
                retry_count = lane.retry_count,
                "max retries exceeded, dropping messages (will retry on next incoming message)"
            );
            lane.retry_count = 0;
            return;
        }
        if lane.retry_scheduled {
            debug!(jid, "retry already scheduled");
            return;
        }
        let delay = policy.delay_for(lane.retry_count, self.rng.next_unit());
        lane.retry_scheduled = true;
        info!(
            jid,
            retry_count = lane.retry_count,
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "scheduling retry with backoff"
        );
        let inner = Arc::clone(self);
        let jid = jid.to_string();
        let cancel = self.cancel.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = tokio::time::sleep(delay) => inner.retry_due(&jid),
            }
        });
    }

    fn retry_due(self: &Arc<Self>, jid: &str) {
        {
            let mut st = self.lock();
            if let Some(lane) = st.lanes.get_mut(jid) {
                lane.retry_scheduled = false;
            }
        }
        let queue = GroupQueue {
            inner: Arc::clone(self),
        };
        queue.enqueue_message_check(jid);
    }

    /// After a lane's job finished: run its own pending work (tasks first),
    /// or — if other lanes are waiting — queue behind them; then hand free
    /// slots to waiting lanes.
    fn drain_lane(self: &Arc<Self>, st: &mut State, jid: &str) {
        if st.shutting_down {
            return;
        }
        if st.lanes.get(jid).is_some_and(Lane::has_pending) {
            if st.waiting.is_empty() && st.active_count < self.max_concurrent() {
                self.start_next_for_lane(st, jid);
                return;
            }
            st.push_waiting(jid);
        }
        self.drain_waiting(st);
    }

    fn drain_waiting(self: &Arc<Self>, st: &mut State) {
        while st.active_count < self.max_concurrent() {
            let Some(next) = st.waiting.pop_front() else {
                break;
            };
            if !self.start_next_for_lane(st, &next) {
                st.gc_lane(&next);
            }
        }
    }

    /// Start the lane's next pending job (tasks before messages).
    fn start_next_for_lane(self: &Arc<Self>, st: &mut State, jid: &str) -> bool {
        let Some(lane) = st.lanes.get_mut(jid) else {
            return false;
        };
        if lane.active.is_some() {
            return false;
        }
        if let Some(task_id) = lane.pending_tasks.pop_front() {
            self.start_job(st, jid, RunKind::Task(task_id));
            true
        } else if lane.pending_messages {
            self.start_job(st, jid, RunKind::Messages);
            true
        } else {
            false
        }
    }
}

/// Writes the `_close` sentinel for a lane after a delay; see
/// [`GroupQueue::close_timer`]. Re-arm with [`reset`](Self::reset) (idle
/// timer semantics) or arm once with [`arm_once`](Self::arm_once) (task close
/// semantics). Dropping the timer cancels it, and so does queue shutdown.
pub struct CloseTimer {
    queue: GroupQueue,
    jid: String,
    delay: Duration,
    handle: Option<JoinHandle<()>>,
}

impl fmt::Debug for CloseTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloseTimer")
            .field("jid", &self.jid)
            .field("delay", &self.delay)
            .field("armed", &self.is_armed())
            .finish()
    }
}

impl CloseTimer {
    /// (Re)start the countdown from now.
    pub fn reset(&mut self) {
        self.cancel();
        let queue = self.queue.clone();
        let jid = self.jid.clone();
        let delay = self.delay;
        let cancel = self.queue.inner.cancel.clone();
        self.handle = Some(tokio::spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = tokio::time::sleep(delay) => {
                    debug!(jid, "close timer fired");
                    queue.close_stdin(&jid);
                }
            }
        }));
    }

    /// Start the countdown unless it was already started (even if it has
    /// fired since). Returns whether this call armed it.
    pub fn arm_once(&mut self) -> bool {
        if self.handle.is_some() {
            return false;
        }
        self.reset();
        true
    }

    /// Cancel a pending countdown.
    pub fn cancel(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }

    /// A countdown is running and has not fired yet.
    pub fn is_armed(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

impl Drop for CloseTimer {
    fn drop(&mut self) {
        self.cancel();
    }
}
