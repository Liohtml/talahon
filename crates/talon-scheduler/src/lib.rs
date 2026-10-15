//! # talon-scheduler — group queue + task scheduler
//!
//! - [`GroupQueue`]: one job per lane (chat
//!   JID), a global concurrency limit, a FIFO waiting list, tasks before
//!   messages, idle preemption, follow-up messages and the `_close` sentinel
//!   via IPC input files, retry with capped + jittered exponential backoff,
//!   `/status` snapshots and a bounded graceful shutdown.
//! - [`TaskScheduler`]: poll loop with
//!   wake-up, due tasks from a [`TaskStore`] (implemented for
//!   `talon_db::Db`), execution through the host's [`TaskExecutor`] under a
//!   timeout, run logs, next-run computation via
//!   `talon_core::schedule::compute_next_run`, and a run-once catch-up
//!   policy for missed runs.
//!
//! Neither depends on the container crate: the host plugs in through
//! [`LaneProcessor`], [`TaskExecutor`], [`RunningContainer`] and
//! [`GroupDirectory`].
//!
//! ## Wiring (host)
//!
//! ```ignore
//! let queue = GroupQueue::new(QueueConfig::from_talon_config(&cfg));
//! let scheduler = Arc::new(TaskScheduler::new(
//!     SchedulerConfig::from_talon_config(&cfg),
//!     Arc::new(db.clone()),            // talon_db::Db: TaskStore
//!     queue.clone(),
//!     Arc::new(ContainerTaskExecutor { /* runner, queue, channels, ... */ }),
//!     Arc::new(move || groups.snapshot()), // GroupDirectory
//! ));
//! // The host's LaneProcessor: process_messages -> its message pipeline,
//! // run_task(jid, id) -> scheduler.run_task(jid, id).await.
//! queue.set_processor(Arc::new(Lanes { scheduler: scheduler.clone(), /* ... */ }));
//! tokio::spawn({ let s = scheduler.clone(); let c = cancel.clone(); async move { s.run(c).await } });
//! // ...
//! cancel.cancel();
//! let report = queue.shutdown(Duration::from_secs(10)).await;
//! ```

#![warn(missing_docs)]

mod backoff;
mod clock;
pub mod ipc_input;
mod queue;
mod scheduler;
mod store;

pub use backoff::RetryPolicy;
pub use clock::{Clock, SystemClock, TokioClock};
pub use queue::{
    CloseTimer, EnqueueOutcome, GroupQueue, LaneJob, LaneProcessor, LaneSnapshot, QueueConfig,
    QueueSnapshot, RunningContainer, ShutdownReport,
};
pub use scheduler::{
    GroupDirectory, PollReport, SchedulerConfig, SkipReason, TaskExecution, TaskExecutor,
    TaskRunContext, TaskRunOutcome, TaskRunReport, TaskScheduler,
};
pub use store::{MemoryTaskStore, TaskStore};
/// Re-exported so hosts can implement `ChannelHost::queue_status` directly.
pub use talon_core::channel::QueueStatus;
