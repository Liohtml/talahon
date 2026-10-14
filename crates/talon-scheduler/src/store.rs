//! The slice of persistence the scheduler needs, behind a small trait so the
//! scheduler can be tested without SQLite. [`talon_db::Db`] implements it
//! (blocking SQLite calls run on `spawn_blocking`); [`MemoryTaskStore`] is an
//! in-memory fake with the same semantics.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use talon_core::time::now_iso;
use talon_core::types::{ScheduledTask, TaskRunLog, TaskStatus, TaskUpdate};
use talon_core::{Error, Result};

/// Task persistence used by the [`TaskScheduler`](crate::TaskScheduler).
#[async_trait]
pub trait TaskStore: Send + Sync {
    /// Active tasks with `next_run <= now_iso`, oldest due first.
    async fn get_due_tasks(&self, now_iso: &str) -> Result<Vec<ScheduledTask>>;

    /// One task by id.
    async fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>>;

    /// Record a finished run: `last_run = now`, `last_result`, `next_run`,
    /// and `status = completed` when `next_run` is `None`.
    async fn update_task_after_run(
        &self,
        id: &str,
        next_run: Option<&str>,
        last_result: &str,
    ) -> Result<()>;

    /// Append a run log entry.
    async fn log_task_run(&self, log: &TaskRunLog) -> Result<()>;

    /// Set `status = paused`.
    async fn pause_task(&self, id: &str) -> Result<()>;

    /// Move `next_run` without recording a run (deferred attempts).
    async fn reschedule_task(&self, id: &str, next_run: &str) -> Result<()>;
}

async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Db(format!("database task failed: {e}")))?
}

#[async_trait]
impl TaskStore for talon_db::Db {
    async fn get_due_tasks(&self, now_iso: &str) -> Result<Vec<ScheduledTask>> {
        let (db, now) = (self.clone(), now_iso.to_string());
        blocking(move || db.get_due_tasks(&now)).await
    }

    async fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        let (db, id) = (self.clone(), id.to_string());
        blocking(move || db.get_task_by_id(&id)).await
    }

    async fn update_task_after_run(
        &self,
        id: &str,
        next_run: Option<&str>,
        last_result: &str,
    ) -> Result<()> {
        let (db, id) = (self.clone(), id.to_string());
        let next_run = next_run.map(str::to_string);
        let last_result = last_result.to_string();
        blocking(move || db.update_task_after_run(&id, next_run.as_deref(), &last_result)).await
    }

    async fn log_task_run(&self, log: &TaskRunLog) -> Result<()> {
        let (db, log) = (self.clone(), log.clone());
        blocking(move || db.log_task_run(&log)).await
    }

    async fn pause_task(&self, id: &str) -> Result<()> {
        let (db, id) = (self.clone(), id.to_string());
        let update = TaskUpdate {
            status: Some(TaskStatus::Paused),
            ..TaskUpdate::default()
        };
        blocking(move || db.update_task(&id, &update)).await
    }

    async fn reschedule_task(&self, id: &str, next_run: &str) -> Result<()> {
        let (db, id) = (self.clone(), id.to_string());
        let update = TaskUpdate {
            next_run: Some(Some(next_run.to_string())),
            ..TaskUpdate::default()
        };
        blocking(move || db.update_task(&id, &update)).await
    }
}

#[derive(Debug, Default)]
struct MemoryState {
    tasks: BTreeMap<String, ScheduledTask>,
    runs: Vec<TaskRunLog>,
    fail_reads: bool,
}

/// In-memory [`TaskStore`] with the same semantics as the SQLite store.
/// Intended for tests (here and in the host crate).
#[derive(Debug, Default, Clone)]
pub struct MemoryTaskStore {
    state: Arc<Mutex<MemoryState>>,
}

impl MemoryTaskStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, MemoryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Insert or replace a task.
    pub fn insert(&self, task: ScheduledTask) {
        self.lock().tasks.insert(task.id.clone(), task);
    }

    /// Current copy of a task.
    pub fn task(&self, id: &str) -> Option<ScheduledTask> {
        self.lock().tasks.get(id).cloned()
    }

    /// Mutate a task in place; returns whether it existed.
    pub fn update(&self, id: &str, f: impl FnOnce(&mut ScheduledTask)) -> bool {
        match self.lock().tasks.get_mut(id) {
            Some(task) => {
                f(task);
                true
            }
            None => false,
        }
    }

    /// Remove a task.
    pub fn remove(&self, id: &str) -> Option<ScheduledTask> {
        self.lock().tasks.remove(id)
    }

    /// Run logs of one task, in insertion order.
    pub fn run_logs(&self, task_id: &str) -> Vec<TaskRunLog> {
        self.lock()
            .runs
            .iter()
            .filter(|r| r.task_id == task_id)
            .cloned()
            .collect()
    }

    /// Make `get_due_tasks` / `get_task_by_id` fail (error-path tests).
    pub fn set_fail_reads(&self, fail: bool) {
        self.lock().fail_reads = fail;
    }

    fn check_reads(&self) -> Result<()> {
        if self.lock().fail_reads {
            Err(Error::Db("simulated read failure".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl TaskStore for MemoryTaskStore {
    async fn get_due_tasks(&self, now_iso: &str) -> Result<Vec<ScheduledTask>> {
        self.check_reads()?;
        let mut due: Vec<ScheduledTask> = self
            .lock()
            .tasks
            .values()
            .filter(|t| {
                t.status == TaskStatus::Active
                    && t.next_run.as_deref().is_some_and(|n| n <= now_iso)
            })
            .cloned()
            .collect();
        due.sort_by(|a, b| a.next_run.cmp(&b.next_run));
        Ok(due)
    }

    async fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        self.check_reads()?;
        Ok(self.task(id))
    }

    async fn update_task_after_run(
        &self,
        id: &str,
        next_run: Option<&str>,
        last_result: &str,
    ) -> Result<()> {
        self.update(id, |t| {
            t.last_run = Some(now_iso());
            t.last_result = Some(last_result.to_string());
            t.next_run = next_run.map(str::to_string);
            if next_run.is_none() {
                t.status = TaskStatus::Completed;
            }
        });
        Ok(())
    }

    async fn log_task_run(&self, log: &TaskRunLog) -> Result<()> {
        self.lock().runs.push(log.clone());
        Ok(())
    }

    async fn pause_task(&self, id: &str) -> Result<()> {
        self.update(id, |t| t.status = TaskStatus::Paused);
        Ok(())
    }

    async fn reschedule_task(&self, id: &str, next_run: &str) -> Result<()> {
        self.update(id, |t| t.next_run = Some(next_run.to_string()));
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use talon_core::types::{ContextMode, ScheduleType, TaskRunStatus};

    use super::*;

    fn task(id: &str, next_run: Option<&str>, status: TaskStatus) -> ScheduledTask {
        ScheduledTask {
            id: id.into(),
            group_folder: "main".into(),
            chat_jid: "main@g.us".into(),
            prompt: "p".into(),
            script: None,
            schedule_type: ScheduleType::Cron,
            schedule_value: "* * * * *".into(),
            context_mode: ContextMode::Isolated,
            next_run: next_run.map(str::to_string),
            last_run: None,
            last_result: None,
            status,
            created_at: "2026-01-01T00:00:00.000Z".into(),
        }
    }

    #[tokio::test]
    async fn memory_store_due_tasks_semantics() {
        let s = MemoryTaskStore::new();
        s.insert(task(
            "b",
            Some("2026-01-01T00:02:00.000Z"),
            TaskStatus::Active,
        ));
        s.insert(task(
            "a",
            Some("2026-01-01T00:01:00.000Z"),
            TaskStatus::Active,
        ));
        s.insert(task(
            "future",
            Some("2026-01-01T01:00:00.000Z"),
            TaskStatus::Active,
        ));
        s.insert(task(
            "paused",
            Some("2026-01-01T00:00:00.000Z"),
            TaskStatus::Paused,
        ));
        s.insert(task("none", None, TaskStatus::Active));
        let due = s.get_due_tasks("2026-01-01T00:05:00.000Z").await.unwrap();
        let ids: Vec<&str> = due.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn memory_store_updates() {
        let s = MemoryTaskStore::new();
        s.insert(task(
            "t",
            Some("2026-01-01T00:00:00.000Z"),
            TaskStatus::Active,
        ));
        s.update_task_after_run("t", Some("2026-01-02T00:00:00.000Z"), "ok")
            .await
            .unwrap();
        let t = s.task("t").unwrap();
        assert_eq!(t.next_run.as_deref(), Some("2026-01-02T00:00:00.000Z"));
        assert_eq!(t.last_result.as_deref(), Some("ok"));
        assert!(t.last_run.is_some());
        assert_eq!(t.status, TaskStatus::Active);

        s.update_task_after_run("t", None, "done").await.unwrap();
        assert_eq!(s.task("t").unwrap().status, TaskStatus::Completed);

        s.reschedule_task("t", "2026-03-01T00:00:00.000Z")
            .await
            .unwrap();
        assert_eq!(
            s.task("t").unwrap().next_run.as_deref(),
            Some("2026-03-01T00:00:00.000Z")
        );
        s.pause_task("t").await.unwrap();
        assert_eq!(s.task("t").unwrap().status, TaskStatus::Paused);

        s.log_task_run(&TaskRunLog {
            task_id: "t".into(),
            run_at: "2026-01-01T00:00:00.000Z".into(),
            duration_ms: 5,
            status: TaskRunStatus::Success,
            result: None,
            error: None,
        })
        .await
        .unwrap();
        assert_eq!(s.run_logs("t").len(), 1);
        assert!(s.run_logs("other").is_empty());

        s.set_fail_reads(true);
        assert!(s.get_task_by_id("t").await.is_err());
        assert!(s.get_due_tasks("x").await.is_err());
    }
}
