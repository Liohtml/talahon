//! Task persistence seam.
//!
//! The watcher only needs four task operations. They sit behind
//! [`TaskStore`] so the processing logic can be unit-tested with an
//! in-memory fake; production uses the [`talon_db::Db`] implementation.

use talon_core::Result;
use talon_core::types::{ScheduledTask, TaskUpdate};

/// The subset of `talon-db` the IPC watcher uses.
///
/// Implementations must be cheap and short (single-row SQLite statements);
/// they are called from async context.
pub trait TaskStore: Send + Sync {
    /// Insert a new task. Must fail (not upsert) when `task.id` exists.
    fn create_task(&self, task: &ScheduledTask) -> Result<()>;
    /// Look a task up by id.
    fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>>;
    /// Apply a partial update.
    fn update_task(&self, id: &str, update: &TaskUpdate) -> Result<()>;
    /// Delete a task (and its run logs).
    fn delete_task(&self, id: &str) -> Result<()>;
}

impl TaskStore for talon_db::Db {
    fn create_task(&self, task: &ScheduledTask) -> Result<()> {
        talon_db::Db::create_task(self, task)
    }

    fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        talon_db::Db::get_task_by_id(self, id)
    }

    fn update_task(&self, id: &str, update: &TaskUpdate) -> Result<()> {
        talon_db::Db::update_task(self, id, update)
    }

    fn delete_task(&self, id: &str) -> Result<()> {
        talon_db::Db::delete_task(self, id)
    }
}

impl<T: TaskStore + ?Sized> TaskStore for std::sync::Arc<T> {
    fn create_task(&self, task: &ScheduledTask) -> Result<()> {
        (**self).create_task(task)
    }

    fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        (**self).get_task_by_id(id)
    }

    fn update_task(&self, id: &str, update: &TaskUpdate) -> Result<()> {
        (**self).update_task(id, update)
    }

    fn delete_task(&self, id: &str) -> Result<()> {
        (**self).delete_task(id)
    }
}
