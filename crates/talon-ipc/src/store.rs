//! Task persistence seam.
//!
//! The watcher only needs a handful of task operations. They sit behind
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
    /// Delete a task (and its run logs and owner record).
    fn delete_task(&self, id: &str) -> Result<()>;
    /// Record that the IPC namespace `owner` created task `id`.
    fn set_task_owner(&self, id: &str, owner: &str) -> Result<()>;
    /// Recorded owner of task `id`; `None` means the task was created by the
    /// host (or does not exist).
    fn get_task_owner(&self, id: &str) -> Result<Option<String>>;
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

    fn set_task_owner(&self, id: &str, owner: &str) -> Result<()> {
        talon_db::Db::set_task_owner(self, id, owner)
    }

    fn get_task_owner(&self, id: &str) -> Result<Option<String>> {
        talon_db::Db::get_task_owner(self, id)
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

    fn set_task_owner(&self, id: &str, owner: &str) -> Result<()> {
        (**self).set_task_owner(id, owner)
    }

    fn get_task_owner(&self, id: &str) -> Result<Option<String>> {
        (**self).get_task_owner(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talon_core::types::{ContextMode, ScheduleType, TaskStatus};

    #[test]
    fn db_store_records_and_forgets_owners() {
        let db = talon_db::Db::open_in_memory().unwrap();
        let store: &dyn TaskStore = &db;
        let task = ScheduledTask {
            id: "t-1".into(),
            group_folder: "copilot".into(),
            chat_jid: "http:copilot:u:alice".into(),
            prompt: "p".into(),
            script: None,
            schedule_type: ScheduleType::Once,
            schedule_value: "2026-01-01T00:00:00".into(),
            context_mode: ContextMode::Isolated,
            next_run: None,
            last_run: None,
            last_result: None,
            status: TaskStatus::Active,
            created_at: "2026-01-01T00:00:00.000Z".into(),
        };
        store.create_task(&task).unwrap();
        assert_eq!(store.get_task_owner("t-1").unwrap(), None);
        store.set_task_owner("t-1", "copilot-u-alice").unwrap();
        assert_eq!(
            store.get_task_owner("t-1").unwrap().as_deref(),
            Some("copilot-u-alice")
        );
        store.delete_task("t-1").unwrap();
        assert_eq!(store.get_task_owner("t-1").unwrap(), None);
        assert!(store.set_task_owner("t-1", "copilot-u-alice").is_err());
    }
}
