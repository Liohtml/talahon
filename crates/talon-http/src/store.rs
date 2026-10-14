//! The slice of `talon-db` the HTTP channel uses, behind a trait so the
//! server can be tested with an in-memory fake. [`talon_db::Db`] implements
//! it by delegation.
//!
//! All methods are blocking (SQLite); the server calls them through
//! [`run_blocking`] so they never stall the async runtime.

use std::sync::Arc;

use talon_core::types::{ScheduledTask, SessionRow};
use talon_core::{Error, Result};
use talon_db::{Db, Investigation};

/// Persistence operations used by the HTTP channel.
pub trait HttpStore: Send + Sync {
    /// Scheduled task by id.
    fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>>;
    /// Insert a scheduled task.
    fn create_task(&self, task: &ScheduledTask) -> Result<()>;
    /// Delete a scheduled task (and its run logs).
    fn delete_task(&self, id: &str) -> Result<()>;
    /// Tasks belonging to a group folder.
    fn get_tasks_for_group(&self, group_folder: &str) -> Result<Vec<ScheduledTask>>;
    /// Stored sessions, keyed by lane session key.
    fn get_session_rows(&self) -> Result<Vec<SessionRow>>;
    /// Insert or update an investigation job.
    fn upsert_investigation(&self, inv: &Investigation) -> Result<()>;
    /// Investigation by id.
    fn get_investigation(&self, id: &str) -> Result<Option<Investigation>>;
    /// Most recent investigations first.
    fn list_investigations(&self, limit: usize) -> Result<Vec<Investigation>>;
    /// Latest investigation for an alert id.
    fn latest_investigation_for_alert(&self, alert_id: &str) -> Result<Option<Investigation>>;
}

impl HttpStore for Db {
    fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        Db::get_task_by_id(self, id)
    }
    fn create_task(&self, task: &ScheduledTask) -> Result<()> {
        Db::create_task(self, task)
    }
    fn delete_task(&self, id: &str) -> Result<()> {
        Db::delete_task(self, id)
    }
    fn get_tasks_for_group(&self, group_folder: &str) -> Result<Vec<ScheduledTask>> {
        Db::get_tasks_for_group(self, group_folder)
    }
    fn get_session_rows(&self) -> Result<Vec<SessionRow>> {
        Db::get_session_rows(self)
    }
    fn upsert_investigation(&self, inv: &Investigation) -> Result<()> {
        Db::upsert_investigation(self, inv)
    }
    fn get_investigation(&self, id: &str) -> Result<Option<Investigation>> {
        Db::get_investigation(self, id)
    }
    fn list_investigations(&self, limit: usize) -> Result<Vec<Investigation>> {
        Db::list_investigations(self, limit)
    }
    fn latest_investigation_for_alert(&self, alert_id: &str) -> Result<Option<Investigation>> {
        Db::latest_investigation_for_alert(self, alert_id)
    }
}

/// Run a store operation on the blocking pool. A panic inside the store is
/// contained and reported as an error instead of tearing down the request
/// task.
pub(crate) async fn run_blocking<T, F>(store: &Arc<dyn HttpStore>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn HttpStore) -> Result<T> + Send + 'static,
{
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || f(store.as_ref()))
        .await
        .map_err(|e| Error::Db(format!("store task failed: {e}")))?
}
