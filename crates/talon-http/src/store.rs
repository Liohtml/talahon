//! The slice of `talon-db` the HTTP channel uses, behind a trait so the
//! server can be tested with an in-memory fake. [`talon_db::Db`] implements
//! it by delegation.
//!
//! All methods are blocking (SQLite); the server calls them through
//! [`run_blocking`] so they never stall the async runtime.

use std::collections::BTreeMap;
use std::sync::Arc;

use talon_core::types::{ScheduledTask, SessionRow};
use talon_core::{Error, Result};
use talon_db::{Db, Investigation, InvestigationTiming};

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
    /// Number of investigations per status (`queued`, `running`, ...).
    fn investigation_status_counts(&self) -> Result<BTreeMap<String, u64>> {
        let mut counts = BTreeMap::new();
        for inv in self.list_investigations(usize::MAX)? {
            *counts.entry(inv.status).or_insert(0) += 1;
        }
        Ok(counts)
    }
    /// Completed and failed investigations whose last status change
    /// (`updated_at`) is at or after `since`, latest change first, at most
    /// `limit` (for the health metrics). The default reads every row; the
    /// database answers it from an index.
    fn finished_investigations_since(
        &self,
        since: &str,
        limit: usize,
    ) -> Result<Vec<InvestigationTiming>> {
        Ok(finished_since(
            self.list_investigations(usize::MAX)?,
            since,
            limit,
        ))
    }
}

/// [`HttpStore::finished_investigations_since`] over full rows.
pub(crate) fn finished_since(
    rows: Vec<Investigation>,
    since: &str,
    limit: usize,
) -> Vec<InvestigationTiming> {
    let mut finished: Vec<InvestigationTiming> = rows
        .into_iter()
        .filter(|i| {
            i.updated_at.as_str() >= since && matches!(i.status.as_str(), "completed" | "failed")
        })
        .map(|i| InvestigationTiming {
            status: i.status,
            created_at: i.created_at,
            updated_at: i.updated_at,
        })
        .collect();
    finished.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    finished.truncate(limit);
    finished
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
    fn investigation_status_counts(&self) -> Result<BTreeMap<String, u64>> {
        Db::investigation_status_counts(self)
    }
    fn finished_investigations_since(
        &self,
        since: &str,
        limit: usize,
    ) -> Result<Vec<InvestigationTiming>> {
        Db::finished_investigations_since(self, since, limit)
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
