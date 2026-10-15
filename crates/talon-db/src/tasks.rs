//! Scheduled tasks and their run logs.

use rusqlite::{Row, params};
use talon_core::paths::assert_valid_group_folder;
use talon_core::time::now_iso;
use talon_core::types::{
    ContextMode, ScheduleType, ScheduledTask, TaskRunLog, TaskRunStatus, TaskStatus, TaskUpdate,
};
use talon_core::{Error, Result};

use crate::{Db, SqlResultExt, col, sql_limit};

/// Maximum length of a recorded task owner (an IPC key or `host`).
pub const MAX_TASK_OWNER_LEN: usize = 128;

const TASK_COLUMNS: &str = "id, group_folder, chat_jid, prompt, script, schedule_type, \
     schedule_value, context_mode, next_run, last_run, last_result, status, created_at";

/// A task row that could not be mapped onto [`ScheduledTask`] (unknown enum
/// value written by hand or by a newer release).
struct CorruptRow {
    id: String,
    reason: String,
}

fn task_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<std::result::Result<ScheduledTask, CorruptRow>> {
    let id = col::text(row, "id")?;
    let schedule_type_raw = col::text(row, "schedule_type")?;
    let Some(schedule_type) = ScheduleType::parse(&schedule_type_raw) else {
        return Ok(Err(CorruptRow {
            id,
            reason: format!("unknown schedule_type {schedule_type_raw:?}"),
        }));
    };
    // NULL -> 'active' (the column default).
    let status_raw = col::opt_text(row, "status")?.unwrap_or_else(|| "active".to_string());
    let Some(status) = TaskStatus::parse(&status_raw) else {
        return Ok(Err(CorruptRow {
            id,
            reason: format!("unknown status {status_raw:?}"),
        }));
    };
    // Anything but 'group' is treated as isolated; isolated is also the
    // less privileged mode, so unknown values fall back to it.
    let context_mode = col::opt_text(row, "context_mode")?
        .and_then(|m| ContextMode::parse(&m))
        .unwrap_or_default();
    Ok(Ok(ScheduledTask {
        group_folder: col::text(row, "group_folder")?,
        chat_jid: col::text(row, "chat_jid")?,
        prompt: col::text(row, "prompt")?,
        script: col::opt_text(row, "script")?.filter(|s| !s.is_empty()),
        schedule_type,
        schedule_value: col::text(row, "schedule_value")?,
        context_mode,
        next_run: col::opt_text(row, "next_run")?,
        last_run: col::opt_text(row, "last_run")?,
        last_result: col::opt_text(row, "last_result")?,
        status,
        created_at: col::text(row, "created_at")?,
        id,
    }))
}

/// Collect mapped rows, skipping (and logging) corrupt ones.
fn collect_tasks(
    rows: impl Iterator<Item = rusqlite::Result<std::result::Result<ScheduledTask, CorruptRow>>>,
) -> Result<Vec<ScheduledTask>> {
    let mut out = Vec::new();
    for r in rows {
        match r.db()? {
            Ok(t) => out.push(t),
            Err(c) => {
                tracing::warn!(task_id = %c.id, reason = %c.reason, "skipping corrupt scheduled task row")
            }
        }
    }
    Ok(out)
}

fn parse_run_status(s: &str) -> Option<TaskRunStatus> {
    match s {
        "success" => Some(TaskRunStatus::Success),
        "error" => Some(TaskRunStatus::Error),
        _ => None,
    }
}

impl Db {
    // ---- scheduled tasks -------------------------------------------------

    /// Insert a new task. Fails if the id already exists or the group folder
    /// is not a valid folder name. An empty `script` is stored as NULL.
    ///
    /// The new task has no owner record (it is host-owned, see
    /// [`Db::get_task_owner`]); a stale owner row left behind for the same id
    /// (a deletion by a connection without foreign-key enforcement) is
    /// cleared in the same transaction, so a re-created task never inherits
    /// a previous owner.
    pub fn create_task(&self, task: &ScheduledTask) -> Result<()> {
        if task.id.is_empty() {
            return Err(Error::invalid("task id must not be empty"));
        }
        assert_valid_group_folder(&task.group_folder)?;
        let script = task.script.as_deref().filter(|s| !s.is_empty());
        self.with_tx(false, |tx| {
            tx.prepare_cached("DELETE FROM task_owners WHERE task_id = ?1")
                .db()?
                .execute([&task.id])
                .db()?;
            tx.prepare_cached(
                "INSERT INTO scheduled_tasks (id, group_folder, chat_jid, prompt, script,
                   schedule_type, schedule_value, context_mode, next_run, last_run, last_result,
                   status, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )
            .db()?
            .execute(params![
                task.id,
                task.group_folder,
                task.chat_jid,
                task.prompt,
                script,
                task.schedule_type.as_str(),
                task.schedule_value,
                task.context_mode.as_str(),
                task.next_run,
                task.last_run,
                task.last_result,
                task.status.as_str(),
                task.created_at,
            ])
            .db()?;
            Ok(())
        })
    }

    /// One task by id. A row with an unknown `schedule_type` / `status`
    /// value is reported as [`Error::Db`].
    pub fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        self.with_conn(|conn| {
            let sql = format!("SELECT {TASK_COLUMNS} FROM scheduled_tasks WHERE id = ?1");
            let mut stmt = conn.prepare_cached(&sql).db()?;
            let mut rows = stmt.query_map([id], task_from_row).db()?;
            match rows.next().transpose().db()? {
                None => Ok(None),
                Some(Ok(t)) => Ok(Some(t)),
                Some(Err(c)) => Err(Error::Db(format!(
                    "corrupt scheduled task {}: {}",
                    c.id, c.reason
                ))),
            }
        })
    }

    /// Tasks of one group, newest first. Corrupt rows are skipped.
    pub fn get_tasks_for_group(&self, group_folder: &str) -> Result<Vec<ScheduledTask>> {
        self.with_conn(|conn| {
            let sql = format!(
                "SELECT {TASK_COLUMNS} FROM scheduled_tasks WHERE group_folder = ?1 \
                 ORDER BY created_at DESC"
            );
            let mut stmt = conn.prepare_cached(&sql).db()?;
            let rows = stmt.query_map([group_folder], task_from_row).db()?;
            collect_tasks(rows)
        })
    }

    /// Tasks whose `chat_jid` is one of `jids`, newest first. Corrupt rows
    /// are skipped; an empty list returns no tasks (without touching the
    /// database).
    ///
    /// Used for per-lane `current_tasks.json` snapshots so a container start
    /// loads only its own lane's tasks instead of the whole table (N-3). The
    /// JID list is bound as one JSON array parameter (`json_each`), so the
    /// statement text is constant and nothing is spliced into the SQL.
    pub fn get_tasks_for_jids(&self, jids: &[String]) -> Result<Vec<ScheduledTask>> {
        if jids.is_empty() {
            return Ok(Vec::new());
        }
        let jids_json = serde_json::to_string(jids)?;
        self.with_conn(|conn| {
            let sql = format!(
                "SELECT {TASK_COLUMNS} FROM scheduled_tasks \
                 WHERE chat_jid IN (SELECT value FROM json_each(?1)) \
                 ORDER BY created_at DESC, id"
            );
            let mut stmt = conn.prepare_cached(&sql).db()?;
            let rows = stmt.query_map([&jids_json], task_from_row).db()?;
            collect_tasks(rows)
        })
    }

    /// Number of tasks recorded as owned by `owner` (an IPC key, see
    /// [`Db::set_task_owner`]) that are not `completed` — i.e. active and
    /// paused tasks (a NULL status counts as active, like everywhere else).
    /// Orphaned owner records are ignored; host-owned tasks (no record) are
    /// never counted. Used for per-lane task quotas (N-3).
    pub fn count_tasks_owned_by(&self, owner: &str) -> Result<u64> {
        self.with_conn(|conn| {
            let n: i64 = conn
                .prepare_cached(
                    "SELECT COUNT(*) FROM task_owners o
                     JOIN scheduled_tasks t ON t.id = o.task_id
                     WHERE o.owner = ?1 AND COALESCE(t.status, 'active') != 'completed'",
                )
                .db()?
                .query_row([owner], |row| row.get(0))
                .db()?;
            // COUNT(*) is never negative.
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    /// All tasks, newest first. Corrupt rows are skipped.
    pub fn get_all_tasks(&self) -> Result<Vec<ScheduledTask>> {
        self.with_conn(|conn| {
            let sql =
                format!("SELECT {TASK_COLUMNS} FROM scheduled_tasks ORDER BY created_at DESC");
            let mut stmt = conn.prepare_cached(&sql).db()?;
            let rows = stmt.query_map([], task_from_row).db()?;
            collect_tasks(rows)
        })
    }

    /// Apply a partial update. Fields left `None` are unchanged; an empty
    /// update is a no-op, as is updating an unknown id. A script of
    /// `Some(Some(""))` clears it like `Some(None)`.
    pub fn update_task(&self, id: &str, update: &TaskUpdate) -> Result<()> {
        if update.is_empty() {
            return Ok(());
        }
        let script = update
            .script
            .as_ref()
            .map(|s| s.as_deref().filter(|s| !s.is_empty()));
        self.with_conn(|conn| {
            // One constant statement: each column is only assigned when its
            // "present" flag is set.
            conn.prepare_cached(
                "UPDATE scheduled_tasks SET
                   prompt = CASE WHEN ?1 THEN ?2 ELSE prompt END,
                   script = CASE WHEN ?3 THEN ?4 ELSE script END,
                   schedule_type = CASE WHEN ?5 THEN ?6 ELSE schedule_type END,
                   schedule_value = CASE WHEN ?7 THEN ?8 ELSE schedule_value END,
                   context_mode = CASE WHEN ?9 THEN ?10 ELSE context_mode END,
                   next_run = CASE WHEN ?11 THEN ?12 ELSE next_run END,
                   status = CASE WHEN ?13 THEN ?14 ELSE status END
                 WHERE id = ?15",
            )
            .db()?
            .execute(params![
                update.prompt.is_some(),
                update.prompt,
                script.is_some(),
                script.flatten(),
                update.schedule_type.is_some(),
                update.schedule_type.map(|t| t.as_str()),
                update.schedule_value.is_some(),
                update.schedule_value,
                update.context_mode.is_some(),
                update.context_mode.map(|m| m.as_str()),
                update.next_run.is_some(),
                update.next_run.clone().flatten(),
                update.status.is_some(),
                update.status.map(|s| s.as_str()),
                id,
            ])
            .db()?;
            Ok(())
        })
    }

    /// Deletes the task, its run logs and its owner record (atomically).
    pub fn delete_task(&self, id: &str) -> Result<()> {
        self.with_tx(false, |tx| {
            tx.prepare_cached("DELETE FROM task_run_logs WHERE task_id = ?1")
                .db()?
                .execute([id])
                .db()?;
            tx.prepare_cached("DELETE FROM task_owners WHERE task_id = ?1")
                .db()?
                .execute([id])
                .db()?;
            tx.prepare_cached("DELETE FROM scheduled_tasks WHERE id = ?1")
                .db()?
                .execute([id])
                .db()?;
            Ok(())
        })
    }

    /// Record who created task `task_id` (normally the IPC key of the lane
    /// that scheduled it over IPC). Replaces an existing record.
    ///
    /// Fails with [`Error::NotFound`] when the task does not exist and with
    /// [`Error::InvalidInput`] when `owner` is empty, longer than
    /// [`MAX_TASK_OWNER_LEN`] bytes, padded with whitespace or contains
    /// control characters.
    pub fn set_task_owner(&self, task_id: &str, owner: &str) -> Result<()> {
        if task_id.is_empty() {
            return Err(Error::invalid("task id must not be empty"));
        }
        if owner.is_empty()
            || owner.len() > MAX_TASK_OWNER_LEN
            || owner.trim() != owner
            || owner.chars().any(char::is_control)
        {
            return Err(Error::invalid("invalid task owner"));
        }
        let created_at = now_iso();
        self.with_tx(true, |tx| {
            let exists = tx
                .prepare_cached("SELECT 1 FROM scheduled_tasks WHERE id = ?1")
                .db()?
                .exists([task_id])
                .db()?;
            if !exists {
                return Err(Error::NotFound(format!("scheduled task {task_id:?}")));
            }
            tx.prepare_cached(
                "INSERT INTO task_owners (task_id, owner, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(task_id) DO UPDATE
                   SET owner = excluded.owner, created_at = excluded.created_at",
            )
            .db()?
            .execute(params![task_id, owner, created_at])
            .db()?;
            Ok(())
        })
    }

    /// Recorded owner of task `task_id`. `None` when the task has no owner
    /// record — i.e. it was created by the host (HTTP investigations, seeded
    /// tasks, rows that predate ownership records) — or does not exist.
    /// Orphaned records (whose task is gone) are ignored.
    pub fn get_task_owner(&self, task_id: &str) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT o.owner FROM task_owners o
                     JOIN scheduled_tasks t ON t.id = o.task_id
                     WHERE o.task_id = ?1",
                )
                .db()?;
            let mut rows = stmt
                .query_map([task_id], |row| col::opt_text(row, "owner"))
                .db()?;
            Ok(rows.next().transpose().db()?.flatten())
        })
    }

    /// Active tasks with `next_run <= now_iso`, oldest due first.
    pub fn get_due_tasks(&self, now_iso: &str) -> Result<Vec<ScheduledTask>> {
        self.with_conn(|conn| {
            let sql = format!(
                "SELECT {TASK_COLUMNS} FROM scheduled_tasks
                 WHERE status = 'active' AND next_run IS NOT NULL AND next_run <= ?1
                 ORDER BY next_run"
            );
            let mut stmt = conn.prepare_cached(&sql).db()?;
            let rows = stmt.query_map([now_iso], task_from_row).db()?;
            collect_tasks(rows)
        })
    }

    /// Record a finished run: sets `last_run = now`, `last_result`,
    /// `next_run`, and `status = 'completed'` when `next_run` is `None`.
    pub fn update_task_after_run(
        &self,
        id: &str,
        next_run: Option<&str>,
        last_result: &str,
    ) -> Result<()> {
        self.with_conn(|conn| {
            conn.prepare_cached(
                "UPDATE scheduled_tasks
                 SET next_run = ?1, last_run = ?2, last_result = ?3,
                     status = CASE WHEN ?1 IS NULL THEN 'completed' ELSE status END
                 WHERE id = ?4",
            )
            .db()?
            .execute(params![next_run, now_iso(), last_result, id])
            .db()?;
            Ok(())
        })
    }

    /// Append a run log. The task must exist (foreign key).
    pub fn log_task_run(&self, log: &TaskRunLog) -> Result<()> {
        self.with_conn(|conn| {
            conn.prepare_cached(
                "INSERT INTO task_run_logs (task_id, run_at, duration_ms, status, result, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .db()?
            .execute(params![
                log.task_id,
                log.run_at,
                log.duration_ms,
                log.status.as_str(),
                log.result,
                log.error,
            ])
            .db()?;
            Ok(())
        })
    }

    /// Up to `limit` run logs of a task, most recent first.
    pub fn get_task_run_logs(&self, task_id: &str, limit: usize) -> Result<Vec<TaskRunLog>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT task_id, run_at, duration_ms, status, result, error
                     FROM task_run_logs WHERE task_id = ?1
                     ORDER BY run_at DESC, id DESC LIMIT ?2",
                )
                .db()?;
            let rows = stmt
                .query_map(params![task_id, sql_limit(limit)], |row| {
                    let status_raw = col::text(row, "status")?;
                    Ok(TaskRunLog {
                        task_id: col::text(row, "task_id")?,
                        run_at: col::text(row, "run_at")?,
                        duration_ms: col::opt_i64(row, "duration_ms")?.unwrap_or(0),
                        // Anything that is not a recorded success is an error.
                        status: parse_run_status(&status_raw).unwrap_or(TaskRunStatus::Error),
                        result: col::opt_text(row, "result")?,
                        error: col::opt_text(row, "error")?,
                    })
                })
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str) -> ScheduledTask {
        ScheduledTask {
            id: id.into(),
            group_folder: "main".into(),
            chat_jid: "group@g.us".into(),
            prompt: "do something".into(),
            script: None,
            schedule_type: ScheduleType::Once,
            schedule_value: "2024-06-01T00:00:00.000Z".into(),
            context_mode: ContextMode::Isolated,
            next_run: Some("2024-06-01T00:00:00.000Z".into()),
            last_run: None,
            last_result: None,
            status: TaskStatus::Active,
            created_at: "2024-01-01T00:00:00.000Z".into(),
        }
    }

    // --- task CRUD ---

    #[test]
    fn creates_and_retrieves_a_task() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("task-1")).unwrap();
        let t = db.get_task_by_id("task-1").unwrap().unwrap();
        assert_eq!(t.prompt, "do something");
        assert_eq!(t.status, TaskStatus::Active);
        assert_eq!(t, task("task-1"));
    }

    #[test]
    fn updates_task_status() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&ScheduledTask {
            next_run: None,
            ..task("task-2")
        })
        .unwrap();
        db.update_task(
            "task-2",
            &TaskUpdate {
                status: Some(TaskStatus::Paused),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            db.get_task_by_id("task-2").unwrap().unwrap().status,
            TaskStatus::Paused
        );
    }

    #[test]
    fn deletes_a_task_and_its_run_logs() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("task-3")).unwrap();
        db.log_task_run(&TaskRunLog {
            task_id: "task-3".into(),
            run_at: "2024-06-01T00:00:00.000Z".into(),
            duration_ms: 5,
            status: TaskRunStatus::Success,
            result: Some("ok".into()),
            error: None,
        })
        .unwrap();
        db.delete_task("task-3").unwrap();
        assert_eq!(db.get_task_by_id("task-3").unwrap(), None);
        assert!(db.get_task_run_logs("task-3", 10).unwrap().is_empty());
    }

    // --- additional coverage ---

    #[test]
    fn duplicate_id_and_invalid_folder_are_rejected() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("t")).unwrap();
        assert!(matches!(db.create_task(&task("t")), Err(Error::Db(_))));
        let bad = ScheduledTask {
            group_folder: "../etc".into(),
            ..task("t2")
        };
        assert!(matches!(db.create_task(&bad), Err(Error::Security(_))));
        assert!(matches!(
            db.create_task(&task("")),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn update_task_touches_only_given_fields() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&ScheduledTask {
            script: Some("echo hi".into()),
            ..task("t")
        })
        .unwrap();

        db.update_task(
            "t",
            &TaskUpdate {
                prompt: Some("new prompt".into()),
                schedule_type: Some(ScheduleType::Cron),
                schedule_value: Some("0 9 * * *".into()),
                context_mode: Some(ContextMode::Group),
                ..Default::default()
            },
        )
        .unwrap();
        let t = db.get_task_by_id("t").unwrap().unwrap();
        assert_eq!(t.prompt, "new prompt");
        assert_eq!(t.schedule_type, ScheduleType::Cron);
        assert_eq!(t.schedule_value, "0 9 * * *");
        assert_eq!(t.context_mode, ContextMode::Group);
        assert_eq!(t.script.as_deref(), Some("echo hi"));
        assert_eq!(t.next_run.as_deref(), Some("2024-06-01T00:00:00.000Z"));
        assert_eq!(t.status, TaskStatus::Active);

        // Clear script (both spellings) and next_run.
        db.update_task(
            "t",
            &TaskUpdate {
                script: Some(Some(String::new())),
                next_run: Some(None),
                ..Default::default()
            },
        )
        .unwrap();
        let t = db.get_task_by_id("t").unwrap().unwrap();
        assert_eq!(t.script, None);
        assert_eq!(t.next_run, None);
        assert_eq!(t.prompt, "new prompt");

        db.update_task(
            "t",
            &TaskUpdate {
                script: Some(Some("x".into())),
                next_run: Some(Some("2025-01-01T00:00:00.000Z".into())),
                ..Default::default()
            },
        )
        .unwrap();
        db.update_task(
            "t",
            &TaskUpdate {
                script: Some(None),
                ..Default::default()
            },
        )
        .unwrap();
        let t = db.get_task_by_id("t").unwrap().unwrap();
        assert_eq!(t.script, None);
        assert_eq!(t.next_run.as_deref(), Some("2025-01-01T00:00:00.000Z"));

        // Empty update and unknown id are no-ops.
        db.update_task("t", &TaskUpdate::default()).unwrap();
        db.update_task(
            "missing",
            &TaskUpdate {
                prompt: Some("x".into()),
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn listing_orders_newest_first_and_filters_by_group() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("a")).unwrap();
        db.create_task(&ScheduledTask {
            created_at: "2024-02-01T00:00:00.000Z".into(),
            group_folder: "other".into(),
            ..task("b")
        })
        .unwrap();
        let all: Vec<_> = db
            .get_all_tasks()
            .unwrap()
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(all, vec!["b", "a"]);
        let main: Vec<_> = db
            .get_tasks_for_group("main")
            .unwrap()
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(main, vec!["a"]);
    }

    #[test]
    fn due_tasks_are_active_and_ordered_by_next_run() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&ScheduledTask {
            next_run: Some("2024-01-03T00:00:00.000Z".into()),
            ..task("late")
        })
        .unwrap();
        db.create_task(&ScheduledTask {
            next_run: Some("2024-01-02T00:00:00.000Z".into()),
            ..task("early")
        })
        .unwrap();
        db.create_task(&ScheduledTask {
            next_run: Some("2024-01-01T00:00:00.000Z".into()),
            status: TaskStatus::Paused,
            ..task("paused")
        })
        .unwrap();
        db.create_task(&ScheduledTask {
            next_run: None,
            ..task("never")
        })
        .unwrap();
        db.create_task(&ScheduledTask {
            next_run: Some("2099-01-01T00:00:00.000Z".into()),
            ..task("future")
        })
        .unwrap();
        let due: Vec<_> = db
            .get_due_tasks("2024-06-01T00:00:00.000Z")
            .unwrap()
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(due, vec!["early", "late"]);
        // Boundary is inclusive.
        let due = db.get_due_tasks("2024-01-02T00:00:00.000Z").unwrap();
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn update_after_run_sets_fields_and_completes_once_tasks() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("recurring")).unwrap();
        db.create_task(&task("once")).unwrap();

        db.update_task_after_run("recurring", Some("2024-07-01T00:00:00.000Z"), "ok")
            .unwrap();
        let t = db.get_task_by_id("recurring").unwrap().unwrap();
        assert_eq!(t.status, TaskStatus::Active);
        assert_eq!(t.next_run.as_deref(), Some("2024-07-01T00:00:00.000Z"));
        assert_eq!(t.last_result.as_deref(), Some("ok"));
        assert!(talon_core::time::parse_iso(t.last_run.as_deref().unwrap()).is_some());

        db.update_task_after_run("once", None, "done").unwrap();
        let t = db.get_task_by_id("once").unwrap().unwrap();
        assert_eq!(t.status, TaskStatus::Completed);
        assert_eq!(t.next_run, None);
        assert!(
            db.get_due_tasks("2099-01-01T00:00:00.000Z")
                .unwrap()
                .iter()
                .all(|t| t.id != "once")
        );
    }

    #[test]
    fn run_logs_most_recent_first_with_limit() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("t")).unwrap();
        for i in 0..5 {
            db.log_task_run(&TaskRunLog {
                task_id: "t".into(),
                run_at: format!("2024-01-0{}T00:00:00.000Z", i + 1),
                duration_ms: i,
                status: if i % 2 == 0 {
                    TaskRunStatus::Success
                } else {
                    TaskRunStatus::Error
                },
                result: (i % 2 == 0).then(|| "ok".to_string()),
                error: (i % 2 == 1).then(|| "boom".to_string()),
            })
            .unwrap();
        }
        let logs = db.get_task_run_logs("t", 3).unwrap();
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0].run_at, "2024-01-05T00:00:00.000Z");
        assert_eq!(logs[0].status, TaskRunStatus::Success);
        assert_eq!(logs[1].status, TaskRunStatus::Error);
        assert_eq!(logs[1].error.as_deref(), Some("boom"));
        // Logs for unknown tasks violate the foreign key.
        let orphan = TaskRunLog {
            task_id: "missing".into(),
            run_at: "x".into(),
            duration_ms: 0,
            status: TaskRunStatus::Success,
            result: None,
            error: None,
        };
        assert!(db.log_task_run(&orphan).is_err());
    }

    #[test]
    fn corrupt_rows_are_skipped_in_lists_and_errors_by_id() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("good")).unwrap();
        db.with_conn(|c| {
            c.execute(
                "INSERT INTO scheduled_tasks (id, group_folder, chat_jid, prompt, schedule_type,
                   schedule_value, next_run, status, created_at)
                 VALUES ('bad', 'main', 'j', 'p', 'weekly', 'x', '2024-01-01', 'active', '2024')",
                [],
            )
            .db()
        })
        .unwrap();
        assert_eq!(db.get_all_tasks().unwrap().len(), 1);
        assert_eq!(db.get_due_tasks("2099").unwrap().len(), 1);
        assert!(matches!(db.get_task_by_id("bad"), Err(Error::Db(_))));
    }

    // --- task owners ---

    #[test]
    fn task_owner_roundtrip_and_upsert() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("t")).unwrap();
        // freshly created tasks are host-owned (no record)
        assert_eq!(db.get_task_owner("t").unwrap(), None);
        db.set_task_owner("t", "copilot-u-alice").unwrap();
        assert_eq!(
            db.get_task_owner("t").unwrap().as_deref(),
            Some("copilot-u-alice")
        );
        db.set_task_owner("t", "whatsapp_main").unwrap();
        assert_eq!(
            db.get_task_owner("t").unwrap().as_deref(),
            Some("whatsapp_main")
        );
        // unknown task
        assert_eq!(db.get_task_owner("missing").unwrap(), None);
    }

    #[test]
    fn set_task_owner_validates_input() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("t")).unwrap();
        assert!(matches!(
            db.set_task_owner("missing", "copilot-u-alice"),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            db.set_task_owner("", "x"),
            Err(Error::InvalidInput(_))
        ));
        let long = "a".repeat(MAX_TASK_OWNER_LEN + 1);
        for bad in ["", " x", "x ", "a\nb", "a\u{0}b", long.as_str()] {
            assert!(
                matches!(db.set_task_owner("t", bad), Err(Error::InvalidInput(_))),
                "{bad:?}"
            );
        }
        assert_eq!(db.get_task_owner("t").unwrap(), None);
    }

    #[test]
    fn delete_task_removes_the_owner_and_recreated_tasks_are_host_owned() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("t")).unwrap();
        db.set_task_owner("t", "copilot-u-alice").unwrap();
        db.delete_task("t").unwrap();
        let rows: i64 = db
            .with_conn(|c| {
                c.query_row("SELECT COUNT(*) FROM task_owners", [], |r| r.get(0))
                    .db()
            })
            .unwrap();
        assert_eq!(rows, 0);
        db.create_task(&task("t")).unwrap();
        assert_eq!(db.get_task_owner("t").unwrap(), None);
    }

    #[test]
    fn duplicate_create_keeps_the_existing_owner() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("t")).unwrap();
        db.set_task_owner("t", "copilot-u-alice").unwrap();
        assert!(db.create_task(&task("t")).is_err());
        assert_eq!(
            db.get_task_owner("t").unwrap().as_deref(),
            Some("copilot-u-alice")
        );
    }

    #[test]
    fn stale_owner_rows_are_never_inherited() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("copilot-alert-digest-15m")).unwrap();
        db.set_task_owner("copilot-alert-digest-15m", "copilot-u-alice")
            .unwrap();
        // A connection without foreign-key enforcement (e.g. an older
        // release) deletes the task and leaves the owner row behind.
        db.with_conn(|c| {
            c.execute_batch(
                "PRAGMA foreign_keys = OFF;
                 DELETE FROM scheduled_tasks WHERE id = 'copilot-alert-digest-15m';
                 PRAGMA foreign_keys = ON;",
            )
            .db()
        })
        .unwrap();
        // the orphan is ignored by lookups...
        assert_eq!(db.get_task_owner("copilot-alert-digest-15m").unwrap(), None);
        // ...and cleared when the host re-creates the task
        db.create_task(&task("copilot-alert-digest-15m")).unwrap();
        assert_eq!(db.get_task_owner("copilot-alert-digest-15m").unwrap(), None);
        let rows: i64 = db
            .with_conn(|c| {
                c.query_row("SELECT COUNT(*) FROM task_owners", [], |r| r.get(0))
                    .db()
            })
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn deleting_a_task_row_directly_cascades_to_its_owner() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("t")).unwrap();
        db.set_task_owner("t", "other-group").unwrap();
        db.with_conn(|c| {
            c.execute("DELETE FROM scheduled_tasks WHERE id = 't'", [])
                .db()
        })
        .unwrap();
        let rows: i64 = db
            .with_conn(|c| {
                c.query_row("SELECT COUNT(*) FROM task_owners", [], |r| r.get(0))
                    .db()
            })
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn task_owners_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::DB_FILE_NAME);
        {
            let db = Db::open(&path).unwrap();
            db.create_task(&task("t")).unwrap();
            db.set_task_owner("t", "copilot-u-bob").unwrap();
        }
        for _ in 0..2 {
            let db = Db::open(&path).unwrap();
            assert_eq!(
                db.get_task_owner("t").unwrap().as_deref(),
                Some("copilot-u-bob")
            );
        }
    }

    // --- per-lane queries (N-3) ---

    #[test]
    fn get_tasks_for_jids_filters_by_jid_newest_first() {
        let db = Db::open_in_memory().unwrap();
        for (id, jid, created) in [
            ("a1", "http:copilot:u:alice", "2024-01-01T00:00:00.000Z"),
            ("a2", "http:copilot:u:alice", "2024-03-01T00:00:00.000Z"),
            ("b1", "http:copilot:u:bob", "2024-02-01T00:00:00.000Z"),
            ("w1", "webhook:copilot", "2024-04-01T00:00:00.000Z"),
        ] {
            db.create_task(&ScheduledTask {
                chat_jid: jid.into(),
                group_folder: "copilot".into(),
                created_at: created.into(),
                ..task(id)
            })
            .unwrap();
        }
        let ids = |jids: &[&str]| -> Vec<String> {
            let jids: Vec<String> = jids.iter().map(|j| (*j).to_string()).collect();
            db.get_tasks_for_jids(&jids)
                .unwrap()
                .into_iter()
                .map(|t| t.id)
                .collect()
        };
        assert_eq!(ids(&["http:copilot:u:alice"]), vec!["a2", "a1"]);
        assert_eq!(
            ids(&["http:copilot:u:alice", "http:copilot:u:bob"]),
            vec!["a2", "b1", "a1"]
        );
        // duplicates in the list do not duplicate rows
        assert_eq!(
            ids(&["http:copilot:u:bob", "http:copilot:u:bob"]),
            vec!["b1"]
        );
        assert!(ids(&[]).is_empty());
        assert!(ids(&["unknown@g.us"]).is_empty());
        // values are bound, never spliced: quotes / SQL / JSON-ish text are
        // just non-matching JIDs
        assert!(ids(&["' OR 1=1 --", "\"]", "%", "*"]).is_empty());
        // full rows come back
        let t = &db
            .get_tasks_for_jids(&["webhook:copilot".to_string()])
            .unwrap()[0];
        assert_eq!(t.chat_jid, "webhook:copilot");
        assert_eq!(t.prompt, "do something");
    }

    #[test]
    fn get_tasks_for_jids_skips_corrupt_rows() {
        let db = Db::open_in_memory().unwrap();
        db.create_task(&task("good")).unwrap();
        db.with_conn(|c| {
            c.execute(
                "INSERT INTO scheduled_tasks (id, group_folder, chat_jid, prompt, schedule_type,
                   schedule_value, next_run, status, created_at)
                 VALUES ('bad', 'main', 'group@g.us', 'p', 'weekly', 'x', NULL, 'active', '2024')",
                [],
            )
            .db()
        })
        .unwrap();
        let got = db.get_tasks_for_jids(&["group@g.us".to_string()]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "good");
    }

    #[test]
    fn count_tasks_owned_by_counts_active_and_paused_only() {
        let db = Db::open_in_memory().unwrap();
        for (id, status, owner) in [
            ("a-active", TaskStatus::Active, Some("copilot-u-alice")),
            ("a-paused", TaskStatus::Paused, Some("copilot-u-alice")),
            ("a-done", TaskStatus::Completed, Some("copilot-u-alice")),
            ("b-active", TaskStatus::Active, Some("copilot-u-bob")),
            ("host", TaskStatus::Active, None),
        ] {
            db.create_task(&ScheduledTask { status, ..task(id) })
                .unwrap();
            if let Some(o) = owner {
                db.set_task_owner(id, o).unwrap();
            }
        }
        assert_eq!(db.count_tasks_owned_by("copilot-u-alice").unwrap(), 2);
        assert_eq!(db.count_tasks_owned_by("copilot-u-bob").unwrap(), 1);
        assert_eq!(db.count_tasks_owned_by("host").unwrap(), 0);
        assert_eq!(db.count_tasks_owned_by("nobody").unwrap(), 0);
        assert_eq!(db.count_tasks_owned_by("").unwrap(), 0);

        // completing / deleting a task frees its slot; resuming takes it back
        db.update_task_after_run("a-active", None, "done").unwrap();
        assert_eq!(db.count_tasks_owned_by("copilot-u-alice").unwrap(), 1);
        db.delete_task("a-paused").unwrap();
        assert_eq!(db.count_tasks_owned_by("copilot-u-alice").unwrap(), 0);
        db.update_task(
            "a-done",
            &TaskUpdate {
                status: Some(TaskStatus::Active),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(db.count_tasks_owned_by("copilot-u-alice").unwrap(), 1);
    }

    #[test]
    fn count_tasks_owned_by_treats_null_status_as_active_and_ignores_orphans() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            c.execute_batch(
                "INSERT INTO scheduled_tasks (id, group_folder, chat_jid, prompt, schedule_type,
                   schedule_value, status, created_at)
                 VALUES ('legacy', 'main', 'j', 'p', 'cron', '0 9 * * *', NULL, '2024');
                 INSERT INTO task_owners (task_id, owner, created_at)
                 VALUES ('legacy', 'lane-1', '2024');
                 PRAGMA foreign_keys = OFF;
                 INSERT INTO task_owners (task_id, owner, created_at)
                 VALUES ('gone', 'lane-1', '2024');
                 PRAGMA foreign_keys = ON;",
            )
            .db()
        })
        .unwrap();
        assert_eq!(db.count_tasks_owned_by("lane-1").unwrap(), 1);
    }

    #[test]
    fn per_lane_indexes_exist() {
        let db = Db::open_in_memory().unwrap();
        let names: Vec<String> = db
            .with_conn(|c| {
                let mut stmt = c
                    .prepare("SELECT name FROM sqlite_master WHERE type = 'index' ORDER BY name")
                    .db()?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .db()?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .db()?;
                Ok(rows)
            })
            .unwrap();
        for idx in ["idx_scheduled_tasks_chat_jid", "idx_task_owners_owner"] {
            assert!(names.iter().any(|n| n == idx), "missing {idx}: {names:?}");
        }
    }

    #[test]
    fn legacy_null_context_mode_and_status_read_as_defaults() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            c.execute(
                "INSERT INTO scheduled_tasks (id, group_folder, chat_jid, prompt, schedule_type,
                   schedule_value, context_mode, status, created_at)
                 VALUES ('t', 'main', 'j', 'p', 'cron', '* * * * *', NULL, NULL, '2024')",
                [],
            )
            .db()
        })
        .unwrap();
        let t = db.get_task_by_id("t").unwrap().unwrap();
        assert_eq!(t.context_mode, ContextMode::Isolated);
        assert_eq!(t.status, TaskStatus::Active);
    }
}
