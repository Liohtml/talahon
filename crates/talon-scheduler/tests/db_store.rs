//! The scheduler against the real SQLite store (`talon_db::Db`), through the
//! public API only. Real time; the tasks involved are already due.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use talon_core::time::{parse_iso, to_iso};
use talon_core::types::{
    ContextMode, RegisteredGroup, ScheduleType, ScheduledTask, TaskRunStatus, TaskStatus,
};
use talon_db::Db;
use talon_scheduler::{
    GroupQueue, QueueConfig, SchedulerConfig, TaskExecution, TaskExecutor, TaskRunContext,
    TaskRunOutcome, TaskScheduler, TaskStore,
};

struct Echo;

#[async_trait]
impl TaskExecutor for Echo {
    async fn execute(
        &self,
        task: &ScheduledTask,
        _group: &RegisteredGroup,
        _ctx: &TaskRunContext,
    ) -> TaskExecution {
        if task.prompt == "fail" {
            TaskExecution::failure("boom")
        } else {
            TaskExecution::success(Some(format!("ran {}", task.id)))
        }
    }
}

fn group() -> RegisteredGroup {
    RegisteredGroup {
        name: "Main".into(),
        folder: "main".into(),
        trigger: "@Talon".into(),
        added_at: "2026-01-01T00:00:00.000Z".into(),
        container_config: None,
        requires_trigger: None,
        is_main: true,
        session_key: None,
        ipc_key: None,
        ephemeral_session: false,
        trusted_session_commands: false,
    }
}

fn task(id: &str, schedule_type: ScheduleType, value: &str, prompt: &str) -> ScheduledTask {
    ScheduledTask {
        id: id.into(),
        group_folder: "main".into(),
        chat_jid: "main@g.us".into(),
        prompt: prompt.into(),
        script: None,
        schedule_type,
        schedule_value: value.into(),
        context_mode: ContextMode::Isolated,
        next_run: Some(to_iso(Utc::now() - chrono::Duration::seconds(60))),
        last_run: None,
        last_result: None,
        status: TaskStatus::Active,
        created_at: "2026-01-01T00:00:00.000Z".into(),
    }
}

fn scheduler(db: &Db, dir: &std::path::Path) -> TaskScheduler {
    let groups = HashMap::from([("main@g.us".to_string(), group())]);
    TaskScheduler::new(
        SchedulerConfig::default(),
        Arc::new(db.clone()),
        GroupQueue::new(QueueConfig::new(dir, 2)),
        Arc::new(Echo),
        Arc::new(move || groups.clone()),
    )
}

#[tokio::test]
async fn scheduler_runs_tasks_against_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    db.create_task(&task("every-minute", ScheduleType::Cron, "* * * * *", "go"))
        .unwrap();
    db.create_task(&task(
        "once",
        ScheduleType::Once,
        "2026-01-01T00:00:00",
        "go",
    ))
    .unwrap();
    db.create_task(&task("flaky", ScheduleType::Interval, "3600000", "fail"))
        .unwrap();
    let s = scheduler(&db, dir.path());

    let due = TaskStore::get_due_tasks(&db, &to_iso(Utc::now()))
        .await
        .unwrap();
    assert_eq!(due.len(), 3);

    for id in ["every-minute", "once", "flaky"] {
        let outcome = s.run_task("main@g.us", id).await;
        assert!(
            matches!(outcome, TaskRunOutcome::Finished(_)),
            "{id}: {outcome:?}"
        );
    }

    let now = Utc::now();
    let cron = db.get_task_by_id("every-minute").unwrap().unwrap();
    assert_eq!(cron.status, TaskStatus::Active);
    assert_eq!(cron.last_result.as_deref(), Some("ran every-minute"));
    assert!(cron.last_run.is_some());
    assert!(parse_iso(cron.next_run.as_deref().unwrap()).unwrap() > now);

    let once = db.get_task_by_id("once").unwrap().unwrap();
    assert_eq!(once.status, TaskStatus::Completed);
    assert_eq!(once.next_run, None);

    let flaky = db.get_task_by_id("flaky").unwrap().unwrap();
    assert_eq!(flaky.status, TaskStatus::Active);
    assert_eq!(flaky.last_result.as_deref(), Some("Error: boom"));
    // Retried after ~60 s (±20 % jitter) rather than in an hour.
    let retry_in = parse_iso(flaky.next_run.as_deref().unwrap()).unwrap() - now;
    assert!(retry_in <= chrono::Duration::seconds(75), "{retry_in}");

    let logs = db.get_task_run_logs("flaky", 10).unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].status, TaskRunStatus::Error);
    assert_eq!(logs[0].error.as_deref(), Some("boom"));
    let logs = db.get_task_run_logs("every-minute", 10).unwrap();
    assert_eq!(logs[0].status, TaskRunStatus::Success);
    assert_eq!(logs[0].result.as_deref(), Some("ran every-minute"));

    // Nothing is due any more.
    let due = TaskStore::get_due_tasks(&db, &to_iso(Utc::now()))
        .await
        .unwrap();
    assert!(due.is_empty());
}

#[tokio::test]
async fn pause_and_reschedule_go_through_update_task() {
    let db = Db::open_in_memory().unwrap();
    db.create_task(&task("t", ScheduleType::Cron, "* * * * *", "go"))
        .unwrap();

    let later = to_iso(Utc::now() + chrono::Duration::hours(1));
    TaskStore::reschedule_task(&db, "t", &later).await.unwrap();
    let t = db.get_task_by_id("t").unwrap().unwrap();
    assert_eq!(t.next_run.as_deref(), Some(later.as_str()));
    assert_eq!(t.last_run, None);

    TaskStore::pause_task(&db, "t").await.unwrap();
    assert_eq!(
        db.get_task_by_id("t").unwrap().unwrap().status,
        TaskStatus::Paused
    );
}

#[tokio::test]
async fn poll_loop_with_sqlite_runs_due_task_through_the_queue() {
    use std::sync::OnceLock;
    use talon_scheduler::LaneProcessor;

    struct Lanes(OnceLock<Arc<TaskScheduler>>);

    #[async_trait]
    impl LaneProcessor for Lanes {
        async fn process_messages(&self, _chat_jid: &str) -> bool {
            true
        }
        async fn run_task(&self, chat_jid: &str, task_id: &str) {
            if let Some(s) = self.0.get() {
                s.run_task(chat_jid, task_id).await;
            }
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    db.create_task(&task("t", ScheduleType::Cron, "0 0 1 1 *", "go"))
        .unwrap();
    let s = Arc::new(scheduler(&db, dir.path()));
    let lanes = Arc::new(Lanes(OnceLock::new()));
    lanes.0.set(s.clone()).ok().unwrap();
    s.queue().set_processor(lanes);

    let cancel = tokio_util::sync::CancellationToken::new();
    let handle = tokio::spawn({
        let (s, c) = (s.clone(), cancel.clone());
        async move { s.run(c).await }
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if db.get_task_run_logs("t", 10).unwrap().len() == 1 && !s.queue().is_active("main@g.us") {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "task never ran");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cancel.cancel();
    handle.await.unwrap();
    let report = s.queue().shutdown(Duration::from_secs(1)).await;
    assert!(report.drained);
    assert_eq!(
        db.get_task_by_id("t")
            .unwrap()
            .unwrap()
            .last_result
            .as_deref(),
        Some("ran t")
    );
}
