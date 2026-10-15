//! Task scheduler tests. Wall-clock time follows Tokio's paused clock via
//! [`TokioClock`](crate::TokioClock).

#![allow(clippy::unwrap_used)]

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use talon_core::types::{ContainerConfig, ContextMode, RegisteredGroup, ScheduleType};
use tokio::sync::oneshot;
use tokio::time::sleep;

use super::*;
use crate::clock::TokioClock;
use crate::queue::{GroupQueue, LaneProcessor, QueueConfig, RunningContainer};
use crate::store::MemoryTaskStore;

const T0: &str = "2026-06-01T08:00:00.000Z";
const MAIN_JID: &str = "main@g.us";
const OPS_JID: &str = "ops@g.us";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Host stand-in: messages are no-ops, tasks go to the scheduler.
#[derive(Default)]
struct Lanes {
    scheduler: OnceLock<Arc<TaskScheduler>>,
    outcomes: Mutex<Vec<TaskRunOutcome>>,
}

#[async_trait]
impl LaneProcessor for Lanes {
    async fn process_messages(&self, _chat_jid: &str) -> bool {
        true
    }

    async fn run_task(&self, chat_jid: &str, task_id: &str) {
        if let Some(s) = self.scheduler.get() {
            let outcome = s.run_task(chat_jid, task_id).await;
            self.outcomes.lock().unwrap().push(outcome);
        }
    }
}

#[derive(Debug, Clone)]
struct Call {
    task: ScheduledTask,
    group: RegisteredGroup,
    ctx: TaskRunContext,
}

struct FnExecutor<F> {
    f: F,
    calls: Arc<Mutex<Vec<Call>>>,
}

#[async_trait]
impl<F, Fut> TaskExecutor for FnExecutor<F>
where
    F: Fn(Call) -> Fut + Send + Sync,
    Fut: Future<Output = TaskExecution> + Send,
{
    async fn execute(
        &self,
        task: &ScheduledTask,
        group: &RegisteredGroup,
        ctx: &TaskRunContext,
    ) -> TaskExecution {
        let call = Call {
            task: task.clone(),
            group: group.clone(),
            ctx: ctx.clone(),
        };
        self.calls.lock().unwrap().push(call.clone());
        (self.f)(call).await
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    store: MemoryTaskStore,
    queue: GroupQueue,
    scheduler: Arc<TaskScheduler>,
    lanes: Arc<Lanes>,
    calls: Arc<Mutex<Vec<Call>>>,
    groups: Arc<Mutex<HashMap<String, RegisteredGroup>>>,
}

impl Harness {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn outcomes(&self) -> Vec<TaskRunOutcome> {
        self.lanes.outcomes.lock().unwrap().clone()
    }

    fn now(&self) -> DateTime<Utc> {
        self.scheduler.clock.now()
    }

    fn task(&self, id: &str) -> ScheduledTask {
        self.store.task(id).unwrap()
    }
}

fn group(name: &str, folder: &str, is_main: bool) -> RegisteredGroup {
    RegisteredGroup {
        name: name.into(),
        folder: folder.into(),
        trigger: "@Talon".into(),
        added_at: "2026-01-01T00:00:00.000Z".into(),
        container_config: None,
        requires_trigger: None,
        is_main,
        session_key: None,
        ipc_key: None,
        ephemeral_session: false,
        trusted_session_commands: false,
    }
}

fn default_groups() -> HashMap<String, RegisteredGroup> {
    HashMap::from([
        (MAIN_JID.to_string(), group("Main", "main", true)),
        (OPS_JID.to_string(), group("Ops", "ops", false)),
    ])
}

fn test_config() -> SchedulerConfig {
    SchedulerConfig {
        retry: RetryPolicy {
            jitter: 0.0,
            ..SchedulerConfig::default().retry
        },
        ..SchedulerConfig::default()
    }
}

fn harness_with<F, Fut>(config: SchedulerConfig, exec: F) -> Harness
where
    F: Fn(Call) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = TaskExecution> + Send + 'static,
{
    let dir = tempfile::tempdir().unwrap();
    let store = MemoryTaskStore::new();
    let lanes = Arc::new(Lanes::default());
    let queue = GroupQueue::with_processor(QueueConfig::new(dir.path(), 2), lanes.clone());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let groups = Arc::new(Mutex::new(default_groups()));
    let g = groups.clone();
    let scheduler = Arc::new(
        TaskScheduler::new(
            config,
            Arc::new(store.clone()),
            queue.clone(),
            Arc::new(FnExecutor {
                f: exec,
                calls: calls.clone(),
            }),
            Arc::new(move || g.lock().unwrap().clone()),
        )
        .with_clock(Arc::new(TokioClock::starting_at(parse_iso(T0).unwrap()))),
    );
    lanes.scheduler.set(scheduler.clone()).ok().unwrap();
    Harness {
        _dir: dir,
        store,
        queue,
        scheduler,
        lanes,
        calls,
        groups,
    }
}

fn harness<F, Fut>(exec: F) -> Harness
where
    F: Fn(Call) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = TaskExecution> + Send + 'static,
{
    harness_with(test_config(), exec)
}

fn ok_harness() -> Harness {
    harness(|_| async { TaskExecution::success(Some("done".into())) })
}

fn at(offset_secs: i64) -> String {
    to_iso(parse_iso(T0).unwrap() + chrono::Duration::seconds(offset_secs))
}

fn new_task(id: &str, schedule_type: ScheduleType, value: &str, next_run: &str) -> ScheduledTask {
    ScheduledTask {
        id: id.into(),
        group_folder: "main".into(),
        chat_jid: MAIN_JID.into(),
        prompt: "run".into(),
        script: None,
        schedule_type,
        schedule_value: value.into(),
        context_mode: ContextMode::Isolated,
        next_run: Some(next_run.into()),
        last_run: None,
        last_result: None,
        status: TaskStatus::Active,
        created_at: "2026-01-01T00:00:00.000Z".into(),
    }
}

async fn settle() {
    sleep(Duration::from_millis(10)).await;
}

fn finished(outcome: &TaskRunOutcome) -> &TaskRunReport {
    match outcome {
        TaskRunOutcome::Finished(r) => r,
        other => panic!("expected Finished, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Core scheduler behaviour
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn pauses_due_tasks_with_invalid_group_folders_to_prevent_retry_churn() {
    let h = ok_harness();
    let mut task = new_task(
        "task-invalid-folder",
        ScheduleType::Once,
        "2026-02-22T00:00:00",
        &at(-60),
    );
    task.group_folder = "../../outside".into();
    task.chat_jid = "bad@g.us".into();
    h.store.insert(task);

    let cancel = CancellationToken::new();
    let s = h.scheduler.clone();
    let c = cancel.clone();
    let loop_handle = tokio::spawn(async move { s.run(c).await });
    settle().await;

    assert_eq!(h.task("task-invalid-folder").status, TaskStatus::Paused);
    assert!(h.calls().is_empty(), "executor must not run");
    let logs = h.store.run_logs("task-invalid-folder");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].status, TaskRunStatus::Error);
    assert!(
        logs[0]
            .error
            .as_deref()
            .unwrap()
            .contains("invalid group folder")
    );
    assert!(matches!(h.outcomes()[0], TaskRunOutcome::Paused { .. }));

    // A later poll does not pick it up again.
    sleep(Duration::from_secs(61)).await;
    assert_eq!(h.store.run_logs("task-invalid-folder").len(), 1);
    cancel.cancel();
    loop_handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn interval_next_run_is_anchored_to_the_scheduled_time_to_prevent_drift() {
    let h = ok_harness();
    let scheduled = at(-2);
    h.store.insert(new_task(
        "drift-test",
        ScheduleType::Interval,
        "60000",
        &scheduled,
    ));

    let outcome = h.scheduler.run_task(MAIN_JID, "drift-test").await;
    let report = finished(&outcome);

    // scheduled + 60 s, not now + 60 s.
    assert_eq!(report.next_run.as_deref(), Some(at(58).as_str()));
    assert_eq!(
        h.task("drift-test").next_run.as_deref(),
        Some(at(58).as_str())
    );
}

#[tokio::test(start_paused = true)]
async fn once_tasks_complete_after_running() {
    let h = ok_harness();
    h.store.insert(new_task(
        "once-test",
        ScheduleType::Once,
        "2026-06-01T07:59:59",
        &at(-1),
    ));

    let outcome = h.scheduler.run_task(MAIN_JID, "once-test").await;
    assert_eq!(finished(&outcome).next_run, None);
    let task = h.task("once-test");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.next_run, None);
    assert_eq!(task.last_result.as_deref(), Some("done"));
}

#[tokio::test(start_paused = true)]
async fn interval_skips_missed_runs_without_bursting() {
    let h = ok_harness();
    let ms = 60_000;
    let scheduled = at(-600); // missed 10 intervals
    h.store.insert(new_task(
        "skip-test",
        ScheduleType::Interval,
        &ms.to_string(),
        &scheduled,
    ));

    let report = h.scheduler.poll_once().await;
    assert_eq!(report.enqueued, 1);
    settle().await;
    assert_eq!(h.calls().len(), 1);

    let next = parse_iso(h.task("skip-test").next_run.as_deref().unwrap()).unwrap();
    assert!(next > h.now(), "next run must be in the future");
    let offset = (next - parse_iso(&scheduled).unwrap()).num_milliseconds() % ms;
    assert_eq!(offset, 0, "aligned to the original grid");

    // No catch-up burst: the next poll finds nothing due.
    assert_eq!(h.scheduler.poll_once().await.due, 0);
    settle().await;
    assert_eq!(h.calls().len(), 1);
}

// ---------------------------------------------------------------------------
// Rust additions
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn cron_task_missed_during_downtime_runs_once_then_reschedules_from_now() {
    let h = ok_harness();
    // Hourly task last due five hours ago.
    h.store.insert(new_task(
        "hourly",
        ScheduleType::Cron,
        "0 * * * *",
        &at(-5 * 3600),
    ));

    h.scheduler.poll_once().await;
    settle().await;
    h.scheduler.poll_once().await;
    settle().await;

    let calls = h.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].ctx.late_by, Duration::from_secs(5 * 3600));
    assert_eq!(
        calls[0].ctx.scheduled_for.as_deref(),
        Some(at(-5 * 3600).as_str())
    );
    assert_eq!(
        h.task("hourly").next_run.as_deref(),
        Some(at(3600).as_str())
    );
}

#[tokio::test(start_paused = true)]
async fn successful_run_is_logged_and_summarized() {
    let long = "x".repeat(300);
    let result = long.clone();
    let h = harness(move |_| {
        let r = result.clone();
        async move {
            sleep(Duration::from_millis(1500)).await;
            TaskExecution::success(Some(r))
        }
    });
    h.store
        .insert(new_task("t", ScheduleType::Cron, "*/5 * * * *", &at(0)));

    let outcome = h.scheduler.run_task(MAIN_JID, "t").await;
    let report = finished(&outcome);
    assert_eq!(report.status, TaskRunStatus::Success);
    assert_eq!(report.duration_ms, 1500);
    assert!(!report.timed_out);
    assert_eq!(report.retry_attempt, None);

    let task = h.task("t");
    assert_eq!(task.last_result.as_deref(), Some("x".repeat(200).as_str()));
    assert_eq!(task.next_run.as_deref(), Some(at(300).as_str()));
    let logs = h.store.run_logs("t");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].status, TaskRunStatus::Success);
    assert_eq!(logs[0].result.as_deref(), Some(long.as_str()));
    assert_eq!(logs[0].duration_ms, 1500);
    assert_eq!(logs[0].run_at, at(0));
    assert_eq!(logs[0].error, None);
}

#[tokio::test(start_paused = true)]
async fn empty_result_is_summarized_as_completed_and_huge_results_are_capped() {
    let h = harness(|call| async move {
        if call.task.id == "big" {
            TaskExecution::success(Some("y".repeat(100_000)))
        } else {
            TaskExecution::success(None)
        }
    });
    h.store
        .insert(new_task("quiet", ScheduleType::Cron, "*/5 * * * *", &at(0)));
    h.store
        .insert(new_task("big", ScheduleType::Cron, "*/5 * * * *", &at(0)));
    h.scheduler.run_task(MAIN_JID, "quiet").await;
    h.scheduler.run_task(MAIN_JID, "big").await;

    assert_eq!(h.task("quiet").last_result.as_deref(), Some("Completed"));
    let logged = h.store.run_logs("big")[0].result.clone().unwrap();
    assert!(logged.len() < 70_000);
    assert!(logged.ends_with("[... truncated]"));
}

#[tokio::test(start_paused = true)]
async fn context_flags_and_timeout_are_passed_to_the_executor() {
    let h = ok_harness();
    let mut grouped = new_task("grouped", ScheduleType::Cron, "*/5 * * * *", &at(0));
    grouped.context_mode = ContextMode::Group;
    h.store.insert(grouped);
    let mut isolated = new_task("isolated", ScheduleType::Cron, "*/5 * * * *", &at(0));
    isolated.group_folder = "ops".into();
    isolated.chat_jid = OPS_JID.into();
    h.store.insert(isolated);
    {
        let mut groups = h.groups.lock().unwrap();
        let ops = groups.get_mut(OPS_JID).unwrap();
        ops.container_config = Some(ContainerConfig {
            timeout: Some(120_000),
            ..ContainerConfig::default()
        });
    }

    h.scheduler.poll_once().await;
    settle().await;

    let mut calls = h.calls();
    calls.sort_by(|a, b| a.task.id.cmp(&b.task.id));
    let (g, i) = (&calls[0], &calls[1]);
    assert_eq!(g.task.id, "grouped");
    assert!(g.ctx.uses_group_session());
    assert!(g.ctx.is_main);
    assert_eq!(g.ctx.chat_jid, MAIN_JID);
    assert_eq!(g.ctx.timeout, Duration::from_secs(30 * 60));
    assert_eq!(g.ctx.attempt, 0);
    assert_eq!(g.ctx.started_at, at(0));
    assert_eq!(g.group.folder, "main");

    assert_eq!(i.task.id, "isolated");
    assert!(!i.ctx.uses_group_session());
    assert!(!i.ctx.is_main);
    assert_eq!(i.ctx.timeout, Duration::from_secs(120));
    assert_eq!(i.group.name, "Ops");
}

#[tokio::test(start_paused = true)]
async fn failed_once_task_is_retried_with_backoff_then_completes() {
    let failures_left = Arc::new(AtomicUsize::new(1));
    let f = failures_left.clone();
    let h = harness(move |_| {
        let fail = f
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        async move {
            if fail {
                TaskExecution::failure("vLLM unavailable")
            } else {
                TaskExecution::success(Some("ok".into()))
            }
        }
    });
    h.store.insert(new_task(
        "once",
        ScheduleType::Once,
        "2026-06-01T08:00:00",
        &at(0),
    ));

    let outcome = h.scheduler.run_task(MAIN_JID, "once").await;
    let report = finished(&outcome);
    assert_eq!(report.status, TaskRunStatus::Error);
    assert_eq!(report.retry_attempt, Some(1));
    assert_eq!(report.summary, "Error: vLLM unavailable");
    // Retried after the base delay (60 s, no jitter in tests) instead of completing.
    let task = h.task("once");
    assert_eq!(task.status, TaskStatus::Active);
    assert_eq!(task.next_run.as_deref(), Some(at(60).as_str()));

    // Not due yet.
    assert_eq!(h.scheduler.poll_once().await.due, 0);
    sleep(Duration::from_secs(60)).await;
    assert_eq!(h.scheduler.poll_once().await.enqueued, 1);
    settle().await;

    let task = h.task("once");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.last_result.as_deref(), Some("ok"));
    let calls = h.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].ctx.attempt, 1);
    let logs = h.store.run_logs("once");
    assert_eq!(
        logs.iter().map(|l| l.status).collect::<Vec<_>>(),
        vec![TaskRunStatus::Error, TaskRunStatus::Success]
    );
}

#[tokio::test(start_paused = true)]
async fn failures_give_up_after_max_retries() {
    let mut config = test_config();
    config.retry.max_retries = 2;
    let h = harness_with(config, |_| async { TaskExecution::failure("boom") });
    h.store.insert(new_task(
        "once",
        ScheduleType::Once,
        "2026-06-01T08:00:00",
        &at(0),
    ));

    let mut attempts = Vec::new();
    for _ in 0..3 {
        let outcome = h.scheduler.run_task(MAIN_JID, "once").await;
        attempts.push(finished(&outcome).retry_attempt);
        if let Some(next) = h.task("once").next_run {
            let wait = parse_iso(&next).unwrap() - h.now();
            sleep(wait.to_std().unwrap()).await;
        }
    }
    assert_eq!(attempts, vec![Some(1), Some(2), None]);
    let task = h.task("once");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.last_result.as_deref(), Some("Error: boom"));
    // Delays: 60 s, then 120 s.
    let runs: Vec<String> = h
        .store
        .run_logs("once")
        .into_iter()
        .map(|l| l.run_at)
        .collect();
    assert_eq!(runs, vec![at(0), at(60), at(180)]);
}

#[tokio::test(start_paused = true)]
async fn recurring_failure_uses_the_earlier_of_retry_and_schedule() {
    let h = harness(|_| async { TaskExecution::failure("boom") });
    h.store
        .insert(new_task("hourly", ScheduleType::Cron, "0 * * * *", &at(0)));
    h.store.insert(new_task(
        "minutely",
        ScheduleType::Cron,
        "* * * * *",
        &at(0),
    ));

    let hourly = h.scheduler.run_task(MAIN_JID, "hourly").await;
    assert_eq!(finished(&hourly).next_run.as_deref(), Some(at(60).as_str()));

    // The retry (60 s base) is not earlier than the next regular minute.
    sleep(Duration::from_secs(1)).await;
    let minutely = h.scheduler.run_task(MAIN_JID, "minutely").await;
    assert_eq!(
        finished(&minutely).next_run.as_deref(),
        Some(at(60).as_str())
    );
}

#[tokio::test(start_paused = true)]
async fn missing_group_defers_with_backoff_instead_of_spinning() {
    let h = ok_harness();
    h.groups.lock().unwrap().clear();
    h.store.insert(new_task(
        "orphan",
        ScheduleType::Once,
        "2026-06-01T08:00:00",
        &at(0),
    ));

    let outcome = h.scheduler.run_task(MAIN_JID, "orphan").await;
    let not_found = format!("Group not found: main (lane {MAIN_JID:?} is not registered)");
    assert_eq!(
        outcome,
        TaskRunOutcome::Deferred {
            error: not_found.clone(),
            next_run: at(60),
        }
    );
    let task = h.task("orphan");
    assert_eq!(
        task.status,
        TaskStatus::Active,
        "never completed while orphaned"
    );
    assert_eq!(task.last_run, None);
    let logs = h.store.run_logs("orphan");
    assert_eq!(logs[0].error.as_deref(), Some(not_found.as_str()));

    // Second attempt backs off further (120 s).
    sleep(Duration::from_secs(60)).await;
    let outcome = h.scheduler.run_task(MAIN_JID, "orphan").await;
    assert!(
        matches!(outcome, TaskRunOutcome::Deferred { ref next_run, .. } if *next_run == at(180))
    );

    // Once the group is back, the task runs and completes.
    *h.groups.lock().unwrap() = default_groups();
    sleep(Duration::from_secs(120)).await;
    h.scheduler.poll_once().await;
    settle().await;
    assert_eq!(h.calls().len(), 1);
    assert_eq!(h.task("orphan").status, TaskStatus::Completed);
}

#[test]
fn group_is_resolved_only_by_the_tasks_own_jid() {
    let mut groups = HashMap::new();
    let mut a = group("A", "shared", false);
    a.ipc_key = Some("lane-a".into());
    let mut b = group("B", "shared", false);
    b.ipc_key = Some("lane-b".into());
    groups.insert("b@x".to_string(), b);
    groups.insert("a@x".to_string(), a);
    let mut task = new_task("t", ScheduleType::Cron, "* * * * *", &at(0));
    task.group_folder = "shared".into();

    task.chat_jid = "b@x".into();
    assert_eq!(resolve_group(&groups, &task).unwrap().name, "B");
    task.chat_jid = "a@x".into();
    assert_eq!(resolve_group(&groups, &task).unwrap().name, "A");
    // Unknown JID: no fallback to another lane of the same folder (N-1).
    task.chat_jid = "zzz@x".into();
    assert_eq!(
        resolve_group(&groups, &task),
        Err(UnresolvedLane::NotRegistered)
    );
    // JID registered with another folder: not run there, not elsewhere.
    groups.insert("c@x".to_string(), group("C", "other", false));
    task.chat_jid = "c@x".into();
    assert_eq!(
        resolve_group(&groups, &task),
        Err(UnresolvedLane::FolderMismatch {
            registered_folder: "other".into()
        })
    );
    task.group_folder = "nope".into();
    task.chat_jid = "a@x".into();
    assert!(resolve_group(&groups, &task).is_err());
}

// ---------------------------------------------------------------------------
// N-1: a task never runs in another lane of its folder
// ---------------------------------------------------------------------------

const BASE_JID: &str = "http:copilot";
const INVESTIGATE_JID: &str = "http:copilot:investigate";
const ALICE_JID: &str = "http:copilot:u:alice";
const BOB_JID: &str = "http:copilot:u:bob";

/// A CoPilot lane: shared `copilot` folder, own session/IPC keys unless
/// `key` is `None` (the anonymous base lane keys off the folder).
fn copilot_lane(name: &str, key: Option<&str>) -> RegisteredGroup {
    RegisteredGroup {
        session_key: key.map(Into::into),
        ipc_key: key.map(Into::into),
        trusted_session_commands: true,
        ..group(name, "copilot", false)
    }
}

/// The persisted lanes that survive a host restart.
fn persisted_copilot_lanes() -> [(String, RegisteredGroup); 2] {
    [
        (BASE_JID.into(), copilot_lane("CoPilot", None)),
        (
            INVESTIGATE_JID.into(),
            copilot_lane("CoPilot Investigations", Some("copilot-investigate")),
        ),
    ]
}

fn alice_lane() -> RegisteredGroup {
    copilot_lane("CoPilot — alice", Some("u-alice"))
}

fn lane_task(id: &str, jid: &str, schedule_type: ScheduleType, value: &str) -> ScheduledTask {
    ScheduledTask {
        group_folder: "copilot".into(),
        chat_jid: jid.into(),
        ..new_task(id, schedule_type, value, &at(0))
    }
}

#[tokio::test(start_paused = true)]
async fn unregistered_user_lane_task_is_deferred_and_never_runs_in_the_base_lane() {
    let h = ok_harness();
    // After a restart only the persisted lanes are registered; alice's
    // in-memory lane is gone. `http:copilot` sorts before her JID.
    h.groups.lock().unwrap().extend(persisted_copilot_lanes());
    let mut grouped = lane_task("alice-grouped", ALICE_JID, ScheduleType::Cron, "0 9 * * *");
    grouped.context_mode = ContextMode::Group;
    h.store.insert(grouped);
    // Isolated, once: the "legacy" shape gets no folder fallback either.
    h.store.insert(lane_task(
        "alice-once",
        ALICE_JID,
        ScheduleType::Once,
        "2026-06-01T08:00:00",
    ));

    let not_registered = format!("Group not found: copilot (lane {ALICE_JID:?} is not registered)");
    // The reviewer's PoC path: the host's LaneProcessor calls run_task.
    for id in ["alice-grouped", "alice-once"] {
        let outcome = h.scheduler.run_task(ALICE_JID, id).await;
        assert_eq!(
            outcome,
            TaskRunOutcome::Deferred {
                error: not_registered.clone(),
                next_run: at(60),
            }
        );
    }
    assert!(h.calls().is_empty(), "must not run in any other lane");

    // Through the poll loop and the queue as well, after the backoff.
    sleep(Duration::from_secs(60)).await;
    assert_eq!(h.scheduler.poll_once().await.enqueued, 2);
    settle().await;
    assert!(h.calls().is_empty(), "must not run in any other lane");
    let outcomes = h.outcomes();
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes.iter().all(
            |o| matches!(o, TaskRunOutcome::Deferred { next_run, .. } if *next_run == at(180))
        )
    );
    assert!(!h.queue.is_active(BASE_JID));

    for id in ["alice-grouped", "alice-once"] {
        let task = h.task(id);
        assert_eq!(
            task.status,
            TaskStatus::Active,
            "never completed while orphaned"
        );
        assert_eq!(task.chat_jid, ALICE_JID);
        assert_eq!(task.last_run, None);
        assert_eq!(task.last_result, None);
        assert_eq!(task.next_run.as_deref(), Some(at(180).as_str()));
        let logs = h.store.run_logs(id);
        assert_eq!(logs.len(), 2);
        assert!(logs.iter().all(|l| l.status == TaskRunStatus::Error
            && l.error.as_deref() == Some(not_registered.as_str())));
    }
}

#[tokio::test(start_paused = true)]
async fn deferred_lane_task_runs_in_its_own_lane_once_registered_again() {
    let h = ok_harness();
    h.groups.lock().unwrap().extend(persisted_copilot_lanes());
    let mut task = lane_task(
        "alice-once",
        ALICE_JID,
        ScheduleType::Once,
        "2026-06-01T08:00:00",
    );
    task.context_mode = ContextMode::Group;
    h.store.insert(task);

    let outcome = h.scheduler.run_task(ALICE_JID, "alice-once").await;
    assert!(
        matches!(outcome, TaskRunOutcome::Deferred { ref next_run, .. } if *next_run == at(60))
    );
    assert!(h.calls().is_empty());

    // The analyst comes back: her lane is registered again under her JID.
    h.groups
        .lock()
        .unwrap()
        .insert(ALICE_JID.to_string(), alice_lane());
    sleep(Duration::from_secs(60)).await;
    assert_eq!(h.scheduler.poll_once().await.enqueued, 1);
    settle().await;

    let calls = h.calls();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.ctx.chat_jid, ALICE_JID);
    assert_eq!(call.group, alice_lane());
    assert_eq!(call.group.session_key(), "u-alice");
    assert_eq!(call.group.ipc_key(), "u-alice");
    assert!(call.ctx.uses_group_session());
    assert!(!call.ctx.is_main);
    let task = h.task("alice-once");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.last_result.as_deref(), Some("done"));
}

#[tokio::test(start_paused = true)]
async fn registered_lane_tasks_run_in_their_own_lane_next_to_same_folder_lanes() {
    let h = ok_harness();
    let bob = copilot_lane("CoPilot — bob", Some("u-bob"));
    {
        let mut groups = h.groups.lock().unwrap();
        groups.extend(persisted_copilot_lanes());
        groups.insert(ALICE_JID.to_string(), alice_lane());
        groups.insert(BOB_JID.to_string(), bob.clone());
    }
    for (id, jid) in [
        ("base", BASE_JID),
        ("investigate", INVESTIGATE_JID),
        ("alice", ALICE_JID),
        ("bob", BOB_JID),
        ("main", MAIN_JID),
    ] {
        let mut task = lane_task(id, jid, ScheduleType::Cron, "*/5 * * * *");
        if jid == MAIN_JID {
            task.group_folder = "main".into();
        }
        h.store.insert(task);
    }

    assert_eq!(h.scheduler.poll_once().await.enqueued, 5);
    settle().await;

    let groups = h.groups.lock().unwrap().clone();
    let calls = h.calls();
    assert_eq!(calls.len(), 5);
    for call in &calls {
        assert_eq!(call.ctx.chat_jid, call.task.chat_jid);
        assert_eq!(&call.group, &groups[&call.task.chat_jid]);
    }
    let by_id = |id: &str| calls.iter().find(|c| c.task.id == id).unwrap().clone();
    assert_eq!(by_id("base").group.session_key(), "copilot");
    assert_eq!(by_id("investigate").group.ipc_key(), "copilot-investigate");
    assert_eq!(by_id("alice").group.ipc_key(), "u-alice");
    assert_eq!(by_id("bob").group, bob);
    assert!(by_id("main").ctx.is_main);
    for id in ["base", "investigate", "alice", "bob", "main"] {
        assert_eq!(h.task(id).next_run.as_deref(), Some(at(300).as_str()));
    }
}

#[tokio::test(start_paused = true)]
async fn task_whose_jid_is_registered_for_another_folder_is_deferred() {
    let h = ok_harness();
    h.groups.lock().unwrap().extend(persisted_copilot_lanes());
    // A `copilot` task whose JID now belongs to the `ops` group: neither
    // `ops@g.us` (wrong folder) nor `http:copilot` (wrong lane) may run it.
    h.store
        .insert(lane_task("moved", OPS_JID, ScheduleType::Cron, "0 9 * * *"));

    let outcome = h.scheduler.run_task(OPS_JID, "moved").await;
    assert_eq!(
        outcome,
        TaskRunOutcome::Deferred {
            error: format!(
                "Group not found: copilot (lane {OPS_JID:?} is registered for folder \"ops\")"
            ),
            next_run: at(60),
        }
    );
    assert!(h.calls().is_empty());
    assert_eq!(h.task("moved").status, TaskStatus::Active);
}

#[tokio::test(start_paused = true)]
async fn task_handed_to_another_lane_is_skipped_untouched() {
    let h = ok_harness();
    {
        let mut groups = h.groups.lock().unwrap();
        groups.extend(persisted_copilot_lanes());
        groups.insert(ALICE_JID.to_string(), alice_lane());
    }
    h.store.insert(lane_task(
        "alice",
        ALICE_JID,
        ScheduleType::Cron,
        "*/5 * * * *",
    ));

    assert_eq!(
        h.scheduler.run_task(BASE_JID, "alice").await,
        TaskRunOutcome::Skipped {
            reason: SkipReason::WrongLane
        }
    );
    assert!(h.calls().is_empty());
    assert!(h.store.run_logs("alice").is_empty());
    assert_eq!(h.task("alice").next_run.as_deref(), Some(at(0).as_str()));

    // The next poll enqueues it in its own lane, where it runs.
    assert_eq!(h.scheduler.poll_once().await.enqueued, 1);
    settle().await;
    let calls = h.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].ctx.chat_jid, ALICE_JID);
    assert_eq!(calls[0].group, alice_lane());
}

struct StopSignal {
    stops: AtomicUsize,
    release: Mutex<Option<oneshot::Sender<()>>>,
}

#[async_trait]
impl RunningContainer for StopSignal {
    fn name(&self) -> &str {
        "talon-main-1"
    }

    async fn stop(&self) -> talon_core::Result<()> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        if let Some(tx) = self.release.lock().unwrap().take() {
            let _ = tx.send(());
        }
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn timeout_stops_the_container_and_is_logged() {
    let mut config = test_config();
    config.timeout_grace = Duration::from_secs(5);
    let queue_slot: Arc<OnceLock<GroupQueue>> = Arc::new(OnceLock::new());
    let container = Arc::new(StopSignal {
        stops: AtomicUsize::new(0),
        release: Mutex::new(None),
    });
    let (q, c) = (queue_slot.clone(), container.clone());
    let h = harness_with(config, move |call| {
        let (q, c) = (q.clone(), c.clone());
        async move {
            let (tx, rx) = oneshot::channel();
            *c.release.lock().unwrap() = Some(tx);
            let queue = q.get().unwrap();
            queue.register_process(&call.ctx.chat_jid, c.clone(), "main");
            // Hangs until the container is stopped, then reports partial output.
            let _ = rx.await;
            TaskExecution {
                result: Some("partial".into()),
                error: Some("container exited with code 137".into()),
                duration: Some(Duration::from_secs(1)),
            }
        }
    });
    queue_slot.set(h.queue.clone()).ok().unwrap();
    {
        let mut groups = h.groups.lock().unwrap();
        groups.get_mut(MAIN_JID).unwrap().container_config = Some(ContainerConfig {
            timeout: Some(10_000),
            ..ContainerConfig::default()
        });
    }
    h.store
        .insert(new_task("slow", ScheduleType::Cron, "*/5 * * * *", &at(0)));

    h.scheduler.poll_once().await;
    sleep(Duration::from_secs(20)).await;

    assert_eq!(container.stops.load(Ordering::SeqCst), 1);
    let logs = h.store.run_logs("slow");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].status, TaskRunStatus::Error);
    assert_eq!(
        logs[0].error.as_deref(),
        Some("task timed out after 15s: container exited with code 137")
    );
    assert_eq!(logs[0].result.as_deref(), Some("partial"));
    assert_eq!(logs[0].duration_ms, 15_000);
    let report = finished(&h.outcomes()[0]).clone();
    assert!(report.timed_out);
    assert_eq!(report.retry_attempt, Some(1));
    // The lane is free again.
    assert!(!h.queue.is_active(MAIN_JID));
}

#[tokio::test(start_paused = true)]
async fn hung_executor_is_aborted_after_the_grace_period() {
    let mut config = test_config();
    config.default_run_timeout = Duration::from_secs(10);
    config.timeout_grace = Duration::from_secs(2);
    let h = harness_with(config, |_| async {
        std::future::pending::<()>().await;
        TaskExecution::default()
    });
    h.store
        .insert(new_task("stuck", ScheduleType::Cron, "*/5 * * * *", &at(0)));

    let started = tokio::time::Instant::now();
    let outcome = h.scheduler.run_task(MAIN_JID, "stuck").await;
    // timeout (10 s) + grace (2 s) + wait after stop (2 s)
    assert_eq!(started.elapsed(), Duration::from_secs(14));
    let report = finished(&outcome);
    assert!(report.timed_out);
    assert_eq!(report.summary, "Error: task timed out after 12s");
}

#[tokio::test(start_paused = true)]
async fn executor_panic_is_recorded_as_a_failed_run() {
    let h = harness(|_| async { panic!("executor bug") });
    h.store
        .insert(new_task("p", ScheduleType::Cron, "*/5 * * * *", &at(0)));
    let outcome = h.scheduler.run_task(MAIN_JID, "p").await;
    assert_eq!(finished(&outcome).summary, "Error: task executor panicked");
    assert_eq!(h.task("p").next_run.as_deref(), Some(at(60).as_str()));
}

#[tokio::test(start_paused = true)]
async fn tasks_changed_while_queued_are_skipped() {
    let h = ok_harness();
    let mut paused = new_task("paused", ScheduleType::Cron, "* * * * *", &at(0));
    paused.status = TaskStatus::Paused;
    h.store.insert(paused);
    h.store.insert(new_task(
        "future",
        ScheduleType::Cron,
        "* * * * *",
        &at(3600),
    ));

    assert_eq!(
        h.scheduler.run_task(MAIN_JID, "missing").await,
        TaskRunOutcome::Skipped {
            reason: SkipReason::NotFound
        }
    );
    assert_eq!(
        h.scheduler.run_task(MAIN_JID, "paused").await,
        TaskRunOutcome::Skipped {
            reason: SkipReason::NotActive
        }
    );
    assert_eq!(
        h.scheduler.run_task(MAIN_JID, "future").await,
        TaskRunOutcome::Skipped {
            reason: SkipReason::NotDue
        }
    );
    h.store.set_fail_reads(true);
    assert!(matches!(
        h.scheduler.run_task(MAIN_JID, "future").await,
        TaskRunOutcome::Skipped {
            reason: SkipReason::StoreError(_)
        }
    ));
    assert!(h.calls().is_empty());
    assert!(h.store.run_logs("paused").is_empty());
}

#[tokio::test(start_paused = true)]
async fn task_paused_while_waiting_in_a_busy_lane_does_not_run() {
    let (tx, rx) = oneshot::channel::<()>();
    let gate = Arc::new(Mutex::new(Some(rx)));
    let h = harness(move |call| {
        let gate = gate.clone();
        async move {
            if call.task.id == "first" {
                let rx = gate.lock().unwrap().take();
                if let Some(rx) = rx {
                    let _ = rx.await;
                }
            }
            TaskExecution::success(None)
        }
    });
    h.store
        .insert(new_task("first", ScheduleType::Cron, "*/5 * * * *", &at(0)));
    h.store.insert(new_task(
        "second",
        ScheduleType::Cron,
        "*/5 * * * *",
        &at(0),
    ));
    let report = h.scheduler.poll_once().await;
    assert_eq!(report.enqueued, 2);
    settle().await;
    // "second" waits behind "first" in the same lane; pause it meanwhile.
    h.store.update("second", |t| t.status = TaskStatus::Paused);
    let _ = tx.send(());
    settle().await;

    let ids: Vec<String> = h.calls().into_iter().map(|c| c.task.id).collect();
    assert_eq!(ids, vec!["first".to_string()]);
    assert!(matches!(
        h.outcomes()[1],
        TaskRunOutcome::Skipped {
            reason: SkipReason::NotActive
        }
    ));
}

#[tokio::test(start_paused = true)]
async fn polling_is_idempotent_while_a_task_runs() {
    let (tx, rx) = oneshot::channel::<()>();
    let gate = Arc::new(Mutex::new(Some(rx)));
    let h = harness(move |_| {
        let gate = gate.clone();
        async move {
            let rx = gate.lock().unwrap().take();
            if let Some(rx) = rx {
                let _ = rx.await;
            }
            TaskExecution::success(None)
        }
    });
    h.store
        .insert(new_task("t", ScheduleType::Cron, "*/5 * * * *", &at(0)));

    assert_eq!(h.scheduler.poll_once().await.enqueued, 1);
    settle().await;
    let second = h.scheduler.poll_once().await;
    assert_eq!(second.due, 1);
    assert_eq!(second.already_queued, 1);
    assert_eq!(second.enqueued, 0);
    let _ = tx.send(());
    settle().await;
    assert_eq!(h.calls().len(), 1);
    assert_eq!(h.scheduler.poll_once().await.due, 0);
}

#[tokio::test(start_paused = true)]
async fn run_loop_polls_on_interval_wakes_early_and_stops_on_cancel() {
    let h = ok_harness();
    let cancel = CancellationToken::new();
    let s = h.scheduler.clone();
    let c = cancel.clone();
    let handle = tokio::spawn(async move { s.run(c).await });
    settle().await;

    // Due in 90 s: found by the poll at 120 s, not the one at 60 s.
    h.store
        .insert(new_task("later", ScheduleType::Cron, "0 9 * * *", &at(90)));
    sleep(Duration::from_secs(61)).await;
    assert!(h.calls().is_empty());
    sleep(Duration::from_secs(60)).await;
    assert_eq!(h.calls().len(), 1);

    // A new due task plus wake(): runs without waiting for the interval.
    h.store
        .insert(new_task("now", ScheduleType::Cron, "0 9 * * *", &at(121)));
    h.scheduler.wake();
    settle().await;
    assert_eq!(h.calls().len(), 2);

    // A second loop does not start while one is running.
    let started = tokio::time::Instant::now();
    h.scheduler.run(CancellationToken::new()).await;
    assert_eq!(started.elapsed(), Duration::ZERO);

    cancel.cancel();
    handle.await.unwrap();
    // After stopping, the loop can be started again.
    let again = CancellationToken::new();
    again.cancel();
    h.scheduler.run(again).await;
}

#[tokio::test(start_paused = true)]
async fn store_errors_do_not_kill_the_loop() {
    let h = ok_harness();
    h.store
        .insert(new_task("t", ScheduleType::Cron, "*/5 * * * *", &at(0)));
    h.store.set_fail_reads(true);
    assert_eq!(h.scheduler.poll_once().await, PollReport::default());

    let cancel = CancellationToken::new();
    let s = h.scheduler.clone();
    let c = cancel.clone();
    let handle = tokio::spawn(async move { s.run(c).await });
    settle().await;
    assert!(h.calls().is_empty());
    h.store.set_fail_reads(false);
    sleep(Duration::from_secs(60)).await;
    assert_eq!(h.calls().len(), 1);
    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn invalid_cron_pauses_the_task_after_running() {
    let h = ok_harness();
    h.store.insert(new_task(
        "bad-cron",
        ScheduleType::Cron,
        "not a cron",
        &at(0),
    ));
    let outcome = h.scheduler.run_task(MAIN_JID, "bad-cron").await;
    let report = finished(&outcome);
    assert!(report.paused);
    assert_eq!(report.next_run, None);
    let task = h.task("bad-cron");
    assert_eq!(task.status, TaskStatus::Paused);
    assert_eq!(task.last_result.as_deref(), Some("done"));
}

#[tokio::test(start_paused = true)]
async fn shutdown_queue_rejects_polled_tasks() {
    let h = ok_harness();
    h.store
        .insert(new_task("t", ScheduleType::Cron, "*/5 * * * *", &at(0)));
    h.queue.shutdown(Duration::from_secs(1)).await;
    let report = h.scheduler.poll_once().await;
    assert_eq!(report.due, 1);
    assert_eq!(report.skipped, 1);
    settle().await;
    assert!(h.calls().is_empty());
}

#[test]
fn helpers() {
    assert_eq!(truncate_chars("héllo", 2), "hé");
    assert_eq!(truncate_marked("abc", 5), "abc");
    assert_eq!(truncate_marked("abcdef", 3), "abc\n[... truncated]");
    assert_eq!(human_duration(Duration::from_millis(250)), "250ms");
    assert_eq!(human_duration(Duration::from_secs(90)), "90s");
    let now = parse_iso(T0).unwrap();
    assert_eq!(ensure_after(at(-5), now), at(1));
    assert_eq!(ensure_after(at(5), now), at(5));
}

#[test]
fn config_from_talon_config() {
    let env = talon_core::env::EnvFile::default();
    let cfg = TalonConfig::from_env(Path::new("/srv/talon"), env);
    let s = SchedulerConfig::from_talon_config(&cfg);
    assert_eq!(s.poll_interval, cfg.scheduler_poll_interval);
    assert_eq!(s.default_run_timeout, cfg.container_timeout);
    assert_eq!(s.timezone, cfg.timezone);
    assert_eq!(s.result_summary_chars, 200);
}
