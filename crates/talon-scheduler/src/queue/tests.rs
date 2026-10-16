//! Group queue tests. Time is paused (`start_paused`), so `sleep`
//! auto-advances virtual time once every spawned task is idle.

#![allow(clippy::unwrap_used)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::oneshot;
use tokio::time::sleep;

use super::*;

const G1: &str = "group1@g.us";
const G2: &str = "group2@g.us";
const G3: &str = "group3@g.us";
const IPC_KEY: &str = "test-group";

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

struct FnProcessor<M, T> {
    messages: M,
    task: T,
}

#[async_trait]
impl<M, MF, T, TF> LaneProcessor for FnProcessor<M, T>
where
    M: Fn(String) -> MF + Send + Sync,
    MF: Future<Output = bool> + Send,
    T: Fn(String, String) -> TF + Send + Sync,
    TF: Future<Output = ()> + Send,
{
    async fn process_messages(&self, chat_jid: &str) -> bool {
        (self.messages)(chat_jid.to_string()).await
    }

    async fn run_task(&self, chat_jid: &str, task_id: &str) {
        (self.task)(chat_jid.to_string(), task_id.to_string()).await
    }
}

fn processor<M, MF, T, TF>(messages: M, task: T) -> Arc<dyn LaneProcessor>
where
    M: Fn(String) -> MF + Send + Sync + 'static,
    MF: Future<Output = bool> + Send + 'static,
    T: Fn(String, String) -> TF + Send + Sync + 'static,
    TF: Future<Output = ()> + Send + 'static,
{
    Arc::new(FnProcessor { messages, task })
}

fn messages_only<M, MF>(messages: M) -> Arc<dyn LaneProcessor>
where
    M: Fn(String) -> MF + Send + Sync + 'static,
    MF: Future<Output = bool> + Send + 'static,
{
    processor(messages, |_, _| async {})
}

/// Completion callbacks: one gate per started job, released by the test.
#[derive(Clone, Default)]
struct Gates(Arc<Mutex<Vec<Option<oneshot::Sender<()>>>>>);

impl Gates {
    /// Register a gate now and return a future that resolves on release.
    fn wait(&self) -> impl Future<Output = ()> + Send + use<> {
        let (tx, rx) = oneshot::channel();
        self.0.lock().unwrap().push(Some(tx));
        async move {
            let _ = rx.await;
        }
    }

    fn release(&self, index: usize) {
        if let Some(tx) = self.0.lock().unwrap().get_mut(index).and_then(Option::take) {
            let _ = tx.send(());
        }
    }

    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

#[derive(Default, Clone)]
struct Events(Arc<Mutex<Vec<String>>>);

impl Events {
    fn push(&self, e: impl Into<String>) {
        self.0.lock().unwrap().push(e.into());
    }
    fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

struct FakeContainer {
    name: String,
    stops: AtomicUsize,
    on_stop: Option<Gates>,
}

impl FakeContainer {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            stops: AtomicUsize::new(0),
            on_stop: None,
        })
    }
}

#[async_trait]
impl RunningContainer for FakeContainer {
    fn name(&self) -> &str {
        &self.name
    }

    async fn stop(&self) -> talon_core::Result<()> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        if let Some(gates) = &self.on_stop {
            gates.release(0);
        }
        Ok(())
    }
}

fn config(dir: &Path, max: usize) -> QueueConfig {
    let mut c = QueueConfig::new(dir, max);
    c.retry = RetryPolicy::default().without_jitter();
    c
}

fn close_path(dir: &Path) -> PathBuf {
    dir.join("ipc").join(IPC_KEY).join("input").join("_close")
}

fn take_close(dir: &Path) -> bool {
    std::fs::remove_file(close_path(dir)).is_ok()
}

fn input_messages(dir: &Path) -> Vec<String> {
    let input = dir.join("ipc").join(IPC_KEY).join("input");
    let mut out: Vec<String> = std::fs::read_dir(input)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .map(|p| std::fs::read_to_string(p).unwrap())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Advance virtual time by 10 ms and let every spawned task settle.
async fn settle() {
    sleep(Duration::from_millis(10)).await;
}

/// A queue whose message runs block on `gates` and record into `events`.
fn gated_queue(dir: &Path, max: usize, gates: &Gates, events: &Events) -> GroupQueue {
    let (g, e) = (gates.clone(), events.clone());
    let (g2, e2) = (gates.clone(), events.clone());
    GroupQueue::with_processor(
        config(dir, max),
        processor(
            move |jid| {
                let wait = g.wait();
                let e = e.clone();
                async move {
                    e.push(format!("msg:{jid}"));
                    wait.await;
                    true
                }
            },
            move |jid, task| {
                let wait = g2.wait();
                let e = e2.clone();
                async move {
                    e.push(format!("task:{jid}:{task}"));
                    wait.await;
                }
            },
        ),
    )
}

// ---------------------------------------------------------------------------
// Core queue behaviour
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn only_runs_one_container_per_group_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let current = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let (c, m, n) = (current.clone(), max_seen.clone(), calls.clone());
    let q = GroupQueue::with_processor(
        config(dir.path(), 2),
        messages_only(move |_| {
            let (c, m, n) = (c.clone(), m.clone(), n.clone());
            async move {
                n.fetch_add(1, Ordering::SeqCst);
                let now = c.fetch_add(1, Ordering::SeqCst) + 1;
                m.fetch_max(now, Ordering::SeqCst);
                sleep(Duration::from_millis(100)).await;
                c.fetch_sub(1, Ordering::SeqCst);
                true
            }
        }),
    );

    assert_eq!(q.enqueue_message_check(G1), EnqueueOutcome::Started);
    assert_eq!(q.enqueue_message_check(G1), EnqueueOutcome::Queued);
    sleep(Duration::from_millis(250)).await;

    assert_eq!(max_seen.load(Ordering::SeqCst), 1);
    // The queued check was drained after the first run finished.
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn respects_global_concurrency_limit() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_message_check(G1);
    q.enqueue_message_check(G2);
    assert_eq!(q.enqueue_message_check(G3), EnqueueOutcome::Queued);
    settle().await;

    assert_eq!(events.all().len(), 2);
    assert_eq!(q.status().active_containers, 2);

    gates.release(0);
    settle().await;
    assert_eq!(events.all().len(), 3);
    assert_eq!(q.status().active_containers, 2);
}

#[tokio::test(start_paused = true)]
async fn drains_tasks_before_messages_for_same_group() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;

    // While active, enqueue both a task and pending messages.
    assert_eq!(q.enqueue_task(G1, "task-1"), EnqueueOutcome::Queued);
    assert_eq!(q.enqueue_message_check(G1), EnqueueOutcome::Queued);

    gates.release(0);
    settle().await;
    gates.release(1);
    settle().await;

    assert_eq!(
        events.all(),
        vec![
            format!("msg:{G1}"),
            format!("task:{G1}:task-1"),
            format!("msg:{G1}")
        ]
    );
    gates.release(2);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn retries_with_exponential_backoff_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let q = GroupQueue::with_processor(
        config(dir.path(), 2),
        messages_only(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            async { false }
        }),
    );
    q.enqueue_message_check(G1);

    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // First retry after 5000 ms (base * 2^0).
    sleep(Duration::from_millis(5000)).await;
    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // Second retry after 10000 ms (base * 2^1).
    sleep(Duration::from_millis(10_000)).await;
    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn prevents_new_enqueues_after_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let q = GroupQueue::with_processor(
        config(dir.path(), 2),
        messages_only(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            async { true }
        }),
    );

    let report = q.shutdown(Duration::from_secs(1)).await;
    assert!(report.drained);

    assert_eq!(q.enqueue_message_check(G1), EnqueueOutcome::ShuttingDown);
    assert_eq!(q.enqueue_task(G1, "t"), EnqueueOutcome::ShuttingDown);
    sleep(Duration::from_millis(100)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(q.is_shutting_down());
}

#[tokio::test(start_paused = true)]
async fn stops_retrying_after_max_retries_and_resets() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let q = GroupQueue::with_processor(
        config(dir.path(), 2),
        messages_only(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            async { false }
        }),
    );
    q.enqueue_message_check(G1);
    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    for (i, delay) in [5_000u64, 10_000, 20_000, 40_000, 80_000]
        .iter()
        .enumerate()
    {
        sleep(Duration::from_millis(delay + 10)).await;
        assert_eq!(calls.load(Ordering::SeqCst), i + 2);
    }

    // After 5 retries (6 calls) it stops.
    sleep(Duration::from_secs(200)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    // ...and resets, so the lane state is gone and a new message starts fresh.
    assert!(q.snapshot().lanes.is_empty());
    q.enqueue_message_check(G1);
    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), 7);
    sleep(Duration::from_millis(5_010)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 8);
}

#[tokio::test(start_paused = true)]
async fn drains_waiting_groups_when_active_slots_free_up() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_message_check(G1);
    q.enqueue_message_check(G2);
    settle().await;
    q.enqueue_message_check(G3);
    settle().await;
    assert_eq!(events.all(), vec![format!("msg:{G1}"), format!("msg:{G2}")]);
    assert_eq!(q.status().waiting_groups, 1);

    gates.release(0);
    settle().await;
    assert!(events.all().contains(&format!("msg:{G3}")));
    assert_eq!(q.status().waiting_groups, 0);
}

#[tokio::test(start_paused = true)]
async fn rejects_duplicate_enqueue_of_a_currently_running_task() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    assert_eq!(q.enqueue_task(G1, "task-1"), EnqueueOutcome::Started);
    settle().await;
    assert_eq!(events.all().len(), 1);

    // The scheduler re-discovers the same task while it runs.
    assert_eq!(q.enqueue_task(G1, "task-1"), EnqueueOutcome::AlreadyRunning);
    settle().await;

    gates.release(0);
    settle().await;
    assert_eq!(events.all(), vec![format!("task:{G1}:task-1")]);
}

#[tokio::test(start_paused = true)]
async fn does_not_preempt_active_container_when_not_idle() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;
    assert!(q.register_process(G1, FakeContainer::new("container-1"), IPC_KEY));

    q.enqueue_task(G1, "task-1");
    assert!(
        !take_close(dir.path()),
        "_close must not be written while busy"
    );

    gates.release(0);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn preempts_idle_container_when_task_is_enqueued() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;
    q.register_process(G1, FakeContainer::new("container-1"), IPC_KEY);
    q.notify_idle(G1);
    assert!(!take_close(dir.path()));

    q.enqueue_task(G1, "task-1");
    assert!(
        take_close(dir.path()),
        "_close must be written for an idle container"
    );

    gates.release(0);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn send_message_resets_idle_waiting_so_a_task_enqueue_does_not_preempt() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;
    q.register_process(G1, FakeContainer::new("container-1"), IPC_KEY);
    q.notify_idle(G1);

    assert!(q.send_message(G1, "hello"));

    q.enqueue_task(G1, "task-1");
    assert!(!take_close(dir.path()));

    gates.release(0);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn send_message_returns_false_for_task_containers() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_task(G1, "task-1");
    settle().await;
    q.register_process(G1, FakeContainer::new("container-1"), IPC_KEY);

    assert!(!q.send_message(G1, "hello"));
    assert!(input_messages(dir.path()).is_empty());

    gates.release(0);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn preempts_when_idle_arrives_with_pending_tasks() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;
    q.register_process(G1, FakeContainer::new("container-1"), IPC_KEY);

    q.enqueue_task(G1, "task-1");
    assert!(!take_close(dir.path()));

    q.notify_idle(G1);
    assert!(take_close(dir.path()));

    gates.release(0);
    settle().await;
}

// ---------------------------------------------------------------------------
// Rust additions
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn duplicate_queued_task_is_not_queued_twice() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 1, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;
    assert_eq!(q.enqueue_task(G1, "t1"), EnqueueOutcome::Queued);
    assert_eq!(q.enqueue_task(G1, "t1"), EnqueueOutcome::AlreadyQueued);
    // Also while waiting for a global slot.
    assert_eq!(q.enqueue_task(G2, "t2"), EnqueueOutcome::Queued);
    assert_eq!(q.enqueue_task(G2, "t2"), EnqueueOutcome::AlreadyQueued);
    assert_eq!(q.snapshot().waiting, vec![G2.to_string()]);

    for i in 0..3 {
        gates.release(i);
        settle().await;
    }
    let tasks: Vec<String> = events
        .all()
        .into_iter()
        .filter(|e| e.starts_with("task:"))
        .collect();
    assert_eq!(
        tasks,
        vec![format!("task:{G2}:t2"), format!("task:{G1}:t1")]
    );
}

#[tokio::test(start_paused = true)]
async fn send_message_writes_protocol_file_only_for_registered_message_containers() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    // No running job.
    assert!(!q.send_message(G1, "early"));
    q.enqueue_message_check(G1);
    settle().await;
    // Running, but no container registered yet.
    assert!(!q.send_message(G1, "unregistered"));
    assert!(!q.close_stdin(G1));

    q.register_process(G1, FakeContainer::new("c"), IPC_KEY);
    assert!(q.send_message(G1, "follow-up"));
    assert_eq!(
        input_messages(dir.path()),
        vec![r#"{"type":"message","text":"follow-up"}"#.to_string()]
    );
    assert!(q.close_stdin(G1));
    assert!(close_path(dir.path()).exists());
    // The closing container takes `_close` first and exits: a follow-up
    // must wait for the next run instead of being written unread.
    assert!(!q.send_message(G1, "too late for this run"));
    assert_eq!(input_messages(dir.path()).len(), 1);

    gates.release(0);
    settle().await;
    // Lane finished: registration is gone.
    assert!(!q.send_message(G1, "late"));
    assert!(!q.close_stdin(G1));
}

#[tokio::test(start_paused = true)]
async fn register_process_requires_a_running_job_and_valid_key() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    assert!(!q.register_process(G1, FakeContainer::new("c"), IPC_KEY));
    q.enqueue_message_check(G1);
    settle().await;
    assert!(!q.register_process(G1, FakeContainer::new("c"), "../escape"));
    // The container is known (for stop) but IPC writes are disabled.
    assert!(!q.send_message(G1, "x"));
    assert!(q.stop_container(G1).await);
    assert!(q.register_process(G1, FakeContainer::new("c2"), IPC_KEY));
    assert!(q.send_message(G1, "x"));

    gates.release(0);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn stop_container_calls_the_registered_handle() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    assert!(!q.stop_container(G1).await);
    q.enqueue_message_check(G1);
    settle().await;
    let c = FakeContainer::new("c");
    q.register_process(G1, c.clone(), IPC_KEY);
    assert!(q.stop_container(G1).await);
    assert_eq!(c.stops.load(Ordering::SeqCst), 1);

    gates.release(0);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn status_and_snapshot_report_lanes() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 2, &gates, &events);

    q.enqueue_message_check(G2);
    q.enqueue_task(G1, "t1");
    q.enqueue_message_check(G3);
    settle().await;
    q.register_process(G2, FakeContainer::new("talon-g2"), IPC_KEY);
    q.notify_idle(G2);
    q.enqueue_message_check(G2);
    sleep(Duration::from_millis(500)).await;

    let status = q.status();
    assert_eq!(
        status,
        QueueStatus {
            active_containers: 2,
            max_containers: 2,
            waiting_groups: 1,
            active_jids: vec![G1.to_string(), G2.to_string()],
        }
    );

    let snap = q.snapshot();
    assert_eq!(snap.active, 2);
    assert_eq!(snap.waiting, vec![G3.to_string()]);
    assert!(!snap.shutting_down);
    let jids: Vec<&str> = snap.lanes.iter().map(|l| l.jid.as_str()).collect();
    assert_eq!(jids, vec![G1, G2, G3]);
    let g1 = &snap.lanes[0];
    assert_eq!(
        g1.running,
        Some(LaneJob::Task {
            task_id: "t1".into()
        })
    );
    let g2 = &snap.lanes[1];
    assert_eq!(g2.running, Some(LaneJob::Messages));
    assert!(g2.idle_waiting);
    assert!(g2.pending_messages);
    assert_eq!(g2.container_name.as_deref(), Some("talon-g2"));
    assert_eq!(g2.ipc_key.as_deref(), Some(IPC_KEY));
    assert!(g2.running_for_ms.unwrap() >= 500);
    let g3 = &snap.lanes[2];
    assert!(g3.running.is_none() && g3.waiting && g3.pending_messages);
    // Serializes for /status.
    let json = serde_json::to_value(&snap).unwrap();
    assert_eq!(json["lanes"][0]["running"]["kind"], "task");

    for i in 0..4 {
        gates.release(i);
        settle().await;
    }
}

#[tokio::test(start_paused = true)]
async fn busy_lane_yields_its_slot_to_waiting_lanes() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 1, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;
    q.enqueue_message_check(G2); // waits for the only slot
    q.enqueue_message_check(G1); // G1 has more work while running
    gates.release(0);
    settle().await;
    // G2 waited first, so it runs before G1's follow-up.
    assert_eq!(events.all(), vec![format!("msg:{G1}"), format!("msg:{G2}")]);
    assert_eq!(q.snapshot().waiting, vec![G1.to_string()]);

    gates.release(1);
    settle().await;
    assert_eq!(
        events.all(),
        vec![
            format!("msg:{G1}"),
            format!("msg:{G2}"),
            format!("msg:{G1}")
        ]
    );
    gates.release(2);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn waiting_lane_runs_tasks_before_messages() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 1, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;
    q.enqueue_message_check(G2);
    q.enqueue_task(G2, "t2");
    gates.release(0);
    settle().await;
    gates.release(1);
    settle().await;
    assert_eq!(
        events.all(),
        vec![
            format!("msg:{G1}"),
            format!("task:{G2}:t2"),
            format!("msg:{G2}")
        ]
    );
    gates.release(2);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn panicking_processor_does_not_wedge_the_lane() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let q = GroupQueue::with_processor(
        config(dir.path(), 1),
        processor(
            move |_| {
                let first = n.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    assert!(!first, "simulated host panic");
                    true
                }
            },
            |_, _| async { panic!("task panic") },
        ),
    );

    q.enqueue_message_check(G1);
    settle().await;
    assert!(!q.is_active(G1));
    assert_eq!(q.status().active_containers, 0);
    // Treated as a failure: retried after the backoff.
    sleep(Duration::from_millis(5_010)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // A panicking task releases its slot too.
    q.enqueue_task(G1, "t");
    settle().await;
    assert_eq!(q.status().active_containers, 0);
    assert_eq!(q.enqueue_message_check(G1), EnqueueOutcome::Started);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn idle_lanes_are_garbage_collected() {
    let dir = tempfile::tempdir().unwrap();
    let q = GroupQueue::with_processor(config(dir.path(), 2), messages_only(|_| async { true }));
    for i in 0..50 {
        q.enqueue_message_check(&format!("http:copilot:u:{i}"));
    }
    settle().await;
    assert!(q.snapshot().lanes.is_empty());
}

#[tokio::test(start_paused = true)]
async fn missing_processor_is_a_noop() {
    let dir = tempfile::tempdir().unwrap();
    let q = GroupQueue::new(config(dir.path(), 1));
    assert_eq!(q.enqueue_message_check(G1), EnqueueOutcome::Started);
    settle().await;
    assert_eq!(q.status().active_containers, 0);
    assert!(q.snapshot().lanes.is_empty());
}

#[tokio::test(start_paused = true)]
async fn shutdown_closes_running_containers_and_waits_for_them() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 1, &gates, &events);

    q.enqueue_message_check(G1);
    settle().await;
    q.register_process(G1, FakeContainer::new("c1"), IPC_KEY);
    q.enqueue_message_check(G2); // waiting
    q.enqueue_task(G1, "t1"); // pending

    let q2 = q.clone();
    let shutdown = tokio::spawn(async move { q2.shutdown(Duration::from_secs(10)).await });
    settle().await;
    assert!(
        take_close(dir.path()),
        "shutdown asks running containers to close"
    );
    assert!(!shutdown.is_finished());

    // The container exits after its turn.
    gates.release(0);
    let report = shutdown.await.unwrap();
    assert!(report.drained);
    assert!(report.still_active.is_empty());
    assert_eq!(report.dropped_pending, 2);
    // Nothing else ran after shutdown.
    assert_eq!(events.all(), vec![format!("msg:{G1}")]);
    assert_eq!(gates.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn shutdown_detaches_containers_after_grace_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 1, &gates, &events);
    q.enqueue_message_check(G1);
    settle().await;
    let c = FakeContainer::new("c1");
    q.register_process(G1, c.clone(), IPC_KEY);

    let started = tokio::time::Instant::now();
    let report = q.shutdown(Duration::from_millis(500)).await;
    assert_eq!(started.elapsed(), Duration::from_millis(500));
    assert!(!report.drained);
    assert_eq!(report.still_active, vec![G1.to_string()]);
    assert!(report.stopped_containers.is_empty());
    assert_eq!(c.stops.load(Ordering::SeqCst), 0);
    gates.release(0);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_stops_containers_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let mut cfg = config(dir.path(), 1);
    cfg.stop_on_shutdown = true;
    let (g, e) = (gates.clone(), events.clone());
    let q = GroupQueue::with_processor(
        cfg,
        messages_only(move |jid| {
            let wait = g.wait();
            let e = e.clone();
            async move {
                e.push(jid);
                wait.await;
                true
            }
        }),
    );
    q.enqueue_message_check(G1);
    settle().await;
    // Stopping the container ends the run (the host's runner sees the exit).
    let c = Arc::new(FakeContainer {
        name: "c1".into(),
        stops: AtomicUsize::new(0),
        on_stop: Some(gates.clone()),
    });
    q.register_process(G1, c.clone(), IPC_KEY);

    let report = q.shutdown(Duration::from_millis(200)).await;
    assert_eq!(c.stops.load(Ordering::SeqCst), 1);
    assert_eq!(report.stopped_containers, vec!["c1".to_string()]);
    assert!(report.drained);
    assert!(report.still_active.is_empty());
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_pending_retries() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let q = GroupQueue::with_processor(
        config(dir.path(), 1),
        messages_only(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            async { false }
        }),
    );
    q.enqueue_message_check(G1);
    settle().await;
    assert!(q.snapshot().lanes[0].retry_scheduled);

    let report = q.shutdown(Duration::from_secs(1)).await;
    assert!(report.drained);
    sleep(Duration::from_secs(600)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn close_timer_fires_resets_and_cancels() {
    let dir = tempfile::tempdir().unwrap();
    let gates = Gates::default();
    let events = Events::default();
    let q = gated_queue(dir.path(), 1, &gates, &events);
    q.enqueue_message_check(G1);
    settle().await;
    q.register_process(G1, FakeContainer::new("c"), IPC_KEY);

    // Idle-timer semantics: every reset postpones the close.
    let mut timer = q.close_timer(G1, Duration::from_millis(100));
    assert!(!timer.is_armed());
    timer.reset();
    sleep(Duration::from_millis(60)).await;
    timer.reset();
    sleep(Duration::from_millis(60)).await;
    assert!(!take_close(dir.path()));
    sleep(Duration::from_millis(50)).await;
    assert!(take_close(dir.path()));
    assert!(!timer.is_armed());

    // Task-close semantics: arm once only.
    let mut once = q.close_timer(G1, Duration::from_millis(100));
    assert!(once.arm_once());
    assert!(!once.arm_once());
    assert!(once.is_armed());
    once.cancel();
    sleep(Duration::from_millis(200)).await;
    assert!(!take_close(dir.path()));

    // Dropping cancels.
    let mut dropped = q.close_timer(G1, Duration::from_millis(100));
    dropped.reset();
    drop(dropped);
    sleep(Duration::from_millis(200)).await;
    assert!(!take_close(dir.path()));

    gates.release(0);
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn jittered_retry_delay_stays_within_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let fail = Arc::new(AtomicBool::new(true));
    let (n, f) = (calls.clone(), fail.clone());
    let mut cfg = QueueConfig::new(dir.path(), 1);
    cfg.retry.jitter = 0.2;
    let q = GroupQueue::with_processor(
        cfg,
        messages_only(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            let ok = !f.load(Ordering::SeqCst);
            async move { ok }
        }),
    );
    q.enqueue_message_check(G1);
    settle().await;
    fail.store(false, Ordering::SeqCst);
    // 5 s ± 20 %: not before 4 s, certainly by 6 s.
    sleep(Duration::from_millis(3_980)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    sleep(Duration::from_millis(2_020)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn config_from_talon_config() {
    let env = talon_core::env::EnvFile::default();
    let cfg = talon_core::config::TalonConfig::from_env(Path::new("/srv/talon"), env);
    let q = QueueConfig::from_talon_config(&cfg);
    assert_eq!(q.max_concurrent, cfg.max_concurrent_containers);
    assert_eq!(q.data_dir, cfg.data_dir);
    assert!(!q.stop_on_shutdown);
}
