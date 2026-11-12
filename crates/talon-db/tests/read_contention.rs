//! Read-contention measurement for [`talon_db::Db`] (file-backed, WAL).
//!
//! Not a correctness test: it prints how read latency and throughput behave
//! when several lanes read while one writes, and is therefore `#[ignore]`d.
//! Run it with
//!
//! ```text
//! cargo test -p talahon-db --release --test read_contention -- --ignored --nocapture
//! ```
//!
//! Each scenario runs `readers` threads issuing the reads a lane issues per
//! turn (recent messages of a chat, its registered group, the due tasks, a
//! router cursor) for a fixed wall-clock window, optionally next to one
//! writer thread that stores a message and appends an audit event per
//! iteration (two commits, i.e. two WAL fsyncs).

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use talon_core::types::{ContextMode, ScheduleType, TaskStatus};
use talon_db::{ChatMetadata, DB_FILE_NAME, Db, NewMessage, RegisteredGroup, ScheduledTask};

const CHATS: usize = 5;
const MESSAGES_PER_CHAT: usize = 400;
const WINDOW: Duration = Duration::from_millis(1500);

#[derive(Clone, Copy, PartialEq)]
enum Writer {
    /// No writer: pure reader scaling.
    Off,
    /// One message + one audit event every 5 ms (a busy but realistic host).
    Paced,
    /// Writes back to back (worst case).
    Saturating,
}

fn jid(chat: usize) -> String {
    format!("chat{chat}@g.us")
}

fn message(chat: usize, id: &str, ts: &str) -> NewMessage {
    NewMessage {
        id: id.to_string(),
        chat_jid: jid(chat),
        sender: "analyst".into(),
        sender_name: "Analyst".into(),
        content: "Suspicious PowerShell on host WS-042, please triage and correlate".into(),
        timestamp: ts.to_string(),
        ..Default::default()
    }
}

fn seed(db: &Db) {
    for chat in 0..CHATS {
        db.store_chat_metadata(&ChatMetadata {
            chat_jid: jid(chat),
            timestamp: "2024-01-01T00:00:00.000Z".into(),
            ..Default::default()
        })
        .unwrap();
        db.set_registered_group(
            &jid(chat),
            &RegisteredGroup {
                name: format!("Chat {chat}"),
                folder: format!("chat{chat}"),
                trigger: "@Talahon".into(),
                added_at: "2024-01-01T00:00:00.000Z".into(),
                container_config: None,
                requires_trigger: None,
                is_main: false,
                session_key: None,
                ipc_key: None,
                ephemeral_session: false,
                trusted_session_commands: false,
            },
        )
        .unwrap();
        db.set_router_state(&format!("cursor{chat}"), "2024-01-01T00:00:00.000Z")
            .unwrap();
        for m in 0..MESSAGES_PER_CHAT {
            let ts = format!(
                "2024-01-01T{:02}:{:02}:{:02}.000Z",
                m / 3600,
                (m / 60) % 60,
                m % 60
            );
            db.store_message(&message(chat, &format!("seed-{chat}-{m}"), &ts))
                .unwrap();
        }
    }
    for t in 0..20 {
        db.create_task(&ScheduledTask {
            id: format!("task-{t}"),
            group_folder: "chat0".into(),
            chat_jid: jid(0),
            prompt: "sweep open alerts".into(),
            script: None,
            schedule_type: ScheduleType::Once,
            schedule_value: "2024-06-01T00:00:00.000Z".into(),
            context_mode: ContextMode::Isolated,
            next_run: Some("2024-06-01T00:00:00.000Z".into()),
            last_run: None,
            last_result: None,
            status: TaskStatus::Active,
            created_at: "2024-01-01T00:00:00.000Z".into(),
        })
        .unwrap();
    }
}

/// One lane turn's worth of reads; returns the latency of each call.
fn read_round(db: &Db, chat: usize, out: &mut Vec<Duration>) {
    let mut timed = |f: &dyn Fn()| {
        let start = Instant::now();
        f();
        out.push(start.elapsed());
    };
    timed(&|| {
        let msgs = db
            .get_messages_since(&jid(chat), "", "Talahon", 50)
            .unwrap();
        assert_eq!(msgs.len(), 50);
    });
    timed(&|| assert!(db.get_registered_group(&jid(chat)).unwrap().is_some()));
    timed(&|| {
        assert_eq!(
            db.get_due_tasks("2025-01-01T00:00:00.000Z").unwrap().len(),
            20
        )
    });
    timed(&|| {
        assert!(
            db.get_router_state(&format!("cursor{chat}"))
                .unwrap()
                .is_some()
        );
    });
}

struct Outcome {
    reads_per_sec: f64,
    p50: Duration,
    p99: Duration,
    max: Duration,
    writes_per_sec: f64,
}

fn run(readers: usize, writer: Writer) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join(DB_FILE_NAME)).unwrap();
    seed(&db);
    let stop = Arc::new(AtomicBool::new(false));

    let writer_handle = (writer != Writer::Off).then(|| {
        let (db, stop) = (db.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                db.store_message(&message(
                    0,
                    &format!("w-{n}"),
                    &format!("2025-01-01T00:00:00.{:03}Z", n % 1000),
                ))
                .unwrap();
                db.record_audit(&talon_core::audit::event(
                    "bench.write",
                    "bench",
                    None,
                    "info",
                    serde_json::json!({ "n": n }),
                ))
                .unwrap();
                n += 1;
                if writer == Writer::Paced {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            n * 2
        })
    });

    let start = Instant::now();
    let handles: Vec<_> = (0..readers)
        .map(|r| {
            let (db, stop) = (db.clone(), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut lat = Vec::with_capacity(200_000);
                while !stop.load(Ordering::Relaxed) {
                    read_round(&db, r % CHATS, &mut lat);
                }
                lat
            })
        })
        .collect();
    std::thread::sleep(WINDOW);
    stop.store(true, Ordering::Relaxed);
    let mut lat: Vec<Duration> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let elapsed = start.elapsed().as_secs_f64();
    let writes = writer_handle.map_or(0, |h| h.join().unwrap());

    lat.sort_unstable();
    let pct = |p: f64| lat[((lat.len() - 1) as f64 * p) as usize];
    Outcome {
        reads_per_sec: lat.len() as f64 / elapsed,
        p50: pct(0.50),
        p99: pct(0.99),
        max: lat[lat.len() - 1],
        writes_per_sec: writes as f64 / elapsed,
    }
}

#[test]
#[ignore = "measurement, not a correctness test; run with --ignored --nocapture"]
fn read_latency_while_writing() {
    println!(
        "{:<11} {:>7} {:>11} {:>10} {:>10} {:>10} {:>10}",
        "writer", "readers", "reads/s", "p50", "p99", "max", "commits/s"
    );
    for (name, writer) in [
        ("off", Writer::Off),
        ("paced-5ms", Writer::Paced),
        ("saturating", Writer::Saturating),
    ] {
        for readers in [1, 2, 4, 8] {
            let o = run(readers, writer);
            println!(
                "{:<11} {:>7} {:>11.0} {:>10.1?} {:>10.1?} {:>10.1?} {:>10.0}",
                name, readers, o.reads_per_sec, o.p50, o.p99, o.max, o.writes_per_sec
            );
        }
    }
}
