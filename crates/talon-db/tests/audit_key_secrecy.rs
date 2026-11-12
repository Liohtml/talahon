//! The audit key never reaches a log line, an error message, a `Debug`
//! rendering or the disk.
//!
//! A test binary of its own: it captures `tracing` output, and callsites
//! that another test of the same process hit first without a subscriber
//! would stay disabled.

use std::io::Write;
use std::sync::{Arc, Mutex};

use talon_core::audit::AuditSink;
use talon_db::{
    AuditEvent, AuditFailure, AuditKey, Db, DbAuditSink, default_audit_checkpoint_path,
    default_db_path,
};

const KEY: &str = "5f3a9c1e7b2d4f60a8c1e3b5d7f90a1c2e4b6d8f0a1c3e5b7d9f1a3c5e7b9d0f";
const OTHER_KEY: &str = "another-valid-key-ZYXWVUTSRQPONMLKJIHGFEDCBA-987654";

/// `tracing` writer collecting everything that is logged.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut log) = self.0.lock() {
            log.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn ev(kind: &str) -> AuditEvent {
    talon_core::audit::event(kind, "main", None, "allowed", serde_json::json!({ "n": 1 }))
}

#[test]
fn the_key_never_reaches_logs_errors_or_disk() {
    let logs = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(logs.clone())
        .finish();
    let dir = tempfile::tempdir().unwrap();
    let db_path = default_db_path(dir.path());
    let checkpoint = default_audit_checkpoint_path(dir.path());
    let open = |key: Option<&str>| {
        let db = Db::open(&db_path).unwrap();
        if let Some(key) = key {
            db.enable_keyed_audit(AuditKey::parse(key).unwrap(), Some(checkpoint.clone()))
                .unwrap();
        }
        db
    };
    let mut texts: Vec<String> = Vec::new();

    tracing::subscriber::with_default(subscriber, || {
        // Unkeyed row, then the transition and keyed rows.
        open(None).record_audit(&ev("unkeyed")).unwrap();
        let db = open(Some(KEY));
        texts.push(format!("{db:?} {:?}", AuditKey::parse(KEY).unwrap()));
        for _ in 0..3 {
            db.record_audit(&ev("keyed")).unwrap();
        }

        // Truncated tail: verification failure, then the anomaly at the
        // next append (through the sink, which mirrors to tracing).
        {
            let attacker = rusqlite::Connection::open(&db_path).unwrap();
            attacker
                .execute_batch(
                    "DROP TRIGGER audit_log_no_delete; DELETE FROM audit_log WHERE id > 3;",
                )
                .unwrap();
        }
        let v = db.verify_audit().unwrap();
        assert!(matches!(v.failure, Some(AuditFailure::Truncated { .. })));
        texts.push(format!("{v:?} {}", v.failure.clone().unwrap()));
        texts.push(db.verify_audit_chain().unwrap_err().to_string());
        DbAuditSink::new(db.clone()).record(ev("after"));

        // Checkpoint that can be neither read nor replaced.
        std::fs::remove_file(&checkpoint).unwrap();
        std::fs::create_dir(&checkpoint).unwrap();
        std::fs::write(checkpoint.join("x"), "x").unwrap();
        db.record_audit(&ev("keyed")).unwrap();
        std::fs::remove_dir_all(&checkpoint).unwrap();
        db.record_audit(&ev("keyed")).unwrap();
        assert!(db.verify_audit().unwrap().is_intact());

        // Wrong key, missing key.
        let wrong = open(Some(OTHER_KEY));
        let v = wrong.verify_audit().unwrap();
        assert!(!v.is_intact());
        texts.push(format!("{v:?} {}", v.failure.clone().unwrap()));
        texts.push(format!("{:?}", wrong.audit_key_status()));
        let none = open(None);
        let v = none.verify_audit().unwrap();
        assert!(matches!(v.failure, Some(AuditFailure::KeyMissing { .. })));
        texts.push(format!("{v:?} {}", v.failure.clone().unwrap()));
        texts.push(none.record_audit(&ev("x")).unwrap_err().to_string());
        DbAuditSink::new(none).record(ev("x"));

        // Rejected keys, a second key on the same handle.
        texts.push(AuditKey::parse(&KEY[..20]).unwrap_err().to_string());
        texts.push(format!("{:?}", AuditKey::parse(&"k".repeat(64))));
        texts.push(
            db.enable_keyed_audit(AuditKey::parse(KEY).unwrap(), None)
                .unwrap_err()
                .to_string(),
        );
    });

    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for expected in [
        "audit checkpoint does not match",
        "cannot write the audit checkpoint",
        "failed to persist audit event",
    ] {
        assert!(
            logged.contains(expected),
            "missing {expected:?} in:\n{logged}"
        );
    }
    texts.push(logged);
    texts.push(std::fs::read_to_string(&checkpoint).unwrap());
    // The database file and its WAL hold MACs, never the key.
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        texts.push(String::from_utf8_lossy(&bytes).into_owned());
    }
    for text in &texts {
        for secret in [KEY, OTHER_KEY, &KEY[..20]] {
            assert!(!text.contains(secret), "key leaked into: {text}");
        }
    }
}
