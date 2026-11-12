//! Tests of the keyed audit chain and its checkpoint (child module of
//! `audit`).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::json;

use super::*;
use crate::DB_FILE_NAME;

const KEY: &str = "5f3a9c1e7b2d4f60a8c1e3b5d7f90a1c2e4b6d8f0a1c3e5b7d9f1a3c5e7b9d0f";
/// The key of somebody who can write the database but not read `.env`.
const ATTACKER_KEY: &str = "attacker-chosen-key-0123456789-abcdefghijklmnop";

fn key(raw: &str) -> AuditKey {
    AuditKey::parse(raw).unwrap()
}

fn ev(kind: &str, i: usize) -> AuditEvent {
    AuditEvent {
        timestamp: "2026-01-01T00:00:00.000Z".into(),
        kind: kind.into(),
        actor: "main".into(),
        target: Some("task-1".into()),
        outcome: "allowed".into(),
        details: json!({ "i": i }),
    }
}

fn fill(db: &Db, n: usize) {
    for i in 0..n {
        db.record_audit(&ev("ipc.task.allowed", i)).unwrap();
    }
}

/// A store directory with a database file and a checkpoint path.
struct Store {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    checkpoint: PathBuf,
}

impl Store {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            db_path: dir.path().join(DB_FILE_NAME),
            checkpoint: default_audit_checkpoint_path(dir.path()),
            _dir: dir,
        }
    }

    /// Open without an audit key.
    fn unkeyed(&self) -> Db {
        Db::open(&self.db_path).unwrap()
    }

    /// Open with `raw_key` and the checkpoint file.
    fn keyed_with(&self, raw_key: &str) -> Db {
        let db = self.unkeyed();
        db.enable_keyed_audit(key(raw_key), Some(self.checkpoint.clone()))
            .unwrap();
        db
    }

    fn keyed(&self) -> Db {
        self.keyed_with(KEY)
    }

    /// Open with the key but without a checkpoint file.
    fn keyed_without_checkpoint(&self) -> Db {
        let db = self.unkeyed();
        db.enable_keyed_audit(key(KEY), None).unwrap();
        db
    }

    /// Raw connection of somebody with write access to the database file
    /// (append-only triggers dropped).
    fn attacker(&self) -> Connection {
        attacker(&self.db_path)
    }
}

fn attacker(path: &Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "DROP TRIGGER IF EXISTS audit_log_no_update; DROP TRIGGER IF EXISTS audit_log_no_delete;",
    )
    .unwrap();
    c
}

/// `(id, event, scheme, seq)` of every row, read like an attacker would.
fn raw_rows(c: &Connection) -> Vec<(i64, AuditEvent, String, Option<i64>)> {
    let mut stmt = c
        .prepare(
            "SELECT id, timestamp, kind, actor, target, outcome, details, scheme, seq
             FROM audit_log ORDER BY id",
        )
        .unwrap();
    stmt.query_map([], |r| {
        let details: String = r.get(6)?;
        Ok((
            r.get(0)?,
            AuditEvent {
                timestamp: r.get(1)?,
                kind: r.get(2)?,
                actor: r.get(3)?,
                target: r.get(4)?,
                outcome: r.get(5)?,
                details: serde_json::from_str(&details).unwrap(),
            },
            r.get(7)?,
            r.get(8)?,
        ))
    })
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

fn hash_of(c: &Connection, id: i64) -> String {
    c.query_row("SELECT hash FROM audit_log WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .unwrap()
}

/// Rewrite every row from `from_id` on: apply `edit` to the event and
/// recompute `prev_hash` / `hash` with `rehash(seq, prev, event)`, storing
/// `scheme`. This is what somebody with database write access can do.
fn recompute_from(
    c: &Connection,
    from_id: i64,
    scheme: &str,
    edit: impl Fn(i64, &mut AuditEvent),
    rehash: impl Fn(u64, &str, &AuditEvent) -> String,
) {
    let rows = raw_rows(c);
    let mut prev = if from_id == rows[0].0 {
        AUDIT_GENESIS_HASH.to_string()
    } else {
        hash_of(c, from_id - 1)
    };
    for (position, (id, mut event, _, _)) in rows.into_iter().enumerate() {
        if id < from_id {
            continue;
        }
        edit(id, &mut event);
        let seq = position as u64 + 1;
        let hash = rehash(seq, &prev, &event);
        c.execute(
            "UPDATE audit_log SET outcome = ?1, prev_hash = ?2, hash = ?3, scheme = ?4, seq = ?5
             WHERE id = ?6",
            params![
                event.outcome,
                prev,
                hash,
                scheme,
                (scheme != "sha256").then_some(seq as i64),
                id
            ],
        )
        .unwrap();
        prev = hash;
    }
}

fn row_failure(v: &AuditVerification) -> Option<(i64, AuditRowFailure)> {
    match v.failure {
        Some(AuditFailure::Row { id, reason }) => Some((id, reason)),
        _ => None,
    }
}

#[test]
fn keyed_chain_from_genesis() {
    let store = Store::new();
    let db = store.keyed();
    assert_eq!(db.audit_key_status().unwrap(), AuditKeyStatus::Pending);
    assert!(!store.checkpoint.exists());
    fill(&db, 4);
    assert_eq!(db.audit_key_status().unwrap(), AuditKeyStatus::Active);

    let c = store.attacker();
    let rows = raw_rows(&c);
    assert_eq!(rows.len(), 4, "no marker row without unkeyed rows");
    let mut prev = AUDIT_GENESIS_HASH.to_string();
    for (i, (id, event, scheme, seq)) in rows.iter().enumerate() {
        assert_eq!(scheme, "hmac-sha256");
        assert_eq!(*seq, Some(i as i64 + 1));
        let stored = hash_of(&c, *id);
        assert_eq!(
            stored,
            key(KEY).event_mac(i as u64 + 1, &prev, event).unwrap()
        );
        assert_ne!(stored, audit_event_hash(&prev, event).unwrap());
        prev = stored;
    }

    let v = db.verify_audit().unwrap();
    assert!(v.is_intact(), "{v:?}");
    assert_eq!((v.rows, v.keyed_rows, v.first_keyed_row), (4, 4, Some(1)));
    assert!(v.key_configured);
    assert_eq!(
        v.checkpoint,
        AuditCheckpointState::Verified { seq: 4, lag: 0 }
    );
    let head = db.audit_head().unwrap().unwrap();
    assert_eq!(v.head.as_ref(), Some(&head));
    assert_eq!(
        (head.id, head.scheme, head.seq),
        (4, AuditScheme::HmacSha256, Some(4))
    );
    assert_eq!(head.hash, prev);
    assert_eq!(db.audit_chain_head().unwrap(), Some((4, prev)));
    assert_eq!(db.verify_audit_chain().unwrap(), None);
    assert_eq!(db.audit_checkpoint_anomalies().unwrap(), 0);
    // The key is attached once per handle.
    assert!(db.enable_keyed_audit(key(KEY), None).is_err());
}

#[test]
fn in_memory_keyed_chain_without_checkpoint() {
    let db = Db::open_in_memory().unwrap();
    db.enable_keyed_audit(key(KEY), None).unwrap();
    fill(&db, 3);
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact());
    assert_eq!(v.keyed_rows, 3);
    assert_eq!(v.checkpoint, AuditCheckpointState::Disabled);
}

#[test]
fn forged_row_fails_without_the_key() {
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 5);
    // Edit row 3 and give it the hash an unkeyed chain would have.
    let c = store.attacker();
    let (_, mut event, _, _) = raw_rows(&c).remove(2);
    event.outcome = "denied".into();
    let forged = audit_event_hash(&hash_of(&c, 2), &event).unwrap();
    c.execute(
        "UPDATE audit_log SET outcome = 'denied', hash = ?1 WHERE id = 3",
        [&forged],
    )
    .unwrap();
    let v = db.verify_audit().unwrap();
    assert_eq!(row_failure(&v), Some((3, AuditRowFailure::MacMismatch)));
    assert_eq!(v.rows, 2);
    assert_eq!(db.verify_audit_chain().unwrap(), Some(3));

    // Content edit alone, an appended forged row, a changed sequence number.
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 3);
    let c = store.attacker();
    let head = hash_of(&c, 3);
    let fake = ev("forged", 9);
    c.execute(
        "INSERT INTO audit_log (timestamp, kind, actor, target, outcome, details, prev_hash,
           hash, scheme, seq)
         VALUES (?1, 'forged', 'main', 'task-1', 'allowed', '{\"i\":9}', ?2, ?3, 'hmac-sha256', 4)",
        params![
            fake.timestamp,
            head,
            key(ATTACKER_KEY).event_mac(4, &head, &fake).unwrap()
        ],
    )
    .unwrap();
    assert_eq!(
        row_failure(&db.verify_audit().unwrap()),
        Some((4, AuditRowFailure::MacMismatch))
    );
    c.execute("UPDATE audit_log SET seq = 7 WHERE id = 2", [])
        .unwrap();
    assert_eq!(
        row_failure(&db.verify_audit().unwrap()),
        Some((2, AuditRowFailure::BadSequence))
    );
    c.execute("UPDATE audit_log SET scheme = 'md5' WHERE id = 1", [])
        .unwrap();
    assert_eq!(
        row_failure(&db.verify_audit().unwrap()),
        Some((1, AuditRowFailure::UnknownScheme))
    );
}

#[test]
fn recomputed_chain_without_the_key_fails() {
    // The attack an unkeyed chain cannot detect: edit a row, then recompute
    // every hash and link after it.
    let edit = |id: i64, e: &mut AuditEvent| {
        if id == 2 {
            e.outcome = "denied".into();
        }
    };

    // Unkeyed chain: undetected (this is the residual risk being closed).
    let store = Store::new();
    let db = store.unkeyed();
    fill(&db, 5);
    recompute_from(&store.attacker(), 2, "sha256", edit, |_, prev, e| {
        audit_event_hash(prev, e).unwrap()
    });
    assert!(db.verify_audit().unwrap().is_intact());

    // Keyed chain, recomputed under a key the attacker made up.
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 5);
    let attacker_key = key(ATTACKER_KEY);
    recompute_from(&store.attacker(), 2, "hmac-sha256", edit, |seq, prev, e| {
        attacker_key.event_mac(seq, prev, e).unwrap()
    });
    assert_eq!(
        row_failure(&db.verify_audit().unwrap()),
        Some((2, AuditRowFailure::MacMismatch))
    );

    // Keyed chain, tail recomputed as unkeyed rows: a downgrade.
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 5);
    recompute_from(&store.attacker(), 2, "sha256", edit, |_, prev, e| {
        audit_event_hash(prev, e).unwrap()
    });
    assert_eq!(
        row_failure(&db.verify_audit().unwrap()),
        Some((2, AuditRowFailure::Downgrade))
    );

    // Keyed chain, recomputed as unkeyed rows from the very first row: the
    // table alone is a valid unkeyed chain, the checkpoint gives it away.
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 5);
    recompute_from(&store.attacker(), 1, "sha256", edit, |_, prev, e| {
        audit_event_hash(prev, e).unwrap()
    });
    let v = db.verify_audit().unwrap();
    assert_eq!(v.failure, Some(AuditFailure::CheckpointMismatch { seq: 5 }));
    assert_eq!(v.checkpoint, AuditCheckpointState::Failed);
    // ... and the next append records it.
    fill(&db, 1);
    assert_eq!(db.audit_checkpoint_anomalies().unwrap(), 1);
    // Documented limit: without a checkpoint file nothing remembers that
    // the chain was keyed.
    let store = Store::new();
    let db = store.keyed_without_checkpoint();
    fill(&db, 5);
    recompute_from(&store.attacker(), 1, "sha256", edit, |_, prev, e| {
        audit_event_hash(prev, e).unwrap()
    });
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact());
    assert_eq!(v.keyed_rows, 0);
}

#[test]
fn wrong_key_fails_closed() {
    let store = Store::new();
    fill(&store.keyed(), 3);
    let other = "another-valid-key-ZYXWVUTSRQPONMLKJIHGFEDCBA-987654";
    let db = store.keyed_with(other);
    assert_eq!(db.audit_key_status().unwrap(), AuditKeyStatus::KeyMismatch);
    let v = db.verify_audit().unwrap();
    assert_eq!(row_failure(&v), Some((1, AuditRowFailure::MacMismatch)));
    assert_eq!(v.rows, 0);
    let message = v.failure.unwrap().to_string();
    assert!(message.contains("wrong key"), "{message}");
    assert!(!message.contains(other) && !message.contains(KEY));
    assert_eq!(db.verify_audit_chain().unwrap(), Some(1));
    // The right key still verifies.
    assert!(store.keyed().verify_audit().unwrap().is_intact());
}

#[test]
fn keyed_rows_without_a_key_fail_closed() {
    let store = Store::new();
    fill(&store.unkeyed(), 2);
    fill(&store.keyed(), 2);
    let db = store.unkeyed();
    assert_eq!(db.audit_key_status().unwrap(), AuditKeyStatus::KeyMissing);
    let v = db.verify_audit().unwrap();
    assert_eq!(
        v.failure,
        Some(AuditFailure::KeyMissing { first_keyed_row: 3 })
    );
    assert!(!v.key_configured);
    assert_eq!(v.rows, 2, "the unkeyed rows before it verified");
    let message = v.failure.unwrap().to_string();
    assert!(message.contains(AUDIT_KEY_ENV), "{message}");
    assert_eq!(db.verify_audit_chain().unwrap(), Some(3));

    // No unkeyed row is appended to a keyed chain.
    let before = db.audit_count().unwrap();
    let err = db.record_audit(&ev("late", 0)).unwrap_err();
    assert!(matches!(&err, Error::Security(m) if m.contains(AUDIT_KEY_ENV)));
    assert_eq!(db.audit_count().unwrap(), before);
    // The sink logs and carries on.
    DbAuditSink::without_tracing(db.clone()).record(ev("late", 1));
    assert_eq!(db.audit_count().unwrap(), before);
}

#[test]
fn downgrade_is_rejected() {
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 2);
    // A correctly hashed and linked *unkeyed* row after keyed ones, as an
    // older release or an attacker would append it.
    let c = store.attacker();
    let head = hash_of(&c, 2);
    let e = ev("downgrade", 0);
    c.execute(
        "INSERT INTO audit_log (timestamp, kind, actor, target, outcome, details, prev_hash, hash)
         VALUES (?1, 'downgrade', 'main', 'task-1', 'allowed', '{\"i\":0}', ?2, ?3)",
        params![e.timestamp, head, audit_event_hash(&head, &e).unwrap()],
    )
    .unwrap();
    let v = db.verify_audit().unwrap();
    assert_eq!(row_failure(&v), Some((3, AuditRowFailure::Downgrade)));
    assert!(v.failure.unwrap().to_string().contains("downgrade"));
    // Without the key the keyed rows already fail.
    assert_eq!(store.unkeyed().verify_audit_chain().unwrap(), Some(1));
}

#[test]
fn unkeyed_chain_becomes_keyed() {
    let store = Store::new();
    fill(&store.unkeyed(), 3);

    let db = store.keyed();
    assert_eq!(db.audit_key_status().unwrap(), AuditKeyStatus::Pending);
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact());
    assert_eq!((v.rows, v.keyed_rows), (3, 0));
    assert_eq!(v.checkpoint, AuditCheckpointState::Absent);

    db.record_audit(&ev("first.keyed", 0)).unwrap();
    db.record_audit(&ev("second.keyed", 1)).unwrap();
    let c = store.attacker();
    let rows = raw_rows(&c);
    let shape: Vec<(&str, &str, Option<i64>)> = rows
        .iter()
        .map(|(_, e, scheme, seq)| (e.kind.as_str(), scheme.as_str(), *seq))
        .collect();
    assert_eq!(
        shape,
        vec![
            ("ipc.task.allowed", "sha256", None),
            ("ipc.task.allowed", "sha256", None),
            ("ipc.task.allowed", "sha256", None),
            (AUDIT_KIND_CHAIN_KEYED, "hmac-sha256", Some(4)),
            ("first.keyed", "hmac-sha256", Some(5)),
            ("second.keyed", "hmac-sha256", Some(6)),
        ]
    );
    assert_eq!(rows[3].1.details["unkeyed_rows"], 3);
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact(), "{v:?}");
    assert_eq!((v.rows, v.keyed_rows, v.first_keyed_row), (6, 3, Some(4)));
    assert_eq!(
        v.checkpoint,
        AuditCheckpointState::Verified { seq: 6, lag: 0 }
    );
    assert_eq!(db.recent_audit(1, None).unwrap()[0].kind, "second.keyed");
    drop(c);

    // The unkeyed prefix is frozen by the first keyed row: recomputing it
    // (which went unnoticed before) now breaks the link into the keyed part.
    let store2 = Store::new();
    fill(&store2.unkeyed(), 3);
    let db2 = store2.keyed();
    fill(&db2, 2);
    let c = store2.attacker();
    let (_, mut e2, _, _) = raw_rows(&c).remove(1);
    e2.outcome = "denied".into();
    let h2 = audit_event_hash(&hash_of(&c, 1), &e2).unwrap();
    let (_, e3, _, _) = raw_rows(&c).remove(2);
    let h3 = audit_event_hash(&h2, &e3).unwrap();
    c.execute(
        "UPDATE audit_log SET outcome = 'denied', hash = ?1 WHERE id = 2",
        [&h2],
    )
    .unwrap();
    c.execute(
        "UPDATE audit_log SET prev_hash = ?1, hash = ?2 WHERE id = 3",
        [&h2, &h3],
    )
    .unwrap();
    assert_eq!(
        row_failure(&db2.verify_audit().unwrap()),
        Some((4, AuditRowFailure::BrokenLink))
    );
    // Relinking the first keyed row needs the key.
    c.execute("UPDATE audit_log SET prev_hash = ?1 WHERE id = 4", [&h3])
        .unwrap();
    assert_eq!(
        row_failure(&db2.verify_audit().unwrap()),
        Some((4, AuditRowFailure::MacMismatch))
    );

    // Removing an unkeyed row shifts the keyed rows' positions.
    let store3 = Store::new();
    fill(&store3.unkeyed(), 3);
    let db3 = store3.keyed();
    fill(&db3, 1);
    store3
        .attacker()
        .execute("DELETE FROM audit_log WHERE id = 1", [])
        .unwrap();
    assert_eq!(
        row_failure(&db3.verify_audit().unwrap()),
        Some((2, AuditRowFailure::BrokenLink))
    );
}

#[test]
fn tail_truncation_is_detected_with_a_checkpoint() {
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 5);
    store
        .attacker()
        .execute("DELETE FROM audit_log WHERE id > 3", [])
        .unwrap();
    let v = db.verify_audit().unwrap();
    assert_eq!(
        v.failure,
        Some(AuditFailure::Truncated {
            checkpoint_seq: 5,
            rows: 3
        })
    );
    assert_eq!((v.rows, v.keyed_rows), (3, 3), "the rows themselves verify");
    assert_eq!(v.checkpoint, AuditCheckpointState::Failed);
    let err = db.verify_audit_chain().unwrap_err();
    assert!(matches!(&err, Error::Security(m) if m.contains("truncated")));

    // The next append puts the evidence into the keyed chain and re-anchors.
    db.record_audit(&ev("after", 0)).unwrap();
    let events = db.recent_audit(2, None).unwrap();
    assert_eq!(events[0].kind, "after");
    assert_eq!(events[1].kind, AUDIT_KIND_CHECKPOINT_ANOMALY);
    assert_eq!(events[1].outcome, "error");
    assert_eq!(
        events[1].details,
        json!({ "reason": "ahead", "checkpoint_seq": 5, "chain_seq": 3 })
    );
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact(), "{v:?}");
    assert_eq!(
        v.checkpoint,
        AuditCheckpointState::Verified { seq: 5, lag: 0 }
    );
    assert_eq!(db.audit_checkpoint_anomalies().unwrap(), 1);
    // Only once.
    db.record_audit(&ev("after", 1)).unwrap();
    assert_eq!(db.audit_checkpoint_anomalies().unwrap(), 1);

    // Every keyed row deleted (back to before the transition), and the
    // whole table emptied.
    let store = Store::new();
    fill(&store.unkeyed(), 2);
    let db = store.keyed();
    fill(&db, 2);
    store
        .attacker()
        .execute("DELETE FROM audit_log WHERE id > 2", [])
        .unwrap();
    assert_eq!(
        db.verify_audit().unwrap().failure,
        Some(AuditFailure::Truncated {
            checkpoint_seq: 5,
            rows: 2
        })
    );
    store
        .attacker()
        .execute("DELETE FROM audit_log", [])
        .unwrap();
    assert_eq!(
        db.verify_audit().unwrap().failure,
        Some(AuditFailure::Truncated {
            checkpoint_seq: 5,
            rows: 0
        })
    );
    db.record_audit(&ev("after", 0)).unwrap();
    assert_eq!(
        db.recent_audit(2, None).unwrap()[1].details["reason"],
        "ahead"
    );
    assert!(db.verify_audit().unwrap().is_intact());
}

#[test]
fn tail_truncation_with_a_deleted_checkpoint() {
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 5);
    store
        .attacker()
        .execute("DELETE FROM audit_log WHERE id > 3", [])
        .unwrap();
    std::fs::remove_file(&store.checkpoint).unwrap();
    assert_eq!(
        db.verify_audit().unwrap().failure,
        Some(AuditFailure::CheckpointMissing)
    );
    db.record_audit(&ev("after", 0)).unwrap();
    assert_eq!(
        db.recent_audit(2, None).unwrap()[1].details,
        json!({ "reason": "missing", "checkpoint_seq": null, "chain_seq": 3 })
    );
    assert!(db.verify_audit().unwrap().is_intact());
}

#[test]
fn tail_truncation_without_a_checkpoint_is_not_detected() {
    // Documented limits. (1) No checkpoint file configured.
    let store = Store::new();
    let db = store.keyed_without_checkpoint();
    fill(&db, 5);
    store
        .attacker()
        .execute("DELETE FROM audit_log WHERE id > 3", [])
        .unwrap();
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact());
    assert_eq!(v.checkpoint, AuditCheckpointState::Disabled);
    // ... but an exported head (external anchor) no longer matches.
    assert_eq!(db.audit_head().unwrap().unwrap().seq, Some(3));

    // (2) No key at all: the behaviour of an unkeyed chain is unchanged.
    let store = Store::new();
    let db = store.unkeyed();
    fill(&db, 5);
    store
        .attacker()
        .execute("DELETE FROM audit_log WHERE id > 3", [])
        .unwrap();
    assert_eq!(db.verify_audit_chain().unwrap(), None);
    assert!(!store.checkpoint.exists());

    // (3) Database *and* checkpoint rolled back to an earlier state the
    // attacker kept a copy of.
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 3);
    let old_checkpoint = std::fs::read(&store.checkpoint).unwrap();
    fill(&db, 2);
    store
        .attacker()
        .execute("DELETE FROM audit_log WHERE id > 3", [])
        .unwrap();
    std::fs::write(&store.checkpoint, &old_checkpoint).unwrap();
    assert!(db.verify_audit().unwrap().is_intact());
}

#[test]
fn checkpoint_tampering_is_detected() {
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 4);
    let original = std::fs::read_to_string(&store.checkpoint).unwrap();
    assert!(original.contains("seq=4"));
    assert!(!original.contains(KEY));

    // Lowering the sequence number to cover a truncation needs the key.
    std::fs::write(&store.checkpoint, original.replace("seq=4", "seq=2")).unwrap();
    let v = db.verify_audit().unwrap();
    assert_eq!(v.failure, Some(AuditFailure::CheckpointInvalid));
    assert_eq!(v.rows, 4);
    // So does a checkpoint MAC'd with another key.
    let forged = Store::new();
    fill(&forged.keyed_with(ATTACKER_KEY), 2);
    std::fs::copy(&forged.checkpoint, &store.checkpoint).unwrap();
    assert_eq!(
        db.verify_audit().unwrap().failure,
        Some(AuditFailure::CheckpointInvalid)
    );
    std::fs::write(&store.checkpoint, "").unwrap();
    assert_eq!(
        db.verify_audit().unwrap().failure,
        Some(AuditFailure::CheckpointInvalid)
    );
    // The next append reports it and writes a good one.
    db.record_audit(&ev("after", 0)).unwrap();
    assert_eq!(
        db.recent_audit(2, None).unwrap()[1].details["reason"],
        "invalid"
    );
    assert!(db.verify_audit().unwrap().is_intact());

    // An authentic checkpoint of another chain position: the head differs.
    let a = Store::new();
    let db_a = a.keyed();
    fill(&db_a, 3);
    let b = Store::new();
    let db_b = b.keyed();
    for i in 0..3 {
        db_b.record_audit(&ev("other.history", i)).unwrap();
    }
    std::fs::copy(&b.checkpoint, &a.checkpoint).unwrap();
    assert_eq!(
        db_a.verify_audit().unwrap().failure,
        Some(AuditFailure::CheckpointMismatch { seq: 3 })
    );
    db_a.record_audit(&ev("after", 0)).unwrap();
    assert_eq!(
        db_a.recent_audit(2, None).unwrap()[1].details["reason"],
        "mismatch"
    );

    // An older authentic checkpoint with an untouched table loses nothing:
    // it verifies and reports the lag.
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 2);
    let old = std::fs::read(&store.checkpoint).unwrap();
    fill(&db, 3);
    std::fs::write(&store.checkpoint, old).unwrap();
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact());
    assert_eq!(
        v.checkpoint,
        AuditCheckpointState::Verified { seq: 2, lag: 3 }
    );
    fill(&db, 1);
    assert_eq!(db.audit_checkpoint_anomalies().unwrap(), 0);
}

#[cfg(unix)]
#[test]
fn unwritable_checkpoint_does_not_block_or_flood_the_log() {
    let store = Store::new();
    let db = store.keyed();
    fill(&db, 2);
    // A directory in place of the file: reads and renames fail.
    std::fs::remove_file(&store.checkpoint).unwrap();
    std::fs::create_dir(&store.checkpoint).unwrap();
    std::fs::write(store.checkpoint.join("x"), "x").unwrap();
    fill(&db, 3);
    // One anomaly (the unreadable checkpoint), not one per append.
    assert_eq!(db.audit_checkpoint_anomalies().unwrap(), 1);
    assert_eq!(db.audit_count().unwrap(), 6);
    assert_eq!(
        db.verify_audit().unwrap().failure,
        Some(AuditFailure::CheckpointInvalid)
    );
    // Once it can be written again the checkpoint catches up.
    std::fs::remove_dir_all(&store.checkpoint).unwrap();
    fill(&db, 1);
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact(), "{v:?}");
    assert_eq!(
        v.checkpoint,
        AuditCheckpointState::Verified { seq: 7, lag: 0 }
    );
}

/// `audit_log` exactly as releases before the keyed chain created it.
const V2_2_AUDIT_SCHEMA: &str = "
    CREATE TABLE audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      kind TEXT NOT NULL,
      actor TEXT NOT NULL,
      target TEXT,
      outcome TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT 'null',
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );
    CREATE INDEX idx_audit_log_kind ON audit_log(kind);
    CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
    CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'audit_log is append-only');
    END;
    CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'audit_log is append-only');
    END;";

#[test]
fn existing_unkeyed_database_migrates_in_place() {
    let store = Store::new();
    {
        let c = Connection::open(&store.db_path).unwrap();
        c.execute_batch(V2_2_AUDIT_SCHEMA).unwrap();
        let mut prev = AUDIT_GENESIS_HASH.to_string();
        for i in 0..4 {
            let e = ev("old.release", i);
            let hash = audit_event_hash(&prev, &e).unwrap();
            c.execute(
                "INSERT INTO audit_log (timestamp, kind, actor, target, outcome, details,
                   prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    e.timestamp,
                    e.kind,
                    e.actor,
                    e.target,
                    e.outcome,
                    canonical_json(&e.details).unwrap(),
                    prev,
                    hash
                ],
            )
            .unwrap();
            prev = hash;
        }
        assert!(!crate::schema::has_column(&c, "audit_log", "scheme").unwrap());
    }

    // Without a key: migrated, verified and extended exactly as before.
    let db = store.unkeyed();
    let c = Connection::open(&store.db_path).unwrap();
    assert!(crate::schema::has_column(&c, "audit_log", "scheme").unwrap());
    assert!(crate::schema::has_column(&c, "audit_log", "seq").unwrap());
    assert!(
        raw_rows(&c)
            .iter()
            .all(|(_, _, scheme, seq)| scheme == "sha256" && seq.is_none())
    );
    assert_eq!(db.audit_key_status().unwrap(), AuditKeyStatus::Unkeyed);
    assert_eq!(db.verify_audit_chain().unwrap(), None);
    db.record_audit(&ev("new.release", 4)).unwrap();
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact());
    assert_eq!((v.rows, v.keyed_rows), (5, 0));
    assert_eq!(v.checkpoint, AuditCheckpointState::Disabled);
    assert_eq!(
        db.audit_head().unwrap().unwrap().scheme,
        AuditScheme::Sha256
    );
    // The append-only triggers survived the migration.
    assert!(
        db.with_conn(|c| c.execute("DELETE FROM audit_log", []).db())
            .is_err()
    );
    drop(db);

    // Re-opening is idempotent; with a key the chain becomes keyed.
    let db = store.keyed();
    db.record_audit(&ev("keyed.release", 5)).unwrap();
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact(), "{v:?}");
    assert_eq!((v.rows, v.keyed_rows, v.first_keyed_row), (7, 2, Some(6)));
    assert_eq!(
        raw_rows(&c)[5].1.details,
        json!({ "scheme": "hmac-sha256", "unkeyed_rows": 5 })
    );
}

#[test]
fn archiving_the_log_after_losing_the_key() {
    // The procedure documented in docs/SECURITY.md.
    let store = Store::new();
    fill(&store.keyed(), 3);
    {
        let c = Connection::open(&store.db_path).unwrap();
        c.execute_batch(
            "DROP TRIGGER audit_log_no_update;
             DROP TRIGGER audit_log_no_delete;
             DROP INDEX idx_audit_log_kind;
             DROP INDEX idx_audit_log_timestamp;
             ALTER TABLE audit_log RENAME TO audit_log_lost_key;",
        )
        .unwrap();
        std::fs::remove_file(&store.checkpoint).unwrap();
    }
    let new_key = "a-brand-new-audit-key-0123456789-ABCDEFGHIJKLMNOP";
    let db = store.keyed_with(new_key);
    assert_eq!(db.audit_key_status().unwrap(), AuditKeyStatus::Pending);
    fill(&db, 2);
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact(), "{v:?}");
    assert_eq!((v.rows, v.keyed_rows), (2, 2));
    assert!(
        db.with_conn(|c| c.execute("DELETE FROM audit_log", []).db())
            .is_err()
    );
    let archived: i64 = db
        .with_conn(|c| {
            c.query_row("SELECT COUNT(*) FROM audit_log_lost_key", [], |r| r.get(0))
                .db()
        })
        .unwrap();
    assert_eq!(archived, 3);
}

#[test]
fn concurrent_keyed_writers_and_verifiers() {
    let store = Store::new();
    let db = store.keyed();
    let other_handle = store.keyed();
    // The checkpoint exists before the handles race (two processes that
    // both append the very first keyed row would report it missing).
    fill(&db, 1);
    std::thread::scope(|s| {
        for t in 0..4 {
            let db = if t % 2 == 0 {
                db.clone()
            } else {
                other_handle.clone()
            };
            s.spawn(move || {
                for i in 0..40 {
                    db.record_audit(&ev("concurrent", t * 100 + i)).unwrap();
                }
            });
        }
        let db = db.clone();
        s.spawn(move || {
            for _ in 0..20 {
                let v = db.verify_audit().unwrap();
                assert!(v.is_intact(), "{v:?}");
            }
        });
    });
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact(), "{v:?}");
    assert_eq!((v.rows, v.keyed_rows), (161, 161));
    // Two handles stand in for two processes: the checkpoint of the very
    // last append may lose the race against the one before it.
    assert!(
        matches!(v.checkpoint, AuditCheckpointState::Verified { seq, lag } if seq + lag == 161 && lag <= 1),
        "{v:?}"
    );
    assert_eq!(db.audit_checkpoint_anomalies().unwrap(), 0);
}

#[test]
fn verification_of_a_keyed_chain_spans_batches() {
    let db = Db::open_in_memory().unwrap();
    fill(&db, 5);
    db.enable_keyed_audit(key(KEY), None).unwrap();
    fill(&db, VERIFY_BATCH as usize + 7);
    let v = db.verify_audit().unwrap();
    assert!(v.is_intact());
    assert_eq!(v.rows, VERIFY_BATCH as u64 + 13);
    assert_eq!(v.keyed_rows, VERIFY_BATCH as u64 + 8);
    assert_eq!(v.first_keyed_row, Some(6));
}
