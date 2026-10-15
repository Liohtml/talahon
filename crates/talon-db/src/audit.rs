//! Append-only, hash-chained audit log.
//!
//! Every row stores `prev_hash` (the previous row's `hash`, or
//! [`AUDIT_GENESIS_HASH`] for the first row) and
//! `hash = sha256_hex(prev_hash || canonical_json(event))`, where the event is
//! the [`AuditEvent`] JSON (`target` omitted when `None`) with object keys
//! sorted recursively ([`canonical_json`]). Editing, reordering or deleting a
//! row breaks the chain at that row, which [`Db::verify_audit_chain`]
//! reports. `UPDATE` / `DELETE` on the table are additionally refused by
//! triggers. Truncating the *tail* of the log cannot be detected from the
//! log alone; anchor [`Db::audit_chain_head`] externally if that matters.

use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use talon_core::audit::{AuditSink, TracingAuditSink};
use talon_core::types::AuditEvent;
use talon_core::{Error, Result};

use crate::{Db, SqlResultExt, col, sql_limit};

/// `prev_hash` of the first row: 64 zeros.
pub const AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Upper bound for the serialized `details` of one event. Larger payloads are
/// replaced by a marker object (`{"truncated": true, ...}`) so a single noisy
/// caller cannot bloat the log.
pub const MAX_AUDIT_DETAILS_BYTES: usize = 64 * 1024;

/// Rows checked per lock acquisition in [`Db::verify_audit_chain`], so a
/// long verification does not starve writers.
const VERIFY_BATCH: i64 = 1000;

/// Serialize `value` as canonical JSON: no whitespace, object keys sorted
/// (byte-wise) at every level, strings and numbers as `serde_json` writes
/// them. Independent of `serde_json`'s `preserve_order` feature.
pub fn canonical_json(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k)?);
                out.push(':');
                write_canonical(v, out)?;
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out)?;
            }
            out.push(']');
        }
        scalar => out.push_str(&serde_json::to_string(scalar)?),
    }
    Ok(())
}

/// `sha256_hex(prev_hash || canonical_json(event))`.
pub fn audit_event_hash(prev_hash: &str, event: &AuditEvent) -> Result<String> {
    let canonical = canonical_json(&serde_json::to_value(event)?)?;
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Canonical `details` text as stored, capped at [`MAX_AUDIT_DETAILS_BYTES`].
fn stored_details(details: &Value) -> Result<String> {
    let text = canonical_json(details)?;
    if text.len() <= MAX_AUDIT_DETAILS_BYTES {
        return Ok(text);
    }
    let mut preview_end = 1024.min(text.len());
    while !text.is_char_boundary(preview_end) {
        preview_end -= 1;
    }
    canonical_json(&serde_json::json!({
        "truncated": true,
        "original_bytes": text.len(),
        "preview": &text[..preview_end],
    }))
}

/// One stored row.
struct AuditRow {
    id: i64,
    event: std::result::Result<AuditEvent, String>,
    prev_hash: String,
    hash: String,
}

fn audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    let details_raw = col::text(row, "details")?;
    let event = match serde_json::from_str::<Value>(&details_raw) {
        Ok(details) => Ok(AuditEvent {
            timestamp: col::text(row, "timestamp")?,
            kind: col::text(row, "kind")?,
            actor: col::text(row, "actor")?,
            target: col::opt_text(row, "target")?,
            outcome: col::text(row, "outcome")?,
            details,
        }),
        Err(e) => Err(format!("details is not JSON: {e}")),
    };
    Ok(AuditRow {
        id: row.get("id")?,
        event,
        prev_hash: col::text(row, "prev_hash")?,
        hash: col::text(row, "hash")?,
    })
}

impl Db {
    // ---- audit log (append-only, hash-chained) ---------------------------

    /// Append an event to the chain. The read of the previous hash and the
    /// insert run in one `BEGIN IMMEDIATE` transaction, so concurrent writers
    /// (threads or processes) cannot fork the chain.
    pub fn record_audit(&self, event: &AuditEvent) -> Result<()> {
        let details_text = stored_details(&event.details)?;
        // Hash exactly what is stored (and what verification re-reads).
        let stored = AuditEvent {
            details: serde_json::from_str(&details_text)?,
            ..event.clone()
        };
        self.with_tx(true, |tx| {
            let prev: String = tx
                .prepare_cached("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
                .db()?
                .query_row([], |r| col::text(r, "hash"))
                .optional()
                .db()?
                .unwrap_or_else(|| AUDIT_GENESIS_HASH.to_string());
            let hash = audit_event_hash(&prev, &stored)?;
            tx.prepare_cached(
                "INSERT INTO audit_log (timestamp, kind, actor, target, outcome, details,
                   prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .db()?
            .execute(params![
                stored.timestamp,
                stored.kind,
                stored.actor,
                stored.target,
                stored.outcome,
                details_text,
                prev,
                hash,
            ])
            .db()?;
            Ok(())
        })
    }

    /// Most recent first; optional `kind` prefix filter (e.g. `"ipc."`).
    /// The prefix is matched literally (case-sensitive, no wildcards).
    pub fn recent_audit(&self, limit: usize, kind_prefix: Option<&str>) -> Result<Vec<AuditEvent>> {
        let rows = self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT id, timestamp, kind, actor, target, outcome, details, prev_hash, hash
                     FROM audit_log
                     WHERE ?1 IS NULL OR substr(kind, 1, length(?1)) = ?1
                     ORDER BY id DESC LIMIT ?2",
                )
                .db()?;
            let rows = stmt
                .query_map(params![kind_prefix, sql_limit(limit)], audit_row)
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(|r| {
                r.event
                    .map_err(|e| Error::Db(format!("corrupt audit row {}: {e}", r.id)))
            })
            .collect()
    }

    /// Recompute the hash chain. `Ok(None)` if intact, `Ok(Some(row_id))` of
    /// the first tampered row otherwise (content changed, `prev_hash` not
    /// matching the previous row's hash — e.g. a row before it was deleted —
    /// or stored hash wrong).
    pub fn verify_audit_chain(&self) -> Result<Option<i64>> {
        let mut expected_prev = AUDIT_GENESIS_HASH.to_string();
        let mut last_id = i64::MIN;
        loop {
            let batch = self.with_conn(|conn| {
                let mut stmt = conn
                    .prepare_cached(
                        "SELECT id, timestamp, kind, actor, target, outcome, details, prev_hash,
                           hash
                         FROM audit_log WHERE id > ?1 ORDER BY id LIMIT ?2",
                    )
                    .db()?;
                let rows = stmt
                    .query_map(params![last_id, VERIFY_BATCH], audit_row)
                    .db()?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .db()?;
                Ok(rows)
            })?;
            if batch.is_empty() {
                return Ok(None);
            }
            for row in batch {
                let Ok(event) = &row.event else {
                    return Ok(Some(row.id));
                };
                if row.prev_hash != expected_prev
                    || audit_event_hash(&row.prev_hash, event)? != row.hash
                {
                    return Ok(Some(row.id));
                }
                expected_prev = row.hash;
                last_id = row.id;
            }
        }
    }

    /// `(id, hash)` of the newest row, for anchoring the chain head outside
    /// the database (detects truncation of the tail).
    pub fn audit_chain_head(&self) -> Result<Option<(i64, String)>> {
        self.with_conn(|conn| {
            conn.prepare_cached("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1")
                .db()?
                .query_row([], |r| Ok((r.get::<_, i64>("id")?, col::text(r, "hash")?)))
                .optional()
                .db()
        })
    }

    /// Number of rows in the audit log.
    pub fn audit_count(&self) -> Result<u64> {
        self.with_conn(|conn| {
            let n: i64 = conn
                .prepare_cached("SELECT COUNT(*) FROM audit_log")
                .db()?
                .query_row([], |r| r.get(0))
                .db()?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }
}

/// [`AuditSink`] that appends to the hash-chained `audit_log` table and,
/// optionally, mirrors every event to `tracing` (target `talon::audit`).
/// Persistence failures are logged, never propagated: auditing must not take
/// down the operation being audited.
#[derive(Debug, Clone)]
pub struct DbAuditSink {
    db: Db,
    mirror_to_tracing: bool,
}

impl DbAuditSink {
    /// Persist to `db` and mirror to `tracing`.
    pub fn new(db: Db) -> Self {
        Self {
            db,
            mirror_to_tracing: true,
        }
    }

    /// Persist to `db` only.
    pub fn without_tracing(db: Db) -> Self {
        Self {
            db,
            mirror_to_tracing: false,
        }
    }
}

impl AuditSink for DbAuditSink {
    fn record(&self, event: AuditEvent) {
        if let Err(e) = self.db.record_audit(&event) {
            tracing::error!(target: "talon::audit", kind = %event.kind, error = %e, "failed to persist audit event");
        }
        if self.mirror_to_tracing {
            TracingAuditSink.record(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use serde_json::json;
    use talon_core::audit::{SharedAuditSink, event};

    use super::*;
    use crate::DB_FILE_NAME;

    fn ev(kind: &str, details: Value) -> AuditEvent {
        AuditEvent {
            timestamp: "2026-01-01T00:00:00.000Z".into(),
            kind: kind.into(),
            actor: "main".into(),
            target: Some("task-1".into()),
            outcome: "allowed".into(),
            details,
        }
    }

    /// Raw connection that can tamper with the log (triggers dropped).
    fn tamper(path: &Path, sql: &str) {
        let c = rusqlite::Connection::open(path).unwrap();
        c.execute_batch(
            "DROP TRIGGER IF EXISTS audit_log_no_update; DROP TRIGGER IF EXISTS audit_log_no_delete;",
        )
        .unwrap();
        c.execute_batch(sql).unwrap();
    }

    fn file_db() -> (tempfile::TempDir, std::path::PathBuf, Db) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE_NAME);
        let db = Db::open(&path).unwrap();
        (dir, path, db)
    }

    fn fill(db: &Db, n: usize) {
        for i in 0..n {
            db.record_audit(&ev(
                if i % 2 == 0 {
                    "ipc.task.allowed"
                } else {
                    "container.launch"
                },
                json!({ "i": i, "nested": { "b": 1, "a": [1, 2, { "z": 0, "y": null }] } }),
            ))
            .unwrap();
        }
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let a = json!({ "b": 1, "a": { "d": [ { "y": 2, "x": 1 } ], "c": "é\"" } });
        assert_eq!(
            canonical_json(&a).unwrap(),
            r#"{"a":{"c":"é\"","d":[{"x":1,"y":2}]},"b":1}"#
        );
        let b: Value =
            serde_json::from_str(r#"{ "a": { "c": "é\"", "d": [ {"x":1, "y":2} ] }, "b": 1 }"#)
                .unwrap();
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        assert_eq!(canonical_json(&json!(null)).unwrap(), "null");
        assert_eq!(canonical_json(&json!(1.5)).unwrap(), "1.5");
    }

    #[test]
    fn hash_is_sha256_of_prev_hash_and_canonical_event() {
        let e = ev("k", json!({ "z": 1, "a": 2 }));
        let canonical = r#"{"actor":"main","details":{"a":2,"z":1},"kind":"k","outcome":"allowed","target":"task-1","timestamp":"2026-01-01T00:00:00.000Z"}"#;
        let mut h = Sha256::new();
        h.update(AUDIT_GENESIS_HASH.as_bytes());
        h.update(canonical.as_bytes());
        assert_eq!(
            audit_event_hash(AUDIT_GENESIS_HASH, &e).unwrap(),
            hex::encode(h.finalize())
        );
        // `target: None` is omitted, not null.
        let e2 = AuditEvent { target: None, ..e };
        let c2 = canonical_json(&serde_json::to_value(&e2).unwrap()).unwrap();
        assert!(!c2.contains("target"));
    }

    #[test]
    fn chain_links_rows_from_genesis() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.verify_audit_chain().unwrap(), None);
        assert_eq!(db.audit_chain_head().unwrap(), None);
        fill(&db, 3);
        let rows: Vec<(String, String)> = db
            .with_conn(|c| {
                let mut s = c
                    .prepare("SELECT prev_hash, hash FROM audit_log ORDER BY id")
                    .db()?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .db()?
                    .collect::<rusqlite::Result<_>>()
                    .db()
            })
            .unwrap();
        assert_eq!(rows[0].0, AUDIT_GENESIS_HASH);
        assert_eq!(rows[1].0, rows[0].1);
        assert_eq!(rows[2].0, rows[1].1);
        assert!(rows.iter().all(|(_, h)| h.len() == 64));
        assert_eq!(db.verify_audit_chain().unwrap(), None);
        let (id, hash) = db.audit_chain_head().unwrap().unwrap();
        assert_eq!(id, 3);
        assert_eq!(hash, rows[2].1);
        assert_eq!(db.audit_count().unwrap(), 3);
    }

    #[test]
    fn recent_audit_orders_and_filters_by_prefix() {
        let db = Db::open_in_memory().unwrap();
        fill(&db, 5);
        db.record_audit(&ev("ipcx.other", json!(null))).unwrap();
        let all = db.recent_audit(100, None).unwrap();
        assert_eq!(all.len(), 6);
        assert_eq!(all[0].kind, "ipcx.other");
        let ipc = db.recent_audit(100, Some("ipc.")).unwrap();
        assert_eq!(ipc.len(), 3);
        assert!(ipc.iter().all(|e| e.kind == "ipc.task.allowed"));
        assert_eq!(ipc[0].details["i"], 4);
        assert_eq!(db.recent_audit(2, None).unwrap().len(), 2);
        // Wildcards in the prefix are literal.
        assert!(db.recent_audit(100, Some("%")).unwrap().is_empty());
        assert!(db.recent_audit(100, Some("ipc_")).unwrap().is_empty());
        // Round trip of the event itself.
        let e = ev("x.y", json!({ "b": [1, 2], "a": "s" }));
        db.record_audit(&e).unwrap();
        assert_eq!(db.recent_audit(1, None).unwrap()[0], e);
    }

    #[test]
    fn append_only_triggers_refuse_update_and_delete() {
        let db = Db::open_in_memory().unwrap();
        fill(&db, 1);
        let upd = db.with_conn(|c| c.execute("UPDATE audit_log SET actor = 'x'", []).db());
        assert!(matches!(upd, Err(Error::Db(m)) if m.contains("append-only")));
        let del = db.with_conn(|c| c.execute("DELETE FROM audit_log", []).db());
        assert!(del.is_err());
        assert_eq!(db.audit_count().unwrap(), 1);
    }

    #[test]
    fn detects_modified_content() {
        let (_d, path, db) = file_db();
        fill(&db, 5);
        tamper(
            &path,
            "UPDATE audit_log SET outcome = 'denied' WHERE id = 3",
        );
        assert_eq!(db.verify_audit_chain().unwrap(), Some(3));
    }

    #[test]
    fn detects_modified_details_and_invalid_json() {
        let (_d, path, db) = file_db();
        fill(&db, 4);
        tamper(
            &path,
            r#"UPDATE audit_log SET details = '{"i":99}' WHERE id = 2"#,
        );
        assert_eq!(db.verify_audit_chain().unwrap(), Some(2));
        let (_d2, path2, db2) = file_db();
        fill(&db2, 4);
        tamper(
            &path2,
            "UPDATE audit_log SET details = '{oops' WHERE id = 4",
        );
        assert_eq!(db2.verify_audit_chain().unwrap(), Some(4));
        assert!(db2.recent_audit(10, None).is_err());
    }

    #[test]
    fn detects_deleted_row() {
        let (_d, path, db) = file_db();
        fill(&db, 5);
        tamper(&path, "DELETE FROM audit_log WHERE id = 2");
        assert_eq!(db.verify_audit_chain().unwrap(), Some(3));
    }

    #[test]
    fn detects_rehashed_row_without_relinking() {
        // An attacker who recomputes the hash of an edited row still breaks
        // the link to the next row.
        let (_d, path, db) = file_db();
        fill(&db, 3);
        let row2 = db.recent_audit(3, None).unwrap()[1].clone();
        let edited = AuditEvent {
            outcome: "denied".into(),
            ..row2
        };
        let prev: String = db
            .with_conn(|c| {
                c.query_row("SELECT prev_hash FROM audit_log WHERE id = 2", [], |r| {
                    r.get(0)
                })
                .db()
            })
            .unwrap();
        let new_hash = audit_event_hash(&prev, &edited).unwrap();
        tamper(
            &path,
            &format!("UPDATE audit_log SET outcome = 'denied', hash = '{new_hash}' WHERE id = 2"),
        );
        assert_eq!(db.verify_audit_chain().unwrap(), Some(3));
    }

    #[test]
    fn detects_forged_genesis() {
        let (_d, path, db) = file_db();
        fill(&db, 2);
        tamper(
            &path,
            &format!(
                "UPDATE audit_log SET prev_hash = '{}' WHERE id = 1",
                "1".repeat(64)
            ),
        );
        assert_eq!(db.verify_audit_chain().unwrap(), Some(1));
    }

    #[test]
    fn verification_spans_batches() {
        let db = Db::open_in_memory().unwrap();
        for i in 0..(VERIFY_BATCH as usize * 2 + 5) {
            db.record_audit(&event("bulk", "a", None, "info", json!(i)))
                .unwrap();
        }
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn oversized_details_are_truncated_but_chained() {
        let db = Db::open_in_memory().unwrap();
        let big = "x".repeat(MAX_AUDIT_DETAILS_BYTES + 10);
        db.record_audit(&ev("big", json!({ "blob": big }))).unwrap();
        let got = &db.recent_audit(1, None).unwrap()[0];
        assert_eq!(got.details["truncated"], true);
        assert!(got.details["original_bytes"].as_u64().unwrap() > MAX_AUDIT_DETAILS_BYTES as u64);
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn floats_and_unicode_survive_the_round_trip() {
        let db = Db::open_in_memory().unwrap();
        db.record_audit(&ev(
            "f",
            json!({ "pi": std::f64::consts::PI, "third": 1.0_f64 / 3.0, "tiny": 1e-300, "neg": -0.0, "s": "ü\u{1F600}\n" }),
        ))
        .unwrap();
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn db_audit_sink_persists_events() {
        let db = Db::open_in_memory().unwrap();
        let sink: SharedAuditSink = Arc::new(DbAuditSink::new(db.clone()));
        sink.record(event(
            "mount.rejected",
            "grp",
            Some("/etc"),
            "denied",
            json!({}),
        ));
        DbAuditSink::without_tracing(db.clone()).record(event(
            "tool.call",
            "grp",
            None,
            "info",
            json!({ "tool": "bash" }),
        ));
        let got = db.recent_audit(10, None).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].kind, "mount.rejected");
        assert_eq!(got[1].target.as_deref(), Some("/etc"));
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }
}
