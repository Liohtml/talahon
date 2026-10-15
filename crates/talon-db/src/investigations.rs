//! Investigation jobs (`POST /investigate`, alert sweep).

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Row, params};
use talon_core::{Error, Result};

use crate::{Db, Investigation, SqlResultExt, col, sql_limit};

/// Valid values of [`Investigation::status`].
pub const INVESTIGATION_STATUSES: &[&str] = &["queued", "running", "completed", "failed"];

/// Longest accepted investigation id.
const MAX_ID_LEN: usize = 256;

const INV_COLUMNS: &str = "id, alert_id, customer_code, triggered_by, status, template, \
     created_at, updated_at, verdict, error";

fn investigation_from_row(row: &Row<'_>) -> rusqlite::Result<Investigation> {
    let id = col::text(row, "id")?;
    let verdict = col::opt_text(row, "verdict")?.and_then(|raw| {
        serde_json::from_str(&raw)
            .map_err(
                |e| tracing::warn!(investigation = %id, error = %e, "unparseable verdict JSON"),
            )
            .ok()
    });
    Ok(Investigation {
        alert_id: col::text(row, "alert_id")?,
        customer_code: col::text(row, "customer_code")?,
        triggered_by: col::text(row, "triggered_by")?,
        status: col::text(row, "status")?,
        template: col::opt_text(row, "template")?,
        created_at: col::text(row, "created_at")?,
        updated_at: col::text(row, "updated_at")?,
        verdict,
        error: col::opt_text(row, "error")?,
        id,
    })
}

fn validate(inv: &Investigation) -> Result<()> {
    if inv.id.is_empty() || inv.id.len() > MAX_ID_LEN || inv.id.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "investigation id must be 1..={MAX_ID_LEN} printable characters"
        )));
    }
    if !INVESTIGATION_STATUSES.contains(&inv.status.as_str()) {
        return Err(Error::invalid(format!(
            "unknown investigation status {:?} (expected one of {INVESTIGATION_STATUSES:?})",
            inv.status
        )));
    }
    Ok(())
}

impl Db {
    // ---- investigations --------------------------------------------------

    /// Insert or update by id. `created_at` of an existing row is kept; all
    /// other fields are replaced. The status must be one of
    /// [`INVESTIGATION_STATUSES`].
    pub fn upsert_investigation(&self, inv: &Investigation) -> Result<()> {
        validate(inv)?;
        let verdict = inv
            .verdict
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        self.with_conn(|conn| {
            conn.prepare_cached(
                "INSERT INTO investigations (id, alert_id, customer_code, triggered_by, status,
                   template, created_at, updated_at, verdict, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id) DO UPDATE SET
                   alert_id = excluded.alert_id,
                   customer_code = excluded.customer_code,
                   triggered_by = excluded.triggered_by,
                   status = excluded.status,
                   template = excluded.template,
                   updated_at = excluded.updated_at,
                   verdict = excluded.verdict,
                   error = excluded.error",
            )
            .db()?
            .execute(params![
                inv.id,
                inv.alert_id,
                inv.customer_code,
                inv.triggered_by,
                inv.status,
                inv.template,
                inv.created_at,
                inv.updated_at,
                verdict,
                inv.error,
            ])
            .db()?;
            Ok(())
        })
    }

    /// One investigation by id.
    pub fn get_investigation(&self, id: &str) -> Result<Option<Investigation>> {
        self.with_conn(|conn| {
            let sql = format!("SELECT {INV_COLUMNS} FROM investigations WHERE id = ?1");
            conn.prepare_cached(&sql)
                .db()?
                .query_row([id], investigation_from_row)
                .optional()
                .db()
        })
    }

    /// Most recent first.
    pub fn list_investigations(&self, limit: usize) -> Result<Vec<Investigation>> {
        self.with_conn(|conn| {
            let sql = format!(
                "SELECT {INV_COLUMNS} FROM investigations
                 ORDER BY created_at DESC, rowid DESC LIMIT ?1"
            );
            let mut stmt = conn.prepare_cached(&sql).db()?;
            let rows = stmt
                .query_map([sql_limit(limit)], investigation_from_row)
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })
    }

    /// Latest investigation for an alert, if any (dedup of repeat triggers).
    pub fn latest_investigation_for_alert(&self, alert_id: &str) -> Result<Option<Investigation>> {
        self.with_conn(|conn| {
            let sql = format!(
                "SELECT {INV_COLUMNS} FROM investigations WHERE alert_id = ?1
                 ORDER BY created_at DESC, rowid DESC LIMIT 1"
            );
            conn.prepare_cached(&sql)
                .db()?
                .query_row([alert_id], investigation_from_row)
                .optional()
                .db()
        })
    }

    /// Number of investigations per status (for `/metrics`).
    pub fn investigation_status_counts(&self) -> Result<BTreeMap<String, u64>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT status, COUNT(*) AS n FROM investigations GROUP BY status")
                .db()?;
            let rows = stmt
                .query_map([], |r| {
                    let n = col::opt_i64(r, "n")?.unwrap_or(0);
                    Ok((col::text(r, "status")?, u64::try_from(n).unwrap_or(0)))
                })
                .db()?
                .collect::<rusqlite::Result<BTreeMap<_, _>>>()
                .db()?;
            Ok(rows)
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn inv(id: &str, alert: &str, created: &str) -> Investigation {
        Investigation {
            id: id.into(),
            alert_id: alert.into(),
            customer_code: "acme".into(),
            triggered_by: "webhook".into(),
            status: "queued".into(),
            template: None,
            created_at: created.into(),
            updated_at: created.into(),
            verdict: None,
            error: None,
        }
    }

    #[test]
    fn upsert_get_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let mut i = inv("copilot-inv-1-1", "1", "2026-01-01T00:00:00.000Z");
        db.upsert_investigation(&i).unwrap();
        assert_eq!(db.get_investigation(&i.id).unwrap().unwrap(), i);

        i.status = "completed".into();
        i.updated_at = "2026-01-01T00:05:00.000Z".into();
        i.template = Some("default".into());
        i.verdict = Some(json!({ "verdict": "false_positive", "confidence": 0.9 }));
        // created_at in the update is ignored: the original is kept.
        let mut update = i.clone();
        update.created_at = "2030-01-01T00:00:00.000Z".into();
        db.upsert_investigation(&update).unwrap();
        assert_eq!(db.get_investigation(&i.id).unwrap().unwrap(), i);
        assert_eq!(db.get_investigation("nope").unwrap(), None);
    }

    #[test]
    fn list_most_recent_first_with_limit() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_investigation(&inv("a", "1", "2026-01-01T00:00:00.000Z"))
            .unwrap();
        db.upsert_investigation(&inv("b", "2", "2026-01-03T00:00:00.000Z"))
            .unwrap();
        db.upsert_investigation(&inv("c", "3", "2026-01-02T00:00:00.000Z"))
            .unwrap();
        let ids: Vec<_> = db
            .list_investigations(10)
            .unwrap()
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(ids, vec!["b", "c", "a"]);
        assert_eq!(db.list_investigations(1).unwrap().len(), 1);
    }

    #[test]
    fn latest_for_alert_picks_newest() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.latest_investigation_for_alert("42").unwrap(), None);
        db.upsert_investigation(&inv("old", "42", "2026-01-01T00:00:00.000Z"))
            .unwrap();
        db.upsert_investigation(&inv("new", "42", "2026-01-02T00:00:00.000Z"))
            .unwrap();
        db.upsert_investigation(&inv("other", "43", "2026-01-05T00:00:00.000Z"))
            .unwrap();
        assert_eq!(
            db.latest_investigation_for_alert("42").unwrap().unwrap().id,
            "new"
        );
    }

    #[test]
    fn validation_rejects_bad_status_and_ids() {
        let db = Db::open_in_memory().unwrap();
        let mut i = inv("x", "1", "t");
        i.status = "exploded".into();
        assert!(matches!(
            db.upsert_investigation(&i),
            Err(Error::InvalidInput(_))
        ));
        for bad in [
            String::new(),
            "a".repeat(MAX_ID_LEN + 1),
            "a\nb".to_string(),
        ] {
            assert!(matches!(
                db.upsert_investigation(&inv(&bad, "1", "t")),
                Err(Error::InvalidInput(_))
            ));
        }
        for status in INVESTIGATION_STATUSES {
            let mut ok = inv(&format!("id-{status}"), "1", "t");
            ok.status = (*status).to_string();
            db.upsert_investigation(&ok).unwrap();
        }
    }

    #[test]
    fn status_counts() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_investigation(&inv("a", "1", "t")).unwrap();
        db.upsert_investigation(&inv("b", "2", "t")).unwrap();
        let mut c = inv("c", "3", "t");
        c.status = "failed".into();
        c.error = Some("timeout".into());
        db.upsert_investigation(&c).unwrap();
        let counts = db.investigation_status_counts().unwrap();
        assert_eq!(counts.get("queued"), Some(&2));
        assert_eq!(counts.get("failed"), Some(&1));
        assert_eq!(counts.get("running"), None);
    }

    #[test]
    fn corrupt_verdict_reads_as_none() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_investigation(&inv("a", "1", "t")).unwrap();
        db.with_conn(|c| {
            c.execute(
                "UPDATE investigations SET verdict = '{bad' WHERE id = 'a'",
                [],
            )
            .db()
        })
        .unwrap();
        assert_eq!(db.get_investigation("a").unwrap().unwrap().verdict, None);
    }
}
