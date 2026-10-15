//! IOC sightings for cross-alert correlation.
//!
//! One row per `(ioc_type, value, source_ref)`: recording the same sighting
//! again (an alert investigated twice) only moves `seen_at` forward, so
//! sighting counts are not inflated by retries.

use rusqlite::{Row, params};
use talon_core::{Error, Result};

use crate::{Db, IocSighting, SqlResultExt, col, sql_limit};

/// Longest accepted `ioc_type`.
pub const MAX_IOC_TYPE_LEN: usize = 64;
/// Longest accepted IOC `value` / `source_ref` (bytes).
pub const MAX_IOC_VALUE_LEN: usize = 8192;

fn sighting_from_row(row: &Row<'_>) -> rusqlite::Result<IocSighting> {
    Ok(IocSighting {
        ioc_type: col::text(row, "ioc_type")?,
        value: col::text(row, "value")?,
        source_ref: col::text(row, "source_ref")?,
        customer_code: col::opt_text(row, "customer_code")?,
        seen_at: col::text(row, "seen_at")?,
    })
}

fn validate(s: &IocSighting) -> Result<()> {
    if s.ioc_type.is_empty() || s.ioc_type.len() > MAX_IOC_TYPE_LEN {
        return Err(Error::invalid(format!(
            "ioc_type must be 1..={MAX_IOC_TYPE_LEN} bytes"
        )));
    }
    if s.value.is_empty() || s.value.len() > MAX_IOC_VALUE_LEN {
        return Err(Error::invalid(format!(
            "IOC value must be 1..={MAX_IOC_VALUE_LEN} bytes"
        )));
    }
    if s.source_ref.is_empty() || s.source_ref.len() > MAX_IOC_VALUE_LEN {
        return Err(Error::invalid(format!(
            "IOC source_ref must be 1..={MAX_IOC_VALUE_LEN} bytes"
        )));
    }
    Ok(())
}

impl Db {
    // ---- IOC sightings (correlation) -------------------------------------

    /// Record sightings atomically (all or nothing). Every sighting is
    /// validated first ([`Error::InvalidInput`] on empty / oversized fields).
    /// Re-recording an existing `(ioc_type, value, source_ref)` keeps one row
    /// with the later `seen_at` and the newest non-NULL customer code.
    pub fn record_ioc_sightings(&self, sightings: &[IocSighting]) -> Result<()> {
        if sightings.is_empty() {
            return Ok(());
        }
        sightings.iter().try_for_each(validate)?;
        self.with_tx(true, |tx| {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO ioc_sightings (ioc_type, value, source_ref, customer_code, seen_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(ioc_type, value, source_ref) DO UPDATE SET
                       seen_at = MAX(seen_at, excluded.seen_at),
                       customer_code = COALESCE(excluded.customer_code, customer_code)",
                )
                .db()?;
            for s in sightings {
                stmt.execute(params![
                    s.ioc_type,
                    s.value,
                    s.source_ref,
                    s.customer_code,
                    s.seen_at
                ])
                .db()?;
            }
            Ok(())
        })
    }

    /// Other sightings of the same normalized value, most recent first.
    pub fn find_ioc_sightings(
        &self,
        ioc_type: &str,
        value: &str,
        limit: usize,
    ) -> Result<Vec<IocSighting>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT ioc_type, value, source_ref, customer_code, seen_at
                     FROM ioc_sightings WHERE ioc_type = ?1 AND value = ?2
                     ORDER BY seen_at DESC, id DESC LIMIT ?3",
                )
                .db()?;
            let rows = stmt
                .query_map(
                    params![ioc_type, value, sql_limit(limit)],
                    sighting_from_row,
                )
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })
    }

    /// Number of distinct sources that saw this IOC, optionally excluding
    /// one source (the alert being triaged) — the "prior sightings" input
    /// of the triage score.
    pub fn count_ioc_sightings(
        &self,
        ioc_type: &str,
        value: &str,
        exclude_source_ref: Option<&str>,
    ) -> Result<u64> {
        self.with_conn(|conn| {
            let n: i64 = conn
                .prepare_cached(
                    "SELECT COUNT(*) FROM ioc_sightings
                     WHERE ioc_type = ?1 AND value = ?2 AND (?3 IS NULL OR source_ref != ?3)",
                )
                .db()?
                .query_row(params![ioc_type, value, exclude_source_ref], |r| r.get(0))
                .db()?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    /// Retention: delete sightings last seen before `before_iso`. Returns
    /// rows removed.
    pub fn prune_ioc_sightings_before(&self, before_iso: &str) -> Result<usize> {
        self.with_conn(|conn| {
            conn.prepare_cached("DELETE FROM ioc_sightings WHERE seen_at < ?1")
                .db()?
                .execute([before_iso])
                .db()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t: &str, v: &str, src: &str, seen: &str) -> IocSighting {
        IocSighting {
            ioc_type: t.into(),
            value: v.into(),
            source_ref: src.into(),
            customer_code: Some("acme".into()),
            seen_at: seen.into(),
        }
    }

    #[test]
    fn record_and_find_most_recent_first() {
        let db = Db::open_in_memory().unwrap();
        db.record_ioc_sightings(&[
            s("ipv4", "203.0.113.7", "alert-1", "2026-01-01T00:00:00.000Z"),
            s("ipv4", "203.0.113.7", "alert-2", "2026-01-03T00:00:00.000Z"),
            s("ipv4", "203.0.113.7", "alert-3", "2026-01-02T00:00:00.000Z"),
            s(
                "domain",
                "203.0.113.7",
                "alert-4",
                "2026-01-09T00:00:00.000Z",
            ),
            s(
                "ipv4",
                "198.51.100.1",
                "alert-1",
                "2026-01-01T00:00:00.000Z",
            ),
        ])
        .unwrap();
        let found = db.find_ioc_sightings("ipv4", "203.0.113.7", 10).unwrap();
        let srcs: Vec<_> = found.iter().map(|s| s.source_ref.as_str()).collect();
        assert_eq!(srcs, vec!["alert-2", "alert-3", "alert-1"]);
        assert_eq!(
            db.find_ioc_sightings("ipv4", "203.0.113.7", 1)
                .unwrap()
                .len(),
            1
        );
        assert!(
            db.find_ioc_sightings("ipv4", "192.0.2.1", 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.count_ioc_sightings("ipv4", "203.0.113.7", None).unwrap(),
            3
        );
        assert_eq!(
            db.count_ioc_sightings("ipv4", "203.0.113.7", Some("alert-1"))
                .unwrap(),
            2
        );
    }

    #[test]
    fn re_recording_is_idempotent_and_keeps_latest_time() {
        let db = Db::open_in_memory().unwrap();
        db.record_ioc_sightings(&[s("md5", "abc", "a1", "2026-01-02T00:00:00.000Z")])
            .unwrap();
        let mut again = s("md5", "abc", "a1", "2026-01-01T00:00:00.000Z");
        again.customer_code = None;
        db.record_ioc_sightings(&[again]).unwrap();
        db.record_ioc_sightings(&[s("md5", "abc", "a1", "2026-01-05T00:00:00.000Z")])
            .unwrap();
        let found = db.find_ioc_sightings("md5", "abc", 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].seen_at, "2026-01-05T00:00:00.000Z");
        assert_eq!(found[0].customer_code.as_deref(), Some("acme"));
    }

    #[test]
    fn invalid_batch_is_rejected_atomically() {
        let db = Db::open_in_memory().unwrap();
        let err =
            db.record_ioc_sightings(&[s("ipv4", "1.2.3.4", "a", "t"), s("ipv4", "", "a", "t")]);
        assert!(matches!(err, Err(Error::InvalidInput(_))));
        assert_eq!(db.count_ioc_sightings("ipv4", "1.2.3.4", None).unwrap(), 0);
        let long = "x".repeat(MAX_IOC_VALUE_LEN + 1);
        assert!(
            db.record_ioc_sightings(&[s("url", &long, "a", "t")])
                .is_err()
        );
        assert!(
            db.record_ioc_sightings(&[s(&"t".repeat(65), "v", "a", "t")])
                .is_err()
        );
        assert!(db.record_ioc_sightings(&[s("url", "v", "", "t")]).is_err());
        db.record_ioc_sightings(&[]).unwrap();
    }

    #[test]
    fn prune_removes_old_sightings() {
        let db = Db::open_in_memory().unwrap();
        db.record_ioc_sightings(&[
            s("ipv4", "1.1.1.1", "a", "2025-01-01T00:00:00.000Z"),
            s("ipv4", "1.1.1.1", "b", "2026-01-01T00:00:00.000Z"),
        ])
        .unwrap();
        assert_eq!(
            db.prune_ioc_sightings_before("2025-06-01T00:00:00.000Z")
                .unwrap(),
            1
        );
        assert_eq!(db.count_ioc_sightings("ipv4", "1.1.1.1", None).unwrap(), 1);
    }
}
