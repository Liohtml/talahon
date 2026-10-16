//! Next-run computation for scheduled tasks.
//!
//! - `cron`: standard 5-field cron (optionally 6-field with seconds),
//!   evaluated in the configured timezone.
//! - `interval`: milliseconds, anchored to the previous scheduled time (not
//!   "now") so runs don't drift; missed intervals are skipped.
//! - `once`: a local timestamp without zone suffix (`2026-02-01T15:30:00`),
//!   interpreted in the configured timezone; never recurs.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use croner::Cron;

use crate::time::{parse_iso, to_iso};
use crate::types::ScheduleType;
use crate::{Error, Result};

/// Minimum allowed interval (guards against hot loops).
pub const MIN_INTERVAL_MS: u64 = 10_000;

fn parse_cron(expr: &str) -> Result<Cron> {
    Cron::new(expr.trim())
        .with_seconds_optional()
        .parse()
        .map_err(|e| Error::invalid(format!("invalid cron {expr:?}: {e}")))
}

/// Parse a `once` value: local naive timestamp (no `Z`/offset) in `tz`.
pub fn parse_once(value: &str, tz: Tz) -> Result<DateTime<Utc>> {
    let v = value.trim();
    if v.ends_with('Z') || v.ends_with('z') || has_offset_suffix(v) {
        return Err(Error::invalid(format!(
            "timestamp must be local time without timezone suffix, got {v:?} (use e.g. 2026-02-01T15:30:00)"
        )));
    }
    let naive = NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M"))
        .or_else(|_| NaiveDateTime::parse_from_str(v, "%Y-%m-%d %H:%M:%S"))
        .or_else(|_| NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S%.f"))
        .map_err(|_| Error::invalid(format!("invalid timestamp {v:?}")))?;
    tz.from_local_datetime(&naive)
        .earliest()
        .map(|d| d.with_timezone(&Utc))
        .ok_or_else(|| Error::invalid(format!("timestamp {v:?} does not exist in {tz}")))
}

fn has_offset_suffix(v: &str) -> bool {
    // ...+02:00 / ...-05:30
    let b = v.as_bytes();
    b.len() >= 6 && matches!(b[b.len() - 6], b'+' | b'-') && b[b.len() - 3] == b':'
}

fn parse_interval(value: &str) -> Result<u64> {
    let ms: u64 = value.trim().parse().map_err(|_| {
        Error::invalid(format!("invalid interval {value:?}: expected milliseconds"))
    })?;
    if ms < MIN_INTERVAL_MS {
        return Err(Error::invalid(format!(
            "interval {ms}ms is below the minimum of {MIN_INTERVAL_MS}ms"
        )));
    }
    Ok(ms)
}

/// Validate a schedule and return its **first** run time (ISO string).
pub fn first_run(
    schedule_type: ScheduleType,
    value: &str,
    tz: Tz,
    now: DateTime<Utc>,
) -> Result<String> {
    match schedule_type {
        ScheduleType::Cron => next_cron(value, tz, now),
        ScheduleType::Interval => {
            let ms = parse_interval(value)?;
            Ok(to_iso(now + chrono::Duration::milliseconds(ms as i64)))
        }
        ScheduleType::Once => parse_once(value, tz).map(to_iso),
    }
}

/// Validate without computing anything else.
pub fn validate(schedule_type: ScheduleType, value: &str, tz: Tz) -> Result<()> {
    match schedule_type {
        ScheduleType::Cron => parse_cron(value).map(|_| ()),
        ScheduleType::Interval => parse_interval(value).map(|_| ()),
        ScheduleType::Once => parse_once(value, tz).map(|_| ()),
    }
}

fn next_cron(value: &str, tz: Tz, now: DateTime<Utc>) -> Result<String> {
    let cron = parse_cron(value)?;
    let local_now = now.with_timezone(&tz);
    let next = cron
        .find_next_occurrence(&local_now, false)
        .map_err(|e| Error::invalid(format!("cron {value:?} has no next occurrence: {e}")))?;
    let mut next_utc = next.with_timezone(&Utc);
    if next_utc <= now {
        // A local time that occurs twice (DST fall-back) is resolved to its
        // first instant, which has already passed while `now` is in the
        // repeated hour; the scheduler would then run the task on every poll
        // until the hour is over. Take the second instant of that time.
        if let Some(later) = tz.from_local_datetime(&next.naive_local()).latest() {
            next_utc = later.with_timezone(&Utc);
        }
    }
    Ok(to_iso(next_utc))
}

/// Next run *after* a completed run. `None` for `once` (task completes).
///
/// `previous_next_run` is the `next_run` value the task was due at; interval
/// tasks anchor to it to avoid drift.
pub fn compute_next_run(
    schedule_type: ScheduleType,
    value: &str,
    previous_next_run: Option<&str>,
    tz: Tz,
    now: DateTime<Utc>,
) -> Result<Option<String>> {
    match schedule_type {
        ScheduleType::Once => Ok(None),
        ScheduleType::Cron => next_cron(value, tz, now).map(Some),
        ScheduleType::Interval => {
            let ms = match parse_interval(value) {
                Ok(ms) => ms as i64,
                // Malformed legacy rows: retry in a minute instead of spinning.
                Err(_) => return Ok(Some(to_iso(now + chrono::Duration::seconds(60)))),
            };
            let step = chrono::Duration::milliseconds(ms);
            let anchor = previous_next_run.and_then(parse_iso).unwrap_or(now);
            let mut next = anchor + step;
            if next <= now {
                // Skip missed intervals arithmetically (no unbounded loop).
                let behind = (now - next).num_milliseconds();
                let skips = behind / ms + 1;
                next += chrono::Duration::milliseconds(skips * ms);
            }
            Ok(Some(to_iso(next)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        parse_iso(s).unwrap()
    }

    #[test]
    fn cron_next_in_repeated_dst_hour_is_in_the_future() {
        // Europe/Berlin falls back at 03:00 CEST (01:00Z) on 2026-10-25, so
        // 02:00-02:59 local happens twice. 01:05Z is 02:05 in the second pass.
        let tz: Tz = "Europe/Berlin".parse().unwrap();
        let second_pass = t("2026-10-25T01:05:00.000Z");
        let next = |expr| compute_next_run(ScheduleType::Cron, expr, None, tz, second_pass);
        assert_eq!(
            next("*/15 * * * *").unwrap().as_deref(),
            Some("2026-10-25T01:15:00.000Z")
        );
        assert_eq!(
            next("30 2 * * *").unwrap().as_deref(),
            Some("2026-10-25T01:30:00.000Z")
        );
        // The first pass is unchanged: 02:15 CEST.
        let first_pass = t("2026-10-25T00:05:00.000Z");
        assert_eq!(
            compute_next_run(ScheduleType::Cron, "*/15 * * * *", None, tz, first_pass)
                .unwrap()
                .as_deref(),
            Some("2026-10-25T00:15:00.000Z")
        );
        assert_eq!(
            first_run(ScheduleType::Cron, "*/15 * * * *", tz, second_pass).unwrap(),
            "2026-10-25T01:15:00.000Z"
        );
    }

    #[test]
    fn cron_next_in_timezone() {
        // 09:00 Berlin (CEST, UTC+2) on 2026-06-01
        let next = first_run(
            ScheduleType::Cron,
            "0 9 * * *",
            chrono_tz::Europe::Berlin,
            t("2026-06-01T05:00:00.000Z"),
        )
        .unwrap();
        assert_eq!(next, "2026-06-01T07:00:00.000Z");
    }

    #[test]
    fn invalid_cron_rejected() {
        assert!(validate(ScheduleType::Cron, "not a cron", chrono_tz::UTC).is_err());
    }

    #[test]
    fn interval_anchors_and_skips() {
        let now = t("2026-01-01T00:10:30.000Z");
        let next = compute_next_run(
            ScheduleType::Interval,
            "60000",
            Some("2026-01-01T00:00:00.000Z"),
            chrono_tz::UTC,
            now,
        )
        .unwrap()
        .unwrap();
        assert_eq!(next, "2026-01-01T00:11:00.000Z");
    }

    #[test]
    fn interval_minimum_enforced() {
        assert!(validate(ScheduleType::Interval, "5", chrono_tz::UTC).is_err());
        assert!(validate(ScheduleType::Interval, "-1", chrono_tz::UTC).is_err());
    }

    #[test]
    fn once_is_local_and_rejects_suffix() {
        let r = parse_once("2026-02-01T15:30:00", chrono_tz::Europe::Berlin).unwrap();
        assert_eq!(to_iso(r), "2026-02-01T14:30:00.000Z");
        assert!(parse_once("2026-02-01T15:30:00Z", chrono_tz::UTC).is_err());
        assert!(parse_once("2026-02-01T15:30:00+02:00", chrono_tz::UTC).is_err());
        assert!(
            compute_next_run(ScheduleType::Once, "x", None, chrono_tz::UTC, Utc::now())
                .unwrap()
                .is_none()
        );
    }
}
