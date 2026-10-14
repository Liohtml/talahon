//! Per-lane task quotas (N-3): prompt size and schedule frequency.
//!
//! A single non-main lane could create hundreds of every-minute cron tasks
//! with 250 KiB prompts in under a second (each run is a container start,
//! each snapshot loads every task). The checks here bound what one request
//! may ask for; the number of tasks a lane owns and the rate of executed
//! operations are bounded in `process` / `ratelimit`. All limits come from
//! [`crate::IpcWatcherConfig`].

use std::time::Duration;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use talon_core::schedule::compute_next_run;
use talon_core::time::{parse_iso, to_iso};
use talon_core::types::ScheduleType;

/// Number of consecutive `cron` occurrences inspected by
/// [`check_schedule_frequency`].
///
/// A cron expression repeats the same minute (and second) set in every
/// matching hour, so any pair of consecutive in-hour occurrences closer than
/// the minimum shows up within at most 61 samples wherever the search
/// starts; the margin also covers hour and day boundaries of
/// expressions dense enough to matter. Sampling stops early at the first
/// violation or when the schedule has no further occurrence. 128 samples
/// cost ~1-4 ms (debug build).
pub(crate) const CRON_FREQUENCY_SAMPLES: usize = 128;

/// Reject a prompt longer than `max` UTF-8 bytes (`None`: no cap).
pub(crate) fn check_prompt_bytes(prompt: &str, max: Option<usize>) -> Result<(), String> {
    match max {
        Some(max) if prompt.len() > max => Err(format!(
            "prompt is {} bytes; the limit for this lane is {max} bytes",
            prompt.len()
        )),
        _ => Ok(()),
    }
}

fn describe(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 && secs % 60 == 0 && d.subsec_nanos() == 0 {
        format!("{} min", secs / 60)
    } else if d.subsec_millis() == 0 {
        format!("{secs} s")
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// Reject a recurring schedule whose consecutive runs can be closer than
/// `min` (zero: no check). `once` always passes.
///
/// - `interval`: the value (milliseconds) must be at least `min`.
/// - `cron`: up to [`CRON_FREQUENCY_SAMPLES`] consecutive occurrences after
///   `now` are computed with the scheduler's own
///   [`talon_core::schedule::compute_next_run`] (same parser, timezone and
///   DST handling as the real runs); any two consecutive ones closer than
///   `min` reject the expression. This catches both "next two occurrences
///   are too close" and bursts that only start later (`* 9 * * *` asked at
///   09:59).
///
/// The schedule itself is expected to have been validated already
/// ([`talon_core::schedule::first_run`]); a cron expression without further
/// occurrences simply passes.
pub(crate) fn check_schedule_frequency(
    schedule_type: ScheduleType,
    value: &str,
    tz: Tz,
    now: DateTime<Utc>,
    min: Duration,
) -> Result<(), String> {
    if min.is_zero() {
        return Ok(());
    }
    match schedule_type {
        ScheduleType::Once => Ok(()),
        ScheduleType::Interval => {
            let ms: u64 = value
                .trim()
                .parse()
                .map_err(|_| format!("invalid interval {value:?}: expected milliseconds"))?;
            if u128::from(ms) < min.as_millis() {
                Err(format!(
                    "interval of {ms} ms is shorter than this lane's minimum of {} ({} ms)",
                    describe(min),
                    min.as_millis()
                ))
            } else {
                Ok(())
            }
        }
        ScheduleType::Cron => {
            let mut prev: Option<DateTime<Utc>> = None;
            let mut cursor = now;
            for _ in 0..CRON_FREQUENCY_SAMPLES {
                let next = match compute_next_run(ScheduleType::Cron, value, None, tz, cursor) {
                    Ok(Some(iso)) => match parse_iso(&iso) {
                        Some(t) => t,
                        None => break,
                    },
                    // No further occurrence: nothing left to compare.
                    Ok(None) | Err(_) => break,
                };
                if next <= cursor {
                    // Defensive: no progress means no further occurrences.
                    break;
                }
                if let Some(p) = prev {
                    let gap = (next - p).to_std().unwrap_or(Duration::ZERO);
                    if gap < min {
                        return Err(format!(
                            "cron {value:?} runs {} apart ({} and {}); this lane's minimum is {}",
                            describe(gap),
                            to_iso(p),
                            to_iso(next),
                            describe(min)
                        ));
                    }
                }
                prev = Some(next);
                cursor = next;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIVE_MIN: Duration = Duration::from_secs(300);

    fn at(s: &str) -> DateTime<Utc> {
        parse_iso(s).unwrap()
    }

    fn cron_ok(expr: &str, now: &str) -> bool {
        check_schedule_frequency(ScheduleType::Cron, expr, chrono_tz::UTC, at(now), FIVE_MIN)
            .is_ok()
    }

    #[test]
    fn prompt_cap_counts_utf8_bytes() {
        assert!(check_prompt_bytes("abc", Some(3)).is_ok());
        assert!(check_prompt_bytes("abcd", Some(3)).is_err());
        // 2 chars, 6 bytes
        let err = check_prompt_bytes("日本", Some(5)).unwrap_err();
        assert!(err.contains("6 bytes") && err.contains("limit"), "{err}");
        assert!(check_prompt_bytes(&"x".repeat(1 << 20), None).is_ok());
    }

    #[test]
    fn interval_minimum() {
        let f = |v: &str| {
            check_schedule_frequency(
                ScheduleType::Interval,
                v,
                chrono_tz::UTC,
                Utc::now(),
                FIVE_MIN,
            )
        };
        assert!(f("300000").is_ok());
        assert!(f("3600000").is_ok());
        let err = f("299999").unwrap_err();
        assert!(err.contains("299999 ms") && err.contains("5 min"), "{err}");
        assert!(f("60000").is_err());
        assert!(f("abc").is_err());
        assert!(f("-1").is_err());
    }

    #[test]
    fn once_and_disabled_check_always_pass() {
        assert!(
            check_schedule_frequency(
                ScheduleType::Once,
                "2026-01-01T00:00:00",
                chrono_tz::UTC,
                Utc::now(),
                FIVE_MIN
            )
            .is_ok()
        );
        for (ty, v) in [
            (ScheduleType::Cron, "* * * * *"),
            (ScheduleType::Interval, "10000"),
        ] {
            assert!(
                check_schedule_frequency(ty, v, chrono_tz::UTC, Utc::now(), Duration::ZERO).is_ok()
            );
        }
    }

    #[test]
    fn frequent_crons_are_rejected() {
        let now = "2026-10-14T12:00:30.000Z";
        for expr in [
            "* * * * *",
            "*/2 * * * *",
            "*/4 * * * *",
            "0,1 * * * *",
            // 6-field (seconds) expressions
            "*/10 * * * * *",
            "0 */1 * * * *",
            // close only across the hour boundary: 58 -> 00
            "0,58 * * * *",
            // */7 wraps 56 -> 00 (4 minutes)
            "*/7 * * * *",
        ] {
            let r = check_schedule_frequency(
                ScheduleType::Cron,
                expr,
                chrono_tz::UTC,
                at(now),
                FIVE_MIN,
            );
            assert!(r.is_err(), "{expr} should be rejected");
        }
        let err = check_schedule_frequency(
            ScheduleType::Cron,
            "* * * * *",
            chrono_tz::UTC,
            at(now),
            FIVE_MIN,
        )
        .unwrap_err();
        assert!(
            err.contains("1 min apart") && err.contains("5 min"),
            "{err}"
        );
    }

    #[test]
    fn sparse_crons_are_accepted() {
        let now = "2026-10-14T12:00:30.000Z";
        for expr in [
            "*/5 * * * *",
            "*/15 * * * *",
            "0 * * * *",
            "0 9 * * *",
            "0 9 * * 1-5",
            "0,30 9-17 * * *",
            "0 0 1 1 *",
            "0 0 29 2 *",
        ] {
            assert!(cron_ok(expr, now), "{expr} should be accepted");
        }
    }

    #[test]
    fn bursts_that_start_later_are_still_caught() {
        // Asked at 09:58:30: the next two runs are 09:59 today and 09:00
        // tomorrow (far apart), but 09:00 -> 09:01 follows.
        assert!(!cron_ok("* 9 * * *", "2026-10-14T09:58:30.000Z"));
        // Every minute of the first day of the month, asked on its last
        // minute.
        assert!(!cron_ok("* * 1 * *", "2026-10-01T23:58:30.000Z"));
        // Every minute of one hour on Jan 1st, asked right after it.
        assert!(!cron_ok("* 9 1 1 *", "2026-01-01T09:58:30.000Z"));
    }

    #[test]
    fn evaluated_in_the_configured_timezone() {
        // Once a day is fine.
        let r = check_schedule_frequency(
            ScheduleType::Cron,
            "59 23 * * *",
            chrono_tz::Europe::Berlin,
            at("2026-10-14T12:00:00.000Z"),
            FIVE_MIN,
        );
        assert!(r.is_ok());
        // 00:02, 00:59, 23:02, 23:59 Berlin time: 23:59 -> 00:02 is only
        // 3 minutes, across the local midnight.
        let r = check_schedule_frequency(
            ScheduleType::Cron,
            "2,59 0,23 * * *",
            chrono_tz::Europe::Berlin,
            at("2026-10-14T12:00:00.000Z"),
            FIVE_MIN,
        );
        assert!(r.is_err());
    }

    #[test]
    fn impossible_cron_passes_frequency_check() {
        // `first_run` rejects it; the frequency check has nothing to compare.
        assert!(cron_ok("0 0 31 2 *", "2026-10-14T12:00:00.000Z"));
    }

    #[test]
    fn durations_are_described_readably() {
        assert_eq!(describe(Duration::from_secs(300)), "5 min");
        assert_eq!(describe(Duration::from_secs(90)), "90 s");
        assert_eq!(describe(Duration::from_millis(1500)), "1500 ms");
    }
}
