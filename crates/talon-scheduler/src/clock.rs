//! Wall-clock abstraction so the scheduler's notion of "now" (used for
//! due-task queries and next-run computation) is controllable in tests.

use std::fmt;

use chrono::{DateTime, Utc};

/// Source of the current wall-clock time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current time.
    fn now(&self) -> DateTime<Utc>;
}

/// The system clock (`Utc::now()`). Used in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A wall clock that advances with Tokio's clock: `anchor + (tokio::time::Instant::now() - start)`.
///
/// Under `tokio::time::pause()` / `#[tokio::test(start_paused = true)]` it
/// follows virtual time, which makes scheduler tests deterministic.
#[derive(Debug, Clone)]
pub struct TokioClock {
    anchor: DateTime<Utc>,
    start: tokio::time::Instant,
}

impl TokioClock {
    /// A clock that reads `anchor` now and advances with Tokio time.
    pub fn starting_at(anchor: DateTime<Utc>) -> Self {
        Self {
            anchor,
            start: tokio::time::Instant::now(),
        }
    }
}

impl Clock for TokioClock {
    fn now(&self) -> DateTime<Utc> {
        let elapsed = tokio::time::Instant::now().saturating_duration_since(self.start);
        let elapsed = chrono::Duration::from_std(elapsed).unwrap_or(chrono::Duration::MAX);
        self.anchor
            .checked_add_signed(elapsed)
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn tokio_clock_follows_virtual_time() {
        let anchor = talon_core::time::parse_iso("2026-01-01T00:00:00.000Z").unwrap();
        let clock = TokioClock::starting_at(anchor);
        assert_eq!(clock.now(), anchor);
        tokio::time::sleep(Duration::from_secs(90)).await;
        assert_eq!(
            talon_core::time::to_iso(clock.now()),
            "2026-01-01T00:01:30.000Z"
        );
    }

    #[test]
    fn system_clock_is_close_to_now() {
        let delta = (SystemClock.now() - Utc::now()).num_seconds().abs();
        assert!(delta < 5);
    }
}
