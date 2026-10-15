//! Retry backoff: exponential growth, a hard cap and symmetric jitter.
//!
//! Used by the [`GroupQueue`](crate::GroupQueue) for failed message runs and
//! by the [`TaskScheduler`](crate::TaskScheduler) for failed task runs.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Exponential backoff policy with a cap and jitter.
///
/// The un-jittered delay before retry `n` (1-based) is
/// `base_delay * 2^(n-1)`, capped at `max_delay`. Jitter then scales it by a
/// random factor in `[1 - jitter, 1 + jitter]`, and the result is capped at
/// `max_delay` again, so the cap is a hard upper bound.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryPolicy {
    /// Retries after the initial attempt before giving up (default: 5).
    pub max_retries: u32,
    /// Delay before the first retry (default: 5 s).
    pub base_delay: Duration,
    /// Upper bound for any single delay.
    pub max_delay: Duration,
    /// Jitter fraction in `[0, 1]`; `0` disables jitter.
    pub jitter: f64,
}

impl Default for RetryPolicy {
    /// 5 retries starting at 5 s, with a 5 minute cap and ±20 % jitter.
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(300),
            jitter: 0.2,
        }
    }
}

impl RetryPolicy {
    /// Same policy with jitter disabled (deterministic delays).
    pub fn without_jitter(mut self) -> Self {
        self.jitter = 0.0;
        self
    }

    /// Un-jittered, capped delay before retry number `attempt` (1-based;
    /// `0` is treated as `1`).
    pub fn base_delay_for(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(31);
        let factor = 1u32 << exponent;
        self.base_delay
            .checked_mul(factor)
            .unwrap_or(self.max_delay)
            .min(self.max_delay)
    }

    /// Jittered, capped delay before retry number `attempt`. `unit` is a
    /// uniformly distributed value in `[0, 1)` (out-of-range values are
    /// clamped) that selects the jitter factor.
    pub fn delay_for(&self, attempt: u32, unit: f64) -> Duration {
        let base = self.base_delay_for(attempt);
        let jitter = if self.jitter.is_finite() {
            self.jitter.clamp(0.0, 1.0)
        } else {
            0.0
        };
        if jitter == 0.0 {
            return base;
        }
        let unit = if unit.is_finite() {
            unit.clamp(0.0, 1.0)
        } else {
            0.5
        };
        let factor = 1.0 - jitter + 2.0 * jitter * unit;
        Duration::try_from_secs_f64(base.as_secs_f64() * factor)
            .unwrap_or(self.max_delay)
            .min(self.max_delay)
    }
}

/// Small lock-free pseudo-random source (SplitMix64) for jitter. Seeded from
/// the std `RandomState` keys, so no extra dependency is needed. Not suitable
/// for anything security-relevant.
#[derive(Debug)]
pub(crate) struct JitterRng {
    state: AtomicU64,
}

impl JitterRng {
    const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

    pub(crate) fn new() -> Self {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(0x5EED);
        Self {
            state: AtomicU64::new(hasher.finish()),
        }
    }

    /// Next value, uniformly distributed in `[0, 1)`.
    pub(crate) fn next_unit(&self) -> f64 {
        let mut z = self
            .state
            .fetch_add(Self::GAMMA, Ordering::Relaxed)
            .wrapping_add(Self::GAMMA);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        // 53 random mantissa bits -> [0, 1).
        (z >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn exponential_without_jitter_matches_ts() {
        let p = RetryPolicy::default().without_jitter();
        let delays: Vec<u64> = (1..=5)
            .map(|n| p.delay_for(n, 0.9).as_millis() as u64)
            .collect();
        assert_eq!(delays, vec![5_000, 10_000, 20_000, 40_000, 80_000]);
    }

    #[test]
    fn delays_are_capped() {
        let p = RetryPolicy {
            max_retries: 50,
            base_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(60),
            jitter: 0.5,
        };
        assert_eq!(p.base_delay_for(10), Duration::from_secs(60));
        assert_eq!(p.base_delay_for(40), Duration::from_secs(60));
        for unit in [0.0, 0.25, 0.5, 0.99, 1.0, f64::NAN, 7.0] {
            assert!(p.delay_for(30, unit) <= Duration::from_secs(60));
        }
        // Overflowing base * 2^n saturates at the cap instead of panicking.
        let huge = RetryPolicy {
            base_delay: Duration::MAX,
            max_delay: Duration::MAX,
            ..p
        };
        assert_eq!(huge.delay_for(3, 1.0), Duration::MAX);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let p = RetryPolicy {
            jitter: 0.2,
            max_delay: Duration::from_secs(3600),
            ..RetryPolicy::default()
        };
        let low = p.delay_for(1, 0.0);
        let mid = p.delay_for(1, 0.5);
        let high = p.delay_for(1, 1.0);
        assert_eq!(low, Duration::from_secs(4));
        assert_eq!(mid, Duration::from_secs(5));
        assert_eq!(high, Duration::from_secs(6));

        let rng = JitterRng::new();
        for _ in 0..1000 {
            let d = p.delay_for(2, rng.next_unit());
            assert!(
                d >= Duration::from_secs(8) && d <= Duration::from_secs(12),
                "{d:?}"
            );
        }
    }

    #[test]
    fn rng_is_uniform_enough() {
        let rng = JitterRng::new();
        let samples: Vec<f64> = (0..10_000).map(|_| rng.next_unit()).collect();
        assert!(samples.iter().all(|u| (0.0..1.0).contains(u)));
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!((mean - 0.5).abs() < 0.05, "mean {mean}");
        // Two generators are seeded differently.
        let other = JitterRng::new();
        let a: Vec<f64> = (0..4).map(|_| rng.next_unit()).collect();
        let b: Vec<f64> = (0..4).map(|_| other.next_unit()).collect();
        assert_ne!(a, b);
    }

    #[test]
    fn negative_or_nan_jitter_is_ignored() {
        for jitter in [f64::NAN, -3.0, f64::INFINITY] {
            let p = RetryPolicy {
                jitter,
                ..RetryPolicy::default()
            };
            assert_eq!(p.delay_for(1, 0.0), Duration::from_secs(5), "{jitter}");
        }
    }
}
