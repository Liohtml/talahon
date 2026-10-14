//! Retry policy: exponential backoff with jitter, honouring `Retry-After`.

use std::time::{Duration, SystemTime};

use rand::Rng;

use crate::error::LlmError;

/// How the client retries transient failures (connect errors, timeouts
/// before a response, HTTP 408/425/429/5xx).
///
/// Streaming requests are only retried until the response headers arrive;
/// once tokens have been received, errors are surfaced to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Retries after the first attempt (0 disables retrying).
    pub max_retries: u32,
    /// Backoff before the first retry.
    pub initial_backoff: Duration,
    /// Upper bound for the exponential backoff.
    pub max_backoff: Duration,
    /// A `Retry-After` longer than this is not waited for: the error is
    /// returned instead (the caller can decide to come back later).
    pub max_retry_after: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(20),
            max_retry_after: Duration::from_secs(60),
        }
    }
}

impl RetryPolicy {
    /// Never retry.
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Self::default()
        }
    }

    /// Exponential backoff for retry number `attempt` (0-based), with
    /// "equal jitter": uniformly random in `[base/2, base]`.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.min(30));
        let base = self
            .initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff);
        let base_ms = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
        if base_ms < 2 {
            return base;
        }
        let half = base_ms / 2;
        let jitter = rand::thread_rng().gen_range(0..=base_ms - half);
        Duration::from_millis(half + jitter)
    }

    /// The delay before retry number `attempt` after `err`, or `None` when
    /// the request must not be retried.
    pub fn delay_for(&self, attempt: u32, err: &LlmError) -> Option<Duration> {
        if attempt >= self.max_retries || !err.is_retryable() {
            return None;
        }
        let backoff = self.backoff(attempt);
        match err.retry_after() {
            Some(ra) if ra > self.max_retry_after => None,
            // Honour the server's delay; add a little jitter so parallel
            // clients do not come back in lock-step.
            Some(ra) => {
                let jitter = rand::thread_rng().gen_range(0..=250u64);
                Some(ra.saturating_add(Duration::from_millis(jitter)))
            }
            None => Some(backoff),
        }
    }
}

/// Parse a `Retry-After` header value: delta-seconds or an HTTP-date.
pub(crate) fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    if let Ok(secs) = v.parse::<f64>() {
        if secs.is_finite() && secs >= 0.0 {
            return Some(Duration::from_secs_f64(secs.min(86_400.0)));
        }
        return None;
    }
    let date = chrono::DateTime::parse_from_rfc2822(v).ok()?;
    let target = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(u64::try_from(date.timestamp()).ok()?))?;
    Some(target.duration_since(now).unwrap_or(Duration::ZERO))
}

/// Extract `Retry-After` from response headers.
pub(crate) fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_retry_after(v, SystemTime::now()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        let p = RetryPolicy {
            max_retries: 10,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(1000),
            max_retry_after: Duration::from_secs(5),
        };
        for attempt in 0..10 {
            let d = p.backoff(attempt);
            let base = (100u64 << attempt).min(1000);
            assert!(d.as_millis() as u64 >= base / 2, "attempt {attempt}: {d:?}");
            assert!(d.as_millis() as u64 <= base, "attempt {attempt}: {d:?}");
        }
    }

    #[test]
    fn delay_respects_retry_after_and_limits() {
        let p = RetryPolicy {
            max_retries: 2,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(20),
            max_retry_after: Duration::from_secs(5),
        };
        let rl = LlmError::RateLimited {
            retry_after: Some(Duration::from_secs(2)),
            message: String::new(),
        };
        assert!(p.delay_for(0, &rl).unwrap() >= Duration::from_secs(2));
        let too_long = LlmError::RateLimited {
            retry_after: Some(Duration::from_secs(600)),
            message: String::new(),
        };
        assert_eq!(p.delay_for(0, &too_long), None);
        let conn = LlmError::Connect("x".into());
        assert!(p.delay_for(1, &conn).is_some());
        assert_eq!(p.delay_for(2, &conn), None, "attempts exhausted");
        assert_eq!(p.delay_for(0, &LlmError::Decode("x".into())), None);
        assert_eq!(RetryPolicy::none().delay_for(0, &conn), None);
    }

    #[test]
    fn retry_after_parsing() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_445_412_480); // 2015-10-21 07:28:00Z
        assert_eq!(parse_retry_after("7", now), Some(Duration::from_secs(7)));
        assert_eq!(
            parse_retry_after("1.5", now),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2015 07:28:10 GMT", now),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2015 07:00:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("soon", now), None);
        assert_eq!(parse_retry_after("-1", now), None);
    }
}
