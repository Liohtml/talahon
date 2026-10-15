//! API key verification seam and per-IP auth-failure throttling.
//!
//! Production uses [`SecurityKeyVerifier`], which delegates to
//! [`talon_security::auth`] (constant-time, fail-closed). The trait exists so
//! the server can be unit-tested independently of that crate.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Extracts and verifies the caller's API key.
pub trait KeyVerifier: Send + Sync {
    /// Pull the presented key out of the `X-Api-Key` / `Authorization`
    /// header values.
    fn extract(&self, x_api_key: Option<&str>, authorization: Option<&str>) -> Option<String>;

    /// Constant-time comparison that **fails closed**: false when `expected`
    /// is blank or `provided` is missing/empty.
    fn verify(&self, provided: Option<&str>, expected: &str) -> bool;
}

/// [`KeyVerifier`] backed by [`talon_security::auth`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SecurityKeyVerifier;

impl KeyVerifier for SecurityKeyVerifier {
    fn extract(&self, x_api_key: Option<&str>, authorization: Option<&str>) -> Option<String> {
        talon_security::auth::extract_bearer(x_api_key, authorization)
    }

    fn verify(&self, provided: Option<&str>, expected: &str) -> bool {
        talon_security::auth::verify_api_key(provided, expected)
    }
}

/// Max IPs tracked by the throttle before stale entries are evicted.
const MAX_TRACKED_IPS: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    started: Instant,
    failures: u32,
}

/// Result of recording a failed authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FailureRecord {
    /// Failures from this IP inside the current window.
    pub failures: u32,
    /// This failure tipped the IP into the throttled state.
    pub now_throttled: bool,
}

/// Counts failed authentications per client IP; once an IP reaches
/// `max_failures` inside `window`, further requests from it are refused with
/// 429 (without even looking at the key) until the window expires.
pub(crate) struct AuthThrottle {
    max_failures: u32,
    window: Duration,
    max_entries: usize,
    inner: Mutex<HashMap<IpAddr, FailureWindow>>,
}

impl AuthThrottle {
    pub(crate) fn new(max_failures: u32, window: Duration) -> Self {
        Self::with_capacity(max_failures, window, MAX_TRACKED_IPS)
    }

    fn with_capacity(max_failures: u32, window: Duration, max_entries: usize) -> Self {
        Self {
            max_failures: max_failures.max(1),
            window,
            max_entries: max_entries.max(1),
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, FailureWindow>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `Some(retry_after)` when `ip` is currently throttled.
    pub(crate) fn blocked(&self, ip: IpAddr) -> Option<Duration> {
        self.blocked_at(ip, Instant::now())
    }

    fn blocked_at(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let mut map = self.lock();
        let entry = map.get(&ip).copied()?;
        let elapsed = now.saturating_duration_since(entry.started);
        if elapsed >= self.window {
            map.remove(&ip);
            return None;
        }
        (entry.failures >= self.max_failures).then(|| self.window - elapsed)
    }

    /// Record a failed authentication from `ip`.
    pub(crate) fn record_failure(&self, ip: IpAddr) -> FailureRecord {
        self.record_failure_at(ip, Instant::now())
    }

    fn record_failure_at(&self, ip: IpAddr, now: Instant) -> FailureRecord {
        let mut map = self.lock();
        if !map.contains_key(&ip) && map.len() >= self.max_entries {
            let window = self.window;
            map.retain(|_, e| now.saturating_duration_since(e.started) < window);
            if map.len() >= self.max_entries {
                // Still full of live entries: evict the oldest one.
                if let Some(oldest) = map.iter().min_by_key(|(_, e)| e.started).map(|(k, _)| *k) {
                    map.remove(&oldest);
                }
            }
        }
        let entry = map.entry(ip).or_insert(FailureWindow {
            started: now,
            failures: 0,
        });
        if now.saturating_duration_since(entry.started) >= self.window {
            *entry = FailureWindow {
                started: now,
                failures: 0,
            };
        }
        entry.failures = entry.failures.saturating_add(1);
        FailureRecord {
            failures: entry.failures,
            now_throttled: entry.failures == self.max_failures,
        }
    }

    /// A successful authentication clears the IP's failure count.
    pub(crate) fn record_success(&self, ip: IpAddr) {
        let mut map = self.lock();
        if !map.is_empty() {
            map.remove(&ip);
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::KeyVerifier;

    /// Local stand-in for `talon_security::auth` with the documented
    /// contract (fail closed, constant-time compare, `X-Api-Key` first,
    /// then a case-insensitive `Bearer` scheme).
    #[derive(Debug, Default, Clone, Copy)]
    pub(crate) struct LocalVerifier;

    impl KeyVerifier for LocalVerifier {
        fn extract(&self, x_api_key: Option<&str>, authorization: Option<&str>) -> Option<String> {
            if let Some(k) = x_api_key.map(str::trim).filter(|k| !k.is_empty()) {
                return Some(k.to_string());
            }
            let auth = authorization?.trim();
            let (scheme, rest) = auth.split_once(char::is_whitespace)?;
            if !scheme.eq_ignore_ascii_case("bearer") {
                return None;
            }
            let token = rest.trim();
            (!token.is_empty()).then(|| token.to_string())
        }

        fn verify(&self, provided: Option<&str>, expected: &str) -> bool {
            if expected.trim().is_empty() {
                return false;
            }
            let Some(p) = provided.filter(|p| !p.is_empty()) else {
                return false;
            };
            let (a, b) = (p.as_bytes(), expected.as_bytes());
            if a.len() != b.len() {
                return false;
            }
            a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::LocalVerifier;
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn throttles_after_max_failures_and_recovers_after_the_window() {
        let t = AuthThrottle::new(3, Duration::from_secs(60));
        let start = Instant::now();
        assert_eq!(t.blocked_at(ip(1), start), None);
        assert!(!t.record_failure_at(ip(1), start).now_throttled);
        assert!(!t.record_failure_at(ip(1), start).now_throttled);
        let third = t.record_failure_at(ip(1), start);
        assert!(third.now_throttled);
        assert_eq!(third.failures, 3);
        let retry = t.blocked_at(ip(1), start + Duration::from_secs(10));
        assert_eq!(retry, Some(Duration::from_secs(50)));
        // Other IPs are unaffected.
        assert_eq!(t.blocked_at(ip(2), start), None);
        // Window expiry lifts the block.
        assert_eq!(t.blocked_at(ip(1), start + Duration::from_secs(61)), None);
        assert_eq!(
            t.record_failure_at(ip(1), start + Duration::from_secs(62))
                .failures,
            1
        );
    }

    #[test]
    fn success_resets_the_count() {
        let t = AuthThrottle::new(2, Duration::from_secs(60));
        t.record_failure(ip(1));
        t.record_success(ip(1));
        assert_eq!(t.record_failure(ip(1)).failures, 1);
        assert_eq!(t.blocked(ip(1)), None);
    }

    #[test]
    fn tracked_ip_set_is_bounded() {
        let t = AuthThrottle::with_capacity(5, Duration::from_secs(60), 4);
        for n in 0..50 {
            t.record_failure(ip(n));
        }
        assert!(t.tracked() <= 4);
    }

    #[test]
    fn local_verifier_contract() {
        let v = LocalVerifier;
        assert!(v.verify(Some("k3y"), "k3y"));
        assert!(!v.verify(Some("k3y"), "k3z"));
        assert!(!v.verify(Some(""), ""));
        assert!(!v.verify(None, ""));
        assert!(!v.verify(Some("x"), "   "));
        assert!(!v.verify(None, "k3y"));
        assert_eq!(v.extract(Some("a"), Some("Bearer b")).as_deref(), Some("a"));
        assert_eq!(v.extract(None, Some("bearer  b ")).as_deref(), Some("b"));
        assert_eq!(v.extract(None, Some("Basic b")), None);
        assert_eq!(v.extract(None, None), None);
    }

    /// Exercises the real `talon_security::auth` backend (implemented by A07
    /// concurrently; fails with a `todo!()` panic until that lands).
    #[test]
    fn security_crate_verifier_fails_closed() {
        let v = SecurityKeyVerifier;
        assert!(v.verify(Some("correct-horse-battery"), "correct-horse-battery"));
        assert!(!v.verify(Some("wrong"), "correct-horse-battery"));
        assert!(!v.verify(Some(""), ""));
        assert!(!v.verify(None, ""));
        assert_eq!(
            v.extract(None, Some("Bearer correct-horse-battery"))
                .as_deref(),
            Some("correct-horse-battery")
        );
        assert_eq!(v.extract(Some("k"), None).as_deref(), Some("k"));
    }
}
