//! Per-run gateway tokens: stored only as SHA-256 digests, with a TTL, a
//! per-token token-bucket rate limit and a per-token in-flight cap.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rand::RngCore;
use sha2::{Digest, Sha256};

/// Prefix of every gateway token (makes them recognisable in secret scans).
pub const TOKEN_PREFIX: &str = "tlgw_";

/// Bytes of entropy per token.
const TOKEN_BYTES: usize = 32;

/// Upper bound for a token TTL (keeps `Instant` arithmetic safe).
const MAX_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

type TokenDigest = [u8; 32];

fn digest(token: &str) -> TokenDigest {
    Sha256::digest(token.as_bytes()).into()
}

/// Classic token bucket: `capacity` requests, refilled continuously at
/// `capacity / 60` per second.
#[derive(Debug, Clone)]
struct Bucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl Bucket {
    fn new(per_minute: u32, now: Instant) -> Self {
        let capacity = f64::from(per_minute.max(1));
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec: capacity / 60.0,
            last: now,
        }
    }

    /// Take one request; on failure returns how long until one is available.
    fn take(&mut self, now: Instant) -> Result<(), Duration> {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - self.tokens) / self.refill_per_sec;
            Err(Duration::from_secs_f64(wait.clamp(0.0, 3600.0)))
        }
    }
}

#[derive(Debug)]
struct Entry {
    label: String,
    expires_at: Instant,
    bucket: Option<Bucket>,
    in_flight: Arc<AtomicU32>,
}

/// Holds one in-flight slot of a token; released on drop (for streams:
/// when the passthrough body is dropped).
#[derive(Debug)]
pub(crate) struct InFlightGuard(Arc<AtomicU32>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Result of checking a presented token.
#[derive(Debug)]
pub(crate) enum AuthDecision {
    /// Valid; carries the label the token was issued for and the in-flight
    /// slot (keep it alive for the duration of the request).
    Allowed { label: String, guard: InFlightGuard },
    /// No token presented.
    Missing,
    /// Unknown (or revoked) token.
    Invalid,
    /// The token's TTL elapsed (it is removed).
    Expired { label: String },
    /// Valid but over its request budget.
    RateLimited {
        label: String,
        retry_after: Duration,
    },
    /// Valid but already running the maximum number of concurrent requests.
    TooManyConcurrent { label: String },
}

impl AuthDecision {
    /// Short machine-readable reason for audit records.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            AuthDecision::Allowed { .. } => "allowed",
            AuthDecision::Missing => "missing_token",
            AuthDecision::Invalid => "invalid_token",
            AuthDecision::Expired { .. } => "expired_token",
            AuthDecision::RateLimited { .. } => "rate_limited",
            AuthDecision::TooManyConcurrent { .. } => "too_many_concurrent",
        }
    }
}

/// Thread-safe token registry.
#[derive(Debug)]
pub(crate) struct TokenStore {
    entries: Mutex<HashMap<TokenDigest, Entry>>,
    requests_per_minute: u32,
    max_concurrent: u32,
}

impl TokenStore {
    /// `requests_per_minute == 0` disables rate limiting;
    /// `max_concurrent == 0` disables the in-flight cap.
    pub(crate) fn new(requests_per_minute: u32, max_concurrent: u32) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            requests_per_minute,
            max_concurrent,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<TokenDigest, Entry>> {
        // A poisoned lock only means another thread panicked mid-update of
        // a plain map; the data is still consistent enough to keep serving.
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Mint a token for `label`, valid for `ttl`. Only its digest is kept.
    pub(crate) fn issue(&self, label: &str, ttl: Duration) -> String {
        let mut raw = [0u8; TOKEN_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let token = format!("{TOKEN_PREFIX}{}", hex::encode(raw));
        let now = Instant::now();
        let expires_at = now.checked_add(ttl.min(MAX_TTL)).unwrap_or(now);
        let bucket =
            (self.requests_per_minute > 0).then(|| Bucket::new(self.requests_per_minute, now));
        let mut map = self.lock();
        map.retain(|_, e| e.expires_at > now);
        map.insert(
            digest(&token),
            Entry {
                label: label.to_string(),
                expires_at,
                bucket,
                in_flight: Arc::new(AtomicU32::new(0)),
            },
        );
        token
    }

    /// Revoke one token. Returns whether it existed.
    pub(crate) fn revoke(&self, token: &str) -> bool {
        self.lock().remove(&digest(token.trim())).is_some()
    }

    /// Revoke every token issued for `label`. Returns how many were removed.
    pub(crate) fn revoke_label(&self, label: &str) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, e| e.label != label);
        before - map.len()
    }

    /// Drop expired tokens. Returns how many were removed.
    pub(crate) fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, e| e.expires_at > now);
        before - map.len()
    }

    /// Number of live (non-expired) tokens.
    pub(crate) fn active(&self) -> usize {
        let now = Instant::now();
        self.lock().values().filter(|e| e.expires_at > now).count()
    }

    /// Check a presented token, take an in-flight slot and consume one
    /// request from its budget.
    ///
    /// The lookup is by SHA-256 digest, so timing reveals nothing useful
    /// about stored tokens (an attacker cannot steer digest prefixes).
    pub(crate) fn authorize(&self, presented: Option<&str>) -> AuthDecision {
        let Some(token) = presented.map(str::trim).filter(|t| !t.is_empty()) else {
            return AuthDecision::Missing;
        };
        if !token.starts_with(TOKEN_PREFIX) || token.len() > 256 {
            return AuthDecision::Invalid;
        }
        let key = digest(token);
        let now = Instant::now();
        let mut map = self.lock();
        let Some(entry) = map.get_mut(&key) else {
            return AuthDecision::Invalid;
        };
        if entry.expires_at <= now {
            let label = entry.label.clone();
            map.remove(&key);
            return AuthDecision::Expired { label };
        }
        // Checked (and incremented) under the map lock, so concurrent
        // authorizations of the same token cannot overshoot the cap.
        if self.max_concurrent > 0 && entry.in_flight.load(Ordering::Acquire) >= self.max_concurrent
        {
            return AuthDecision::TooManyConcurrent {
                label: entry.label.clone(),
            };
        }
        if let Some(bucket) = entry.bucket.as_mut() {
            if let Err(retry_after) = bucket.take(now) {
                return AuthDecision::RateLimited {
                    label: entry.label.clone(),
                    retry_after,
                };
            }
        }
        entry.in_flight.fetch_add(1, Ordering::AcqRel);
        AuthDecision::Allowed {
            label: entry.label.clone(),
            guard: InFlightGuard(entry.in_flight.clone()),
        }
    }
}

/// Extract a bearer token from `Authorization: Bearer <t>` (scheme is
/// case-insensitive) or, failing that, `X-Api-Key`.
pub(crate) fn extract_token(
    authorization: Option<&str>,
    x_api_key: Option<&str>,
) -> Option<String> {
    if let Some(auth) = authorization {
        let auth = auth.trim();
        if let Some((scheme, rest)) = auth.split_once(char::is_whitespace) {
            if scheme.eq_ignore_ascii_case("bearer") && !rest.trim().is_empty() {
                return Some(rest.trim().to_string());
            }
        }
    }
    x_api_key
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_authorize_revoke() {
        let store = TokenStore::new(0, 0);
        let t = store.issue("main", Duration::from_secs(60));
        assert!(t.starts_with(TOKEN_PREFIX));
        assert_eq!(t.len(), TOKEN_PREFIX.len() + 64);
        assert!(matches!(
            store.authorize(Some(&t)),
            AuthDecision::Allowed { label, .. } if label == "main"
        ));
        assert_eq!(store.active(), 1);
        assert!(store.revoke(&t));
        assert!(!store.revoke(&t));
        assert!(matches!(store.authorize(Some(&t)), AuthDecision::Invalid));
        assert!(matches!(store.authorize(None), AuthDecision::Missing));
        assert!(matches!(store.authorize(Some("  ")), AuthDecision::Missing));
        assert!(matches!(
            store.authorize(Some("tlgw_nope")),
            AuthDecision::Invalid
        ));
        assert!(matches!(
            store.authorize(Some("Bearer x")),
            AuthDecision::Invalid
        ));
    }

    #[test]
    fn tokens_are_unique_and_only_digests_are_stored() {
        let store = TokenStore::new(0, 0);
        let a = store.issue("x", Duration::from_secs(60));
        let b = store.issue("x", Duration::from_secs(60));
        assert_ne!(a, b);
        {
            let map = store.lock();
            assert!(map.contains_key(&digest(&a)));
            assert!(map.values().all(|e| !e.label.contains(&a)));
        }
        assert_eq!(store.revoke_label("x"), 2);
        assert_eq!(store.active(), 0);
    }

    #[test]
    fn expiry() {
        let store = TokenStore::new(0, 0);
        let t = store.issue("g", Duration::ZERO);
        assert!(matches!(
            store.authorize(Some(&t)),
            AuthDecision::Expired { label } if label == "g"
        ));
        // Removed after the first expired use.
        assert!(matches!(store.authorize(Some(&t)), AuthDecision::Invalid));
        store.issue("h", Duration::ZERO);
        assert_eq!(store.purge_expired(), 1);
        // Absurd TTLs are capped rather than overflowing.
        let t = store.issue("long", Duration::MAX);
        assert!(matches!(
            store.authorize(Some(&t)),
            AuthDecision::Allowed { .. }
        ));
    }

    #[test]
    fn rate_limit_per_token() {
        let store = TokenStore::new(2, 0);
        let a = store.issue("a", Duration::from_secs(60));
        let b = store.issue("b", Duration::from_secs(60));
        assert!(matches!(
            store.authorize(Some(&a)),
            AuthDecision::Allowed { .. }
        ));
        assert!(matches!(
            store.authorize(Some(&a)),
            AuthDecision::Allowed { .. }
        ));
        match store.authorize(Some(&a)) {
            AuthDecision::RateLimited { label, retry_after } => {
                assert_eq!(label, "a");
                assert!(retry_after > Duration::from_secs(20), "{retry_after:?}");
                assert!(retry_after <= Duration::from_secs(30), "{retry_after:?}");
            }
            other => panic!("expected rate limit, got {other:?}"),
        }
        // Another token has its own budget.
        assert!(matches!(
            store.authorize(Some(&b)),
            AuthDecision::Allowed { .. }
        ));
    }

    #[test]
    fn in_flight_cap_per_token() {
        let store = TokenStore::new(0, 2);
        let a = store.issue("a", Duration::from_secs(60));
        let first = store.authorize(Some(&a));
        let second = store.authorize(Some(&a));
        assert!(matches!(first, AuthDecision::Allowed { .. }));
        assert!(matches!(second, AuthDecision::Allowed { .. }));
        let third = store.authorize(Some(&a));
        assert!(matches!(third, AuthDecision::TooManyConcurrent { ref label } if label == "a"));
        assert_eq!(third.reason(), "too_many_concurrent");
        drop(first);
        assert!(matches!(
            store.authorize(Some(&a)),
            AuthDecision::Allowed { .. }
        ));
        // Other tokens are unaffected.
        let b = store.issue("b", Duration::from_secs(60));
        assert!(matches!(
            store.authorize(Some(&b)),
            AuthDecision::Allowed { .. }
        ));
        drop(second);
    }

    #[test]
    fn bucket_refills() {
        let t0 = Instant::now();
        let mut b = Bucket::new(60, t0);
        for _ in 0..60 {
            assert!(b.take(t0).is_ok());
        }
        assert!(b.take(t0).is_err());
        assert!(b.take(t0 + Duration::from_millis(1100)).is_ok());
    }

    #[test]
    fn token_extraction() {
        assert_eq!(
            extract_token(Some("Bearer abc"), None).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_token(Some("bearer   abc  "), None).as_deref(),
            Some("abc")
        );
        assert_eq!(extract_token(Some("Basic abc"), None), None);
        assert_eq!(
            extract_token(Some("Basic abc"), Some("k")).as_deref(),
            Some("k")
        );
        assert_eq!(extract_token(None, Some("  ")), None);
        assert_eq!(extract_token(Some("Bearer"), None), None);
    }
}
