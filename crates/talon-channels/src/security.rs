//! Thin seams over `talon-security`.
//!
//! The channels use HMAC signing, constant-time comparison and the egress
//! (SSRF) policy from `talon-security`. They are reached through the small
//! function types and the [`EgressGuard`] trait below so the channels can be
//! unit-tested independently of the policy engine and so the host can inject
//! a stricter (or test) implementation.

use std::net::SocketAddr;

use async_trait::async_trait;
use talon_core::Result;
use talon_security::egress::EgressPolicy;
use url::Url;

/// Hex HMAC-SHA256 of `message` under `key`.
pub type HmacSha256Fn = fn(key: &[u8], message: &[u8]) -> String;

/// Constant-time byte-string equality (may leak length only).
pub type ConstantTimeEqFn = fn(a: &[u8], b: &[u8]) -> bool;

/// Default signer: [`talon_security::auth::hmac_sha256_hex`].
pub fn default_hmac() -> HmacSha256Fn {
    talon_security::auth::hmac_sha256_hex
}

/// Default comparison: [`talon_security::auth::constant_time_eq`].
pub fn default_constant_time_eq() -> ConstantTimeEqFn {
    talon_security::auth::constant_time_eq
}

/// Decides whether an outbound URL may be contacted.
#[async_trait]
pub trait EgressGuard: Send + Sync {
    /// Check `url` against the outbound policy. On success, returns the
    /// vetted socket addresses the caller should pin the connection to
    /// (DNS-rebinding safe). An empty list means "no pinning needed".
    async fn check(&self, url: &Url) -> Result<Vec<SocketAddr>>;
}

/// [`EgressGuard`] backed by [`EgressPolicy::resolve_and_check`].
#[derive(Debug, Clone, Default)]
pub struct PolicyEgressGuard {
    policy: EgressPolicy,
}

impl PolicyEgressGuard {
    /// Wrap an explicit policy.
    pub fn new(policy: EgressPolicy) -> Self {
        Self { policy }
    }

    /// Policy from `TALON_EGRESS_ALLOW` / `TALON_EGRESS_DENY` /
    /// `TALON_EGRESS_ALLOW_PRIVATE` (see [`EgressPolicy::from_env`]).
    pub fn from_env(env: &talon_core::env::EnvFile) -> Self {
        Self::new(EgressPolicy::from_env(env))
    }
}

#[async_trait]
impl EgressGuard for PolicyEgressGuard {
    async fn check(&self, url: &Url) -> Result<Vec<SocketAddr>> {
        let (_, addrs) = self.policy.resolve_and_check(url.as_str()).await?;
        Ok(addrs)
    }
}

/// Normalize a host for comparison: lowercase, no trailing dot, no IPv6
/// brackets.
fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Whether `host` matches one of `patterns`: exact (case-insensitive) or
/// `*.suffix` (subdomains of `suffix` only, not `suffix` itself).
pub fn host_matches(host: &str, patterns: &[String]) -> bool {
    let host = normalize_host(host);
    if host.is_empty() {
        return false;
    }
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            let suffix = normalize_host(suffix);
            !suffix.is_empty()
                && host
                    .strip_suffix(suffix.as_str())
                    .and_then(|rest| rest.strip_suffix('.'))
                    .is_some_and(|label| !label.is_empty())
        } else {
            let p = normalize_host(pattern);
            !p.is_empty() && p == host
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_and_wildcard_host_matching() {
        let p = pats(&["copilot.internal", "*.corp.example", "10.0.0.5", "[::1]"]);
        assert!(host_matches("copilot.internal", &p));
        assert!(host_matches("COPILOT.internal.", &p));
        assert!(host_matches("a.corp.example", &p));
        assert!(host_matches("a.b.corp.example", &p));
        assert!(!host_matches("corp.example", &p));
        assert!(!host_matches("evilcorp.example", &p));
        assert!(!host_matches("copilot.internal.evil.com", &p));
        assert!(host_matches("10.0.0.5", &p));
        assert!(!host_matches("10.0.0.50", &p));
        assert!(host_matches("[::1]", &p));
        assert!(host_matches("::1", &p));
        assert!(!host_matches("", &p));
        assert!(!host_matches("anything", &pats(&["", "*.", " "])));
    }

    /// Exercises the real `talon-security` primitives. Fails (todo!() panic)
    /// until A07's implementation of `talon_security::auth` lands.
    #[test]
    fn real_security_primitives() {
        let ct = default_constant_time_eq();
        assert!(ct(b"token", b"token"));
        assert!(!ct(b"token", b"tokem"));
        assert!(!ct(b"token", b"token2"));
        let sign = default_hmac();
        // RFC 4231 test case 2.
        assert_eq!(
            sign(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
