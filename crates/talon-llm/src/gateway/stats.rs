//! Gateway counters and per-label usage accounting.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use serde::Serialize;

use crate::types::Usage;

/// Labels beyond this many are aggregated under [`OVERFLOW_LABEL`] so a
/// host that mints unique labels cannot grow the map without bound.
pub const MAX_LABELS: usize = 4096;

/// Bucket for usage once [`MAX_LABELS`] distinct labels exist.
pub const OVERFLOW_LABEL: &str = "_other";

/// Usage attributed to one token label.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LabelStats {
    /// Authorized requests (all routes).
    pub requests: u64,
    /// Chat completions (streamed or not).
    pub completions: u64,
    /// Streamed chat completions.
    pub streamed: u64,
    /// Requests that failed upstream or returned a non-2xx status.
    pub errors: u64,
    /// Requests refused by the per-token rate limit.
    pub rate_limited: u64,
    /// Summed prompt tokens.
    pub prompt_tokens: u64,
    /// Summed completion tokens.
    pub completion_tokens: u64,
    /// Summed prefix-cache hits.
    pub cached_tokens: u64,
}

/// Snapshot returned by `GatewayHandle::stats`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GatewayStats {
    /// Seconds since the gateway started.
    pub uptime_secs: u64,
    /// Authorized requests.
    pub requests: u64,
    /// Requests refused for a missing/invalid/expired token.
    pub auth_failures: u64,
    /// Requests refused by the rate limit.
    pub rate_limited: u64,
    /// Requests refused by policy (bad JSON, too large, ...).
    pub rejected: u64,
    /// Upstream connection failures / timeouts / upstream auth errors.
    pub upstream_errors: u64,
    /// Live tokens.
    pub active_tokens: usize,
    /// Per-label accounting.
    pub labels: BTreeMap<String, LabelStats>,
}

#[derive(Debug, Default)]
struct Inner {
    requests: u64,
    auth_failures: u64,
    rate_limited: u64,
    rejected: u64,
    upstream_errors: u64,
    labels: BTreeMap<String, LabelStats>,
}

impl Inner {
    fn label(&mut self, label: &str) -> &mut LabelStats {
        let key = if self.labels.contains_key(label) || self.labels.len() < MAX_LABELS {
            label
        } else {
            OVERFLOW_LABEL
        };
        self.labels.entry(key.to_string()).or_default()
    }
}

/// Thread-safe recorder.
#[derive(Debug)]
pub(crate) struct StatsRecorder {
    started: Instant,
    inner: Mutex<Inner>,
}

impl StatsRecorder {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn auth_failure(&self) {
        self.lock().auth_failures += 1;
    }

    pub(crate) fn rate_limited(&self, label: &str) {
        let mut g = self.lock();
        g.rate_limited += 1;
        g.label(label).rate_limited += 1;
    }

    pub(crate) fn rejected(&self) {
        self.lock().rejected += 1;
    }

    pub(crate) fn request(&self, label: &str) {
        let mut g = self.lock();
        g.requests += 1;
        g.label(label).requests += 1;
    }

    pub(crate) fn upstream_error(&self, label: &str) {
        let mut g = self.lock();
        g.upstream_errors += 1;
        g.label(label).errors += 1;
    }

    pub(crate) fn error(&self, label: &str) {
        self.lock().label(label).errors += 1;
    }

    pub(crate) fn completion(&self, label: &str, usage: Option<&Usage>, streamed: bool) {
        let mut g = self.lock();
        let s = g.label(label);
        s.completions += 1;
        if streamed {
            s.streamed += 1;
        }
        if let Some(u) = usage {
            s.prompt_tokens = s.prompt_tokens.saturating_add(u.prompt_tokens);
            s.completion_tokens = s.completion_tokens.saturating_add(u.completion_tokens);
            s.cached_tokens = s.cached_tokens.saturating_add(u.cached_tokens);
        }
    }

    pub(crate) fn snapshot(&self, active_tokens: usize) -> GatewayStats {
        let g = self.lock();
        GatewayStats {
            uptime_secs: self.started.elapsed().as_secs(),
            requests: g.requests,
            auth_failures: g.auth_failures,
            rate_limited: g.rate_limited,
            rejected: g.rejected,
            upstream_errors: g.upstream_errors,
            active_tokens,
            labels: g.labels.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_per_label() {
        let s = StatsRecorder::new();
        s.request("a");
        s.request("a");
        s.completion(
            "a",
            Some(&Usage {
                prompt_tokens: 10,
                completion_tokens: 2,
                cached_tokens: 8,
            }),
            true,
        );
        s.completion("a", None, false);
        s.rate_limited("b");
        s.auth_failure();
        s.upstream_error("a");
        s.rejected();
        let snap = s.snapshot(3);
        assert_eq!(snap.requests, 2);
        assert_eq!(snap.auth_failures, 1);
        assert_eq!(snap.rate_limited, 1);
        assert_eq!(snap.upstream_errors, 1);
        assert_eq!(snap.rejected, 1);
        assert_eq!(snap.active_tokens, 3);
        let a = &snap.labels["a"];
        assert_eq!(a.completions, 2);
        assert_eq!(a.streamed, 1);
        assert_eq!(a.prompt_tokens, 10);
        assert_eq!(a.cached_tokens, 8);
        assert_eq!(a.errors, 1);
        assert_eq!(snap.labels["b"].rate_limited, 1);
    }

    #[test]
    fn label_cardinality_is_bounded() {
        let s = StatsRecorder::new();
        for i in 0..(MAX_LABELS + 10) {
            s.request(&format!("l{i}"));
        }
        let snap = s.snapshot(0);
        assert_eq!(snap.labels.len(), MAX_LABELS + 1);
        assert_eq!(snap.labels[OVERFLOW_LABEL].requests, 10);
    }
}
