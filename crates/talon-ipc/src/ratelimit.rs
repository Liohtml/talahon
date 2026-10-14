//! Per-namespace audit rate limiting (MYTH-11).
//!
//! Every IPC file a container drops can produce an audit row (a denial, a
//! quarantined file, a delivered message). A compromised container could
//! therefore grow the hash-chained audit log without bound and bury real
//! events. [`AuditLimiter`] gives each IPC namespace a budget of
//! `max` rows per `window`; rows beyond the budget are *suppressed* —
//! counted per kind and reported as one `ipc.audit.suppressed` summary row
//! (`details.suppressed_since_last`) once the window has passed (on the
//! namespace's next audit row or at the start of the next scan, whichever
//! comes first).
//!
//! Applied task operations (schedule/pause/resume/cancel/update,
//! `register_group`, `refresh_groups`) are state changes and are always
//! written ("priority" rows); they still consume budget so a namespace that
//! floods them cannot also flood denials.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::json;
use talon_core::audit::event;
use talon_core::types::AuditEvent;

use crate::json::sanitize_for_log;
use crate::watcher::IpcWatcher;

/// Audit kind of the summary row written after a window with suppressions.
pub(crate) const SUPPRESSED_KIND: &str = "ipc.audit.suppressed";

/// Rows suppressed for one namespace during one window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Suppressed {
    /// The namespace.
    pub ipc_key: String,
    /// Its group folder (audit actor).
    pub folder: String,
    /// Number of suppressed rows.
    pub count: u64,
    /// Suppressed rows per audit kind.
    pub by_kind: BTreeMap<String, u64>,
}

#[derive(Debug)]
struct Bucket {
    folder: String,
    window_start: Instant,
    written: usize,
    suppressed: u64,
    by_kind: BTreeMap<String, u64>,
}

impl Bucket {
    fn new(folder: &str, now: Instant) -> Self {
        Self {
            folder: folder.to_string(),
            window_start: now,
            written: 0,
            suppressed: 0,
            by_kind: BTreeMap::new(),
        }
    }

    /// Summary of the window so far (if anything was suppressed).
    fn summary(&mut self, ipc_key: &str) -> Option<Suppressed> {
        if self.suppressed == 0 {
            return None;
        }
        let s = Suppressed {
            ipc_key: ipc_key.to_string(),
            folder: self.folder.clone(),
            count: self.suppressed,
            by_kind: std::mem::take(&mut self.by_kind),
        };
        self.suppressed = 0;
        Some(s)
    }
}

/// Decision for one audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Admission {
    /// Write the row.
    pub write: bool,
    /// This is the first suppressed row of the namespace's current window
    /// (worth one log line).
    pub first_suppressed: bool,
    /// Summary of the namespace's previous window, to be written first.
    pub summary: Option<Suppressed>,
}

/// Fixed-window, per-namespace audit budget.
#[derive(Debug)]
pub(crate) struct AuditLimiter {
    max: usize,
    window: Duration,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl AuditLimiter {
    /// `max == 0` (or a zero window) disables the limit.
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn disabled(&self) -> bool {
        self.max == 0 || self.window.is_zero()
    }

    /// Account for one audit row of `kind` from namespace `ipc_key`.
    pub fn admit(
        &self,
        ipc_key: &str,
        folder: &str,
        kind: &str,
        priority: bool,
        now: Instant,
    ) -> Admission {
        if self.disabled() {
            return Admission {
                write: true,
                first_suppressed: false,
                summary: None,
            };
        }
        // A poisoned lock only means another thread panicked mid-update;
        // the counters are still usable.
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        let bucket = buckets
            .entry(ipc_key.to_string())
            .or_insert_with(|| Bucket::new(folder, now));
        let mut summary = None;
        if now.saturating_duration_since(bucket.window_start) >= self.window {
            summary = bucket.summary(ipc_key);
            *bucket = Bucket::new(folder, now);
        }
        if priority || bucket.written < self.max {
            bucket.written = bucket.written.saturating_add(1);
            Admission {
                write: true,
                first_suppressed: false,
                summary,
            }
        } else {
            bucket.suppressed = bucket.suppressed.saturating_add(1);
            let n = bucket.by_kind.entry(kind.to_string()).or_insert(0);
            *n = n.saturating_add(1);
            Admission {
                write: false,
                first_suppressed: bucket.suppressed == 1,
                summary,
            }
        }
    }

    /// Close every window that has ended: return the summaries of those with
    /// suppressions and forget them (keeps the map bounded by the number of
    /// recently active namespaces).
    pub fn drain_expired(&self, now: Instant) -> Vec<Suppressed> {
        if self.disabled() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        buckets.retain(|key, bucket| {
            if now.saturating_duration_since(bucket.window_start) < self.window {
                return true;
            }
            if let Some(s) = bucket.summary(key) {
                out.push(s);
            }
            false
        });
        out.sort_by(|a, b| a.ipc_key.cmp(&b.ipc_key));
        out
    }
}

impl IpcWatcher {
    /// Write `ev` for namespace `ipc_key` subject to the audit rate limit.
    /// `priority` rows (applied state changes) are never suppressed.
    /// Returns whether the row was written.
    pub(crate) fn audit_event(
        &self,
        ipc_key: &str,
        folder: &str,
        ev: AuditEvent,
        priority: bool,
    ) -> bool {
        let adm = self
            .audit_limiter
            .admit(ipc_key, folder, &ev.kind, priority, Instant::now());
        if let Some(s) = adm.summary {
            self.write_suppressed_summary(s);
        }
        if adm.first_suppressed {
            tracing::warn!(
                ipc_key = %sanitize_for_log(ipc_key),
                limit = self.config.audit_max_per_window,
                window_secs = self.config.audit_window.as_secs(),
                "IPC audit rate limit reached; further audit rows of this namespace are counted, not written, until the window ends"
            );
        }
        if adm.write {
            self.audit.record(ev);
        }
        adm.write
    }

    /// Write the summary rows of every audit window that has ended.
    pub(crate) fn flush_audit_summaries(&self) {
        for s in self.audit_limiter.drain_expired(Instant::now()) {
            self.write_suppressed_summary(s);
        }
    }

    fn write_suppressed_summary(&self, s: Suppressed) {
        tracing::warn!(
            ipc_key = %sanitize_for_log(&s.ipc_key),
            suppressed = s.count,
            "IPC audit rows were suppressed by the rate limit"
        );
        self.audit.record(event(
            SUPPRESSED_KIND,
            &s.folder,
            None,
            "suppressed",
            json!({
                "ipcKey": s.ipc_key,
                "suppressed_since_last": s.count,
                "byKind": s.by_kind,
                "limit": self.config.audit_max_per_window,
                "windowSecs": self.config.audit_window.as_secs(),
            }),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(60);

    #[test]
    fn budget_then_suppress_then_summary() {
        let l = AuditLimiter::new(3, W);
        let t0 = Instant::now();
        for _ in 0..3 {
            let a = l.admit("k", "f", "ipc.message.denied", false, t0);
            assert!(a.write && a.summary.is_none());
        }
        let a = l.admit("k", "f", "ipc.message.denied", false, t0);
        assert!(!a.write && a.first_suppressed);
        let a = l.admit(
            "k",
            "f",
            "ipc.file.rejected",
            false,
            t0 + Duration::from_secs(1),
        );
        assert!(!a.write && !a.first_suppressed);
        // next window: the summary comes with the first new row
        let a = l.admit("k", "f", "ipc.message.denied", false, t0 + W);
        assert!(a.write);
        let s = a.summary.unwrap();
        assert_eq!(s.count, 2);
        assert_eq!(s.ipc_key, "k");
        assert_eq!(s.folder, "f");
        assert_eq!(s.by_kind["ipc.message.denied"], 1);
        assert_eq!(s.by_kind["ipc.file.rejected"], 1);
        // and only once
        let a = l.admit("k", "f", "ipc.message.denied", false, t0 + W);
        assert!(a.write && a.summary.is_none());
    }

    #[test]
    fn namespaces_have_separate_budgets() {
        let l = AuditLimiter::new(1, W);
        let t0 = Instant::now();
        assert!(l.admit("alice", "copilot", "x", false, t0).write);
        assert!(!l.admit("alice", "copilot", "x", false, t0).write);
        assert!(l.admit("bob", "copilot", "x", false, t0).write);
    }

    #[test]
    fn priority_rows_are_always_written_but_consume_budget() {
        let l = AuditLimiter::new(2, W);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(l.admit("k", "f", "ipc.task.allowed", true, t0).write);
        }
        assert!(!l.admit("k", "f", "ipc.task.denied", false, t0).write);
    }

    #[test]
    fn drain_reports_and_forgets_expired_windows() {
        let l = AuditLimiter::new(1, W);
        let t0 = Instant::now();
        l.admit("a", "fa", "x", false, t0);
        l.admit("a", "fa", "x", false, t0);
        l.admit("a", "fa", "x", false, t0);
        l.admit("b", "fb", "x", false, t0);
        assert!(l.drain_expired(t0 + Duration::from_secs(1)).is_empty());
        let out = l.drain_expired(t0 + W);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ipc_key, "a");
        assert_eq!(out[0].count, 2);
        assert!(l.buckets.lock().unwrap().is_empty());
        // a fresh window starts with a full budget and no stale summary
        let a = l.admit("a", "fa", "x", false, t0 + W);
        assert!(a.write && a.summary.is_none());
    }

    #[test]
    fn zero_limit_disables() {
        let l = AuditLimiter::new(0, W);
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert!(l.admit("k", "f", "x", false, t0).write);
        }
        assert!(l.drain_expired(t0 + W).is_empty());
    }
}
