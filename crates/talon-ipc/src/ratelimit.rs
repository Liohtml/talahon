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
//! Executed task operations (schedule/pause/resume/cancel/update,
//! `register_group`, `refresh_groups`) are state changes and are always
//! written ("priority" rows); they still consume budget so a namespace that
//! floods them cannot also flood denials.
//!
//! Because priority rows bypass the audit budget, the operations themselves
//! are rate-limited too (N-3): [`TaskOpLimiter`] gives each namespace a
//! budget of executed task operations per window
//! ([`IpcWatcherConfig::max_task_ops_per_window`], higher for main). A
//! permit is taken right before an authorized, valid operation would change
//! state and handed back when it ends up not executing. Requests over the
//! budget are denied **without being executed** and without a row of their
//! own; they are counted per request type and reported as one
//! `ipc.task.throttled` summary row per namespace and window. Every executed
//! operation therefore still has its audit row, and the number of priority
//! rows per window is bounded.
//!
//! [`IpcWatcherConfig::max_task_ops_per_window`]: crate::IpcWatcherConfig::max_task_ops_per_window

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::json;
use talon_core::audit::event;
use talon_core::types::AuditEvent;

use crate::host::SourceIdentity;
use crate::json::sanitize_for_log;
use crate::process::IpcOutcome;
use crate::watcher::IpcWatcher;

/// Audit kind of the summary row written after a window with suppressions.
pub(crate) const SUPPRESSED_KIND: &str = "ipc.audit.suppressed";

/// Audit kind of the summary row written after a window in which task
/// operations were throttled (N-3).
pub(crate) const THROTTLED_KIND: &str = "ipc.task.throttled";

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
        self.drain(Some(now))
    }

    /// Close every window, ended or not (shutdown).
    pub fn drain_all(&self) -> Vec<Suppressed> {
        self.drain(None)
    }

    fn drain(&self, now: Option<Instant>) -> Vec<Suppressed> {
        if self.disabled() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        buckets.retain(|key, bucket| {
            if now
                .is_some_and(|now| now.saturating_duration_since(bucket.window_start) < self.window)
            {
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

/// Task operations of one namespace refused by [`TaskOpLimiter`] during one
/// window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Throttled {
    /// The namespace.
    pub ipc_key: String,
    /// Its group folder (audit actor).
    pub folder: String,
    /// Whether the namespace belongs to the main group.
    pub is_main: bool,
    /// The budget that applied.
    pub limit: usize,
    /// Number of refused requests.
    pub count: u64,
    /// Refused requests per request type (`schedule_task`, ...).
    pub by_type: BTreeMap<String, u64>,
}

#[derive(Debug)]
struct OpBucket {
    folder: String,
    is_main: bool,
    limit: usize,
    window_start: Instant,
    /// Identifies the window; permits of an older window are not refunded
    /// into a newer one.
    generation: u64,
    used: usize,
    throttled: u64,
    by_type: BTreeMap<String, u64>,
}

impl OpBucket {
    fn summary(&mut self, ipc_key: &str) -> Option<Throttled> {
        if self.throttled == 0 {
            return None;
        }
        let s = Throttled {
            ipc_key: ipc_key.to_string(),
            folder: self.folder.clone(),
            is_main: self.is_main,
            limit: self.limit,
            count: self.throttled,
            by_type: std::mem::take(&mut self.by_type),
        };
        self.throttled = 0;
        Some(s)
    }
}

#[derive(Debug, Default)]
struct OpState {
    next_generation: u64,
    buckets: HashMap<String, OpBucket>,
}

/// One unit of a namespace's task-operation budget, taken right before an
/// operation changes state. Hand it back with [`TaskOpLimiter::release`]
/// when the operation did not execute after all.
#[derive(Debug)]
#[must_use = "an unused permit should be released"]
pub(crate) struct OpPermit {
    /// `(ipc_key, window generation)`; `None` when the namespace has no
    /// limit.
    slot: Option<(String, u64)>,
}

/// Decision for one task operation.
#[derive(Debug)]
pub(crate) enum OpAdmission {
    /// Within budget: execute.
    Granted {
        /// The budget unit taken.
        permit: OpPermit,
        /// Summary of the namespace's previous window, to be written first.
        summary: Option<Throttled>,
    },
    /// Over budget: deny without executing.
    Throttled {
        /// First refusal of the namespace's current window (worth one log
        /// line).
        first: bool,
        /// Summary of the namespace's previous window, to be written first.
        summary: Option<Throttled>,
    },
}

/// Fixed-window, per-namespace budget of executed task operations (N-3).
#[derive(Debug)]
pub(crate) struct TaskOpLimiter {
    window: Duration,
    state: Mutex<OpState>,
}

impl TaskOpLimiter {
    /// A zero `window` disables the limiter.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            state: Mutex::new(OpState::default()),
        }
    }

    /// Take one unit of `ipc_key`'s budget for a request of type `op`.
    /// `limit` is the namespace's budget per window (`None`: unlimited).
    pub fn acquire(
        &self,
        source: &SourceIdentity,
        limit: Option<usize>,
        op: &str,
        now: Instant,
    ) -> OpAdmission {
        let Some(limit) = limit.filter(|_| !self.window.is_zero()) else {
            return OpAdmission::Granted {
                permit: OpPermit { slot: None },
                summary: None,
            };
        };
        // A poisoned lock only means another thread panicked mid-update;
        // the counters are still usable.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let OpState {
            next_generation,
            buckets,
        } = &mut *state;
        let mut new_bucket = |now: Instant| {
            *next_generation = next_generation.wrapping_add(1);
            OpBucket {
                folder: source.folder.clone(),
                is_main: source.is_main,
                limit,
                window_start: now,
                generation: *next_generation,
                used: 0,
                throttled: 0,
                by_type: BTreeMap::new(),
            }
        };
        let mut summary = None;
        let bucket = match buckets.entry(source.ipc_key.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => {
                let bucket = e.into_mut();
                if now.saturating_duration_since(bucket.window_start) >= self.window {
                    summary = bucket.summary(&source.ipc_key);
                    *bucket = new_bucket(now);
                }
                bucket
            }
            std::collections::hash_map::Entry::Vacant(e) => e.insert(new_bucket(now)),
        };
        bucket.limit = limit;
        if bucket.used < limit {
            bucket.used = bucket.used.saturating_add(1);
            OpAdmission::Granted {
                permit: OpPermit {
                    slot: Some((source.ipc_key.clone(), bucket.generation)),
                },
                summary,
            }
        } else {
            bucket.throttled = bucket.throttled.saturating_add(1);
            let n = bucket.by_type.entry(op.to_string()).or_insert(0);
            *n = n.saturating_add(1);
            OpAdmission::Throttled {
                first: bucket.throttled == 1,
                summary,
            }
        }
    }

    /// Hand back a permit whose operation did not execute (denied or
    /// rejected after the permit was taken). No-op once its window ended.
    pub fn release(&self, permit: OpPermit) {
        let Some((key, generation)) = permit.slot else {
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(bucket) = state.buckets.get_mut(&key) {
            if bucket.generation == generation {
                bucket.used = bucket.used.saturating_sub(1);
            }
        }
    }

    /// Close every window that has ended (or all of them with
    /// `force`): return the summaries of those with throttled requests and
    /// forget them (keeps the map bounded by the number of recently active
    /// namespaces).
    pub fn drain(&self, now: Instant, force: bool) -> Vec<Throttled> {
        let mut out = Vec::new();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.buckets.retain(|key, bucket| {
            if !force && now.saturating_duration_since(bucket.window_start) < self.window {
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
    /// Take one unit of `source`'s task-operation budget for a request of
    /// type `op`, right before it is executed. Over budget, the request is
    /// denied: it is counted for the namespace's `ipc.task.throttled`
    /// summary row instead of being audited on its own.
    pub(crate) fn acquire_task_op(
        &self,
        source: &SourceIdentity,
        op: &str,
    ) -> Result<OpPermit, IpcOutcome> {
        let limit = self.config.task_op_limit(source.is_main);
        match self
            .task_op_limiter
            .acquire(source, limit, op, Instant::now())
        {
            OpAdmission::Granted { permit, summary } => {
                if let Some(s) = summary {
                    self.write_throttled_summary(s);
                }
                Ok(permit)
            }
            OpAdmission::Throttled { first, summary } => {
                if let Some(s) = summary {
                    self.write_throttled_summary(s);
                }
                let limit = limit.unwrap_or_default();
                let window = self.config.task_op_window.as_secs();
                if first {
                    tracing::warn!(
                        ipc_key = %sanitize_for_log(&source.ipc_key),
                        limit,
                        window_secs = window,
                        "IPC task operation rate limit reached; further task operations of this namespace are denied until the window ends"
                    );
                }
                Err(IpcOutcome::Denied(format!(
                    "task operation rate limit exceeded ({limit} per {window} s); try again later"
                )))
            }
        }
    }

    /// Hand back a permit whose operation did not execute.
    pub(crate) fn release_task_op(&self, permit: OpPermit) {
        self.task_op_limiter.release(permit);
    }

    fn write_throttled_summary(&self, s: Throttled) {
        tracing::warn!(
            ipc_key = %sanitize_for_log(&s.ipc_key),
            throttled = s.count,
            "IPC task operations were denied by the rate limit"
        );
        self.audit.record(event(
            THROTTLED_KIND,
            &s.folder,
            None,
            "denied",
            json!({
                "ipcKey": s.ipc_key,
                "isMain": s.is_main,
                "throttled_since_last": s.count,
                "byType": s.by_type,
                "limit": s.limit,
                "windowSecs": self.config.task_op_window.as_secs(),
            }),
        ));
    }

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

    /// Write the summary rows of every audit and task-operation window
    /// that has ended (all of them with `force`, used on shutdown so no
    /// count is lost).
    pub(crate) fn flush_audit_summaries(&self, force: bool) {
        let now = Instant::now();
        let suppressed = if force {
            self.audit_limiter.drain_all()
        } else {
            self.audit_limiter.drain_expired(now)
        };
        for s in suppressed {
            self.write_suppressed_summary(s);
        }
        for s in self.task_op_limiter.drain(now, force) {
            self.write_throttled_summary(s);
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

    fn src(key: &str, is_main: bool) -> SourceIdentity {
        SourceIdentity {
            ipc_key: key.into(),
            folder: "copilot".into(),
            is_main,
        }
    }

    fn granted(a: OpAdmission) -> (OpPermit, Option<Throttled>) {
        match a {
            OpAdmission::Granted { permit, summary } => (permit, summary),
            OpAdmission::Throttled { .. } => panic!("expected a permit"),
        }
    }

    fn throttled(a: &OpAdmission) -> bool {
        matches!(a, OpAdmission::Throttled { .. })
    }

    #[test]
    fn op_budget_then_throttle_then_one_summary() {
        let l = TaskOpLimiter::new(W);
        let a = src("alice", false);
        let t0 = Instant::now();
        for _ in 0..2 {
            let (p, s) = granted(l.acquire(&a, Some(2), "schedule_task", t0));
            assert!(s.is_none());
            drop(p); // executed: keep the unit
        }
        let x = l.acquire(&a, Some(2), "schedule_task", t0);
        assert!(matches!(
            x,
            OpAdmission::Throttled {
                first: true,
                summary: None
            }
        ));
        let x = l.acquire(&a, Some(2), "pause_task", t0);
        assert!(matches!(x, OpAdmission::Throttled { first: false, .. }));
        // another namespace has its own budget
        let (_p, _) = granted(l.acquire(&src("bob", false), Some(2), "schedule_task", t0));
        // next window: fresh budget, and the summary comes with it, once
        let (_p, s) = granted(l.acquire(&a, Some(2), "cancel_task", t0 + W));
        let s = s.unwrap();
        assert_eq!(s.ipc_key, "alice");
        assert_eq!(s.folder, "copilot");
        assert!(!s.is_main);
        assert_eq!(s.limit, 2);
        assert_eq!(s.count, 2);
        assert_eq!(s.by_type["schedule_task"], 1);
        assert_eq!(s.by_type["pause_task"], 1);
        let (_p, s) = granted(l.acquire(&a, Some(2), "cancel_task", t0 + W));
        assert!(s.is_none());
        assert!(throttled(&l.acquire(&a, Some(2), "cancel_task", t0 + W)));
    }

    #[test]
    fn released_permits_return_their_unit() {
        let l = TaskOpLimiter::new(W);
        let a = src("alice", false);
        let t0 = Instant::now();
        for _ in 0..10 {
            let (p, _) = granted(l.acquire(&a, Some(1), "schedule_task", t0));
            l.release(p);
        }
        let (_kept, _) = granted(l.acquire(&a, Some(1), "schedule_task", t0));
        assert!(throttled(&l.acquire(&a, Some(1), "schedule_task", t0)));
    }

    #[test]
    fn permits_of_an_ended_window_are_not_refunded_into_the_next() {
        let l = TaskOpLimiter::new(W);
        let a = src("alice", false);
        let t0 = Instant::now();
        let (old, _) = granted(l.acquire(&a, Some(1), "schedule_task", t0));
        let (_new, _) = granted(l.acquire(&a, Some(1), "schedule_task", t0 + W));
        l.release(old);
        assert!(throttled(&l.acquire(&a, Some(1), "schedule_task", t0 + W)));
    }

    #[test]
    fn unlimited_namespaces_and_zero_window_never_throttle() {
        let a = src("main", true);
        let t0 = Instant::now();
        let l = TaskOpLimiter::new(W);
        for _ in 0..1000 {
            let (p, _) = granted(l.acquire(&a, None, "schedule_task", t0));
            l.release(p);
        }
        let l = TaskOpLimiter::new(Duration::ZERO);
        for _ in 0..1000 {
            let _ = granted(l.acquire(&a, Some(1), "schedule_task", t0));
        }
        assert!(l.drain(t0, true).is_empty());
    }

    #[test]
    fn op_drain_reports_expired_windows_and_all_on_force() {
        let l = TaskOpLimiter::new(W);
        let t0 = Instant::now();
        for key in ["a", "b"] {
            let s = src(key, key == "b");
            let _ = granted(l.acquire(&s, Some(1), "update_task", t0));
            assert!(throttled(&l.acquire(&s, Some(1), "update_task", t0)));
        }
        let _ = granted(l.acquire(&src("c", false), Some(1), "update_task", t0));
        assert!(l.drain(t0 + Duration::from_secs(1), false).is_empty());
        let out = l.drain(t0 + Duration::from_secs(1), true);
        assert_eq!(out.len(), 2);
        assert_eq!((out[0].ipc_key.as_str(), out[0].is_main), ("a", false));
        assert_eq!((out[1].ipc_key.as_str(), out[1].is_main), ("b", true));
        assert!(l.state.lock().unwrap().buckets.is_empty());
        // expired windows are closed without force
        assert!(throttled(&{
            let s = src("d", false);
            let _ = granted(l.acquire(&s, Some(1), "x", t0));
            l.acquire(&s, Some(1), "x", t0)
        }));
        let out = l.drain(t0 + W, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 1);
    }

    #[test]
    fn audit_drain_all_closes_open_windows() {
        let l = AuditLimiter::new(1, W);
        let t0 = Instant::now();
        l.admit("k", "f", "x", false, t0);
        l.admit("k", "f", "x", false, t0);
        assert!(l.drain_expired(t0).is_empty());
        let out = l.drain_all();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 1);
        assert!(l.drain_all().is_empty());
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
