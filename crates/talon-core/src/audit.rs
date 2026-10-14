//! Audit sink abstraction. Security-relevant decisions are reported through
//! an [`AuditSink`]; the host wires a sink that persists to the hash-chained
//! `audit_log` table (talon-db) and mirrors to `tracing`.

use std::sync::{Arc, Mutex};

use crate::time::now_iso;
use crate::types::AuditEvent;

pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
}

/// Shared handle type used across crates.
pub type SharedAuditSink = Arc<dyn AuditSink>;

/// Logs every event via `tracing` (target `talon::audit`).
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, e: AuditEvent) {
        if e.outcome == "denied" || e.outcome == "error" {
            tracing::warn!(target: "talon::audit", kind = %e.kind, actor = %e.actor, target_obj = ?e.target, outcome = %e.outcome, details = %e.details, "audit");
        } else {
            tracing::info!(target: "talon::audit", kind = %e.kind, actor = %e.actor, target_obj = ?e.target, outcome = %e.outcome, details = %e.details, "audit");
        }
    }
}

/// Collects events in memory (tests).
#[derive(Debug, Default, Clone)]
pub struct MemoryAuditSink {
    pub events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl MemoryAuditSink {
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        if let Ok(mut v) = self.events.lock() {
            v.push(event);
        }
    }
}

/// Convenience constructor.
pub fn event(
    kind: &str,
    actor: &str,
    target: Option<&str>,
    outcome: &str,
    details: serde_json::Value,
) -> AuditEvent {
    AuditEvent {
        timestamp: now_iso(),
        kind: kind.to_string(),
        actor: actor.to_string(),
        target: target.map(str::to_string),
        outcome: outcome.to_string(),
        details,
    }
}
