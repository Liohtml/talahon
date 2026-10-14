//! In-process counters and the Prometheus text exposition for `/metrics`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use talon_core::channel::QueueStatus;

/// Monotonic counters updated by the request handlers.
#[derive(Debug, Default)]
pub(crate) struct Metrics {
    responses: Mutex<BTreeMap<u16, u64>>,
    pub auth_failures: AtomicU64,
    pub auth_throttled: AtomicU64,
    pub messages: AtomicU64,
    pub investigations_created: AtomicU64,
    pub investigations_deduplicated: AtomicU64,
    pub palace_ok: AtomicU64,
    pub palace_failed: AtomicU64,
    pub sse_dropped_chunks: AtomicU64,
}

impl Metrics {
    /// Count a response by status code.
    pub(crate) fn record_response(&self, status: u16) {
        let mut map = self.responses.lock().unwrap_or_else(|e| e.into_inner());
        *map.entry(status).or_insert(0) += 1;
    }

    pub(crate) fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Point-in-time gauges gathered by the `/metrics` handler.
#[derive(Debug, Default, Clone)]
pub(crate) struct Gauges {
    pub uptime_seconds: u64,
    pub queue: QueueStatus,
    pub sse_pending: usize,
    pub sse_active: usize,
    pub lanes_in_turn: usize,
    pub user_lanes: usize,
    /// Status counts over the most recent investigations, when the store
    /// answered.
    pub investigations_by_status: Option<BTreeMap<String, u64>>,
    pub investigations_window: usize,
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn sample(out: &mut String, name: &str, labels: &str, value: impl std::fmt::Display) {
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
    } else {
        let _ = writeln!(out, "{name}{{{labels}}} {value}");
    }
}

/// Escape a label value per the exposition format.
fn label_value(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Render Prometheus text format v0.0.4.
pub(crate) fn render(m: &Metrics, g: &Gauges) -> String {
    let mut out = String::with_capacity(4096);

    header(
        &mut out,
        "talon_http_uptime_seconds",
        "gauge",
        "Seconds since the HTTP channel started.",
    );
    sample(&mut out, "talon_http_uptime_seconds", "", g.uptime_seconds);

    header(
        &mut out,
        "talon_queue_active_containers",
        "gauge",
        "Agent containers currently running.",
    );
    sample(
        &mut out,
        "talon_queue_active_containers",
        "",
        g.queue.active_containers,
    );
    header(
        &mut out,
        "talon_queue_max_containers",
        "gauge",
        "Configured container concurrency limit.",
    );
    sample(
        &mut out,
        "talon_queue_max_containers",
        "",
        g.queue.max_containers,
    );
    header(
        &mut out,
        "talon_queue_waiting_groups",
        "gauge",
        "Lanes waiting for a container slot.",
    );
    sample(
        &mut out,
        "talon_queue_waiting_groups",
        "",
        g.queue.waiting_groups,
    );

    header(
        &mut out,
        "talon_http_sse_streams",
        "gauge",
        "Open SSE streams by state.",
    );
    sample(
        &mut out,
        "talon_http_sse_streams",
        "state=\"pending\"",
        g.sse_pending,
    );
    sample(
        &mut out,
        "talon_http_sse_streams",
        "state=\"active\"",
        g.sse_active,
    );
    header(
        &mut out,
        "talon_http_lanes_in_turn",
        "gauge",
        "CoPilot lanes with an agent turn in progress.",
    );
    sample(&mut out, "talon_http_lanes_in_turn", "", g.lanes_in_turn);
    header(
        &mut out,
        "talon_http_user_lanes",
        "gauge",
        "Registered per-user CoPilot lanes.",
    );
    sample(&mut out, "talon_http_user_lanes", "", g.user_lanes);

    header(
        &mut out,
        "talon_http_responses_total",
        "counter",
        "HTTP responses by status code.",
    );
    {
        let map = m.responses.lock().unwrap_or_else(|e| e.into_inner());
        for (code, n) in map.iter() {
            sample(
                &mut out,
                "talon_http_responses_total",
                &format!("code=\"{code}\""),
                n,
            );
        }
    }
    header(
        &mut out,
        "talon_http_auth_failures_total",
        "counter",
        "Rejected API key presentations.",
    );
    sample(
        &mut out,
        "talon_http_auth_failures_total",
        "",
        Metrics::get(&m.auth_failures),
    );
    header(
        &mut out,
        "talon_http_auth_throttled_total",
        "counter",
        "Requests refused by the per-IP auth-failure throttle.",
    );
    sample(
        &mut out,
        "talon_http_auth_throttled_total",
        "",
        Metrics::get(&m.auth_throttled),
    );
    header(
        &mut out,
        "talon_http_messages_total",
        "counter",
        "Chat messages accepted on POST /message.",
    );
    sample(
        &mut out,
        "talon_http_messages_total",
        "",
        Metrics::get(&m.messages),
    );
    header(
        &mut out,
        "talon_http_sse_dropped_chunks_total",
        "counter",
        "Agent output chunks dropped because a stream buffer was full.",
    );
    sample(
        &mut out,
        "talon_http_sse_dropped_chunks_total",
        "",
        Metrics::get(&m.sse_dropped_chunks),
    );
    header(
        &mut out,
        "talon_investigations_created_total",
        "counter",
        "Investigation jobs queued by this process.",
    );
    sample(
        &mut out,
        "talon_investigations_created_total",
        "",
        Metrics::get(&m.investigations_created),
    );
    header(
        &mut out,
        "talon_investigations_deduplicated_total",
        "counter",
        "Investigation triggers answered with an existing job.",
    );
    sample(
        &mut out,
        "talon_investigations_deduplicated_total",
        "",
        Metrics::get(&m.investigations_deduplicated),
    );
    header(
        &mut out,
        "talon_palace_calls_total",
        "counter",
        "MemPalace calls by outcome.",
    );
    sample(
        &mut out,
        "talon_palace_calls_total",
        "outcome=\"ok\"",
        Metrics::get(&m.palace_ok),
    );
    sample(
        &mut out,
        "talon_palace_calls_total",
        "outcome=\"error\"",
        Metrics::get(&m.palace_failed),
    );

    if let Some(by_status) = &g.investigations_by_status {
        header(
            &mut out,
            "talon_investigations_recent",
            "gauge",
            &format!(
                "Investigations by status among the {} most recent jobs.",
                g.investigations_window
            ),
        );
        for (status, n) in by_status {
            sample(
                &mut out,
                "talon_investigations_recent",
                &format!("status=\"{}\"", label_value(status)),
                n,
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_exposition_lines() {
        let m = Metrics::default();
        m.record_response(200);
        m.record_response(200);
        m.record_response(401);
        Metrics::inc(&m.auth_failures);
        let mut by_status = BTreeMap::new();
        by_status.insert("queued".to_string(), 2);
        by_status.insert("we\"ird".to_string(), 1);
        let g = Gauges {
            uptime_seconds: 42,
            queue: QueueStatus {
                active_containers: 1,
                max_containers: 5,
                waiting_groups: 2,
                active_jids: vec![],
            },
            investigations_by_status: Some(by_status),
            investigations_window: 1000,
            ..Gauges::default()
        };
        let text = render(&m, &g);
        assert!(text.contains("talon_http_uptime_seconds 42\n"));
        assert!(text.contains("talon_queue_max_containers 5\n"));
        assert!(text.contains("talon_http_responses_total{code=\"200\"} 2\n"));
        assert!(text.contains("talon_http_responses_total{code=\"401\"} 1\n"));
        assert!(text.contains("talon_http_auth_failures_total 1\n"));
        assert!(text.contains("talon_investigations_recent{status=\"queued\"} 2\n"));
        assert!(text.contains("talon_investigations_recent{status=\"we\\\"ird\"} 1\n"));
        for line in text.lines() {
            assert!(
                line.starts_with("# HELP ")
                    || line.starts_with("# TYPE ")
                    || line.starts_with("talon_"),
                "{line}"
            );
        }
    }

    #[test]
    fn investigations_gauge_is_omitted_without_store_data() {
        let text = render(&Metrics::default(), &Gauges::default());
        assert!(!text.contains("talon_investigations_recent"));
    }
}
