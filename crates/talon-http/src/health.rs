//! The health API CoPilot's health dashboard reads: `GET /v2/health`,
//! `GET /v2/health/history` and `GET /v2/health/metrics`.
//!
//! The wire shapes follow what CoPilot's dashboard parses (a status, a list
//! of components, history and metric buckets). CoPilot copies every field one
//! by one and treats each as optional, so this module reports **only what
//! Talahon measures** and leaves the rest out instead of sending zeros:
//!
//! - **Components.** `api` (this server), `database` (a timed read),
//!   `queue` (container slots and waiting lanes), plus whatever the host
//!   supplies through [`HealthProbe`] (the LLM gateway and the model server).
//!   The MCP servers are not listed: they run inside the agent containers and
//!   the host learns nothing about them.
//! - **History.** Every check is counted per component in fixed
//!   five-minute buckets. The buckets live in memory, are kept for seven days
//!   and **do not survive a restart**.
//! - **Metrics.** Finished and failed investigations and their duration come
//!   from the investigation table (bucketed by the time of the last status
//!   change; the duration runs from creation to that change, so it includes
//!   the time spent queued). The deepest queue per bucket comes from the
//!   in-memory samples. Tool calls, model errors and cost are not measured and
//!   therefore absent.
//!
//! A check is cached for [`CACHE_TTL`] and runs one at a time; every part has
//! its own deadline ([`CHECK_DEADLINE`]), so the routes answer even when the
//! database or the model server hangs. Texts are fixed: no error message of a
//! backend (which may name hosts) is relayed.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use serde_json::{Map, Value, json};
use talon_core::channel::QueueStatus;
use talon_core::time::parse_iso;
use talon_db::Investigation;
use tokio::sync::Mutex as AsyncMutex;

use crate::investigate::STATUS_FAILED;
use crate::server::{ApiError, HttpState};
use crate::store::run_blocking;

/// Width of a history / metrics bucket.
pub const BUCKET_MINUTES: i64 = 5;
const BUCKET_SECS: i64 = BUCKET_MINUTES * 60;
/// The windows the routes accept (`?hours=`), as CoPilot asks for them.
pub const ALLOWED_HOURS: [i64; 2] = [24, 168];
const DEFAULT_HOURS: i64 = 24;
/// History is kept this long.
const RETENTION_SECS: i64 = 168 * 3600;
/// How long one check is served from the cache.
pub const CACHE_TTL: Duration = Duration::from_secs(15);
/// Deadline of each part of a check.
pub const CHECK_DEADLINE: Duration = Duration::from_secs(4);
/// How often the background sampler checks, so the history has no holes
/// while nobody opens the dashboard.
pub(crate) const SAMPLE_PERIOD: Duration = Duration::from_secs(60);
/// Most recent investigations read for the metrics.
const METRICS_ROWS: usize = 20_000;
const STATUS_COMPLETED: &str = "completed";

/// The dashboard's component groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentGroup {
    /// Talahon itself: API, database, queue, gateway.
    Core,
    /// An MCP server.
    Mcp,
    /// The model server or provider.
    Model,
    /// Optional tools.
    Tools,
}

impl ComponentGroup {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Mcp => "mcp",
            Self::Model => "model",
            Self::Tools => "tools",
        }
    }
}

/// A component's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentStatus {
    /// Working.
    Ok,
    /// Working, but degraded or needing attention.
    Warn,
    /// Not working.
    Fail,
    /// Not configured or turned off on purpose.
    Off,
}

impl ComponentStatus {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Off => "off",
        }
    }
}

/// One component's check result.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentCheck {
    /// Stable id (`[A-Za-z0-9_.-]{1,64}`), also the history key.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Dashboard group.
    pub group: ComponentGroup,
    /// Result.
    pub status: ComponentStatus,
    /// How long the check took, when one was made.
    pub latency_ms: Option<f64>,
    /// One line on what was found. Must not hold secrets or host names.
    pub detail: Option<String>,
    /// What the operator can do about a problem.
    pub fix: Option<String>,
    /// A failure of this component means Talahon as a whole is `down`
    /// (otherwise a failure only makes it `degraded`).
    pub critical: bool,
}

impl ComponentCheck {
    /// A check with the given result and nothing else set.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        group: ComponentGroup,
        status: ComponentStatus,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            group,
            status,
            latency_ms: None,
            detail: None,
            fix: None,
            critical: false,
        }
    }

    /// Set the detail line.
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Set the fix text.
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    /// Mark a failure of this component as fatal for the overall state.
    pub fn critical(mut self) -> Self {
        self.critical = true;
        self
    }

    /// Set the measured latency.
    pub fn latency(mut self, elapsed: Duration) -> Self {
        self.latency_ms = Some(millis(elapsed));
        self
    }
}

/// The models Talahon is configured to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthModels {
    /// Model answering chat.
    pub chat: String,
    /// Model running investigations.
    pub investigation: String,
}

/// Health checks the host adds to the channel's own (the LLM gateway, the
/// model server): the HTTP channel cannot reach those itself.
#[async_trait]
pub trait HealthProbe: Send + Sync {
    /// Id of the component reported when [`Self::check`] misses its deadline.
    fn id(&self) -> &str;
    /// Display name of that component.
    fn name(&self) -> &str;
    /// Group of that component.
    fn group(&self) -> ComponentGroup;
    /// Run the check. Bounded by [`CHECK_DEADLINE`] from outside; may return
    /// several components.
    async fn check(&self) -> Vec<ComponentCheck>;
    /// The configured models, when this probe knows them.
    fn models(&self) -> Option<HealthModels> {
        None
    }
}

/// The overall state: `down` when a critical component fails, `degraded`
/// when any component warns or fails, else `ok`.
pub fn overall(components: &[ComponentCheck]) -> &'static str {
    if components
        .iter()
        .any(|c| c.critical && c.status == ComponentStatus::Fail)
    {
        "down"
    } else if components
        .iter()
        .any(|c| matches!(c.status, ComponentStatus::Warn | ComponentStatus::Fail))
    {
        "degraded"
    } else {
        "ok"
    }
}

fn millis(elapsed: Duration) -> f64 {
    (elapsed.as_secs_f64() * 10_000.0).round() / 10.0
}

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn bucket_of(t: DateTime<Utc>) -> i64 {
    t.timestamp().div_euclid(BUCKET_SECS) * BUCKET_SECS
}

fn bucket_iso(start: i64) -> Option<String> {
    Utc.timestamp_opt(start, 0).single().map(iso)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Bucket {
    /// Per component: checks that came back ok, warn, fail.
    components: BTreeMap<String, [u64; 3]>,
    /// Deepest queue (waiting lanes) seen in the bucket.
    queue_depth_max: u64,
}

/// Check counts per component in five-minute buckets (in memory, seven days).
#[derive(Debug, Default)]
pub(crate) struct History {
    buckets: BTreeMap<i64, Bucket>,
}

impl History {
    /// Count one check. `off` components are not counted: they were not
    /// checked.
    pub(crate) fn record(
        &mut self,
        at: DateTime<Utc>,
        components: &[ComponentCheck],
        waiting: u64,
    ) {
        let start = bucket_of(at);
        let bucket = self.buckets.entry(start).or_default();
        bucket.queue_depth_max = bucket.queue_depth_max.max(waiting);
        for c in components {
            let slot = match c.status {
                ComponentStatus::Ok => 0,
                ComponentStatus::Warn => 1,
                ComponentStatus::Fail => 2,
                ComponentStatus::Off => continue,
            };
            bucket.components.entry(c.id.clone()).or_default()[slot] += 1;
        }
        let oldest = start - RETENTION_SECS;
        self.buckets = self.buckets.split_off(&oldest);
    }

    /// The `/v2/health/history` body for the last `hours`.
    pub(crate) fn to_json(&self, now: DateTime<Utc>, hours: i64) -> Value {
        let from = bucket_of(now) - hours * 3600;
        let mut components: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
        for (start, bucket) in self.buckets.range(from..) {
            let Some(t) = bucket_iso(*start) else {
                continue;
            };
            for (id, [ok, warn, fail]) in &bucket.components {
                components
                    .entry(id.as_str())
                    .or_default()
                    .push(json!({ "t": t, "ok": ok, "warn": warn, "fail": fail }));
            }
        }
        json!({ "bucket_minutes": BUCKET_MINUTES, "components": components })
    }

    fn queue_depths(&self, from: i64) -> HashMap<i64, u64> {
        self.buckets
            .range(from..)
            .map(|(start, b)| (*start, b.queue_depth_max))
            .collect()
    }
}

/// Nearest-rank percentile of a sorted, non-empty slice.
fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted.get(rank.clamp(1, sorted.len()) - 1).copied()
}

/// The `/v2/health/metrics` body: one entry per bucket of the last `hours`.
///
/// `investigations` are the most recent rows, `truncated` says the read hit
/// its row limit: then buckets older than the oldest row carry no
/// investigation numbers (they would be undercounted). `queue_depths` holds
/// the sampled buckets only.
pub(crate) fn metrics_json(
    now: DateTime<Utc>,
    hours: i64,
    investigations: &[Investigation],
    truncated: bool,
    queue_depths: &HashMap<i64, u64>,
) -> Value {
    let last = bucket_of(now);
    let from = last - hours * 3600;
    #[derive(Default)]
    struct Counts {
        completed: u64,
        failed: u64,
        durations: Vec<f64>,
    }
    let mut counts: HashMap<i64, Counts> = HashMap::new();
    let mut oldest_row: Option<i64> = None;
    for inv in investigations {
        let Some(changed) = parse_iso(&inv.updated_at) else {
            continue;
        };
        let start = bucket_of(changed);
        oldest_row = Some(oldest_row.map_or(start, |o: i64| o.min(start)));
        if start < from || start > last {
            continue;
        }
        let entry = counts.entry(start).or_default();
        if inv.status == STATUS_COMPLETED {
            entry.completed += 1;
            if let Some(created) = parse_iso(&inv.created_at) {
                let secs = (changed - created).num_milliseconds() as f64 / 1000.0;
                if secs >= 0.0 {
                    entry.durations.push(secs);
                }
            }
        } else if inv.status == STATUS_FAILED {
            entry.failed += 1;
        }
    }
    // With a truncated read, the bucket holding the oldest row is itself
    // incomplete.
    let counted_from = match (truncated, oldest_row) {
        (true, Some(oldest)) => oldest + BUCKET_SECS,
        _ => from,
    };
    let mut series = Vec::new();
    let mut start = from;
    while start <= last {
        let mut row = Map::new();
        if start >= counted_from {
            let c = counts.remove(&start).unwrap_or_default();
            row.insert("investigations_completed".into(), json!(c.completed));
            row.insert("investigations_failed".into(), json!(c.failed));
            let mut durations = c.durations;
            durations.sort_by(f64::total_cmp);
            if let Some(p50) = percentile(&durations, 50.0) {
                row.insert("duration_p50_s".into(), json!(p50));
            }
            if let Some(p95) = percentile(&durations, 95.0) {
                row.insert("duration_p95_s".into(), json!(p95));
            }
        }
        if let Some(depth) = queue_depths.get(&start) {
            row.insert("queue_depth_max".into(), json!(depth));
        }
        if let (false, Some(t)) = (row.is_empty(), bucket_iso(start)) {
            row.insert("t".into(), json!(t));
            series.push(Value::Object(row));
        }
        start += BUCKET_SECS;
    }
    json!({ "bucket_minutes": BUCKET_MINUTES, "series": series })
}

/// One finished check.
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    pub checked_at: DateTime<Utc>,
    pub components: Vec<ComponentCheck>,
}

/// The cache and the history behind the health routes.
#[derive(Default)]
pub(crate) struct HealthState {
    // tokio's clock, so tests can advance it.
    cache: AsyncMutex<Option<(tokio::time::Instant, Arc<Snapshot>)>>,
    history: Mutex<History>,
}

impl HealthState {
    fn history(&self) -> std::sync::MutexGuard<'_, History> {
        self.history.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn queue_component(q: &QueueStatus) -> ComponentCheck {
    let detail = format!(
        "{} of {} agent containers running, {} lane(s) waiting",
        q.active_containers, q.max_containers, q.waiting_groups
    );
    let busy = q.waiting_groups > 0;
    let check = ComponentCheck::new(
        "queue",
        "Agent queue",
        ComponentGroup::Core,
        if busy {
            ComponentStatus::Warn
        } else {
            ComponentStatus::Ok
        },
    )
    .detail(detail);
    if busy {
        check.fix(
            "Work is waiting for a free agent container. It clears by itself when the running \
             turns finish; if it stays, raise MAX_CONCURRENT_CONTAINERS in .env (and the model \
             server's capacity) and restart Talahon.",
        )
    } else {
        check
    }
}

async fn database_component(st: &HttpState) -> ComponentCheck {
    let started = Instant::now();
    let read = tokio::time::timeout(
        CHECK_DEADLINE,
        run_blocking(&st.0.store, |store| store.investigation_status_counts()),
    )
    .await;
    let base = |status| {
        ComponentCheck::new("database", "Database", ComponentGroup::Core, status)
            .critical()
            .latency(started.elapsed())
    };
    const FIX: &str = "Check that the store directory is writable and the disk is not full, then \
                       run `talahon doctor` and restart Talahon.";
    match read {
        Ok(Ok(counts)) => {
            let total: u64 = counts.values().sum();
            base(ComponentStatus::Ok).detail(format!("Read {total} investigation(s)"))
        }
        Ok(Err(e)) => {
            tracing::warn!(err = %e, "health: the database read failed");
            base(ComponentStatus::Fail)
                .detail("The database read failed")
                .fix(FIX)
        }
        Err(_) => base(ComponentStatus::Fail)
            .detail(format!(
                "The database did not answer within {} s",
                CHECK_DEADLINE.as_secs()
            ))
            .fix(FIX),
    }
}

async fn probe_components(probe: &Arc<dyn HealthProbe>) -> Vec<ComponentCheck> {
    match tokio::time::timeout(CHECK_DEADLINE, probe.check()).await {
        Ok(components) => components,
        Err(_) => vec![
            ComponentCheck::new(
                probe.id(),
                probe.name(),
                probe.group(),
                ComponentStatus::Fail,
            )
            .detail(format!(
                "The check did not finish within {} s",
                CHECK_DEADLINE.as_secs()
            )),
        ],
    }
}

fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl HttpState {
    /// The current health check: cached for [`CACHE_TTL`], one run at a
    /// time. A fresh run is counted in the history.
    pub(crate) async fn health_snapshot(&self) -> Arc<Snapshot> {
        let s = &self.0;
        let mut cache = s.health.cache.lock().await;
        if let Some((at, snapshot)) = cache.as_ref()
            && at.elapsed() < CACHE_TTL
        {
            return Arc::clone(snapshot);
        }
        let queue = s.host.queue_status();
        let mut components = vec![
            ComponentCheck::new(
                "api",
                "Talahon API",
                ComponentGroup::Core,
                ComponentStatus::Ok,
            )
            .critical()
            .detail("The HTTP channel is answering"),
        ];
        let (database, probed) = tokio::join!(
            database_component(self),
            futures::future::join_all(s.probes.iter().map(probe_components)),
        );
        components.push(database);
        components.push(queue_component(&queue));
        for check in probed.into_iter().flatten() {
            if valid_id(&check.id) && !components.iter().any(|c| c.id == check.id) {
                components.push(check);
            }
        }
        let snapshot = Arc::new(Snapshot {
            checked_at: Utc::now(),
            components,
        });
        s.health.history().record(
            snapshot.checked_at,
            &snapshot.components,
            queue.waiting_groups as u64,
        );
        *cache = Some((tokio::time::Instant::now(), Arc::clone(&snapshot)));
        snapshot
    }
}

fn component_json(c: &ComponentCheck, checked_at: &str) -> Value {
    let mut row = Map::new();
    row.insert("id".into(), json!(c.id));
    row.insert("name".into(), json!(c.name));
    row.insert("group".into(), json!(c.group.as_str()));
    row.insert("status".into(), json!(c.status.as_str()));
    if let Some(latency) = c.latency_ms {
        row.insert("latency_ms".into(), json!(latency));
    }
    if let Some(detail) = &c.detail {
        row.insert("detail".into(), json!(detail));
    }
    if let Some(fix) = &c.fix {
        row.insert("fix".into(), json!(fix));
    }
    row.insert("checked_at".into(), json!(checked_at));
    Value::Object(row)
}

/// `GET /v2/health`.
pub(crate) async fn health_v2(State(st): State<HttpState>) -> Response {
    let snapshot = st.health_snapshot().await;
    let checked_at = iso(snapshot.checked_at);
    let components: Vec<Value> = snapshot
        .components
        .iter()
        .map(|c| component_json(c, &checked_at))
        .collect();
    // Only what Talahon knows: it has none of talon-analyst's v2 API, so the
    // switch is reported off; write-back mode, budgets and the other
    // switches do not exist here and are left out.
    let mut config = Map::new();
    config.insert("v2_api".into(), json!(false));
    if let Some(models) = st.0.probes.iter().find_map(|p| p.models()) {
        config.insert(
            "models".into(),
            json!({ "chat": models.chat, "investigation": models.investigation }),
        );
    }
    Json(json!({
        "status": overall(&snapshot.components),
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": st.0.started_at.elapsed().as_secs(),
        "checked_at": checked_at,
        "components": components,
        "config": config,
    }))
    .into_response()
}

fn hours_param(
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<i64, ApiError> {
    let Query(params) = query.map_err(|_| ApiError::bad_request("invalid query string"))?;
    match params.get("hours") {
        None => Ok(DEFAULT_HOURS),
        Some(raw) => raw
            .parse::<i64>()
            .ok()
            .filter(|h| ALLOWED_HOURS.contains(h))
            .ok_or_else(|| ApiError::bad_request("hours must be 24 or 168")),
    }
}

/// `GET /v2/health/history?hours=24|168`.
pub(crate) async fn health_history(
    State(st): State<HttpState>,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<Response, ApiError> {
    let hours = hours_param(query)?;
    Ok(Json(st.0.health.history().to_json(Utc::now(), hours)).into_response())
}

/// `GET /v2/health/metrics?hours=24|168`.
pub(crate) async fn health_metrics(
    State(st): State<HttpState>,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<Response, ApiError> {
    let hours = hours_param(query)?;
    let rows = tokio::time::timeout(
        CHECK_DEADLINE,
        run_blocking(&st.0.store, |store| store.list_investigations(METRICS_ROWS)),
    )
    .await
    .map_err(|_| ApiError::internal("failed to read metrics"))?
    .map_err(|e| {
        tracing::error!(err = %e, "GET /v2/health/metrics failed");
        ApiError::internal("failed to read metrics")
    })?;
    let now = Utc::now();
    let depths =
        st.0.health
            .history()
            .queue_depths(bucket_of(now) - hours * 3600);
    let truncated = rows.len() >= METRICS_ROWS;
    Ok(Json(metrics_json(now, hours, &rows, truncated, &depths)).into_response())
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use chrono::Duration as ChronoDuration;

    use super::*;
    use crate::testutil::*;

    fn at(s: &str) -> DateTime<Utc> {
        parse_iso(s).unwrap()
    }

    fn check(id: &str, status: ComponentStatus) -> ComponentCheck {
        ComponentCheck::new(id, id, ComponentGroup::Core, status)
    }

    fn investigation(id: &str, status: &str, created: &str, updated: &str) -> Investigation {
        Investigation {
            id: id.into(),
            alert_id: "1".into(),
            customer_code: "acme".into(),
            triggered_by: "webhook".into(),
            status: status.into(),
            template: None,
            created_at: created.into(),
            updated_at: updated.into(),
            verdict: None,
            error: None,
        }
    }

    struct FixedProbe(Vec<ComponentCheck>);

    #[async_trait]
    impl HealthProbe for FixedProbe {
        fn id(&self) -> &str {
            "model"
        }
        fn name(&self) -> &str {
            "Model server"
        }
        fn group(&self) -> ComponentGroup {
            ComponentGroup::Model
        }
        async fn check(&self) -> Vec<ComponentCheck> {
            self.0.clone()
        }
        fn models(&self) -> Option<HealthModels> {
            Some(HealthModels {
                chat: "test-model".into(),
                investigation: "test-model".into(),
            })
        }
    }

    struct HangingProbe;

    #[async_trait]
    impl HealthProbe for HangingProbe {
        fn id(&self) -> &str {
            "model"
        }
        fn name(&self) -> &str {
            "Model server"
        }
        fn group(&self) -> ComponentGroup {
            ComponentGroup::Model
        }
        async fn check(&self) -> Vec<ComponentCheck> {
            std::future::pending().await
        }
    }

    #[test]
    fn overall_is_down_only_for_a_critical_failure() {
        assert_eq!(overall(&[check("a", ComponentStatus::Ok)]), "ok");
        assert_eq!(overall(&[check("a", ComponentStatus::Off)]), "ok");
        assert_eq!(overall(&[check("a", ComponentStatus::Warn)]), "degraded");
        assert_eq!(overall(&[check("a", ComponentStatus::Fail)]), "degraded");
        assert_eq!(
            overall(&[
                check("a", ComponentStatus::Ok),
                check("b", ComponentStatus::Fail).critical()
            ]),
            "down"
        );
        // A critical component that only warns does not take Talahon down.
        assert_eq!(
            overall(&[check("b", ComponentStatus::Warn).critical()]),
            "degraded"
        );
    }

    #[test]
    fn history_counts_checks_in_five_minute_buckets() {
        let mut history = History::default();
        let ok = [check("database", ComponentStatus::Ok)];
        let fail = [
            check("database", ComponentStatus::Fail),
            check("palace", ComponentStatus::Off),
        ];
        history.record(at("2026-01-02T10:00:00Z"), &ok, 0);
        history.record(at("2026-01-02T10:04:59Z"), &fail, 3);
        history.record(at("2026-01-02T10:05:00Z"), &ok, 1);
        let body = history.to_json(at("2026-01-02T10:06:00Z"), 24);
        assert_eq!(
            body,
            json!({
                "bucket_minutes": 5,
                "components": { "database": [
                    { "t": "2026-01-02T10:00:00Z", "ok": 1, "warn": 0, "fail": 1 },
                    { "t": "2026-01-02T10:05:00Z", "ok": 1, "warn": 0, "fail": 0 },
                ] },
            })
        );
        assert_eq!(
            history
                .queue_depths(0)
                .get(&at("2026-01-02T10:00:00Z").timestamp()),
            Some(&3)
        );
    }

    #[test]
    fn history_keeps_seven_days_and_serves_the_asked_window() {
        let mut history = History::default();
        let ok = [check("database", ComponentStatus::Ok)];
        let now = at("2026-01-10T12:00:00Z");
        history.record(now - ChronoDuration::days(8), &ok, 0);
        history.record(now - ChronoDuration::hours(30), &ok, 0);
        history.record(now, &ok, 0);
        assert_eq!(
            history.buckets.len(),
            2,
            "the bucket past seven days is dropped"
        );
        let day = history.to_json(now, 24);
        assert_eq!(day["components"]["database"].as_array().unwrap().len(), 1);
        let week = history.to_json(now, 168);
        assert_eq!(week["components"]["database"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn metrics_report_only_what_was_measured() {
        let now = at("2026-01-02T10:07:00Z");
        let rows = [
            investigation(
                "a",
                "completed",
                "2026-01-02T10:00:00Z",
                "2026-01-02T10:01:40Z",
            ),
            investigation(
                "b",
                "completed",
                "2026-01-02T09:58:00Z",
                "2026-01-02T10:03:00Z",
            ),
            investigation(
                "c",
                "failed",
                "2026-01-02T10:00:00Z",
                "2026-01-02T10:04:00Z",
            ),
            investigation(
                "d",
                "running",
                "2026-01-02T10:00:00Z",
                "2026-01-02T10:02:00Z",
            ),
            investigation(
                "old",
                "completed",
                "2025-12-01T10:00:00Z",
                "2025-12-01T10:02:00Z",
            ),
        ];
        let depths = HashMap::from([(at("2026-01-02T10:05:00Z").timestamp(), 2)]);
        let body = metrics_json(now, 24, &rows, false, &depths);
        assert_eq!(body["bucket_minutes"], 5);
        let series = body["series"].as_array().unwrap();
        assert_eq!(series.len(), 24 * 12 + 1);
        let bucket = |t: &str| series.iter().find(|b| b["t"] == t).unwrap().clone();
        assert_eq!(
            bucket("2026-01-02T10:00:00Z"),
            json!({
                "t": "2026-01-02T10:00:00Z",
                "investigations_completed": 2,
                "investigations_failed": 1,
                "duration_p50_s": 100.0,
                "duration_p95_s": 300.0,
            })
        );
        // No finished investigation: a true zero, but no duration and no
        // invented tool or model numbers; the queue only where it was sampled.
        assert_eq!(
            bucket("2026-01-02T10:05:00Z"),
            json!({
                "t": "2026-01-02T10:05:00Z",
                "investigations_completed": 0,
                "investigations_failed": 0,
                "queue_depth_max": 2,
            })
        );
        assert!(
            bucket("2026-01-02T09:00:00Z")
                .get("queue_depth_max")
                .is_none()
        );
    }

    #[test]
    fn a_truncated_read_leaves_older_buckets_without_investigation_numbers() {
        let now = at("2026-01-02T10:07:00Z");
        let rows = [
            investigation(
                "a",
                "completed",
                "2026-01-02T10:00:00Z",
                "2026-01-02T10:01:00Z",
            ),
            investigation(
                "b",
                "completed",
                "2026-01-02T09:00:00Z",
                "2026-01-02T09:01:00Z",
            ),
        ];
        let depths = HashMap::from([(at("2026-01-02T08:00:00Z").timestamp(), 0)]);
        let body = metrics_json(now, 24, &rows, true, &depths);
        let series = body["series"].as_array().unwrap();
        assert_eq!(
            series[0],
            json!({ "t": "2026-01-02T08:00:00Z", "queue_depth_max": 0 })
        );
        assert_eq!(series[1]["t"], "2026-01-02T09:05:00Z");
        assert_eq!(series.last().unwrap()["investigations_completed"], 0);
    }

    #[tokio::test]
    async fn health_reports_talahons_own_components() {
        let h = Harness::new();
        let res = h.send(authed("GET", "/v2/health", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_json(res).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert!(body["uptime_seconds"].is_u64());
        assert!(parse_iso(body["checked_at"].as_str().unwrap()).is_some());
        let components = body["components"].as_array().unwrap();
        let ids: Vec<&str> = components
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["api", "database", "queue"]);
        for c in components {
            assert_eq!(c["group"], "core");
            assert_eq!(c["status"], "ok");
            assert!(c["name"].is_string() && c["checked_at"].is_string());
        }
        assert!(components[1]["latency_ms"].is_number());
        assert_eq!(
            components[2]["detail"],
            "1 of 5 agent containers running, 0 lane(s) waiting"
        );
        // Talahon has no talon-analyst v2 API and says so; nothing it does
        // not know is reported.
        assert_eq!(body["config"], json!({ "v2_api": false }));
    }

    #[tokio::test]
    async fn health_routes_require_the_key() {
        let h = Harness::with_config(|c| c.auth_max_failures = 100);
        for uri in ["/v2/health", "/v2/health/history", "/v2/health/metrics"] {
            let res = h.send(request("GET", uri, None, None)).await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn only_the_dashboards_windows_are_accepted() {
        let h = Harness::new();
        for route in ["/v2/health/history", "/v2/health/metrics"] {
            for good in ["", "?hours=24", "?hours=168"] {
                let res = h.send(authed("GET", &format!("{route}{good}"), None)).await;
                assert_eq!(res.status(), StatusCode::OK, "{route}{good}");
            }
            for bad in [
                "?hours=1",
                "?hours=0",
                "?hours=abc",
                "?hours=",
                "?hours=24.0",
            ] {
                let res = h.send(authed("GET", &format!("{route}{bad}"), None)).await;
                assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{route}{bad}");
                assert_eq!(body_json(res).await["error"], "hours must be 24 or 168");
            }
        }
    }

    #[tokio::test]
    async fn a_failing_database_is_down_and_a_failing_probe_degraded() {
        let store = MemoryStore {
            fail_reads: true,
            ..MemoryStore::default()
        };
        let h = Harness::with(|_| {}, store, FakeHost::default());
        let body = body_json(h.send(authed("GET", "/v2/health", None)).await).await;
        assert_eq!(body["status"], "down");
        let database = &body["components"][1];
        assert_eq!(database["status"], "fail");
        assert_eq!(database["detail"], "The database read failed");
        assert!(database["fix"].is_string());
        // The store's own error text is not relayed.
        assert!(!body.to_string().contains("disk full"));

        let probe = FixedProbe(vec![
            ComponentCheck::new(
                "model",
                "Model server",
                ComponentGroup::Model,
                ComponentStatus::Fail,
            )
            .detail("The model server could not be reached"),
            ComponentCheck::new("bad id!", "x", ComponentGroup::Tools, ComponentStatus::Fail),
            ComponentCheck::new(
                "api",
                "duplicate",
                ComponentGroup::Tools,
                ComponentStatus::Fail,
            ),
        ]);
        let h = Harness::with_probes(vec![Arc::new(probe)]);
        let body = body_json(h.send(authed("GET", "/v2/health", None)).await).await;
        assert_eq!(body["status"], "degraded");
        let components = body["components"].as_array().unwrap();
        assert_eq!(
            components.len(),
            4,
            "an unusable or duplicate id is dropped"
        );
        assert_eq!(components[3]["id"], "model");
        assert_eq!(components[3]["group"], "model");
        assert_eq!(
            body["config"],
            json!({ "v2_api": false, "models": { "chat": "test-model", "investigation": "test-model" } })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_probe_fails_at_its_deadline_and_the_check_is_cached() {
        let h = Harness::with_probes(vec![Arc::new(HangingProbe)]);
        let first = h.state.health_snapshot().await;
        let model = first.components.iter().find(|c| c.id == "model").unwrap();
        assert_eq!(model.status, ComponentStatus::Fail);
        assert_eq!(
            model.detail.as_deref(),
            Some("The check did not finish within 4 s")
        );
        let again = h.state.health_snapshot().await;
        assert!(Arc::ptr_eq(&first, &again), "served from the cache");
        tokio::time::advance(CACHE_TTL + Duration::from_secs(1)).await;
        let later = h.state.health_snapshot().await;
        assert!(!Arc::ptr_eq(&first, &later));

        // Every fresh check is in the history; the cached one is not.
        let res = h.send(authed("GET", "/v2/health/history", None)).await;
        let body = body_json(res).await;
        let total = |id: &str, field: &str| -> u64 {
            body["components"][id]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b[field].as_u64().unwrap())
                .sum()
        };
        assert_eq!(total("model", "fail"), 2);
        assert_eq!(total("database", "ok"), 2);
    }

    #[tokio::test]
    async fn metrics_come_from_the_investigation_table() {
        let h = Harness::new();
        let now = Utc::now();
        let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(SecondsFormat::Millis, true);
        h.store.investigations.lock().unwrap().push(investigation(
            "a",
            "completed",
            &stamp(now - ChronoDuration::seconds(90)),
            &stamp(now),
        ));
        let res = h
            .send(authed("GET", "/v2/health/metrics?hours=24", None))
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_json(res).await;
        let last = body["series"].as_array().unwrap().last().unwrap().clone();
        assert_eq!(last["investigations_completed"], 1);
        assert_eq!(last["duration_p50_s"], 90.0);
        assert!(last.get("tool_calls").is_none() && last.get("cost_usd").is_none());
    }
}
