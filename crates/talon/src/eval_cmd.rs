//! `talon eval score` and `talon eval run`: the golden-set regression
//! harness for investigation quality.
//!
//! The scoring itself is pure and lives in [`talon_intel::eval`]; this
//! module does the I/O around it:
//!
//! - loading golden cases (`evals/golden/<case id>.json`),
//! - `score`: reading one already-produced report per case from a
//!   directory and printing the summary,
//! - `run`: submitting every case to a running Talon through the CoPilot
//!   HTTP API (`POST /investigate`, then polling
//!   `GET /investigations/{id}`), i.e. the same path CoPilot uses, and
//!   scoring the verdict Talon recorded.
//!
//! Reports are agent output: they are read without following symlinks and
//! with a size cap ([`crate::safe_fs`]), parsed as data only, and whatever
//! of them reaches the terminal has been stripped of control characters by
//! the scorer.
//!
//! Exit codes: `0` pass rate reached, `1` pass rate below
//! `--min-pass-rate`, `2` unusable input or configuration.

use std::collections::{BTreeMap, HashSet};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use serde_json::{Value, json};
use talon_core::config::TalonConfig;
use talon_http::HttpConfig;
use talon_http::validate::{
    is_valid_customer_code, is_valid_investigation_id, is_valid_template_name,
};
use talon_intel::eval::{
    CaseRequest, GoldenCase, Outcome, Summary, is_valid_case_id, score_case, summarize,
};
use tokio::time::Instant;

use crate::cli::{EvalCommonArgs, EvalRunArgs, EvalScoreArgs};
use crate::safe_fs::{OpenRefusal, open_regular_at, open_root, read_capped};

/// Golden-case directory below the project root.
pub const DEFAULT_CASES_DIR: &str = "evals/golden";
/// Largest golden-case file read.
pub const MAX_CASE_BYTES: u64 = 1024 * 1024;
/// Largest report / investigation record read (file or HTTP body).
pub const MAX_REPORT_BYTES: u64 = 2 * 1024 * 1024;
/// `triggered_by` of harness-submitted investigations (the HTTP API
/// accepts `manual`, `scheduled` and `webhook`).
pub const TRIGGERED_BY: &str = "manual";
/// Consecutive failed status polls after which a case is given up.
pub const MAX_POLL_ERRORS: u32 = 3;
/// Timeout of one HTTP request to Talon.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Exit code: the pass rate is below the threshold.
pub const EXIT_BELOW_THRESHOLD: i32 = 1;
/// Exit code: unusable input or configuration.
pub const EXIT_USAGE: i32 = 2;

fn read_regular(dir: BorrowedFd<'_>, name: &str, max: u64) -> Result<Option<Vec<u8>>, String> {
    match open_regular_at(dir, name, max) {
        Ok((file, _)) => read_capped(file, max)
            .map(Some)
            .map_err(|e| format!("cannot read: {e}")),
        Err(OpenRefusal::Missing) => Ok(None),
        Err(OpenRefusal::Rejected(reason)) => Err(reason),
    }
}

/// Load and validate every `*.json` golden case in `dir`, sorted by file
/// name. The file stem must equal the case id.
///
/// # Errors
/// The directory cannot be read, holds no cases, or a case file is
/// unreadable, malformed or invalid (every problem is listed).
pub fn load_cases(dir: &Path) -> anyhow::Result<Vec<GoldenCase>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("cannot read the golden-case directory {}", dir.display()))?
    {
        let name = entry?.file_name();
        if let Some(name) = name.to_str().filter(|n| n.ends_with(".json")) {
            names.push(name.to_string());
        }
    }
    names.sort();
    if names.is_empty() {
        bail!("no golden cases (*.json) in {}", dir.display());
    }
    let root = open_root(dir).with_context(|| format!("cannot open {}", dir.display()))?;
    let mut cases = Vec::new();
    let mut problems = Vec::new();
    for name in &names {
        let stem = name.trim_end_matches(".json");
        let raw = match read_regular(root.as_fd(), name, MAX_CASE_BYTES) {
            Ok(Some(raw)) => raw,
            Ok(None) => continue,
            Err(reason) => {
                problems.push(format!("{name}: {reason}"));
                continue;
            }
        };
        let case = match std::str::from_utf8(&raw)
            .map_err(|e| format!("not UTF-8: {e}"))
            .and_then(GoldenCase::from_json_str)
        {
            Ok(case) => case,
            Err(e) => {
                problems.push(format!("{name}: {e}"));
                continue;
            }
        };
        let mut issues = case.validate();
        if case.id != stem {
            issues.push(format!("id {:?} does not match the file name", case.id));
        }
        problems.extend(issues.into_iter().map(|i| format!("{name}: {i}")));
        cases.push(case);
    }
    if !problems.is_empty() {
        bail!("invalid golden cases:\n  {}", problems.join("\n  "));
    }
    Ok(cases)
}

/// What `<case_id>.json` in the open reports directory says about a case.
pub fn load_outcome(reports: BorrowedFd<'_>, case_id: &str) -> Outcome {
    if !is_valid_case_id(case_id) {
        return Outcome::Missing("invalid case id".to_string());
    }
    let name = format!("{case_id}.json");
    match read_regular(reports, &name, MAX_REPORT_BYTES) {
        Ok(Some(raw)) => match serde_json::from_slice::<Value>(&raw) {
            Ok(doc) => Outcome::from_document(doc),
            Err(e) => Outcome::Failed(format!("{name} is not valid JSON: {e}")),
        },
        Ok(None) => Outcome::Missing(format!("no {name} in the reports directory")),
        Err(reason) => Outcome::Failed(format!("{name} was not read: {reason}")),
    }
}

/// Score the reports in `reports_dir` against `cases`.
///
/// # Errors
/// The reports directory cannot be opened.
pub fn score_reports(cases: &[GoldenCase], reports_dir: &Path) -> anyhow::Result<Summary> {
    let reports = open_root(reports_dir).with_context(|| {
        format!(
            "cannot open the reports directory {}",
            reports_dir.display()
        )
    })?;
    Ok(summarize(
        cases
            .iter()
            .map(|case| score_case(case, &load_outcome(reports.as_fd(), &case.id)))
            .collect(),
    ))
}

fn cases_dir(root: &Path, common: &EvalCommonArgs) -> PathBuf {
    match &common.cases {
        Some(dir) => dir.clone(),
        None => root.join(DEFAULT_CASES_DIR),
    }
}

/// Print the summary and turn it into the exit code.
fn report(summary: &Summary, common: &EvalCommonArgs) -> i32 {
    if common.json {
        match serde_json::to_string_pretty(summary) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("talon eval: cannot serialize the summary: {e}");
                return EXIT_USAGE;
            }
        }
    } else {
        print!("{}", summary.render_table());
    }
    if summary.meets(common.min_pass_rate) {
        0
    } else {
        eprintln!(
            "talon eval: pass rate {:.1}% is below the required {:.1}%",
            summary.pass_rate * 100.0,
            common.min_pass_rate * 100.0
        );
        EXIT_BELOW_THRESHOLD
    }
}

fn usage_error(e: &anyhow::Error) -> i32 {
    eprintln!("talon eval: {e:#}");
    EXIT_USAGE
}

/// `talon eval score`: returns the process exit code.
pub fn score(root: &Path, args: &EvalScoreArgs) -> i32 {
    let result = load_cases(&cases_dir(root, &args.common))
        .and_then(|cases| score_reports(&cases, &args.reports));
    match result {
        Ok(summary) => report(&summary, &args.common),
        Err(e) => usage_error(&e),
    }
}

// ---------------------------------------------------------------------------
// Online mode
// ---------------------------------------------------------------------------

/// Answer of `POST /investigate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// Investigation job id.
    pub job_id: String,
    /// Talon returned an existing job instead of starting a new one.
    pub deduplicated: bool,
}

/// The slice of the CoPilot HTTP API the harness uses; a trait so the run
/// loop is tested without a server.
#[async_trait]
pub trait InvestigationApi: Send + Sync {
    /// `POST /investigate`.
    async fn submit(&self, request: &CaseRequest) -> anyhow::Result<Submission>;
    /// `GET /investigations/{id}`: the investigation record.
    async fn fetch(&self, job_id: &str) -> anyhow::Result<Value>;
}

/// [`InvestigationApi`] over HTTP against a running Talon.
pub struct HttpInvestigationApi {
    client: reqwest::Client,
    base: String,
    api_key: String,
}

impl HttpInvestigationApi {
    /// Client for the Talon HTTP API at `base_url`, authenticating with
    /// `api_key` (`X-Api-Key`). Redirects are not followed, so the key is
    /// never forwarded to another origin.
    ///
    /// # Errors
    /// `base_url` is not an `http(s)` URL with a host, or the HTTP client
    /// cannot be built.
    pub fn new(base_url: &str, api_key: impl Into<String>) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(base_url.trim())
            .map_err(|e| anyhow!("invalid Talon URL {base_url:?}: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            bail!("the Talon URL must be http(s)://host[:port], got {base_url:?}");
        }
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("cannot build the HTTP client")?;
        Ok(Self {
            client,
            base: url.as_str().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
        })
    }

    /// Read a JSON body of at most [`MAX_REPORT_BYTES`]; a non-2xx status
    /// becomes an error naming the status and the API's `error` text.
    async fn json_body(mut response: reqwest::Response, what: &str) -> anyhow::Result<Value> {
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("{what}: reading the response failed"))?
        {
            body.extend_from_slice(&chunk);
            if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_REPORT_BYTES {
                bail!("{what}: response exceeds {MAX_REPORT_BYTES} bytes");
            }
        }
        let parsed = serde_json::from_slice::<Value>(&body);
        if !status.is_success() {
            let message = parsed
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            let message: String = message
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            bail!("{what}: HTTP {status} {message}");
        }
        parsed.with_context(|| format!("{what}: the response is not JSON"))
    }
}

/// The `POST /investigate` body for a case request.
pub fn investigate_body(request: &CaseRequest) -> Value {
    let mut body = json!({
        "alert_id": request.alert_id,
        "customer_code": request.customer_code,
        "triggered_by": TRIGGERED_BY,
    });
    if let Some(template) = &request.template_override {
        body["template_override"] = json!(template);
    }
    body
}

#[async_trait]
impl InvestigationApi for HttpInvestigationApi {
    async fn submit(&self, request: &CaseRequest) -> anyhow::Result<Submission> {
        let response = self
            .client
            .post(format!("{}/investigate", self.base))
            .header("x-api-key", &self.api_key)
            .json(&investigate_body(request))
            .send()
            .await
            .map_err(|e| anyhow!("POST /investigate: {}", e.without_url()))?;
        let body = Self::json_body(response, "POST /investigate").await?;
        let job_id = body
            .get("job_id")
            .and_then(Value::as_str)
            .filter(|id| is_valid_investigation_id(id))
            .ok_or_else(|| anyhow!("POST /investigate: the response has no valid job_id"))?;
        Ok(Submission {
            job_id: job_id.to_string(),
            deduplicated: body.get("deduplicated").and_then(Value::as_bool) == Some(true),
        })
    }

    async fn fetch(&self, job_id: &str) -> anyhow::Result<Value> {
        if !is_valid_investigation_id(job_id) {
            bail!("invalid investigation id");
        }
        let response = self
            .client
            .get(format!("{}/investigations/{job_id}", self.base))
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .map_err(|e| anyhow!("GET /investigations/{job_id}: {}", e.without_url()))?;
        Self::json_body(response, "GET /investigations/{id}").await
    }
}

/// How the run loop waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOptions {
    /// Longest wait for one investigation's verdict.
    pub timeout: Duration,
    /// Pause between status polls.
    pub poll: Duration,
    /// Score a de-duplicated (pre-existing) job instead of failing the
    /// case.
    pub allow_deduplicated: bool,
}

/// What investigating one case through the API produced.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseRun {
    /// Job id, once the submission was accepted.
    pub job_id: Option<String>,
    /// The final investigation record, when the job reached a terminal
    /// status.
    pub record: Option<Value>,
    /// The outcome to score.
    pub outcome: Outcome,
}

impl CaseRun {
    fn failed(job_id: Option<String>, reason: String) -> Self {
        Self {
            job_id,
            record: None,
            outcome: Outcome::Failed(reason),
        }
    }
}

/// Submit `request` and wait for its investigation to finish.
///
/// Never returns an error: a rejected submission, a de-duplicated trigger
/// (unless allowed), repeated poll failures and a timeout all become
/// [`Outcome::Failed`]. A job that times out here keeps running in Talon —
/// the HTTP API has no cancel operation.
pub async fn investigate_case(
    api: &dyn InvestigationApi,
    request: &CaseRequest,
    options: RunOptions,
) -> CaseRun {
    let submission = match api.submit(request).await {
        Ok(s) => s,
        Err(e) => return CaseRun::failed(None, format!("submission failed: {e:#}")),
    };
    let job_id = submission.job_id;
    if submission.deduplicated && !options.allow_deduplicated {
        return CaseRun::failed(
            Some(job_id.clone()),
            format!(
                "Talon de-duplicated the trigger to the existing job {job_id}; its verdict may \
                 predate the change under test (set COPILOT_INVESTIGATION_DEDUP_MINUTES=0 on \
                 the eval instance, or pass --allow-deduplicated)"
            ),
        );
    }
    let deadline = Instant::now() + options.timeout;
    let mut last_status = "unknown".to_string();
    let mut errors = 0;
    loop {
        match api.fetch(&job_id).await {
            Ok(record) => {
                errors = 0;
                let status = record
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if matches!(status, "completed" | "failed") {
                    return CaseRun {
                        job_id: Some(job_id),
                        outcome: Outcome::from_document(record.clone()),
                        record: Some(record),
                    };
                }
                last_status = status
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(32)
                    .collect();
            }
            Err(e) => {
                errors += 1;
                if errors >= MAX_POLL_ERRORS {
                    return CaseRun::failed(
                        Some(job_id),
                        format!("status polling failed {errors} times in a row: {e:#}"),
                    );
                }
            }
        }
        if Instant::now() + options.poll > deadline {
            return CaseRun::failed(
                Some(job_id.clone()),
                format!(
                    "no verdict within {}s (last status: {last_status}); job {job_id} may \
                     still be running in Talon",
                    options.timeout.as_secs()
                ),
            );
        }
        tokio::time::sleep(options.poll).await;
    }
}

/// Parse an `--alert-map` document: `{"<case id>": <alert id>, ...}`.
///
/// # Errors
/// Not a JSON object of positive integers.
pub fn parse_alert_map(text: &str) -> anyhow::Result<BTreeMap<String, u64>> {
    let map: BTreeMap<String, u64> = serde_json::from_str(text)
        .context("the alert map must be a JSON object of case id -> alert id")?;
    if let Some((id, _)) = map.iter().find(|(_, alert)| **alert == 0) {
        bail!("alert map: the alert id of {id:?} must be positive");
    }
    Ok(map)
}

/// The request to submit for each case: the case's own, with the alert id
/// from `alert_map` and the customer code from `customer_code` when given.
/// Validated against the HTTP API's input rules before anything is sent.
///
/// # Errors
/// The map names an unknown case, or a resulting request would be rejected
/// by `POST /investigate`.
pub fn prepare_requests(
    cases: &[GoldenCase],
    alert_map: &BTreeMap<String, u64>,
    customer_code: Option<&str>,
) -> anyhow::Result<Vec<CaseRequest>> {
    let known: HashSet<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    if let Some(unknown) = alert_map.keys().find(|id| !known.contains(id.as_str())) {
        bail!("alert map: no golden case named {unknown:?}");
    }
    cases
        .iter()
        .map(|case| {
            let mut request = case.request.clone();
            if let Some(alert_id) = alert_map.get(&case.id) {
                request.alert_id = *alert_id;
            }
            if let Some(code) = customer_code {
                request.customer_code = code.to_string();
            }
            if request.alert_id == 0 || request.alert_id > talon_http::validate::MAX_ALERT_ID {
                bail!("{}: alert_id is out of range", case.id);
            }
            if !is_valid_customer_code(&request.customer_code) {
                bail!(
                    "{}: customer_code must match ^[A-Za-z0-9_-]{{1,64}}$",
                    case.id
                );
            }
            if let Some(template) = &request.template_override
                && !is_valid_template_name(template)
            {
                bail!(
                    "{}: template_override must be a plain .txt filename",
                    case.id
                );
            }
            Ok(request)
        })
        .collect()
}

/// Investigate every case in turn (one at a time: the investigation lane
/// is serialized anyway, and a per-case timeout stays meaningful) and
/// score the outcomes. `progress` receives one line per step.
pub async fn run_cases(
    api: &dyn InvestigationApi,
    cases: &[GoldenCase],
    requests: &[CaseRequest],
    options: RunOptions,
    mut progress: impl FnMut(&str) + Send,
) -> (Summary, Vec<CaseRun>) {
    let mut results = Vec::new();
    let mut runs = Vec::new();
    for (i, (case, request)) in cases.iter().zip(requests).enumerate() {
        progress(&format!(
            "[{}/{}] {}: investigating alert {} ({})",
            i + 1,
            cases.len(),
            case.id,
            request.alert_id,
            request.customer_code
        ));
        let run = investigate_case(api, request, options).await;
        let result = score_case(case, &run.outcome);
        progress(&format!(
            "[{}/{}] {}: {} (job {}, verdict {})",
            i + 1,
            cases.len(),
            case.id,
            if result.passed { "PASS" } else { "FAIL" },
            run.job_id.as_deref().unwrap_or("-"),
            result.actual_verdict
        ));
        results.push(result);
        runs.push(run);
    }
    (summarize(results), runs)
}

/// Write each finished run's investigation record to
/// `<dir>/<case id>.json` (the layout `talon eval score --reports` reads).
/// Cases without a record (submission failed, timed out) get no file and
/// score as missing.
fn save_records(dir: &Path, cases: &[GoldenCase], runs: &[CaseRun]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    for (case, run) in cases.iter().zip(runs) {
        let Some(record) = &run.record else { continue };
        let path = dir.join(format!("{}.json", case.id));
        let text = serde_json::to_vec_pretty(record)?;
        std::fs::write(&path, text).with_context(|| format!("cannot write {}", path.display()))?;
    }
    Ok(())
}

fn default_base_url(http: &HttpConfig) -> String {
    let host = match http.bind {
        ip if ip.is_unspecified() => "127.0.0.1".to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        std::net::IpAddr::V4(ip) => ip.to_string(),
    };
    format!("http://{host}:{}", http.port)
}

/// Whether sending the API key to `url` would expose it on the network:
/// plain HTTP to a host that is not loopback.
fn is_cleartext_remote(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    let host = url.host_str().unwrap_or_default();
    let loopback = match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    };
    url.scheme() == "http" && !loopback
}

async fn run_inner(root: &Path, config: &TalonConfig, args: &EvalRunArgs) -> anyhow::Result<i32> {
    let cases = load_cases(&cases_dir(root, &args.common))?;
    let alert_map = match &args.alert_map {
        Some(path) => parse_alert_map(
            &std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?,
        )?,
        None => BTreeMap::new(),
    };
    let requests = prepare_requests(&cases, &alert_map, args.customer_code.as_deref())?;

    let http = HttpConfig::from_talon_config(config).map_err(|e| anyhow!("{e}"))?;
    if !http.api_key.is_configured() {
        bail!(
            "HTTP_API_KEY is not set in the project's .env; the Talon HTTP API rejects every request without it"
        );
    }
    let base = match &args.url {
        Some(url) => url.clone(),
        None => default_base_url(&http),
    };
    if is_cleartext_remote(&base) {
        eprintln!(
            "talon eval: warning: sending the API key over plain HTTP to a non-loopback host"
        );
    }
    let api = HttpInvestigationApi::new(&base, http.api_key.expose())?;
    let options = RunOptions {
        timeout: Duration::from_secs(args.timeout_secs),
        poll: Duration::from_secs(args.poll_secs),
        allow_deduplicated: args.allow_deduplicated,
    };
    let (summary, runs) =
        run_cases(&api, &cases, &requests, options, |line| eprintln!("{line}")).await;
    if let Some(dir) = &args.save_dir {
        save_records(dir, &cases, &runs)?;
    }
    Ok(report(&summary, &args.common))
}

/// `talon eval run`: returns the process exit code.
pub async fn run(root: &Path, config: &TalonConfig, args: &EvalRunArgs) -> i32 {
    match run_inner(root, config, args).await {
        Ok(code) => code,
        Err(e) => usage_error(&e),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use talon_intel::eval::{ACTUAL_FAILED, ACTUAL_MISSING};
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn case_json(id: &str, alert_id: u64) -> Value {
        json!({
            "id": id,
            "description": "test",
            "request": {"alert_id": alert_id, "customer_code": "golden"},
            "alert": {},
            "expect": {
                "verdict": "true_positive",
                "severity": {"min": "medium", "max": "critical"},
                "required_iocs": [{"type": "ip", "value": "203.0.113.10"}],
                "forbidden_strings": ["USER_1"]
            }
        })
    }

    fn case(id: &str, alert_id: u64) -> GoldenCase {
        serde_json::from_value(case_json(id, alert_id)).unwrap()
    }

    fn good_report() -> Value {
        json!({
            "alert_id": "1", "verdict": "true_positive", "confidence": 90, "severity": "high",
            "summary": "Beaconing to 203.0.113.10.",
            "iocs": [{"value": "203.0.113.10", "type": "ip", "verdict": "malicious", "details": "c2"}],
            "mitre": [], "timeline": [], "evidence": [],
            "recommended_actions": [{"action": "Isolate the host", "priority": "immediate", "rationale": "c2"}]
        })
    }

    fn record(status: &str, verdict: Value) -> Value {
        json!({"id": "copilot-inv-1-2", "alert_id": "1", "customer_code": "golden",
               "triggered_by": "manual", "status": status, "template": null,
               "created_at": "t", "updated_at": "t", "verdict": verdict, "error": null})
    }

    fn write(dir: &Path, name: &str, v: &Value) {
        std::fs::write(dir.join(name), serde_json::to_vec(v).unwrap()).unwrap();
    }

    // -- loading ----------------------------------------------------------

    #[test]
    fn load_cases_sorted_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b-case.json", &case_json("b-case", 2));
        write(dir.path(), "a-case.json", &case_json("a-case", 1));
        std::fs::write(dir.path().join("README.md"), "docs").unwrap();
        let cases = load_cases(dir.path()).unwrap();
        assert_eq!(
            cases.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["a-case", "b-case"]
        );
    }

    #[test]
    fn load_cases_lists_every_problem() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            load_cases(dir.path())
                .unwrap_err()
                .to_string()
                .contains("no golden cases")
        );
        assert!(load_cases(&dir.path().join("absent")).is_err());

        write(dir.path(), "renamed.json", &case_json("other", 1));
        std::fs::write(dir.path().join("broken.json"), "{").unwrap();
        let mut bad = case_json("bad", 1);
        bad["expect"]["severity"] = json!({"min": "high", "max": "low"});
        write(dir.path(), "bad.json", &bad);
        std::os::unix::fs::symlink(dir.path().join("bad.json"), dir.path().join("link.json"))
            .unwrap();
        let err = load_cases(dir.path()).unwrap_err().to_string();
        for needle in [
            "renamed.json: id \"other\" does not match",
            "broken.json: not a golden case",
            "bad.json: expect.severity.min",
            "link.json: symbolic link",
        ] {
            assert!(err.contains(needle), "{needle} missing in {err}");
        }
    }

    // -- offline scoring --------------------------------------------------

    #[test]
    fn score_reports_handles_reports_records_and_bad_files() {
        let reports = tempfile::tempdir().unwrap();
        let cases: Vec<GoldenCase> = [
            "bare",
            "record",
            "failed-run",
            "no-verdict",
            "absent",
            "garbage",
            "leaky",
            "linked",
        ]
        .iter()
        .map(|id| case(id, 1))
        .collect();
        write(reports.path(), "bare.json", &good_report());
        write(
            reports.path(),
            "record.json",
            &record("completed", good_report()),
        );
        let mut failed = record("failed", json!(null));
        failed["error"] = json!("container exited 137");
        write(reports.path(), "failed-run.json", &failed);
        write(
            reports.path(),
            "no-verdict.json",
            &record("completed", json!(null)),
        );
        std::fs::write(reports.path().join("garbage.json"), "<html>").unwrap();
        let mut leaky = good_report();
        leaky["summary"] = json!("USER_1 beaconed to 203.0.113.10.");
        write(reports.path(), "leaky.json", &leaky);
        std::os::unix::fs::symlink(
            reports.path().join("bare.json"),
            reports.path().join("linked.json"),
        )
        .unwrap();

        let s = score_reports(&cases, reports.path()).unwrap();
        let by_id = |id: &str| s.cases.iter().find(|c| c.case_id == id).unwrap();
        assert!(by_id("bare").passed && by_id("record").passed);
        assert_eq!(by_id("failed-run").actual_verdict, ACTUAL_FAILED);
        assert!(
            by_id("failed-run").checks[0]
                .detail
                .contains("container exited 137")
        );
        assert_eq!(by_id("no-verdict").actual_verdict, ACTUAL_MISSING);
        assert_eq!(by_id("absent").actual_verdict, ACTUAL_MISSING);
        assert_eq!(by_id("garbage").actual_verdict, ACTUAL_FAILED);
        assert_eq!(by_id("leaky").actual_verdict, "true_positive");
        assert!(!by_id("leaky").passed);
        // A symlinked report is refused, not followed.
        assert_eq!(by_id("linked").actual_verdict, ACTUAL_FAILED);
        assert!(by_id("linked").checks[0].detail.contains("symbolic link"));
        assert_eq!((s.total, s.passed), (8, 2));

        assert!(score_reports(&cases, &reports.path().join("absent")).is_err());
    }

    #[test]
    fn score_exit_codes() {
        let root = tempfile::tempdir().unwrap();
        let golden = root.path().join(DEFAULT_CASES_DIR);
        std::fs::create_dir_all(&golden).unwrap();
        write(&golden, "one.json", &case_json("one", 1));
        write(&golden, "two.json", &case_json("two", 2));
        let reports = tempfile::tempdir().unwrap();
        write(reports.path(), "one.json", &good_report());
        let args = |min: f64, json: bool| EvalScoreArgs {
            reports: reports.path().to_path_buf(),
            common: EvalCommonArgs {
                cases: None,
                json,
                min_pass_rate: min,
            },
        };
        assert_eq!(score(root.path(), &args(1.0, false)), EXIT_BELOW_THRESHOLD);
        assert_eq!(score(root.path(), &args(0.5, true)), 0);
        write(reports.path(), "two.json", &good_report());
        assert_eq!(score(root.path(), &args(1.0, false)), 0);

        // Unusable input: no cases / no reports directory.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(score(empty.path(), &args(1.0, false)), EXIT_USAGE);
        let mut missing = args(1.0, false);
        missing.reports = reports.path().join("absent");
        assert_eq!(score(root.path(), &missing), EXIT_USAGE);
    }

    // -- request preparation ----------------------------------------------

    #[test]
    fn alert_map_and_customer_override() {
        let cases = vec![case("a", 1), case("b", 2)];
        let map = parse_alert_map(r#"{"b": 4711}"#).unwrap();
        let reqs = prepare_requests(&cases, &map, Some("lab_01")).unwrap();
        assert_eq!((reqs[0].alert_id, reqs[1].alert_id), (1, 4711));
        assert!(reqs.iter().all(|r| r.customer_code == "lab_01"));

        assert!(prepare_requests(&cases, &parse_alert_map(r#"{"c": 1}"#).unwrap(), None).is_err());
        assert!(prepare_requests(&cases, &BTreeMap::new(), Some("bad code")).is_err());
        let too_big = BTreeMap::from([("a".to_string(), u64::MAX)]);
        assert!(prepare_requests(&cases, &too_big, None).is_err());
        let mut templated = case("t", 1);
        templated.request.template_override = Some("../x.txt".into());
        assert!(prepare_requests(&[templated], &BTreeMap::new(), None).is_err());

        for bad in [r#"{"a": 0}"#, r#"{"a": "1"}"#, r#"{"a": -1}"#, "[]", "{"] {
            assert!(parse_alert_map(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn investigate_body_matches_the_http_contract() {
        let mut request = case("a", 7).request;
        assert_eq!(
            investigate_body(&request),
            json!({"alert_id": 7, "customer_code": "golden", "triggered_by": "manual"})
        );
        request.template_override = Some("sysmon_event_1.txt".into());
        assert_eq!(
            investigate_body(&request)["template_override"],
            "sysmon_event_1.txt"
        );
        // The label must be one the API accepts.
        assert!(talon_http::validate::is_valid_triggered_by(TRIGGERED_BY));
    }

    // -- run loop (fake API) ----------------------------------------------

    struct FakeApi {
        submit: Mutex<VecDeque<anyhow::Result<Submission>>>,
        fetch: Mutex<VecDeque<anyhow::Result<Value>>>,
        fetched: Mutex<Vec<String>>,
    }

    impl FakeApi {
        fn new(submit: Vec<anyhow::Result<Submission>>, fetch: Vec<anyhow::Result<Value>>) -> Self {
            Self {
                submit: Mutex::new(submit.into()),
                fetch: Mutex::new(fetch.into()),
                fetched: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl InvestigationApi for FakeApi {
        async fn submit(&self, _request: &CaseRequest) -> anyhow::Result<Submission> {
            self.submit.lock().unwrap().pop_front().unwrap()
        }
        async fn fetch(&self, job_id: &str) -> anyhow::Result<Value> {
            self.fetched.lock().unwrap().push(job_id.to_string());
            // Once the script is exhausted the job stays `running`.
            self.fetch
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(record("running", json!(null))))
        }
    }

    fn submitted(job: &str, deduplicated: bool) -> anyhow::Result<Submission> {
        Ok(Submission {
            job_id: job.into(),
            deduplicated,
        })
    }

    const FAST: RunOptions = RunOptions {
        timeout: Duration::from_millis(200),
        poll: Duration::from_millis(1),
        allow_deduplicated: false,
    };

    #[tokio::test]
    async fn waits_through_queued_and_running() {
        let api = FakeApi::new(
            vec![submitted("job-1", false)],
            vec![
                Ok(record("queued", json!(null))),
                Err(anyhow!("connection reset")),
                Ok(record("running", json!(null))),
                Ok(record("completed", good_report())),
            ],
        );
        let run = investigate_case(&api, &case("a", 1).request, FAST).await;
        assert_eq!(run.job_id.as_deref(), Some("job-1"));
        assert_eq!(run.outcome, Outcome::Report(good_report()));
        assert_eq!(run.record.unwrap()["status"], "completed");
        assert_eq!(api.fetched.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn failure_modes_become_failed_outcomes() {
        let request = case("a", 1).request;
        let reason = |run: CaseRun| match run.outcome {
            Outcome::Failed(r) => r,
            other => panic!("expected a failure, got {other:?}"),
        };

        // Submission rejected.
        let api = FakeApi::new(vec![Err(anyhow!("HTTP 401 Unauthorized"))], vec![]);
        let run = investigate_case(&api, &request, FAST).await;
        assert_eq!(run.job_id, None);
        assert!(reason(run).contains("submission failed: HTTP 401"));

        // De-duplicated trigger: never polled, never scored.
        let api = FakeApi::new(vec![submitted("old-job", true)], vec![]);
        let run = investigate_case(&api, &request, FAST).await;
        assert!(reason(run).contains("de-duplicated the trigger to the existing job old-job"));
        assert!(api.fetched.lock().unwrap().is_empty());

        // ... unless explicitly allowed.
        let api = FakeApi::new(
            vec![submitted("old-job", true)],
            vec![Ok(record("completed", good_report()))],
        );
        let allow = RunOptions {
            allow_deduplicated: true,
            ..FAST
        };
        let run = investigate_case(&api, &request, allow).await;
        assert!(matches!(run.outcome, Outcome::Report(_)));

        // Investigation failed.
        let mut failed = record("failed", json!(null));
        failed["error"] = json!("agent crashed");
        let api = FakeApi::new(vec![submitted("job-2", false)], vec![Ok(failed)]);
        let run = investigate_case(&api, &request, FAST).await;
        assert!(run.record.is_some());
        assert!(reason(run).contains("agent crashed"));

        // Polling keeps failing.
        let api = FakeApi::new(
            vec![submitted("job-3", false)],
            (0..5).map(|_| Err(anyhow!("HTTP 500"))).collect(),
        );
        let run = investigate_case(&api, &request, FAST).await;
        assert!(reason(run).contains("status polling failed 3 times in a row"));
        assert_eq!(api.fetched.lock().unwrap().len(), 3);

        // Timeout while the job is still running.
        let api = FakeApi::new(vec![submitted("job-4", false)], vec![]);
        let quick = RunOptions {
            timeout: Duration::from_millis(20),
            ..FAST
        };
        let started = std::time::Instant::now();
        let run = investigate_case(&api, &request, quick).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(run.record, None);
        let reason = reason(run);
        assert!(
            reason.contains("no verdict within 0s (last status: running)"),
            "{reason}"
        );
        assert!(reason.contains("job-4"));
    }

    #[tokio::test]
    async fn completed_without_verdict_is_missing() {
        let api = FakeApi::new(
            vec![submitted("job-1", false)],
            vec![Ok(record("completed", json!(null)))],
        );
        let run = investigate_case(&api, &case("a", 1).request, FAST).await;
        assert!(matches!(run.outcome, Outcome::Missing(_)));
    }

    #[tokio::test]
    async fn run_cases_scores_and_round_trips_through_score() {
        let cases = vec![case("good", 1), case("wrong", 2), case("dead", 3)];
        let requests = prepare_requests(&cases, &BTreeMap::new(), None).unwrap();
        let mut wrong = good_report();
        wrong["verdict"] = json!("false_positive");
        let api = FakeApi::new(
            vec![
                submitted("job-1", false),
                submitted("job-2", false),
                Err(anyhow!("HTTP 503")),
            ],
            vec![
                Ok(record("completed", good_report())),
                Ok(record("completed", wrong)),
            ],
        );
        let mut lines = Vec::new();
        let (summary, runs) =
            run_cases(&api, &cases, &requests, FAST, |l| lines.push(l.to_string())).await;
        assert_eq!((summary.total, summary.passed), (3, 1));
        assert_eq!(summary.confusion["true_positive"]["false_positive"], 1);
        assert_eq!(summary.confusion["true_positive"][ACTUAL_FAILED], 1);
        assert_eq!(lines.len(), 6);
        assert!(lines[1].contains("good: PASS (job job-1, verdict true_positive)"));
        assert!(lines[5].contains("dead: FAIL (job -, verdict failed)"));

        // Saved records re-score offline; the case that never ran has no
        // file and counts as missing.
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path().join("out");
        save_records(&save, &cases, &runs).unwrap();
        let rescored = score_reports(&cases, &save).unwrap();
        assert_eq!((rescored.total, rescored.passed), (3, 1));
        assert_eq!(rescored.cases[0], summary.cases[0]);
        assert_eq!(rescored.cases[1], summary.cases[1]);
        assert_eq!(rescored.cases[2].actual_verdict, ACTUAL_MISSING);
    }

    // -- HTTP client (wire level) -------------------------------------------

    #[tokio::test]
    async fn http_api_speaks_the_copilot_contract() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/investigate"))
            .and(header("x-api-key", "s3cret"))
            .and(body_json(json!({
                "alert_id": 7, "customer_code": "golden", "triggered_by": "manual"
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "job_id": "copilot-inv-7-1700000000000", "status": "queued",
                "template_override": null, "deduplicated": false
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/investigations/copilot-inv-7-1700000000000"))
            .and(header("x-api-key", "s3cret"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(record("completed", good_report())),
            )
            .expect(1)
            .mount(&server)
            .await;

        // A trailing slash on the base URL is tolerated.
        let api = HttpInvestigationApi::new(&format!("{}/", server.uri()), "s3cret").unwrap();
        let run = investigate_case(&api, &case("a", 7).request, FAST).await;
        assert_eq!(run.job_id.as_deref(), Some("copilot-inv-7-1700000000000"));
        assert_eq!(run.outcome, Outcome::Report(good_report()));
    }

    #[tokio::test]
    async fn http_api_reports_errors_without_leaking_the_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/investigate"))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(json!({"error": "Unauthorized\u{1b}[2J"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/investigations/job-1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
            .mount(&server)
            .await;
        let api = HttpInvestigationApi::new(&server.uri(), "s3cret-key").unwrap();
        let err = api
            .submit(&case("a", 7).request)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("HTTP 401") && err.contains("Unauthorized"),
            "{err}"
        );
        assert!(!err.contains('\u{1b}') && !err.contains("s3cret-key"));
        let err = format!("{:#}", api.fetch("job-1").await.unwrap_err());
        assert!(err.contains("not JSON"), "{err}");
        // Ids that are not investigation ids never reach the URL.
        assert!(api.fetch("../status").await.is_err());

        // Deduplicated answer (HTTP 200) and a response without a job id.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/investigate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "job_id": "copilot-inv-7-1", "status": "completed", "deduplicated": true
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/investigate"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"job_id": "a/b"})))
            .mount(&server)
            .await;
        let api = HttpInvestigationApi::new(&server.uri(), "k").unwrap();
        let first = api.submit(&case("a", 7).request).await.unwrap();
        assert!(first.deduplicated);
        assert!(api.submit(&case("a", 7).request).await.is_err());

        // Nothing listening.
        let api = HttpInvestigationApi::new("http://127.0.0.1:1", "s3cret-key").unwrap();
        let err = format!("{:#}", api.submit(&case("a", 7).request).await.unwrap_err());
        assert!(err.starts_with("POST /investigate:"), "{err}");
    }

    #[test]
    fn url_handling() {
        for bad in [
            "",
            "ftp://x",
            "localhost:3100",
            "http://",
            "file:///etc/passwd",
        ] {
            assert!(HttpInvestigationApi::new(bad, "k").is_err(), "{bad}");
        }
        assert!(HttpInvestigationApi::new("https://talon.example.com", "k").is_ok());
        assert!(is_cleartext_remote("http://talon.example.com:3100"));
        assert!(is_cleartext_remote("http://192.0.2.10:3100"));
        for fine in [
            "http://127.0.0.1:3100",
            "http://localhost:3100",
            "http://[::1]:3100",
            "https://talon.example.com",
        ] {
            assert!(!is_cleartext_remote(fine), "{fine}");
        }
        let mut http = HttpConfig::new("/srv/talon");
        assert_eq!(default_base_url(&http), "http://127.0.0.1:3100");
        http.bind = "0.0.0.0".parse().unwrap();
        http.port = 3200;
        assert_eq!(default_base_url(&http), "http://127.0.0.1:3200");
        http.bind = "::1".parse().unwrap();
        assert_eq!(default_base_url(&http), "http://[::1]:3200");
    }

    // -- the shipped golden set -------------------------------------------

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// A report that satisfies every expectation of `case`.
    fn ideal_report(case: &GoldenCase) -> Value {
        let e = &case.expect;
        let iocs: Vec<Value> = e
            .required_iocs
            .iter()
            .map(|i| {
                // An untyped expectation is reported the way an agent most
                // plausibly would.
                let ioc_type = match i.ioc_type {
                    Some(t) => t.as_str(),
                    None if i.value.parse::<std::net::IpAddr>().is_ok() => "ip",
                    None => "domain",
                };
                json!({"value": i.value, "type": ioc_type,
                       "verdict": "unknown", "details": "from the alert"})
            })
            .collect();
        let mitre: Vec<Value> = e
            .required_mitre
            .iter()
            .map(|id| {
                let t = talon_intel::mitre::technique(id).unwrap_or_else(|| {
                    panic!("{}: {id} is not in the embedded ATT&CK table", case.id)
                });
                json!({"technique_id": t.id, "name": t.full_name(),
                       "tactic": t.tactics[0], "rationale": "observed"})
            })
            .collect();
        json!({
            "alert_id": case.request.alert_id.to_string(),
            "verdict": talon_intel::eval::verdict_str(e.verdict),
            "confidence": 80,
            "severity": e.severity.min.as_str(),
            "summary": "Synthetic ideal answer.",
            "iocs": iocs, "mitre": mitre, "timeline": [], "evidence": [],
            "recommended_actions": [
                {"action": "Review", "priority": "medium", "rationale": "golden"}
            ]
        })
    }

    #[test]
    fn shipped_golden_cases_are_valid_and_self_consistent() {
        let root = repo_root();
        if !root.join("Cargo.lock").exists() {
            // Built from a published crate tarball: the repository's
            // golden set is not part of the package.
            return;
        }
        let cases = load_cases(&root.join(DEFAULT_CASES_DIR)).unwrap();
        assert!((5..=8).contains(&cases.len()), "{} cases", cases.len());
        prepare_requests(&cases, &BTreeMap::new(), None).unwrap();

        let mut alert_ids = HashSet::new();
        let mut verdicts = HashSet::new();
        let mut types = HashSet::new();
        for case in &cases {
            let id = &case.id;
            assert!(
                alert_ids.insert(case.request.alert_id),
                "{id}: duplicate alert_id"
            );
            verdicts.insert(case.expect.verdict);
            assert!(case.alert.is_object(), "{id}: no alert document");
            assert!(!case.description.is_empty(), "{id}: no description");

            // The alert type names a shipped prompt template.
            let alert_type = case
                .alert_type
                .as_deref()
                .unwrap_or_else(|| panic!("{id}: no alert_type"));
            types.insert(alert_type.to_string());
            let template = root
                .join("groups/copilot/prompts")
                .join(format!("{alert_type}.txt"));
            assert!(template.is_file(), "{id}: no template {alert_type}.txt");

            // Expectations derive from the alert: required indicators occur
            // in it, forbidden content does not.
            let alert_text = case.alert.to_string().replace("\\\\", "\\").to_lowercase();
            for ioc in &case.expect.required_iocs {
                assert!(
                    alert_text.contains(&ioc.value.to_lowercase()),
                    "{id}: required IOC {} is not in the alert",
                    ioc.value
                );
            }
            for forbidden in case
                .expect
                .forbidden_iocs
                .iter()
                .chain(&case.expect.forbidden_strings)
            {
                assert!(
                    !alert_text.contains(&forbidden.to_lowercase()),
                    "{id}: forbidden {forbidden} occurs in the alert"
                );
            }
            // Every case guards against leaked anonymization tokens.
            assert!(
                !case.expect.forbidden_patterns.is_empty(),
                "{id}: no forbidden_patterns"
            );

            // An ideal answer passes every check; an empty one does not.
            let ideal = score_case(case, &Outcome::Report(ideal_report(case)));
            assert!(
                ideal.passed,
                "{id}: {:?}",
                ideal.failures().collect::<Vec<_>>()
            );
            assert!(!score_case(case, &Outcome::Report(json!({}))).passed);
            let mut leaky = ideal_report(case);
            leaky["summary"] = json!("USER_1 on HOST_2 did it.");
            assert!(!score_case(case, &Outcome::Report(leaky)).passed, "{id}");
        }
        assert!(verdicts.len() >= 3, "verdict classes covered: {verdicts:?}");
        assert!(types.len() >= 4, "alert types covered: {types:?}");
    }
}
