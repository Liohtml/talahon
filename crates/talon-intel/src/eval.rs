//! Golden-set scoring of investigation quality.
//!
//! A [`GoldenCase`] names an alert with a known expected outcome; an
//! [`Outcome`] is what an investigation of that alert produced (the
//! structured [`TriageReport`] verdict, or nothing). [`score_case`] compares
//! the two check by check and [`summarize`] aggregates the per-case results
//! into totals and a verdict confusion matrix.
//!
//! Everything here is pure: no I/O, no model calls. The produced report is
//! agent output and therefore untrusted — it is read leniently (a report
//! that does not match the schema is still scored field by field, with a
//! failing `schema` check), every value echoed into a result is stripped of
//! control characters and truncated, and nothing in it is ever interpreted.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::common::{Severity, strip_control_chars, truncate_chars};
use crate::ioc::refang;
use crate::mitre;
use crate::report::{ReportIocType, TriageReport, Verdict};

/// Longest accepted case id.
pub const MAX_CASE_ID_LEN: usize = 64;
/// Longest report value echoed into a check detail (characters).
pub const MAX_DETAIL_CHARS: usize = 160;
/// Compiled-size limit of a `forbidden_patterns` regex (bytes).
pub const MAX_PATTERN_SIZE: usize = 1 << 20;
/// Depth to which a report is searched for strings.
const MAX_WALK_DEPTH: usize = 32;

/// Confusion-matrix column of a case whose investigation left no report.
pub const ACTUAL_MISSING: &str = "missing";
/// Confusion-matrix column of a case whose investigation failed.
pub const ACTUAL_FAILED: &str = "failed";
/// Confusion-matrix column of a report without a recognisable verdict.
pub const ACTUAL_INVALID: &str = "invalid";

/// The investigation request of a case: the body `POST /investigate`
/// accepts, minus `triggered_by` (set by the runner).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRequest {
    /// CoPilot alert id the synthetic alert is seeded under.
    pub alert_id: u64,
    /// Customer code (`^[A-Za-z0-9_-]{1,64}$`).
    pub customer_code: String,
    /// Prompt template forced for the run (a plain `.txt` filename).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_override: Option<String>,
}

/// Inclusive severity range a report may land in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityRange {
    /// Lowest acceptable severity.
    pub min: Severity,
    /// Highest acceptable severity.
    pub max: Severity,
}

impl SeverityRange {
    /// Whether `severity` lies in the range.
    pub fn contains(self, severity: Severity) -> bool {
        self.min <= severity && severity <= self.max
    }
}

/// An indicator the report's `iocs` must list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedIoc {
    /// Required IOC type; any type when absent.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub ioc_type: Option<ReportIocType>,
    /// Indicator value. Compared refanged and case-insensitively: equal for
    /// `ip`, `domain` and `hash`; contained in the reported value for the
    /// free-form types (`process`, `url`, `user`, `command`), so
    /// `powershell.exe` matches a full image path.
    pub value: String,
}

/// What a correct investigation of the case looks like.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectations {
    /// Expected verdict class (the row of the confusion matrix).
    pub verdict: Verdict,
    /// Further verdicts that also pass (e.g. `needs_escalation` on an
    /// ambiguous case expected to be `inconclusive`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_acceptable: Vec<Verdict>,
    /// Acceptable severity range (inclusive).
    pub severity: SeverityRange,
    /// Indicators that must be listed in the report's `iocs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_iocs: Vec<ExpectedIoc>,
    /// Indicators that must appear nowhere in the report (neither in `iocs`
    /// nor in any text field) — typically plausible-looking values that are
    /// not in the alert, to catch hallucinations. Matched refanged,
    /// case-insensitively and only at token boundaries (`203.0.113.5` does
    /// not match `203.0.113.55`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_iocs: Vec<String>,
    /// Literal, case-sensitive substrings that must appear in no string of
    /// the report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_strings: Vec<String>,
    /// Regular expressions that must match no string of the report (e.g.
    /// `\b(USER|HOST)_\d+\b` for leaked anonymization tokens).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_patterns: Vec<String>,
    /// ATT&CK technique ids the report must cite. A parent id (`T1059`) is
    /// satisfied by any of its sub-techniques; a sub-technique id must
    /// match exactly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_mitre: Vec<String>,
}

/// One golden case: an alert with a known expected outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenCase {
    /// Case id (`^[a-z0-9][a-z0-9_-]{0,63}$`); also the file stem of the
    /// case file and of the report scored against it.
    pub id: String,
    /// What the case exercises.
    #[serde(default)]
    pub description: String,
    /// Alert type, named like the prompt template it should select
    /// (`sysmon_event_1`, `windows_defender`, ...). Informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_type: Option<String>,
    /// The investigation request submitted for this case.
    pub request: CaseRequest,
    /// The synthetic raw SIEM event behind `request.alert_id`. The HTTP
    /// channel takes only an alert reference, so this document has to be
    /// seeded into the target stack before an online run; offline it
    /// documents what the expectations were derived from.
    #[serde(default)]
    pub alert: Value,
    /// Expected outcome.
    pub expect: Expectations,
}

/// Whether `id` is a valid case id.
pub fn is_valid_case_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_CASE_ID_LEN
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

fn compile_pattern(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .size_limit(MAX_PATTERN_SIZE)
        .build()
        .map_err(|e| {
            let e = e.to_string();
            e.lines().last().unwrap_or("invalid pattern").to_string()
        })
}

impl GoldenCase {
    /// Parse a case file.
    ///
    /// # Errors
    /// A description of the JSON or schema problem.
    pub fn from_json_str(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| format!("not a golden case: {e}"))
    }

    /// Problems that make the case unusable (empty when it is fine).
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if !is_valid_case_id(&self.id) {
            issues.push("id must match ^[a-z0-9][a-z0-9_-]{0,63}$".to_string());
        }
        if self.request.alert_id == 0 {
            issues.push("request.alert_id must be a positive integer".to_string());
        }
        let cc = &self.request.customer_code;
        if cc.is_empty()
            || cc.len() > 64
            || !cc
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            issues.push("request.customer_code must match ^[A-Za-z0-9_-]{1,64}$".to_string());
        }
        if !(self.alert.is_null() || self.alert.is_object()) {
            issues.push("alert must be a JSON object".to_string());
        }
        let e = &self.expect;
        if e.severity.min > e.severity.max {
            issues.push("expect.severity.min is above expect.severity.max".to_string());
        }
        for (i, ioc) in e.required_iocs.iter().enumerate() {
            if normalize(&ioc.value).is_empty() {
                issues.push(format!("expect.required_iocs[{i}].value is empty"));
            }
        }
        for (i, v) in e.forbidden_iocs.iter().enumerate() {
            let needle = normalize(v);
            if needle.is_empty() {
                issues.push(format!("expect.forbidden_iocs[{i}] is empty"));
            } else if e
                .required_iocs
                .iter()
                .any(|r| normalize(&r.value) == needle)
            {
                issues.push(format!("expect.forbidden_iocs[{i}] is also a required IOC"));
            }
        }
        for (i, s) in e.forbidden_strings.iter().enumerate() {
            if s.is_empty() {
                issues.push(format!("expect.forbidden_strings[{i}] is empty"));
            }
        }
        for (i, p) in e.forbidden_patterns.iter().enumerate() {
            match compile_pattern(p) {
                Ok(re) if re.is_match("") => issues.push(format!(
                    "expect.forbidden_patterns[{i}] matches the empty string"
                )),
                Ok(_) => {}
                Err(err) => issues.push(format!("expect.forbidden_patterns[{i}]: {err}")),
            }
        }
        for (i, t) in e.required_mitre.iter().enumerate() {
            if !mitre::is_technique_id(&t.trim().to_ascii_uppercase()) {
                issues.push(format!(
                    "expect.required_mitre[{i}] is not a technique id (T1234 or T1234.001)"
                ));
            }
        }
        issues
    }
}

/// What an investigation of a case produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// A report document (ideally a [`TriageReport`]; scored leniently).
    Report(Value),
    /// The investigation finished without a structured verdict, or no
    /// report exists for the case. Carries the reason.
    Missing(String),
    /// The investigation failed, timed out or could not be submitted.
    Failed(String),
}

impl Outcome {
    /// Classify a JSON document keyed to a case: either a bare report, or an
    /// investigation record as returned by `GET /investigations/{id}`
    /// (`{"status": ..., "verdict": {...} | null, "error": ...}`).
    pub fn from_document(doc: Value) -> Self {
        let is_record = doc.get("status").is_some_and(Value::is_string)
            && doc
                .get("verdict")
                .is_none_or(|v| v.is_object() || v.is_null());
        if !is_record {
            return Outcome::Report(doc);
        }
        let status = doc.get("status").and_then(Value::as_str).unwrap_or("");
        if status == "failed" {
            let error = doc
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("no error recorded");
            return Outcome::Failed(format!("investigation failed: {}", echo(error)));
        }
        match doc.get("verdict") {
            Some(v) if v.is_object() => Outcome::Report(v.clone()),
            _ => Outcome::Missing(format!(
                "investigation is {} without a structured verdict",
                echo(status)
            )),
        }
    }
}

/// One check of one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    /// Check name (`verdict`, `severity`, `required_ioc`, ...).
    pub check: String,
    /// The expectation the check tested (an IOC, a pattern, ...); empty for
    /// checks without a subject.
    pub subject: String,
    /// Whether the report met the expectation.
    pub passed: bool,
    /// Human-readable explanation.
    pub detail: String,
}

/// The scored result of one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseResult {
    /// Case id.
    pub case_id: String,
    /// Expected verdict (wire value).
    pub expected_verdict: String,
    /// Produced verdict (wire value), or [`ACTUAL_MISSING`],
    /// [`ACTUAL_FAILED`], [`ACTUAL_INVALID`].
    pub actual_verdict: String,
    /// Produced severity (wire value) when the report has a valid one.
    pub actual_severity: Option<String>,
    /// Whether every check passed.
    pub passed: bool,
    /// The individual checks, in a stable order.
    pub checks: Vec<CheckResult>,
}

impl CaseResult {
    /// The failed checks.
    pub fn failures(&self) -> impl Iterator<Item = &CheckResult> {
        self.checks.iter().filter(|c| !c.passed)
    }
}

/// Wire value of a verdict (`true_positive`, ...).
pub fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::TruePositive => "true_positive",
        Verdict::FalsePositive => "false_positive",
        Verdict::BenignTruePositive => "benign_true_positive",
        Verdict::NeedsEscalation => "needs_escalation",
        Verdict::Inconclusive => "inconclusive",
    }
}

/// A report-derived value made safe to print: no control characters, at
/// most [`MAX_DETAIL_CHARS`] characters.
fn echo(s: &str) -> String {
    truncate_chars(&strip_control_chars(s), MAX_DETAIL_CHARS)
}

/// Comparison form of an indicator: trimmed, refanged, lowercase.
fn normalize(s: &str) -> String {
    refang(s.trim()).to_lowercase()
}

fn check(name: &str, subject: &str, passed: bool, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        check: name.to_string(),
        subject: subject.to_string(),
        passed,
        detail: detail.into(),
    }
}

/// Every string value in `v` (object keys are not report content).
fn collect_strings<'a>(v: &'a Value, depth: usize, out: &mut Vec<&'a str>) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, depth + 1, out)),
        Value::Object(o) => o.values().for_each(|x| collect_strings(x, depth + 1, out)),
        _ => {}
    }
}

/// Whether `needle` occurs in `haystack` with no alphanumeric character
/// directly before or after it.
fn contains_token(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack.match_indices(needle).any(|(start, m)| {
        let before = haystack[..start].chars().next_back();
        let after = haystack[start + m.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

/// The `(type, normalized value)` pairs of the report's `iocs`.
fn reported_iocs(report: &Value) -> Vec<(Option<ReportIocType>, String)> {
    let Some(list) = report.get("iocs").and_then(Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|ioc| {
            let value = ioc.get("value").and_then(Value::as_str)?;
            let ioc_type = ioc
                .get("type")
                .and_then(|t| serde_json::from_value::<ReportIocType>(t.clone()).ok());
            Some((ioc_type, normalize(value)))
        })
        .collect()
}

fn ioc_matches(expected: &ExpectedIoc, reported: &[(Option<ReportIocType>, String)]) -> bool {
    let want = normalize(&expected.value);
    reported.iter().any(|(ioc_type, value)| {
        if expected.ioc_type.is_some() && expected.ioc_type != *ioc_type {
            return false;
        }
        let free_form = matches!(
            ioc_type,
            Some(
                ReportIocType::Process
                    | ReportIocType::Url
                    | ReportIocType::User
                    | ReportIocType::Command
            )
        );
        *value == want || (free_form && value.contains(&want))
    })
}

/// The upper-cased technique ids the report cites.
fn reported_techniques(report: &Value) -> HashSet<String> {
    report
        .get("mitre")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|m| m.get("technique_id").and_then(Value::as_str))
                .map(|id| id.trim().to_ascii_uppercase())
                .collect()
        })
        .unwrap_or_default()
}

fn technique_cited(expected: &str, cited: &HashSet<String>) -> bool {
    let want = expected.trim().to_ascii_uppercase();
    if cited.contains(&want) {
        return true;
    }
    // A parent technique is satisfied by any of its sub-techniques.
    !want.contains('.')
        && cited.iter().any(|c| {
            c.strip_prefix(&want)
                .is_some_and(|rest| rest.starts_with('.'))
        })
}

fn schema_check(report: &Value) -> CheckResult {
    match TriageReport::from_json(report) {
        Ok(parsed) => {
            let validation = parsed.validate();
            if validation.is_ok() {
                check("schema", "", true, "report matches the triage schema")
            } else {
                let first = validation
                    .errors
                    .first()
                    .map(|i| format!("{}: {}", i.path, i.message))
                    .unwrap_or_default();
                check(
                    "schema",
                    "",
                    false,
                    format!(
                        "{} validation error(s), first: {}",
                        validation.errors.len(),
                        echo(&first)
                    ),
                )
            }
        }
        Err(e) => check("schema", "", false, echo(&e)),
    }
}

fn score_report(case: &GoldenCase, report: &Value) -> CaseResult {
    let expect = &case.expect;
    let expected_verdict = verdict_str(expect.verdict);
    // A report stored as a JSON string is unwrapped once, as
    // `TriageReport::from_json` does.
    let unwrapped;
    let report = match report {
        Value::String(s) => match serde_json::from_str::<Value>(s) {
            Ok(v) => {
                unwrapped = v;
                &unwrapped
            }
            Err(_) => report,
        },
        other => other,
    };

    let mut checks = vec![
        check("report_present", "", true, "a report was produced"),
        schema_check(report),
    ];

    // Verdict.
    let raw_verdict = report.get("verdict").and_then(Value::as_str);
    let verdict = raw_verdict.and_then(|s| {
        serde_json::from_value::<Verdict>(Value::String(s.trim().to_ascii_lowercase())).ok()
    });
    let actual_verdict = verdict.map_or(ACTUAL_INVALID, verdict_str).to_string();
    let accepted: Vec<&str> = std::iter::once(expect.verdict)
        .chain(expect.also_acceptable.iter().copied())
        .map(verdict_str)
        .collect();
    checks.push(match verdict {
        Some(v) if v == expect.verdict || expect.also_acceptable.contains(&v) => check(
            "verdict",
            expected_verdict,
            true,
            format!("verdict is {}", verdict_str(v)),
        ),
        Some(v) => check(
            "verdict",
            expected_verdict,
            false,
            format!(
                "verdict is {}, expected {}",
                verdict_str(v),
                accepted.join(" or ")
            ),
        ),
        None => check(
            "verdict",
            expected_verdict,
            false,
            match raw_verdict {
                Some(raw) => format!("unknown verdict {:?}", echo(raw)),
                None => "the report has no verdict".to_string(),
            },
        ),
    });

    // Severity.
    let severity = report
        .get("severity")
        .and_then(|s| serde_json::from_value::<Severity>(s.clone()).ok());
    let range = format!(
        "{}..={}",
        expect.severity.min.as_str(),
        expect.severity.max.as_str()
    );
    checks.push(match severity {
        Some(s) if expect.severity.contains(s) => check(
            "severity",
            &range,
            true,
            format!("severity is {}", s.as_str()),
        ),
        Some(s) => check(
            "severity",
            &range,
            false,
            format!("severity is {}, outside {range}", s.as_str()),
        ),
        None => check(
            "severity",
            &range,
            false,
            "the report has no valid severity",
        ),
    });

    // Required indicators.
    let iocs = reported_iocs(report);
    for expected in &expect.required_iocs {
        let found = ioc_matches(expected, &iocs);
        checks.push(check(
            "required_ioc",
            &expected.value,
            found,
            if found {
                "listed in iocs".to_string()
            } else {
                match expected.ioc_type {
                    Some(t) => format!("not listed in iocs as type {}", t.as_str()),
                    None => "not listed in iocs".to_string(),
                }
            },
        ));
    }

    // Forbidden content, searched in every string of the report.
    let mut strings = Vec::new();
    collect_strings(report, 0, &mut strings);
    let normalized: Vec<String> = strings.iter().map(|s| normalize(s)).collect();
    for forbidden in &expect.forbidden_iocs {
        let needle = normalize(forbidden);
        let hit = normalized.iter().any(|s| contains_token(s, &needle));
        checks.push(check(
            "forbidden_ioc",
            forbidden,
            !hit,
            if hit {
                "appears in the report"
            } else {
                "absent"
            },
        ));
    }
    for forbidden in &expect.forbidden_strings {
        let hit = !forbidden.is_empty() && strings.iter().any(|s| s.contains(forbidden.as_str()));
        checks.push(check(
            "forbidden_string",
            forbidden,
            !hit,
            if hit {
                "appears in the report"
            } else {
                "absent"
            },
        ));
    }
    for pattern in &expect.forbidden_patterns {
        checks.push(match compile_pattern(pattern) {
            Ok(re) => match strings.iter().find_map(|s| re.find(s)) {
                Some(m) => check(
                    "forbidden_pattern",
                    pattern,
                    false,
                    format!("matches {:?}", echo(m.as_str())),
                ),
                None => check("forbidden_pattern", pattern, true, "no match"),
            },
            Err(e) => check(
                "forbidden_pattern",
                pattern,
                false,
                format!("invalid pattern: {e}"),
            ),
        });
    }

    // Required ATT&CK techniques.
    let cited = reported_techniques(report);
    for technique in &expect.required_mitre {
        let found = technique_cited(technique, &cited);
        checks.push(check(
            "required_mitre",
            technique,
            found,
            if found { "cited" } else { "not cited in mitre" },
        ));
    }

    CaseResult {
        case_id: case.id.clone(),
        expected_verdict: expected_verdict.to_string(),
        actual_verdict,
        actual_severity: severity.map(|s| s.as_str().to_string()),
        passed: checks.iter().all(|c| c.passed),
        checks,
    }
}

/// Score what an investigation produced against the case's expectations.
///
/// With a report, the checks are `report_present`, `schema`, `verdict`,
/// `severity`, then one `required_ioc`, `forbidden_ioc`, `forbidden_string`,
/// `forbidden_pattern` and `required_mitre` check per expectation. Without
/// one, the single failing `report_present` check carries the reason.
pub fn score_case(case: &GoldenCase, outcome: &Outcome) -> CaseResult {
    let (label, reason) = match outcome {
        Outcome::Report(report) => return score_report(case, report),
        Outcome::Missing(reason) => (ACTUAL_MISSING, reason),
        Outcome::Failed(reason) => (ACTUAL_FAILED, reason),
    };
    CaseResult {
        case_id: case.id.clone(),
        expected_verdict: verdict_str(case.expect.verdict).to_string(),
        actual_verdict: label.to_string(),
        actual_severity: None,
        passed: false,
        checks: vec![check("report_present", "", false, echo(reason))],
    }
}

/// Aggregate of a scored golden set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    /// Number of cases.
    pub total: usize,
    /// Cases whose every check passed.
    pub passed: usize,
    /// Cases with at least one failed check.
    pub failed: usize,
    /// `passed / total` (`0.0` for an empty set).
    pub pass_rate: f64,
    /// Number of checks across all cases.
    pub checks_total: usize,
    /// Number of passed checks across all cases.
    pub checks_passed: usize,
    /// Verdict confusion matrix: expected verdict → actual verdict → count.
    /// Actual may also be `missing`, `failed` or `invalid`.
    pub confusion: BTreeMap<String, BTreeMap<String, usize>>,
    /// Per-case results, in input order.
    pub cases: Vec<CaseResult>,
}

/// Aggregate per-case results.
pub fn summarize(cases: Vec<CaseResult>) -> Summary {
    let total = cases.len();
    let passed = cases.iter().filter(|c| c.passed).count();
    let mut confusion: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for case in &cases {
        *confusion
            .entry(case.expected_verdict.clone())
            .or_default()
            .entry(case.actual_verdict.clone())
            .or_insert(0) += 1;
    }
    Summary {
        total,
        passed,
        failed: total - passed,
        pass_rate: if total == 0 {
            0.0
        } else {
            // Case counts are far below 2^52, so the conversion is exact.
            passed as f64 / total as f64
        },
        checks_total: cases.iter().map(|c| c.checks.len()).sum(),
        checks_passed: cases
            .iter()
            .map(|c| c.checks.iter().filter(|k| k.passed).count())
            .sum(),
        confusion,
        cases,
    }
}

/// Render rows as left-aligned, space-padded columns.
fn render_columns(out: &mut String, rows: &[Vec<String>]) {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..columns)
        .map(|i| {
            rows.iter()
                .filter_map(|r| r.get(i))
                .map(|c| c.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for row in rows {
        let mut line = String::new();
        for (cell, width) in row.iter().zip(&widths) {
            let _ = write!(line, "{cell:<width$}  ");
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
}

impl Summary {
    /// Whether the pass rate reaches `min_pass_rate` (a fraction, `0..=1`).
    /// An empty set never does.
    pub fn meets(&self, min_pass_rate: f64) -> bool {
        self.total > 0 && self.pass_rate + f64::EPSILON >= min_pass_rate
    }

    /// Plain-text report: one row per case, the failed checks, the verdict
    /// confusion matrix and the totals.
    pub fn render_table(&self) -> String {
        let mut out = String::new();
        let mut rows = vec![
            ["CASE", "RESULT", "EXPECTED", "ACTUAL", "SEVERITY", "CHECKS"]
                .map(String::from)
                .to_vec(),
        ];
        for case in &self.cases {
            let ok = case.checks.iter().filter(|c| c.passed).count();
            rows.push(vec![
                case.case_id.clone(),
                if case.passed { "PASS" } else { "FAIL" }.to_string(),
                case.expected_verdict.clone(),
                case.actual_verdict.clone(),
                case.actual_severity.clone().unwrap_or_else(|| "-".into()),
                format!("{ok}/{}", case.checks.len()),
            ]);
        }
        render_columns(&mut out, &rows);

        if self.failed > 0 {
            out.push_str("\nFailed checks:\n");
            for case in self.cases.iter().filter(|c| !c.passed) {
                for failure in case.failures() {
                    let subject = if failure.subject.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", echo(&failure.subject))
                    };
                    let _ = writeln!(
                        out,
                        "  {}: {}{subject}: {}",
                        case.case_id, failure.check, failure.detail
                    );
                }
            }
        }

        if !self.confusion.is_empty() {
            out.push_str("\nVerdict confusion (rows: expected, columns: actual):\n");
            let actuals: Vec<&String> = self
                .confusion
                .values()
                .flat_map(BTreeMap::keys)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let mut rows = vec![
                std::iter::once(String::new())
                    .chain(actuals.iter().map(|a| (*a).clone()))
                    .collect::<Vec<_>>(),
            ];
            for (expected, counts) in &self.confusion {
                rows.push(
                    std::iter::once(expected.clone())
                        .chain(
                            actuals
                                .iter()
                                .map(|a| counts.get(*a).copied().unwrap_or(0).to_string()),
                        )
                        .collect(),
                );
            }
            render_columns(&mut out, &rows);
        }

        let _ = writeln!(
            out,
            "\n{}/{} cases passed ({:.1}%), {}/{} checks passed",
            self.passed,
            self.total,
            self.pass_rate * 100.0,
            self.checks_passed,
            self.checks_total
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn case() -> GoldenCase {
        serde_json::from_value(json!({
            "id": "office-powershell",
            "description": "Word spawns encoded PowerShell",
            "alert_type": "sysmon_event_1",
            "request": {"alert_id": 48213, "customer_code": "golden"},
            "alert": {"rule": {"level": 12}},
            "expect": {
                "verdict": "true_positive",
                "also_acceptable": ["needs_escalation"],
                "severity": {"min": "high", "max": "critical"},
                "required_iocs": [
                    {"type": "ip", "value": "185.220.101.4"},
                    {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                    {"type": "url", "value": "evil.example/a.ps1"}
                ],
                "forbidden_iocs": ["198.51.100.77", "185.220.101.40"],
                "forbidden_strings": ["USER_1"],
                "forbidden_patterns": ["\\b(USER|HOST|IP_INT)_\\d+\\b"],
                "required_mitre": ["T1059", "T1204.002"]
            }
        }))
        .unwrap()
    }

    fn report() -> Value {
        let mut r = crate::report::tests::sample();
        r.sanitize();
        serde_json::to_value(r).unwrap()
    }

    fn failed(r: &CaseResult) -> Vec<(&str, &str)> {
        r.failures()
            .map(|c| (c.check.as_str(), c.subject.as_str()))
            .collect()
    }

    #[test]
    fn good_report_passes_every_check() {
        let r = score_case(&case(), &Outcome::Report(report()));
        assert!(r.passed, "{:?}", failed(&r));
        assert_eq!(r.actual_verdict, "true_positive");
        assert_eq!(r.actual_severity.as_deref(), Some("high"));
        // present, schema, verdict, severity, 3 iocs, 2 forbidden iocs,
        // 1 string, 1 pattern, 2 techniques.
        assert_eq!(r.checks.len(), 13);
    }

    #[test]
    fn case_round_trips_and_rejects_unknown_fields() {
        let c = case();
        let text = serde_json::to_string(&c).unwrap();
        assert_eq!(GoldenCase::from_json_str(&text).unwrap(), c);
        assert!(c.validate().is_empty(), "{:?}", c.validate());
        let mut v = serde_json::to_value(&c).unwrap();
        v["expect"]["verdit"] = json!("true_positive");
        assert!(GoldenCase::from_json_str(&v.to_string()).is_err());
        assert!(GoldenCase::from_json_str("[]").is_err());
        assert!(GoldenCase::from_json_str("{").is_err());
    }

    #[test]
    fn validate_reports_every_problem() {
        let mut c = case();
        c.id = "Bad Id".into();
        c.request.alert_id = 0;
        c.request.customer_code = "a b".into();
        c.alert = json!([1]);
        c.expect.severity = SeverityRange {
            min: Severity::High,
            max: Severity::Low,
        };
        c.expect.required_iocs.push(ExpectedIoc {
            ioc_type: None,
            value: "  ".into(),
        });
        c.expect.forbidden_iocs = vec!["".into(), "185.220.101[.]4".into()];
        c.expect.forbidden_strings = vec!["".into()];
        c.expect.forbidden_patterns = vec!["(".into(), "x*".into()];
        c.expect.required_mitre = vec!["T12".into()];
        let issues = c.validate();
        assert_eq!(issues.len(), 12, "{issues:#?}");
        assert!(issues.iter().any(|i| i.contains("also a required IOC")));
        assert!(
            issues
                .iter()
                .any(|i| i.contains("matches the empty string"))
        );
    }

    #[test]
    fn case_ids() {
        for ok in ["a", "sysmon-1_tp", "0day"] {
            assert!(is_valid_case_id(ok), "{ok}");
        }
        for bad in ["", "-a", "A", "a.b", "a/b", "../x", &"a".repeat(65)] {
            assert!(!is_valid_case_id(bad), "{bad}");
        }
    }

    #[test]
    fn wrong_verdict_and_severity_fail() {
        let mut rep = report();
        rep["verdict"] = json!("false_positive");
        rep["severity"] = json!("low");
        let r = score_case(&case(), &Outcome::Report(rep));
        assert!(!r.passed);
        assert_eq!(r.actual_verdict, "false_positive");
        let names: Vec<&str> = r.failures().map(|c| c.check.as_str()).collect();
        // The report is no longer coherent for the schema validator either
        // way; the two expectation checks must be among the failures.
        assert!(names.contains(&"verdict") && names.contains(&"severity"));
        let verdict = r.checks.iter().find(|c| c.check == "verdict").unwrap();
        assert!(
            verdict
                .detail
                .contains("expected true_positive or needs_escalation")
        );
    }

    #[test]
    fn also_acceptable_verdict_and_severity_aliases_pass() {
        let mut rep = report();
        rep["verdict"] = json!(" Needs_Escalation ");
        rep["severity"] = json!("Critical");
        let r = score_case(&case(), &Outcome::Report(rep));
        assert_eq!(r.actual_verdict, "needs_escalation");
        assert_eq!(r.actual_severity.as_deref(), Some("critical"));
        assert!(
            r.checks
                .iter()
                .filter(|c| matches!(c.check.as_str(), "verdict" | "severity"))
                .all(|c| c.passed)
        );
    }

    #[test]
    fn missing_required_ioc_and_type_mismatch() {
        let mut rep = report();
        // The IP is reported, but as a domain.
        rep["iocs"][0]["type"] = json!("domain");
        rep["iocs"].as_array_mut().unwrap().remove(1);
        let r = score_case(&case(), &Outcome::Report(rep));
        let f = failed(&r);
        assert!(f.contains(&("required_ioc", "185.220.101.4")), "{f:?}");
        assert!(
            f.iter()
                .any(|(c, s)| *c == "required_ioc" && s.starts_with("e3b0"))
        );
        assert!(!f.iter().any(|(_, s)| *s == "evil.example/a.ps1"));
    }

    #[test]
    fn required_ioc_matching_is_refanged_and_case_insensitive() {
        let mut c = case();
        c.expect.required_iocs = vec![
            ExpectedIoc {
                ioc_type: Some(ReportIocType::Ip),
                value: "185[.]220[.]101[.]4".into(),
            },
            ExpectedIoc {
                ioc_type: Some(ReportIocType::Process),
                value: "POWERSHELL.EXE".into(),
            },
        ];
        let mut rep = report();
        rep["iocs"].as_array_mut().unwrap().push(json!({
            "value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "type": "process", "verdict": "suspicious", "details": ""
        }));
        let r = score_case(&c, &Outcome::Report(rep));
        assert!(
            r.checks
                .iter()
                .filter(|k| k.check == "required_ioc")
                .all(|k| k.passed)
        );
        // Containment applies to free-form types only: an IP prefix is not
        // a match.
        c.expect.required_iocs = vec![ExpectedIoc {
            ioc_type: None,
            value: "185.220.101".into(),
        }];
        let r = score_case(&c, &Outcome::Report(report()));
        assert_eq!(failed(&r), vec![("required_ioc", "185.220.101")]);
    }

    #[test]
    fn hallucinated_indicator_is_caught_anywhere_in_the_report() {
        // In the summary, defanged.
        let mut rep = report();
        rep["summary"] = json!("Beaconing to 198[.]51[.]100[.]77 was observed.");
        let r = score_case(&case(), &Outcome::Report(rep));
        assert_eq!(failed(&r), vec![("forbidden_ioc", "198.51.100.77")]);

        // In a nested text field.
        let mut rep = report();
        rep["evidence"][0]["observation"] = json!("connection to 198.51.100.77:443");
        let r = score_case(&case(), &Outcome::Report(rep));
        assert_eq!(failed(&r), vec![("forbidden_ioc", "198.51.100.77")]);
    }

    #[test]
    fn forbidden_ioc_respects_token_boundaries() {
        // 185.220.101.40 is forbidden, 185.220.101.4 is in the report: the
        // good report passes (checked above). The reverse must not match
        // either.
        let mut c = case();
        c.expect.required_iocs.clear();
        c.expect.forbidden_iocs = vec!["185.220.101.4".into()];
        let mut rep = report();
        rep["iocs"][0]["value"] = json!("185.220.101.40");
        rep["summary"] = json!("Traffic to 185.220.101.40 and x185.220.101.4.");
        rep["iocs"].as_array_mut().unwrap().truncate(1);
        let r = score_case(&c, &Outcome::Report(rep.clone()));
        assert!(!failed(&r).iter().any(|(k, _)| *k == "forbidden_ioc"));
        // At a sentence end it does.
        rep["summary"] = json!("Traffic to 185.220.101.4.");
        let r = score_case(&c, &Outcome::Report(rep));
        assert!(failed(&r).contains(&("forbidden_ioc", "185.220.101.4")));
        assert!(!contains_token("abc", ""));
    }

    #[test]
    fn leaked_anonymization_tokens_are_caught() {
        let mut rep = report();
        rep["recommended_actions"][0]["action"] = json!("Reset the password of USER_1");
        let r = score_case(&case(), &Outcome::Report(rep));
        let f = failed(&r);
        assert!(f.contains(&("forbidden_string", "USER_1")), "{f:?}");
        assert!(f.iter().any(|(k, _)| *k == "forbidden_pattern"));

        // Only the pattern catches other tokens; strings are case-sensitive.
        let mut rep = report();
        rep["summary"] = json!("HOST_12 contacted user_1.");
        let r = score_case(&case(), &Outcome::Report(rep));
        let f = failed(&r);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].0, "forbidden_pattern");
        let detail = &r.failures().next().unwrap().detail;
        assert!(detail.contains("HOST_12"), "{detail}");
    }

    #[test]
    fn mitre_parent_and_sub_technique_rules() {
        let cited: HashSet<String> = ["T1059.001".to_string()].into();
        assert!(technique_cited("t1059", &cited));
        assert!(technique_cited("T1059.001", &cited));
        assert!(!technique_cited("T1059.003", &cited));
        assert!(!technique_cited("T105", &cited));
        let parent: HashSet<String> = ["T1059".to_string()].into();
        assert!(!technique_cited("T1059.001", &parent));

        let mut rep = report();
        rep["mitre"].as_array_mut().unwrap().remove(1);
        let r = score_case(&case(), &Outcome::Report(rep));
        assert_eq!(failed(&r), vec![("required_mitre", "T1204.002")]);
    }

    #[test]
    fn malformed_reports_are_scored_without_panicking() {
        let c = case();
        for rep in [
            json!(null),
            json!(42),
            json!([]),
            json!("not json at all"),
            json!({}),
            json!({"verdict": 7, "severity": ["high"], "iocs": "none", "mitre": {"a": 1}}),
            json!({"verdict": "true_positive", "severity": "high",
                   "iocs": [1, null, {"value": 5}, {"type": "ip"}, {"value": "185.220.101.4", "type": "bogus"}],
                   "mitre": [null, {"technique_id": 3}, "T1059"]}),
        ] {
            let r = score_case(&c, &Outcome::Report(rep.clone()));
            assert!(!r.passed, "{rep}");
            assert!(r.checks[0].passed, "report_present for {rep}");
            assert!(!r.checks[1].passed, "schema must fail for {rep}");
            assert_eq!(r.checks.len(), 13, "every expectation is still checked");
        }
        let r = score_case(&c, &Outcome::Report(json!({"verdict": "pwned"})));
        assert_eq!(r.actual_verdict, ACTUAL_INVALID);
        assert_eq!(r.actual_severity, None);
    }

    #[test]
    fn partially_valid_report_gets_credit_for_what_is_right() {
        // An unknown extra field breaks the strict schema; the content
        // checks still pass. The untyped required hash matches an IOC with
        // an unknown type.
        let mut rep = report();
        rep["extra"] = json!("x");
        rep["iocs"][1]["type"] = json!("sha256");
        let r = score_case(&case(), &Outcome::Report(rep));
        assert_eq!(failed(&r), vec![("schema", "")]);
    }

    #[test]
    fn report_wrapped_in_a_json_string_is_unwrapped() {
        let rep = Value::String(report().to_string());
        let r = score_case(&case(), &Outcome::Report(rep));
        assert!(r.passed, "{:?}", failed(&r));
    }

    #[test]
    fn untrusted_values_are_sanitised_in_details() {
        let mut rep = report();
        rep["verdict"] = json!(format!("\u{1b}[31mowned\u{7}{}", "x".repeat(500)));
        let r = score_case(&case(), &Outcome::Report(rep));
        let detail = &r
            .checks
            .iter()
            .find(|c| c.check == "verdict")
            .unwrap()
            .detail;
        assert!(!detail.contains('\u{1b}') && !detail.contains('\u{7}'));
        assert!(detail.chars().count() < MAX_DETAIL_CHARS + 40, "{detail}");

        let r = score_case(&case(), &Outcome::Failed("boom\u{1b}[2J".into()));
        assert!(!r.checks[0].detail.contains('\u{1b}'));
    }

    #[test]
    fn deeply_nested_report_does_not_overflow() {
        let mut v = json!("USER_1");
        for _ in 0..100 {
            v = json!([v]);
        }
        let r = score_case(&case(), &Outcome::Report(json!({"summary": v})));
        // Beyond the walk depth the string is simply not seen.
        assert!(
            r.checks
                .iter()
                .find(|c| c.check == "forbidden_string")
                .unwrap()
                .passed
        );
    }

    #[test]
    fn missing_and_failed_outcomes() {
        let r = score_case(&case(), &Outcome::Missing("no report file".into()));
        assert!(!r.passed);
        assert_eq!(r.actual_verdict, ACTUAL_MISSING);
        assert_eq!(failed(&r), vec![("report_present", "")]);
        let r = score_case(&case(), &Outcome::Failed("timed out".into()));
        assert_eq!(r.actual_verdict, ACTUAL_FAILED);
        assert_eq!(r.checks[0].detail, "timed out");
    }

    #[test]
    fn outcome_from_document() {
        // A bare report: `verdict` is a string.
        assert_eq!(Outcome::from_document(report()), Outcome::Report(report()));
        // Investigation records.
        let rec = |status: &str, verdict: Value, error: Value| {
            json!({"id": "copilot-inv-1-2", "alert_id": "1", "status": status,
                   "verdict": verdict, "error": error})
        };
        assert_eq!(
            Outcome::from_document(rec("completed", report(), json!(null))),
            Outcome::Report(report())
        );
        assert!(matches!(
            Outcome::from_document(rec("completed", json!(null), json!(null))),
            Outcome::Missing(m) if m.contains("completed without a structured verdict")
        ));
        assert!(matches!(
            Outcome::from_document(rec("failed", json!(null), json!("container exited 137"))),
            Outcome::Failed(m) if m.contains("container exited 137")
        ));
        assert!(matches!(
            Outcome::from_document(json!({"status": "running"})),
            Outcome::Missing(_)
        ));
        // Anything else is handed to the scorer as a (malformed) report.
        assert!(matches!(
            Outcome::from_document(json!([1])),
            Outcome::Report(_)
        ));
    }

    #[test]
    fn summary_totals_and_confusion_matrix() {
        let c = case();
        let mut benign = case();
        benign.id = "benign".into();
        benign.expect.verdict = Verdict::FalsePositive;
        let mut wrong = report();
        wrong["verdict"] = json!("inconclusive");
        let results = vec![
            score_case(&c, &Outcome::Report(report())),
            score_case(&c, &Outcome::Report(wrong)),
            score_case(&c, &Outcome::Missing("none".into())),
            score_case(&benign, &Outcome::Report(report())),
            score_case(&benign, &Outcome::Report(json!({"verdict": "??"}))),
        ];
        let s = summarize(results);
        assert_eq!((s.total, s.passed, s.failed), (5, 1, 4));
        assert!((s.pass_rate - 0.2).abs() < 1e-9);
        assert_eq!(s.confusion["true_positive"]["true_positive"], 1);
        assert_eq!(s.confusion["true_positive"]["inconclusive"], 1);
        assert_eq!(s.confusion["true_positive"][ACTUAL_MISSING], 1);
        assert_eq!(s.confusion["false_positive"]["true_positive"], 1);
        assert_eq!(s.confusion["false_positive"][ACTUAL_INVALID], 1);
        assert!(s.checks_passed < s.checks_total);
        assert!(s.meets(0.2) && s.meets(0.0) && !s.meets(0.21));

        // Serializes for `--json` and round-trips.
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["cases"][0]["checks"][0]["check"], "report_present");
        assert_eq!(serde_json::from_value::<Summary>(v).unwrap(), s);

        let table = s.render_table();
        assert!(table.contains("1/5 cases passed (20.0%)"), "{table}");
        assert!(table.contains("Failed checks:"));
        assert!(table.contains("benign: verdict [false_positive]"));
        assert!(table.contains("Verdict confusion"));
        assert!(table.lines().all(|l| l == l.trim_end()));
    }

    #[test]
    fn empty_summary_never_meets_a_threshold() {
        let s = summarize(Vec::new());
        assert_eq!(s.total, 0);
        assert!(s.pass_rate.abs() < f64::EPSILON);
        assert!(!s.meets(0.0));
        assert!(s.render_table().contains("0/0 cases passed"));
        let all = summarize(vec![score_case(&case(), &Outcome::Report(report()))]);
        assert!(all.meets(1.0));
        assert!(!all.render_table().contains("Failed checks"));
    }
}
