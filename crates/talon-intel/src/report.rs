//! Structured triage report: strict JSON schema (for vLLM guided decoding),
//! validation, sanitisation and Markdown rendering.
//!
//! IOC types and verdicts deliberately match CoPilot's
//! `SubmitAiAnalystIocsTool` (`ip|domain|hash|process|url|user|command`,
//! `malicious|suspicious|clean|unknown`) and severities its
//! `severity_assessment`, so a validated report can be written back without
//! re-mapping.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::common::{Severity, strip_control_chars, truncate_chars};
use crate::ioc::{self, IocType};
use crate::mitre::{self, Tactic};

/// Maximum characters in `summary`.
pub const MAX_SUMMARY_CHARS: usize = 2000;
/// Maximum characters in any other free-text field.
pub const MAX_TEXT_CHARS: usize = 1000;
/// Maximum IOC entries.
pub const MAX_IOCS: usize = 200;
/// Maximum MITRE entries.
pub const MAX_MITRE: usize = 50;
/// Maximum timeline entries.
pub const MAX_TIMELINE: usize = 100;
/// Maximum evidence entries.
pub const MAX_EVIDENCE: usize = 100;
/// Maximum recommended actions.
pub const MAX_ACTIONS: usize = 30;
/// Maximum `alert_id` length.
pub const MAX_ALERT_ID: usize = 128;

/// Final triage verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Malicious activity confirmed.
    TruePositive,
    /// The detection logic misfired; no malicious or policy-relevant activity.
    FalsePositive,
    /// The detection is correct but the activity is authorised/expected
    /// (admin tooling, pentest, known software).
    BenignTruePositive,
    /// Needs a human / IR team now (insufficient access or high stakes).
    NeedsEscalation,
    /// Not enough evidence either way.
    Inconclusive,
}

impl Verdict {
    /// Wire values.
    pub const ALL: [&'static str; 5] = [
        "true_positive",
        "false_positive",
        "benign_true_positive",
        "needs_escalation",
        "inconclusive",
    ];

    /// Human label.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::TruePositive => "True positive",
            Verdict::FalsePositive => "False positive",
            Verdict::BenignTruePositive => "Benign true positive",
            Verdict::NeedsEscalation => "Needs escalation",
            Verdict::Inconclusive => "Inconclusive",
        }
    }
}

/// IOC type (CoPilot vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportIocType {
    /// IPv4 / IPv6 address.
    Ip,
    /// Domain / host name.
    Domain,
    /// File hash (MD5/SHA1/SHA256/SHA512).
    Hash,
    /// Process / executable path or name.
    Process,
    /// URL.
    Url,
    /// User account.
    User,
    /// Command line.
    Command,
}

impl ReportIocType {
    /// Wire values.
    pub const ALL: [&'static str; 7] =
        ["ip", "domain", "hash", "process", "url", "user", "command"];

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ReportIocType::Ip => "ip",
            ReportIocType::Domain => "domain",
            ReportIocType::Hash => "hash",
            ReportIocType::Process => "process",
            ReportIocType::Url => "url",
            ReportIocType::User => "user",
            ReportIocType::Command => "command",
        }
    }

    /// Map an extracted indicator type (`None` for types CoPilot has no
    /// slot for: CVE, MITRE, registry, user agent, e-mail).
    pub fn from_ioc_type(t: IocType) -> Option<Self> {
        match t {
            IocType::Ipv4 | IocType::Ipv6 => Some(ReportIocType::Ip),
            IocType::Domain => Some(ReportIocType::Domain),
            IocType::Url => Some(ReportIocType::Url),
            t if t.is_hash() => Some(ReportIocType::Hash),
            IocType::WindowsPath | IocType::UnixPath => Some(ReportIocType::Process),
            _ => None,
        }
    }
}

/// Threat-intel verdict for one IOC (CoPilot `vt_verdict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocVerdict {
    /// Known bad.
    Malicious,
    /// Some negative reputation.
    Suspicious,
    /// Known good / no detections.
    Clean,
    /// Not looked up or no data.
    Unknown,
}

impl IocVerdict {
    /// Wire values.
    pub const ALL: [&'static str; 4] = ["malicious", "suspicious", "clean", "unknown"];

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            IocVerdict::Malicious => "malicious",
            IocVerdict::Suspicious => "suspicious",
            IocVerdict::Clean => "clean",
            IocVerdict::Unknown => "unknown",
        }
    }
}

/// Direction an evidence item points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAssessment {
    /// Points to malicious activity.
    SupportsMalicious,
    /// Points to benign activity.
    SupportsBenign,
    /// Context only.
    Neutral,
}

impl EvidenceAssessment {
    /// Wire values.
    pub const ALL: [&'static str; 3] = ["supports_malicious", "supports_benign", "neutral"];
}

/// Urgency of a recommended action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPriority {
    /// Do now (containment).
    Immediate,
    /// Within hours.
    High,
    /// Within days.
    Medium,
    /// Hardening / follow-up.
    Low,
}

impl ActionPriority {
    /// Wire values.
    pub const ALL: [&'static str; 4] = ["immediate", "high", "medium", "low"];

    fn label(self) -> &'static str {
        match self {
            ActionPriority::Immediate => "Immediate",
            ActionPriority::High => "High",
            ActionPriority::Medium => "Medium",
            ActionPriority::Low => "Low",
        }
    }
}

/// One indicator in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportIoc {
    /// Indicator value (refanged).
    pub value: String,
    /// Indicator type.
    #[serde(rename = "type")]
    pub ioc_type: ReportIocType,
    /// Threat-intel verdict.
    pub verdict: IocVerdict,
    /// Enrichment details (engine counts, reputation, context).
    pub details: String,
}

/// One ATT&CK technique in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportMitre {
    /// `T1059.001`.
    pub technique_id: String,
    /// Technique name.
    pub name: String,
    /// Tactic this activity serves.
    pub tactic: Tactic,
    /// Why the technique applies.
    pub rationale: String,
}

/// One timeline event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineEntry {
    /// ISO-8601 timestamp (UTC preferred).
    pub timestamp: String,
    /// What happened.
    pub event: String,
}

/// One piece of evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// The observation.
    pub observation: String,
    /// Where it came from (SIEM field, tool, intel source).
    pub source: String,
    /// What it supports.
    pub assessment: EvidenceAssessment,
}

/// One recommended action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendedAction {
    /// The action (imperative).
    pub action: String,
    /// Urgency.
    pub priority: ActionPriority,
    /// Why.
    pub rationale: String,
}

/// The structured verdict an investigation ends with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageReport {
    /// CoPilot alert id (or another stable reference).
    pub alert_id: String,
    /// Verdict.
    pub verdict: Verdict,
    /// Confidence in the verdict, 0–100.
    pub confidence: u8,
    /// Severity assessment.
    pub severity: Severity,
    /// 1–3 sentence summary leading with the finding.
    pub summary: String,
    /// Indicators with intel verdicts.
    pub iocs: Vec<ReportIoc>,
    /// ATT&CK techniques observed.
    pub mitre: Vec<ReportMitre>,
    /// Chronological events.
    pub timeline: Vec<TimelineEntry>,
    /// Evidence for and against.
    pub evidence: Vec<Evidence>,
    /// Recommended actions.
    pub recommended_actions: Vec<RecommendedAction>,
}

/// One validation problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// JSON path (`iocs[2].value`).
    pub path: String,
    /// Problem.
    pub message: String,
}

/// Result of [`TriageReport::validate`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validation {
    /// Blocking problems.
    pub errors: Vec<ValidationIssue>,
    /// Non-blocking coherence warnings.
    pub warnings: Vec<ValidationIssue>,
}

impl Validation {
    /// No errors.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    fn err(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.errors.push(ValidationIssue {
            path: path.into(),
            message: message.into(),
        });
    }

    fn warn(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(ValidationIssue {
            path: path.into(),
            message: message.into(),
        });
    }

    /// Render as a bullet list.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for e in &self.errors {
            let _ = writeln!(out, "- error at `{}`: {}", e.path, e.message);
        }
        for w in &self.warnings {
            let _ = writeln!(out, "- warning at `{}`: {}", w.path, w.message);
        }
        out
    }
}

fn str_schema(description: &str, max: usize) -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": max, "description": description})
}

fn enum_schema(values: &[&str], description: &str) -> Value {
    json!({"type": "string", "enum": values, "description": description})
}

fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

/// Strict JSON schema of [`TriageReport`]: every object closes with
/// `additionalProperties: false`, every property is required, closed
/// vocabularies are enums. Suitable for vLLM `response_format`
/// (`json_schema`) / guided decoding.
pub fn json_schema() -> Value {
    let tactics: Vec<&str> = Tactic::ALL.iter().map(|t| t.name()).collect();
    let severities: Vec<&str> = Severity::ALL.iter().map(|s| s.as_str()).collect();
    object_schema(
        json!({
            "alert_id": str_schema("CoPilot alert id or other stable reference", MAX_ALERT_ID),
            "verdict": enum_schema(&Verdict::ALL, "true_positive: malicious activity confirmed; false_positive: detection misfired; benign_true_positive: correct detection of authorised/expected activity; needs_escalation: hand to a human/IR now; inconclusive: not enough evidence"),
            "confidence": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Confidence in the verdict (0-100)"},
            "severity": enum_schema(&severities, "Severity assessment"),
            "summary": str_schema("1-3 sentences leading with the finding", MAX_SUMMARY_CHARS),
            "iocs": {
                "type": "array",
                "maxItems": MAX_IOCS,
                "items": object_schema(json!({
                    "value": str_schema("Indicator value (not defanged)", MAX_TEXT_CHARS),
                    "type": enum_schema(&ReportIocType::ALL, "Indicator type"),
                    "verdict": enum_schema(&IocVerdict::ALL, "Threat-intel verdict"),
                    "details": {"type": "string", "maxLength": MAX_TEXT_CHARS, "description": "Enrichment details"}
                }), &["value", "type", "verdict", "details"])
            },
            "mitre": {
                "type": "array",
                "maxItems": MAX_MITRE,
                "items": object_schema(json!({
                    "technique_id": {"type": "string", "minLength": 5, "maxLength": 9, "description": "ATT&CK id, e.g. T1059.001"},
                    "name": str_schema("Technique name", 200),
                    "tactic": enum_schema(&tactics, "Tactic"),
                    "rationale": str_schema("Why the technique applies", MAX_TEXT_CHARS)
                }), &["technique_id", "name", "tactic", "rationale"])
            },
            "timeline": {
                "type": "array",
                "maxItems": MAX_TIMELINE,
                "items": object_schema(json!({
                    "timestamp": str_schema("ISO-8601 timestamp", 64),
                    "event": str_schema("What happened", MAX_TEXT_CHARS)
                }), &["timestamp", "event"])
            },
            "evidence": {
                "type": "array",
                "maxItems": MAX_EVIDENCE,
                "items": object_schema(json!({
                    "observation": str_schema("Observation", MAX_TEXT_CHARS),
                    "source": str_schema("Field, tool or intel source", 200),
                    "assessment": enum_schema(&EvidenceAssessment::ALL, "What the observation supports")
                }), &["observation", "source", "assessment"])
            },
            "recommended_actions": {
                "type": "array",
                "maxItems": MAX_ACTIONS,
                "items": object_schema(json!({
                    "action": str_schema("Action (imperative)", MAX_TEXT_CHARS),
                    "priority": enum_schema(&ActionPriority::ALL, "Urgency"),
                    "rationale": {"type": "string", "maxLength": MAX_TEXT_CHARS, "description": "Why"}
                }), &["action", "priority", "rationale"])
            }
        }),
        &[
            "alert_id",
            "verdict",
            "confidence",
            "severity",
            "summary",
            "iocs",
            "mitre",
            "timeline",
            "evidence",
            "recommended_actions",
        ],
    )
}

/// [`json_schema`] reduced to the keywords every guided-decoding backend
/// supports (`type`, `properties`, `required`, `additionalProperties`,
/// `enum`, `items`, `description`): length, size and range limits are
/// dropped. Use [`TriageReport::clamp_to_limits`] + [`TriageReport::validate`]
/// on the decoded result to enforce them.
pub fn guided_json_schema() -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(o) => {
                for k in [
                    "minLength",
                    "maxLength",
                    "maxItems",
                    "minItems",
                    "minimum",
                    "maximum",
                ] {
                    o.remove(k);
                }
                for child in o.values_mut() {
                    strip(child);
                }
            }
            Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut s = json_schema();
    strip(&mut s);
    s
}

/// OpenAI/vLLM `response_format` (`json_schema`, strict) for a triage
/// report; `guided` selects [`guided_json_schema`] over [`json_schema`].
pub fn response_format(guided: bool) -> Value {
    let schema = if guided {
        guided_json_schema()
    } else {
        json_schema()
    };
    json!({
        "type": "json_schema",
        "json_schema": {"name": "triage_report", "strict": true, "schema": schema}
    })
}

fn clean(s: &str) -> String {
    strip_control_chars(s).trim().to_string()
}

fn check_text(v: &mut Validation, path: &str, s: &str, max: usize, required: bool) {
    let n = s.chars().count();
    if required && s.trim().is_empty() {
        v.err(path, "must not be empty");
    }
    if n > max {
        v.err(path, format!("too long ({n} > {max} characters)"));
    }
}

fn check_ioc_value(t: ReportIocType, value: &str) -> Result<(), String> {
    let v = ioc::refang(value.trim()).into_owned();
    match t {
        ReportIocType::Ip => v
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| format!("{value:?} is not an IP address")),
        ReportIocType::Domain => {
            if ioc::is_valid_hostname(&v.to_ascii_lowercase()) {
                Ok(())
            } else {
                Err(format!("{value:?} is not a valid domain"))
            }
        }
        ReportIocType::Hash => {
            let ok =
                matches!(v.len(), 32 | 40 | 64 | 128) && v.chars().all(|c| c.is_ascii_hexdigit());
            if ok {
                Ok(())
            } else {
                Err(format!(
                    "{value:?} is not an MD5/SHA1/SHA256/SHA512 hex digest"
                ))
            }
        }
        ReportIocType::Url => match url::Url::parse(&v) {
            Ok(u) if u.host_str().is_some_and(|h| !h.is_empty()) => Ok(()),
            _ => Err(format!("{value:?} is not an absolute URL with a host")),
        },
        ReportIocType::Process | ReportIocType::User | ReportIocType::Command => Ok(()),
    }
}

impl TriageReport {
    /// Parse from JSON (also accepts a JSON string containing the object).
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let owned;
        let v = match v {
            Value::String(s) => {
                owned = serde_json::from_str::<Value>(s)
                    .map_err(|e| format!("report is not valid JSON: {e}"))?;
                &owned
            }
            other => other,
        };
        serde_json::from_value(v.clone())
            .map_err(|e| format!("report does not match the schema: {e}"))
    }

    /// Normalise in place: strip control characters, trim, refang and
    /// canonicalise IOC values (lowercase hashes/domains, uppercase
    /// technique ids), drop duplicate IOCs, clamp confidence.
    pub fn sanitize(&mut self) {
        self.alert_id = clean(&self.alert_id);
        self.summary = clean(&self.summary);
        self.confidence = self.confidence.min(100);
        let mut seen = HashSet::new();
        self.iocs.retain_mut(|i| {
            i.details = clean(&i.details);
            let mut v = clean(&i.value);
            if matches!(
                i.ioc_type,
                ReportIocType::Ip | ReportIocType::Domain | ReportIocType::Url
            ) {
                v = ioc::refang(&v).into_owned();
            }
            if matches!(
                i.ioc_type,
                ReportIocType::Hash | ReportIocType::Domain | ReportIocType::Ip
            ) {
                v = v.to_ascii_lowercase();
            }
            if i.ioc_type == ReportIocType::Domain {
                v = v.trim_end_matches('.').to_string();
            }
            i.value = v;
            let key = if matches!(i.ioc_type, ReportIocType::Url | ReportIocType::Command) {
                i.value.clone()
            } else {
                i.value.to_lowercase()
            };
            seen.insert((i.ioc_type, key))
        });
        for m in &mut self.mitre {
            m.technique_id = clean(&m.technique_id).to_ascii_uppercase();
            m.name = clean(&m.name);
            m.rationale = clean(&m.rationale);
        }
        for t in &mut self.timeline {
            t.timestamp = clean(&t.timestamp);
            t.event = clean(&t.event);
        }
        for e in &mut self.evidence {
            e.observation = clean(&e.observation);
            e.source = clean(&e.source);
        }
        for a in &mut self.recommended_actions {
            a.action = clean(&a.action);
            a.rationale = clean(&a.rationale);
        }
        self.timeline.sort_by(|a, b| {
            let pa = crate::alert::parse_timestamp_str(&a.timestamp);
            let pb = crate::alert::parse_timestamp_str(&b.timestamp);
            match (pa, pb) {
                (Some(x), Some(y)) => x.cmp(&y),
                _ => std::cmp::Ordering::Equal,
            }
        });
    }

    /// Truncate over-long text and lists to the schema limits (useful after
    /// guided decoding with [`guided_json_schema`]); never drops required
    /// structure. Text is cut on character boundaries with an ellipsis.
    pub fn clamp_to_limits(&mut self) {
        let cut = |s: &mut String, max: usize| {
            if s.chars().count() > max {
                *s = truncate_chars(s, max);
            }
        };
        cut(&mut self.alert_id, MAX_ALERT_ID);
        cut(&mut self.summary, MAX_SUMMARY_CHARS);
        self.confidence = self.confidence.min(100);
        self.iocs.truncate(MAX_IOCS);
        self.mitre.truncate(MAX_MITRE);
        self.timeline.truncate(MAX_TIMELINE);
        self.evidence.truncate(MAX_EVIDENCE);
        self.recommended_actions.truncate(MAX_ACTIONS);
        for i in &mut self.iocs {
            cut(&mut i.value, MAX_TEXT_CHARS);
            cut(&mut i.details, MAX_TEXT_CHARS);
        }
        for m in &mut self.mitre {
            cut(&mut m.name, 200);
            cut(&mut m.rationale, MAX_TEXT_CHARS);
        }
        for t in &mut self.timeline {
            cut(&mut t.timestamp, 64);
            cut(&mut t.event, MAX_TEXT_CHARS);
        }
        for e in &mut self.evidence {
            cut(&mut e.observation, MAX_TEXT_CHARS);
            cut(&mut e.source, 200);
        }
        for a in &mut self.recommended_actions {
            cut(&mut a.action, MAX_TEXT_CHARS);
            cut(&mut a.rationale, MAX_TEXT_CHARS);
        }
    }

    /// Validate structure, value formats and verdict coherence.
    pub fn validate(&self) -> Validation {
        let mut v = Validation::default();
        check_text(&mut v, "alert_id", &self.alert_id, MAX_ALERT_ID, true);
        check_text(&mut v, "summary", &self.summary, MAX_SUMMARY_CHARS, true);
        if self.confidence > 100 {
            v.err("confidence", "must be between 0 and 100");
        }
        for (name, len, max) in [
            ("iocs", self.iocs.len(), MAX_IOCS),
            ("mitre", self.mitre.len(), MAX_MITRE),
            ("timeline", self.timeline.len(), MAX_TIMELINE),
            ("evidence", self.evidence.len(), MAX_EVIDENCE),
            (
                "recommended_actions",
                self.recommended_actions.len(),
                MAX_ACTIONS,
            ),
        ] {
            if len > max {
                v.err(name, format!("too many entries ({len} > {max})"));
            }
        }
        for (i, ioc) in self.iocs.iter().enumerate() {
            let p = format!("iocs[{i}]");
            check_text(
                &mut v,
                &format!("{p}.value"),
                &ioc.value,
                MAX_TEXT_CHARS,
                true,
            );
            check_text(
                &mut v,
                &format!("{p}.details"),
                &ioc.details,
                MAX_TEXT_CHARS,
                false,
            );
            if let Err(e) = check_ioc_value(ioc.ioc_type, &ioc.value) {
                v.err(format!("{p}.value"), e);
            }
        }
        for (i, m) in self.mitre.iter().enumerate() {
            let p = format!("mitre[{i}]");
            if !mitre::is_technique_id(m.technique_id.trim()) {
                v.err(
                    format!("{p}.technique_id"),
                    format!(
                        "{:?} is not a technique id (T1234 or T1234.001)",
                        m.technique_id
                    ),
                );
                continue;
            }
            check_text(&mut v, &format!("{p}.name"), &m.name, 200, true);
            check_text(
                &mut v,
                &format!("{p}.rationale"),
                &m.rationale,
                MAX_TEXT_CHARS,
                true,
            );
            match mitre::technique(&m.technique_id) {
                Some(t) => {
                    let name = m.name.trim().to_ascii_lowercase();
                    if name != t.name.to_ascii_lowercase()
                        && name != t.full_name().to_ascii_lowercase()
                    {
                        v.warn(
                            format!("{p}.name"),
                            format!("ATT&CK name for {} is {:?}", t.id, t.full_name()),
                        );
                    }
                    if !t.tactics.contains(&m.tactic) {
                        let names: Vec<&str> = t.tactics.iter().map(|t| t.name()).collect();
                        v.warn(
                            format!("{p}.tactic"),
                            format!("{} belongs to {}", t.id, names.join(", ")),
                        );
                    }
                }
                None => v.warn(
                    format!("{p}.technique_id"),
                    format!(
                        "{} is not in the embedded ATT&CK table; double-check it",
                        m.technique_id
                    ),
                ),
            }
        }
        for (i, t) in self.timeline.iter().enumerate() {
            let p = format!("timeline[{i}]");
            check_text(
                &mut v,
                &format!("{p}.event"),
                &t.event,
                MAX_TEXT_CHARS,
                true,
            );
            if crate::alert::parse_timestamp_str(&t.timestamp).is_none() {
                v.warn(
                    format!("{p}.timestamp"),
                    format!("{:?} is not an ISO-8601 timestamp", t.timestamp),
                );
            }
        }
        for (i, e) in self.evidence.iter().enumerate() {
            let p = format!("evidence[{i}]");
            check_text(
                &mut v,
                &format!("{p}.observation"),
                &e.observation,
                MAX_TEXT_CHARS,
                true,
            );
            check_text(&mut v, &format!("{p}.source"), &e.source, 200, true);
        }
        for (i, a) in self.recommended_actions.iter().enumerate() {
            let p = format!("recommended_actions[{i}]");
            check_text(
                &mut v,
                &format!("{p}.action"),
                &a.action,
                MAX_TEXT_CHARS,
                true,
            );
            check_text(
                &mut v,
                &format!("{p}.rationale"),
                &a.rationale,
                MAX_TEXT_CHARS,
                false,
            );
        }

        // Coherence (warnings: the model may have good reasons).
        match self.verdict {
            Verdict::TruePositive => {
                if self.confidence < 40 {
                    v.warn("confidence", "true_positive with confidence below 40; consider inconclusive or needs_escalation");
                }
                if self.recommended_actions.is_empty() {
                    v.warn(
                        "recommended_actions",
                        "a true positive should come with recommended actions",
                    );
                }
                if self.severity == Severity::Informational {
                    v.warn("severity", "true_positive with informational severity");
                }
                if self
                    .evidence
                    .iter()
                    .all(|e| e.assessment != EvidenceAssessment::SupportsMalicious)
                {
                    v.warn(
                        "evidence",
                        "true_positive without evidence that supports_malicious",
                    );
                }
            }
            Verdict::FalsePositive | Verdict::BenignTruePositive => {
                if self.severity >= Severity::High {
                    v.warn(
                        "severity",
                        "benign verdicts normally carry low or informational severity",
                    );
                }
                if self.iocs.iter().any(|i| i.verdict == IocVerdict::Malicious) {
                    v.warn("iocs", "benign verdict while an IOC is marked malicious");
                }
            }
            Verdict::NeedsEscalation => {
                if !self
                    .recommended_actions
                    .iter()
                    .any(|a| a.priority <= ActionPriority::High)
                {
                    v.warn(
                        "recommended_actions",
                        "needs_escalation should include an immediate or high-priority action",
                    );
                }
            }
            Verdict::Inconclusive => {}
        }
        v
    }

    /// Render the analyst-facing Markdown. Network indicators are defanged
    /// so that chat clients do not turn them into live links.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        let _ = writeln!(md, "# Triage report: alert {}", inline(&self.alert_id));
        let _ = writeln!(md);
        let _ = writeln!(
            md,
            "**Verdict:** {} | **Severity:** {} | **Confidence:** {}%",
            self.verdict.label(),
            self.severity.label(),
            self.confidence
        );
        let _ = writeln!(md);
        let _ = writeln!(md, "## Summary\n\n{}\n", self.summary);

        if !self.iocs.is_empty() {
            let _ = writeln!(md, "## Indicators of compromise\n");
            let _ = writeln!(
                md,
                "| Indicator | Type | Verdict | Details |\n|---|---|---|---|"
            );
            for i in &self.iocs {
                let shown = match i.ioc_type {
                    ReportIocType::Ip => ioc::defang(
                        &i.value,
                        if i.value.contains(':') {
                            IocType::Ipv6
                        } else {
                            IocType::Ipv4
                        },
                    ),
                    ReportIocType::Domain => ioc::defang(&i.value, IocType::Domain),
                    ReportIocType::Url => ioc::defang(&i.value, IocType::Url),
                    _ => i.value.clone(),
                };
                let verdict = match i.verdict {
                    IocVerdict::Malicious | IocVerdict::Suspicious => {
                        format!("**{}**", i.verdict.as_str())
                    }
                    other => other.as_str().to_string(),
                };
                let _ = writeln!(
                    md,
                    "| {} | {} | {} | {} |",
                    code(&truncate_chars(&shown, 200)),
                    i.ioc_type.as_str(),
                    verdict,
                    cell(&i.details)
                );
            }
            let _ = writeln!(md);
        }

        if !self.mitre.is_empty() {
            let _ = writeln!(md, "## MITRE ATT&CK\n");
            let _ = writeln!(
                md,
                "| Technique | Name | Tactic | Rationale |\n|---|---|---|---|"
            );
            for m in &self.mitre {
                let _ = writeln!(
                    md,
                    "| {} | {} | {} | {} |",
                    cell(&m.technique_id),
                    cell(&m.name),
                    m.tactic.name(),
                    cell(&m.rationale)
                );
            }
            let _ = writeln!(md);
        }

        if !self.timeline.is_empty() {
            let _ = writeln!(md, "## Timeline\n");
            let _ = writeln!(md, "| Time | Event |\n|---|---|");
            for t in &self.timeline {
                let _ = writeln!(md, "| {} | {} |", cell(&t.timestamp), cell(&t.event));
            }
            let _ = writeln!(md);
        }

        if !self.evidence.is_empty() {
            let _ = writeln!(md, "## Evidence\n");
            for e in &self.evidence {
                let tag = match e.assessment {
                    EvidenceAssessment::SupportsMalicious => "malicious",
                    EvidenceAssessment::SupportsBenign => "benign",
                    EvidenceAssessment::Neutral => "context",
                };
                let _ = writeln!(
                    md,
                    "- [{tag}] {} (source: {})",
                    one_line(&e.observation),
                    one_line(&e.source)
                );
            }
            let _ = writeln!(md);
        }

        if !self.recommended_actions.is_empty() {
            let _ = writeln!(md, "## Recommended actions\n");
            let mut actions = self.recommended_actions.clone();
            actions.sort_by_key(|a| a.priority);
            for (n, a) in actions.iter().enumerate() {
                let _ = write!(
                    md,
                    "{}. **[{}]** {}",
                    n + 1,
                    a.priority.label(),
                    one_line(&a.action)
                );
                if !a.rationale.trim().is_empty() {
                    let _ = write!(md, " — {}", one_line(&a.rationale));
                }
                let _ = writeln!(md);
            }
        }
        md.trim_end().to_string() + "\n"
    }
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn cell(s: &str) -> String {
    one_line(s).replace('|', "\\|")
}

fn code(s: &str) -> String {
    let s = one_line(s);
    if s.contains('`') {
        format!("`` {} ``", s.replace('|', "\\|"))
    } else {
        format!("`{}`", s.replace('|', "\\|"))
    }
}

fn inline(s: &str) -> String {
    one_line(s).replace(['`', '*', '_', '[', ']'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> TriageReport {
        serde_json::from_value(json!({
            "alert_id": "48213",
            "verdict": "true_positive",
            "confidence": 85,
            "severity": "high",
            "summary": "PowerShell launched from WINWORD.EXE downloaded and executed a payload from 185.220.101.4.",
            "iocs": [
                {"value": "185.220.101[.]4", "type": "ip", "verdict": "malicious", "details": "45/94 engines; Tor exit node"},
                {"value": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "type": "hash", "verdict": "suspicious", "details": "first seen 2 days ago"},
                {"value": "hxxp://evil.example/a.ps1", "type": "url", "verdict": "malicious", "details": "payload | stage 2"},
                {"value": "185.220.101.4", "type": "ip", "verdict": "malicious", "details": "dup"}
            ],
            "mitre": [
                {"technique_id": "t1059.001", "name": "PowerShell", "tactic": "Execution", "rationale": "encoded PowerShell"},
                {"technique_id": "T1204.002", "name": "Malicious File", "tactic": "Execution", "rationale": "macro document"}
            ],
            "timeline": [
                {"timestamp": "2024-05-01T12:00:05Z", "event": "powershell.exe started"},
                {"timestamp": "2024-05-01T12:00:00Z", "event": "WINWORD.EXE opened invoice.docm"}
            ],
            "evidence": [
                {"observation": "Office spawned PowerShell with -enc", "source": "data_win_eventdata_parentImage", "assessment": "supports_malicious"}
            ],
            "recommended_actions": [
                {"action": "Reset the user's password", "priority": "high", "rationale": "possible credential theft"},
                {"action": "Isolate WS-042", "priority": "immediate", "rationale": "active C2"}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn schema_is_strict() {
        fn walk(v: &Value, path: &str) {
            if let Some(o) = v.as_object() {
                if o.get("type") == Some(&json!("object")) {
                    assert_eq!(o.get("additionalProperties"), Some(&json!(false)), "{path}");
                    let props: Vec<&String> = o["properties"].as_object().unwrap().keys().collect();
                    let req: Vec<&str> = o["required"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap())
                        .collect();
                    for p in props {
                        assert!(req.contains(&p.as_str()), "{path}.{p} not required");
                    }
                }
                for (k, child) in o {
                    walk(child, &format!("{path}.{k}"));
                }
            } else if let Some(a) = v.as_array() {
                for c in a {
                    walk(c, path);
                }
            }
        }
        let s = json_schema();
        walk(&s, "$");
        assert_eq!(
            s["properties"]["verdict"]["enum"]
                .as_array()
                .map(|a| a.len()),
            Some(5)
        );
        assert_eq!(
            s["properties"]["iocs"]["items"]["properties"]["type"]["enum"]
                .as_array()
                .map(|a| a.len()),
            Some(7)
        );
        assert_eq!(
            s["properties"]["mitre"]["items"]["properties"]["tactic"]["enum"]
                .as_array()
                .map(|a| a.len()),
            Some(14)
        );
        assert_eq!(response_format(false)["json_schema"]["strict"], json!(true));
        let g = guided_json_schema();
        let text = g.to_string();
        for k in ["maxLength", "minLength", "maxItems", "minimum", "maximum"] {
            assert!(!text.contains(k), "{k} left in guided schema");
        }
        walk(&g, "$");
        assert_eq!(response_format(true)["json_schema"]["schema"], g);
    }

    #[test]
    fn sample_validates_after_sanitize() {
        let mut r = sample();
        r.sanitize();
        let v = r.validate();
        assert!(v.is_ok(), "{}", v.render());
        assert_eq!(r.iocs.len(), 3, "duplicate IP removed");
        assert_eq!(r.iocs[0].value, "185.220.101.4");
        assert_eq!(r.iocs[2].value, "http://evil.example/a.ps1");
        assert!(r.iocs[1].value.chars().all(|c| !c.is_ascii_uppercase()));
        assert_eq!(r.mitre[0].technique_id, "T1059.001");
        assert_eq!(r.timeline[0].event, "WINWORD.EXE opened invoice.docm");
        assert!(v.warnings.is_empty(), "{}", v.render());
    }

    #[test]
    fn schema_matches_serde_shape() {
        // Every serialized key exists in the schema and vice versa.
        let r = sample();
        let v = serde_json::to_value(&r).unwrap();
        let s = json_schema();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        let props: Vec<&String> = s["properties"].as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), props.len());
        for k in keys {
            assert!(s["properties"].get(k).is_some(), "{k}");
        }
        let ioc_keys: Vec<&String> = v["iocs"][0].as_object().unwrap().keys().collect();
        for k in ioc_keys {
            assert!(
                s["properties"]["iocs"]["items"]["properties"]
                    .get(k)
                    .is_some(),
                "{k}"
            );
        }
    }

    #[test]
    fn invalid_values_are_errors() {
        let mut r = sample();
        r.iocs[0].value = "999.1.1.1".into();
        r.iocs[1].value = "xyz".into();
        r.mitre[0].technique_id = "TA0002".into();
        r.summary = String::new();
        let v = r.validate();
        let paths: Vec<&str> = v.errors.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"iocs[0].value"));
        assert!(paths.contains(&"iocs[1].value"));
        assert!(paths.contains(&"mitre[0].technique_id"));
        assert!(paths.contains(&"summary"));
    }

    #[test]
    fn unknown_fields_and_bad_enums_rejected() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["extra"] = json!(1);
        assert!(TriageReport::from_json(&v).is_err());
        let mut v = serde_json::to_value(sample()).unwrap();
        v["verdict"] = json!("malicious");
        assert!(TriageReport::from_json(&v).unwrap_err().contains("schema"));
        let s = serde_json::to_string(&sample()).unwrap();
        assert!(TriageReport::from_json(&Value::String(s)).is_ok());
        let mut v = serde_json::to_value(sample()).unwrap();
        v["severity"] = json!("High");
        assert!(
            TriageReport::from_json(&v).is_ok(),
            "CoPilot capitalisation accepted"
        );
    }

    #[test]
    fn coherence_warnings() {
        let mut r = sample();
        r.verdict = Verdict::FalsePositive;
        r.severity = Severity::Critical;
        let v = r.validate();
        assert!(v.is_ok());
        assert!(v.warnings.iter().any(|w| w.path == "severity"));
        assert!(v.warnings.iter().any(|w| w.path == "iocs"));
        let mut r = sample();
        r.mitre[1].name = "Something Else".into();
        r.mitre[1].tactic = Tactic::Impact;
        r.timeline[0].timestamp = "yesterday".into();
        let v = r.validate();
        assert!(v.warnings.iter().any(|w| w.path == "mitre[1].name"));
        assert!(v.warnings.iter().any(|w| w.path == "mitre[1].tactic"));
        assert!(v.warnings.iter().any(|w| w.path == "timeline[0].timestamp"));
        let mut r = sample();
        r.verdict = Verdict::NeedsEscalation;
        r.recommended_actions.clear();
        assert!(
            r.validate()
                .warnings
                .iter()
                .any(|w| w.path == "recommended_actions")
        );
    }

    #[test]
    fn markdown_rendering() {
        let mut r = sample();
        r.sanitize();
        let md = r.to_markdown();
        assert!(md.starts_with("# Triage report: alert 48213"));
        assert!(
            md.contains("**Verdict:** True positive | **Severity:** High | **Confidence:** 85%")
        );
        assert!(md.contains("`185[.]220[.]101[.]4`"), "{md}");
        assert!(md.contains("`hxxp://evil[.]example/a.ps1`"), "{md}");
        assert!(md.contains("payload \\| stage 2"));
        assert!(md.contains("| T1059.001 | PowerShell | Execution |"));
        // Actions sorted by priority.
        let iso = md.find("Isolate WS-042").unwrap_or(usize::MAX);
        let reset = md.find("Reset the user's password").unwrap_or(0);
        assert!(iso < reset);
        assert!(md.contains("1. **[Immediate]** Isolate WS-042 — active C2"));
        assert!(md.contains("- [malicious] Office spawned PowerShell with -enc"));
    }

    #[test]
    fn sanitize_strips_control_chars() {
        let mut r = sample();
        r.summary = "bad\u{0}summary\u{1b}[31m\nline2".into();
        r.sanitize();
        assert_eq!(r.summary, "badsummary[31m\nline2");
    }

    #[test]
    fn ioc_type_mapping() {
        assert_eq!(
            ReportIocType::from_ioc_type(IocType::Sha256),
            Some(ReportIocType::Hash)
        );
        assert_eq!(
            ReportIocType::from_ioc_type(IocType::Ipv6),
            Some(ReportIocType::Ip)
        );
        assert_eq!(
            ReportIocType::from_ioc_type(IocType::WindowsPath),
            Some(ReportIocType::Process)
        );
        assert_eq!(ReportIocType::from_ioc_type(IocType::Cve), None);
    }

    #[test]
    fn clamp_makes_oversized_reports_valid() {
        let mut r = sample();
        r.summary = "x".repeat(MAX_SUMMARY_CHARS + 50);
        r.recommended_actions = (0..(MAX_ACTIONS + 5))
            .map(|i| RecommendedAction {
                action: format!("action {i}"),
                priority: ActionPriority::Medium,
                rationale: "y".repeat(MAX_TEXT_CHARS * 2),
            })
            .collect();
        assert!(!r.validate().is_ok());
        r.clamp_to_limits();
        r.sanitize();
        let v = r.validate();
        assert!(v.is_ok(), "{}", v.render());
        assert_eq!(r.summary.chars().count(), MAX_SUMMARY_CHARS);
        assert_eq!(r.recommended_actions.len(), MAX_ACTIONS);
    }
}
