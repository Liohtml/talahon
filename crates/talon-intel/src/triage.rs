//! Deterministic, explainable risk scoring (0–100 + severity + rationale).
//!
//! The score is a *grounded prior* for the LLM, not a verdict. It is the sum
//! of independent, bounded factors, clamped to `0..=100`:
//!
//! | factor | points |
//! |---|---|
//! | Wazuh rule level (band-aligned: 4→20, 8→40, 12→60, 15→80) | 0–80 |
//! | most severe ATT&CK tactic (+2 per extra tactic, max +6) | 0–21 |
//! | most severe rule-group category | 0–15 |
//! | IOC classes present (public IP, external domain/URL, hash, CVE, e-mail) | 0–15 |
//! | command-line analysis score / 5 (when ≥ 15) | 0–20 |
//! | asset criticality | 0–15 |
//! | prior sightings of the alert's indicators | 0–10 |
//! | threat-intel verdict (clean −10 … malicious +25) | −10–25 |
//! | known false positive | −25 |
//!
//! Every factor is monotonic in its input, so the score is monotonic too:
//! a higher rule level, more tactics, more IOC classes, a more critical asset,
//! more prior sightings or a worse intel verdict never lower the score.

use serde::{Deserialize, Serialize};

use crate::common::{Confidence, Severity};
use crate::ioc::{IocReport, IocType};
use crate::mitre::Tactic;

/// Business criticality of the affected asset.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AssetCriticality {
    /// Not known.
    #[default]
    Unknown,
    /// Low value asset.
    Low,
    /// Normal business asset.
    Medium,
    /// Important server / privileged workstation.
    High,
    /// Crown jewel (domain controller, critical database, ...).
    Critical,
}

impl AssetCriticality {
    fn points(self) -> i32 {
        match self {
            AssetCriticality::Unknown | AssetCriticality::Low => 0,
            AssetCriticality::Medium => 4,
            AssetCriticality::High => 8,
            AssetCriticality::Critical => 15,
        }
    }
}

/// Aggregated threat-intel verdict for the alert's indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelVerdict {
    /// All enriched indicators clean.
    Clean,
    /// No conclusive intel.
    Unknown,
    /// At least one suspicious indicator.
    Suspicious,
    /// At least one malicious indicator.
    Malicious,
}

impl IntelVerdict {
    fn points(self) -> i32 {
        match self {
            IntelVerdict::Clean => -10,
            IntelVerdict::Unknown => 0,
            IntelVerdict::Suspicious => 12,
            IntelVerdict::Malicious => 25,
        }
    }
}

/// Counts of the indicator classes that matter for scoring.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IocSummary {
    /// Public IPs.
    pub public_ips: u32,
    /// External domains.
    pub external_domains: u32,
    /// URLs with an external host.
    pub external_urls: u32,
    /// File hashes.
    pub hashes: u32,
    /// E-mail addresses.
    pub emails: u32,
    /// CVE ids.
    pub cves: u32,
}

impl IocSummary {
    /// Summarise an extraction.
    pub fn from_report(r: &IocReport) -> Self {
        let mut s = IocSummary::default();
        for i in &r.iocs {
            match i.ioc_type {
                IocType::Ipv4 | IocType::Ipv6 if i.is_external() => s.public_ips += 1,
                IocType::Domain if i.is_external() => s.external_domains += 1,
                IocType::Url if i.is_external() => s.external_urls += 1,
                t if t.is_hash() => s.hashes += 1,
                IocType::Email => s.emails += 1,
                IocType::Cve => s.cves += 1,
                _ => {}
            }
        }
        s
    }

    fn is_empty(&self) -> bool {
        *self == IocSummary::default()
    }
}

/// Inputs to [`score`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TriageInput {
    /// Wazuh rule level (0–15).
    #[serde(default)]
    pub rule_level: Option<u8>,
    /// Wazuh rule groups.
    #[serde(default)]
    pub rule_groups: Vec<String>,
    /// ATT&CK tactics involved.
    #[serde(default)]
    pub tactics: Vec<Tactic>,
    /// Indicator classes present.
    #[serde(default)]
    pub iocs: IocSummary,
    /// Command-line analysis score, when a command line was analysed.
    #[serde(default)]
    pub command_line_score: Option<u8>,
    /// Titles of the strongest command-line findings (for the rationale).
    #[serde(default)]
    pub command_line_findings: Vec<String>,
    /// Asset criticality.
    #[serde(default)]
    pub asset_criticality: AssetCriticality,
    /// Prior sightings of this alert's indicators / rule on the asset.
    #[serde(default)]
    pub prior_sightings: u32,
    /// The alert matches a recorded false-positive pattern.
    #[serde(default)]
    pub known_false_positive: bool,
    /// Aggregated threat-intel verdict, once enrichment ran.
    #[serde(default)]
    pub intel_verdict: Option<IntelVerdict>,
}

/// Analyst-provided context for scoring a raw alert.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TriageContext {
    /// Asset criticality.
    #[serde(default)]
    pub asset_criticality: AssetCriticality,
    /// Prior sightings count.
    #[serde(default)]
    pub prior_sightings: u32,
    /// Known false-positive pattern.
    #[serde(default)]
    pub known_false_positive: bool,
    /// Aggregated threat-intel verdict.
    #[serde(default)]
    pub intel_verdict: Option<IntelVerdict>,
}

/// One scoring contribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreFactor {
    /// Factor id (`rule_level`, `tactics`, ...).
    pub factor: String,
    /// Signed points contributed.
    pub points: i32,
    /// Why.
    pub detail: String,
}

/// Result of [`score`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageScore {
    /// Risk 0–100.
    pub score: u8,
    /// Severity band of the score.
    pub severity: Severity,
    /// How much evidence the prior rests on (number of signal classes).
    pub confidence: Confidence,
    /// Contributions (non-zero ones, plus rule level always).
    pub factors: Vec<ScoreFactor>,
    /// One line per factor (`+60 rule level 12 ...`).
    pub rationale: Vec<String>,
    /// One-sentence summary.
    pub summary: String,
}

impl TriageScore {
    /// `true` when an ATT&CK tactic contributed to the score.
    pub fn tactics_present(&self) -> bool {
        self.factors
            .iter()
            .any(|f| f.factor == "tactics" && f.points > 0)
    }
}

/// Points for a Wazuh rule level, aligned with the severity bands
/// (0–3 → 0–6, 4–7 → 20–29, 8–11 → 40–49, 12–14 → 60–66, 15 → 80).
pub fn rule_level_points(level: u8) -> i32 {
    let l = i32::from(level.min(15));
    match l {
        0..=3 => 2 * l,
        4..=7 => 20 + 3 * (l - 4),
        8..=11 => 40 + 3 * (l - 8),
        12..=14 => 60 + 3 * (l - 12),
        _ => 80,
    }
}

/// Weight of a tactic for scoring (impact / credential access highest).
pub fn tactic_weight(t: Tactic) -> i32 {
    match t {
        Tactic::Impact | Tactic::CredentialAccess => 15,
        Tactic::Exfiltration => 14,
        Tactic::LateralMovement => 13,
        Tactic::CommandAndControl => 12,
        Tactic::PrivilegeEscalation => 11,
        Tactic::DefenseEvasion | Tactic::Persistence | Tactic::InitialAccess => 10,
        Tactic::Execution | Tactic::Collection => 8,
        Tactic::Discovery => 5,
        Tactic::Reconnaissance | Tactic::ResourceDevelopment => 3,
    }
}

/// `(pattern, points, label)`; `~` prefix = substring match.
const GROUP_WEIGHTS: &[(&str, i32, &str)] = &[
    ("~ransomware", 15, "ransomware detection"),
    ("~rootkit", 15, "rootkit detection"),
    ("~malware", 15, "malware detection"),
    ("~trojan", 15, "trojan detection"),
    ("virus", 15, "antivirus detection"),
    ("yara", 12, "YARA match"),
    ("~exploit", 12, "exploitation attempt"),
    ("sql_injection", 12, "SQL injection attempt"),
    ("~shellshock", 12, "Shellshock attempt"),
    ("~web_attack", 12, "web attack"),
    ("attack", 10, "attack signature"),
    ("virustotal", 10, "VirusTotal positive"),
    ("windows_defender", 8, "Microsoft Defender event"),
    ("~brute", 8, "brute force"),
    (
        "authentication_failures",
        8,
        "multiple authentication failures",
    ),
    ("rootcheck", 6, "rootcheck anomaly"),
    ("ids", 6, "IDS signature"),
    ("suricata", 6, "IDS signature"),
    ("web_scan", 5, "scanning"),
    ("recon", 5, "reconnaissance"),
    ("vulnerability-detector", 4, "vulnerability finding"),
    ("authentication_failed", 3, "failed authentication"),
    ("policy_violation", 3, "policy violation"),
    ("syscheck", 2, "file integrity change"),
];

fn group_points(groups: &[String]) -> Option<(i32, String)> {
    let mut best: Option<(i32, String)> = None;
    for g in groups {
        let g = g.trim().to_ascii_lowercase();
        for (pat, pts, label) in GROUP_WEIGHTS {
            let hit = match pat.strip_prefix('~') {
                Some(sub) => g.contains(sub),
                None => g == *pat,
            };
            if hit && best.as_ref().is_none_or(|(b, _)| *pts > *b) {
                best = Some((*pts, format!("rule group `{g}` ({label})")));
            }
        }
    }
    best
}

fn prior_points(n: u32) -> i32 {
    match n {
        0 => 0,
        1 => 3,
        2..=4 => 6,
        _ => 10,
    }
}

/// Compute the score.
pub fn score(input: &TriageInput) -> TriageScore {
    let mut factors: Vec<ScoreFactor> = Vec::new();
    let mut push = |factor: &str, points: i32, detail: String| {
        factors.push(ScoreFactor {
            factor: factor.to_string(),
            points,
            detail,
        });
    };
    let mut signals = 0;

    match input.rule_level {
        Some(l) => {
            signals += 1;
            let l = l.min(15);
            push(
                "rule_level",
                rule_level_points(l),
                format!(
                    "Wazuh rule level {l} ({} band)",
                    Severity::from_rule_level(l).as_str()
                ),
            );
        }
        None => push("rule_level", 0, "rule level unknown".to_string()),
    }

    let mut tactics = input.tactics.clone();
    tactics.sort();
    tactics.dedup();
    if let Some(top) = tactics.iter().copied().max_by_key(|t| tactic_weight(*t)) {
        signals += 1;
        let extra = ((tactics.len() as i32 - 1) * 2).clamp(0, 6);
        let names: Vec<&str> = tactics.iter().map(|t| t.name()).collect();
        push(
            "tactics",
            tactic_weight(top) + extra,
            format!(
                "ATT&CK tactics: {} (most severe: {}{})",
                names.join(", "),
                top.name(),
                if extra > 0 {
                    format!(", +{extra} for multi-stage")
                } else {
                    String::new()
                }
            ),
        );
    }

    if let Some((pts, detail)) = group_points(&input.rule_groups) {
        push("rule_groups", pts, detail);
    }

    if !input.iocs.is_empty() {
        signals += 1;
        let s = &input.iocs;
        let mut pts = 0;
        let mut parts = Vec::new();
        let mut class = |n: u32, p: i32, label: &str| {
            if n > 0 {
                pts += p;
                parts.push(format!("{n} {label}"));
            }
        };
        class(s.public_ips, 6, "public IP(s)");
        class(s.external_domains, 5, "external domain(s)");
        class(s.external_urls, 6, "external URL(s)");
        class(s.cves, 4, "CVE(s)");
        class(s.hashes, 2, "file hash(es)");
        class(s.emails, 1, "e-mail address(es)");
        push(
            "iocs",
            pts.min(15),
            format!("indicators present: {}", parts.join(", ")),
        );
    }

    if let Some(cs) = input.command_line_score {
        signals += 1;
        if cs >= 15 {
            let pts = (i32::from(cs.min(100)) + 2) / 5;
            let top: Vec<&str> = input
                .command_line_findings
                .iter()
                .take(3)
                .map(String::as_str)
                .collect();
            push(
                "command_line",
                pts.min(20),
                format!(
                    "command-line analysis score {cs}/100{}",
                    if top.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", top.join("; "))
                    }
                ),
            );
        }
    }

    if input.asset_criticality != AssetCriticality::Unknown {
        signals += 1;
        let p = input.asset_criticality.points();
        if p != 0 {
            push(
                "asset_criticality",
                p,
                format!(
                    "asset criticality {}",
                    serde_json::to_value(input.asset_criticality)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default()
                ),
            );
        }
    }

    if input.prior_sightings > 0 {
        signals += 1;
        push(
            "prior_sightings",
            prior_points(input.prior_sightings),
            format!(
                "indicators/rule seen {} time(s) before (recurrence raises urgency)",
                input.prior_sightings
            ),
        );
    }

    if let Some(v) = input.intel_verdict {
        signals += 1;
        let p = v.points();
        if p != 0 {
            push(
                "intel_verdict",
                p,
                format!(
                    "threat-intel verdict {}",
                    serde_json::to_value(v)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default()
                ),
            );
        }
    }

    if input.known_false_positive {
        push(
            "known_false_positive",
            -25,
            "matches a recorded false-positive pattern for this rule/asset".to_string(),
        );
    }

    let total: i32 = factors.iter().map(|f| f.points).sum();
    let score = total.clamp(0, 100) as u8;
    let severity = Severity::from_score(score);
    let confidence = match signals {
        0..=1 => Confidence::Low,
        2..=3 => Confidence::Medium,
        _ => Confidence::High,
    };
    let rationale: Vec<String> = factors
        .iter()
        .filter(|f| f.points != 0 || f.factor == "rule_level")
        .map(|f| format!("{:+} {}", f.points, f.detail))
        .collect();
    let mut drivers: Vec<&ScoreFactor> = factors.iter().filter(|f| f.points > 0).collect();
    drivers.sort_by_key(|f| std::cmp::Reverse(f.points));
    let summary = format!(
        "Risk {score}/100 ({}), {} confidence prior; main drivers: {}.",
        severity.label(),
        confidence.as_str(),
        if drivers.is_empty() {
            "none".to_string()
        } else {
            drivers
                .iter()
                .take(3)
                .map(|f| f.factor.replace('_', " "))
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    TriageScore {
        score,
        severity,
        confidence,
        factors,
        rationale,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> TriageInput {
        TriageInput {
            rule_level: Some(8),
            ..Default::default()
        }
    }

    #[test]
    fn rule_level_alone_matches_wazuh_bands() {
        for l in 0..=15u8 {
            let s = score(&TriageInput {
                rule_level: Some(l),
                ..Default::default()
            });
            assert_eq!(s.severity, Severity::from_rule_level(l), "level {l}");
            assert_eq!(s.confidence, Confidence::Low);
        }
        let unknown = score(&TriageInput::default());
        assert_eq!(unknown.score, 0);
        assert!(unknown.rationale[0].contains("unknown"));
    }

    #[test]
    fn monotonic_in_rule_level() {
        let mut prev = 0;
        for l in 0..=20u8 {
            let mut i = base();
            i.rule_level = Some(l);
            i.tactics = vec![Tactic::Execution];
            let s = score(&i).score;
            assert!(s >= prev, "level {l}: {s} < {prev}");
            prev = s;
        }
    }

    #[test]
    fn monotonic_in_context_inputs() {
        let mut prev = 0;
        for c in [
            AssetCriticality::Unknown,
            AssetCriticality::Low,
            AssetCriticality::Medium,
            AssetCriticality::High,
            AssetCriticality::Critical,
        ] {
            let mut i = base();
            i.asset_criticality = c;
            let s = score(&i).score;
            assert!(s >= prev);
            prev = s;
        }
        let mut prev = 0;
        for n in 0..30 {
            let mut i = base();
            i.prior_sightings = n;
            let s = score(&i).score;
            assert!(s >= prev);
            prev = s;
        }
        let mut prev = 0;
        for v in [
            IntelVerdict::Clean,
            IntelVerdict::Unknown,
            IntelVerdict::Suspicious,
            IntelVerdict::Malicious,
        ] {
            let mut i = base();
            i.intel_verdict = Some(v);
            let s = score(&i).score;
            assert!(s >= prev, "{v:?}");
            prev = s;
        }
        let mut prev = 0;
        for cs in 0..=100u8 {
            let mut i = base();
            i.command_line_score = Some(cs);
            let s = score(&i).score;
            assert!(s >= prev, "cmd {cs}");
            prev = s;
        }
    }

    #[test]
    fn monotonic_in_tactics_and_iocs() {
        let mut i = base();
        let mut prev = score(&i).score;
        for t in Tactic::ALL {
            i.tactics.push(t);
            let s = score(&i).score;
            assert!(s >= prev, "{t:?}");
            prev = s;
        }
        let mut i = base();
        let mut prev = score(&i).score;
        let steps: [fn(&mut IocSummary); 6] = [
            |s| s.emails += 1,
            |s| s.hashes += 1,
            |s| s.cves += 1,
            |s| s.public_ips += 1,
            |s| s.external_domains += 1,
            |s| s.external_urls += 1,
        ];
        for step in steps {
            step(&mut i.iocs);
            let s = score(&i).score;
            assert!(s >= prev);
            prev = s;
        }
    }

    #[test]
    fn known_false_positive_lowers_and_clamps() {
        let mut i = base();
        let before = score(&i).score;
        i.known_false_positive = true;
        let after = score(&i);
        assert!(after.score < before);
        assert!(after.rationale.iter().any(|r| r.starts_with("-25")));
        let low = score(&TriageInput {
            rule_level: Some(2),
            known_false_positive: true,
            intel_verdict: Some(IntelVerdict::Clean),
            ..Default::default()
        });
        assert_eq!(low.score, 0);
    }

    #[test]
    fn realistic_credential_dumping_is_critical() {
        let s = score(&TriageInput {
            rule_level: Some(12),
            rule_groups: vec!["sysmon".into(), "sysmon_eid10_detections".into()],
            tactics: vec![Tactic::CredentialAccess],
            command_line_score: Some(90),
            command_line_findings: vec!["ProcDump against LSASS".into()],
            asset_criticality: AssetCriticality::Critical,
            ..Default::default()
        });
        assert!(s.score >= 80, "{}", s.score);
        assert_eq!(s.severity, Severity::Critical);
        assert_eq!(s.confidence, Confidence::High);
        assert!(s.rationale.iter().any(|r| r.contains("ProcDump")));
        assert!(s.summary.contains("rule level"));
    }

    #[test]
    fn group_categories_take_max() {
        let (p, d) = group_points(&["syscheck".into(), "virus".into(), "attack".into()])
            .unwrap_or((0, String::new()));
        assert_eq!(p, 15);
        assert!(d.contains("virus"));
        assert!(group_points(&["windows".into()]).is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let c: TriageContext = serde_json::from_str(
            r#"{"asset_criticality":"critical","prior_sightings":2,"intel_verdict":"malicious"}"#,
        )
        .unwrap();
        assert_eq!(c.asset_criticality, AssetCriticality::Critical);
        assert_eq!(c.intel_verdict, Some(IntelVerdict::Malicious));
        let s = score(&base());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["severity"], "medium");
    }
}
