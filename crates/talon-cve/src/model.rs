//! The records the importers produce and the store keeps.

use serde::{Deserialize, Serialize};

/// CVSS metrics kept per CVE at most.
pub const MAX_METRICS: usize = 12;
/// References kept per CVE at most.
pub const MAX_REFERENCES: usize = 40;
/// CPE matches kept per CVE at most (the total is stored beside them).
pub const MAX_CPE_MATCHES: usize = 40;
/// Vendor/product pairs kept per CVE at most.
pub const MAX_PRODUCTS: usize = 200;
/// Characters of a description kept at most.
pub const MAX_DESCRIPTION_CHARS: usize = 8_000;

/// One CVSS assessment of a CVE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    /// CVSS version (`4.0`, `3.1`, `3.0`, `2.0`).
    pub version: String,
    /// Base score.
    pub score: f64,
    /// Base severity (`CRITICAL`, `HIGH`, ...).
    pub severity: String,
    /// Vector string.
    pub vector: String,
    /// Who assessed (`nvd@nist.gov`, a CNA, ...).
    pub source: String,
    /// `Primary` (NVD or the CNA of record) or `Secondary`.
    pub kind: String,
}

/// One reference of a CVE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    /// Link.
    pub url: String,
    /// NVD tags (`Patch`, `Exploit`, `Vendor Advisory`, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// One vulnerable CPE match of a CVE's configurations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpeMatch {
    /// CPE 2.3 match string.
    pub criteria: String,
    /// First affected version, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_start_including: Option<String>,
    /// First affected version, exclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_start_excluding: Option<String>,
    /// Last affected version, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_end_including: Option<String>,
    /// First fixed version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_end_excluding: Option<String>,
}

/// A CVE as stored.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CveRecord {
    /// `CVE-YYYY-N`.
    pub id: String,
    /// Publication time as NVD writes it.
    pub published: Option<String>,
    /// Last modification time as NVD writes it.
    pub modified: Option<String>,
    /// NVD status.
    pub status: Option<String>,
    /// English description.
    pub description: String,
    /// CVSS assessments.
    pub metrics: Vec<Metric>,
    /// CWE ids.
    pub cwes: Vec<String>,
    /// References.
    pub references: Vec<Reference>,
    /// Vulnerable CPE matches (the first [`MAX_CPE_MATCHES`]).
    pub cpe: Vec<CpeMatch>,
    /// Number of vulnerable CPE matches NVD lists.
    pub cpe_total: u32,
    /// Distinct `(vendor, product)` pairs, lower case.
    pub products: Vec<(String, String)>,
}

impl CveRecord {
    /// The assessment used for filtering and sorting: a primary CVSS 3.x,
    /// then any 3.x, then 4.0, then 2.0. CVSS 3.x comes first because it is
    /// the scale most tooling and policies still refer to and the one NVD
    /// itself assigns.
    pub fn headline(&self) -> Option<&Metric> {
        let rank = |m: &Metric| -> u8 {
            let v3 = m.version.starts_with('3');
            match (v3, m.kind == "Primary", m.version.starts_with('4')) {
                (true, true, _) => 0,
                (true, false, _) => 1,
                (false, _, true) => 2,
                _ => 3,
            }
        };
        self.metrics.iter().min_by_key(|m| rank(m))
    }
}

/// One line of the EPSS file.
#[derive(Debug, Clone, PartialEq)]
pub struct EpssScore {
    /// CVE id.
    pub cve_id: String,
    /// Probability of exploitation in the next 30 days, `0.0`–`1.0`.
    pub score: f64,
    /// Share of CVEs scored at or below this one, `0.0`–`1.0`.
    pub percentile: f64,
}

/// One entry of the CISA KEV catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KevEntry {
    /// CVE id.
    pub cve_id: String,
    /// Vendor or project.
    pub vendor: String,
    /// Product.
    pub product: String,
    /// CISA's name of the vulnerability.
    pub name: String,
    /// Date added to the catalogue (`YYYY-MM-DD`).
    pub date_added: String,
    /// Remediation due date for US federal agencies.
    pub due_date: String,
    /// Short description.
    pub description: String,
    /// Required action.
    pub required_action: String,
    /// `Known` or `Unknown` ransomware campaign use.
    pub ransomware: String,
    /// Notes (usually advisory links).
    pub notes: String,
}

/// Whether `id` is a CVE id in canonical form: `CVE-`, a four-digit year,
/// `-`, four to nineteen digits.
pub fn is_cve_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, number)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=19).contains(&number.len())
        && number.bytes().all(|b| b.is_ascii_digit())
}

/// `text` cut to `max` characters (on a character boundary).
pub fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((at, _)) => text[..at].to_string(),
        None => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric(version: &str, kind: &str, score: f64) -> Metric {
        Metric {
            version: version.into(),
            score,
            severity: "HIGH".into(),
            vector: String::new(),
            source: String::new(),
            kind: kind.into(),
        }
    }

    #[test]
    fn cve_id_format() {
        for ok in [
            "CVE-1999-0001",
            "CVE-2026-114713",
            "CVE-2024-1234567890123456789",
        ] {
            assert!(is_cve_id(ok), "{ok}");
        }
        for bad in [
            "cve-2024-1234",
            "CVE-2024-123",
            "CVE-24-1234",
            "CVE-2024-12a4",
            "CVE-2024-1234 ",
            "CVE-2024-1234' OR 1=1",
            "CVE-2024-12345678901234567890",
            "",
        ] {
            assert!(!is_cve_id(bad), "{bad}");
        }
    }

    #[test]
    fn headline_prefers_primary_v3() {
        let rec = CveRecord {
            metrics: vec![
                metric("4.0", "Secondary", 9.3),
                metric("2.0", "Primary", 7.5),
                metric("3.1", "Secondary", 8.1),
                metric("3.1", "Primary", 8.8),
            ],
            ..CveRecord::default()
        };
        assert_eq!(rec.headline().map(|m| m.score), Some(8.8));
        let rec = CveRecord {
            metrics: vec![
                metric("2.0", "Primary", 7.5),
                metric("4.0", "Secondary", 9.3),
            ],
            ..CveRecord::default()
        };
        assert_eq!(rec.headline().map(|m| m.score), Some(9.3));
        assert!(CveRecord::default().headline().is_none());
    }

    #[test]
    fn clip_respects_characters() {
        assert_eq!(clip("äöü", 2), "äö");
        assert_eq!(clip("ab", 5), "ab");
    }
}
