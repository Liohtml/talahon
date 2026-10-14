//! Investigation bookkeeping: structured verdicts written by the agent and
//! the IOC sightings derived from them.
//!
//! `talon-intel`'s `submit_triage_report` tool writes the validated
//! `TriageReport` to `<group dir>/reports/<id>.json` (the container's cwd is
//! the group folder). The host reads it after the run, stores it as the
//! investigation's `verdict` and records every indicator in
//! `ioc_sightings` for cross-alert correlation.
//!
//! The report was written by the (untrusted) agent, so reading is
//! defensive: regular files only (no symlinks), size-capped, must be a JSON
//! object; indicator values are normalized, length-checked and capped.

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::Value;
use talon_db::{IocSighting, MAX_IOC_VALUE_LEN};

/// Directory (inside the group folder) the agent writes reports to.
pub const REPORTS_DIR: &str = "reports";
/// Largest report file the host reads.
pub const MAX_REPORT_BYTES: u64 = 1024 * 1024;
/// At most this many indicators are recorded per investigation.
pub const MAX_SIGHTINGS: usize = 200;
/// Longest stored investigation error text (characters).
pub const MAX_ERROR_CHARS: usize = 2000;

/// `queued` status (set by the HTTP API).
pub const STATUS_QUEUED: &str = "queued";
/// Status while the agent runs.
pub const STATUS_RUNNING: &str = "running";
/// Terminal success status.
pub const STATUS_COMPLETED: &str = "completed";
/// Terminal failure status.
pub const STATUS_FAILED: &str = "failed";

/// A report id usable as a file name: `[A-Za-z0-9_.-]{1,200}`, not
/// starting with a dot.
pub fn is_safe_report_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn report_path(group_dir: &Path, id: &str) -> Option<PathBuf> {
    is_safe_report_id(id).then(|| group_dir.join(REPORTS_DIR).join(format!("{id}.json")))
}

/// Read one report file defensively. `not_before`: ignore files last
/// modified before this time (stale reports of an earlier run).
fn read_report_file(path: &Path, not_before: Option<SystemTime>) -> Option<Value> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        if meta.file_type().is_symlink() {
            tracing::warn!(path = %path.display(), "ignoring symlinked investigation report");
        }
        return None;
    }
    if meta.len() > MAX_REPORT_BYTES {
        tracing::warn!(path = %path.display(), bytes = meta.len(), "investigation report too large; ignored");
        return None;
    }
    if let (Some(limit), Ok(modified)) = (not_before, meta.modified()) {
        if modified < limit {
            return None;
        }
    }
    let file = std::fs::File::open(path).ok()?;
    let mut raw = String::new();
    file.take(MAX_REPORT_BYTES + 1)
        .read_to_string(&mut raw)
        .ok()?;
    match serde_json::from_str::<Value>(&raw) {
        Ok(v @ Value::Object(_)) => Some(v),
        Ok(_) => {
            tracing::warn!(path = %path.display(), "investigation report is not a JSON object; ignored");
            None
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "unparseable investigation report; ignored");
            None
        }
    }
}

/// Find the verdict for investigation `job_id` (alert `alert_id`) in
/// `group_dir/reports/`: `<job_id>.json`, else `<alert_id>.json` if it was
/// written after `run_started`.
pub fn load_verdict(
    group_dir: &Path,
    job_id: &str,
    alert_id: &str,
    run_started: SystemTime,
) -> Option<Value> {
    if let Some(v) = report_path(group_dir, job_id).and_then(|p| read_report_file(&p, None)) {
        return Some(v);
    }
    report_path(group_dir, alert_id).and_then(|p| read_report_file(&p, Some(run_started)))
}

fn refang(value: &str) -> String {
    value
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("(dot)", ".")
        .replace("[:]", ":")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
}

fn is_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Map a report indicator (`{"type": "ip|domain|hash|process|url|user|command", "value": ...}`)
/// to an `(ioc_type, normalized value)` pair for `ioc_sightings`. Command
/// lines are not recorded (too unique to correlate on).
pub fn normalize_indicator(kind: &str, value: &str) -> Option<(String, String)> {
    let value = refang(value.trim());
    if value.is_empty() || value.len() > MAX_IOC_VALUE_LEN {
        return None;
    }
    let (t, v) = match kind.trim().to_ascii_lowercase().as_str() {
        "ip" | "ipv4" | "ipv6" => {
            let ip: IpAddr = value.trim_matches(['[', ']']).parse().ok()?;
            match ip {
                IpAddr::V4(_) => ("ipv4", ip.to_string()),
                IpAddr::V6(_) => ("ipv6", ip.to_string()),
            }
        }
        "domain" => {
            let d = value.trim_end_matches('.').to_ascii_lowercase();
            if d.contains(char::is_whitespace) || !d.contains('.') {
                return None;
            }
            ("domain", d)
        }
        "hash" | "md5" | "sha1" | "sha256" | "sha512" => {
            let h = value.to_ascii_lowercase();
            if !is_hex(&h) {
                return None;
            }
            let t = match h.len() {
                32 => "md5",
                40 => "sha1",
                64 => "sha256",
                128 => "sha512",
                _ => return None,
            };
            (t, h)
        }
        "url" => ("url", value),
        "user" => ("user", value.to_ascii_lowercase()),
        "process" => ("process", value),
        "email" => ("email", value.to_ascii_lowercase()),
        "cve" => ("cve", value.to_ascii_uppercase()),
        _ => return None,
    };
    Some((t.to_string(), v))
}

/// Sightings for every indicator in `verdict.iocs` (deduplicated, capped
/// at [`MAX_SIGHTINGS`]). `source_ref` is the alert id, so re-investigating
/// an alert does not inflate prior-sighting counts.
pub fn sightings_from_verdict(
    verdict: &Value,
    source_ref: &str,
    customer_code: Option<&str>,
    seen_at: &str,
) -> Vec<IocSighting> {
    let Some(iocs) = verdict.get("iocs").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for ioc in iocs {
        if out.len() >= MAX_SIGHTINGS {
            break;
        }
        let kind = ioc.get("type").and_then(Value::as_str).unwrap_or_default();
        let value = ioc.get("value").and_then(Value::as_str).unwrap_or_default();
        let Some((ioc_type, value)) = normalize_indicator(kind, value) else {
            continue;
        };
        if !seen.insert((ioc_type.clone(), value.clone())) {
            continue;
        }
        out.push(IocSighting {
            ioc_type,
            value,
            source_ref: source_ref.to_string(),
            customer_code: customer_code.map(str::to_string),
            seen_at: seen_at.to_string(),
        });
    }
    out
}

/// Error text stored on a failed investigation: first
/// [`MAX_ERROR_CHARS`] characters.
pub fn truncate_error(error: &str) -> String {
    match error.char_indices().nth(MAX_ERROR_CHARS) {
        Some((idx, _)) => format!("{}…", &error[..idx]),
        None => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    #[test]
    fn report_ids_are_restricted() {
        assert!(is_safe_report_id("copilot-inv-42-1700000000000"));
        assert!(is_safe_report_id("42"));
        assert!(!is_safe_report_id(""));
        assert!(!is_safe_report_id("../etc/passwd"));
        assert!(!is_safe_report_id(".hidden"));
        assert!(!is_safe_report_id("a/b"));
    }

    #[test]
    fn loads_job_report_and_ignores_stale_alert_report() {
        let dir = tempfile::tempdir().unwrap();
        let reports = dir.path().join(REPORTS_DIR);
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::write(reports.join("42.json"), r#"{"verdict":"false_positive"}"#).unwrap();
        let future = SystemTime::now() + Duration::from_secs(3600);
        // The alert-id report predates the run: ignored.
        assert!(load_verdict(dir.path(), "job-1", "42", future).is_none());
        // Written during the run: used.
        let past = SystemTime::now() - Duration::from_secs(3600);
        assert_eq!(
            load_verdict(dir.path(), "job-1", "42", past).unwrap()["verdict"],
            "false_positive"
        );
        // The job report always wins.
        std::fs::write(reports.join("job-1.json"), r#"{"verdict":"true_positive"}"#).unwrap();
        assert_eq!(
            load_verdict(dir.path(), "job-1", "42", future).unwrap()["verdict"],
            "true_positive"
        );
    }

    #[test]
    fn rejects_symlinks_non_objects_and_oversized_reports() {
        let dir = tempfile::tempdir().unwrap();
        let reports = dir.path().join(REPORTS_DIR);
        std::fs::create_dir_all(&reports).unwrap();
        let outside = dir.path().join("secret.json");
        std::fs::write(&outside, r#"{"verdict":"x"}"#).unwrap();
        std::os::unix::fs::symlink(&outside, reports.join("job-s.json")).unwrap();
        assert!(load_verdict(dir.path(), "job-s", "none", SystemTime::now()).is_none());

        std::fs::write(reports.join("job-a.json"), "[1,2]").unwrap();
        assert!(load_verdict(dir.path(), "job-a", "none", SystemTime::now()).is_none());

        let big = format!(
            r#"{{"x":"{}"}}"#,
            "a".repeat(MAX_REPORT_BYTES as usize + 10)
        );
        std::fs::write(reports.join("job-b.json"), big).unwrap();
        assert!(load_verdict(dir.path(), "job-b", "none", SystemTime::now()).is_none());
    }

    #[test]
    fn indicator_normalization() {
        assert_eq!(
            normalize_indicator("ip", " 8.8.8.8 "),
            Some(("ipv4".into(), "8.8.8.8".into()))
        );
        assert_eq!(
            normalize_indicator("ip", "2001:db8::1"),
            Some(("ipv6".into(), "2001:db8::1".into()))
        );
        assert_eq!(normalize_indicator("ip", "not-an-ip"), None);
        assert_eq!(
            normalize_indicator("domain", "Evil[.]Example.COM"),
            Some(("domain".into(), "evil.example.com".into()))
        );
        assert_eq!(
            normalize_indicator("hash", &"A".repeat(64)),
            Some(("sha256".into(), "a".repeat(64)))
        );
        assert_eq!(normalize_indicator("hash", "abc"), None);
        assert_eq!(
            normalize_indicator("url", "hxxp://bad[.]example/x"),
            Some(("url".into(), "http://bad.example/x".into()))
        );
        assert_eq!(normalize_indicator("command", "whoami /all"), None);
        assert_eq!(normalize_indicator("ip", ""), None);
    }

    #[test]
    fn sightings_are_deduplicated_and_typed() {
        let verdict = json!({
            "verdict": "true_positive",
            "iocs": [
                {"type": "ip", "value": "1.2.3.4", "verdict": "malicious", "details": ""},
                {"type": "ip", "value": "1.2.3.4", "verdict": "malicious", "details": ""},
                {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "verdict": "unknown", "details": ""},
                {"type": "command", "value": "powershell -enc AAAA", "verdict": "suspicious", "details": ""},
                {"value": "missing type"}
            ]
        });
        let s = sightings_from_verdict(&verdict, "42", Some("acme"), "2026-01-01T00:00:00.000Z");
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].ioc_type, "ipv4");
        assert_eq!(s[0].source_ref, "42");
        assert_eq!(s[0].customer_code.as_deref(), Some("acme"));
        assert_eq!(s[1].ioc_type, "md5");
        assert!(sightings_from_verdict(&json!({}), "42", None, "t").is_empty());
    }

    #[test]
    fn error_truncation() {
        assert_eq!(truncate_error("short"), "short");
        let long = "x".repeat(MAX_ERROR_CHARS + 5);
        assert_eq!(truncate_error(&long).chars().count(), MAX_ERROR_CHARS + 1);
    }
}
