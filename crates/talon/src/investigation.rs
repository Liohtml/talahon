//! Investigation bookkeeping: structured verdicts written by the agent and
//! the IOC sightings derived from them.
//!
//! `talon-intel`'s `submit_triage_report` tool writes the validated
//! `TriageReport` into the lane-private agent state directory
//! (`/home/agent/.talon/reports/<id>.json` in the container, i.e.
//! `<data_dir>/sessions/<session_key>/reports/<id>.json` on the host). The
//! host reads it after the run, stores it as the investigation's `verdict`
//! and records every indicator in `ioc_sightings` for cross-alert
//! correlation.
//!
//! The report is read from the state directory of the lane that ran the
//! investigation, never from the group folder: every lane on a shared
//! folder (all CoPilot chat lanes share `groups/copilot`) can write there,
//! so a report in `groups/<folder>/reports/` could be forged by another
//! analyst's lane (N-2). The job's own `<job_id>.json` wins; otherwise
//! `<alert_id>.json` (the name the agent's guided-decoding fallback uses,
//! see [`alert_report_id`]) counts when it was written after the run
//! started — also only inside the lane-private directory.
//!
//! The report was written by the (untrusted) agent, so reading is
//! defensive (MYTH-10): `data/sessions` is operator controlled and opened
//! normally; `<session_key>` and `reports/` are opened with
//! `O_DIRECTORY | O_NOFOLLOW` relative to the already-open parent, the file
//! with `O_NOFOLLOW | O_NONBLOCK` (a symlink fails, a FIFO cannot block) and
//! checked on the opened inode (`fstat`): regular file, one link, at most
//! [`MAX_REPORT_BYTES`]; it must be a JSON object; indicator values are
//! normalized, length-checked and capped. The read runs on the blocking
//! pool ([`load_verdict_async`]).

use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::Value;
use talon_core::paths::is_valid_group_folder;
use talon_db::{IocSighting, MAX_IOC_VALUE_LEN};

use crate::safe_fs::{OpenRefusal, open_dir_at, open_regular_at, open_root, read_capped};

/// Directory below `<data_dir>` holding one agent state directory per
/// session key (mounted at `/home/agent/.talon`).
pub const SESSIONS_DIR: &str = "sessions";
/// Directory (inside the lane's agent state directory) the agent writes
/// reports to.
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

/// Longest report file id derived from an alert id (same limit as
/// `talon-intel`'s `submit_triage_report`).
const MAX_DERIVED_ID_CHARS: usize = 100;

/// The file id `submit_triage_report` uses for alert `alert_id` when no
/// `report_id` is given (the agent's guided-decoding fallback): every
/// character outside `[A-Za-z0-9._-]` becomes `_`, at most 100 characters,
/// leading dots removed. `None` when nothing usable is left (the tool would
/// fall back to a generic name that identifies no alert).
pub fn alert_report_id(alert_id: &str) -> Option<String> {
    let derived: String = alert_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(MAX_DERIVED_ID_CHARS)
        .collect();
    let derived = derived.trim_start_matches('.');
    (!derived.is_empty() && is_safe_report_id(derived)).then(|| derived.to_string())
}

/// Read one report file from the open `reports/` directory. `not_before`:
/// ignore files last modified before this time (stale reports of an
/// earlier run).
fn read_report_at(
    reports: BorrowedFd<'_>,
    id: &str,
    not_before: Option<SystemTime>,
) -> Option<Value> {
    if !is_safe_report_id(id) {
        return None;
    }
    let name = format!("{id}.json");
    let (file, meta) = match open_regular_at(reports, &name, MAX_REPORT_BYTES) {
        Ok(opened) => opened,
        Err(OpenRefusal::Missing) => return None,
        Err(OpenRefusal::Rejected(reason)) => {
            tracing::warn!(report = %name, %reason, "ignoring unsafe investigation report");
            return None;
        }
    };
    if let (Some(limit), Ok(modified)) = (not_before, meta.modified()) {
        if modified < limit {
            return None;
        }
    }
    let raw = match read_capped(file, MAX_REPORT_BYTES) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(report = %name, error = %e, "cannot read investigation report; ignored");
            return None;
        }
    };
    match serde_json::from_slice::<Value>(&raw) {
        Ok(v @ Value::Object(_)) => Some(v),
        Ok(_) => {
            tracing::warn!(report = %name, "investigation report is not a JSON object; ignored");
            None
        }
        Err(e) => {
            tracing::warn!(report = %name, error = %e, "unparseable investigation report; ignored");
            None
        }
    }
}

/// Find the verdict for investigation `job_id` (alert `alert_id`) in
/// `<data_dir>/sessions/<session_key>/reports/`, where `session_key` is the
/// session key of the lane that ran the investigation (its private agent
/// state directory — no other lane can write there): `<job_id>.json`, else
/// the alert's report ([`alert_report_id`]) if it was written after
/// `run_started`.
///
/// Blocking (filesystem); async callers use [`load_verdict_async`]. Only
/// `<data_dir>/sessions` (operator controlled) may be a symlink: the
/// lane's state directory, `reports/` and the report itself are never
/// followed.
pub fn load_verdict(
    data_dir: &Path,
    session_key: &str,
    job_id: &str,
    alert_id: &str,
    run_started: SystemTime,
) -> Option<Value> {
    if !is_valid_group_folder(session_key) {
        tracing::warn!(session_key = ?session_key, "invalid session key; no verdict read");
        return None;
    }
    let sessions_dir = data_dir.join(SESSIONS_DIR);
    let sessions = match open_root(&sessions_dir) {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(dir = %sessions_dir.display(), error = %e, "cannot open the sessions directory");
            return None;
        }
    };
    let open_reports = open_dir_at(sessions.as_fd(), session_key)
        .and_then(|state| open_dir_at(state.as_fd(), REPORTS_DIR));
    let reports = match open_reports {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(session_key, error = %e, "cannot open the lane's reports directory; no verdict read");
            return None;
        }
    };
    read_report_at(reports.as_fd(), job_id, None).or_else(|| {
        let id = alert_report_id(alert_id)?;
        read_report_at(reports.as_fd(), &id, Some(run_started))
    })
}

/// [`load_verdict`] on the blocking thread pool.
pub async fn load_verdict_async(
    data_dir: PathBuf,
    session_key: String,
    job_id: String,
    alert_id: String,
    run_started: SystemTime,
) -> Option<Value> {
    let joined = tokio::task::spawn_blocking(move || {
        load_verdict(&data_dir, &session_key, &job_id, &alert_id, run_started)
    })
    .await;
    match joined {
        Ok(verdict) => verdict,
        Err(e) => {
            tracing::error!(error = %e, "verdict reader task failed");
            None
        }
    }
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

    /// Session key of the investigation lane.
    const LANE: &str = "copilot-investigate";

    /// `(tempdir, data_dir, reports_dir)` with the lane's reports dir
    /// created under `data/sessions/<LANE>/`.
    fn layout() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let reports = data.join(SESSIONS_DIR).join(LANE).join(REPORTS_DIR);
        std::fs::create_dir_all(&reports).unwrap();
        (dir, data, reports)
    }

    fn past() -> SystemTime {
        SystemTime::now() - Duration::from_secs(3600)
    }

    fn future() -> SystemTime {
        SystemTime::now() + Duration::from_secs(3600)
    }

    #[test]
    fn alert_report_ids_mirror_submit_triage_report() {
        assert_eq!(alert_report_id("48213").as_deref(), Some("48213"));
        assert_eq!(alert_report_id("a/b c").as_deref(), Some("a_b_c"));
        assert_eq!(alert_report_id("../x").as_deref(), Some("_x"));
        assert_eq!(alert_report_id("..x").as_deref(), Some("x"));
        assert_eq!(alert_report_id("é1").as_deref(), Some("_1"));
        assert_eq!(
            alert_report_id(&"9".repeat(150)).map(|s| s.len()),
            Some(100)
        );
        assert_eq!(alert_report_id(""), None);
        assert_eq!(alert_report_id("..."), None);
    }

    #[test]
    fn loads_job_report_and_ignores_stale_alert_report() {
        let (_dir, data, reports) = layout();
        assert!(load_verdict(&data, LANE, "job-1", "42", past()).is_none());
        std::fs::write(reports.join("42.json"), r#"{"verdict":"false_positive"}"#).unwrap();
        // The alert-id report predates the run: ignored.
        assert!(load_verdict(&data, LANE, "job-1", "42", future()).is_none());
        // Written during the run (the guided-decoding fallback): used.
        assert_eq!(
            load_verdict(&data, LANE, "job-1", "42", past()).unwrap()["verdict"],
            "false_positive"
        );
        // The job report always wins.
        std::fs::write(reports.join("job-1.json"), r#"{"verdict":"true_positive"}"#).unwrap();
        assert_eq!(
            load_verdict(&data, LANE, "job-1", "42", future()).unwrap()["verdict"],
            "true_positive"
        );
        // Unsafe ids and session keys are never turned into paths.
        assert!(load_verdict(&data, LANE, "../job-1", "../42", past()).is_none());
        assert!(load_verdict(&data, LANE, ".job-1", "", past()).is_none());
        assert!(load_verdict(&data, "../etc", "job-1", "42", past()).is_none());
        assert!(load_verdict(&data, "a/b", "job-1", "42", past()).is_none());
        // Another lane's state dir has no report for this job.
        assert!(load_verdict(&data, "copilot-u-alice", "job-1", "42", past()).is_none());
        // No sessions dir at all.
        assert!(load_verdict(&data.join("nowhere"), LANE, "job-1", "42", past()).is_none());
    }

    #[test]
    fn alert_fallback_uses_the_sanitized_alert_id() {
        let (_dir, data, reports) = layout();
        std::fs::write(reports.join("a_b.json"), r#"{"verdict":"benign"}"#).unwrap();
        assert_eq!(
            load_verdict(&data, LANE, "job-1", "a/b", past()).unwrap()["verdict"],
            "benign"
        );
    }

    #[test]
    fn shared_group_folder_and_other_lanes_reports_are_ignored() {
        // N-2: any lane on the shared `copilot` folder can write
        // `groups/copilot/reports/`, and each lane its own state dir; only
        // the investigation lane's private state dir counts — for the job
        // report and for the alert-id fallback alike.
        let (dir, data, reports) = layout();
        let forged = r#"{"verdict":"forged"}"#;
        let shared = dir.path().join("groups").join("copilot").join(REPORTS_DIR);
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(shared.join("job-1.json"), forged).unwrap();
        std::fs::write(shared.join("42.json"), forged).unwrap();
        let alice = data
            .join(SESSIONS_DIR)
            .join("copilot-u-alice")
            .join(REPORTS_DIR);
        std::fs::create_dir_all(&alice).unwrap();
        std::fs::write(alice.join("job-1.json"), forged).unwrap();
        std::fs::write(alice.join("42.json"), forged).unwrap();
        assert!(load_verdict(&data, LANE, "job-1", "42", past()).is_none());

        std::fs::write(reports.join("job-1.json"), r#"{"verdict":"benign"}"#).unwrap();
        assert_eq!(
            load_verdict(&data, LANE, "job-1", "42", past()).unwrap()["verdict"],
            "benign"
        );
    }

    #[test]
    fn rejects_symlinks_non_objects_and_oversized_reports() {
        let (dir, data, reports) = layout();
        let now = SystemTime::now();
        let outside = dir.path().join("secret.json");
        std::fs::write(&outside, r#"{"verdict":"x"}"#).unwrap();
        std::os::unix::fs::symlink(&outside, reports.join("job-s.json")).unwrap();
        assert!(load_verdict(&data, LANE, "job-s", "none", now).is_none());
        // Also for the alert-id fallback.
        std::os::unix::fs::symlink(&outside, reports.join("43.json")).unwrap();
        assert!(load_verdict(&data, LANE, "job-x", "43", past()).is_none());

        std::fs::write(reports.join("job-a.json"), "[1,2]").unwrap();
        assert!(load_verdict(&data, LANE, "job-a", "none", now).is_none());

        std::fs::write(reports.join("job-j.json"), "{not json").unwrap();
        assert!(load_verdict(&data, LANE, "job-j", "none", now).is_none());

        let big = format!(
            r#"{{"x":"{}"}}"#,
            "a".repeat(MAX_REPORT_BYTES as usize + 10)
        );
        std::fs::write(reports.join("job-b.json"), big).unwrap();
        assert!(load_verdict(&data, LANE, "job-b", "none", now).is_none());

        // A hard link to a file elsewhere is not trusted either.
        std::fs::hard_link(&outside, reports.join("job-h.json")).unwrap();
        assert!(load_verdict(&data, LANE, "job-h", "none", now).is_none());

        // Nor is a directory named like a report.
        std::fs::create_dir(reports.join("job-d.json")).unwrap();
        assert!(load_verdict(&data, LANE, "job-d", "none", now).is_none());
    }

    #[test]
    fn symlinked_reports_dir_is_not_followed() {
        let (dir, data, reports) = layout();
        // The agent swaps reports/ for a symlink to a directory another
        // lane controls (here: the shared group folder).
        let shared = dir.path().join("groups").join("copilot").join(REPORTS_DIR);
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(shared.join("job-1.json"), r#"{"verdict":"planted"}"#).unwrap();
        std::fs::write(shared.join("42.json"), r#"{"verdict":"planted"}"#).unwrap();
        std::fs::remove_dir(&reports).unwrap();
        std::os::unix::fs::symlink(&shared, &reports).unwrap();
        assert!(load_verdict(&data, LANE, "job-1", "42", past()).is_none());
    }

    #[test]
    fn symlinked_lane_state_dir_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let sessions = data.join(SESSIONS_DIR);
        std::fs::create_dir_all(&sessions).unwrap();
        let other = sessions.join("copilot-u-mallory");
        std::fs::create_dir_all(other.join(REPORTS_DIR)).unwrap();
        std::fs::write(
            other.join(REPORTS_DIR).join("job-1.json"),
            r#"{"verdict":"planted"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&other, sessions.join(LANE)).unwrap();
        assert!(load_verdict(&data, LANE, "job-1", "42", past()).is_none());
    }

    #[test]
    fn operator_symlinked_sessions_root_is_followed() {
        // `data/sessions` itself is operator controlled (e.g. moved to
        // another volume) and may be a symlink.
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let volume = dir.path().join("volume");
        let reports = volume.join(LANE).join(REPORTS_DIR);
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::write(reports.join("job-1.json"), r#"{"verdict":"benign"}"#).unwrap();
        std::os::unix::fs::symlink(&volume, data.join(SESSIONS_DIR)).unwrap();
        assert_eq!(
            load_verdict(&data, LANE, "job-1", "42", past()).unwrap()["verdict"],
            "benign"
        );
    }

    #[tokio::test]
    async fn fifo_report_does_not_block_the_reader() {
        let (_dir, data, reports) = layout();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            reports.join("job-f.json"),
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        // Without O_NONBLOCK the open would wait for a writer forever.
        let verdict = tokio::time::timeout(
            Duration::from_secs(5),
            load_verdict_async(
                data.clone(),
                LANE.to_string(),
                "job-f".to_string(),
                "none".to_string(),
                SystemTime::now(),
            ),
        )
        .await
        .expect("a FIFO must not block the verdict reader");
        assert!(verdict.is_none());

        std::fs::write(reports.join("job-g.json"), r#"{"verdict":"benign"}"#).unwrap();
        let verdict = load_verdict_async(
            data,
            LANE.to_string(),
            "job-g".to_string(),
            "none".to_string(),
            SystemTime::now(),
        )
        .await;
        assert_eq!(verdict.unwrap()["verdict"], "benign");
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
