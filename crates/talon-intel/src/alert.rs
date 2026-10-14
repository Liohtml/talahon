//! Normalised view of a raw Wazuh / OpenSearch alert document.
//!
//! The same event can reach the agent in several shapes:
//! - nested Wazuh JSON (`{"rule":{"level":12},"data":{"win":{"eventdata":{..}}}}`),
//! - Graylog-flattened (`{"rule_level":12,"data_win_eventdata_image":..}`),
//! - dotted literal keys (`{"rule.level":12}`),
//! - an OpenSearch hit wrapper (`{"_id":..,"_source":{..}}`).
//!
//! [`lookup`] resolves a dotted path against all of them (case-insensitive
//! keys), and [`AlertFields::from_json`] extracts the fields the intel engine
//! needs.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

/// Unwrap an OpenSearch hit (`_source`) if present.
pub fn source_root(v: &Value) -> &Value {
    match v.get("_source") {
        Some(s) if s.is_object() => s,
        _ => v,
    }
}

fn get_ci<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    if let Some(v) = obj.get(key) {
        return Some(v);
    }
    obj.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v)
}

fn nested<'a>(root: &'a Value, segs: &[&str]) -> Option<&'a Value> {
    let mut cur = root;
    for seg in segs {
        cur = get_ci(cur.as_object()?, seg)?;
    }
    Some(cur)
}

fn lookup_in<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let obj = root.as_object()?;
    let segs: Vec<&str> = path.split('.').collect();
    if let Some(v) = nested(root, &segs) {
        return Some(v);
    }
    if let Some(v) = get_ci(obj, &segs.join("_")) {
        return Some(v);
    }
    if let Some(v) = get_ci(obj, path) {
        return Some(v);
    }
    // Mixed shapes: nested prefix, flattened remainder (`data: {win_eventdata_image}`).
    for k in 1..segs.len() {
        if let Some(prefix) = nested(root, &segs[..k]) {
            if let Some(o) = prefix.as_object() {
                if let Some(v) = get_ci(o, &segs[k..].join("_")) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Resolve a dotted path (`data.win.eventdata.commandLine`) in a raw alert,
/// trying nested, flattened (`data_win_eventdata_commandLine`), dotted-literal
/// and `_source`-wrapped shapes with case-insensitive keys.
pub fn lookup<'a>(alert: &'a Value, path: &str) -> Option<&'a Value> {
    let src = source_root(alert);
    lookup_in(src, path).or_else(|| {
        if std::ptr::eq(src, alert) {
            None
        } else {
            lookup_in(alert, path)
        }
    })
}

/// Scalar JSON value as a trimmed, non-empty string (`"-"` counts as empty).
pub fn scalar_string(v: &Value) -> Option<String> {
    let s = match v {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    if s.is_empty() || s == "-" {
        None
    } else {
        Some(s)
    }
}

/// First non-empty string among `paths`.
pub fn first_string(alert: &Value, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|p| lookup(alert, p).and_then(scalar_string))
}

/// String list from an array or a delimited string.
fn string_list(v: &Value, split_whitespace: bool) -> Vec<String> {
    match v {
        Value::Array(items) => items.iter().filter_map(scalar_string).collect(),
        Value::String(s) => {
            let t = s.trim();
            // Graylog sometimes stores arrays as JSON text.
            if t.starts_with('[') {
                if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(t) {
                    return items.iter().filter_map(scalar_string).collect();
                }
            }
            t.split(|c: char| c == ',' || c == ';' || (split_whitespace && c.is_whitespace()))
                .map(|p| p.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
                .filter(|p| !p.is_empty())
                .collect()
        }
        other => scalar_string(other).into_iter().collect(),
    }
}

fn first_list(alert: &Value, paths: &[&str], split_whitespace: bool) -> Vec<String> {
    for p in paths {
        if let Some(v) = lookup(alert, p) {
            let l = string_list(v, split_whitespace);
            if !l.is_empty() {
                return l;
            }
        }
    }
    Vec::new()
}

/// Parse the timestamp formats seen in Wazuh / Graylog / CoPilot data:
/// RFC 3339, `2024-05-01T12:00:00.123+0000`, `2024-05-01 12:00:00(.fff)`
/// (UTC), and epoch seconds / milliseconds.
pub fn parse_timestamp(v: &Value) -> Option<DateTime<Utc>> {
    match v {
        Value::Number(n) => {
            let x = n.as_f64()?;
            if !x.is_finite() || x <= 0.0 {
                return None;
            }
            // > 1e11 → milliseconds (year 5138 in seconds).
            let millis = if x > 1e11 { x } else { x * 1000.0 };
            Utc.timestamp_millis_opt(millis as i64).single()
        }
        Value::String(s) => parse_timestamp_str(s),
        _ => None,
    }
}

/// String variant of [`parse_timestamp`].
pub fn parse_timestamp_str(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%d %H:%M:%S%.f%z"] {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        let n: i64 = s.parse().ok()?;
        let millis = if n > 100_000_000_000 { n } else { n * 1000 };
        return Utc.timestamp_millis_opt(millis).single();
    }
    None
}

/// The fields of a raw alert the intel engine reasons about.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AlertFields {
    /// Document / alert id (`_id`, `id`, `alert_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Event time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    /// Wazuh rule id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Wazuh rule level (0–15).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_level: Option<u8>,
    /// Rule description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_description: Option<String>,
    /// `rule.groups`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule_groups: Vec<String>,
    /// `rule.mitre.id`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mitre_ids: Vec<String>,
    /// `rule.mitre.tactic`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mitre_tactics: Vec<String>,
    /// Endpoint host name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// Wazuh agent id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Endpoint IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_ip: Option<String>,
    /// Windows event id (`data.win.system.eventID`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u32>,
    /// Windows event channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Windows event provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Process image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Parent process image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_image: Option<String>,
    /// Command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Parent command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_command_line: Option<String>,
    /// Acting user (`DOMAIN\user` for Sysmon).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Target account (logon / account-management events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user: Option<String>,
    /// Source IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    /// Destination IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    /// Destination port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<String>,
    /// DNS query name (Sysmon 22).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_name: Option<String>,
    /// Target file name (Sysmon 11/15/2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_filename: Option<String>,
    /// Registry target object (Sysmon 12/13/14).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_object: Option<String>,
    /// Registry value details (Sysmon 13).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Source image (Sysmon 8/10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_image: Option<String>,
    /// Target image (Sysmon 8/10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_image: Option<String>,
    /// Granted access mask (Sysmon 10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_access: Option<String>,
    /// Call trace (Sysmon 10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_trace: Option<String>,
    /// Loaded image (Sysmon 6/7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_loaded: Option<String>,
    /// Signature status (Sysmon 6/7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_status: Option<String>,
    /// Signed flag (Sysmon 6/7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<String>,
    /// Pipe name (Sysmon 17/18).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_name: Option<String>,
    /// Sysmon hashes string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<String>,
}

impl AlertFields {
    /// Extract the known fields from a raw alert in any supported shape.
    pub fn from_json(alert: &Value) -> Self {
        let s = |paths: &[&str]| first_string(alert, paths);
        let rule_level = s(&["rule.level"])
            .and_then(|l| l.parse::<f64>().ok())
            .filter(|l| l.is_finite() && *l >= 0.0)
            .map(|l| l.min(15.0) as u8);
        let event_id = s(&[
            "data.win.system.eventID",
            "winlog.event_id",
            "event.code",
            "event_id",
            "eventID",
        ])
        .and_then(|e| e.parse::<u32>().ok());
        let timestamp = [
            "@timestamp",
            "timestamp",
            "timestamp_utc",
            "alert_creation_time",
            "data.win.system.systemTime",
        ]
        .iter()
        .find_map(|p| lookup(alert, p).and_then(parse_timestamp));

        let mut mitre_ids = first_list(alert, &["rule.mitre.id"], true);
        for id in &mut mitre_ids {
            *id = id.to_ascii_uppercase();
        }
        let mut seen = std::collections::HashSet::new();
        mitre_ids.retain(|id| seen.insert(id.clone()));

        AlertFields {
            id: s(&["_id", "id", "alert_id"]),
            timestamp,
            rule_id: s(&["rule.id"]),
            rule_level,
            rule_description: s(&["rule.description", "alert_name"]),
            rule_groups: first_list(alert, &["rule.groups"], true),
            mitre_ids,
            mitre_tactics: first_list(alert, &["rule.mitre.tactic"], false),
            agent_name: s(&[
                "agent.name",
                "data.win.system.computer",
                "predecoder.hostname",
                "asset_name",
                "host.name",
                "hostname",
            ]),
            agent_id: s(&["agent.id", "agent_id"]),
            agent_ip: s(&["agent.ip"]),
            event_id,
            channel: s(&["data.win.system.channel", "winlog.channel"]),
            provider: s(&["data.win.system.providerName", "winlog.provider_name"]),
            image: s(&[
                "data.win.eventdata.image",
                "data.win.eventdata.newProcessName",
                "process.executable",
            ]),
            parent_image: s(&[
                "data.win.eventdata.parentImage",
                "data.win.eventdata.parentProcessName",
                "process.parent.executable",
            ]),
            command_line: s(&[
                "data.win.eventdata.commandLine",
                "data.win.eventdata.processCommandLine",
                "process.command_line",
                "data.command",
            ]),
            parent_command_line: s(&[
                "data.win.eventdata.parentCommandLine",
                "process.parent.command_line",
            ]),
            user: s(&[
                "data.win.eventdata.user",
                "data.win.eventdata.subjectUserName",
                "data.srcuser",
                "data.user",
                "user.name",
            ]),
            target_user: s(&["data.win.eventdata.targetUserName", "data.dstuser"]),
            src_ip: s(&[
                "data.srcip",
                "data.win.eventdata.sourceIp",
                "data.win.eventdata.ipAddress",
                "data.src_ip",
                "source.ip",
            ]),
            dst_ip: s(&[
                "data.dstip",
                "data.win.eventdata.destinationIp",
                "data.dest_ip",
                "destination.ip",
            ]),
            dst_port: s(&[
                "data.dstport",
                "data.win.eventdata.destinationPort",
                "data.dest_port",
                "destination.port",
            ]),
            query_name: s(&["data.win.eventdata.queryName", "dns.question.name"]),
            target_filename: s(&["data.win.eventdata.targetFilename"]),
            target_object: s(&["data.win.eventdata.targetObject"]),
            details: s(&["data.win.eventdata.details"]),
            source_image: s(&["data.win.eventdata.sourceImage"]),
            target_image: s(&["data.win.eventdata.targetImage"]),
            granted_access: s(&["data.win.eventdata.grantedAccess"]),
            call_trace: s(&["data.win.eventdata.callTrace"]),
            image_loaded: s(&["data.win.eventdata.imageLoaded"]),
            signature_status: s(&["data.win.eventdata.signatureStatus"]),
            signed: s(&["data.win.eventdata.signed"]),
            pipe_name: s(&["data.win.eventdata.pipeName"]),
            hashes: s(&["data.win.eventdata.hashes"]),
        }
    }

    /// `true` when the event comes from Sysmon (group, channel or provider).
    pub fn is_sysmon(&self) -> bool {
        self.rule_groups
            .iter()
            .any(|g| g.to_ascii_lowercase().contains("sysmon"))
            || self
                .channel
                .as_deref()
                .is_some_and(|c| c.to_ascii_lowercase().contains("sysmon"))
            || self
                .provider
                .as_deref()
                .is_some_and(|c| c.to_ascii_lowercase().contains("sysmon"))
    }

    /// `true` when the event comes from Microsoft Defender.
    pub fn is_defender(&self) -> bool {
        let has = |s: &Option<String>| {
            s.as_deref()
                .is_some_and(|c| c.to_ascii_lowercase().contains("defender"))
        };
        self.rule_groups
            .iter()
            .any(|g| g.to_ascii_lowercase().contains("defender"))
            || has(&self.channel)
            || has(&self.provider)
    }

    /// Event id, falling back to a `sysmon_eid<N>_detections` style group.
    pub fn effective_event_id(&self) -> Option<u32> {
        self.event_id.or_else(|| {
            self.rule_groups.iter().find_map(|g| {
                let g = g.to_ascii_lowercase();
                let rest = g.strip_prefix("sysmon_eid")?;
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                digits.parse().ok()
            })
        })
    }

    /// The host this alert is about (lowercased).
    pub fn host(&self) -> Option<String> {
        self.agent_name
            .as_ref()
            .map(|h| h.trim().to_ascii_lowercase())
    }

    /// The most relevant human account, normalised for correlation
    /// (`CORP\Alice` → `alice`), ignoring built-in service principals and
    /// machine accounts.
    pub fn principal_user(&self) -> Option<String> {
        [&self.user, &self.target_user]
            .into_iter()
            .flatten()
            .find_map(|u| normalize_user(u))
    }
}

/// Normalise an account name for correlation; `None` for built-in service
/// principals (`SYSTEM`, `LOCAL SERVICE`, ...), machine accounts (`HOST$`)
/// and placeholders.
pub fn normalize_user(raw: &str) -> Option<String> {
    let u = raw.trim();
    let base = u
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(u)
        .split('@')
        .next()
        .unwrap_or(u)
        .trim()
        .to_ascii_lowercase();
    const BUILTIN: &[&str] = &[
        "",
        "-",
        "n/a",
        "system",
        "local service",
        "localservice",
        "network service",
        "networkservice",
        "anonymous logon",
        "anonymous",
        "root",
        "nobody",
    ];
    if BUILTIN.contains(&base.as_str())
        || base.ends_with('$')
        || base.starts_with("dwm-")
        || base.starts_with("umfd-")
    {
        return None;
    }
    Some(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nested_alert() -> Value {
        json!({
            "_id": "abc123",
            "_source": {
                "timestamp": "2024-05-01T12:00:00.123+0000",
                "rule": {"id": "92213", "level": 12, "description": "Executable dropped in folder commonly used by malware",
                          "groups": ["sysmon", "sysmon_eid11_detections", "windows"],
                          "mitre": {"id": ["T1105"], "tactic": ["Command and Control"]}},
                "agent": {"id": "007", "name": "WIN-DC01", "ip": "10.0.0.5"},
                "data": {"win": {
                    "system": {"eventID": "11", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {"image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                  "targetFilename": "C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe",
                                  "user": "CORP\\bob"}}}
            }
        })
    }

    #[test]
    fn nested_shape() {
        let f = AlertFields::from_json(&nested_alert());
        assert_eq!(f.id.as_deref(), Some("abc123"));
        assert_eq!(f.rule_level, Some(12));
        assert_eq!(f.rule_id.as_deref(), Some("92213"));
        assert_eq!(f.event_id, Some(11));
        assert_eq!(f.mitre_ids, vec!["T1105"]);
        assert_eq!(f.mitre_tactics, vec!["Command and Control"]);
        assert_eq!(f.host().as_deref(), Some("win-dc01"));
        assert_eq!(f.principal_user().as_deref(), Some("bob"));
        assert!(f.is_sysmon());
        assert!(!f.is_defender());
        assert_eq!(
            f.timestamp.map(|t| t.to_rfc3339()),
            Some("2024-05-01T12:00:00.123+00:00".to_string())
        );
    }

    #[test]
    fn graylog_flattened_shape() {
        let v = json!({
            "rule_level": "10",
            "rule_groups": "sysmon,sysmon_eid1_detections,windows",
            "rule_mitre_id": "T1059.001, t1105",
            "rule_mitre_tactic": "Execution, Command and Control",
            "agent_name": "LAPTOP-7",
            "data_win_system_eventID": 1,
            "data_win_eventdata_commandLine": "powershell -enc AAAA",
            "data_win_eventdata_parentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "timestamp": "2024-05-01 12:00:00.000"
        });
        let f = AlertFields::from_json(&v);
        assert_eq!(f.rule_level, Some(10));
        assert_eq!(
            f.rule_groups,
            vec!["sysmon", "sysmon_eid1_detections", "windows"]
        );
        assert_eq!(f.mitre_ids, vec!["T1059.001", "T1105"]);
        assert_eq!(f.mitre_tactics, vec!["Execution", "Command and Control"]);
        assert_eq!(f.event_id, Some(1));
        assert_eq!(f.command_line.as_deref(), Some("powershell -enc AAAA"));
        assert!(
            f.parent_image
                .as_deref()
                .unwrap_or("")
                .ends_with("WINWORD.EXE")
        );
        assert!(f.timestamp.is_some());
    }

    #[test]
    fn dotted_literal_and_mixed_shapes() {
        let v = json!({"rule.level": 7, "data": {"win_eventdata_image": "C:\\x.exe"}});
        let f = AlertFields::from_json(&v);
        assert_eq!(f.rule_level, Some(7));
        assert_eq!(f.image.as_deref(), Some("C:\\x.exe"));
    }

    #[test]
    fn effective_event_id_from_group() {
        let f = AlertFields {
            rule_groups: vec!["sysmon".into(), "sysmon_eid22_detections".into()],
            ..Default::default()
        };
        assert_eq!(f.effective_event_id(), Some(22));
    }

    #[test]
    fn timestamps() {
        assert!(parse_timestamp_str("2024-05-01T12:00:00Z").is_some());
        assert!(parse_timestamp_str("2024-05-01T12:00:00.5+0200").is_some());
        assert!(parse_timestamp_str("2024-05-01 12:00:00").is_some());
        assert!(parse_timestamp(&json!(1714564800)).is_some());
        assert!(parse_timestamp(&json!(1714564800000_i64)).is_some());
        assert!(parse_timestamp_str("1714564800000").is_some());
        assert!(parse_timestamp_str("yesterday").is_none());
        assert!(parse_timestamp(&json!(-5)).is_none());
    }

    #[test]
    fn users() {
        assert_eq!(normalize_user("CORP\\Alice").as_deref(), Some("alice"));
        assert_eq!(normalize_user("alice@corp.local").as_deref(), Some("alice"));
        assert_eq!(normalize_user("NT AUTHORITY\\SYSTEM"), None);
        assert_eq!(normalize_user("WS01$"), None);
        assert_eq!(normalize_user("-"), None);
        assert_eq!(normalize_user("Font Driver Host\\UMFD-0"), None);
    }
}
