//! Bounded parsing and shape validation of container-written IPC payloads.
//!
//! Pipeline: nesting-depth pre-scan (linear, no recursion) -> `serde_json`
//! into a generic value -> lenient normalization -> typed
//! protocol structs -> shape checks (non-empty required fields, length and
//! charset limits). Anything failing here is *malformed* and gets
//! quarantined; semantic problems (authorization, bad schedules, duplicate
//! ids) are decided later and audited.

use serde_json::Value;
use talon_core::protocol::{IpcOutbound, IpcTask};

/// Maximum length of a JID / chat id.
pub const MAX_JID_LEN: usize = 256;
/// Maximum length of a task id.
pub const MAX_TASK_ID_LEN: usize = 128;
/// Maximum length of a schedule value.
pub const MAX_SCHEDULE_VALUE_LEN: usize = 256;
/// Maximum length of a group display name or trigger.
pub const MAX_NAME_LEN: usize = 256;
/// Maximum number of additional mounts a `register_group` may request.
pub const MAX_ADDITIONAL_MOUNTS: usize = 32;
/// Reasons (which may echo attacker-controlled text) are truncated to this.
pub const MAX_REASON_LEN: usize = 300;

/// Replacement for characters that must not reach a log line or audit row.
pub(crate) const LOG_REPLACEMENT_CHAR: char = '\u{FFFD}';

/// Characters that can forge or disguise log lines: C0/C1 controls
/// (including `\n`, `\r`, `\t`, ESC, DEL, NEL), the Unicode
/// bidirectional controls (ALM, LRM, RLM, LRE/RLE/PDF/LRO/RLO,
/// LRI/RLI/FSI/PDI) and the line/paragraph separators.
fn is_log_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{2028}'
                | '\u{2029}'
        )
}

/// Make container-influenced text (file names, JIDs, reasons that echo
/// input) safe for logs and audit rows: every control / bidi character is
/// replaced by [`LOG_REPLACEMENT_CHAR`] and the result is truncated to
/// [`MAX_REASON_LEN`] characters (plus `…`).
pub(crate) fn sanitize_for_log(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_REASON_LEN * 4));
    let mut chars = s.chars();
    for c in chars.by_ref().take(MAX_REASON_LEN) {
        out.push(if is_log_unsafe(c) {
            LOG_REPLACEMENT_CHAR
        } else {
            c
        });
    }
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// Truncate a human-readable reason on a char boundary and neutralize
/// control / bidi characters (see [`sanitize_for_log`]).
pub(crate) fn truncate_reason(s: &str) -> String {
    sanitize_for_log(s)
}

/// Returns true when `bytes` nests arrays/objects deeper than `max_depth`.
///
/// String contents (including escaped quotes) are skipped, so brackets
/// inside strings don't count. Linear time, constant memory.
pub fn exceeds_depth(bytes: &[u8], max_depth: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

fn parse_object(bytes: &[u8], max_depth: usize) -> Result<serde_json::Map<String, Value>, String> {
    if exceeds_depth(bytes, max_depth) {
        return Err(format!("JSON nesting exceeds depth limit of {max_depth}"));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| truncate_reason(&format!("invalid JSON: {e}")))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err("payload is not a JSON object".into()),
    }
}

fn type_of(map: &serde_json::Map<String, Value>) -> Result<&str, String> {
    match map.get("type") {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(_) => Err("field `type` is not a string".into()),
        None => Err("missing field `type`".into()),
    }
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

fn check_jid(field: &str, jid: &str) -> Result<(), String> {
    if jid.is_empty() {
        return Err(format!("`{field}` must not be empty"));
    }
    if jid.len() > MAX_JID_LEN {
        return Err(format!("`{field}` exceeds {MAX_JID_LEN} bytes"));
    }
    if has_control(jid) || jid.trim() != jid {
        return Err(format!(
            "`{field}` contains control characters or surrounding whitespace"
        ));
    }
    Ok(())
}

/// `^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`
pub fn is_valid_task_id(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    id.len() <= MAX_TASK_ID_LEN
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

fn check_task_id(id: &str) -> Result<(), String> {
    if is_valid_task_id(id) {
        Ok(())
    } else {
        Err("`taskId` must match ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$".into())
    }
}

fn check_text(field: &str, s: &str, max: usize) -> Result<(), String> {
    if s.trim().is_empty() {
        return Err(format!("`{field}` must not be empty"));
    }
    if s.len() > max {
        return Err(format!("`{field}` exceeds {max} bytes"));
    }
    if has_control(s) {
        return Err(format!("`{field}` contains control characters"));
    }
    Ok(())
}

fn check_schedule_value(v: &str) -> Result<(), String> {
    if v.trim().is_empty() {
        return Err("`schedule_value` must not be empty".into());
    }
    if v.len() > MAX_SCHEDULE_VALUE_LEN {
        return Err(format!(
            "`schedule_value` exceeds {MAX_SCHEDULE_VALUE_LEN} bytes"
        ));
    }
    if has_control(v) {
        return Err("`schedule_value` contains control characters".into());
    }
    Ok(())
}

/// Shape checks for an outbound message (required fields present and sane).
pub fn validate_outbound_shape(msg: &IpcOutbound) -> Result<(), String> {
    let IpcOutbound::Message { chat_jid, text, .. } = msg;
    check_jid("chatJid", chat_jid)?;
    if text.is_empty() {
        return Err("`text` must not be empty".into());
    }
    Ok(())
}

/// Shape checks for a task request.
pub fn validate_task_shape(task: &IpcTask) -> Result<(), String> {
    match task {
        IpcTask::ScheduleTask {
            task_id,
            prompt,
            schedule_value,
            target_jid,
            ..
        } => {
            if let Some(id) = task_id {
                check_task_id(id)?;
            }
            if prompt.trim().is_empty() {
                return Err("`prompt` must not be empty".into());
            }
            check_schedule_value(schedule_value)?;
            check_jid("targetJid", target_jid)
        }
        IpcTask::PauseTask { task_id, .. }
        | IpcTask::ResumeTask { task_id, .. }
        | IpcTask::CancelTask { task_id, .. } => check_task_id(task_id),
        IpcTask::UpdateTask {
            task_id,
            prompt,
            schedule_value,
            ..
        } => {
            check_task_id(task_id)?;
            if let Some(p) = prompt {
                if p.trim().is_empty() {
                    return Err("`prompt` must not be empty".into());
                }
            }
            if let Some(v) = schedule_value {
                check_schedule_value(v)?;
            }
            Ok(())
        }
        IpcTask::RefreshGroups { .. } => Ok(()),
        IpcTask::RegisterGroup {
            jid,
            name,
            folder,
            trigger,
            container_config,
            ..
        } => {
            check_jid("jid", jid)?;
            check_text("name", name, MAX_NAME_LEN)?;
            if folder.is_empty() {
                return Err("`folder` must not be empty".into());
            }
            check_text("trigger", trigger, MAX_NAME_LEN)?;
            if let Some(cfg) = container_config {
                if cfg.additional_mounts.len() > MAX_ADDITIONAL_MOUNTS {
                    return Err(format!(
                        "`containerConfig.additionalMounts` exceeds {MAX_ADDITIONAL_MOUNTS} entries"
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Parse and validate a `messages/*.json` payload.
pub fn parse_outbound(bytes: &[u8], max_depth: usize) -> Result<IpcOutbound, String> {
    let map = parse_object(bytes, max_depth)?;
    let ty = type_of(&map)?;
    if ty != "message" {
        return Err(truncate_reason(&format!("unknown message type {ty:?}")));
    }
    let msg: IpcOutbound = serde_json::from_value(Value::Object(map))
        .map_err(|e| truncate_reason(&format!("invalid message: {e}")))?;
    validate_outbound_shape(&msg)?;
    Ok(msg)
}

const TASK_TYPES: &[&str] = &[
    "schedule_task",
    "pause_task",
    "resume_task",
    "cancel_task",
    "update_task",
    "refresh_groups",
    "register_group",
];

/// Leniency applied before typed deserialization:
/// - `context_mode` other than `"group"` / `"isolated"` falls back to the
///   default (isolated) instead of failing the whole request;
/// - `schedule_task`: empty `taskId` / `script` mean "not given"
///   (`data.taskId || generated`, `data.script || null`).
fn normalize_task(ty: &str, map: &mut serde_json::Map<String, Value>) {
    let ctx_ok = match map.get("context_mode") {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s == "group" || s == "isolated",
        Some(_) => false,
    };
    if !ctx_ok {
        map.remove("context_mode");
    }
    if ty == "schedule_task" {
        for key in ["taskId", "script"] {
            if matches!(map.get(key), Some(Value::String(s)) if s.is_empty()) {
                map.remove(key);
            }
        }
    }
}

/// Parse and validate a `tasks/*.json` payload.
pub fn parse_task(bytes: &[u8], max_depth: usize) -> Result<IpcTask, String> {
    let mut map = parse_object(bytes, max_depth)?;
    let ty = type_of(&map)?.to_string();
    if !TASK_TYPES.contains(&ty.as_str()) {
        return Err(truncate_reason(&format!("unknown task type {ty:?}")));
    }
    normalize_task(&ty, &mut map);
    let task: IpcTask = serde_json::from_value(Value::Object(map))
        .map_err(|e| truncate_reason(&format!("invalid {ty} request: {e}")))?;
    validate_task_shape(&task)?;
    Ok(task)
}

/// Stable name of a task variant (the wire `type`).
pub fn task_type_name(task: &IpcTask) -> &'static str {
    match task {
        IpcTask::ScheduleTask { .. } => "schedule_task",
        IpcTask::PauseTask { .. } => "pause_task",
        IpcTask::ResumeTask { .. } => "resume_task",
        IpcTask::CancelTask { .. } => "cancel_task",
        IpcTask::UpdateTask { .. } => "update_task",
        IpcTask::RefreshGroups { .. } => "refresh_groups",
        IpcTask::RegisterGroup { .. } => "register_group",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talon_core::types::{ContextMode, ScheduleType};

    #[test]
    fn depth_scan_counts_only_structure() {
        assert!(!exceeds_depth(br#"{"a":{"b":[1,2]}}"#, 3));
        assert!(exceeds_depth(br#"{"a":{"b":[1,2]}}"#, 2));
        // brackets inside strings (and escaped quotes) are ignored
        assert!(!exceeds_depth(br#"{"a":"[[[[\"{{{{"}"#, 1));
        let deep = "[".repeat(10_000) + &"]".repeat(10_000);
        assert!(exceeds_depth(deep.as_bytes(), 16));
    }

    #[test]
    fn too_deep_payload_rejected_before_parsing() {
        let deep = format!(
            r#"{{"type":"message","chatJid":"a","text":"t","x":{}{}}}"#,
            "[".repeat(40),
            "]".repeat(40)
        );
        let err = parse_outbound(deep.as_bytes(), 16).unwrap_err();
        assert!(err.contains("depth"), "{err}");
    }

    #[test]
    fn parses_container_message_with_extra_fields() {
        let raw = br#"{"type":"message","chatJid":"tg:1","text":"hi","sender":"Researcher","groupFolder":"main","timestamp":"2026-01-01T00:00:00.000Z"}"#;
        let IpcOutbound::Message { chat_jid, text, .. } = parse_outbound(raw, 16).unwrap();
        assert_eq!(chat_jid, "tg:1");
        assert_eq!(text, "hi");
    }

    #[test]
    fn rejects_malformed_messages() {
        for raw in [
            &b"not json"[..],
            br#"[1,2]"#,
            br#"{"chatJid":"a","text":"t"}"#,
            br#"{"type":"bogus","chatJid":"a","text":"t"}"#,
            br#"{"type":"message","chatJid":"","text":"t"}"#,
            br#"{"type":"message","chatJid":"a","text":""}"#,
            br#"{"type":"message","text":"t"}"#,
            br#"{"type":"message","chatJid":"a\nb","text":"t"}"#,
            br#"{"type":7,"chatJid":"a","text":"t"}"#,
        ] {
            assert!(
                parse_outbound(raw, 16).is_err(),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn invalid_context_mode_defaults_to_isolated() {
        let raw = br#"{"type":"schedule_task","prompt":"p","schedule_type":"once","schedule_value":"2025-06-01T00:00:00","context_mode":"bogus","targetJid":"other@g.us"}"#;
        let IpcTask::ScheduleTask { context_mode, .. } = parse_task(raw, 16).unwrap() else {
            panic!("wrong variant")
        };
        assert_eq!(context_mode.unwrap_or_default(), ContextMode::Isolated);

        let raw = br#"{"type":"schedule_task","prompt":"p","schedule_type":"once","schedule_value":"2025-06-01T00:00:00","context_mode":"group","targetJid":"other@g.us"}"#;
        let IpcTask::ScheduleTask { context_mode, .. } = parse_task(raw, 16).unwrap() else {
            panic!("wrong variant")
        };
        assert_eq!(context_mode, Some(ContextMode::Group));
    }

    #[test]
    fn empty_task_id_and_script_mean_absent_for_schedule() {
        let raw = br#"{"type":"schedule_task","taskId":"","script":"","prompt":"p","schedule_type":"cron","schedule_value":"0 9 * * *","targetJid":"x"}"#;
        let IpcTask::ScheduleTask {
            task_id,
            script,
            schedule_type,
            ..
        } = parse_task(raw, 16).unwrap()
        else {
            panic!("wrong variant")
        };
        assert!(task_id.is_none());
        assert!(script.is_none());
        assert_eq!(schedule_type, ScheduleType::Cron);
    }

    #[test]
    fn update_task_keeps_empty_script_as_clear() {
        let raw = br#"{"type":"update_task","taskId":"t-1","script":"","groupFolder":"x","isMain":"true"}"#;
        let IpcTask::UpdateTask { script, .. } = parse_task(raw, 16).unwrap() else {
            panic!("wrong variant")
        };
        assert_eq!(script.as_deref(), Some(""));
    }

    #[test]
    fn rejects_malformed_tasks() {
        for raw in [
            &br#"{"type":"nuke_everything"}"#[..],
            br#"{"type":"schedule_task","prompt":"p","schedule_type":"weekly","schedule_value":"x","targetJid":"x"}"#,
            br#"{"type":"schedule_task","prompt":"","schedule_type":"cron","schedule_value":"* * * * *","targetJid":"x"}"#,
            br#"{"type":"schedule_task","prompt":"p","schedule_type":"cron","schedule_value":"","targetJid":"x"}"#,
            br#"{"type":"schedule_task","taskId":"../../etc","prompt":"p","schedule_type":"cron","schedule_value":"* * * * *","targetJid":"x"}"#,
            br#"{"type":"pause_task"}"#,
            br#"{"type":"pause_task","taskId":"a b"}"#,
            br#"{"type":"update_task","taskId":"t","prompt":"  "}"#,
            br#"{"type":"register_group","jid":"partial@g.us","name":"Partial"}"#,
            br#"{"type":"register_group","jid":"j","name":"n","folder":"","trigger":"@A"}"#,
            br#"{"type":"register_group","jid":"j","name":"n","folder":"f","trigger":"@A","requiresTrigger":"yes"}"#,
            br#"{"type":"message","chatJid":"a","text":"t"}"#,
        ] {
            assert!(parse_task(raw, 16).is_err(), "{}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn task_id_charset() {
        assert!(is_valid_task_id("task-1700000000000-abc123"));
        assert!(is_valid_task_id("copilot-alert-digest-15m"));
        assert!(!is_valid_task_id(""));
        assert!(!is_valid_task_id("-x"));
        assert!(!is_valid_task_id("a/b"));
        assert!(!is_valid_task_id(&"a".repeat(129)));
    }

    #[test]
    fn reasons_are_truncated() {
        let long = "x".repeat(10_000);
        let r = truncate_reason(&long);
        assert!(r.chars().count() <= MAX_REASON_LEN + 1);
        let raw = format!(r#"{{"type":"{long}"}}"#);
        let err = parse_task(raw.as_bytes(), 16).unwrap_err();
        assert!(err.len() < 1_000);
    }

    #[test]
    fn log_text_is_sanitized() {
        let forged = "x.json\n2026-01-01T00:00:00Z INFO fake line\r\u{1b}[31m";
        let s = sanitize_for_log(forged);
        assert!(!s.contains('\n') && !s.contains('\r') && !s.contains('\u{1b}'));
        assert!(s.starts_with("x.json\u{FFFD}2026"));
        for bidi in [
            '\u{202E}', '\u{202A}', '\u{2066}', '\u{2069}', '\u{200E}', '\u{200F}', '\u{061C}',
            '\u{2028}', '\u{2029}', '\u{85}', '\u{7f}', '\t',
        ] {
            let s = truncate_reason(&format!("evil{bidi}gpj.exe"));
            assert!(!s.contains(bidi), "{bidi:?}");
            assert_eq!(s, "evil\u{FFFD}gpj.exe");
        }
        // ordinary non-ASCII text is preserved
        assert_eq!(sanitize_for_log("Grüße — 日本"), "Grüße — 日本");
        // truncation still applies
        let long = "\n".repeat(10_000);
        let s = sanitize_for_log(&long);
        assert_eq!(s.chars().count(), MAX_REASON_LEN + 1);
        assert!(s.ends_with('…'));
        assert_eq!(
            sanitize_for_log(&"y".repeat(MAX_REASON_LEN))
                .chars()
                .count(),
            MAX_REASON_LEN
        );
    }

    #[test]
    fn task_type_names_match_wire() {
        let t = IpcTask::RefreshGroups { timestamp: None };
        assert_eq!(task_type_name(&t), "refresh_groups");
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["type"], task_type_name(&t));
    }
}
