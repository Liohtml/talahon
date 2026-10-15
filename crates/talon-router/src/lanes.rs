//! Lane resolution, trigger gating and the available-groups snapshot
//! (ports of `src/session-lane.ts`, the trigger-gating logic of
//! `src/index.ts` exercised by `formatting.test.ts`, and `getAvailableGroups`
//! exercised by `routing.test.ts`).
//!
//! A *lane* is one addressable conversation: a JID with its own agent
//! session, IPC namespace, queue slot and outbound writer. Several lanes may
//! share a group folder (same CLAUDE.md, prompts and mounts) — that is how
//! the CoPilot channel runs chat and alert investigations as separate
//! conversations without duplicating group content on disk.

use std::collections::HashMap;

use regex::Regex;
use talon_core::trigger::build_trigger_pattern;
use talon_core::types::{AvailableGroup, ChatInfo, NewMessage, RegisteredGroup};

/// Sentinel chat row the TypeScript release used to record group syncs.
pub const GROUP_SYNC_SENTINEL: &str = "__group_sync__";

/// Storage key for a lane's agent session (defaults to the group folder).
pub fn session_key_for(group: &RegisteredGroup) -> &str {
    group.session_key()
}

/// IPC namespace for a lane's container (defaults to the group folder).
///
/// Two concurrently running containers must never resolve to the same key:
/// the IPC input directory is how follow-up messages reach a running agent.
pub fn ipc_key_for(group: &RegisteredGroup) -> &str {
    group.ipc_key()
}

/// Whether a lane stores its session between runs. Ephemeral lanes (alert
/// investigations) never do, so one alert's context cannot bleed into the
/// next.
pub fn should_persist_session(group: &RegisteredGroup) -> bool {
    group.should_persist_session()
}

/// The session id a lane should resume, or `None` to start fresh.
pub fn resumable_session_id<'a>(
    group: &RegisteredGroup,
    sessions: &'a HashMap<String, String>,
) -> Option<&'a str> {
    if !should_persist_session(group) {
        return None;
    }
    sessions.get(session_key_for(group)).map(String::as_str)
}

/// `!is_main && requires_trigger != Some(false)` — whether a batch needs the
/// trigger word before the agent runs.
pub fn should_require_trigger(is_main_group: bool, requires_trigger: Option<bool>) -> bool {
    !is_main_group && requires_trigger != Some(false)
}

/// The trigger regex for a group (its own trigger, or `@<assistant_name>`
/// when empty).
pub fn trigger_pattern_for(group: &RegisteredGroup, assistant_name: &str) -> Regex {
    build_trigger_pattern(&group.trigger, assistant_name)
}

/// Whether any message (trimmed) starts with the trigger.
pub fn has_trigger(messages: &[NewMessage], pattern: &Regex) -> bool {
    messages.iter().any(|m| pattern.is_match(m.content.trim()))
}

/// Whether a pending batch should be handed to the agent: always for the
/// main group and trigger-less groups, otherwise only if a message carries
/// the group's trigger.
pub fn should_process(
    group: &RegisteredGroup,
    assistant_name: &str,
    messages: &[NewMessage],
) -> bool {
    if !should_require_trigger(group.is_main, group.requires_trigger) {
        return true;
    }
    has_trigger(messages, &trigger_pattern_for(group, assistant_name))
}

/// Build the `available_groups.json` view from the chat table: group chats
/// only (the sync sentinel excluded), flagged when registered, most recent
/// activity first.
pub fn available_groups(
    chats: &[ChatInfo],
    registered: &HashMap<String, RegisteredGroup>,
) -> Vec<AvailableGroup> {
    let mut groups: Vec<AvailableGroup> = chats
        .iter()
        .filter(|c| c.jid != GROUP_SYNC_SENTINEL && c.is_group)
        .map(|c| AvailableGroup {
            jid: c.jid.clone(),
            name: c.name.clone(),
            last_activity: c.last_message_time.clone(),
            is_registered: registered.contains_key(&c.jid),
        })
        .collect();
    // ISO-8601 strings sort chronologically; stable sort keeps DB order on ties.
    groups.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASSISTANT: &str = "Andy";

    fn make_group() -> RegisteredGroup {
        RegisteredGroup {
            name: "CoPilot".into(),
            folder: "copilot".into(),
            trigger: String::new(),
            added_at: "2026-01-01T00:00:00.000Z".into(),
            container_config: None,
            requires_trigger: Some(false),
            is_main: false,
            session_key: None,
            ipc_key: None,
            ephemeral_session: false,
            trusted_session_commands: false,
        }
    }

    fn msg(content: &str) -> NewMessage {
        NewMessage {
            id: "1".into(),
            chat_jid: "group@g.us".into(),
            sender: "123".into(),
            sender_name: "Alice".into(),
            content: content.into(),
            timestamp: "2024-01-01T00:00:00.000Z".into(),
            ..Default::default()
        }
    }

    // --- session_key_for ----------------------------------------------------

    #[test]
    fn session_key_defaults_to_folder() {
        assert_eq!(session_key_for(&make_group()), "copilot");
    }

    #[test]
    fn session_key_uses_override() {
        let g = RegisteredGroup {
            session_key: Some("copilot-investigate".into()),
            ..make_group()
        };
        assert_eq!(session_key_for(&g), "copilot-investigate");
    }

    #[test]
    fn lanes_sharing_a_folder_have_separate_session_keys() {
        let chat = make_group();
        let inv = RegisteredGroup {
            session_key: Some("copilot-investigate".into()),
            ..make_group()
        };
        assert_eq!(chat.folder, inv.folder);
        assert_ne!(session_key_for(&chat), session_key_for(&inv));
    }

    // --- ipc_key_for --------------------------------------------------------

    #[test]
    fn ipc_key_defaults_to_folder() {
        assert_eq!(ipc_key_for(&make_group()), "copilot");
    }

    #[test]
    fn ipc_key_uses_override() {
        let g = RegisteredGroup {
            ipc_key: Some("copilot-investigate".into()),
            ..make_group()
        };
        assert_eq!(ipc_key_for(&g), "copilot-investigate");
    }

    #[test]
    fn concurrent_lanes_have_separate_ipc_namespaces() {
        let chat = make_group();
        let inv = RegisteredGroup {
            ipc_key: Some("copilot-investigate".into()),
            ..make_group()
        };
        assert_ne!(ipc_key_for(&chat), ipc_key_for(&inv));
    }

    // --- should_persist_session ---------------------------------------------

    #[test]
    fn persists_by_default() {
        assert!(should_persist_session(&make_group()));
    }

    #[test]
    fn ephemeral_lane_does_not_persist() {
        let g = RegisteredGroup {
            ephemeral_session: true,
            ..make_group()
        };
        assert!(!should_persist_session(&g));
    }

    // --- resumable_session_id -----------------------------------------------

    fn sessions() -> HashMap<String, String> {
        HashMap::from([
            ("copilot".to_string(), "chat-session-1".to_string()),
            (
                "copilot-investigate".to_string(),
                "stale-investigate-session".to_string(),
            ),
        ])
    }

    #[test]
    fn resumes_session_under_lane_key() {
        let s = sessions();
        assert_eq!(
            resumable_session_id(&make_group(), &s),
            Some("chat-session-1")
        );
    }

    #[test]
    fn ephemeral_lane_never_resumes() {
        let s = sessions();
        let g = RegisteredGroup {
            session_key: Some("copilot-investigate".into()),
            ephemeral_session: true,
            ..make_group()
        };
        assert_eq!(resumable_session_id(&g, &s), None);
    }

    #[test]
    fn resumes_nothing_without_stored_session() {
        let s = sessions();
        let g = RegisteredGroup {
            session_key: Some("copilot-u-42".into()),
            ..make_group()
        };
        assert_eq!(resumable_session_id(&g, &s), None);
    }

    // --- trigger pattern (formatting.test.ts TRIGGER_PATTERN) ----------------

    fn default_pattern() -> Regex {
        build_trigger_pattern("", ASSISTANT)
    }

    #[test]
    fn trigger_matches_at_start() {
        assert!(default_pattern().is_match("@Andy hello"));
    }

    #[test]
    fn trigger_matches_case_insensitively() {
        assert!(default_pattern().is_match("@andy hello"));
        assert!(default_pattern().is_match("@ANDY hello"));
    }

    #[test]
    fn trigger_not_matched_mid_message() {
        assert!(!default_pattern().is_match("hello @Andy"));
    }

    #[test]
    fn trigger_requires_word_boundary() {
        assert!(!default_pattern().is_match("@Andyextra hello"));
    }

    #[test]
    fn trigger_word_boundary_before_apostrophe() {
        assert!(default_pattern().is_match("@Andy's thing"));
    }

    #[test]
    fn trigger_alone_matches() {
        assert!(default_pattern().is_match("@Andy"));
    }

    #[test]
    fn per_group_trigger_is_used() {
        let p = build_trigger_pattern("@Claw", ASSISTANT);
        assert!(p.is_match("@Claw hello"));
        assert!(!p.is_match("@Andy hello"));
    }

    #[test]
    fn custom_trigger_regex_chars_are_literal() {
        let p = build_trigger_pattern("@C.L.A.U.D.E", ASSISTANT);
        assert!(p.is_match("@C.L.A.U.D.E hello"));
        assert!(!p.is_match("@CXLXAUXDXE hello"));
    }

    // --- trigger gating -----------------------------------------------------

    fn gate(is_main: bool, requires_trigger: Option<bool>, trigger: &str, content: &str) -> bool {
        let g = RegisteredGroup {
            is_main,
            requires_trigger,
            trigger: trigger.into(),
            ..make_group()
        };
        should_process(&g, ASSISTANT, &[msg(content)])
    }

    #[test]
    fn main_group_always_processes() {
        assert!(gate(true, None, "", "hello no trigger"));
        assert!(gate(true, Some(true), "", "hello no trigger"));
    }

    #[test]
    fn non_main_defaults_to_requiring_trigger() {
        assert!(!gate(false, None, "", "hello no trigger"));
        assert!(!gate(false, Some(true), "", "hello no trigger"));
    }

    #[test]
    fn non_main_processes_with_trigger() {
        assert!(gate(false, Some(true), "", "@Andy do something"));
        assert!(gate(false, Some(true), "", "   @Andy do something"));
    }

    #[test]
    fn non_main_uses_its_own_trigger() {
        assert!(gate(false, Some(true), "@Claw", "@Claw do something"));
        assert!(!gate(false, Some(true), "@Claw", "@Andy do something"));
    }

    #[test]
    fn non_main_without_trigger_requirement_always_processes() {
        assert!(gate(false, Some(false), "", "hello no trigger"));
    }

    #[test]
    fn should_require_trigger_truth_table() {
        assert!(!should_require_trigger(true, None));
        assert!(!should_require_trigger(true, Some(true)));
        assert!(should_require_trigger(false, None));
        assert!(should_require_trigger(false, Some(true)));
        assert!(!should_require_trigger(false, Some(false)));
    }

    // --- available_groups (routing.test.ts) ---------------------------------

    fn chat(jid: &str, ts: &str, name: &str, is_group: bool) -> ChatInfo {
        ChatInfo {
            jid: jid.into(),
            name: name.into(),
            last_message_time: ts.into(),
            channel: Some("telegram".into()),
            is_group,
        }
    }

    #[test]
    fn returns_only_groups() {
        let chats = [
            chat("group1@g.us", "2024-01-01T00:00:01.000Z", "Group 1", true),
            chat(
                "user@s.whatsapp.net",
                "2024-01-01T00:00:02.000Z",
                "User DM",
                false,
            ),
            chat("group2@g.us", "2024-01-01T00:00:03.000Z", "Group 2", true),
        ];
        let groups = available_groups(&chats, &HashMap::new());
        let jids: Vec<_> = groups.iter().map(|g| g.jid.as_str()).collect();
        assert_eq!(groups.len(), 2);
        assert!(jids.contains(&"group1@g.us"));
        assert!(jids.contains(&"group2@g.us"));
        assert!(!jids.contains(&"user@s.whatsapp.net"));
    }

    #[test]
    fn excludes_group_sync_sentinel() {
        let chats = [
            chat(
                GROUP_SYNC_SENTINEL,
                "2024-01-01T00:00:00.000Z",
                GROUP_SYNC_SENTINEL,
                true,
            ),
            chat("group@g.us", "2024-01-01T00:00:01.000Z", "Group", true),
        ];
        let groups = available_groups(&chats, &HashMap::new());
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].jid, "group@g.us");
    }

    #[test]
    fn marks_registered_groups() {
        let chats = [
            chat("reg@g.us", "2024-01-01T00:00:01.000Z", "Registered", true),
            chat(
                "unreg@g.us",
                "2024-01-01T00:00:02.000Z",
                "Unregistered",
                true,
            ),
        ];
        let registered = HashMap::from([(
            "reg@g.us".to_string(),
            RegisteredGroup {
                name: "Registered".into(),
                folder: "registered".into(),
                trigger: "@Andy".into(),
                ..make_group()
            },
        )]);
        let groups = available_groups(&chats, &registered);
        assert!(
            groups
                .iter()
                .find(|g| g.jid == "reg@g.us")
                .unwrap()
                .is_registered
        );
        assert!(
            !groups
                .iter()
                .find(|g| g.jid == "unreg@g.us")
                .unwrap()
                .is_registered
        );
    }

    #[test]
    fn ordered_by_most_recent_activity() {
        let chats = [
            chat("old@g.us", "2024-01-01T00:00:01.000Z", "Old", true),
            chat("new@g.us", "2024-01-01T00:00:05.000Z", "New", true),
            chat("mid@g.us", "2024-01-01T00:00:03.000Z", "Mid", true),
        ];
        let groups = available_groups(&chats, &HashMap::new());
        let jids: Vec<_> = groups.iter().map(|g| g.jid.as_str()).collect();
        assert_eq!(jids, vec!["new@g.us", "mid@g.us", "old@g.us"]);
    }

    #[test]
    fn excludes_non_group_chats_regardless_of_jid_format() {
        let chats = [
            chat(
                "unknown-format-123",
                "2024-01-01T00:00:01.000Z",
                "Unknown",
                false,
            ),
            chat("custom:abc", "2024-01-01T00:00:02.000Z", "Custom DM", false),
            chat("group@g.us", "2024-01-01T00:00:03.000Z", "Group", true),
        ];
        let groups = available_groups(&chats, &HashMap::new());
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].jid, "group@g.us");
    }

    #[test]
    fn empty_when_no_chats() {
        assert!(available_groups(&[], &HashMap::new()).is_empty());
    }
}
