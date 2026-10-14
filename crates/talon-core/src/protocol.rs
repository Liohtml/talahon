//! Host <-> container wire protocol.
//!
//! ```text
//!   host (talon)                                container (talon-agent)
//!   ────────────                                ───────────────────────
//!   stdin  ── ContainerInput JSON, then EOF ──▶ read once at start
//!   stdout ◀─ OUTPUT_START / ContainerOutput / OUTPUT_END ── (repeatable)
//!   stderr ◀─ free-form log lines (tracing)
//!
//!   data/ipc/<ipc_key>/input/*.json   ──▶ /workspace/ipc/input/   (follow-ups)
//!   data/ipc/<ipc_key>/input/_close   ──▶ end of session sentinel
//!   data/ipc/<ipc_key>/messages/*.json ◀── /workspace/ipc/messages/ (send_message)
//!   data/ipc/<ipc_key>/tasks/*.json    ◀── /workspace/ipc/tasks/    (task ops)
//!   data/ipc/<ipc_key>/current_tasks.json   ──▶ snapshot (read-only for agent)
//!   data/ipc/<ipc_key>/available_groups.json──▶ snapshot (read-only for agent)
//! ```
//!
//! Every IPC file is written atomically (`<name>.json.tmp` then rename) and
//! named `<unix_millis>-<random6>.json` so lexical order == arrival order.
//! The host derives the *sender identity* from the directory the file was
//! found in, never from the file contents.

use serde::{Deserialize, Serialize};

use crate::types::{ContainerConfig, ContextMode, ScheduleType};

/// Marks the start of one JSON-encoded [`ContainerOutput`] on stdout.
pub const OUTPUT_START_MARKER: &str = "---TALON_OUTPUT_START---";
/// Marks the end of one JSON-encoded [`ContainerOutput`] on stdout.
pub const OUTPUT_END_MARKER: &str = "---TALON_OUTPUT_END---";

/// Name of the sentinel file that ends a container session.
pub const IPC_CLOSE_SENTINEL: &str = "_close";

/// Well-known paths inside the agent container.
pub mod container_paths {
    /// The group's folder (CLAUDE.md, prompts/, conversations/, logs/). cwd.
    pub const GROUP: &str = "/workspace/group";
    /// Shared read-only global memory (groups/global).
    pub const GLOBAL: &str = "/workspace/global";
    /// The project root (main group only, read-only, `.env` shadowed).
    pub const PROJECT: &str = "/workspace/project";
    /// Additional allowlisted mounts live under here.
    pub const EXTRA: &str = "/workspace/extra";
    /// IPC namespace root.
    pub const IPC: &str = "/workspace/ipc";
    pub const IPC_INPUT: &str = "/workspace/ipc/input";
    pub const IPC_MESSAGES: &str = "/workspace/ipc/messages";
    pub const IPC_TASKS: &str = "/workspace/ipc/tasks";
    pub const CURRENT_TASKS: &str = "/workspace/ipc/current_tasks.json";
    pub const AVAILABLE_GROUPS: &str = "/workspace/ipc/available_groups.json";
    /// Per-lane persistent agent state (sessions/transcripts). Mounted from
    /// `data/sessions/<session_key>/`.
    pub const AGENT_STATE: &str = "/home/agent/.talon";
    /// Per-group MCP server definitions.
    pub const MCP_JSON: &str = "/workspace/group/.mcp.json";
}

/// Everything the in-container runtime needs to reach the model.
///
/// Delivered over **stdin only** (never env vars), so the token is not visible
/// in `docker inspect` or `/proc/1/environ` and cannot be inherited by tool
/// subprocesses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmEndpoint {
    /// OpenAI-compatible base URL **including** `/v1`, normally the host LLM
    /// gateway, e.g. `http://host.docker.internal:3001/v1`.
    pub base_url: String,
    /// Bearer token for `base_url` (a per-run gateway token).
    pub token: String,
    /// Primary model name.
    pub model: String,
    /// Auxiliary model for compaction / extraction. Falls back to `model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast_model: Option<String>,
    /// Context window of `model`, tokens.
    pub max_context_tokens: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_thinking: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_secs: Option<u64>,
}

/// Written by the host to the container's stdin, then stdin is closed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerInput {
    pub prompt: String,
    /// Session to resume. `None` = fresh session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub group_folder: String,
    pub chat_jid: String,
    pub is_main: bool,
    #[serde(default)]
    pub is_scheduled_task: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assistant_name: Option<String>,
    /// Optional pre-flight bash script for scheduled tasks. Must print
    /// `{"wakeAgent": bool, "data"?: any}` as its last stdout line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// Model endpoint. `None` only in tests / mock mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmEndpoint>,
    /// Do not persist the session transcript (investigation lanes).
    #[serde(default)]
    pub ephemeral: bool,
    /// IANA timezone of the host, for timestamps shown to the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStatus {
    Success,
    Error,
}

/// Token usage for one agent turn. Field names follow the Anthropic shape the
/// host already stores; the vLLM runtime maps
/// `prompt_tokens - cached_tokens -> input_tokens`,
/// `prompt_tokens_details.cached_tokens -> cache_read_input_tokens`,
/// `completion_tokens -> output_tokens`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_input_tokens: Option<u64>,
}

impl SessionUsage {
    /// Total context size of the turn (what grows when a session is resumed).
    pub fn context_size(&self) -> u64 {
        self.input_tokens.unwrap_or(0)
            + self.cache_creation_input_tokens.unwrap_or(0)
            + self.cache_read_input_tokens.unwrap_or(0)
    }
}

/// One result block emitted by the container between the output markers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerOutput {
    pub status: OutputStatus,
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<SessionUsage>,
}

impl ContainerOutput {
    pub fn success(result: Option<String>, new_session_id: Option<String>) -> Self {
        Self {
            status: OutputStatus::Success,
            result,
            new_session_id,
            error: None,
            usage: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: OutputStatus::Error,
            result: None,
            new_session_id: None,
            error: Some(message.into()),
            usage: None,
        }
    }

    /// Render this output framed by the markers, ready for stdout.
    pub fn to_framed(&self) -> String {
        // ContainerOutput serialization cannot fail (no maps with non-string keys).
        let json = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        format!("{OUTPUT_START_MARKER}\n{json}\n{OUTPUT_END_MARKER}\n")
    }
}

/// Host -> container follow-up message (`input/*.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcInput {
    Message { text: String },
}

/// Container -> host outbound chat message (`messages/*.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcOutbound {
    Message {
        #[serde(rename = "chatJid")]
        chat_jid: String,
        text: String,
        #[serde(rename = "groupFolder", default, skip_serializing_if = "Option::is_none")]
        group_folder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },
}

/// Container -> host task operation (`tasks/*.json`).
///
/// The host MUST authorize every variant against the *directory-derived*
/// source group (see `talon-ipc`): non-main groups may only touch their own
/// tasks and may never register groups.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcTask {
    ScheduleTask {
        #[serde(rename = "taskId", default, skip_serializing_if = "Option::is_none")]
        task_id: Option<String>,
        prompt: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        script: Option<String>,
        schedule_type: ScheduleType,
        schedule_value: String,
        #[serde(default)]
        context_mode: Option<ContextMode>,
        #[serde(rename = "targetJid")]
        target_jid: String,
        #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
        created_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },
    PauseTask {
        #[serde(rename = "taskId")]
        task_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },
    ResumeTask {
        #[serde(rename = "taskId")]
        task_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },
    CancelTask {
        #[serde(rename = "taskId")]
        task_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },
    UpdateTask {
        #[serde(rename = "taskId")]
        task_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt: Option<String>,
        /// Empty string clears the script.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        script: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schedule_type: Option<ScheduleType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schedule_value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },
    RefreshGroups {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },
    RegisterGroup {
        jid: String,
        name: String,
        folder: String,
        trigger: String,
        #[serde(rename = "requiresTrigger", default, skip_serializing_if = "Option::is_none")]
        requires_trigger: Option<bool>,
        #[serde(rename = "containerConfig", default, skip_serializing_if = "Option::is_none")]
        container_config: Option<ContainerConfig>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },
}

/// Result of a scheduled task's pre-flight script (last stdout line).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptResult {
    pub wake_agent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Build a lexically ordered, collision-resistant IPC file name
/// (`<unix_millis>-<random6>.json`).
pub fn ipc_file_name() -> String {
    let millis = chrono::Utc::now().timestamp_millis();
    let rand = uuid::Uuid::new_v4().simple().to_string();
    format!("{millis}-{}.json", &rand[..6])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_task_roundtrip_matches_ts_shape() {
        let raw = r#"{"type":"schedule_task","taskId":"task-1","prompt":"hi","schedule_type":"cron","schedule_value":"*/5 * * * *","context_mode":"group","targetJid":"tg:1","createdBy":"main","timestamp":"2026-01-01T00:00:00.000Z"}"#;
        let t: IpcTask = serde_json::from_str(raw).unwrap();
        match &t {
            IpcTask::ScheduleTask {
                task_id,
                schedule_type,
                target_jid,
                ..
            } => {
                assert_eq!(task_id.as_deref(), Some("task-1"));
                assert_eq!(*schedule_type, ScheduleType::Cron);
                assert_eq!(target_jid, "tg:1");
            }
            other => panic!("unexpected {other:?}"),
        }
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["type"], "schedule_task");
        assert_eq!(v["targetJid"], "tg:1");
    }

    #[test]
    fn outbound_message_shape() {
        let raw = r#"{"type":"message","chatJid":"x","text":"t","groupFolder":"g"}"#;
        let m: IpcOutbound = serde_json::from_str(raw).unwrap();
        let IpcOutbound::Message { chat_jid, .. } = m;
        assert_eq!(chat_jid, "x");
    }

    #[test]
    fn framed_output_contains_markers() {
        let s = ContainerOutput::success(Some("ok".into()), Some("s1".into())).to_framed();
        assert!(s.starts_with(OUTPUT_START_MARKER));
        assert!(s.trim_end().ends_with(OUTPUT_END_MARKER));
        assert!(s.contains("\"newSessionId\":\"s1\""));
    }

    #[test]
    fn usage_context_size() {
        let u = SessionUsage {
            input_tokens: Some(10),
            output_tokens: Some(99),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: Some(5),
        };
        assert_eq!(u.context_size(), 15);
    }

    #[test]
    fn ipc_file_names_sort_and_differ() {
        let a = ipc_file_name();
        let b = ipc_file_name();
        assert!(a.ends_with(".json"));
        assert_ne!(a, b);
    }
}
