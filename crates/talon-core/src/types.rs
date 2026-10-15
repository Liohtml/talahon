//! Domain model shared by the host and the in-container runtime.
//!
//! Serde field names deliberately match the JSON the TypeScript implementation
//! wrote (a mix of camelCase and snake_case), so existing SQLite rows
//! (`registered_groups.container_config`) and IPC snapshot files keep parsing
//! after an in-place upgrade.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Mounts
// ---------------------------------------------------------------------------

/// An extra host directory a group asks to have mounted into its container.
/// Always validated against the [`MountAllowlist`] before use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionalMount {
    /// Absolute path on the host (`~` is expanded).
    pub host_path: String,
    /// Mounted at `/workspace/extra/{container_path}`. Defaults to the
    /// basename of `host_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_path: Option<String>,
    /// Read-only unless explicitly set to `false`.
    #[serde(default = "default_true")]
    pub readonly: bool,
}

/// Tamper-proof mount policy. Lives outside the project root
/// (`~/.config/talon/mount-allowlist.json`) and is never mounted into a
/// container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MountAllowlist {
    pub allowed_roots: Vec<AllowedRoot>,
    #[serde(default)]
    pub blocked_patterns: Vec<String>,
    /// Non-main groups only ever get read-only mounts when true.
    #[serde(default = "default_true")]
    pub non_main_read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedRoot {
    pub path: String,
    #[serde(default)]
    pub allow_read_write: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Provider (vLLM)
// ---------------------------------------------------------------------------

/// Agent model provider. Talon speaks the OpenAI-compatible API exposed by
/// vLLM. Values written by older releases (`"anthropic"`, `"ollama"`)
/// deserialize to [`ProviderKind::Unsupported`] and are ignored with a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Vllm,
    #[serde(other)]
    Unsupported,
}

impl ProviderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderKind::Vllm => "vllm",
            ProviderKind::Unsupported => "unsupported",
        }
    }
}

/// Connection + sampling settings for a vLLM OpenAI-compatible server.
///
/// The API key is intentionally *not* part of this struct: it is read by the
/// host from `.env` (`TALON_VLLM_API_KEY`) and only ever held by the host-side
/// LLM gateway. Containers authenticate to the gateway with a short-lived,
/// per-run token instead (see [`crate::protocol::LlmEndpoint`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VllmConfig {
    /// e.g. `http://vllm.internal:8000` (with or without a trailing `/v1`).
    pub base_url: String,
    /// The served model name (`--served-model-name`), e.g. `Qwen/Qwen3-32B`.
    pub model: String,
    /// Optional smaller/faster model for auxiliary work: context compaction,
    /// IOC extraction, summarisation. Falls back to `model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast_model: Option<String>,
    /// Context window of `model` in tokens. Drives compaction thresholds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_context_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Forwarded as `chat_template_kwargs.enable_thinking` for reasoning
    /// models (Qwen3, DeepSeek-R1 distills, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_thinking: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// Container config (per group, stored as JSON in `registered_groups`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_mounts: Vec<AdditionalMount>,
    /// Hard timeout for a container run, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vllm: Option<VllmConfig>,
    /// Raw env overlay for the container (escape hatch). Never put secrets
    /// here — use OneCLI or the per-MCP secret files.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Hostnames routed to 127.0.0.1 inside the container (fail-closed egress).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_hosts: Vec<String>,
    /// Docker `--memory` value, e.g. `"4g"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// Docker `--cpus` value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<f64>,
    /// Docker `--pids-limit` value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<u32>,
    /// Docker `--network` value. Defaults to the runtime default bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

// ---------------------------------------------------------------------------
// Groups / lanes
// ---------------------------------------------------------------------------

/// A chat (JID) Talon answers in, bound to a group folder on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredGroup {
    pub name: String,
    pub folder: String,
    pub trigger: String,
    #[serde(rename = "added_at")]
    pub added_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_config: Option<ContainerConfig>,
    /// Default: true for groups, false for solo chats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_trigger: Option<bool>,
    /// The main control group: no trigger needed, elevated privileges.
    #[serde(default)]
    pub is_main: bool,
    /// Key the lane's session id is stored under. Defaults to `folder`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    /// IPC namespace for the lane's container. Defaults to `folder`. MUST be
    /// unique per concurrently running container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipc_key: Option<String>,
    /// Never resume or persist a session (one-shot investigations).
    #[serde(default)]
    pub ephemeral_session: bool,
    /// The channel authenticates its own callers, so session commands are
    /// allowed without `is_main` / `is_from_me`.
    #[serde(default)]
    pub trusted_session_commands: bool,
}

impl RegisteredGroup {
    /// Session storage key for this lane.
    pub fn session_key(&self) -> &str {
        self.session_key.as_deref().unwrap_or(&self.folder)
    }

    /// IPC namespace for this lane.
    pub fn ipc_key(&self) -> &str {
        self.ipc_key.as_deref().unwrap_or(&self.folder)
    }

    pub fn should_persist_session(&self) -> bool {
        !self.ephemeral_session
    }

    /// Whether non-main messages need the trigger word.
    pub fn needs_trigger(&self) -> bool {
        !self.is_main && self.requires_trigger != Some(false)
    }
}

// ---------------------------------------------------------------------------
// Messages / chats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewMessage {
    pub id: String,
    pub chat_jid: String,
    pub sender: String,
    pub sender_name: String,
    pub content: String,
    /// ISO-8601 timestamp (see [`crate::time::now_iso`]).
    pub timestamp: String,
    #[serde(default)]
    pub is_from_me: bool,
    #[serde(default)]
    pub is_bot_message: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_sender_name: Option<String>,
}

/// Chat metadata discovered by a channel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMetadata {
    pub chat_jid: String,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_group: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatInfo {
    pub jid: String,
    pub name: String,
    pub last_message_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default)]
    pub is_group: bool,
}

/// A group the agent may see in `available_groups.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableGroup {
    pub jid: String,
    pub name: String,
    pub last_activity: String,
    pub is_registered: bool,
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRow {
    /// Session key (historically the group folder).
    pub group_folder: String,
    pub session_id: String,
    pub provider: Option<String>,
    pub input_tokens: Option<i64>,
    pub updated_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Scheduled tasks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleType {
    Cron,
    Interval,
    Once,
}

impl ScheduleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScheduleType::Cron => "cron",
            ScheduleType::Interval => "interval",
            ScheduleType::Once => "once",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cron" => Some(Self::Cron),
            "interval" => Some(Self::Interval),
            "once" => Some(Self::Once),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextMode {
    /// Runs with the group's chat history and memory.
    Group,
    /// Fresh session; the prompt must carry all context.
    #[default]
    Isolated,
}

impl ContextMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContextMode::Group => "group",
            ContextMode::Isolated => "isolated",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "group" => Some(Self::Group),
            "isolated" => Some(Self::Isolated),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    #[default]
    Active,
    Paused,
    Completed,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Active => "active",
            TaskStatus::Paused => "paused",
            TaskStatus::Completed => "completed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub id: String,
    pub group_folder: String,
    pub chat_jid: String,
    pub prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    pub schedule_type: ScheduleType,
    pub schedule_value: String,
    #[serde(default)]
    pub context_mode: ContextMode,
    pub next_run: Option<String>,
    pub last_run: Option<String>,
    pub last_result: Option<String>,
    pub status: TaskStatus,
    pub created_at: String,
}

/// Partial update for a scheduled task. `None` = leave unchanged.
/// For `script`, `Some(None)` clears it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskUpdate {
    pub prompt: Option<String>,
    pub script: Option<Option<String>>,
    pub schedule_type: Option<ScheduleType>,
    pub schedule_value: Option<String>,
    pub context_mode: Option<ContextMode>,
    pub next_run: Option<Option<String>>,
    pub status: Option<TaskStatus>,
}

impl TaskUpdate {
    pub fn is_empty(&self) -> bool {
        self == &TaskUpdate::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskRunStatus {
    Success,
    Error,
}

impl TaskRunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskRunStatus::Success => "success",
            TaskRunStatus::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRunLog {
    pub task_id: String,
    pub run_at: String,
    pub duration_ms: i64,
    pub status: TaskRunStatus,
    pub result: Option<String>,
    pub error: Option<String>,
}

/// Entry in the `current_tasks.json` snapshot handed to a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSnapshot {
    pub id: String,
    #[serde(rename = "groupFolder")]
    pub group_folder: String,
    pub prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    pub schedule_type: ScheduleType,
    pub schedule_value: String,
    pub status: TaskStatus,
    pub next_run: Option<String>,
}

impl From<&ScheduledTask> for TaskSnapshot {
    fn from(t: &ScheduledTask) -> Self {
        Self {
            id: t.id.clone(),
            group_folder: t.group_folder.clone(),
            prompt: t.prompt.clone(),
            script: t.script.clone(),
            schedule_type: t.schedule_type,
            schedule_value: t.schedule_value.clone(),
            status: t.status,
            next_run: t.next_run.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit trail (new in the Rust rewrite)
// ---------------------------------------------------------------------------

/// Security-relevant event recorded in the append-only audit log
/// (`audit_log` table). Every privileged decision (IPC authorization, mount
/// validation, blocked prompt injection, container launch, tool call) should
/// leave one of these behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// Dotted category, e.g. `ipc.task.denied`, `container.launch`,
    /// `mount.rejected`, `injection.detected`, `http.auth.failed`.
    pub kind: String,
    /// Who/what caused it (group folder, channel name, remote addr, ...).
    pub actor: String,
    /// Target object (task id, jid, path, ...), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `allowed` | `denied` | `info` | `error`.
    pub outcome: String,
    /// Free-form JSON details. Must already be redacted.
    #[serde(default)]
    pub details: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_provider_values_are_tolerated() {
        let cfg: ContainerConfig = serde_json::from_str(
            r#"{"provider":"ollama","ollama":{"baseUrl":"http://x","model":"m"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.provider, Some(ProviderKind::Unsupported));
        assert!(cfg.vllm.is_none());
    }

    #[test]
    fn registered_group_json_is_ts_compatible() {
        let g: RegisteredGroup = serde_json::from_str(
            r#"{"name":"Main","folder":"main","trigger":"@Andy","added_at":"2024-01-01T00:00:00.000Z","isMain":true,"requiresTrigger":false}"#,
        )
        .unwrap();
        assert!(g.is_main);
        assert_eq!(g.session_key(), "main");
        assert!(!g.needs_trigger());
        let back = serde_json::to_value(&g).unwrap();
        assert_eq!(back["added_at"], "2024-01-01T00:00:00.000Z");
        assert_eq!(back["isMain"], true);
    }

    #[test]
    fn mount_defaults_to_readonly() {
        let m: AdditionalMount = serde_json::from_str(r#"{"hostPath":"/srv/x"}"#).unwrap();
        assert!(m.readonly);
    }

    #[test]
    fn task_snapshot_field_names() {
        let s = TaskSnapshot {
            id: "t".into(),
            group_folder: "g".into(),
            prompt: "p".into(),
            script: None,
            schedule_type: ScheduleType::Cron,
            schedule_value: "* * * * *".into(),
            status: TaskStatus::Active,
            next_run: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["groupFolder"], "g");
        assert_eq!(v["schedule_type"], "cron");
    }
}
