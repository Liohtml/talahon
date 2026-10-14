//! IPC tools — Rust port of `container/agent-runner/src/ipc-mcp-stdio.ts`.
//!
//! Same tool names, descriptions and parameters as the TypeScript MCP server
//! (`send_message`, `schedule_task`, `list_tasks`, `pause_task`,
//! `resume_task`, `cancel_task`, `update_task`, `register_group`). Requests
//! are written as [`talon_core::protocol::IpcOutbound`] /
//! [`talon_core::protocol::IpcTask`] JSON files, atomically
//! (`<name>.json.tmp` + rename), under `ToolContext.ipc_dir`
//! (`messages/` and `tasks/`). The host authorizes every request by the
//! directory it was found in, so these tools only pre-validate for good error
//! messages: they are not a security boundary.
//!
//! Differences from the TypeScript version (hardening):
//! - schedules are validated with [`talon_core::schedule::validate`] (same
//!   rules the host applies, incl. the 10 s minimum interval and `once`
//!   timestamps that must exist in the configured timezone);
//! - `update_task` validates a new `schedule_value` against the task's real
//!   schedule type (looked up in `current_tasks.json`) instead of assuming
//!   cron, and requires `schedule_value` when `schedule_type` changes;
//! - empty texts/prompts/ids and invalid group folders are rejected early.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono_tz::Tz;
use serde::Serialize;
use serde_json::{Value, json};
use talon_core::paths::is_valid_group_folder;
use talon_core::protocol::{IpcOutbound, IpcTask, container_paths, ipc_file_name};
use talon_core::schedule::{MIN_INTERVAL_MS, validate};
use talon_core::time::now_iso;
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};
use talon_core::types::{ContextMode, ScheduleType};

use crate::args::Args;
use crate::atomic::write_ipc_file;

/// Tool name: send a chat message now.
pub const SEND_MESSAGE: &str = "send_message";
/// Tool name: schedule a task.
pub const SCHEDULE_TASK: &str = "schedule_task";
/// Tool name: list scheduled tasks.
pub const LIST_TASKS: &str = "list_tasks";
/// Tool name: pause a task.
pub const PAUSE_TASK: &str = "pause_task";
/// Tool name: resume a task.
pub const RESUME_TASK: &str = "resume_task";
/// Tool name: cancel a task.
pub const CANCEL_TASK: &str = "cancel_task";
/// Tool name: update a task.
pub const UPDATE_TASK: &str = "update_task";
/// Tool name: register a group (main only).
pub const REGISTER_GROUP: &str = "register_group";

/// Largest message text accepted by `send_message`.
const MAX_TEXT_BYTES: usize = 100_000;
/// Largest task prompt / script accepted.
const MAX_PROMPT_BYTES: usize = 100_000;
/// Largest `current_tasks.json` read by `list_tasks`.
const MAX_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;
/// Longest accepted task id / jid / name.
const MAX_ID_LEN: usize = 256;

/// Settings shared by the IPC tools.
#[derive(Debug, Clone)]
pub struct IpcOptions {
    /// Timezone used to validate `once` schedules (the host's `TZ`).
    pub timezone: Tz,
}

impl Default for IpcOptions {
    fn default() -> Self {
        Self {
            timezone: chrono_tz::UTC,
        }
    }
}

fn messages_dir(ctx: &ToolContext) -> PathBuf {
    ctx.ipc_dir.join("messages")
}

fn tasks_dir(ctx: &ToolContext) -> PathBuf {
    ctx.ipc_dir.join("tasks")
}

fn current_tasks_file(ctx: &ToolContext) -> PathBuf {
    ctx.ipc_dir.join("current_tasks.json")
}

async fn write_request<T: Serialize>(dir: PathBuf, value: &T) -> Result<String, String> {
    let data = serde_json::to_vec_pretty(value)
        .map_err(|e| format!("failed to encode IPC request: {e}"))?;
    tokio::task::spawn_blocking(move || write_ipc_file(&dir, &data))
        .await
        .map_err(|e| format!("IPC write task failed: {e}"))?
        .map_err(|e| format!("failed to write IPC request: {e}"))
}

fn parse(args: Value) -> Result<Args, ToolOutput> {
    Args::parse(args).map_err(ToolOutput::err)
}

fn require_id(args: &Args, key: &str) -> Result<String, String> {
    let v = args.str(key)?;
    let v = v.trim().to_string();
    if v.is_empty() {
        return Err(format!("`{key}` must not be empty"));
    }
    if v.len() > MAX_ID_LEN || v.chars().any(char::is_control) {
        return Err(format!("`{key}` is not a valid identifier"));
    }
    Ok(v)
}

fn parse_schedule_type(raw: &str) -> Result<ScheduleType, String> {
    ScheduleType::parse(raw.trim()).ok_or_else(|| {
        format!("Invalid schedule_type: \"{raw}\". Use \"cron\", \"interval\" or \"once\".")
    })
}

/// `...Z`, `...z` or a `+HH:MM` / `-HH:MM` suffix (the TS regexes).
fn has_tz_suffix(v: &str) -> bool {
    if v.ends_with('Z') || v.ends_with('z') {
        return true;
    }
    let b = v.as_bytes();
    b.len() >= 6 && {
        let s = &b[b.len() - 6..];
        matches!(s[0], b'+' | b'-')
            && s[1].is_ascii_digit()
            && s[2].is_ascii_digit()
            && s[3] == b':'
            && s[4].is_ascii_digit()
            && s[5].is_ascii_digit()
    }
}

/// Validate a schedule with the TS error messages.
fn validate_schedule(st: ScheduleType, value: &str, tz: Tz) -> Result<(), String> {
    match st {
        ScheduleType::Cron => validate(st, value, tz).map_err(|_| {
            format!(
                "Invalid cron: \"{value}\". Use format like \"0 9 * * *\" (daily 9am) or \"*/5 * * * *\" (every 5 min)."
            )
        }),
        ScheduleType::Interval => validate(st, value, tz).map_err(|_| {
            format!(
                "Invalid interval: \"{value}\". Must be positive milliseconds, at least {MIN_INTERVAL_MS} (e.g., \"300000\" for 5 min)."
            )
        }),
        ScheduleType::Once => {
            if has_tz_suffix(value.trim()) {
                return Err(format!(
                    "Timestamp must be local time without timezone suffix. Got \"{value}\" — use format like \"2026-02-01T15:30:00\"."
                ));
            }
            validate(st, value, tz).map_err(|_| {
                format!(
                    "Invalid timestamp: \"{value}\". Use local time format like \"2026-02-01T15:30:00\"."
                )
            })
        }
    }
}

fn new_task_id() -> String {
    // `<millis>-<random6>.json` -> `task-<millis>-<random6>` (TS shape).
    let name = ipc_file_name();
    format!("task-{}", name.trim_end_matches(".json"))
}

fn read_snapshot(path: &Path) -> Result<Option<Vec<Value>>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if meta.len() > MAX_SNAPSHOT_BYTES {
        return Err(format!("{} is too large", path.display()));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    match serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string())? {
        Value::Array(a) => Ok(Some(a)),
        _ => Err("current_tasks.json is not a JSON array".to_string()),
    }
}

fn str_field<'a>(t: &'a Value, key: &str) -> &'a str {
    t.get(key).and_then(Value::as_str).unwrap_or("")
}

// ---------------------------------------------------------------------------
// send_message
// ---------------------------------------------------------------------------

/// `send_message`: deliver a chat message immediately.
#[derive(Debug, Clone, Default)]
pub struct SendMessageTool;

#[async_trait]
impl Tool for SendMessageTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: SEND_MESSAGE.to_string(),
            description: "Send a message to the user or group immediately while you're still running. Use this for progress updates or to send multiple messages. You can call this multiple times.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "The message text to send"},
                    "sender": {"type": "string", "description": "Your role/identity name (e.g. \"Researcher\"). When set, messages appear from a dedicated bot in Telegram."}
                },
                "required": ["text"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> ToolOutput {
        let args = match parse(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let text = match args.str("text") {
            Ok(t) => t,
            Err(e) => return ToolOutput::err(e),
        };
        if text.trim().is_empty() {
            return ToolOutput::err("`text` must not be empty");
        }
        if text.len() > MAX_TEXT_BYTES {
            return ToolOutput::err(format!(
                "`text` is longer than {MAX_TEXT_BYTES} bytes; split it into several messages"
            ));
        }
        let sender = match args.opt_str("sender") {
            Ok(s) => s
                .map(|s| s.trim().chars().take(64).collect::<String>())
                .filter(|s| !s.is_empty()),
            Err(e) => return ToolOutput::err(e),
        };
        let msg = IpcOutbound::Message {
            chat_jid: ctx.chat_jid.clone(),
            text,
            group_folder: Some(ctx.group_folder.clone()),
            timestamp: Some(now_iso()),
        };
        let mut value = match serde_json::to_value(&msg) {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(format!("failed to encode message: {e}")),
        };
        // `sender` is not part of the frozen IpcOutbound shape; it is carried
        // as an extra field (ignored by hosts that don't know it), as in TS.
        if let (Some(s), Some(obj)) = (sender, value.as_object_mut()) {
            obj.insert("sender".to_string(), Value::String(s));
        }
        match write_request(messages_dir(ctx), &value).await {
            Ok(_) => ToolOutput::ok("Message sent."),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// schedule_task
// ---------------------------------------------------------------------------

/// `schedule_task`: create a cron/interval/once task.
#[derive(Debug, Clone, Default)]
pub struct ScheduleTaskTool {
    opts: IpcOptions,
}

impl ScheduleTaskTool {
    /// New tool.
    pub fn new(opts: IpcOptions) -> Self {
        Self { opts }
    }
}

const SCHEDULE_TASK_DESCRIPTION: &str = "Schedule a recurring or one-time task. The task will run as a full agent with access to all tools. Returns the task ID for future reference. To modify an existing task, use update_task instead.

CONTEXT MODE - Choose based on task type:
\u{2022} \"group\": Task runs in the group's conversation context, with access to chat history. Use for tasks that need context about ongoing discussions, user preferences, or recent interactions.
\u{2022} \"isolated\": Task runs in a fresh session with no conversation history. Use for independent tasks that don't need prior context. When using isolated mode, include all necessary context in the prompt itself.

If unsure which mode to use, you can ask the user. Examples:
- \"Remind me about our discussion\" \u{2192} group (needs conversation context)
- \"Check the weather every morning\" \u{2192} isolated (self-contained task)
- \"Follow up on my request\" \u{2192} group (needs to know what was requested)
- \"Generate a daily report\" \u{2192} isolated (just needs instructions in prompt)

MESSAGING BEHAVIOR - The task agent's output is sent to the user or group. It can also use send_message for immediate delivery, or wrap output in <internal> tags to suppress it. Include guidance in the prompt about whether the agent should:
\u{2022} Always send a message (e.g., reminders, daily briefings)
\u{2022} Only send a message when there's something to report (e.g., \"notify me if...\")
\u{2022} Never send a message (background maintenance tasks)

SCHEDULE VALUE FORMAT (all times are LOCAL timezone):
\u{2022} cron: Standard cron expression (e.g., \"*/5 * * * *\" for every 5 minutes, \"0 9 * * *\" for daily at 9am LOCAL time)
\u{2022} interval: Milliseconds between runs (e.g., \"300000\" for 5 minutes, \"3600000\" for 1 hour)
\u{2022} once: Local time WITHOUT \"Z\" suffix (e.g., \"2026-02-01T15:30:00\"). Do NOT use UTC/Z suffix.";

#[async_trait]
impl Tool for ScheduleTaskTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: SCHEDULE_TASK.to_string(),
            description: SCHEDULE_TASK_DESCRIPTION.to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "description": "What the agent should do when the task runs. For isolated mode, include all necessary context here."},
                    "schedule_type": {"type": "string", "enum": ["cron", "interval", "once"], "description": "cron=recurring at specific times, interval=recurring every N ms, once=run once at specific time"},
                    "schedule_value": {"type": "string", "description": "cron: \"*/5 * * * *\" | interval: milliseconds like \"300000\" | once: local timestamp like \"2026-02-01T15:30:00\" (no Z suffix!)"},
                    "context_mode": {"type": "string", "enum": ["group", "isolated"], "default": "group", "description": "group=runs with chat history and memory, isolated=fresh session (include context in prompt)"},
                    "target_group_jid": {"type": "string", "description": "(Main group only) JID of the group to schedule the task for. Defaults to the current group."},
                    "script": {"type": "string", "description": "Optional bash script to run before waking the agent. Script must output JSON on the last line of stdout: { \"wakeAgent\": boolean, \"data\"?: any }. If wakeAgent is false, the agent is not called. Test your script with bash -c \"...\" before scheduling."}
                },
                "required": ["prompt", "schedule_type", "schedule_value"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> ToolOutput {
        let args = match parse(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let parsed = (|| -> Result<_, String> {
            let prompt = args.str("prompt")?;
            if prompt.trim().is_empty() {
                return Err("`prompt` must not be empty".to_string());
            }
            if prompt.len() > MAX_PROMPT_BYTES {
                return Err(format!("`prompt` is longer than {MAX_PROMPT_BYTES} bytes"));
            }
            let schedule_type = parse_schedule_type(&args.str("schedule_type")?)?;
            let schedule_value = args.str("schedule_value")?.trim().to_string();
            let context_mode = match args.opt_str("context_mode")? {
                None => ContextMode::Group,
                Some(m) if m.trim().is_empty() => ContextMode::Group,
                Some(m) => ContextMode::parse(m.trim()).ok_or_else(|| {
                    format!("Invalid context_mode: \"{m}\". Use \"group\" or \"isolated\".")
                })?,
            };
            let target = args
                .opt_str("target_group_jid")?
                .map(|t| t.trim().to_string());
            let script = args.opt_str("script")?.filter(|s| !s.is_empty());
            if script.as_ref().is_some_and(|s| s.len() > MAX_PROMPT_BYTES) {
                return Err(format!("`script` is longer than {MAX_PROMPT_BYTES} bytes"));
            }
            Ok((
                prompt,
                schedule_type,
                schedule_value,
                context_mode,
                target,
                script,
            ))
        })();
        let (prompt, schedule_type, schedule_value, context_mode, target, script) = match parsed {
            Ok(p) => p,
            Err(e) => return ToolOutput::err(e),
        };
        if let Err(e) = validate_schedule(schedule_type, &schedule_value, self.opts.timezone) {
            return ToolOutput::err(e);
        }

        // Non-main groups can only schedule for themselves.
        let mut note = String::new();
        let target_jid = match target.filter(|t| !t.is_empty()) {
            Some(t) if ctx.is_main => t,
            Some(t) => {
                if t != ctx.chat_jid {
                    note = " (target_group_jid ignored: only the main group can schedule tasks for other groups)".to_string();
                }
                ctx.chat_jid.clone()
            }
            None => ctx.chat_jid.clone(),
        };
        let task_id = new_task_id();
        let task = IpcTask::ScheduleTask {
            task_id: Some(task_id.clone()),
            prompt,
            script,
            schedule_type,
            schedule_value: schedule_value.clone(),
            context_mode: Some(context_mode),
            target_jid,
            created_by: Some(ctx.group_folder.clone()),
            timestamp: Some(now_iso()),
        };
        match write_request(tasks_dir(ctx), &task).await {
            Ok(_) => ToolOutput::ok(format!(
                "Task {task_id} scheduled: {} - {schedule_value}{note}",
                schedule_type.as_str()
            )),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// list_tasks
// ---------------------------------------------------------------------------

/// `list_tasks`: read the host-written `current_tasks.json` snapshot.
#[derive(Debug, Clone, Default)]
pub struct ListTasksTool;

fn format_tasks(all: Vec<Value>, ctx: &ToolContext) -> String {
    let tasks: Vec<&Value> = all
        .iter()
        .filter(|t| ctx.is_main || str_field(t, "groupFolder") == ctx.group_folder)
        .collect();
    if tasks.is_empty() {
        return "No scheduled tasks found.".to_string();
    }
    let lines: Vec<String> = tasks
        .iter()
        .map(|t| {
            let prompt: String = str_field(t, "prompt").chars().take(50).collect();
            let next = match str_field(t, "next_run") {
                "" => "N/A",
                n => n,
            };
            format!(
                "- [{}] {prompt}... ({}: {}) - {}, next: {next}",
                str_field(t, "id"),
                str_field(t, "schedule_type"),
                str_field(t, "schedule_value"),
                str_field(t, "status"),
            )
        })
        .collect();
    format!("Scheduled tasks:\n{}", lines.join("\n"))
}

#[async_trait]
impl Tool for ListTasksTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: LIST_TASKS.to_string(),
            description: "List all scheduled tasks. From main: shows all tasks. From other groups: shows only that group's tasks.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, _args: Value, ctx: &ToolContext) -> ToolOutput {
        let path = current_tasks_file(ctx);
        let read = tokio::task::spawn_blocking(move || read_snapshot(&path)).await;
        match read {
            Ok(Ok(None)) => ToolOutput::ok("No scheduled tasks found."),
            Ok(Ok(Some(all))) => ToolOutput::ok(format_tasks(all, ctx)),
            Ok(Err(e)) => ToolOutput::err(format!("Error reading tasks: {e}")),
            Err(e) => ToolOutput::err(format!("Error reading tasks: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// pause_task / resume_task / cancel_task
// ---------------------------------------------------------------------------

/// Which task-control operation a [`TaskControlTool`] performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskControl {
    /// `pause_task`
    Pause,
    /// `resume_task`
    Resume,
    /// `cancel_task`
    Cancel,
}

/// `pause_task`, `resume_task` and `cancel_task`.
#[derive(Debug, Clone)]
pub struct TaskControlTool {
    kind: TaskControl,
}

impl TaskControlTool {
    /// Tool for the given operation.
    pub fn new(kind: TaskControl) -> Self {
        Self { kind }
    }
}

#[async_trait]
impl Tool for TaskControlTool {
    fn spec(&self) -> ToolSpec {
        let (name, description, param) = match self.kind {
            TaskControl::Pause => (
                PAUSE_TASK,
                "Pause a scheduled task. It will not run until resumed.",
                "The task ID to pause",
            ),
            TaskControl::Resume => (
                RESUME_TASK,
                "Resume a paused task.",
                "The task ID to resume",
            ),
            TaskControl::Cancel => (
                CANCEL_TASK,
                "Cancel and delete a scheduled task.",
                "The task ID to cancel",
            ),
        };
        ToolSpec {
            name: name.to_string(),
            description: description.to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": param}
                },
                "required": ["task_id"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> ToolOutput {
        let args = match parse(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let task_id = match require_id(&args, "task_id") {
            Ok(t) => t,
            Err(e) => return ToolOutput::err(e),
        };
        let timestamp = Some(now_iso());
        let (task, verb) = match self.kind {
            TaskControl::Pause => (
                IpcTask::PauseTask {
                    task_id: task_id.clone(),
                    timestamp,
                },
                "pause requested",
            ),
            TaskControl::Resume => (
                IpcTask::ResumeTask {
                    task_id: task_id.clone(),
                    timestamp,
                },
                "resume requested",
            ),
            TaskControl::Cancel => (
                IpcTask::CancelTask {
                    task_id: task_id.clone(),
                    timestamp,
                },
                "cancellation requested",
            ),
        };
        match write_request(tasks_dir(ctx), &task).await {
            Ok(_) => ToolOutput::ok(format!("Task {task_id} {verb}.")),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// update_task
// ---------------------------------------------------------------------------

/// `update_task`: change prompt, schedule or script of a task.
#[derive(Debug, Clone, Default)]
pub struct UpdateTaskTool {
    opts: IpcOptions,
}

impl UpdateTaskTool {
    /// New tool.
    pub fn new(opts: IpcOptions) -> Self {
        Self { opts }
    }
}

/// Schedule type of `task_id` according to the snapshot, if known.
fn snapshot_schedule_type(snapshot: &Path, task_id: &str) -> Option<ScheduleType> {
    let tasks = read_snapshot(snapshot).ok().flatten()?;
    tasks
        .iter()
        .find(|t| str_field(t, "id") == task_id)
        .and_then(|t| ScheduleType::parse(str_field(t, "schedule_type")))
}

#[async_trait]
impl Tool for UpdateTaskTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: UPDATE_TASK.to_string(),
            description: "Update an existing scheduled task. Only provided fields are changed; omitted fields stay the same.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "The task ID to update"},
                    "prompt": {"type": "string", "description": "New prompt for the task"},
                    "schedule_type": {"type": "string", "enum": ["cron", "interval", "once"], "description": "New schedule type"},
                    "schedule_value": {"type": "string", "description": "New schedule value (see schedule_task for format)"},
                    "script": {"type": "string", "description": "New script for the task. Set to empty string to remove the script."}
                },
                "required": ["task_id"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> ToolOutput {
        let args = match parse(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let parsed = (|| -> Result<_, String> {
            let task_id = require_id(&args, "task_id")?;
            let prompt = args.opt_str("prompt")?;
            if prompt.as_ref().is_some_and(|p| p.trim().is_empty()) {
                return Err("`prompt` must not be empty when given".to_string());
            }
            if prompt.as_ref().is_some_and(|p| p.len() > MAX_PROMPT_BYTES) {
                return Err(format!("`prompt` is longer than {MAX_PROMPT_BYTES} bytes"));
            }
            let schedule_type = match args.opt_str("schedule_type")? {
                Some(s) => Some(parse_schedule_type(&s)?),
                None => None,
            };
            let schedule_value = args
                .opt_str("schedule_value")?
                .map(|v| v.trim().to_string());
            let script = args.opt_str("script")?;
            if script.as_ref().is_some_and(|s| s.len() > MAX_PROMPT_BYTES) {
                return Err(format!("`script` is longer than {MAX_PROMPT_BYTES} bytes"));
            }
            Ok((task_id, prompt, schedule_type, schedule_value, script))
        })();
        let (task_id, prompt, schedule_type, schedule_value, script) = match parsed {
            Ok(p) => p,
            Err(e) => return ToolOutput::err(e),
        };
        if prompt.is_none()
            && schedule_type.is_none()
            && schedule_value.is_none()
            && script.is_none()
        {
            return ToolOutput::err(
                "Nothing to update: provide at least one of prompt, schedule_type, schedule_value or script.",
            );
        }
        if schedule_type.is_some() && schedule_value.is_none() {
            return ToolOutput::err(
                "schedule_value is required when changing schedule_type (see schedule_task for formats).",
            );
        }
        if let Some(value) = &schedule_value {
            let effective = match schedule_type {
                Some(t) => t,
                None => {
                    let snapshot = current_tasks_file(ctx);
                    let id = task_id.clone();
                    tokio::task::spawn_blocking(move || snapshot_schedule_type(&snapshot, &id))
                        .await
                        .ok()
                        .flatten()
                        // Unknown task: the TypeScript tool assumed cron.
                        .unwrap_or(ScheduleType::Cron)
                }
            };
            if let Err(e) = validate_schedule(effective, value, self.opts.timezone) {
                return ToolOutput::err(e);
            }
        }
        let task = IpcTask::UpdateTask {
            task_id: task_id.clone(),
            prompt,
            script,
            schedule_type,
            schedule_value,
            timestamp: Some(now_iso()),
        };
        match write_request(tasks_dir(ctx), &task).await {
            Ok(_) => ToolOutput::ok(format!("Task {task_id} update requested.")),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// register_group
// ---------------------------------------------------------------------------

/// `register_group`: main group only.
#[derive(Debug, Clone, Default)]
pub struct RegisterGroupTool;

#[async_trait]
impl Tool for RegisterGroupTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: REGISTER_GROUP.to_string(),
            description: "Register a new chat/group so the agent can respond to messages there. Main group only.

Use available_groups.json to find the JID for a group. The folder name must be channel-prefixed: \"{channel}_{group-name}\" (e.g., \"whatsapp_family-chat\", \"telegram_dev-team\", \"discord_general\"). Use lowercase with hyphens for the group name part.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "jid": {"type": "string", "description": "The chat JID (e.g., \"120363336345536173@g.us\", \"tg:-1001234567890\", \"dc:1234567890123456\")"},
                    "name": {"type": "string", "description": "Display name for the group"},
                    "folder": {"type": "string", "description": "Channel-prefixed folder name (e.g., \"whatsapp_family-chat\", \"telegram_dev-team\")"},
                    "trigger": {"type": "string", "description": "Trigger word (e.g., \"@Andy\")"},
                    "requiresTrigger": {"type": "boolean", "description": "Whether messages must start with the trigger word. Default: false (respond to all messages). Set to true for busy groups with many participants where you only want the agent to respond when explicitly mentioned."}
                },
                "required": ["jid", "name", "folder", "trigger"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> ToolOutput {
        if !ctx.is_main {
            return ToolOutput::err("Only the main group can register new groups.");
        }
        let args = match parse(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let parsed = (|| -> Result<_, String> {
            let jid = require_id(&args, "jid")?;
            let name = require_id(&args, "name")?;
            let folder = args.str("folder")?.trim().to_string();
            if !is_valid_group_folder(&folder) {
                return Err(format!(
                    "Invalid folder \"{folder}\": use letters, digits, '_' and '-' only (max 64 chars, \
                     e.g. \"telegram_dev-team\"); \"global\" and \"errors\" are reserved."
                ));
            }
            let trigger = require_id(&args, "trigger")?;
            let requires_trigger = args.opt_bool("requiresTrigger")?.unwrap_or(false);
            Ok((jid, name, folder, trigger, requires_trigger))
        })();
        let (jid, name, folder, trigger, requires_trigger) = match parsed {
            Ok(p) => p,
            Err(e) => return ToolOutput::err(e),
        };
        let task = IpcTask::RegisterGroup {
            jid,
            name: name.clone(),
            folder,
            trigger,
            requires_trigger: Some(requires_trigger),
            container_config: None,
            timestamp: Some(now_iso()),
        };
        match write_request(tasks_dir(ctx), &task).await {
            Ok(_) => ToolOutput::ok(format!(
                "Group \"{name}\" registered. It will start receiving messages immediately."
            )),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// The default IPC directory inside the container (`/workspace/ipc`).
pub fn default_ipc_dir() -> PathBuf {
    PathBuf::from(container_paths::IPC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ctx_for;

    fn files_in(dir: &Path) -> Vec<Value> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default();
        names.sort();
        for n in &names {
            let s = n.to_string_lossy();
            assert!(s.ends_with(".json"), "unexpected file {s}");
        }
        names
            .iter()
            .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn send_message_writes_outbound_file() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let out = SendMessageTool
            .call(json!({"text": "hello", "sender": "Researcher"}), &ctx)
            .await;
        assert_eq!(out, ToolOutput::ok("Message sent."));
        let files = files_in(&ctx.ipc_dir.join("messages"));
        assert_eq!(files.len(), 1);
        let v = &files[0];
        assert_eq!(v["type"], "message");
        assert_eq!(v["chatJid"], "tg:42");
        assert_eq!(v["text"], "hello");
        assert_eq!(v["groupFolder"], "testgroup");
        assert_eq!(v["sender"], "Researcher");
        assert!(v["timestamp"].as_str().unwrap().ends_with('Z'));
        // Parses as the frozen protocol type.
        let parsed: IpcOutbound = serde_json::from_value(v.clone()).unwrap();
        let IpcOutbound::Message { text, .. } = parsed;
        assert_eq!(text, "hello");

        assert!(
            SendMessageTool
                .call(json!({"text": " "}), &ctx)
                .await
                .is_error
        );
        assert!(SendMessageTool.call(json!({}), &ctx).await.is_error);
    }

    #[tokio::test]
    async fn schedule_task_valid_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let t = ScheduleTaskTool::default();
        let out = t
            .call(
                json!({"prompt": "daily digest", "schedule_type": "cron", "schedule_value": "0 9 * * *", "script": ""}),
                &ctx,
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.starts_with("Task task-"));
        assert!(out.content.ends_with("scheduled: cron - 0 9 * * *"));
        let files = files_in(&ctx.ipc_dir.join("tasks"));
        assert_eq!(files.len(), 1);
        let v = &files[0];
        assert_eq!(v["type"], "schedule_task");
        assert_eq!(v["context_mode"], "group");
        assert_eq!(v["targetJid"], "tg:42");
        assert_eq!(v["createdBy"], "testgroup");
        assert!(v.get("script").is_none());
        let id = v["taskId"].as_str().unwrap();
        assert!(out.content.contains(id));
        let parsed: IpcTask = serde_json::from_value(v.clone()).unwrap();
        assert!(matches!(parsed, IpcTask::ScheduleTask { .. }));
    }

    #[tokio::test]
    async fn schedule_task_validation_messages() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let t = ScheduleTaskTool::default();
        let call = |st: &str, sv: &str| {
            let t = t.clone();
            let ctx = ctx.clone();
            let args = json!({"prompt": "p", "schedule_type": st, "schedule_value": sv});
            async move { t.call(args, &ctx).await }
        };
        let out = call("cron", "not a cron").await;
        assert!(out.is_error);
        assert!(out.content.starts_with("Invalid cron: \"not a cron\""));
        let out = call("interval", "abc").await;
        assert!(out.content.starts_with("Invalid interval: \"abc\""));
        let out = call("interval", "-5").await;
        assert!(out.is_error);
        let out = call("interval", "500").await;
        assert!(out.is_error, "below the 10s minimum");
        let out = call("once", "2026-02-01T15:30:00Z").await;
        assert!(out.content.starts_with("Timestamp must be local time"));
        let out = call("once", "2026-02-01T15:30:00+02:00").await;
        assert!(out.content.starts_with("Timestamp must be local time"));
        let out = call("once", "tomorrow").await;
        assert!(out.content.starts_with("Invalid timestamp: \"tomorrow\""));
        let out = call("weekly", "x").await;
        assert!(out.content.contains("schedule_type"));
        assert!(!call("interval", "300000").await.is_error);
        assert!(!call("once", "2030-02-01T15:30:00").await.is_error);
        let out = t
            .call(
                json!({"prompt": "p", "schedule_type": "cron", "schedule_value": "* * * * *", "context_mode": "shared"}),
                &ctx,
            )
            .await;
        assert!(out.is_error && out.content.contains("context_mode"));
    }

    #[tokio::test]
    async fn schedule_task_target_only_for_main() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_for(dir.path());
        let t = ScheduleTaskTool::default();
        let args = json!({"prompt": "p", "schedule_type": "interval", "schedule_value": "60000", "target_group_jid": "tg:999", "context_mode": "isolated"});
        let out = t.call(args.clone(), &ctx).await;
        assert!(out.content.contains("target_group_jid ignored"));
        ctx.is_main = true;
        let out = t.call(args, &ctx).await;
        assert!(!out.content.contains("ignored"));
        let files = files_in(&ctx.ipc_dir.join("tasks"));
        let targets: Vec<&str> = files
            .iter()
            .map(|v| v["targetJid"].as_str().unwrap())
            .collect();
        assert!(targets.contains(&"tg:42"));
        assert!(targets.contains(&"tg:999"));
        assert!(files.iter().all(|v| v["context_mode"] == "isolated"));
    }

    #[tokio::test]
    async fn list_tasks_filters_by_group_unless_main() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_for(dir.path());
        let t = ListTasksTool;
        assert_eq!(
            t.call(json!({}), &ctx).await.content,
            "No scheduled tasks found."
        );
        std::fs::create_dir_all(&ctx.ipc_dir).unwrap();
        let snapshot = json!([
            {"id": "task-1", "groupFolder": "testgroup", "prompt": "A very long prompt that goes on and on and on beyond fifty chars", "schedule_type": "cron", "schedule_value": "0 9 * * *", "status": "active", "next_run": "2026-01-01T09:00:00.000Z"},
            {"id": "task-2", "groupFolder": "other", "prompt": "Other", "schedule_type": "once", "schedule_value": "2026-01-01T10:00:00", "status": "paused", "next_run": null}
        ]);
        std::fs::write(ctx.ipc_dir.join("current_tasks.json"), snapshot.to_string()).unwrap();
        let out = t.call(json!({}), &ctx).await;
        assert_eq!(
            out.content,
            "Scheduled tasks:\n- [task-1] A very long prompt that goes on and on and on beyo... (cron: 0 9 * * *) - active, next: 2026-01-01T09:00:00.000Z"
        );
        ctx.is_main = true;
        let out = t.call(json!({}), &ctx).await;
        assert!(
            out.content
                .contains("- [task-2] Other... (once: 2026-01-01T10:00:00) - paused, next: N/A")
        );
        std::fs::write(ctx.ipc_dir.join("current_tasks.json"), "{bad").unwrap();
        let out = t.call(json!({}), &ctx).await;
        assert!(out.is_error && out.content.starts_with("Error reading tasks"));
    }

    #[tokio::test]
    async fn task_control_tools() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let cases = [
            (
                TaskControl::Pause,
                "pause_task",
                "Task task-1 pause requested.",
            ),
            (
                TaskControl::Resume,
                "resume_task",
                "Task task-1 resume requested.",
            ),
            (
                TaskControl::Cancel,
                "cancel_task",
                "Task task-1 cancellation requested.",
            ),
        ];
        for (kind, ty, msg) in cases {
            let t = TaskControlTool::new(kind);
            assert_eq!(t.spec().name, ty);
            let out = t.call(json!({"task_id": "task-1"}), &ctx).await;
            assert_eq!(out.content, msg);
            assert!(t.call(json!({"task_id": ""}), &ctx).await.is_error);
        }
        let files = files_in(&ctx.ipc_dir.join("tasks"));
        let types: Vec<&str> = files.iter().map(|v| v["type"].as_str().unwrap()).collect();
        assert_eq!(types.len(), 3);
        for ty in ["pause_task", "resume_task", "cancel_task"] {
            assert!(types.contains(&ty));
        }
        assert!(files.iter().all(|v| v["taskId"] == "task-1"));
    }

    #[tokio::test]
    async fn update_task_validation_uses_snapshot_type() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        std::fs::create_dir_all(&ctx.ipc_dir).unwrap();
        std::fs::write(
            ctx.ipc_dir.join("current_tasks.json"),
            json!([{"id": "task-int", "groupFolder": "testgroup", "prompt": "p", "schedule_type": "interval", "schedule_value": "60000", "status": "active", "next_run": null}]).to_string(),
        )
        .unwrap();
        let t = UpdateTaskTool::default();
        // Interval value for an interval task: OK (TS would have rejected it as cron).
        let out = t
            .call(
                json!({"task_id": "task-int", "schedule_value": "120000"}),
                &ctx,
            )
            .await;
        assert_eq!(out.content, "Task task-int update requested.");
        // Unknown task -> cron assumed.
        let out = t
            .call(
                json!({"task_id": "task-x", "schedule_value": "120000"}),
                &ctx,
            )
            .await;
        assert!(out.content.starts_with("Invalid cron"));
        let out = t
            .call(
                json!({"task_id": "task-x", "schedule_type": "interval", "schedule_value": "0"}),
                &ctx,
            )
            .await;
        assert!(out.content.starts_with("Invalid interval"));
        let out = t
            .call(json!({"task_id": "task-x", "schedule_type": "cron"}), &ctx)
            .await;
        assert!(out.is_error && out.content.contains("schedule_value is required"));
        let out = t.call(json!({"task_id": "task-x"}), &ctx).await;
        assert!(out.is_error && out.content.contains("Nothing to update"));
        let out = t
            .call(
                json!({"task_id": "task-x", "script": "", "prompt": "new"}),
                &ctx,
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        let files = files_in(&ctx.ipc_dir.join("tasks"));
        let last = files.iter().find(|v| v["taskId"] == "task-x").unwrap();
        assert_eq!(last["type"], "update_task");
        assert_eq!(last["script"], "");
        assert_eq!(last["prompt"], "new");
        assert!(last.get("schedule_type").is_none());
    }

    #[tokio::test]
    async fn register_group_main_only_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_for(dir.path());
        let t = RegisterGroupTool;
        let args = json!({"jid": "tg:-100123", "name": "Dev Team", "folder": "telegram_dev-team", "trigger": "@Talon"});
        let out = t.call(args.clone(), &ctx).await;
        assert_eq!(
            out,
            ToolOutput::err("Only the main group can register new groups.")
        );
        ctx.is_main = true;
        let out = t.call(args, &ctx).await;
        assert_eq!(
            out.content,
            "Group \"Dev Team\" registered. It will start receiving messages immediately."
        );
        let files = files_in(&ctx.ipc_dir.join("tasks"));
        assert_eq!(files[0]["type"], "register_group");
        assert_eq!(files[0]["requiresTrigger"], false);
        assert_eq!(files[0]["folder"], "telegram_dev-team");
        let bad = json!({"jid": "x", "name": "n", "folder": "../etc", "trigger": "@T"});
        assert!(t.call(bad, &ctx).await.is_error);
        let bad = json!({"jid": "x", "name": "n", "folder": "global", "trigger": "@T"});
        assert!(t.call(bad, &ctx).await.is_error);
    }

    #[test]
    fn tz_suffix_detection_matches_ts() {
        assert!(has_tz_suffix("2026-01-01T00:00:00Z"));
        assert!(has_tz_suffix("2026-01-01T00:00:00-05:30"));
        assert!(!has_tz_suffix("2026-01-01T00:00:00"));
        assert!(!has_tz_suffix("2026-01-01"));
        assert!(new_task_id().starts_with("task-"));
    }
}
