//! # talon-tools — built-in agent tools
//!
//! **Owner: agent A04.** See `docs/RUST_ARCHITECTURE.md` §A04.
//!
//! Native replacements for the Claude Code built-in tools the TypeScript
//! runtime got from the Claude Agent SDK, plus a port of the `nanoclaw` IPC
//! MCP server. Every tool implements [`talon_core::tool::Tool`]:
//!
//! | tool | module | concurrency |
//! |------|--------|-------------|
//! | `bash` | [`bash`] | exclusive |
//! | `read_file`, `list_dir` | [`files`] | read-only |
//! | `write_file`, `edit_file` | [`files`] | exclusive |
//! | `glob`, `grep` | [`search`] | read-only |
//! | `web_fetch` | [`web`] | read-only |
//! | `todo_write` | [`todo`] | exclusive |
//! | `send_message`, `schedule_task`, `pause_task`, `resume_task`, `cancel_task`, `update_task`, `register_group` | [`ipc`] | exclusive |
//! | `list_tasks` | [`ipc`] | read-only |
//!
//! Security model:
//! - file tools resolve every path through the [`guard::PathGuard`]
//!   (canonicalization, `allowed_roots` / `read_only_roots`, symlink-escape
//!   refusal);
//! - `bash` runs with a scrubbed environment in its own process group that is
//!   killed on timeout, cancellation and return;
//! - `web_fetch` checks every hop with the egress policy, pins DNS, and fences
//!   the content as untrusted (§3.4);
//! - IPC tools only write request files; the host authorizes them.
//!
//! Entry point: [`builtin_tools`].

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::sync::Arc;

use talon_core::audit::SharedAuditSink;
use talon_core::tool::{Tool, ToolOutput};

mod args;
mod atomic;
pub mod bash;
pub mod files;
pub mod guard;
pub mod html;
pub mod ipc;
mod output;
pub mod search;
pub mod todo;
pub mod web;

pub use bash::{BashOptions, BashResult, BashTool, Termination};
pub use files::{EditFileTool, FileLimits, ListDirTool, ReadFileTool, WriteFileTool};
pub use guard::{Access, GuardedPath, PathGuard};
pub use ipc::{
    IpcOptions, ListTasksTool, RegisterGroupTool, ScheduleTaskTool, SendMessageTool, TaskControl,
    TaskControlTool, UpdateTaskTool,
};
pub use search::{GlobTool, GrepTool};
pub use todo::{TodoItem, TodoList, TodoStatus, TodoWriteTool};
pub use web::{EgressCheck, EgressError, FenceFn, WebFetchOptions, WebFetchTool};

/// Names of all built-in tools.
pub mod names {
    pub use crate::bash::NAME as BASH;
    pub use crate::files::{EDIT_FILE, LIST_DIR, READ_FILE, WRITE_FILE};
    pub use crate::ipc::{
        CANCEL_TASK, LIST_TASKS, PAUSE_TASK, REGISTER_GROUP, RESUME_TASK, SCHEDULE_TASK,
        SEND_MESSAGE, UPDATE_TASK,
    };
    pub use crate::search::{GLOB, GREP};
    pub use crate::todo::NAME as TODO_WRITE;
    pub use crate::web::NAME as WEB_FETCH;

    /// Every built-in tool name, in [`crate::builtin_tools`] order.
    pub const ALL: &[&str] = &[
        BASH,
        READ_FILE,
        WRITE_FILE,
        EDIT_FILE,
        LIST_DIR,
        GLOB,
        GREP,
        WEB_FETCH,
        TODO_WRITE,
        SEND_MESSAGE,
        SCHEDULE_TASK,
        LIST_TASKS,
        PAUSE_TASK,
        RESUME_TASK,
        CANCEL_TASK,
        UPDATE_TASK,
        REGISTER_GROUP,
    ];
}

/// Which built-in tools to create and how to configure them.
#[derive(Clone)]
pub struct BuiltinOptions {
    /// Timezone for validating `once` schedules (the host's `TZ`,
    /// `ContainerInput.timezone`). Default UTC.
    pub timezone: chrono_tz::Tz,
    /// `bash` settings; `None` omits the tool.
    pub bash: Option<BashOptions>,
    /// Limits for the file and search tools.
    pub files: FileLimits,
    /// `web_fetch` settings (incl. the egress policy); `None` omits the tool.
    pub web_fetch: Option<WebFetchOptions>,
    /// Include the IPC tools (`send_message`, task tools, `register_group`).
    pub ipc_tools: bool,
    /// Include `register_group` (only useful for the main group; the tool
    /// also refuses at call time when `ToolContext.is_main` is false).
    pub register_group: bool,
    /// Backing store for `todo_write`; keep a clone to observe the plan.
    pub todo_list: TodoList,
    /// Audit sink for `egress.denied` events from `web_fetch`.
    pub audit: Option<SharedAuditSink>,
}

impl std::fmt::Debug for BuiltinOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltinOptions")
            .field("timezone", &self.timezone)
            .field("bash", &self.bash)
            .field("files", &self.files)
            .field("web_fetch", &self.web_fetch)
            .field("ipc_tools", &self.ipc_tools)
            .field("register_group", &self.register_group)
            .field("audit", &self.audit.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for BuiltinOptions {
    fn default() -> Self {
        Self {
            timezone: chrono_tz::UTC,
            bash: Some(BashOptions::default()),
            files: FileLimits::default(),
            web_fetch: Some(WebFetchOptions::default()),
            ipc_tools: true,
            register_group: true,
            todo_list: TodoList::new(),
            audit: None,
        }
    }
}

impl BuiltinOptions {
    /// Defaults with the timezone set from an IANA name (falls back to UTC).
    pub fn with_timezone_name(mut self, tz: &str) -> Self {
        self.timezone = talon_core::time::parse_tz(tz);
        self
    }
}

/// Create the built-in tools selected by `opts`, in a stable order
/// (see [`names::ALL`]).
pub fn builtin_tools(opts: &BuiltinOptions) -> Vec<Arc<dyn Tool>> {
    let mut tools: Vec<Arc<dyn Tool>> = Vec::new();
    if let Some(b) = &opts.bash {
        tools.push(Arc::new(BashTool::new(b.clone())));
    }
    let limits = opts.files.clone();
    tools.push(Arc::new(ReadFileTool::new(limits.clone())));
    tools.push(Arc::new(WriteFileTool::new(limits.clone())));
    tools.push(Arc::new(EditFileTool::new(limits.clone())));
    tools.push(Arc::new(ListDirTool::new(limits.clone())));
    tools.push(Arc::new(GlobTool::new(limits.clone())));
    tools.push(Arc::new(GrepTool::new(limits)));
    if let Some(w) = &opts.web_fetch {
        let mut tool = WebFetchTool::new(w.clone());
        if let Some(a) = &opts.audit {
            tool = tool.with_audit(a.clone());
        }
        tools.push(Arc::new(tool));
    }
    tools.push(Arc::new(TodoWriteTool::new(opts.todo_list.clone())));
    if opts.ipc_tools {
        let ipc = IpcOptions {
            timezone: opts.timezone,
        };
        tools.push(Arc::new(SendMessageTool));
        tools.push(Arc::new(ScheduleTaskTool::new(ipc.clone())));
        tools.push(Arc::new(ListTasksTool));
        tools.push(Arc::new(TaskControlTool::new(TaskControl::Pause)));
        tools.push(Arc::new(TaskControlTool::new(TaskControl::Resume)));
        tools.push(Arc::new(TaskControlTool::new(TaskControl::Cancel)));
        tools.push(Arc::new(UpdateTaskTool::new(ipc)));
        if opts.register_group {
            tools.push(Arc::new(RegisterGroupTool));
        }
    }
    tools
}

/// Run blocking filesystem work on the blocking pool.
pub(crate) async fn run_blocking<F>(f: F) -> ToolOutput
where
    F: FnOnce() -> ToolOutput + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| ToolOutput::err(format!("internal error: {e}")))
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::Path;

    use talon_core::tool::ToolContext;
    use tokio_util::sync::CancellationToken;

    /// Context rooted at `dir` (canonicalized): cwd = allowed root = `dir`,
    /// IPC dir `dir/ipc`, non-main group `testgroup` in chat `tg:42`.
    pub(crate) fn ctx_for(dir: &Path) -> ToolContext {
        let dir = std::fs::canonicalize(dir).unwrap();
        ToolContext {
            cwd: dir.clone(),
            allowed_roots: vec![dir.clone()],
            read_only_roots: vec![],
            group_folder: "testgroup".to_string(),
            chat_jid: "tg:42".to_string(),
            is_main: false,
            ipc_dir: dir.join("ipc"),
            cancel: CancellationToken::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use talon_core::tool::ToolConcurrency;

    fn check_schema(name: &str, schema: &serde_json::Value) {
        assert_eq!(
            schema["type"], "object",
            "{name}: root must be an object schema"
        );
        let props = schema["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}: properties must be an object"));
        if let Some(req) = schema.get("required") {
            for r in req.as_array().unwrap() {
                let r = r.as_str().unwrap();
                assert!(
                    props.contains_key(r),
                    "{name}: required `{r}` not in properties"
                );
            }
        }
        for (p, def) in props {
            let ty = def["type"]
                .as_str()
                .unwrap_or_else(|| panic!("{name}.{p}: missing type"));
            assert!(
                ["string", "integer", "number", "boolean", "array", "object"].contains(&ty),
                "{name}.{p}: bad type {ty}"
            );
            if ty == "array" {
                assert!(
                    def.get("items").is_some(),
                    "{name}.{p}: array without items"
                );
            }
        }
    }

    #[test]
    fn all_tools_have_valid_unique_specs() {
        let tools = builtin_tools(&BuiltinOptions::default());
        let names: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
        assert_eq!(
            names,
            names::ALL.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        let unique: HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
        let re = regex::Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap();
        for t in &tools {
            let s = t.spec();
            assert!(re.is_match(&s.name), "{}", s.name);
            assert!(
                s.description.len() > 20,
                "{}: description too short",
                s.name
            );
            check_schema(&s.name, &s.parameters);
            // Serializable as an OpenAI tool definition.
            serde_json::to_string(&s).unwrap();
        }
    }

    #[test]
    fn read_only_tools_are_marked() {
        let tools = builtin_tools(&BuiltinOptions::default());
        let read_only: HashSet<String> = tools
            .iter()
            .filter(|t| t.concurrency() == ToolConcurrency::ReadOnly)
            .map(|t| t.spec().name)
            .collect();
        let expected: HashSet<String> = [
            names::READ_FILE,
            names::LIST_DIR,
            names::GLOB,
            names::GREP,
            names::WEB_FETCH,
            names::LIST_TASKS,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(read_only, expected);
    }

    #[test]
    fn options_select_tools() {
        let opts = BuiltinOptions {
            bash: None,
            web_fetch: None,
            ipc_tools: false,
            ..BuiltinOptions::default()
        }
        .with_timezone_name("Europe/Berlin");
        assert_eq!(opts.timezone, chrono_tz::Europe::Berlin);
        let names: Vec<String> = builtin_tools(&opts).iter().map(|t| t.spec().name).collect();
        assert!(!names.contains(&"bash".to_string()));
        assert!(!names.contains(&"web_fetch".to_string()));
        assert!(!names.contains(&"send_message".to_string()));
        assert!(names.contains(&"todo_write".to_string()));

        let opts = BuiltinOptions {
            register_group: false,
            ..BuiltinOptions::default()
        };
        let names: Vec<String> = builtin_tools(&opts).iter().map(|t| t.spec().name).collect();
        assert!(!names.contains(&"register_group".to_string()));
        assert!(names.contains(&"update_task".to_string()));
        assert!(format!("{opts:?}").contains("BuiltinOptions"));
    }

    #[tokio::test]
    async fn todo_list_is_shared_with_options() {
        let opts = BuiltinOptions::default();
        let tools = builtin_tools(&opts);
        let todo = tools
            .iter()
            .find(|t| t.spec().name == names::TODO_WRITE)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_support::ctx_for(dir.path());
        let out = todo
            .call(
                serde_json::json!({"todos": [{"content": "x", "status": "pending"}]}),
                &ctx,
            )
            .await;
        assert!(!out.is_error);
        assert_eq!(opts.todo_list.snapshot().len(), 1);
    }
}
