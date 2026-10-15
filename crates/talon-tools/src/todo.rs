//! `todo_write` — an in-memory task plan the model maintains during a run.
//!
//! Each call replaces the whole list and returns it rendered in full, so the
//! current plan is always visible in the transcript. The list lives in a
//! [`TodoList`] handle that the agent runtime can share (e.g. to show progress
//! or persist it with the session).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use talon_core::tool::{Tool, ToolContext, ToolOutput, ToolSpec};

use crate::args::Args;

/// Tool name.
pub const NAME: &str = "todo_write";

/// Maximum number of items.
pub const MAX_ITEMS: usize = 100;
/// Maximum length of one item's text.
const MAX_ITEM_CHARS: usize = 500;

/// Status of a todo item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoStatus {
    /// Not started.
    Pending,
    /// Currently being worked on.
    InProgress,
    /// Done.
    Completed,
}

/// One plan item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TodoItem {
    /// Imperative description, e.g. "Enrich source IP".
    pub content: String,
    /// Current status.
    pub status: TodoStatus,
    /// Present-continuous form shown while in progress ("Enriching source IP").
    #[serde(
        rename = "activeForm",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub active_form: Option<String>,
}

/// Shared handle to the current todo list.
#[derive(Debug, Clone, Default)]
pub struct TodoList(Arc<Mutex<Vec<TodoItem>>>);

impl TodoList {
    /// Empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy of the current items.
    pub fn snapshot(&self) -> Vec<TodoItem> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// Replace the items.
    pub fn replace(&self, items: Vec<TodoItem>) {
        if let Ok(mut v) = self.0.lock() {
            *v = items;
        }
    }

    /// Render as a checklist (`[x]` done, `[~]` in progress, `[ ]` pending).
    pub fn render(&self) -> String {
        render_items(&self.snapshot())
    }
}

fn render_items(items: &[TodoItem]) -> String {
    if items.is_empty() {
        return "Todo list is empty.".to_string();
    }
    let done = items
        .iter()
        .filter(|i| i.status == TodoStatus::Completed)
        .count();
    let active = items
        .iter()
        .filter(|i| i.status == TodoStatus::InProgress)
        .count();
    let mut out = format!(
        "Todo list ({} item{}: {done} completed, {active} in progress, {} pending):\n",
        items.len(),
        if items.len() == 1 { "" } else { "s" },
        items.len() - done - active
    );
    for (n, i) in items.iter().enumerate() {
        let mark = match i.status {
            TodoStatus::Completed => "[x]",
            TodoStatus::InProgress => "[~]",
            TodoStatus::Pending => "[ ]",
        };
        out.push_str(&format!("{mark} {}. {}", n + 1, i.content));
        if i.status == TodoStatus::InProgress {
            if let Some(a) = &i.active_form {
                out.push_str(&format!(" ({a})"));
            }
        }
        out.push('\n');
    }
    out.trim_end().to_string()
}

fn parse_items(args: &Args) -> Result<Vec<TodoItem>, String> {
    let Some(raw) = args.value("todos") else {
        return Err("missing required parameter `todos` (array)".to_string());
    };
    let raw = match raw {
        serde_json::Value::String(s) => serde_json::from_str::<serde_json::Value>(s)
            .map_err(|_| "`todos` must be an array of {content, status} objects".to_string())?,
        v => v.clone(),
    };
    let arr = raw
        .as_array()
        .ok_or_else(|| "`todos` must be an array of {content, status} objects".to_string())?;
    if arr.len() > MAX_ITEMS {
        return Err(format!(
            "too many todos ({}); the maximum is {MAX_ITEMS}",
            arr.len()
        ));
    }
    let mut items = Vec::with_capacity(arr.len());
    for (n, v) in arr.iter().enumerate() {
        let item: TodoItem = serde_json::from_value(v.clone()).map_err(|e| {
            format!(
                "todos[{n}] is invalid ({e}); each item needs \"content\" (string) and \"status\" \
                 (\"pending\" | \"in_progress\" | \"completed\")"
            )
        })?;
        let content = item.content.trim();
        if content.is_empty() {
            return Err(format!("todos[{n}].content must not be empty"));
        }
        if content.chars().count() > MAX_ITEM_CHARS {
            return Err(format!(
                "todos[{n}].content is longer than {MAX_ITEM_CHARS} characters"
            ));
        }
        items.push(TodoItem {
            content: content.to_string(),
            status: item.status,
            active_form: item
                .active_form
                .map(|a| a.trim().chars().take(MAX_ITEM_CHARS).collect::<String>())
                .filter(|a| !a.is_empty()),
        });
    }
    Ok(items)
}

/// The `todo_write` tool.
#[derive(Debug, Clone, Default)]
pub struct TodoWriteTool {
    list: TodoList,
}

impl TodoWriteTool {
    /// Tool backed by `list`.
    pub fn new(list: TodoList) -> Self {
        Self { list }
    }

    /// The backing list.
    pub fn list(&self) -> &TodoList {
        &self.list
    }
}

#[async_trait]
impl Tool for TodoWriteTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: NAME.to_string(),
            description: "Create or update your task plan for the current request. Each call REPLACES the \
                 whole list; the full list is returned.\n\
                 \n\
                 Use it for multi-step work (e.g. an investigation with several enrichment and \
                 correlation steps): write the plan up front, mark exactly one item `in_progress` \
                 while you work on it, and mark items `completed` as soon as they are done. Skip it \
                 for trivial single-step requests.\n\
                 \n\
                 Example: {\"todos\": [\
                 {\"content\": \"Pull the alert and related events\", \"status\": \"completed\"}, \
                 {\"content\": \"Enrich source IP 203.0.113.7\", \"status\": \"in_progress\", \"activeForm\": \"Enriching source IP\"}, \
                 {\"content\": \"Write triage verdict\", \"status\": \"pending\"}]}"
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "todos": {
                        "type": "array",
                        "maxItems": MAX_ITEMS,
                        "description": "The complete, updated list of todo items.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "content": {"type": "string", "description": "What needs to be done (imperative)."},
                                "status": {"type": "string", "enum": ["pending", "in_progress", "completed"]},
                                "activeForm": {"type": "string", "description": "Present-continuous form shown while in progress."}
                            },
                            "required": ["content", "status"],
                            "additionalProperties": false
                        }
                    }
                },
                "required": ["todos"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolOutput {
        let args = match Args::parse(args) {
            Ok(a) => a,
            Err(e) => return ToolOutput::err(e),
        };
        let items = match parse_items(&args) {
            Ok(i) => i,
            Err(e) => return ToolOutput::err(e),
        };
        let in_progress = items
            .iter()
            .filter(|i| i.status == TodoStatus::InProgress)
            .count();
        let mut out = render_items(&items);
        if in_progress > 1 {
            out.push_str(&format!(
                "\nNote: {in_progress} items are in_progress; keep exactly one in progress at a time."
            ));
        }
        self.list.replace(items);
        ToolOutput::ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ctx_for;

    #[tokio::test]
    async fn replaces_and_renders_list() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let list = TodoList::new();
        let t = TodoWriteTool::new(list.clone());
        let out = t
            .call(
                json!({"todos": [
                    {"content": "Pull alert", "status": "completed"},
                    {"content": "Enrich IP", "status": "in_progress", "activeForm": "Enriching IP"},
                    {"content": "Report", "status": "pending"}
                ]}),
                &ctx,
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert_eq!(
            out.content,
            "Todo list (3 items: 1 completed, 1 in progress, 1 pending):\n\
             [x] 1. Pull alert\n[~] 2. Enrich IP (Enriching IP)\n[ ] 3. Report"
        );
        assert_eq!(list.snapshot().len(), 3);

        let out = t.call(json!({"todos": []}), &ctx).await;
        assert_eq!(out.content, "Todo list is empty.");
        assert!(list.snapshot().is_empty());
    }

    #[tokio::test]
    async fn validation() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let t = TodoWriteTool::default();
        assert!(t.call(json!({}), &ctx).await.is_error);
        assert!(t.call(json!({"todos": "nope"}), &ctx).await.is_error);
        let out = t
            .call(
                json!({"todos": [{"content": "x", "status": "doing"}]}),
                &ctx,
            )
            .await;
        assert!(out.is_error && out.content.contains("todos[0]"));
        assert!(
            t.call(
                json!({"todos": [{"content": "  ", "status": "pending"}]}),
                &ctx
            )
            .await
            .is_error
        );
        let many: Vec<_> = (0..101)
            .map(|i| json!({"content": format!("t{i}"), "status": "pending"}))
            .collect();
        assert!(t.call(json!({ "todos": many }), &ctx).await.is_error);
        // Stringified array is accepted.
        let out = t
            .call(
                json!({"todos": "[{\"content\":\"a\",\"status\":\"pending\"}]"}),
                &ctx,
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        let out = t
            .call(
                json!({"todos": [
                    {"content": "a", "status": "in_progress"},
                    {"content": "b", "status": "in_progress"}
                ]}),
                &ctx,
            )
            .await;
        assert!(out.content.contains("keep exactly one"));
    }
}
