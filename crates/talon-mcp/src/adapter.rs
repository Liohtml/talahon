//! Exposes remote MCP tools as [`talon_core::tool::Tool`]s.
//!
//! Names are `mcp__<server>__<tool>`, sanitized to `^[a-zA-Z0-9_-]{1,64}$`
//! (invalid characters become `_`; over-long names are cut and suffixed
//! with a stable hash) and made unique by a [`ToolNameAllocator`].

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};

use crate::client::McpClient;
use crate::types::McpTool;

/// Maximum tool name length accepted by OpenAI-compatible APIs.
pub const MAX_TOOL_NAME_LEN: usize = 64;

/// Hook applied to every tool result before it reaches the model:
/// `(server, tool, text) -> text`. The agent uses it to fence untrusted
/// output (`talon_security::injection::fence_untrusted`).
pub type ResultPostProcessor = Arc<dyn Fn(&str, &str, String) -> String + Send + Sync>;

/// Options for [`McpToolAdapter`].
#[derive(Clone)]
pub struct AdapterOptions {
    /// Per-call timeout (default 300 s).
    pub call_timeout: Duration,
    /// Results longer than this many bytes are truncated (before the
    /// post-processor runs, so fences stay intact). Default 200 000.
    pub max_output_bytes: usize,
    /// Tool descriptions are cut to this many characters (default 4 000).
    pub max_description_chars: usize,
    /// Optional result post-processor (see [`ResultPostProcessor`]).
    pub post_processor: Option<ResultPostProcessor>,
    /// When true, every MCP tool is [`ToolConcurrency::Exclusive`]
    /// regardless of `readOnlyHint` (default false).
    pub force_exclusive: bool,
}

impl Default for AdapterOptions {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_secs(300),
            max_output_bytes: 200_000,
            max_description_chars: 4000,
            post_processor: None,
            force_exclusive: false,
        }
    }
}

impl fmt::Debug for AdapterOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdapterOptions")
            .field("call_timeout", &self.call_timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("max_description_chars", &self.max_description_chars)
            .field("post_processor", &self.post_processor.is_some())
            .field("force_exclusive", &self.force_exclusive)
            .finish()
    }
}

/// 64-bit FNV-1a, used for stable name suffixes.
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Replace every character outside `[a-zA-Z0-9_-]` with `_`; empty input
/// becomes `_`; names longer than 64 are cut to 55 characters plus `_` and
/// an 8-hex-digit hash of the original, so distinct long names stay
/// distinct.
pub fn sanitize_tool_name(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        s.push('_');
    }
    if s.len() > MAX_TOOL_NAME_LEN {
        let hash = format!("{:08x}", fnv1a(raw) & 0xffff_ffff);
        s.truncate(MAX_TOOL_NAME_LEN - hash.len() - 1);
        s.push('_');
        s.push_str(&hash);
    }
    s
}

/// `mcp__<server>__<tool>`, sanitized (not yet de-duplicated).
pub fn mcp_tool_name(server: &str, tool: &str) -> String {
    sanitize_tool_name(&format!("mcp__{server}__{tool}"))
}

/// True if `name` matches `^[a-zA-Z0-9_-]{1,64}$`.
pub fn is_valid_tool_name(name: &str) -> bool {
    (1..=MAX_TOOL_NAME_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Hands out unique tool names. Reserve the names of built-in tools first
/// so an MCP tool can never shadow them.
#[derive(Debug, Default, Clone)]
pub struct ToolNameAllocator {
    used: HashSet<String>,
}

impl ToolNameAllocator {
    /// Empty allocator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `name` as taken. Returns false if it already was.
    pub fn reserve(&mut self, name: &str) -> bool {
        self.used.insert(name.to_string())
    }

    /// Whether `name` is taken.
    pub fn contains(&self, name: &str) -> bool {
        self.used.contains(name)
    }

    /// Allocate a unique name for `server`/`tool`: `mcp__server__tool`,
    /// or with `_2`, `_3`, ... appended (keeping within 64 chars) on
    /// collision.
    pub fn allocate(&mut self, server: &str, tool: &str) -> String {
        let base = mcp_tool_name(server, tool);
        if self.used.insert(base.clone()) {
            return base;
        }
        let mut n: u64 = 2;
        loop {
            let suffix = format!("_{n}");
            let mut candidate = base.clone();
            if candidate.len() + suffix.len() > MAX_TOOL_NAME_LEN {
                candidate.truncate(MAX_TOOL_NAME_LEN - suffix.len());
            }
            candidate.push_str(&suffix);
            if self.used.insert(candidate.clone()) {
                return candidate;
            }
            n += 1;
        }
    }
}

/// Normalize a tool input schema for OpenAI-style function calling:
/// always an object schema with `type: "object"` and a `properties` map.
pub fn normalize_input_schema(schema: &Value) -> Value {
    let mut obj = match schema {
        Value::Object(m) => m.clone(),
        _ => serde_json::Map::new(),
    };
    match obj.get("type") {
        Some(Value::String(t)) if t == "object" => {}
        _ => {
            obj.insert("type".into(), json!("object"));
        }
    }
    if !obj.get("properties").is_some_and(Value::is_object) {
        obj.insert("properties".into(), json!({}));
    }
    Value::Object(obj)
}

/// Cut `text` to at most `max_bytes` (on a char boundary) and append a
/// marker saying how much was dropped.
pub fn truncate_output(text: String, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text;
    }
    let mut cut = max_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let total = text.len();
    let mut out = text;
    out.truncate(cut);
    out.push_str(&format!(
        "\n\n[... output truncated: showing the first {cut} of {total} bytes ...]"
    ));
    out
}

/// A remote MCP tool exposed as a Talon [`Tool`].
pub struct McpToolAdapter {
    client: Arc<McpClient>,
    tool: McpTool,
    exposed_name: String,
    options: AdapterOptions,
}

impl fmt::Debug for McpToolAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpToolAdapter")
            .field("server", &self.client.name())
            .field("tool", &self.tool.name)
            .field("exposed_name", &self.exposed_name)
            .finish()
    }
}

impl McpToolAdapter {
    /// Wrap `tool` of `client` under `exposed_name` (normally from
    /// [`ToolNameAllocator::allocate`]; sanitized again here for safety).
    pub fn new(
        client: Arc<McpClient>,
        tool: McpTool,
        exposed_name: impl Into<String>,
        options: AdapterOptions,
    ) -> Self {
        let exposed_name = exposed_name.into();
        let exposed_name = if is_valid_tool_name(&exposed_name) {
            exposed_name
        } else {
            sanitize_tool_name(&exposed_name)
        };
        Self {
            client,
            tool,
            exposed_name,
            options,
        }
    }

    /// Wrap every tool of `client`, allocating names from `allocator`.
    pub fn wrap_all(
        client: &Arc<McpClient>,
        tools: &[McpTool],
        allocator: &mut ToolNameAllocator,
        options: &AdapterOptions,
    ) -> Vec<Arc<McpToolAdapter>> {
        tools
            .iter()
            .map(|t| {
                let name = allocator.allocate(client.name(), &t.name);
                Arc::new(Self::new(
                    Arc::clone(client),
                    t.clone(),
                    name,
                    options.clone(),
                ))
            })
            .collect()
    }

    /// Server name.
    pub fn server_name(&self) -> &str {
        self.client.name()
    }

    /// The tool's name on the server.
    pub fn tool_name(&self) -> &str {
        &self.tool.name
    }

    /// The name the model sees.
    pub fn exposed_name(&self) -> &str {
        &self.exposed_name
    }

    /// The raw tool definition.
    pub fn mcp_tool(&self) -> &McpTool {
        &self.tool
    }

    /// The underlying client.
    pub fn client(&self) -> &Arc<McpClient> {
        &self.client
    }

    fn description(&self) -> String {
        let base = self
            .tool
            .description
            .as_deref()
            .filter(|d| !d.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "{} (tool '{}' of MCP server '{}')",
                    self.tool.display_title(),
                    self.tool.name,
                    self.client.name()
                )
            });
        crate::error::truncate_chars(&base, self.options.max_description_chars)
    }

    fn finish(&self, content: String, is_error: bool) -> ToolOutput {
        let content = truncate_output(content, self.options.max_output_bytes);
        let content = match &self.options.post_processor {
            Some(p) => p(self.client.name(), &self.tool.name, content),
            None => content,
        };
        ToolOutput { content, is_error }
    }
}

#[async_trait]
impl Tool for McpToolAdapter {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.exposed_name.clone(),
            description: self.description(),
            parameters: normalize_input_schema(&self.tool.input_schema),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        if !self.options.force_exclusive && self.tool.is_read_only() {
            ToolConcurrency::ReadOnly
        } else {
            ToolConcurrency::Exclusive
        }
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> ToolOutput {
        let args = match args {
            Value::Null => json!({}),
            Value::Object(_) => args,
            _ => {
                return self.finish(
                    format!(
                        "Invalid arguments for {}: expected a JSON object",
                        self.exposed_name
                    ),
                    true,
                );
            }
        };
        let started = std::time::Instant::now();
        let result = self
            .client
            .call_tool_cancellable(
                &self.tool.name,
                args,
                Some(self.options.call_timeout),
                &ctx.cancel,
            )
            .await;
        tracing::debug!(
            server = %self.client.name(),
            tool = %self.tool.name,
            elapsed_ms = started.elapsed().as_millis() as u64,
            ok = result.as_ref().map(|r| !r.is_error).unwrap_or(false),
            "MCP tool call finished"
        );
        match result {
            Ok(r) => self.finish(r.render_text(), r.is_error),
            Err(e) => self.finish(format!("MCP tool call failed: {e}"), true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_names() {
        assert_eq!(
            mcp_tool_name("opensearch", "search_index"),
            "mcp__opensearch__search_index"
        );
        assert_eq!(
            mcp_tool_name("my server", "get.thing/x"),
            "mcp__my_server__get_thing_x"
        );
        assert_eq!(mcp_tool_name("srv", "tööl"), "mcp__srv__t__l");
        assert_eq!(sanitize_tool_name(""), "_");
        for name in [
            mcp_tool_name("a", "b"),
            mcp_tool_name(&"s".repeat(100), &"t".repeat(100)),
            sanitize_tool_name("💥"),
        ] {
            assert!(is_valid_tool_name(&name), "{name}");
        }
    }

    #[test]
    fn long_names_are_hashed_and_distinct() {
        let a = mcp_tool_name("server", &format!("{}_alpha", "x".repeat(80)));
        let b = mcp_tool_name("server", &format!("{}_beta", "x".repeat(80)));
        assert_eq!(a.len(), MAX_TOOL_NAME_LEN);
        assert_eq!(b.len(), MAX_TOOL_NAME_LEN);
        assert_ne!(a, b);
        assert!(a.starts_with("mcp__server__xxx"));
        // Stable across calls.
        assert_eq!(
            a,
            mcp_tool_name("server", &format!("{}_alpha", "x".repeat(80)))
        );
        // Exactly 64 is not hashed.
        let exact = "a".repeat(64);
        assert_eq!(sanitize_tool_name(&exact), exact);
    }

    #[test]
    fn allocator_resolves_collisions() {
        let mut alloc = ToolNameAllocator::new();
        assert!(alloc.reserve("bash"));
        assert!(!alloc.reserve("bash"));
        let a = alloc.allocate("s", "a.b");
        let b = alloc.allocate("s", "a_b");
        let c = alloc.allocate("s", "a/b");
        assert_eq!(a, "mcp__s__a_b");
        assert_eq!(b, "mcp__s__a_b_2");
        assert_eq!(c, "mcp__s__a_b_3");
        assert!(alloc.contains(&c));

        // Collisions on 64-char names keep the length bound.
        let long = "y".repeat(100);
        let first = alloc.allocate("s", &long);
        let second = alloc.allocate("s", &long);
        assert_ne!(first, second);
        assert!(is_valid_tool_name(&first));
        assert!(is_valid_tool_name(&second));
        assert!(second.ends_with("_2"));

        // Built-in names cannot be taken.
        let mut alloc = ToolNameAllocator::new();
        alloc.reserve("mcp__x__y");
        assert_eq!(alloc.allocate("x", "y"), "mcp__x__y_2");
    }

    #[test]
    fn schema_normalization() {
        assert_eq!(
            normalize_input_schema(&json!(null)),
            json!({"type":"object","properties":{}})
        );
        assert_eq!(
            normalize_input_schema(
                &json!({"properties": {"q": {"type": "string"}}, "required": ["q"]})
            ),
            json!({"type":"object","properties":{"q":{"type":"string"}},"required":["q"]})
        );
        assert_eq!(
            normalize_input_schema(&json!({"type": "array", "properties": 3})),
            json!({"type":"object","properties":{}})
        );
        let keep = json!({"type":"object","properties":{},"additionalProperties":false});
        assert_eq!(normalize_input_schema(&keep), keep);
    }

    #[test]
    fn output_truncation() {
        assert_eq!(truncate_output("short".into(), 10), "short");
        let t = truncate_output("äääää".into(), 5);
        assert!(t.starts_with("ää"));
        assert!(t.contains("first 4 of 10 bytes"));
        let t = truncate_output("x".repeat(100), 10);
        assert!(t.starts_with(&"x".repeat(10)));
        assert!(!t.starts_with(&"x".repeat(11)));
    }

    #[test]
    fn fnv_is_stable() {
        assert_eq!(fnv1a(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a("a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn options_debug_hides_closure() {
        let opts = AdapterOptions {
            post_processor: Some(Arc::new(|_, _, s| s)),
            ..AdapterOptions::default()
        };
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("post_processor: true"));
    }
}
