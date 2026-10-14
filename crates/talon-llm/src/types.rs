//! OpenAI-compatible chat-completions wire types, with the vLLM extensions
//! Talon uses (`chat_template_kwargs`, guided decoding via `response_format`
//! `json_schema`, `prompt_tokens_details.cached_tokens`, `reasoning_content`).
//!
//! Deserialization is deliberately lenient (servers differ in small ways:
//! `reasoning` vs `reasoning_content`, content as a parts array, tool-call
//! arguments as an object instead of a string, `null` instead of a missing
//! field), while serialization produces strictly spec-shaped JSON.

use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use talon_core::protocol::SessionUsage;
use talon_core::tool::ToolSpec;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Author of a chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System prompt. `developer` (newer OpenAI naming) is accepted as an alias.
    #[serde(alias = "developer")]
    System,
    /// End-user input.
    User,
    /// Model output.
    Assistant,
    /// Result of a tool call (`tool_call_id` must be set).
    Tool,
}

impl Role {
    /// The wire name of the role.
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

fn default_assistant() -> Role {
    Role::Assistant
}

/// One message of a conversation.
///
/// `content` is plain text. When a server returns content as an array of
/// parts, the text parts are concatenated on deserialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "ChatMessageWire")]
pub struct ChatMessage {
    /// Who wrote the message.
    pub role: Role,
    /// Text content. `None` for assistant messages that only carry tool
    /// calls (serialized as `null`, which every OpenAI-compatible server accepts).
    pub content: Option<String>,
    /// Tool calls requested by the assistant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// For `role = tool`: the id of the call this message answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Optional participant / tool name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Model "thinking" (vLLM reasoning parser output, or text split out of
    /// `<think>...</think>`). Sent back only when set — reasoning chat
    /// templates (Qwen3) use it for interleaved thinking during tool use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
}

impl ChatMessage {
    fn with_role(role: Role, content: Option<String>) -> Self {
        Self {
            role,
            content,
            tool_calls: Vec::new(),
            tool_call_id: None,
            name: None,
            reasoning_content: None,
        }
    }

    /// A system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::with_role(Role::System, Some(content.into()))
    }

    /// A user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::with_role(Role::User, Some(content.into()))
    }

    /// A plain-text assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::with_role(Role::Assistant, Some(content.into()))
    }

    /// An assistant message carrying tool calls (and optional text).
    pub fn assistant_tool_calls(content: Option<String>, tool_calls: Vec<ToolCall>) -> Self {
        let mut m = Self::with_role(Role::Assistant, content);
        m.tool_calls = tool_calls;
        m
    }

    /// A tool result answering `tool_call_id`.
    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        let mut m = Self::with_role(Role::Tool, Some(content.into()));
        m.tool_call_id = Some(tool_call_id.into());
        m
    }

    /// The text content, or `""`.
    pub fn text(&self) -> &str {
        self.content.as_deref().unwrap_or("")
    }

    /// Whether the message requests at least one tool call.
    pub fn has_tool_calls(&self) -> bool {
        !self.tool_calls.is_empty()
    }

    /// Replace empty or invalid-JSON tool-call `arguments` with `{}` and
    /// return how many were changed.
    ///
    /// vLLM parses the `arguments` of assistant messages in the history when
    /// rendering the chat template, so a malformed value (e.g. truncated by
    /// `max_tokens`) would make *every following request* fail with HTTP 400.
    /// Call this before appending a model message to the history (after
    /// answering the broken calls with an error tool result).
    pub fn normalize_tool_arguments(&mut self) -> usize {
        let mut changed = 0;
        for call in &mut self.tool_calls {
            let valid = matches!(call.parse_arguments(), Ok(Value::Object(_)));
            if !valid || call.function.arguments.trim().is_empty() {
                call.function.arguments = "{}".to_string();
                changed += 1;
            }
        }
        changed
    }
}

/// Lenient deserialization shape for [`ChatMessage`].
#[derive(Deserialize)]
struct ChatMessageWire {
    #[serde(default = "default_assistant")]
    role: Role,
    #[serde(default)]
    content: Option<ContentWire>,
    #[serde(default)]
    tool_calls: Option<Vec<ToolCall>>,
    #[serde(default)]
    tool_call_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    /// Newer vLLM releases name the field `reasoning`.
    #[serde(default)]
    reasoning: Option<String>,
}

impl From<ChatMessageWire> for ChatMessage {
    fn from(w: ChatMessageWire) -> Self {
        Self {
            role: w.role,
            content: w.content.and_then(ContentWire::into_text),
            tool_calls: w.tool_calls.unwrap_or_default(),
            tool_call_id: w.tool_call_id,
            name: w.name,
            reasoning_content: w.reasoning_content.or(w.reasoning),
        }
    }
}

/// Content as either a string or an array of typed parts.
#[derive(Deserialize)]
#[serde(untagged)]
enum ContentWire {
    Text(String),
    Parts(Vec<Value>),
    Other(Value),
}

impl ContentWire {
    fn into_text(self) -> Option<String> {
        match self {
            ContentWire::Text(s) => Some(s),
            ContentWire::Parts(parts) => {
                let text: Vec<&str> = parts
                    .iter()
                    .filter_map(|p| match p {
                        Value::String(s) => Some(s.as_str()),
                        Value::Object(o) => o.get("text").and_then(Value::as_str),
                        _ => None,
                    })
                    .collect();
                Some(text.join(""))
            }
            ContentWire::Other(Value::Null) => None,
            ContentWire::Other(v) => Some(v.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tool calls / tool definitions
// ---------------------------------------------------------------------------

/// The only tool type OpenAI-compatible servers define.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolKind {
    /// A function tool.
    #[default]
    Function,
}

/// A tool call requested by the model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Call id; echoed back in the `tool` message. Filled in by the client
    /// when a server omits it.
    #[serde(default)]
    pub id: String,
    /// Always `function`.
    #[serde(rename = "type", default)]
    pub kind: ToolKind,
    /// The function name and JSON-encoded arguments.
    pub function: FunctionCall,
}

impl ToolCall {
    /// Build a function tool call.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind: ToolKind::Function,
            function: FunctionCall {
                name: name.into(),
                arguments: arguments.into(),
            },
        }
    }

    /// The function name.
    pub fn name(&self) -> &str {
        &self.function.name
    }

    /// Parse the JSON arguments. Empty/whitespace arguments yield `{}`.
    pub fn parse_arguments(&self) -> Result<Value, serde_json::Error> {
        let raw = self.function.arguments.trim();
        if raw.is_empty() {
            return Ok(Value::Object(Map::new()));
        }
        serde_json::from_str(raw)
    }
}

/// Function name + JSON-encoded arguments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionCall {
    /// Tool name as offered in the request.
    pub name: String,
    /// JSON-encoded arguments (a string per the OpenAI spec; servers that
    /// return an object are accepted and re-encoded).
    #[serde(default, deserialize_with = "de_arguments")]
    pub arguments: String,
}

/// Accept `arguments` as a string, an object, or null.
fn de_arguments<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let v = Option::<Value>::deserialize(d)?;
    Ok(match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s,
        Some(other) => other.to_string(),
    })
}

/// Tool advertised to the model (`{"type":"function","function":{...}}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Always `function`.
    #[serde(rename = "type", default)]
    pub kind: ToolKind,
    /// Name, description and JSON-schema parameters.
    pub function: FunctionDefinition,
}

/// The `function` object of a [`ToolDefinition`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// Tool name (`^[a-zA-Z0-9_-]{1,64}$`).
    pub name: String,
    /// What the tool does (shown to the model).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// JSON schema of the arguments object.
    #[serde(default = "empty_object_schema")]
    pub parameters: Value,
    /// Ask the server to enforce the schema (structured outputs for tools).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

fn empty_object_schema() -> Value {
    serde_json::json!({"type": "object", "properties": {}})
}

impl From<&ToolSpec> for ToolDefinition {
    fn from(spec: &ToolSpec) -> Self {
        let parameters = if spec.parameters.is_object() {
            spec.parameters.clone()
        } else {
            empty_object_schema()
        };
        Self {
            kind: ToolKind::Function,
            function: FunctionDefinition {
                name: spec.name.clone(),
                description: spec.description.clone(),
                parameters,
                strict: None,
            },
        }
    }
}

impl From<ToolSpec> for ToolDefinition {
    fn from(spec: ToolSpec) -> Self {
        Self::from(&spec)
    }
}

/// `tool_choice`: `"auto"`, `"none"`, `"required"`, or a named function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolChoice {
    /// The model decides (default when tools are offered).
    Auto,
    /// Never call tools.
    None,
    /// Must call at least one tool (vLLM enforces this with guided decoding).
    Required,
    /// Must call exactly this function.
    Function(String),
}

impl Serialize for ToolChoice {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            ToolChoice::Auto => s.serialize_str("auto"),
            ToolChoice::None => s.serialize_str("none"),
            ToolChoice::Required => s.serialize_str("required"),
            ToolChoice::Function(name) => serde_json::json!({
                "type": "function",
                "function": {"name": name}
            })
            .serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for ToolChoice {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        match &v {
            Value::String(s) => match s.as_str() {
                "auto" => Ok(ToolChoice::Auto),
                "none" => Ok(ToolChoice::None),
                "required" => Ok(ToolChoice::Required),
                other => Err(de::Error::custom(format!("unknown tool_choice {other:?}"))),
            },
            Value::Object(_) => v
                .pointer("/function/name")
                .and_then(Value::as_str)
                .map(|n| ToolChoice::Function(n.to_string()))
                .ok_or_else(|| de::Error::custom("tool_choice object without function.name")),
            _ => Err(de::Error::custom("invalid tool_choice")),
        }
    }
}

// ---------------------------------------------------------------------------
// Structured output
// ---------------------------------------------------------------------------

/// `response_format`. vLLM implements `json_schema` with guided decoding, so
/// the output is guaranteed to parse against the schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseFormat {
    /// Free text (the default).
    Text,
    /// Any JSON object.
    JsonObject,
    /// JSON constrained by a schema.
    JsonSchema {
        /// Schema wrapper (`{"name","schema","strict"}`).
        json_schema: JsonSchemaFormat,
    },
}

impl ResponseFormat {
    /// Guided decoding against `schema`.
    pub fn json_schema(name: impl Into<String>, schema: Value, strict: bool) -> Self {
        ResponseFormat::JsonSchema {
            json_schema: JsonSchemaFormat {
                name: name.into(),
                description: None,
                schema,
                strict: Some(strict),
            },
        }
    }
}

/// The `json_schema` object of [`ResponseFormat::JsonSchema`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonSchemaFormat {
    /// Schema name (`^[a-zA-Z0-9_-]{1,64}$`).
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The JSON schema.
    pub schema: Value,
    /// Strict schema adherence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

/// `stream_options` (`include_usage` makes the server send a final usage chunk).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamOptions {
    /// Send a final chunk with `usage` and empty `choices`.
    pub include_usage: bool,
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A `POST /v1/chat/completions` request.
///
/// Build it with [`ChatRequest::new`] (or `VllmClient::request`, which
/// seeds the endpoint's defaults) and the builder methods. `stream` and
/// `stream_options` are managed by the client (`chat` vs `chat_stream`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Served model name.
    pub model: String,
    /// The conversation.
    pub messages: Vec<ChatMessage>,
    /// Tools offered to the model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDefinition>,
    /// Tool selection policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Allow several tool calls in one turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    /// Sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus sampling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Upper bound on generated tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Stop sequences.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    /// Sampling seed (reproducibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
    /// Structured output / guided decoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    /// vLLM: extra variables for the chat template, e.g.
    /// `{"enable_thinking": false}` for Qwen3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_template_kwargs: Option<Map<String, Value>>,
    /// Managed by the client.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stream: bool,
    /// Managed by the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<StreamOptions>,
    /// Any other (vLLM-specific) sampling parameters, e.g. `top_k`,
    /// `min_p`, `repetition_penalty`. Flattened into the request body.
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

impl ChatRequest {
    /// A request with no tools and server-default sampling.
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            model: model.into(),
            messages,
            tools: Vec::new(),
            tool_choice: None,
            parallel_tool_calls: None,
            temperature: None,
            top_p: None,
            max_tokens: None,
            stop: Vec::new(),
            seed: None,
            response_format: None,
            chat_template_kwargs: None,
            stream: false,
            stream_options: None,
            extra: Map::new(),
        }
    }

    /// Offer these tools (converted from [`ToolSpec`]).
    pub fn tools<'a>(mut self, specs: impl IntoIterator<Item = &'a ToolSpec>) -> Self {
        self.tools = specs.into_iter().map(ToolDefinition::from).collect();
        self
    }

    /// Offer pre-built tool definitions.
    pub fn tool_definitions(mut self, tools: Vec<ToolDefinition>) -> Self {
        self.tools = tools;
        self
    }

    /// Set `tool_choice`.
    pub fn tool_choice(mut self, choice: ToolChoice) -> Self {
        self.tool_choice = Some(choice);
        self
    }

    /// Set `parallel_tool_calls`.
    pub fn parallel_tool_calls(mut self, allow: bool) -> Self {
        self.parallel_tool_calls = Some(allow);
        self
    }

    /// Set the sampling temperature.
    pub fn temperature(mut self, t: f32) -> Self {
        self.temperature = Some(t);
        self
    }

    /// Set `top_p`.
    pub fn top_p(mut self, p: f32) -> Self {
        self.top_p = Some(p);
        self
    }

    /// Set `max_tokens`.
    pub fn max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = Some(n);
        self
    }

    /// Set stop sequences.
    pub fn stop(mut self, stop: Vec<String>) -> Self {
        self.stop = stop;
        self
    }

    /// Set the sampling seed.
    pub fn seed(mut self, seed: i64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Set `response_format`.
    pub fn response_format(mut self, format: ResponseFormat) -> Self {
        self.response_format = Some(format);
        self
    }

    /// Guided decoding: the reply must be JSON matching `schema`.
    pub fn json_schema(self, name: impl Into<String>, schema: Value, strict: bool) -> Self {
        self.response_format(ResponseFormat::json_schema(name, schema, strict))
    }

    /// Set one `chat_template_kwargs` entry.
    pub fn chat_template_kwarg(mut self, key: impl Into<String>, value: Value) -> Self {
        self.chat_template_kwargs
            .get_or_insert_with(Map::new)
            .insert(key.into(), value);
        self
    }

    /// `chat_template_kwargs.enable_thinking` (Qwen3-style reasoning switch).
    pub fn enable_thinking(self, enable: bool) -> Self {
        self.chat_template_kwarg("enable_thinking", Value::Bool(enable))
    }

    /// Set an extra top-level parameter (e.g. `top_k`).
    pub fn extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Names of the offered tools.
    pub fn offered_tool_names(&self) -> impl Iterator<Item = &str> {
        self.tools.iter().map(|t| t.function.name.as_str())
    }

    /// Whether tool calls are possible for this request (tools offered and
    /// `tool_choice` is not `none`).
    pub fn tools_enabled(&self) -> bool {
        !self.tools.is_empty() && self.tool_choice != Some(ToolChoice::None)
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// Why generation stopped.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FinishReason {
    /// Natural stop or stop sequence.
    Stop,
    /// `max_tokens` (or the context window) reached — output is truncated.
    Length,
    /// The model requested tool calls.
    ToolCalls,
    /// Content filter.
    ContentFilter,
    /// Request aborted server-side.
    Abort,
    /// Anything else, verbatim.
    Other(String),
}

impl FinishReason {
    /// Parse a wire value.
    pub fn parse(s: &str) -> Self {
        match s {
            "stop" | "eos" | "end_turn" | "stop_sequence" => FinishReason::Stop,
            "length" | "max_tokens" => FinishReason::Length,
            "tool_calls" | "function_call" | "tool_use" => FinishReason::ToolCalls,
            "content_filter" => FinishReason::ContentFilter,
            "abort" => FinishReason::Abort,
            other => FinishReason::Other(other.to_string()),
        }
    }

    /// The wire value.
    pub fn as_str(&self) -> &str {
        match self {
            FinishReason::Stop => "stop",
            FinishReason::Length => "length",
            FinishReason::ToolCalls => "tool_calls",
            FinishReason::ContentFilter => "content_filter",
            FinishReason::Abort => "abort",
            FinishReason::Other(s) => s,
        }
    }
}

impl fmt::Display for FinishReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for FinishReason {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FinishReason {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(FinishReason::parse(&s))
    }
}

/// Token accounting for one completion (or a sum of several).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "UsageWire", into = "UsageWire")]
pub struct Usage {
    /// Prompt tokens, including cached ones.
    pub prompt_tokens: u64,
    /// Generated tokens (including reasoning tokens).
    pub completion_tokens: u64,
    /// Prompt tokens served from vLLM's prefix cache
    /// (`usage.prompt_tokens_details.cached_tokens`; needs
    /// `--enable-prompt-tokens-details` on the server, else 0).
    pub cached_tokens: u64,
}

impl Usage {
    /// `prompt_tokens + completion_tokens`.
    pub fn total_tokens(&self) -> u64 {
        self.prompt_tokens.saturating_add(self.completion_tokens)
    }

    /// Prompt tokens that were not served from the prefix cache.
    pub fn uncached_prompt_tokens(&self) -> u64 {
        self.prompt_tokens.saturating_sub(self.cached_tokens)
    }

    /// Whether nothing was counted.
    pub fn is_zero(&self) -> bool {
        *self == Usage::default()
    }

    /// Add another usage record (saturating).
    pub fn accumulate(&mut self, other: &Usage) {
        self.prompt_tokens = self.prompt_tokens.saturating_add(other.prompt_tokens);
        self.completion_tokens = self
            .completion_tokens
            .saturating_add(other.completion_tokens);
        self.cached_tokens = self.cached_tokens.saturating_add(other.cached_tokens);
    }
}

impl std::ops::AddAssign for Usage {
    fn add_assign(&mut self, rhs: Usage) {
        self.accumulate(&rhs);
    }
}

/// Maps vLLM usage onto the Anthropic-shaped [`SessionUsage`] the host stores:
/// `prompt - cached -> input_tokens`, `cached -> cache_read_input_tokens`,
/// `completion -> output_tokens`.
impl From<&Usage> for SessionUsage {
    fn from(u: &Usage) -> Self {
        SessionUsage {
            input_tokens: Some(u.uncached_prompt_tokens()),
            output_tokens: Some(u.completion_tokens),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: Some(u.cached_tokens),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct UsageWire {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
    #[serde(default)]
    total_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prompt_tokens_details: Option<PromptTokensDetails>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PromptTokensDetails {
    #[serde(default)]
    cached_tokens: Option<u64>,
}

impl From<UsageWire> for Usage {
    fn from(w: UsageWire) -> Self {
        Usage {
            prompt_tokens: w.prompt_tokens.unwrap_or(0),
            completion_tokens: w.completion_tokens.unwrap_or(0),
            cached_tokens: w
                .prompt_tokens_details
                .and_then(|d| d.cached_tokens)
                .unwrap_or(0),
        }
    }
}

impl From<Usage> for UsageWire {
    fn from(u: Usage) -> Self {
        UsageWire {
            prompt_tokens: Some(u.prompt_tokens),
            completion_tokens: Some(u.completion_tokens),
            total_tokens: Some(u.total_tokens()),
            prompt_tokens_details: Some(PromptTokensDetails {
                cached_tokens: Some(u.cached_tokens),
            }),
        }
    }
}

/// Which text format a recovered tool call was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallFormat {
    /// `<tool_call>{"name":..,"arguments":..}</tool_call>` (Hermes, Qwen).
    Hermes,
    /// `[TOOL_CALLS][{...}]` or `[TOOL_CALLS]name[ARGS]{...}` (Mistral).
    Mistral,
    /// `<|python_tag|>{"name":..,"parameters":..}` (Llama 3.x).
    Llama,
    /// A fenced ```` ```json ```` block with a tool-call object.
    FencedJson,
    /// The whole message is a bare tool-call JSON object.
    BareJson,
}

/// A text tool call that was recognised but not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedToolCall {
    /// The name the model used (may be empty when unparseable).
    pub name: String,
    /// Why it was rejected (unknown tool, invalid JSON, ...).
    pub reason: String,
}

/// What the client's post-processing did to a response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostProcessReport {
    /// `<think>` content was moved out of `content` into `reasoning_content`.
    pub reasoning_extracted: bool,
    /// Tool calls recovered from text, and their format.
    pub recovered_format: Option<ToolCallFormat>,
    /// Number of tool calls recovered from text.
    pub recovered_tool_calls: usize,
    /// Text tool calls that were recognised but rejected.
    pub rejected_tool_calls: Vec<RejectedToolCall>,
    /// Server-parsed tool calls naming tools that were not offered
    /// (kept, so the agent can answer them with an error).
    pub unknown_tool_names: Vec<String>,
    /// Ids of tool calls whose `arguments` are not valid JSON (typically
    /// cut off by `max_tokens`). See [`ChatMessage::normalize_tool_arguments`].
    pub malformed_arguments: Vec<String>,
}

impl PostProcessReport {
    /// Whether post-processing changed or flagged anything.
    pub fn is_empty(&self) -> bool {
        *self == PostProcessReport::default()
    }
}

/// The result of a chat completion (first choice).
#[derive(Debug, Clone, PartialEq)]
pub struct ChatResponse {
    /// Server-assigned completion id.
    pub id: String,
    /// The model that actually served the request.
    pub model: String,
    /// The assistant message (after fallback tool-call parsing and
    /// `<think>` splitting).
    pub message: ChatMessage,
    /// Why generation stopped.
    pub finish_reason: Option<FinishReason>,
    /// Token usage (zero if the server did not report it).
    pub usage: Usage,
    /// What client-side post-processing did.
    pub postprocess: PostProcessReport,
}

impl ChatResponse {
    /// A response wrapping `message` (finish reason inferred, zero usage).
    /// Handy for tests and scripted backends.
    pub fn from_message(message: ChatMessage) -> Self {
        let finish_reason = if message.has_tool_calls() {
            FinishReason::ToolCalls
        } else {
            FinishReason::Stop
        };
        Self {
            id: String::new(),
            model: String::new(),
            message,
            finish_reason: Some(finish_reason),
            usage: Usage::default(),
            postprocess: PostProcessReport::default(),
        }
    }

    /// Whether the output was cut off by `max_tokens` / the context window.
    pub fn is_truncated(&self) -> bool {
        self.finish_reason == Some(FinishReason::Length)
    }

    /// Parse the message content as JSON (for `json_schema` requests).
    /// Leading/trailing whitespace and a surrounding Markdown code fence are
    /// tolerated.
    pub fn content_json(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_str(strip_code_fence(self.message.text()))
    }

    /// The token usage in the host's [`SessionUsage`] shape.
    pub fn session_usage(&self) -> SessionUsage {
        SessionUsage::from(&self.usage)
    }
}

/// Strip one surrounding Markdown code fence (```` ```json ... ``` ````).
pub(crate) fn strip_code_fence(s: &str) -> &str {
    let t = s.trim();
    let Some(rest) = t.strip_prefix("```") else {
        return t;
    };
    let Some(body) = rest.strip_suffix("```") else {
        return t;
    };
    // Drop the info string (e.g. `json`) on the first line.
    match body.find('\n') {
        Some(nl) => body[nl + 1..].trim(),
        None => body.trim(),
    }
}

/// Raw `chat.completion` object.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ChatCompletionWire {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub choices: Vec<ChoiceWire>,
    #[serde(default)]
    pub usage: Option<Usage>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ChoiceWire {
    #[serde(default)]
    pub index: u32,
    pub message: ChatMessage,
    #[serde(default)]
    pub finish_reason: Option<FinishReason>,
}

// ---------------------------------------------------------------------------
// Streaming chunks
// ---------------------------------------------------------------------------

/// One `chat.completion.chunk` SSE payload.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ChatCompletionChunk {
    /// Completion id (same for every chunk).
    #[serde(default)]
    pub id: String,
    /// Serving model.
    #[serde(default)]
    pub model: String,
    /// Choice deltas (empty in the final usage chunk).
    #[serde(default, deserialize_with = "de_null_default")]
    pub choices: Vec<ChunkChoice>,
    /// Present in the final chunk when `stream_options.include_usage` is set.
    #[serde(default)]
    pub usage: Option<Usage>,
}

/// One choice inside a [`ChatCompletionChunk`].
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ChunkChoice {
    /// Choice index (Talon only uses 0).
    #[serde(default)]
    pub index: u32,
    /// The incremental update.
    #[serde(default, deserialize_with = "de_null_default")]
    pub delta: ChunkDelta,
    /// Set on the last content chunk of the choice.
    #[serde(default)]
    pub finish_reason: Option<FinishReason>,
}

/// Incremental message update.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(from = "ChunkDeltaWire")]
pub struct ChunkDelta {
    /// Only in the first chunk.
    pub role: Option<Role>,
    /// Text delta.
    pub content: Option<String>,
    /// Reasoning delta (`reasoning_content` or `reasoning`).
    pub reasoning_content: Option<String>,
    /// Tool-call deltas.
    pub tool_calls: Vec<ToolCallDelta>,
}

#[derive(Deserialize)]
struct ChunkDeltaWire {
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<ToolCallDelta>>,
}

impl From<ChunkDeltaWire> for ChunkDelta {
    fn from(w: ChunkDeltaWire) -> Self {
        Self {
            role: w.role,
            content: w.content,
            reasoning_content: w.reasoning_content.or(w.reasoning),
            tool_calls: w.tool_calls.unwrap_or_default(),
        }
    }
}

/// Incremental tool-call update. The first delta of a call carries `id` and
/// `function.name`; following deltas append to `function.arguments`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ToolCallDelta {
    /// Position of the call in the final `tool_calls` array.
    #[serde(default)]
    pub index: Option<u32>,
    /// Call id (first delta only).
    #[serde(default)]
    pub id: Option<String>,
    /// Name / argument fragments.
    #[serde(default)]
    pub function: Option<FunctionDelta>,
}

/// Function fragment of a [`ToolCallDelta`].
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct FunctionDelta {
    /// Function name (first delta only).
    #[serde(default)]
    pub name: Option<String>,
    /// Arguments fragment.
    #[serde(default, deserialize_with = "de_opt_arguments")]
    pub arguments: Option<String>,
}

fn de_opt_arguments<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let v = Option::<Value>::deserialize(d)?;
    Ok(match v {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    })
}

fn de_null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Models / tokenize
// ---------------------------------------------------------------------------

/// One entry of `GET /v1/models`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Served model name.
    pub id: String,
    /// Owner (vLLM reports `vllm`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned_by: Option<String>,
    /// Unix creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    /// Underlying model path (vLLM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Context window (vLLM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_model_len: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ModelListWire {
    #[serde(default)]
    pub data: Vec<ModelInfo>,
}

/// Result of [`crate::VllmClient::tokenize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCount {
    /// Number of tokens.
    pub count: u64,
    /// Context window reported by vLLM, when known.
    pub max_model_len: Option<u64>,
    /// `true` when the count is a ~4 chars/token estimate because the
    /// server's `/tokenize` endpoint was unavailable.
    pub estimated: bool,
}

/// Rough token estimate (~4 characters per token, rounded up).
pub fn estimate_tokens(text: &str) -> u64 {
    let chars = text.chars().count() as u64;
    chars.div_ceil(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_serializes_vllm_extensions() {
        let spec = ToolSpec {
            name: "lookup".into(),
            description: "look up".into(),
            parameters: json!({"type":"object","properties":{"q":{"type":"string"}}}),
        };
        let req = ChatRequest::new(
            "qwen",
            vec![ChatMessage::system("s"), ChatMessage::user("u")],
        )
        .tools([&spec])
        .tool_choice(ToolChoice::Function("lookup".into()))
        .parallel_tool_calls(false)
        .temperature(0.7)
        .max_tokens(256)
        .enable_thinking(false)
        .json_schema("verdict", json!({"type":"object"}), true)
        .extra("top_k", json!(20));
        // Serialize like the client does (f32 -> shortest decimal), then inspect.
        let wire = serde_json::to_string(&req).unwrap();
        assert!(wire.contains("\"temperature\":0.7"), "{wire}");
        let v: Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(v["model"], "qwen");
        assert_eq!(v["tools"][0]["type"], "function");
        assert_eq!(v["tools"][0]["function"]["name"], "lookup");
        assert_eq!(v["tool_choice"]["function"]["name"], "lookup");
        assert_eq!(v["parallel_tool_calls"], false);
        assert_eq!(v["temperature"], json!(0.7));
        assert_eq!(v["chat_template_kwargs"]["enable_thinking"], false);
        assert_eq!(v["response_format"]["type"], "json_schema");
        assert_eq!(v["response_format"]["json_schema"]["name"], "verdict");
        assert_eq!(v["response_format"]["json_schema"]["strict"], true);
        assert_eq!(v["top_k"], 20);
        assert!(v.get("stream").is_none());
        assert!(v.get("stop").is_none());
        // Round-trips.
        let back: ChatRequest = serde_json::from_value(v).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn tool_choice_strings() {
        for (c, s) in [
            (ToolChoice::Auto, "auto"),
            (ToolChoice::None, "none"),
            (ToolChoice::Required, "required"),
        ] {
            assert_eq!(serde_json::to_value(&c).unwrap(), json!(s));
            let back: ToolChoice = serde_json::from_value(json!(s)).unwrap();
            assert_eq!(back, c);
        }
        assert!(serde_json::from_value::<ToolChoice>(json!("bogus")).is_err());
    }

    #[test]
    fn assistant_tool_call_message_serializes_null_content() {
        let m = ChatMessage::assistant_tool_calls(None, vec![ToolCall::new("c1", "f", "{}")]);
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["role"], "assistant");
        assert!(v["content"].is_null());
        assert_eq!(v["tool_calls"][0]["type"], "function");
        assert!(v.get("reasoning_content").is_none());
        let t = serde_json::to_value(ChatMessage::tool_result("c1", "ok")).unwrap();
        assert_eq!(t["tool_call_id"], "c1");
        assert_eq!(t["role"], "tool");
    }

    #[test]
    fn lenient_message_deserialization() {
        let m: ChatMessage = serde_json::from_value(json!({
            "role": "assistant",
            "content": [{"type":"text","text":"a"},{"type":"text","text":"b"}],
            "tool_calls": [{"id":"x","type":"function","function":{"name":"f","arguments":{"k":1}}}],
            "reasoning": "hmm"
        }))
        .unwrap();
        assert_eq!(m.text(), "ab");
        assert_eq!(m.tool_calls[0].function.arguments, r#"{"k":1}"#);
        assert_eq!(m.reasoning_content.as_deref(), Some("hmm"));

        let m: ChatMessage =
            serde_json::from_value(json!({"role":"assistant","content":null,"tool_calls":null}))
                .unwrap();
        assert!(m.content.is_none());
        assert!(m.tool_calls.is_empty());

        let m: ChatMessage =
            serde_json::from_value(json!({"role":"developer","content":"d"})).unwrap();
        assert_eq!(m.role, Role::System);
    }

    #[test]
    fn usage_maps_cached_tokens() {
        let u: Usage = serde_json::from_value(json!({
            "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
            "prompt_tokens_details": {"cached_tokens": 64}
        }))
        .unwrap();
        assert_eq!(u.cached_tokens, 64);
        let s = SessionUsage::from(&u);
        assert_eq!(s.input_tokens, Some(36));
        assert_eq!(s.cache_read_input_tokens, Some(64));
        assert_eq!(s.output_tokens, Some(20));
        assert_eq!(s.context_size(), 100);

        let u: Usage = serde_json::from_value(
            json!({"prompt_tokens": 5, "completion_tokens": 1, "prompt_tokens_details": null}),
        )
        .unwrap();
        assert_eq!(u.cached_tokens, 0);
        let mut total = Usage::default();
        total += u;
        total += u;
        assert_eq!(total.total_tokens(), 12);
        let v = serde_json::to_value(total).unwrap();
        assert_eq!(v["total_tokens"], 12);
    }

    #[test]
    fn finish_reason_parsing() {
        assert_eq!(FinishReason::parse("tool_calls"), FinishReason::ToolCalls);
        assert_eq!(FinishReason::parse("length"), FinishReason::Length);
        assert_eq!(
            FinishReason::parse("weird"),
            FinishReason::Other("weird".into())
        );
        let f: Option<FinishReason> = serde_json::from_value(json!(null)).unwrap();
        assert!(f.is_none());
    }

    #[test]
    fn chunk_parsing_handles_nulls_and_reasoning_alias() {
        let c: ChatCompletionChunk = serde_json::from_value(json!({
            "id": "c", "model": "m",
            "choices": [{"index":0,"delta":{"reasoning":"r","tool_calls":[{"index":0,"function":{"arguments":"{"}}]},"finish_reason":null}],
            "usage": null
        }))
        .unwrap();
        assert_eq!(c.choices[0].delta.reasoning_content.as_deref(), Some("r"));
        assert_eq!(
            c.choices[0].delta.tool_calls[0]
                .function
                .as_ref()
                .unwrap()
                .arguments
                .as_deref(),
            Some("{")
        );
        let c: ChatCompletionChunk =
            serde_json::from_value(json!({"choices": null, "usage": {"prompt_tokens": 3}}))
                .unwrap();
        assert!(c.choices.is_empty());
        assert_eq!(c.usage.unwrap().prompt_tokens, 3);
    }

    #[test]
    fn tool_definition_from_spec_defaults_schema() {
        let spec = ToolSpec {
            name: "t".into(),
            description: String::new(),
            parameters: Value::Null,
        };
        let d = ToolDefinition::from(&spec);
        assert_eq!(d.function.parameters["type"], "object");
        let v = serde_json::to_value(&d).unwrap();
        assert!(v["function"].get("description").is_none());
    }

    #[test]
    fn content_json_tolerates_fences() {
        let resp = ChatResponse {
            id: String::new(),
            model: String::new(),
            message: ChatMessage::assistant("```json\n{\"a\":1}\n```"),
            finish_reason: Some(FinishReason::Stop),
            usage: Usage::default(),
            postprocess: PostProcessReport::default(),
        };
        assert_eq!(resp.content_json().unwrap()["a"], 1);
        assert!(!resp.is_truncated());
        assert_eq!(strip_code_fence("  {\"b\":2} "), "{\"b\":2}");
    }

    #[test]
    fn parse_arguments_empty_is_object() {
        let c = ToolCall::new("1", "f", "  ");
        assert_eq!(c.parse_arguments().unwrap(), json!({}));
        let c = ToolCall::new("1", "f", "{\"x\":true}");
        assert_eq!(c.parse_arguments().unwrap()["x"], true);
        assert!(ToolCall::new("1", "f", "{").parse_arguments().is_err());
    }

    #[test]
    fn estimate_is_four_chars_per_token() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
    }
}
