//! Request policy applied by the gateway before forwarding to vLLM.
//!
//! vLLM accepts far more than the OpenAI schema: server-side chat template
//! overrides (`chat_template`, `chat_template_kwargs.chat_template`), media
//! parts whose URLs the vLLM host fetches (`image_url`, `input_audio`,
//! `video_url`, ...), grammar/regex guided decoding, `ignore_eos`,
//! `min_tokens`, `request_id`, logits processors, priorities, KV-transfer
//! internals, and new fields with every release. A denylist cannot keep up,
//! so the gateway works from **allowlists**: every request is rebuilt from
//! the fields below; anything else is dropped (counted in the gateway
//! stats and logged at `debug`), and allowed fields with a shape the
//! gateway does not accept are refused with `400`.
//!
//! The body is parsed once, filtered in place (values are moved, never
//! cloned) and serialized once by the caller.

use std::fmt;
use std::io;

use rand::RngCore;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Top-level fields forwarded for `POST /v1/chat/completions`. Everything
/// else is dropped.
///
/// - `model` — pinned to the allow-list.
/// - `messages` — roles `system`/`user`/`assistant`/`tool`; content is a
///   string or `text` parts only (media parts are refused: vLLM fetches
///   their URLs, i.e. SSRF from the vLLM host).
/// - `tools`, `tool_choice`, `parallel_tool_calls` — `function` tools only,
///   size-capped.
/// - `temperature`, `top_p`, `top_k`, `min_p`, `presence_penalty`,
///   `frequency_penalty`, `repetition_penalty`, `seed`, `stop` — plain
///   sampling knobs; none of them changes the amount of work per token
///   (`stop` is count/length-capped).
/// - `max_tokens`, `max_completion_tokens` — clamped to the configured cap.
/// - `n` — forced to `1`.
/// - `stream`, `stream_options` — `include_usage` is forced on.
/// - `response_format` — `text`, `json_object` or a size-capped
///   `json_schema` (no grammar / regex / structural-tag forms).
/// - `chat_template_kwargs` — `enable_thinking` (bool) only.
///
/// Deliberately **not** forwarded: `user` (unused by vLLM, ends up in its
/// logs), `logprobs`/`top_logprobs`/`logit_bias` (not needed by Talon),
/// `cache_salt` (a client value is ignored; the gateway sets its own per
/// label when `GatewayConfig::cache_salt` is on), and every vLLM extension
/// (`chat_template`, `guided_*`, `structured_outputs`, `ignore_eos`,
/// `min_tokens`, `request_id`, `priority`, `logits_processors`,
/// `vllm_xargs`, `kv_transfer_params`, `mm_processor_kwargs`, `documents`,
/// `continue_final_message`, `add_generation_prompt`, ...).
pub const CHAT_ALLOWED_FIELDS: [&str; 21] = [
    "model",
    "messages",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "presence_penalty",
    "frequency_penalty",
    "repetition_penalty",
    "seed",
    "stop",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "stream",
    "stream_options",
    "response_format",
    "chat_template_kwargs",
];

/// Top-level fields forwarded for vLLM `POST /tokenize`.
///
/// `model`, exactly one of `prompt` (string) or `messages` (validated like
/// chat), `add_special_tokens`, `add_generation_prompt`, plus `tools` and
/// `chat_template_kwargs` (validated like chat) so that
/// `VllmClient::tokenize_messages` counts the same prompt the chat
/// template will render. Everything else is dropped.
pub const TOKENIZE_ALLOWED_FIELDS: [&str; 7] = [
    "model",
    "prompt",
    "messages",
    "add_special_tokens",
    "add_generation_prompt",
    "tools",
    "chat_template_kwargs",
];

/// Cap on a `response_format.json_schema.schema` (serialized bytes).
/// Guided decoding compiles the schema into a grammar on the vLLM host.
pub const MAX_SCHEMA_BYTES: usize = 64 * 1024;

/// Cap on one tool definition (serialized bytes). With `tool_choice`
/// `required`/named or `strict`, its parameters become a grammar too.
pub const MAX_TOOL_DEFINITION_BYTES: usize = 64 * 1024;

/// Cap on the number of tools offered in one request.
pub const MAX_TOOLS: usize = 512;

/// Cap on stop sequences (each at most [`MAX_STOP_BYTES`]).
pub const MAX_STOP_SEQUENCES: usize = 16;

/// Cap on the length of one stop sequence.
pub const MAX_STOP_BYTES: usize = 1024;

/// Cap on the nesting depth of a JSON schema (response format or tool
/// parameters), relative to the schema root.
pub const MAX_SCHEMA_DEPTH: usize = 32;

/// Cap on JSON values in a request body, checked on the raw bytes before
/// parsing. A `serde_json::Value` costs 32+ bytes per node, so a 4 MiB body
/// of `[0,0,0,...]` would otherwise expand to ~100 MiB of host memory.
/// Real agent requests stay far below this (long histories are long
/// strings, not many values).
pub const MAX_JSON_NODES: usize = 128 * 1024;

/// How many dropped field names are kept per request for the debug log.
const MAX_RECORDED_DROPS: usize = 16;
/// Dropped field names are truncated to this many characters in logs.
const MAX_RECORDED_NAME_CHARS: usize = 64;

/// Whether `bytes` holds at most about `limit` JSON values: counts `[`,
/// `{`, `,` and `:` outside strings (one per container, element and
/// member). Linear, allocation-free.
pub(crate) fn json_nodes_within(bytes: &[u8], limit: usize) -> bool {
    let mut in_string = false;
    let mut escaped = false;
    let mut nodes: usize = 0;
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
            b'[' | b'{' | b',' | b':' => {
                nodes += 1;
                if nodes > limit {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Per-gateway secret from which each label's `cache_salt` is derived.
#[derive(Clone)]
pub(crate) struct CacheSaltKey([u8; 32]);

impl CacheSaltKey {
    /// A fresh random key (one per gateway process).
    pub(crate) fn random() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// `hex(SHA-256(domain || key || label))`: stable per label for the
    /// gateway's lifetime, unguessable without the key, so lanes never
    /// share vLLM prefix-cache blocks (no cross-lane timing side channel).
    pub(crate) fn salt(&self, label: &str) -> String {
        let mut h = Sha256::new();
        h.update(b"talon-llm-gateway/cache_salt/v1\0");
        h.update(self.0);
        h.update(label.as_bytes());
        hex::encode(h.finalize())
    }
}

impl fmt::Debug for CacheSaltKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CacheSaltKey(<redacted>)")
    }
}

/// What the gateway enforces on every request.
#[derive(Debug, Clone)]
pub(crate) struct RequestPolicy {
    pub allowed_models: Vec<String>,
    pub default_model: String,
    pub max_output_tokens_cap: Option<u32>,
    /// `Some` = set a per-label `cache_salt` on chat requests.
    pub cache_salt: Option<CacheSaltKey>,
}

/// What [`RequestPolicy::apply_chat`] / [`RequestPolicy::apply_tokenize`]
/// changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PolicyOutcome {
    /// The model that will be used upstream.
    pub model: String,
    /// The client asked for another (or no) model.
    pub model_rewritten: bool,
    /// `max_tokens` was lowered or inserted.
    pub max_tokens_clamped: bool,
    /// `stream: true`.
    pub stream: bool,
    /// Names of dropped fields (first [`MAX_RECORDED_DROPS`], truncated;
    /// nested ones as `parent.child`).
    pub dropped: Vec<String>,
    /// Total number of dropped fields.
    pub dropped_count: usize,
}

impl PolicyOutcome {
    fn drop_field(&mut self, parent: &str, key: &str) {
        self.dropped_count += 1;
        if self.dropped.len() < MAX_RECORDED_DROPS {
            let mut name = String::with_capacity(parent.len() + 1 + key.len().min(64));
            if !parent.is_empty() {
                name.push_str(parent);
                name.push('.');
            }
            name.extend(key.chars().take(MAX_RECORDED_NAME_CHARS));
            self.dropped.push(name);
        }
    }
}

type PolicyResult<T> = Result<T, String>;

impl RequestPolicy {
    /// Whether `model` may be used.
    pub(crate) fn is_allowed(&self, model: &str) -> bool {
        model == self.default_model || self.allowed_models.iter().any(|m| m == model)
    }

    /// Pin the requested model to the allow-list (unknown -> default).
    fn pin_model(&self, requested: Option<Value>, obj: &mut Map<String, Value>) -> (String, bool) {
        match requested {
            Some(Value::String(m)) if self.is_allowed(&m) => {
                obj.insert("model".into(), Value::String(m.clone()));
                (m, false)
            }
            _ => {
                obj.insert("model".into(), Value::String(self.default_model.clone()));
                (self.default_model.clone(), true)
            }
        }
    }

    /// Enforce the policy on a `/v1/chat/completions` body (in place).
    /// `label` selects the `cache_salt`.
    pub(crate) fn apply_chat(&self, body: &mut Value, label: &str) -> PolicyResult<PolicyOutcome> {
        let obj = body
            .as_object_mut()
            .ok_or_else(|| "request body must be a JSON object".to_string())?;
        let input = std::mem::take(obj);
        let mut out = PolicyOutcome::default();
        let mut requested_model = None;
        let mut n_present = false;
        let mut stream_options = None;

        for (key, value) in input {
            if value.is_null() {
                // `null` means "unset" for every allowed field.
                if !CHAT_ALLOWED_FIELDS.contains(&key.as_str()) && key != "cache_salt" {
                    out.drop_field("", &key);
                }
                continue;
            }
            match key.as_str() {
                "model" => requested_model = Some(value),
                "messages" => {
                    let v = check_messages(value, &mut out)?;
                    obj.insert(key, v);
                }
                "tools" => {
                    let v = check_tools(value, &mut out)?;
                    obj.insert(key, v);
                }
                "tool_choice" => {
                    let v = check_tool_choice(value)?;
                    obj.insert(key, v);
                }
                "parallel_tool_calls" | "stream" => {
                    expect_bool(&key, &value)?;
                    obj.insert(key, value);
                }
                "temperature" | "top_p" | "min_p" | "presence_penalty" | "frequency_penalty"
                | "repetition_penalty" => {
                    if !value.is_number() {
                        return Err(format!("`{key}` must be a number"));
                    }
                    obj.insert(key, value);
                }
                "top_k" | "seed" => {
                    if !(value.is_i64() || value.is_u64()) {
                        return Err(format!("`{key}` must be an integer"));
                    }
                    obj.insert(key, value);
                }
                "max_tokens" | "max_completion_tokens" => {
                    if !value.is_u64() {
                        return Err(format!("`{key}` must be a non-negative integer"));
                    }
                    obj.insert(key, value);
                }
                "stop" => {
                    let v = check_stop(value)?;
                    obj.insert(key, v);
                }
                "n" => n_present = true,
                "stream_options" => stream_options = Some(value),
                "response_format" => {
                    let v = check_response_format(value)?;
                    obj.insert(key, v);
                }
                "chat_template_kwargs" => {
                    if let Some(v) = check_chat_template_kwargs(value, &mut out)? {
                        obj.insert(key, v);
                    }
                }
                // Set by the gateway below; a client-chosen salt is ignored
                // silently (it is not a probe, just an OpenAI-compatible
                // client that knows the field).
                "cache_salt" => {}
                _ => out.drop_field("", &key),
            }
        }

        if !obj.get("messages").is_some_and(Value::is_array) {
            return Err("`messages` must be an array".into());
        }
        (out.model, out.model_rewritten) = self.pin_model(requested_model, obj);

        // One choice only: `n > 1` multiplies generation cost.
        if n_present {
            obj.insert("n".into(), json!(1));
        }

        let mut saw_limit = false;
        for key in ["max_tokens", "max_completion_tokens"] {
            let Some(n) = obj.get(key).and_then(Value::as_u64) else {
                continue;
            };
            saw_limit = true;
            if let Some(cap) = self.max_output_tokens_cap {
                if n > u64::from(cap) {
                    obj.insert(key.into(), json!(cap));
                    out.max_tokens_clamped = true;
                }
            }
        }
        if !saw_limit {
            if let Some(cap) = self.max_output_tokens_cap {
                obj.insert("max_tokens".into(), json!(cap));
                out.max_tokens_clamped = true;
            }
        }

        out.stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
        if out.stream {
            // Always ask for the usage chunk so usage can be accounted.
            let mut opts = Map::new();
            opts.insert("include_usage".into(), Value::Bool(true));
            if let Some(Value::Object(mut client)) = stream_options {
                if let Some(Value::Bool(b)) = client.remove("continuous_usage_stats") {
                    opts.insert("continuous_usage_stats".into(), Value::Bool(b));
                }
                for k in client.keys() {
                    if k != "include_usage" {
                        out.drop_field("stream_options", k);
                    }
                }
            }
            obj.insert("stream_options".into(), Value::Object(opts));
        }

        if let Some(key) = &self.cache_salt {
            obj.insert("cache_salt".into(), Value::String(key.salt(label)));
        }
        Ok(out)
    }

    /// Enforce the policy on a vLLM `/tokenize` body (in place).
    pub(crate) fn apply_tokenize(&self, body: &mut Value) -> PolicyResult<PolicyOutcome> {
        let obj = body
            .as_object_mut()
            .ok_or_else(|| "request body must be a JSON object".to_string())?;
        let input = std::mem::take(obj);
        let mut out = PolicyOutcome::default();
        let mut requested_model = None;
        for (key, value) in input {
            if value.is_null() {
                if !TOKENIZE_ALLOWED_FIELDS.contains(&key.as_str()) {
                    out.drop_field("", &key);
                }
                continue;
            }
            match key.as_str() {
                "model" => requested_model = Some(value),
                "prompt" => {
                    if !value.is_string() {
                        return Err("`prompt` must be a string".into());
                    }
                    obj.insert(key, value);
                }
                "messages" => {
                    let v = check_messages(value, &mut out)?;
                    obj.insert(key, v);
                }
                "add_special_tokens" | "add_generation_prompt" => {
                    expect_bool(&key, &value)?;
                    obj.insert(key, value);
                }
                "tools" => {
                    let v = check_tools(value, &mut out)?;
                    obj.insert(key, v);
                }
                "chat_template_kwargs" => {
                    if let Some(v) = check_chat_template_kwargs(value, &mut out)? {
                        obj.insert(key, v);
                    }
                }
                _ => out.drop_field("", &key),
            }
        }
        match (obj.contains_key("prompt"), obj.contains_key("messages")) {
            (true, true) => return Err("send either `prompt` or `messages`, not both".into()),
            (false, false) => return Err("`prompt` or `messages` is required".into()),
            _ => {}
        }
        (out.model, out.model_rewritten) = self.pin_model(requested_model, obj);
        Ok(out)
    }

    /// Keep only allowed models in a `/v1/models` listing.
    pub(crate) fn filter_models(&self, body: &mut Value) {
        if let Some(data) = body.get_mut("data").and_then(Value::as_array_mut) {
            data.retain(|m| {
                m.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| self.is_allowed(id))
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Field validators. Each takes the value by move and returns the (possibly
// rebuilt) value to forward; nothing is cloned.
// ---------------------------------------------------------------------------

fn expect_bool(key: &str, value: &Value) -> PolicyResult<()> {
    if value.is_boolean() {
        Ok(())
    } else {
        Err(format!("`{key}` must be a boolean"))
    }
}

fn expect_string_or_null(what: &str, value: &Value) -> PolicyResult<()> {
    if value.is_string() || value.is_null() {
        Ok(())
    } else {
        Err(format!("`{what}` must be a string"))
    }
}

/// `messages`: an array of objects with an allowed role and text content.
fn check_messages(value: Value, out: &mut PolicyOutcome) -> PolicyResult<Value> {
    let Value::Array(mut messages) = value else {
        return Err("`messages` must be an array".into());
    };
    for (i, message) in messages.iter_mut().enumerate() {
        check_message(i, message, out)?;
    }
    Ok(Value::Array(messages))
}

fn check_message(i: usize, message: &mut Value, out: &mut PolicyOutcome) -> PolicyResult<()> {
    let Value::Object(map) = message else {
        return Err(format!("`messages[{i}]` must be an object"));
    };
    let input = std::mem::take(map);
    let mut has_role = false;
    for (key, value) in input {
        match key.as_str() {
            "role" => {
                let ok = matches!(
                    value.as_str(),
                    Some("system" | "user" | "assistant" | "tool")
                );
                if !ok {
                    return Err(format!(
                        "`messages[{i}].role` must be system, user, assistant or tool"
                    ));
                }
                has_role = true;
                map.insert(key, value);
            }
            "content" => {
                let v = check_content(i, value)?;
                map.insert(key, v);
            }
            "name" | "tool_call_id" | "reasoning_content" => {
                expect_string_or_null(&format!("messages[{i}].{key}"), &value)?;
                if !value.is_null() {
                    map.insert(key, value);
                }
            }
            "tool_calls" => {
                if !value.is_null() {
                    let v = check_tool_calls(i, value, out)?;
                    map.insert(key, v);
                }
            }
            _ => out.drop_field("messages[]", &key),
        }
    }
    if !has_role {
        return Err(format!("`messages[{i}].role` is required"));
    }
    Ok(())
}

/// Content: a string, `null`, or an array of `{"type":"text","text":...}`
/// parts (rebuilt with just those two keys). Any other part type (images,
/// audio, video, files, embeddings, ...) is refused: vLLM would fetch the
/// URL or decode the payload on its host.
fn check_content(i: usize, value: Value) -> PolicyResult<Value> {
    match value {
        Value::Null | Value::String(_) => Ok(value),
        Value::Array(parts) => {
            let mut rebuilt = Vec::with_capacity(parts.len());
            for (j, part) in parts.into_iter().enumerate() {
                let Value::Object(mut part) = part else {
                    return Err(format!("`messages[{i}].content[{j}]` must be an object"));
                };
                if part.get("type").and_then(Value::as_str) != Some("text") {
                    return Err(format!(
                        "`messages[{i}].content[{j}]`: only `text` content parts are allowed"
                    ));
                }
                let Some(text @ Value::String(_)) = part.remove("text") else {
                    return Err(format!(
                        "`messages[{i}].content[{j}].text` must be a string"
                    ));
                };
                let mut clean = Map::new();
                clean.insert("type".into(), Value::String("text".into()));
                clean.insert("text".into(), text);
                rebuilt.push(Value::Object(clean));
            }
            Ok(Value::Array(rebuilt))
        }
        _ => Err(format!(
            "`messages[{i}].content` must be a string or an array of text parts"
        )),
    }
}

/// Assistant `tool_calls`: `{id, type: "function", function: {name, arguments}}`.
fn check_tool_calls(i: usize, value: Value, out: &mut PolicyOutcome) -> PolicyResult<Value> {
    let Value::Array(calls) = value else {
        return Err(format!("`messages[{i}].tool_calls` must be an array"));
    };
    let mut rebuilt = Vec::with_capacity(calls.len());
    for (j, call) in calls.into_iter().enumerate() {
        let what = format!("messages[{i}].tool_calls[{j}]");
        let Value::Object(call) = call else {
            return Err(format!("`{what}` must be an object"));
        };
        let mut clean = Map::new();
        for (key, value) in call {
            match key.as_str() {
                "id" => {
                    expect_string_or_null(&format!("{what}.id"), &value)?;
                    if !value.is_null() {
                        clean.insert(key, value);
                    }
                }
                "type" => {
                    if value.as_str() != Some("function") {
                        return Err(format!("`{what}.type` must be \"function\""));
                    }
                }
                "function" => {
                    let Value::Object(function) = value else {
                        return Err(format!("`{what}.function` must be an object"));
                    };
                    let mut f = Map::new();
                    for (fk, fv) in function {
                        match fk.as_str() {
                            "name" | "arguments" => {
                                if !fv.is_string() {
                                    return Err(format!("`{what}.function.{fk}` must be a string"));
                                }
                                f.insert(fk, fv);
                            }
                            _ => out.drop_field("messages[].tool_calls[].function", &fk),
                        }
                    }
                    if !f.contains_key("name") {
                        return Err(format!("`{what}.function.name` is required"));
                    }
                    clean.insert(key, Value::Object(f));
                }
                _ => out.drop_field("messages[].tool_calls[]", &key),
            }
        }
        if !clean.contains_key("function") {
            return Err(format!("`{what}.function` is required"));
        }
        clean.insert("type".into(), Value::String("function".into()));
        rebuilt.push(Value::Object(clean));
    }
    Ok(Value::Array(rebuilt))
}

/// `tools`: at most [`MAX_TOOLS`] `function` tools, each at most
/// [`MAX_TOOL_DEFINITION_BYTES`], parameters at most [`MAX_SCHEMA_DEPTH`] deep.
fn check_tools(value: Value, out: &mut PolicyOutcome) -> PolicyResult<Value> {
    let Value::Array(tools) = value else {
        return Err("`tools` must be an array".into());
    };
    if tools.len() > MAX_TOOLS {
        return Err(format!("at most {MAX_TOOLS} tools may be offered"));
    }
    let mut rebuilt = Vec::with_capacity(tools.len());
    for (i, tool) in tools.into_iter().enumerate() {
        let Value::Object(tool) = tool else {
            return Err(format!("`tools[{i}]` must be an object"));
        };
        let mut function = None;
        for (key, value) in tool {
            match key.as_str() {
                "type" => {
                    if value.as_str() != Some("function") {
                        return Err(format!("`tools[{i}].type` must be \"function\""));
                    }
                }
                "function" => function = Some(value),
                _ => out.drop_field("tools[]", &key),
            }
        }
        let Some(Value::Object(function)) = function else {
            return Err(format!("`tools[{i}].function` must be an object"));
        };
        let mut f = Map::new();
        for (key, value) in function {
            match key.as_str() {
                "name" => {
                    if !value.as_str().is_some_and(|s| !s.is_empty()) {
                        return Err(format!(
                            "`tools[{i}].function.name` must be a non-empty string"
                        ));
                    }
                    f.insert(key, value);
                }
                "description" => {
                    expect_string_or_null(&format!("tools[{i}].function.description"), &value)?;
                    if !value.is_null() {
                        f.insert(key, value);
                    }
                }
                "parameters" => {
                    if value.is_null() {
                        continue;
                    }
                    if !value.is_object() {
                        return Err(format!(
                            "`tools[{i}].function.parameters` must be an object"
                        ));
                    }
                    if depth(&value) > MAX_SCHEMA_DEPTH {
                        return Err(format!(
                            "`tools[{i}].function.parameters` is nested too deeply"
                        ));
                    }
                    f.insert(key, value);
                }
                "strict" => {
                    if !value.is_null() {
                        expect_bool(&format!("tools[{i}].function.strict"), &value)?;
                        f.insert(key, value);
                    }
                }
                _ => out.drop_field("tools[].function", &key),
            }
        }
        if !f.contains_key("name") {
            return Err(format!("`tools[{i}].function.name` is required"));
        }
        let mut clean = Map::new();
        clean.insert("type".into(), Value::String("function".into()));
        clean.insert("function".into(), Value::Object(f));
        let clean = Value::Object(clean);
        if !serialized_within(&clean, MAX_TOOL_DEFINITION_BYTES) {
            return Err(format!(
                "`tools[{i}]` exceeds {MAX_TOOL_DEFINITION_BYTES} bytes"
            ));
        }
        rebuilt.push(clean);
    }
    Ok(Value::Array(rebuilt))
}

/// `tool_choice`: `auto` / `none` / `required` or a named function.
fn check_tool_choice(value: Value) -> PolicyResult<Value> {
    match &value {
        Value::String(s) if matches!(s.as_str(), "auto" | "none" | "required") => Ok(value),
        Value::Object(o) if o.get("type").and_then(Value::as_str) == Some("function") => {
            match o
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
            {
                Some(name) if !name.is_empty() => Ok(json!({
                    "type": "function",
                    "function": {"name": name}
                })),
                _ => Err("`tool_choice.function.name` must be a non-empty string".into()),
            }
        }
        _ => Err(
            "`tool_choice` must be \"auto\", \"none\", \"required\" or a function choice".into(),
        ),
    }
}

/// `stop`: a string or up to [`MAX_STOP_SEQUENCES`] strings, each at most
/// [`MAX_STOP_BYTES`].
fn check_stop(value: Value) -> PolicyResult<Value> {
    let too_long = || format!("stop sequences are limited to {MAX_STOP_BYTES} bytes");
    match &value {
        Value::String(s) => {
            if s.len() > MAX_STOP_BYTES {
                return Err(too_long());
            }
        }
        Value::Array(items) => {
            if items.len() > MAX_STOP_SEQUENCES {
                return Err(format!(
                    "at most {MAX_STOP_SEQUENCES} stop sequences are allowed"
                ));
            }
            for item in items {
                let Some(s) = item.as_str() else {
                    return Err("`stop` must be a string or an array of strings".into());
                };
                if s.len() > MAX_STOP_BYTES {
                    return Err(too_long());
                }
            }
        }
        _ => return Err("`stop` must be a string or an array of strings".into()),
    }
    Ok(value)
}

/// `response_format`: `text`, `json_object`, or `json_schema` with a schema
/// of at most [`MAX_SCHEMA_BYTES`]. Grammar, regex, structural-tag and any
/// other forms are refused.
fn check_response_format(value: Value) -> PolicyResult<Value> {
    let Value::Object(mut rf) = value else {
        return Err("`response_format` must be an object".into());
    };
    match rf.get("type").and_then(Value::as_str) {
        Some("text") => Ok(json!({"type": "text"})),
        Some("json_object") => Ok(json!({"type": "json_object"})),
        Some("json_schema") => {
            let Some(Value::Object(spec)) = rf.remove("json_schema") else {
                return Err("`response_format.json_schema` must be an object".into());
            };
            let mut clean = Map::new();
            for (key, value) in spec {
                match key.as_str() {
                    "name" => {
                        if !value.is_string() {
                            return Err(
                                "`response_format.json_schema.name` must be a string".into()
                            );
                        }
                        clean.insert(key, value);
                    }
                    "description" => {
                        if value.is_string() {
                            clean.insert(key, value);
                        }
                    }
                    "strict" => {
                        if value.is_boolean() {
                            clean.insert(key, value);
                        }
                    }
                    "schema" => {
                        if !value.is_object() {
                            return Err(
                                "`response_format.json_schema.schema` must be an object".into()
                            );
                        }
                        if !serialized_within(&value, MAX_SCHEMA_BYTES) {
                            return Err(format!(
                                "`response_format.json_schema.schema` exceeds {MAX_SCHEMA_BYTES} bytes"
                            ));
                        }
                        if depth(&value) > MAX_SCHEMA_DEPTH {
                            return Err(
                                "`response_format.json_schema.schema` is nested too deeply".into(),
                            );
                        }
                        clean.insert(key, value);
                    }
                    _ => {}
                }
            }
            if !clean.contains_key("schema") {
                return Err("`response_format.json_schema.schema` is required".into());
            }
            if !clean.contains_key("name") {
                clean.insert("name".into(), Value::String("response".into()));
            }
            Ok(json!({"type": "json_schema", "json_schema": Value::Object(clean)}))
        }
        _ => Err("`response_format.type` must be text, json_object or json_schema".into()),
    }
}

/// `chat_template_kwargs`: only `enable_thinking` (bool) survives; anything
/// else (notably `chat_template`, which vLLM would render as Jinja) is
/// dropped. Returns `None` when nothing is left.
fn check_chat_template_kwargs(
    value: Value,
    out: &mut PolicyOutcome,
) -> PolicyResult<Option<Value>> {
    let Value::Object(kwargs) = value else {
        return Err("`chat_template_kwargs` must be an object".into());
    };
    let mut clean = Map::new();
    for (key, value) in kwargs {
        if key == "enable_thinking" {
            if value.is_null() {
                continue;
            }
            expect_bool("chat_template_kwargs.enable_thinking", &value)?;
            clean.insert(key, value);
        } else {
            out.drop_field("chat_template_kwargs", &key);
        }
    }
    Ok((!clean.is_empty()).then_some(Value::Object(clean)))
}

/// Nesting depth of `v` (a scalar is depth 0). Recursion is bounded by
/// serde_json's parse recursion limit (128).
fn depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Counts serialized bytes and fails once `limit` is exceeded, so checking
/// a size cap never allocates the serialization.
struct ByteBudget {
    remaining: usize,
}

impl io::Write for ByteBudget {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(buf.len())
            .ok_or_else(|| io::Error::other("size limit exceeded"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Whether `v` serializes to at most `limit` bytes.
fn serialized_within(v: &Value, limit: usize) -> bool {
    serde_json::to_writer(&mut ByteBudget { remaining: limit }, v).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(cap: Option<u32>) -> RequestPolicy {
        RequestPolicy {
            allowed_models: vec!["big".into(), "small".into()],
            default_model: "big".into(),
            max_output_tokens_cap: cap,
            cache_salt: None,
        }
    }

    fn chat(p: &RequestPolicy, mut b: Value) -> (Value, PolicyOutcome) {
        let o = p.apply_chat(&mut b, "lane").unwrap();
        (b, o)
    }

    fn user(text: &str) -> Value {
        json!([{"role": "user", "content": text}])
    }

    #[test]
    fn pins_models() {
        let p = policy(None);
        let (b, o) = chat(&p, json!({"model": "small", "messages": []}));
        assert_eq!(o.model, "small");
        assert!(!o.model_rewritten);
        assert_eq!(b["model"], "small");

        let (b, o) = chat(&p, json!({"model": "gpt-4-evil", "messages": []}));
        assert!(o.model_rewritten);
        assert_eq!(b["model"], "big");

        let (b, _) = chat(&p, json!({"messages": []}));
        assert_eq!(b["model"], "big");

        let (b, _) = chat(&p, json!({"model": 7, "messages": []}));
        assert_eq!(b["model"], "big");
    }

    #[test]
    fn clamps_and_inserts_max_tokens() {
        let p = policy(Some(1000));
        let (b, o) = chat(
            &p,
            json!({"messages": [], "max_tokens": 50000, "max_completion_tokens": 10}),
        );
        assert!(o.max_tokens_clamped);
        assert_eq!(b["max_tokens"], 1000);
        assert_eq!(b["max_completion_tokens"], 10);

        let (b, _) = chat(&p, json!({"messages": []}));
        assert_eq!(b["max_tokens"], 1000);

        let (b, o) = chat(&p, json!({"messages": [], "max_tokens": 10}));
        assert!(!o.max_tokens_clamped);
        assert_eq!(b["max_tokens"], 10);

        // `null` = unset: the cap is inserted.
        let (b, _) = chat(&p, json!({"messages": [], "max_tokens": null}));
        assert_eq!(b["max_tokens"], 1000);

        let mut b = json!({"messages": [], "max_tokens": -5});
        assert!(p.apply_chat(&mut b, "l").is_err());
        let mut b = json!({"messages": [], "max_tokens": "lots"});
        assert!(p.apply_chat(&mut b, "l").is_err());

        // No cap configured: untouched, nothing inserted.
        let (b, _) = chat(&policy(None), json!({"messages": [], "max_tokens": 50000}));
        assert_eq!(b["max_tokens"], 50000);
        let (b, _) = chat(&policy(None), json!({"messages": []}));
        assert!(b.get("max_tokens").is_none());
    }

    /// Everything the Mythos review got through the old denylist, plus the
    /// rest of vLLM's extension surface, is dropped.
    #[test]
    fn unknown_and_vllm_specific_fields_are_dropped() {
        let p = policy(None);
        let blocked = [
            ("chat_template", json!("{{ evil }}")),
            ("guided_regex", json!("(a+)+$")),
            ("guided_grammar", json!("root ::= \"x\"")),
            ("guided_json", json!({"type": "object"})),
            ("guided_choice", json!(["a", "b"])),
            ("guided_decoding_backend", json!("outlines")),
            ("structured_outputs", json!({"grammar": "root ::= \"x\""})),
            ("ignore_eos", json!(true)),
            ("min_tokens", json!(100000)),
            ("request_id", json!("victim-request")),
            ("logits_processors", json!(["os.system"])),
            ("best_of", json!(8)),
            ("use_beam_search", json!(true)),
            ("prompt_logprobs", json!(20)),
            ("priority", json!(-100)),
            ("kv_transfer_params", json!({"do_remote_prefill": true})),
            ("vllm_xargs", json!({"x": 1})),
            ("mm_processor_kwargs", json!({"x": 1})),
            ("documents", json!([{"text": "x"}])),
            ("continue_final_message", json!(true)),
            ("add_generation_prompt", json!(false)),
            ("echo", json!(true)),
            ("logprobs", json!(true)),
            ("top_logprobs", json!(20)),
            ("logit_bias", json!({"1": 100})),
            ("stop_token_ids", json!([1])),
            ("skip_special_tokens", json!(false)),
            ("return_tokens_as_token_ids", json!(true)),
            ("truncate_prompt_tokens", json!(1)),
            ("user", json!("x\ny")),
            ("functions", json!([])),
            ("tool_parser", json!("x")),
        ];
        let mut body = json!({"messages": user("hi")});
        for (k, v) in &blocked {
            body[*k] = v.clone();
        }
        let (b, o) = chat(&p, body);
        for (k, _) in &blocked {
            assert!(b.get(*k).is_none(), "{k} must be dropped");
        }
        assert_eq!(o.dropped_count, blocked.len());
        assert_eq!(o.dropped.len(), MAX_RECORDED_DROPS);
        let mut keys: Vec<&str> = b.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["messages", "model"]);
        // Every allowlisted field is known to the validator (none is
        // silently dropped as "unknown").
        for k in CHAT_ALLOWED_FIELDS.iter().filter(|k| **k != "messages") {
            let mut body = json!({"messages": []});
            body[*k] = Value::Null;
            assert_eq!(chat(&p, body).1.dropped_count, 0, "{k}");
        }
    }

    #[test]
    fn allowed_fields_pass_unchanged() {
        let p = policy(Some(4096));
        let tools = json!([{"type": "function", "function": {
            "name": "get_weather", "description": "w", "strict": true,
            "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
        }}]);
        let rf = json!({"type": "json_schema", "json_schema": {
            "name": "report", "strict": true, "schema": {"type": "object"}
        }});
        let body = json!({
            "model": "small",
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]},
                {"role": "assistant", "content": null, "reasoning_content": "think",
                 "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": "c1", "name": "get_weather", "content": "sunny"}
            ],
            "tools": tools,
            "tool_choice": {"type": "function", "function": {"name": "get_weather"}},
            "parallel_tool_calls": true,
            "temperature": 0.6, "top_p": 0.95, "top_k": 20, "min_p": 0.0,
            "presence_penalty": 0.5, "frequency_penalty": 0.1, "repetition_penalty": 1.05,
            "seed": 42, "stop": ["</s>", "END"],
            "max_tokens": 100, "max_completion_tokens": 200,
            "n": 1, "stream": false,
            "response_format": rf,
            "chat_template_kwargs": {"enable_thinking": false}
        });
        let expected = body.clone();
        let (b, o) = chat(&p, body);
        assert_eq!(o.dropped_count, 0, "{:?}", o.dropped);
        assert_eq!(b, expected);
    }

    #[test]
    fn chat_template_kwargs_keep_only_enable_thinking() {
        let p = policy(None);
        let (b, o) = chat(
            &p,
            json!({"messages": [], "chat_template_kwargs": {
                "enable_thinking": true, "chat_template": "{% for x in range(10**9) %}{% endfor %}",
                "tokenize": true, "documents": []
            }}),
        );
        assert_eq!(b["chat_template_kwargs"], json!({"enable_thinking": true}));
        assert_eq!(o.dropped_count, 3);
        assert!(
            o.dropped
                .contains(&"chat_template_kwargs.chat_template".to_string())
        );

        let (b, _) = chat(
            &p,
            json!({"messages": [], "chat_template_kwargs": {"chat_template": "x"}}),
        );
        assert!(
            b.get("chat_template_kwargs").is_none(),
            "empty kwargs removed"
        );

        for bad in [
            json!({"messages": [], "chat_template_kwargs": {"enable_thinking": "yes"}}),
            json!({"messages": [], "chat_template_kwargs": "x"}),
        ] {
            let mut bad = bad;
            assert!(p.apply_chat(&mut bad, "l").is_err());
        }
    }

    #[test]
    fn media_and_unknown_content_parts_are_refused() {
        let p = policy(None);
        let parts = [
            json!({"type": "image_url", "image_url": {"url": "http://169.254.169.254/latest/meta-data/"}}),
            json!({"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}}),
            json!({"type": "audio_url", "audio_url": {"url": "http://10.0.0.1/a.wav"}}),
            json!({"type": "video_url", "video_url": {"url": "file:///etc/passwd"}}),
            json!({"type": "image_embeds", "image_embeds": "AAAA"}),
            json!({"type": "image_pil", "image_pil": "x"}),
            json!({"type": "file", "file": {"file_id": "x"}}),
            json!({"type": "input_image", "image_url": "http://x"}),
            json!({"image_url": {"url": "http://x"}}),
            json!({"type": "text"}),
            json!({"type": "text", "text": 5}),
            json!("bare string part"),
        ];
        for part in parts {
            let mut b = json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "ok"}, part.clone()]}]});
            assert!(p.apply_chat(&mut b, "l").is_err(), "{part}");
        }
        // Extra keys on a text part are removed (vLLM must never see a URL).
        let (b, _) = chat(
            &p,
            json!({"messages": [{"role": "user", "content": [
                {"type": "text", "text": "hi", "image_url": {"url": "http://169.254.169.254/"}}
            ]}]}),
        );
        assert_eq!(
            b["messages"][0]["content"],
            json!([{"type": "text", "text": "hi"}])
        );
        let mut b = json!({"messages": [{"role": "user", "content": {"type": "text"}}]});
        assert!(p.apply_chat(&mut b, "l").is_err());
    }

    #[test]
    fn roles_and_message_fields() {
        let p = policy(None);
        for role in ["developer", "function", "ipython", "System", ""] {
            let mut b = json!({"messages": [{"role": role, "content": "x"}]});
            assert!(p.apply_chat(&mut b, "l").is_err(), "{role}");
        }
        let mut b = json!({"messages": [{"content": "x"}]});
        assert!(p.apply_chat(&mut b, "l").is_err(), "role required");
        let mut b = json!({"messages": ["x"]});
        assert!(p.apply_chat(&mut b, "l").is_err());
        let mut b = json!({"messages": [{"role": "assistant", "tool_calls": [{"type": "code", "function": {"name": "x"}}]}]});
        assert!(p.apply_chat(&mut b, "l").is_err());
        let mut b = json!({"messages": [{"role": "assistant", "tool_calls": [{"function": {"name": "x", "arguments": {"a": 1}}}]}]});
        assert!(p.apply_chat(&mut b, "l").is_err());

        let (b, o) = chat(
            &p,
            json!({"messages": [{"role": "user", "content": "x", "audio": {"id": "a"}, "chat_template": "y",
                "tool_calls": [{"function": {"name": "f", "arguments": "{}", "extra": 1}, "index": 0}]}]}),
        );
        assert_eq!(
            b["messages"][0],
            json!({"role": "user", "content": "x",
                "tool_calls": [{"type": "function", "function": {"name": "f", "arguments": "{}"}}]})
        );
        assert_eq!(o.dropped_count, 4);
    }

    #[test]
    fn response_format_forms() {
        let p = policy(None);
        for rf in [
            json!({"type": "grammar", "grammar": "root ::= \"x\""}),
            json!({"type": "regex", "regex": "(a+)+$"}),
            json!({"type": "structural_tag", "structures": []}),
            json!({"type": "json_schema"}),
            json!({"type": "json_schema", "json_schema": {"name": "x"}}),
            json!({"type": "json_schema", "json_schema": {"name": "x", "schema": "s"}}),
            json!({"json_schema": {"schema": {}}}),
            json!("json_object"),
        ] {
            let mut b = json!({"messages": [], "response_format": rf.clone()});
            assert!(p.apply_chat(&mut b, "l").is_err(), "{rf}");
        }
        let (b, _) = chat(
            &p,
            json!({"messages": [], "response_format": {"type": "json_object", "grammar": "x"}}),
        );
        assert_eq!(b["response_format"], json!({"type": "json_object"}));
        let (b, _) = chat(
            &p,
            json!({"messages": [], "response_format": {"type": "json_schema", "json_schema": {
            "schema": {"type": "object"}, "backend": "outlines"}}}),
        );
        assert_eq!(
            b["response_format"],
            json!({"type": "json_schema", "json_schema": {"name": "response", "schema": {"type": "object"}}})
        );

        let big = json!({"type": "object", "description": "x".repeat(MAX_SCHEMA_BYTES)});
        let mut b = json!({"messages": [], "response_format": {"type": "json_schema", "json_schema": {"name": "x", "schema": big}}});
        assert!(p.apply_chat(&mut b, "l").is_err());

        let mut deep = json!({"type": "string"});
        for _ in 0..MAX_SCHEMA_DEPTH {
            deep = json!({"type": "array", "items": deep});
        }
        let mut b = json!({"messages": [], "response_format": {"type": "json_schema", "json_schema": {"name": "x", "schema": deep}}});
        assert!(p.apply_chat(&mut b, "l").is_err());
    }

    #[test]
    fn tool_definitions() {
        let p = policy(None);
        for tools in [
            json!([{"type": "code_interpreter"}]),
            json!([{"type": "retrieval", "function": {"name": "x"}}]),
            json!([{"type": "function"}]),
            json!([{"type": "function", "function": {"name": ""}}]),
            json!([{"type": "function", "function": {"name": "x", "parameters": "s"}}]),
            json!([{"type": "function", "function": {"name": "x", "parameters": {"description": "x".repeat(MAX_TOOL_DEFINITION_BYTES)}}}]),
            json!({"type": "function"}),
        ] {
            let mut b = json!({"messages": [], "tools": tools.clone()});
            assert!(p.apply_chat(&mut b, "l").is_err(), "{tools}");
        }
        let many: Vec<Value> = (0..=MAX_TOOLS)
            .map(|i| json!({"type": "function", "function": {"name": format!("t{i}")}}))
            .collect();
        let mut b = json!({"messages": [], "tools": many});
        assert!(p.apply_chat(&mut b, "l").is_err());

        let (b, o) = chat(
            &p,
            json!({"messages": [], "tools": [{"type": "function", "x": 1,
                "function": {"name": "f", "parameters": {"type": "object"}, "chat_template": "x"}}]}),
        );
        assert_eq!(
            b["tools"],
            json!([{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}])
        );
        assert_eq!(o.dropped_count, 2);
        // A missing `type` defaults to `function` (as in vLLM) and is made explicit.
        let (b, _) = chat(
            &p,
            json!({"messages": [], "tools": [{"function": {"name": "f"}}]}),
        );
        assert_eq!(
            b["tools"],
            json!([{"type": "function", "function": {"name": "f"}}])
        );

        for choice in [
            json!("any"),
            json!({"type": "function"}),
            json!(3),
            json!({"type": "x", "function": {"name": "f"}}),
        ] {
            let mut b = json!({"messages": [], "tool_choice": choice.clone()});
            assert!(p.apply_chat(&mut b, "l").is_err(), "{choice}");
        }
        let (b, _) = chat(
            &p,
            json!({"messages": [], "tool_choice": {"type": "function", "function": {"name": "f", "x": 1}, "y": 2}}),
        );
        assert_eq!(
            b["tool_choice"],
            json!({"type": "function", "function": {"name": "f"}})
        );
    }

    #[test]
    fn scalar_types_and_stop_are_checked() {
        let p = policy(None);
        for (k, v) in [
            ("temperature", json!("hot")),
            ("top_p", json!(true)),
            ("top_k", json!(1.5)),
            ("seed", json!("1")),
            ("stream", json!("yes")),
            ("parallel_tool_calls", json!(1)),
            ("stop", json!(5)),
            ("stop", json!([1])),
            ("stop", json!(vec!["x"; MAX_STOP_SEQUENCES + 1])),
            ("stop", json!("x".repeat(MAX_STOP_BYTES + 1))),
        ] {
            let mut b = json!({"messages": []});
            b[k] = v.clone();
            assert!(p.apply_chat(&mut b, "l").is_err(), "{k}={v}");
        }
        let (b, _) = chat(&p, json!({"messages": [], "stop": "END", "top_k": -1}));
        assert_eq!(b["stop"], "END");
        assert_eq!(b["top_k"], -1);
    }

    #[test]
    fn forces_single_choice() {
        let p = policy(None);
        let (b, _) = chat(&p, json!({"messages": [], "n": 5}));
        assert_eq!(b["n"], 1);
        let (b, _) = chat(&p, json!({"messages": [], "n": "many"}));
        assert_eq!(b["n"], 1);
    }

    #[test]
    fn streaming_forces_usage() {
        let p = policy(None);
        let (b, o) = chat(&p, json!({"messages": [], "stream": true}));
        assert!(o.stream);
        assert_eq!(b["stream_options"], json!({"include_usage": true}));
        let (b, o) = chat(
            &p,
            json!({"messages": [], "stream": true, "stream_options": {
                "include_usage": false, "continuous_usage_stats": true, "x": 1}}),
        );
        assert_eq!(
            b["stream_options"],
            json!({"include_usage": true, "continuous_usage_stats": true})
        );
        assert_eq!(o.dropped, vec!["stream_options.x".to_string()]);
        // Not streaming: stream_options would only make vLLM return 400.
        let (b, _) = chat(
            &p,
            json!({"messages": [], "stream_options": {"include_usage": true}}),
        );
        assert!(b.get("stream_options").is_none());
    }

    #[test]
    fn cache_salt_is_per_label_and_overrides_the_client() {
        let mut p = policy(None);
        let mut b = json!({"messages": [], "cache_salt": "mine"});
        p.apply_chat(&mut b, "a").unwrap();
        assert!(
            b.get("cache_salt").is_none(),
            "disabled: client salt dropped too"
        );

        p.cache_salt = Some(CacheSaltKey::random());
        let salt = |p: &RequestPolicy, label: &str| {
            let mut b = json!({"messages": [], "cache_salt": "attacker-chosen"});
            let o = p.apply_chat(&mut b, label).unwrap();
            assert_eq!(o.dropped_count, 0);
            b["cache_salt"].as_str().unwrap().to_string()
        };
        let a1 = salt(&p, "a");
        assert_eq!(a1.len(), 64);
        assert!(a1.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a1, salt(&p, "a"), "stable per label");
        assert_ne!(a1, salt(&p, "b"), "different per label");
        let other = RequestPolicy {
            cache_salt: Some(CacheSaltKey::random()),
            ..policy(None)
        };
        assert_ne!(a1, salt(&other, "a"), "keyed per gateway");
        assert!(
            !format!("{:?}", p.cache_salt).contains(&hex::encode(p.cache_salt.as_ref().unwrap().0))
        );
    }

    #[test]
    fn rejects_non_objects() {
        let p = policy(None);
        assert!(p.apply_chat(&mut json!([1]), "l").is_err());
        assert!(p.apply_chat(&mut json!({"model": "big"}), "l").is_err());
        assert!(p.apply_chat(&mut json!({"messages": null}), "l").is_err());
        assert!(p.apply_chat(&mut json!({"messages": {}}), "l").is_err());
    }

    #[test]
    fn tokenize_allowlist() {
        let p = policy(None);
        assert!(p.apply_tokenize(&mut json!("x")).is_err());
        assert!(p.apply_tokenize(&mut json!({"model": "big"})).is_err());
        assert!(
            p.apply_tokenize(&mut json!({"prompt": "a", "messages": user("b")}))
                .is_err()
        );
        assert!(p.apply_tokenize(&mut json!({"prompt": ["a"]})).is_err());
        assert!(
            p.apply_tokenize(&mut json!({"messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "http://169.254.169.254/"}}]}]}))
                .is_err()
        );

        let mut t = json!({"model": "nope", "prompt": "hi", "add_special_tokens": false,
            "chat_template": "x", "return_token_strs": true, "mm_processor_kwargs": {}});
        let o = p.apply_tokenize(&mut t).unwrap();
        assert_eq!(o.model, "big");
        assert_eq!(
            t,
            json!({"model": "big", "prompt": "hi", "add_special_tokens": false})
        );
        assert_eq!(o.dropped_count, 3);

        let mut t = json!({"model": "small", "messages": user("x"), "add_generation_prompt": true,
            "tools": [{"type": "function", "function": {"name": "f"}}],
            "chat_template_kwargs": {"enable_thinking": false, "chat_template": "x"},
            "continue_final_message": true});
        let o = p.apply_tokenize(&mut t).unwrap();
        assert_eq!(o.model, "small");
        assert_eq!(t["chat_template_kwargs"], json!({"enable_thinking": false}));
        assert!(t.get("continue_final_message").is_none());
        assert_eq!(t["tools"][0]["function"]["name"], "f");
        assert_eq!(o.dropped_count, 2);
    }

    #[test]
    fn filters_model_listing() {
        let p = policy(None);
        let mut list = json!({"object":"list","data":[{"id":"big"},{"id":"secret-internal"},{"id":"small"},{"nope":1}]});
        p.filter_models(&mut list);
        let ids: Vec<&str> = list["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["big", "small"]);
    }

    #[test]
    fn json_node_budget() {
        assert!(json_nodes_within(b"{}", 1));
        assert!(!json_nodes_within(b"{}", 0));
        assert!(json_nodes_within(br#"{"a":1}"#, 2));
        assert!(!json_nodes_within(br#"{"a":1}"#, 1));
        // Structural characters inside strings (and escaped quotes) are not counted.
        assert!(json_nodes_within(br#""[,{:\"[,{:\\""#, 0));
        assert!(json_nodes_within(br#""\\"[,"#, 2));
        assert!(!json_nodes_within(br#""\\"[,"#, 1));
        let flat = format!("[{}0]", "0,".repeat(1000));
        assert!(json_nodes_within(flat.as_bytes(), 1001));
        assert!(!json_nodes_within(flat.as_bytes(), 1000));
    }

    #[test]
    fn serialized_size_budget() {
        let v = json!({"a": "x".repeat(100)});
        let len = serde_json::to_vec(&v).unwrap().len();
        assert!(serialized_within(&v, len));
        assert!(!serialized_within(&v, len - 1));
        assert_eq!(depth(&json!(1)), 0);
        assert_eq!(depth(&json!({"a": [1]})), 2);
    }
}
