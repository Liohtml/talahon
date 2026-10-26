//! OpenAI chat ⇄ Anthropic Messages translation (non-streaming).
//!
//! Input is the request body **after** the gateway policy: fields are
//! already allow-listed, the model pinned, `max_tokens` clamped, schemas
//! sanitized. This module only changes shape.

use serde_json::{Map, Value, json};

use super::{THINKING_MARKER_CLOSE, THINKING_MARKER_OPEN};

/// Hard ceiling when the client sent no `max_tokens` (the policy normally
/// inserts its cap first; the Messages API requires the field).
pub const DEFAULT_MAX_TOKENS: u64 = 16_384;

/// Host-side switches for the translation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Allow adaptive thinking (`TALON_ANTHROPIC_THINKING`). The request's
    /// `chat_template_kwargs.enable_thinking: false` still turns it off.
    pub thinking: bool,
}

/// A translated request.
#[derive(Debug, Clone, PartialEq)]
pub struct Translated {
    /// The `POST /v1/messages` body.
    pub body: Value,
    /// `stream: true` was requested.
    pub stream: bool,
    /// The model sent upstream.
    pub model: String,
}

/// Translate a policy-filtered `chat/completions` body.
///
/// # Errors
/// A body the Messages API cannot represent (no messages, a `tool` message
/// without `tool_call_id`, ...). The text is safe to return to the client.
pub fn request(body: &Value, opts: Options) -> Result<Translated, String> {
    let obj = body
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_string())?;
    let model = obj
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .ok_or_else(|| "`model` is missing".to_string())?
        .to_string();
    let messages = obj
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "`messages` must be an array".to_string())?;

    let mut out = Map::new();
    out.insert("model".into(), Value::String(model.clone()));

    let (system, turns) = convert_messages(messages)?;
    let mut system = system;
    if let Some(Value::Object(rf)) = obj.get("response_format") {
        match rf.get("type").and_then(Value::as_str) {
            Some("json_schema") => {
                if let Some(schema) = rf.get("json_schema").and_then(|j| j.get("schema")) {
                    out.insert(
                        "output_config".into(),
                        json!({"format": {"type": "json_schema", "schema": schema.clone()}}),
                    );
                }
            }
            Some("json_object") => {
                system.push("Respond with a single JSON object and nothing else.".to_string())
            }
            _ => {}
        }
    }
    if !system.is_empty() {
        out.insert("system".into(), system_blocks(&system));
    }
    if turns.is_empty() {
        return Err("`messages` must contain at least one user message".into());
    }
    out.insert("messages".into(), Value::Array(turns));

    let max_tokens = ["max_tokens", "max_completion_tokens"]
        .iter()
        .find_map(|k| obj.get(*k).and_then(Value::as_u64))
        .unwrap_or(DEFAULT_MAX_TOKENS)
        .max(1);
    out.insert("max_tokens".into(), json!(max_tokens));

    match obj.get("stop") {
        Some(Value::String(s)) if !s.is_empty() => {
            out.insert("stop_sequences".into(), json!([s]));
        }
        Some(Value::Array(a)) if !a.is_empty() => {
            out.insert("stop_sequences".into(), Value::Array(a.clone()));
        }
        _ => {}
    }

    if let Some(Value::Array(tools)) = obj.get("tools") {
        let converted: Vec<Value> = tools.iter().filter_map(convert_tool).collect();
        if !converted.is_empty() {
            out.insert("tools".into(), Value::Array(converted));
            let parallel = obj
                .get("parallel_tool_calls")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if let Some(choice) = convert_tool_choice(obj.get("tool_choice"), parallel) {
                out.insert("tool_choice".into(), choice);
            }
        }
    }

    let requested_thinking = obj
        .get("chat_template_kwargs")
        .and_then(|k| k.get("enable_thinking"))
        .and_then(Value::as_bool);
    if opts.thinking && requested_thinking != Some(false) {
        out.insert("thinking".into(), json!({"type": "adaptive"}));
    }

    let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
    if stream {
        out.insert("stream".into(), Value::Bool(true));
    }
    // `temperature`, `top_p`, `top_k`, penalties, `seed`, `n`,
    // `stream_options`, `cache_salt`: no equivalent, or rejected by current
    // Claude models. Dropped on purpose.
    Ok(Translated {
        body: Value::Object(out),
        stream,
        model,
    })
}

/// A `POST /v1/messages/count_tokens` body for a vLLM-style `/tokenize`
/// request (`{model, messages, tools?, chat_template_kwargs?}` or
/// `{model, prompt}`).
///
/// # Errors
/// See [`request`].
pub fn count_tokens_request(body: &Value, opts: Options) -> Result<Value, String> {
    let mut body = body.clone();
    if let Some(obj) = body.as_object_mut() {
        if let Some(prompt) = obj.remove("prompt") {
            // Plain-text tokenize: count it as one user message.
            obj.insert(
                "messages".into(),
                json!([{"role": "user", "content": prompt}]),
            );
        }
        obj.remove("stream");
    }
    let mut translated = request(&body, opts)?.body;
    if let Some(obj) = translated.as_object_mut() {
        for key in ["max_tokens", "stop_sequences", "stream", "output_config"] {
            obj.remove(key);
        }
    }
    Ok(translated)
}

/// Translate a Messages API response into a `chat.completion` object.
pub fn response(message: &Value, created: u64) -> Value {
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    let mut thinking_text = String::new();
    let mut thinking_blocks = Vec::new();
    if let Some(blocks) = message.get("content").and_then(Value::as_array) {
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(Value::as_str) {
                        text.push_str(t);
                    }
                }
                Some("tool_use") => tool_calls.push(tool_call_from_use(
                    block.get("id").and_then(Value::as_str).unwrap_or_default(),
                    block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    &block
                        .get("input")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Map::new()))
                        .to_string(),
                )),
                Some("thinking") => {
                    if let Some(t) = block.get("thinking").and_then(Value::as_str) {
                        thinking_text.push_str(t);
                    }
                    thinking_blocks.push(block.clone());
                }
                Some("redacted_thinking") => thinking_blocks.push(block.clone()),
                _ => {}
            }
        }
    }
    let stop_reason = message.get("stop_reason").and_then(Value::as_str);
    let finish_reason = finish_reason(stop_reason, !tool_calls.is_empty());

    let mut msg = Map::new();
    msg.insert("role".into(), json!("assistant"));
    msg.insert(
        "content".into(),
        if text.is_empty() && !tool_calls.is_empty() {
            Value::Null
        } else {
            Value::String(text)
        },
    );
    if !tool_calls.is_empty() {
        msg.insert("tool_calls".into(), Value::Array(tool_calls));
    }
    if let Some(r) = reasoning_content(&thinking_text, &thinking_blocks) {
        msg.insert("reasoning_content".into(), Value::String(r));
    }

    json!({
        "id": message.get("id").cloned().unwrap_or_else(|| json!("msg")),
        "object": "chat.completion",
        "created": created,
        "model": message.get("model").cloned().unwrap_or(Value::Null),
        "choices": [{
            "index": 0,
            "message": Value::Object(msg),
            "finish_reason": finish_reason,
        }],
        "usage": usage(message.get("usage")),
    })
}

/// OpenAI-style `finish_reason` for a `stop_reason`.
pub fn finish_reason(stop_reason: Option<&str>, has_tool_calls: bool) -> &'static str {
    match stop_reason {
        Some("tool_use") => "tool_calls",
        Some("max_tokens") => "length",
        Some("refusal") => "content_filter",
        Some("end_turn" | "stop_sequence" | "pause_turn") | None => {
            if has_tool_calls {
                "tool_calls"
            } else {
                "stop"
            }
        }
        Some(_) => "stop",
    }
}

/// OpenAI-style `usage` from a Messages API `usage` object. Cached and
/// cache-creation tokens are part of the prompt; the cache hits are
/// reported as `prompt_tokens_details.cached_tokens` like vLLM does.
pub fn usage(usage: Option<&Value>) -> Value {
    let get = |k: &str| {
        usage
            .and_then(|u| u.get(k))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let cached = get("cache_read_input_tokens");
    let prompt = get("input_tokens")
        .saturating_add(cached)
        .saturating_add(get("cache_creation_input_tokens"));
    let completion = get("output_tokens");
    json!({
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt.saturating_add(completion),
        "prompt_tokens_details": {"cached_tokens": cached},
    })
}

/// A `tool_calls` entry.
pub fn tool_call_from_use(id: &str, name: &str, arguments: &str) -> Value {
    json!({
        "id": id,
        "type": "function",
        "function": {"name": name, "arguments": arguments},
    })
}

/// `reasoning_content` carrying readable thinking text plus the opaque,
/// signed blocks for replay. `None` when there was no thinking.
pub fn reasoning_content(text: &str, blocks: &[Value]) -> Option<String> {
    if blocks.is_empty() {
        return if text.is_empty() {
            None
        } else {
            Some(text.to_string())
        };
    }
    let encoded = hex::encode(Value::Array(blocks.to_vec()).to_string());
    let mut out = String::with_capacity(text.len() + encoded.len() + 40);
    out.push_str(text);
    if !text.is_empty() {
        out.push('\n');
    }
    out.push_str(THINKING_MARKER_OPEN);
    out.push_str(&encoded);
    out.push_str(THINKING_MARKER_CLOSE);
    Some(out)
}

/// Signed thinking blocks hidden in `reasoning_content` by
/// [`reasoning_content`]; empty when there is no (valid) marker.
pub fn thinking_blocks(reasoning: &str) -> Vec<Value> {
    let Some(start) = reasoning.find(THINKING_MARKER_OPEN) else {
        return Vec::new();
    };
    let inner = &reasoning[start + THINKING_MARKER_OPEN.len()..];
    let Some(end) = inner.find(THINKING_MARKER_CLOSE) else {
        return Vec::new();
    };
    hex::decode(&inner[..end])
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|b| {
            matches!(
                b.get("type").and_then(Value::as_str),
                Some("thinking" | "redacted_thinking")
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Returns the system texts and the user/assistant turns (alternating,
/// same-role neighbours merged).
fn convert_messages(messages: &[Value]) -> Result<(Vec<String>, Vec<Value>), String> {
    let mut system = Vec::new();
    let mut turns: Vec<(&'static str, Vec<Value>)> = Vec::new();
    let mut push = |role: &'static str, blocks: Vec<Value>| {
        if blocks.is_empty() {
            return;
        }
        match turns.last_mut() {
            Some((r, existing)) if *r == role => existing.extend(blocks),
            _ => turns.push((role, blocks)),
        }
    };
    for m in messages {
        let role = m.get("role").and_then(Value::as_str).unwrap_or("user");
        let content = text_content(m.get("content"));
        match role {
            "system" | "developer" => {
                if !content.trim().is_empty() {
                    system.push(content);
                }
            }
            "user" => push("user", text_blocks(&content)),
            "assistant" => {
                let mut blocks = Vec::new();
                if let Some(r) = m.get("reasoning_content").and_then(Value::as_str) {
                    blocks.extend(thinking_blocks(r));
                }
                blocks.extend(text_blocks(&content));
                if let Some(calls) = m.get("tool_calls").and_then(Value::as_array) {
                    for call in calls {
                        blocks.push(tool_use_from_call(call)?);
                    }
                }
                push("assistant", blocks);
            }
            "tool" => {
                let id = m
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "a `tool` message needs `tool_call_id`".to_string())?;
                push(
                    "user",
                    vec![json!({"type": "tool_result", "tool_use_id": id, "content": content})],
                );
            }
            other => return Err(format!("unsupported message role {other:?}")),
        }
    }
    let turns = turns
        .into_iter()
        .map(|(role, blocks)| json!({"role": role, "content": blocks}))
        .collect();
    Ok((system, turns))
}

/// The text of an OpenAI `content` (string, `null`, or text parts).
fn text_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

fn text_blocks(text: &str) -> Vec<Value> {
    if text.is_empty() {
        Vec::new()
    } else {
        vec![json!({"type": "text", "text": text})]
    }
}

fn system_blocks(system: &[String]) -> Value {
    let text = system.join("\n\n");
    // One breakpoint on the whole system prompt: Talon keeps it byte-stable
    // across turns, so every turn after the first is a cache hit.
    json!([{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}])
}

fn tool_use_from_call(call: &Value) -> Result<Value, String> {
    let id = call
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "a tool call needs an `id`".to_string())?;
    let function = call.get("function").unwrap_or(&Value::Null);
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "a tool call needs `function.name`".to_string())?;
    let input = match function.get("arguments") {
        Some(Value::String(s)) => serde_json::from_str::<Value>(s)
            .ok()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({"_raw_arguments": s})),
        Some(v @ Value::Object(_)) => v.clone(),
        _ => Value::Object(Map::new()),
    };
    Ok(json!({"type": "tool_use", "id": id, "name": name, "input": input}))
}

fn convert_tool(tool: &Value) -> Option<Value> {
    let f = tool.get("function")?;
    let name = f.get("name")?.as_str()?;
    let mut out = Map::new();
    out.insert("name".into(), json!(name));
    if let Some(d) = f.get("description").and_then(Value::as_str) {
        out.insert("description".into(), json!(d));
    }
    out.insert(
        "input_schema".into(),
        f.get("parameters")
            .cloned()
            .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
    );
    Some(Value::Object(out))
}

fn convert_tool_choice(choice: Option<&Value>, parallel: bool) -> Option<Value> {
    let mut out = match choice {
        Some(Value::String(s)) => match s.as_str() {
            "none" => return Some(json!({"type": "none"})),
            "required" => json!({"type": "any"}),
            _ => json!({"type": "auto"}),
        },
        Some(Value::Object(o)) => {
            let name = o
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)?;
            json!({"type": "tool", "name": name})
        }
        _ => json!({"type": "auto"}),
    };
    if !parallel {
        out["disable_parallel_tool_use"] = Value::Bool(true);
    } else if choice.is_none() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chat(extra: Value) -> Value {
        let mut v = json!({
            "model": "claude-sonnet-5-5",
            "messages": [
                {"role": "system", "content": "You are Talon."},
                {"role": "user", "content": "Investigate alert 7."},
            ],
            "max_tokens": 4096,
        });
        if let (Some(a), Some(b)) = (v.as_object_mut(), extra.as_object()) {
            for (k, val) in b {
                a.insert(k.clone(), val.clone());
            }
        }
        v
    }

    #[test]
    fn system_and_user_turns_with_cache_breakpoint() {
        let t = request(&chat(json!({})), Options::default()).unwrap();
        assert_eq!(t.model, "claude-sonnet-5-5");
        assert!(!t.stream);
        assert_eq!(t.body["max_tokens"], 4096);
        assert_eq!(t.body["system"][0]["text"], "You are Talon.");
        assert_eq!(t.body["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(t.body["messages"][0]["role"], "user");
        assert_eq!(
            t.body["messages"][0]["content"][0]["text"],
            "Investigate alert 7."
        );
        assert!(t.body.get("thinking").is_none());
        assert!(t.body.get("temperature").is_none());
    }

    #[test]
    fn tool_calls_and_results_become_blocks_in_alternating_turns() {
        let body = json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "x"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "lookup", "arguments": "{\"q\":1}"}},
                    {"id": "c2", "type": "function", "function": {"name": "lookup", "arguments": "{\"q\":2}"}}
                ]},
                {"role": "tool", "tool_call_id": "c1", "content": "r1"},
                {"role": "tool", "tool_call_id": "c2", "content": "r2"},
                {"role": "user", "content": "and now?"}
            ],
            "tools": [{"type": "function", "function": {"name": "lookup", "description": "d",
                       "parameters": {"type": "object", "properties": {"q": {"type": "integer"}}}}}],
            "parallel_tool_calls": false,
            "stream": true,
        });
        let t = request(&body, Options::default()).unwrap();
        assert!(t.stream);
        let m = t.body["messages"].as_array().unwrap();
        assert_eq!(m.len(), 3, "user, assistant, user(tool results + text)");
        assert_eq!(m[1]["content"][0]["type"], "tool_use");
        assert_eq!(m[1]["content"][0]["input"]["q"], 1);
        assert_eq!(m[2]["role"], "user");
        assert_eq!(m[2]["content"].as_array().unwrap().len(), 3);
        assert_eq!(m[2]["content"][1]["tool_use_id"], "c2");
        assert_eq!(m[2]["content"][2]["text"], "and now?");
        assert_eq!(
            t.body["tools"][0]["input_schema"]["properties"]["q"]["type"],
            "integer"
        );
        assert_eq!(t.body["tool_choice"]["type"], "auto");
        assert_eq!(t.body["tool_choice"]["disable_parallel_tool_use"], true);
    }

    #[test]
    fn tool_choice_forms() {
        let t = |c: Value| {
            request(
                &chat(json!({"tools": [{"type":"function","function":{"name":"f"}}], "tool_choice": c})),
                Options::default(),
            )
            .unwrap()
            .body["tool_choice"]
                .clone()
        };
        assert_eq!(t(json!("required"))["type"], "any");
        assert_eq!(t(json!("none"))["type"], "none");
        assert_eq!(
            t(json!({"type":"function","function":{"name":"f"}}))["name"],
            "f"
        );
    }

    #[test]
    fn json_schema_becomes_output_config_and_stop_becomes_sequences() {
        let t = request(
            &chat(json!({
                "response_format": {"type": "json_schema", "json_schema": {"name": "r", "schema": {"type": "object"}}},
                "stop": ["END"],
                "temperature": 0.2,
                "chat_template_kwargs": {"enable_thinking": true},
            })),
            Options { thinking: true },
        )
        .unwrap();
        assert_eq!(t.body["output_config"]["format"]["type"], "json_schema");
        assert_eq!(
            t.body["output_config"]["format"]["schema"]["type"],
            "object"
        );
        assert_eq!(t.body["stop_sequences"][0], "END");
        assert_eq!(t.body["thinking"]["type"], "adaptive");
        assert!(t.body.get("temperature").is_none());
    }

    #[test]
    fn thinking_is_host_opt_in_and_request_opt_out() {
        let on = request(&chat(json!({})), Options { thinking: true }).unwrap();
        assert_eq!(on.body["thinking"]["type"], "adaptive");
        let off = request(
            &chat(json!({"chat_template_kwargs": {"enable_thinking": false}})),
            Options { thinking: true },
        )
        .unwrap();
        assert!(off.body.get("thinking").is_none());
        let host_off = request(
            &chat(json!({"chat_template_kwargs": {"enable_thinking": true}})),
            Options::default(),
        )
        .unwrap();
        assert!(host_off.body.get("thinking").is_none());
    }

    #[test]
    fn thinking_blocks_round_trip_through_reasoning_content() {
        let blocks = vec![json!({"type": "thinking", "thinking": "hm", "signature": "sig=="})];
        let r = reasoning_content("hm", &blocks).unwrap();
        assert!(r.starts_with("hm\n<talon-thinking>"));
        assert_eq!(thinking_blocks(&r), blocks);
        assert!(thinking_blocks("plain reasoning").is_empty());
        assert!(thinking_blocks("<talon-thinking>zz</talon-thinking>").is_empty());

        let body = json!({"model": "m", "messages": [
            {"role": "user", "content": "x"},
            {"role": "assistant", "content": "", "reasoning_content": r,
             "tool_calls": [{"id": "c1", "function": {"name": "f", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "ok"}
        ]});
        let t = request(&body, Options { thinking: true }).unwrap();
        let assistant = &t.body["messages"][1]["content"];
        assert_eq!(assistant[0]["type"], "thinking");
        assert_eq!(assistant[0]["signature"], "sig==");
        assert_eq!(assistant[1]["type"], "tool_use");
    }

    #[test]
    fn invalid_bodies_are_refused() {
        assert!(request(&json!({"messages": []}), Options::default()).is_err());
        assert!(request(&json!({"model": "m", "messages": []}), Options::default()).is_err());
        assert!(
            request(
                &json!({"model": "m", "messages": [{"role": "tool", "content": "x"}]}),
                Options::default()
            )
            .is_err()
        );
        assert!(
            request(
                &json!({"model": "m", "messages": [{"role": "weird", "content": "x"}]}),
                Options::default()
            )
            .is_err()
        );
    }

    #[test]
    fn response_maps_text_tools_thinking_and_usage() {
        let msg = json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
            "content": [
                {"type": "thinking", "thinking": "let me see", "signature": "s"},
                {"type": "text", "text": "Checking."},
                {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {"q": 1}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "cache_read_input_tokens": 90, "cache_creation_input_tokens": 5, "output_tokens": 7}
        });
        let r = response(&msg, 1);
        assert_eq!(r["object"], "chat.completion");
        let c = &r["choices"][0];
        assert_eq!(c["finish_reason"], "tool_calls");
        assert_eq!(c["message"]["content"], "Checking.");
        assert_eq!(c["message"]["tool_calls"][0]["id"], "toolu_1");
        assert_eq!(
            c["message"]["tool_calls"][0]["function"]["arguments"],
            "{\"q\":1}"
        );
        let reasoning = c["message"]["reasoning_content"].as_str().unwrap();
        assert!(reasoning.starts_with("let me see\n<talon-thinking>"));
        assert_eq!(r["usage"]["prompt_tokens"], 105);
        assert_eq!(r["usage"]["completion_tokens"], 7);
        assert_eq!(r["usage"]["prompt_tokens_details"]["cached_tokens"], 90);

        let plain = response(
            &json!({"content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn"}),
            1,
        );
        assert_eq!(plain["choices"][0]["finish_reason"], "stop");
        assert!(plain["choices"][0]["message"].get("tool_calls").is_none());
        assert!(
            plain["choices"][0]["message"]
                .get("reasoning_content")
                .is_none()
        );
        assert_eq!(finish_reason(Some("max_tokens"), false), "length");
        assert_eq!(finish_reason(Some("refusal"), false), "content_filter");
    }

    #[test]
    fn count_tokens_body_has_no_generation_fields() {
        let v = count_tokens_request(
            &json!({"model": "m", "prompt": "abc def", "add_special_tokens": false}),
            Options::default(),
        )
        .unwrap();
        assert_eq!(v["messages"][0]["content"][0]["text"], "abc def");
        assert!(v.get("max_tokens").is_none());
        let v =
            count_tokens_request(&chat(json!({"stop": "x"})), Options { thinking: true }).unwrap();
        assert!(v.get("stop_sequences").is_none());
        assert_eq!(v["thinking"]["type"], "adaptive");
    }
}
