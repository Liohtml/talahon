//! Fallback parsing for models whose tool calls / reasoning arrive as text.
//!
//! vLLM only returns structured `tool_calls` when it runs with
//! `--enable-auto-tool-choice --tool-call-parser <name>` and the parser
//! matches the model. When it does not, the model's tool-call syntax ends up
//! in `content`. This module recovers those calls:
//!
//! | format | example |
//! |--------|---------|
//! | Hermes / Qwen | `<tool_call>{"name":"f","arguments":{..}}</tool_call>` |
//! | Mistral | `[TOOL_CALLS][{"name":"f","arguments":{..}}]` or `[TOOL_CALLS]f[ARGS]{..}` |
//! | Llama 3.x | `<|python_tag|>{"name":"f","parameters":{..}}` |
//! | fenced JSON | ```` ```json {"name":"f","arguments":{..}} ``` ```` |
//! | bare JSON | the whole message is `{"name":"f","arguments":{..}}` |
//!
//! Only tools that were actually offered are accepted. Explicit tool-call
//! markup (Hermes/Mistral/Llama) naming an unknown tool is reported as
//! rejected; fenced/bare JSON that does not name an offered tool is left
//! alone, because it is most likely ordinary JSON output.
//!
//! It also splits `<think>...</think>` (reasoning models served without
//! `--reasoning-parser`) into `reasoning_content`.

use rand::Rng;
use rand::distributions::Alphanumeric;
use serde_json::Value;

use crate::types::{
    ChatMessage, PostProcessReport, RejectedToolCall, Role, ToolCall, ToolCallFormat,
};

pub(crate) const THINK_OPEN: &str = "<think>";
pub(crate) const THINK_CLOSE: &str = "</think>";
pub(crate) const HERMES_OPEN: &str = "<tool_call>";
pub(crate) const HERMES_CLOSE: &str = "</tool_call>";
pub(crate) const MISTRAL_MARKER: &str = "[TOOL_CALLS]";
pub(crate) const LLAMA_MARKER: &str = "<|python_tag|>";

/// What the post-processor is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostProcessOptions {
    /// Move `<think>...</think>` out of `content` into `reasoning_content`.
    pub split_think: bool,
    /// Recover tool calls written as text.
    pub recover_tool_calls: bool,
}

impl Default for PostProcessOptions {
    fn default() -> Self {
        Self {
            split_think: true,
            recover_tool_calls: true,
        }
    }
}

/// Tool calls recovered from text.
#[derive(Debug, Clone, PartialEq)]
pub struct TextToolCalls {
    /// Accepted calls (offered tool names, valid JSON object arguments).
    pub calls: Vec<ToolCall>,
    /// Recognised but rejected calls.
    pub rejected: Vec<RejectedToolCall>,
    /// The text with the tool-call markup removed.
    pub content: String,
    /// Which syntax was found.
    pub format: ToolCallFormat,
}

/// A fresh OpenAI-style tool-call id (`call_<24 alphanumerics>`).
pub fn new_call_id() -> String {
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    format!("call_{suffix}")
}

/// Split `<think>...</think>` out of `text`.
///
/// Returns `None` when there are no think tags, else `(reasoning, content)`.
/// Handles a missing opening tag (templates that put `<think>` in the
/// prompt, e.g. DeepSeek-R1 / Qwen3) and a missing closing tag (output cut
/// off while thinking: everything after `<think>` is reasoning).
pub fn split_think(text: &str) -> Option<(Option<String>, String)> {
    let open = text.find(THINK_OPEN);
    let close = text.find(THINK_CLOSE);
    let (reasoning, content) = match (open, close) {
        (Some(o), Some(c)) if c > o => {
            let reasoning = &text[o + THINK_OPEN.len()..c];
            let content = format!("{}{}", &text[..o], &text[c + THINK_CLOSE.len()..]);
            (reasoning.to_string(), content)
        }
        (_, Some(c)) => {
            let content = text[c + THINK_CLOSE.len()..].replace(THINK_OPEN, "");
            (text[..c].replace(THINK_OPEN, ""), content)
        }
        (Some(o), None) => (
            text[o + THINK_OPEN.len()..].to_string(),
            text[..o].to_string(),
        ),
        (None, None) => return None,
    };
    let reasoning = reasoning.trim();
    let reasoning = (!reasoning.is_empty()).then(|| reasoning.to_string());
    Some((reasoning, content.trim().to_string()))
}

/// Recover tool calls written as text. `is_known` decides whether a tool
/// name was offered. Returns `None` when no tool-call syntax was found.
pub fn parse_text_tool_calls(text: &str, is_known: &dyn Fn(&str) -> bool) -> Option<TextToolCalls> {
    if text.contains(HERMES_OPEN) {
        return Some(parse_hermes(text, is_known));
    }
    if text.contains(MISTRAL_MARKER) {
        return Some(parse_mistral(text, is_known));
    }
    if text.contains(LLAMA_MARKER) {
        return Some(parse_llama(text, is_known));
    }
    if let Some(found) = parse_fenced(text, is_known) {
        return Some(found);
    }
    parse_bare(text, is_known)
}

/// Apply `<think>` splitting and tool-call recovery to an assistant message,
/// assign missing tool-call ids, normalize empty arguments to `{}`, and
/// flag tool calls naming tools that were not offered.
///
/// `offered_tools` empty means "no tools were offered" — recovery is skipped.
pub fn postprocess_message(
    message: &mut ChatMessage,
    offered_tools: &[String],
    options: &PostProcessOptions,
) -> PostProcessReport {
    let mut report = PostProcessReport::default();
    if message.role != Role::Assistant {
        return report;
    }

    if options.split_think {
        if let Some(content) = message.content.as_deref() {
            if let Some((reasoning, rest)) = split_think(content) {
                if let Some(r) = reasoning {
                    message.reasoning_content = Some(match message.reasoning_content.take() {
                        Some(existing) if !existing.trim().is_empty() => format!("{existing}\n{r}"),
                        _ => r,
                    });
                }
                message.content = (!rest.is_empty()).then_some(rest);
                report.reasoning_extracted = true;
            }
        }
    }

    if options.recover_tool_calls && !offered_tools.is_empty() && message.tool_calls.is_empty() {
        if let Some(content) = message.content.as_deref() {
            let is_known = |name: &str| offered_tools.iter().any(|t| t == name);
            if let Some(parsed) = parse_text_tool_calls(content, &is_known) {
                report.rejected_tool_calls = parsed.rejected;
                if !parsed.calls.is_empty() {
                    report.recovered_format = Some(parsed.format);
                    report.recovered_tool_calls = parsed.calls.len();
                    message.tool_calls = parsed.calls;
                    let rest = parsed.content.trim();
                    message.content = (!rest.is_empty()).then(|| rest.to_string());
                }
                // When nothing was accepted the original text is kept, so the
                // agent still has something to show / feed back.
            }
        }
    }

    for call in &mut message.tool_calls {
        if call.id.trim().is_empty() {
            call.id = new_call_id();
        }
        if call.function.arguments.trim().is_empty() {
            call.function.arguments = "{}".to_string();
        }
        if !matches!(call.parse_arguments(), Ok(Value::Object(_))) {
            report.malformed_arguments.push(call.id.clone());
        }
        if !offered_tools.is_empty()
            && !offered_tools.contains(&call.function.name)
            && !report.unknown_tool_names.contains(&call.function.name)
        {
            report.unknown_tool_names.push(call.function.name.clone());
        }
    }
    report
}

// ---------------------------------------------------------------------------
// Format parsers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Collected {
    calls: Vec<ToolCall>,
    rejected: Vec<RejectedToolCall>,
}

impl Collected {
    fn reject(&mut self, name: impl Into<String>, reason: impl Into<String>) {
        self.rejected.push(RejectedToolCall {
            name: name.into(),
            reason: reason.into(),
        });
    }

    /// Classify each JSON value (arrays are flattened) as a call.
    fn take_values(&mut self, values: Vec<Value>, is_known: &dyn Fn(&str) -> bool) {
        for value in flatten(values) {
            match call_from_value(&value) {
                CallParse::Call { name, arguments } => {
                    if is_known(&name) {
                        self.calls
                            .push(ToolCall::new(new_call_id(), name, arguments));
                    } else {
                        self.reject(name, "unknown tool (not offered in this request)");
                    }
                }
                CallParse::Invalid { name, reason } => self.reject(name, reason),
                CallParse::NotACall => {
                    self.reject("", "tool-call payload is not a {name, arguments} object")
                }
            }
        }
    }

    fn into_result(self, content: String, format: ToolCallFormat) -> TextToolCalls {
        TextToolCalls {
            calls: self.calls,
            rejected: self.rejected,
            content,
            format,
        }
    }
}

fn parse_hermes(text: &str, is_known: &dyn Fn(&str) -> bool) -> TextToolCalls {
    let mut out = Collected::default();
    let mut content = String::new();
    let mut rest = text;
    while let Some(start) = rest.find(HERMES_OPEN) {
        content.push_str(&rest[..start]);
        let after = &rest[start + HERMES_OPEN.len()..];
        let (body, next) = match after.find(HERMES_CLOSE) {
            Some(end) => (&after[..end], &after[end + HERMES_CLOSE.len()..]),
            // Unclosed (the closing tag is often the stop token).
            None => (after, ""),
        };
        let body = crate::types::strip_code_fence(body);
        let (values, consumed) = parse_json_sequence(body);
        if values.is_empty() {
            out.reject(guess_name(body), "tool call is not valid JSON");
        } else {
            out.take_values(values, is_known);
            push_leftover(&mut content, &body[consumed..]);
        }
        rest = next;
    }
    content.push_str(rest);
    let content = content.replace(HERMES_CLOSE, "");
    out.into_result(content, ToolCallFormat::Hermes)
}

fn parse_mistral(text: &str, is_known: &dyn Fn(&str) -> bool) -> TextToolCalls {
    let mut out = Collected::default();
    let Some(first) = text.find(MISTRAL_MARKER) else {
        return out.into_result(text.to_string(), ToolCallFormat::Mistral);
    };
    let mut content = text[..first].to_string();
    for segment in text[first + MISTRAL_MARKER.len()..].split(MISTRAL_MARKER) {
        let seg = segment.trim_start();
        if seg.starts_with('[') || seg.starts_with('{') {
            let (values, consumed) = parse_json_sequence(seg);
            if values.is_empty() {
                out.reject(guess_name(seg), "[TOOL_CALLS] payload is not valid JSON");
                continue;
            }
            out.take_values(values, is_known);
            push_leftover(&mut content, &seg[consumed..]);
        } else if let Some(args_pos) = seg.find("[ARGS]") {
            // v11+ tokenizer: `name[ARGS]{...}` (optionally `name[CALL_ID]id[ARGS]{...}`).
            let head = &seg[..args_pos];
            let name = head
                .split("[CALL_ID]")
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let args_text = &seg[args_pos + "[ARGS]".len()..];
            let (values, consumed) = parse_json_sequence(args_text);
            match values.into_iter().next() {
                Some(Value::Object(map)) => {
                    let obj = Value::Object(map);
                    if is_known(&name) {
                        out.calls
                            .push(ToolCall::new(new_call_id(), name, obj.to_string()));
                    } else {
                        out.reject(name, "unknown tool (not offered in this request)");
                    }
                    push_leftover(&mut content, &args_text[consumed..]);
                }
                Some(_) => out.reject(name, "arguments must be a JSON object"),
                None => out.reject(name, "arguments are not valid JSON"),
            }
        } else {
            out.reject(guess_name(seg), "unparseable [TOOL_CALLS] payload");
        }
    }
    out.into_result(content, ToolCallFormat::Mistral)
}

fn parse_llama(text: &str, is_known: &dyn Fn(&str) -> bool) -> TextToolCalls {
    let mut out = Collected::default();
    let mut segments = text.split(LLAMA_MARKER);
    let mut content = segments.next().unwrap_or("").to_string();
    for segment in segments {
        let body = segment.replace("<|eom_id|>", "").replace("<|eot_id|>", "");
        let (values, consumed) = parse_json_sequence(&body);
        if values.is_empty() {
            // e.g. built-in `brave_search.call(query="...")` — not offered.
            let name: String = body
                .trim()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            out.reject(name, "unsupported <|python_tag|> call (expected JSON)");
            continue;
        }
        out.take_values(values, is_known);
        push_leftover(&mut content, &body[consumed..]);
    }
    out.into_result(content, ToolCallFormat::Llama)
}

/// Fenced code blocks whose JSON consists solely of calls to offered tools.
fn parse_fenced(text: &str, is_known: &dyn Fn(&str) -> bool) -> Option<TextToolCalls> {
    const FENCE: &str = "```";
    const INFOS: [&str; 7] = [
        "",
        "json",
        "tool_call",
        "tool_calls",
        "tool_code",
        "function_call",
        "javascript",
    ];
    let mut calls = Vec::new();
    let mut content = String::new();
    let mut rest = text;
    while let Some(open) = rest.find(FENCE) {
        let after_open = &rest[open + FENCE.len()..];
        let Some(nl) = after_open.find('\n') else {
            break;
        };
        let info = after_open[..nl].trim().to_ascii_lowercase();
        let body_start = &after_open[nl + 1..];
        let Some(close) = body_start.find(FENCE) else {
            break;
        };
        let body = &body_start[..close];
        let block_end = &body_start[close + FENCE.len()..];
        let block_calls = if INFOS.contains(&info.as_str()) {
            all_known_calls(body, is_known)
        } else {
            None
        };
        match block_calls {
            Some(found) => {
                content.push_str(&rest[..open]);
                calls.extend(found);
            }
            None => content.push_str(&rest[..open + FENCE.len() + nl + 1 + close + FENCE.len()]),
        }
        rest = block_end;
    }
    content.push_str(rest);
    if calls.is_empty() {
        return None;
    }
    Some(TextToolCalls {
        calls,
        rejected: Vec::new(),
        content,
        format: ToolCallFormat::FencedJson,
    })
}

/// The whole message is a tool-call JSON object (or array of them).
fn parse_bare(text: &str, is_known: &dyn Fn(&str) -> bool) -> Option<TextToolCalls> {
    let t = text.trim();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return None;
    }
    let calls = all_known_calls(t, is_known)?;
    Some(TextToolCalls {
        calls,
        rejected: Vec::new(),
        content: String::new(),
        format: ToolCallFormat::BareJson,
    })
}

/// `Some(calls)` only if `body` is entirely JSON and every value is a valid
/// call to an offered tool.
fn all_known_calls(body: &str, is_known: &dyn Fn(&str) -> bool) -> Option<Vec<ToolCall>> {
    let (values, consumed) = parse_json_sequence(body);
    if values.is_empty() || !body[consumed..].trim().is_empty() {
        return None;
    }
    let mut calls = Vec::new();
    for value in flatten(values) {
        match call_from_value(&value) {
            CallParse::Call { name, arguments } if is_known(&name) => {
                calls.push(ToolCall::new(new_call_id(), name, arguments));
            }
            _ => return None,
        }
    }
    (!calls.is_empty()).then_some(calls)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

enum CallParse {
    Call { name: String, arguments: String },
    Invalid { name: String, reason: String },
    NotACall,
}

/// Interpret one JSON value as a `{name, arguments}` call. Accepts the
/// common variants: `arguments` / `parameters` / `args` / `input`, an
/// OpenAI-shaped `{"function":{"name","arguments"}}`, and arguments given
/// as an object or a JSON-encoded string.
fn call_from_value(value: &Value) -> CallParse {
    let Some(obj) = value.as_object() else {
        return CallParse::NotACall;
    };
    let function = obj.get("function").and_then(Value::as_object);
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| function.and_then(|f| f.get("name")).and_then(Value::as_str))
        .or_else(|| obj.get("tool_name").and_then(Value::as_str))
        .or_else(|| obj.get("function").and_then(Value::as_str));
    let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) else {
        return CallParse::NotACall;
    };
    let name = name.to_string();
    let args = ["arguments", "parameters", "args", "input"]
        .iter()
        .find_map(|k| obj.get(*k))
        .or_else(|| function.and_then(|f| f.get("arguments").or_else(|| f.get("parameters"))));
    match args {
        None | Some(Value::Null) => CallParse::Call {
            name,
            arguments: "{}".to_string(),
        },
        Some(v @ Value::Object(_)) => CallParse::Call {
            name,
            arguments: v.to_string(),
        },
        Some(Value::String(s)) if s.trim().is_empty() => CallParse::Call {
            name,
            arguments: "{}".to_string(),
        },
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(v @ Value::Object(_)) => CallParse::Call {
                name,
                arguments: v.to_string(),
            },
            Ok(_) => CallParse::Invalid {
                name,
                reason: "arguments must be a JSON object".to_string(),
            },
            Err(_) => CallParse::Invalid {
                name,
                reason: "arguments are not valid JSON".to_string(),
            },
        },
        Some(_) => CallParse::Invalid {
            name,
            reason: "arguments must be a JSON object".to_string(),
        },
    }
}

/// Parse consecutive JSON values separated by whitespace, `,` or `;`.
/// Returns the values and the number of bytes consumed.
fn parse_json_sequence(s: &str) -> (Vec<Value>, usize) {
    let mut values = Vec::new();
    let mut pos = 0usize;
    loop {
        let rest = &s[pos..];
        let trimmed = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ';' || c == ',');
        let skipped = rest.len() - trimmed.len();
        if trimmed.is_empty() || !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
            // Do not count trailing separators as consumed unless all is done.
            if trimmed.is_empty() {
                pos += skipped;
            }
            break;
        }
        let mut stream = serde_json::Deserializer::from_str(trimmed).into_iter::<Value>();
        match stream.next() {
            Some(Ok(v)) => {
                pos += skipped + stream.byte_offset();
                values.push(v);
            }
            _ => break,
        }
    }
    (values, pos)
}

fn flatten(values: Vec<Value>) -> Vec<Value> {
    let mut out = Vec::new();
    for v in values {
        match v {
            Value::Array(items) => out.extend(items),
            other => out.push(other),
        }
    }
    out
}

/// End-of-turn special tokens some servers leave in the text.
const SPECIAL_TOKENS: [&str; 5] = ["</s>", "<|eot_id|>", "<|eom_id|>", "<|im_end|>", "<|end|>"];

fn push_leftover(content: &mut String, leftover: &str) {
    let mut cleaned = leftover.to_string();
    for token in SPECIAL_TOKENS {
        cleaned = cleaned.replace(token, "");
    }
    let l = cleaned.trim();
    if !l.is_empty() {
        if !content.is_empty() && !content.ends_with(char::is_whitespace) {
            content.push('\n');
        }
        content.push_str(l);
    }
}

/// Best-effort tool name from broken JSON (`"name": "x"`), for error reports.
fn guess_name(body: &str) -> String {
    let Some(pos) = body.find("\"name\"") else {
        return String::new();
    };
    let after = body[pos + 6..].trim_start();
    let Some(after) = after.strip_prefix(':') else {
        return String::new();
    };
    let after = after.trim_start();
    let Some(after) = after.strip_prefix('"') else {
        return String::new();
    };
    after.chars().take_while(|c| *c != '"').take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn known(name: &str) -> bool {
        matches!(name, "get_weather" | "search_alerts" | "noop")
    }

    fn args(call: &ToolCall) -> Value {
        call.parse_arguments().unwrap()
    }

    #[test]
    fn hermes_single_and_multiple() {
        let text = "Let me check.\n<tool_call>\n{\"name\": \"get_weather\", \"arguments\": {\"city\": \"Berlin\"}}\n</tool_call>\n<tool_call>{\"name\":\"search_alerts\",\"arguments\":\"{\\\"q\\\":\\\"x\\\"}\"}</tool_call>";
        let r = parse_text_tool_calls(text, &known).unwrap();
        assert_eq!(r.format, ToolCallFormat::Hermes);
        assert_eq!(r.calls.len(), 2);
        assert_eq!(r.calls[0].name(), "get_weather");
        assert_eq!(args(&r.calls[0]), json!({"city": "Berlin"}));
        assert_eq!(args(&r.calls[1]), json!({"q": "x"}));
        assert!(r.calls[0].id.starts_with("call_"));
        assert_ne!(r.calls[0].id, r.calls[1].id);
        assert_eq!(r.content.trim(), "Let me check.");
        assert!(r.rejected.is_empty());
    }

    #[test]
    fn hermes_unclosed_and_unknown_and_broken() {
        let r = parse_text_tool_calls(
            "<tool_call>{\"name\":\"get_weather\",\"arguments\":{}}",
            &known,
        )
        .unwrap();
        assert_eq!(r.calls.len(), 1);
        assert_eq!(r.calls[0].function.arguments, "{}");

        let r = parse_text_tool_calls(
            "<tool_call>{\"name\":\"rm_rf\",\"arguments\":{}}</tool_call><tool_call>{\"name\": \"get_weather\", \"arguments\": {\"city\": </tool_call>",
            &known,
        )
        .unwrap();
        assert!(r.calls.is_empty());
        assert_eq!(r.rejected.len(), 2);
        assert_eq!(r.rejected[0].name, "rm_rf");
        assert!(r.rejected[0].reason.contains("unknown tool"));
        assert_eq!(r.rejected[1].name, "get_weather");
        assert!(r.rejected[1].reason.contains("not valid JSON"));
    }

    #[test]
    fn mistral_array_and_v11_formats() {
        let r = parse_text_tool_calls(
            "[TOOL_CALLS] [{\"name\": \"get_weather\", \"arguments\": {\"city\": \"Paris\"}, \"id\": \"abc123def\"}, {\"name\":\"noop\",\"arguments\":{}}]</s>",
            &known,
        )
        .unwrap();
        assert_eq!(r.format, ToolCallFormat::Mistral);
        assert_eq!(r.calls.len(), 2);
        assert_eq!(args(&r.calls[0]), json!({"city": "Paris"}));
        assert_eq!(r.content.trim(), "", "special tokens are dropped");

        let r = parse_text_tool_calls(
            "[TOOL_CALLS]get_weather[ARGS]{\"city\": \"Rome\"}[TOOL_CALLS]noop[CALL_ID]x1[ARGS]{}",
            &known,
        )
        .unwrap();
        assert_eq!(r.calls.len(), 2);
        assert_eq!(r.calls[0].name(), "get_weather");
        assert_eq!(args(&r.calls[0]), json!({"city": "Rome"}));
        assert_eq!(r.calls[1].name(), "noop");

        let r = parse_text_tool_calls("[TOOL_CALLS]evil[ARGS]{}", &known).unwrap();
        assert!(r.calls.is_empty());
        assert_eq!(r.rejected[0].name, "evil");
    }

    #[test]
    fn llama_python_tag() {
        let r = parse_text_tool_calls(
            "<|python_tag|>{\"name\": \"get_weather\", \"parameters\": {\"city\": \"Oslo\"}}; {\"name\": \"noop\", \"parameters\": {}}<|eom_id|>",
            &known,
        )
        .unwrap();
        assert_eq!(r.format, ToolCallFormat::Llama);
        assert_eq!(r.calls.len(), 2);
        assert_eq!(args(&r.calls[0]), json!({"city": "Oslo"}));

        let r =
            parse_text_tool_calls("<|python_tag|>brave_search.call(query=\"x\")", &known).unwrap();
        assert!(r.calls.is_empty());
        assert_eq!(r.rejected[0].name, "brave_search");
    }

    #[test]
    fn fenced_json_only_for_known_tools() {
        let text = "I'll search.\n```json\n{\"name\": \"search_alerts\", \"arguments\": {\"q\": \"4625\"}}\n```\nDone.";
        let r = parse_text_tool_calls(text, &known).unwrap();
        assert_eq!(r.format, ToolCallFormat::FencedJson);
        assert_eq!(r.calls.len(), 1);
        assert_eq!(r.content, "I'll search.\n\nDone.");

        // Ordinary JSON output (a report) is left alone.
        let report =
            "Here is the report:\n```json\n{\"name\": \"Incident 7\", \"severity\": \"high\"}\n```";
        assert!(parse_text_tool_calls(report, &known).is_none());
        // A fenced block with a call to an unknown tool is left alone too.
        let other = "```json\n{\"name\": \"delete_all\", \"arguments\": {}}\n```";
        assert!(parse_text_tool_calls(other, &known).is_none());
        // Non-JSON fences are ignored.
        assert!(parse_text_tool_calls("```bash\nls\n```", &known).is_none());
    }

    #[test]
    fn bare_json_and_openai_shape() {
        let r = parse_text_tool_calls(
            " {\"name\": \"get_weather\", \"parameters\": {\"city\": \"Kyiv\"}} ",
            &known,
        )
        .unwrap();
        assert_eq!(r.format, ToolCallFormat::BareJson);
        assert_eq!(args(&r.calls[0]), json!({"city": "Kyiv"}));

        let r = parse_text_tool_calls(
            "[{\"type\":\"function\",\"function\":{\"name\":\"noop\",\"arguments\":\"{}\"}}]",
            &known,
        )
        .unwrap();
        assert_eq!(r.calls[0].name(), "noop");

        assert!(parse_text_tool_calls("{\"verdict\": \"benign\"}", &known).is_none());
        assert!(parse_text_tool_calls("plain answer", &known).is_none());
        assert!(
            parse_text_tool_calls("{\"name\":\"noop\",\"arguments\":{}} trailing", &known)
                .is_none()
        );
    }

    #[test]
    fn non_object_arguments_are_rejected() {
        let r = parse_text_tool_calls(
            "<tool_call>{\"name\":\"noop\",\"arguments\":[1,2]}</tool_call>",
            &known,
        )
        .unwrap();
        assert!(r.calls.is_empty());
        assert!(r.rejected[0].reason.contains("JSON object"));
    }

    #[test]
    fn think_splitting_variants() {
        assert_eq!(
            split_think("<think>\nreason\n</think>\n\nAnswer"),
            Some((Some("reason".into()), "Answer".into()))
        );
        // Opening tag injected by the chat template.
        assert_eq!(
            split_think("reason</think>Answer"),
            Some((Some("reason".into()), "Answer".into()))
        );
        // Cut off while thinking.
        assert_eq!(
            split_think("<think>still going"),
            Some((Some("still going".into()), String::new()))
        );
        // Empty think block (enable_thinking=false on Qwen3).
        assert_eq!(
            split_think("<think>\n\n</think>\n\nHi"),
            Some((None, "Hi".into()))
        );
        assert_eq!(split_think("no tags"), None);
    }

    #[test]
    fn postprocess_think_then_tool_call() {
        let mut msg = ChatMessage::assistant(
            "<think>I should call the tool. <tool_call>{\"name\":\"noop\"}</tool_call> maybe</think>\n<tool_call>\n{\"name\": \"get_weather\", \"arguments\": {\"city\": \"Bonn\"}}\n</tool_call>",
        );
        let offered = vec!["get_weather".to_string(), "noop".to_string()];
        let report = postprocess_message(&mut msg, &offered, &PostProcessOptions::default());
        assert!(report.reasoning_extracted);
        assert_eq!(report.recovered_tool_calls, 1, "{report:?}");
        assert_eq!(report.recovered_format, Some(ToolCallFormat::Hermes));
        assert_eq!(msg.tool_calls.len(), 1);
        assert_eq!(msg.tool_calls[0].name(), "get_weather");
        assert!(msg.content.is_none());
        assert!(
            msg.reasoning_content
                .as_deref()
                .unwrap()
                .contains("I should call")
        );
    }

    #[test]
    fn postprocess_keeps_text_when_nothing_accepted() {
        let raw = "<tool_call>{\"name\":\"evil\",\"arguments\":{}}</tool_call>";
        let mut msg = ChatMessage::assistant(raw);
        let offered = vec!["noop".to_string()];
        let report = postprocess_message(&mut msg, &offered, &PostProcessOptions::default());
        assert_eq!(report.recovered_tool_calls, 0);
        assert_eq!(report.rejected_tool_calls.len(), 1);
        assert_eq!(msg.text(), raw);
        assert!(msg.tool_calls.is_empty());
    }

    #[test]
    fn postprocess_flags_server_calls_and_fills_ids() {
        let mut msg = ChatMessage::assistant_tool_calls(
            None,
            vec![
                ToolCall::new("", "noop", ""),
                ToolCall::new("c2", "ghost", "{\"a\":"),
            ],
        );
        let offered = vec!["noop".to_string()];
        let report = postprocess_message(&mut msg, &offered, &PostProcessOptions::default());
        assert!(msg.tool_calls[0].id.starts_with("call_"));
        assert_eq!(msg.tool_calls[0].function.arguments, "{}");
        assert_eq!(report.unknown_tool_names, vec!["ghost".to_string()]);
        assert_eq!(report.malformed_arguments, vec!["c2".to_string()]);
        assert_eq!(msg.normalize_tool_arguments(), 1);
        assert_eq!(msg.tool_calls[1].function.arguments, "{}");
    }

    #[test]
    fn postprocess_respects_options_and_no_tools() {
        let raw = "<think>x</think><tool_call>{\"name\":\"noop\",\"arguments\":{}}</tool_call>";
        let mut msg = ChatMessage::assistant(raw);
        let report = postprocess_message(
            &mut msg,
            &[],
            &PostProcessOptions {
                split_think: false,
                recover_tool_calls: true,
            },
        );
        assert!(report.is_empty());
        assert_eq!(msg.text(), raw);
        // User messages are never touched.
        let mut user = ChatMessage::user("<think>x</think>");
        assert!(postprocess_message(&mut user, &[], &PostProcessOptions::default()).is_empty());
        assert_eq!(user.text(), "<think>x</think>");
    }

    #[test]
    fn json_sequence_parsing() {
        let (v, n) = parse_json_sequence("{\"a\":1} ; {\"b\":2}, [3] tail");
        assert_eq!(v.len(), 3);
        assert_eq!(&"{\"a\":1} ; {\"b\":2}, [3] tail"[n..], " tail");
        let (v, n) = parse_json_sequence("  ");
        assert!(v.is_empty());
        assert_eq!(n, 2);
        assert_eq!(guess_name("{\"name\": \"abc\", \"arguments\": {"), "abc");
        assert_eq!(guess_name("garbage"), "");
    }
}
