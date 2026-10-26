//! Anthropic SSE → OpenAI `chat.completion.chunk` SSE.
//!
//! Fed with the raw upstream bytes, [`Translator::push`] returns the bytes
//! to send to the client. The output is what vLLM would stream: a first
//! chunk with the role, text / `reasoning_content` / `tool_calls` deltas, a
//! chunk with `finish_reason`, a final chunk with `usage` and empty
//! `choices` (`stream_options.include_usage`), then `data: [DONE]`.
//!
//! Signed thinking blocks are forwarded for replay the same way as in the
//! non-streaming path: after a thinking block ends, one more
//! `reasoning_content` delta carries the opaque marker.

use serde_json::{Map, Value, json};

use super::translate::{finish_reason, reasoning_content, usage};
use crate::error::LlmError;
use crate::sse::SseDecoder;

/// What an open content block is.
#[derive(Debug, Clone)]
enum Block {
    Text,
    ToolUse {
        /// Position in the OpenAI `tool_calls` array.
        index: u32,
    },
    Thinking {
        text: String,
        signature: String,
    },
    RedactedThinking {
        data: String,
    },
    Other,
}

/// Incremental translator for one streamed response.
#[derive(Debug)]
pub struct Translator {
    decoder: SseDecoder,
    id: String,
    model: String,
    created: u64,
    /// Open content blocks by Anthropic index.
    blocks: Vec<Option<Block>>,
    tool_calls: u32,
    role_sent: bool,
    finish_sent: bool,
    done: bool,
    input_usage: Option<Value>,
    output_tokens: u64,
    stop_reason: Option<String>,
}

impl Translator {
    /// A translator for a response to `model`, stamping `created` on
    /// every chunk.
    pub fn new(model: impl Into<String>, created: u64) -> Self {
        Self {
            decoder: SseDecoder::default(),
            id: String::from("chatcmpl-anthropic"),
            model: model.into(),
            created,
            blocks: Vec::new(),
            tool_calls: 0,
            role_sent: false,
            finish_sent: false,
            done: false,
            input_usage: None,
            output_tokens: 0,
            stop_reason: None,
        }
    }

    /// Whether `[DONE]` has been emitted.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Feed upstream bytes; returns client bytes (possibly empty).
    ///
    /// # Errors
    /// Malformed SSE, or an `error` event from the API (the message is
    /// safe to log; the client sees a truncated stream).
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, LlmError> {
        let mut out = Vec::new();
        for ev in self.decoder.push(bytes)? {
            if self.done {
                break;
            }
            let value: Value = match serde_json::from_str(&ev.data) {
                Ok(v) => v,
                Err(_) => continue, // keep-alive comments, blank data
            };
            self.event(&value, &mut out)?;
        }
        Ok(out)
    }

    /// Upstream ended. Returns whatever is still owed to the client (a
    /// finish chunk, the usage chunk and `[DONE]`) — an empty vector when
    /// the stream already ended properly.
    ///
    /// # Errors
    /// A dangling partial SSE event.
    pub fn finish(&mut self) -> Result<Vec<u8>, LlmError> {
        let mut out = Vec::new();
        if let Some(ev) = self.decoder.finish()? {
            if let Ok(v) = serde_json::from_str::<Value>(&ev.data) {
                self.event(&v, &mut out)?;
            }
        }
        if !self.done {
            // Truncated upstream: tell the client it ended, without
            // claiming a natural stop.
            self.emit_finish(Some("abort"), &mut out);
            self.emit_done(&mut out);
        }
        Ok(out)
    }

    fn event(&mut self, v: &Value, out: &mut Vec<u8>) -> Result<(), LlmError> {
        match v.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                let message = v.get("message").cloned().unwrap_or(Value::Null);
                if let Some(id) = message.get("id").and_then(Value::as_str) {
                    self.id = id.to_string();
                }
                if let Some(m) = message.get("model").and_then(Value::as_str) {
                    self.model = m.to_string();
                }
                self.input_usage = message.get("usage").cloned();
                if let Some(n) = message
                    .get("usage")
                    .and_then(|u| u.get("output_tokens"))
                    .and_then(Value::as_u64)
                {
                    self.output_tokens = n;
                }
                self.emit_delta(json!({"role": "assistant", "content": ""}), out);
            }
            Some("content_block_start") => {
                let index = index_of(v);
                let block = v.get("content_block").cloned().unwrap_or(Value::Null);
                let kind = match block.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(t) = block.get("text").and_then(Value::as_str) {
                            if !t.is_empty() {
                                self.emit_delta(json!({"content": t}), out);
                            }
                        }
                        Block::Text
                    }
                    Some("tool_use") => {
                        let i = self.tool_calls;
                        self.tool_calls += 1;
                        self.emit_delta(
                            json!({"tool_calls": [{
                                "index": i,
                                "id": block.get("id").cloned().unwrap_or(Value::Null),
                                "type": "function",
                                "function": {
                                    "name": block.get("name").cloned().unwrap_or(Value::Null),
                                    "arguments": "",
                                },
                            }]}),
                            out,
                        );
                        Block::ToolUse { index: i }
                    }
                    Some("thinking") => Block::Thinking {
                        text: String::new(),
                        signature: String::new(),
                    },
                    Some("redacted_thinking") => Block::RedactedThinking {
                        data: block
                            .get("data")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    },
                    _ => Block::Other,
                };
                self.set_block(index, kind);
            }
            Some("content_block_delta") => {
                let index = index_of(v);
                let delta = v.get("delta").cloned().unwrap_or(Value::Null);
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(t) = delta.get("text").and_then(Value::as_str) {
                            self.emit_delta(json!({"content": t}), out);
                        }
                    }
                    Some("input_json_delta") => {
                        let fragment = delta
                            .get("partial_json")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        if let Some(Block::ToolUse { index: i }) = self.block(index) {
                            let i = *i;
                            self.emit_delta(
                                json!({"tool_calls": [{"index": i, "function": {"arguments": fragment}}]}),
                                out,
                            );
                        }
                    }
                    Some("thinking_delta") => {
                        let t = delta
                            .get("thinking")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        if let Some(Block::Thinking { text, .. }) = self.block(index) {
                            text.push_str(&t);
                        }
                        if !t.is_empty() {
                            self.emit_delta(json!({"reasoning_content": t}), out);
                        }
                    }
                    Some("signature_delta") => {
                        let s = delta
                            .get("signature")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        if let Some(Block::Thinking { signature, .. }) = self.block(index) {
                            signature.push_str(&s);
                        }
                    }
                    _ => {}
                }
            }
            Some("content_block_stop") => {
                let index = index_of(v);
                let marker = match self.block(index) {
                    Some(Block::Thinking { text, signature }) => {
                        let block = json!({
                            "type": "thinking",
                            "thinking": text.clone(),
                            "signature": signature.clone(),
                        });
                        reasoning_content("", &[block])
                    }
                    Some(Block::RedactedThinking { data }) => {
                        let block = json!({"type": "redacted_thinking", "data": data.clone()});
                        reasoning_content("", &[block])
                    }
                    _ => None,
                };
                if let Some(m) = marker {
                    // The readable text already went out as deltas; this
                    // delta only carries the signed block for replay.
                    self.emit_delta(json!({"reasoning_content": format!("\n{m}")}), out);
                }
                self.set_block(index, Block::Other);
            }
            Some("message_delta") => {
                if let Some(reason) = v
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    self.stop_reason = Some(reason.to_string());
                }
                if let Some(n) = v
                    .get("usage")
                    .and_then(|u| u.get("output_tokens"))
                    .and_then(Value::as_u64)
                {
                    self.output_tokens = n;
                }
                let reason = finish_reason(self.stop_reason.as_deref(), self.tool_calls > 0);
                self.emit_finish(Some(reason), out);
            }
            Some("message_stop") => {
                if !self.finish_sent {
                    let reason = finish_reason(self.stop_reason.as_deref(), self.tool_calls > 0);
                    self.emit_finish(Some(reason), out);
                }
                self.emit_done(out);
            }
            Some("error") => {
                let message = v
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("upstream error");
                let kind = v
                    .get("error")
                    .and_then(|e| e.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("error");
                return Err(LlmError::Stream(format!(
                    "Anthropic stream error ({kind}): {message}"
                )));
            }
            // `ping` and unknown events.
            _ => {}
        }
        Ok(())
    }

    fn block(&mut self, index: usize) -> Option<&mut Block> {
        self.blocks.get_mut(index).and_then(Option::as_mut)
    }

    fn set_block(&mut self, index: usize, block: Block) {
        if self.blocks.len() <= index {
            self.blocks.resize(index + 1, None);
        }
        self.blocks[index] = Some(block);
    }

    fn chunk(&self, choices: Value, usage: Option<Value>) -> Value {
        let mut chunk = Map::new();
        chunk.insert("id".into(), json!(self.id));
        chunk.insert("object".into(), json!("chat.completion.chunk"));
        chunk.insert("created".into(), json!(self.created));
        chunk.insert("model".into(), json!(self.model));
        chunk.insert("choices".into(), choices);
        if let Some(u) = usage {
            chunk.insert("usage".into(), u);
        }
        Value::Object(chunk)
    }

    fn write(out: &mut Vec<u8>, payload: &Value) {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(payload.to_string().as_bytes());
        out.extend_from_slice(b"\n\n");
    }

    fn emit_delta(&mut self, mut delta: Value, out: &mut Vec<u8>) {
        if !self.role_sent {
            self.role_sent = true;
            if delta.get("role").is_none() {
                delta["role"] = json!("assistant");
            }
        }
        let chunk = self.chunk(
            json!([{"index": 0, "delta": delta, "finish_reason": null}]),
            None,
        );
        Self::write(out, &chunk);
    }

    fn emit_finish(&mut self, reason: Option<&str>, out: &mut Vec<u8>) {
        if self.finish_sent {
            return;
        }
        self.finish_sent = true;
        if !self.role_sent {
            self.emit_delta(json!({"role": "assistant", "content": ""}), out);
        }
        let chunk = self.chunk(
            json!([{"index": 0, "delta": {}, "finish_reason": reason}]),
            None,
        );
        Self::write(out, &chunk);
    }

    fn emit_done(&mut self, out: &mut Vec<u8>) {
        if self.done {
            return;
        }
        self.done = true;
        let mut u = self.input_usage.clone().unwrap_or_else(|| json!({}));
        u["output_tokens"] = json!(self.output_tokens);
        let chunk = self.chunk(json!([]), Some(usage(Some(&u))));
        Self::write(out, &chunk);
        out.extend_from_slice(b"data: [DONE]\n\n");
    }
}

fn index_of(v: &Value) -> usize {
    v.get("index")
        .and_then(Value::as_u64)
        .and_then(|i| usize::try_from(i).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::StreamAccumulator;
    use crate::types::ChatCompletionChunk;

    fn sse(events: &[(&str, Value)]) -> Vec<u8> {
        let mut s = String::new();
        for (name, data) in events {
            s.push_str(&format!("event: {name}\ndata: {data}\n\n"));
        }
        s.into_bytes()
    }

    fn chunks(bytes: &[u8]) -> Vec<Value> {
        String::from_utf8_lossy(bytes)
            .split("\n\n")
            .filter_map(|l| l.strip_prefix("data: "))
            .filter(|d| *d != "[DONE]")
            .map(|d| serde_json::from_str(d).unwrap())
            .collect()
    }

    #[test]
    fn text_tool_and_usage_stream() {
        let upstream = sse(&[
            (
                "message_start",
                json!({"type":"message_start","message":{"id":"msg_9","model":"claude-sonnet-5-5","usage":{"input_tokens":12,"cache_read_input_tokens":100,"output_tokens":1}}}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":0}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"lookup","input":{}}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"q\":"}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"1}"}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":1}),
            ),
            (
                "message_delta",
                json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}}),
            ),
            ("message_stop", json!({"type":"message_stop"})),
        ]);
        let mut t = Translator::new("claude-sonnet-5-5", 7);
        let mut out = Vec::new();
        // Feed in awkward pieces to exercise the SSE decoder.
        for piece in upstream.chunks(13) {
            out.extend(t.push(piece).unwrap());
        }
        assert!(t.is_done());
        assert!(t.finish().unwrap().is_empty());
        let text = String::from_utf8_lossy(&out);
        assert!(text.ends_with("data: [DONE]\n\n"));

        let c = chunks(&out);
        assert_eq!(c[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(c[0]["id"], "msg_9");
        let content: String = c
            .iter()
            .filter_map(|ch| {
                ch["choices"][0]["delta"]["content"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(content, "Hello");
        let args: String = c
            .iter()
            .filter_map(|ch| {
                ch["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(args, "{\"q\":1}");
        let finish = c
            .iter()
            .find(|ch| !ch["choices"][0]["finish_reason"].is_null())
            .unwrap();
        assert_eq!(finish["choices"][0]["finish_reason"], "tool_calls");
        let last = c.last().unwrap();
        assert!(last["choices"].as_array().unwrap().is_empty());
        assert_eq!(last["usage"]["prompt_tokens"], 112);
        assert_eq!(last["usage"]["completion_tokens"], 9);
        assert_eq!(last["usage"]["prompt_tokens_details"]["cached_tokens"], 100);

        // The agent's own stream accumulator accepts the output.
        let mut decoder = SseDecoder::default();
        let mut acc = StreamAccumulator::new(false, false);
        for ev in decoder.push(&out).unwrap() {
            if ev.data == "[DONE]" {
                break;
            }
            let chunk: ChatCompletionChunk = serde_json::from_str(&ev.data).unwrap();
            acc.push(chunk);
        }
        let resp = acc.into_response();
        assert_eq!(resp.message.text(), "Hello");
        assert_eq!(resp.message.tool_calls.len(), 1);
        assert_eq!(resp.message.tool_calls[0].function.name, "lookup");
        assert_eq!(resp.usage.cached_tokens, 100);
    }

    #[test]
    fn thinking_blocks_are_streamed_readably_and_as_replay_marker() {
        let upstream = sse(&[
            (
                "message_start",
                json!({"type":"message_start","message":{"id":"m","usage":{"input_tokens":1}}}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hm"}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":0}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"ok"}}),
            ),
            (
                "content_block_stop",
                json!({"type":"content_block_stop","index":1}),
            ),
            (
                "message_delta",
                json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}),
            ),
            ("message_stop", json!({"type":"message_stop"})),
        ]);
        let mut t = Translator::new("m", 1);
        let out = t.push(&upstream).unwrap();
        let reasoning: String = chunks(&out)
            .iter()
            .filter_map(|ch| {
                ch["choices"][0]["delta"]["reasoning_content"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        assert!(reasoning.starts_with("hm\n<talon-thinking>"));
        let blocks = super::super::translate::thinking_blocks(&reasoning);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0]["signature"], "sig");
        assert_eq!(blocks[0]["thinking"], "hm");
        let finish = chunks(&out)
            .into_iter()
            .find(|ch| !ch["choices"][0]["finish_reason"].is_null())
            .unwrap();
        assert_eq!(finish["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn truncated_upstream_ends_with_abort_and_done() {
        let upstream = sse(&[
            (
                "message_start",
                json!({"type":"message_start","message":{"id":"m","usage":{"input_tokens":1}}}),
            ),
            (
                "content_block_start",
                json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            ),
            (
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"par"}}),
            ),
        ]);
        let mut t = Translator::new("m", 1);
        let mut out = t.push(&upstream).unwrap();
        assert!(!t.is_done());
        out.extend(t.finish().unwrap());
        assert!(t.is_done());
        let c = chunks(&out);
        let finish = c
            .iter()
            .find(|ch| !ch["choices"][0]["finish_reason"].is_null())
            .unwrap();
        assert_eq!(finish["choices"][0]["finish_reason"], "abort");
        assert!(String::from_utf8_lossy(&out).ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn error_event_fails_the_stream() {
        let upstream = sse(&[(
            "error",
            json!({"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}),
        )]);
        let mut t = Translator::new("m", 1);
        let err = t.push(&upstream).unwrap_err();
        assert!(err.to_string().contains("overloaded_error"));
    }
}
