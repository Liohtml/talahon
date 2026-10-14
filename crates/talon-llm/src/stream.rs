//! Streaming chat completions: the delta accumulator, the event stream, and
//! a small router that keeps `<think>` / tool-call markup out of the
//! user-visible `Content` events.

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;

use crate::error::{LlmError, MAX_ERROR_MESSAGE_CHARS, error_message_from_value, truncate};
use crate::fallback::{
    HERMES_OPEN, LLAMA_MARKER, MISTRAL_MARKER, PostProcessOptions, THINK_CLOSE, THINK_OPEN,
    postprocess_message,
};
use crate::sse::{SseDecoder, SseEvent};
use crate::types::{
    ChatCompletionChunk, ChatMessage, ChatRequest, ChatResponse, FinishReason, PostProcessReport,
    ResponseFormat, Role, ToolCall, ToolCallDelta, Usage,
};

/// One event of a streamed completion.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    /// User-visible text delta (think/tool-call markup removed).
    Content(String),
    /// Reasoning ("thinking") delta.
    Reasoning(String),
    /// A tool call started (its name is known).
    ToolCallStart {
        /// Position in the final `tool_calls` array.
        index: u32,
        /// Call id (may be empty if the server sends it later / never).
        id: String,
        /// Tool name.
        name: String,
    },
    /// A fragment of a tool call's JSON arguments.
    ToolCallArguments {
        /// Position in the final `tool_calls` array.
        index: u32,
        /// The fragment.
        fragment: String,
    },
    /// Token usage (sent once, at the end, with `include_usage`).
    Usage(Usage),
    /// The assembled, post-processed response. Always the last event.
    Done(Box<ChatResponse>),
}

// ---------------------------------------------------------------------------
// Accumulator
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
    announced: bool,
}

/// Assembles `chat.completion.chunk` deltas (content, reasoning, tool-call
/// fragments, usage) into a final [`ChatResponse`].
///
/// Usable on its own when you parse SSE yourself; [`ChatStream`] uses it
/// internally.
#[derive(Debug, Default)]
pub struct StreamAccumulator {
    id: String,
    model: String,
    content: String,
    reasoning: String,
    calls: BTreeMap<u32, PartialCall>,
    last_index: Option<u32>,
    finish_reason: Option<FinishReason>,
    usage: Option<Usage>,
    chunks: usize,
    router: ContentRouter,
}

impl StreamAccumulator {
    /// An accumulator. `route_think` routes `<think>` text in `content` to
    /// [`StreamEvent::Reasoning`]; `hide_tool_markup` suppresses `Content`
    /// events once text tool-call markup (`<tool_call>`, `[TOOL_CALLS]`,
    /// `<|python_tag|>`) starts. The *final* response always carries the
    /// full raw text for post-processing either way.
    pub fn new(route_think: bool, hide_tool_markup: bool) -> Self {
        Self {
            router: ContentRouter::new(route_think, hide_tool_markup),
            ..Self::default()
        }
    }

    /// Feed one chunk; returns the events it produced.
    pub fn push(&mut self, chunk: ChatCompletionChunk) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        self.chunks += 1;
        if self.id.is_empty() && !chunk.id.is_empty() {
            self.id = chunk.id;
        }
        if self.model.is_empty() && !chunk.model.is_empty() {
            self.model = chunk.model;
        }
        for choice in chunk.choices {
            if choice.index != 0 {
                continue; // Talon never asks for n > 1.
            }
            let delta = choice.delta;
            if let Some(r) = delta.reasoning_content.filter(|r| !r.is_empty()) {
                self.reasoning.push_str(&r);
                events.push(StreamEvent::Reasoning(r));
            }
            if let Some(c) = delta.content.filter(|c| !c.is_empty()) {
                self.content.push_str(&c);
                self.router.push(&c, &mut events);
            }
            for tc in delta.tool_calls {
                self.push_tool_delta(tc, &mut events);
            }
            if let Some(fr) = choice.finish_reason {
                self.finish_reason = Some(fr);
            }
        }
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage);
            events.push(StreamEvent::Usage(usage));
        }
        events
    }

    fn push_tool_delta(&mut self, tc: ToolCallDelta, events: &mut Vec<StreamEvent>) {
        let index = match tc.index {
            Some(i) => i,
            None => {
                let new_call = tc
                    .id
                    .as_deref()
                    .filter(|id| !id.is_empty())
                    .is_some_and(|id| !self.calls.values().any(|c| c.id == id));
                if new_call || self.last_index.is_none() {
                    self.calls
                        .keys()
                        .next_back()
                        .map_or(0, |k| k.saturating_add(1))
                } else {
                    self.last_index.unwrap_or(0)
                }
            }
        };
        self.last_index = Some(index);
        let entry = self.calls.entry(index).or_default();
        if let Some(id) = tc.id.filter(|id| !id.is_empty()) {
            if entry.id.is_empty() {
                entry.id = id;
            }
        }
        if let Some(f) = tc.function {
            if let Some(name) = f.name.filter(|n| !n.is_empty()) {
                if entry.name.is_empty() {
                    entry.name = name;
                } else if entry.name != name {
                    entry.name.push_str(&name);
                }
            }
            if !entry.announced && !entry.name.is_empty() {
                entry.announced = true;
                events.push(StreamEvent::ToolCallStart {
                    index,
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                });
            }
            if let Some(args) = f.arguments.filter(|a| !a.is_empty()) {
                entry.arguments.push_str(&args);
                events.push(StreamEvent::ToolCallArguments {
                    index,
                    fragment: args,
                });
            }
        }
    }

    /// Whether a `finish_reason` has been seen.
    pub fn saw_finish_reason(&self) -> bool {
        self.finish_reason.is_some()
    }

    /// Number of chunks fed so far.
    pub fn chunk_count(&self) -> usize {
        self.chunks
    }

    /// Emit any text the router was holding back (call once at the end).
    pub fn flush(&mut self) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        self.router.flush(&mut events);
        events
    }

    /// The assembled response (raw: no fallback parsing applied).
    pub fn into_response(self) -> ChatResponse {
        let tool_calls: Vec<ToolCall> = self
            .calls
            .into_values()
            .filter(|c| !(c.name.is_empty() && c.arguments.is_empty()))
            .map(|c| ToolCall::new(c.id, c.name, c.arguments))
            .collect();
        let message = ChatMessage {
            role: Role::Assistant,
            content: (!self.content.is_empty()).then_some(self.content),
            tool_calls,
            tool_call_id: None,
            name: None,
            reasoning_content: (!self.reasoning.is_empty()).then_some(self.reasoning),
        };
        ChatResponse {
            id: self.id,
            model: self.model,
            message,
            finish_reason: self.finish_reason,
            usage: self.usage.unwrap_or_default(),
            postprocess: PostProcessReport::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Content router
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum RouteMode {
    #[default]
    Text,
    Think,
    Suppressed,
}

/// Splits streamed content into Content / Reasoning events and hides
/// tool-call markup, holding back partial markers split across chunks.
#[derive(Debug, Default)]
struct ContentRouter {
    mode: RouteMode,
    pending: String,
    route_think: bool,
    hide_tool_markup: bool,
    trim_next: bool,
}

const TOOL_MARKERS: [&str; 3] = [HERMES_OPEN, MISTRAL_MARKER, LLAMA_MARKER];

impl ContentRouter {
    fn new(route_think: bool, hide_tool_markup: bool) -> Self {
        Self {
            route_think,
            hide_tool_markup,
            ..Self::default()
        }
    }

    fn text_markers(&self) -> Vec<&'static str> {
        let mut m = Vec::with_capacity(5);
        if self.route_think {
            m.push(THINK_OPEN);
            m.push(THINK_CLOSE);
        }
        if self.hide_tool_markup {
            m.extend(TOOL_MARKERS);
        }
        m
    }

    fn push(&mut self, delta: &str, out: &mut Vec<StreamEvent>) {
        if !self.route_think && !self.hide_tool_markup {
            out.push(StreamEvent::Content(delta.to_string()));
            return;
        }
        self.pending.push_str(delta);
        loop {
            match self.mode {
                RouteMode::Suppressed => {
                    self.pending.clear();
                    return;
                }
                RouteMode::Text => {
                    let markers = self.text_markers();
                    let found = markers
                        .iter()
                        .filter_map(|m| self.pending.find(m).map(|p| (p, *m)))
                        .min_by_key(|(p, _)| *p);
                    if let Some((pos, marker)) = found {
                        let before = self.pending[..pos].to_string();
                        self.emit_content(before, out);
                        self.pending.drain(..pos + marker.len());
                        self.mode = if marker == THINK_OPEN {
                            RouteMode::Think
                        } else if marker == THINK_CLOSE {
                            // Opening tag was in the prompt; drop the stray close.
                            self.trim_next = true;
                            RouteMode::Text
                        } else {
                            RouteMode::Suppressed
                        };
                        continue;
                    }
                    let keep = partial_suffix_len(&self.pending, &markers);
                    let emit_len = self.pending.len() - keep;
                    let text: String = self.pending.drain(..emit_len).collect();
                    self.emit_content(text, out);
                    return;
                }
                RouteMode::Think => {
                    if let Some(pos) = self.pending.find(THINK_CLOSE) {
                        let reasoning: String = self.pending.drain(..pos).collect();
                        if !reasoning.is_empty() {
                            out.push(StreamEvent::Reasoning(reasoning));
                        }
                        self.pending.drain(..THINK_CLOSE.len());
                        self.mode = RouteMode::Text;
                        self.trim_next = true;
                        continue;
                    }
                    let keep = partial_suffix_len(&self.pending, &[THINK_CLOSE]);
                    let emit_len = self.pending.len() - keep;
                    let reasoning: String = self.pending.drain(..emit_len).collect();
                    if !reasoning.is_empty() {
                        out.push(StreamEvent::Reasoning(reasoning));
                    }
                    return;
                }
            }
        }
    }

    fn emit_content(&mut self, text: String, out: &mut Vec<StreamEvent>) {
        let text = if self.trim_next {
            let t = text.trim_start();
            if t.is_empty() {
                return;
            }
            self.trim_next = false;
            t.to_string()
        } else {
            text
        };
        if !text.is_empty() {
            out.push(StreamEvent::Content(text));
        }
    }

    fn flush(&mut self, out: &mut Vec<StreamEvent>) {
        let rest = std::mem::take(&mut self.pending);
        match self.mode {
            RouteMode::Text => self.emit_content(rest, out),
            RouteMode::Think if !rest.is_empty() => out.push(StreamEvent::Reasoning(rest)),
            _ => {}
        }
    }
}

/// Length of the longest suffix of `s` that is a proper prefix of a marker.
/// Markers are ASCII, so the cut is always on a char boundary.
fn partial_suffix_len(s: &str, markers: &[&str]) -> usize {
    let mut best = 0;
    for m in markers {
        for k in (1..m.len()).rev() {
            if k <= s.len() && s.ends_with(&m[..k]) {
                best = best.max(k);
                break;
            }
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Post-processing shared by `chat` and `chat_stream`
// ---------------------------------------------------------------------------

/// Applies fallback parsing to a finished response, using the request's
/// offered tools.
#[derive(Debug, Clone, Default)]
pub(crate) struct Finalizer {
    offered_tools: Vec<String>,
    options: PostProcessOptions,
}

impl Finalizer {
    pub(crate) fn for_request(req: &ChatRequest, options: PostProcessOptions) -> Self {
        // Structured-output requests produce JSON on purpose: never mistake
        // it for a bare tool call.
        let structured = matches!(
            req.response_format,
            Some(ResponseFormat::JsonSchema { .. } | ResponseFormat::JsonObject)
        );
        let offered_tools = if req.tools_enabled() && !structured {
            req.offered_tool_names().map(str::to_string).collect()
        } else {
            Vec::new()
        };
        Self {
            offered_tools,
            options,
        }
    }

    pub(crate) fn hides_tool_markup(&self) -> bool {
        self.options.recover_tool_calls && !self.offered_tools.is_empty()
    }

    pub(crate) fn routes_think(&self) -> bool {
        self.options.split_think
    }

    pub(crate) fn finalize(&self, resp: &mut ChatResponse) {
        resp.postprocess =
            postprocess_message(&mut resp.message, &self.offered_tools, &self.options);
        if resp.message.has_tool_calls()
            && matches!(resp.finish_reason, None | Some(FinishReason::Stop))
        {
            resp.finish_reason = Some(FinishReason::ToolCalls);
        }
        let report = &resp.postprocess;
        if report.recovered_tool_calls > 0 {
            tracing::debug!(
                count = report.recovered_tool_calls,
                format = ?report.recovered_format,
                "recovered tool calls from text"
            );
        }
        if !report.rejected_tool_calls.is_empty() || !report.unknown_tool_names.is_empty() {
            tracing::debug!(
                rejected = report.rejected_tool_calls.len(),
                unknown = ?report.unknown_tool_names,
                "model produced tool calls that were not accepted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ChatStream
// ---------------------------------------------------------------------------

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, LlmError>> + Send>>;

/// A streamed chat completion: a `Stream` of [`StreamEvent`]s ending with
/// [`StreamEvent::Done`].
///
/// Dropping it aborts the request.
pub struct ChatStream {
    body: ByteStream,
    idle_timeout: Option<Duration>,
    idle_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    decoder: SseDecoder,
    acc: Option<StreamAccumulator>,
    finalizer: Finalizer,
    pending: VecDeque<StreamEvent>,
    received: usize,
    max_bytes: usize,
    done: bool,
}

impl std::fmt::Debug for ChatStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatStream")
            .field("received", &self.received)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl ChatStream {
    /// `idle_timeout`: maximum silence between two chunks. Must be called
    /// inside a tokio runtime when set.
    pub(crate) fn new(
        body: ByteStream,
        finalizer: Finalizer,
        max_bytes: usize,
        idle_timeout: Option<Duration>,
    ) -> Self {
        let acc = StreamAccumulator::new(finalizer.routes_think(), finalizer.hides_tool_markup());
        Self {
            body,
            idle_timeout,
            idle_sleep: idle_timeout.map(|d| Box::pin(tokio::time::sleep(d))),
            decoder: SseDecoder::default(),
            acc: Some(acc),
            finalizer,
            pending: VecDeque::new(),
            received: 0,
            max_bytes,
            done: false,
        }
    }

    /// Wrap a response that arrived complete (server ignored `stream`).
    pub(crate) fn from_completed(mut resp: ChatResponse, finalizer: &Finalizer) -> Self {
        finalizer.finalize(&mut resp);
        let mut pending = VecDeque::new();
        if let Some(r) = resp.message.reasoning_content.clone() {
            pending.push_back(StreamEvent::Reasoning(r));
        }
        if let Some(c) = resp.message.content.clone() {
            pending.push_back(StreamEvent::Content(c));
        }
        for (i, call) in resp.message.tool_calls.iter().enumerate() {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            pending.push_back(StreamEvent::ToolCallStart {
                index,
                id: call.id.clone(),
                name: call.function.name.clone(),
            });
            pending.push_back(StreamEvent::ToolCallArguments {
                index,
                fragment: call.function.arguments.clone(),
            });
        }
        if !resp.usage.is_zero() {
            pending.push_back(StreamEvent::Usage(resp.usage));
        }
        pending.push_back(StreamEvent::Done(Box::new(resp)));
        Self {
            body: Box::pin(futures::stream::empty()),
            idle_timeout: None,
            idle_sleep: None,
            decoder: SseDecoder::default(),
            acc: None,
            finalizer: finalizer.clone(),
            pending,
            received: 0,
            max_bytes: usize::MAX,
            done: true,
        }
    }

    /// Build a stream over raw SSE bytes (any source). Mostly useful for
    /// tests and for callers that perform the HTTP request themselves.
    pub fn from_sse_bytes<S>(bytes: S, request: &ChatRequest, options: PostProcessOptions) -> Self
    where
        S: Stream<Item = Result<Bytes, LlmError>> + Send + 'static,
    {
        Self::new(
            Box::pin(bytes),
            Finalizer::for_request(request, options),
            usize::MAX,
            None,
        )
    }

    /// Drain the stream and return the final response.
    pub async fn into_response(mut self) -> Result<ChatResponse, LlmError> {
        while let Some(ev) = self.next().await {
            if let StreamEvent::Done(resp) = ev? {
                return Ok(*resp);
            }
        }
        Err(LlmError::Stream("stream ended without a response".into()))
    }

    fn handle_sse(&mut self, ev: SseEvent) -> Result<(), LlmError> {
        if self.acc.is_none() {
            return Ok(()); // already finalized
        }
        let data = ev.data.trim();
        if data.is_empty() {
            return Ok(());
        }
        if data == "[DONE]" {
            self.finalize();
            return Ok(());
        }
        let value: Value = serde_json::from_str(data)
            .map_err(|e| LlmError::Decode(format!("invalid stream chunk: {e}")))?;
        if ev.event.as_deref() == Some("error")
            || value.get("error").is_some()
            || value.get("object").and_then(Value::as_str) == Some("error")
        {
            let msg = error_message_from_value(&value)
                .unwrap_or_else(|| truncate(data, MAX_ERROR_MESSAGE_CHARS));
            return Err(LlmError::Stream(format!(
                "server error during stream: {msg}"
            )));
        }
        let chunk: ChatCompletionChunk = serde_json::from_value(value)
            .map_err(|e| LlmError::Decode(format!("invalid stream chunk: {e}")))?;
        if let Some(acc) = self.acc.as_mut() {
            self.pending.extend(acc.push(chunk));
        }
        Ok(())
    }

    fn finalize(&mut self) {
        if let Some(mut acc) = self.acc.take() {
            self.pending.extend(acc.flush());
            let mut resp = acc.into_response();
            self.finalizer.finalize(&mut resp);
            self.pending.push_back(StreamEvent::Done(Box::new(resp)));
        }
        self.done = true;
    }

    fn fail(&mut self, err: LlmError) -> Poll<Option<Result<StreamEvent, LlmError>>> {
        self.done = true;
        self.acc = None;
        self.pending.clear();
        Poll::Ready(Some(Err(err)))
    }
}

impl Stream for ChatStream {
    type Item = Result<StreamEvent, LlmError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        loop {
            if let Some(ev) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(ev)));
            }
            if this.done {
                return Poll::Ready(None);
            }
            match this.body.as_mut().poll_next(cx) {
                Poll::Pending => {
                    if let Some(sleep) = this.idle_sleep.as_mut() {
                        if sleep.as_mut().poll(cx).is_ready() {
                            let secs = this.idle_timeout.map_or(0, |d| d.as_secs());
                            return this.fail(LlmError::Timeout(format!(
                                "no data from LLM server for {secs}s"
                            )));
                        }
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    if let (Some(sleep), Some(idle)) = (this.idle_sleep.as_mut(), this.idle_timeout)
                    {
                        sleep.as_mut().reset(tokio::time::Instant::now() + idle);
                    }
                    this.received = this.received.saturating_add(bytes.len());
                    if this.received > this.max_bytes {
                        return this.fail(LlmError::ResponseTooLarge {
                            limit: this.max_bytes,
                        });
                    }
                    let events = match this.decoder.push(&bytes) {
                        Ok(evs) => evs,
                        Err(e) => return this.fail(e),
                    };
                    for ev in events {
                        if let Err(e) = this.handle_sse(ev) {
                            return this.fail(e);
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => return this.fail(e),
                Poll::Ready(None) => {
                    match this.decoder.finish() {
                        Ok(Some(ev)) => {
                            if let Err(e) = this.handle_sse(ev) {
                                return this.fail(e);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => return this.fail(e),
                    }
                    if this.acc.is_some() {
                        let complete = this
                            .acc
                            .as_ref()
                            .is_some_and(StreamAccumulator::saw_finish_reason);
                        if complete {
                            this.finalize();
                        } else {
                            return this.fail(LlmError::Stream(
                                "connection closed before the completion finished".into(),
                            ));
                        }
                    }
                    this.done = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChatMessage;
    use serde_json::json;
    use talon_core::tool::ToolSpec;

    fn chunk(v: Value) -> ChatCompletionChunk {
        serde_json::from_value(v).unwrap()
    }

    fn sse(lines: &[Value]) -> String {
        let mut s = String::new();
        for l in lines {
            s.push_str("data: ");
            s.push_str(&l.to_string());
            s.push_str("\n\n");
        }
        s.push_str("data: [DONE]\n\n");
        s
    }

    fn request_with_tool() -> ChatRequest {
        let spec = ToolSpec {
            name: "get_weather".into(),
            description: "d".into(),
            parameters: json!({"type":"object"}),
        };
        ChatRequest::new("m", vec![ChatMessage::user("hi")]).tools([&spec])
    }

    fn byte_chunks(s: &str, size: usize) -> Vec<Result<Bytes, LlmError>> {
        s.as_bytes()
            .chunks(size)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect()
    }

    #[test]
    fn accumulates_tool_call_deltas() {
        let mut acc = StreamAccumulator::new(true, true);
        let mut events = Vec::new();
        events.extend(acc.push(chunk(json!({"id":"c1","model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}))));
        events.extend(acc.push(chunk(json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}))));
        events.extend(acc.push(chunk(json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\": "}}]}}]}))));
        events.extend(acc.push(chunk(json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Bonn\"}"}}]}}]}))));
        events.extend(acc.push(chunk(json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"noop","arguments":"{}"}}]}}]}))));
        events.extend(acc.push(chunk(
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}),
        )));
        events.extend(acc.push(chunk(json!({"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}}))));
        assert!(acc.saw_finish_reason());
        assert_eq!(acc.chunk_count(), 7);
        let resp = acc.into_response();
        assert_eq!(resp.id, "c1");
        assert_eq!(resp.message.tool_calls.len(), 2);
        assert_eq!(resp.message.tool_calls[0].id, "call_a");
        assert_eq!(
            resp.message.tool_calls[0].parse_arguments().unwrap(),
            json!({"city":"Bonn"})
        );
        assert_eq!(resp.message.tool_calls[1].name(), "noop");
        assert_eq!(resp.finish_reason, Some(FinishReason::ToolCalls));
        assert_eq!(resp.usage.cached_tokens, 4);
        assert!(resp.message.content.is_none());
        let starts = events
            .iter()
            .filter(|e| matches!(e, StreamEvent::ToolCallStart { .. }))
            .count();
        assert_eq!(starts, 2);
        assert!(events.contains(&StreamEvent::ToolCallArguments {
            index: 0,
            fragment: "\"Bonn\"}".into()
        }));
    }

    #[test]
    fn tool_deltas_without_index_are_grouped_by_id() {
        let mut acc = StreamAccumulator::new(false, false);
        acc.push(chunk(json!({"choices":[{"delta":{"tool_calls":[{"id":"a","function":{"name":"f","arguments":"{\"x\""}}]}}]})));
        acc.push(chunk(
            json!({"choices":[{"delta":{"tool_calls":[{"function":{"arguments":":1}"}}]}}]}),
        ));
        acc.push(chunk(json!({"choices":[{"delta":{"tool_calls":[{"id":"b","function":{"name":"g","arguments":"{}"}}]},"finish_reason":"stop"}]})));
        let resp = acc.into_response();
        assert_eq!(resp.message.tool_calls.len(), 2);
        assert_eq!(resp.message.tool_calls[0].function.arguments, "{\"x\":1}");
        assert_eq!(resp.message.tool_calls[1].id, "b");
    }

    #[test]
    fn router_splits_think_and_hides_tool_markup_across_chunks() {
        let mut router = ContentRouter::new(true, true);
        let mut out = Vec::new();
        for piece in [
            "<th",
            "ink>plan",
            " it</thi",
            "nk>\n\nHello ",
            "world <tool",
            "_call>{\"name\"",
            "}",
        ] {
            router.push(piece, &mut out);
        }
        router.flush(&mut out);
        let reasoning: String = out
            .iter()
            .filter_map(|e| match e {
                StreamEvent::Reasoning(r) => Some(r.as_str()),
                _ => None,
            })
            .collect();
        let content: String = out
            .iter()
            .filter_map(|e| match e {
                StreamEvent::Content(c) => Some(c.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(reasoning, "plan it");
        assert_eq!(content, "Hello world ");
    }

    #[test]
    fn router_passthrough_and_stray_close() {
        let mut router = ContentRouter::new(false, false);
        let mut out = Vec::new();
        router.push("<think>x", &mut out);
        assert_eq!(out, vec![StreamEvent::Content("<think>x".into())]);

        let mut router = ContentRouter::new(true, false);
        let mut out = Vec::new();
        router.push("a < b", &mut out);
        router.push("</think> c", &mut out);
        router.flush(&mut out);
        let content: String = out
            .iter()
            .filter_map(|e| match e {
                StreamEvent::Content(c) => Some(c.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(content, "a < bc");
    }

    #[tokio::test]
    async fn chat_stream_end_to_end_with_byte_splits() {
        let body = sse(&[
            json!({"id":"x","model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"<think>hmm</think>"}}]}),
            json!({"choices":[{"index":0,"delta":{"content":"<tool_call>{\"name\": \"get_weather\", "}}]}),
            json!({"choices":[{"index":0,"delta":{"content":"\"arguments\": {\"city\": \"Köln\"}}</tool_call>"},"finish_reason":"stop"}]}),
            json!({"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}),
        ]);
        for size in [1, 3, 17, 4096] {
            let req = request_with_tool();
            let stream = ChatStream::from_sse_bytes(
                futures::stream::iter(byte_chunks(&body, size)),
                &req,
                PostProcessOptions::default(),
            );
            let events: Vec<_> = stream.collect().await;
            let events: Vec<StreamEvent> = events.into_iter().map(Result::unwrap).collect();
            assert!(
                !events.iter().any(|e| matches!(e, StreamEvent::Content(_))),
                "markup must not leak as content (size {size}): {events:?}"
            );
            assert!(events.contains(&StreamEvent::Reasoning("hmm".into())));
            let Some(StreamEvent::Done(resp)) = events.last() else {
                panic!("last event must be Done");
            };
            assert_eq!(resp.message.tool_calls.len(), 1);
            assert_eq!(
                resp.message.tool_calls[0].parse_arguments().unwrap(),
                json!({"city": "Köln"})
            );
            assert_eq!(resp.finish_reason, Some(FinishReason::ToolCalls));
            assert_eq!(resp.message.reasoning_content.as_deref(), Some("hmm"));
            assert_eq!(resp.usage.prompt_tokens, 7);
            assert_eq!(resp.postprocess.recovered_tool_calls, 1);
        }
    }

    #[tokio::test]
    async fn chat_stream_errors() {
        let req = ChatRequest::new("m", vec![]);
        // Truncated: no finish_reason, no [DONE].
        let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"par\"}}]}\n\n";
        let s = ChatStream::from_sse_bytes(
            futures::stream::iter(byte_chunks(body, 8)),
            &req,
            PostProcessOptions::default(),
        );
        let err = s.into_response().await.unwrap_err();
        assert!(matches!(err, LlmError::Stream(_)), "{err:?}");

        // Error object mid-stream.
        let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\ndata: {\"object\":\"error\",\"message\":\"boom\",\"code\":500}\n\n";
        let s = ChatStream::from_sse_bytes(
            futures::stream::iter(byte_chunks(body, 64)),
            &req,
            PostProcessOptions::default(),
        );
        let err = s.into_response().await.unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");

        // Garbage chunk.
        let s = ChatStream::from_sse_bytes(
            futures::stream::iter(byte_chunks("data: {not json\n\n", 64)),
            &req,
            PostProcessOptions::default(),
        );
        assert!(matches!(
            s.into_response().await.unwrap_err(),
            LlmError::Decode(_)
        ));

        // Finish reason but no [DONE] is accepted.
        let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n";
        let s = ChatStream::from_sse_bytes(
            futures::stream::iter(byte_chunks(body, 5)),
            &req,
            PostProcessOptions::default(),
        );
        assert_eq!(s.into_response().await.unwrap().message.text(), "ok");
    }

    #[tokio::test]
    async fn idle_timeout_fires_when_the_server_goes_silent() {
        let req = ChatRequest::new("m", vec![]);
        let first = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\n";
        let body = futures::stream::iter(byte_chunks(first, 64)).chain(futures::stream::pending());
        let stream = ChatStream::new(
            Box::pin(body),
            Finalizer::for_request(&req, PostProcessOptions::default()),
            usize::MAX,
            Some(Duration::from_millis(50)),
        );
        let started = std::time::Instant::now();
        let events: Vec<_> = stream.collect().await;
        assert!(matches!(events.first(), Some(Ok(StreamEvent::Content(c))) if c == "a"));
        assert!(
            matches!(events.last(), Some(Err(LlmError::Timeout(_)))),
            "{events:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn completed_response_is_replayed_as_events() {
        let req = ChatRequest::new("m", vec![]);
        let resp = ChatResponse {
            id: "i".into(),
            model: "m".into(),
            message: ChatMessage::assistant("<think>r</think>answer"),
            finish_reason: Some(FinishReason::Stop),
            usage: Usage {
                prompt_tokens: 1,
                completion_tokens: 1,
                cached_tokens: 0,
            },
            postprocess: PostProcessReport::default(),
        };
        let fin = Finalizer::for_request(&req, PostProcessOptions::default());
        let events: Vec<StreamEvent> = ChatStream::from_completed(resp, &fin)
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(events[0], StreamEvent::Reasoning("r".into()));
        assert_eq!(events[1], StreamEvent::Content("answer".into()));
        assert!(matches!(events.last(), Some(StreamEvent::Done(_))));
    }

    #[test]
    fn finalizer_skips_recovery_for_structured_output() {
        let req = request_with_tool().json_schema("s", json!({"type":"object"}), true);
        let fin = Finalizer::for_request(&req, PostProcessOptions::default());
        assert!(!fin.hides_tool_markup());
        let mut resp = ChatResponse {
            id: String::new(),
            model: String::new(),
            message: ChatMessage::assistant("{\"name\":\"get_weather\",\"arguments\":{}}"),
            finish_reason: Some(FinishReason::Stop),
            usage: Usage::default(),
            postprocess: PostProcessReport::default(),
        };
        fin.finalize(&mut resp);
        assert!(resp.message.tool_calls.is_empty());
        assert_eq!(resp.finish_reason, Some(FinishReason::Stop));
    }

    #[test]
    fn partial_suffix() {
        assert_eq!(partial_suffix_len("abc<thi", &[THINK_OPEN]), 4);
        assert_eq!(partial_suffix_len("abc", &[THINK_OPEN]), 0);
        assert_eq!(
            partial_suffix_len("x[TOOL", &[MISTRAL_MARKER, THINK_OPEN]),
            5
        );
    }
}
