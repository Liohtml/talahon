//! [`ChatBackend`]: the seam between the agent loop and the model, so the
//! loop can be unit-tested without HTTP ([`ScriptedBackend`]).

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::client::{VllmClient, estimate_conversation_tokens};
use crate::error::LlmError;
use crate::fallback::PostProcessOptions;
use crate::stream::{Finalizer, StreamEvent};
use crate::types::{ChatMessage, ChatRequest, ChatResponse, TokenCount, ToolDefinition};

/// Callback receiving intermediate [`StreamEvent`]s.
pub type EventSink<'a> = dyn for<'e> FnMut(&'e StreamEvent) + Send + 'a;

/// Something that completes chat requests.
///
/// [`VllmClient`] implements it by streaming; tests use [`ScriptedBackend`].
#[async_trait]
pub trait ChatBackend: Send + Sync {
    /// Complete `req`, reporting intermediate events (text/reasoning/tool
    /// deltas, usage) to `on_event`, and return the final response.
    async fn complete(
        &self,
        req: &ChatRequest,
        on_event: &mut EventSink<'_>,
    ) -> Result<ChatResponse, LlmError>;

    /// Prompt size of a conversation in tokens (may be an estimate).
    async fn count_tokens(&self, messages: &[ChatMessage], tools: &[ToolDefinition]) -> TokenCount {
        TokenCount {
            count: estimate_conversation_tokens(messages, tools),
            max_model_len: None,
            estimated: true,
        }
    }
}

#[async_trait]
impl ChatBackend for VllmClient {
    async fn complete(
        &self,
        req: &ChatRequest,
        on_event: &mut EventSink<'_>,
    ) -> Result<ChatResponse, LlmError> {
        self.chat_streaming(req, |ev| on_event(ev)).await
    }

    async fn count_tokens(&self, messages: &[ChatMessage], tools: &[ToolDefinition]) -> TokenCount {
        self.tokenize_messages(messages, tools).await
    }
}

/// Test double: answers with queued results in order and records every
/// request. Responses go through the same post-processing as real ones
/// (text tool-call recovery, `<think>` splitting), so a scripted
/// `"<tool_call>{...}</tool_call>"` reply behaves like a real server's.
#[derive(Debug, Default)]
pub struct ScriptedBackend {
    queue: Mutex<VecDeque<Result<ChatResponse, LlmError>>>,
    requests: Mutex<Vec<ChatRequest>>,
}

impl ScriptedBackend {
    /// A backend that will return `results` in order.
    pub fn new(results: impl IntoIterator<Item = Result<ChatResponse, LlmError>>) -> Self {
        Self {
            queue: Mutex::new(results.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Queue another result.
    pub fn push(&self, result: Result<ChatResponse, LlmError>) {
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(result);
    }

    /// Requests received so far.
    pub fn requests(&self) -> Vec<ChatRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Results not consumed yet.
    pub fn remaining(&self) -> usize {
        self.queue.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[async_trait]
impl ChatBackend for ScriptedBackend {
    async fn complete(
        &self,
        req: &ChatRequest,
        on_event: &mut EventSink<'_>,
    ) -> Result<ChatResponse, LlmError> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(req.clone());
        let next = self
            .queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front();
        let mut resp =
            next.unwrap_or_else(|| Err(LlmError::Stream("scripted backend exhausted".into())))?;
        Finalizer::for_request(req, PostProcessOptions::default()).finalize(&mut resp);
        if let Some(r) = &resp.message.reasoning_content {
            on_event(&StreamEvent::Reasoning(r.clone()));
        }
        if let Some(c) = &resp.message.content {
            on_event(&StreamEvent::Content(c.clone()));
        }
        for (i, call) in resp.message.tool_calls.iter().enumerate() {
            on_event(&StreamEvent::ToolCallStart {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                id: call.id.clone(),
                name: call.function.name.clone(),
            });
        }
        on_event(&StreamEvent::Usage(resp.usage));
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FinishReason, ToolCall};
    use serde_json::json;
    use talon_core::tool::ToolSpec;

    #[tokio::test]
    async fn scripted_backend_replays_and_postprocesses() {
        let backend = ScriptedBackend::new([
            Ok(ChatResponse::from_message(ChatMessage::assistant(
                "<tool_call>{\"name\":\"lookup\",\"arguments\":{\"q\":1}}</tool_call>",
            ))),
            Ok(ChatResponse::from_message(
                ChatMessage::assistant_tool_calls(None, vec![ToolCall::new("c1", "lookup", "{}")]),
            )),
            Err(LlmError::ContextLengthExceeded("too long".into())),
        ]);
        let spec = ToolSpec {
            name: "lookup".into(),
            description: String::new(),
            parameters: json!({"type":"object"}),
        };
        let req = ChatRequest::new("m", vec![ChatMessage::user("x")]).tools([&spec]);
        let mut events = Vec::new();
        let r1 = backend
            .complete(&req, &mut |e: &StreamEvent| events.push(e.clone()))
            .await
            .unwrap();
        assert_eq!(r1.message.tool_calls.len(), 1);
        assert_eq!(r1.finish_reason, Some(FinishReason::ToolCalls));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, StreamEvent::ToolCallStart { name, .. } if name == "lookup"))
        );
        let r2 = backend
            .complete(&req, &mut |_: &StreamEvent| {})
            .await
            .unwrap();
        assert_eq!(r2.finish_reason, Some(FinishReason::ToolCalls));
        let e = backend
            .complete(&req, &mut |_: &StreamEvent| {})
            .await
            .unwrap_err();
        assert!(matches!(e, LlmError::ContextLengthExceeded(_)));
        assert!(
            backend
                .complete(&req, &mut |_: &StreamEvent| {})
                .await
                .is_err()
        );
        assert_eq!(backend.requests().len(), 4);
        assert_eq!(backend.remaining(), 0);
        let n = backend
            .count_tokens(&[ChatMessage::user("abcd")], &[])
            .await;
        assert!(n.estimated);
    }
}
