//! # talon-llm — vLLM provider + host LLM gateway
//!
//! Talon talks to [vLLM](https://docs.vllm.ai) through its OpenAI-compatible
//! API. This crate has two halves:
//!
//! - **Client** ([`VllmClient`]) — chat completions (plain and SSE
//!   streaming), retries with backoff/`Retry-After`, timeouts, `/v1/models`,
//!   `/health`, `/tokenize`, and a fallback parser that recovers tool calls a
//!   model wrote as text (Hermes `<tool_call>`, Mistral `[TOOL_CALLS]`, Llama
//!   `<|python_tag|>`, fenced/bare JSON) and splits `<think>` reasoning.
//!   Used by the in-container agent (`talon-agent`) and by host-side checks.
//! - **Gateway** ([`gateway::LlmGateway`]) — the host-side reverse proxy
//!   containers use instead of vLLM: short-lived per-run tokens (stored as
//!   SHA-256 digests), upstream key injection, a request-parameter
//!   allowlist (no template overrides, media URLs or grammar decoding),
//!   model pinning, `max_tokens` clamp, per-label `cache_salt`, body and
//!   JSON-size limits, per-token rate limit, per-token and global
//!   concurrency caps, slowloris-safe serving via `talon-net`, SSE
//!   passthrough, usage per label, audit of auth failures.
//!
//! ```text
//! talon (host) ── LlmGateway::start ── issue_token(label, ttl) ──▶ ContainerInput.llm (stdin)
//!                                                                     │
//! talon-agent (container) ── VllmClient::from_endpoint(&llm) ──▶ gateway ──▶ vLLM
//! ```
//!
//! ## In the container: the agent loop
//!
//! ```no_run
//! use talon_core::protocol::{ContainerInput, SessionUsage};
//! use talon_core::tool::{Tool, ToolContext, ToolOutput};
//! use talon_llm::{ChatMessage, LlmError, StreamEvent, Usage, VllmClient};
//!
//! async fn run(
//!     input: &ContainerInput,
//!     tools: &[std::sync::Arc<dyn Tool>],
//!     ctx: &ToolContext,
//! ) -> Result<(String, SessionUsage), LlmError> {
//!     let Some(endpoint) = input.llm.as_ref() else {
//!         return Err(LlmError::Config("no LLM endpoint in ContainerInput".into()));
//!     };
//!     // Base URL is the gateway, token is the per-run gateway token.
//!     let client = VllmClient::from_endpoint(endpoint)?;
//!     let specs: Vec<_> = tools.iter().map(|t| t.spec()).collect();
//!     let mut history = vec![
//!         ChatMessage::system("You are Talon, a SOC analyst."),
//!         ChatMessage::user(&input.prompt),
//!     ];
//!     let mut usage = Usage::default();
//!     loop {
//!         // `request` seeds model, temperature, top_p, max_tokens and
//!         // enable_thinking from the endpoint.
//!         let req = client.request(history.clone()).tools(&specs);
//!         let resp = match client
//!             .chat_streaming(&req, |ev| {
//!                 if let StreamEvent::Content(text) = ev {
//!                     let _ = text; // progress / typing indicator
//!                 }
//!             })
//!             .await
//!         {
//!             Ok(resp) => resp,
//!             Err(LlmError::ContextLengthExceeded(_)) => {
//!                 // Compact `history` with `client.fast_request(..)`, then retry.
//!                 continue;
//!             }
//!             Err(e) => return Err(e),
//!         };
//!         usage += resp.usage;
//!         let mut message = resp.message;
//!         if message.tool_calls.is_empty() {
//!             return Ok((message.text().to_string(), SessionUsage::from(&usage)));
//!         }
//!         let calls = message.tool_calls.clone();
//!         // Keep the history valid for vLLM's chat template.
//!         message.normalize_tool_arguments();
//!         history.push(message);
//!         for call in calls {
//!             let tool = tools.iter().find(|t| t.spec().name == call.name());
//!             let output = match (tool, call.parse_arguments()) {
//!                 (Some(tool), Ok(args)) => tool.call(args, ctx).await,
//!                 (None, _) => ToolOutput::err(format!("unknown tool {}", call.name())),
//!                 (_, Err(e)) => ToolOutput::err(format!("invalid JSON arguments: {e}")),
//!             };
//!             history.push(ChatMessage::tool_result(call.id.clone(), output.content));
//!         }
//!     }
//! }
//! ```
//!
//! Structured verdicts use vLLM guided decoding:
//!
//! ```no_run
//! # async fn verdict(client: &talon_llm::VllmClient, history: Vec<talon_llm::ChatMessage>, schema: serde_json::Value) -> Result<(), talon_llm::LlmError> {
//! let req = client
//!     .request(history)
//!     .json_schema("triage_report", schema, true)
//!     .enable_thinking(false);
//! let resp = client.chat(&req).await?;
//! let report = resp
//!     .content_json()
//!     .map_err(|e| talon_llm::LlmError::Decode(e.to_string()))?;
//! # let _ = report; Ok(()) }
//! ```
//!
//! For unit tests of the loop, program against [`ChatBackend`] and use
//! [`ScriptedBackend`].
//!
//! ## On the host: the gateway
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//! use std::time::Duration;
//! use talon_core::audit::TracingAuditSink;
//! use talon_core::types::VllmConfig;
//! use talon_llm::gateway::{GatewayConfig, LlmGateway};
//!
//! # async fn host(vllm: VllmConfig, api_key: Option<String>) -> Result<(), talon_llm::LlmError> {
//! let mut config = GatewayConfig::from_vllm(&vllm, api_key); // TALON_VLLM_API_KEY
//! config.bind = SocketAddr::from(([172, 17, 0, 1], 3001)); // docker bridge on Linux
//! let gateway = LlmGateway::start(config, Arc::new(TracingAuditSink)).await?;
//!
//! // Per container run (ttl = container timeout):
//! let token = gateway.issue_token("main", Duration::from_secs(30 * 60));
//! let endpoint = gateway.endpoint(token.clone(), "host.docker.internal", &vllm);
//! // ... ContainerInput { llm: Some(endpoint), .. } written to the container's stdin ...
//! gateway.revoke(&token); // when the run ends
//!
//! let stats = gateway.stats(); // per-label usage for /metrics
//! # let _ = stats;
//! gateway.shutdown().await;
//! # Ok(()) }
//! ```

pub mod backend;
pub mod client;
pub mod error;
pub mod fallback;
pub mod gateway;
pub mod retry;
pub mod sse;
pub mod stream;
pub mod types;

pub use backend::{ChatBackend, ScriptedBackend};
pub use client::{ClientConfig, VllmClient, estimate_conversation_tokens};
pub use error::LlmError;
pub use fallback::{PostProcessOptions, parse_text_tool_calls, postprocess_message, split_think};
pub use gateway::{GatewayConfig, GatewayHandle, GatewayStats, LlmGateway};
pub use retry::RetryPolicy;
pub use stream::{ChatStream, StreamAccumulator, StreamEvent};
pub use types::{
    ChatMessage, ChatRequest, ChatResponse, FinishReason, ModelInfo, PostProcessReport,
    ResponseFormat, Role, TokenCount, ToolCall, ToolCallFormat, ToolChoice, ToolDefinition, Usage,
    estimate_tokens,
};
