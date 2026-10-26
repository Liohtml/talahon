//! Anthropic Messages API as a gateway upstream.
//!
//! The agent in the container only ever speaks the OpenAI-compatible chat
//! API to the host gateway. With `TALON_PROVIDER=anthropic` the gateway
//! translates in both directions, so nothing in `talon-agent` changes and
//! the API key stays on the host exactly like a vLLM key:
//!
//! ```text
//! talon-agent ──OpenAI chat/completions──▶ gateway ──Messages API (x-api-key)──▶ api.anthropic.com
//!             ◀──chat.completion(.chunk)──         ◀──message / SSE events──
//! ```
//!
//! - [`translate::request`] rebuilds the (policy-filtered) chat body as a
//!   `POST /v1/messages` body: `system` blocks with prompt caching,
//!   alternating user/assistant turns, `tool`/`tool_use`/`tool_result`
//!   blocks, `response_format` → `output_config.format`, `tool_choice`,
//!   `stop` → `stop_sequences`. Sampling knobs are dropped (current Claude
//!   models reject them), `chat_template_kwargs.enable_thinking` becomes
//!   adaptive thinking.
//! - [`translate::response`] maps a `message` back to a `chat.completion`.
//! - [`stream::Translator`] turns the Anthropic SSE event stream into
//!   `chat.completion.chunk` events (plus the final usage chunk and
//!   `[DONE]`), so the agent's streaming client and the gateway's usage tap
//!   see exactly what vLLM would have sent.
//!
//! ## Thinking blocks
//!
//! With thinking on, the API requires the signed `thinking` blocks of an
//! assistant turn to be replayed verbatim when its tool calls are answered.
//! The OpenAI shape has no place for them, so the gateway tucks them into
//! `reasoning_content` as an opaque marker ([`THINKING_MARKER_OPEN`] …
//! [`THINKING_MARKER_CLOSE`], base64 JSON) after any readable thinking
//! text, and [`translate::request`] restores them. The agent already sends
//! `reasoning_content` back untouched for reasoning chat templates.
//!
//! ## Token counting
//!
//! `/tokenize` is answered through `POST /v1/messages/count_tokens`
//! ([`translate::count_tokens_request`]); the result is mapped to vLLM's
//! `{count, max_model_len}` shape.

pub mod stream;
pub mod translate;

/// `anthropic-version` header sent upstream.
pub const API_VERSION: &str = "2023-06-01";

/// Opens the opaque thinking-block marker inside `reasoning_content`.
pub const THINKING_MARKER_OPEN: &str = "<talon-thinking>";
/// Closes the opaque thinking-block marker inside `reasoning_content`.
pub const THINKING_MARKER_CLOSE: &str = "</talon-thinking>";

pub use stream::Translator;
pub use translate::{Translated, count_tokens_request, request, response};
