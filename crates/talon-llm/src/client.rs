//! `VllmClient`: OpenAI-compatible chat completions against vLLM (directly
//! on the host, or through the LLM gateway from inside a container).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::StreamExt;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::{Value, json};
use talon_core::protocol::LlmEndpoint;
use talon_core::types::VllmConfig;

use crate::error::LlmError;
use crate::fallback::PostProcessOptions;
use crate::retry::{RetryPolicy, retry_after_from_headers};
use crate::stream::{ChatStream, Finalizer, StreamEvent};
use crate::types::{
    ChatCompletionWire, ChatMessage, ChatRequest, ChatResponse, ModelInfo, ModelListWire,
    PostProcessReport, StreamOptions, TokenCount, ToolDefinition, estimate_tokens,
};

/// Default per-request timeout (whole request, including a streamed body).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
/// Default TCP connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default maximum silence between two stream chunks (covers the prefill of
/// long prompts before the first token).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Default cap on a response body.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// Error bodies are read up to this size.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
/// `/tokenize` and `/health` are quick; don't let them hang an agent turn.
const AUX_TIMEOUT: Duration = Duration::from_secs(30);

/// Client configuration.
#[derive(Clone)]
pub struct ClientConfig {
    /// Server base URL, with or without the trailing `/v1`
    /// (`http://vllm:8000`, `http://host.docker.internal:3001/v1`).
    pub base_url: String,
    /// Bearer token (vLLM `--api-key`, or a per-run gateway token).
    pub api_key: Option<String>,
    /// Default model for [`VllmClient::request`].
    pub model: String,
    /// Auxiliary model for [`VllmClient::fast_request`] (falls back to `model`).
    pub fast_model: Option<String>,
    /// Context window of `model`, if known.
    pub max_context_tokens: Option<u32>,
    /// Default `max_tokens`.
    pub max_output_tokens: Option<u32>,
    /// Default temperature.
    pub temperature: Option<f32>,
    /// Default `top_p`.
    pub top_p: Option<f32>,
    /// Default `chat_template_kwargs.enable_thinking`.
    pub enable_thinking: Option<bool>,
    /// Whole-request timeout.
    pub request_timeout: Duration,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Maximum silence between two chunks of a *streamed* response
    /// (`0` disables). Non-streamed responses arrive only after generation
    /// finishes, so they are bounded by `request_timeout` alone.
    pub idle_timeout: Duration,
    /// Retry behaviour for transient failures.
    pub retry: RetryPolicy,
    /// Maximum response size in bytes (streamed or not).
    pub max_response_bytes: usize,
    /// Text tool-call recovery and `<think>` splitting.
    pub postprocess: PostProcessOptions,
    /// Honour `HTTP(S)_PROXY` from the environment. Off by default: the
    /// client talks to an internal vLLM or the local gateway, and the bearer
    /// token should not transit a proxy.
    pub use_system_proxy: bool,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("model", &self.model)
            .field("fast_model", &self.fast_model)
            .field("max_context_tokens", &self.max_context_tokens)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("request_timeout", &self.request_timeout)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    /// A config with defaults for everything but the URL and model.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: None,
            model: model.into(),
            fast_model: None,
            max_context_tokens: None,
            max_output_tokens: None,
            temperature: None,
            top_p: None,
            enable_thinking: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            retry: RetryPolicy::default(),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            postprocess: PostProcessOptions::default(),
            use_system_proxy: false,
        }
    }

    /// Set the bearer token.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Config for the in-container runtime, from the endpoint the host put
    /// into `ContainerInput.llm` (gateway URL + per-run token).
    pub fn from_endpoint(ep: &LlmEndpoint) -> Self {
        let mut cfg = Self::new(ep.base_url.clone(), ep.model.clone());
        cfg.api_key = Some(ep.token.clone()).filter(|t| !t.is_empty());
        cfg.fast_model = ep.fast_model.clone();
        cfg.max_context_tokens = Some(ep.max_context_tokens).filter(|n| *n > 0);
        cfg.max_output_tokens = ep.max_output_tokens;
        cfg.temperature = ep.temperature;
        cfg.top_p = ep.top_p;
        cfg.enable_thinking = ep.enable_thinking;
        if let Some(secs) = ep.request_timeout_secs.filter(|s| *s > 0) {
            cfg.request_timeout = Duration::from_secs(secs);
        }
        cfg
    }

    /// Config for direct host-side access (e.g. `talon setup verify`).
    pub fn from_vllm(cfg: &VllmConfig, api_key: Option<String>) -> Self {
        let mut out = Self::new(cfg.base_url.clone(), cfg.model.clone());
        out.api_key = api_key.filter(|k| !k.trim().is_empty());
        out.fast_model = cfg.fast_model.clone();
        out.max_context_tokens = cfg.max_context_tokens;
        out.max_output_tokens = cfg.max_output_tokens;
        out.temperature = cfg.temperature;
        out.top_p = cfg.top_p;
        out.enable_thinking = cfg.enable_thinking;
        if let Some(secs) = cfg.request_timeout_secs.filter(|s| *s > 0) {
            out.request_timeout = Duration::from_secs(secs);
        }
        out
    }
}

/// Normalized server URLs: `api` ends with `/v1`, `root` does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BaseUrls {
    pub api: String,
    pub root: String,
}

/// Split a base URL into the `/v1` API prefix and the server root (where
/// vLLM serves `/health` and `/tokenize`).
pub(crate) fn normalize_base_url(raw: &str) -> Result<BaseUrls, LlmError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = url::Url::parse(trimmed)
        .map_err(|e| LlmError::Config(format!("invalid LLM base URL {trimmed:?}: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(LlmError::Config(format!(
            "LLM base URL must be http(s), got {:?}",
            parsed.scheme()
        )));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(LlmError::Config("LLM base URL has no host".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LlmError::Config(
            "LLM base URL must not contain credentials; use the API key setting".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LlmError::Config(
            "LLM base URL must not contain a query or fragment".into(),
        ));
    }
    let (api, root) = match trimmed.strip_suffix("/v1") {
        Some(root) => (trimmed.to_string(), root.to_string()),
        None => (format!("{trimmed}/v1"), trimmed.to_string()),
    };
    Ok(BaseUrls { api, root })
}

/// OpenAI-compatible vLLM client. Cheap to clone (shares the connection pool).
///
/// Dropping a returned future (or a [`ChatStream`]) cancels the request,
/// including any pending retry backoff.
#[derive(Clone)]
pub struct VllmClient {
    http: reqwest::Client,
    cfg: Arc<ClientConfig>,
    urls: Arc<BaseUrls>,
    tokenize_unavailable: Arc<AtomicBool>,
}

impl fmt::Debug for VllmClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VllmClient")
            .field("api", &self.urls.api)
            .field("model", &self.cfg.model)
            .finish_non_exhaustive()
    }
}

impl VllmClient {
    /// Build a client.
    pub fn new(config: ClientConfig) -> Result<Self, LlmError> {
        if config.model.trim().is_empty() {
            return Err(LlmError::Config("model name is empty".into()));
        }
        let urls = normalize_base_url(&config.base_url)?;
        let mut headers = HeaderMap::new();
        if let Some(key) = config.api_key.as_deref().filter(|k| !k.is_empty()) {
            let mut value = HeaderValue::from_str(&format!("Bearer {key}"))
                .map_err(|_| LlmError::Config("API key contains invalid characters".into()))?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .user_agent(concat!("talon-llm/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(config.connect_timeout)
            .pool_idle_timeout(Duration::from_secs(90));
        if !config.use_system_proxy {
            builder = builder.no_proxy();
        }
        let http = builder
            .build()
            .map_err(|e| LlmError::Config(format!("cannot build HTTP client: {e}")))?;
        Ok(Self {
            http,
            cfg: Arc::new(config),
            urls: Arc::new(urls),
            tokenize_unavailable: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Client for the in-container runtime (see [`ClientConfig::from_endpoint`]).
    pub fn from_endpoint(ep: &LlmEndpoint) -> Result<Self, LlmError> {
        Self::new(ClientConfig::from_endpoint(ep))
    }

    /// The active configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    /// The `/v1` API base URL.
    pub fn api_base(&self) -> &str {
        &self.urls.api
    }

    /// Primary model name.
    pub fn model(&self) -> &str {
        &self.cfg.model
    }

    /// Auxiliary model name (falls back to the primary model).
    pub fn fast_model(&self) -> &str {
        self.cfg.fast_model.as_deref().unwrap_or(&self.cfg.model)
    }

    /// A request for the primary model, seeded with the configured defaults
    /// (temperature, top_p, max_tokens, enable_thinking).
    pub fn request(&self, messages: Vec<ChatMessage>) -> ChatRequest {
        self.seeded(self.cfg.model.clone(), messages)
    }

    /// A request for the fast model (compaction, extraction, summaries).
    /// Thinking is disabled when the endpoint enables it by default.
    pub fn fast_request(&self, messages: Vec<ChatMessage>) -> ChatRequest {
        let mut req = self.seeded(self.fast_model().to_string(), messages);
        if self.cfg.enable_thinking == Some(true) {
            req = req.enable_thinking(false);
        }
        req
    }

    fn seeded(&self, model: String, messages: Vec<ChatMessage>) -> ChatRequest {
        let mut req = ChatRequest::new(model, messages);
        req.temperature = self.cfg.temperature;
        req.top_p = self.cfg.top_p;
        req.max_tokens = self.cfg.max_output_tokens;
        if let Some(enable) = self.cfg.enable_thinking {
            req = req.enable_thinking(enable);
        }
        req
    }

    // -----------------------------------------------------------------------
    // Chat
    // -----------------------------------------------------------------------

    /// Non-streaming chat completion (with retries).
    pub async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let started = Instant::now();
        let body = self.encode(req, false)?;
        let url = format!("{}/chat/completions", self.urls.api);
        let limit = self.cfg.max_response_bytes;
        let bytes = self
            .with_retry("chat", || {
                let request = self
                    .http
                    .post(&url)
                    .header(CONTENT_TYPE, "application/json")
                    .header(ACCEPT, "application/json")
                    .timeout(self.cfg.request_timeout)
                    .body(body.clone());
                async move { read_body_capped(send_once(request).await?, limit).await }
            })
            .await?;
        let mut out = parse_completion(&bytes)?;
        Finalizer::for_request(req, self.cfg.postprocess).finalize(&mut out);
        tracing::debug!(
            model = %out.model,
            finish = ?out.finish_reason,
            prompt_tokens = out.usage.prompt_tokens,
            completion_tokens = out.usage.completion_tokens,
            cached_tokens = out.usage.cached_tokens,
            tool_calls = out.message.tool_calls.len(),
            elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "chat completion"
        );
        Ok(out)
    }

    /// Streaming chat completion. Connection-level failures and error
    /// statuses are retried before the first byte; the returned stream
    /// yields [`StreamEvent`]s and ends with [`StreamEvent::Done`].
    pub async fn chat_stream(&self, req: &ChatRequest) -> Result<ChatStream, LlmError> {
        let body = self.encode(req, true)?;
        let url = format!("{}/chat/completions", self.urls.api);
        let resp = self
            .with_retry("chat_stream", || {
                send_once(
                    self.http
                        .post(&url)
                        .header(CONTENT_TYPE, "application/json")
                        .header(ACCEPT, "text/event-stream")
                        .timeout(self.cfg.request_timeout)
                        .body(body.clone()),
                )
            })
            .await?;
        let finalizer = Finalizer::for_request(req, self.cfg.postprocess);
        let is_sse = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"));
        if !is_sse {
            // Server ignored `stream: true` and answered with a full JSON body.
            let bytes = read_body_capped(resp, self.cfg.max_response_bytes).await?;
            let out = parse_completion(&bytes)?;
            return Ok(ChatStream::from_completed(out, &finalizer));
        }
        let body_stream = resp.bytes_stream().map(|r| {
            r.map_err(|e| {
                if e.is_timeout() {
                    LlmError::Timeout(format!("request timeout reached while streaming: {e}"))
                } else {
                    LlmError::Stream(format!("stream read failed: {e}"))
                }
            })
        });
        Ok(ChatStream::new(
            Box::pin(body_stream),
            finalizer,
            self.cfg.max_response_bytes,
            Some(self.cfg.idle_timeout).filter(|d| !d.is_zero()),
        ))
    }

    /// Stream a completion, calling `on_event` for every intermediate event
    /// (text/reasoning/tool-call deltas, usage), and return the final
    /// response. The simplest way to stream from the agent loop.
    pub async fn chat_streaming<F>(
        &self,
        req: &ChatRequest,
        mut on_event: F,
    ) -> Result<ChatResponse, LlmError>
    where
        F: FnMut(&StreamEvent) + Send,
    {
        let mut stream = self.chat_stream(req).await?;
        while let Some(ev) = stream.next().await {
            match ev? {
                StreamEvent::Done(resp) => return Ok(*resp),
                other => on_event(&other),
            }
        }
        Err(LlmError::Stream("stream ended without a response".into()))
    }

    fn encode(&self, req: &ChatRequest, stream: bool) -> Result<Bytes, LlmError> {
        if req.model.trim().is_empty() {
            return Err(LlmError::Config("request has no model".into()));
        }
        let mut wire = req.clone();
        wire.stream = stream;
        wire.stream_options = stream.then_some(StreamOptions {
            include_usage: true,
        });
        let body = serde_json::to_vec(&wire)
            .map_err(|e| LlmError::Config(format!("cannot encode request: {e}")))?;
        Ok(Bytes::from(body))
    }

    // -----------------------------------------------------------------------
    // Models / health / tokenize
    // -----------------------------------------------------------------------

    /// `GET /v1/models`.
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>, LlmError> {
        let url = format!("{}/models", self.urls.api);
        let limit = self.cfg.max_response_bytes;
        let bytes = self
            .with_retry("list_models", || {
                let request = self
                    .http
                    .get(&url)
                    .timeout(AUX_TIMEOUT.min(self.cfg.request_timeout));
                async move { read_body_capped(send_once(request).await?, limit).await }
            })
            .await?;
        let list: ModelListWire = serde_json::from_slice(&bytes)
            .map_err(|e| LlmError::Decode(format!("invalid /v1/models response: {e}")))?;
        Ok(list.data)
    }

    /// Liveness check: vLLM `GET /health`, falling back to `GET /v1/models`
    /// when `/health` is not served (e.g. through the gateway). No retries.
    pub async fn health(&self) -> Result<(), LlmError> {
        let url = format!("{}/health", self.urls.root);
        let resp = self
            .http
            .get(&url)
            .timeout(AUX_TIMEOUT.min(self.cfg.request_timeout))
            .send()
            .await
            .map_err(|e| LlmError::from_reqwest(&e))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        if matches!(status.as_u16(), 401 | 403 | 404 | 405) {
            let url = format!("{}/models", self.urls.api);
            let resp = self
                .http
                .get(&url)
                .timeout(AUX_TIMEOUT.min(self.cfg.request_timeout))
                .send()
                .await
                .map_err(|e| LlmError::from_reqwest(&e))?;
            if resp.status().is_success() {
                return Ok(());
            }
            return Err(error_from_response(resp).await);
        }
        Err(error_from_response(resp).await)
    }

    /// Count tokens of `text` with the primary model's tokenizer via vLLM
    /// `POST /tokenize`. Never fails: when the endpoint is unavailable the
    /// result is a ~4 chars/token estimate with `estimated = true`.
    pub async fn tokenize(&self, text: &str) -> TokenCount {
        let body = json!({
            "model": self.cfg.model,
            "prompt": text,
            "add_special_tokens": false,
        });
        self.tokenize_request(body, || estimate_tokens(text)).await
    }

    /// Count the prompt tokens of a conversation (chat template applied,
    /// generation prompt added) via `POST /tokenize`. Falls back to an
    /// estimate like [`VllmClient::tokenize`].
    pub async fn tokenize_messages(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> TokenCount {
        let mut body = json!({
            "model": self.cfg.model,
            "messages": messages,
            "add_generation_prompt": true,
        });
        if !tools.is_empty() {
            body["tools"] = json!(tools);
        }
        if let Some(enable) = self.cfg.enable_thinking {
            body["chat_template_kwargs"] = json!({"enable_thinking": enable});
        }
        self.tokenize_request(body, || estimate_conversation_tokens(messages, tools))
            .await
    }

    async fn tokenize_request(&self, body: Value, estimate: impl FnOnce() -> u64) -> TokenCount {
        let fallback = |estimate: u64| TokenCount {
            count: estimate,
            max_model_len: self.cfg.max_context_tokens.map(u64::from),
            estimated: true,
        };
        if self.tokenize_unavailable.load(Ordering::Relaxed) {
            return fallback(estimate());
        }
        let url = format!("{}/tokenize", self.urls.root);
        let result = self
            .http
            .post(&url)
            .timeout(AUX_TIMEOUT.min(self.cfg.request_timeout))
            .json(&body)
            .send()
            .await;
        let resp = match result {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "tokenize request failed; estimating");
                return fallback(estimate());
            }
        };
        let status = resp.status().as_u16();
        if matches!(status, 404 | 405 | 501) {
            // Not served (e.g. older vLLM / other backends): stop asking.
            self.tokenize_unavailable.store(true, Ordering::Relaxed);
            return fallback(estimate());
        }
        if !resp.status().is_success() {
            tracing::debug!(status, "tokenize returned an error; estimating");
            return fallback(estimate());
        }
        let parsed = read_body_capped(resp, MAX_ERROR_BODY_BYTES * 16)
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
        match parsed
            .as_ref()
            .and_then(|v| v.get("count"))
            .and_then(Value::as_u64)
        {
            Some(count) => TokenCount {
                count,
                max_model_len: parsed
                    .as_ref()
                    .and_then(|v| v.get("max_model_len"))
                    .and_then(Value::as_u64)
                    .or(self.cfg.max_context_tokens.map(u64::from)),
                estimated: false,
            },
            None => fallback(estimate()),
        }
    }

    // -----------------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------------

    /// Run `attempt` until it succeeds, the error is not retryable, or the
    /// retry budget is spent (exponential backoff + jitter, `Retry-After`).
    async fn with_retry<T, F, Fut>(
        &self,
        op: &'static str,
        mut attempt_fn: F,
    ) -> Result<T, LlmError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, LlmError>>,
    {
        let mut attempt: u32 = 0;
        loop {
            let err = match attempt_fn().await {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            match self.cfg.retry.delay_for(attempt, &err) {
                Some(delay) => {
                    // Server messages can echo request content: keep them at debug.
                    tracing::warn!(
                        op,
                        attempt = attempt + 1,
                        delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        status = ?err.status(),
                        kind = err.kind(),
                        "LLM request failed; retrying"
                    );
                    tracing::debug!(op, error = %err, "LLM request failure detail");
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                None => return Err(err),
            }
        }
    }
}

/// Send once; non-2xx statuses become typed errors.
async fn send_once(request: reqwest::RequestBuilder) -> Result<reqwest::Response, LlmError> {
    match request.send().await {
        Ok(resp) if resp.status().is_success() => Ok(resp),
        Ok(resp) => Err(error_from_response(resp).await),
        Err(e) => Err(LlmError::from_reqwest(&e)),
    }
}

/// Classify a non-2xx response (reads a bounded amount of the body).
async fn error_from_response(resp: reqwest::Response) -> LlmError {
    let status = resp.status().as_u16();
    let retry_after = retry_after_from_headers(resp.headers());
    let body = read_body_capped(resp, MAX_ERROR_BODY_BYTES)
        .await
        .unwrap_or_default();
    LlmError::from_status(status, &body, retry_after)
}

/// Read a body, failing once it exceeds `limit` bytes. A body that is cut
/// off at `limit` for error reporting is fine: callers that need complete
/// bodies get `ResponseTooLarge`.
pub(crate) async fn read_body_capped(
    resp: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, LlmError> {
    if let Some(len) = resp.content_length() {
        if usize::try_from(len).map_or(true, |l| l > limit) {
            return Err(LlmError::ResponseTooLarge { limit });
        }
    }
    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| LlmError::from_reqwest(&e))?;
        if out.len().saturating_add(chunk.len()) > limit {
            return Err(LlmError::ResponseTooLarge { limit });
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Parse a `chat.completion` body into a (raw) [`ChatResponse`].
fn parse_completion(bytes: &[u8]) -> Result<ChatResponse, LlmError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| LlmError::Decode(format!("invalid chat completion JSON: {e}")))?;
    if value.get("object").and_then(Value::as_str) == Some("error") || value.get("error").is_some()
    {
        let msg = crate::error::error_message_from_value(&value).unwrap_or_default();
        return Err(LlmError::Http {
            status: 200,
            message: msg,
            retry_after: None,
        });
    }
    let wire: ChatCompletionWire = serde_json::from_value(value)
        .map_err(|e| LlmError::Decode(format!("unexpected chat completion shape: {e}")))?;
    let choice = wire
        .choices
        .into_iter()
        .min_by_key(|c| c.index)
        .ok_or_else(|| LlmError::Decode("chat completion has no choices".into()))?;
    Ok(ChatResponse {
        id: wire.id,
        model: wire.model,
        message: choice.message,
        finish_reason: choice.finish_reason,
        usage: wire.usage.unwrap_or_default(),
        postprocess: PostProcessReport::default(),
    })
}

/// Rough prompt size of a conversation: content + reasoning + tool calls,
/// ~4 tokens of template overhead per message, plus tool schemas.
pub fn estimate_conversation_tokens(messages: &[ChatMessage], tools: &[ToolDefinition]) -> u64 {
    let mut total: u64 = 3;
    for m in messages {
        total = total.saturating_add(4);
        total = total.saturating_add(estimate_tokens(m.text()));
        if let Some(r) = &m.reasoning_content {
            total = total.saturating_add(estimate_tokens(r));
        }
        for c in &m.tool_calls {
            total = total
                .saturating_add(estimate_tokens(&c.function.name))
                .saturating_add(estimate_tokens(&c.function.arguments))
                .saturating_add(4);
        }
    }
    for t in tools {
        let schema = serde_json::to_string(t).unwrap_or_default();
        total = total.saturating_add(estimate_tokens(&schema));
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_normalization() {
        let u = normalize_base_url("http://vllm:8000").unwrap();
        assert_eq!(u.api, "http://vllm:8000/v1");
        assert_eq!(u.root, "http://vllm:8000");
        let u = normalize_base_url("http://host.docker.internal:3001/v1/").unwrap();
        assert_eq!(u.api, "http://host.docker.internal:3001/v1");
        assert_eq!(u.root, "http://host.docker.internal:3001");
        let u = normalize_base_url("https://gw.example/prefix").unwrap();
        assert_eq!(u.api, "https://gw.example/prefix/v1");
        assert!(normalize_base_url("ftp://x").is_err());
        assert!(normalize_base_url("not a url").is_err());
        assert!(normalize_base_url("http://user:pw@x:1").is_err());
        assert!(normalize_base_url("http://x:1/v1?key=1").is_err());
    }

    #[test]
    fn config_from_endpoint_and_debug_redacts() {
        let ep = LlmEndpoint {
            base_url: "http://host.docker.internal:3001/v1".into(),
            token: "tlgw_secret".into(),
            model: "qwen".into(),
            fast_model: Some("small".into()),
            max_context_tokens: 32768,
            max_output_tokens: Some(1024),
            temperature: Some(0.2),
            top_p: None,
            enable_thinking: Some(true),
            request_timeout_secs: Some(42),
        };
        let cfg = ClientConfig::from_endpoint(&ep);
        assert_eq!(cfg.request_timeout, Duration::from_secs(42));
        assert_eq!(cfg.api_key.as_deref(), Some("tlgw_secret"));
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("tlgw_secret"), "{dbg}");
        assert!(dbg.contains("<redacted>"));

        let client = VllmClient::new(cfg).unwrap();
        assert_eq!(client.fast_model(), "small");
        assert!(!format!("{client:?}").contains("tlgw_secret"));
        let req = client.request(vec![ChatMessage::user("x")]);
        assert_eq!(req.model, "qwen");
        assert_eq!(req.max_tokens, Some(1024));
        assert_eq!(req.temperature, Some(0.2));
        assert_eq!(
            req.chat_template_kwargs.as_ref().unwrap()["enable_thinking"],
            true
        );
        let fast = client.fast_request(vec![]);
        assert_eq!(fast.model, "small");
        assert_eq!(
            fast.chat_template_kwargs.as_ref().unwrap()["enable_thinking"],
            false
        );
    }

    #[test]
    fn empty_model_is_rejected() {
        assert!(matches!(
            VllmClient::new(ClientConfig::new("http://x", " ")),
            Err(LlmError::Config(_))
        ));
    }

    #[test]
    fn parse_completion_variants() {
        let body = br#"{"id":"c","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}"#;
        let r = parse_completion(body).unwrap();
        assert_eq!(r.message.text(), "hi");
        assert_eq!(r.usage.prompt_tokens, 3);
        assert!(matches!(
            parse_completion(br#"{"choices":[]}"#),
            Err(LlmError::Decode(_))
        ));
        assert!(matches!(
            parse_completion(br#"{"object":"error","message":"x"}"#),
            Err(LlmError::Http { .. })
        ));
        assert!(matches!(
            parse_completion(b"<html>"),
            Err(LlmError::Decode(_))
        ));
    }

    #[test]
    fn conversation_estimate_counts_everything() {
        let msgs = vec![ChatMessage::user("a".repeat(400))];
        let n = estimate_conversation_tokens(&msgs, &[]);
        assert!((100..120).contains(&n), "{n}");
    }
}
