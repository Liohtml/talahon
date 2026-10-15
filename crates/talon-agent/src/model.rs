//! Model settings derived from `ContainerInput.llm`, and request builders
//! that mirror `VllmClient::request` / `fast_request` but work with any
//! [`talon_llm::ChatBackend`].

use talon_core::protocol::LlmEndpoint;
use talon_core::provider::DEFAULT_MAX_CONTEXT_TOKENS;
use talon_llm::{ChatMessage, ChatRequest};

/// Tokens kept free for the chat template / generation prompt when deriving
/// the compaction threshold.
const TEMPLATE_MARGIN_TOKENS: u64 = 512;

/// Which model to use and how to sample.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelSettings {
    /// Primary model.
    pub model: String,
    /// Auxiliary model for compaction (falls back to `model`).
    pub fast_model: String,
    /// Context window of the primary model, tokens.
    pub max_context_tokens: u64,
    /// `max_tokens` per completion.
    pub max_output_tokens: Option<u32>,
    /// Sampling temperature.
    pub temperature: Option<f32>,
    /// Nucleus sampling.
    pub top_p: Option<f32>,
    /// `chat_template_kwargs.enable_thinking`.
    pub enable_thinking: Option<bool>,
}

impl ModelSettings {
    /// Settings for `model` with a context window and server defaults.
    pub fn new(model: impl Into<String>, max_context_tokens: u64) -> Self {
        let model = model.into();
        Self {
            fast_model: model.clone(),
            model,
            max_context_tokens: if max_context_tokens == 0 {
                u64::from(DEFAULT_MAX_CONTEXT_TOKENS)
            } else {
                max_context_tokens
            },
            max_output_tokens: None,
            temperature: None,
            top_p: None,
            enable_thinking: None,
        }
    }

    /// From the endpoint the host put into `ContainerInput.llm`.
    pub fn from_endpoint(ep: &LlmEndpoint) -> Self {
        let mut s = Self::new(ep.model.clone(), u64::from(ep.max_context_tokens));
        if let Some(fast) = ep.fast_model.as_ref().filter(|m| !m.trim().is_empty()) {
            s.fast_model = fast.clone();
        }
        s.max_output_tokens = ep.max_output_tokens.filter(|n| *n > 0);
        s.temperature = ep.temperature;
        s.top_p = ep.top_p;
        s.enable_thinking = ep.enable_thinking;
        s
    }

    /// A request for the primary model with the configured sampling.
    pub fn request(&self, messages: Vec<ChatMessage>) -> ChatRequest {
        let mut req = ChatRequest::new(self.model.clone(), messages);
        req.temperature = self.temperature;
        req.top_p = self.top_p;
        req.max_tokens = self.max_output_tokens;
        if let Some(enable) = self.enable_thinking {
            req = req.enable_thinking(enable);
        }
        req
    }

    /// A request for the fast model (thinking disabled, bounded output).
    pub fn fast_request(&self, messages: Vec<ChatMessage>, max_tokens: u32) -> ChatRequest {
        let mut req = ChatRequest::new(self.fast_model.clone(), messages);
        req.temperature = Some(0.2);
        req.max_tokens = Some(max_tokens);
        if self.enable_thinking.is_some() {
            req = req.enable_thinking(false);
        }
        req
    }

    /// Prompt size (tokens) above which the conversation is compacted:
    /// `ratio` of the window, but always leaving room for `max_output_tokens`.
    pub fn compaction_threshold(&self, ratio: f64) -> u64 {
        let ctx = self.max_context_tokens;
        let by_ratio = (ctx as f64 * ratio.clamp(0.1, 0.98)) as u64;
        let by_output = match self.max_output_tokens {
            Some(out) => ctx.saturating_sub(u64::from(out) + TEMPLATE_MARGIN_TOKENS),
            None => ctx,
        };
        by_ratio.min(by_output).max(ctx / 4)
    }

    /// Token budget for the verbatim tail kept by compaction (30 % of the
    /// window).
    pub fn keep_budget(&self) -> u64 {
        self.max_context_tokens * 3 / 10
    }

    /// `max_tokens` for a compaction summary.
    pub fn summary_max_tokens(&self) -> u32 {
        let n = (self.max_context_tokens / 10).clamp(512, 4096);
        u32::try_from(n).unwrap_or(4096)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> LlmEndpoint {
        LlmEndpoint {
            base_url: "http://gw/v1".into(),
            token: "t".into(),
            model: "big".into(),
            fast_model: Some("small".into()),
            max_context_tokens: 32_768,
            max_output_tokens: Some(4096),
            temperature: Some(0.1),
            top_p: None,
            enable_thinking: Some(true),
            request_timeout_secs: None,
        }
    }

    #[test]
    fn from_endpoint_and_requests() {
        let m = ModelSettings::from_endpoint(&endpoint());
        assert_eq!(m.fast_model, "small");
        let r = m.request(vec![ChatMessage::user("x")]);
        assert_eq!(r.model, "big");
        assert_eq!(r.max_tokens, Some(4096));
        assert_eq!(
            r.chat_template_kwargs.as_ref().unwrap()["enable_thinking"],
            serde_json::json!(true)
        );
        let f = m.fast_request(vec![], 1000);
        assert_eq!(f.model, "small");
        assert_eq!(f.max_tokens, Some(1000));
        assert_eq!(
            f.chat_template_kwargs.as_ref().unwrap()["enable_thinking"],
            serde_json::json!(false)
        );
    }

    #[test]
    fn thresholds() {
        let m = ModelSettings::from_endpoint(&endpoint());
        // 75% of 32768 = 24576; 32768 - 4096 - 512 = 28160 -> 24576
        assert_eq!(m.compaction_threshold(0.75), 24_576);
        let mut big_out = m.clone();
        big_out.max_output_tokens = Some(16_000);
        assert_eq!(big_out.compaction_threshold(0.75), 32_768 - 16_512);
        assert_eq!(m.keep_budget(), 9_830);
        assert_eq!(m.summary_max_tokens(), 3_276);
        let zero = ModelSettings::new("m", 0);
        assert_eq!(zero.max_context_tokens, 32_768);
        assert_eq!(zero.fast_model, "m");
    }
}
