//! Request policy applied by the gateway before forwarding to vLLM:
//! model pinning, `max_tokens` clamping, and removal of parameters a
//! compromised container could abuse (custom chat templates, beam search,
//! scheduling priority, custom logits processors, ...).

use serde_json::{Map, Value, json};

/// Top-level request fields the gateway always removes.
///
/// - `chat_template`: arbitrary Jinja supplied by the client.
/// - `logits_processors`: vLLM can load processors by qualified name.
/// - `best_of`, `use_beam_search`, `prompt_logprobs`: cost amplification.
/// - `priority`: would let one container starve others on a priority-scheduled server.
/// - `kv_transfer_params`, `vllm_xargs`: disaggregated-serving / plugin internals.
pub const STRIPPED_FIELDS: [&str; 8] = [
    "chat_template",
    "logits_processors",
    "best_of",
    "use_beam_search",
    "prompt_logprobs",
    "priority",
    "kv_transfer_params",
    "vllm_xargs",
];

/// What the gateway enforces on every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestPolicy {
    pub allowed_models: Vec<String>,
    pub default_model: String,
    pub max_output_tokens_cap: Option<u32>,
}

/// What [`RequestPolicy::apply_chat`] changed.
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
    /// Fields that were removed.
    pub removed: Vec<&'static str>,
}

impl RequestPolicy {
    /// Whether `model` may be used.
    pub(crate) fn is_allowed(&self, model: &str) -> bool {
        model == self.default_model || self.allowed_models.iter().any(|m| m == model)
    }

    /// Pin `obj["model"]` to the allow-list (unknown -> default model).
    fn pin_model(&self, obj: &mut Map<String, Value>) -> (String, bool) {
        let requested = obj.get("model").and_then(Value::as_str).unwrap_or("");
        if self.is_allowed(requested) {
            return (requested.to_string(), false);
        }
        obj.insert("model".into(), Value::String(self.default_model.clone()));
        (self.default_model.clone(), true)
    }

    fn strip(obj: &mut Map<String, Value>) -> Vec<&'static str> {
        STRIPPED_FIELDS
            .iter()
            .filter(|f| obj.remove(**f).is_some())
            .copied()
            .collect()
    }

    /// Enforce the policy on a `/v1/chat/completions` body.
    pub(crate) fn apply_chat(&self, body: &mut Value) -> Result<PolicyOutcome, String> {
        let obj = body
            .as_object_mut()
            .ok_or_else(|| "request body must be a JSON object".to_string())?;
        if !obj.get("messages").is_some_and(Value::is_array) {
            return Err("`messages` must be an array".into());
        }
        let (model, model_rewritten) = self.pin_model(obj);
        let removed = Self::strip(obj);

        // One choice only: `n > 1` multiplies generation cost.
        if let Some(n) = obj.get("n") {
            if n.as_u64() != Some(1) {
                obj.insert("n".into(), json!(1));
            }
        }

        let mut max_tokens_clamped = false;
        let mut saw_limit = false;
        for key in ["max_tokens", "max_completion_tokens"] {
            let Some(v) = obj.get(key) else { continue };
            if v.is_null() {
                obj.remove(key);
                continue;
            }
            let n = v
                .as_u64()
                .ok_or_else(|| format!("`{key}` must be a non-negative integer"))?;
            saw_limit = true;
            if let Some(cap) = self.max_output_tokens_cap {
                if n > u64::from(cap) {
                    obj.insert(key.into(), json!(cap));
                    max_tokens_clamped = true;
                }
            }
        }
        if !saw_limit {
            if let Some(cap) = self.max_output_tokens_cap {
                obj.insert("max_tokens".into(), json!(cap));
                max_tokens_clamped = true;
            }
        }

        let stream = match obj.get("stream") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err("`stream` must be a boolean".into()),
        };
        if stream {
            // Always ask for the usage chunk so usage can be accounted.
            match obj.get_mut("stream_options") {
                Some(Value::Object(opts)) => {
                    opts.insert("include_usage".into(), Value::Bool(true));
                }
                _ => {
                    obj.insert("stream_options".into(), json!({"include_usage": true}));
                }
            }
        }

        Ok(PolicyOutcome {
            model,
            model_rewritten,
            max_tokens_clamped,
            stream,
            removed,
        })
    }

    /// Enforce the policy on a vLLM `/tokenize` body. Returns the model.
    pub(crate) fn apply_tokenize(&self, body: &mut Value) -> Result<String, String> {
        let obj = body
            .as_object_mut()
            .ok_or_else(|| "request body must be a JSON object".to_string())?;
        if !obj.contains_key("prompt") && !obj.contains_key("messages") {
            return Err("`prompt` or `messages` is required".into());
        }
        let (model, _) = self.pin_model(obj);
        Self::strip(obj);
        Ok(model)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(cap: Option<u32>) -> RequestPolicy {
        RequestPolicy {
            allowed_models: vec!["big".into(), "small".into()],
            default_model: "big".into(),
            max_output_tokens_cap: cap,
        }
    }

    #[test]
    fn pins_models() {
        let p = policy(None);
        let mut b = json!({"model": "small", "messages": []});
        let o = p.apply_chat(&mut b).unwrap();
        assert_eq!(o.model, "small");
        assert!(!o.model_rewritten);

        let mut b = json!({"model": "gpt-4-evil", "messages": []});
        let o = p.apply_chat(&mut b).unwrap();
        assert!(o.model_rewritten);
        assert_eq!(b["model"], "big");

        let mut b = json!({"messages": []});
        p.apply_chat(&mut b).unwrap();
        assert_eq!(b["model"], "big");

        let mut b = json!({"model": 7, "messages": []});
        p.apply_chat(&mut b).unwrap();
        assert_eq!(b["model"], "big");
    }

    #[test]
    fn clamps_and_inserts_max_tokens() {
        let p = policy(Some(1000));
        let mut b = json!({"messages": [], "max_tokens": 50000, "max_completion_tokens": 10});
        let o = p.apply_chat(&mut b).unwrap();
        assert!(o.max_tokens_clamped);
        assert_eq!(b["max_tokens"], 1000);
        assert_eq!(b["max_completion_tokens"], 10);

        let mut b = json!({"messages": []});
        p.apply_chat(&mut b).unwrap();
        assert_eq!(b["max_tokens"], 1000);

        let mut b = json!({"messages": [], "max_tokens": 10});
        let o = p.apply_chat(&mut b).unwrap();
        assert!(!o.max_tokens_clamped);
        assert_eq!(b["max_tokens"], 10);

        let mut b = json!({"messages": [], "max_tokens": -5});
        assert!(p.apply_chat(&mut b).is_err());
        let mut b = json!({"messages": [], "max_tokens": "lots"});
        assert!(p.apply_chat(&mut b).is_err());

        // No cap configured: untouched, nothing inserted.
        let mut b = json!({"messages": [], "max_tokens": 50000});
        policy(None).apply_chat(&mut b).unwrap();
        assert_eq!(b["max_tokens"], 50000);
        let mut b = json!({"messages": []});
        policy(None).apply_chat(&mut b).unwrap();
        assert!(b.get("max_tokens").is_none());
    }

    #[test]
    fn strips_dangerous_fields_and_forces_single_choice() {
        let p = policy(None);
        let mut b = json!({
            "messages": [], "chat_template": "{{ evil }}", "best_of": 8, "priority": -100,
            "logits_processors": ["os.system"], "n": 5, "top_k": 20
        });
        let o = p.apply_chat(&mut b).unwrap();
        assert!(o.removed.contains(&"chat_template"));
        assert!(o.removed.contains(&"priority"));
        assert!(b.get("chat_template").is_none());
        assert!(b.get("logits_processors").is_none());
        assert_eq!(b["n"], 1);
        assert_eq!(b["top_k"], 20, "ordinary sampling params pass through");
    }

    #[test]
    fn streaming_forces_usage() {
        let p = policy(None);
        let mut b = json!({"messages": [], "stream": true});
        assert!(p.apply_chat(&mut b).unwrap().stream);
        assert_eq!(b["stream_options"]["include_usage"], true);
        let mut b = json!({"messages": [], "stream": true, "stream_options": {"include_usage": false, "continuous_usage_stats": true}});
        p.apply_chat(&mut b).unwrap();
        assert_eq!(b["stream_options"]["include_usage"], true);
        assert_eq!(b["stream_options"]["continuous_usage_stats"], true);
        let mut b = json!({"messages": [], "stream": "yes"});
        assert!(p.apply_chat(&mut b).is_err());
    }

    #[test]
    fn rejects_non_objects() {
        let p = policy(None);
        assert!(p.apply_chat(&mut json!([1])).is_err());
        assert!(p.apply_chat(&mut json!({"model": "big"})).is_err());
        assert!(p.apply_tokenize(&mut json!("x")).is_err());
        assert!(p.apply_tokenize(&mut json!({"model": "big"})).is_err());
        let mut t = json!({"model": "nope", "prompt": "hi", "chat_template": "x"});
        assert_eq!(p.apply_tokenize(&mut t).unwrap(), "big");
        assert!(t.get("chat_template").is_none());
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
}
