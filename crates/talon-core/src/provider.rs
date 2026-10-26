//! Model provider configuration: `.env` defaults merged with per-group
//! overrides.
//!
//! `TALON_PROVIDER` selects the upstream the host LLM gateway talks to:
//! `vllm` (default) or `anthropic`. The agent in the container is unaware
//! of the choice — it always speaks the OpenAI-compatible API to the
//! gateway.
//!
//! Recognised `.env` keys for `vllm` (non-secret):
//!
//! | key                         | meaning                                         |
//! |-----------------------------|-------------------------------------------------|
//! | `TALON_VLLM_BASE_URL`       | e.g. `http://vllm.internal:8000` (required)     |
//! | `TALON_VLLM_MODEL`          | served model name (required)                    |
//! | `TALON_VLLM_FAST_MODEL`     | optional auxiliary model                        |
//! | `TALON_VLLM_MAX_CONTEXT`    | context window in tokens (default 32768)        |
//! | `TALON_VLLM_MAX_OUTPUT`     | max output tokens per completion                |
//! | `TALON_VLLM_TEMPERATURE`    | sampling temperature                            |
//! | `TALON_VLLM_TOP_P`          | nucleus sampling                                |
//! | `TALON_VLLM_ENABLE_THINKING`| `true`/`false` for reasoning chat templates     |
//! | `TALON_VLLM_TIMEOUT_SECS`   | per-request timeout                             |
//! | `TALON_BLOCKED_HOSTS`       | comma-separated hosts routed to 127.0.0.1       |
//!
//! Recognised `.env` keys for `anthropic` (non-secret):
//!
//! | key                              | meaning                                                |
//! |----------------------------------|--------------------------------------------------------|
//! | `TALON_ANTHROPIC_MODEL`          | model id, e.g. `claude-sonnet-5-5` (required)          |
//! | `TALON_ANTHROPIC_FAST_MODEL`     | optional auxiliary model                               |
//! | `TALON_ANTHROPIC_BASE_URL`       | default `https://api.anthropic.com`                    |
//! | `TALON_ANTHROPIC_MAX_CONTEXT`    | context window in tokens (default 200000)              |
//! | `TALON_ANTHROPIC_MAX_OUTPUT`     | max output tokens per completion                       |
//! | `TALON_ANTHROPIC_THINKING`       | `true` = adaptive thinking (off by default)            |
//! | `TALON_ANTHROPIC_TIMEOUT_SECS`   | per-request timeout                                    |
//!
//! The secrets `TALON_VLLM_API_KEY` / `TALON_ANTHROPIC_API_KEY` are read
//! separately by the host LLM gateway via
//! [`crate::env::EnvFile::file_value`] and never enter a container.

use crate::env::EnvFile;
use crate::types::{ContainerConfig, ProviderKind, VllmConfig};

/// Default context window when neither `.env` nor the group says otherwise.
pub const DEFAULT_MAX_CONTEXT_TOKENS: u32 = 32_768;
/// Default context window of the Anthropic provider.
pub const ANTHROPIC_DEFAULT_MAX_CONTEXT_TOKENS: u32 = 200_000;
/// Default Anthropic API base URL.
pub const ANTHROPIC_DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Read provider defaults from the environment. Returns a config with
/// `provider = Some(Vllm)` only when both base URL and model are present,
/// or `Some(Anthropic)` when `TALON_PROVIDER=anthropic` and
/// `TALON_ANTHROPIC_MODEL` is set.
pub fn load_provider_env_defaults(env: &EnvFile) -> ContainerConfig {
    let mut out = ContainerConfig::default();

    let provider = env
        .get("TALON_PROVIDER")
        .map(|p| p.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "vllm".to_string());
    if provider == "anthropic" {
        load_anthropic(env, &mut out);
        load_blocked_hosts(env, &mut out);
        return out;
    }

    let base_url = env.get("TALON_VLLM_BASE_URL");
    let model = env.get("TALON_VLLM_MODEL");
    match (base_url, model) {
        (Some(base_url), Some(model)) => {
            out.provider = Some(ProviderKind::Vllm);
            out.vllm = Some(VllmConfig {
                base_url,
                model,
                fast_model: env.get("TALON_VLLM_FAST_MODEL"),
                max_context_tokens: env
                    .get("TALON_VLLM_MAX_CONTEXT")
                    .and_then(|v| v.trim().parse().ok()),
                max_output_tokens: env
                    .get("TALON_VLLM_MAX_OUTPUT")
                    .and_then(|v| v.trim().parse().ok()),
                temperature: env
                    .get("TALON_VLLM_TEMPERATURE")
                    .and_then(|v| v.trim().parse().ok()),
                top_p: env
                    .get("TALON_VLLM_TOP_P")
                    .and_then(|v| v.trim().parse().ok()),
                enable_thinking: env
                    .get("TALON_VLLM_ENABLE_THINKING")
                    .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on")),
                request_timeout_secs: env
                    .get("TALON_VLLM_TIMEOUT_SECS")
                    .and_then(|v| v.trim().parse().ok()),
            });
        }
        (None, None) => {}
        _ => tracing::warn!(
            "TALON_VLLM_BASE_URL and TALON_VLLM_MODEL must both be set — vLLM provider disabled"
        ),
    }

    if provider != "vllm" {
        tracing::warn!(%provider, "unknown TALON_PROVIDER; supported: \"vllm\", \"anthropic\"");
    }

    load_blocked_hosts(env, &mut out);
    out
}

fn load_anthropic(env: &EnvFile, out: &mut ContainerConfig) {
    let Some(model) = env
        .get("TALON_ANTHROPIC_MODEL")
        .filter(|m| !m.trim().is_empty())
    else {
        tracing::warn!(
            "TALON_PROVIDER=anthropic but TALON_ANTHROPIC_MODEL is not set — provider disabled"
        );
        return;
    };
    out.provider = Some(ProviderKind::Anthropic);
    out.vllm = Some(VllmConfig {
        base_url: env
            .get("TALON_ANTHROPIC_BASE_URL")
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| ANTHROPIC_DEFAULT_BASE_URL.to_string()),
        model: model.trim().to_string(),
        fast_model: env.get("TALON_ANTHROPIC_FAST_MODEL"),
        max_context_tokens: Some(
            env.get("TALON_ANTHROPIC_MAX_CONTEXT")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(ANTHROPIC_DEFAULT_MAX_CONTEXT_TOKENS),
        ),
        max_output_tokens: env
            .get("TALON_ANTHROPIC_MAX_OUTPUT")
            .and_then(|v| v.trim().parse().ok()),
        // Current Claude models reject sampling parameters; the gateway
        // drops them anyway. Thinking is opt-in: with tool use the signed
        // thinking blocks must be replayed, which the gateway does through
        // `reasoning_content` (see `talon_llm::anthropic`).
        temperature: None,
        top_p: None,
        enable_thinking: env
            .get("TALON_ANTHROPIC_THINKING")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on")),
        request_timeout_secs: env
            .get("TALON_ANTHROPIC_TIMEOUT_SECS")
            .and_then(|v| v.trim().parse().ok()),
    });
}

fn load_blocked_hosts(env: &EnvFile, out: &mut ContainerConfig) {
    if let Some(hosts) = env.get("TALON_BLOCKED_HOSTS") {
        out.blocked_hosts = hosts
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .collect();
    }
}

/// Merge `.env` defaults with a group's own config. Precedence:
/// defaults -> group (group wins).
///
/// - `provider`/`vllm`: a group value replaces the default wholesale.
/// - `env`: shallow-merged (group keys win).
/// - `blocked_hosts`: union (a group can only add, never remove).
/// - mounts / timeout / limits: group-only.
pub fn merge_container_config(
    defaults: &ContainerConfig,
    group: Option<&ContainerConfig>,
) -> ContainerConfig {
    let Some(group) = group else {
        return defaults.clone();
    };
    let mut merged = group.clone();

    let group_has_llm = matches!(
        group.provider,
        Some(ProviderKind::Vllm | ProviderKind::Anthropic)
    ) && group.vllm.is_some();
    if !group_has_llm {
        merged.provider = defaults.provider;
        merged.vllm = defaults.vllm.clone();
    }

    let mut env = defaults.env.clone();
    env.extend(group.env.clone());
    merged.env = env;

    let mut hosts = defaults.blocked_hosts.clone();
    for h in &group.blocked_hosts {
        if !hosts.contains(h) {
            hosts.push(h.clone());
        }
    }
    merged.blocked_hosts = hosts;
    merged
}

/// The model settings a run should use, if a provider is configured
/// (vLLM or Anthropic — the fields are the same, see [`VllmConfig`]).
pub fn effective_vllm(config: &ContainerConfig) -> Option<&VllmConfig> {
    match (config.provider, config.vllm.as_ref()) {
        (Some(ProviderKind::Vllm | ProviderKind::Anthropic), Some(v)) => Some(v),
        _ => None,
    }
}

/// The configured provider, if its settings are complete.
pub fn provider_kind(config: &ContainerConfig) -> Option<ProviderKind> {
    effective_vllm(config).and(config.provider)
}

/// Stable identifier stored next to a session, so a provider/model switch
/// can invalidate sessions that were produced by a different model.
pub fn provider_fingerprint(config: &ContainerConfig) -> String {
    match (provider_kind(config), effective_vllm(config)) {
        (Some(kind), Some(v)) => format!("{}:{}", kind.as_str(), v.model),
        _ => "none".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_defaults_require_url_and_model() {
        let env = EnvFile::from_str_content("TALON_VLLM_BASE_URL=http://v:8000\n");
        assert!(effective_vllm(&load_provider_env_defaults(&env)).is_none());

        let env = EnvFile::from_str_content(
            "TALON_VLLM_BASE_URL=http://v:8000\nTALON_VLLM_MODEL=qwen\nTALON_VLLM_MAX_CONTEXT=131072\nTALON_BLOCKED_HOSTS=a.com, b.com\n",
        );
        let cfg = load_provider_env_defaults(&env);
        let v = effective_vllm(&cfg).unwrap();
        assert_eq!(v.model, "qwen");
        assert_eq!(v.max_context_tokens, Some(131072));
        assert_eq!(cfg.blocked_hosts, vec!["a.com", "b.com"]);
        assert_eq!(provider_fingerprint(&cfg), "vllm:qwen");
    }

    #[test]
    fn anthropic_provider_from_env() {
        let env = EnvFile::from_str_content(
            "TALON_PROVIDER=anthropic\nTALON_ANTHROPIC_MODEL=claude-sonnet-5-5\nTALON_ANTHROPIC_THINKING=true\n",
        );
        let cfg = load_provider_env_defaults(&env);
        assert_eq!(provider_kind(&cfg), Some(ProviderKind::Anthropic));
        let v = effective_vllm(&cfg).unwrap();
        assert_eq!(v.model, "claude-sonnet-5-5");
        assert_eq!(v.base_url, ANTHROPIC_DEFAULT_BASE_URL);
        assert_eq!(
            v.max_context_tokens,
            Some(ANTHROPIC_DEFAULT_MAX_CONTEXT_TOKENS)
        );
        assert_eq!(v.enable_thinking, Some(true));
        assert_eq!(provider_fingerprint(&cfg), "anthropic:claude-sonnet-5-5");
        assert_eq!(
            ProviderKind::Anthropic.api_key_env(),
            "TALON_ANTHROPIC_API_KEY"
        );

        // Without a model the provider stays off, even when vLLM keys exist.
        let env = EnvFile::from_str_content(
            "TALON_PROVIDER=anthropic\nTALON_VLLM_BASE_URL=http://v\nTALON_VLLM_MODEL=a\n",
        );
        assert!(provider_kind(&load_provider_env_defaults(&env)).is_none());
    }

    #[test]
    fn group_overrides_and_unions() {
        let env = EnvFile::from_str_content(
            "TALON_VLLM_BASE_URL=http://v\nTALON_VLLM_MODEL=a\nTALON_BLOCKED_HOSTS=x.com\n",
        );
        let defaults = load_provider_env_defaults(&env);
        let mut group = ContainerConfig {
            blocked_hosts: vec!["y.com".into(), "x.com".into()],
            ..Default::default()
        };
        group.env.insert("K".into(), "V".into());
        let merged = merge_container_config(&defaults, Some(&group));
        assert_eq!(effective_vllm(&merged).unwrap().model, "a");
        assert_eq!(merged.blocked_hosts, vec!["x.com", "y.com"]);
        assert_eq!(merged.env.get("K").map(String::as_str), Some("V"));

        group.provider = Some(ProviderKind::Vllm);
        group.vllm = Some(VllmConfig {
            base_url: "http://other".into(),
            model: "b".into(),
            fast_model: None,
            max_context_tokens: None,
            max_output_tokens: None,
            temperature: None,
            top_p: None,
            enable_thinking: None,
            request_timeout_secs: None,
        });
        let merged = merge_container_config(&defaults, Some(&group));
        assert_eq!(effective_vllm(&merged).unwrap().model, "b");
    }
}
