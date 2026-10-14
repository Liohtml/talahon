//! vLLM provider configuration: `.env` defaults merged with per-group
//! overrides.
//!
//! Recognised `.env` keys (non-secret):
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
//! The secret `TALON_VLLM_API_KEY` is read separately by the host LLM gateway
//! via [`crate::env::EnvFile::file_value`] and never enters a container.

use crate::env::EnvFile;
use crate::types::{ContainerConfig, ProviderKind, VllmConfig};

/// Default context window when neither `.env` nor the group says otherwise.
pub const DEFAULT_MAX_CONTEXT_TOKENS: u32 = 32_768;

/// Read provider defaults from the environment. Returns a config with
/// `provider = Some(Vllm)` only when both base URL and model are present.
pub fn load_provider_env_defaults(env: &EnvFile) -> ContainerConfig {
    let mut out = ContainerConfig::default();

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
                top_p: env.get("TALON_VLLM_TOP_P").and_then(|v| v.trim().parse().ok()),
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

    if let Some(provider) = env.get("TALON_PROVIDER") {
        if !provider.eq_ignore_ascii_case("vllm") {
            tracing::warn!(%provider, "TALON_PROVIDER is no longer configurable; only \"vllm\" is supported");
        }
    }

    if let Some(hosts) = env.get("TALON_BLOCKED_HOSTS") {
        out.blocked_hosts = hosts
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .collect();
    }
    out
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

    let group_has_vllm = group.provider == Some(ProviderKind::Vllm) && group.vllm.is_some();
    if !group_has_vllm {
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

/// The vLLM settings a run should use, if the provider is configured.
pub fn effective_vllm(config: &ContainerConfig) -> Option<&VllmConfig> {
    match (config.provider, config.vllm.as_ref()) {
        (Some(ProviderKind::Vllm), Some(v)) => Some(v),
        _ => None,
    }
}

/// Stable identifier stored next to a session, so a provider/model switch
/// can invalidate sessions that were produced by a different model.
pub fn provider_fingerprint(config: &ContainerConfig) -> String {
    match effective_vllm(config) {
        Some(v) => format!("vllm:{}", v.model),
        None => "none".to_string(),
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
