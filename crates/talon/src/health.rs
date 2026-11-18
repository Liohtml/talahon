//! The host's part of `GET /v2/health` (see [`talon_http::health`]): the LLM
//! gateway and the model server, which the HTTP channel cannot reach itself.
//!
//! - **`gateway`** is read from the running gateway's own counters; nothing
//!   is sent. Without a gateway no agent turn can reach a model, so that is a
//!   critical failure.
//! - **`model`** is a real request to the vLLM server (`GET /v1/models`)
//!   with the host's API key, made from the host and not through the
//!   gateway: a gateway token would count as another lane there. It is not
//!   `GET /health`: vLLM's `--api-key` guards only `/v1/*`, so `/health`
//!   answers a wrong key too. A refused key is critical; an unreachable
//!   server only degrades (chat and investigations queue until it is back).
//!   The request has its own deadline ([`MODEL_DEADLINE`]) below the
//!   channel's deadline for the whole probe, so a slow model server never
//!   costs the `gateway` component. The Anthropic provider is **not** probed:
//!   its API has no free liveness call, so no `model` component is reported
//!   for it.
//!
//! Details are fixed texts: a backend's error message names hosts and ports
//! and is only logged.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use talon_core::config::TalonConfig;
use talon_core::provider::{effective_vllm, provider_kind};
use talon_core::types::ProviderKind;
use talon_http::health::CHECK_DEADLINE;
use talon_http::{ComponentCheck, ComponentGroup, ComponentStatus, HealthModels, HealthProbe};
use talon_llm::gateway::GatewayStats;
use talon_llm::{ClientConfig, GatewayHandle, LlmError, RetryPolicy, VllmClient};

use crate::app::api_key_env;

/// Deadline of the whole model server check. The channel discards a probe
/// that misses [`CHECK_DEADLINE`] together with its `gateway` component, so
/// this stays safely below it.
const MODEL_DEADLINE: Duration = Duration::from_secs(3);
const _: () = assert!(MODEL_DEADLINE.as_millis() + 500 <= CHECK_DEADLINE.as_millis());

type StatsFn = Arc<dyn Fn() -> GatewayStats + Send + Sync>;

/// Reports the `gateway` and `model` components.
pub struct HostHealthProbe {
    gateway: Option<StatsFn>,
    model: Option<VllmClient>,
    /// Bound on [`Self::model_component`]; [`MODEL_DEADLINE`] outside tests.
    model_deadline: Duration,
    anthropic: bool,
    models: Option<HealthModels>,
}

impl std::fmt::Debug for HostHealthProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostHealthProbe").finish_non_exhaustive()
    }
}

impl HostHealthProbe {
    /// The probe for this host: `gateway` is the running LLM gateway, if one
    /// was started.
    pub fn new(config: &TalonConfig, gateway: Option<GatewayHandle>) -> Self {
        let vllm = effective_vllm(&config.provider_defaults);
        let anthropic = provider_kind(&config.provider_defaults) == Some(ProviderKind::Anthropic);
        let model = vllm.filter(|_| !anthropic).and_then(|v| {
            let mut client = ClientConfig::new(v.base_url.clone(), v.model.clone());
            client.api_key = config
                .env
                .file_value(api_key_env(config))
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .map(str::to_string);
            client.request_timeout = MODEL_DEADLINE;
            client.connect_timeout = MODEL_DEADLINE;
            // One request: a retry with backoff would not fit the deadline.
            client.retry = RetryPolicy::none();
            VllmClient::new(client).ok()
        });
        Self {
            gateway: gateway.map(|g| Arc::new(move || g.stats()) as StatsFn),
            model,
            model_deadline: MODEL_DEADLINE,
            anthropic,
            // One model serves both: Talahon has no separate chat model.
            models: vllm.map(|v| HealthModels {
                chat: v.model.clone(),
                investigation: v.model.clone(),
            }),
        }
    }

    fn gateway_component(&self) -> ComponentCheck {
        let base = |status| {
            ComponentCheck::new("gateway", "LLM gateway", ComponentGroup::Core, status).critical()
        };
        match &self.gateway {
            Some(stats) => {
                let s = stats();
                let mut detail = format!(
                    "Up {} s: {} request(s), {} upstream error(s), {} in flight",
                    s.uptime_secs, s.requests, s.upstream_errors, s.in_flight
                );
                if self.anthropic {
                    detail.push_str("; the Anthropic API itself is not probed");
                }
                base(ComponentStatus::Ok).detail(detail)
            }
            None => base(ComponentStatus::Fail)
                .detail("The LLM gateway is not running: no model provider is configured")
                .fix(
                    "Set TALAHON_VLLM_BASE_URL and TALAHON_VLLM_MODEL (or TALAHON_PROVIDER=anthropic \
                     with TALAHON_ANTHROPIC_MODEL) in .env, restart Talahon and run `talahon doctor`.",
                ),
        }
    }

    async fn model_component(client: &VllmClient, deadline: Duration) -> ComponentCheck {
        let started = Instant::now();
        // An authenticated endpoint, so a wrong key shows here and not only
        // in every agent turn.
        let result = tokio::time::timeout(deadline, client.list_models())
            .await
            .unwrap_or_else(|_| {
                Err(LlmError::Timeout(format!(
                    "no answer within {} ms",
                    deadline.as_millis()
                )))
            });
        let base = |status| {
            ComponentCheck::new("model", "Model server", ComponentGroup::Model, status)
                .latency(started.elapsed())
        };
        match result {
            Ok(_) => base(ComponentStatus::Ok).detail("The model server answered"),
            Err(e) => {
                tracing::warn!(err = %e, "health: the model server check failed");
                match e {
                    LlmError::Unauthorized { .. } => base(ComponentStatus::Fail)
                        .critical()
                        .detail("The model server refused Talahon's API key")
                        .fix(
                            "Set TALAHON_VLLM_API_KEY in .env to the key the model server was \
                             started with (`--api-key`) and restart Talahon.",
                        ),
                    LlmError::Connect(_) | LlmError::Timeout(_) => base(ComponentStatus::Fail)
                        .detail("The model server could not be reached in time")
                        .fix(
                            "Check that the model server is running and reachable from this host \
                             (TALAHON_VLLM_BASE_URL, firewall), then run `talahon doctor`.",
                        ),
                    _ => base(ComponentStatus::Fail)
                        .detail("The model server answered with an error")
                        .fix("See the model server's log; `talahon doctor` shows the request."),
                }
            }
        }
    }
}

#[async_trait]
impl HealthProbe for HostHealthProbe {
    fn id(&self) -> &str {
        "model"
    }

    fn name(&self) -> &str {
        "Model server"
    }

    fn group(&self) -> ComponentGroup {
        ComponentGroup::Model
    }

    async fn check(&self) -> Vec<ComponentCheck> {
        let mut components = vec![self.gateway_component()];
        if let Some(client) = &self.model {
            components.push(Self::model_component(client, self.model_deadline).await);
        }
        components
    }

    fn models(&self) -> Option<HealthModels> {
        self.models.clone()
    }
}

#[cfg(test)]
mod tests {
    use talon_core::env::EnvFile;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn probe(env: &str, gateway: bool) -> HostHealthProbe {
        let config = TalonConfig::from_env(
            std::path::Path::new("/srv/talahon"),
            EnvFile::from_str_content(env),
        );
        let mut probe = HostHealthProbe::new(&config, None);
        if gateway {
            probe.gateway = Some(Arc::new(|| GatewayStats {
                uptime_secs: 60,
                requests: 7,
                upstream_errors: 1,
                ..GatewayStats::default()
            }));
        }
        probe
    }

    fn vllm_env(base: &str) -> String {
        format!(
            "TALAHON_VLLM_BASE_URL={base}\nTALAHON_VLLM_MODEL=test-model\nTALAHON_VLLM_API_KEY=upstream-key\n"
        )
    }

    fn model_list() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "list",
            "data": [{ "id": "test-model", "object": "model", "owned_by": "vllm" }],
        }))
    }

    #[tokio::test]
    async fn no_provider_is_a_critical_gateway_failure_and_no_model_component() {
        let p = probe("", false);
        let components = p.check().await;
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].id, "gateway");
        assert_eq!(components[0].status, ComponentStatus::Fail);
        assert!(components[0].critical && components[0].fix.is_some());
        assert_eq!(p.models(), None);
    }

    #[tokio::test]
    async fn a_healthy_model_server_is_asked_with_the_hosts_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer upstream-key"))
            .respond_with(model_list())
            .expect(1)
            .mount(&server)
            .await;
        let p = probe(&vllm_env(&server.uri()), true);
        let components = p.check().await;
        assert_eq!(components[0].id, "gateway");
        assert_eq!(components[0].status, ComponentStatus::Ok);
        assert_eq!(
            components[0].detail.as_deref(),
            Some("Up 60 s: 7 request(s), 1 upstream error(s), 0 in flight")
        );
        assert_eq!(components[1].id, "model");
        assert_eq!(components[1].group, ComponentGroup::Model);
        assert_eq!(components[1].status, ComponentStatus::Ok);
        assert!(components[1].latency_ms.is_some());
        let models = p.models().unwrap();
        assert_eq!(
            (models.chat.as_str(), models.investigation.as_str()),
            ("test-model", "test-model")
        );
    }

    #[tokio::test]
    async fn a_refused_key_is_critical_and_an_unreachable_server_is_not() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad key for host-a:8000"))
            .mount(&server)
            .await;
        let refused = probe(&vllm_env(&server.uri()), true).check().await;
        assert_eq!(refused[1].status, ComponentStatus::Fail);
        assert!(refused[1].critical);
        assert_eq!(
            refused[1].detail.as_deref(),
            Some("The model server refused Talahon's API key")
        );

        // A port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let down = probe(&vllm_env(&closed), true).check().await;
        assert_eq!(down[1].status, ComponentStatus::Fail);
        assert!(!down[1].critical);
        // The backend's own text (it names the address) is not relayed.
        assert!(!format!("{:?}", down[1]).contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn a_wrong_key_is_caught_although_health_answers_without_one() {
        // As vLLM with `--api-key`: `/health` is open, `/v1/*` checks the key.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer the-servers-key"))
            .respond_with(model_list())
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let components = probe(&vllm_env(&server.uri()), true).check().await;
        let model = &components[1];
        assert_eq!(model.id, "model");
        assert_eq!(model.status, ComponentStatus::Fail);
        assert!(model.critical, "a refused key takes Talahon down");
        assert_eq!(
            model.detail.as_deref(),
            Some("The model server refused Talahon's API key")
        );
    }

    #[tokio::test]
    async fn a_slow_model_server_fails_in_time_and_keeps_the_gateway() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(model_list().set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let mut p = probe(&vllm_env(&server.uri()), true);
        // Shorter than the client's own request timeout, so this bound is
        // what ends the check.
        p.model_deadline = Duration::from_millis(200);
        let started = Instant::now();
        let components = p.check().await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "ended by the probe's bound, not the client's 3 s timeout"
        );
        let ids: Vec<&str> = components.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["gateway", "model"]);
        assert_eq!(components[0].status, ComponentStatus::Ok);
        assert_eq!(components[1].status, ComponentStatus::Fail);
        assert!(!components[1].critical);
        assert_eq!(
            components[1].detail.as_deref(),
            Some("The model server could not be reached in time")
        );
    }

    #[tokio::test]
    async fn the_anthropic_provider_is_not_probed() {
        let p = probe(
            "TALAHON_PROVIDER=anthropic\nTALAHON_ANTHROPIC_MODEL=some-model\nTALAHON_ANTHROPIC_API_KEY=k\n",
            true,
        );
        let components = p.check().await;
        assert_eq!(components.len(), 1, "no model component is invented");
        assert!(
            components[0]
                .detail
                .as_deref()
                .unwrap()
                .ends_with("the Anthropic API itself is not probed")
        );
        assert_eq!(p.models().unwrap().investigation, "some-model");
    }
}
