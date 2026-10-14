//! Outbound webhook channel: POSTs agent output (typically scheduled-task
//! digests) as JSON to a configured URL.
//!
//! Port of `src/channels/webhook.ts`. Kept: the `webhook:copilot` JID bound
//! to the `copilot` folder and registered in memory at connect time, the
//! `{"text", "timestamp"}` body, `WEBHOOK_URL` / `WEBHOOK_SECRET`, and
//! never surfacing delivery failures as errors.
//!
//! Hardened:
//! - **Signed, not bearer.** With a secret, every request carries
//!   `X-Talon-Timestamp: <unix seconds>` and
//!   `X-Talon-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>`;
//!   the secret itself never goes over the wire (the TS release sent it as
//!   `Authorization: Bearer`, still available via `WEBHOOK_LEGACY_BEARER=true`
//!   for old receivers). `X-Talon-Delivery` is a per-message UUID receivers
//!   can use to drop retried duplicates.
//! - **Egress policy.** Unless the URL host is listed in
//!   `WEBHOOK_ALLOWED_HOSTS` (exact or `*.suffix`), the URL is checked with
//!   [`EgressGuard`] (by default `talon_security::egress::EgressPolicy`) and
//!   the connection is pinned to the vetted addresses (DNS-rebinding safe).
//!   Denials are audited as `egress.denied`.
//! - **No redirects** are followed (a 3xx is a failed delivery).
//! - **Retries** with exponential backoff and jitter on connect/timeouts,
//!   408, 429 (honouring `Retry-After`) and 5xx; other 4xx fail fast.
//! - The URL (which may embed tokens) is never logged, only its host.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use serde_json::json;
use talon_core::audit::{SharedAuditSink, event};
use talon_core::channel::{Channel, ChannelHost, ChannelType};
use talon_core::env::EnvFile;
use talon_core::time::now_iso;
use talon_core::types::{ChatMetadata, RegisteredGroup};
use talon_core::{Error, Result};
use tracing::{error, info, warn};
use url::Url;

use crate::security::{EgressGuard, HmacSha256Fn, PolicyEgressGuard, default_hmac, host_matches};
use crate::util::{backoff_delay, list_setting, secret_value, setting};

/// JID used by the webhook channel. Tasks that want their output POSTed to
/// the webhook use this as their `chat_jid`.
pub const WEBHOOK_JID: &str = "webhook:copilot";
/// Group folder the webhook lane runs in.
pub const WEBHOOK_GROUP_FOLDER: &str = "copilot";
/// Display name of the webhook lane.
pub const WEBHOOK_GROUP_NAME: &str = "CoPilot Webhook";
/// Signature header (`sha256=<hex>`).
pub const SIGNATURE_HEADER: &str = "X-Talon-Signature";
/// Unix-seconds timestamp header covered by the signature.
pub const TIMESTAMP_HEADER: &str = "X-Talon-Timestamp";
/// Per-message delivery id (stable across retries).
pub const DELIVERY_HEADER: &str = "X-Talon-Delivery";

/// Env var: destination URL (enables the channel).
pub const WEBHOOK_URL_ENV: &str = "WEBHOOK_URL";
/// Env var: HMAC secret.
pub const WEBHOOK_SECRET_ENV: &str = "WEBHOOK_SECRET";
/// Env var: comma list of hosts exempt from the egress policy.
pub const WEBHOOK_ALLOWED_HOSTS_ENV: &str = "WEBHOOK_ALLOWED_HOSTS";
/// Env var: also send the secret as `Authorization: Bearer` (legacy).
pub const WEBHOOK_LEGACY_BEARER_ENV: &str = "WEBHOOK_LEGACY_BEARER";

/// Webhook channel configuration.
#[derive(Clone)]
pub struct WebhookConfig {
    /// Destination (`http`/`https`, no userinfo). May contain tokens; never
    /// logged.
    pub url: String,
    /// HMAC-SHA256 signing secret. Without it requests are unsigned.
    pub secret: Option<String>,
    /// Hosts (exact or `*.suffix`) trusted by the operator: no egress-policy
    /// check (e.g. an internal CoPilot on a private address).
    pub allowed_hosts: Vec<String>,
    /// Also send `Authorization: Bearer <secret>` like the TS release.
    pub legacy_bearer: bool,
    /// Retries after the first attempt.
    pub max_retries: u32,
    /// Base backoff delay.
    pub backoff_base: Duration,
    /// Backoff cap (also caps `Retry-After`).
    pub backoff_max: Duration,
    /// Per-attempt timeout.
    pub request_timeout: Duration,
}

impl std::fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = Url::parse(&self.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string));
        f.debug_struct("WebhookConfig")
            .field("url_host", &host)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("allowed_hosts", &self.allowed_hosts)
            .field("legacy_bearer", &self.legacy_bearer)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl WebhookConfig {
    /// Defaults: 3 retries, 500 ms base / 10 s cap backoff, 15 s timeout.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            secret: None,
            allowed_hosts: Vec::new(),
            legacy_bearer: false,
            max_retries: 3,
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(10),
            request_timeout: Duration::from_secs(15),
        }
    }

    /// From `WEBHOOK_URL`, `WEBHOOK_SECRET`, `WEBHOOK_ALLOWED_HOSTS`,
    /// `WEBHOOK_LEGACY_BEARER`. `None` when no URL is configured.
    pub fn from_env(env: &EnvFile) -> Option<Self> {
        let url = setting(env, WEBHOOK_URL_ENV)?;
        let mut cfg = Self::new(url);
        cfg.secret = secret_value(env, WEBHOOK_SECRET_ENV);
        cfg.allowed_hosts = list_setting(env, WEBHOOK_ALLOWED_HOSTS_ENV);
        cfg.legacy_bearer = env.get_bool(WEBHOOK_LEGACY_BEARER_ENV);
        Some(cfg)
    }
}

/// `sha256=<hex HMAC(secret, "<timestamp>.<body>")>` — the value of
/// [`SIGNATURE_HEADER`]. Receivers recompute it over the raw body and the
/// [`TIMESTAMP_HEADER`] value and should reject stale timestamps.
pub fn signature_header_value(
    sign: HmacSha256Fn,
    secret: &str,
    timestamp: i64,
    body: &str,
) -> String {
    let message = format!("{timestamp}.{body}");
    format!("sha256={}", sign(secret.as_bytes(), message.as_bytes()))
}

/// Outbound webhook channel (owns [`WEBHOOK_JID`]).
pub struct WebhookChannel {
    config: WebhookConfig,
    url: Url,
    host_label: String,
    host_allowlisted: bool,
    host: Arc<dyn ChannelHost>,
    audit: SharedAuditSink,
    egress: Arc<dyn EgressGuard>,
    sign: HmacSha256Fn,
    client: reqwest::Client,
    connected: AtomicBool,
}

impl std::fmt::Debug for WebhookChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookChannel")
            .field("host", &self.host_label)
            .field("host_allowlisted", &self.host_allowlisted)
            .field("connected", &self.connected.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

enum Attempt {
    Delivered,
    Retry(Option<Duration>),
    Fail,
}

impl WebhookChannel {
    /// Validate the URL (http/https, a host, no userinfo) and build the
    /// channel with the default egress policy ([`PolicyEgressGuard`] with
    /// `EgressPolicy::default()`) and signer. Use
    /// [`with_egress_guard`](Self::with_egress_guard) to supply the
    /// operator's policy.
    pub fn new(
        config: WebhookConfig,
        host: Arc<dyn ChannelHost>,
        audit: SharedAuditSink,
    ) -> Result<Self> {
        let url = Url::parse(config.url.trim())
            .map_err(|e| Error::Config(format!("WEBHOOK_URL is not a valid URL: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::Config(format!(
                "WEBHOOK_URL scheme {:?} not allowed (http/https only)",
                url.scheme()
            )));
        }
        let Some(host_str) = url.host_str().filter(|h| !h.is_empty()) else {
            return Err(Error::Config("WEBHOOK_URL has no host".to_string()));
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::Config(
                "WEBHOOK_URL must not embed credentials; use WEBHOOK_SECRET".to_string(),
            ));
        }
        let host_label = host_str.to_string();
        let host_allowlisted = host_matches(&host_label, &config.allowed_hosts);
        if config.secret.is_none() {
            warn!(host = %host_label, "Webhook channel: WEBHOOK_SECRET not set, requests are unsigned");
        }
        let client = Self::build_client(&config, None)?;
        Ok(Self {
            config,
            url,
            host_label,
            host_allowlisted,
            host,
            audit,
            egress: Arc::new(PolicyEgressGuard::default()),
            sign: default_hmac(),
            client,
            connected: AtomicBool::new(false),
        })
    }

    /// Replace the egress guard (the host passes the configured policy).
    pub fn with_egress_guard(mut self, guard: Arc<dyn EgressGuard>) -> Self {
        self.egress = guard;
        self
    }

    /// Replace the HMAC implementation (tests / alternative crypto).
    pub fn with_signer(mut self, sign: HmacSha256Fn) -> Self {
        self.sign = sign;
        self
    }

    /// Whether the URL host bypasses the egress policy.
    pub fn is_host_allowlisted(&self) -> bool {
        self.host_allowlisted
    }

    fn build_client(
        config: &WebhookConfig,
        pin: Option<(&str, &[SocketAddr])>,
    ) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // A proxy would resolve the name itself and defeat pinning.
            .no_proxy()
            .connect_timeout(config.request_timeout.min(Duration::from_secs(10)))
            .timeout(config.request_timeout)
            .user_agent(concat!("talon-webhook/", env!("CARGO_PKG_VERSION")));
        if let Some((domain, addrs)) = pin {
            builder = builder.resolve_to_addrs(domain, addrs);
        }
        builder
            .build()
            .map_err(|e| Error::Channel(format!("webhook client: {}", e.without_url())))
    }

    /// Client for this delivery: egress-checked and pinned unless the host
    /// is allowlisted. `None` when the policy denies the URL.
    async fn client_for_delivery(&self) -> Option<reqwest::Client> {
        if self.host_allowlisted {
            return Some(self.client.clone());
        }
        match self.egress.check(&self.url).await {
            Ok(addrs) => {
                let is_domain = matches!(self.url.host(), Some(url::Host::Domain(_)));
                if is_domain && !addrs.is_empty() {
                    match Self::build_client(&self.config, Some((&self.host_label, &addrs))) {
                        Ok(client) => Some(client),
                        Err(e) => {
                            error!(host = %self.host_label, err = %e, "Webhook channel: client build failed");
                            None
                        }
                    }
                } else {
                    Some(self.client.clone())
                }
            }
            Err(e) => {
                error!(
                    host = %self.host_label,
                    err = %e,
                    "Webhook channel: egress policy denied the webhook URL (add the host to WEBHOOK_ALLOWED_HOSTS to trust it)"
                );
                self.audit.record(event(
                    "egress.denied",
                    "channel:webhook",
                    Some(&self.host_label),
                    "denied",
                    json!({ "reason": e.to_string(), "channel": "webhook" }),
                ));
                None
            }
        }
    }

    async fn attempt(&self, client: &reqwest::Client, body: &str, delivery_id: &str) -> Attempt {
        let mut request = client
            .post(self.url.clone())
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .header(DELIVERY_HEADER, delivery_id);
        if let Some(secret) = &self.config.secret {
            let timestamp = chrono::Utc::now().timestamp();
            request = request
                .header(TIMESTAMP_HEADER, timestamp.to_string())
                .header(
                    SIGNATURE_HEADER,
                    signature_header_value(self.sign, secret, timestamp, body),
                );
            if self.config.legacy_bearer {
                request = request.header(AUTHORIZATION, format!("Bearer {secret}"));
            }
        }
        match request.body(body.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    Attempt::Delivered
                } else if status.is_redirection() {
                    warn!(host = %self.host_label, status = status.as_u16(), "Webhook channel: redirect not followed");
                    Attempt::Fail
                } else if status.as_u16() == 408
                    || status.as_u16() == 429
                    || status.is_server_error()
                {
                    let retry_after = resp
                        .headers()
                        .get(RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .map(Duration::from_secs);
                    warn!(host = %self.host_label, status = status.as_u16(), "Webhook channel: POST returned retryable status");
                    Attempt::Retry(retry_after)
                } else {
                    warn!(host = %self.host_label, status = status.as_u16(), "Webhook channel: POST returned non-2xx");
                    Attempt::Fail
                }
            }
            Err(e) => {
                warn!(host = %self.host_label, err = %e.without_url(), "Webhook channel: POST failed");
                Attempt::Retry(None)
            }
        }
    }
}

#[async_trait]
impl Channel for WebhookChannel {
    fn name(&self) -> &str {
        "webhook"
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Plain
    }

    async fn connect(&self) -> Result<()> {
        let now = now_iso();
        let group = RegisteredGroup {
            name: WEBHOOK_GROUP_NAME.to_string(),
            folder: WEBHOOK_GROUP_FOLDER.to_string(),
            trigger: String::new(),
            added_at: now.clone(),
            container_config: None,
            requires_trigger: Some(false),
            is_main: false,
            session_key: None,
            ipc_key: None,
            ephemeral_session: false,
            trusted_session_commands: false,
        };
        // In-memory only, like the TS `opts.registerGroup`.
        self.host.register_group(WEBHOOK_JID, group, false).await;
        self.host
            .on_chat_metadata(ChatMetadata {
                chat_jid: WEBHOOK_JID.to_string(),
                timestamp: now,
                name: Some(WEBHOOK_GROUP_NAME.to_string()),
                channel: Some("webhook".to_string()),
                is_group: Some(false),
            })
            .await;
        self.connected.store(true, Ordering::SeqCst);
        info!(
            host = %self.host_label,
            allowlisted = self.host_allowlisted,
            signed = self.config.secret.is_some(),
            "Webhook channel connected"
        );
        Ok(())
    }

    async fn send_message(&self, jid: &str, text: &str) -> Result<()> {
        if jid != WEBHOOK_JID {
            return Err(Error::invalid(format!("not the webhook JID: {jid}")));
        }
        let Some(client) = self.client_for_delivery().await else {
            return Ok(());
        };
        let body = json!({ "text": text, "timestamp": now_iso() }).to_string();
        let delivery_id = uuid::Uuid::new_v4().to_string();
        let attempts = self.config.max_retries.saturating_add(1);
        for attempt in 0..attempts {
            match self.attempt(&client, &body, &delivery_id).await {
                Attempt::Delivered => {
                    info!(
                        host = %self.host_label,
                        length = text.chars().count(),
                        attempt = attempt + 1,
                        "Webhook channel: message delivered"
                    );
                    return Ok(());
                }
                Attempt::Fail => break,
                Attempt::Retry(retry_after) => {
                    if attempt + 1 >= attempts {
                        break;
                    }
                    let backoff =
                        backoff_delay(attempt, self.config.backoff_base, self.config.backoff_max);
                    let delay = retry_after
                        .map(|ra| ra.max(backoff))
                        .unwrap_or(backoff)
                        .min(self.config.backoff_max);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        error!(host = %self.host_label, delivery_id, "Webhook channel: delivery failed");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    fn owns_jid(&self, jid: &str) -> bool {
        jid == WEBHOOK_JID
    }

    async fn disconnect(&self) -> Result<()> {
        self.connected.store(false, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
