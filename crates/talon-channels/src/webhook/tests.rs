//! Webhook channel tests against a `wiremock` receiver.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use talon_core::audit::MemoryAuditSink;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::test_support::{RecordingHost, test_hmac};

/// Allows everything; optionally returns addresses to pin to.
#[derive(Default)]
struct AllowGuard {
    addrs: Vec<SocketAddr>,
    calls: AtomicUsize,
}

#[async_trait]
impl EgressGuard for AllowGuard {
    async fn check(&self, _url: &Url) -> Result<Vec<SocketAddr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.addrs.clone())
    }
}

/// Denies everything.
#[derive(Default)]
struct DenyGuard {
    calls: AtomicUsize,
}

#[async_trait]
impl EgressGuard for DenyGuard {
    async fn check(&self, _url: &Url) -> Result<Vec<SocketAddr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(Error::security("destination resolves to a private address"))
    }
}

const SECRET: &str = "whsec-test-secret";

fn config(url: &str) -> WebhookConfig {
    let mut cfg = WebhookConfig::new(url);
    cfg.secret = Some(SECRET.to_string());
    cfg.max_retries = 2;
    cfg.backoff_base = Duration::from_millis(1);
    cfg.backoff_max = Duration::from_millis(20);
    cfg.request_timeout = Duration::from_secs(5);
    cfg
}

struct Fixture {
    host: Arc<RecordingHost>,
    audit: MemoryAuditSink,
    channel: WebhookChannel,
}

fn fixture(cfg: WebhookConfig, guard: Arc<dyn EgressGuard>) -> Fixture {
    let host = Arc::new(RecordingHost::default());
    let audit = MemoryAuditSink::default();
    let channel = WebhookChannel::new(cfg, host.clone(), Arc::new(audit.clone()))
        .unwrap()
        .with_egress_guard(guard)
        .with_signer(test_hmac);
    Fixture {
        host,
        audit,
        channel,
    }
}

async fn hook_server(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

async fn received(server: &MockServer) -> Vec<wiremock::Request> {
    server.received_requests().await.unwrap_or_default()
}

fn header<'a>(req: &'a wiremock::Request, name: &str) -> Option<&'a str> {
    req.headers.get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn connect_registers_in_memory_lane_and_metadata() {
    let f = fixture(
        config("https://hooks.example.com/x"),
        Arc::new(AllowGuard::default()),
    );
    assert!(!f.channel.is_connected());
    f.channel.connect().await.unwrap();
    assert!(f.channel.is_connected());

    let regs = f.host.registrations();
    assert_eq!(regs.len(), 1);
    let (jid, group, persist) = &regs[0];
    assert_eq!(jid, WEBHOOK_JID);
    assert!(!persist, "webhook lane must be in-memory only");
    assert_eq!(group.name, "CoPilot Webhook");
    assert_eq!(group.folder, "copilot");
    assert_eq!(group.trigger, "");
    assert_eq!(group.requires_trigger, Some(false));
    assert!(!group.is_main);

    let meta = f.host.metadata();
    assert_eq!(meta.len(), 1);
    assert_eq!(meta[0].chat_jid, WEBHOOK_JID);
    assert_eq!(meta[0].name.as_deref(), Some("CoPilot Webhook"));
    assert_eq!(meta[0].channel.as_deref(), Some("webhook"));
    assert_eq!(meta[0].is_group, Some(false));

    f.channel.disconnect().await.unwrap();
    assert!(!f.channel.is_connected());
}

#[tokio::test]
async fn channel_properties() {
    let f = fixture(
        config("https://hooks.example.com/x"),
        Arc::new(AllowGuard::default()),
    );
    assert_eq!(f.channel.name(), "webhook");
    assert_eq!(f.channel.channel_type(), ChannelType::Plain);
    assert!(f.channel.owns_jid("webhook:copilot"));
    assert!(!f.channel.owns_jid("webhook:other"));
    assert!(!f.channel.owns_jid("tg:1"));
    assert!(f.channel.send_message("tg:1", "x").await.is_err());
}

#[tokio::test]
async fn delivers_signed_json() {
    let server = hook_server(200).await;
    let guard = Arc::new(AllowGuard::default());
    let f = fixture(config(&format!("{}/hook", server.uri())), guard.clone());
    f.channel
        .send_message(WEBHOOK_JID, "digest ready")
        .await
        .unwrap();

    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(guard.calls.load(Ordering::SeqCst), 1, "egress checked");
    let req = &reqs[0];
    let body = std::str::from_utf8(&req.body).unwrap();
    let parsed: Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed["text"], "digest ready");
    assert!(talon_core::time::parse_iso(parsed["timestamp"].as_str().unwrap()).is_some());

    assert_eq!(header(req, "content-type"), Some("application/json"));
    let ts = header(req, "x-talon-timestamp").unwrap();
    let ts_num: i64 = ts.parse().unwrap();
    assert!((chrono::Utc::now().timestamp() - ts_num).abs() < 60);
    let expected = format!(
        "sha256={}",
        test_hmac(SECRET.as_bytes(), format!("{ts}.{body}").as_bytes())
    );
    assert_eq!(header(req, "x-talon-signature"), Some(expected.as_str()));
    assert!(uuid::Uuid::parse_str(header(req, "x-talon-delivery").unwrap()).is_ok());
    assert!(
        header(req, "authorization").is_none(),
        "secret must not be sent"
    );
}

#[tokio::test]
async fn unsigned_without_secret() {
    let server = hook_server(204).await;
    let mut cfg = config(&format!("{}/hook", server.uri()));
    cfg.secret = None;
    let f = fixture(cfg, Arc::new(AllowGuard::default()));
    f.channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 1);
    assert!(header(&reqs[0], "x-talon-signature").is_none());
    assert!(header(&reqs[0], "x-talon-timestamp").is_none());
    assert!(header(&reqs[0], "x-talon-delivery").is_some());
}

#[tokio::test]
async fn legacy_bearer_is_opt_in() {
    let server = hook_server(200).await;
    let mut cfg = config(&format!("{}/hook", server.uri()));
    cfg.legacy_bearer = true;
    let f = fixture(cfg, Arc::new(AllowGuard::default()));
    f.channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    let reqs = received(&server).await;
    let expected = format!("Bearer {SECRET}");
    assert_eq!(header(&reqs[0], "authorization"), Some(expected.as_str()));
    assert!(header(&reqs[0], "x-talon-signature").is_some());
}

#[tokio::test]
async fn retries_server_errors_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let f = fixture(
        config(&format!("{}/hook", server.uri())),
        Arc::new(AllowGuard::default()),
    );
    f.channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 2);
    // Same delivery id on the retry so receivers can de-duplicate.
    assert_eq!(
        header(&reqs[0], "x-talon-delivery"),
        header(&reqs[1], "x-talon-delivery")
    );
}

#[tokio::test]
async fn gives_up_after_max_retries() {
    let server = hook_server(500).await;
    let f = fixture(
        config(&format!("{}/hook", server.uri())),
        Arc::new(AllowGuard::default()),
    );
    // Delivery failures are logged, not returned.
    assert!(f.channel.send_message(WEBHOOK_JID, "x").await.is_ok());
    assert_eq!(received(&server).await.len(), 3);
}

#[tokio::test]
async fn does_not_retry_client_errors() {
    let server = hook_server(400).await;
    let f = fixture(
        config(&format!("{}/hook", server.uri())),
        Arc::new(AllowGuard::default()),
    );
    f.channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    assert_eq!(received(&server).await.len(), 1);
}

#[tokio::test]
async fn retries_429_honouring_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let f = fixture(
        config(&format!("{}/hook", server.uri())),
        Arc::new(AllowGuard::default()),
    );
    f.channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    assert_eq!(received(&server).await.len(), 2);
}

#[tokio::test]
async fn retries_timeouts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(500)))
        .mount(&server)
        .await;
    let mut cfg = config(&format!("{}/hook", server.uri()));
    cfg.request_timeout = Duration::from_millis(100);
    cfg.max_retries = 1;
    let f = fixture(cfg, Arc::new(AllowGuard::default()));
    f.channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    assert_eq!(received(&server).await.len(), 2);
}

#[tokio::test]
async fn never_follows_redirects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/elsewhere", server.uri()).as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let f = fixture(
        config(&format!("{}/hook", server.uri())),
        Arc::new(AllowGuard::default()),
    );
    f.channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    server.verify().await;
}

#[tokio::test]
async fn egress_denial_blocks_and_audits() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let guard = Arc::new(DenyGuard::default());
    let f = fixture(
        config(&format!("{}/hook?token=abc", server.uri())),
        guard.clone(),
    );
    assert!(f.channel.send_message(WEBHOOK_JID, "x").await.is_ok());
    assert_eq!(guard.calls.load(Ordering::SeqCst), 1);
    let events = f.audit.snapshot();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "egress.denied");
    assert_eq!(events[0].outcome, "denied");
    assert_eq!(events[0].actor, "channel:webhook");
    assert_eq!(events[0].target.as_deref(), Some("127.0.0.1"));
    assert!(!events[0].details.to_string().contains("token=abc"));
    server.verify().await;
}

#[tokio::test]
async fn allowlisted_host_bypasses_egress_policy() {
    let server = hook_server(200).await;
    let mut cfg = config(&format!("{}/hook", server.uri()));
    cfg.allowed_hosts = vec!["localhost".into(), "127.0.0.1".into()];
    let guard = Arc::new(DenyGuard::default());
    let f = fixture(cfg, guard.clone());
    assert!(f.channel.is_host_allowlisted());
    f.channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    assert_eq!(guard.calls.load(Ordering::SeqCst), 0);
    assert_eq!(received(&server).await.len(), 1);
    assert!(f.audit.snapshot().is_empty());
}

#[tokio::test]
async fn connection_is_pinned_to_vetted_addresses() {
    let server = hook_server(200).await;
    let addr = *server.address();
    // `.invalid` never resolves: delivery only works through the pin.
    let guard = Arc::new(AllowGuard {
        addrs: vec![addr],
        calls: AtomicUsize::new(0),
    });
    let url = format!("http://webhook.invalid:{}/hook", addr.port());
    let f = fixture(config(&url), guard);
    f.channel.send_message(WEBHOOK_JID, "pinned").await.unwrap();
    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        header(&reqs[0], "host"),
        Some(format!("webhook.invalid:{}", addr.port()).as_str())
    );
}

#[test]
fn rejects_unsafe_urls() {
    let host: Arc<dyn ChannelHost> = Arc::new(RecordingHost::default());
    let audit: SharedAuditSink = Arc::new(MemoryAuditSink::default());
    for bad in [
        "ftp://example.com/x",
        "file:///etc/passwd",
        "not a url",
        "https://user:pass@example.com/x",
        "https://user@example.com/x",
        "data:text/plain,hi",
    ] {
        assert!(
            WebhookChannel::new(
                WebhookConfig::new(bad),
                Arc::clone(&host),
                Arc::clone(&audit)
            )
            .is_err(),
            "{bad} accepted"
        );
    }
    assert!(
        WebhookChannel::new(
            WebhookConfig::new("https://hooks.example.com/x"),
            host,
            audit
        )
        .is_ok()
    );
}

#[test]
fn debug_output_hides_secret_and_url_path() {
    let mut cfg = WebhookConfig::new("https://hooks.example.com/T0KEN-IN-PATH");
    cfg.secret = Some("sup3r-secret".into());
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("sup3r-secret"), "{dbg}");
    assert!(!dbg.contains("T0KEN-IN-PATH"), "{dbg}");
    assert!(dbg.contains("hooks.example.com"), "{dbg}");
}

#[test]
fn config_from_env() {
    let clean = [
        WEBHOOK_URL_ENV,
        WEBHOOK_SECRET_ENV,
        WEBHOOK_ALLOWED_HOSTS_ENV,
        WEBHOOK_LEGACY_BEARER_ENV,
    ]
    .iter()
    .all(|k| std::env::var(k).map(|v| v.is_empty()).unwrap_or(true));
    if !clean {
        return;
    }
    assert!(WebhookConfig::from_env(&EnvFile::from_str_content("WEBHOOK_SECRET=x\n")).is_none());
    let env = EnvFile::from_str_content(
        "WEBHOOK_URL=https://h.example/x\nWEBHOOK_SECRET=s\nWEBHOOK_ALLOWED_HOSTS=h.example, *.corp\nWEBHOOK_LEGACY_BEARER=true\n",
    );
    let cfg = WebhookConfig::from_env(&env).unwrap();
    assert_eq!(cfg.url, "https://h.example/x");
    assert_eq!(cfg.secret.as_deref(), Some("s"));
    assert_eq!(cfg.allowed_hosts, vec!["h.example", "*.corp"]);
    assert!(cfg.legacy_bearer);
}

#[test]
fn signature_value_format() {
    let value = signature_header_value(test_hmac, "key", 1_700_000_000, r#"{"text":"hi"}"#);
    assert_eq!(
        value,
        format!(
            "sha256={}",
            test_hmac(b"key", br#"1700000000.{"text":"hi"}"#)
        )
    );
}

/// Uses the real `talon_security::auth::hmac_sha256_hex`; panics (todo!())
/// until A07's implementation lands.
#[test]
fn signature_with_real_hmac_matches_reference() {
    let body = r#"{"text":"hi","timestamp":"2026-01-01T00:00:00.000Z"}"#;
    assert_eq!(
        signature_header_value(crate::security::default_hmac(), SECRET, 42, body),
        signature_header_value(test_hmac, SECRET, 42, body)
    );
}

#[test]
fn reference_hmac_matches_rfc4231() {
    assert_eq!(
        test_hmac(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// Uses the real `talon_security::egress::EgressPolicy` (default policy
/// denies loopback); fails (todo!() panic) until A07's egress
/// implementation lands.
#[tokio::test]
async fn default_policy_denies_loopback_destinations() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let host = Arc::new(RecordingHost::default());
    let audit = MemoryAuditSink::default();
    let channel = WebhookChannel::new(
        config(&format!("{}/hook", server.uri())),
        host,
        Arc::new(audit.clone()),
    )
    .unwrap();
    channel.send_message(WEBHOOK_JID, "x").await.unwrap();
    let events = audit.snapshot();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "egress.denied");
    server.verify().await;
}
