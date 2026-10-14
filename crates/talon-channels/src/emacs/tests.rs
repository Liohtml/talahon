//! Port of `src/channels/emacs.test.ts` (HTTP-level tests against the real
//! listener on an ephemeral loopback port) plus hardening tests.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::{Value, json};
use talon_core::audit::MemoryAuditSink;

use super::*;
use crate::test_support::{RecordingHost, group, test_ct_eq};

const TOKEN: &str = "test-token-0123456789";

fn main_group() -> RegisteredGroup {
    let mut g = group("main", "main", "");
    g.is_main = true;
    g
}

fn main_host() -> Arc<RecordingHost> {
    Arc::new(RecordingHost::with_groups(&[("main:jid", main_group())]))
}

fn make(host: Arc<RecordingHost>, audit: &MemoryAuditSink) -> EmacsBridgeChannel {
    make_with_dir(host, audit, None)
}

fn make_with_dir(
    host: Arc<RecordingHost>,
    audit: &MemoryAuditSink,
    groups_dir: Option<PathBuf>,
) -> EmacsBridgeChannel {
    EmacsBridgeChannel::new(
        EmacsConfig {
            port: 0,
            auth_token: TOKEN.to_string(),
            groups_dir,
        },
        host,
        Arc::new(audit.clone()),
    )
    .unwrap()
    .with_constant_time_eq(test_ct_eq)
}

async fn connected(host: Arc<RecordingHost>) -> (EmacsBridgeChannel, SocketAddr, MemoryAuditSink) {
    let audit = MemoryAuditSink::default();
    let channel = make(host, &audit);
    channel.connect().await.unwrap();
    let addr = channel.local_addr().await.unwrap();
    (channel, addr, audit)
}

/// HTTP request; returns status and parsed (or raw string) body.
async fn req(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    auth: Option<&str>,
) -> (u16, Value) {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}{path}");
    let mut request = client
        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url)
        .header("Content-Type", "application/json");
    if let Some(auth) = auth {
        request = request.header("Authorization", auth);
    }
    if let Some(body) = body {
        request = request.body(body.to_string());
    }
    let resp = request.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let data = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, data)
}

fn bearer() -> String {
    format!("Bearer {TOKEN}")
}

async fn authed(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, Value) {
    req(addr, method, path, body, Some(&bearer())).await
}

// --- connect / disconnect / is_connected ----------------------------------------

#[tokio::test]
async fn is_connected_false_before_connect() {
    let channel = make(main_host(), &MemoryAuditSink::default());
    assert!(!channel.is_connected());
    assert!(channel.local_addr().await.is_none());
}

#[tokio::test]
async fn is_connected_true_after_connect() {
    let (channel, addr, _) = connected(main_host()).await;
    assert!(channel.is_connected());
    assert!(addr.ip().is_loopback(), "must bind loopback only: {addr}");
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn is_connected_false_after_disconnect() {
    let (channel, addr, _) = connected(main_host()).await;
    channel.disconnect().await.unwrap();
    assert!(!channel.is_connected());
    // The port is released.
    assert!(
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{addr}/api/messages"))
            .send()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn disconnect_is_a_noop_when_not_connected() {
    let channel = make(main_host(), &MemoryAuditSink::default());
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn connect_twice_is_idempotent() {
    let (channel, addr, _) = connected(main_host()).await;
    channel.connect().await.unwrap();
    assert_eq!(channel.local_addr().await, Some(addr));
    channel.disconnect().await.unwrap();
}

// --- owns_jid ---------------------------------------------------------------------

#[test]
fn owns_only_emacs_default() {
    let channel = make(main_host(), &MemoryAuditSink::default());
    assert!(channel.owns_jid("emacs:default"));
    for jid in ["tg:123456", "main:jid", "", "emacs:other", "123456@g.us"] {
        assert!(!channel.owns_jid(jid), "{jid}");
    }
    assert_eq!(channel.name(), "emacs");
    assert_eq!(channel.channel_type(), ChannelType::Markdown);
}

// --- group auto-registration ----------------------------------------------------------

#[tokio::test]
async fn registers_group_when_absent() {
    let host = main_host();
    let (channel, _, _) = connected(host.clone()).await;
    let regs = host.registrations();
    assert_eq!(regs.len(), 1);
    let (jid, g, persist) = &regs[0];
    assert_eq!(jid, "emacs:default");
    assert!(*persist, "emacs lane is persisted like setRegisteredGroup");
    assert_eq!(g.name, "emacs");
    assert_eq!(g.folder, "emacs");
    assert_eq!(g.requires_trigger, Some(false));
    assert!(!g.is_main);
    // The live map sees it immediately.
    assert!(host.registered_groups().contains_key("emacs:default"));
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn skips_registration_when_already_present() {
    let host = Arc::new(RecordingHost::with_groups(&[(
        "emacs:default",
        group("emacs", "emacs", ""),
    )]));
    let (channel, _, _) = connected(host.clone()).await;
    assert!(host.registrations().is_empty());
    channel.disconnect().await.unwrap();
}

// --- POST /api/message -------------------------------------------------------------

#[tokio::test]
async fn post_returns_message_id_and_numeric_timestamp() {
    let (channel, addr, _) = connected(main_host()).await;
    let (status, data) = authed(addr, "POST", "/api/message", Some(r#"{"text":"hello"}"#)).await;
    assert_eq!(status, 200);
    assert!(data["messageId"].as_str().unwrap().starts_with("emacs-"));
    assert!(data["timestamp"].is_i64());
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn post_delivers_message_with_correct_structure() {
    let host = main_host();
    let (channel, addr, _) = connected(host.clone()).await;
    let (_, data) = authed(addr, "POST", "/api/message", Some(r#"{"text":"ping"}"#)).await;
    let msgs = host.messages();
    assert_eq!(msgs.len(), 1);
    let (jid, msg) = &msgs[0];
    assert_eq!(jid, "emacs:default");
    assert_eq!(msg.chat_jid, "emacs:default");
    assert_eq!(msg.content, "ping");
    assert_eq!(msg.sender, "emacs");
    assert_eq!(msg.sender_name, "Emacs");
    assert!(!msg.is_from_me);
    assert_eq!(msg.id, data["messageId"].as_str().unwrap());
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn post_reports_metadata_before_message() {
    let host = main_host();
    let (channel, addr, _) = connected(host.clone()).await;
    authed(addr, "POST", "/api/message", Some(r#"{"text":"hi"}"#)).await;
    let order: Vec<&str> = host
        .events()
        .iter()
        .filter_map(|e| match e {
            crate::test_support::HostEvent::Metadata(m) => {
                assert_eq!(m.chat_jid, "emacs:default");
                assert_eq!(m.name.as_deref(), Some("Emacs"));
                assert_eq!(m.channel.as_deref(), Some("emacs"));
                assert_eq!(m.is_group, Some(false));
                Some("meta")
            }
            crate::test_support::HostEvent::Message(..) => Some("msg"),
            _ => None,
        })
        .collect();
    assert_eq!(order, vec!["meta", "msg"]);
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn post_rejects_empty_whitespace_invalid_and_non_string_text() {
    let host = main_host();
    let (channel, addr, _) = connected(host.clone()).await;
    for body in [
        r#"{"text":""}"#,
        r#"{"text":"   "}"#,
        "not-json",
        "null",
        r#"{"text":42}"#,
        "{}",
    ] {
        let (status, _) = authed(addr, "POST", "/api/message", Some(body)).await;
        assert_eq!(status, 400, "{body}");
    }
    assert!(host.messages().is_empty());
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn post_rejects_oversized_bodies() {
    let host = main_host();
    let (channel, addr, _) = connected(host.clone()).await;
    let big = json!({ "text": "a".repeat(MAX_BODY_BYTES + 1) }).to_string();
    let (status, _) = authed(addr, "POST", "/api/message", Some(&big)).await;
    assert_eq!(status, 413);
    assert!(host.messages().is_empty());
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn unknown_paths_and_methods_are_404() {
    let (channel, addr, _) = connected(main_host()).await;
    let (status, data) = authed(addr, "POST", "/api/unknown", Some(r#"{"text":"hi"}"#)).await;
    assert_eq!(status, 404);
    assert_eq!(data["error"], "Not found");
    let (status, _) = authed(addr, "GET", "/api/message", None).await;
    assert_eq!(status, 404);
    let (status, _) = authed(addr, "DELETE", "/api/messages", None).await;
    assert_eq!(status, 404);
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn rapid_posts_get_unique_message_ids() {
    let (channel, addr, _) = connected(main_host()).await;
    let mut ids = std::collections::HashSet::new();
    for i in 0..20 {
        let body = json!({ "text": format!("m{i}") }).to_string();
        let (_, data) = authed(addr, "POST", "/api/message", Some(&body)).await;
        assert!(ids.insert(data["messageId"].as_str().unwrap().to_string()));
    }
    channel.disconnect().await.unwrap();
}

// --- GET /api/messages ---------------------------------------------------------------

#[tokio::test]
async fn poll_returns_empty_array_initially() {
    let (channel, addr, _) = connected(main_host()).await;
    let (status, data) = authed(addr, "GET", "/api/messages?since=0", None).await;
    assert_eq!(status, 200);
    assert_eq!(data, json!({ "messages": [] }));
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn poll_returns_messages_added_via_send_message() {
    let (channel, addr, _) = connected(main_host()).await;
    channel.send_message(EMACS_JID, "hello back").await.unwrap();
    let (_, data) = authed(addr, "GET", "/api/messages?since=0", None).await;
    let msgs = data["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["text"], "hello back");
    // `since` is optional.
    let (_, data) = authed(addr, "GET", "/api/messages", None).await;
    assert_eq!(data["messages"].as_array().unwrap().len(), 1);
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn poll_filters_messages_at_or_before_since() {
    let (channel, addr, _) = connected(main_host()).await;
    channel.send_message(EMACS_JID, "old").await.unwrap();
    let (_, data) = authed(addr, "GET", "/api/messages?since=0", None).await;
    let since = data["messages"][0]["timestamp"].as_i64().unwrap();
    // Sent within the same millisecond, still strictly newer.
    channel.send_message(EMACS_JID, "new").await.unwrap();
    let (_, data) = authed(addr, "GET", &format!("/api/messages?since={since}"), None).await;
    let texts: Vec<&str> = data["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts, vec!["new"]);
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn poll_rejects_invalid_since() {
    let (channel, addr, _) = connected(main_host()).await;
    let (status, _) = authed(addr, "GET", "/api/messages?since=abc", None).await;
    assert_eq!(status, 400);
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn buffer_is_capped_at_200_dropping_the_oldest() {
    let (channel, addr, _) = connected(main_host()).await;
    for i in 0..201 {
        channel
            .send_message(EMACS_JID, &format!("msg-{i}"))
            .await
            .unwrap();
    }
    let (_, data) = authed(addr, "GET", "/api/messages?since=0", None).await;
    let texts: Vec<&str> = data["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts.len(), 200);
    assert!(!texts.contains(&"msg-0"));
    assert!(texts.contains(&"msg-1"));
    assert!(texts.contains(&"msg-200"));
    channel.disconnect().await.unwrap();
}

// --- send_message ---------------------------------------------------------------------

#[tokio::test]
async fn send_message_pushes_exact_text_with_epoch_ms_timestamp() {
    let (channel, addr, _) = connected(main_host()).await;
    let before = chrono::Utc::now().timestamp_millis();
    channel
        .send_message(EMACS_JID, "response text")
        .await
        .unwrap();
    let after = chrono::Utc::now().timestamp_millis();
    let (_, data) = authed(addr, "GET", "/api/messages?since=0", None).await;
    assert_eq!(data["messages"][0]["text"], "response text");
    let ts = data["messages"][0]["timestamp"].as_i64().unwrap();
    assert!(
        ts >= before && ts <= after + 1,
        "{before} <= {ts} <= {after}"
    );
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn reply_timestamps_strictly_increase() {
    let channel = make(main_host(), &MemoryAuditSink::default());
    for i in 0..50 {
        channel
            .send_message(EMACS_JID, &i.to_string())
            .await
            .unwrap();
    }
    let buffer = channel.shared.buffer.lock().unwrap();
    let stamps: Vec<i64> = buffer.iter().map(|m| m.timestamp).collect();
    assert!(stamps.windows(2).all(|w| w[1] > w[0]));
}

// --- authentication -------------------------------------------------------------------

#[tokio::test]
async fn rejects_requests_without_or_with_wrong_token() {
    let host = main_host();
    let (channel, addr, audit) = connected(host.clone()).await;
    let body = Some(r#"{"text":"hi"}"#);
    assert_eq!(req(addr, "POST", "/api/message", body, None).await.0, 401);
    assert_eq!(
        req(addr, "POST", "/api/message", body, Some("Bearer wrong"))
            .await
            .0,
        401
    );
    assert_eq!(
        req(addr, "POST", "/api/message", body, Some(TOKEN)).await.0,
        401,
        "token without scheme"
    );
    let prefixed = format!("Bearer {TOKEN}x");
    assert_eq!(
        req(addr, "POST", "/api/message", body, Some(&prefixed))
            .await
            .0,
        401
    );
    assert_eq!(
        req(addr, "GET", "/api/messages?since=0", None, None)
            .await
            .0,
        401
    );
    // Auth runs before routing: unknown paths do not reveal a 404.
    let (status, data) = req(addr, "GET", "/nope", None, None).await;
    assert_eq!(status, 401);
    assert_eq!(data["error"], "Unauthorized");
    assert!(host.messages().is_empty());

    let events = audit.snapshot();
    assert_eq!(events.len(), 6);
    assert!(events.iter().all(|e| e.kind == "http.auth.failed"
        && e.outcome == "denied"
        && e.actor == "channel:emacs"));
    assert_eq!(events[0].target.as_deref(), Some("/api/message"));
    assert!(!events[1].details.to_string().contains("wrong"));
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn accepts_correct_bearer_token() {
    let (channel, addr, audit) = connected(main_host()).await;
    let (status, _) = authed(addr, "POST", "/api/message", Some(r#"{"text":"hi"}"#)).await;
    assert_eq!(status, 200);
    let (status, _) = authed(addr, "GET", "/api/messages?since=0", None).await;
    assert_eq!(status, 200);
    let lower = format!("bearer {TOKEN}");
    let (status, _) = req(addr, "GET", "/api/messages", None, Some(&lower)).await;
    assert_eq!(status, 200);
    assert!(audit.snapshot().is_empty());
    channel.disconnect().await.unwrap();
}

#[test]
fn empty_token_is_refused_at_construction() {
    for token in ["", "   "] {
        let result = EmacsBridgeChannel::new(
            EmacsConfig {
                port: 0,
                auth_token: token.to_string(),
                groups_dir: None,
            },
            main_host(),
            Arc::new(MemoryAuditSink::default()),
        );
        assert!(result.is_err());
    }
}

#[test]
fn config_from_env_requires_token() {
    let clean = [EMACS_AUTH_TOKEN_ENV, EMACS_CHANNEL_PORT_ENV]
        .iter()
        .all(|k| std::env::var(k).map(|v| v.is_empty()).unwrap_or(true));
    if !clean {
        return;
    }
    assert!(EmacsConfig::from_env(&EnvFile::from_str_content("EMACS_CHANNEL_PORT=1\n")).is_none());
    let cfg = EmacsConfig::from_env(&EnvFile::from_str_content("EMACS_AUTH_TOKEN=abc\n")).unwrap();
    assert_eq!(cfg.port, DEFAULT_EMACS_PORT);
    assert_eq!(cfg.auth_token, "abc");
    assert!(
        cfg.groups_dir
            .as_ref()
            .is_some_and(|d| d.ends_with("groups"))
    );
    let cfg = EmacsConfig::from_env(&EnvFile::from_str_content(
        "EMACS_AUTH_TOKEN=abc\nEMACS_CHANNEL_PORT=8767\n",
    ))
    .unwrap();
    assert_eq!(cfg.port, 8767);
    assert!(
        EmacsConfig::from_env(&EnvFile::from_str_content(
            "EMACS_AUTH_TOKEN=abc\nEMACS_CHANNEL_PORT=99999\n"
        ))
        .is_none()
    );
    assert!(!format!("{cfg:?}").contains("abc"));
}

/// Uses the real `talon_security::auth::constant_time_eq`; panics
/// (todo!()) until A07's implementation lands.
#[tokio::test]
async fn auth_with_real_constant_time_eq() {
    let audit = MemoryAuditSink::default();
    let channel = EmacsBridgeChannel::new(
        EmacsConfig {
            port: 0,
            auth_token: TOKEN.to_string(),
            groups_dir: None,
        },
        main_host(),
        Arc::new(audit),
    )
    .unwrap();
    channel.connect().await.unwrap();
    let addr = channel.local_addr().await.unwrap();
    assert_eq!(authed(addr, "GET", "/api/messages", None).await.0, 200);
    assert_eq!(
        req(addr, "GET", "/api/messages", None, Some("Bearer nope"))
            .await
            .0,
        401
    );
    channel.disconnect().await.unwrap();
}

// --- filesystem bootstrap ---------------------------------------------------------------

fn ops_main_host() -> Arc<RecordingHost> {
    Arc::new(RecordingHost::with_groups(&[("main:jid", {
        let mut g = group("Ops", "ops-main", "");
        g.is_main = true;
        g
    })]))
}

/// MYTH-09: the Emacs lane gets its own real folder, never main's.
#[tokio::test]
async fn creates_own_emacs_folder_and_writes_claude_md() {
    let dir = tempfile::tempdir().unwrap();
    // Fresh install: not even `groups/` exists yet.
    let groups = dir.path().join("groups");
    let host = ops_main_host();
    let channel = make_with_dir(
        host.clone(),
        &MemoryAuditSink::default(),
        Some(groups.clone()),
    );
    channel.connect().await.unwrap();

    let meta = std::fs::symlink_metadata(groups.join("emacs")).unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());
    let md = std::fs::read_to_string(groups.join("emacs").join("CLAUDE.md")).unwrap();
    assert_eq!(md, CLAUDE_MD);
    assert!(md.contains("Always format responses in standard markdown"));
    // Main's folder is never created or written by the Emacs lane.
    assert!(!groups.join("ops-main").exists());
    assert!(!groups.join("main").exists());
    let regs = host.registrations();
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].1.folder, EMACS_GROUP_FOLDER);
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn keeps_existing_claude_md() {
    let dir = tempfile::tempdir().unwrap();
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(groups.join("emacs")).unwrap();
    std::fs::write(groups.join("emacs").join("CLAUDE.md"), "keep me").unwrap();
    let channel = make_with_dir(
        main_host(),
        &MemoryAuditSink::default(),
        Some(groups.clone()),
    );
    channel.connect().await.unwrap();
    assert_eq!(
        std::fs::read_to_string(groups.join("emacs").join("CLAUDE.md")).unwrap(),
        "keep me"
    );
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn leaves_existing_emacs_directory_alone() {
    let dir = tempfile::tempdir().unwrap();
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(groups.join("emacs")).unwrap();
    std::fs::write(groups.join("emacs").join("notes.md"), "mine").unwrap();
    let channel = make_with_dir(
        main_host(),
        &MemoryAuditSink::default(),
        Some(groups.clone()),
    );
    channel.connect().await.unwrap();
    let meta = std::fs::symlink_metadata(groups.join("emacs")).unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());
    assert!(groups.join("emacs").join("CLAUDE.md").exists());
    assert_eq!(
        std::fs::read_to_string(groups.join("emacs").join("notes.md")).unwrap(),
        "mine"
    );
    assert!(!groups.join("main").exists());
    channel.disconnect().await.unwrap();
}

/// MYTH-09: a legacy `groups/emacs -> groups/<main>` link is neither
/// followed nor deleted; the bridge refuses to start and says how to fix it.
#[cfg(unix)]
#[tokio::test]
async fn refuses_to_start_on_legacy_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(groups.join("ops-main")).unwrap();
    std::fs::write(groups.join("ops-main").join("CLAUDE.md"), "main prompt").unwrap();
    std::os::unix::fs::symlink(groups.join("ops-main"), groups.join("emacs")).unwrap();
    let host = ops_main_host();
    let channel = make_with_dir(
        host.clone(),
        &MemoryAuditSink::default(),
        Some(groups.clone()),
    );

    let err = channel.connect().await.unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, Error::Config(_)), "{err:?}");
    assert!(msg.contains("symlink"), "{msg}");
    assert!(msg.contains("rm "), "{msg}");
    assert!(
        msg.contains(&groups.join("emacs").display().to_string()),
        "{msg}"
    );

    // Link untouched, main untouched, nothing registered, nothing listening.
    let meta = std::fs::symlink_metadata(groups.join("emacs")).unwrap();
    assert!(meta.file_type().is_symlink());
    assert_eq!(
        std::fs::read_link(groups.join("emacs")).unwrap(),
        groups.join("ops-main")
    );
    assert_eq!(
        std::fs::read_to_string(groups.join("ops-main").join("CLAUDE.md")).unwrap(),
        "main prompt"
    );
    assert_eq!(
        std::fs::read_dir(groups.join("ops-main")).unwrap().count(),
        1
    );
    assert!(host.registrations().is_empty());
    assert!(!channel.is_connected());
    assert!(channel.local_addr().await.is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn refuses_to_start_on_dangling_legacy_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    let target = dir.path().join("gone");
    std::os::unix::fs::symlink(&target, groups.join("emacs")).unwrap();
    let channel = make_with_dir(
        main_host(),
        &MemoryAuditSink::default(),
        Some(groups.clone()),
    );
    assert!(channel.connect().await.is_err());
    assert!(!target.exists(), "the link target must not be created");
    assert!(
        std::fs::symlink_metadata(groups.join("emacs"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[tokio::test]
async fn refuses_to_start_when_emacs_entry_is_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    std::fs::write(groups.join("emacs"), "not a dir").unwrap();
    let host = main_host();
    let channel = make_with_dir(
        host.clone(),
        &MemoryAuditSink::default(),
        Some(groups.clone()),
    );
    let err = channel.connect().await.unwrap_err();
    assert!(err.to_string().contains("not a directory"), "{err}");
    assert_eq!(
        std::fs::read_to_string(groups.join("emacs")).unwrap(),
        "not a dir"
    );
    assert!(host.registrations().is_empty());
    assert!(!channel.is_connected());
}

/// MYTH-10: an agent-planted dangling `CLAUDE.md` symlink must not make the
/// bootstrap create an arbitrary host file.
#[cfg(unix)]
#[tokio::test]
async fn never_writes_claude_md_through_a_dangling_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(groups.join("emacs")).unwrap();
    let outside = dir.path().join("outside").join("planted.txt");
    std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
    let link = groups.join("emacs").join("CLAUDE.md");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let channel = make_with_dir(
        main_host(),
        &MemoryAuditSink::default(),
        Some(groups.clone()),
    );
    channel.connect().await.unwrap();
    assert!(!outside.exists(), "write followed the planted symlink");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read_link(&link).unwrap(), outside);
    channel.disconnect().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn never_writes_claude_md_through_a_symlink_to_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(groups.join("emacs")).unwrap();
    std::fs::create_dir_all(groups.join("main")).unwrap();
    let main_md = groups.join("main").join("CLAUDE.md");
    std::fs::write(&main_md, "main prompt").unwrap();
    std::os::unix::fs::symlink(&main_md, groups.join("emacs").join("CLAUDE.md")).unwrap();
    let channel = make_with_dir(
        main_host(),
        &MemoryAuditSink::default(),
        Some(groups.clone()),
    );
    channel.connect().await.unwrap();
    assert_eq!(std::fs::read_to_string(&main_md).unwrap(), "main prompt");
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn main_group_folder_is_never_used() {
    let dir = tempfile::tempdir().unwrap();
    let groups = dir.path().join("groups");
    let host = Arc::new(RecordingHost::with_groups(&[("main:jid", {
        let mut g = group("evil", "../outside", "");
        g.is_main = true;
        g
    })]));
    let channel = make_with_dir(host, &MemoryAuditSink::default(), Some(groups.clone()));
    channel.connect().await.unwrap();
    let meta = std::fs::symlink_metadata(groups.join("emacs")).unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());
    assert!(!dir.path().join("outside").exists());
    channel.disconnect().await.unwrap();
}

// --- connection limits (MYTH-06) -----------------------------------------------------

#[test]
fn server_limits_cap_connections() {
    let limits = server_limits();
    assert_eq!(limits.max_connections, 32);
    assert_eq!(limits.max_connections_per_ip, 16);
    let defaults = talon_net::ServerLimits::default();
    assert_eq!(limits.header_read_timeout, defaults.header_read_timeout);
    assert!(limits.header_read_timeout <= Duration::from_secs(30));
}

/// Idle connections that never send a request (slowloris) cannot pile up:
/// beyond the per-IP cap new connections are closed before any parsing.
#[tokio::test]
async fn excess_idle_connections_are_closed() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    let (channel, addr, _) = connected(main_host()).await;
    let mut idle = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_IP {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut excess = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), excess.read(&mut buf))
        .await
        .expect("excess connection must be closed promptly")
        .unwrap_or(0);
    assert_eq!(n, 0);

    // Freeing the slots makes the bridge usable again.
    drop(idle);
    drop(excess);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut status = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Ok(resp) = client
            .get(format!("http://{addr}/api/messages"))
            .header("Authorization", bearer())
            .send()
            .await
        {
            status = Some(resp.status().as_u16());
            break;
        }
    }
    assert_eq!(status, Some(200));
    drop(client);
    channel.disconnect().await.unwrap();
    assert!(!channel.is_connected());
}
