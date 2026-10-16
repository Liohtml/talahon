//! Telegram channel tests, including Bot-API-level tests against a
//! `wiremock` Telegram.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::api::{Message, User};
use super::*;
use crate::test_support::{RecordingHost, group};

const TOKEN: &str = "123456:test-token";

fn api_path(method_name: &str) -> String {
    format!("/bot{TOKEN}/{method_name}")
}

fn ok(result: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({ "ok": true, "result": result }))
}

fn default_host() -> Arc<RecordingHost> {
    Arc::new(RecordingHost::with_groups(&[(
        "tg:100200300",
        group("Test Group", "test-group", "@Talon"),
    )]))
}

fn config(server: &MockServer) -> TelegramConfig {
    let mut cfg = TelegramConfig::new(TOKEN, "Talon");
    cfg.api_base_url = server.uri();
    cfg.poll_timeout = Duration::from_secs(1);
    cfg.error_backoff_base = Duration::from_millis(5);
    cfg.error_backoff_max = Duration::from_millis(20);
    cfg
}

/// Channel marked connected with a known bot identity, without polling.
fn ready_channel(server: &MockServer, host: Arc<RecordingHost>) -> TelegramChannel {
    let channel = TelegramChannel::new(config(server), host).unwrap();
    channel.inner.set_me(&User {
        id: 12345,
        first_name: Some("Talon".into()),
        username: Some("talonai_bot".into()),
    });
    channel.inner.connected.store(true, Ordering::SeqCst);
    channel
}

async fn mount_send_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(api_path("sendMessage")))
        .respond_with(ok(json!({ "message_id": 1 })))
        .mount(server)
        .await;
}

async fn mount_startup(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(api_path("getMe")))
        .respond_with(ok(json!({
            "id": 12345, "is_bot": true, "first_name": "Talon", "username": "talonai_bot"
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(api_path("deleteWebhook")))
        .respond_with(ok(json!(true)))
        .mount(server)
        .await;
}

async fn mount_idle_updates(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(api_path("getUpdates")))
        .respond_with(ok(json!([])).set_delay(Duration::from_millis(200)))
        .mount(server)
        .await;
}

async fn requests_to(server: &MockServer, method_name: &str) -> Vec<Value> {
    let wanted = api_path(method_name);
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == wanted)
        .map(|r| serde_json::from_slice(&r.body).unwrap_or(Value::Null))
        .collect()
}

async fn wait_requests(server: &MockServer, method_name: &str, n: usize) -> Vec<Value> {
    for _ in 0..300 {
        let reqs = requests_to(server, method_name).await;
        if reqs.len() >= n {
            return reqs;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    requests_to(server, method_name).await
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn text_json(text: &str) -> Value {
    json!({
        "message_id": 1,
        "date": now_secs(),
        "chat": { "id": 100200300, "type": "group", "title": "Test Group" },
        "from": { "id": 99001, "is_bot": false, "first_name": "Alice", "username": "alice_user" },
        "text": text,
        "entities": []
    })
}

fn media_json(extra: Value) -> Value {
    let mut v = json!({
        "message_id": 1,
        "date": now_secs(),
        "chat": { "id": 100200300, "type": "group", "title": "Test Group" },
        "from": { "id": 99001, "is_bot": false, "first_name": "Alice", "username": "alice_user" }
    });
    if let (Some(obj), Some(extra)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in extra {
            obj.insert(k.clone(), val.clone());
        }
    }
    v
}

async fn deliver(channel: &TelegramChannel, v: Value) {
    let msg: Message = serde_json::from_value(v).unwrap();
    channel.inner.handle_message(msg).await;
}

fn only_message(host: &RecordingHost) -> NewMessage {
    let msgs = host.messages();
    assert_eq!(msgs.len(), 1, "expected exactly one message: {msgs:?}");
    assert_eq!(msgs[0].0, msgs[0].1.chat_jid);
    msgs[0].1.clone()
}

// --- Connection lifecycle -----------------------------------------------------

#[tokio::test]
async fn resolves_connect_when_bot_starts() {
    let server = MockServer::start().await;
    mount_startup(&server).await;
    mount_idle_updates(&server).await;
    let channel = TelegramChannel::new(config(&server), default_host()).unwrap();
    channel.connect().await.unwrap();
    assert!(channel.is_connected());
    // deleteWebhook is called before polling (getUpdates would 409 otherwise).
    assert_eq!(requests_to(&server, "deleteWebhook").await.len(), 1);
    assert!(!wait_requests(&server, "getUpdates", 1).await.is_empty());
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn disconnects_cleanly() {
    let server = MockServer::start().await;
    mount_startup(&server).await;
    mount_idle_updates(&server).await;
    let channel = TelegramChannel::new(config(&server), default_host()).unwrap();
    channel.connect().await.unwrap();
    assert!(channel.is_connected());
    channel.disconnect().await.unwrap();
    assert!(!channel.is_connected());
    // Polling stopped: no further getUpdates after disconnect settles.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let before = requests_to(&server, "getUpdates").await.len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(requests_to(&server, "getUpdates").await.len(), before);
    // Idempotent.
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn is_connected_false_before_connect() {
    let server = MockServer::start().await;
    let channel = TelegramChannel::new(config(&server), default_host()).unwrap();
    assert!(!channel.is_connected());
}

#[tokio::test]
async fn connect_fails_on_rejected_token_without_leaking_it() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(api_path("getMe")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "ok": false, "error_code": 401, "description": "Unauthorized"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let channel = TelegramChannel::new(config(&server), default_host()).unwrap();
    let err = channel.connect().await.unwrap_err().to_string();
    assert!(err.contains("Unauthorized"), "{err}");
    assert!(!err.contains("test-token"), "token leaked: {err}");
    assert!(!channel.is_connected());
}

#[tokio::test]
async fn rejects_malformed_tokens() {
    let host: Arc<dyn ChannelHost> = default_host();
    for bad in ["", "123/../x", "123:abc?x=1", "tok en", "123:abc#frag"] {
        let err = TelegramChannel::new(TelegramConfig::new(bad, "Talon"), Arc::clone(&host))
            .unwrap_err()
            .to_string();
        if !bad.is_empty() {
            assert!(!err.contains(bad), "token echoed: {err}");
        }
    }
}

#[test]
fn config_debug_redacts_token() {
    let dbg = format!("{:?}", TelegramConfig::new("123:SECRETSECRET", "Talon"));
    assert!(!dbg.contains("SECRETSECRET"), "{dbg}");
}

#[test]
fn config_from_env() {
    if std::env::var("TELEGRAM_BOT_TOKEN").is_ok_and(|v| !v.is_empty()) {
        return;
    }
    let env = EnvFile::from_str_content("TELEGRAM_BOT_TOKEN=1:abc\n");
    let cfg = TelegramConfig::from_env(&env).unwrap();
    assert_eq!(cfg.bot_token, "1:abc");
    assert_eq!(cfg.api_base_url, DEFAULT_TELEGRAM_API_BASE);
    assert!(
        cfg.state_path
            .as_ref()
            .is_some_and(|p| p.ends_with("data/telegram/state.json"))
    );
    assert!(TelegramConfig::from_env(&EnvFile::from_str_content("")).is_none());
}

// --- Polling + offset persistence ---------------------------------------------

#[tokio::test]
async fn polls_delivers_updates_and_persists_offset() {
    let server = MockServer::start().await;
    mount_startup(&server).await;
    let mut update = text_json("Hello from polling");
    update["message_id"] = json!(77);
    Mock::given(method("POST"))
        .and(path(api_path("getUpdates")))
        .respond_with(ok(json!([{ "update_id": 7, "message": update }])))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_idle_updates(&server).await;

    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("telegram").join("state.json");
    let host = default_host();
    let mut cfg = config(&server);
    cfg.state_path = Some(state.clone());
    let channel = TelegramChannel::new(cfg, host.clone()).unwrap();
    channel.connect().await.unwrap();

    let msgs = host.wait_for_messages(1).await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].1.id, "77");
    assert_eq!(msgs[0].1.content, "Hello from polling");

    let polls = wait_requests(&server, "getUpdates", 2).await;
    assert_eq!(polls[0]["offset"], 0);
    assert_eq!(polls[0]["allowed_updates"], json!(["message"]));
    assert_eq!(polls[1]["offset"], 8);
    channel.disconnect().await.unwrap();

    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(saved["offset"], 8);
}

#[tokio::test]
async fn resumes_from_persisted_offset() {
    let server = MockServer::start().await;
    mount_startup(&server).await;
    mount_idle_updates(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    std::fs::write(&state, r#"{"offset":42}"#).unwrap();
    let mut cfg = config(&server);
    cfg.state_path = Some(state);
    let channel = TelegramChannel::new(cfg, default_host()).unwrap();
    channel.connect().await.unwrap();
    let polls = wait_requests(&server, "getUpdates", 1).await;
    assert_eq!(polls[0]["offset"], 42);
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn corrupt_state_file_starts_from_zero() {
    let server = MockServer::start().await;
    mount_startup(&server).await;
    mount_idle_updates(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    std::fs::write(&state, "{not json").unwrap();
    let mut cfg = config(&server);
    cfg.state_path = Some(state);
    let channel = TelegramChannel::new(cfg, default_host()).unwrap();
    channel.connect().await.unwrap();
    let polls = wait_requests(&server, "getUpdates", 1).await;
    assert_eq!(polls[0]["offset"], 0);
    channel.disconnect().await.unwrap();
}

#[tokio::test]
async fn undecodable_update_is_skipped_but_offset_advances() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let good = json!({ "update_id": 11, "message": text_json("ok") });
    let bad = json!({ "update_id": 10, "message": { "message_id": "NaN", "chat": 5 } });
    let no_id = json!({ "message": text_json("no id") });
    let next = channel
        .inner
        .process_updates(vec![bad, good, no_id], 3)
        .await;
    assert_eq!(next, 12);
    assert_eq!(only_message(&host).content, "ok");
    // Updates other than `message` (e.g. edits) are acknowledged and ignored.
    let edit = json!({ "update_id": 20, "edited_message": text_json("edited") });
    assert_eq!(channel.inner.process_updates(vec![edit], next).await, 21);
    assert_eq!(host.messages().len(), 1);
}

#[tokio::test]
async fn poll_errors_back_off_and_recover() {
    let server = MockServer::start().await;
    mount_startup(&server).await;
    Mock::given(method("POST"))
        .and(path(api_path("getUpdates")))
        .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway"))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(api_path("getUpdates")))
        .respond_with(ok(
            json!([{ "update_id": 1, "message": text_json("after errors") }]),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_idle_updates(&server).await;
    let host = default_host();
    let channel = TelegramChannel::new(config(&server), host.clone()).unwrap();
    channel.connect().await.unwrap();
    let msgs = host.wait_for_messages(1).await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].1.content, "after errors");
    channel.disconnect().await.unwrap();
}

// --- Text message handling ------------------------------------------------------

#[tokio::test]
async fn delivers_message_for_registered_group() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    deliver(&channel, text_json("Hello everyone")).await;

    let meta = host.metadata();
    assert_eq!(meta.len(), 1);
    assert_eq!(meta[0].chat_jid, "tg:100200300");
    assert_eq!(meta[0].name.as_deref(), Some("Test Group"));
    assert_eq!(meta[0].channel.as_deref(), Some("telegram"));
    assert_eq!(meta[0].is_group, Some(true));

    let msg = only_message(&host);
    assert_eq!(msg.id, "1");
    assert_eq!(msg.chat_jid, "tg:100200300");
    assert_eq!(msg.sender, "99001");
    assert_eq!(msg.sender_name, "Alice");
    assert_eq!(msg.content, "Hello everyone");
    assert!(!msg.is_from_me);
    assert!(!msg.is_bot_message);
}

#[tokio::test]
async fn only_emits_metadata_for_unregistered_chats() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Unknown chat");
    v["chat"]["id"] = json!(999999);
    deliver(&channel, v).await;

    let meta = host.metadata();
    assert_eq!(meta.len(), 1);
    assert_eq!(meta[0].chat_jid, "tg:999999");
    assert_eq!(meta[0].name.as_deref(), Some("Test Group"));
    assert_eq!(meta[0].is_group, Some(true));
    assert!(host.messages().is_empty());
}

#[tokio::test]
async fn skips_bot_commands_but_passes_other_slash_messages() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());

    deliver(&channel, text_json("/chatid")).await;
    assert!(host.messages().is_empty());
    assert!(host.metadata().is_empty());

    deliver(&channel, text_json("/ping")).await;
    deliver(&channel, text_json("/PING@talonai_bot")).await;
    deliver(&channel, text_json("/chatid@some_other_bot")).await;
    assert!(host.messages().is_empty());

    deliver(&channel, text_json("/remote-control")).await;
    let msg = only_message(&host);
    assert_eq!(msg.content, "/remote-control");

    // /chatid, /ping, /PING@talonai_bot answered; the other bot's command not.
    assert_eq!(requests_to(&server, "sendMessage").await.len(), 3);
}

#[tokio::test]
async fn extracts_sender_name_from_first_name() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Hi");
    v["from"]["first_name"] = json!("Bob");
    deliver(&channel, v).await;
    assert_eq!(only_message(&host).sender_name, "Bob");
}

#[tokio::test]
async fn falls_back_to_username_when_first_name_missing() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Hi");
    v["from"].as_object_mut().unwrap().remove("first_name");
    deliver(&channel, v).await;
    assert_eq!(only_message(&host).sender_name, "alice_user");
}

#[tokio::test]
async fn falls_back_to_user_id_when_name_and_username_missing() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Hi");
    v["from"] = json!({ "id": 42, "is_bot": false });
    deliver(&channel, v).await;
    let msg = only_message(&host);
    assert_eq!(msg.sender_name, "42");
    assert_eq!(msg.sender, "42");
}

#[tokio::test]
async fn missing_sender_is_unknown() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Hi");
    v.as_object_mut().unwrap().remove("from");
    deliver(&channel, v).await;
    let msg = only_message(&host);
    assert_eq!(msg.sender_name, "Unknown");
    assert_eq!(msg.sender, "");
}

#[tokio::test]
async fn uses_sender_name_as_chat_name_for_private_chats() {
    let server = MockServer::start().await;
    let host = Arc::new(RecordingHost::with_groups(&[(
        "tg:100200300",
        group("Private", "private", "@Talon"),
    )]));
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Hello");
    v["chat"] = json!({ "id": 100200300, "type": "private" });
    deliver(&channel, v).await;
    let meta = host.metadata();
    assert_eq!(meta[0].name.as_deref(), Some("Alice"));
    assert_eq!(meta[0].is_group, Some(false));
}

#[tokio::test]
async fn uses_chat_title_as_name_for_group_chats() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Hello");
    v["chat"] = json!({ "id": 100200300, "type": "supergroup", "title": "Project Team" });
    deliver(&channel, v).await;
    let meta = host.metadata();
    assert_eq!(meta[0].name.as_deref(), Some("Project Team"));
    assert_eq!(meta[0].is_group, Some(true));
}

#[tokio::test]
async fn untitled_group_falls_back_to_jid() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Hello");
    v["chat"] = json!({ "id": 100200300, "type": "group" });
    deliver(&channel, v).await;
    assert_eq!(host.metadata()[0].name.as_deref(), Some("tg:100200300"));
}

#[tokio::test]
async fn converts_message_date_to_iso_timestamp() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("Hello");
    v["date"] = json!(1_704_067_200);
    deliver(&channel, v).await;
    assert_eq!(only_message(&host).timestamp, "2024-01-01T00:00:00.000Z");
}

#[tokio::test]
async fn carries_reply_context_and_topic_thread() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("what about this?");
    v["reply_to_message"] = json!({
        "message_id": 5, "date": 1, "chat": { "id": 100200300, "type": "supergroup" },
        "from": { "id": 7, "is_bot": false, "first_name": "Carol" },
        "text": "the original"
    });
    v["message_thread_id"] = json!(3);
    v["is_topic_message"] = json!(true);
    deliver(&channel, v).await;
    let msg = only_message(&host);
    assert_eq!(msg.reply_to_message_id.as_deref(), Some("5"));
    assert_eq!(
        msg.reply_to_message_content.as_deref(),
        Some("the original")
    );
    assert_eq!(msg.reply_to_sender_name.as_deref(), Some("Carol"));
    assert_eq!(msg.thread_id.as_deref(), Some("3"));
}

#[tokio::test]
async fn topic_root_is_not_reply_context() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("in a topic");
    v["reply_to_message"] = json!({
        "message_id": 3, "date": 1, "chat": { "id": 100200300, "type": "supergroup" },
        "forum_topic_created": { "name": "Ops" }
    });
    v["message_thread_id"] = json!(3);
    v["is_topic_message"] = json!(true);
    deliver(&channel, v).await;
    let msg = only_message(&host);
    assert!(msg.reply_to_message_id.is_none());
    assert_eq!(msg.thread_id.as_deref(), Some("3"));
}

// --- @mention translation -------------------------------------------------------

async fn mention_case(text: &str, entities: Value) -> String {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json(text);
    v["entities"] = entities;
    deliver(&channel, v).await;
    only_message(&host).content
}

#[tokio::test]
async fn translates_bot_mention_to_trigger_format() {
    let content = mention_case(
        "@talonai_bot what time is it?",
        json!([{ "type": "mention", "offset": 0, "length": 12 }]),
    )
    .await;
    assert_eq!(content, "@Talon @talonai_bot what time is it?");
}

#[tokio::test]
async fn does_not_translate_if_message_already_matches_trigger() {
    let content = mention_case(
        "@Talon @talonai_bot hello",
        json!([{ "type": "mention", "offset": 7, "length": 12 }]),
    )
    .await;
    assert_eq!(content, "@Talon @talonai_bot hello");
}

#[tokio::test]
async fn a_mention_becomes_the_groups_own_trigger_word() {
    let server = MockServer::start().await;
    let host = Arc::new(RecordingHost::with_groups(&[(
        "tg:100200300",
        group("SOC Team", "soc-team", "@soc"),
    )]));
    let channel = ready_channel(&server, host.clone());
    let mut v = text_json("@talonai_bot check host web-01");
    v["entities"] = json!([{ "type": "mention", "offset": 0, "length": 12 }]);
    deliver(&channel, v).await;
    assert_eq!(
        only_message(&host).content,
        "@soc @talonai_bot check host web-01"
    );
}

#[tokio::test]
async fn does_not_translate_mentions_of_other_bots() {
    let content = mention_case(
        "@some_other_bot hi",
        json!([{ "type": "mention", "offset": 0, "length": 15 }]),
    )
    .await;
    assert_eq!(content, "@some_other_bot hi");
}

#[tokio::test]
async fn handles_mention_in_middle_of_message() {
    let content = mention_case(
        "hey @talonai_bot check this",
        json!([{ "type": "mention", "offset": 4, "length": 12 }]),
    )
    .await;
    assert_eq!(content, "@Talon hey @talonai_bot check this");
}

#[tokio::test]
async fn mention_offsets_are_utf16() {
    // The emoji takes two UTF-16 units, so the mention starts at offset 3.
    let content = mention_case(
        "😂 @TalonAI_Bot look",
        json!([{ "type": "mention", "offset": 3, "length": 12 }]),
    )
    .await;
    assert_eq!(content, "@Talon 😂 @TalonAI_Bot look");
}

#[tokio::test]
async fn out_of_range_entities_are_ignored() {
    let content = mention_case(
        "@talonai_bot",
        json!([{ "type": "mention", "offset": 5, "length": 400 }]),
    )
    .await;
    assert_eq!(content, "@talonai_bot");
}

#[tokio::test]
async fn handles_message_with_no_entities() {
    let content = mention_case("plain message", json!([])).await;
    assert_eq!(content, "plain message");
}

#[tokio::test]
async fn ignores_non_mention_entities() {
    let content = mention_case(
        "check https://example.com",
        json!([{ "type": "url", "offset": 6, "length": 19 }]),
    )
    .await;
    assert_eq!(content, "check https://example.com");
}

// --- Non-text messages ----------------------------------------------------------

async fn media_case(extra: Value) -> (Arc<RecordingHost>, Option<NewMessage>) {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    deliver(&channel, media_json(extra)).await;
    let msg = host.messages().into_iter().next().map(|(_, m)| m);
    (host, msg)
}

#[tokio::test]
async fn stores_photo_with_placeholder() {
    let (host, msg) = media_case(json!({ "photo": [{ "file_id": "a" }] })).await;
    assert_eq!(msg.unwrap().content, "[Photo]");
    let meta = host.metadata();
    assert_eq!(meta.len(), 1);
    assert_eq!(meta[0].name, None);
    assert_eq!(meta[0].is_group, Some(true));
}

#[tokio::test]
async fn stores_photo_with_caption() {
    let (_, msg) = media_case(json!({ "photo": [], "caption": "Look at this" })).await;
    assert_eq!(msg.unwrap().content, "[Photo] Look at this");
}

#[tokio::test]
async fn a_caption_can_carry_the_trigger() {
    // Written trigger: it stays at the start.
    let (_, msg) = media_case(json!({ "photo": [], "caption": "@Talon what is this?" })).await;
    assert_eq!(msg.unwrap().content, "@Talon what is this? [Photo]");
    // Bot mention in the caption.
    let (_, msg) = media_case(json!({
        "photo": [],
        "caption": "@talonai_bot is this phishing?",
        "caption_entities": [{ "type": "mention", "offset": 0, "length": 12 }]
    }))
    .await;
    assert_eq!(
        msg.unwrap().content,
        "@Talon @talonai_bot is this phishing? [Photo]"
    );
}

#[tokio::test]
async fn stores_video_with_placeholder() {
    let (_, msg) = media_case(json!({ "video": {} })).await;
    assert_eq!(msg.unwrap().content, "[Video]");
}

#[tokio::test]
async fn stores_voice_message_with_placeholder() {
    let (_, msg) = media_case(json!({ "voice": {} })).await;
    assert_eq!(msg.unwrap().content, "[Voice message]");
}

#[tokio::test]
async fn stores_audio_with_placeholder() {
    let (_, msg) = media_case(json!({ "audio": {} })).await;
    assert_eq!(msg.unwrap().content, "[Audio]");
}

#[tokio::test]
async fn stores_document_with_filename() {
    let (_, msg) = media_case(json!({ "document": { "file_name": "report.pdf" } })).await;
    assert_eq!(msg.unwrap().content, "[Document: report.pdf]");
}

#[tokio::test]
async fn stores_document_with_fallback_name_when_filename_missing() {
    let (_, msg) = media_case(json!({ "document": {} })).await;
    assert_eq!(msg.unwrap().content, "[Document: file]");
}

#[tokio::test]
async fn stores_sticker_with_emoji() {
    let (_, msg) = media_case(json!({ "sticker": { "emoji": "😂" } })).await;
    assert_eq!(msg.unwrap().content, "[Sticker 😂]");
}

#[tokio::test]
async fn stores_location_with_placeholder() {
    let (_, msg) = media_case(json!({ "location": { "latitude": 1.0, "longitude": 2.0 } })).await;
    assert_eq!(msg.unwrap().content, "[Location]");
}

#[tokio::test]
async fn stores_contact_with_placeholder() {
    let (_, msg) = media_case(json!({ "contact": { "phone_number": "1" } })).await;
    assert_eq!(msg.unwrap().content, "[Contact]");
}

#[tokio::test]
async fn ignores_non_text_messages_from_unregistered_chats() {
    let server = MockServer::start().await;
    let host = default_host();
    let channel = ready_channel(&server, host.clone());
    let mut v = media_json(json!({ "photo": [] }));
    v["chat"]["id"] = json!(999999);
    deliver(&channel, v).await;
    assert!(host.events().is_empty());
}

#[tokio::test]
async fn ignores_unsupported_message_kinds() {
    let (host, msg) = media_case(json!({ "poll": { "question": "?" } })).await;
    assert!(msg.is_none());
    assert!(host.events().is_empty());
}

// --- send_message -----------------------------------------------------------------

#[tokio::test]
async fn sends_message_via_bot_api() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    channel.send_message("tg:100200300", "Hello").await.unwrap();
    let reqs = requests_to(&server, "sendMessage").await;
    assert_eq!(
        reqs,
        vec![json!({ "chat_id": "100200300", "text": "Hello", "parse_mode": "HTML" })]
    );
}

#[tokio::test]
async fn sends_identifiers_and_paths_unaltered() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    let text = r"*IOC*: file_a.exe and file_b.dll in C:\Users\*\AppData <tmp>";
    channel.send_message("tg:1", text).await.unwrap();
    let reqs = requests_to(&server, "sendMessage").await;
    assert_eq!(
        reqs[0]["text"],
        r"<b>IOC</b>: file_a.exe and file_b.dll in C:\Users\*\AppData &lt;tmp&gt;"
    );
    assert_eq!(reqs[0]["parse_mode"], "HTML");
}

#[tokio::test]
async fn strips_tg_prefix_from_jid() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    channel
        .send_message("tg:-1001234567890", "Group message")
        .await
        .unwrap();
    let reqs = requests_to(&server, "sendMessage").await;
    assert_eq!(reqs[0]["chat_id"], "-1001234567890");
    assert_eq!(reqs[0]["text"], "Group message");
}

#[tokio::test]
async fn splits_messages_exceeding_4096_characters() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    channel
        .send_message("tg:100200300", &"x".repeat(5000))
        .await
        .unwrap();
    let reqs = requests_to(&server, "sendMessage").await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0]["text"], "x".repeat(4096));
    assert_eq!(reqs[0]["parse_mode"], "HTML");
    assert_eq!(reqs[1]["text"], "x".repeat(904));
    assert_eq!(reqs[1]["parse_mode"], "HTML");
}

#[tokio::test]
async fn sends_exactly_one_message_at_4096_characters() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    channel
        .send_message("tg:100200300", &"y".repeat(4096))
        .await
        .unwrap();
    assert_eq!(requests_to(&server, "sendMessage").await.len(), 1);
}

#[tokio::test]
async fn falls_back_to_plain_text_on_400() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(api_path("sendMessage")))
        .and(body_partial_json(json!({ "parse_mode": "HTML" })))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "ok": false, "error_code": 400,
            "description": "Bad Request: can't parse entities"
        })))
        .mount(&server)
        .await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    channel
        .send_message("tg:100200300", "*broken markdown")
        .await
        .unwrap();
    let reqs = requests_to(&server, "sendMessage").await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0]["parse_mode"], "HTML");
    assert_eq!(
        reqs[1],
        json!({ "chat_id": "100200300", "text": "*broken markdown" })
    );
}

#[tokio::test]
async fn no_plain_fallback_for_non_400_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(api_path("sendMessage")))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "ok": false, "error_code": 403, "description": "Forbidden: bot was blocked by the user"
        })))
        .mount(&server)
        .await;
    let channel = ready_channel(&server, default_host());
    channel.send_message("tg:1", "hi").await.unwrap();
    assert_eq!(requests_to(&server, "sendMessage").await.len(), 1);
}

#[tokio::test]
async fn honours_retry_after_on_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(api_path("sendMessage")))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "ok": false, "error_code": 429, "description": "Too Many Requests: retry after 0",
            "parameters": { "retry_after": 0 }
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    channel.send_message("tg:1", "hi").await.unwrap();
    let reqs = requests_to(&server, "sendMessage").await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1]["parse_mode"], "HTML");
}

#[tokio::test]
async fn handles_send_failure_gracefully() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(api_path("sendMessage")))
        .respond_with(ResponseTemplate::new(500).set_body_string("Network error"))
        .mount(&server)
        .await;
    let channel = ready_channel(&server, default_host());
    assert!(
        channel
            .send_message("tg:100200300", "Will fail")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn stops_sending_chunks_after_a_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(api_path("sendMessage")))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "ok": false, "error_code": 403, "description": "Forbidden"
        })))
        .mount(&server)
        .await;
    let channel = ready_channel(&server, default_host());
    channel
        .send_message("tg:1", &"z".repeat(9000))
        .await
        .unwrap();
    assert_eq!(requests_to(&server, "sendMessage").await.len(), 1);
}

#[tokio::test]
async fn does_nothing_when_bot_is_not_initialized() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ok(json!({})))
        .expect(0)
        .mount(&server)
        .await;
    let channel = TelegramChannel::new(config(&server), default_host()).unwrap();
    channel
        .send_message("tg:100200300", "No bot")
        .await
        .unwrap();
    channel.set_typing("tg:100200300", true).await.unwrap();
}

#[tokio::test]
async fn skips_empty_text_and_rejects_foreign_jids() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ok(json!({})))
        .expect(0)
        .mount(&server)
        .await;
    let channel = ready_channel(&server, default_host());
    channel.send_message("tg:1", "  \n").await.unwrap();
    assert!(channel.send_message("12345@g.us", "hi").await.is_err());
    assert!(channel.send_message("tg:", "hi").await.is_err());
}

// --- owns_jid -----------------------------------------------------------------------

#[tokio::test]
async fn owns_jid_rules() {
    let server = MockServer::start().await;
    let channel = TelegramChannel::new(config(&server), default_host()).unwrap();
    assert!(channel.owns_jid("tg:123456"));
    assert!(channel.owns_jid("tg:-1001234567890"));
    assert!(!channel.owns_jid("12345@g.us"));
    assert!(!channel.owns_jid("12345@s.whatsapp.net"));
    assert!(!channel.owns_jid("random-string"));
}

// --- set_typing -------------------------------------------------------------------

#[tokio::test]
async fn sends_typing_action_when_is_typing_is_true() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(api_path("sendChatAction")))
        .respond_with(ok(json!(true)))
        .expect(1)
        .mount(&server)
        .await;
    let channel = ready_channel(&server, default_host());
    channel.set_typing("tg:100200300", true).await.unwrap();
    let reqs = requests_to(&server, "sendChatAction").await;
    assert_eq!(
        reqs[0],
        json!({ "chat_id": "100200300", "action": "typing" })
    );
}

#[tokio::test]
async fn does_nothing_when_is_typing_is_false() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ok(json!(true)))
        .expect(0)
        .mount(&server)
        .await;
    let channel = ready_channel(&server, default_host());
    channel.set_typing("tg:100200300", false).await.unwrap();
}

#[tokio::test]
async fn handles_typing_indicator_failure_gracefully() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(api_path("sendChatAction")))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "ok": false, "error_code": 429, "description": "Rate limited"
        })))
        .mount(&server)
        .await;
    let channel = ready_channel(&server, default_host());
    assert!(channel.set_typing("tg:100200300", true).await.is_ok());
}

// --- Bot commands -------------------------------------------------------------------

#[tokio::test]
async fn chatid_replies_with_chat_id_and_metadata() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    let mut v = text_json("/chatid");
    v["chat"] = json!({ "id": 100200300, "type": "group" });
    deliver(&channel, v).await;
    let reqs = requests_to(&server, "sendMessage").await;
    assert_eq!(reqs.len(), 1);
    let text = reqs[0]["text"].as_str().unwrap();
    assert!(text.contains("<code>tg:100200300</code>"), "{text}");
    assert!(text.contains("Name: Unknown"), "{text}");
    assert!(text.contains("Type: group"), "{text}");
    assert_eq!(reqs[0]["parse_mode"], "HTML");
    assert_eq!(reqs[0]["chat_id"], "100200300");
}

#[tokio::test]
async fn chatid_shows_chat_type_and_private_name() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    let mut v = text_json("/chatid");
    v["chat"] = json!({ "id": 555, "type": "private" });
    v["from"]["first_name"] = json!("Bob");
    deliver(&channel, v).await;
    let reqs = requests_to(&server, "sendMessage").await;
    let text = reqs[0]["text"].as_str().unwrap();
    assert!(text.contains("private"), "{text}");
    assert!(text.contains("Name: Bob"), "{text}");
    assert!(text.contains("tg:555"), "{text}");
}

#[tokio::test]
async fn ping_replies_with_bot_status() {
    let server = MockServer::start().await;
    mount_send_ok(&server).await;
    let channel = ready_channel(&server, default_host());
    deliver(&channel, text_json("/ping")).await;
    let reqs = requests_to(&server, "sendMessage").await;
    assert_eq!(
        reqs,
        vec![json!({ "chat_id": "100200300", "text": "Talon is online." })]
    );
}

// --- Channel properties -----------------------------------------------------------

#[tokio::test]
async fn has_name_telegram_and_telegram_dialect() {
    let server = MockServer::start().await;
    let channel = TelegramChannel::new(config(&server), default_host()).unwrap();
    assert_eq!(channel.name(), "telegram");
    assert_eq!(channel.channel_type(), ChannelType::Telegram);
}

#[tokio::test]
async fn reconnect_without_state_file_resumes_from_memory() {
    let server = MockServer::start().await;
    mount_startup(&server).await;
    Mock::given(method("POST"))
        .and(path(api_path("getUpdates")))
        .respond_with(ok(
            json!([{ "update_id": 30, "message": text_json("once") }]),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_idle_updates(&server).await;
    let host = default_host();
    let channel = TelegramChannel::new(config(&server), host.clone()).unwrap();
    channel.connect().await.unwrap();
    assert_eq!(host.wait_for_messages(1).await.len(), 1);
    wait_requests(&server, "getUpdates", 2).await;
    channel.disconnect().await.unwrap();

    let before = requests_to(&server, "getUpdates").await.len();
    channel.connect().await.unwrap();
    let polls = wait_requests(&server, "getUpdates", before + 1).await;
    assert_eq!(polls[before]["offset"], 31);
    channel.disconnect().await.unwrap();
    assert_eq!(host.messages().len(), 1);
}
