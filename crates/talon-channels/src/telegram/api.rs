//! Minimal Telegram Bot API client (raw HTTPS + JSON, no bot framework) and
//! the subset of the update schema the channel consumes.
//!
//! The bot token is part of every request URL, so transport errors are
//! always stripped of their URL (`reqwest::Error::without_url`) before they
//! are formatted, and nothing in here implements `Debug` with the token.

use std::time::Duration;

use serde::Deserialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use serde_json::{Value, json};

/// Upper bound on a Bot API response body we are willing to buffer.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Failure of a Bot API call. Never contains the bot token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ApiError {
    /// Telegram answered with `ok: false` (or a non-2xx status).
    #[error("Telegram API error {status}: {description}")]
    Api {
        status: u16,
        description: String,
        retry_after: Option<u64>,
        migrate_to_chat_id: Option<i64>,
    },
    /// The request did not complete. `connect` is true when the request
    /// provably never reached the server (safe to retry without duplicates).
    #[error("Telegram transport error: {message}")]
    Transport { message: String, connect: bool },
    /// The response could not be decoded.
    #[error("Telegram response decode error: {0}")]
    Decode(String),
}

impl ApiError {
    pub(crate) fn status(&self) -> Option<u16> {
        match self {
            ApiError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    fn from_reqwest(err: reqwest::Error) -> Self {
        let connect = err.is_connect();
        ApiError::Transport {
            message: err.without_url().to_string(),
            connect,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    error_code: Option<u16>,
    #[serde(default)]
    parameters: Option<ResponseParameters>,
}

#[derive(Debug, Deserialize)]
struct ResponseParameters {
    #[serde(default)]
    retry_after: Option<u64>,
    #[serde(default)]
    migrate_to_chat_id: Option<i64>,
}

/// `User` (only the fields Talon uses).
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct User {
    pub id: i64,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

/// `Chat`.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Chat {
    pub id: i64,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub title: Option<String>,
}

/// `MessageEntity`.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Entity {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub length: usize,
}

/// `Document`.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Document {
    #[serde(default)]
    pub file_name: Option<String>,
}

/// `Sticker`.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Sticker {
    #[serde(default)]
    pub emoji: Option<String>,
}

/// `Message`. Media payloads Talon only acknowledges with a placeholder are
/// skipped without being parsed.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Message {
    pub message_id: i64,
    #[serde(default)]
    pub date: i64,
    pub chat: Chat,
    #[serde(default)]
    pub from: Option<User>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub entities: Vec<Entity>,
    #[serde(default)]
    pub message_thread_id: Option<i64>,
    #[serde(default)]
    pub is_topic_message: Option<bool>,
    #[serde(default)]
    pub reply_to_message: Option<Box<Message>>,
    #[serde(default)]
    pub photo: Option<IgnoredAny>,
    #[serde(default)]
    pub video: Option<IgnoredAny>,
    #[serde(default)]
    pub voice: Option<IgnoredAny>,
    #[serde(default)]
    pub audio: Option<IgnoredAny>,
    #[serde(default)]
    pub document: Option<Document>,
    #[serde(default)]
    pub sticker: Option<Sticker>,
    #[serde(default)]
    pub location: Option<IgnoredAny>,
    #[serde(default)]
    pub contact: Option<IgnoredAny>,
}

/// `Update` (only `message` updates are requested).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Update {
    #[serde(default)]
    pub message: Option<Message>,
}

/// Bot API client bound to one token.
pub(crate) struct BotApi {
    client: reqwest::Client,
    base_url: String,
    token: String,
    request_timeout: Duration,
}

impl BotApi {
    pub(crate) fn new(
        base_url: &str,
        token: &str,
        request_timeout: Duration,
    ) -> Result<Self, ApiError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("talon/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(ApiError::from_reqwest)?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            request_timeout,
        })
    }

    /// POST `{base}/bot<token>/{method}` with a JSON body.
    pub(crate) async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        body: &Value,
        timeout: Option<Duration>,
    ) -> Result<T, ApiError> {
        let url = format!("{}/bot{}/{}", self.base_url, self.token, method);
        let mut resp = self
            .client
            .post(url)
            .timeout(timeout.unwrap_or(self.request_timeout))
            .json(body)
            .send()
            .await
            .map_err(ApiError::from_reqwest)?;
        let status = resp.status().as_u16();

        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(ApiError::from_reqwest)? {
            if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(ApiError::Decode(format!(
                    "{method}: response exceeds {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            buf.extend_from_slice(&chunk);
        }

        let envelope: Envelope = match serde_json::from_slice(&buf) {
            Ok(env) => env,
            Err(e) if (200..300).contains(&status) => {
                return Err(ApiError::Decode(format!("{method}: {e}")));
            }
            Err(_) => {
                return Err(ApiError::Api {
                    status,
                    description: format!("HTTP {status} from {method}"),
                    retry_after: None,
                    migrate_to_chat_id: None,
                });
            }
        };

        if !envelope.ok || !(200..300).contains(&status) {
            let params = envelope.parameters;
            return Err(ApiError::Api {
                status: envelope.error_code.unwrap_or(status),
                description: envelope
                    .description
                    .unwrap_or_else(|| format!("{method} failed")),
                retry_after: params.as_ref().and_then(|p| p.retry_after),
                migrate_to_chat_id: params.as_ref().and_then(|p| p.migrate_to_chat_id),
            });
        }

        serde_json::from_value(envelope.result.unwrap_or(Value::Null))
            .map_err(|e| ApiError::Decode(format!("{method}: {e}")))
    }

    pub(crate) async fn get_me(&self) -> Result<User, ApiError> {
        self.call("getMe", &json!({}), None).await
    }

    pub(crate) async fn delete_webhook(&self) -> Result<bool, ApiError> {
        self.call(
            "deleteWebhook",
            &json!({ "drop_pending_updates": false }),
            None,
        )
        .await
    }

    /// Long poll. Returns raw updates so one malformed update cannot wedge
    /// the offset.
    pub(crate) async fn get_updates(
        &self,
        offset: i64,
        poll_timeout: Duration,
    ) -> Result<Vec<Value>, ApiError> {
        let body = json!({
            "offset": offset,
            "timeout": poll_timeout.as_secs(),
            "allowed_updates": ["message"],
        });
        // The HTTP timeout must outlast Telegram's long-poll hold time.
        let http_timeout = poll_timeout + Duration::from_secs(15);
        self.call("getUpdates", &body, Some(http_timeout)).await
    }

    pub(crate) async fn send_message(
        &self,
        chat_id: &str,
        text: &str,
        parse_mode: Option<&str>,
        message_thread_id: Option<i64>,
    ) -> Result<(), ApiError> {
        let mut body = json!({ "chat_id": chat_id, "text": text });
        if let Some(mode) = parse_mode {
            body["parse_mode"] = json!(mode);
        }
        if let Some(thread) = message_thread_id {
            body["message_thread_id"] = json!(thread);
        }
        let _: IgnoredAny = self.call("sendMessage", &body, None).await?;
        Ok(())
    }

    pub(crate) async fn send_chat_action(
        &self,
        chat_id: &str,
        action: &str,
    ) -> Result<(), ApiError> {
        let _: IgnoredAny = self
            .call(
                "sendChatAction",
                &json!({ "chat_id": chat_id, "action": action }),
                None,
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "123456:SECRET_token-value";

    #[tokio::test]
    async fn decodes_ok_envelope() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/bot{TOKEN}/getMe")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "result": {"id": 42, "is_bot": true, "first_name": "Talon", "username": "talonai_bot"}
            })))
            .mount(&server)
            .await;
        let api = BotApi::new(&server.uri(), TOKEN, Duration::from_secs(5)).unwrap();
        let me = api.get_me().await.unwrap();
        assert_eq!(me.id, 42);
        assert_eq!(me.username.as_deref(), Some("talonai_bot"));
    }

    #[tokio::test]
    async fn maps_error_envelope_with_parameters() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "ok": false, "error_code": 429,
                "description": "Too Many Requests: retry after 3",
                "parameters": {"retry_after": 3}
            })))
            .mount(&server)
            .await;
        let api = BotApi::new(&server.uri(), TOKEN, Duration::from_secs(5)).unwrap();
        let err = api.send_message("1", "x", None, None).await.unwrap_err();
        assert_eq!(err.status(), Some(429));
        match err {
            ApiError::Api { retry_after, .. } => assert_eq!(retry_after, Some(3)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_json_error_body_keeps_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(502).set_body_string("<html>bad gateway</html>"))
            .mount(&server)
            .await;
        let api = BotApi::new(&server.uri(), TOKEN, Duration::from_secs(5)).unwrap();
        let err = api.get_me().await.unwrap_err();
        assert_eq!(err.status(), Some(502));
    }

    #[tokio::test]
    async fn transport_errors_never_contain_the_token() {
        // Nothing listens on this port (bound then dropped).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let api = BotApi::new(&format!("http://{addr}"), TOKEN, Duration::from_secs(2)).unwrap();
        let err = api.get_me().await.unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(!text.contains("SECRET_token"), "token leaked: {text}");
        assert!(matches!(err, ApiError::Transport { connect: true, .. }));
    }

    #[test]
    fn message_schema_tolerates_unknown_and_missing_fields() {
        let msg: Message = serde_json::from_value(json!({
            "message_id": 5, "date": 1, "chat": {"id": -100, "type": "supergroup", "title": "T"},
            "photo": [{"file_id": "x", "width": 1, "height": 1}],
            "brand_new_field": {"nested": true}
        }))
        .unwrap();
        assert!(msg.photo.is_some());
        assert!(msg.from.is_none());
        assert!(msg.entities.is_empty());
    }
}
