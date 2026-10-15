//! Telegram channel: Bot API long polling (`getUpdates`) over raw HTTPS.
//!
//! Behaviour:
//! - JIDs are `tg:<chat id>` (negative ids for groups/supergroups).
//! - `/chatid` and `/ping` are answered by the bot itself and never stored;
//!   every other `/command` flows through as a normal message.
//! - Chat metadata is reported for every text message (even from
//!   unregistered chats, for discovery); messages are only delivered for
//!   registered chats.
//! - An `@bot_username` mention is translated into the trigger
//!   (`@<ASSISTANT_NAME> ...`) unless the text already matches it.
//! - Non-text messages become placeholders (`[Photo]`, `[Document: x]`, ...)
//!   plus caption, for registered chats only.
//! - Outbound text is split at 4096 UTF-16 units, sent with Markdown parse
//!   mode and re-sent as plain text when Telegram rejects the markup (400).
//! - Delivery failures are logged, never returned as errors (the host's turn
//!   bookkeeping must not roll back because a chat send failed).
//!
//! Robustness: the update offset is persisted to a small state file so a
//! restart neither replays nor loses updates; `retry_after` (429) is
//! honoured; malformed updates are skipped instead of wedging the poller;
//! entity offsets are handled in UTF-16 like Telegram defines them; reply
//! context and forum-topic ids are carried into [`NewMessage`]; the bot token
//! is validated and never appears in logs or errors.

mod api;
pub mod text;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use serde_json::{Value, json};
use talon_core::channel::{Channel, ChannelHost, ChannelType};
use talon_core::env::EnvFile;
use talon_core::time::{now_iso, to_iso};
use talon_core::types::{ChatMetadata, NewMessage};
use talon_core::{Error, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use self::api::{ApiError, BotApi, Message, Update, User};
use self::text::{TELEGRAM_MAX_MESSAGE_LEN, chunk_text, utf16_slice};
use crate::util::{backoff_delay, project_root, secret_value, setting, write_atomic};

/// Env var holding the bot token.
pub const TELEGRAM_BOT_TOKEN_ENV: &str = "TELEGRAM_BOT_TOKEN";
/// Default Bot API endpoint.
pub const DEFAULT_TELEGRAM_API_BASE: &str = "https://api.telegram.org";
/// JID prefix for Telegram chats.
pub const TELEGRAM_JID_PREFIX: &str = "tg:";

/// Commands the bot answers itself; they are never stored as messages.
const BOT_COMMANDS: [&str; 2] = ["chatid", "ping"];
/// Attempts per outbound API call (429 / connect errors / 502-504).
const MAX_SEND_ATTEMPTS: u32 = 3;
/// Longest `retry_after` we are willing to sleep inline.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Telegram channel configuration.
#[derive(Clone)]
pub struct TelegramConfig {
    /// Bot token from BotFather (`<id>:<secret>`). Never logged.
    pub bot_token: String,
    /// Bot API base URL (default [`DEFAULT_TELEGRAM_API_BASE`]); injectable
    /// for tests and self-hosted Bot API servers.
    pub api_base_url: String,
    /// Assistant name used for the trigger (`@<name>`) and `/ping`.
    pub assistant_name: String,
    /// Where the `getUpdates` offset is persisted. `None` disables
    /// persistence (Telegram then redelivers unconfirmed updates).
    pub state_path: Option<PathBuf>,
    /// Long-poll hold time passed to `getUpdates`.
    pub poll_timeout: Duration,
    /// Timeout for ordinary API calls.
    pub request_timeout: Duration,
    /// Base delay for poller error backoff.
    pub error_backoff_base: Duration,
    /// Cap for poller error backoff.
    pub error_backoff_max: Duration,
}

impl std::fmt::Debug for TelegramConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramConfig")
            .field("bot_token", &"<redacted>")
            .field("api_base_url", &self.api_base_url)
            .field("assistant_name", &self.assistant_name)
            .field("state_path", &self.state_path)
            .field("poll_timeout", &self.poll_timeout)
            .finish_non_exhaustive()
    }
}

impl TelegramConfig {
    /// Defaults for everything but the token and assistant name.
    pub fn new(bot_token: impl Into<String>, assistant_name: impl Into<String>) -> Self {
        Self {
            bot_token: bot_token.into(),
            api_base_url: DEFAULT_TELEGRAM_API_BASE.to_string(),
            assistant_name: assistant_name.into(),
            state_path: None,
            poll_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
            error_backoff_base: Duration::from_secs(1),
            error_backoff_max: Duration::from_secs(60),
        }
    }

    /// From `TELEGRAM_BOT_TOKEN` (`.env`, then process env) and
    /// `ASSISTANT_NAME`. The offset is persisted to
    /// `<project root>/data/telegram/state.json`. `None` when no token is
    /// configured.
    pub fn from_env(env: &EnvFile) -> Option<Self> {
        let token = secret_value(env, TELEGRAM_BOT_TOKEN_ENV)?;
        let name = setting(env, "ASSISTANT_NAME").unwrap_or_else(|| "Talon".to_string());
        let mut cfg = Self::new(token, name);
        cfg.state_path =
            project_root(env).map(|root| root.join("data").join("telegram").join("state.json"));
        Some(cfg)
    }
}

/// Bot tokens look like `123456:AA...`; anything else could alter the
/// request path.
fn is_valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-'))
}

struct Inner {
    api: BotApi,
    host: Arc<dyn ChannelHost>,
    assistant_name: String,
    trigger: Regex,
    /// The bot's own `@username` (from `getMe`), lowercase comparison.
    bot_username: RwLock<Option<String>>,
    connected: AtomicBool,
    /// Next `getUpdates` offset seen by this process (survives reconnects).
    offset: AtomicI64,
    state_path: Option<PathBuf>,
    poll_timeout: Duration,
    error_backoff_base: Duration,
    error_backoff_max: Duration,
}

struct PollTask {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// Telegram Bot API channel (`tg:<chat id>` JIDs).
pub struct TelegramChannel {
    inner: Arc<Inner>,
    poller: Mutex<Option<PollTask>>,
}

impl std::fmt::Debug for TelegramChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramChannel")
            .field("connected", &self.inner.connected.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl TelegramChannel {
    /// Build the channel. Fails on an empty or malformed token (the token is
    /// not echoed in the error).
    pub fn new(config: TelegramConfig, host: Arc<dyn ChannelHost>) -> Result<Self> {
        if !is_valid_token(&config.bot_token) {
            return Err(Error::Config(
                "TELEGRAM_BOT_TOKEN is empty or malformed".to_string(),
            ));
        }
        let api = BotApi::new(
            &config.api_base_url,
            &config.bot_token,
            config.request_timeout,
        )
        .map_err(|e| Error::Channel(e.to_string()))?;
        let assistant_name = config.assistant_name.trim().to_string();
        let assistant_name = if assistant_name.is_empty() {
            "Talon".to_string()
        } else {
            assistant_name
        };
        let trigger = talon_core::trigger::build_trigger_pattern(
            &talon_core::trigger::default_trigger(&assistant_name),
            &assistant_name,
        );
        Ok(Self {
            inner: Arc::new(Inner {
                api,
                host,
                assistant_name,
                trigger,
                bot_username: RwLock::new(None),
                connected: AtomicBool::new(false),
                offset: AtomicI64::new(0),
                state_path: config.state_path,
                poll_timeout: config.poll_timeout,
                error_backoff_base: config.error_backoff_base,
                error_backoff_max: config.error_backoff_max,
            }),
            poller: Mutex::new(None),
        })
    }

    fn take_poller(&self) -> Option<PollTask> {
        self.poller.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// `tg:<id>` -> `<id>`; `None` for foreign or empty JIDs.
fn chat_id_from_jid(jid: &str) -> Option<&str> {
    jid.strip_prefix(TELEGRAM_JID_PREFIX)
        .map(str::trim)
        .filter(|id| !id.is_empty())
}

#[async_trait]
impl Channel for TelegramChannel {
    fn name(&self) -> &str {
        "telegram"
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Telegram
    }

    async fn connect(&self) -> Result<()> {
        if self.inner.connected.load(Ordering::SeqCst) {
            return Ok(());
        }
        let me = self.inner.get_me_with_retry().await?;
        info!(
            username = me.username.as_deref().unwrap_or(""),
            id = me.id,
            "Telegram bot connected (send /chatid to the bot to get a chat's registration ID)"
        );
        self.inner.set_me(&me);

        // getUpdates is refused (409) while a webhook is set.
        if let Err(e) = self.inner.api.delete_webhook().await {
            warn!(err = %e, "Telegram: deleteWebhook failed; polling may conflict");
        }

        let offset = self.inner.load_offset().await;
        let cancel = CancellationToken::new();
        let inner = Arc::clone(&self.inner);
        let token = cancel.clone();
        let handle = tokio::spawn(async move { inner.poll_loop(token, offset).await });
        let previous = self
            .poller
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(PollTask { cancel, handle });
        if let Some(old) = previous {
            old.cancel.cancel();
        }
        self.inner.connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn send_message(&self, jid: &str, text: &str) -> Result<()> {
        let Some(chat_id) = chat_id_from_jid(jid) else {
            return Err(Error::invalid(format!("not a Telegram JID: {jid}")));
        };
        if !self.inner.connected.load(Ordering::SeqCst) {
            warn!(jid, "Telegram bot not initialized");
            return Ok(());
        }
        if text.trim().is_empty() {
            debug!(jid, "Telegram: skipping empty message");
            return Ok(());
        }
        for chunk in chunk_text(text, TELEGRAM_MAX_MESSAGE_LEN) {
            if let Err(e) = self.inner.send_text(chat_id, chunk, None).await {
                error!(jid, err = %e, "Failed to send Telegram message");
                return Ok(());
            }
        }
        info!(jid, length = text.chars().count(), "Telegram message sent");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    fn owns_jid(&self, jid: &str) -> bool {
        jid.starts_with(TELEGRAM_JID_PREFIX)
    }

    async fn disconnect(&self) -> Result<()> {
        let was_connected = self.inner.connected.swap(false, Ordering::SeqCst);
        if let Some(task) = self.take_poller() {
            task.cancel.cancel();
            let mut handle = task.handle;
            if tokio::time::timeout(Duration::from_secs(5), &mut handle)
                .await
                .is_err()
            {
                handle.abort();
            }
        }
        if was_connected {
            info!("Telegram bot stopped");
        }
        Ok(())
    }

    async fn set_typing(&self, jid: &str, is_typing: bool) -> Result<()> {
        if !is_typing || !self.inner.connected.load(Ordering::SeqCst) {
            return Ok(());
        }
        let Some(chat_id) = chat_id_from_jid(jid) else {
            return Ok(());
        };
        if let Err(e) = self.inner.api.send_chat_action(chat_id, "typing").await {
            debug!(jid, err = %e, "Failed to send Telegram typing indicator");
        }
        Ok(())
    }
}

/// Parsed `/command[@bot] args`.
struct Command<'a> {
    name: String,
    target: Option<&'a str>,
}

fn parse_command(text: &str) -> Option<Command<'_>> {
    let rest = text.strip_prefix('/')?;
    let token = rest.split(char::is_whitespace).next().unwrap_or("");
    let (name, target) = match token.split_once('@') {
        Some((name, target)) => (name, Some(target)),
        None => (token, None),
    };
    Some(Command {
        name: name.to_lowercase(),
        target,
    })
}

/// `first_name || username || id || "Unknown"` (JS `||` semantics: empty
/// strings fall through).
fn sender_name(from: Option<&User>) -> String {
    let Some(user) = from else {
        return "Unknown".to_string();
    };
    user.first_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| user.username.as_deref().filter(|s| !s.is_empty()))
        .map(str::to_string)
        .unwrap_or_else(|| user.id.to_string())
}

fn unix_to_iso(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(to_iso)
        .unwrap_or_else(now_iso)
}

fn is_group_chat(kind: &str) -> bool {
    kind == "group" || kind == "supergroup"
}

/// Placeholder for a non-text message, or `None` for kinds Talon ignores.
fn non_text_placeholder(msg: &Message) -> Option<String> {
    if msg.photo.is_some() {
        Some("[Photo]".to_string())
    } else if msg.video.is_some() {
        Some("[Video]".to_string())
    } else if msg.voice.is_some() {
        Some("[Voice message]".to_string())
    } else if msg.audio.is_some() {
        Some("[Audio]".to_string())
    } else if let Some(doc) = &msg.document {
        let name = doc
            .file_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("file");
        Some(format!("[Document: {name}]"))
    } else if let Some(sticker) = &msg.sticker {
        Some(format!(
            "[Sticker {}]",
            sticker.emoji.as_deref().unwrap_or("")
        ))
    } else if msg.location.is_some() {
        Some("[Location]".to_string())
    } else if msg.contact.is_some() {
        Some("[Contact]".to_string())
    } else {
        None
    }
}

impl Inner {
    fn set_me(&self, me: &User) {
        *self.bot_username.write().unwrap_or_else(|e| e.into_inner()) =
            me.username.clone().filter(|u| !u.is_empty());
    }

    fn bot_username(&self) -> Option<String> {
        self.bot_username
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn get_me_with_retry(&self) -> Result<User> {
        let mut attempt = 0u32;
        loop {
            match self.api.get_me().await {
                Ok(me) => return Ok(me),
                Err(e) => {
                    let fatal = matches!(e.status(), Some(401 | 403 | 404));
                    attempt += 1;
                    if fatal || attempt >= 3 {
                        return Err(Error::Channel(format!("Telegram getMe failed: {e}")));
                    }
                    warn!(err = %e, attempt, "Telegram getMe failed, retrying");
                    tokio::time::sleep(backoff_delay(
                        attempt,
                        self.error_backoff_base,
                        self.error_backoff_max,
                    ))
                    .await;
                }
            }
        }
    }

    // ---- offset persistence ------------------------------------------------

    /// Resume point: the larger of the in-memory and the persisted offset.
    async fn load_offset(&self) -> i64 {
        let persisted = self.read_persisted_offset().await;
        persisted.max(self.offset.load(Ordering::SeqCst))
    }

    async fn read_persisted_offset(&self) -> i64 {
        let Some(path) = &self.state_path else {
            return 0;
        };
        match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("offset").and_then(Value::as_i64))
                .filter(|o| *o >= 0)
                .unwrap_or_else(|| {
                    warn!(path = %path.display(), "Telegram: ignoring unreadable offset state");
                    0
                }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => {
                warn!(path = %path.display(), err = %e, "Telegram: cannot read offset state");
                0
            }
        }
    }

    async fn save_offset(&self, offset: i64) {
        let Some(path) = &self.state_path else {
            return;
        };
        let body = json!({ "offset": offset, "updated_at": now_iso() }).to_string();
        if let Err(e) = write_atomic(path, body.as_bytes()).await {
            warn!(path = %path.display(), err = %e, "Telegram: cannot persist offset");
        }
    }

    // ---- polling -----------------------------------------------------------

    async fn poll_loop(self: Arc<Self>, cancel: CancellationToken, mut offset: i64) {
        let mut failures: u32 = 0;
        loop {
            let result = tokio::select! {
                _ = cancel.cancelled() => break,
                r = self.api.get_updates(offset, self.poll_timeout) => r,
            };
            match result {
                Ok(updates) => {
                    failures = 0;
                    let next = self.process_updates(updates, offset).await;
                    if next != offset {
                        offset = next;
                        self.offset.store(offset, Ordering::SeqCst);
                        self.save_offset(offset).await;
                    }
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    let delay = match &e {
                        ApiError::Api {
                            status: 429,
                            retry_after: Some(secs),
                            ..
                        } => Duration::from_secs(*secs),
                        ApiError::Api {
                            status: 401 | 404, ..
                        } => {
                            error!(err = %e, "Telegram: bot token rejected; retrying slowly");
                            self.error_backoff_max
                        }
                        ApiError::Api { status: 409, .. } => {
                            warn!(err = %e, "Telegram: another poller or webhook is active");
                            backoff_delay(failures, self.error_backoff_base, self.error_backoff_max)
                        }
                        _ => {
                            warn!(err = %e, failures, "Telegram: getUpdates failed");
                            backoff_delay(failures, self.error_backoff_base, self.error_backoff_max)
                        }
                    };
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
        debug!("Telegram poller stopped");
    }

    /// Handle a batch; returns the next offset (max `update_id` + 1).
    async fn process_updates(&self, updates: Vec<Value>, offset: i64) -> i64 {
        let mut next = offset;
        for raw in updates {
            let Some(update_id) = raw.get("update_id").and_then(Value::as_i64) else {
                warn!("Telegram: update without update_id skipped");
                continue;
            };
            next = next.max(update_id.saturating_add(1));
            match serde_json::from_value::<Update>(raw) {
                Ok(update) => {
                    if let Some(message) = update.message {
                        self.handle_message(message).await;
                    }
                }
                Err(e) => warn!(update_id, err = %e, "Telegram: undecodable update skipped"),
            }
        }
        next
    }

    // ---- inbound -----------------------------------------------------------

    async fn handle_message(&self, msg: Message) {
        if let Some(text) = msg.text.clone() {
            self.handle_text(&msg, text).await;
        } else if let Some(placeholder) = non_text_placeholder(&msg) {
            self.store_non_text(&msg, &placeholder).await;
        }
    }

    fn reply_fields(msg: &Message) -> (Option<String>, Option<String>, Option<String>) {
        match msg.reply_to_message.as_deref() {
            // In forum supergroups every topic message "replies" to the
            // topic's creation message; that is not real reply context.
            Some(r) if Some(r.message_id) != msg.message_thread_id => (
                Some(r.message_id.to_string()),
                r.text.clone().or_else(|| r.caption.clone()),
                r.from.as_ref().map(|u| sender_name(Some(u))),
            ),
            _ => (None, None, None),
        }
    }

    fn thread_id(msg: &Message) -> Option<String> {
        if msg.is_topic_message == Some(true) {
            msg.message_thread_id.map(|t| t.to_string())
        } else {
            None
        }
    }

    async fn handle_text(&self, msg: &Message, text: String) {
        let bot_username = self.bot_username();

        if let Some(cmd) = parse_command(&text) {
            if BOT_COMMANDS.contains(&cmd.name.as_str()) {
                let for_us = match (cmd.target, bot_username.as_deref()) {
                    (None, _) => true,
                    (Some(target), Some(me)) => target.eq_ignore_ascii_case(me),
                    (Some(_), None) => false,
                };
                if for_us {
                    self.answer_command(&cmd.name, msg).await;
                }
                return;
            }
        }

        let chat_jid = format!("{TELEGRAM_JID_PREFIX}{}", msg.chat.id);
        let timestamp = unix_to_iso(msg.date);
        let sender_name = sender_name(msg.from.as_ref());
        let sender = msg
            .from
            .as_ref()
            .map(|u| u.id.to_string())
            .unwrap_or_default();
        let chat_name = if msg.chat.kind == "private" {
            sender_name.clone()
        } else {
            msg.chat
                .title
                .clone()
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| chat_jid.clone())
        };

        // Translate `@bot_username` mentions into the trigger format: a
        // Telegram mention (`@talonai_bot`) won't match `^@Talon\b`.
        let mut content = text;
        if let Some(username) = bot_username {
            let wanted = format!("@{}", username.to_lowercase());
            let mentioned = msg.entities.iter().any(|entity| {
                entity.kind == "mention"
                    && utf16_slice(&content, entity.offset, entity.length)
                        .is_some_and(|m| m.to_lowercase() == wanted)
            });
            if mentioned && !self.trigger.is_match(&content) {
                content = format!("@{} {content}", self.assistant_name);
            }
        }

        let is_group = is_group_chat(&msg.chat.kind);
        self.host
            .on_chat_metadata(ChatMetadata {
                chat_jid: chat_jid.clone(),
                timestamp: timestamp.clone(),
                name: Some(chat_name),
                channel: Some("telegram".to_string()),
                is_group: Some(is_group),
            })
            .await;

        if !self.host.registered_groups().contains_key(&chat_jid) {
            debug!(chat_jid, "Message from unregistered Telegram chat");
            return;
        }

        let (reply_id, reply_content, reply_sender) = Self::reply_fields(msg);
        let length = content.chars().count();
        self.host
            .on_message(
                &chat_jid,
                NewMessage {
                    id: msg.message_id.to_string(),
                    chat_jid: chat_jid.clone(),
                    sender,
                    sender_name,
                    content,
                    timestamp,
                    is_from_me: false,
                    is_bot_message: false,
                    thread_id: Self::thread_id(msg),
                    reply_to_message_id: reply_id,
                    reply_to_message_content: reply_content,
                    reply_to_sender_name: reply_sender,
                },
            )
            .await;
        info!(chat_jid, length, "Telegram message stored");
    }

    async fn store_non_text(&self, msg: &Message, placeholder: &str) {
        let chat_jid = format!("{TELEGRAM_JID_PREFIX}{}", msg.chat.id);
        if !self.host.registered_groups().contains_key(&chat_jid) {
            return;
        }
        let timestamp = unix_to_iso(msg.date);
        let content = match msg.caption.as_deref().filter(|c| !c.is_empty()) {
            Some(caption) => format!("{placeholder} {caption}"),
            None => placeholder.to_string(),
        };
        self.host
            .on_chat_metadata(ChatMetadata {
                chat_jid: chat_jid.clone(),
                timestamp: timestamp.clone(),
                name: None,
                channel: Some("telegram".to_string()),
                is_group: Some(is_group_chat(&msg.chat.kind)),
            })
            .await;
        let (reply_id, reply_content, reply_sender) = Self::reply_fields(msg);
        self.host
            .on_message(
                &chat_jid,
                NewMessage {
                    id: msg.message_id.to_string(),
                    chat_jid: chat_jid.clone(),
                    sender: msg
                        .from
                        .as_ref()
                        .map(|u| u.id.to_string())
                        .unwrap_or_default(),
                    sender_name: sender_name(msg.from.as_ref()),
                    content,
                    timestamp,
                    is_from_me: false,
                    is_bot_message: false,
                    thread_id: Self::thread_id(msg),
                    reply_to_message_id: reply_id,
                    reply_to_message_content: reply_content,
                    reply_to_sender_name: reply_sender,
                },
            )
            .await;
    }

    async fn answer_command(&self, name: &str, msg: &Message) {
        let chat_id = msg.chat.id.to_string();
        let thread = if msg.is_topic_message == Some(true) {
            msg.message_thread_id
        } else {
            None
        };
        let result = match name {
            "chatid" => {
                let chat_name = if msg.chat.kind == "private" {
                    msg.from
                        .as_ref()
                        .and_then(|u| u.first_name.clone())
                        .filter(|n| !n.is_empty())
                        .unwrap_or_else(|| "Private".to_string())
                } else {
                    msg.chat
                        .title
                        .clone()
                        .filter(|t| !t.is_empty())
                        .unwrap_or_else(|| "Unknown".to_string())
                };
                let reply = format!(
                    "Chat ID: `{TELEGRAM_JID_PREFIX}{}`\nName: {chat_name}\nType: {}",
                    msg.chat.id, msg.chat.kind
                );
                self.send_text(&chat_id, &reply, thread).await
            }
            "ping" => {
                let reply = format!("{} is online.", self.assistant_name);
                self.send_with_retry(&chat_id, &reply, None, thread).await
            }
            _ => Ok(()),
        };
        if let Err(e) = result {
            warn!(command = name, err = %e, "Telegram: command reply failed");
        }
    }

    // ---- outbound ----------------------------------------------------------

    /// Send with Markdown, falling back to plain text when Telegram rejects
    /// the markup (HTTP 400).
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
        thread: Option<i64>,
    ) -> std::result::Result<(), ApiError> {
        match self
            .send_with_retry(chat_id, text, Some("Markdown"), thread)
            .await
        {
            Err(e) if e.status() == Some(400) => {
                debug!(err = %e, "Markdown send failed, falling back to plain text");
                self.send_with_retry(chat_id, text, None, thread).await
            }
            other => other,
        }
    }

    async fn send_with_retry(
        &self,
        chat_id: &str,
        text: &str,
        parse_mode: Option<&str>,
        thread: Option<i64>,
    ) -> std::result::Result<(), ApiError> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let err = match self
                .api
                .send_message(chat_id, text, parse_mode, thread)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };
            if let ApiError::Api {
                migrate_to_chat_id: Some(new_id),
                ..
            } = &err
            {
                warn!(
                    new_jid = %format!("{TELEGRAM_JID_PREFIX}{new_id}"),
                    "Telegram chat was migrated to a supergroup; re-register the new JID"
                );
            }
            let delay = match &err {
                ApiError::Api {
                    status: 429,
                    retry_after,
                    ..
                } => Some(Duration::from_secs(retry_after.unwrap_or(1)).min(MAX_RETRY_AFTER)),
                ApiError::Api {
                    status: 502..=504, ..
                }
                | ApiError::Transport { connect: true, .. } => Some(backoff_delay(
                    attempt,
                    self.error_backoff_base,
                    self.error_backoff_max,
                )),
                _ => None,
            };
            match delay {
                Some(delay) if attempt < MAX_SEND_ATTEMPTS => {
                    debug!(err = %err, attempt, "Telegram send failed, retrying");
                    tokio::time::sleep(delay).await;
                }
                _ => return Err(err),
            }
        }
    }
}

#[cfg(test)]
mod tests;
