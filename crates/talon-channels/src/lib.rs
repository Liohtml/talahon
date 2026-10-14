//! # talon-channels — Telegram, webhook, Emacs channels
//!
//! **Owner: agent A12.** See `docs/RUST_ARCHITECTURE.md` §A12.
//!
//! [`talon_core::channel::Channel`] implementations built directly on
//! `reqwest` / `axum` (no bot framework):
//!
//! | Channel | JIDs | Enabled by |
//! |---|---|---|
//! | [`TelegramChannel`] | `tg:<chat id>` | `TELEGRAM_BOT_TOKEN` |
//! | [`EmacsBridgeChannel`] | `emacs:default` | `EMACS_AUTH_TOKEN` (+ `EMACS_CHANNEL_PORT`, default 8766) |
//! | [`WebhookChannel`] | `webhook:copilot` | `WEBHOOK_URL` (+ `WEBHOOK_SECRET`, `WEBHOOK_ALLOWED_HOSTS`, `WEBHOOK_LEGACY_BEARER`) |
//!
//! [`build_channels`] constructs every channel whose credentials are
//! configured. Secrets are read from `.env` first, then the process
//! environment, and are never logged.
//!
//! All channels follow the TypeScript contract that `send_message` does not
//! surface *delivery* failures as errors (they are logged, and audited when
//! security-relevant); `Err` is only returned for a JID the channel does not
//! own.

pub mod emacs;
pub mod security;
pub mod telegram;
mod util;
pub mod webhook;

use std::sync::Arc;

use talon_core::audit::SharedAuditSink;
use talon_core::channel::{Channel, ChannelHost};
use talon_core::env::EnvFile;
use tracing::{debug, warn};

pub use emacs::{EMACS_JID, EmacsBridgeChannel, EmacsConfig};
pub use security::{EgressGuard, PolicyEgressGuard};
pub use telegram::{TelegramChannel, TelegramConfig};
pub use webhook::{WEBHOOK_JID, WebhookChannel, WebhookConfig};

/// Build every channel whose credentials are configured, in the order the
/// TypeScript registry connected them (telegram, emacs, webhook).
///
/// Channels are returned unconnected; the host calls
/// [`Channel::connect`]. Invalid configurations are logged and skipped.
/// The webhook gets an egress guard built from `TALON_EGRESS_*`
/// ([`PolicyEgressGuard::from_env`]).
pub fn build_channels(
    host: Arc<dyn ChannelHost>,
    env: &EnvFile,
    audit: SharedAuditSink,
) -> Vec<Arc<dyn Channel>> {
    let mut channels: Vec<Arc<dyn Channel>> = Vec::new();

    match TelegramConfig::from_env(env) {
        Some(config) => match TelegramChannel::new(config, Arc::clone(&host)) {
            Ok(channel) => channels.push(Arc::new(channel)),
            Err(e) => warn!(err = %e, "Telegram channel not started"),
        },
        None => debug!("Telegram: TELEGRAM_BOT_TOKEN not set"),
    }

    match EmacsConfig::from_env(env) {
        Some(config) => {
            match EmacsBridgeChannel::new(config, Arc::clone(&host), Arc::clone(&audit)) {
                Ok(channel) => channels.push(Arc::new(channel)),
                Err(e) => warn!(err = %e, "Emacs bridge not started"),
            }
        }
        None => debug!("Emacs bridge: EMACS_AUTH_TOKEN not set"),
    }

    match WebhookConfig::from_env(env) {
        Some(config) => match WebhookChannel::new(config, Arc::clone(&host), Arc::clone(&audit)) {
            Ok(channel) => {
                let guard = Arc::new(PolicyEgressGuard::from_env(env));
                channels.push(Arc::new(channel.with_egress_guard(guard)));
            }
            Err(e) => warn!(err = %e, "Webhook channel not started"),
        },
        None => debug!("Webhook channel: WEBHOOK_URL not set"),
    }

    channels
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::RecordingHost;
    use talon_core::audit::MemoryAuditSink;

    fn names(channels: &[Arc<dyn Channel>]) -> Vec<String> {
        channels.iter().map(|c| c.name().to_string()).collect()
    }

    fn host() -> Arc<dyn ChannelHost> {
        Arc::new(RecordingHost::default())
    }

    fn audit() -> SharedAuditSink {
        Arc::new(MemoryAuditSink::default())
    }

    // Process env may carry these in CI; the tests below only use `.env`
    // content, so skip when the process env would interfere.
    fn process_env_clean() -> bool {
        [
            "TELEGRAM_BOT_TOKEN",
            "EMACS_AUTH_TOKEN",
            "EMACS_CHANNEL_PORT",
            "WEBHOOK_URL",
        ]
        .iter()
        .all(|k| std::env::var(k).map(|v| v.is_empty()).unwrap_or(true))
    }

    #[test]
    fn no_credentials_no_channels() {
        if !process_env_clean() {
            return;
        }
        let env = EnvFile::from_str_content("ASSISTANT_NAME=Andy\nEMACS_CHANNEL_PORT=9999\n");
        assert!(build_channels(host(), &env, audit()).is_empty());
    }

    #[test]
    fn telegram_and_emacs_from_env() {
        if !process_env_clean() {
            return;
        }
        let env = EnvFile::from_str_content(
            "TELEGRAM_BOT_TOKEN=123:abc\nEMACS_AUTH_TOKEN=0123456789abcdef0123\n",
        );
        let channels = build_channels(host(), &env, audit());
        assert_eq!(names(&channels), vec!["telegram", "emacs"]);
        assert!(channels[0].owns_jid("tg:1"));
        assert!(channels[1].owns_jid(EMACS_JID));
    }

    #[test]
    fn malformed_values_are_skipped() {
        if !process_env_clean() {
            return;
        }
        let env = EnvFile::from_str_content(
            "TELEGRAM_BOT_TOKEN=bad/token\nEMACS_AUTH_TOKEN=tok\nEMACS_CHANNEL_PORT=notaport\nWEBHOOK_URL=ftp://x\n",
        );
        assert!(build_channels(host(), &env, audit()).is_empty());
    }

    /// Uses the real `EgressPolicy::from_env`; panics (todo!()) until A07's
    /// `talon_security::egress` implementation lands.
    #[test]
    fn webhook_from_env_uses_real_egress_policy() {
        if !process_env_clean() {
            return;
        }
        let env = EnvFile::from_str_content(
            "WEBHOOK_URL=https://hooks.example.com/talon\nWEBHOOK_SECRET=s\n",
        );
        let channels = build_channels(host(), &env, audit());
        assert_eq!(names(&channels), vec!["webhook"]);
        assert!(channels[0].owns_jid(WEBHOOK_JID));
    }
}
