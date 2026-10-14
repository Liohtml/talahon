//! Outbound text: `<internal>` stripping, channel-dialect formatting and
//! routing to the owning channel (port of `stripInternalTags`,
//! `formatOutbound`, `routeOutbound` and `findChannel` in `src/router.ts`).

use std::sync::Arc;

use talon_core::channel::{Channel, ChannelType};
use talon_core::{Error, Result};

use crate::styles::parse_text_styles;

const INTERNAL_OPEN: &str = "<internal>";
const INTERNAL_CLOSE: &str = "</internal>";

/// Remove every `<internal>…</internal>` block (the agent's private notes)
/// and trim the result.
///
/// Hardening over the TypeScript version: an *unterminated* `<internal>`
/// hides everything after it instead of leaking the agent's private notes
/// to the chat.
pub fn strip_internal_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        match rest.find(INTERNAL_OPEN) {
            Some(start) => {
                out.push_str(&rest[..start]);
                let after = &rest[start + INTERNAL_OPEN.len()..];
                match after.find(INTERNAL_CLOSE) {
                    Some(end) => rest = &after[end + INTERNAL_CLOSE.len()..],
                    None => break,
                }
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }
    out.trim().to_string()
}

/// Prepare agent output for delivery on a channel of type `channel`:
/// strip `<internal>` blocks, then convert Markdown to the channel dialect.
/// Returns an empty string when nothing is left to send.
pub fn format_outbound(raw_text: &str, channel: ChannelType) -> String {
    let text = strip_internal_tags(raw_text);
    if text.is_empty() {
        return String::new();
    }
    parse_text_styles(&text, channel)
}

/// The first channel that owns `jid` (connected or not).
pub fn find_channel<'a>(
    channels: &'a [Arc<dyn Channel>],
    jid: &str,
) -> Option<&'a Arc<dyn Channel>> {
    channels.iter().find(|c| c.owns_jid(jid))
}

/// Send already-formatted `text` to `jid` through the first *connected*
/// channel that owns it.
///
/// # Errors
/// [`Error::Channel`] when no connected channel owns `jid`, or whatever the
/// channel's `send_message` returns.
pub async fn route_outbound(channels: &[Arc<dyn Channel>], jid: &str, text: &str) -> Result<()> {
    let channel = channels
        .iter()
        .find(|c| c.owns_jid(jid) && c.is_connected())
        .ok_or_else(|| Error::Channel(format!("No channel for JID: {jid}")))?;
    channel.send_message(jid, text).await
}

/// Format raw agent output for the owning channel's dialect and send it.
///
/// Returns `Ok(false)` when the text was empty after stripping
/// `<internal>` blocks (nothing sent), `Ok(true)` when it was delivered.
///
/// # Errors
/// As [`route_outbound`].
pub async fn send_formatted(
    channels: &[Arc<dyn Channel>],
    jid: &str,
    raw_text: &str,
) -> Result<bool> {
    let channel = channels
        .iter()
        .find(|c| c.owns_jid(jid) && c.is_connected())
        .ok_or_else(|| Error::Channel(format!("No channel for JID: {jid}")))?;
    let text = format_outbound(raw_text, channel.channel_type());
    if text.is_empty() {
        return Ok(false);
    }
    channel.send_message(jid, &text).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;

    use super::*;

    // --- strip_internal_tags ------------------------------------------------

    #[test]
    fn strips_single_line_internal_tags() {
        assert_eq!(
            strip_internal_tags("hello <internal>secret</internal> world"),
            "hello  world"
        );
    }

    #[test]
    fn strips_multi_line_internal_tags() {
        assert_eq!(
            strip_internal_tags("hello <internal>\nsecret\nstuff\n</internal> world"),
            "hello  world"
        );
    }

    #[test]
    fn strips_multiple_internal_blocks() {
        assert_eq!(
            strip_internal_tags("<internal>a</internal>hello<internal>b</internal>"),
            "hello"
        );
    }

    #[test]
    fn only_internal_yields_empty() {
        assert_eq!(strip_internal_tags("<internal>only this</internal>"), "");
    }

    #[test]
    fn unterminated_internal_hides_the_rest() {
        assert_eq!(
            strip_internal_tags("visible <internal>private notes"),
            "visible"
        );
    }

    #[test]
    fn stray_closing_tag_is_kept() {
        assert_eq!(strip_internal_tags("a </internal> b"), "a </internal> b");
    }

    // --- format_outbound ----------------------------------------------------

    #[test]
    fn outbound_plain_markdown_passthrough() {
        assert_eq!(
            format_outbound("hello world", ChannelType::Markdown),
            "hello world"
        );
    }

    #[test]
    fn outbound_all_internal_is_empty() {
        assert_eq!(
            format_outbound("<internal>hidden</internal>", ChannelType::Markdown),
            ""
        );
    }

    #[test]
    fn outbound_strips_internal_from_remaining_text() {
        assert_eq!(
            format_outbound(
                "<internal>thinking</internal>The answer is 42",
                ChannelType::Markdown
            ),
            "The answer is 42"
        );
    }

    #[test]
    fn outbound_applies_channel_styles() {
        assert_eq!(format_outbound("**bold**", ChannelType::WhatsApp), "*bold*");
    }

    #[test]
    fn outbound_markdown_keeps_markers() {
        assert_eq!(
            format_outbound("**bold**", ChannelType::Markdown),
            "**bold**"
        );
    }

    #[test]
    fn outbound_strips_then_formats() {
        assert_eq!(
            format_outbound(
                "<internal>thinking</internal>**done**",
                ChannelType::Telegram
            ),
            "*done*"
        );
    }

    #[test]
    fn outbound_signal_is_passthrough() {
        assert_eq!(format_outbound("**bold**", ChannelType::Signal), "**bold**");
    }

    #[test]
    fn outbound_plain_strips_markup() {
        assert_eq!(
            format_outbound("**done** [x](https://y)", ChannelType::Plain),
            "done x (https://y)"
        );
    }

    // --- routing ------------------------------------------------------------

    struct MockChannel {
        name: &'static str,
        prefix: &'static str,
        kind: ChannelType,
        connected: AtomicBool,
        sent: Mutex<Vec<(String, String)>>,
    }

    impl MockChannel {
        fn new(
            name: &'static str,
            prefix: &'static str,
            kind: ChannelType,
            connected: bool,
        ) -> Arc<Self> {
            Arc::new(Self {
                name,
                prefix,
                kind,
                connected: AtomicBool::new(connected),
                sent: Mutex::new(Vec::new()),
            })
        }
        fn sent(&self) -> Vec<(String, String)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Channel for MockChannel {
        fn name(&self) -> &str {
            self.name
        }
        fn channel_type(&self) -> ChannelType {
            self.kind
        }
        async fn connect(&self) -> Result<()> {
            self.connected.store(true, Ordering::SeqCst);
            Ok(())
        }
        async fn send_message(&self, jid: &str, text: &str) -> Result<()> {
            self.sent
                .lock()
                .unwrap()
                .push((jid.to_string(), text.to_string()));
            Ok(())
        }
        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::SeqCst)
        }
        fn owns_jid(&self, jid: &str) -> bool {
            jid.starts_with(self.prefix)
        }
        async fn disconnect(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn find_channel_by_ownership() {
        let tg = MockChannel::new("telegram", "tg:", ChannelType::Telegram, false);
        let http = MockChannel::new("http", "http:", ChannelType::Markdown, true);
        let channels: Vec<Arc<dyn Channel>> = vec![tg, http];
        assert_eq!(
            find_channel(&channels, "tg:123").map(|c| c.name()),
            Some("telegram")
        );
        assert_eq!(
            find_channel(&channels, "http:copilot").map(|c| c.name()),
            Some("http")
        );
        assert!(find_channel(&channels, "12345678@g.us").is_none());
    }

    #[tokio::test]
    async fn route_outbound_requires_connected_owner() {
        let tg = MockChannel::new("telegram", "tg:", ChannelType::Telegram, false);
        let channels: Vec<Arc<dyn Channel>> = vec![tg.clone()];
        let err = route_outbound(&channels, "tg:1", "hi").await.unwrap_err();
        assert!(err.to_string().contains("No channel for JID: tg:1"));

        tg.connect().await.unwrap();
        route_outbound(&channels, "tg:1", "hi").await.unwrap();
        assert_eq!(tg.sent(), vec![("tg:1".to_string(), "hi".to_string())]);
    }

    #[tokio::test]
    async fn send_formatted_uses_channel_dialect() {
        let tg = MockChannel::new("telegram", "tg:", ChannelType::Telegram, true);
        let http = MockChannel::new("http", "http:", ChannelType::Markdown, true);
        let channels: Vec<Arc<dyn Channel>> = vec![tg.clone(), http.clone()];

        assert!(send_formatted(&channels, "tg:1", "**x**").await.unwrap());
        assert!(
            send_formatted(&channels, "http:copilot", "**x**")
                .await
                .unwrap()
        );
        assert!(
            !send_formatted(&channels, "tg:1", "<internal>n</internal>")
                .await
                .unwrap()
        );

        assert_eq!(tg.sent(), vec![("tg:1".to_string(), "*x*".to_string())]);
        assert_eq!(
            http.sent(),
            vec![("http:copilot".to_string(), "**x**".to_string())]
        );
    }
}
