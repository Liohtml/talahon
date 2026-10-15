//! # talon-router — formatting, routing, session lanes & commands
//!
//! Pure, synchronous text processing plus two small async helpers:
//!
//! - [`format`] — inbound envelope: [`escape_xml`], [`format_messages`]
//!   (XML, timezone-aware times, reply context), [`format_local_time`].
//! - [`outbound`] — [`strip_internal_tags`], [`format_outbound`] (strip
//!   `<internal>` + Markdown -> channel dialect), [`find_channel`],
//!   [`route_outbound`], [`send_formatted`].
//! - [`styles`] — [`parse_text_styles`] (code regions protected),
//!   [`parse_signal_styles`] (Signal `textStyle` ranges), [`markdown_to_plain`].
//! - [`split`] — [`split_message`] / [`split_message_with`]: code-fence aware
//!   chunking that never splits a UTF-8 character (Telegram: 4096).
//! - [`session_commands`] — `/compact`, `/new` (`/reset`, `/clear`):
//!   [`extract_session_command`], [`is_session_command_allowed`],
//!   [`handle_session_command`] driven through the host-implemented
//!   [`SessionCommandDeps`] trait.
//! - [`lanes`] — lane keys ([`session_key_for`], [`ipc_key_for`],
//!   [`resumable_session_id`]), trigger gating ([`should_process`]) and the
//!   [`available_groups`] snapshot.

#![warn(missing_docs)]

pub mod format;
pub mod lanes;
pub mod outbound;
pub mod session_commands;
pub mod split;
pub mod styles;

pub use format::{escape_xml, format_local_time, format_messages, resolve_timezone};
pub use lanes::{
    GROUP_SYNC_SENTINEL, available_groups, has_trigger, ipc_key_for, resumable_session_id,
    session_key_for, should_persist_session, should_process, should_require_trigger,
    trigger_pattern_for,
};
pub use outbound::{
    find_channel, format_outbound, route_outbound, send_formatted, strip_internal_tags,
};
pub use session_commands::{
    AgentOutputHandler, SessionCommand, SessionCommandDeps, SessionCommandOutcome,
    SessionCommandRequest, extract_session_command, handle_session_command,
    is_session_command_allowed,
};
pub use split::{LengthUnit, TELEGRAM_MAX_MESSAGE_LEN, split_message, split_message_with};
pub use styles::{
    SignalStyle, SignalText, SignalTextStyle, markdown_to_plain, parse_signal_styles,
    parse_text_styles,
};
