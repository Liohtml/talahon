//! Chats (metadata only, for group discovery) and stored messages.

use rusqlite::{Connection, OptionalExtension, Row, params};
use talon_core::time::{now_iso, parse_iso, to_iso};
use talon_core::types::{ChatInfo, ChatMetadata, NewMessage};
use talon_core::{Error, Result};

use crate::{DEFAULT_MESSAGE_LIMIT, Db, SqlResultExt, bot_prefix_pattern, col, sql_limit};

/// Sentinel `chats` row that stores the last group-metadata sync time
/// (same as in earlier releases). Never returned by [`Db::get_all_chats`].
pub(crate) const GROUP_SYNC_JID: &str = "__group_sync__";

fn chat_from_row(row: &Row<'_>) -> rusqlite::Result<ChatInfo> {
    let jid = col::text(row, "jid")?;
    let name = col::opt_text(row, "name")?
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| jid.clone());
    Ok(ChatInfo {
        name,
        last_message_time: col::text(row, "last_message_time")?,
        channel: col::opt_text(row, "channel")?,
        is_group: col::flag(row, "is_group")?,
        jid,
    })
}

fn message_from_row(row: &Row<'_>) -> rusqlite::Result<NewMessage> {
    Ok(NewMessage {
        id: col::text(row, "id")?,
        chat_jid: col::text(row, "chat_jid")?,
        sender: col::text(row, "sender")?,
        sender_name: col::text(row, "sender_name")?,
        content: col::text(row, "content")?,
        timestamp: col::text(row, "timestamp")?,
        is_from_me: col::flag(row, "is_from_me")?,
        is_bot_message: col::flag(row, "is_bot_message")?,
        thread_id: col::opt_text(row, "thread_id")?,
        reply_to_message_id: col::opt_text(row, "reply_to_message_id")?,
        reply_to_message_content: col::opt_text(row, "reply_to_message_content")?,
        reply_to_sender_name: col::opt_text(row, "reply_to_sender_name")?,
    })
}

fn require_jid(jid: &str) -> Result<()> {
    if jid.is_empty() {
        Err(Error::invalid("chat jid must not be empty"))
    } else {
        Ok(())
    }
}

/// The timestamp to store `msg` with (see [`Db::store_message`]): the stored
/// one for a message already present, else its own time when that is later
/// than every stored message, else 1 ms after the latest stored message.
/// Times that are not RFC 3339 are stored as given.
fn storage_timestamp(conn: &Connection, msg: &NewMessage) -> Result<String> {
    let stored: Option<String> = conn
        .prepare_cached("SELECT timestamp FROM messages WHERE id = ?1 AND chat_jid = ?2")
        .db()?
        .query_row(params![msg.id, msg.chat_jid], |row| row.get(0))
        .optional()
        .db()?;
    if let Some(stored) = stored {
        return Ok(stored);
    }
    let Some(own) = parse_iso(&msg.timestamp) else {
        return Ok(msg.timestamp.clone());
    };
    let latest: Option<String> = conn
        .prepare_cached("SELECT MAX(timestamp) FROM messages")
        .db()?
        .query_row([], |row| row.get(0))
        .db()?;
    Ok(match latest.as_deref().and_then(parse_iso) {
        Some(latest) if own <= latest => to_iso(latest + chrono::Duration::milliseconds(1)),
        _ => to_iso(own),
    })
}

impl Db {
    // ---- chats -----------------------------------------------------------

    /// Store chat metadata only (no message content). Used for every chat a
    /// channel sees, to enable group discovery.
    ///
    /// With a non-empty `name` the stored name is replaced; without one the
    /// JID becomes the name of a new chat and an existing name is kept. The
    /// stored `last_message_time` only ever moves forward; `channel` and
    /// `is_group` are only overwritten by non-`None` values.
    pub fn store_chat_metadata(&self, meta: &ChatMetadata) -> Result<()> {
        require_jid(&meta.chat_jid)?;
        let name = meta.name.as_deref().filter(|n| !n.is_empty());
        let is_group = meta.is_group.map(i64::from);
        self.with_conn(|conn| {
            // MAX() with a NULL argument is NULL in SQLite, so legacy rows
            // with a NULL time are coalesced first (otherwise they would
            // never be updated).
            if let Some(name) = name {
                conn.prepare_cached(
                    "INSERT INTO chats (jid, name, last_message_time, channel, is_group)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(jid) DO UPDATE SET
                       name = excluded.name,
                       last_message_time = MAX(COALESCE(last_message_time, ''), excluded.last_message_time),
                       channel = COALESCE(excluded.channel, channel),
                       is_group = COALESCE(excluded.is_group, is_group)",
                )
                .db()?
                .execute(params![
                    meta.chat_jid,
                    name,
                    meta.timestamp,
                    meta.channel,
                    is_group
                ])
                .db()?;
            } else {
                conn.prepare_cached(
                    "INSERT INTO chats (jid, name, last_message_time, channel, is_group)
                     VALUES (?1, ?1, ?2, ?3, ?4)
                     ON CONFLICT(jid) DO UPDATE SET
                       last_message_time = MAX(COALESCE(last_message_time, ''), excluded.last_message_time),
                       channel = COALESCE(excluded.channel, channel),
                       is_group = COALESCE(excluded.is_group, is_group)",
                )
                .db()?
                .execute(params![meta.chat_jid, meta.timestamp, meta.channel, is_group])
                .db()?;
            }
            Ok(())
        })
    }

    /// Update a chat's name without touching its timestamp. New chats get
    /// the current time as their initial timestamp (group metadata sync).
    pub fn update_chat_name(&self, chat_jid: &str, name: &str) -> Result<()> {
        require_jid(chat_jid)?;
        self.with_conn(|conn| {
            conn.prepare_cached(
                "INSERT INTO chats (jid, name, last_message_time) VALUES (?1, ?2, ?3)
                 ON CONFLICT(jid) DO UPDATE SET name = excluded.name",
            )
            .db()?
            .execute(params![chat_jid, name, now_iso()])
            .db()?;
            Ok(())
        })
    }

    /// All known chats, most recent activity first. The internal
    /// group-sync sentinel row is excluded. A NULL name reads as the JID.
    pub fn get_all_chats(&self) -> Result<Vec<ChatInfo>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT jid, name, last_message_time, channel, is_group
                     FROM chats WHERE jid != ?1
                     ORDER BY last_message_time DESC",
                )
                .db()?;
            let rows = stmt
                .query_map([GROUP_SYNC_JID], chat_from_row)
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })
    }

    /// A single chat, if known.
    pub fn get_chat(&self, chat_jid: &str) -> Result<Option<ChatInfo>> {
        if chat_jid == GROUP_SYNC_JID {
            return Ok(None);
        }
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT jid, name, last_message_time, channel, is_group
                     FROM chats WHERE jid = ?1",
                )
                .db()?;
            let mut rows = stmt.query_map([chat_jid], chat_from_row).db()?;
            rows.next().transpose().db()
        })
    }

    /// Timestamp of the last group metadata sync.
    pub fn get_last_group_sync(&self) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT last_message_time FROM chats WHERE jid = ?1")
                .db()?;
            let mut rows = stmt
                .query_map([GROUP_SYNC_JID], |r| col::opt_text(r, "last_message_time"))
                .db()?;
            Ok(rows
                .next()
                .transpose()
                .db()?
                .flatten()
                .filter(|s| !s.is_empty()))
        })
    }

    /// Record that group metadata was synced (now).
    pub fn set_last_group_sync(&self) -> Result<()> {
        self.with_conn(|conn| {
            conn.prepare_cached(
                "INSERT INTO chats (jid, name, last_message_time) VALUES (?1, ?1, ?2)
                 ON CONFLICT(jid) DO UPDATE SET last_message_time = excluded.last_message_time",
            )
            .db()?
            .execute(params![GROUP_SYNC_JID, now_iso()])
            .db()?;
            Ok(())
        })
    }

    // ---- messages --------------------------------------------------------

    /// Insert or replace (idempotent on `(id, chat_jid)`).
    ///
    /// The message cursors compare timestamps (`timestamp > cursor`), so a
    /// new message is stored after every message already stored: one whose
    /// time is not later than the latest (a Telegram message, whose time has
    /// whole-second precision, arriving in the same second as another or
    /// after a message from another channel) is stored 1 ms after the latest
    /// instead. Otherwise a cursor that already passed its time would skip
    /// it for good. A message stored again keeps its first timestamp, so a
    /// redelivery is not processed twice.
    ///
    /// The chat row must exist (`messages.chat_jid` is a foreign key into
    /// `chats`); call [`Db::store_chat_metadata`] first.
    pub fn store_message(&self, msg: &NewMessage) -> Result<()> {
        self.with_tx(true, |conn| {
            let timestamp = storage_timestamp(conn, msg)?;
            conn.prepare_cached(
                "INSERT OR REPLACE INTO messages (id, chat_jid, sender, sender_name, content,
                   timestamp, is_from_me, is_bot_message, thread_id, reply_to_message_id,
                   reply_to_message_content, reply_to_sender_name)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .db()?
            .execute(params![
                msg.id,
                msg.chat_jid,
                msg.sender,
                msg.sender_name,
                msg.content,
                timestamp,
                i64::from(msg.is_from_me),
                i64::from(msg.is_bot_message),
                msg.thread_id,
                msg.reply_to_message_id,
                msg.reply_to_message_content,
                msg.reply_to_sender_name,
            ])
            .db()?;
            Ok(())
        })
    }

    /// Messages newer than `since` across `jids`, excluding the assistant's
    /// own messages: `is_bot_message`, or (stored by releases that had no
    /// such flag) sent from the assistant's own account and prefixed
    /// `"{bot_prefix}:"`. A user's message that starts with the prefix
    /// ("Talon: show open alerts") is kept.
    /// Returns the messages (oldest first) and the new high-water timestamp.
    ///
    /// At most [`DEFAULT_MESSAGE_LIMIT`] (the most recent) are returned; see
    /// [`Db::get_new_messages_limited`].
    pub fn get_new_messages(
        &self,
        jids: &[String],
        since: &str,
        bot_prefix: &str,
    ) -> Result<(Vec<NewMessage>, String)> {
        self.get_new_messages_limited(jids, since, bot_prefix, DEFAULT_MESSAGE_LIMIT)
    }

    /// [`Db::get_new_messages`] with an explicit cap: the `limit` most recent
    /// matching messages, returned oldest first.
    pub fn get_new_messages_limited(
        &self,
        jids: &[String],
        since: &str,
        bot_prefix: &str,
        limit: usize,
    ) -> Result<(Vec<NewMessage>, String)> {
        if jids.is_empty() {
            return Ok((Vec::new(), since.to_string()));
        }
        // The JID list is bound as one JSON array parameter, so the statement
        // text is constant (cacheable, no variable-count placeholders).
        let jids_json = serde_json::to_string(jids)?;
        let messages = self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    r"SELECT * FROM (
                        SELECT rowid AS rid, id, chat_jid, sender, sender_name, content, timestamp,
                               is_from_me, is_bot_message, thread_id, reply_to_message_id,
                               reply_to_message_content, reply_to_sender_name
                        FROM messages
                        WHERE timestamp > ?1 AND chat_jid IN (SELECT value FROM json_each(?2))
                          AND COALESCE(is_bot_message, 0) = 0
                          AND NOT (COALESCE(is_from_me, 0) = 1 AND content LIKE ?3 ESCAPE '\')
                          AND content != '' AND content IS NOT NULL
                        ORDER BY timestamp DESC, rid DESC
                        LIMIT ?4
                      ) ORDER BY timestamp, rid",
                )
                .db()?;
            let rows = stmt
                .query_map(
                    params![
                        since,
                        jids_json,
                        bot_prefix_pattern(bot_prefix),
                        sql_limit(limit)
                    ],
                    message_from_row,
                )
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })?;
        let new_ts = messages
            .iter()
            .map(|m| m.timestamp.as_str())
            .fold(since, |acc, ts| if ts > acc { ts } else { acc })
            .to_string();
        Ok((messages, new_ts))
    }

    /// Up to `limit` most recent non-bot messages in `chat_jid` newer than
    /// `since` (see [`Db::get_new_messages`]), returned oldest first.
    pub fn get_messages_since(
        &self,
        chat_jid: &str,
        since: &str,
        bot_prefix: &str,
        limit: usize,
    ) -> Result<Vec<NewMessage>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    r"SELECT * FROM (
                        SELECT rowid AS rid, id, chat_jid, sender, sender_name, content, timestamp,
                               is_from_me, is_bot_message, thread_id, reply_to_message_id,
                               reply_to_message_content, reply_to_sender_name
                        FROM messages
                        WHERE chat_jid = ?1 AND timestamp > ?2
                          AND COALESCE(is_bot_message, 0) = 0
                          AND NOT (COALESCE(is_from_me, 0) = 1 AND content LIKE ?3 ESCAPE '\')
                          AND content != '' AND content IS NOT NULL
                        ORDER BY timestamp DESC, rid DESC
                        LIMIT ?4
                      ) ORDER BY timestamp, rid",
                )
                .db()?;
            let rows = stmt
                .query_map(
                    params![
                        chat_jid,
                        since,
                        bot_prefix_pattern(bot_prefix),
                        sql_limit(limit)
                    ],
                    message_from_row,
                )
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })
    }

    /// Timestamp of the assistant's most recent message in `chat_jid`
    /// (`is_bot_message`, or sent from its own account and prefixed
    /// `"{bot_prefix}:"`). Used to recover the agent cursor when it was lost.
    pub fn get_last_bot_message_timestamp(
        &self,
        chat_jid: &str,
        bot_prefix: &str,
    ) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    r"SELECT MAX(timestamp) AS ts FROM messages
                      WHERE chat_jid = ?1
                        AND (is_bot_message = 1 OR (is_from_me = 1 AND content LIKE ?2 ESCAPE '\'))",
                )
                .db()?;
            stmt.query_row(params![chat_jid, bot_prefix_pattern(bot_prefix)], |r| {
                col::opt_text(r, "ts")
            })
            .db()
        })
    }

    /// Retention: delete messages older than `before_iso`. Returns rows removed.
    pub fn prune_messages_before(&self, before_iso: &str) -> Result<usize> {
        self.with_conn(|conn| {
            conn.prepare_cached("DELETE FROM messages WHERE timestamp < ?1")
                .db()?
                .execute([before_iso])
                .db()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Db {
        Db::open_in_memory().unwrap()
    }

    fn meta(jid: &str, ts: &str) -> ChatMetadata {
        ChatMetadata {
            chat_jid: jid.into(),
            timestamp: ts.into(),
            ..Default::default()
        }
    }

    fn named(jid: &str, ts: &str, name: &str) -> ChatMetadata {
        ChatMetadata {
            name: Some(name.into()),
            ..meta(jid, ts)
        }
    }

    /// Store one message with the given fields.
    fn store(db: &Db, id: &str, jid: &str, sender: &str, name: &str, content: &str, ts: &str) {
        db.store_message(&NewMessage {
            id: id.into(),
            chat_jid: jid.into(),
            sender: sender.into(),
            sender_name: name.into(),
            content: content.into(),
            timestamp: ts.into(),
            ..Default::default()
        })
        .unwrap();
    }

    fn store_bot(db: &Db, id: &str, jid: &str, content: &str, ts: &str) {
        db.store_message(&NewMessage {
            id: id.into(),
            chat_jid: jid.into(),
            sender: "Bot@s.whatsapp.net".into(),
            sender_name: "Bot".into(),
            content: content.into(),
            timestamp: ts.into(),
            is_bot_message: true,
            ..Default::default()
        })
        .unwrap();
    }

    const T0: &str = "2024-01-01T00:00:00.000Z";

    // --- storeMessage ---

    #[test]
    fn stores_a_message_and_retrieves_it() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        store(
            &db,
            "msg-1",
            "group@g.us",
            "123@s.whatsapp.net",
            "Alice",
            "hello world",
            "2024-01-01T00:00:01.000Z",
        );
        let m = db
            .get_messages_since("group@g.us", T0, "Talon", 200)
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].id, "msg-1");
        assert_eq!(m[0].sender, "123@s.whatsapp.net");
        assert_eq!(m[0].sender_name, "Alice");
        assert_eq!(m[0].content, "hello world");
    }

    #[test]
    fn same_second_message_after_the_cursor_is_not_skipped() {
        // Telegram times have whole-second precision: two messages in the
        // same second share a time. The cursor moved to the first one before
        // the second was stored.
        let db = db();
        db.store_chat_metadata(&meta("tg:1", T0)).unwrap();
        let jids = vec!["tg:1".to_string()];
        store(
            &db,
            "1",
            "tg:1",
            "u",
            "U",
            "part one",
            "2024-01-01T10:00:05.000Z",
        );
        let (first, cursor) = db.get_new_messages(&jids, T0, "Talon").unwrap();
        assert_eq!(first.len(), 1);
        store(
            &db,
            "2",
            "tg:1",
            "u",
            "U",
            "part two",
            "2024-01-01T10:00:05.000Z",
        );
        let (second, _) = db.get_new_messages(&jids, &cursor, "Talon").unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].content, "part two");
        assert_eq!(second[0].timestamp, "2024-01-01T10:00:05.001Z");
    }

    #[test]
    fn late_message_from_another_channel_is_not_skipped() {
        // An HTTP message (host time, ms precision) moved the shared cursor
        // past the time of a Telegram message that is stored afterwards.
        let db = db();
        db.store_chat_metadata(&meta("http:a", T0)).unwrap();
        db.store_chat_metadata(&meta("tg:1", T0)).unwrap();
        let jids = vec!["http:a".to_string(), "tg:1".to_string()];
        store(
            &db,
            "h1",
            "http:a",
            "u",
            "U",
            "from http",
            "2024-01-01T12:00:00.900Z",
        );
        let (_, cursor) = db.get_new_messages(&jids, T0, "Talon").unwrap();
        store(
            &db,
            "t1",
            "tg:1",
            "u",
            "U",
            "from telegram",
            "2024-01-01T12:00:00.000Z",
        );
        let (late, _) = db.get_new_messages(&jids, &cursor, "Talon").unwrap();
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].content, "from telegram");
        assert!(
            db.get_messages_since("tg:1", &cursor, "Talon", 10)
                .unwrap()
                .len()
                == 1
        );
    }

    #[test]
    fn redelivered_message_keeps_its_time() {
        let db = db();
        db.store_chat_metadata(&meta("tg:1", T0)).unwrap();
        let jids = vec!["tg:1".to_string()];
        store(
            &db,
            "1",
            "tg:1",
            "u",
            "U",
            "hello",
            "2024-01-01T10:00:05.000Z",
        );
        store(
            &db,
            "2",
            "tg:1",
            "u",
            "U",
            "later",
            "2024-01-01T10:00:09.000Z",
        );
        let (_, cursor) = db.get_new_messages(&jids, T0, "Talon").unwrap();
        store(
            &db,
            "1",
            "tg:1",
            "u",
            "U",
            "hello",
            "2024-01-01T10:00:05.000Z",
        );
        let (again, _) = db.get_new_messages(&jids, &cursor, "Talon").unwrap();
        assert!(again.is_empty(), "redelivery processed twice: {again:?}");
    }

    #[test]
    fn filters_out_empty_content() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        store(
            &db,
            "msg-2",
            "group@g.us",
            "111@s.whatsapp.net",
            "Dave",
            "",
            "2024-01-01T00:00:04.000Z",
        );
        let m = db
            .get_messages_since("group@g.us", T0, "Talon", 200)
            .unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn stores_is_from_me_flag() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        db.store_message(&NewMessage {
            id: "msg-3".into(),
            chat_jid: "group@g.us".into(),
            sender: "me@s.whatsapp.net".into(),
            sender_name: "Me".into(),
            content: "my message".into(),
            timestamp: "2024-01-01T00:00:05.000Z".into(),
            is_from_me: true,
            ..Default::default()
        })
        .unwrap();
        let m = db
            .get_messages_since("group@g.us", T0, "Talon", 200)
            .unwrap();
        assert_eq!(m.len(), 1);
        assert!(m[0].is_from_me);
    }

    #[test]
    fn upserts_on_duplicate_id_and_chat_jid() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        let ts = "2024-01-01T00:00:01.000Z";
        store(&db, "msg-dup", "group@g.us", "123", "Alice", "original", ts);
        store(&db, "msg-dup", "group@g.us", "123", "Alice", "updated", ts);
        let m = db
            .get_messages_since("group@g.us", T0, "Talon", 200)
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].content, "updated");
    }

    #[test]
    fn thread_id_round_trips() {
        let db = db();
        db.store_chat_metadata(&meta("tg:1", T0)).unwrap();
        db.store_message(&NewMessage {
            id: "1".into(),
            chat_jid: "tg:1".into(),
            content: "in a topic".into(),
            timestamp: "2024-01-01T00:00:01.000Z".into(),
            thread_id: Some("77".into()),
            ..Default::default()
        })
        .unwrap();
        let m = db.get_messages_since("tg:1", "", "Talon", 10).unwrap();
        assert_eq!(m[0].thread_id.as_deref(), Some("77"));
    }

    // --- reply context ---

    #[test]
    fn stores_and_retrieves_reply_to_fields() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        db.store_message(&NewMessage {
            id: "reply-1".into(),
            chat_jid: "group@g.us".into(),
            sender: "123".into(),
            sender_name: "Alice".into(),
            content: "Yes, on my way!".into(),
            timestamp: "2024-01-01T00:00:01.000Z".into(),
            reply_to_message_id: Some("42".into()),
            reply_to_message_content: Some("Are you coming tonight?".into()),
            reply_to_sender_name: Some("Bob".into()),
            ..Default::default()
        })
        .unwrap();
        let m = db
            .get_messages_since("group@g.us", T0, "Talon", 200)
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].reply_to_message_id.as_deref(), Some("42"));
        assert_eq!(
            m[0].reply_to_message_content.as_deref(),
            Some("Are you coming tonight?")
        );
        assert_eq!(m[0].reply_to_sender_name.as_deref(), Some("Bob"));
    }

    #[test]
    fn returns_none_for_messages_without_reply_context() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        store(
            &db,
            "no-reply",
            "group@g.us",
            "123",
            "Alice",
            "Just a normal message",
            "2024-01-01T00:00:01.000Z",
        );
        let m = db
            .get_messages_since("group@g.us", T0, "Talon", 200)
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].reply_to_message_id, None);
        assert_eq!(m[0].reply_to_message_content, None);
        assert_eq!(m[0].reply_to_sender_name, None);
    }

    #[test]
    fn retrieves_reply_context_via_get_new_messages() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        db.store_message(&NewMessage {
            id: "reply-2".into(),
            chat_jid: "group@g.us".into(),
            sender: "456".into(),
            sender_name: "Carol".into(),
            content: "Agreed".into(),
            timestamp: "2024-01-01T00:00:01.000Z".into(),
            reply_to_message_id: Some("99".into()),
            reply_to_message_content: Some("We should meet".into()),
            reply_to_sender_name: Some("Dave".into()),
            ..Default::default()
        })
        .unwrap();
        let (m, _) = db
            .get_new_messages(&["group@g.us".to_string()], T0, "Talon")
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].reply_to_message_id.as_deref(), Some("99"));
        assert_eq!(m[0].reply_to_sender_name.as_deref(), Some("Dave"));
    }

    // --- getMessagesSince ---

    fn since_fixture() -> Db {
        since_fixture_after(|_| {})
    }

    /// [`since_fixture`] with `history` stored first: messages arrive in
    /// insertion order, so older history has to be stored before.
    fn since_fixture_after(history: impl FnOnce(&Db)) -> Db {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        history(&db);
        store(
            &db,
            "m1",
            "group@g.us",
            "Alice@s.whatsapp.net",
            "Alice",
            "first",
            "2024-01-01T00:00:01.000Z",
        );
        store(
            &db,
            "m2",
            "group@g.us",
            "Bob@s.whatsapp.net",
            "Bob",
            "second",
            "2024-01-01T00:00:02.000Z",
        );
        store_bot(
            &db,
            "m3",
            "group@g.us",
            "bot reply",
            "2024-01-01T00:00:03.000Z",
        );
        store(
            &db,
            "m4",
            "group@g.us",
            "Carol@s.whatsapp.net",
            "Carol",
            "third",
            "2024-01-01T00:00:04.000Z",
        );
        db
    }

    #[test]
    fn returns_messages_after_the_given_timestamp() {
        let db = since_fixture();
        let m = db
            .get_messages_since("group@g.us", "2024-01-01T00:00:02.000Z", "Talon", 200)
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].content, "third");
    }

    #[test]
    fn excludes_bot_messages_via_is_bot_message_flag() {
        let db = since_fixture();
        let m = db
            .get_messages_since("group@g.us", T0, "Talon", 200)
            .unwrap();
        assert!(m.iter().all(|m| m.content != "bot reply"));
    }

    #[test]
    fn returns_all_non_bot_messages_when_since_is_empty() {
        let db = since_fixture();
        let m = db
            .get_messages_since("group@g.us", "", "Talon", 200)
            .unwrap();
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn recovers_cursor_from_last_bot_reply() {
        let db = since_fixture_after(|db| {
            for i in 1..=50 {
                store(
                    db,
                    &format!("history-{i}"),
                    "group@g.us",
                    "user@s.whatsapp.net",
                    "User",
                    &format!("old message {i}"),
                    &format!("2023-06-{i:02}T12:00:00.000Z"),
                );
            }
        });
        store(
            &db,
            "new-1",
            "group@g.us",
            "user@s.whatsapp.net",
            "User",
            "new message after bot reply",
            "2024-01-02T00:00:00.000Z",
        );
        let recovered = db
            .get_last_bot_message_timestamp("group@g.us", "Talon")
            .unwrap();
        assert_eq!(recovered.as_deref(), Some("2024-01-01T00:00:03.000Z"));
        let m = db
            .get_messages_since("group@g.us", recovered.as_deref().unwrap(), "Talon", 10)
            .unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].content, "third");
        assert_eq!(m[1].content, "new message after bot reply");
    }

    #[test]
    fn caps_messages_to_limit_even_with_recovered_cursor() {
        let db = since_fixture();
        for i in 1..=30 {
            store(
                &db,
                &format!("pending-{i}"),
                "group@g.us",
                "user@s.whatsapp.net",
                "User",
                &format!("pending message {i}"),
                &format!("2024-02-{i:02}T12:00:00.000Z"),
            );
        }
        let recovered = db
            .get_last_bot_message_timestamp("group@g.us", "Talon")
            .unwrap()
            .unwrap();
        assert_eq!(recovered, "2024-01-01T00:00:03.000Z");
        let m = db
            .get_messages_since("group@g.us", &recovered, "Talon", 10)
            .unwrap();
        assert_eq!(m.len(), 10);
        assert_eq!(m[0].content, "pending message 21");
        assert_eq!(m[9].content, "pending message 30");
    }

    #[test]
    fn returns_last_n_messages_when_no_bot_reply_and_no_cursor() {
        let db = since_fixture();
        db.store_chat_metadata(&meta("fresh@g.us", T0)).unwrap();
        for i in 1..=20 {
            store(
                &db,
                &format!("fresh-{i}"),
                "fresh@g.us",
                "user@s.whatsapp.net",
                "User",
                &format!("message {i}"),
                &format!("2024-02-{i:02}T12:00:00.000Z"),
            );
        }
        assert_eq!(
            db.get_last_bot_message_timestamp("fresh@g.us", "Talon")
                .unwrap(),
            None
        );
        let m = db
            .get_messages_since("fresh@g.us", "", "Talon", 10)
            .unwrap();
        assert_eq!(m.len(), 10);
        assert_eq!(m[0].content, "message 11");
        assert_eq!(m[9].content, "message 20");
    }

    #[test]
    fn filters_pre_migration_bot_messages_via_content_prefix() {
        let db = since_fixture();
        db.store_message(&NewMessage {
            id: "m5".into(),
            chat_jid: "group@g.us".into(),
            sender: "Bot@s.whatsapp.net".into(),
            sender_name: "Bot".into(),
            content: "Talon: old bot reply".into(),
            timestamp: "2024-01-01T00:00:05.000Z".into(),
            is_from_me: true,
            ..Default::default()
        })
        .unwrap();
        let m = db
            .get_messages_since("group@g.us", "2024-01-01T00:00:04.000Z", "Talon", 200)
            .unwrap();
        assert!(m.is_empty());
        // ...and it counts as the last bot message.
        assert_eq!(
            db.get_last_bot_message_timestamp("group@g.us", "Talon")
                .unwrap()
                .as_deref(),
            Some("2024-01-01T00:00:05.000Z")
        );
    }

    #[test]
    fn bot_prefix_wildcards_are_literal() {
        let db = db();
        db.store_chat_metadata(&meta("c", T0)).unwrap();
        let own = |id: &str, content: &str, ts: &str| NewMessage {
            id: id.into(),
            chat_jid: "c".into(),
            sender: "me".into(),
            sender_name: "Me".into(),
            content: content.into(),
            timestamp: ts.into(),
            is_from_me: true,
            ..Default::default()
        };
        db.store_message(&own(
            "1",
            "Talon: not from T_lon",
            "2024-01-01T00:00:01.000Z",
        ))
        .unwrap();
        db.store_message(&own("2", "T_lon: from bot", "2024-01-01T00:00:02.000Z"))
            .unwrap();
        let m = db.get_messages_since("c", "", "T_lon", 10).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].id, "1");
        let m = db.get_messages_since("c", "", "%", 10).unwrap();
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn user_messages_starting_with_the_assistant_name_are_kept() {
        let db = db();
        db.store_chat_metadata(&meta("c", T0)).unwrap();
        store(
            &db,
            "1",
            "c",
            "u",
            "U",
            "Talon: show open alerts",
            "2024-01-01T00:00:01.000Z",
        );
        store(
            &db,
            "2",
            "c",
            "u",
            "U",
            "talon: and the closed ones",
            "2024-01-01T00:00:02.000Z",
        );
        let m = db.get_messages_since("c", "", "Talon", 10).unwrap();
        assert_eq!(m.len(), 2);
        let (m, _) = db.get_new_messages(&jids(&["c"]), "", "Talon").unwrap();
        assert_eq!(m.len(), 2);
        // ...and none of them counts as a bot reply for cursor recovery.
        assert_eq!(
            db.get_last_bot_message_timestamp("c", "Talon").unwrap(),
            None
        );
    }

    // --- getNewMessages ---

    fn new_fixture() -> Db {
        let db = db();
        db.store_chat_metadata(&meta("group1@g.us", T0)).unwrap();
        db.store_chat_metadata(&meta("group2@g.us", T0)).unwrap();
        store(
            &db,
            "a1",
            "group1@g.us",
            "user@s.whatsapp.net",
            "User",
            "g1 msg1",
            "2024-01-01T00:00:01.000Z",
        );
        store(
            &db,
            "a2",
            "group2@g.us",
            "user@s.whatsapp.net",
            "User",
            "g2 msg1",
            "2024-01-01T00:00:02.000Z",
        );
        store_bot(
            &db,
            "a3",
            "group1@g.us",
            "bot reply",
            "2024-01-01T00:00:03.000Z",
        );
        store(
            &db,
            "a4",
            "group1@g.us",
            "user@s.whatsapp.net",
            "User",
            "g1 msg2",
            "2024-01-01T00:00:04.000Z",
        );
        db
    }

    fn jids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn returns_new_messages_across_multiple_groups() {
        let db = new_fixture();
        let (m, ts) = db
            .get_new_messages(&jids(&["group1@g.us", "group2@g.us"]), T0, "Talon")
            .unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(ts, "2024-01-01T00:00:04.000Z");
    }

    #[test]
    fn get_new_messages_filters_by_timestamp() {
        let db = new_fixture();
        let (m, _) = db
            .get_new_messages(
                &jids(&["group1@g.us", "group2@g.us"]),
                "2024-01-01T00:00:02.000Z",
                "Talon",
            )
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].content, "g1 msg2");
    }

    #[test]
    fn get_new_messages_only_returns_requested_jids() {
        let db = new_fixture();
        let (m, ts) = db
            .get_new_messages(&jids(&["group2@g.us"]), T0, "Talon")
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].chat_jid, "group2@g.us");
        assert_eq!(ts, "2024-01-01T00:00:02.000Z");
    }

    #[test]
    fn returns_empty_for_no_registered_groups() {
        let db = new_fixture();
        let (m, ts) = db.get_new_messages(&[], "", "Talon").unwrap();
        assert!(m.is_empty());
        assert_eq!(ts, "");
    }

    #[test]
    fn new_timestamp_stays_put_without_messages() {
        let db = new_fixture();
        let since = "2030-01-01T00:00:00.000Z";
        let (m, ts) = db
            .get_new_messages(&jids(&["group1@g.us"]), since, "Talon")
            .unwrap();
        assert!(m.is_empty());
        assert_eq!(ts, since);
    }

    // --- storeChatMetadata ---

    #[test]
    fn stores_chat_with_jid_as_default_name() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        let chats = db.get_all_chats().unwrap();
        assert_eq!(chats.len(), 1);
        assert_eq!(chats[0].jid, "group@g.us");
        assert_eq!(chats[0].name, "group@g.us");
    }

    #[test]
    fn stores_chat_with_explicit_name() {
        let db = db();
        db.store_chat_metadata(&named("group@g.us", T0, "My Group"))
            .unwrap();
        assert_eq!(db.get_all_chats().unwrap()[0].name, "My Group");
    }

    #[test]
    fn updates_name_on_subsequent_call_with_name() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        db.store_chat_metadata(&named(
            "group@g.us",
            "2024-01-01T00:00:01.000Z",
            "Updated Name",
        ))
        .unwrap();
        let chats = db.get_all_chats().unwrap();
        assert_eq!(chats.len(), 1);
        assert_eq!(chats[0].name, "Updated Name");
    }

    #[test]
    fn preserves_newer_timestamp_on_conflict() {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", "2024-01-01T00:00:05.000Z"))
            .unwrap();
        db.store_chat_metadata(&meta("group@g.us", "2024-01-01T00:00:01.000Z"))
            .unwrap();
        assert_eq!(
            db.get_all_chats().unwrap()[0].last_message_time,
            "2024-01-01T00:00:05.000Z"
        );
    }

    #[test]
    fn keeps_name_channel_and_group_flag_when_not_given() {
        let db = db();
        db.store_chat_metadata(&ChatMetadata {
            chat_jid: "tg:-1".into(),
            timestamp: T0.into(),
            name: Some("Ops".into()),
            channel: Some("telegram".into()),
            is_group: Some(true),
        })
        .unwrap();
        db.store_chat_metadata(&meta("tg:-1", "2024-01-02T00:00:00.000Z"))
            .unwrap();
        let c = db.get_chat("tg:-1").unwrap().unwrap();
        assert_eq!(c.name, "Ops");
        assert_eq!(c.channel.as_deref(), Some("telegram"));
        assert!(c.is_group);
        assert_eq!(c.last_message_time, "2024-01-02T00:00:00.000Z");
    }

    #[test]
    fn null_timestamp_rows_are_updated() {
        let db = db();
        db.update_chat_name("x", "X").unwrap();
        db.with_conn(|c| {
            c.execute(
                "UPDATE chats SET last_message_time = NULL WHERE jid = 'x'",
                [],
            )
            .db()
        })
        .unwrap();
        db.store_chat_metadata(&meta("x", "2024-05-05T00:00:00.000Z"))
            .unwrap();
        assert_eq!(
            db.get_chat("x").unwrap().unwrap().last_message_time,
            "2024-05-05T00:00:00.000Z"
        );
    }

    #[test]
    fn empty_jid_is_rejected() {
        let db = db();
        assert!(matches!(
            db.store_chat_metadata(&meta("", T0)),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn update_chat_name_keeps_timestamp() {
        let db = db();
        db.store_chat_metadata(&meta("g@g.us", "2024-01-01T00:00:09.000Z"))
            .unwrap();
        db.update_chat_name("g@g.us", "Renamed").unwrap();
        let c = db.get_chat("g@g.us").unwrap().unwrap();
        assert_eq!(c.name, "Renamed");
        assert_eq!(c.last_message_time, "2024-01-01T00:00:09.000Z");
        // New chats get "now".
        db.update_chat_name("new@g.us", "New").unwrap();
        let n = db.get_chat("new@g.us").unwrap().unwrap();
        assert_eq!(n.last_message_time.len(), 24);
    }

    #[test]
    fn group_sync_sentinel_round_trip_and_hidden() {
        let db = db();
        assert_eq!(db.get_last_group_sync().unwrap(), None);
        db.set_last_group_sync().unwrap();
        let first = db.get_last_group_sync().unwrap().unwrap();
        assert!(talon_core::time::parse_iso(&first).is_some());
        db.set_last_group_sync().unwrap();
        assert!(db.get_all_chats().unwrap().is_empty());
        assert_eq!(db.get_chat(GROUP_SYNC_JID).unwrap(), None);
    }

    // --- LIMIT behaviour ---

    fn limit_fixture() -> Db {
        let db = db();
        db.store_chat_metadata(&meta("group@g.us", T0)).unwrap();
        for i in 1..=10 {
            store(
                &db,
                &format!("lim-{i}"),
                "group@g.us",
                "user@s.whatsapp.net",
                "User",
                &format!("message {i}"),
                &format!("2024-01-01T00:00:{i:02}.000Z"),
            );
        }
        db
    }

    #[test]
    fn get_new_messages_caps_to_limit_chronologically() {
        let db = limit_fixture();
        let (m, ts) = db
            .get_new_messages_limited(&jids(&["group@g.us"]), T0, "Talon", 3)
            .unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].content, "message 8");
        assert_eq!(m[2].content, "message 10");
        assert!(m[1].timestamp > m[0].timestamp);
        assert_eq!(ts, "2024-01-01T00:00:10.000Z");
    }

    #[test]
    fn get_messages_since_caps_to_limit_chronologically() {
        let db = limit_fixture();
        let m = db.get_messages_since("group@g.us", T0, "Talon", 3).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].content, "message 8");
        assert_eq!(m[2].content, "message 10");
        assert!(m[1].timestamp > m[0].timestamp);
    }

    #[test]
    fn returns_all_messages_when_count_is_under_limit() {
        let db = limit_fixture();
        let (m, _) = db
            .get_new_messages_limited(&jids(&["group@g.us"]), T0, "Talon", 50)
            .unwrap();
        assert_eq!(m.len(), 10);
    }

    // --- foreign key ---

    #[test]
    fn rejects_a_message_for_an_unknown_chat() {
        let db = db();
        let msg = NewMessage {
            id: "investigate-1".into(),
            chat_jid: "http:copilot:investigate".into(),
            sender: "copilot-webhook".into(),
            sender_name: "CoPilot".into(),
            content: "investigate alert 1".into(),
            timestamp: "100".into(),
            ..Default::default()
        };
        assert!(matches!(db.store_message(&msg), Err(Error::Db(_))));

        db.store_chat_metadata(&ChatMetadata {
            chat_jid: "http:copilot:investigate".into(),
            timestamp: "100".into(),
            name: Some("CoPilot Investigations".into()),
            channel: Some("http".into()),
            is_group: Some(false),
        })
        .unwrap();
        db.store_message(&msg).unwrap();
    }

    // --- retention ---

    #[test]
    fn prune_messages_before_removes_old_rows_only() {
        let db = limit_fixture();
        let n = db
            .prune_messages_before("2024-01-01T00:00:04.000Z")
            .unwrap();
        assert_eq!(n, 3);
        let m = db
            .get_messages_since("group@g.us", "", "Talon", 100)
            .unwrap();
        assert_eq!(m.len(), 7);
        assert_eq!(m[0].content, "message 4");
    }
}
