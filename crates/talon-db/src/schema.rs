//! Schema creation and idempotent migrations.
//!
//! The base tables are the TypeScript `createSchema()` statements verbatim,
//! followed by the same `ALTER TABLE ... ADD COLUMN` migrations (and their
//! one-time backfills), so a database written by either implementation can
//! be opened by the other. Instead of TypeScript's "try ALTER, swallow the
//! error" pattern, columns are added only when `pragma_table_info` says they
//! are missing, and the whole migration runs in one `BEGIN IMMEDIATE`
//! transaction so concurrent openers cannot race.
//!
//! Additions of the Rust release (all invisible to the TypeScript code):
//! - `messages.thread_id`, `registered_groups.lane_config` (nullable)
//! - `idx_messages_chat_ts` (per-chat message queries)
//! - tables `audit_log` (+ append-only triggers), `investigations`,
//!   `ioc_sightings`, `task_owners`

use rusqlite::{Connection, Transaction, TransactionBehavior};
use talon_core::Result;

use crate::{DbOptions, SqlResultExt, bot_prefix_pattern};

/// The TypeScript base schema, verbatim (`src/db.ts` `createSchema`).
const TS_BASE_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS chats (
      jid TEXT PRIMARY KEY,
      name TEXT,
      last_message_time TEXT,
      channel TEXT,
      is_group INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT,
      chat_jid TEXT,
      sender TEXT,
      sender_name TEXT,
      content TEXT,
      timestamp TEXT,
      is_from_me INTEGER,
      is_bot_message INTEGER DEFAULT 0,
      PRIMARY KEY (id, chat_jid),
      FOREIGN KEY (chat_jid) REFERENCES chats(jid)
    );
    CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp);

    CREATE TABLE IF NOT EXISTS scheduled_tasks (
      id TEXT PRIMARY KEY,
      group_folder TEXT NOT NULL,
      chat_jid TEXT NOT NULL,
      prompt TEXT NOT NULL,
      schedule_type TEXT NOT NULL,
      schedule_value TEXT NOT NULL,
      next_run TEXT,
      last_run TEXT,
      last_result TEXT,
      status TEXT DEFAULT 'active',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_next_run ON scheduled_tasks(next_run);
    CREATE INDEX IF NOT EXISTS idx_status ON scheduled_tasks(status);

    CREATE TABLE IF NOT EXISTS task_run_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id TEXT NOT NULL,
      run_at TEXT NOT NULL,
      duration_ms INTEGER NOT NULL,
      status TEXT NOT NULL,
      result TEXT,
      error TEXT,
      FOREIGN KEY (task_id) REFERENCES scheduled_tasks(id)
    );
    CREATE INDEX IF NOT EXISTS idx_task_run_logs ON task_run_logs(task_id, run_at);

    CREATE TABLE IF NOT EXISTS router_state (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      group_folder TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      provider TEXT
    );
    CREATE TABLE IF NOT EXISTS registered_groups (
      jid TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      folder TEXT NOT NULL UNIQUE,
      trigger_pattern TEXT NOT NULL,
      added_at TEXT NOT NULL,
      container_config TEXT,
      requires_trigger INTEGER DEFAULT 1
    );
"#;

/// Tables and indexes introduced by the Rust release.
const RUST_SCHEMA: &str = r#"
    CREATE INDEX IF NOT EXISTS idx_messages_chat_ts ON messages(chat_jid, timestamp);

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      kind TEXT NOT NULL,
      actor TEXT NOT NULL,
      target TEXT,
      outcome TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT 'null',
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_kind ON audit_log(kind);
    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
    CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'audit_log is append-only');
    END;
    CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'audit_log is append-only');
    END;

    CREATE TABLE IF NOT EXISTS investigations (
      id TEXT PRIMARY KEY,
      alert_id TEXT NOT NULL,
      customer_code TEXT NOT NULL,
      triggered_by TEXT NOT NULL,
      status TEXT NOT NULL,
      template TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      verdict TEXT,
      error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_investigations_alert ON investigations(alert_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_investigations_created ON investigations(created_at);

    CREATE TABLE IF NOT EXISTS ioc_sightings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ioc_type TEXT NOT NULL,
      value TEXT NOT NULL,
      source_ref TEXT NOT NULL,
      customer_code TEXT,
      seen_at TEXT NOT NULL
    );
    -- Lookup index on (ioc_type, value); the trailing source_ref makes
    -- re-recording the same sighting idempotent.
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_sightings_type_value
      ON ioc_sightings(ioc_type, value, source_ref);
    CREATE INDEX IF NOT EXISTS idx_ioc_sightings_seen_at ON ioc_sightings(seen_at);

    -- Who created a scheduled task over IPC (the source lane's IPC key).
    -- Tasks without a row were created by the host (investigations, seeded
    -- tasks, rows that predate this table) and count as owned by `host`.
    -- Kept in a side table so the TypeScript `scheduled_tasks` shape is
    -- untouched; rows follow their task (ON DELETE CASCADE, and
    -- `Db::delete_task` / `Db::create_task` clear them explicitly for
    -- connections without foreign-key enforcement).
    CREATE TABLE IF NOT EXISTS task_owners (
      task_id TEXT PRIMARY KEY REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
      owner TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
"#;

/// A column added after a table's original `CREATE TABLE`.
struct ColumnMigration {
    table: &'static str,
    column: &'static str,
    definition: &'static str,
}

const fn col(
    table: &'static str,
    column: &'static str,
    definition: &'static str,
) -> ColumnMigration {
    ColumnMigration {
        table,
        column,
        definition,
    }
}

/// Columns that pre-date the migrations but are added defensively if a very
/// old database lacks them (the TypeScript code would have crashed on it).
const DEFENSIVE_COLUMNS: &[ColumnMigration] = &[
    col("registered_groups", "container_config", "TEXT"),
    col("registered_groups", "requires_trigger", "INTEGER DEFAULT 1"),
];

/// Column added by the Rust release with no backfill.
const RUST_COLUMNS: &[ColumnMigration] = &[
    col("messages", "thread_id", "TEXT"),
    col("registered_groups", "lane_config", "TEXT"),
];

/// Create the schema and bring an existing database up to date.
pub(crate) fn migrate(conn: &mut Connection, opts: &DbOptions) -> Result<()> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .db()?;
    tx.execute_batch(TS_BASE_SCHEMA).db()?;
    ts_migrations(&tx, opts)?;
    for m in DEFENSIVE_COLUMNS.iter().chain(RUST_COLUMNS) {
        add_column_if_missing(&tx, m)?;
    }
    tx.execute_batch(RUST_SCHEMA).db()?;
    tx.commit().db()?;
    Ok(())
}

/// The `ALTER TABLE` migrations of `src/db.ts`, in the same order, with the
/// same one-time backfills (run only when the column was actually added).
fn ts_migrations(tx: &Transaction<'_>, opts: &DbOptions) -> Result<()> {
    // Sessions: provider (NULL = unknown), last-turn context size.
    add_column_if_missing(tx, &col("sessions", "provider", "TEXT"))?;
    add_column_if_missing(tx, &col("sessions", "input_tokens", "INTEGER"))?;
    add_column_if_missing(tx, &col("sessions", "updated_at", "TEXT"))?;

    // Scheduled tasks: context mode, pre-run script.
    add_column_if_missing(
        tx,
        &col("scheduled_tasks", "context_mode", "TEXT DEFAULT 'isolated'"),
    )?;
    add_column_if_missing(tx, &col("scheduled_tasks", "script", "TEXT"))?;

    // Messages: bot flag, backfilled from the content-prefix convention.
    if add_column_if_missing(tx, &col("messages", "is_bot_message", "INTEGER DEFAULT 0"))? {
        let n = tx
            .execute(
                r"UPDATE messages SET is_bot_message = 1 WHERE content LIKE ?1 ESCAPE '\'",
                [bot_prefix_pattern(&opts.assistant_name)],
            )
            .db()?;
        tracing::info!(rows = n, "migration: backfilled messages.is_bot_message");
    }

    // Registered groups: main flag, backfilled from folder = 'main'.
    if add_column_if_missing(
        tx,
        &col("registered_groups", "is_main", "INTEGER DEFAULT 0"),
    )? {
        tx.execute(
            "UPDATE registered_groups SET is_main = 1 WHERE folder = 'main'",
            [],
        )
        .db()?;
    }

    // Chats: channel + is_group, backfilled from JID patterns.
    let added_channel = add_column_if_missing(tx, &col("chats", "channel", "TEXT"))?;
    let added_is_group = add_column_if_missing(tx, &col("chats", "is_group", "INTEGER DEFAULT 0"))?;
    if added_channel || added_is_group {
        tx.execute_batch(
            "UPDATE chats SET channel = 'whatsapp', is_group = 1 WHERE jid LIKE '%@g.us';
             UPDATE chats SET channel = 'whatsapp', is_group = 0 WHERE jid LIKE '%@s.whatsapp.net';
             UPDATE chats SET channel = 'discord', is_group = 1 WHERE jid LIKE 'dc:%';
             UPDATE chats SET channel = 'telegram', is_group = 0 WHERE jid LIKE 'tg:%';",
        )
        .db()?;
        tracing::info!("migration: backfilled chats.channel / chats.is_group");
    }

    // Messages: reply context.
    add_column_if_missing(tx, &col("messages", "reply_to_message_id", "TEXT"))?;
    add_column_if_missing(tx, &col("messages", "reply_to_message_content", "TEXT"))?;
    add_column_if_missing(tx, &col("messages", "reply_to_sender_name", "TEXT"))?;
    Ok(())
}

/// Whether `table` has a column called `column`.
pub(crate) fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare_cached("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2")
        .db()?;
    stmt.exists([table, column]).db()
}

/// Add the column if it is missing. Returns `true` when it was added.
fn add_column_if_missing(tx: &Transaction<'_>, m: &ColumnMigration) -> Result<bool> {
    if has_column(tx, m.table, m.column)? {
        return Ok(false);
    }
    // Identifiers come from the static migration table above, never from
    // input, so formatting them into the statement is safe.
    let sql = format!(
        "ALTER TABLE {} ADD COLUMN {} {}",
        m.table, m.column, m.definition
    );
    tx.execute_batch(&sql).db()?;
    tracing::info!(
        table = m.table,
        column = m.column,
        "migration: added column"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::*;
    use crate::{DB_FILE_NAME, Db};

    /// The oldest TypeScript schema: the base `CREATE TABLE` statements of
    /// `src/db.ts` without any column that was later added by a migration.
    const LEGACY_TS_SCHEMA: &str = r#"
        CREATE TABLE chats (
          jid TEXT PRIMARY KEY,
          name TEXT,
          last_message_time TEXT
        );
        CREATE TABLE messages (
          id TEXT,
          chat_jid TEXT,
          sender TEXT,
          sender_name TEXT,
          content TEXT,
          timestamp TEXT,
          is_from_me INTEGER,
          PRIMARY KEY (id, chat_jid),
          FOREIGN KEY (chat_jid) REFERENCES chats(jid)
        );
        CREATE INDEX idx_timestamp ON messages(timestamp);
        CREATE TABLE scheduled_tasks (
          id TEXT PRIMARY KEY,
          group_folder TEXT NOT NULL,
          chat_jid TEXT NOT NULL,
          prompt TEXT NOT NULL,
          schedule_type TEXT NOT NULL,
          schedule_value TEXT NOT NULL,
          next_run TEXT,
          last_run TEXT,
          last_result TEXT,
          status TEXT DEFAULT 'active',
          created_at TEXT NOT NULL
        );
        CREATE INDEX idx_next_run ON scheduled_tasks(next_run);
        CREATE INDEX idx_status ON scheduled_tasks(status);
        CREATE TABLE task_run_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          task_id TEXT NOT NULL,
          run_at TEXT NOT NULL,
          duration_ms INTEGER NOT NULL,
          status TEXT NOT NULL,
          result TEXT,
          error TEXT,
          FOREIGN KEY (task_id) REFERENCES scheduled_tasks(id)
        );
        CREATE INDEX idx_task_run_logs ON task_run_logs(task_id, run_at);
        CREATE TABLE router_state (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TABLE sessions (
          group_folder TEXT PRIMARY KEY,
          session_id TEXT NOT NULL
        );
        CREATE TABLE registered_groups (
          jid TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          folder TEXT NOT NULL UNIQUE,
          trigger_pattern TEXT NOT NULL,
          added_at TEXT NOT NULL,
          container_config TEXT,
          requires_trigger INTEGER DEFAULT 1
        );
    "#;

    /// Apply the full TypeScript `createSchema()` (base + every ALTER) the way
    /// the TypeScript release leaves a current database.
    fn create_current_ts_db(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(TS_BASE_SCHEMA).unwrap();
        conn.execute_batch(
            "ALTER TABLE sessions ADD COLUMN input_tokens INTEGER;
             ALTER TABLE sessions ADD COLUMN updated_at TEXT;
             ALTER TABLE scheduled_tasks ADD COLUMN context_mode TEXT DEFAULT 'isolated';
             ALTER TABLE scheduled_tasks ADD COLUMN script TEXT;
             ALTER TABLE registered_groups ADD COLUMN is_main INTEGER DEFAULT 0;
             ALTER TABLE messages ADD COLUMN reply_to_message_id TEXT;
             ALTER TABLE messages ADD COLUMN reply_to_message_content TEXT;
             ALTER TABLE messages ADD COLUMN reply_to_sender_name TEXT;",
        )
        .unwrap();
    }

    fn columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY name")
            .unwrap();
        stmt.query_map([table], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    fn schema_columns(conn: &Connection) -> BTreeMap<String, Vec<String>> {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        let tables: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        tables
            .into_iter()
            .map(|t| {
                let c = columns(conn, &t);
                (t, c)
            })
            .collect()
    }

    fn fresh_schema() -> BTreeMap<String, Vec<String>> {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| Ok(schema_columns(c))).unwrap()
    }

    #[test]
    fn fresh_schema_has_all_ts_columns() {
        let s = fresh_schema();
        for (table, cols) in [
            (
                "chats",
                &["jid", "name", "last_message_time", "channel", "is_group"][..],
            ),
            (
                "messages",
                &[
                    "id",
                    "chat_jid",
                    "sender",
                    "sender_name",
                    "content",
                    "timestamp",
                    "is_from_me",
                    "is_bot_message",
                    "reply_to_message_id",
                    "reply_to_message_content",
                    "reply_to_sender_name",
                    "thread_id",
                ][..],
            ),
            (
                "scheduled_tasks",
                &[
                    "id",
                    "group_folder",
                    "chat_jid",
                    "prompt",
                    "script",
                    "schedule_type",
                    "schedule_value",
                    "context_mode",
                    "next_run",
                    "last_run",
                    "last_result",
                    "status",
                    "created_at",
                ][..],
            ),
            (
                "sessions",
                &[
                    "group_folder",
                    "session_id",
                    "provider",
                    "input_tokens",
                    "updated_at",
                ][..],
            ),
            (
                "registered_groups",
                &[
                    "jid",
                    "name",
                    "folder",
                    "trigger_pattern",
                    "added_at",
                    "container_config",
                    "requires_trigger",
                    "is_main",
                    "lane_config",
                ][..],
            ),
        ] {
            let mut expected: Vec<String> = cols.iter().map(|c| (*c).to_string()).collect();
            expected.sort();
            assert_eq!(s[table], expected, "columns of {table}");
        }
        for t in [
            "task_run_logs",
            "router_state",
            "audit_log",
            "investigations",
            "ioc_sightings",
            "task_owners",
        ] {
            assert!(s.contains_key(t), "missing table {t}");
        }
    }

    #[test]
    fn legacy_ts_schema_migrates_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE_NAME);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(LEGACY_TS_SCHEMA).unwrap();
            conn.execute_batch(
                "INSERT INTO chats VALUES ('room@g.us', 'WA Group', '2024-01-01T00:00:02.000Z');
                 INSERT INTO chats VALUES ('123@s.whatsapp.net', 'WA DM', '2024-01-01T00:00:03.000Z');
                 INSERT INTO chats VALUES ('dc:42', 'Discord', '2024-01-01T00:00:04.000Z');
                 INSERT INTO chats VALUES ('tg:12345', 'TG DM', '2024-01-01T00:00:00.000Z');
                 INSERT INTO messages VALUES ('m1', 'room@g.us', 'u', 'U', 'hello', '2024-01-01T00:00:01.000Z', 0);
                 INSERT INTO messages VALUES ('m2', 'room@g.us', 'b', 'Andy', 'Andy: hi there', '2024-01-01T00:00:02.000Z', 1);
                 INSERT INTO scheduled_tasks (id, group_folder, chat_jid, prompt, schedule_type, schedule_value, next_run, status, created_at)
                   VALUES ('t1', 'main', 'room@g.us', 'p', 'interval', '60000', '2024-01-01T00:00:00.000Z', 'active', '2024-01-01T00:00:00.000Z');
                 INSERT INTO sessions VALUES ('main', 'sess-legacy');
                 INSERT INTO registered_groups VALUES ('main@s.whatsapp.net', 'Main', 'main', '@Andy', '2024-01-01T00:00:00.000Z', NULL, 0);
                 INSERT INTO registered_groups VALUES ('room@g.us', 'Room', 'room', '@Andy', '2024-01-01T00:00:00.000Z', '{\"timeout\":1000}', 1);",
            )
            .unwrap();
        }

        let db = Db::open(&path).unwrap();

        // Backfills.
        let chats = db.get_all_chats().unwrap();
        let find = |jid: &str| chats.iter().find(|c| c.jid == jid).unwrap().clone();
        assert_eq!(find("room@g.us").channel.as_deref(), Some("whatsapp"));
        assert!(find("room@g.us").is_group);
        assert_eq!(
            find("123@s.whatsapp.net").channel.as_deref(),
            Some("whatsapp")
        );
        assert!(!find("123@s.whatsapp.net").is_group);
        assert_eq!(find("dc:42").channel.as_deref(), Some("discord"));
        assert!(find("dc:42").is_group);
        assert_eq!(find("tg:12345").channel.as_deref(), Some("telegram"));
        assert!(!find("tg:12345").is_group);

        // is_bot_message backfill: the prefixed message is now a bot message.
        let msgs = db
            .get_messages_since("room@g.us", "", "Nobody", 10)
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].id, "m1");
        assert_eq!(
            db.get_last_bot_message_timestamp("room@g.us", "Nobody")
                .unwrap()
                .as_deref(),
            Some("2024-01-01T00:00:02.000Z")
        );

        // is_main backfill and container_config parsing.
        let groups = db.get_all_registered_groups().unwrap();
        assert!(groups["main@s.whatsapp.net"].is_main);
        assert_eq!(groups["main@s.whatsapp.net"].requires_trigger, Some(false));
        assert!(!groups["room@g.us"].is_main);
        assert_eq!(
            groups["room@g.us"]
                .container_config
                .as_ref()
                .unwrap()
                .timeout,
            Some(1000)
        );

        // Tasks get the default context mode; sessions have no provider.
        let task = db.get_task_by_id("t1").unwrap().unwrap();
        assert_eq!(task.context_mode, talon_core::types::ContextMode::Isolated);
        assert_eq!(task.script, None);
        assert_eq!(
            db.get_session("main").unwrap().as_deref(),
            Some("sess-legacy")
        );
        assert_eq!(db.get_session_provider("main").unwrap(), None);
        let rows = db.get_session_rows().unwrap();
        assert_eq!(rows[0].input_tokens, None);

        // Same column set as a fresh database.
        let migrated = db.with_conn(|c| Ok(schema_columns(c))).unwrap();
        assert_eq!(migrated, fresh_schema());
        drop(db);

        // Re-open: idempotent, backfills don't re-run.
        let db = Db::open(&path).unwrap();
        db.with_conn(|c| {
            c.execute(
                "UPDATE chats SET channel = 'custom' WHERE jid = 'tg:12345'",
                [],
            )
            .db()
        })
        .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let chats = db.get_all_chats().unwrap();
        assert_eq!(
            chats
                .iter()
                .find(|c| c.jid == "tg:12345")
                .unwrap()
                .channel
                .as_deref(),
            Some("custom")
        );
    }

    #[test]
    fn current_ts_schema_opens_and_is_readable_back_by_ts_queries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE_NAME);
        create_current_ts_db(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "INSERT INTO chats (jid, name, last_message_time, channel, is_group)
                   VALUES ('tg:1', 'TG', '2024-01-01T00:00:00.000Z', 'telegram', 0);
                 INSERT INTO messages (id, chat_jid, sender, sender_name, content, timestamp, is_from_me, is_bot_message, reply_to_message_id)
                   VALUES ('m1', 'tg:1', 'u', 'U', 'hi', '2024-01-01T00:00:01.000Z', 0, 0, 'r9');
                 INSERT INTO registered_groups (jid, name, folder, trigger_pattern, added_at, container_config, requires_trigger, is_main)
                   VALUES ('tg:1', 'TG', 'telegram_main', '@Andy', '2024-01-01T00:00:00.000Z', NULL, 0, 1);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let msgs = db.get_messages_since("tg:1", "", "Andy", 10).unwrap();
        assert_eq!(msgs[0].reply_to_message_id.as_deref(), Some("r9"));
        assert!(db.get_registered_group("tg:1").unwrap().unwrap().is_main);
        assert_eq!(
            db.with_conn(|c| Ok(schema_columns(c))).unwrap(),
            fresh_schema()
        );

        // Writes made by Rust stay readable by the TypeScript statements.
        db.store_message(&talon_core::types::NewMessage {
            id: "m2".into(),
            chat_jid: "tg:1".into(),
            sender: "u".into(),
            sender_name: "U".into(),
            content: "second".into(),
            timestamp: "2024-01-01T00:00:02.000Z".into(),
            ..Default::default()
        })
        .unwrap();
        drop(db);
        let conn = Connection::open(&path).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE chat_jid = 'tg:1' AND is_bot_message = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2);
        let (folder, is_main): (String, i64) = conn
            .query_row(
                "SELECT folder, is_main FROM registered_groups WHERE jid = 'tg:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((folder.as_str(), is_main), ("telegram_main", 1));
    }

    // Port of src/db-migration.test.ts.
    #[test]
    fn defaults_telegram_backfill_chats_to_direct_messages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store").join(DB_FILE_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        {
            let legacy = Connection::open(&path).unwrap();
            legacy
                .execute_batch(
                    "CREATE TABLE chats (jid TEXT PRIMARY KEY, name TEXT, last_message_time TEXT);",
                )
                .unwrap();
            for (jid, name, ts) in [
                ("tg:12345", "Telegram DM", "2024-01-01T00:00:00.000Z"),
                ("tg:-10012345", "Telegram Group", "2024-01-01T00:00:01.000Z"),
                ("room@g.us", "WhatsApp Group", "2024-01-01T00:00:02.000Z"),
            ] {
                legacy
                    .execute(
                        "INSERT INTO chats (jid, name, last_message_time) VALUES (?, ?, ?)",
                        [jid, name, ts],
                    )
                    .unwrap();
            }
        }
        let db = Db::open(&path).unwrap();
        let chats = db.get_all_chats().unwrap();
        let get = |jid: &str| chats.iter().find(|c| c.jid == jid).unwrap();
        assert_eq!(get("tg:12345").channel.as_deref(), Some("telegram"));
        assert!(!get("tg:12345").is_group);
        assert_eq!(get("tg:-10012345").channel.as_deref(), Some("telegram"));
        assert!(!get("tg:-10012345").is_group);
        assert_eq!(get("room@g.us").channel.as_deref(), Some("whatsapp"));
        assert!(get("room@g.us").is_group);
    }

    #[test]
    fn bot_backfill_uses_configured_assistant_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE_NAME);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(LEGACY_TS_SCHEMA).unwrap();
            conn.execute_batch(
                "INSERT INTO chats VALUES ('c', 'c', '2024');
                 INSERT INTO messages VALUES ('1', 'c', 's', 'S', 'Talon: report', '2024-01-01', 1);
                 INSERT INTO messages VALUES ('2', 'c', 's', 'S', 'Andy: other bot', '2024-01-02', 1);
                 INSERT INTO messages VALUES ('3', 'c', 's', 'S', 'Talonx: user', '2024-01-03', 0);",
            )
            .unwrap();
        }
        let db = Db::open_with_options(
            &path,
            &DbOptions {
                assistant_name: "Talon".into(),
            },
        )
        .unwrap();
        let flagged: Vec<String> = db
            .with_conn(|c| {
                let mut s = c
                    .prepare("SELECT id FROM messages WHERE is_bot_message = 1 ORDER BY id")
                    .db()?;
                s.query_map([], |r| r.get(0))
                    .db()?
                    .collect::<rusqlite::Result<_>>()
                    .db()
            })
            .unwrap();
        assert_eq!(flagged, vec!["1".to_string()]);
    }

    #[test]
    fn audit_triggers_exist_after_migration() {
        let db = Db::open_in_memory().unwrap();
        let n: i64 = db
            .with_conn(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log'",
                    [],
                    |r| r.get(0),
                )
                .db()
            })
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn ioc_lookup_uses_an_index() {
        let db = Db::open_in_memory().unwrap();
        let plan: Vec<String> = db
            .with_conn(|c| {
                let mut s = c
                    .prepare(
                        "EXPLAIN QUERY PLAN SELECT * FROM ioc_sightings WHERE ioc_type = 'ipv4' AND value = '1.2.3.4'",
                    )
                    .db()?;
                s.query_map([], |r| r.get::<_, String>(3))
                    .db()?
                    .collect::<rusqlite::Result<_>>()
                    .db()
            })
            .unwrap();
        assert!(
            plan.iter().any(|p| p.contains("USING INDEX")),
            "plan: {plan:?}"
        );
    }
}
