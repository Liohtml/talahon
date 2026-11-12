//! # talon-db — SQLite persistence
//!
//! The public API below is the contract other crates
//! (scheduler, ipc, http, host) are written against. Methods may be added,
//! but the original signatures must not change without coordinating.
//!
//! Properties:
//! - Migrates databases created by earlier releases in place: an existing
//!   `store/messages.db` opens and gets every missing
//!   `ALTER TABLE ... ADD COLUMN` migration (idempotent, inside one
//!   `BEGIN IMMEDIATE` transaction). The base tables keep their original
//!   shape, so a database created here is still readable by earlier
//!   releases.
//! - WAL mode, `foreign_keys=ON`, `busy_timeout=5000`, prepared-statement
//!   cache (`prepare_cached`).
//! - [`Db`] is cheap to clone and `Send + Sync`. One connection behind a
//!   mutex does every write and everything that runs inside a transaction
//!   (a poisoned mutex surfaces as [`Error::Db`], never a panic). File-backed
//!   WAL databases additionally get a small pool of `query_only` connections
//!   ([`READ_POOL_SIZE`]) for the read-only queries, so lanes that read do
//!   not queue behind each other or behind a commit. A read sees every write
//!   that returned before it started (WAL readers see all committed data).
//!   In-memory databases are private to their connection and keep using the
//!   single connection for everything.
//! - New tables: `audit_log` (append-only, **hash-chained**: each row stores
//!   `prev_hash` and `hash = sha256_hex(prev_hash || canonical_json(event))`,
//!   with [`Db::verify_audit_chain`]), `investigations`, `ioc_sightings`,
//!   `task_owners` (who created a scheduled task over IPC, see
//!   [`Db::set_task_owner`] / [`Db::get_task_owner`]; per-lane quotas use
//!   [`Db::count_tasks_owned_by`], per-lane task snapshots
//!   [`Db::get_tasks_for_jids`]).
//! - Every query is parameterized; no SQL is ever built from user input.
//!
//! Module map (all of them add methods to [`Db`]):
//! - `schema`         — base tables + idempotent migrations
//! - `chats`          — chat metadata and messages
//! - `tasks`          — scheduled tasks, run logs and task owners
//! - `state`          — router state and lane sessions
//! - `groups`         — registered groups (base column mapping + `lane_config`)
//! - [`audit`]        — hash-chained audit log, [`audit::DbAuditSink`]
//! - `investigations` — investigation jobs
//! - `iocs`           — IOC sightings for cross-alert correlation

#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use talon_core::{Error, Result};

pub mod audit;
mod chats;
mod groups;
mod investigations;
mod iocs;
mod schema;
mod state;
mod tasks;

pub use audit::{AUDIT_GENESIS_HASH, DbAuditSink, audit_event_hash, canonical_json};
pub use investigations::INVESTIGATION_STATUSES;
pub use iocs::{MAX_IOC_TYPE_LEN, MAX_IOC_VALUE_LEN};
pub use tasks::MAX_TASK_OWNER_LEN;

// Re-exported so callers can name every type of this API through talon-db.
pub use talon_core::types::{
    AuditEvent, ChatInfo, ChatMetadata, NewMessage, RegisteredGroup, ScheduledTask, SessionRow,
    TaskRunLog, TaskUpdate,
};

/// File name of the database inside the store directory (`store/messages.db`),
/// unchanged from earlier releases.
pub const DB_FILE_NAME: &str = "messages.db";

/// Default number of messages returned by the message queries when the
/// caller does not pass an explicit limit.
pub const DEFAULT_MESSAGE_LIMIT: usize = 200;

/// `busy_timeout` applied to every connection.
pub const BUSY_TIMEOUT: Duration = Duration::from_millis(5000);

/// Number of additional read-only connections a file-backed database opens
/// for its read-only queries (see the crate docs). Zero for in-memory
/// databases.
pub const READ_POOL_SIZE: usize = 4;

/// Capacity of the per-connection prepared-statement cache.
const STATEMENT_CACHE_CAPACITY: usize = 64;

/// `<store_dir>/messages.db`.
pub fn default_db_path(store_dir: &Path) -> PathBuf {
    store_dir.join(DB_FILE_NAME)
}

/// Investigation job triggered via `POST /investigate` or the alert sweep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Investigation {
    /// e.g. `copilot-inv-<alert_id>-<millis>`
    pub id: String,
    /// Alert id in the SIEM / CoPilot.
    pub alert_id: String,
    /// Customer the alert belongs to.
    pub customer_code: String,
    /// Who started the job (`webhook`, `sweep`, a user id, ...).
    pub triggered_by: String,
    /// `queued` | `running` | `completed` | `failed`
    /// (see [`INVESTIGATION_STATUSES`]).
    pub status: String,
    /// Prompt template used for the run, if any.
    pub template: Option<String>,
    /// ISO-8601 creation time. Preserved across upserts.
    pub created_at: String,
    /// ISO-8601 time of the last status change.
    pub updated_at: String,
    /// Structured verdict JSON from the agent (see talon-intel `TriageReport`).
    pub verdict: Option<serde_json::Value>,
    /// Failure description when `status == "failed"`.
    pub error: Option<String>,
}

/// An IOC observed in an alert/investigation, for cross-alert correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IocSighting {
    /// `ipv4` | `ipv6` | `domain` | `url` | `md5` | `sha1` | `sha256` | `email` | `cve` | ...
    pub ioc_type: String,
    /// Normalized (refanged, lowercased where case-insensitive) value.
    pub value: String,
    /// Alert / investigation reference.
    pub source_ref: String,
    /// Customer the sighting belongs to, if known.
    pub customer_code: Option<String>,
    /// ISO-8601 time of the (latest) sighting.
    pub seen_at: String,
}

/// Options for [`Db::open_with_options`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbOptions {
    /// Assistant name used by the one-time `is_bot_message` backfill when a
    /// pre-migration database is upgraded (`content LIKE '<name>:%'`).
    /// Defaults to `Talon`, the default `ASSISTANT_NAME`.
    pub assistant_name: String,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            assistant_name: "Talon".to_string(),
        }
    }
}

/// Thread-safe SQLite handle.
#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    /// The read-write connection: every write and every transaction.
    conn: Mutex<Connection>,
    /// `query_only` connections on the same file for read-only queries.
    /// Empty when the database cannot be shared across connections
    /// (in-memory) or is not in WAL mode; reads then use `conn`.
    readers: Vec<Mutex<Connection>>,
    /// Round-robin cursor into `readers`.
    next_reader: AtomicUsize,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("read_connections", &self.inner.readers.len())
            .finish_non_exhaustive()
    }
}

impl Db {
    // ---- lifecycle -------------------------------------------------------

    /// Open (creating parent dirs) and migrate, with default [`DbOptions`].
    ///
    /// A database file created by this call gets mode `0600` on Unix (it
    /// holds chat content and the audit trail).
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_options(path, &DbOptions::default())
    }

    /// Open (creating parent dirs) and migrate.
    pub fn open_with_options(path: &Path, opts: &DbOptions) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let existed = path.exists();
        let conn = Connection::open(path).db()?;
        if !existed {
            restrict_permissions(path);
        }
        let db = Self::init(conn, opts)?;
        Ok(db.with_read_pool(path))
    }

    /// Fresh in-memory database with the full schema (tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().db()?;
        Self::init(conn, &DbOptions::default())
    }

    fn init(mut conn: Connection, opts: &DbOptions) -> Result<Self> {
        configure_connection(&conn)?;
        schema::migrate(&mut conn, opts)?;
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Mutex::new(conn),
                readers: Vec::new(),
                next_reader: AtomicUsize::new(0),
            }),
        })
    }

    /// Add the read-only connections when the database just opened at `path`
    /// can be shared across connections. Never fails: without a pool reads
    /// simply keep using the read-write connection.
    fn with_read_pool(self, path: &Path) -> Self {
        let readers = match self.with_conn(|conn| open_readers(conn, path)) {
            Ok(readers) => readers,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "sqlite read pool unavailable; reads share the write connection"
                );
                return self;
            }
        };
        if readers.is_empty() {
            return self;
        }
        match Arc::try_unwrap(self.inner) {
            Ok(inner) => Self {
                inner: Arc::new(Inner { readers, ..inner }),
            },
            // Not reachable (the handle was created by the caller and never
            // cloned); keep the handle as it is.
            Err(inner) => Self { inner },
        }
    }

    /// Number of read-only connections in use ([`READ_POOL_SIZE`] for a
    /// file-backed WAL database, `0` when reads share the write connection).
    pub fn read_connections(&self) -> usize {
        self.inner.readers.len()
    }

    /// Lock the connection. A poisoned mutex is reported as [`Error::Db`].
    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.inner
            .conn
            .lock()
            .map_err(|_| Error::Db("database mutex poisoned".to_string()))
    }

    /// Run `f` with exclusive access to the read-write connection.
    pub(crate) fn with_conn<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
        let mut guard = self.lock()?;
        f(&mut guard)
    }

    /// Run the read-only query `f`.
    ///
    /// Uses an idle connection of the read pool, so readers neither wait for
    /// each other nor for a commit on the write connection. The connection
    /// is in autocommit mode, so `f` starts a fresh WAL snapshot and sees
    /// every write committed before it was called (read-your-writes, also
    /// across threads). `f` must not write: the pool is `query_only`.
    /// Anything that has to be atomic with a write belongs in
    /// [`Db::with_tx`]. Without a pool this is [`Db::with_conn`].
    pub(crate) fn with_read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let readers = &self.inner.readers;
        if readers.is_empty() {
            return self.with_conn(|conn| f(conn));
        }
        let start = self.inner.next_reader.fetch_add(1, Ordering::Relaxed) % readers.len();
        // A poisoned reader is reused: a `query_only` connection holds no
        // state a panicking query could have left half-written (its
        // statement was reset when the panic unwound).
        for offset in 0..readers.len() {
            match readers[(start + offset) % readers.len()].try_lock() {
                Ok(guard) => return f(&guard),
                Err(TryLockError::Poisoned(poisoned)) => return f(&poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => {}
            }
        }
        // Every reader is busy: queue on one of them.
        let guard = readers[start]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        f(&guard)
    }

    /// Run `f` inside a transaction, committing on `Ok` and rolling back on
    /// `Err`. `immediate` takes the write lock up front (`BEGIN IMMEDIATE`),
    /// which is required for read-then-write sequences across processes.
    pub(crate) fn with_tx<T>(
        &self,
        immediate: bool,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_conn(|conn| {
            let behavior = if immediate {
                rusqlite::TransactionBehavior::Immediate
            } else {
                rusqlite::TransactionBehavior::Deferred
            };
            let tx = conn.transaction_with_behavior(behavior).db()?;
            let out = f(&tx)?;
            tx.commit().db()?;
            Ok(out)
        })
    }
}

/// Connection-level settings shared by file and in-memory databases.
fn configure_connection(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT).db()?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
    // In-memory databases report "memory"; files switch to WAL persistently.
    let mode: String = conn
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .db()?;
    tracing::debug!(journal_mode = %mode, "sqlite journal mode");
    conn.pragma_update(None, "foreign_keys", "ON").db()?;
    Ok(())
}

/// Open the read pool for the database `main` has open at `path`.
///
/// Returns no connections when `main` is not a WAL database stored in a
/// file: a private in-memory or temporary database exists only inside its
/// own connection, and without WAL a reader would block on (and block) the
/// writer instead of reading the last committed snapshot.
fn open_readers(main: &Connection, path: &Path) -> Result<Vec<Mutex<Connection>>> {
    let file: Option<String> = main
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )
        .db()?;
    let mode: String = main
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .db()?;
    if file.is_none_or(|f| f.is_empty()) || !mode.eq_ignore_ascii_case("wal") {
        return Ok(Vec::new());
    }
    (0..READ_POOL_SIZE)
        .map(|_| open_reader(path).map(Mutex::new))
        .collect()
}

/// One pooled read connection: the settings of the main connection that
/// matter for reading, plus `query_only` (a write through it is an error).
fn open_reader(path: &Path) -> Result<Connection> {
    // Read-write at the file level (a WAL reader updates the shared-memory
    // index and may have to run recovery), never creating the file.
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .db()?;
    conn.busy_timeout(BUSY_TIMEOUT).db()?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
    conn.pragma_update(None, "foreign_keys", "ON").db()?;
    conn.pragma_update(None, "query_only", "ON").db()?;
    Ok(conn)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(path = %path.display(), error = %e, "could not restrict database file permissions");
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

// ---------------------------------------------------------------------------
// Internal helpers shared by the modules
// ---------------------------------------------------------------------------

fn db_err(e: rusqlite::Error) -> Error {
    Error::Db(e.to_string())
}

/// `rusqlite::Result<T>` -> `talon_core::Result<T>`.
pub(crate) trait SqlResultExt<T> {
    fn db(self) -> Result<T>;
}

impl<T> SqlResultExt<T> for rusqlite::Result<T> {
    fn db(self) -> Result<T> {
        self.map_err(db_err)
    }
}

/// `usize` limit -> SQLite `LIMIT` parameter (saturating).
pub(crate) fn sql_limit(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

/// Escape `%`, `_` and `\` for a `LIKE ... ESCAPE '\'` pattern.
pub(crate) fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `LIKE` pattern matching content written by the assistant (`"<prefix>:%"`).
pub(crate) fn bot_prefix_pattern(bot_prefix: &str) -> String {
    format!("{}:%", escape_like(bot_prefix))
}

/// Lenient column readers: rows written by earlier releases (or by
/// hand) may hold NULLs or unexpected storage classes; never fail on them.
pub(crate) mod col {
    use super::ValueRef;
    use rusqlite::Row;

    /// Text column; NULL -> `None`, numbers are stringified.
    pub fn opt_text(row: &Row<'_>, name: &str) -> rusqlite::Result<Option<String>> {
        Ok(match row.get_ref(name)? {
            ValueRef::Null => None,
            ValueRef::Integer(i) => Some(i.to_string()),
            ValueRef::Real(f) => Some(f.to_string()),
            ValueRef::Text(t) | ValueRef::Blob(t) => Some(String::from_utf8_lossy(t).into_owned()),
        })
    }

    /// Text column; NULL -> `""`.
    pub fn text(row: &Row<'_>, name: &str) -> rusqlite::Result<String> {
        Ok(opt_text(row, name)?.unwrap_or_default())
    }

    /// Integer column; NULL / non-numeric -> `None`.
    pub fn opt_i64(row: &Row<'_>, name: &str) -> rusqlite::Result<Option<i64>> {
        Ok(match row.get_ref(name)? {
            ValueRef::Integer(i) => Some(i),
            // Saturating float->int conversion is the intent here.
            #[allow(clippy::cast_possible_truncation)]
            ValueRef::Real(f) => Some(f as i64),
            ValueRef::Text(t) => std::str::from_utf8(t)
                .ok()
                .and_then(|s| s.trim().parse().ok()),
            ValueRef::Null | ValueRef::Blob(_) => None,
        })
    }

    /// Boolean flag stored as INTEGER 0/1; NULL -> `None`.
    pub fn opt_flag(row: &Row<'_>, name: &str) -> rusqlite::Result<Option<bool>> {
        Ok(match row.get_ref(name)? {
            ValueRef::Null => None,
            ValueRef::Integer(i) => Some(i != 0),
            ValueRef::Real(f) => Some(f != 0.0),
            ValueRef::Text(t) | ValueRef::Blob(t) => {
                let s = String::from_utf8_lossy(t);
                let s = s.trim();
                Some(s == "1" || s.eq_ignore_ascii_case("true"))
            }
        })
    }

    /// Boolean flag; NULL -> `false`.
    pub fn flag(row: &Row<'_>, name: &str) -> rusqlite::Result<bool> {
        Ok(opt_flag(row, name)?.unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talon_core::types::ChatMetadata;

    fn chat(jid: &str) -> ChatMetadata {
        ChatMetadata {
            chat_jid: jid.to_string(),
            timestamp: "2024-01-01T00:00:00.000Z".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn db_is_send_sync_clone() {
        fn assert_traits<T: Send + Sync + Clone + 'static>() {}
        assert_traits::<Db>();
    }

    #[test]
    fn open_creates_parent_dirs_and_uses_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("store").join(DB_FILE_NAME);
        let db = Db::open(&path).unwrap();
        assert!(path.exists());
        let (mode, fk, busy): (String, i64, i64) = db
            .with_conn(|c| {
                let mode = c.query_row("PRAGMA journal_mode", [], |r| r.get(0)).db()?;
                let fk = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).db()?;
                let busy = c.query_row("PRAGMA busy_timeout", [], |r| r.get(0)).db()?;
                Ok((mode, fk, busy))
            })
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        assert_eq!(fk, 1);
        assert_eq!(busy, 5000);
    }

    #[cfg(unix)]
    #[test]
    fn new_database_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE_NAME);
        Db::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn reopen_is_idempotent_and_keeps_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE_NAME);
        {
            let db = Db::open(&path).unwrap();
            db.store_chat_metadata(&chat("a@g.us")).unwrap();
            db.set_router_state("k", "v").unwrap();
        }
        for _ in 0..3 {
            let db = Db::open(&path).unwrap();
            assert_eq!(db.get_router_state("k").unwrap().as_deref(), Some("v"));
            assert_eq!(db.get_all_chats().unwrap().len(), 1);
        }
    }

    #[test]
    fn escape_like_escapes_wildcards() {
        assert_eq!(escape_like("T_lon%"), "T\\_lon\\%");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
        assert_eq!(bot_prefix_pattern("Talon"), "Talon:%");
    }

    #[test]
    fn poisoned_mutex_is_an_error_not_a_panic() {
        let db = Db::open_in_memory().unwrap();
        let clone = db.clone();
        let _ = std::thread::spawn(move || {
            let _guard = clone.inner.conn.lock().unwrap();
            panic!("poison the mutex");
        })
        .join();
        match db.get_router_state("x") {
            Err(Error::Db(msg)) => assert!(msg.contains("poisoned")),
            other => panic!("expected Error::Db, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_clones_across_threads() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join(DB_FILE_NAME)).unwrap();
        db.store_chat_metadata(&chat("c@g.us")).unwrap();

        let threads: Vec<_> = (0..8)
            .map(|t| {
                let db = db.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        db.store_message(&NewMessage {
                            id: format!("t{t}-m{i}"),
                            chat_jid: "c@g.us".into(),
                            sender: "u".into(),
                            sender_name: "U".into(),
                            content: format!("message {t}/{i}"),
                            timestamp: format!("2024-01-01T00:{t:02}:{i:02}.000Z"),
                            ..Default::default()
                        })
                        .unwrap();
                        db.record_audit(&talon_core::audit::event(
                            "test.concurrent",
                            &format!("thread-{t}"),
                            None,
                            "info",
                            serde_json::json!({ "i": i }),
                        ))
                        .unwrap();
                        db.set_router_state(&format!("t{t}"), &i.to_string())
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let msgs = db.get_messages_since("c@g.us", "", "Talon", 1000).unwrap();
        assert_eq!(msgs.len(), 200);
        assert_eq!(db.recent_audit(1000, Some("test.")).unwrap().len(), 200);
        assert_eq!(db.verify_audit_chain().unwrap(), None);
        for t in 0..8 {
            assert_eq!(
                db.get_router_state(&format!("t{t}")).unwrap().as_deref(),
                Some("24")
            );
        }
    }

    fn file_db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join(DB_FILE_NAME)).unwrap();
        (dir, db)
    }

    #[test]
    fn file_databases_get_a_read_pool_and_in_memory_ones_do_not() {
        let (_dir, db) = file_db();
        assert_eq!(db.read_connections(), READ_POOL_SIZE);
        assert_eq!(db.clone().read_connections(), READ_POOL_SIZE);

        // A private in-memory database exists only inside its connection.
        for mem in [
            Db::open_in_memory().unwrap(),
            Db::open(Path::new(":memory:")).unwrap(),
        ] {
            assert_eq!(mem.read_connections(), 0);
            mem.set_router_state("k", "v").unwrap();
            assert_eq!(mem.get_router_state("k").unwrap().as_deref(), Some("v"));
        }
    }

    #[test]
    fn read_pool_connections_are_query_only_with_the_shared_settings() {
        let (_dir, db) = file_db();
        // Every pooled connection (round robin) refuses to write.
        for _ in 0..READ_POOL_SIZE * 2 {
            let (query_only, busy): (i64, i64) = db
                .with_read(|c| {
                    let q = c.query_row("PRAGMA query_only", [], |r| r.get(0)).db()?;
                    let b = c.query_row("PRAGMA busy_timeout", [], |r| r.get(0)).db()?;
                    Ok((q, b))
                })
                .unwrap();
            assert_eq!((query_only, busy), (1, 5000));
            let write = db.with_read(|c| {
                c.execute(
                    "INSERT INTO router_state (key, value) VALUES ('k', 'v')",
                    [],
                )
                .db()
            });
            assert!(matches!(write, Err(Error::Db(_))), "{write:?}");
        }
        assert_eq!(db.get_router_state("k").unwrap(), None);
    }

    #[test]
    fn a_caller_reads_its_own_writes_through_the_pool() {
        let (_dir, db) = file_db();
        db.store_chat_metadata(&chat("c@g.us")).unwrap();
        for i in 0..200 {
            let v = i.to_string();
            db.set_router_state("cursor", &v).unwrap();
            assert_eq!(db.get_router_state("cursor").unwrap(), Some(v));

            db.record_audit(&talon_core::audit::event(
                "test.ryw",
                "t",
                None,
                "info",
                serde_json::json!(i),
            ))
            .unwrap();
            assert_eq!(db.audit_count().unwrap(), i + 1);
            assert_eq!(db.audit_chain_head().unwrap().map(|(id, _)| id), {
                let newest = db.with_conn(|c| {
                    c.query_row("SELECT MAX(id) FROM audit_log", [], |r| r.get(0))
                        .db()
                });
                newest.unwrap()
            });
        }
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn a_write_is_visible_to_other_threads_as_soon_as_it_returns() {
        let (_dir, db) = file_db();
        let (tx, rx) = std::sync::mpsc::channel::<u64>();
        // Several readers so that every pooled connection takes part.
        let rx = Arc::new(Mutex::new(rx));
        let readers: Vec<_> = (0..READ_POOL_SIZE + 2)
            .map(|_| {
                let (db, rx) = (db.clone(), Arc::clone(&rx));
                std::thread::spawn(move || {
                    loop {
                        let Ok(written) = rx.lock().unwrap().recv() else {
                            return;
                        };
                        // `written` was committed before it was sent.
                        let seen: u64 = db
                            .get_router_state("counter")
                            .unwrap()
                            .unwrap()
                            .parse()
                            .unwrap();
                        assert!(seen >= written, "stale read: {seen} < {written}");
                        assert!(db.audit_count().unwrap() >= written);
                    }
                })
            })
            .collect();
        for i in 1..=300u64 {
            db.record_audit(&talon_core::audit::event(
                "test.visible",
                "t",
                None,
                "info",
                serde_json::json!(i),
            ))
            .unwrap();
            db.set_router_state("counter", &i.to_string()).unwrap();
            tx.send(i).unwrap();
        }
        drop(tx);
        for r in readers {
            r.join().unwrap();
        }
    }

    #[test]
    fn reads_do_not_wait_for_the_write_connection() {
        let (_dir, db) = file_db();
        db.set_router_state("k", "v").unwrap();
        // Hold the write connection (as a slow commit would).
        let guard = db.inner.conn.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn({
            let db = db.clone();
            move || tx.send(db.get_router_state("k").unwrap()).unwrap()
        });
        let got = rx.recv_timeout(Duration::from_secs(30));
        drop(guard);
        reader.join().unwrap();
        assert_eq!(got.unwrap().as_deref(), Some("v"));
    }

    #[test]
    fn a_panic_in_a_pooled_read_does_not_break_later_reads() {
        let (_dir, db) = file_db();
        db.set_router_state("k", "v").unwrap();
        for _ in 0..READ_POOL_SIZE {
            let clone = db.clone();
            let _ = std::thread::spawn(move || {
                let _ = clone.with_read(|_| -> Result<()> { panic!("poison a reader") });
            })
            .join();
        }
        for _ in 0..READ_POOL_SIZE * 2 {
            assert_eq!(db.get_router_state("k").unwrap().as_deref(), Some("v"));
        }
    }

    /// Every read-only method goes through the `query_only` pool on a file
    /// database: one that wrote would fail here.
    #[test]
    fn every_read_method_works_on_the_read_pool() {
        let (_dir, db) = file_db();
        db.store_chat_metadata(&chat("c@g.us")).unwrap();
        let jids = vec!["c@g.us".to_string()];

        db.recent_audit(10, Some("x.")).unwrap();
        db.verify_audit_chain().unwrap();
        db.audit_chain_head().unwrap();
        db.audit_count().unwrap();

        assert_eq!(db.get_all_chats().unwrap().len(), 1);
        assert!(db.get_chat("c@g.us").unwrap().is_some());
        db.get_last_group_sync().unwrap();
        db.get_new_messages(&jids, "", "Talon").unwrap();
        db.get_messages_since("c@g.us", "", "Talon", 10).unwrap();
        db.get_last_bot_message_timestamp("c@g.us", "Talon")
            .unwrap();

        db.get_registered_group("c@g.us").unwrap();
        db.get_all_registered_groups().unwrap();

        db.get_investigation("i").unwrap();
        db.list_investigations(10).unwrap();
        db.latest_investigation_for_alert("a").unwrap();
        db.investigation_status_counts().unwrap();

        db.find_ioc_sightings("ipv4", "198.51.100.7", 10).unwrap();
        db.count_ioc_sightings("ipv4", "198.51.100.7", None)
            .unwrap();

        db.get_router_state("k").unwrap();
        db.get_session("s").unwrap();
        db.get_session_provider("s").unwrap();
        db.get_session_rows().unwrap();
        db.get_all_sessions().unwrap();

        db.get_task_by_id("t").unwrap();
        db.get_tasks_for_group("g").unwrap();
        db.get_tasks_for_jids(&jids).unwrap();
        db.count_tasks_owned_by("o").unwrap();
        db.get_all_tasks().unwrap();
        db.get_task_owner("t").unwrap();
        db.get_due_tasks("2024-01-01T00:00:00.000Z").unwrap();
        db.get_task_run_logs("t", 10).unwrap();
    }

    #[test]
    fn two_handles_on_one_file_share_the_audit_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE_NAME);
        let a = Db::open(&path).unwrap();
        let b = Db::open(&path).unwrap();
        let ha = std::thread::spawn({
            let a = a.clone();
            move || {
                for i in 0..20 {
                    a.record_audit(&talon_core::audit::event(
                        "x.a",
                        "a",
                        None,
                        "info",
                        serde_json::json!(i),
                    ))
                    .unwrap();
                }
            }
        });
        for i in 0..20 {
            b.record_audit(&talon_core::audit::event(
                "x.b",
                "b",
                None,
                "info",
                serde_json::json!(i),
            ))
            .unwrap();
        }
        ha.join().unwrap();
        assert_eq!(a.verify_audit_chain().unwrap(), None);
        assert_eq!(b.recent_audit(100, Some("x.")).unwrap().len(), 40);
    }
}
