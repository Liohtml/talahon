//! The database side: one bounded statement per connection.
//!
//! Like the Python server, every tool call opens its own connection, runs
//! one statement in autocommit mode and closes it, so nothing (`USE`,
//! `SET`, temporary tables, an open transaction) carries over between
//! calls. On top of that this module adds the bounds the Python server
//! does not have:
//!
//! - **connect timeout** ([`Config::connect_timeout`]) over TCP connect,
//!   TLS handshake, login and session set-up;
//! - **query timeout** ([`Config::query_timeout`]) over sending the
//!   statement and reading its result;
//! - **result limits** ([`Config::max_rows`], [`Config::max_result_bytes`]):
//!   rows are rendered while they are read and reading stops at the limit,
//!   so memory use does not depend on the size of the table. One row is at
//!   most [`MAX_PACKET_BYTES`];
//! - on a timeout, a truncated result or a cancelled call the statement is
//!   stopped on the server with `KILL` from a second connection instead of
//!   being left running.
//!
//! `LOAD DATA LOCAL INFILE` cannot read files of this process: no local
//! infile handler is installed.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use mysql_async::consts::{ColumnFlags, ColumnType};
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, DriverError, Error, IoError, Opts, OptsBuilder, SslOpts, Value};

use crate::config::{Config, TlsMode};
use crate::pyfmt;

/// Largest protocol packet accepted or sent (one row, one statement). Equal
/// to the largest JSON-RPC message a `talon-mcp` peer accepts, so it does
/// not restrict the statements that can arrive.
pub const MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;
/// Character set number of `binary`.
const BINARY_CHARSET: u16 = 63;
/// Longest error text handed to the caller, in characters.
const MAX_ERROR_CHARS: usize = 2000;
/// How long a `KILL` or a clean disconnect may take.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a result set is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truncation {
    /// More rows than [`Config::max_rows`].
    Rows(usize),
    /// More text than [`Config::max_result_bytes`].
    Bytes(usize),
}

/// A result set with every cell already rendered as the Python server
/// prints it (`None` is SQL `NULL`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rows {
    /// Column names.
    pub columns: Vec<String>,
    /// Row values.
    pub rows: Vec<Vec<Option<String>>>,
    /// Set when reading stopped at a limit; `rows` holds what was read.
    pub truncated: Option<Truncation>,
}

/// What a statement produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A result set (possibly without rows).
    Rows(Rows),
    /// No result set: the number of affected rows.
    Affected(u64),
}

/// Why a statement failed. `Display` is the text for the model; it never
/// contains the password.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DbError {
    /// The server rejected the login or the statement (its message).
    #[error("{0}")]
    Server(String),
    /// No connection could be established.
    #[error("{0}")]
    Connect(String),
    /// Connecting took longer than the connect timeout.
    #[error("Can't connect to MySQL server on '{address}' (timed out after {secs} s)")]
    ConnectTimeout {
        /// `host:port`.
        address: String,
        /// The timeout in seconds.
        secs: u64,
    },
    /// The statement took longer than the query timeout and was killed.
    #[error(
        "Query timed out after {secs} s and was cancelled (TALON_MYSQL_QUERY_TIMEOUT). \
         A statement that changes data may have been applied partially or not at all; \
         check before retrying."
    )]
    Timeout {
        /// The timeout in seconds.
        secs: u64,
    },
    /// One row or one statement is larger than [`MAX_PACKET_BYTES`].
    #[error(
        "Packet larger than {limit} bytes: select fewer or shorter columns \
         (for example LEFT(col, 1000)) or send a smaller statement"
    )]
    TooLarge {
        /// The limit in bytes.
        limit: usize,
    },
    /// The connection broke while the statement ran.
    #[error("Lost connection to MySQL server during query ({0})")]
    Lost(String),
}

/// Runs single statements. Implemented by [`MySqlBackend`]; tests use an
/// in-memory one.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Run one statement on a fresh connection.
    async fn run(&self, sql: &str) -> Result<Outcome, DbError>;

    /// The configured default database, if any.
    fn database(&self) -> Option<&str>;
}

// --- cell rendering ---------------------------------------------------

/// How a column's text-protocol bytes are turned into Python-style text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellKind {
    /// Integer types and `YEAR`.
    Int,
    /// `FLOAT` / `DOUBLE`.
    Float,
    /// `DECIMAL`.
    Decimal,
    /// `DATE`.
    Date,
    /// `DATETIME` / `TIMESTAMP`.
    DateTime,
    /// `TIME`.
    Time,
    /// `BIT`.
    Bit,
    /// `SET`.
    Set,
    /// Character data (also `JSON` and `ENUM`).
    Text,
    /// Binary data (`BINARY`, `BLOB`, geometry, ...).
    Bytes,
}

/// Pick the rendering for a column, following the type dispatch of
/// `mysql-connector-python`'s C extension.
pub fn cell_kind(column_type: ColumnType, flags: ColumnFlags, charset: u16) -> CellKind {
    use ColumnType::*;
    match column_type {
        MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_INT24 | MYSQL_TYPE_LONG
        | MYSQL_TYPE_LONGLONG | MYSQL_TYPE_YEAR => CellKind::Int,
        MYSQL_TYPE_FLOAT | MYSQL_TYPE_DOUBLE => CellKind::Float,
        MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => CellKind::Decimal,
        MYSQL_TYPE_DATE | MYSQL_TYPE_NEWDATE => CellKind::Date,
        MYSQL_TYPE_DATETIME
        | MYSQL_TYPE_DATETIME2
        | MYSQL_TYPE_TIMESTAMP
        | MYSQL_TYPE_TIMESTAMP2 => CellKind::DateTime,
        MYSQL_TYPE_TIME | MYSQL_TYPE_TIME2 => CellKind::Time,
        MYSQL_TYPE_BIT => CellKind::Bit,
        MYSQL_TYPE_JSON => CellKind::Text,
        _ if flags.contains(ColumnFlags::SET_FLAG) || column_type == MYSQL_TYPE_SET => {
            CellKind::Set
        }
        _ if charset == BINARY_CHARSET => CellKind::Bytes,
        _ => CellKind::Text,
    }
}

/// Render one non-NULL cell. `None` means Python `None` (a date Python
/// cannot represent), which is printed like SQL `NULL`.
pub fn render_cell(kind: CellKind, raw: &[u8]) -> Option<String> {
    let text = || String::from_utf8_lossy(raw);
    let or_text = |rendered: Option<String>| Some(rendered.unwrap_or_else(|| text().into_owned()));
    match kind {
        CellKind::Int => or_text(pyfmt::int_str(&text())),
        CellKind::Float => or_text(pyfmt::float_str(&text())),
        CellKind::Decimal => or_text(pyfmt::decimal_str(&text())),
        CellKind::Date => pyfmt::date_str(&text()),
        CellKind::DateTime => pyfmt::datetime_str(&text()),
        CellKind::Time => or_text(pyfmt::time_str(&text())),
        CellKind::Bit => Some(pyfmt::bit_str(raw).unwrap_or_else(|| pyfmt::bytes_repr(raw))),
        CellKind::Set => Some(pyfmt::set_str(&text())),
        CellKind::Text => Some(text().into_owned()),
        CellKind::Bytes => Some(pyfmt::bytes_repr(raw)),
    }
}

/// Accumulates rendered rows up to the row and byte limits.
#[derive(Debug)]
pub struct Collector {
    rows: Rows,
    max_rows: usize,
    max_bytes: usize,
    bytes: usize,
}

impl Collector {
    /// Start a result set with these column names.
    pub fn new(columns: Vec<String>, max_rows: usize, max_bytes: usize) -> Self {
        let bytes = columns.iter().map(|c| c.len() + 1).sum();
        Self {
            rows: Rows {
                columns,
                rows: Vec::new(),
                truncated: None,
            },
            max_rows,
            max_bytes,
            bytes,
        }
    }

    /// Add a row. Returns `false` when the row did not fit: the result is
    /// then marked truncated and no further row may be added.
    pub fn push(&mut self, row: Vec<Option<String>>) -> bool {
        if self.rows.truncated.is_some() {
            return false;
        }
        if self.rows.rows.len() >= self.max_rows {
            self.rows.truncated = Some(Truncation::Rows(self.max_rows));
            return false;
        }
        // "NULL" is the longest rendering of a NULL cell; one separator or
        // line break per cell.
        let size: usize = row
            .iter()
            .map(|cell| cell.as_ref().map_or(4, String::len) + 1)
            .sum();
        if self.bytes.saturating_add(size) > self.max_bytes {
            self.rows.truncated = Some(Truncation::Bytes(self.max_bytes));
            return false;
        }
        self.bytes += size;
        self.rows.rows.push(row);
        true
    }

    /// The collected result.
    pub fn finish(self) -> Rows {
        self.rows
    }
}

// --- error texts --------------------------------------------------------

fn cap(text: &str) -> String {
    let mut out: String = text.chars().take(MAX_ERROR_CHARS).collect();
    if text.chars().count() > MAX_ERROR_CHARS {
        out.push_str("... (truncated)");
    }
    out
}

/// Remove the password from a message, should a driver or server ever
/// echo it. Short passwords are left alone: masking every occurrence of
/// e.g. `a` would only garble the text.
fn scrub(text: &str, password: &str) -> String {
    if password.len() >= 6 && text.contains(password) {
        cap(&text.replace(password, "***"))
    } else {
        cap(text)
    }
}

// --- the real backend ---------------------------------------------------

struct Shared {
    /// Connection options for statements.
    primary: Opts,
    /// Plaintext options used when the server has no TLS (`PREFERRED`).
    fallback: Option<Opts>,
    /// Options for the `KILL` connection, per transport.
    kill_primary: Opts,
    kill_fallback: Option<Opts>,
    address: String,
    password: String,
    tls: TlsMode,
    loopback: bool,
    connect_timeout: Duration,
    warned_plaintext: AtomicBool,
    /// `KILL`s started by dropped calls that have not finished yet.
    pending_kills: AtomicUsize,
    kills_done: tokio::sync::Notify,
}

/// [`Backend`] on a MySQL / MariaDB server through `mysql_async`.
pub struct MySqlBackend {
    shared: Arc<Shared>,
    database: Option<String>,
    query_timeout: Duration,
    max_rows: usize,
    max_result_bytes: usize,
}

impl std::fmt::Debug for MySqlBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySqlBackend")
            .field("address", &self.shared.address)
            .field("tls", &self.shared.tls)
            .field("database", &self.database)
            .finish()
    }
}

fn ssl_opts(config: &Config) -> Option<SslOpts> {
    match config.tls {
        TlsMode::Disabled => None,
        TlsMode::Preferred => Some(SslOpts::default().with_danger_accept_invalid_certs(true)),
        TlsMode::Required | TlsMode::VerifyCa | TlsMode::VerifyIdentity => {
            let mut opts = match &config.ssl_ca {
                // Only the given CA is trusted, not the public web roots.
                Some(path) => SslOpts::default()
                    .with_root_certs(vec![path.clone().into()])
                    .with_disable_built_in_roots(true),
                None => SslOpts::default(),
            };
            if let Some(name) = &config.ssl_hostname {
                opts = opts.with_danger_tls_hostname_override(Some(name.clone()));
            }
            Some(opts)
        }
    }
}

fn base_opts(config: &Config, ssl: Option<SslOpts>) -> OptsBuilder {
    OptsBuilder::default()
        .ip_or_hostname(config.host.clone())
        .tcp_port(config.port)
        .user(Some(config.user.clone()))
        .pass(Some(config.password.clone()))
        // Always TCP: never hop to the unix socket the server advertises.
        .prefer_socket(false)
        .stmt_cache_size(0)
        // Fixed instead of asking the server on every connection.
        .max_allowed_packet(Some(MAX_PACKET_BYTES))
        .wait_timeout(Some(28_800))
        .ssl_opts(ssl)
}

impl MySqlBackend {
    /// Prepare the backend. No connection is made until a statement runs.
    pub fn new(config: &Config) -> Self {
        let statement_opts = |ssl: Option<SslOpts>| -> Opts {
            base_opts(config, ssl)
                .db_name(config.database.clone())
                .init(config.session_setup())
                .into()
        };
        let kill_opts = |ssl: Option<SslOpts>| -> Opts { base_opts(config, ssl).into() };
        let ssl = ssl_opts(config);
        let preferred = config.tls == TlsMode::Preferred;
        Self {
            shared: Arc::new(Shared {
                primary: statement_opts(ssl.clone()),
                fallback: preferred.then(|| statement_opts(None)),
                kill_primary: kill_opts(ssl),
                kill_fallback: preferred.then(|| kill_opts(None)),
                address: config.address(),
                password: config.password.clone(),
                tls: config.tls,
                loopback: config.is_loopback(),
                connect_timeout: config.connect_timeout,
                warned_plaintext: AtomicBool::new(false),
                pending_kills: AtomicUsize::new(0),
                kills_done: tokio::sync::Notify::new(),
            }),
            database: config.database.clone(),
            query_timeout: config.query_timeout,
            max_rows: config.max_rows,
            max_result_bytes: config.max_result_bytes,
        }
    }

    /// Wait (at most `max`) for the `KILL`s of cancelled calls to be sent.
    /// Call it before the process exits, so that a statement whose call was
    /// dropped at shutdown does not keep running on the server.
    pub async fn settle(&self, max: Duration) {
        let shared = &self.shared;
        let wait = async {
            loop {
                let notified = shared.kills_done.notified();
                if shared.pending_kills.load(Ordering::SeqCst) == 0 {
                    break;
                }
                notified.await;
            }
        };
        let _ = tokio::time::timeout(max, wait).await;
    }
}

impl Shared {
    /// Connect with `primary`, or with `fallback` when the server has no
    /// TLS and the mode allows plaintext.
    async fn open(&self, primary: &Opts, fallback: Option<&Opts>) -> Result<Conn, Error> {
        match Conn::new(primary.clone()).await {
            Err(Error::Driver(DriverError::NoClientSslFlagFromServer)) => match fallback {
                Some(plain) => {
                    if !self.loopback && !self.warned_plaintext.swap(true, Ordering::Relaxed) {
                        tracing::warn!(
                            server = %self.address,
                            "the MySQL server does not offer TLS: using an unencrypted \
                             connection (MYSQL_SSL_MODE=PREFERRED)"
                        );
                    }
                    Conn::new(plain.clone()).await
                }
                None => Err(Error::Driver(DriverError::NoClientSslFlagFromServer)),
            },
            other => other,
        }
    }

    async fn connect(&self) -> Result<Conn, DbError> {
        let attempt = self.open(&self.primary, self.fallback.as_ref());
        match tokio::time::timeout(self.connect_timeout, attempt).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(self.connect_error(e)),
            Err(_) => Err(DbError::ConnectTimeout {
                address: self.address.clone(),
                secs: self.connect_timeout.as_secs(),
            }),
        }
    }

    fn connect_error(&self, error: Error) -> DbError {
        let address = &self.address;
        match error {
            // Access denied, unknown database, a rejected session setting.
            Error::Server(e) => DbError::Server(scrub(&e.message, &self.password)),
            Error::Driver(DriverError::NoClientSslFlagFromServer) => DbError::Connect(format!(
                "SSL connection error: the MySQL server on '{address}' does not offer TLS \
                 (MYSQL_SSL_MODE={})",
                self.tls.as_str()
            )),
            Error::Io(IoError::Tls(e)) => {
                DbError::Connect(scrub(&format!("SSL connection error: {e}"), &self.password))
            }
            Error::Io(IoError::Io(e)) => {
                // rustls failures (certificate, protocol version) arrive
                // as `InvalidData` I/O errors.
                let what = if e.kind() == std::io::ErrorKind::InvalidData {
                    format!(
                        "SSL connection error: {e} (MYSQL_SSL_MODE={})",
                        self.tls.as_str()
                    )
                } else {
                    format!("Can't connect to MySQL server on '{address}' ({e})")
                };
                DbError::Connect(scrub(&what, &self.password))
            }
            other => DbError::Connect(scrub(
                &format!("Can't connect to MySQL server on '{address}' ({other})"),
                &self.password,
            )),
        }
    }

    fn query_error(&self, error: Error) -> DbError {
        match error {
            Error::Server(e) => DbError::Server(scrub(&e.message, &self.password)),
            Error::Driver(DriverError::PacketTooLarge) => DbError::TooLarge {
                limit: MAX_PACKET_BYTES,
            },
            // The server asked for a local file; none is ever sent. The
            // text is the server's own for a client without the capability.
            Error::Driver(DriverError::LocalInfile(_)) => DbError::Server(
                "Loading local data is disabled; this must be enabled on both the client \
                 and server sides"
                    .to_string(),
            ),
            other => {
                let text = other.to_string();
                if text.contains("max_allowed_packet") || text.contains("Packet too large") {
                    DbError::TooLarge {
                        limit: MAX_PACKET_BYTES,
                    }
                } else {
                    DbError::Lost(scrub(&text, &self.password))
                }
            }
        }
    }

    /// Stop whatever connection `id` is doing (`KILL`), best effort.
    async fn kill(&self, id: u32) {
        let work = async {
            let mut conn = self
                .open(&self.kill_primary, self.kill_fallback.as_ref())
                .await?;
            conn.query_drop(format!("KILL {id}")).await?;
            conn.disconnect().await
        };
        let budget = self.connect_timeout.min(CLEANUP_TIMEOUT);
        match tokio::time::timeout(budget, work).await {
            Ok(Ok(())) => tracing::debug!(connection = id, "killed the server-side statement"),
            Ok(Err(e)) => {
                // "Unknown thread id" is the normal case when it already ended.
                tracing::debug!(connection = id, error = %scrub(&e.to_string(), &self.password),
                    "could not kill the server-side statement");
            }
            Err(_) => tracing::debug!(connection = id, "timed out killing the statement"),
        }
    }
}

/// Kills the statement if the call is dropped while it runs (the MCP
/// client cancelled the request or went away).
struct KillOnDrop {
    shared: Option<Arc<Shared>>,
    id: u32,
}

impl KillOnDrop {
    fn disarm(&mut self) {
        self.shared = None;
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let id = self.id;
            shared.pending_kills.fetch_add(1, Ordering::SeqCst);
            handle.spawn(async move {
                shared.kill(id).await;
                shared.pending_kills.fetch_sub(1, Ordering::SeqCst);
                shared.kills_done.notify_waiters();
            });
        }
    }
}

async fn read_result(
    conn: &mut Conn,
    sql: &str,
    max_rows: usize,
    max_bytes: usize,
) -> Result<Outcome, Error> {
    let mut result = conn.query_iter(sql).await?;
    let (names, kinds): (Vec<String>, Vec<CellKind>) = result
        .columns_ref()
        .iter()
        .map(|c| {
            (
                c.name_str().into_owned(),
                cell_kind(c.column_type(), c.flags(), c.character_set()),
            )
        })
        .unzip();
    if names.is_empty() {
        return Ok(Outcome::Affected(result.affected_rows()));
    }
    let mut collector = Collector::new(names, max_rows, max_bytes);
    // `next` yields `None` at the end of the first result set; further sets
    // (a procedure with several SELECTs) are not read, as in the Python
    // server.
    while let Some(row) = result.next().await? {
        let cells = row
            .unwrap()
            .into_iter()
            .zip(&kinds)
            .map(|(value, kind)| match value {
                Value::NULL => None,
                Value::Bytes(raw) => render_cell(*kind, &raw),
                // The text protocol only sends bytes; be total anyway.
                other => Some(other.as_sql(true)),
            })
            .collect();
        if !collector.push(cells) {
            break;
        }
    }
    Ok(Outcome::Rows(collector.finish()))
}

#[async_trait]
impl Backend for MySqlBackend {
    async fn run(&self, sql: &str) -> Result<Outcome, DbError> {
        let shared = &self.shared;
        let mut conn = shared.connect().await?;
        let id = conn.id();
        let mut guard = KillOnDrop {
            shared: Some(Arc::clone(shared)),
            id,
        };
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            self.query_timeout,
            read_result(&mut conn, sql, self.max_rows, self.max_result_bytes),
        )
        .await;
        guard.disarm();
        // Never the statement or the data: only sizes and timing.
        tracing::debug!(
            connection = id,
            statement_bytes = sql.len(),
            elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "statement finished"
        );
        match outcome {
            Err(_) => {
                shared.kill(id).await;
                drop(conn);
                Err(DbError::Timeout {
                    secs: self.query_timeout.as_secs(),
                })
            }
            Ok(Err(e)) => {
                drop(conn);
                Err(shared.query_error(e))
            }
            Ok(Ok(Outcome::Rows(rows))) if rows.truncated.is_some() => {
                // The server is still sending rows: stop it rather than
                // read (and discard) the rest of the table.
                shared.kill(id).await;
                drop(conn);
                Ok(Outcome::Rows(rows))
            }
            Ok(Ok(outcome)) => {
                let _ = tokio::time::timeout(CLEANUP_TIMEOUT, conn.disconnect()).await;
                Ok(outcome)
            }
        }
    }

    fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ColumnType::*;

    const UTF8MB4: u16 = 255;

    fn kind(t: ColumnType) -> CellKind {
        cell_kind(t, ColumnFlags::empty(), UTF8MB4)
    }

    #[test]
    fn column_types_map_like_the_python_connector() {
        for t in [
            MYSQL_TYPE_TINY,
            MYSQL_TYPE_SHORT,
            MYSQL_TYPE_INT24,
            MYSQL_TYPE_LONG,
            MYSQL_TYPE_LONGLONG,
            MYSQL_TYPE_YEAR,
        ] {
            assert_eq!(
                cell_kind(t, ColumnFlags::empty(), BINARY_CHARSET),
                CellKind::Int
            );
        }
        assert_eq!(kind(MYSQL_TYPE_FLOAT), CellKind::Float);
        assert_eq!(kind(MYSQL_TYPE_DOUBLE), CellKind::Float);
        assert_eq!(kind(MYSQL_TYPE_NEWDECIMAL), CellKind::Decimal);
        assert_eq!(kind(MYSQL_TYPE_DECIMAL), CellKind::Decimal);
        assert_eq!(kind(MYSQL_TYPE_DATE), CellKind::Date);
        assert_eq!(kind(MYSQL_TYPE_DATETIME), CellKind::DateTime);
        assert_eq!(kind(MYSQL_TYPE_TIMESTAMP), CellKind::DateTime);
        assert_eq!(kind(MYSQL_TYPE_TIME), CellKind::Time);
        assert_eq!(kind(MYSQL_TYPE_BIT), CellKind::Bit);
        assert_eq!(kind(MYSQL_TYPE_VAR_STRING), CellKind::Text);
        assert_eq!(kind(MYSQL_TYPE_STRING), CellKind::Text);
        assert_eq!(kind(MYSQL_TYPE_BLOB), CellKind::Text); // TEXT columns
        // JSON columns report the binary character set but are text.
        assert_eq!(
            cell_kind(MYSQL_TYPE_JSON, ColumnFlags::BINARY_FLAG, BINARY_CHARSET),
            CellKind::Text
        );
        for t in [
            MYSQL_TYPE_BLOB,
            MYSQL_TYPE_TINY_BLOB,
            MYSQL_TYPE_LONG_BLOB,
            MYSQL_TYPE_VAR_STRING,
            MYSQL_TYPE_STRING,
            MYSQL_TYPE_GEOMETRY,
        ] {
            assert_eq!(
                cell_kind(t, ColumnFlags::BINARY_FLAG, BINARY_CHARSET),
                CellKind::Bytes,
                "{t:?}"
            );
        }
        // SET columns arrive as STRING with the SET flag.
        assert_eq!(
            cell_kind(MYSQL_TYPE_STRING, ColumnFlags::SET_FLAG, UTF8MB4),
            CellKind::Set
        );
        assert_eq!(
            cell_kind(MYSQL_TYPE_STRING, ColumnFlags::ENUM_FLAG, UTF8MB4),
            CellKind::Text
        );
    }

    #[test]
    fn cells_render_like_python_str() {
        let r = |k, raw: &[u8]| render_cell(k, raw);
        assert_eq!(r(CellKind::Int, b"-128").as_deref(), Some("-128"));
        assert_eq!(r(CellKind::Int, b"0042").as_deref(), Some("42"));
        assert_eq!(r(CellKind::Float, b"1e20").as_deref(), Some("1e+20"));
        assert_eq!(
            r(CellKind::Decimal, b"1.100000").as_deref(),
            Some("1.100000")
        );
        assert_eq!(
            r(CellKind::Date, b"2025-01-02").as_deref(),
            Some("2025-01-02")
        );
        assert_eq!(r(CellKind::Date, b"0000-00-00"), None);
        assert_eq!(
            r(CellKind::DateTime, b"2025-01-02 03:04:05.120").as_deref(),
            Some("2025-01-02 03:04:05.120000")
        );
        assert_eq!(r(CellKind::DateTime, b"0000-00-00 00:00:00"), None);
        assert_eq!(
            r(CellKind::Time, b"838:59:59").as_deref(),
            Some("34 days, 22:59:59")
        );
        assert_eq!(r(CellKind::Bit, &[0xa5]).as_deref(), Some("165"));
        assert_eq!(r(CellKind::Set, b"x,z").as_deref(), Some("{'x', 'z'}"));
        assert_eq!(r(CellKind::Set, b"").as_deref(), Some("set()"));
        assert_eq!(r(CellKind::Text, "é✓".as_bytes()).as_deref(), Some("é✓"));
        assert_eq!(
            r(CellKind::Bytes, b"\x00\xffAB").as_deref(),
            Some(r"b'\x00\xffAB'")
        );
        // Unparseable numbers fall back to the server's text.
        assert_eq!(r(CellKind::Int, b"n/a").as_deref(), Some("n/a"));
        assert_eq!(r(CellKind::Float, b"").as_deref(), Some(""));
        assert_eq!(r(CellKind::Time, b"??").as_deref(), Some("??"));
        // Invalid UTF-8 in a text column does not fail the call.
        assert_eq!(r(CellKind::Text, b"a\xffb").as_deref(), Some("a\u{fffd}b"));
    }

    fn row(cells: &[Option<&str>]) -> Vec<Option<String>> {
        cells.iter().map(|c| c.map(str::to_string)).collect()
    }

    #[test]
    fn collector_stops_at_the_row_limit() {
        let mut c = Collector::new(vec!["id".into()], 2, 1_000);
        assert!(c.push(row(&[Some("1")])));
        assert!(c.push(row(&[Some("2")])));
        assert!(!c.push(row(&[Some("3")])));
        assert!(!c.push(row(&[Some("4")])));
        let rows = c.finish();
        assert_eq!(rows.rows.len(), 2);
        assert_eq!(rows.truncated, Some(Truncation::Rows(2)));
    }

    #[test]
    fn exactly_the_limit_is_not_truncated() {
        let mut c = Collector::new(vec!["id".into()], 2, 1_000);
        assert!(c.push(row(&[Some("1")])));
        assert!(c.push(row(&[Some("2")])));
        assert_eq!(c.finish().truncated, None);
    }

    #[test]
    fn collector_stops_at_the_byte_limit() {
        // Header "id," = 3 bytes; each row "xxxxxxxx," = 9 bytes.
        let mut c = Collector::new(vec!["id".into()], 100, 30);
        for _ in 0..3 {
            assert!(c.push(row(&[Some("xxxxxxxx")])));
        }
        assert!(!c.push(row(&[Some("xxxxxxxx")])));
        let rows = c.finish();
        assert_eq!(rows.rows.len(), 3);
        assert_eq!(rows.truncated, Some(Truncation::Bytes(30)));
    }

    #[test]
    fn a_single_oversized_row_yields_no_rows_but_a_marker() {
        let mut c = Collector::new(vec!["blob".into()], 100, 16);
        assert!(!c.push(row(&[Some(&"x".repeat(100))])));
        let rows = c.finish();
        assert!(rows.rows.is_empty());
        assert_eq!(rows.truncated, Some(Truncation::Bytes(16)));
    }

    #[test]
    fn null_cells_count_towards_the_byte_limit() {
        let mut c = Collector::new(vec!["a".into()], 100, 12);
        assert!(c.push(row(&[None]))); // 2 + 5
        assert!(c.push(row(&[None]))); // 12
        assert!(!c.push(row(&[None])));
    }

    #[test]
    fn error_texts_are_capped_and_scrubbed() {
        assert_eq!(
            scrub("Access denied (pw hunter2-secret)", "hunter2-secret"),
            "Access denied (pw ***)"
        );
        // Too short to mask without garbling the message.
        assert_eq!(
            scrub("Table 'a' doesn't exist", "a"),
            "Table 'a' doesn't exist"
        );
        assert_eq!(scrub("plain", ""), "plain");
        let long = "x".repeat(5_000);
        let capped = scrub(&long, "pw");
        assert!(capped.ends_with("... (truncated)"));
        assert_eq!(
            capped.chars().count(),
            MAX_ERROR_CHARS + "... (truncated)".len()
        );
    }

    #[test]
    fn error_display() {
        assert_eq!(
            DbError::ConnectTimeout {
                address: "db:3306".into(),
                secs: 10
            }
            .to_string(),
            "Can't connect to MySQL server on 'db:3306' (timed out after 10 s)"
        );
        assert!(
            DbError::Timeout { secs: 120 }
                .to_string()
                .starts_with("Query timed out after 120 s and was cancelled")
        );
        assert!(
            DbError::TooLarge { limit: 16 }
                .to_string()
                .starts_with("Packet larger than 16 bytes")
        );
        assert_eq!(
            DbError::Lost("eof".into()).to_string(),
            "Lost connection to MySQL server during query (eof)"
        );
    }

    #[test]
    fn tls_options_follow_the_mode() {
        let config = |mode: &str, ca: Option<&str>| {
            Config::from_lookup(|name| match name {
                "MYSQL_USER" => Some("u".into()),
                "MYSQL_PASSWORD" => Some("p".into()),
                "MYSQL_SSL_MODE" => Some(mode.into()),
                "MYSQL_SSL_CA" => ca.map(str::to_string),
                _ => None,
            })
            .unwrap()
        };
        assert!(ssl_opts(&config("DISABLED", None)).is_none());
        let preferred = ssl_opts(&config("PREFERRED", None)).unwrap();
        assert!(preferred.accept_invalid_certs());
        for mode in ["REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY"] {
            let opts = ssl_opts(&config(mode, None)).unwrap();
            assert!(!opts.accept_invalid_certs(), "{mode}");
            assert!(!opts.skip_domain_validation(), "{mode}");
            assert!(!opts.disable_built_in_roots(), "{mode}");
            assert_eq!(opts.tls_hostname_override(), None);
        }
        // With a CA file only that CA is trusted.
        let ca = std::env::current_exe().unwrap();
        let pinned = ssl_opts(&config("VERIFY_CA", ca.to_str())).unwrap();
        assert!(pinned.disable_built_in_roots());
        assert_eq!(pinned.root_certs().len(), 1);
    }

    #[test]
    fn certificate_name_override() {
        let config = Config::from_lookup(|name| match name {
            "MYSQL_USER" => Some("u".into()),
            "MYSQL_PASSWORD" => Some("p".into()),
            "MYSQL_HOST" => Some("10.0.0.5".into()),
            "MYSQL_SSL_MODE" => Some("VERIFY_IDENTITY".into()),
            "MYSQL_SSL_HOSTNAME" => Some("db.internal".into()),
            _ => None,
        })
        .unwrap();
        let opts = ssl_opts(&config).unwrap();
        assert_eq!(opts.tls_hostname_override(), Some("db.internal"));
    }

    #[test]
    fn backend_debug_has_no_credentials() {
        let config = Config::from_lookup(|name| match name {
            "MYSQL_USER" => Some("talon-user".into()),
            "MYSQL_PASSWORD" => Some("hunter2-secret".into()),
            _ => None,
        })
        .unwrap();
        let backend = MySqlBackend::new(&config);
        let text = format!("{backend:?}");
        assert!(
            !text.contains("hunter2-secret") && !text.contains("talon-user"),
            "{text}"
        );
        assert_eq!(backend.database(), None);
    }
}
