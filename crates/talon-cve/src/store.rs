//! The SQLite file: its schema, the writer used by the importers and the
//! read-only queries behind the MCP tools.
//!
//! ## Layout
//! | Table | Content |
//! |---|---|
//! | `meta` | `key → value`: schema version, time of the last sync, per-source state |
//! | `cve` | one row per CVE: dates, status, English description, headline CVSS, CWEs, JSON of all metrics, references and CPE matches |
//! | `product` | `(vendor, product, cve)` for the product search |
//! | `cve_fts` | FTS5 index over id, description and product names |
//! | `epss` | EPSS score and percentile per CVE |
//! | `kev` | the CISA Known Exploited Vulnerabilities catalogue |
//!
//! ## Reading
//! [`Reader`] opens the file read-only and *immutable* for every call: the
//! file is never changed in place (a sync builds a new one and renames it
//! over the old, see [`crate::sync`]), so SQLite needs no journal, no lock
//! file and no write access to the directory, which is a read-only mount in
//! the agent container. A call that started before a swap keeps reading the
//! old file.
//!
//! Every statement is parameterised; user text never becomes SQL. The full
//! text query is built from tokens that were reduced to letters and digits
//! and quoted ([`fts_query`]).

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params, params_from_iter};
use serde::Serialize;
use serde_json::Value;

use crate::model::{CveRecord, EpssScore, KevEntry};

/// Version of the table layout. A file with another version is rebuilt
/// from scratch by the next sync and refused by the reader.
pub const SCHEMA_VERSION: &str = "1";

/// `meta` key: schema version.
pub const META_SCHEMA: &str = "schema_version";
/// `meta` key: when the last successful sync finished (RFC 3339, UTC).
pub const META_SYNCED_AT: &str = "synced_at";
/// `meta` key: when NVD data was last applied (RFC 3339, UTC).
pub const META_NVD_SYNCED_AT: &str = "nvd_synced_at";
/// `meta` key prefix: SHA-256 of the NVD feed `<name>` that was imported.
pub const META_NVD_FEED_PREFIX: &str = "nvd_feed:";
/// `meta` key: `score_date` of the imported EPSS file.
pub const META_EPSS_DATE: &str = "epss_score_date";
/// `meta` key: `model_version` of the imported EPSS file.
pub const META_EPSS_MODEL: &str = "epss_model_version";
/// `meta` key: `catalogVersion` of the imported KEV catalogue.
pub const META_KEV_VERSION: &str = "kev_catalog_version";
/// `meta` key: `dateReleased` of the imported KEV catalogue.
pub const META_KEV_RELEASED: &str = "kev_date_released";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS cve (
    rid           INTEGER PRIMARY KEY,
    id            TEXT NOT NULL UNIQUE,
    published     TEXT,
    modified      TEXT,
    status        TEXT,
    description   TEXT NOT NULL DEFAULT '',
    cvss_version  TEXT,
    cvss_score    REAL,
    cvss_severity TEXT,
    cvss_vector   TEXT,
    cwe           TEXT NOT NULL DEFAULT '',
    metrics       TEXT NOT NULL DEFAULT '[]',
    refs          TEXT NOT NULL DEFAULT '[]',
    cpe           TEXT NOT NULL DEFAULT '[]',
    cpe_total     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cve_published ON cve (published);

CREATE TABLE IF NOT EXISTS product (
    vendor  TEXT NOT NULL,
    product TEXT NOT NULL,
    cve_id  TEXT NOT NULL,
    PRIMARY KEY (product, vendor, cve_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_product_cve ON product (cve_id);
CREATE INDEX IF NOT EXISTS idx_product_vendor ON product (vendor, cve_id);

CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5 (
    text,
    content = '',
    contentless_delete = 1,
    tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS kev (
    cve_id          TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL DEFAULT '',
    product         TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL DEFAULT '',
    date_added      TEXT NOT NULL DEFAULT '',
    due_date        TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    required_action TEXT NOT NULL DEFAULT '',
    ransomware      TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT ''
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_kev_added ON kev (date_added);
";

/// A failure of the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database file does not exist.
    #[error("the CVE database {0} does not exist")]
    Missing(PathBuf),
    /// The file was written by another version of the layout.
    #[error("the CVE database has schema version {found}, this program reads version {expected}")]
    Schema {
        /// Version in the file (`none` when the file is not a CVE database).
        found: String,
        /// Version this program reads and writes.
        expected: &'static str,
    },
    /// SQLite reported an error.
    #[error("CVE database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A filesystem operation failed.
    #[error("CVE database: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias of the store.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Writes a database file. Used only by a sync, on a private copy that no
/// reader sees until it is renamed into place.
#[derive(Debug)]
pub struct Writer {
    conn: Connection,
}

impl Writer {
    /// Open (or create) the file at `path` for writing and make sure the
    /// tables exist.
    ///
    /// The file is a working copy: the rollback journal is kept in memory
    /// and fsync is off for speed, because a failed run throws the copy
    /// away. A failed [`Writer::batch`] still rolls back.
    ///
    /// # Errors
    /// SQLite cannot open or initialise the file, or the file holds another
    /// schema version.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "MEMORY")?;
        conn.pragma_update(None, "synchronous", "OFF")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.execute_batch(SCHEMA)?;
        let writer = Self { conn };
        match writer.meta(META_SCHEMA)? {
            None => writer.set_meta(META_SCHEMA, SCHEMA_VERSION)?,
            Some(v) if v == SCHEMA_VERSION => {}
            Some(found) => {
                return Err(StoreError::Schema {
                    found,
                    expected: SCHEMA_VERSION,
                });
            }
        }
        Ok(writer)
    }

    /// Value of a `meta` key.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    /// Set a `meta` key.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    /// Run `f` inside one transaction (one per feed: orders of magnitude
    /// faster than a statement at a time).
    ///
    /// # Errors
    /// What `f` returns, or SQLite errors of `BEGIN` / `COMMIT`.
    pub fn batch<T, E>(
        &mut self,
        f: impl FnOnce(&Batch<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<StoreError>,
    {
        let tx = self.conn.transaction().map_err(StoreError::from)?;
        let out = f(&Batch { conn: &tx })?;
        tx.commit().map_err(StoreError::from)?;
        Ok(out)
    }

    /// Number of rows in `table` (`cve`, `epss`, `kev`, `product`).
    ///
    /// # Errors
    /// SQLite errors.
    pub fn count(&self, table: Table) -> Result<u64> {
        count(&self.conn, table)
    }

    /// Check the file (`PRAGMA quick_check`), merge the full-text index and
    /// close it.
    ///
    /// # Errors
    /// SQLite errors, or a file that fails the check.
    pub fn finish(self) -> Result<()> {
        self.conn
            .execute("INSERT INTO cve_fts (cve_fts) VALUES ('optimize')", [])?;
        let verdict: String = self
            .conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if verdict != "ok" {
            return Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
                Some(format!("quick_check: {verdict}")),
            )));
        }
        self.conn.close().map_err(|(_, e)| StoreError::Sqlite(e))
    }
}

/// The tables whose rows are counted for the status report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    /// CVE records.
    Cve,
    /// EPSS scores.
    Epss,
    /// KEV entries.
    Kev,
}

impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Cve => "cve",
            Self::Epss => "epss",
            Self::Kev => "kev",
        }
    }
}

fn count(conn: &Connection, table: Table) -> Result<u64> {
    // The table name comes from the enum above, never from input.
    let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {}", table.name()), [], |r| {
        r.get(0)
    })?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// Write access inside one transaction ([`Writer::batch`]).
#[derive(Debug)]
pub struct Batch<'a> {
    conn: &'a Connection,
}

impl Batch<'_> {
    /// Insert a CVE, or replace it when the stored row is not newer
    /// (`lastModified`). Returns whether the row was written.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn upsert_cve(&self, rec: &CveRecord) -> Result<bool> {
        let existing: Option<(i64, Option<String>)> = self
            .conn
            .prepare_cached("SELECT rid, modified FROM cve WHERE id = ?1")?
            .query_row([&rec.id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        if let Some((_, Some(stored))) = &existing
            && rec.modified.as_deref().is_some_and(|m| m < stored.as_str())
        {
            return Ok(false);
        }
        let metrics = serde_json::to_string(&rec.metrics).unwrap_or_else(|_| "[]".into());
        let refs = serde_json::to_string(&rec.references).unwrap_or_else(|_| "[]".into());
        let cpe = serde_json::to_string(&rec.cpe).unwrap_or_else(|_| "[]".into());
        let headline = rec.headline();
        let cwe = rec.cwes.join(",");
        let rid = match existing {
            Some((rid, _)) => {
                self.conn
                    .prepare_cached(
                        "UPDATE cve SET published = ?2, modified = ?3, status = ?4,
                             description = ?5, cvss_version = ?6, cvss_score = ?7,
                             cvss_severity = ?8, cvss_vector = ?9, cwe = ?10, metrics = ?11,
                             refs = ?12, cpe = ?13, cpe_total = ?14
                         WHERE rid = ?1",
                    )?
                    .execute(params![
                        rid,
                        rec.published,
                        rec.modified,
                        rec.status,
                        rec.description,
                        headline.map(|m| m.version.as_str()),
                        headline.map(|m| m.score),
                        headline.map(|m| m.severity.as_str()),
                        headline.map(|m| m.vector.as_str()),
                        cwe,
                        metrics,
                        refs,
                        cpe,
                        rec.cpe_total,
                    ])?;
                self.conn
                    .prepare_cached("DELETE FROM product WHERE cve_id = ?1")?
                    .execute([&rec.id])?;
                self.conn
                    .prepare_cached("DELETE FROM cve_fts WHERE rowid = ?1")?
                    .execute([rid])?;
                rid
            }
            None => {
                self.conn
                    .prepare_cached(
                        "INSERT INTO cve (id, published, modified, status, description,
                             cvss_version, cvss_score, cvss_severity, cvss_vector, cwe, metrics,
                             refs, cpe, cpe_total)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    )?
                    .execute(params![
                        rec.id,
                        rec.published,
                        rec.modified,
                        rec.status,
                        rec.description,
                        headline.map(|m| m.version.as_str()),
                        headline.map(|m| m.score),
                        headline.map(|m| m.severity.as_str()),
                        headline.map(|m| m.vector.as_str()),
                        cwe,
                        metrics,
                        refs,
                        cpe,
                        rec.cpe_total,
                    ])?;
                self.conn.last_insert_rowid()
            }
        };
        let mut insert_product = self.conn.prepare_cached(
            "INSERT OR IGNORE INTO product (vendor, product, cve_id) VALUES (?1, ?2, ?3)",
        )?;
        let mut names = String::new();
        for (vendor, product) in &rec.products {
            insert_product.execute(params![vendor, product, rec.id])?;
            names.push(' ');
            names.push_str(vendor);
            names.push(' ');
            names.push_str(product);
        }
        self.conn
            .prepare_cached("INSERT INTO cve_fts (rowid, text) VALUES (?1, ?2)")?
            .execute(params![
                rid,
                format!("{} {}{}", rec.id, rec.description, names.replace('_', " "))
            ])?;
        Ok(true)
    }

    /// Replace every EPSS score with `scores`. Returns the number of rows.
    ///
    /// # Errors
    /// SQLite errors, or the first error `scores` yields.
    pub fn replace_epss<E>(
        &self,
        scores: impl Iterator<Item = std::result::Result<EpssScore, E>>,
    ) -> std::result::Result<u64, E>
    where
        E: From<StoreError>,
    {
        let sql = |e: rusqlite::Error| E::from(StoreError::from(e));
        self.conn.execute("DELETE FROM epss", []).map_err(sql)?;
        let mut insert = self
            .conn
            .prepare_cached(
                "INSERT OR REPLACE INTO epss (cve_id, score, percentile) VALUES (?1, ?2, ?3)",
            )
            .map_err(sql)?;
        let mut n = 0;
        for score in scores {
            let score = score?;
            insert
                .execute(params![score.cve_id, score.score, score.percentile])
                .map_err(sql)?;
            n += 1;
        }
        Ok(n)
    }

    /// Replace the KEV catalogue with `entries`. Returns the number of rows.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn replace_kev(&self, entries: &[KevEntry]) -> Result<u64> {
        self.conn.execute("DELETE FROM kev", [])?;
        let mut insert = self.conn.prepare_cached(
            "INSERT OR REPLACE INTO kev (cve_id, vendor, product, name, date_added, due_date,
                 description, required_action, ransomware, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for e in entries {
            insert.execute(params![
                e.cve_id,
                e.vendor,
                e.product,
                e.name,
                e.date_added,
                e.due_date,
                e.description,
                e.required_action,
                e.ransomware,
                e.notes,
            ])?;
        }
        Ok(entries.len() as u64)
    }
}

/// What the database holds and how old it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    /// When the last successful sync finished (RFC 3339, UTC).
    pub synced_at: Option<String>,
    /// When NVD data was last applied.
    pub nvd_synced_at: Option<String>,
    /// CVE records.
    pub cve_count: u64,
    /// EPSS scores.
    pub epss_count: u64,
    /// `score_date` of the EPSS file.
    pub epss_score_date: Option<String>,
    /// `model_version` of the EPSS file.
    pub epss_model_version: Option<String>,
    /// KEV entries.
    pub kev_count: u64,
    /// `catalogVersion` of the KEV catalogue.
    pub kev_catalog_version: Option<String>,
    /// `dateReleased` of the KEV catalogue.
    pub kev_date_released: Option<String>,
}

impl Status {
    /// Whole days since the last sync at `now`; `None` when the file never
    /// recorded one (or the timestamp cannot be read).
    pub fn age_days(&self, now: chrono::DateTime<chrono::Utc>) -> Option<i64> {
        let synced = chrono::DateTime::parse_from_rfc3339(self.synced_at.as_deref()?).ok()?;
        Some((now - synced.with_timezone(&chrono::Utc)).num_days().max(0))
    }
}

/// One row of a search: enough to decide which CVE to look up.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Hit {
    /// CVE id.
    pub id: String,
    /// Publication date.
    pub published: Option<String>,
    /// NVD status (`Analyzed`, `Awaiting Analysis`, `Rejected`, ...).
    pub status: Option<String>,
    /// Headline CVSS base score.
    pub cvss_score: Option<f64>,
    /// Headline CVSS severity.
    pub cvss_severity: Option<String>,
    /// EPSS probability.
    pub epss: Option<f64>,
    /// Listed in CISA KEV.
    pub kev: bool,
    /// Start of the description.
    pub summary: String,
}

/// How search results are ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// Newest publication first.
    #[default]
    Published,
    /// Highest CVSS base score first.
    Cvss,
    /// Highest EPSS probability first.
    Epss,
}

/// Filters of [`Reader::search`]. All set filters must match.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Search {
    /// Words that must all appear in id, description or product names.
    pub query: Option<String>,
    /// Vendor name as in CPE (`microsoft`), exact, lower case.
    pub vendor: Option<String>,
    /// Product name as in CPE (`exchange_server`), exact, lower case.
    pub product: Option<String>,
    /// Lowest headline CVSS base score.
    pub min_cvss: Option<f64>,
    /// Lowest EPSS probability.
    pub min_epss: Option<f64>,
    /// Only CVEs in CISA KEV.
    pub kev_only: bool,
    /// Published on or after this date (`YYYY-MM-DD`).
    pub published_after: Option<String>,
    /// Order.
    pub sort: Sort,
    /// Rows returned at most.
    pub limit: usize,
}

/// Characters of a description shown in a search hit.
pub const SUMMARY_CHARS: usize = 240;

/// Read-only access for the tools.
#[derive(Debug, Clone)]
pub struct Reader {
    path: PathBuf,
}

impl Reader {
    /// A reader of the file at `path`. Nothing is opened yet.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open(&self) -> Result<Connection> {
        if !self.path.is_file() {
            return Err(StoreError::Missing(self.path.clone()));
        }
        // `immutable=1`: no locks, no journal lookups, no write to the
        // directory. Safe because the file is only ever replaced by rename.
        let uri = format!("file:{}?mode=ro&immutable=1", uri_path(&self.path));
        let conn = Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.pragma_update(None, "query_only", true)?;
        let found: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_SCHEMA],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        match found {
            Some(v) if v == SCHEMA_VERSION => Ok(conn),
            other => Err(StoreError::Schema {
                found: other.unwrap_or_else(|| "none".to_string()),
                expected: SCHEMA_VERSION,
            }),
        }
    }

    /// Counts and source versions.
    ///
    /// # Errors
    /// The file is missing, of another schema version, or unreadable.
    pub fn status(&self) -> Result<Status> {
        let conn = self.open()?;
        let meta = |key: &str| -> Result<Option<String>> {
            Ok(conn
                .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
                .optional()?)
        };
        Ok(Status {
            synced_at: meta(META_SYNCED_AT)?,
            nvd_synced_at: meta(META_NVD_SYNCED_AT)?,
            cve_count: count(&conn, Table::Cve)?,
            epss_count: count(&conn, Table::Epss)?,
            epss_score_date: meta(META_EPSS_DATE)?,
            epss_model_version: meta(META_EPSS_MODEL)?,
            kev_count: count(&conn, Table::Kev)?,
            kev_catalog_version: meta(META_KEV_VERSION)?,
            kev_date_released: meta(META_KEV_RELEASED)?,
        })
    }

    /// Everything stored about each of `ids` (upper-case CVE ids), in the
    /// order given. An id the database does not know yields
    /// `{"id": ..., "found": false}`.
    ///
    /// # Errors
    /// The file is missing, of another schema version, or unreadable.
    pub fn lookup(&self, ids: &[String], with_references: bool) -> Result<Vec<Value>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            "SELECT published, modified, status, description, cvss_version, cvss_score,
                    cvss_severity, cvss_vector, cwe, metrics, refs, cpe, cpe_total
             FROM cve WHERE id = ?1",
        )?;
        let mut products = conn.prepare(
            "SELECT vendor, product FROM product WHERE cve_id = ?1 ORDER BY vendor, product
             LIMIT ?2",
        )?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let row = stmt
                .query_row([id], |r| {
                    Ok(serde_json::json!({
                        "id": id,
                        "found": true,
                        "published": r.get::<_, Option<String>>(0)?,
                        "last_modified": r.get::<_, Option<String>>(1)?,
                        "status": r.get::<_, Option<String>>(2)?,
                        "description": r.get::<_, String>(3)?,
                        "cvss": cvss_json(r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?),
                        "cwe": split_list(&r.get::<_, String>(8)?),
                        "all_metrics": json_column(&r.get::<_, String>(9)?),
                        "references": json_column(&r.get::<_, String>(10)?),
                        "cpe_matches": json_column(&r.get::<_, String>(11)?),
                        "cpe_matches_total": r.get::<_, i64>(12)?,
                    }))
                })
                .optional()?;
            let Some(mut row) = row else {
                // EPSS and KEV may know a CVE that NVD has not published yet.
                let epss = epss_of(&conn, id)?;
                let kev = kev_of(&conn, id)?;
                out.push(serde_json::json!({
                    "id": id,
                    "found": epss.is_some() || kev.is_some(),
                    "note": "not in the local NVD copy",
                    "epss": epss,
                    "kev": kev,
                }));
                continue;
            };
            if !with_references && let Some(map) = row.as_object_mut() {
                let total = map
                    .get("references")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                map.insert("references".into(), Value::Null);
                map.insert("references_total".into(), total.into());
            }
            let names: Vec<Value> = products
                .query_map(params![id, MAX_PRODUCTS_SHOWN as i64], |r| {
                    Ok(serde_json::json!({
                        "vendor": r.get::<_, String>(0)?,
                        "product": r.get::<_, String>(1)?,
                    }))
                })?
                .collect::<std::result::Result<_, _>>()?;
            row["products"] = Value::Array(names);
            row["epss"] = epss_of(&conn, id)?.unwrap_or(Value::Null);
            row["kev"] = kev_of(&conn, id)?.unwrap_or(Value::Null);
            out.push(row);
        }
        Ok(out)
    }

    /// EPSS score and percentile of each of `ids`; `null` where EPSS has no
    /// score.
    ///
    /// # Errors
    /// The file is missing, of another schema version, or unreadable.
    pub fn epss(&self, ids: &[String]) -> Result<Vec<Value>> {
        let conn = self.open()?;
        ids.iter()
            .map(|id| {
                let score = epss_of(&conn, id)?;
                Ok(serde_json::json!({"id": id, "epss": score}))
            })
            .collect()
    }

    /// The KEV entry of each of `ids`; `in_kev: false` where there is none.
    ///
    /// # Errors
    /// The file is missing, of another schema version, or unreadable.
    pub fn kev(&self, ids: &[String]) -> Result<Vec<Value>> {
        let conn = self.open()?;
        ids.iter()
            .map(|id| {
                let entry = kev_of(&conn, id)?;
                Ok(serde_json::json!({"id": id, "in_kev": entry.is_some(), "kev": entry}))
            })
            .collect()
    }

    /// KEV entries, newest first, filtered by date added, text in vendor /
    /// product / name, and ransomware use.
    ///
    /// # Errors
    /// The file is missing, of another schema version, or unreadable.
    pub fn kev_list(
        &self,
        added_after: Option<&str>,
        text: Option<&str>,
        ransomware_only: bool,
        limit: usize,
    ) -> Result<Vec<Value>> {
        let conn = self.open()?;
        let mut sql = String::from(
            "SELECT cve_id, vendor, product, name, date_added, due_date, description,
                    required_action, ransomware, notes FROM kev WHERE 1 = 1",
        );
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(date) = added_after {
            sql.push_str(" AND date_added >= ?");
            args.push(date.to_string().into());
        }
        if let Some(text) = text {
            sql.push_str(
                " AND (vendor LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\' \
                 OR name LIKE ? ESCAPE '\\')",
            );
            let pattern = format!("%{}%", like_escape(text));
            for _ in 0..3 {
                args.push(pattern.clone().into());
            }
        }
        if ransomware_only {
            sql.push_str(" AND ransomware = 'Known'");
        }
        sql.push_str(" ORDER BY date_added DESC, cve_id DESC LIMIT ?");
        args.push((limit as i64).into());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(args), kev_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// CVEs matching `search`. Returns the hits and whether more rows
    /// matched than `search.limit`.
    ///
    /// # Errors
    /// The file is missing, of another schema version, or unreadable.
    pub fn search(&self, search: &Search) -> Result<(Vec<Hit>, bool)> {
        let conn = self.open()?;
        let mut sql = String::from(
            "SELECT c.id, c.published, c.status, c.cvss_score, c.cvss_severity, e.score,
                    k.cve_id IS NOT NULL, substr(c.description, 1, ?) FROM cve c
             LEFT JOIN epss e ON e.cve_id = c.id
             LEFT JOIN kev k ON k.cve_id = c.id
             WHERE 1 = 1",
        );
        let mut args: Vec<rusqlite::types::Value> = vec![(SUMMARY_CHARS as i64).into()];
        if let Some(q) = search.query.as_deref().and_then(fts_query) {
            sql.push_str(" AND c.rid IN (SELECT rowid FROM cve_fts WHERE cve_fts MATCH ?)");
            args.push(q.into());
        }
        match (&search.vendor, &search.product) {
            (Some(v), Some(p)) => {
                sql.push_str(
                    " AND c.id IN (SELECT cve_id FROM product WHERE product = ? AND vendor = ?)",
                );
                args.push(p.clone().into());
                args.push(v.clone().into());
            }
            (None, Some(p)) => {
                sql.push_str(" AND c.id IN (SELECT cve_id FROM product WHERE product = ?)");
                args.push(p.clone().into());
            }
            (Some(v), None) => {
                sql.push_str(" AND c.id IN (SELECT cve_id FROM product WHERE vendor = ?)");
                args.push(v.clone().into());
            }
            (None, None) => {}
        }
        if let Some(min) = search.min_cvss {
            sql.push_str(" AND c.cvss_score >= ?");
            args.push(min.into());
        }
        if let Some(min) = search.min_epss {
            sql.push_str(" AND e.score >= ?");
            args.push(min.into());
        }
        if search.kev_only {
            sql.push_str(" AND k.cve_id IS NOT NULL");
        }
        if let Some(date) = &search.published_after {
            sql.push_str(" AND c.published >= ?");
            args.push(date.clone().into());
        }
        sql.push_str(match search.sort {
            Sort::Published => " ORDER BY c.published DESC, c.id DESC",
            Sort::Cvss => " ORDER BY c.cvss_score DESC NULLS LAST, c.published DESC",
            Sort::Epss => " ORDER BY e.score DESC NULLS LAST, c.published DESC",
        });
        sql.push_str(" LIMIT ?");
        // One more than asked for tells "there is more" without a count.
        args.push((search.limit as i64 + 1).into());
        let mut stmt = conn.prepare(&sql)?;
        let mut hits = stmt
            .query_map(params_from_iter(args), |r| {
                Ok(Hit {
                    id: r.get(0)?,
                    published: r.get(1)?,
                    status: r.get(2)?,
                    cvss_score: r.get(3)?,
                    cvss_severity: r.get(4)?,
                    epss: r.get(5)?,
                    kev: r.get(6)?,
                    summary: r.get(7)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let more = hits.len() > search.limit;
        hits.truncate(search.limit);
        Ok((hits, more))
    }
}

/// Products listed per CVE in a lookup.
pub const MAX_PRODUCTS_SHOWN: usize = 50;

fn cvss_json(
    version: Option<String>,
    score: Option<f64>,
    severity: Option<String>,
    vector: Option<String>,
) -> Value {
    match score {
        Some(score) => serde_json::json!({
            "version": version, "base_score": score, "severity": severity, "vector": vector,
        }),
        None => Value::Null,
    }
}

fn split_list(text: &str) -> Vec<&str> {
    text.split(',').filter(|s| !s.is_empty()).collect()
}

fn json_column(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

fn epss_of(conn: &Connection, id: &str) -> Result<Option<Value>> {
    Ok(conn
        .prepare_cached("SELECT score, percentile FROM epss WHERE cve_id = ?1")?
        .query_row([id], |r| {
            Ok(serde_json::json!({
                "score": r.get::<_, f64>(0)?,
                "percentile": r.get::<_, f64>(1)?,
            }))
        })
        .optional()?)
}

fn kev_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(serde_json::json!({
        "cve_id": r.get::<_, String>(0)?,
        "vendor": r.get::<_, String>(1)?,
        "product": r.get::<_, String>(2)?,
        "name": r.get::<_, String>(3)?,
        "date_added": r.get::<_, String>(4)?,
        "due_date": r.get::<_, String>(5)?,
        "description": r.get::<_, String>(6)?,
        "required_action": r.get::<_, String>(7)?,
        "known_ransomware_use": r.get::<_, String>(8)?,
        "notes": r.get::<_, String>(9)?,
    }))
}

fn kev_of(conn: &Connection, id: &str) -> Result<Option<Value>> {
    Ok(conn
        .prepare_cached(
            "SELECT cve_id, vendor, product, name, date_added, due_date, description,
                    required_action, ransomware, notes FROM kev WHERE cve_id = ?1",
        )?
        .query_row([id], kev_row)
        .optional()?)
}

/// `%`, `_` and `\` of `text` escaped for `LIKE ... ESCAPE '\'`.
fn like_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Words of a search at most.
pub const MAX_QUERY_TERMS: usize = 8;

/// The FTS5 query for free text: every word (letters and digits only; any
/// other character separates words) as a quoted term, all required. No FTS
/// operator of the input survives, so the input cannot change the query's
/// structure. `None` when no word is left.
pub fn fts_query(text: &str) -> Option<String> {
    let terms: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .take(MAX_QUERY_TERMS)
        .map(|t| format!("\"{t}\""))
        .collect();
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" AND "))
    }
}

/// `path` for a SQLite `file:` URI: `%`, `?` and `#` percent-encoded.
fn uri_path(path: &Path) -> String {
    let mut out = String::new();
    for c in path.to_string_lossy().chars() {
        match c {
            '%' => out.push_str("%25"),
            '?' => out.push_str("%3f"),
            '#' => out.push_str("%23"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fts_query_keeps_only_words() {
        assert_eq!(
            fts_query("Exchange  server").as_deref(),
            Some("\"Exchange\" AND \"server\"")
        );
        // Operators, quotes and column filters become separators.
        assert_eq!(
            fts_query("\"a\" OR text:b* NEAR(c)").as_deref(),
            Some("\"a\" AND \"OR\" AND \"text\" AND \"b\" AND \"NEAR\" AND \"c\"")
        );
        assert_eq!(fts_query("--- \"\" *"), None);
        assert_eq!(
            fts_query("a b c d e f g h i j").map(|q| q.matches("AND").count()),
            Some(MAX_QUERY_TERMS - 1)
        );
    }

    #[test]
    fn like_and_uri_escaping() {
        assert_eq!(like_escape("50%_a\\"), "50\\%\\_a\\\\");
        assert_eq!(uri_path(Path::new("/a b/c?d#e%f")), "/a b/c%3fd%23e%25f");
    }
}
