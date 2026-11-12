//! Append-only, hash-chained audit log.
//!
//! Every row stores `prev_hash` (the previous row's `hash`, or
//! [`AUDIT_GENESIS_HASH`] for the first row), the `scheme` that produced its
//! `hash` and, for keyed rows, its position `seq` in the chain:
//!
//! - [`AuditScheme::Sha256`] (no audit key configured, and every row written
//!   by releases before the keyed chain):
//!   `hash = sha256_hex(prev_hash || canonical_json(event))`
//!   ([`audit_event_hash`]).
//! - [`AuditScheme::HmacSha256`] (an [`AuditKey`] was attached with
//!   [`Db::enable_keyed_audit`]):
//!   `hash = hex(HMAC-SHA-256(key, seq || prev_hash || canonical_json(event)))`
//!   ([`AuditKey::event_mac`]), where `seq` is the 1-based position of the
//!   row in the chain.
//!
//! The event is the [`AuditEvent`] JSON (`target` omitted when `None`) with
//! object keys sorted recursively ([`canonical_json`]). Editing, reordering
//! or deleting a row breaks the chain at that row, which
//! [`Db::verify_audit`] reports. `UPDATE` / `DELETE` on the table are
//! additionally refused by triggers.
//!
//! # What the key adds
//!
//! An unkeyed chain only detects *inconsistent* edits: whoever can write the
//! database can recompute every hash after an edit. Keyed rows cannot be
//! forged or recomputed without the key. A chain may start unkeyed and
//! become keyed (the first keyed row authenticates the hash and the number
//! of the unkeyed rows before it, and an `audit.chain.keyed` event marks the
//! transition); the reverse — an unkeyed row after a keyed one — is a
//! downgrade and fails verification. Keyed rows cannot be verified without
//! the key: verification fails closed.
//!
//! # Truncation
//!
//! Deleting the newest rows leaves a shorter, perfectly valid chain. With a
//! checkpoint path configured, every keyed append therefore also rewrites a
//! small file outside the database holding `seq` and `hash` of the newest
//! row, authenticated with the key. [`Db::verify_audit`] fails when that
//! checkpoint is ahead of the table, missing or does not verify, and the
//! next append records an `audit.checkpoint.anomaly` event in the chain
//! before it rewrites the checkpoint. Limits: somebody who can write the
//! database *and* the checkpoint file can roll both back to an earlier state
//! for which they kept a copy of the checkpoint, and somebody who also holds
//! the key can do anything. Export [`Db::audit_head`] to a system the host
//! cannot write if that matters.

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use talon_core::audit::{AuditSink, TracingAuditSink};
use talon_core::time::now_iso;
use talon_core::types::AuditEvent;
use talon_core::{Error, Result};

use crate::audit_key::{AuditKeying, Checkpoint, CheckpointRead, hash_eq, mac_matches};
use crate::{Db, SqlResultExt, col, sql_limit};

pub use crate::audit_key::{
    AUDIT_CHECKPOINT_FILE_NAME, AUDIT_KEY_ENV, AuditKey, MIN_AUDIT_KEY_LEN,
    default_audit_checkpoint_path,
};

/// `prev_hash` of the first row: 64 zeros.
pub const AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Upper bound for the serialized `details` of one event. Larger payloads are
/// replaced by a marker object (`{"truncated": true, ...}`) so a single noisy
/// caller cannot bloat the log.
pub const MAX_AUDIT_DETAILS_BYTES: usize = 64 * 1024;

/// Kind of the event the database appends as the first keyed row of a chain
/// that has unkeyed rows (`details.unkeyed_rows` is their number).
pub const AUDIT_KIND_CHAIN_KEYED: &str = "audit.chain.keyed";

/// Kind of the event the database appends when the checkpoint file does not
/// match the chain at the time of a keyed append (`details.reason` is
/// `missing`, `invalid`, `ahead` or `mismatch`): the tail of the log was
/// truncated, the database was restored from a backup, or the checkpoint
/// file was deleted or modified.
pub const AUDIT_KIND_CHECKPOINT_ANOMALY: &str = "audit.checkpoint.anomaly";

/// Actor of the events the database appends on its own.
const AUDIT_ACTOR_DB: &str = "talon-db";

/// Rows checked per lock acquisition in [`Db::verify_audit`], so a long
/// verification does not starve writers.
const VERIFY_BATCH: i64 = 1000;

/// Columns [`audit_row`] reads.
const ROW_COLUMNS: &str =
    "id, timestamp, kind, actor, target, outcome, details, prev_hash, hash, scheme, seq";

/// How the `hash` of an audit row was computed (column `scheme`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditScheme {
    /// `sha256_hex(prev_hash || canonical_json(event))`: detects
    /// inconsistent edits only.
    Sha256,
    /// `HMAC-SHA-256` under the [`AuditKey`] over the row's sequence number,
    /// `prev_hash` and the canonical event.
    HmacSha256,
}

impl AuditScheme {
    /// Value of the `scheme` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::HmacSha256 => "hmac-sha256",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "sha256" => Some(Self::Sha256),
            "hmac-sha256" => Some(Self::HmacSha256),
            _ => None,
        }
    }
}

impl fmt::Display for AuditScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The newest row of the chain ([`Db::audit_head`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditHead {
    /// Row id.
    pub id: i64,
    /// The row's `hash` (a MAC for [`AuditScheme::HmacSha256`]).
    pub hash: String,
    /// Scheme that produced `hash`.
    pub scheme: AuditScheme,
    /// 1-based position of the row in the chain (keyed rows only).
    pub seq: Option<u64>,
}

/// Whether the configured audit key fits the chain ([`Db::audit_key_status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditKeyStatus {
    /// No key configured and the newest row is unkeyed (or there is none).
    Unkeyed,
    /// A key is configured and the newest row is unkeyed (or there is
    /// none): the next append keys the chain.
    Pending,
    /// A key is configured and authenticates the newest row.
    Active,
    /// The newest row is keyed but no key is configured.
    KeyMissing,
    /// The newest row does not verify under the configured key (wrong key,
    /// or the row was tampered with).
    KeyMismatch,
}

/// Why one row failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditRowFailure {
    /// The stored row cannot be decoded (`details` is not JSON).
    Corrupt,
    /// `prev_hash` is not the previous row's hash (a row before it was
    /// deleted, inserted or replaced).
    BrokenLink,
    /// Unkeyed row whose content does not match its hash.
    HashMismatch,
    /// Keyed row whose MAC does not verify under the configured key: the
    /// row was forged or edited, or the configured key is not the one the
    /// row was written with.
    MacMismatch,
    /// Keyed row whose sequence number is not its position in the chain.
    BadSequence,
    /// Unkeyed row after a keyed one (downgrade).
    Downgrade,
    /// The `scheme` column holds an unknown value.
    UnknownScheme,
}

impl fmt::Display for AuditRowFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Corrupt => "the row cannot be decoded",
            Self::BrokenLink => "prev_hash does not match the previous row",
            Self::HashMismatch => "the content does not match the hash",
            Self::MacMismatch => {
                "the MAC does not verify under the configured audit key (forged or edited row, \
                 or the wrong key is configured)"
            }
            Self::BadSequence => "the sequence number is not the row's position in the chain",
            Self::Downgrade => "unkeyed row after a keyed one (downgrade)",
            Self::UnknownScheme => "unknown hash scheme",
        })
    }
}

/// Why an audit verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditFailure {
    /// Row `id` is the first one that does not verify.
    Row {
        /// Row id.
        id: i64,
        /// What is wrong with it.
        reason: AuditRowFailure,
    },
    /// The chain has keyed rows (the first is `first_keyed_row`) but no
    /// audit key is configured: they cannot be verified.
    KeyMissing {
        /// Row id of the first keyed row.
        first_keyed_row: i64,
    },
    /// The chain has keyed rows but the checkpoint file does not exist.
    CheckpointMissing,
    /// The checkpoint file is unreadable, malformed or its MAC does not
    /// verify under the configured key.
    CheckpointInvalid,
    /// The checkpoint was written for row number `checkpoint_seq`, but the
    /// chain has only `rows` rows: the tail was deleted (or the database
    /// was restored from an older backup).
    Truncated {
        /// Sequence number in the checkpoint.
        checkpoint_seq: u64,
        /// Rows in the chain.
        rows: u64,
    },
    /// Row number `seq` exists but is not the row the checkpoint was
    /// written for (the tail was deleted and other rows were appended, or
    /// keyed rows were replaced by unkeyed ones).
    CheckpointMismatch {
        /// Sequence number in the checkpoint.
        seq: u64,
    },
}

impl fmt::Display for AuditFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Row { id, reason } => write!(f, "audit row {id}: {reason}"),
            Self::KeyMissing { first_keyed_row } => write!(
                f,
                "the audit chain is keyed from row {first_keyed_row} on but no audit key is \
                 configured ({AUDIT_KEY_ENV}): keyed rows cannot be verified"
            ),
            Self::CheckpointMissing => f.write_str(
                "the audit chain has keyed rows but the audit checkpoint file is missing \
                 (deleted, or the database was copied without it)",
            ),
            Self::CheckpointInvalid => f.write_str(
                "the audit checkpoint file does not verify under the configured audit key \
                 (modified, or written with another key)",
            ),
            Self::Truncated {
                checkpoint_seq,
                rows,
            } => write!(
                f,
                "the audit log was truncated: the checkpoint was written for row number \
                 {checkpoint_seq} but only {rows} rows exist (tail deleted, or the database \
                 was restored from a backup)"
            ),
            Self::CheckpointMismatch { seq } => write!(
                f,
                "audit row number {seq} is not the row the checkpoint was written for (tail \
                 deleted and rewritten, or keyed rows replaced)"
            ),
        }
    }
}

/// State of the checkpoint file in an [`AuditVerification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditCheckpointState {
    /// No audit key or no checkpoint path is configured.
    Disabled,
    /// No checkpoint file, and no keyed rows that would need one.
    Absent,
    /// Authentic and consistent with the chain. `lag` is the number of rows
    /// appended after the checkpointed one (normally 0; more only while
    /// rows are being appended, after a crash between an append and the
    /// checkpoint write, or while the file cannot be written).
    Verified {
        /// Sequence number in the checkpoint.
        seq: u64,
        /// Rows after the checkpointed one.
        lag: u64,
    },
    /// Not checked because the chain itself failed, or failed itself (see
    /// [`AuditVerification::failure`]).
    Failed,
}

/// Result of [`Db::verify_audit`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditVerification {
    /// Rows that verified (all of them when `failure` is `None` or a
    /// checkpoint failure).
    pub rows: u64,
    /// How many of them are keyed.
    pub keyed_rows: u64,
    /// Row id of the first keyed row (where the chain became keyed).
    pub first_keyed_row: Option<i64>,
    /// The newest verified row.
    pub head: Option<AuditHead>,
    /// Whether an audit key is configured on this handle.
    pub key_configured: bool,
    /// State of the checkpoint file.
    pub checkpoint: AuditCheckpointState,
    /// `None` when the chain (and the checkpoint, if any) verified.
    pub failure: Option<AuditFailure>,
}

impl AuditVerification {
    /// Whether everything verified.
    pub fn is_intact(&self) -> bool {
        self.failure.is_none()
    }
}

/// Serialize `value` as canonical JSON: no whitespace, object keys sorted
/// (byte-wise) at every level, strings and numbers as `serde_json` writes
/// them. Independent of `serde_json`'s `preserve_order` feature.
pub fn canonical_json(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k)?);
                out.push(':');
                write_canonical(v, out)?;
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out)?;
            }
            out.push(']');
        }
        scalar => out.push_str(&serde_json::to_string(scalar)?),
    }
    Ok(())
}

/// `sha256_hex(prev_hash || canonical_json(event))`, the hash of an
/// [`AuditScheme::Sha256`] row.
pub fn audit_event_hash(prev_hash: &str, event: &AuditEvent) -> Result<String> {
    let canonical = canonical_json(&serde_json::to_value(event)?)?;
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

impl AuditKey {
    /// The hash of an [`AuditScheme::HmacSha256`] row, as lowercase hex:
    /// `HMAC-SHA-256(key, "talon-audit-row-v1" || L(seq) || L(prev_hash) ||
    /// L(canonical_json(event)))`, where `L(x)` is `x` prefixed with its
    /// length as a big-endian `u64` and `seq` (the 1-based position of the
    /// row in the chain) is encoded as a big-endian `u64`.
    pub fn event_mac(&self, seq: u64, prev_hash: &str, event: &AuditEvent) -> Result<String> {
        let canonical = canonical_json(&serde_json::to_value(event)?)?;
        self.row_mac(seq, prev_hash, &canonical)
    }
}

/// Canonical `details` text as stored, capped at [`MAX_AUDIT_DETAILS_BYTES`].
fn stored_details(details: &Value) -> Result<String> {
    let text = canonical_json(details)?;
    if text.len() <= MAX_AUDIT_DETAILS_BYTES {
        return Ok(text);
    }
    let mut preview_end = 1024.min(text.len());
    while !text.is_char_boundary(preview_end) {
        preview_end -= 1;
    }
    canonical_json(&serde_json::json!({
        "truncated": true,
        "original_bytes": text.len(),
        "preview": &text[..preview_end],
    }))
}

/// One stored row.
struct AuditRow {
    id: i64,
    event: std::result::Result<AuditEvent, String>,
    prev_hash: String,
    hash: String,
    scheme: String,
    seq: Option<i64>,
}

fn audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    let details_raw = col::text(row, "details")?;
    let event = match serde_json::from_str::<Value>(&details_raw) {
        Ok(details) => Ok(AuditEvent {
            timestamp: col::text(row, "timestamp")?,
            kind: col::text(row, "kind")?,
            actor: col::text(row, "actor")?,
            target: col::opt_text(row, "target")?,
            outcome: col::text(row, "outcome")?,
            details,
        }),
        Err(e) => Err(format!("details is not JSON: {e}")),
    };
    Ok(AuditRow {
        id: row.get("id")?,
        event,
        prev_hash: col::text(row, "prev_hash")?,
        hash: col::text(row, "hash")?,
        scheme: col::text(row, "scheme")?,
        seq: row.get("seq")?,
    })
}

impl AuditRow {
    /// Sequence number of a keyed row, if it is a valid one.
    fn keyed_seq(&self) -> Option<u64> {
        self.seq.and_then(|s| u64::try_from(s).ok())
    }

    /// Whether the row's MAC verifies under `key`.
    fn mac_verifies(&self, key: &AuditKey) -> Result<bool> {
        let (Ok(event), Some(seq)) = (&self.event, self.keyed_seq()) else {
            return Ok(false);
        };
        Ok(mac_matches(
            &key.event_mac(seq, &self.prev_hash, event)?,
            &self.hash,
        ))
    }
}

/// What the checkpoint file says about the chain head a keyed append is
/// about to extend. `keyed_head` is `(seq, hash)` of the newest row when it
/// is keyed. Returns the anomaly (`reason`, checkpoint sequence number).
fn checkpoint_anomaly(
    read: &CheckpointRead,
    keyed_head: Option<(u64, &str)>,
) -> Option<(&'static str, Option<u64>)> {
    match (read, keyed_head) {
        (CheckpointRead::Missing, None) => None,
        (CheckpointRead::Missing, Some(_)) => Some(("missing", None)),
        (CheckpointRead::Invalid(_), _) => Some(("invalid", None)),
        // A checkpoint always refers to a keyed row; the newest row is not.
        (CheckpointRead::Valid(cp), None) => Some(("ahead", Some(cp.seq))),
        (CheckpointRead::Valid(cp), Some((seq, hash))) => {
            if cp.seq > seq {
                Some(("ahead", Some(cp.seq)))
            } else if cp.seq == seq && !hash_eq(&cp.head, hash) {
                Some(("mismatch", Some(cp.seq)))
            } else {
                // Equal, or behind (a crash between an append and its
                // checkpoint write): nothing was lost.
                None
            }
        }
    }
}

fn own_event(kind: &str, outcome: &str, details: Value) -> AuditEvent {
    AuditEvent {
        timestamp: now_iso(),
        kind: kind.to_string(),
        actor: AUDIT_ACTOR_DB.to_string(),
        target: None,
        outcome: outcome.to_string(),
        details,
    }
}

fn insert_row(
    tx: &rusqlite::Transaction<'_>,
    event: &AuditEvent,
    details_text: &str,
    prev_hash: &str,
    hash: &str,
    scheme: AuditScheme,
    seq: Option<u64>,
) -> Result<()> {
    let seq = seq
        .map(|s| i64::try_from(s).map_err(|_| Error::Db("audit sequence overflow".to_string())))
        .transpose()?;
    tx.prepare_cached(
        "INSERT INTO audit_log (timestamp, kind, actor, target, outcome, details,
           prev_hash, hash, scheme, seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .db()?
    .execute(params![
        event.timestamp,
        event.kind,
        event.actor,
        event.target,
        event.outcome,
        details_text,
        prev_hash,
        hash,
        scheme.as_str(),
        seq,
    ])
    .db()?;
    Ok(())
}

/// Append `stored` to the chain inside `tx`. Returns the checkpoint to
/// write once the transaction is committed (keyed chains only) and whether
/// it must replace a checkpoint that is further ahead.
fn append(
    tx: &rusqlite::Transaction<'_>,
    keying: Option<&AuditKeying>,
    stored: &AuditEvent,
    details_text: &str,
) -> Result<Option<(Checkpoint, bool)>> {
    let head: Option<(String, String, Option<i64>)> = tx
        .prepare_cached("SELECT hash, scheme, seq FROM audit_log ORDER BY id DESC LIMIT 1")
        .db()?
        .query_row([], |r| {
            Ok((
                col::text(r, "hash")?,
                col::text(r, "scheme")?,
                r.get("seq")?,
            ))
        })
        .optional()
        .db()?;
    let head_unkeyed = head
        .as_ref()
        .is_none_or(|(_, scheme, _)| scheme == AuditScheme::Sha256.as_str());

    let Some(keying) = keying else {
        if !head_unkeyed {
            // Appending an unkeyed row would be a downgrade.
            return Err(Error::Security(format!(
                "the audit chain is keyed but no audit key is configured ({AUDIT_KEY_ENV}): \
                 refusing to append an unkeyed row"
            )));
        }
        let prev = head.map_or_else(|| AUDIT_GENESIS_HASH.to_string(), |(hash, _, _)| hash);
        let hash = audit_event_hash(&prev, stored)?;
        insert_row(
            tx,
            stored,
            details_text,
            &prev,
            &hash,
            AuditScheme::Sha256,
            None,
        )?;
        return Ok(None);
    };

    // Sequence number of the newest row when it is a well-formed keyed row.
    let keyed_head_seq = head
        .as_ref()
        .filter(|_| !head_unkeyed)
        .and_then(|(_, _, seq)| seq.and_then(|s| u64::try_from(s).ok()));
    let (mut prev, mut seq) = match &head {
        None => (AUDIT_GENESIS_HASH.to_string(), 0),
        Some((hash, _, _)) => {
            let seq = match keyed_head_seq {
                Some(seq) => seq,
                // First keyed row after unkeyed ones (or a damaged head,
                // which verification reports): its position is the count.
                None => {
                    let n: i64 = tx
                        .prepare_cached("SELECT COUNT(*) FROM audit_log")
                        .db()?
                        .query_row([], |r| r.get(0))
                        .db()?;
                    u64::try_from(n).unwrap_or(0)
                }
            };
            (hash.clone(), seq)
        }
    };

    let mut own: Vec<AuditEvent> = Vec::new();
    if head.is_some() && head_unkeyed {
        own.push(own_event(
            AUDIT_KIND_CHAIN_KEYED,
            "info",
            serde_json::json!({ "scheme": AuditScheme::HmacSha256.as_str(), "unkeyed_rows": seq }),
        ));
    }
    let mut force_checkpoint = false;
    if !keying.checkpoint_stale.load(Ordering::Relaxed)
        && let Some(read) = keying.read_checkpoint()
        && let Some((reason, checkpoint_seq)) =
            checkpoint_anomaly(&read, keyed_head_seq.map(|s| (s, prev.as_str())))
    {
        tracing::error!(
            target: "talon::audit",
            reason,
            checkpoint_seq = ?checkpoint_seq,
            chain_seq = seq,
            "audit checkpoint does not match the audit log (truncated tail, restored database, \
             or deleted/modified checkpoint file)"
        );
        own.push(own_event(
            AUDIT_KIND_CHECKPOINT_ANOMALY,
            "error",
            serde_json::json!({
                "reason": reason,
                "checkpoint_seq": checkpoint_seq,
                "chain_seq": seq,
            }),
        ));
        force_checkpoint = true;
    }

    let own_texts = own
        .iter()
        .map(|e| canonical_json(&e.details))
        .collect::<Result<Vec<_>>>()?;
    let rows = own
        .iter()
        .zip(own_texts.iter().map(String::as_str))
        .chain(std::iter::once((stored, details_text)));
    for (event, text) in rows {
        seq += 1;
        let hash = keying.key.event_mac(seq, &prev, event)?;
        insert_row(
            tx,
            event,
            text,
            &prev,
            &hash,
            AuditScheme::HmacSha256,
            Some(seq),
        )?;
        prev = hash;
    }
    Ok(Some((Checkpoint { seq, head: prev }, force_checkpoint)))
}

/// Running state of a chain verification.
struct ChainWalk<'a> {
    key: Option<&'a AuditKey>,
    /// Sequence number of the checkpoint to compare with, if any.
    checkpoint_seq: Option<u64>,
    expected_prev: String,
    rows: u64,
    keyed_rows: u64,
    first_keyed_row: Option<i64>,
    head: Option<AuditHead>,
    /// The row at position `checkpoint_seq`.
    checkpoint_row: Option<(AuditScheme, String)>,
}

impl ChainWalk<'_> {
    /// Check one row; the inner `Err` is the verification failure.
    fn check(&mut self, row: AuditRow) -> Result<std::result::Result<(), AuditFailure>> {
        let id = row.id;
        let fail = |reason| Ok(Err(AuditFailure::Row { id, reason }));
        let Ok(event) = &row.event else {
            return fail(AuditRowFailure::Corrupt);
        };
        if row.prev_hash != self.expected_prev {
            return fail(AuditRowFailure::BrokenLink);
        }
        let position = self.rows + 1;
        let Some(scheme) = AuditScheme::parse(&row.scheme) else {
            return fail(AuditRowFailure::UnknownScheme);
        };
        let mut seq = None;
        match scheme {
            AuditScheme::Sha256 => {
                if self.keyed_rows > 0 {
                    return fail(AuditRowFailure::Downgrade);
                }
                if audit_event_hash(&row.prev_hash, event)? != row.hash {
                    return fail(AuditRowFailure::HashMismatch);
                }
            }
            AuditScheme::HmacSha256 => {
                let Some(key) = self.key else {
                    return Ok(Err(AuditFailure::KeyMissing {
                        first_keyed_row: id,
                    }));
                };
                if row.keyed_seq() != Some(position) {
                    return fail(AuditRowFailure::BadSequence);
                }
                if !row.mac_verifies(key)? {
                    return fail(AuditRowFailure::MacMismatch);
                }
                self.keyed_rows += 1;
                self.first_keyed_row.get_or_insert(id);
                seq = Some(position);
            }
        }
        self.rows = position;
        if self.checkpoint_seq == Some(position) {
            self.checkpoint_row = Some((scheme, row.hash.clone()));
        }
        self.expected_prev.clone_from(&row.hash);
        self.head = Some(AuditHead {
            id,
            hash: row.hash,
            scheme,
            seq,
        });
        Ok(Ok(()))
    }
}

impl Db {
    // ---- audit log (append-only, hash-chained) ---------------------------

    /// Key the audit chain of this handle (and its clones): every row
    /// appended from now on is an [`AuditScheme::HmacSha256`] row under
    /// `key`, and [`Db::verify_audit`] can verify keyed rows.
    ///
    /// With a `checkpoint_path` (see [`default_audit_checkpoint_path`]; keep
    /// it outside anything a container can reach) every append also
    /// rewrites the checkpoint file and verification compares it with the
    /// table, which detects a truncated tail.
    ///
    /// # Errors
    /// [`Error::Config`] when a key was already attached to this handle.
    pub fn enable_keyed_audit(
        &self,
        key: AuditKey,
        checkpoint_path: Option<PathBuf>,
    ) -> Result<()> {
        self.inner
            .audit_keying
            .set(AuditKeying::new(key, checkpoint_path))
            .map_err(|_| {
                Error::Config(
                    "an audit key is already attached to this database handle".to_string(),
                )
            })
    }

    /// Whether the configured audit key (if any) fits the newest row of the
    /// chain. Cheap (reads one row); meant for startup checks. A full
    /// verification is [`Db::verify_audit`].
    pub fn audit_key_status(&self) -> Result<AuditKeyStatus> {
        let head = self.with_read(|conn| {
            conn.prepare_cached(&format!(
                "SELECT {ROW_COLUMNS} FROM audit_log ORDER BY id DESC LIMIT 1"
            ))
            .db()?
            .query_row([], audit_row)
            .optional()
            .db()
        })?;
        let keyed_head = head.filter(|row| row.scheme != AuditScheme::Sha256.as_str());
        Ok(match (self.inner.audit_keying.get(), keyed_head) {
            (None, None) => AuditKeyStatus::Unkeyed,
            (None, Some(_)) => AuditKeyStatus::KeyMissing,
            (Some(_), None) => AuditKeyStatus::Pending,
            (Some(keying), Some(row)) => {
                if row.scheme == AuditScheme::HmacSha256.as_str()
                    && row.mac_verifies(&keying.key)?
                {
                    AuditKeyStatus::Active
                } else {
                    AuditKeyStatus::KeyMismatch
                }
            }
        })
    }

    /// Append an event to the chain. The read of the previous hash and the
    /// insert run in one `BEGIN IMMEDIATE` transaction on the write
    /// connection, so concurrent writers (threads or processes) cannot fork
    /// the chain. With an audit key ([`Db::enable_keyed_audit`]) the row is
    /// keyed and the checkpoint file is rewritten after the commit, before
    /// the write connection is released.
    ///
    /// # Errors
    /// [`Error::Security`] when the chain is keyed but this handle has no
    /// audit key (an unkeyed row would be a downgrade); database failures.
    pub fn record_audit(&self, event: &AuditEvent) -> Result<()> {
        let details_text = stored_details(&event.details)?;
        // Hash exactly what is stored (and what verification re-reads).
        let stored = AuditEvent {
            details: serde_json::from_str(&details_text)?,
            ..event.clone()
        };
        let keying = self.inner.audit_keying.get();
        self.with_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db()?;
            let checkpoint = append(&tx, keying, &stored, &details_text)?;
            tx.commit().db()?;
            if let (Some(keying), Some((checkpoint, force))) = (keying, checkpoint) {
                keying.store_checkpoint(&checkpoint, force);
            }
            Ok(())
        })
    }

    /// Most recent first; optional `kind` prefix filter (e.g. `"ipc."`).
    /// The prefix is matched literally (case-sensitive, no wildcards).
    pub fn recent_audit(&self, limit: usize, kind_prefix: Option<&str>) -> Result<Vec<AuditEvent>> {
        let rows = self.with_read(|conn| {
            let mut stmt = conn
                .prepare_cached(&format!(
                    "SELECT {ROW_COLUMNS} FROM audit_log
                     WHERE ?1 IS NULL OR substr(kind, 1, length(?1)) = ?1
                     ORDER BY id DESC LIMIT ?2"
                ))
                .db()?;
            let rows = stmt
                .query_map(params![kind_prefix, sql_limit(limit)], audit_row)
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(|r| {
                r.event
                    .map_err(|e| Error::Db(format!("corrupt audit row {}: {e}", r.id)))
            })
            .collect()
    }

    /// Verify the whole chain and, with an audit key and a checkpoint path,
    /// the checkpoint file.
    ///
    /// The rows that exist when the call starts are verified as one
    /// snapshot (the table is append-only, so rows appended meanwhile do
    /// not disturb it) in batches, without holding a connection for the
    /// whole run. The checkpoint is read *before* that snapshot is taken:
    /// it is written after its row is committed, so an intact chain always
    /// contains the checkpointed row.
    ///
    /// Fails closed: keyed rows without a configured key are
    /// [`AuditFailure::KeyMissing`], an unkeyed row after a keyed one is
    /// [`AuditRowFailure::Downgrade`].
    ///
    /// # Errors
    /// Database read failures. Verification failures are reported in
    /// [`AuditVerification::failure`], not as `Err`.
    pub fn verify_audit(&self) -> Result<AuditVerification> {
        let keying = self.inner.audit_keying.get();
        let checkpoint = keying.and_then(AuditKeying::read_checkpoint);
        let snapshot_max: Option<i64> = self.with_read(|conn| {
            conn.prepare_cached("SELECT MAX(id) FROM audit_log")
                .db()?
                .query_row([], |r| r.get(0))
                .db()
        })?;

        let mut walk = ChainWalk {
            key: keying.map(|k| &k.key),
            checkpoint_seq: match &checkpoint {
                Some(CheckpointRead::Valid(cp)) => Some(cp.seq),
                _ => None,
            },
            expected_prev: AUDIT_GENESIS_HASH.to_string(),
            rows: 0,
            keyed_rows: 0,
            first_keyed_row: None,
            head: None,
            checkpoint_row: None,
        };
        let mut failure = None;
        let mut last_id = i64::MIN;
        'chain: while let Some(max_id) = snapshot_max {
            let batch = self.with_read(|conn| {
                let mut stmt = conn
                    .prepare_cached(&format!(
                        "SELECT {ROW_COLUMNS} FROM audit_log
                         WHERE id > ?1 AND id <= ?2 ORDER BY id LIMIT ?3"
                    ))
                    .db()?;
                let rows = stmt
                    .query_map(params![last_id, max_id, VERIFY_BATCH], audit_row)
                    .db()?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .db()?;
                Ok(rows)
            })?;
            if batch.is_empty() {
                break;
            }
            for row in batch {
                last_id = row.id;
                if let Err(f) = walk.check(row)? {
                    failure = Some(f);
                    break 'chain;
                }
            }
        }

        let mut state = if failure.is_some() {
            AuditCheckpointState::Failed
        } else {
            AuditCheckpointState::Disabled
        };
        if failure.is_none()
            && let Some(read) = &checkpoint
        {
            let checked = match read {
                CheckpointRead::Missing if walk.keyed_rows == 0 => Ok(AuditCheckpointState::Absent),
                CheckpointRead::Missing => Err(AuditFailure::CheckpointMissing),
                CheckpointRead::Invalid(_) => Err(AuditFailure::CheckpointInvalid),
                CheckpointRead::Valid(cp) if cp.seq > walk.rows => Err(AuditFailure::Truncated {
                    checkpoint_seq: cp.seq,
                    rows: walk.rows,
                }),
                CheckpointRead::Valid(cp) => match &walk.checkpoint_row {
                    Some((AuditScheme::HmacSha256, hash)) if hash_eq(hash, &cp.head) => {
                        Ok(AuditCheckpointState::Verified {
                            seq: cp.seq,
                            lag: walk.rows - cp.seq,
                        })
                    }
                    _ => Err(AuditFailure::CheckpointMismatch { seq: cp.seq }),
                },
            };
            match checked {
                Ok(s) => state = s,
                Err(f) => {
                    state = AuditCheckpointState::Failed;
                    failure = Some(f);
                }
            }
        }
        Ok(AuditVerification {
            rows: walk.rows,
            keyed_rows: walk.keyed_rows,
            first_keyed_row: walk.first_keyed_row,
            head: walk.head,
            key_configured: keying.is_some(),
            checkpoint: state,
            failure,
        })
    }

    /// Recompute the hash chain. `Ok(None)` if intact, `Ok(Some(row_id))` of
    /// the first row that does not verify otherwise (content changed,
    /// `prev_hash` not matching the previous row's hash — e.g. a row before
    /// it was deleted —, stored hash or MAC wrong, downgrade, or a keyed
    /// row while no audit key is configured). [`Db::verify_audit`] reports
    /// the reason.
    ///
    /// # Errors
    /// Database read failures, and [`Error::Security`] when every row
    /// verifies but the checkpoint file does not (truncated tail, missing
    /// or modified checkpoint): there is no row to point at.
    pub fn verify_audit_chain(&self) -> Result<Option<i64>> {
        match self.verify_audit()?.failure {
            None => Ok(None),
            Some(AuditFailure::Row { id, .. }) => Ok(Some(id)),
            Some(AuditFailure::KeyMissing { first_keyed_row }) => Ok(Some(first_keyed_row)),
            Some(other) => Err(Error::Security(other.to_string())),
        }
    }

    /// `(id, hash)` of the newest row, for anchoring the chain head outside
    /// the database (detects truncation of the tail). [`Db::audit_head`]
    /// also returns the scheme and the sequence number.
    pub fn audit_chain_head(&self) -> Result<Option<(i64, String)>> {
        self.with_read(|conn| {
            conn.prepare_cached("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1")
                .db()?
                .query_row([], |r| Ok((r.get::<_, i64>("id")?, col::text(r, "hash")?)))
                .optional()
                .db()
        })
    }

    /// The newest row of the chain, for anchoring it outside the host
    /// (the only complete defence against truncation and rollback). Not
    /// verified: use [`Db::verify_audit`] for that.
    ///
    /// # Errors
    /// Database read failures; [`Error::Db`] when the row's `scheme` is
    /// unknown.
    pub fn audit_head(&self) -> Result<Option<AuditHead>> {
        let row = self.with_read(|conn| {
            conn.prepare_cached(
                "SELECT id, hash, scheme, seq FROM audit_log ORDER BY id DESC LIMIT 1",
            )
            .db()?
            .query_row([], |r| {
                Ok((
                    r.get::<_, i64>("id")?,
                    col::text(r, "hash")?,
                    col::text(r, "scheme")?,
                    r.get::<_, Option<i64>>("seq")?,
                ))
            })
            .optional()
            .db()
        })?;
        row.map(|(id, hash, scheme, seq)| {
            let scheme = AuditScheme::parse(&scheme)
                .ok_or_else(|| Error::Db(format!("audit row {id} has an unknown hash scheme")))?;
            Ok(AuditHead {
                id,
                hash,
                scheme,
                seq: seq.and_then(|s| u64::try_from(s).ok()),
            })
        })
        .transpose()
    }

    /// Number of rows of kind [`AUDIT_KIND_CHECKPOINT_ANOMALY`]: how often
    /// an append found the checkpoint file not matching the chain.
    pub fn audit_checkpoint_anomalies(&self) -> Result<u64> {
        self.with_read(|conn| {
            let n: i64 = conn
                .prepare_cached("SELECT COUNT(*) FROM audit_log WHERE kind = ?1")
                .db()?
                .query_row([AUDIT_KIND_CHECKPOINT_ANOMALY], |r| r.get(0))
                .db()?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    /// Number of rows in the audit log.
    pub fn audit_count(&self) -> Result<u64> {
        self.with_read(|conn| {
            let n: i64 = conn
                .prepare_cached("SELECT COUNT(*) FROM audit_log")
                .db()?
                .query_row([], |r| r.get(0))
                .db()?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }
}

/// [`AuditSink`] that appends to the hash-chained `audit_log` table and,
/// optionally, mirrors every event to `tracing` (target `talon::audit`).
/// Persistence failures are logged, never propagated: auditing must not take
/// down the operation being audited.
#[derive(Debug, Clone)]
pub struct DbAuditSink {
    db: Db,
    mirror_to_tracing: bool,
}

impl DbAuditSink {
    /// Persist to `db` and mirror to `tracing`.
    pub fn new(db: Db) -> Self {
        Self {
            db,
            mirror_to_tracing: true,
        }
    }

    /// Persist to `db` only.
    pub fn without_tracing(db: Db) -> Self {
        Self {
            db,
            mirror_to_tracing: false,
        }
    }
}

impl AuditSink for DbAuditSink {
    fn record(&self, event: AuditEvent) {
        if let Err(e) = self.db.record_audit(&event) {
            tracing::error!(target: "talon::audit", kind = %event.kind, error = %e, "failed to persist audit event");
        }
        if self.mirror_to_tracing {
            TracingAuditSink.record(event);
        }
    }
}

#[cfg(test)]
#[path = "audit_keyed_tests.rs"]
mod keyed_tests;

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use serde_json::json;
    use talon_core::audit::{SharedAuditSink, event};

    use super::*;
    use crate::DB_FILE_NAME;

    fn ev(kind: &str, details: Value) -> AuditEvent {
        AuditEvent {
            timestamp: "2026-01-01T00:00:00.000Z".into(),
            kind: kind.into(),
            actor: "main".into(),
            target: Some("task-1".into()),
            outcome: "allowed".into(),
            details,
        }
    }

    /// Raw connection that can tamper with the log (triggers dropped).
    fn tamper(path: &Path, sql: &str) {
        let c = rusqlite::Connection::open(path).unwrap();
        c.execute_batch(
            "DROP TRIGGER IF EXISTS audit_log_no_update; DROP TRIGGER IF EXISTS audit_log_no_delete;",
        )
        .unwrap();
        c.execute_batch(sql).unwrap();
    }

    fn file_db() -> (tempfile::TempDir, std::path::PathBuf, Db) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE_NAME);
        let db = Db::open(&path).unwrap();
        (dir, path, db)
    }

    fn fill(db: &Db, n: usize) {
        for i in 0..n {
            db.record_audit(&ev(
                if i % 2 == 0 {
                    "ipc.task.allowed"
                } else {
                    "container.launch"
                },
                json!({ "i": i, "nested": { "b": 1, "a": [1, 2, { "z": 0, "y": null }] } }),
            ))
            .unwrap();
        }
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let a = json!({ "b": 1, "a": { "d": [ { "y": 2, "x": 1 } ], "c": "é\"" } });
        assert_eq!(
            canonical_json(&a).unwrap(),
            r#"{"a":{"c":"é\"","d":[{"x":1,"y":2}]},"b":1}"#
        );
        let b: Value =
            serde_json::from_str(r#"{ "a": { "c": "é\"", "d": [ {"x":1, "y":2} ] }, "b": 1 }"#)
                .unwrap();
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        assert_eq!(canonical_json(&json!(null)).unwrap(), "null");
        assert_eq!(canonical_json(&json!(1.5)).unwrap(), "1.5");
    }

    #[test]
    fn hash_is_sha256_of_prev_hash_and_canonical_event() {
        let e = ev("k", json!({ "z": 1, "a": 2 }));
        let canonical = r#"{"actor":"main","details":{"a":2,"z":1},"kind":"k","outcome":"allowed","target":"task-1","timestamp":"2026-01-01T00:00:00.000Z"}"#;
        let mut h = Sha256::new();
        h.update(AUDIT_GENESIS_HASH.as_bytes());
        h.update(canonical.as_bytes());
        assert_eq!(
            audit_event_hash(AUDIT_GENESIS_HASH, &e).unwrap(),
            hex::encode(h.finalize())
        );
        // `target: None` is omitted, not null.
        let e2 = AuditEvent { target: None, ..e };
        let c2 = canonical_json(&serde_json::to_value(&e2).unwrap()).unwrap();
        assert!(!c2.contains("target"));
    }

    #[test]
    fn chain_links_rows_from_genesis() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.verify_audit_chain().unwrap(), None);
        assert_eq!(db.audit_chain_head().unwrap(), None);
        fill(&db, 3);
        let rows: Vec<(String, String)> = db
            .with_conn(|c| {
                let mut s = c
                    .prepare("SELECT prev_hash, hash FROM audit_log ORDER BY id")
                    .db()?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .db()?
                    .collect::<rusqlite::Result<_>>()
                    .db()
            })
            .unwrap();
        assert_eq!(rows[0].0, AUDIT_GENESIS_HASH);
        assert_eq!(rows[1].0, rows[0].1);
        assert_eq!(rows[2].0, rows[1].1);
        assert!(rows.iter().all(|(_, h)| h.len() == 64));
        assert_eq!(db.verify_audit_chain().unwrap(), None);
        let (id, hash) = db.audit_chain_head().unwrap().unwrap();
        assert_eq!(id, 3);
        assert_eq!(hash, rows[2].1);
        assert_eq!(db.audit_count().unwrap(), 3);
    }

    #[test]
    fn recent_audit_orders_and_filters_by_prefix() {
        let db = Db::open_in_memory().unwrap();
        fill(&db, 5);
        db.record_audit(&ev("ipcx.other", json!(null))).unwrap();
        let all = db.recent_audit(100, None).unwrap();
        assert_eq!(all.len(), 6);
        assert_eq!(all[0].kind, "ipcx.other");
        let ipc = db.recent_audit(100, Some("ipc.")).unwrap();
        assert_eq!(ipc.len(), 3);
        assert!(ipc.iter().all(|e| e.kind == "ipc.task.allowed"));
        assert_eq!(ipc[0].details["i"], 4);
        assert_eq!(db.recent_audit(2, None).unwrap().len(), 2);
        // Wildcards in the prefix are literal.
        assert!(db.recent_audit(100, Some("%")).unwrap().is_empty());
        assert!(db.recent_audit(100, Some("ipc_")).unwrap().is_empty());
        // Round trip of the event itself.
        let e = ev("x.y", json!({ "b": [1, 2], "a": "s" }));
        db.record_audit(&e).unwrap();
        assert_eq!(db.recent_audit(1, None).unwrap()[0], e);
    }

    #[test]
    fn append_only_triggers_refuse_update_and_delete() {
        let db = Db::open_in_memory().unwrap();
        fill(&db, 1);
        let upd = db.with_conn(|c| c.execute("UPDATE audit_log SET actor = 'x'", []).db());
        assert!(matches!(upd, Err(Error::Db(m)) if m.contains("append-only")));
        let del = db.with_conn(|c| c.execute("DELETE FROM audit_log", []).db());
        assert!(del.is_err());
        assert_eq!(db.audit_count().unwrap(), 1);
    }

    #[test]
    fn detects_modified_content() {
        let (_d, path, db) = file_db();
        fill(&db, 5);
        tamper(
            &path,
            "UPDATE audit_log SET outcome = 'denied' WHERE id = 3",
        );
        assert_eq!(db.verify_audit_chain().unwrap(), Some(3));
    }

    #[test]
    fn detects_modified_details_and_invalid_json() {
        let (_d, path, db) = file_db();
        fill(&db, 4);
        tamper(
            &path,
            r#"UPDATE audit_log SET details = '{"i":99}' WHERE id = 2"#,
        );
        assert_eq!(db.verify_audit_chain().unwrap(), Some(2));
        let (_d2, path2, db2) = file_db();
        fill(&db2, 4);
        tamper(
            &path2,
            "UPDATE audit_log SET details = '{oops' WHERE id = 4",
        );
        assert_eq!(db2.verify_audit_chain().unwrap(), Some(4));
        assert!(db2.recent_audit(10, None).is_err());
    }

    #[test]
    fn detects_deleted_row() {
        let (_d, path, db) = file_db();
        fill(&db, 5);
        tamper(&path, "DELETE FROM audit_log WHERE id = 2");
        assert_eq!(db.verify_audit_chain().unwrap(), Some(3));
    }

    #[test]
    fn detects_rehashed_row_without_relinking() {
        // An attacker who recomputes the hash of an edited row still breaks
        // the link to the next row.
        let (_d, path, db) = file_db();
        fill(&db, 3);
        let row2 = db.recent_audit(3, None).unwrap()[1].clone();
        let edited = AuditEvent {
            outcome: "denied".into(),
            ..row2
        };
        let prev: String = db
            .with_conn(|c| {
                c.query_row("SELECT prev_hash FROM audit_log WHERE id = 2", [], |r| {
                    r.get(0)
                })
                .db()
            })
            .unwrap();
        let new_hash = audit_event_hash(&prev, &edited).unwrap();
        tamper(
            &path,
            &format!("UPDATE audit_log SET outcome = 'denied', hash = '{new_hash}' WHERE id = 2"),
        );
        assert_eq!(db.verify_audit_chain().unwrap(), Some(3));
    }

    #[test]
    fn detects_forged_genesis() {
        let (_d, path, db) = file_db();
        fill(&db, 2);
        tamper(
            &path,
            &format!(
                "UPDATE audit_log SET prev_hash = '{}' WHERE id = 1",
                "1".repeat(64)
            ),
        );
        assert_eq!(db.verify_audit_chain().unwrap(), Some(1));
    }

    #[test]
    fn verification_spans_batches() {
        let db = Db::open_in_memory().unwrap();
        for i in 0..(VERIFY_BATCH as usize * 2 + 5) {
            db.record_audit(&event("bulk", "a", None, "info", json!(i)))
                .unwrap();
        }
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn oversized_details_are_truncated_but_chained() {
        let db = Db::open_in_memory().unwrap();
        let big = "x".repeat(MAX_AUDIT_DETAILS_BYTES + 10);
        db.record_audit(&ev("big", json!({ "blob": big }))).unwrap();
        let got = &db.recent_audit(1, None).unwrap()[0];
        assert_eq!(got.details["truncated"], true);
        assert!(got.details["original_bytes"].as_u64().unwrap() > MAX_AUDIT_DETAILS_BYTES as u64);
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn floats_and_unicode_survive_the_round_trip() {
        let db = Db::open_in_memory().unwrap();
        db.record_audit(&ev(
            "f",
            json!({ "pi": std::f64::consts::PI, "third": 1.0_f64 / 3.0, "tiny": 1e-300, "neg": -0.0, "s": "ü\u{1F600}\n" }),
        ))
        .unwrap();
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn db_audit_sink_persists_events() {
        let db = Db::open_in_memory().unwrap();
        let sink: SharedAuditSink = Arc::new(DbAuditSink::new(db.clone()));
        sink.record(event(
            "mount.rejected",
            "grp",
            Some("/etc"),
            "denied",
            json!({}),
        ));
        DbAuditSink::without_tracing(db.clone()).record(event(
            "tool.call",
            "grp",
            None,
            "info",
            json!({ "tool": "bash" }),
        ));
        let got = db.recent_audit(10, None).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].kind, "mount.rejected");
        assert_eq!(got[1].target.as_deref(), Some("/etc"));
        assert_eq!(db.verify_audit_chain().unwrap(), None);
    }
}
