//! Audit key and the keyed checkpoint file.
//!
//! With an [`AuditKey`] the audit chain is keyed: every new row carries
//! `HMAC-SHA-256(key, seq || prev_hash || canonical_json(event))` instead of
//! a plain SHA-256, so somebody who can write the database but does not hold
//! the key can neither forge a row nor recompute the chain. The same key
//! authenticates a small checkpoint file outside the database (sequence
//! number and hash of the newest row), which makes a truncated tail
//! detectable (see [`crate::audit`]).
//!
//! The key never appears in an error, a log line or a `Debug` rendering.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use talon_core::{Error, Result};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// `.env` key holding the audit key (a secret: read from the file only).
pub const AUDIT_KEY_ENV: &str = "TALON_AUDIT_KEY";

/// Minimum length of the audit key in bytes (`openssl rand -hex 32` yields
/// 64).
pub const MIN_AUDIT_KEY_LEN: usize = 32;

/// Minimum number of distinct bytes in the audit key (rejects padding such
/// as `aaaa...`).
const MIN_AUDIT_KEY_DISTINCT: usize = 8;

/// File name of the audit checkpoint inside the store directory
/// (`store/audit.checkpoint`).
pub const AUDIT_CHECKPOINT_FILE_NAME: &str = "audit.checkpoint";

/// First line of a checkpoint file.
const CHECKPOINT_MAGIC: &str = "talon-audit-checkpoint v1";
/// Largest checkpoint file that is read (a real one is under 200 bytes).
const MAX_CHECKPOINT_BYTES: u64 = 1024;

const ROW_DOMAIN: &[u8] = b"talon-audit-row-v1";
const CHECKPOINT_DOMAIN: &[u8] = b"talon-audit-checkpoint-v1";

/// `<store_dir>/audit.checkpoint`.
pub fn default_audit_checkpoint_path(store_dir: &Path) -> PathBuf {
    store_dir.join(AUDIT_CHECKPOINT_FILE_NAME)
}

/// Secret key of the keyed audit chain.
///
/// Cheap to clone; the key material is zeroed when the last clone is
/// dropped. `Debug` never prints it.
#[derive(Clone)]
pub struct AuditKey(Arc<Zeroizing<Vec<u8>>>);

impl fmt::Debug for AuditKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditKey(<redacted>)")
    }
}

impl AuditKey {
    /// Parse the value of [`AUDIT_KEY_ENV`] (surrounding whitespace is
    /// ignored).
    ///
    /// # Errors
    /// [`Error::Config`] when the key is shorter than [`MIN_AUDIT_KEY_LEN`]
    /// bytes or obviously not random. The message never contains the key.
    pub fn parse(raw: &str) -> Result<Self> {
        let value = raw.trim().as_bytes();
        if value.len() < MIN_AUDIT_KEY_LEN {
            return Err(Error::Config(format!(
                "{AUDIT_KEY_ENV} is too short ({} bytes, minimum {MIN_AUDIT_KEY_LEN}): \
                 generate one with `openssl rand -hex 32`",
                value.len()
            )));
        }
        let mut seen = [false; 256];
        for b in value {
            seen[usize::from(*b)] = true;
        }
        if seen.iter().filter(|s| **s).count() < MIN_AUDIT_KEY_DISTINCT {
            return Err(Error::Config(format!(
                "{AUDIT_KEY_ENV} is not random enough (fewer than {MIN_AUDIT_KEY_DISTINCT} \
                 distinct characters): generate one with `openssl rand -hex 32`"
            )));
        }
        Ok(Self(Arc::new(Zeroizing::new(value.to_vec()))))
    }

    /// `HMAC-SHA-256(key, domain || len-prefixed parts)`.
    fn mac(&self, domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
        let mut mac = HmacSha256::new_from_slice(&self.0)
            .map_err(|_| Error::Other("audit key rejected by HMAC".to_string()))?;
        mac.update(domain);
        for part in parts {
            // Length prefixes keep the encoding unambiguous.
            mac.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            mac.update(part);
        }
        Ok(mac.finalize().into_bytes().into())
    }

    /// Hex MAC of a keyed audit row: `seq` is the 1-based position of the
    /// row in the chain, `prev_hash` the previous row's hash and
    /// `canonical_event` the event's canonical JSON.
    pub(crate) fn row_mac(
        &self,
        seq: u64,
        prev_hash: &str,
        canonical_event: &str,
    ) -> Result<String> {
        self.mac(
            ROW_DOMAIN,
            &[
                &seq.to_be_bytes(),
                prev_hash.as_bytes(),
                canonical_event.as_bytes(),
            ],
        )
        .map(hex::encode)
    }

    fn checkpoint_mac(&self, seq: u64, head: &str) -> Result<[u8; 32]> {
        self.mac(CHECKPOINT_DOMAIN, &[&seq.to_be_bytes(), head.as_bytes()])
    }
}

/// Constant-time comparison of a computed MAC with a stored hex MAC.
/// Anything that is not the hex of 32 bytes does not match.
pub(crate) fn mac_matches(expected_hex: &str, stored_hex: &str) -> bool {
    let (Ok(expected), Ok(stored)) = (hex::decode(expected_hex), hex::decode(stored_hex)) else {
        return false;
    };
    expected.len() == 32 && bool::from(expected.ct_eq(&stored))
}

/// Constant-time comparison of two stored hashes.
pub(crate) fn hash_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Sequence number and hash of the newest keyed row, as checkpointed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    /// 1-based position of the row in the chain.
    pub(crate) seq: u64,
    /// The row's `hash`.
    pub(crate) head: String,
}

/// Result of reading the checkpoint file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheckpointRead {
    /// No file.
    Missing,
    /// Unreadable, malformed, or its MAC does not verify under the key.
    Invalid(&'static str),
    /// Authentic checkpoint.
    Valid(Checkpoint),
}

/// The key plus where the checkpoint lives, as attached to a [`crate::Db`].
pub(crate) struct AuditKeying {
    pub(crate) key: AuditKey,
    pub(crate) checkpoint_path: Option<PathBuf>,
    /// The last checkpoint write of this process failed: the file is known
    /// to be stale, so it is not evidence of truncation until a write
    /// succeeds again.
    pub(crate) checkpoint_stale: AtomicBool,
}

impl AuditKeying {
    pub(crate) fn new(key: AuditKey, checkpoint_path: Option<PathBuf>) -> Self {
        Self {
            key,
            checkpoint_path,
            checkpoint_stale: AtomicBool::new(false),
        }
    }

    /// Read and authenticate the checkpoint. `None` without a checkpoint
    /// path.
    pub(crate) fn read_checkpoint(&self) -> Option<CheckpointRead> {
        let path = self.checkpoint_path.as_deref()?;
        Some(read_checkpoint(path, &self.key))
    }

    /// Write `checkpoint` (atomically). Unless `force`, an authentic
    /// checkpoint that is already further ahead (another process appended
    /// in the meantime) is kept. Failures are logged, never propagated: the
    /// audit row itself is already committed.
    pub(crate) fn store_checkpoint(&self, checkpoint: &Checkpoint, force: bool) {
        let Some(path) = self.checkpoint_path.as_deref() else {
            return;
        };
        if !force
            && let CheckpointRead::Valid(existing) = read_checkpoint(path, &self.key)
            && existing.seq > checkpoint.seq
        {
            return;
        }
        match write_checkpoint(path, &self.key, checkpoint) {
            Ok(()) => self.checkpoint_stale.store(false, Ordering::Relaxed),
            Err(e) => {
                self.checkpoint_stale.store(true, Ordering::Relaxed);
                tracing::error!(
                    target: "talon::audit",
                    path = %path.display(),
                    error = %e,
                    "cannot write the audit checkpoint; tail truncation is not detectable until it is written again"
                );
            }
        }
    }
}

fn read_checkpoint(path: &Path, key: &AuditKey) -> CheckpointRead {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CheckpointRead::Missing,
        Err(_) => return CheckpointRead::Invalid("unreadable"),
    };
    let mut text = String::new();
    if file
        .take(MAX_CHECKPOINT_BYTES + 1)
        .read_to_string(&mut text)
        .is_err()
    {
        return CheckpointRead::Invalid("unreadable");
    }
    if text.len() as u64 > MAX_CHECKPOINT_BYTES {
        return CheckpointRead::Invalid("malformed");
    }
    let mut lines = text.lines();
    if lines.next() != Some(CHECKPOINT_MAGIC) {
        return CheckpointRead::Invalid("malformed");
    }
    let (mut seq, mut head, mut mac) = (None, None, None);
    for line in lines {
        match line.split_once('=') {
            Some(("seq", v)) => seq = v.parse::<u64>().ok(),
            Some(("head", v)) => head = Some(v.to_string()),
            Some(("mac", v)) => mac = Some(v.to_string()),
            _ => return CheckpointRead::Invalid("malformed"),
        }
    }
    let (Some(seq), Some(head), Some(mac)) = (seq, head, mac) else {
        return CheckpointRead::Invalid("malformed");
    };
    match key.checkpoint_mac(seq, &head) {
        Ok(expected) if mac_matches(&hex::encode(expected), &mac) => {
            CheckpointRead::Valid(Checkpoint { seq, head })
        }
        _ => CheckpointRead::Invalid("MAC does not verify"),
    }
}

/// Write the checkpoint to a temporary file next to `path` (mode `0600`),
/// sync it and rename it over `path`.
fn write_checkpoint(path: &Path, key: &AuditKey, checkpoint: &Checkpoint) -> Result<()> {
    let mac = hex::encode(key.checkpoint_mac(checkpoint.seq, &checkpoint.head)?);
    let content = format!(
        "{CHECKPOINT_MAGIC}\nseq={}\nhead={}\nmac={mac}\n",
        checkpoint.seq, checkpoint.head
    );
    let mut tmp_name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    // Unique per write: two handles of one process may write concurrently.
    static NEXT_TMP: AtomicU64 = AtomicU64::new(0);
    tmp_name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        NEXT_TMP.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = path.with_file_name(tmp_name);
    let written = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        // Best effort: do not leave the temporary file behind.
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn key_validation_never_echoes_the_key() {
        let short = "s3cr3t-short-key";
        let err = AuditKey::parse(short).unwrap_err().to_string();
        assert!(err.contains("too short"), "{err}");
        assert!(!err.contains(short));
        let flat = "a".repeat(64);
        let err = AuditKey::parse(&flat).unwrap_err().to_string();
        assert!(err.contains("not random enough"), "{err}");
        assert!(!err.contains(&flat));
        assert!(AuditKey::parse("   ").is_err());

        let key = AuditKey::parse(&format!("  {KEY}\n")).unwrap();
        assert_eq!(format!("{key:?}"), "AuditKey(<redacted>)");
        // Whitespace around the value is not part of the key.
        assert_eq!(
            key.row_mac(1, "p", "{}").unwrap(),
            AuditKey::parse(KEY).unwrap().row_mac(1, "p", "{}").unwrap()
        );
    }

    #[test]
    fn row_mac_binds_key_sequence_link_and_content() {
        let key = AuditKey::parse(KEY).unwrap();
        let other = AuditKey::parse(&KEY.replace('0', "f")).unwrap();
        let mac = key.row_mac(7, "prev", "{\"a\":1}").unwrap();
        assert_eq!(mac.len(), 64);
        assert_ne!(mac, other.row_mac(7, "prev", "{\"a\":1}").unwrap());
        assert_ne!(mac, key.row_mac(8, "prev", "{\"a\":1}").unwrap());
        assert_ne!(mac, key.row_mac(7, "pre", "v{\"a\":1}").unwrap());
        assert_ne!(mac, key.row_mac(7, "prev", "{\"a\":2}").unwrap());
        assert!(mac_matches(&mac, &mac));
        assert!(mac_matches(&mac, &mac.to_uppercase()));
        assert!(!mac_matches(&mac, "zz"));
        assert!(!mac_matches(&mac, &mac[..62]));
    }

    #[test]
    fn checkpoint_round_trip_and_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_CHECKPOINT_FILE_NAME);
        let key = AuditKey::parse(KEY).unwrap();
        assert_eq!(read_checkpoint(&path, &key), CheckpointRead::Missing);
        let cp = Checkpoint {
            seq: 42,
            head: "ab".repeat(32),
        };
        write_checkpoint(&path, &key, &cp).unwrap();
        assert_eq!(read_checkpoint(&path, &key), CheckpointRead::Valid(cp));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(KEY));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // Another key, an edited sequence number, garbage.
        let other = AuditKey::parse(&KEY.replace('0', "f")).unwrap();
        assert!(matches!(
            read_checkpoint(&path, &other),
            CheckpointRead::Invalid(_)
        ));
        std::fs::write(&path, text.replace("seq=42", "seq=41")).unwrap();
        assert!(matches!(
            read_checkpoint(&path, &key),
            CheckpointRead::Invalid(_)
        ));
        std::fs::write(&path, "garbage").unwrap();
        assert!(matches!(
            read_checkpoint(&path, &key),
            CheckpointRead::Invalid(_)
        ));
        std::fs::write(&path, "x".repeat(5000)).unwrap();
        assert!(matches!(
            read_checkpoint(&path, &key),
            CheckpointRead::Invalid(_)
        ));
    }

    #[test]
    fn store_checkpoint_keeps_a_newer_one_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_CHECKPOINT_FILE_NAME);
        let keying = AuditKeying::new(AuditKey::parse(KEY).unwrap(), Some(path));
        let cp = |seq| Checkpoint {
            seq,
            head: "cd".repeat(32),
        };
        keying.store_checkpoint(&cp(5), false);
        keying.store_checkpoint(&cp(4), false);
        assert_eq!(keying.read_checkpoint(), Some(CheckpointRead::Valid(cp(5))));
        keying.store_checkpoint(&cp(4), true);
        assert_eq!(keying.read_checkpoint(), Some(CheckpointRead::Valid(cp(4))));
        keying.store_checkpoint(&cp(6), false);
        assert_eq!(keying.read_checkpoint(), Some(CheckpointRead::Valid(cp(6))));
    }
}
