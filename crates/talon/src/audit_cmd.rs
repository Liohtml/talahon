//! `talon audit verify`, `talon audit head` and `talon audit tail`, plus the
//! audit key wiring shared with `talon run` and `talon doctor`.

use std::io::Write;

use anyhow::{anyhow, bail};
use talon_core::config::TalonConfig;
use talon_db::{
    AUDIT_KEY_ENV, AuditCheckpointState, AuditFailure, AuditKey, AuditKeyStatus, Db, DbOptions,
    default_audit_checkpoint_path, default_db_path,
};
use talon_setup::StatusBlock;

/// Shown wherever the chain turns out to be unkeyed.
pub const UNKEYED_HINT: &str = "the audit chain is unkeyed: somebody who can write the database \
     can rewrite or truncate it unnoticed. Set TALON_AUDIT_KEY in .env (openssl rand -hex 32) \
     and restart talon";

/// The audit key from `.env` ([`AUDIT_KEY_ENV`]; a secret, so the process
/// environment is not consulted). `None` when unset or blank.
///
/// # Errors
/// The key is set but too short or not random; the message never contains
/// it.
pub fn audit_key(config: &TalonConfig) -> anyhow::Result<Option<AuditKey>> {
    match config.env.file_value(AUDIT_KEY_ENV) {
        Some(raw) if !raw.trim().is_empty() => {
            AuditKey::parse(raw).map(Some).map_err(|e| anyhow!("{e}"))
        }
        _ => Ok(None),
    }
}

/// Attach the configured audit key (and the checkpoint file
/// `store/audit.checkpoint`) to `db`. Returns whether a key is configured.
///
/// # Errors
/// An invalid key (see [`audit_key`]).
pub fn enable_audit_key(db: &Db, config: &TalonConfig) -> anyhow::Result<bool> {
    let Some(key) = audit_key(config)? else {
        return Ok(false);
    };
    db.enable_keyed_audit(key, Some(default_audit_checkpoint_path(&config.store_dir)))
        .map_err(|e| anyhow!("{e}"))?;
    Ok(true)
}

/// Startup check of `talon run`: attach the audit key and make sure events
/// can be recorded with it.
///
/// # Errors
/// An invalid key, a keyed chain without a key, or a key that does not
/// authenticate the newest row: Talon must not run without a working audit
/// log.
pub fn prepare_audit(db: &Db, config: &TalonConfig) -> anyhow::Result<AuditKeyStatus> {
    enable_audit_key(db, config)?;
    let status = db.audit_key_status().map_err(|e| anyhow!("{e}"))?;
    match status {
        AuditKeyStatus::KeyMissing => bail!(
            "the audit log is keyed but {AUDIT_KEY_ENV} is not set in .env: refusing to start, \
             because audit events could not be recorded. Restore the key (see docs/SECURITY.md, \
             \"Audit key\")"
        ),
        AuditKeyStatus::KeyMismatch => bail!(
            "{AUDIT_KEY_ENV} does not authenticate the newest audit row (wrong key, or the audit \
             log was tampered with): refusing to start. Run `talon audit verify`"
        ),
        AuditKeyStatus::Unkeyed => tracing::info!("{UNKEYED_HINT}"),
        AuditKeyStatus::Pending => {
            tracing::info!("audit key configured: the audit chain is keyed from the next event on");
        }
        _ => {}
    }
    Ok(status)
}

fn open_db(config: &TalonConfig) -> anyhow::Result<Option<Db>> {
    let path = default_db_path(&config.store_dir);
    if !path.exists() {
        return Ok(None);
    }
    Db::open_with_options(
        &path,
        &DbOptions {
            assistant_name: config.assistant_name.clone(),
        },
    )
    .map(Some)
    .map_err(|e| anyhow!("cannot open {}: {e}", path.display()))
}

/// Status block for an audit-chain verification of `db` (with the audit key
/// attached, if one is configured: see [`enable_audit_key`]).
///
/// `CHAIN` is `intact`, `tampered` (a row or the checkpoint does not
/// verify), `truncated` (the checkpoint is ahead of the log) or
/// `unverifiable` (keyed rows, no key).
///
/// # Errors
/// Database read failures.
pub fn verify_block(db: &Db) -> anyhow::Result<(StatusBlock, bool)> {
    let count = db.audit_count().map_err(|e| anyhow!("{e}"))?;
    let v = db.verify_audit().map_err(|e| anyhow!("{e}"))?;
    let mut block = StatusBlock::new("AUDIT_VERIFY").field("EVENTS", count);
    block.set(
        "KEY",
        if v.key_configured {
            "configured"
        } else {
            "not configured"
        },
    );
    block.set("KEYED_EVENTS", v.keyed_rows);
    if let Some(id) = v.first_keyed_row {
        block.set("FIRST_KEYED_ROW", id);
    }
    match v.checkpoint {
        AuditCheckpointState::Disabled => block.set("CHECKPOINT", "disabled"),
        AuditCheckpointState::Absent => block.set("CHECKPOINT", "absent"),
        AuditCheckpointState::Verified { seq, lag } => {
            block.set("CHECKPOINT", "verified");
            block.set("CHECKPOINT_SEQ", seq);
            block.set("CHECKPOINT_LAG", lag);
        }
        _ => block.set("CHECKPOINT", "failed"),
    }
    let anomalies = db
        .audit_checkpoint_anomalies()
        .map_err(|e| anyhow!("{e}"))?;
    if anomalies > 0 {
        // Past truncations / restores that an append recorded in the chain.
        block.set("CHECKPOINT_ANOMALIES", anomalies);
    }
    let Some(failure) = &v.failure else {
        match &v.head {
            Some(head) => {
                block.set("HEAD_ID", head.id);
                block.set("HEAD_HASH", &head.hash);
                block.set("HEAD_SCHEME", head.scheme);
            }
            None => block.set("HEAD_ID", "none"),
        }
        if !v.key_configured {
            block.set("HINT", UNKEYED_HINT);
        } else if v.keyed_rows == 0 && v.rows > 0 {
            block.set(
                "WARNING",
                "an audit key is configured but the chain has no keyed rows: talon keys it with \
                 the next event it records. If it was keyed before, the keyed rows were removed",
            );
        }
        block.set("CHAIN", "intact");
        block.set("STATUS", "success");
        return Ok((block, true));
    };
    let chain = match failure {
        AuditFailure::KeyMissing { first_keyed_row } => {
            block.set("FIRST_BAD_ROW", first_keyed_row);
            "unverifiable"
        }
        AuditFailure::Row { id, .. } => {
            block.set("FIRST_BAD_ROW", id);
            "tampered"
        }
        AuditFailure::Truncated { .. } => "truncated",
        _ => "tampered",
    };
    block.set("CHAIN", chain);
    block.set("ERROR", failure);
    block.set("STATUS", "failed");
    Ok((block, false))
}

/// `talon audit verify`: exit code 0 when the chain is intact, 1 otherwise.
///
/// # Errors
/// The database cannot be opened or read, or the audit key is invalid.
pub fn verify(config: &TalonConfig) -> anyhow::Result<i32> {
    let Some(db) = open_db(config)? else {
        println!(
            "{}",
            StatusBlock::new("AUDIT_VERIFY")
                .field("CHAIN", "missing")
                .field("STATUS", "failed")
                .field("ERROR", "no database (talon has not run yet)")
        );
        return Ok(1);
    };
    enable_audit_key(&db, config)?;
    let (block, ok) = verify_block(&db)?;
    println!("{block}");
    Ok(if ok { 0 } else { 1 })
}

/// Status block with the newest row of the chain, for anchoring it on a
/// system the host cannot write. Not a verification.
///
/// # Errors
/// Database read failures.
pub fn head_block(db: &Db) -> anyhow::Result<StatusBlock> {
    let count = db.audit_count().map_err(|e| anyhow!("{e}"))?;
    let mut block = StatusBlock::new("AUDIT_HEAD").field("EVENTS", count);
    match db.audit_head().map_err(|e| anyhow!("{e}"))? {
        Some(head) => {
            block.set("HEAD_ID", head.id);
            block.set("HEAD_HASH", head.hash);
            block.set("HEAD_SCHEME", head.scheme);
            if let Some(seq) = head.seq {
                block.set("HEAD_SEQ", seq);
            }
        }
        None => block.set("HEAD_ID", "none"),
    }
    block.set("STATUS", "success");
    Ok(block)
}

/// `talon audit head`: print the chain head (needs no audit key).
///
/// # Errors
/// The database cannot be opened or read.
pub fn head(config: &TalonConfig) -> anyhow::Result<i32> {
    let Some(db) = open_db(config)? else {
        eprintln!("no database (talon has not run yet)");
        return Ok(1);
    };
    println!("{}", head_block(&db)?);
    Ok(0)
}

/// JSON lines of the `n` most recent events (oldest first), optionally
/// filtered by kind prefix.
///
/// # Errors
/// Database read failures.
pub fn tail_lines(db: &Db, n: usize, kind: Option<&str>) -> anyhow::Result<Vec<String>> {
    let mut events = db
        .recent_audit(n, kind.filter(|k| !k.is_empty()))
        .map_err(|e| anyhow!("{e}"))?;
    events.reverse();
    events
        .iter()
        .map(|e| serde_json::to_string(e).map_err(|e| anyhow!("{e}")))
        .collect()
}

/// `talon audit tail`.
///
/// # Errors
/// The database cannot be opened or read.
pub fn tail(config: &TalonConfig, n: usize, kind: Option<&str>) -> anyhow::Result<i32> {
    let Some(db) = open_db(config)? else {
        eprintln!("no database (talon has not run yet)");
        return Ok(1);
    };
    let lines = tail_lines(&db, n, kind)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in lines {
        // A closed pipe (`| head`) ends the listing quietly.
        if writeln!(out, "{line}").is_err() {
            break;
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use talon_core::audit::event;
    use talon_core::env::EnvFile;

    use super::*;

    const KEY: &str = "9d2c4e6f8a0b1c3d5e7f9a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d";

    fn fill(db: &Db, n: usize) {
        for i in 0..n {
            db.record_audit(&event(
                "container.launch",
                "main",
                None,
                "allowed",
                serde_json::json!({ "i": i }),
            ))
            .unwrap();
        }
    }

    /// A project root whose `.env` is `env`.
    fn project(env: &str) -> (tempfile::TempDir, TalonConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = TalonConfig::from_env(dir.path(), EnvFile::from_str_content(env));
        (dir, config)
    }

    fn open(config: &TalonConfig) -> Db {
        Db::open(&default_db_path(&config.store_dir)).unwrap()
    }

    #[test]
    fn verify_and_tail_on_a_real_chain() {
        let db = Db::open_in_memory().unwrap();
        let (block, ok) = verify_block(&db).unwrap();
        assert!(ok);
        assert_eq!(block.get("HEAD_ID"), Some("none"));

        for (i, kind) in ["ipc.task.allowed", "container.launch", "ipc.message.denied"]
            .iter()
            .enumerate()
        {
            db.record_audit(&event(
                kind,
                "main",
                None,
                "allowed",
                serde_json::json!({ "i": i }),
            ))
            .unwrap();
        }
        let (block, ok) = verify_block(&db).unwrap();
        assert!(ok);
        assert_eq!(block.get("EVENTS"), Some("3"));
        assert_eq!(block.get("CHAIN"), Some("intact"));
        // Unkeyed: still a success, with a hint.
        assert_eq!(block.get("KEY"), Some("not configured"));
        assert_eq!(block.get("KEYED_EVENTS"), Some("0"));
        assert_eq!(block.get("HEAD_SCHEME"), Some("sha256"));
        assert_eq!(block.get("CHECKPOINT"), Some("disabled"));
        assert!(block.get("HINT").unwrap().contains("TALON_AUDIT_KEY"));

        let head = head_block(&db).unwrap();
        assert_eq!(head.get("HEAD_ID"), Some("3"));
        assert_eq!(head.get("HEAD_HASH"), block.get("HEAD_HASH"));
        assert_eq!(head.get("HEAD_SEQ"), None);

        let all = tail_lines(&db, 10, None).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all[0].contains("ipc.task.allowed"), "oldest first: {all:?}");
        let ipc = tail_lines(&db, 10, Some("ipc.")).unwrap();
        assert_eq!(ipc.len(), 2);
        let last = tail_lines(&db, 1, None).unwrap();
        assert!(last[0].contains("ipc.message.denied"));
    }

    #[test]
    fn audit_key_comes_from_the_env_file_and_is_validated() {
        let (_d, config) = project("");
        assert!(audit_key(&config).unwrap().is_none());
        let (_d, config) = project("TALON_AUDIT_KEY=\n");
        assert!(audit_key(&config).unwrap().is_none());
        let (_d, config) = project(&format!("TALON_AUDIT_KEY={KEY}\n"));
        assert!(audit_key(&config).unwrap().is_some());

        let (_d, config) = project("TALON_AUDIT_KEY=hunter2-too-short\n");
        let err = format!("{:#}", audit_key(&config).unwrap_err());
        assert!(err.contains("TALON_AUDIT_KEY is too short"), "{err}");
        assert!(!err.contains("hunter2"));
        let db = Db::open_in_memory().unwrap();
        assert!(enable_audit_key(&db, &config).is_err());
        assert!(prepare_audit(&db, &config).is_err());
    }

    #[test]
    fn keyed_chain_lifecycle_through_the_commands() {
        let (_d, unkeyed_config) = project("");
        let env = format!("TALON_AUDIT_KEY={KEY}\n");
        let keyed_config = TalonConfig::from_env(
            &unkeyed_config.project_root,
            EnvFile::from_str_content(&env),
        );
        let checkpoint = default_audit_checkpoint_path(&keyed_config.store_dir);

        // An existing unkeyed installation.
        let db = open(&unkeyed_config);
        assert_eq!(
            prepare_audit(&db, &unkeyed_config).unwrap(),
            AuditKeyStatus::Unkeyed
        );
        fill(&db, 2);
        assert!(!checkpoint.exists());
        drop(db);

        // The operator sets the key: verify warns until talon has run.
        let db = open(&keyed_config);
        assert!(enable_audit_key(&db, &keyed_config).unwrap());
        let (block, ok) = verify_block(&db).unwrap();
        assert!(ok);
        assert_eq!(block.get("KEY"), Some("configured"));
        assert!(block.get("WARNING").unwrap().contains("no keyed rows"));
        assert_eq!(block.get("CHECKPOINT"), Some("absent"));
        drop(db);

        let db = open(&keyed_config);
        assert_eq!(
            prepare_audit(&db, &keyed_config).unwrap(),
            AuditKeyStatus::Pending
        );
        fill(&db, 3);
        assert_eq!(db.audit_key_status().unwrap(), AuditKeyStatus::Active);
        let (block, ok) = verify_block(&db).unwrap();
        assert!(ok, "{block}");
        assert_eq!(block.get("EVENTS"), Some("6"));
        assert_eq!(block.get("KEYED_EVENTS"), Some("4"));
        assert_eq!(block.get("FIRST_KEYED_ROW"), Some("3"));
        assert_eq!(block.get("HEAD_SCHEME"), Some("hmac-sha256"));
        assert_eq!(block.get("CHECKPOINT"), Some("verified"));
        assert_eq!(block.get("CHECKPOINT_SEQ"), Some("6"));
        assert_eq!(block.get("CHECKPOINT_LAG"), Some("0"));
        assert_eq!(block.get("CHECKPOINT_ANOMALIES"), None);
        assert_eq!(block.get("HINT"), None);
        assert_eq!(block.get("WARNING"), None);
        let head = head_block(&db).unwrap();
        assert_eq!(head.get("HEAD_SEQ"), Some("6"));
        assert_eq!(head.get("HEAD_SCHEME"), Some("hmac-sha256"));
        assert_eq!(head.get("HEAD_HASH"), block.get("HEAD_HASH"));
        let rendered = format!("{block}{head}");
        assert!(!rendered.contains(KEY));
        drop(db);

        // The key disappears from .env: nothing verifies, talon does not start.
        let db = open(&unkeyed_config);
        let (block, ok) = verify_block(&db).unwrap();
        assert!(!ok);
        assert_eq!(block.get("CHAIN"), Some("unverifiable"));
        assert_eq!(block.get("FIRST_BAD_ROW"), Some("3"));
        assert!(block.get("ERROR").unwrap().contains("TALON_AUDIT_KEY"));
        let err = format!("{:#}", prepare_audit(&db, &unkeyed_config).unwrap_err());
        assert!(err.contains("refusing to start"), "{err}");
        // `talon audit head` needs no key.
        assert_eq!(head_block(&db).unwrap().get("HEAD_SEQ"), Some("6"));
        drop(db);

        // Another key.
        let other = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let other_config = TalonConfig::from_env(
            &unkeyed_config.project_root,
            EnvFile::from_str_content(&format!("TALON_AUDIT_KEY={other}\n")),
        );
        let db = open(&other_config);
        let err = format!("{:#}", prepare_audit(&db, &other_config).unwrap_err());
        assert!(err.contains("does not authenticate"), "{err}");
        assert!(!err.contains(other) && !err.contains(KEY));
        let (block, ok) = verify_block(&db).unwrap();
        assert!(!ok);
        assert_eq!(block.get("CHAIN"), Some("tampered"));
        assert_eq!(block.get("FIRST_BAD_ROW"), Some("3"));
        assert!(!format!("{block}").contains(other));
        drop(db);

        // Tail truncated behind talon's back.
        assert_eq!(delete_tail(&default_db_path(&keyed_config.store_dir)), 2);
        let db = open(&keyed_config);
        enable_audit_key(&db, &keyed_config).unwrap();
        let (block, ok) = verify_block(&db).unwrap();
        assert!(!ok);
        assert_eq!(block.get("CHAIN"), Some("truncated"));
        assert_eq!(block.get("CHECKPOINT"), Some("failed"));
        assert!(block.get("ERROR").unwrap().contains("truncated"));
        // talon still starts, and its first event records the anomaly.
        assert_eq!(
            prepare_audit(&open(&keyed_config), &keyed_config).unwrap(),
            AuditKeyStatus::Active
        );
        fill(&db, 1);
        let (block, ok) = verify_block(&db).unwrap();
        assert!(ok, "{block}");
        assert_eq!(block.get("CHECKPOINT_ANOMALIES"), Some("1"));
        let anomalies = tail_lines(&db, 10, Some("audit.checkpoint.")).unwrap();
        assert_eq!(anomalies.len(), 1);
        assert!(anomalies[0].contains("\"reason\":\"ahead\""));
    }

    /// Delete the two newest audit rows the way somebody with write access
    /// to the database file would. Returns the number of deleted rows.
    fn delete_tail(path: &std::path::Path) -> usize {
        let c = rusqlite::Connection::open(path).unwrap();
        c.execute_batch("DROP TRIGGER audit_log_no_delete;")
            .unwrap();
        c.execute(
            "DELETE FROM audit_log WHERE id > (SELECT MAX(id) - 2 FROM audit_log)",
            [],
        )
        .unwrap()
    }
}
