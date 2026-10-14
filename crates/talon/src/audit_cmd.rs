//! `talon audit verify` and `talon audit tail`.

use std::io::Write;

use anyhow::anyhow;
use talon_core::config::TalonConfig;
use talon_db::{Db, DbOptions, default_db_path};
use talon_setup::StatusBlock;

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

/// Status block for an audit-chain verification of `db`.
///
/// # Errors
/// Database read failures.
pub fn verify_block(db: &Db) -> anyhow::Result<(StatusBlock, bool)> {
    let count = db.audit_count().map_err(|e| anyhow!("{e}"))?;
    let tampered = db.verify_audit_chain().map_err(|e| anyhow!("{e}"))?;
    let mut block = StatusBlock::new("AUDIT_VERIFY").field("EVENTS", count);
    let ok = match tampered {
        None => {
            match db.audit_chain_head().map_err(|e| anyhow!("{e}"))? {
                Some((id, hash)) => {
                    block.set("HEAD_ID", id);
                    block.set("HEAD_HASH", hash);
                }
                None => block.set("HEAD_ID", "none"),
            }
            block.set("CHAIN", "intact");
            block.set("STATUS", "success");
            true
        }
        Some(row) => {
            block.set("CHAIN", "tampered");
            block.set("FIRST_BAD_ROW", row);
            block.set("STATUS", "failed");
            false
        }
    };
    Ok((block, ok))
}

/// `talon audit verify`: exit code 0 when the chain is intact, 1 otherwise.
///
/// # Errors
/// The database cannot be opened or read.
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
    let (block, ok) = verify_block(&db)?;
    println!("{block}");
    Ok(if ok { 0 } else { 1 })
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

    use super::*;

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

        let all = tail_lines(&db, 10, None).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all[0].contains("ipc.task.allowed"), "oldest first: {all:?}");
        let ipc = tail_lines(&db, 10, Some("ipc.")).unwrap();
        assert_eq!(ipc.len(), 2);
        let last = tail_lines(&db, 1, None).unwrap();
        assert!(last[0].contains("ipc.message.denied"));
    }
}
