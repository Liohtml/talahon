//! Step `groups`.
//!
//! Talon's channels (CoPilot HTTP, Telegram, webhook, Emacs) discover chat
//! names at runtime, so no group metadata is synced up front: the sync is
//! always skipped (`REASON: runtime_discovery`) and the step only reports
//! how many group chats the store knows.
//!
//! `--list [--limit N]` prints `jid|name` lines for known group chats, most
//! recently active first (no status block).

use super::StepArgs;
use crate::context::{SETUP_LOG, SetupContext};
use crate::status::{StatusBlock, StepOutcome};

/// The sync sentinel chat row written by earlier releases.
const GROUP_SYNC_SENTINEL: &str = "__group_sync__";

/// Default and maximum `--limit`.
const DEFAULT_LIMIT: usize = 30;
const MAX_LIMIT: usize = 1000;

/// Keep `jid|name` lines parseable: no separators or control characters.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() || c == '|' { ' ' } else { c })
        .collect()
}

/// Run the step.
///
/// # Errors
/// Database failures while listing.
pub async fn run(args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    if args.flag("--list") {
        let limit = args
            .value("--limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_LIMIT)
            .clamp(1, MAX_LIMIT);
        return list_groups(ctx, limit).await;
    }

    let groups_in_db = if ctx.db_path().exists() {
        ctx.with_db(|db| db.get_all_chats())
            .await
            .map(|chats| {
                chats
                    .iter()
                    .filter(|c| c.is_group && c.jid != GROUP_SYNC_SENTINEL)
                    .count()
            })
            .unwrap_or(0)
    } else {
        0
    };
    tracing::info!("Group metadata is discovered at runtime — skipping upfront sync");
    Ok(StepOutcome::ok(
        StatusBlock::new("SYNC_GROUPS")
            .field("BUILD", "skipped")
            .field("SYNC", "skipped")
            .field("GROUPS_IN_DB", groups_in_db)
            .field("REASON", "runtime_discovery")
            .field("STATUS", "success")
            .field("LOG", SETUP_LOG),
    ))
}

async fn list_groups(ctx: &SetupContext, limit: usize) -> anyhow::Result<StepOutcome> {
    if !ctx.db_path().exists() {
        return Ok(StepOutcome::lines(
            vec!["ERROR: database not found".into()],
            1,
        ));
    }
    let chats = ctx.with_db(|db| db.get_all_chats()).await?;
    let mut groups: Vec<_> = chats
        .into_iter()
        .filter(|c| {
            c.is_group && c.jid != GROUP_SYNC_SENTINEL && c.name != c.jid && !c.name.is_empty()
        })
        .collect();
    groups.sort_by(|a, b| b.last_message_time.cmp(&a.last_message_time));
    let lines = groups
        .iter()
        .take(limit)
        .map(|c| format!("{}|{}", clean(&c.jid), clean(&c.name)))
        .collect();
    Ok(StepOutcome::lines(lines, 0))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use talon_core::types::ChatMetadata;
    use talon_db::Db;

    use super::*;
    use crate::runner::mock::MockRunner;

    #[tokio::test]
    async fn list_without_database_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        let out = run(&StepArgs::new(["--list"]), &ctx).await.unwrap();
        assert_eq!(out.exit_code, 1);
        assert_eq!(out.lines, vec!["ERROR: database not found"]);
        assert!(!ctx.db_path().exists());
    }

    #[tokio::test]
    async fn sync_is_skipped_without_database() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("SYNC"), Some("skipped"));
        assert_eq!(b.get("GROUPS_IN_DB"), Some("0"));
        assert_eq!(b.status(), Some("success"));
    }

    #[test]
    fn clean_strips_separators() {
        assert_eq!(clean("a|b\nc"), "a b c");
    }

    /// Uses the real talon-db.
    #[tokio::test]
    async fn lists_group_chats_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        let db = Db::open(&ctx.db_path()).unwrap();
        let meta = |jid: &str, ts: &str, name: Option<&str>, is_group: bool| ChatMetadata {
            chat_jid: jid.into(),
            timestamp: ts.into(),
            name: name.map(str::to_string),
            channel: Some("telegram".into()),
            is_group: Some(is_group),
        };
        db.store_chat_metadata(&meta(
            "tg:-1",
            "2024-01-01T00:00:01.000Z",
            Some("Old|SOC"),
            true,
        ))
        .unwrap();
        db.store_chat_metadata(&meta(
            "tg:-2",
            "2024-01-01T00:00:05.000Z",
            Some("New"),
            true,
        ))
        .unwrap();
        db.store_chat_metadata(&meta("tg:3", "2024-01-01T00:00:09.000Z", Some("DM"), false))
            .unwrap();
        drop(db);
        let out = run(&StepArgs::new(["--list", "--limit", "5"]), &ctx)
            .await
            .unwrap();
        assert_eq!(out.lines, vec!["tg:-2|New", "tg:-1|Old SOC"]);
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        assert_eq!(out.block.unwrap().get("GROUPS_IN_DB"), Some("2"));
    }
}
