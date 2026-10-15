//! Router state (key/value cursors) and lane sessions.

use std::collections::HashMap;

use rusqlite::params;
use talon_core::Result;
use talon_core::time::now_iso;
use talon_core::types::SessionRow;

use crate::{Db, SqlResultExt, col};

impl Db {
    // ---- router state ----------------------------------------------------

    /// Value stored under `key` (`last_timestamp`, `last_agent_timestamp`, ...).
    pub fn get_router_state(&self, key: &str) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT value FROM router_state WHERE key = ?1")
                .db()?;
            let mut rows = stmt.query_map([key], |r| col::text(r, "value")).db()?;
            rows.next().transpose().db()
        })
    }

    /// Insert or replace the value stored under `key`.
    pub fn set_router_state(&self, key: &str, value: &str) -> Result<()> {
        self.with_conn(|conn| {
            conn.prepare_cached("INSERT OR REPLACE INTO router_state (key, value) VALUES (?1, ?2)")
                .db()?
                .execute(params![key, value])
                .db()?;
            Ok(())
        })
    }

    // ---- sessions (keyed by lane session key) ----------------------------

    /// Stored agent session id for a lane.
    pub fn get_session(&self, key: &str) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT session_id FROM sessions WHERE group_folder = ?1")
                .db()?;
            let mut rows = stmt.query_map([key], |r| col::text(r, "session_id")).db()?;
            rows.next().transpose().db()
        })
    }

    /// Store (replace) a lane's session id and the provider that produced
    /// it. Replacing resets the recorded usage, as in the TypeScript release.
    pub fn set_session(&self, key: &str, session_id: &str, provider: Option<&str>) -> Result<()> {
        self.with_conn(|conn| {
            conn.prepare_cached(
                "INSERT OR REPLACE INTO sessions (group_folder, session_id, provider)
                 VALUES (?1, ?2, ?3)",
            )
            .db()?
            .execute(params![key, session_id, provider])
            .db()?;
            Ok(())
        })
    }

    /// Provider that produced the stored session; `None` when there is no
    /// session or it predates the provider column.
    pub fn get_session_provider(&self, key: &str) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT provider FROM sessions WHERE group_folder = ?1")
                .db()?;
            let mut rows = stmt
                .query_map([key], |r| col::opt_text(r, "provider"))
                .db()?;
            Ok(rows.next().transpose().db()?.flatten())
        })
    }

    /// Record the context size of a lane's most recent turn (advisory; a
    /// no-op when the lane has no stored session).
    pub fn record_session_usage(&self, key: &str, input_tokens: u64) -> Result<()> {
        let tokens = i64::try_from(input_tokens).unwrap_or(i64::MAX);
        self.with_conn(|conn| {
            conn.prepare_cached(
                "UPDATE sessions SET input_tokens = ?1, updated_at = ?2 WHERE group_folder = ?3",
            )
            .db()?
            .execute(params![tokens, now_iso(), key])
            .db()?;
            Ok(())
        })
    }

    /// Every stored session with its last recorded context size.
    pub fn get_session_rows(&self) -> Result<Vec<SessionRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT group_folder, session_id, provider, input_tokens, updated_at
                     FROM sessions ORDER BY group_folder",
                )
                .db()?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(SessionRow {
                        group_folder: col::text(r, "group_folder")?,
                        session_id: col::text(r, "session_id")?,
                        provider: col::opt_text(r, "provider")?,
                        input_tokens: col::opt_i64(r, "input_tokens")?,
                        updated_at: col::opt_text(r, "updated_at")?,
                    })
                })
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })
    }

    /// Forget a lane's session (and its recorded usage).
    pub fn delete_session(&self, key: &str) -> Result<()> {
        self.with_conn(|conn| {
            conn.prepare_cached("DELETE FROM sessions WHERE group_folder = ?1")
                .db()?
                .execute([key])
                .db()?;
            Ok(())
        })
    }

    /// Session key -> session id for every stored session.
    pub fn get_all_sessions(&self) -> Result<HashMap<String, String>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT group_folder, session_id FROM sessions")
                .db()?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((col::text(r, "group_folder")?, col::text(r, "session_id")?))
                })
                .db()?
                .collect::<rusqlite::Result<HashMap<_, _>>>()
                .db()?;
            Ok(rows)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Db {
        Db::open_in_memory().unwrap()
    }

    #[test]
    fn router_state_round_trip_and_overwrite() {
        let db = db();
        assert_eq!(db.get_router_state("last_timestamp").unwrap(), None);
        db.set_router_state("last_timestamp", "a").unwrap();
        db.set_router_state("last_timestamp", "b").unwrap();
        assert_eq!(
            db.get_router_state("last_timestamp").unwrap().as_deref(),
            Some("b")
        );
    }

    // --- session provider (ports of db.test.ts) ---

    #[test]
    fn stores_and_returns_the_provider_alongside_the_session() {
        let db = db();
        db.set_session("grp", "sess-1", Some("vllm")).unwrap();
        assert_eq!(db.get_session("grp").unwrap().as_deref(), Some("sess-1"));
        assert_eq!(
            db.get_session_provider("grp").unwrap().as_deref(),
            Some("vllm")
        );
    }

    #[test]
    fn returns_none_provider_when_saved_without_one() {
        let db = db();
        db.set_session("grp", "sess-1", None).unwrap();
        assert_eq!(db.get_session("grp").unwrap().as_deref(), Some("sess-1"));
        assert_eq!(db.get_session_provider("grp").unwrap(), None);
    }

    #[test]
    fn overwrites_provider_on_re_save() {
        let db = db();
        db.set_session("grp", "sess-1", Some("ollama")).unwrap();
        db.set_session("grp", "sess-2", Some("vllm")).unwrap();
        assert_eq!(db.get_session("grp").unwrap().as_deref(), Some("sess-2"));
        assert_eq!(
            db.get_session_provider("grp").unwrap().as_deref(),
            Some("vllm")
        );
    }

    #[test]
    fn returns_none_for_missing_group_and_after_delete() {
        let db = db();
        assert_eq!(db.get_session_provider("nope").unwrap(), None);
        db.set_session("grp", "sess-1", Some("vllm")).unwrap();
        db.delete_session("grp").unwrap();
        assert_eq!(db.get_session("grp").unwrap(), None);
        assert_eq!(db.get_session_provider("grp").unwrap(), None);
    }

    // --- session usage (ports of db.test.ts) ---

    #[test]
    fn records_the_last_turn_context_size() {
        let db = db();
        db.set_session("copilot", "sess-1", Some("vllm")).unwrap();
        db.record_session_usage("copilot", 312_410).unwrap();
        let rows = db.get_session_rows().unwrap();
        let row = rows.iter().find(|r| r.group_folder == "copilot").unwrap();
        assert_eq!(row.input_tokens, Some(312_410));
        assert!(row.updated_at.as_deref().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn reports_null_context_size_until_a_turn_is_recorded() {
        let db = db();
        db.set_session("copilot", "sess-1", Some("vllm")).unwrap();
        let rows = db.get_session_rows().unwrap();
        assert_eq!(rows[0].input_tokens, None);
    }

    #[test]
    fn keeps_lanes_that_share_a_group_folder_on_separate_rows() {
        let db = db();
        db.set_session("copilot", "chat-session", Some("vllm"))
            .unwrap();
        db.set_session("copilot-u-42", "user-session", Some("vllm"))
            .unwrap();
        db.record_session_usage("copilot", 100).unwrap();
        db.record_session_usage("copilot-u-42", 900).unwrap();
        let rows = db.get_session_rows().unwrap();
        let tokens = |k: &str| {
            rows.iter()
                .find(|r| r.group_folder == k)
                .unwrap()
                .input_tokens
        };
        assert_eq!(tokens("copilot"), Some(100));
        assert_eq!(tokens("copilot-u-42"), Some(900));
        let all = db.get_all_sessions().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all["copilot-u-42"], "user-session");
    }

    #[test]
    fn drops_the_recorded_usage_along_with_the_session() {
        let db = db();
        db.set_session("copilot", "sess-1", Some("vllm")).unwrap();
        db.record_session_usage("copilot", 500).unwrap();
        db.delete_session("copilot").unwrap();
        assert!(
            db.get_session_rows()
                .unwrap()
                .iter()
                .all(|r| r.group_folder != "copilot")
        );
    }

    #[test]
    fn usage_is_a_no_op_for_a_missing_session() {
        let db = db();
        db.record_session_usage("nope", 100).unwrap();
        assert!(db.get_session_rows().unwrap().is_empty());
    }

    #[test]
    fn huge_token_counts_saturate() {
        let db = db();
        db.set_session("k", "s", None).unwrap();
        db.record_session_usage("k", u64::MAX).unwrap();
        assert_eq!(
            db.get_session_rows().unwrap()[0].input_tokens,
            Some(i64::MAX)
        );
    }
}
