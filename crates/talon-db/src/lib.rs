//! # talon-db — SQLite persistence
//!
//! **Owner: agent A01.** The public API below is the contract other crates
//! (scheduler, ipc, http, host) are written against. Implement every
//! `todo!()`; you may add methods/types, but do not change or remove the
//! signatures below without coordinating.
//!
//! Requirements:
//! - Schema-compatible with `src/db.ts` of the TypeScript release so an
//!   existing `store/messages.db` opens and migrates in place (all the
//!   `ALTER TABLE ... ADD COLUMN` migrations, idempotent).
//! - WAL mode, `foreign_keys=ON`, `busy_timeout`, prepared-statement cache.
//! - `Db` is cheap to clone and `Send + Sync` (connection behind a mutex).
//! - New tables: `audit_log` (append-only, **hash-chained**: each row stores
//!   `prev_hash` and `hash = sha256(prev_hash || canonical_json(event))`,
//!   with [`Db::verify_audit_chain`]), `investigations`, `ioc_sightings`.
//! - Every query parameterized; no string-built SQL with user input.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use talon_core::types::{
    AuditEvent, ChatInfo, ChatMetadata, NewMessage, RegisteredGroup, ScheduledTask, SessionRow,
    TaskRunLog, TaskUpdate,
};
use talon_core::{Error, Result};

/// Investigation job triggered via `POST /investigate` or the alert sweep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Investigation {
    /// e.g. `copilot-inv-<alert_id>-<millis>`
    pub id: String,
    pub alert_id: String,
    pub customer_code: String,
    pub triggered_by: String,
    /// `queued` | `running` | `completed` | `failed`
    pub status: String,
    pub template: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Structured verdict JSON from the agent (see talon-intel `TriageReport`).
    pub verdict: Option<serde_json::Value>,
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
    pub customer_code: Option<String>,
    pub seen_at: String,
}

/// Thread-safe SQLite handle.
#[derive(Clone)]
pub struct Db {
    #[allow(dead_code)]
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").finish_non_exhaustive()
    }
}

#[allow(unused_variables, clippy::todo)]
impl Db {
    // ---- lifecycle -------------------------------------------------------
    /// Open (creating parent dirs) and migrate.
    pub fn open(path: &Path) -> Result<Self> {
        todo!()
    }
    /// Fresh in-memory database with the full schema (tests).
    pub fn open_in_memory() -> Result<Self> {
        todo!()
    }

    // ---- chats -----------------------------------------------------------
    pub fn store_chat_metadata(&self, meta: &ChatMetadata) -> Result<()> {
        todo!()
    }
    pub fn update_chat_name(&self, chat_jid: &str, name: &str) -> Result<()> {
        todo!()
    }
    pub fn get_all_chats(&self) -> Result<Vec<ChatInfo>> {
        todo!()
    }
    pub fn get_last_group_sync(&self) -> Result<Option<String>> {
        todo!()
    }
    pub fn set_last_group_sync(&self) -> Result<()> {
        todo!()
    }

    // ---- messages --------------------------------------------------------
    /// Insert or replace (idempotent on `(id, chat_jid)`).
    pub fn store_message(&self, msg: &NewMessage) -> Result<()> {
        todo!()
    }
    /// Messages newer than `since` across `jids`, excluding the assistant's
    /// own messages (`is_bot_message` or content prefixed `"{bot_prefix}:"`).
    /// Returns the messages (oldest first) and the new high-water timestamp.
    pub fn get_new_messages(
        &self,
        jids: &[String],
        since: &str,
        bot_prefix: &str,
    ) -> Result<(Vec<NewMessage>, String)> {
        todo!()
    }
    /// Up to `limit` most recent non-bot messages in `chat_jid` newer than
    /// `since`, returned oldest first.
    pub fn get_messages_since(
        &self,
        chat_jid: &str,
        since: &str,
        bot_prefix: &str,
        limit: usize,
    ) -> Result<Vec<NewMessage>> {
        todo!()
    }
    pub fn get_last_bot_message_timestamp(
        &self,
        chat_jid: &str,
        bot_prefix: &str,
    ) -> Result<Option<String>> {
        todo!()
    }
    /// Retention: delete messages older than `before_iso`. Returns rows removed.
    pub fn prune_messages_before(&self, before_iso: &str) -> Result<usize> {
        todo!()
    }

    // ---- scheduled tasks -------------------------------------------------
    pub fn create_task(&self, task: &ScheduledTask) -> Result<()> {
        todo!()
    }
    pub fn get_task_by_id(&self, id: &str) -> Result<Option<ScheduledTask>> {
        todo!()
    }
    pub fn get_tasks_for_group(&self, group_folder: &str) -> Result<Vec<ScheduledTask>> {
        todo!()
    }
    pub fn get_all_tasks(&self) -> Result<Vec<ScheduledTask>> {
        todo!()
    }
    pub fn update_task(&self, id: &str, update: &TaskUpdate) -> Result<()> {
        todo!()
    }
    /// Deletes the task and its run logs.
    pub fn delete_task(&self, id: &str) -> Result<()> {
        todo!()
    }
    /// Active tasks with `next_run <= now_iso`, oldest due first.
    pub fn get_due_tasks(&self, now_iso: &str) -> Result<Vec<ScheduledTask>> {
        todo!()
    }
    /// Record a finished run: sets `last_run = now`, `last_result`,
    /// `next_run`, and `status = 'completed'` when `next_run` is `None`.
    pub fn update_task_after_run(
        &self,
        id: &str,
        next_run: Option<&str>,
        last_result: &str,
    ) -> Result<()> {
        todo!()
    }
    pub fn log_task_run(&self, log: &TaskRunLog) -> Result<()> {
        todo!()
    }
    pub fn get_task_run_logs(&self, task_id: &str, limit: usize) -> Result<Vec<TaskRunLog>> {
        todo!()
    }

    // ---- router state ----------------------------------------------------
    pub fn get_router_state(&self, key: &str) -> Result<Option<String>> {
        todo!()
    }
    pub fn set_router_state(&self, key: &str, value: &str) -> Result<()> {
        todo!()
    }

    // ---- sessions (keyed by lane session key) ----------------------------
    pub fn get_session(&self, key: &str) -> Result<Option<String>> {
        todo!()
    }
    pub fn set_session(&self, key: &str, session_id: &str, provider: Option<&str>) -> Result<()> {
        todo!()
    }
    pub fn get_session_provider(&self, key: &str) -> Result<Option<String>> {
        todo!()
    }
    pub fn record_session_usage(&self, key: &str, input_tokens: u64) -> Result<()> {
        todo!()
    }
    pub fn get_session_rows(&self) -> Result<Vec<SessionRow>> {
        todo!()
    }
    pub fn delete_session(&self, key: &str) -> Result<()> {
        todo!()
    }
    pub fn get_all_sessions(&self) -> Result<HashMap<String, String>> {
        todo!()
    }

    // ---- registered groups ----------------------------------------------
    pub fn get_registered_group(&self, jid: &str) -> Result<Option<RegisteredGroup>> {
        todo!()
    }
    pub fn set_registered_group(&self, jid: &str, group: &RegisteredGroup) -> Result<()> {
        todo!()
    }
    pub fn delete_registered_group(&self, jid: &str) -> Result<bool> {
        todo!()
    }
    pub fn get_all_registered_groups(&self) -> Result<HashMap<String, RegisteredGroup>> {
        todo!()
    }

    // ---- audit log (append-only, hash-chained) ---------------------------
    pub fn record_audit(&self, event: &AuditEvent) -> Result<()> {
        todo!()
    }
    /// Most recent first; optional `kind` prefix filter (e.g. `"ipc."`).
    pub fn recent_audit(&self, limit: usize, kind_prefix: Option<&str>) -> Result<Vec<AuditEvent>> {
        todo!()
    }
    /// Recompute the hash chain. `Ok(None)` if intact, `Ok(Some(row_id))` of
    /// the first tampered row otherwise.
    pub fn verify_audit_chain(&self) -> Result<Option<i64>> {
        todo!()
    }

    // ---- investigations --------------------------------------------------
    pub fn upsert_investigation(&self, inv: &Investigation) -> Result<()> {
        todo!()
    }
    pub fn get_investigation(&self, id: &str) -> Result<Option<Investigation>> {
        todo!()
    }
    /// Most recent first.
    pub fn list_investigations(&self, limit: usize) -> Result<Vec<Investigation>> {
        todo!()
    }
    /// Latest investigation for an alert, if any (dedup of repeat triggers).
    pub fn latest_investigation_for_alert(&self, alert_id: &str) -> Result<Option<Investigation>> {
        todo!()
    }

    // ---- IOC sightings (correlation) -------------------------------------
    pub fn record_ioc_sightings(&self, sightings: &[IocSighting]) -> Result<()> {
        todo!()
    }
    /// Other sightings of the same normalized value, most recent first.
    pub fn find_ioc_sightings(&self, ioc_type: &str, value: &str, limit: usize) -> Result<Vec<IocSighting>> {
        todo!()
    }
}

#[allow(dead_code)]
fn db_err(e: rusqlite::Error) -> Error {
    Error::Db(e.to_string())
}
