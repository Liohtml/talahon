//! One-shot import of the pre-SQLite JSON state files (`router_state.json`,
//! `sessions.json`, `registered_groups.json` in the data directory), ported
//! from `migrateJsonState()` in `src/db.ts`. Each file that parses is renamed
//! to `<name>.migrated` before its contents are applied, so the import runs
//! at most once.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use talon_core::Result;
use talon_core::types::RegisteredGroup;

use crate::Db;

/// Largest state file that will be read.
const MAX_STATE_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// What [`Db::migrate_json_state`] imported.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct JsonMigrationReport {
    /// `router_state.json` was found and imported.
    pub router_state: bool,
    /// Sessions imported from `sessions.json`.
    pub sessions: usize,
    /// Groups imported from `registered_groups.json`.
    pub groups: usize,
    /// Groups skipped (invalid folder, folder conflict, ...).
    pub skipped_groups: usize,
}

#[derive(Debug, Deserialize)]
struct RouterStateFile {
    #[serde(default)]
    last_timestamp: Option<String>,
    #[serde(default)]
    last_agent_timestamp: Option<serde_json::Value>,
}

/// Read and parse `<data_dir>/<name>`, then rename it to `<name>.migrated`.
/// Missing, oversized, non-regular or unparseable files yield `None` (and
/// are left in place), exactly like the TypeScript helper.
fn take_file<T: DeserializeOwned>(data_dir: &Path, name: &str) -> Option<T> {
    let path = data_dir.join(name);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_STATE_FILE_BYTES {
        tracing::warn!(path = %path.display(), "ignoring legacy state file (not a regular file or too large)");
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let data = match serde_json::from_str::<T>(&text) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "ignoring unparseable legacy state file");
            return None;
        }
    };
    let mut migrated = path.clone().into_os_string();
    migrated.push(".migrated");
    if let Err(e) = std::fs::rename(&path, &migrated) {
        // Without the rename the import would repeat on every start.
        tracing::warn!(path = %path.display(), error = %e, "could not rename legacy state file; skipping import");
        return None;
    }
    Some(data)
}

impl Db {
    /// Import the legacy JSON state files from `data_dir` (see module docs).
    /// Safe to call on every start: once imported, the files are renamed.
    pub fn migrate_json_state(&self, data_dir: &Path) -> Result<JsonMigrationReport> {
        let mut report = JsonMigrationReport::default();

        if let Some(state) = take_file::<RouterStateFile>(data_dir, "router_state.json") {
            report.router_state = true;
            if let Some(ts) = state.last_timestamp.filter(|s| !s.is_empty()) {
                self.set_router_state("last_timestamp", &ts)?;
            }
            if let Some(map) = state.last_agent_timestamp.filter(|v| !v.is_null()) {
                self.set_router_state("last_agent_timestamp", &serde_json::to_string(&map)?)?;
            }
        }

        if let Some(sessions) = take_file::<BTreeMap<String, String>>(data_dir, "sessions.json") {
            for (key, session_id) in sessions {
                self.set_session(&key, &session_id, None)?;
                report.sessions += 1;
            }
        }

        if let Some(groups) =
            take_file::<BTreeMap<String, RegisteredGroup>>(data_dir, "registered_groups.json")
        {
            for (jid, group) in groups {
                match self.set_registered_group(&jid, &group) {
                    Ok(()) => report.groups += 1,
                    Err(e) => {
                        report.skipped_groups += 1;
                        tracing::warn!(%jid, folder = %group.folder, error = %e, "skipping migrated registered group");
                    }
                }
            }
        }

        if report != JsonMigrationReport::default() {
            tracing::info!(?report, "imported legacy JSON state");
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_all_three_files_once() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(
            d.join("router_state.json"),
            r#"{"last_timestamp":"2024-01-01T00:00:00.000Z","last_agent_timestamp":{"a@g.us":"2024-01-01T00:00:01.000Z"}}"#,
        )
        .unwrap();
        std::fs::write(d.join("sessions.json"), r#"{"main":"s-1","fam":"s-2"}"#).unwrap();
        std::fs::write(
            d.join("registered_groups.json"),
            r#"{
              "main@s.whatsapp.net": {"name":"Main","folder":"main","trigger":"@Andy","added_at":"2024-01-01T00:00:00.000Z","isMain":true},
              "evil@g.us": {"name":"Evil","folder":"../etc","trigger":"@Andy","added_at":"2024-01-01T00:00:00.000Z"}
            }"#,
        )
        .unwrap();

        let db = Db::open_in_memory().unwrap();
        let report = db.migrate_json_state(d).unwrap();
        assert_eq!(
            report,
            JsonMigrationReport {
                router_state: true,
                sessions: 2,
                groups: 1,
                skipped_groups: 1,
            }
        );
        assert_eq!(
            db.get_router_state("last_timestamp").unwrap().as_deref(),
            Some("2024-01-01T00:00:00.000Z")
        );
        let agent: serde_json::Value = serde_json::from_str(
            &db.get_router_state("last_agent_timestamp")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(agent["a@g.us"], "2024-01-01T00:00:01.000Z");
        assert_eq!(db.get_session("fam").unwrap().as_deref(), Some("s-2"));
        let groups = db.get_all_registered_groups().unwrap();
        assert!(groups["main@s.whatsapp.net"].is_main);
        assert!(!groups.contains_key("evil@g.us"));

        assert!(d.join("sessions.json.migrated").exists());
        assert!(!d.join("sessions.json").exists());
        // Second run is a no-op.
        assert_eq!(
            db.migrate_json_state(d).unwrap(),
            JsonMigrationReport::default()
        );
    }

    #[test]
    fn missing_or_broken_files_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join("sessions.json"), "{not json").unwrap();
        let db = Db::open_in_memory().unwrap();
        assert_eq!(
            db.migrate_json_state(d).unwrap(),
            JsonMigrationReport::default()
        );
        assert!(d.join("sessions.json").exists());
        assert!(
            db.migrate_json_state(&d.join("does-not-exist"))
                .unwrap()
                .sessions
                == 0
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let target = d.join("elsewhere.json");
        std::fs::write(&target, r#"{"main":"s-1"}"#).unwrap();
        std::os::unix::fs::symlink(&target, d.join("sessions.json")).unwrap();
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.migrate_json_state(d).unwrap().sessions, 0);
        assert!(target.exists());
    }
}
