//! Registered groups.
//!
//! Base column mapping (`name`, `folder`, `trigger_pattern`, `added_at`,
//! `container_config` JSON, `requires_trigger`, `is_main`), unchanged from
//! earlier releases. Lane-only fields (`session_key`, `ipc_key`,
//! `ephemeral_session`, `trusted_session_commands`) are persisted as JSON in
//! the nullable `lane_config` column, which earlier releases ignore.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use talon_core::paths::{assert_valid_group_folder, is_valid_group_folder};
use talon_core::types::{ContainerConfig, RegisteredGroup};
use talon_core::{Error, Result};

use crate::{Db, SqlResultExt, col};

/// JSON stored in `registered_groups.lane_config`.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LaneConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipc_key: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    ephemeral_session: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    trusted_session_commands: bool,
}

impl LaneConfig {
    fn from_group(g: &RegisteredGroup) -> Self {
        Self {
            session_key: g.session_key.clone(),
            ipc_key: g.ipc_key.clone(),
            ephemeral_session: g.ephemeral_session,
            trusted_session_commands: g.trusted_session_commands,
        }
    }

    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

/// Raw `registered_groups` row before validation.
struct GroupRow {
    jid: String,
    name: String,
    folder: String,
    trigger: String,
    added_at: String,
    container_config: Option<String>,
    requires_trigger: Option<bool>,
    is_main: bool,
    lane_config: Option<String>,
}

fn group_row(row: &Row<'_>) -> rusqlite::Result<GroupRow> {
    Ok(GroupRow {
        jid: col::text(row, "jid")?,
        name: col::text(row, "name")?,
        folder: col::text(row, "folder")?,
        trigger: col::text(row, "trigger_pattern")?,
        added_at: col::text(row, "added_at")?,
        container_config: col::opt_text(row, "container_config")?.filter(|s| !s.is_empty()),
        requires_trigger: col::opt_flag(row, "requires_trigger")?,
        is_main: col::flag(row, "is_main")?,
        lane_config: col::opt_text(row, "lane_config")?.filter(|s| !s.is_empty()),
    })
}

/// Lane keys become host paths (IPC and session directories), so they must
/// pass the same validation as group folders.
fn lane_key_ok(key: Option<&str>) -> bool {
    key.is_none_or(is_valid_group_folder)
}

impl GroupRow {
    /// Validate and convert. Rows that would be unsafe or ambiguous to use
    /// (invalid folder or lane key, unparseable JSON) are rejected with a
    /// reason so callers can skip them: running a group without its stored
    /// container config could silently drop egress restrictions.
    fn into_group(self) -> std::result::Result<(String, RegisteredGroup), String> {
        if !is_valid_group_folder(&self.folder) {
            return Err(format!("invalid folder {:?}", self.folder));
        }
        let container_config: Option<ContainerConfig> = match &self.container_config {
            None => None,
            Some(raw) => Some(
                serde_json::from_str(raw).map_err(|e| format!("invalid container_config: {e}"))?,
            ),
        };
        let lane: LaneConfig = match &self.lane_config {
            None => LaneConfig::default(),
            Some(raw) => {
                serde_json::from_str(raw).map_err(|e| format!("invalid lane_config: {e}"))?
            }
        };
        if !lane_key_ok(lane.session_key.as_deref()) || !lane_key_ok(lane.ipc_key.as_deref()) {
            return Err("invalid session/ipc key in lane_config".to_string());
        }
        Ok((
            self.jid,
            RegisteredGroup {
                name: self.name,
                folder: self.folder,
                trigger: self.trigger,
                added_at: self.added_at,
                container_config,
                requires_trigger: self.requires_trigger,
                is_main: self.is_main,
                session_key: lane.session_key,
                ipc_key: lane.ipc_key,
                ephemeral_session: lane.ephemeral_session,
                trusted_session_commands: lane.trusted_session_commands,
            },
        ))
    }
}

const GROUP_COLUMNS: &str = "jid, name, folder, trigger_pattern, added_at, container_config, \
     requires_trigger, is_main, lane_config";

impl Db {
    // ---- registered groups ----------------------------------------------

    /// The group registered for `jid`. Rows with an invalid folder / lane
    /// key or unparseable JSON are treated as absent (and logged).
    pub fn get_registered_group(&self, jid: &str) -> Result<Option<RegisteredGroup>> {
        let row = self.with_conn(|conn| {
            let sql = format!("SELECT {GROUP_COLUMNS} FROM registered_groups WHERE jid = ?1");
            let mut stmt = conn.prepare_cached(&sql).db()?;
            stmt.query_row([jid], group_row).optional().db()
        })?;
        Ok(row.and_then(|r| match r.into_group() {
            Ok((_, g)) => Some(g),
            Err(reason) => {
                tracing::warn!(jid, %reason, "skipping invalid registered group");
                None
            }
        }))
    }

    /// Register (or update) the group for `jid`.
    ///
    /// The folder (and `session_key` / `ipc_key`, when set) must be valid
    /// folder names ([`Error::Security`] otherwise). Folders are unique: if
    /// another JID already owns `group.folder` this fails with
    /// [`Error::InvalidInput`] instead of silently unregistering that JID
    /// (as a plain `INSERT OR REPLACE` would). Lanes that share a folder
    /// with their base group stay in memory. An unset `requires_trigger` is stored as `1`.
    pub fn set_registered_group(&self, jid: &str, group: &RegisteredGroup) -> Result<()> {
        if jid.is_empty() {
            return Err(Error::invalid("group jid must not be empty"));
        }
        assert_valid_group_folder(&group.folder)?;
        for key in [group.session_key.as_deref(), group.ipc_key.as_deref()]
            .into_iter()
            .flatten()
        {
            assert_valid_group_folder(key)?;
        }
        let container_config = group
            .container_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let lane = LaneConfig::from_group(group);
        let lane_config = if lane.is_default() {
            None
        } else {
            Some(serde_json::to_string(&lane)?)
        };

        self.with_tx(true, |tx| {
            let owner: Option<String> = tx
                .prepare_cached("SELECT jid FROM registered_groups WHERE folder = ?1 AND jid != ?2")
                .db()?
                .query_row(params![group.folder, jid], |r| col::text(r, "jid"))
                .optional()
                .db()?;
            if let Some(owner) = owner {
                return Err(Error::invalid(format!(
                    "folder {:?} is already registered to {owner}",
                    group.folder
                )));
            }
            tx.prepare_cached(
                "INSERT INTO registered_groups (jid, name, folder, trigger_pattern, added_at,
                   container_config, requires_trigger, is_main, lane_config)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(jid) DO UPDATE SET
                   name = excluded.name,
                   folder = excluded.folder,
                   trigger_pattern = excluded.trigger_pattern,
                   added_at = excluded.added_at,
                   container_config = excluded.container_config,
                   requires_trigger = excluded.requires_trigger,
                   is_main = excluded.is_main,
                   lane_config = excluded.lane_config",
            )
            .db()?
            .execute(params![
                jid,
                group.name,
                group.folder,
                group.trigger,
                group.added_at,
                container_config,
                i64::from(group.requires_trigger.unwrap_or(true)),
                i64::from(group.is_main),
                lane_config,
            ])
            .db()?;
            Ok(())
        })
    }

    /// Unregister `jid`. Returns whether a row was removed.
    pub fn delete_registered_group(&self, jid: &str) -> Result<bool> {
        self.with_conn(|conn| {
            let n = conn
                .prepare_cached("DELETE FROM registered_groups WHERE jid = ?1")
                .db()?
                .execute([jid])
                .db()?;
            Ok(n > 0)
        })
    }

    /// Every valid registered group keyed by JID (invalid rows are skipped
    /// and logged, see [`Db::get_registered_group`]).
    pub fn get_all_registered_groups(&self) -> Result<HashMap<String, RegisteredGroup>> {
        let rows = self.with_conn(|conn| {
            let sql = format!("SELECT {GROUP_COLUMNS} FROM registered_groups");
            let mut stmt = conn.prepare_cached(&sql).db()?;
            let rows = stmt
                .query_map([], group_row)
                .db()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .db()?;
            Ok(rows)
        })?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let jid = row.jid.clone();
            match row.into_group() {
                Ok((jid, g)) => {
                    out.insert(jid, g);
                }
                Err(reason) => tracing::warn!(%jid, %reason, "skipping invalid registered group"),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use talon_core::types::{AdditionalMount, ProviderKind};

    use super::*;

    fn group(folder: &str) -> RegisteredGroup {
        RegisteredGroup {
            name: "Family Chat".into(),
            folder: folder.into(),
            trigger: "@Talon".into(),
            added_at: "2024-01-01T00:00:00.000Z".into(),
            container_config: None,
            requires_trigger: None,
            is_main: false,
            session_key: None,
            ipc_key: None,
            ephemeral_session: false,
            trusted_session_commands: false,
        }
    }

    // --- registered group isMain ---

    #[test]
    fn persists_is_main_through_round_trip() {
        let db = Db::open_in_memory().unwrap();
        db.set_registered_group(
            "main@s.whatsapp.net",
            &RegisteredGroup {
                name: "Main Chat".into(),
                is_main: true,
                ..group("whatsapp_main")
            },
        )
        .unwrap();
        let groups = db.get_all_registered_groups().unwrap();
        let g = &groups["main@s.whatsapp.net"];
        assert!(g.is_main);
        assert_eq!(g.folder, "whatsapp_main");
    }

    #[test]
    fn non_main_groups_are_not_main() {
        let db = Db::open_in_memory().unwrap();
        db.set_registered_group("group@g.us", &group("whatsapp_family-chat"))
            .unwrap();
        let groups = db.get_all_registered_groups().unwrap();
        assert!(!groups["group@g.us"].is_main);
    }

    // --- additional coverage ---

    #[test]
    fn full_round_trip_with_container_and_lane_config() {
        let db = Db::open_in_memory().unwrap();
        let g = RegisteredGroup {
            container_config: Some(ContainerConfig {
                additional_mounts: vec![AdditionalMount {
                    host_path: "~/repos".into(),
                    container_path: Some("repos".into()),
                    readonly: true,
                }],
                timeout: Some(600_000),
                provider: Some(ProviderKind::Vllm),
                env: BTreeMap::from([("TZ".to_string(), "UTC".to_string())]),
                blocked_hosts: vec!["api.anthropic.com".into()],
                memory: Some("2g".into()),
                ..Default::default()
            }),
            requires_trigger: Some(false),
            session_key: Some("copilot-investigate".into()),
            ipc_key: Some("copilot-investigate".into()),
            ephemeral_session: true,
            trusted_session_commands: true,
            ..group("copilot")
        };
        db.set_registered_group("http:copilot:investigate", &g)
            .unwrap();
        assert_eq!(
            db.get_registered_group("http:copilot:investigate")
                .unwrap()
                .unwrap(),
            g
        );
        // container_config is stored with the established (camelCase) keys.
        let raw: String = db
            .with_conn(|c| {
                c.query_row("SELECT container_config FROM registered_groups", [], |r| {
                    r.get(0)
                })
                .db()
            })
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["additionalMounts"][0]["hostPath"], "~/repos");
        assert_eq!(v["blockedHosts"][0], "api.anthropic.com");
    }

    #[test]
    fn plain_groups_store_null_lane_config_and_default_requires_trigger() {
        let db = Db::open_in_memory().unwrap();
        db.set_registered_group("g@g.us", &group("fam")).unwrap();
        let (lane, req): (Option<String>, i64) = db
            .with_conn(|c| {
                c.query_row(
                    "SELECT lane_config, requires_trigger FROM registered_groups",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .db()
            })
            .unwrap();
        assert_eq!(lane, None);
        assert_eq!(req, 1);
        let g = db.get_registered_group("g@g.us").unwrap().unwrap();
        assert_eq!(g.requires_trigger, Some(true));
        assert!(g.needs_trigger());
    }

    #[test]
    fn invalid_folders_and_lane_keys_are_rejected_on_write() {
        let db = Db::open_in_memory().unwrap();
        for bad in ["../etc", "", "global", "a/b"] {
            assert!(matches!(
                db.set_registered_group("x", &group(bad)),
                Err(Error::Security(_))
            ));
        }
        let bad_lane = RegisteredGroup {
            ipc_key: Some("../../tmp".into()),
            ..group("ok")
        };
        assert!(matches!(
            db.set_registered_group("x", &bad_lane),
            Err(Error::Security(_))
        ));
        assert!(db.get_all_registered_groups().unwrap().is_empty());
    }

    #[test]
    fn invalid_rows_are_skipped_on_read() {
        let db = Db::open_in_memory().unwrap();
        db.set_registered_group("good", &group("good")).unwrap();
        db.with_conn(|c| {
            c.execute_batch(
                "INSERT INTO registered_groups (jid, name, folder, trigger_pattern, added_at)
                   VALUES ('bad-folder', 'x', '../escape', '@A', '2024');
                 INSERT INTO registered_groups (jid, name, folder, trigger_pattern, added_at, container_config)
                   VALUES ('bad-json', 'x', 'badjson', '@A', '2024', '{not json');
                 INSERT INTO registered_groups (jid, name, folder, trigger_pattern, added_at, lane_config)
                   VALUES ('bad-lane', 'x', 'badlane', '@A', '2024', '{\"ipcKey\":\"../x\"}');",
            )
            .db()
        })
        .unwrap();
        let all = db.get_all_registered_groups().unwrap();
        assert_eq!(all.len(), 1);
        assert!(all.contains_key("good"));
        for jid in ["bad-folder", "bad-json", "bad-lane"] {
            assert_eq!(db.get_registered_group(jid).unwrap(), None, "{jid}");
        }
    }

    #[test]
    fn ts_container_config_with_legacy_provider_still_loads() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            c.execute(
                "INSERT INTO registered_groups (jid, name, folder, trigger_pattern, added_at,
                   container_config, requires_trigger, is_main)
                 VALUES ('j', 'n', 'f', '@A', '2024',
                   '{\"provider\":\"ollama\",\"ollama\":{\"baseUrl\":\"http://x\",\"model\":\"m\"},\"timeout\":5}',
                   NULL, NULL)",
                [],
            )
            .db()
        })
        .unwrap();
        let g = db.get_registered_group("j").unwrap().unwrap();
        let cc = g.container_config.unwrap();
        assert_eq!(cc.provider, Some(ProviderKind::Unsupported));
        assert_eq!(cc.timeout, Some(5));
        assert_eq!(g.requires_trigger, None);
        assert!(!g.is_main);
    }

    #[test]
    fn re_registering_same_jid_updates_in_place() {
        let db = Db::open_in_memory().unwrap();
        db.set_registered_group("j", &group("one")).unwrap();
        db.set_registered_group(
            "j",
            &RegisteredGroup {
                name: "Renamed".into(),
                ..group("two")
            },
        )
        .unwrap();
        let all = db.get_all_registered_groups().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all["j"].folder, "two");
        assert_eq!(all["j"].name, "Renamed");
    }

    #[test]
    fn folder_owned_by_another_jid_is_not_silently_replaced() {
        let db = Db::open_in_memory().unwrap();
        db.set_registered_group("a", &group("shared")).unwrap();
        assert!(matches!(
            db.set_registered_group("b", &group("shared")),
            Err(Error::InvalidInput(_))
        ));
        let all = db.get_all_registered_groups().unwrap();
        assert_eq!(all.len(), 1);
        assert!(all.contains_key("a"));
    }

    #[test]
    fn delete_registered_group_reports_removal() {
        let db = Db::open_in_memory().unwrap();
        db.set_registered_group("j", &group("f")).unwrap();
        assert!(db.delete_registered_group("j").unwrap());
        assert!(!db.delete_registered_group("j").unwrap());
        assert_eq!(db.get_registered_group("j").unwrap(), None);
    }
}
