//! IPC snapshot writers (port of `writeTasksSnapshot` /
//! `writeGroupsSnapshot` in `src/container-runner.ts`).
//!
//! Snapshots live in the lane's IPC directory, which the agent can write to.
//! They are therefore written atomically through a freshly created
//! (`O_CREAT|O_EXCL`, never following symlinks) temporary file that is then
//! renamed over the target — a symlink the agent planted at the target or a
//! predictable temp name can never redirect the host's write.
//!
//! Visibility: the main group sees every task and every available group;
//! other groups see only their own tasks and no groups. Lanes that share a
//! group folder (CoPilot analysts, webhook lanes) use
//! [`write_lane_tasks_snapshot`], which filters by the lane's chat JIDs
//! instead of the folder (MYTH-03).

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use talon_core::paths::{assert_valid_group_folder, group_ipc_path};
use talon_core::protocol::container_paths;
use talon_core::types::{AvailableGroup, ScheduledTask, TaskSnapshot};
use talon_core::{Error, Result};

/// File name of the tasks snapshot.
pub const TASKS_SNAPSHOT: &str = "current_tasks.json";
/// File name of the groups snapshot.
pub const GROUPS_SNAPSHOT: &str = "available_groups.json";

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically replace `dir/file_name` with `contents` (mode 0644 so the
/// unprivileged agent can read it).
pub fn write_atomic(dir: &Path, file_name: &str, contents: &[u8]) -> Result<PathBuf> {
    if file_name.is_empty() || file_name.contains('/') || file_name.starts_with('.') {
        return Err(Error::invalid(format!(
            "invalid snapshot file name {file_name:?}"
        )));
    }
    let target = dir.join(file_name);
    let mut attempts = 0;
    let (tmp, mut file) = loop {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let tmp = dir.join(format!(
            ".{file_name}.{}.{nanos:x}.{n}.tmp",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)
        {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempts < 16 => {
                attempts += 1;
            }
            Err(e) => return Err(e.into()),
        }
    };
    let written = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&tmp, &target));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(target)
}

/// `data/ipc/<key>` as a real directory: `data/ipc` is operator-controlled
/// (created, symlinks followed); the lane directory itself must not be a
/// symlink (a legacy alias would send one lane's snapshot into another
/// lane's namespace) and is created without following links.
fn lane_ipc_dir(data_dir: &Path, key: &str) -> Result<PathBuf> {
    let dir = group_ipc_path(data_dir, key)?;
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    let check = |meta: fs::Metadata| -> Result<PathBuf> {
        if meta.file_type().is_dir() {
            Ok(dir.clone())
        } else {
            Err(Error::security(format!(
                "{} is not a real directory; refusing to write a snapshot",
                dir.display()
            )))
        }
    };
    match fs::symlink_metadata(&dir) {
        Ok(meta) => check(meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&dir) {
            Ok(()) => Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                check(fs::symlink_metadata(&dir)?)
            }
            Err(e) => Err(e.into()),
        },
        Err(e) => Err(e.into()),
    }
}

fn ipc_dir(data_dir: &Path, group_folder: &str, ipc_key: Option<&str>) -> Result<PathBuf> {
    assert_valid_group_folder(group_folder)?;
    lane_ipc_dir(data_dir, ipc_key.unwrap_or(group_folder))
}

fn pretty<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(value)?)
}

/// Write `current_tasks.json` into the lane's IPC directory
/// (`data/ipc/<ipc_key or folder>/`). Main sees all tasks; other groups only
/// tasks whose `groupFolder` is their own (ownership is a property of the
/// group, not of the lane reading the snapshot).
pub fn write_tasks_snapshot(
    data_dir: &Path,
    group_folder: &str,
    is_main: bool,
    tasks: &[TaskSnapshot],
    ipc_key: Option<&str>,
) -> Result<PathBuf> {
    let dir = ipc_dir(data_dir, group_folder, ipc_key)?;
    let visible: Vec<&TaskSnapshot> = tasks
        .iter()
        .filter(|t| is_main || t.group_folder == group_folder)
        .collect();
    write_atomic(&dir, TASKS_SNAPSHOT, &pretty(&visible)?)
}

/// Write `current_tasks.json` into `data/ipc/<ipc_key>/` for one lane.
/// Main sees every task; any other lane only tasks whose `chat_jid` is one
/// of `lane_jids` (so lanes sharing a group folder never see each other's
/// tasks). Same atomic, symlink-safe write as [`write_tasks_snapshot`].
pub fn write_lane_tasks_snapshot(
    data_dir: &Path,
    ipc_key: &str,
    is_main: bool,
    lane_jids: &[String],
    tasks: &[ScheduledTask],
) -> Result<PathBuf> {
    let dir = lane_ipc_dir(data_dir, ipc_key)?;
    let visible: Vec<TaskSnapshot> = tasks
        .iter()
        .filter(|t| is_main || lane_jids.contains(&t.chat_jid))
        .map(TaskSnapshot::from)
        .collect();
    write_atomic(&dir, TASKS_SNAPSHOT, &pretty(&visible)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupsSnapshot<'a> {
    groups: Vec<&'a AvailableGroup>,
    last_sync: String,
}

/// Write `available_groups.json` (`{"groups": [...], "lastSync": iso}`).
/// Only the main group sees the groups (it is the only one that can
/// activate them); everyone else gets an empty list.
pub fn write_groups_snapshot(
    data_dir: &Path,
    group_folder: &str,
    is_main: bool,
    groups: &[AvailableGroup],
    ipc_key: Option<&str>,
) -> Result<PathBuf> {
    let dir = ipc_dir(data_dir, group_folder, ipc_key)?;
    let snapshot = GroupsSnapshot {
        groups: if is_main {
            groups.iter().collect()
        } else {
            Vec::new()
        },
        last_sync: talon_core::time::now_iso(),
    };
    write_atomic(&dir, GROUPS_SNAPSHOT, &pretty(&snapshot)?)
}

/// Container-side paths of the snapshots (for documentation / tools).
pub fn container_snapshot_paths() -> (&'static str, &'static str) {
    (
        container_paths::CURRENT_TASKS,
        container_paths::AVAILABLE_GROUPS,
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use talon_core::types::{ContextMode, ScheduleType, TaskStatus};

    use super::*;

    fn task(id: &str, folder: &str) -> TaskSnapshot {
        TaskSnapshot {
            id: id.into(),
            group_folder: folder.into(),
            prompt: "p".into(),
            script: None,
            schedule_type: ScheduleType::Cron,
            schedule_value: "0 * * * *".into(),
            status: TaskStatus::Active,
            next_run: None,
        }
    }

    fn scheduled(id: &str, folder: &str, jid: &str) -> ScheduledTask {
        ScheduledTask {
            id: id.into(),
            group_folder: folder.into(),
            chat_jid: jid.into(),
            prompt: format!("prompt {id}"),
            script: None,
            schedule_type: ScheduleType::Interval,
            schedule_value: "60000".into(),
            context_mode: ContextMode::default(),
            next_run: None,
            last_run: None,
            last_result: None,
            status: TaskStatus::Active,
            created_at: "2026-01-01T00:00:00.000Z".into(),
        }
    }

    fn ids(p: &Path) -> Vec<String> {
        read_json(p)
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["id"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn lane_snapshot_filters_by_chat_jid() {
        let tmp = tempfile::tempdir().unwrap();
        // Two analysts share the `copilot` folder; a third task is main's.
        let tasks = vec![
            scheduled("a1", "copilot", "http:copilot:alice"),
            scheduled("b1", "copilot", "http:copilot:bob"),
            scheduled("a2", "copilot", "http:copilot:alice"),
            scheduled("m1", "main", "main@g.us"),
        ];
        let alice = vec!["http:copilot:alice".to_string()];
        let p = write_lane_tasks_snapshot(tmp.path(), "copilot-u-alice", false, &alice, &tasks)
            .unwrap();
        assert_eq!(p, tmp.path().join("ipc/copilot-u-alice/current_tasks.json"));
        assert_eq!(ids(&p), vec!["a1", "a2"]);
        // TS snapshot shape (no chat JIDs of other lanes leak).
        let v = read_json(&p);
        assert_eq!(v[0]["groupFolder"], "copilot");
        assert!(v[0].get("chat_jid").is_none() && v[0].get("chatJid").is_none());

        // A lane with several JIDs sees all of them.
        let both = vec!["http:copilot:bob".to_string(), "main@g.us".to_string()];
        let p = write_lane_tasks_snapshot(tmp.path(), "multi", false, &both, &tasks).unwrap();
        assert_eq!(ids(&p), vec!["b1", "m1"]);

        // No JIDs: nothing. Main: everything, whatever its JIDs.
        let p = write_lane_tasks_snapshot(tmp.path(), "empty", false, &[], &tasks).unwrap();
        assert!(ids(&p).is_empty());
        let p = write_lane_tasks_snapshot(tmp.path(), "main", true, &[], &tasks).unwrap();
        assert_eq!(ids(&p), vec!["a1", "b1", "a2", "m1"]);
    }

    #[test]
    fn lane_snapshot_is_atomic_and_symlink_safe() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim.txt");
        fs::write(&victim, "precious").unwrap();
        let dir = tmp.path().join("ipc/lane-1");
        fs::create_dir_all(&dir).unwrap();
        symlink(&victim, dir.join(TASKS_SNAPSHOT)).unwrap();
        let jids = vec!["x@g.us".to_string()];
        let tasks = vec![scheduled("t", "team", "x@g.us")];
        let p = write_lane_tasks_snapshot(tmp.path(), "lane-1", false, &jids, &tasks).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert!(fs::symlink_metadata(&p).unwrap().file_type().is_file());
        assert_eq!(ids(&p), vec!["t"]);
        let leftovers = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
        // Invalid lane keys never escape data/ipc.
        for bad in ["../x", "global", "", "a/b"] {
            assert!(write_lane_tasks_snapshot(tmp.path(), bad, false, &jids, &tasks).is_err());
        }
        // A symlinked lane directory (alias of another lane) is refused by
        // both writers; nothing is written into the target.
        let main_dir = tmp.path().join("ipc/main");
        fs::create_dir_all(&main_dir).unwrap();
        symlink(&main_dir, tmp.path().join("ipc/alias")).unwrap();
        assert!(write_lane_tasks_snapshot(tmp.path(), "alias", true, &[], &tasks).is_err());
        assert!(write_tasks_snapshot(tmp.path(), "alias", true, &[], None).is_err());
        assert!(write_groups_snapshot(tmp.path(), "team", true, &[], Some("alias")).is_err());
        assert_eq!(fs::read_dir(&main_dir).unwrap().count(), 0);
    }

    fn group(jid: &str) -> AvailableGroup {
        AvailableGroup {
            jid: jid.into(),
            name: jid.into(),
            last_activity: "2026-01-01T00:00:00.000Z".into(),
            is_registered: false,
        }
    }

    fn read_json(p: &Path) -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn main_sees_all_tasks_others_only_own() {
        let tmp = tempfile::tempdir().unwrap();
        let tasks = vec![task("a", "main"), task("b", "team"), task("c", "other")];

        let p = write_tasks_snapshot(tmp.path(), "main", true, &tasks, None).unwrap();
        assert_eq!(p, tmp.path().join("ipc/main/current_tasks.json"));
        assert_eq!(read_json(&p).as_array().unwrap().len(), 3);

        let p = write_tasks_snapshot(tmp.path(), "team", false, &tasks, None).unwrap();
        let v = read_json(&p);
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["id"], "b");
        assert_eq!(v[0]["groupFolder"], "team");
        assert_eq!(v[0]["schedule_type"], "cron");
        // Pretty-printed like the TS version.
        assert!(fs::read_to_string(&p).unwrap().contains("\n  {"));
    }

    #[test]
    fn lanes_write_into_their_own_ipc_key() {
        let tmp = tempfile::tempdir().unwrap();
        let tasks = vec![task("b", "copilot"), task("c", "other")];
        let p = write_tasks_snapshot(tmp.path(), "copilot", false, &tasks, Some("copilot-u-1"))
            .unwrap();
        assert_eq!(p, tmp.path().join("ipc/copilot-u-1/current_tasks.json"));
        // Filter still keys on the group folder.
        assert_eq!(read_json(&p).as_array().unwrap().len(), 1);
        assert!(write_tasks_snapshot(tmp.path(), "copilot", false, &tasks, Some("../x")).is_err());
        assert!(write_tasks_snapshot(tmp.path(), "../x", false, &tasks, None).is_err());
    }

    #[test]
    fn groups_snapshot_visibility() {
        let tmp = tempfile::tempdir().unwrap();
        let groups = vec![group("a@g"), group("b@g")];
        let p = write_groups_snapshot(tmp.path(), "main", true, &groups, None).unwrap();
        let v = read_json(&p);
        assert_eq!(v["groups"].as_array().unwrap().len(), 2);
        assert_eq!(v["groups"][0]["lastActivity"], "2026-01-01T00:00:00.000Z");
        assert_eq!(v["groups"][0]["isRegistered"], false);
        assert_eq!(v["lastSync"].as_str().unwrap().len(), 24);

        let p = write_groups_snapshot(tmp.path(), "team", false, &groups, None).unwrap();
        assert!(read_json(&p)["groups"].as_array().unwrap().is_empty());
    }

    #[test]
    fn writes_are_atomic_and_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_tasks_snapshot(tmp.path(), "team", false, &[], None).unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o044, 0o044, "agent must be able to read it");
        let leftovers: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn planted_symlink_is_replaced_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim.txt");
        fs::write(&victim, "precious").unwrap();
        let dir = tmp.path().join("ipc/team");
        fs::create_dir_all(&dir).unwrap();
        symlink(&victim, dir.join(TASKS_SNAPSHOT)).unwrap();

        write_tasks_snapshot(tmp.path(), "team", false, &[task("t", "team")], None).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        let meta = fs::symlink_metadata(dir.join(TASKS_SNAPSHOT)).unwrap();
        assert!(meta.file_type().is_file());
    }

    #[test]
    fn directory_at_target_is_an_error_without_leftovers() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ipc/team");
        fs::create_dir_all(dir.join(GROUPS_SNAPSHOT).join("x")).unwrap();
        assert!(write_groups_snapshot(tmp.path(), "team", false, &[], None).is_err());
        let tmp_files = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(tmp_files, 0);
    }

    #[test]
    fn write_atomic_rejects_bad_names() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(write_atomic(tmp.path(), "../x", b"").is_err());
        assert!(write_atomic(tmp.path(), "", b"").is_err());
        assert!(write_atomic(tmp.path(), ".hidden", b"").is_err());
        assert_eq!(
            container_snapshot_paths(),
            (
                "/workspace/ipc/current_tasks.json",
                "/workspace/ipc/available_groups.json"
            )
        );
    }
}
