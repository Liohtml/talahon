//! Host -> container IPC writes into `<data_dir>/ipc/<ipc_key>/input/`.
//!
//! The `input/` directory is mounted read-write into the agent container, so
//! its contents are attacker-controlled if the container is compromised.
//! Every write therefore:
//! - resolves the lane directory through [`talon_core::paths::group_ipc_path`]
//!   (validated key, no traversal),
//! - refuses an `input` path that is a symlink or not a directory,
//! - creates a fresh temp file with `create_new` (never follows or truncates
//!   a planted file/symlink), then `rename`s it into place — the rename
//!   replaces a planted symlink at the destination instead of writing
//!   through it. This matters for the fixed-name `_close` sentinel.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use talon_core::paths::group_ipc_path;
use talon_core::protocol::{IPC_CLOSE_SENTINEL, IpcInput, ipc_file_name};
use talon_core::{Error, Result};

/// `<data_dir>/ipc/<ipc_key>/input` (validated, not created).
pub fn input_dir(data_dir: &Path, ipc_key: &str) -> Result<PathBuf> {
    Ok(group_ipc_path(data_dir, ipc_key)?.join("input"))
}

/// Write a follow-up [`IpcInput::Message`] for the lane's running container.
/// Returns the final path of the written file.
pub fn write_message(data_dir: &Path, ipc_key: &str, text: &str) -> Result<PathBuf> {
    let body = serde_json::to_vec(&IpcInput::Message {
        text: text.to_string(),
    })?;
    let dir = prepare_input_dir(data_dir, ipc_key)?;
    let name = ipc_file_name();
    let path = dir.join(&name);
    write_atomic(&dir, &path, &format!("{name}.tmp"), &body)?;
    Ok(path)
}

/// Write the `_close` sentinel that tells the container to finish its
/// current turn and exit. Returns the sentinel path.
pub fn write_close_sentinel(data_dir: &Path, ipc_key: &str) -> Result<PathBuf> {
    let dir = prepare_input_dir(data_dir, ipc_key)?;
    let path = dir.join(IPC_CLOSE_SENTINEL);
    // The temp name must not end in `.json` (the agent would treat it as a
    // message) and must be unpredictable.
    let tmp = format!("{IPC_CLOSE_SENTINEL}.{}.tmp", ipc_file_name());
    write_atomic(&dir, &path, &tmp, b"")?;
    Ok(path)
}

/// Ensure `<ipc>/<key>/input` exists as a real directory (not a symlink).
fn prepare_input_dir(data_dir: &Path, ipc_key: &str) -> Result<PathBuf> {
    let lane_dir = group_ipc_path(data_dir, ipc_key)?;
    fs::create_dir_all(&lane_dir)?;
    ensure_real_dir(&lane_dir)?;
    let input = lane_dir.join("input");
    match fs::symlink_metadata(&input) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => match fs::create_dir(&input) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        },
        Err(e) => return Err(e.into()),
    }
    ensure_real_dir(&input)?;
    Ok(input)
}

fn ensure_real_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::security(format!(
            "IPC path {} is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

/// `create_new` temp file in `dir`, then rename onto `dest`.
fn write_atomic(dir: &Path, dest: &Path, tmp_name: &str, body: &[u8]) -> Result<()> {
    let tmp = dir.join(tmp_name);
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(body)?;
        file.flush()?;
        drop(file);
        fs::rename(&tmp, dest)
    })();
    if let Err(e) = result {
        // Only remove what we may have created; never follow a link.
        if fs::symlink_metadata(&tmp).is_ok_and(|m| m.is_file()) {
            let _ = fs::remove_file(&tmp);
        }
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn message_is_written_atomically_with_protocol_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_message(tmp.path(), "lane-1", "hello \"world\"").unwrap();
        assert_eq!(path.parent().unwrap(), tmp.path().join("ipc/lane-1/input"));
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with(".json"));
        let parsed: IpcInput = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            parsed,
            IpcInput::Message {
                text: "hello \"world\"".into()
            }
        );
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["type"], "message");
        // No temp files left behind.
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn close_sentinel_is_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_close_sentinel(tmp.path(), "g").unwrap();
        assert_eq!(path, tmp.path().join("ipc/g/input/_close"));
        assert_eq!(fs::read(&path).unwrap().len(), 0);
        // Idempotent.
        write_close_sentinel(tmp.path(), "g").unwrap();
        let entries = fs::read_dir(tmp.path().join("ipc/g/input"))
            .unwrap()
            .count();
        assert_eq!(entries, 1);
    }

    #[test]
    fn invalid_ipc_keys_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        for key in ["../escape", "a/b", "", "global", ".hidden"] {
            assert!(write_message(tmp.path(), key, "x").is_err(), "{key}");
            assert!(write_close_sentinel(tmp.path(), key).is_err(), "{key}");
        }
        assert!(!tmp.path().join("escape").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_input_dir_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let lane = tmp.path().join("ipc/g");
        fs::create_dir_all(&lane).unwrap();
        std::os::unix::fs::symlink(&outside, lane.join("input")).unwrap();
        let err = write_message(tmp.path(), "g", "x").unwrap_err();
        assert!(matches!(err, Error::Security(_)), "{err:?}");
        assert!(write_close_sentinel(tmp.path(), "g").is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn planted_close_symlink_is_replaced_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim.txt");
        fs::write(&victim, "precious").unwrap();
        let input = tmp.path().join("ipc/g/input");
        fs::create_dir_all(&input).unwrap();
        std::os::unix::fs::symlink(&victim, input.join("_close")).unwrap();

        write_close_sentinel(tmp.path(), "g").unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        let meta = fs::symlink_metadata(input.join("_close")).unwrap();
        assert!(meta.is_file() && !meta.file_type().is_symlink());
    }

    #[test]
    fn input_dir_that_is_a_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let lane = tmp.path().join("ipc/g");
        fs::create_dir_all(&lane).unwrap();
        fs::write(lane.join("input"), "not a dir").unwrap();
        assert!(write_message(tmp.path(), "g", "x").is_err());
    }
}
