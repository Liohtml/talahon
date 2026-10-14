//! Watcher configuration.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono_tz::Tz;
use talon_core::config::TalonConfig;

/// Default cap for a single IPC file (256 KiB).
pub const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024;
/// Default maximum JSON nesting depth. IPC payloads are flat; the deepest
/// legitimate shape (`register_group.containerConfig.additionalMounts[]`)
/// nests four levels.
pub const DEFAULT_MAX_JSON_DEPTH: usize = 16;
/// Default number of `messages/*.json` files handled per namespace per scan.
pub const DEFAULT_MAX_MESSAGES_PER_SCAN: usize = 32;
/// Default number of `tasks/*.json` files handled per namespace per scan.
pub const DEFAULT_MAX_TASKS_PER_SCAN: usize = 32;
/// Default bound on directory entries read from one IPC directory per scan.
pub const DEFAULT_MAX_DIR_ENTRIES: usize = 4096;
/// Default number of quarantine records kept in `data/ipc/errors/`.
pub const DEFAULT_MAX_ERROR_FILES: usize = 500;
/// Default number of content bytes preserved in a quarantine record.
pub const DEFAULT_MAX_ERROR_CONTENT_BYTES: usize = 32 * 1024;
/// Default timeout for a single async host callback.
pub const DEFAULT_HOST_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Default poll interval (matches the TypeScript `IPC_POLL_INTERVAL`).
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(1_000);

/// Configuration for [`crate::IpcWatcher`].
///
/// Every limit is a hard bound on work done for (potentially hostile)
/// container-written input; the defaults are deliberately conservative.
#[derive(Debug, Clone)]
pub struct IpcWatcherConfig {
    /// IPC root, normally `<data_dir>/ipc`. One sub-directory per lane
    /// (`<ipc_key>/`), plus the host-owned `errors/` quarantine directory.
    pub ipc_dir: PathBuf,
    /// Delay between scans.
    pub poll_interval: Duration,
    /// Timezone used to evaluate `cron` / `once` schedules.
    pub timezone: Tz,
    /// Files larger than this are rejected without being parsed.
    pub max_file_bytes: u64,
    /// Maximum JSON nesting depth accepted.
    pub max_json_depth: usize,
    /// Per-namespace, per-scan limit for `messages/` (excess waits for the
    /// next scan).
    pub max_messages_per_scan: usize,
    /// Per-namespace, per-scan limit for `tasks/`.
    pub max_tasks_per_scan: usize,
    /// Upper bound on directory entries read from one IPC directory per scan.
    /// Under a file flood only this many names are considered (name order is
    /// then best-effort).
    pub max_dir_entries: usize,
    /// Retention bound for the quarantine directory (oldest pruned first).
    pub max_error_files: usize,
    /// How many bytes of a rejected file are preserved in its quarantine
    /// record.
    pub max_error_content_bytes: usize,
    /// Timeout applied to every async [`crate::IpcHost`] callback so one stuck
    /// channel cannot wedge the watcher.
    pub host_call_timeout: Duration,
    /// Also audit *allowed* outbound messages (`ipc.message.allowed`).
    /// Denials and failures are always audited.
    pub audit_allowed_messages: bool,
}

impl IpcWatcherConfig {
    /// Defaults rooted at `<data_dir>/ipc`.
    pub fn new(data_dir: &Path, timezone: Tz) -> Self {
        Self {
            ipc_dir: data_dir.join("ipc"),
            poll_interval: DEFAULT_POLL_INTERVAL,
            timezone,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_json_depth: DEFAULT_MAX_JSON_DEPTH,
            max_messages_per_scan: DEFAULT_MAX_MESSAGES_PER_SCAN,
            max_tasks_per_scan: DEFAULT_MAX_TASKS_PER_SCAN,
            max_dir_entries: DEFAULT_MAX_DIR_ENTRIES,
            max_error_files: DEFAULT_MAX_ERROR_FILES,
            max_error_content_bytes: DEFAULT_MAX_ERROR_CONTENT_BYTES,
            host_call_timeout: DEFAULT_HOST_CALL_TIMEOUT,
            audit_allowed_messages: true,
        }
    }

    /// Derive from the process-wide host configuration (data dir, IPC poll
    /// interval, timezone).
    pub fn from_talon_config(cfg: &TalonConfig) -> Self {
        Self {
            poll_interval: cfg.ipc_poll_interval,
            ..Self::new(&cfg.data_dir, cfg.timezone)
        }
    }

    /// The quarantine directory, `<ipc_dir>/errors`.
    pub fn errors_dir(&self) -> PathBuf {
        self.ipc_dir.join(ERRORS_DIR_NAME)
    }
}

/// Name of the quarantine directory inside the IPC root. It is a reserved
/// group-folder name, so no lane can ever own a namespace with this name.
pub const ERRORS_DIR_NAME: &str = "errors";

#[cfg(test)]
mod tests {
    use super::*;
    use talon_core::env::EnvFile;

    #[test]
    fn defaults_are_bounded() {
        let c = IpcWatcherConfig::new(Path::new("/srv/talon/data"), chrono_tz::UTC);
        assert_eq!(c.ipc_dir, PathBuf::from("/srv/talon/data/ipc"));
        assert_eq!(c.errors_dir(), PathBuf::from("/srv/talon/data/ipc/errors"));
        assert_eq!(c.max_file_bytes, 256 * 1024);
        assert!(c.max_json_depth >= 4);
        assert!(c.max_messages_per_scan > 0 && c.max_tasks_per_scan > 0);
    }

    #[test]
    fn from_talon_config_uses_data_dir_and_tz() {
        let tc = TalonConfig::from_env(
            Path::new("/opt/talon"),
            EnvFile::from_str_content("IPC_POLL_INTERVAL=250\n"),
        );
        let c = IpcWatcherConfig::from_talon_config(&tc);
        assert_eq!(c.ipc_dir, PathBuf::from("/opt/talon/data/ipc"));
        assert_eq!(c.timezone, tc.timezone);
        assert_eq!(c.poll_interval, tc.ipc_poll_interval);
    }

    #[test]
    fn errors_dir_name_is_a_reserved_folder() {
        assert!(!talon_core::paths::is_valid_group_folder(ERRORS_DIR_NAME));
    }
}
