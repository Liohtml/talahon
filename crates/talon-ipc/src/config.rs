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
/// Default poll interval.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(1_000);
/// Default number of audit rows one IPC namespace may produce per
/// [`DEFAULT_AUDIT_WINDOW`] before further rows are suppressed (counted
/// and summarized).
pub const DEFAULT_AUDIT_MAX_PER_WINDOW: usize = 60;
/// Default audit rate-limit window.
pub const DEFAULT_AUDIT_WINDOW: Duration = Duration::from_secs(60);
/// Default number of active + paused tasks one non-main IPC namespace may
/// own (N-3).
pub const DEFAULT_MAX_TASKS_PER_LANE: usize = 25;
/// Default cap on a task prompt from a non-main namespace (16 KiB).
pub const DEFAULT_MAX_PROMPT_BYTES: usize = 16 * 1024;
/// Default cap on a task prompt from the main group (64 KiB).
pub const DEFAULT_MAIN_MAX_PROMPT_BYTES: usize = 64 * 1024;
/// Default minimum spacing between two runs of a recurring task scheduled
/// by a non-main namespace (5 minutes).
pub const DEFAULT_MIN_SCHEDULE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Default number of executed task operations one non-main namespace may
/// perform per [`DEFAULT_TASK_OP_WINDOW`].
pub const DEFAULT_MAX_TASK_OPS_PER_WINDOW: usize = 30;
/// Default number of executed task operations the main group may perform
/// per [`DEFAULT_TASK_OP_WINDOW`].
pub const DEFAULT_MAIN_MAX_TASK_OPS_PER_WINDOW: usize = 120;
/// Default task-operation rate-limit window.
pub const DEFAULT_TASK_OP_WINDOW: Duration = Duration::from_secs(60);

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
    /// Denials and failures are always audited (subject to the rate limit).
    pub audit_allowed_messages: bool,
    /// Per-namespace audit budget: at most this many audit rows per
    /// [`audit_window`](Self::audit_window); further rows are suppressed
    /// and reported as one `ipc.audit.suppressed` summary row
    /// (`suppressed_since_last`) once the window has passed. Applied
    /// (state-changing) task operations are always audited. `0` disables
    /// the limit.
    pub audit_max_per_window: usize,
    /// Length of the audit rate-limit window.
    pub audit_window: Duration,
    /// Per-lane task quota (N-3): a **non-main** namespace may own at most
    /// this many active + paused tasks (counted through the task owner
    /// records, see [`crate::TaskStore::count_tasks_owned_by`]). Scheduling
    /// a new task — or resuming a completed one — beyond it is denied.
    /// Main is exempt. `0` disables the quota.
    pub max_tasks_per_lane: usize,
    /// Largest task prompt (UTF-8 bytes) a **non-main** namespace may
    /// schedule or set via `update_task`. `0` disables the cap.
    pub max_prompt_bytes: usize,
    /// Largest task prompt (UTF-8 bytes) the main group may schedule or set.
    /// `0` disables the cap.
    pub main_max_prompt_bytes: usize,
    /// Minimum spacing between consecutive runs of a recurring task
    /// scheduled (or rescheduled / resumed) by a **non-main** namespace:
    /// `interval` schedules below it, and `cron` expressions with two
    /// consecutive occurrences closer than it, are denied. `once` is always
    /// fine. Main is exempt (it is still bound by
    /// [`talon_core::schedule::MIN_INTERVAL_MS`]). Zero disables the check.
    pub min_schedule_interval: Duration,
    /// Per-namespace budget of *executed* task operations (schedule, pause,
    /// resume, cancel, update, `refresh_groups`, `register_group`) per
    /// [`task_op_window`](Self::task_op_window) for **non-main**
    /// namespaces. Authorized, valid requests beyond it are denied without
    /// being executed; they are not audited one by one but reported as one
    /// `ipc.task.throttled` summary row per namespace and window. Every
    /// executed operation is still audited. `0` disables the limit.
    pub max_task_ops_per_window: usize,
    /// Like [`max_task_ops_per_window`](Self::max_task_ops_per_window), for
    /// the main group. `0` disables the limit.
    pub main_max_task_ops_per_window: usize,
    /// Length of the task-operation rate-limit window. Zero disables the
    /// limit.
    pub task_op_window: Duration,
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
            audit_max_per_window: DEFAULT_AUDIT_MAX_PER_WINDOW,
            audit_window: DEFAULT_AUDIT_WINDOW,
            max_tasks_per_lane: DEFAULT_MAX_TASKS_PER_LANE,
            max_prompt_bytes: DEFAULT_MAX_PROMPT_BYTES,
            main_max_prompt_bytes: DEFAULT_MAIN_MAX_PROMPT_BYTES,
            min_schedule_interval: DEFAULT_MIN_SCHEDULE_INTERVAL,
            max_task_ops_per_window: DEFAULT_MAX_TASK_OPS_PER_WINDOW,
            main_max_task_ops_per_window: DEFAULT_MAIN_MAX_TASK_OPS_PER_WINDOW,
            task_op_window: DEFAULT_TASK_OP_WINDOW,
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

    /// Prompt cap for a main (`true`) or non-main namespace; `None` when
    /// disabled.
    pub fn prompt_limit(&self, is_main: bool) -> Option<usize> {
        let limit = if is_main {
            self.main_max_prompt_bytes
        } else {
            self.max_prompt_bytes
        };
        (limit > 0).then_some(limit)
    }

    /// Executed-task-operation budget per window for a main (`true`) or
    /// non-main namespace; `None` when disabled.
    pub fn task_op_limit(&self, is_main: bool) -> Option<usize> {
        let limit = if is_main {
            self.main_max_task_ops_per_window
        } else {
            self.max_task_ops_per_window
        };
        (limit > 0 && !self.task_op_window.is_zero()).then_some(limit)
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
        assert_eq!(c.audit_max_per_window, 60);
        assert_eq!(c.audit_window, Duration::from_secs(60));
    }

    #[test]
    fn task_quota_defaults() {
        let c = IpcWatcherConfig::new(Path::new("/srv/talon/data"), chrono_tz::UTC);
        assert_eq!(c.max_tasks_per_lane, 25);
        assert_eq!(c.max_prompt_bytes, 16 * 1024);
        assert_eq!(c.main_max_prompt_bytes, 64 * 1024);
        assert_eq!(c.min_schedule_interval, Duration::from_secs(300));
        assert_eq!(c.max_task_ops_per_window, 30);
        assert_eq!(c.main_max_task_ops_per_window, 120);
        assert_eq!(c.task_op_window, Duration::from_secs(60));
        assert_eq!(c.prompt_limit(false), Some(16 * 1024));
        assert_eq!(c.prompt_limit(true), Some(64 * 1024));
        assert_eq!(c.task_op_limit(false), Some(30));
        assert_eq!(c.task_op_limit(true), Some(120));
        // the host's constructor gets the same defaults
        let tc = TalonConfig::from_env(Path::new("/opt/talon"), EnvFile::from_str_content(""));
        let h = IpcWatcherConfig::from_talon_config(&tc);
        assert_eq!(h.max_tasks_per_lane, 25);
        assert_eq!(h.task_op_limit(false), Some(30));
    }

    #[test]
    fn zero_disables_limits() {
        let mut c = IpcWatcherConfig::new(Path::new("/d"), chrono_tz::UTC);
        c.max_prompt_bytes = 0;
        c.main_max_task_ops_per_window = 0;
        assert_eq!(c.prompt_limit(false), None);
        assert_eq!(c.task_op_limit(true), None);
        assert_eq!(c.task_op_limit(false), Some(30));
        c.task_op_window = Duration::ZERO;
        assert_eq!(c.task_op_limit(false), None);
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
