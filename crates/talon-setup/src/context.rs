//! Shared state for setup steps: paths, configuration, platform facts and
//! the command runner.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use talon_core::config::TalonConfig;
use talon_core::env::EnvFile;
use talon_db::Db;
use tokio::io::AsyncReadExt;

use crate::platform::{self, Platform, PlatformInfo};
use crate::runner::{CommandRunner, SystemCommandRunner};

/// Relative log path reported in every status block (`LOG:`).
pub const SETUP_LOG: &str = "logs/setup.log";

/// Where a step that reads standard input gets it from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdinSource {
    /// The process's real stdin.
    Process,
    /// Fixed text (tests, or a host that already read stdin).
    Text(String),
}

/// Everything a setup step needs. Construct with [`SetupContext::detect`]
/// in the CLI, or [`SetupContext::new`] for a deterministic context.
#[derive(Clone)]
pub struct SetupContext {
    /// Talahon checkout / install directory (contains `.env`, `groups/`, ...).
    pub project_root: PathBuf,
    /// The invoking user's home directory.
    pub home_dir: PathBuf,
    /// `~/.config/talahon` (mount allowlist, sender allowlist).
    pub config_dir: PathBuf,
    /// Resolved configuration (`.env` + process env).
    pub config: TalonConfig,
    /// Host platform facts.
    pub platform: PlatformInfo,
    /// Command runner (real or scripted).
    pub runner: Arc<dyn CommandRunner>,
    /// The `talahon` binary the service should run (`<binary> run`).
    pub talon_binary: PathBuf,
    /// Source of stdin for steps that read it (`mounts`).
    pub stdin: StdinSource,
    /// `TZ` of the invoking process environment.
    pub env_tz: Option<String>,
    /// Host timezone detected from `/etc/localtime` / `/etc/timezone`.
    pub system_tz: Option<String>,
    /// Timeout for HTTP probes (vLLM).
    pub http_timeout: Duration,
    /// How long to wait after (re)starting a service before checking it.
    pub service_settle: Duration,
    /// `resolv.conf` candidates (first readable one wins) for the upstream
    /// DNS servers Docker's embedded resolver forwards to. Empty in
    /// [`SetupContext::new`] (deterministic), the host's files in
    /// [`SetupContext::detect`].
    pub resolv_conf_paths: Vec<PathBuf>,
    /// Directory for system-wide systemd units written by root steps
    /// (`egress --persist`). `/etc/systemd/system` in
    /// [`SetupContext::detect`]; a directory below the project root in
    /// [`SetupContext::new`], so a deterministic context never touches the
    /// host's units.
    pub systemd_system_dir: PathBuf,
}

impl std::fmt::Debug for SetupContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupContext")
            .field("project_root", &self.project_root)
            .field("home_dir", &self.home_dir)
            .field("config_dir", &self.config_dir)
            .field("platform", &self.platform)
            .field("talon_binary", &self.talon_binary)
            .finish_non_exhaustive()
    }
}

/// Name of the host binary.
pub const BINARY_NAME: &str = "talahon";
/// Its name up to 2.x (still installed as an alias).
pub const LEGACY_BINARY_NAME: &str = "talon";

/// The binary units and scripts should point at: `exe`, or, when setup was
/// started through the deprecated `talon` alias and `talahon` is installed
/// next to it, that `talahon`. Generated units then keep working once the
/// alias is gone.
pub fn preferred_binary(exe: PathBuf) -> PathBuf {
    if exe.file_name().and_then(|n| n.to_str()) != Some(LEGACY_BINARY_NAME) {
        return exe;
    }
    let sibling = exe.with_file_name(BINARY_NAME);
    if crate::runner::is_executable(&sibling) {
        sibling
    } else {
        exe
    }
}

/// `~/.config/talahon`, or the pre-rename `~/.config/talon` when only that
/// exists (exactly one is authoritative, see
/// [`talon_core::paths::resolve_config_dir`]).
fn default_config_dir(home: &Path) -> PathBuf {
    talon_core::paths::resolve_config_dir(home).path
}

impl SetupContext {
    /// Context for the real host: detects the platform, uses the system
    /// command runner, the current executable as the `talahon` binary and the
    /// process stdin.
    pub fn detect(project_root: &Path) -> Self {
        let home_dir = platform::home_dir();
        let mut ctx = Self::new(project_root, &home_dir, Arc::new(SystemCommandRunner));
        ctx.platform = PlatformInfo::detect();
        ctx.env_tz = std::env::var("TZ").ok().filter(|v| !v.is_empty());
        ctx.system_tz = platform::detect_system_timezone();
        // With systemd-resolved (`nameserver 127.0.0.53`) Docker forwards to
        // the upstream servers listed in the resolved-managed file.
        ctx.resolv_conf_paths = vec![
            PathBuf::from("/run/systemd/resolve/resolv.conf"),
            PathBuf::from("/etc/resolv.conf"),
        ];
        ctx.systemd_system_dir = PathBuf::from("/etc/systemd/system");
        if let Ok(exe) = std::env::current_exe() {
            ctx.talon_binary = preferred_binary(exe);
        }
        ctx
    }

    /// Deterministic context: Linux without systemd, unknown uid, no
    /// detected timezones, stdin empty, `talahon` binary assumed at
    /// `<project_root>/target/release/talahon`.
    pub fn new(project_root: &Path, home_dir: &Path, runner: Arc<dyn CommandRunner>) -> Self {
        let config = TalonConfig::from_env(project_root, EnvFile::load(project_root));
        Self {
            project_root: project_root.to_path_buf(),
            home_dir: home_dir.to_path_buf(),
            config_dir: default_config_dir(home_dir),
            config,
            platform: PlatformInfo {
                platform: Platform::Linux,
                is_wsl: false,
                is_headless: true,
                has_systemd: false,
                uid: None,
            },
            runner,
            talon_binary: project_root
                .join("target")
                .join("release")
                .join(BINARY_NAME),
            stdin: StdinSource::Text(String::new()),
            env_tz: None,
            system_tz: None,
            http_timeout: Duration::from_secs(10),
            service_settle: Duration::from_secs(3),
            resolv_conf_paths: Vec::new(),
            systemd_system_dir: project_root.join("data").join("systemd-system"),
        }
    }

    /// Re-read `.env` (after a step changed it).
    pub fn reload_config(&mut self) {
        self.config = TalonConfig::from_env(&self.project_root, EnvFile::load(&self.project_root));
    }

    /// `<project_root>/.env`
    pub fn env_path(&self) -> PathBuf {
        self.project_root.join(".env")
    }

    /// `<store>/messages.db`
    pub fn db_path(&self) -> PathBuf {
        self.config.store_dir.join("messages.db")
    }

    /// `<project_root>/logs`
    pub fn logs_dir(&self) -> PathBuf {
        self.project_root.join("logs")
    }

    /// `<config_dir>/mount-allowlist.json`
    pub fn mount_allowlist_path(&self) -> PathBuf {
        self.config_dir.join("mount-allowlist.json")
    }

    /// Read stdin (at most `max` bytes).
    ///
    /// # Errors
    /// I/O errors, or `InvalidData` when the input exceeds `max` bytes.
    pub async fn read_stdin(&self, max: usize) -> io::Result<String> {
        let text = match &self.stdin {
            StdinSource::Text(t) => t.clone(),
            StdinSource::Process => {
                let mut buf = Vec::new();
                let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
                tokio::io::stdin().take(limit).read_to_end(&mut buf).await?;
                String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            }
        };
        if text.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "input too large",
            ));
        }
        Ok(text)
    }

    /// Append a titled section to `logs/setup.log` (best effort).
    ///
    /// A root run (`sudo talahon setup egress --apply`) hands a `logs/`
    /// directory or log file it had to create over to the owner of the
    /// project directory; otherwise the later steps, run as that user, could
    /// no longer append.
    pub fn append_log(&self, title: &str, body: &str) {
        use std::io::Write;
        let dir = self.logs_dir();
        let dir_existed = dir.exists();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("setup.log");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "--- {} {title} ---\n{body}", talon_core::time::now_iso());
            #[cfg(unix)]
            if self.platform.is_root() {
                owner::hand_over_log(&self.project_root, &dir, !dir_existed, &path, &f);
            }
        }
    }

    /// Run `f` against the SQLite store on the blocking pool. A missing
    /// database file is created (with the full schema) by `Db::open`.
    ///
    /// # Errors
    /// Database errors, or a panic inside the store (reported as an error
    /// rather than aborting the step).
    pub async fn with_db<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Db) -> talon_core::Result<T> + Send + 'static,
    {
        let path = self.db_path();
        let joined = tokio::task::spawn_blocking(move || {
            let db = Db::open(&path)?;
            f(&db)
        })
        .await;
        match joined {
            Ok(result) => result.map_err(anyhow::Error::from),
            Err(e) => Err(anyhow::anyhow!("database task failed: {e}")),
        }
    }

    /// Number of registered groups, or `None` if the database does not
    /// exist yet or cannot be read.
    pub async fn registered_group_count(&self) -> Option<usize> {
        if !self.db_path().exists() {
            return None;
        }
        match self.with_db(|db| db.get_all_registered_groups()).await {
            Ok(groups) => Some(groups.len()),
            Err(e) => {
                tracing::debug!(error = %e, "could not count registered groups");
                None
            }
        }
    }
}

/// Ownership of the setup log after a root run.
#[cfg(unix)]
mod owner {
    use std::fs::{File, Metadata};
    use std::os::unix::fs::{MetadataExt, fchown, lchown};
    use std::path::Path;

    /// What matters about a file for the hand-over decision.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct Facts {
        pub regular_file: bool,
        pub uid: u32,
        pub links: u64,
    }

    impl Facts {
        fn of(meta: &Metadata) -> Self {
            Self {
                regular_file: meta.is_file(),
                uid: meta.uid(),
                links: meta.nlink(),
            }
        }
    }

    /// The `(uid, gid)` a root-owned log file is handed to, if any: only a
    /// regular, root-owned file with a single link, and only when the
    /// project directory belongs to another user.
    pub(super) fn new_owner(project_owner: (u32, u32), log: Facts) -> Option<(u32, u32)> {
        (project_owner.0 != 0 && log.regular_file && log.uid == 0 && log.links == 1)
            .then_some(project_owner)
    }

    /// Give `log` (open as `file`) and, when this run created it, `dir` to
    /// the owner of `project_root`. Best effort, and deliberately narrow:
    /// the project directory is writable by an unprivileged user, so this
    /// must not become a way to have root chown something else. The file is
    /// changed through the open handle, after checking that the path is not
    /// a symlink and still names that same inode; the directory with
    /// `lchown`, which does not follow symlinks.
    pub(super) fn hand_over_log(
        project_root: &Path,
        dir: &Path,
        dir_created: bool,
        log: &Path,
        file: &File,
    ) {
        let Ok(root) = std::fs::metadata(project_root) else {
            return;
        };
        let project_owner = (root.uid(), root.gid());
        let (Ok(open), Ok(named)) = (file.metadata(), std::fs::symlink_metadata(log)) else {
            return;
        };
        let same_file = !named.file_type().is_symlink()
            && named.dev() == open.dev()
            && named.ino() == open.ino();
        if !same_file {
            return;
        }
        let Some((uid, gid)) = new_owner(project_owner, Facts::of(&open)) else {
            return;
        };
        if let Err(e) = fchown(file, Some(uid), Some(gid)) {
            tracing::debug!(error = %e, "could not hand logs/setup.log to the project owner");
            return;
        }
        if dir_created && std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir() && m.uid() == 0) {
            let _ = lchown(dir, Some(uid), Some(gid));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::mock::MockRunner;

    #[tokio::test]
    async fn paths_and_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let mut ctx = SetupContext::new(dir.path(), &home, Arc::new(MockRunner::new()));
        assert_eq!(ctx.env_path(), dir.path().join(".env"));
        assert_eq!(ctx.db_path(), dir.path().join("store").join("messages.db"));
        assert_eq!(
            ctx.mount_allowlist_path(),
            home.join(".config/talahon/mount-allowlist.json")
        );
        ctx.stdin = StdinSource::Text("abc".into());
        assert_eq!(ctx.read_stdin(10).await.unwrap(), "abc");
        assert!(ctx.read_stdin(2).await.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn root_owned_log_goes_to_the_project_owner_only_when_safe() {
        use super::owner::{Facts, new_owner};
        let fresh = Facts {
            regular_file: true,
            uid: 0,
            links: 1,
        };
        assert_eq!(new_owner((1000, 1001), fresh), Some((1000, 1001)));
        // Project owned by root: nothing to hand over.
        assert_eq!(new_owner((0, 0), fresh), None);
        // Already someone else's file, a hard link, or not a regular file.
        assert_eq!(new_owner((1000, 1000), Facts { uid: 1000, ..fresh }), None);
        assert_eq!(new_owner((1000, 1000), Facts { links: 2, ..fresh }), None);
        assert_eq!(
            new_owner(
                (1000, 1000),
                Facts {
                    regular_file: false,
                    ..fresh
                }
            ),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn append_log_as_pretend_root_leaves_a_user_owned_log_alone() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        // The context believes it is root; the process (and so the file's
        // owner) is whoever runs the tests, hence no ownership change.
        ctx.platform.uid = Some(0);
        ctx.append_log("egress", "applied");
        ctx.append_log("egress", "applied again");
        let path = dir.path().join(SETUP_LOG);
        let log = std::fs::read_to_string(&path).unwrap();
        assert_eq!(log.matches(" egress ---").count(), 2, "{log}");
        let owner = std::fs::metadata(dir.path()).unwrap().uid();
        assert_eq!(std::fs::metadata(&path).unwrap().uid(), owner);
    }

    #[test]
    fn setup_started_through_the_old_alias_points_units_at_the_new_binary() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("talon");
        let new = dir.path().join("talahon");
        std::fs::write(&old, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Only the alias exists (e.g. a hand-made copy): keep it.
        assert_eq!(preferred_binary(old.clone()), old);
        // `talahon` installed next to it: units get the name that stays.
        std::fs::write(&new, "#!/bin/sh\n").unwrap();
        assert_eq!(preferred_binary(old.clone()), old, "not executable yet");
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(preferred_binary(old), new);
        // Any other name is taken as it is.
        assert_eq!(preferred_binary(new.clone()), new);
        let other = dir.path().join("talon-dev");
        assert_eq!(preferred_binary(other.clone()), other);
    }

    #[test]
    fn config_dir_falls_back_to_the_pre_rename_directory() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let runner = || Arc::new(crate::runner::mock::MockRunner::new());
        // Fresh install.
        let ctx = SetupContext::new(dir.path(), &home, runner());
        assert_eq!(ctx.config_dir, home.join(".config/talahon"));
        // Upgraded install: the allowlists stay where they are.
        std::fs::create_dir_all(home.join(".config/talon")).unwrap();
        let ctx = SetupContext::new(dir.path(), &home, runner());
        assert_eq!(ctx.config_dir, home.join(".config/talon"));
        assert_eq!(
            ctx.mount_allowlist_path(),
            home.join(".config/talon/mount-allowlist.json")
        );
        // Once ~/.config/talahon exists it alone is used.
        std::fs::create_dir_all(home.join(".config/talahon")).unwrap();
        let ctx = SetupContext::new(dir.path(), &home, runner());
        assert_eq!(ctx.config_dir, home.join(".config/talahon"));
    }

    #[test]
    fn append_log_writes_section() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        ctx.append_log("build", "output");
        let log = std::fs::read_to_string(dir.path().join("logs/setup.log")).unwrap();
        assert!(log.contains("build ---\noutput"));
    }

    #[tokio::test]
    async fn no_db_means_no_count() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        assert_eq!(ctx.registered_group_count().await, None);
        assert!(
            !ctx.db_path().exists(),
            "counting must not create the database"
        );
    }
}
