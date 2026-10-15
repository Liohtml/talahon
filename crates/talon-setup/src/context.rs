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
    /// Talon checkout / install directory (contains `.env`, `groups/`, ...).
    pub project_root: PathBuf,
    /// The invoking user's home directory.
    pub home_dir: PathBuf,
    /// `~/.config/talon` (mount allowlist, sender allowlist).
    pub config_dir: PathBuf,
    /// Resolved configuration (`.env` + process env).
    pub config: TalonConfig,
    /// Host platform facts.
    pub platform: PlatformInfo,
    /// Command runner (real or scripted).
    pub runner: Arc<dyn CommandRunner>,
    /// The `talon` binary the service should run (`<binary> run`).
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

fn default_config_dir(home: &Path) -> PathBuf {
    home.join(".config").join("talon")
}

impl SetupContext {
    /// Context for the real host: detects the platform, uses the system
    /// command runner, the current executable as the `talon` binary and the
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
        if let Ok(exe) = std::env::current_exe() {
            ctx.talon_binary = exe;
        }
        ctx
    }

    /// Deterministic context: Linux without systemd, unknown uid, no
    /// detected timezones, stdin empty, `talon` binary assumed at
    /// `<project_root>/target/release/talon`.
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
            talon_binary: project_root.join("target").join("release").join("talon"),
            stdin: StdinSource::Text(String::new()),
            env_tz: None,
            system_tz: None,
            http_timeout: Duration::from_secs(10),
            service_settle: Duration::from_secs(3),
            resolv_conf_paths: Vec::new(),
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
    pub fn append_log(&self, title: &str, body: &str) {
        use std::io::Write;
        let dir = self.logs_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("setup.log");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "--- {} {title} ---\n{body}", talon_core::time::now_iso());
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
            home.join(".config/talon/mount-allowlist.json")
        );
        ctx.stdin = StdinSource::Text("abc".into());
        assert_eq!(ctx.read_stdin(10).await.unwrap(), "abc");
        assert!(ctx.read_stdin(2).await.is_err());
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
