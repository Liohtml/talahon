//! External command execution behind a trait, so steps that drive
//! `docker`, `systemctl`, `launchctl`, ... are unit-testable with a scripted
//! runner. Commands are always executed directly (argv), never through a
//! shell, so paths and names can't inject shell syntax.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;

/// Default timeout for quick probes (`docker info`, `systemctl is-active`).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// Captured output is truncated to this many bytes (the tail is kept).
pub const MAX_CAPTURE_BYTES: usize = 256 * 1024;

/// A command to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    /// Program name (looked up on `PATH`) or path.
    pub program: String,
    /// Arguments.
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: Option<PathBuf>,
    /// Extra environment variables (added to the inherited environment).
    pub env: Vec<(String, String)>,
    /// Hard timeout; the process is killed when it expires.
    pub timeout: Duration,
}

impl CommandSpec {
    /// `program args...` with [`PROBE_TIMEOUT`].
    pub fn new<I, S>(program: &str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.to_string(),
            args: args.into_iter().map(Into::into).collect(),
            cwd: None,
            env: Vec::new(),
            timeout: PROBE_TIMEOUT,
        }
    }

    /// Set the working directory.
    #[must_use]
    pub fn cwd(mut self, dir: &Path) -> Self {
        self.cwd = Some(dir.to_path_buf());
        self
    }

    /// Add an environment variable.
    #[must_use]
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    /// Set the timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// `program arg1 arg2 ...` for logs and test matching.
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Result of running a command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit code (`None` if killed by a signal, timed out or never started).
    pub exit_code: Option<i32>,
    /// Captured stdout (lossy UTF-8, tail-truncated).
    pub stdout: String,
    /// Captured stderr (lossy UTF-8, tail-truncated).
    pub stderr: String,
    /// The timeout expired and the process was killed.
    pub timed_out: bool,
    /// The process could not be started (e.g. binary not found).
    pub spawn_error: Option<String>,
}

impl CommandOutput {
    /// Exited with status 0.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && self.spawn_error.is_none()
    }

    /// Successful output with `stdout` (tests / mocks).
    pub fn ok(stdout: &str) -> Self {
        Self {
            exit_code: Some(0),
            stdout: stdout.to_string(),
            ..Default::default()
        }
    }

    /// Failed output with exit `code` and `stderr` (tests / mocks).
    pub fn failed(code: i32, stderr: &str) -> Self {
        Self {
            exit_code: Some(code),
            stderr: stderr.to_string(),
            ..Default::default()
        }
    }

    /// Output for a program that could not be started.
    pub fn not_started(err: &str) -> Self {
        Self {
            spawn_error: Some(err.to_string()),
            ..Default::default()
        }
    }
}

/// Runs external commands.
#[async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run `spec` to completion (or timeout).
    async fn run(&self, spec: &CommandSpec) -> CommandOutput;

    /// Resolve `program` on `PATH` (no shell involved).
    fn which(&self, program: &str) -> Option<PathBuf> {
        find_in_path(program)
    }
}

/// Look up an executable on `$PATH`.
pub fn find_in_path(program: &str) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    if program.contains('/') {
        let p = PathBuf::from(program);
        return is_executable(&p).then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

/// Regular file with an execute bit.
pub fn is_executable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.is_file() && meta.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                meta.is_file()
            }
        }
        Err(_) => false,
    }
}

fn tail_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(MAX_CAPTURE_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// Runs commands with `tokio::process` (stdin closed, output captured,
/// killed on timeout).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommandRunner;

#[async_trait]
impl CommandRunner for SystemCommandRunner {
    async fn run(&self, spec: &CommandSpec) -> CommandOutput {
        let mut cmd = tokio::process::Command::new(&spec.program);
        cmd.args(&spec.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if let Some(dir) = &spec.cwd {
            cmd.current_dir(dir);
        }
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                tracing::debug!(command = %spec.display(), error = %e, "command failed to start");
                return CommandOutput::not_started(&e.to_string());
            }
        };
        match tokio::time::timeout(spec.timeout, child.wait_with_output()).await {
            Ok(Ok(out)) => CommandOutput {
                exit_code: out.status.code(),
                stdout: tail_lossy(&out.stdout),
                stderr: tail_lossy(&out.stderr),
                timed_out: false,
                spawn_error: None,
            },
            Ok(Err(e)) => CommandOutput::not_started(&e.to_string()),
            // Dropping the future drops the child, which kills it.
            Err(_) => CommandOutput {
                timed_out: true,
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
pub(crate) mod mock {
    //! Scripted runner for tests.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// Responds by longest matching command-line prefix; records calls.
    #[derive(Default)]
    pub struct MockRunner {
        responses: Mutex<Vec<(String, CommandOutput)>>,
        pub calls: Mutex<Vec<CommandSpec>>,
        pub binaries: Mutex<HashMap<String, PathBuf>>,
    }

    impl MockRunner {
        pub fn new() -> Self {
            Self::default()
        }

        /// Respond to commands whose display starts with `prefix`.
        pub fn on(&self, prefix: &str, out: CommandOutput) -> &Self {
            self.responses
                .lock()
                .unwrap()
                .push((prefix.to_string(), out));
            self
        }

        /// Pretend `name` is installed.
        pub fn install(&self, name: &str) -> &Self {
            self.binaries
                .lock()
                .unwrap()
                .insert(name.to_string(), PathBuf::from(format!("/usr/bin/{name}")));
            self
        }

        pub fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(CommandSpec::display)
                .collect()
        }

        pub fn called(&self, prefix: &str) -> bool {
            self.calls().iter().any(|c| c.starts_with(prefix))
        }
    }

    #[async_trait]
    impl CommandRunner for MockRunner {
        async fn run(&self, spec: &CommandSpec) -> CommandOutput {
            self.calls.lock().unwrap().push(spec.clone());
            let line = spec.display();
            let responses = self.responses.lock().unwrap();
            responses
                .iter()
                .filter(|(p, _)| line.starts_with(p.as_str()))
                .max_by_key(|(p, _)| p.len())
                .map(|(_, out)| out.clone())
                .unwrap_or_else(|| CommandOutput::failed(127, "not scripted"))
        }

        fn which(&self, program: &str) -> Option<PathBuf> {
            self.binaries.lock().unwrap().get(program).cloned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_real_commands() {
        let out = SystemCommandRunner
            .run(&CommandSpec::new(
                "sh",
                ["-c", "echo hi; echo err >&2; exit 3"],
            ))
            .await;
        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.stdout.trim(), "hi");
        assert_eq!(out.stderr.trim(), "err");
        assert!(!out.success());
    }

    #[tokio::test]
    async fn missing_binary_is_not_started() {
        let out = SystemCommandRunner
            .run(&CommandSpec::new(
                "this_command_does_not_exist_xyz_123",
                Vec::<String>::new(),
            ))
            .await;
        assert!(out.spawn_error.is_some());
        assert!(!out.success());
    }

    #[tokio::test]
    async fn timeout_kills() {
        let out = SystemCommandRunner
            .run(&CommandSpec::new("sleep", ["5"]).timeout(Duration::from_millis(100)))
            .await;
        assert!(out.timed_out);
        assert!(!out.success());
    }

    #[test]
    fn which_finds_sh_and_rejects_missing() {
        assert!(find_in_path("sh").is_some());
        assert!(find_in_path("this_command_does_not_exist_xyz_123").is_none());
        assert!(find_in_path("").is_none());
    }

    #[test]
    fn display_joins_argv() {
        let spec = CommandSpec::new("docker", ["image", "inspect", "x:1"]);
        assert_eq!(spec.display(), "docker image inspect x:1");
    }
}
