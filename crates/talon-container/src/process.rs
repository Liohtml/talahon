//! Injectable process-spawn layer.
//!
//! [`crate::runner::ContainerRunner`] never calls `tokio::process` directly:
//! it asks a [`ProcessSpawner`] for a [`SpawnedProcess`] (three pipes plus a
//! [`ProcessControl`]). Production uses [`TokioProcessSpawner`]; tests use
//! in-memory fakes or `bash -c` scripts that emit frames, so the full run
//! loop (timeouts, stop/kill escalation, parsing) is testable without a
//! container daemon.

use std::io;
use std::pin::Pin;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// Program + argv (no shell involved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessCommand {
    /// Executable (runtime binary).
    pub program: String,
    /// Arguments.
    pub args: Vec<String>,
}

/// Boxed async writer (child stdin).
pub type BoxedWriter = Pin<Box<dyn AsyncWrite + Send>>;
/// Boxed async reader (child stdout / stderr).
pub type BoxedReader = Pin<Box<dyn AsyncRead + Send>>;

/// How a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    /// Exit code, if it exited normally.
    pub code: Option<i32>,
    /// Terminating signal, if it was killed.
    pub signal: Option<i32>,
}

impl ExitInfo {
    /// Normal exit with `code`.
    pub fn code(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
        }
    }

    /// Shell-style code: the exit code, or `128 + signal`.
    pub fn shell_code(&self) -> Option<i32> {
        self.code
            .or_else(|| self.signal.map(|s| 128_i32.saturating_add(s)))
    }
}

/// Control over a spawned process.
#[async_trait]
pub trait ProcessControl: Send {
    /// Wait for exit. Must be cancel-safe (it is polled inside `select!`).
    async fn wait(&mut self) -> io::Result<ExitInfo>;
    /// Send SIGKILL (non-blocking).
    fn start_kill(&mut self) -> io::Result<()>;
    /// OS process id, if any.
    fn id(&self) -> Option<u32>;
}

/// A running child with its pipes.
pub struct SpawnedProcess {
    /// Child stdin (taken by the runner, written once, then closed).
    pub stdin: Option<BoxedWriter>,
    /// Child stdout.
    pub stdout: BoxedReader,
    /// Child stderr.
    pub stderr: BoxedReader,
    /// Wait / kill.
    pub control: Box<dyn ProcessControl>,
}

/// Spawns processes.
pub trait ProcessSpawner: Send + Sync {
    /// Spawn `cmd` with all three standard streams piped.
    fn spawn(&self, cmd: &ProcessCommand) -> io::Result<SpawnedProcess>;
}

/// [`ProcessSpawner`] backed by `tokio::process` (kill-on-drop).
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioProcessSpawner;

struct TokioChild(tokio::process::Child);

#[async_trait]
impl ProcessControl for TokioChild {
    async fn wait(&mut self) -> io::Result<ExitInfo> {
        use std::os::unix::process::ExitStatusExt;
        let status = self.0.wait().await?;
        Ok(ExitInfo {
            code: status.code(),
            signal: status.signal(),
        })
    }

    fn start_kill(&mut self) -> io::Result<()> {
        self.0.start_kill()
    }

    fn id(&self) -> Option<u32> {
        self.0.id()
    }
}

fn missing(what: &str) -> io::Error {
    io::Error::other(format!("child {what} was not captured"))
}

impl ProcessSpawner for TokioProcessSpawner {
    fn spawn(&self, cmd: &ProcessCommand) -> io::Result<SpawnedProcess> {
        let mut child = tokio::process::Command::new(&cmd.program)
            .args(&cmd.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| missing("stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| missing("stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| missing("stderr"))?;
        Ok(SpawnedProcess {
            stdin: Some(Box::pin(stdin)),
            stdout: Box::pin(stdout),
            stderr: Box::pin(stderr),
            control: Box::new(TokioChild(child)),
        })
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Process fakes.

    use std::io;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, DuplexStream, duplex};
    use tokio::sync::watch;

    use super::*;

    /// Runs `bash -c <script>` instead of the runtime command, recording the
    /// command it was asked to run.
    #[derive(Default)]
    pub struct BashSpawner {
        pub script: String,
        pub seen: Mutex<Vec<ProcessCommand>>,
    }

    impl BashSpawner {
        pub fn new(script: &str) -> Self {
            Self {
                script: script.to_string(),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProcessSpawner for BashSpawner {
        fn spawn(&self, cmd: &ProcessCommand) -> io::Result<SpawnedProcess> {
            self.seen.lock().unwrap().push(cmd.clone());
            TokioProcessSpawner.spawn(&ProcessCommand {
                program: "bash".into(),
                args: vec!["-c".into(), self.script.clone()],
            })
        }
    }

    /// Always fails to spawn.
    pub struct FailingSpawner;

    impl ProcessSpawner for FailingSpawner {
        fn spawn(&self, _cmd: &ProcessCommand) -> io::Result<SpawnedProcess> {
            Err(io::Error::new(io::ErrorKind::NotFound, "docker: not found"))
        }
    }

    /// Test-side ends of an in-memory fake process.
    pub struct FakeProcessHandle {
        /// Write here to emit container stdout.
        pub stdout: DuplexStream,
        /// Write here to emit container stderr.
        pub stderr: DuplexStream,
        /// Read what the runner wrote to stdin.
        pub stdin: DuplexStream,
        exit: watch::Sender<Option<ExitInfo>>,
    }

    impl FakeProcessHandle {
        /// Make the process exit with `code`.
        pub fn exit(&self, code: i32) {
            let _ = self.exit.send(Some(ExitInfo::code(code)));
        }

        /// Exit sender usable from other places (e.g. the executor fake).
        pub fn exit_sender(&self) -> watch::Sender<Option<ExitInfo>> {
            self.exit.clone()
        }

        /// Read everything the runner wrote to stdin (until it closed it).
        pub async fn read_stdin(&mut self) -> String {
            let mut s = String::new();
            self.stdin.read_to_string(&mut s).await.unwrap();
            s
        }
    }

    struct FakeControl {
        exit: watch::Receiver<Option<ExitInfo>>,
        exit_tx: watch::Sender<Option<ExitInfo>>,
        killed: Arc<Mutex<u32>>,
        ignore_kill: bool,
    }

    #[async_trait]
    impl ProcessControl for FakeControl {
        async fn wait(&mut self) -> io::Result<ExitInfo> {
            let info: Option<ExitInfo> = *self
                .exit
                .wait_for(|e| e.is_some())
                .await
                .map_err(|_| io::Error::other("fake exit sender dropped"))?;
            Ok(info.unwrap_or(ExitInfo::code(-1)))
        }

        fn start_kill(&mut self) -> io::Result<()> {
            *self.killed.lock().unwrap() += 1;
            if !self.ignore_kill {
                let _ = self.exit_tx.send(Some(ExitInfo {
                    code: None,
                    signal: Some(9),
                }));
            }
            Ok(())
        }

        fn id(&self) -> Option<u32> {
            Some(4242)
        }
    }

    /// Hands out one pre-built in-memory process.
    pub struct FakeSpawner {
        pending: Mutex<Option<SpawnedProcess>>,
        pub seen: Mutex<Vec<ProcessCommand>>,
        pub kills: Arc<Mutex<u32>>,
    }

    impl FakeSpawner {
        /// Create a spawner plus the test-side handle of its process.
        pub fn new() -> (Arc<Self>, FakeProcessHandle) {
            Self::with_options(false)
        }

        /// `ignore_kill`: SIGKILL does not end the fake process (exercises
        /// the runner's last-resort abandon path).
        pub fn with_options(ignore_kill: bool) -> (Arc<Self>, FakeProcessHandle) {
            let (stdout_child, stdout_test) = duplex(1 << 16);
            let (stderr_child, stderr_test) = duplex(1 << 16);
            let (stdin_test, stdin_child) = duplex(1 << 16);
            let (exit_tx, exit_rx) = watch::channel(None);
            let kills = Arc::new(Mutex::new(0));
            let proc = SpawnedProcess {
                stdin: Some(Box::pin(stdin_child)),
                stdout: Box::pin(stdout_child),
                stderr: Box::pin(stderr_child),
                control: Box::new(FakeControl {
                    exit: exit_rx,
                    exit_tx: exit_tx.clone(),
                    killed: kills.clone(),
                    ignore_kill,
                }),
            };
            let spawner = Arc::new(Self {
                pending: Mutex::new(Some(proc)),
                seen: Mutex::new(Vec::new()),
                kills,
            });
            let handle = FakeProcessHandle {
                stdout: stdout_test,
                stderr: stderr_test,
                stdin: stdin_test,
                exit: exit_tx,
            };
            (spawner, handle)
        }

        pub fn kill_count(&self) -> u32 {
            *self.kills.lock().unwrap()
        }
    }

    impl ProcessSpawner for FakeSpawner {
        fn spawn(&self, cmd: &ProcessCommand) -> io::Result<SpawnedProcess> {
            self.seen.lock().unwrap().push(cmd.clone());
            self.pending
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| io::Error::other("fake process already spawned"))
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn tokio_spawner_pipes_and_exit_code() {
        let mut p = TokioProcessSpawner
            .spawn(&ProcessCommand {
                program: "bash".into(),
                args: vec!["-c".into(), "cat; echo err >&2; exit 7".into()],
            })
            .unwrap();
        let mut stdin = p.stdin.take().unwrap();
        stdin.write_all(b"hello").await.unwrap();
        drop(stdin);
        let mut out = String::new();
        p.stdout.read_to_string(&mut out).await.unwrap();
        let mut err = String::new();
        p.stderr.read_to_string(&mut err).await.unwrap();
        let exit = p.control.wait().await.unwrap();
        assert_eq!(out, "hello");
        assert_eq!(err.trim(), "err");
        assert_eq!(exit, ExitInfo::code(7));
        assert_eq!(exit.shell_code(), Some(7));
    }

    #[tokio::test]
    async fn kill_reports_signal() {
        let mut p = TokioProcessSpawner
            .spawn(&ProcessCommand {
                program: "sleep".into(),
                args: vec!["30".into()],
            })
            .unwrap();
        assert!(p.control.id().is_some());
        p.control.start_kill().unwrap();
        let exit = p.control.wait().await.unwrap();
        assert_eq!(exit.signal, Some(9));
        assert_eq!(exit.shell_code(), Some(137));
    }

    #[test]
    fn spawn_error_for_missing_binary() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let r = TokioProcessSpawner.spawn(&ProcessCommand {
                program: "/nonexistent/talon-docker".into(),
                args: vec![],
            });
            assert!(r.is_err());
        });
    }
}
