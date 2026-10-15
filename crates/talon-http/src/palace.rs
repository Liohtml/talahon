//! MemPalace bridge (port of `src/palace-client.ts`).
//!
//! CoPilot never talks to MemPalace directly; the HTTP channel runs one
//! palace process per request, writes one JSON request to its stdin and
//! reads one JSON response from stdout.
//!
//! ## Where palace code runs (MYTH-01)
//! MemPalace keeps its data (ChromaDB, including pickled index metadata) in
//! `mempalace-data/`, a directory agent containers mount. Running the Python
//! palace code *on the host* against that directory would unpickle data an
//! agent may have written: host code execution as the Talon user. So:
//!
//! - the default runner is [`DisabledPalaceRunner`]: every `/palace/*` call
//!   answers `503 {"error":"palace not configured"}`;
//! - production wiring supplies a [`CommandPalaceRunner`], a generic
//!   "spawn this program" runner the host builds as `docker run <hardened
//!   palace args>`, so palace code only ever runs inside a locked-down
//!   container as `mcp-palace`;
//! - [`ScriptPalaceRunner`] (host execution of `mempalace/palace-call.sh`)
//!   is only selected when the operator sets
//!   `TALON_PALACE_HOST_EXEC=unsafe` ([`HOST_EXEC_ENV`]). **Dangerous**: any
//!   agent that can write `mempalace-data/` can then run code on the host.
//!
//! Every process-backed runner keeps the same safeguards: an allowlisted
//! environment (no inherited secrets), stdout capped (1 MiB by default) with
//! recovery from non-JSON noise, stderr logged at debug level and never
//! returned to callers, bounded concurrency (4 by default), and the child
//! killed on timeout or when the request future is dropped.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Semaphore;

/// Env var that opts into running `palace-call.sh` directly on the host.
pub const HOST_EXEC_ENV: &str = "TALON_PALACE_HOST_EXEC";
/// The only value of [`HOST_EXEC_ENV`] that enables host execution.
pub const HOST_EXEC_UNSAFE: &str = "unsafe";
/// Default cap on a palace call's stdout.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Default number of concurrently running palace calls.
pub const DEFAULT_MAX_CONCURRENCY: usize = 4;
/// Max bytes of stderr kept for logging.
const MAX_STDERR_BYTES: usize = 64 * 1024;
/// Process env vars a [`CommandPalaceRunner`] child inherits.
const COMMAND_ENV_ALLOWLIST: &[&str] = &["PATH", "LANG", "TZ"];
/// `PATH` used when the host process has none.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Process env vars passed through to a host-executed `palace-call.sh`.
const SCRIPT_ENV_ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "USER", "LOGNAME",
];
/// Env var prefixes passed through to a host-executed `palace-call.sh`
/// (palace path, model caches).
const SCRIPT_ENV_PREFIX_ALLOWLIST: &[&str] = &[
    "MEMPALACE_",
    "HF_",
    "TRANSFORMERS_",
    "SENTENCE_TRANSFORMERS_",
    "XDG_",
];

/// Why a palace call failed. Messages are safe to return to callers (no
/// stderr/stdout contents).
#[derive(Debug, thiserror::Error)]
pub enum PalaceError {
    /// No palace runner is configured (the default; see the module docs).
    #[error("palace not configured")]
    Disabled,
    /// The palace process could not be started.
    #[error("palace call could not be started: {0}")]
    Spawn(String),
    /// The call exceeded its timeout and was killed.
    #[error("palace call timed out after {0:?}")]
    Timeout(Duration),
    /// Non-zero exit status.
    #[error("palace call exited with status {0}")]
    Exit(String),
    /// Stdout held no parseable JSON object.
    #[error("palace call returned non-JSON output")]
    NonJson,
    /// Stdout exceeded the size cap.
    #[error("palace call output exceeded {0} bytes")]
    OutputTooLarge(usize),
    /// Too many palace calls in flight.
    #[error("too many concurrent palace calls")]
    Busy,
}

/// Executes one palace request.
#[async_trait]
pub trait PalaceRunner: Send + Sync {
    /// Run `request` (`{"op": ...}`) and return the JSON response.
    async fn call(&self, request: Value) -> Result<Value, PalaceError>;

    /// Short label for startup logs (`disabled`, `command`, ...).
    fn mode(&self) -> &'static str {
        "custom"
    }
}

/// `add_drawer` request for a teach-the-palace lesson (TS `addLesson`).
pub fn add_lesson_request(
    customer_code: &str,
    lesson_type: &str,
    lesson_text: &str,
    durability: &str,
) -> Value {
    json!({
        "op": "add_drawer",
        "wing": customer_code,
        "room": lesson_type,
        "content": lesson_text,
        "source_file": format!("review_lesson:{durability}"),
        "added_by": "copilot-review",
    })
}

/// `search` request (TS `searchPalace`). `room: None` searches every room.
pub fn search_request(customer_code: &str, room: Option<&str>, query: &str, limit: u32) -> Value {
    let mut req = json!({
        "op": "search",
        "query": query,
        "wing": customer_code,
        "limit": limit,
    });
    if let (Some(room), Some(obj)) = (room, req.as_object_mut()) {
        obj.insert("room".into(), Value::String(room.to_string()));
    }
    req
}

/// `delete_drawer` request (TS `forgetLesson`).
pub fn forget_request(drawer_id: &str) -> Value {
    json!({ "op": "delete_drawer", "drawer_id": drawer_id })
}

/// Parse the palace's stdout. The python wrapper always writes the response
/// as the final line, but mempalace/chromadb internals occasionally print
/// to stdout first: try the whole output, then scan from the bottom for the
/// last line that is a JSON object.
pub fn parse_palace_stdout(stdout: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(stdout.trim()) {
        return Some(v);
    }
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{') && l.ends_with('}'))
        .rev()
        .find_map(|l| serde_json::from_str::<Value>(l).ok())
}

// ---------------------------------------------------------------------------
// Disabled (default)
// ---------------------------------------------------------------------------

/// The default runner: palace calls fail with [`PalaceError::Disabled`]
/// (`503 {"error":"palace not configured"}`). Nothing is executed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisabledPalaceRunner;

#[async_trait]
impl PalaceRunner for DisabledPalaceRunner {
    async fn call(&self, _request: Value) -> Result<Value, PalaceError> {
        Err(PalaceError::Disabled)
    }

    fn mode(&self) -> &'static str {
        "disabled"
    }
}

// ---------------------------------------------------------------------------
// Shared process plumbing
// ---------------------------------------------------------------------------

/// One child process per call: program, arguments, a fixed environment and
/// the limits every process-backed runner enforces.
struct ProcessSpec {
    program: PathBuf,
    args: Vec<String>,
    env: Vec<(OsString, OsString)>,
    current_dir: Option<PathBuf>,
    timeout: Duration,
    max_output: usize,
    max_concurrency: usize,
    permits: Semaphore,
}

impl fmt::Debug for ProcessSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Env values are never printed, only their names.
        let env_keys: Vec<_> = self.env.iter().map(|(k, _)| k).collect();
        f.debug_struct("ProcessSpec")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env_keys", &env_keys)
            .field("current_dir", &self.current_dir)
            .field("timeout", &self.timeout)
            .field("max_output", &self.max_output)
            .field("max_concurrency", &self.max_concurrency)
            .finish()
    }
}

/// Snapshot the allowlisted part of the process environment.
fn allowlisted_env(exact: &[&str], prefixes: &[&str]) -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(key, _)| {
            key.to_str()
                .is_some_and(|k| exact.contains(&k) || prefixes.iter().any(|p| k.starts_with(p)))
        })
        .collect()
}

impl ProcessSpec {
    fn new(
        program: PathBuf,
        args: Vec<String>,
        env: Vec<(OsString, OsString)>,
        timeout: Duration,
    ) -> Self {
        Self {
            program,
            args,
            env,
            current_dir: None,
            timeout,
            max_output: DEFAULT_MAX_OUTPUT_BYTES,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            permits: Semaphore::new(DEFAULT_MAX_CONCURRENCY),
        }
    }

    fn set_max_output(&mut self, bytes: usize) {
        self.max_output = bytes.max(1);
    }

    fn set_max_concurrency(&mut self, n: usize) {
        self.max_concurrency = n.max(1);
        self.permits = Semaphore::new(self.max_concurrency);
    }

    fn set_env(&mut self, key: OsString, value: OsString) {
        self.env.retain(|(k, _)| *k != key);
        self.env.push((key, value));
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)));
        if let Some(dir) = &self.current_dir {
            cmd.current_dir(dir);
        }
        cmd
    }

    async fn call(&self, request: Value) -> Result<Value, PalaceError> {
        let _permit = tokio::time::timeout(self.timeout, self.permits.acquire())
            .await
            .map_err(|_| PalaceError::Busy)?
            .map_err(|_| PalaceError::Busy)?;

        let mut child = self
            .command()
            .spawn()
            .map_err(|e| PalaceError::Spawn(e.kind().to_string()))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let payload = request.to_string().into_bytes();
        let max_output = self.max_output;

        let io = async {
            let write = async move {
                if let Some(mut stdin) = stdin {
                    let _ = stdin.write_all(&payload).await;
                    let _ = stdin.shutdown().await;
                }
            };
            let out = async move {
                match stdout {
                    Some(s) => read_capped(s, max_output).await,
                    None => (Vec::new(), false),
                }
            };
            let err = async move {
                match stderr {
                    Some(s) => read_capped(s, MAX_STDERR_BYTES).await,
                    None => (Vec::new(), false),
                }
            };
            let ((), out, err) = tokio::join!(write, out, err);
            (out, err)
        };

        let result = tokio::time::timeout(self.timeout, async {
            let (out, err) = io.await;
            let status = child.wait().await;
            (out, err, status)
        })
        .await;

        let ((stdout, stdout_overflow), (stderr, _), status) = match result {
            Ok(r) => r,
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                tracing::warn!(timeout = ?self.timeout, "palace call timed out; killed");
                return Err(PalaceError::Timeout(self.timeout));
            }
        };

        let stderr = String::from_utf8_lossy(&stderr);
        if !stderr.trim().is_empty() {
            tracing::debug!(stderr = %stderr.trim(), "palace call stderr");
        }
        let status = status.map_err(|e| PalaceError::Spawn(e.kind().to_string()))?;
        if !status.success() {
            let code = status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string());
            tracing::warn!(%code, "palace call failed");
            return Err(PalaceError::Exit(code));
        }
        if stdout_overflow {
            return Err(PalaceError::OutputTooLarge(max_output));
        }
        let text = String::from_utf8_lossy(&stdout);
        match parse_palace_stdout(&text) {
            Some(v) => {
                if serde_json::from_str::<Value>(text.trim()).is_err() {
                    tracing::warn!(
                        "palace call emitted non-JSON noise on stdout; recovered last JSON line"
                    );
                }
                Ok(v)
            }
            None => Err(PalaceError::NonJson),
        }
    }
}

/// Read up to `cap` bytes; keep draining (and discarding) past the cap so the
/// child never blocks on a full pipe. Returns the bytes and whether the cap
/// was exceeded.
async fn read_capped<R: AsyncRead + Unpin>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut overflow = false;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                if n > room {
                    overflow = true;
                }
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    (out, overflow)
}

// ---------------------------------------------------------------------------
// Command runner (production: palace inside a hardened container)
// ---------------------------------------------------------------------------

/// Runs `program args...` per request: the JSON request goes to its stdin,
/// the JSON response is read from its stdout.
///
/// Intended to be built by the host as `docker <hardened palace run args>`,
/// so palace code runs only inside a locked-down container as `mcp-palace`.
/// The child gets a cleared environment holding only `PATH` (a standard
/// default when the host has none), `LANG` and `TZ`, plus whatever the
/// caller adds explicitly with [`Self::with_env`].
///
/// Defaults: stdout capped at [`DEFAULT_MAX_OUTPUT_BYTES`], at most
/// [`DEFAULT_MAX_CONCURRENCY`] calls in flight (excess callers wait up to
/// `timeout`, then get [`PalaceError::Busy`]).
///
/// Killing the client process on timeout does not necessarily stop a
/// container it started; the container side must bound its own runtime.
#[derive(Debug)]
pub struct CommandPalaceRunner {
    spec: ProcessSpec,
}

impl CommandPalaceRunner {
    /// Runner for `program args...` with a per-call `timeout`.
    pub fn new(program: PathBuf, args: Vec<String>, timeout: Duration) -> Self {
        let mut env = allowlisted_env(COMMAND_ENV_ALLOWLIST, &[]);
        if !env.iter().any(|(k, _)| k == "PATH") {
            env.push(("PATH".into(), DEFAULT_PATH.into()));
        }
        Self {
            spec: ProcessSpec::new(program, args, env, timeout),
        }
    }

    /// Add (or replace) one environment variable of the child, e.g.
    /// `DOCKER_HOST` for a rootless daemon. Never pass secrets this way.
    pub fn with_env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.spec.set_env(key.into(), value.into());
        self
    }

    /// Override the stdout cap (bytes, at least 1).
    pub fn with_max_output(mut self, bytes: usize) -> Self {
        self.spec.set_max_output(bytes);
        self
    }

    /// Override the concurrency limit (at least 1).
    pub fn with_max_concurrency(mut self, n: usize) -> Self {
        self.spec.set_max_concurrency(n);
        self
    }

    /// The program spawned per call.
    pub fn program(&self) -> &Path {
        &self.spec.program
    }

    /// The arguments passed to [`Self::program`].
    pub fn args(&self) -> &[String] {
        &self.spec.args
    }

    /// The per-call timeout.
    pub fn timeout(&self) -> Duration {
        self.spec.timeout
    }
}

#[async_trait]
impl PalaceRunner for CommandPalaceRunner {
    async fn call(&self, request: Value) -> Result<Value, PalaceError> {
        self.spec.call(request).await
    }

    fn mode(&self) -> &'static str {
        "command"
    }
}

// ---------------------------------------------------------------------------
// Host script runner (explicit, dangerous opt-in)
// ---------------------------------------------------------------------------

/// Spawns `mempalace/palace-call.sh` **on the host** per request.
///
/// **Dangerous** (MYTH-01): the script loads ChromaDB data from
/// `mempalace-data/`, which agent containers can write, so a compromised
/// agent can get code executed as the host user. Only selected when the
/// operator sets `TALON_PALACE_HOST_EXEC=unsafe`; prefer
/// [`CommandPalaceRunner`].
#[derive(Debug)]
pub struct ScriptPalaceRunner {
    spec: ProcessSpec,
}

impl ScriptPalaceRunner {
    /// New runner for `script` with a per-call `timeout`, a stdout cap and a
    /// concurrency limit.
    pub fn new(
        script: impl Into<PathBuf>,
        timeout: Duration,
        max_output: usize,
        max_concurrency: usize,
    ) -> Self {
        let script = script.into();
        let env = allowlisted_env(SCRIPT_ENV_ALLOWLIST, SCRIPT_ENV_PREFIX_ALLOWLIST);
        let mut spec = ProcessSpec::new(script, Vec::new(), env, timeout);
        spec.current_dir = spec.program.parent().map(Path::to_path_buf);
        spec.set_max_output(max_output);
        spec.set_max_concurrency(max_concurrency);
        Self { spec }
    }
}

#[async_trait]
impl PalaceRunner for ScriptPalaceRunner {
    async fn call(&self, request: Value) -> Result<Value, PalaceError> {
        self.spec.call(request).await
    }

    fn mode(&self) -> &'static str {
        "host-script (UNSAFE)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &tempfile::TempDir, body: &str) -> PathBuf {
        let path = dir.path().join("palace-call.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&path, perm).unwrap();
        path
    }

    fn runner(path: PathBuf, timeout_ms: u64) -> ScriptPalaceRunner {
        ScriptPalaceRunner::new(path, Duration::from_millis(timeout_ms), 4096, 2)
    }

    /// A `CommandPalaceRunner` running `/bin/sh -c <body> palace <extra...>`
    /// (a stand-in for `docker run ...`).
    fn sh(body: &str, timeout_ms: u64) -> CommandPalaceRunner {
        CommandPalaceRunner::new(
            PathBuf::from("/bin/sh"),
            vec!["-c".into(), body.into(), "palace".into()],
            Duration::from_millis(timeout_ms),
        )
    }

    #[test]
    fn request_shapes_match_the_ts_client() {
        let add = add_lesson_request("acme", "environment", "DC01 patches at 02:00", "durable");
        assert_eq!(add["op"], "add_drawer");
        assert_eq!(add["wing"], "acme");
        assert_eq!(add["room"], "environment");
        assert_eq!(add["content"], "DC01 patches at 02:00");
        assert_eq!(add["source_file"], "review_lesson:durable");
        assert_eq!(add["added_by"], "copilot-review");

        let s = search_request("acme", None, "svchost", 5);
        assert_eq!(s["op"], "search");
        assert_eq!(s["limit"], 5);
        assert!(s.get("room").is_none());
        let s = search_request("acme", Some("assets"), "q", 7);
        assert_eq!(s["room"], "assets");

        assert_eq!(
            forget_request("d1"),
            json!({"op": "delete_drawer", "drawer_id": "d1"})
        );
    }

    #[test]
    fn stdout_parsing_recovers_the_last_json_line() {
        assert_eq!(parse_palace_stdout(" {\"a\":1} \n"), Some(json!({"a": 1})));
        assert_eq!(
            parse_palace_stdout("Filed drawer: x\n{\"a\":1}\nnoise\n{\"b\":2}\n"),
            Some(json!({"b": 2}))
        );
        assert_eq!(parse_palace_stdout("no json here"), None);
        assert_eq!(parse_palace_stdout(""), None);
    }

    // ---- DisabledPalaceRunner ------------------------------------------------

    #[tokio::test]
    async fn disabled_runner_never_executes_anything() {
        let err = DisabledPalaceRunner
            .call(forget_request("d"))
            .await
            .unwrap_err();
        assert!(matches!(err, PalaceError::Disabled));
        assert_eq!(err.to_string(), "palace not configured");
        assert_eq!(DisabledPalaceRunner.mode(), "disabled");
    }

    // ---- CommandPalaceRunner -------------------------------------------------

    #[tokio::test]
    async fn command_runner_passes_args_and_round_trips_json() {
        let dir = tempfile::tempdir().unwrap();
        // Fake `docker`: echo the argv and the request back.
        let fake = script(
            &dir,
            r#"req=$(cat); printf '{"args":"%s","req":%s}\n' "$*" "$req""#,
        );
        let runner = CommandPalaceRunner::new(
            fake.clone(),
            vec!["run".into(), "--rm".into(), "-i".into(), "palace".into()],
            Duration::from_secs(5),
        );
        assert_eq!(runner.program(), fake.as_path());
        assert_eq!(runner.args().len(), 4);
        assert_eq!(runner.mode(), "command");
        let out = runner.call(forget_request("drawer-1")).await.unwrap();
        assert_eq!(out["args"], "run --rm -i palace");
        assert_eq!(out["req"]["drawer_id"], "drawer-1");
    }

    #[tokio::test]
    async fn command_runner_env_is_only_path_lang_tz() {
        // cargo sets CARGO_MANIFEST_DIR for test binaries; it must not leak.
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
        let runner = sh(
            r#"cat >/dev/null; names=$(env | cut -d= -f1 | grep -v -x -e PWD -e SHLVL -e _ | sort | tr '\n' ' '); printf '{"names":"%s"}\n' "$names""#,
            5_000,
        );
        let out = runner.call(json!({})).await.unwrap();
        let names: Vec<&str> = out["names"].as_str().unwrap().split_whitespace().collect();
        assert!(names.contains(&"PATH"), "{names:?}");
        for n in &names {
            assert!(["PATH", "LANG", "TZ"].contains(n), "unexpected env var {n}");
        }
    }

    #[tokio::test]
    async fn command_runner_explicit_env_is_added() {
        let runner = sh(
            r#"cat >/dev/null; printf '{"host":"%s"}\n' "$DOCKER_HOST""#,
            5_000,
        )
        .with_env("DOCKER_HOST", "unix:///run/user/1000/docker.sock");
        let out = runner.call(json!({})).await.unwrap();
        assert_eq!(out["host"], "unix:///run/user/1000/docker.sock");
    }

    #[tokio::test]
    async fn command_runner_recovers_from_stdout_noise() {
        let out = sh(
            r#"cat >/dev/null; echo 'Fixed 3 BLOB seq_ids'; echo '{"success":true}'"#,
            5_000,
        )
        .call(json!({"op": "x"}))
        .await
        .unwrap();
        assert_eq!(out, json!({"success": true}));
    }

    #[tokio::test]
    async fn command_runner_failure_never_leaks_stderr() {
        let err = sh(
            "cat >/dev/null; echo 'secret-ish detail' >&2; exit 3",
            5_000,
        )
        .call(json!({}))
        .await
        .unwrap_err();
        assert!(matches!(err, PalaceError::Exit(ref c) if c == "3"));
        assert!(!err.to_string().contains("secret-ish"));
    }

    #[tokio::test]
    async fn command_runner_times_out_and_kills_the_child() {
        let started = std::time::Instant::now();
        let err = sh("exec sleep 30", 300).call(json!({})).await.unwrap_err();
        assert!(matches!(err, PalaceError::Timeout(_)));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn command_runner_caps_output_at_one_mib_by_default() {
        // ~1.2 MiB of JSON lines.
        let err = sh(
            r#"cat >/dev/null; i=0; while [ $i -lt 40000 ]; do echo '{"padding":"xxxxxxxxxxxxxxxxx"}'; i=$((i+1)); done"#,
            30_000,
        )
        .call(json!({}))
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            PalaceError::OutputTooLarge(DEFAULT_MAX_OUTPUT_BYTES)
        ));
        let err = sh(
            r#"cat >/dev/null; echo '{"padding":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}'"#,
            5_000,
        )
        .with_max_output(16)
        .call(json!({}))
        .await
        .unwrap_err();
        assert!(matches!(err, PalaceError::OutputTooLarge(16)));
    }

    #[tokio::test]
    async fn command_runner_bounds_concurrency() {
        // One permit: A holds it until its timeout, B (FIFO) inherits it and
        // holds it for another timeout, so C's wait (one timeout) expires.
        let runner =
            std::sync::Arc::new(sh("cat >/dev/null; exec sleep 5", 500).with_max_concurrency(1));
        let spawn = |r: std::sync::Arc<CommandPalaceRunner>| {
            tokio::spawn(async move { r.call(json!({})).await })
        };
        let a = spawn(runner.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let b = spawn(runner.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let c = runner.call(json!({})).await.unwrap_err();
        assert!(matches!(c, PalaceError::Busy), "{c:?}");
        assert!(matches!(a.await.unwrap(), Err(PalaceError::Timeout(_))));
        assert!(matches!(b.await.unwrap(), Err(PalaceError::Timeout(_))));
    }

    #[tokio::test]
    async fn command_runner_missing_program_is_a_spawn_error() {
        let err = CommandPalaceRunner::new(
            PathBuf::from("/nonexistent/docker"),
            vec![],
            Duration::from_secs(1),
        )
        .call(json!({}))
        .await
        .unwrap_err();
        assert!(matches!(err, PalaceError::Spawn(_)));
    }

    #[test]
    fn command_runner_debug_never_prints_env_values() {
        let r = sh("true", 1_000).with_env("DOCKER_HOST", "tcp://secret-host:2376");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DOCKER_HOST"), "{dbg}");
        assert!(!dbg.contains("secret-host"), "{dbg}");
    }

    // ---- ScriptPalaceRunner (unsafe opt-in) ----------------------------------

    #[tokio::test]
    async fn round_trips_json_over_stdio() {
        let dir = tempfile::tempdir().unwrap();
        // Echo the request back inside a response object.
        let path = script(&dir, r#"read -r line; printf '{"echo":%s}\n' "$line""#);
        let out = runner(path, 5_000)
            .call(forget_request("drawer-1"))
            .await
            .unwrap();
        assert_eq!(out["echo"]["drawer_id"], "drawer-1");
    }

    #[tokio::test]
    async fn recovers_from_stdout_noise() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(
            &dir,
            r#"cat >/dev/null; echo 'Fixed 3 BLOB seq_ids'; echo '{"success":true}'"#,
        );
        let out = runner(path, 5_000).call(json!({"op": "x"})).await.unwrap();
        assert_eq!(out, json!({"success": true}));
    }

    #[tokio::test]
    async fn non_zero_exit_is_an_error_without_leaking_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(&dir, "cat >/dev/null; echo 'secret-ish detail' >&2; exit 3");
        let err = runner(path, 5_000).call(json!({})).await.unwrap_err();
        assert!(matches!(err, PalaceError::Exit(ref c) if c == "3"));
        assert!(!err.to_string().contains("secret-ish"));
    }

    #[tokio::test]
    async fn non_json_output_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(&dir, "cat >/dev/null; echo hello");
        let err = runner(path, 5_000).call(json!({})).await.unwrap_err();
        assert!(matches!(err, PalaceError::NonJson));
    }

    #[tokio::test]
    async fn times_out_and_kills_the_child() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(&dir, "exec sleep 30");
        let started = std::time::Instant::now();
        let err = runner(path, 300).call(json!({})).await.unwrap_err();
        assert!(matches!(err, PalaceError::Timeout(_)));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn oversized_output_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(
            &dir,
            r#"cat >/dev/null; i=0; while [ $i -lt 2000 ]; do echo '{"padding":"xxxxxxxxxxxxxxxxxxxxxxxx"}'; i=$((i+1)); done"#,
        );
        let err = runner(path, 10_000).call(json!({})).await.unwrap_err();
        assert!(matches!(err, PalaceError::OutputTooLarge(4096)));
    }

    #[tokio::test]
    async fn missing_script_is_a_spawn_error() {
        let err = runner(PathBuf::from("/nonexistent/palace-call.sh"), 1_000)
            .call(json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, PalaceError::Spawn(_)));
    }

    #[tokio::test]
    async fn child_env_is_scrubbed() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(
            &dir,
            r#"cat >/dev/null; if [ -n "$HTTP_API_KEY$TALON_VLLM_API_KEY" ]; then echo '{"leak":true}'; else echo '{"leak":false}'; fi"#,
        );
        // The test process may or may not have these set; the child must
        // never see them either way.
        let out = runner(path, 5_000).call(json!({})).await.unwrap();
        assert_eq!(out, json!({"leak": false}));
        assert_eq!(
            runner(PathBuf::from("/x"), 1).mode(),
            "host-script (UNSAFE)"
        );
    }
}
