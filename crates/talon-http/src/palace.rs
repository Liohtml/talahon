//! MemPalace bridge (port of `src/palace-client.ts`).
//!
//! CoPilot never talks to MemPalace directly; the HTTP channel spawns
//! `mempalace/palace-call.sh`, writes one JSON request to its stdin and reads
//! one JSON response from stdout.
//!
//! Hardening over the TS client: the child gets a minimal allowlisted
//! environment (no inherited secrets), stdout/stderr are size-capped,
//! concurrent calls are bounded, the child is killed on timeout or when the
//! request is dropped, and stderr never reaches the HTTP caller.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Semaphore;

/// Max bytes of stderr kept for logging.
const MAX_STDERR_BYTES: usize = 64 * 1024;
/// Process env vars passed through to `palace-call.sh`.
const ENV_ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "USER", "LOGNAME",
];
/// Env var prefixes passed through (palace path, model caches).
const ENV_PREFIX_ALLOWLIST: &[&str] = &[
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
    /// The script could not be started.
    #[error("palace-call.sh could not be started: {0}")]
    Spawn(String),
    /// The call exceeded its timeout and was killed.
    #[error("palace-call.sh timed out after {0:?}")]
    Timeout(Duration),
    /// Non-zero exit status.
    #[error("palace-call.sh exited with status {0}")]
    Exit(String),
    /// Stdout held no parseable JSON object.
    #[error("palace-call.sh returned non-JSON output")]
    NonJson,
    /// Stdout exceeded the size cap.
    #[error("palace-call.sh output exceeded {0} bytes")]
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

/// Parse the script's stdout. The python wrapper always writes the response
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

/// Spawns `palace-call.sh` per request.
#[derive(Debug)]
pub struct ScriptPalaceRunner {
    script: PathBuf,
    timeout: Duration,
    max_output: usize,
    permits: Semaphore,
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
        Self {
            script: script.into(),
            timeout,
            max_output: max_output.max(1),
            permits: Semaphore::new(max_concurrency.max(1)),
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.script);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear();
        for (key, value) in std::env::vars_os() {
            let Some(k) = key.to_str() else { continue };
            if ENV_ALLOWLIST.contains(&k) || ENV_PREFIX_ALLOWLIST.iter().any(|p| k.starts_with(p)) {
                cmd.env(&key, value);
            }
        }
        if let Some(dir) = self.script.parent() {
            cmd.current_dir(dir);
        }
        cmd
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

#[async_trait]
impl PalaceRunner for ScriptPalaceRunner {
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
                tracing::warn!(timeout = ?self.timeout, "palace-call.sh timed out; killed");
                return Err(PalaceError::Timeout(self.timeout));
            }
        };

        let stderr = String::from_utf8_lossy(&stderr);
        if !stderr.trim().is_empty() {
            tracing::debug!(stderr = %stderr.trim(), "palace-call.sh stderr");
        }
        let status = status.map_err(|e| PalaceError::Spawn(e.kind().to_string()))?;
        if !status.success() {
            let code = status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string());
            tracing::warn!(%code, "palace-call.sh failed");
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
                        "palace-call.sh emitted non-JSON noise on stdout; recovered last JSON line"
                    );
                }
                Ok(v)
            }
            None => Err(PalaceError::NonJson),
        }
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
    }
}
