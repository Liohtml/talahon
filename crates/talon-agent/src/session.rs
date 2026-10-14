//! Session transcripts: one JSONL file per session at
//! `<state>/sessions/<uuid>.jsonl` (mode 0600, directory 0700).
//!
//! ```text
//! {"type":"session","version":1,"id":"<uuid>","createdAt":"..."}
//! {"type":"message","ts":"...","message":{"role":"user","content":"..."}}
//! {"type":"message","ts":"...","message":{"role":"assistant","content":null,"tool_calls":[...]}}
//! {"type":"compaction","ts":"...","archivedTo":"/workspace/group/conversations/..."}
//! ```
//!
//! Messages are appended as they happen; compaction rewrites the file
//! atomically (temp file + rename). The system prompt is never stored — it is
//! rebuilt on every run so `CLAUDE.md` edits take effect. Ids must be
//! canonical hyphenated UUIDs, so an id can never traverse out of the
//! sessions directory. Loading tolerates a torn last line and repairs
//! tool-call/result pairing (see [`sanitize_history`]).

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use talon_core::time::now_iso;
use talon_llm::{ChatMessage, Role};

use crate::error::AgentError;

/// Transcript format version written in the header line.
pub const SESSION_FORMAT_VERSION: u32 = 1;
/// Session files larger than this are refused on load.
pub const MAX_SESSION_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Lines longer than this are skipped on load.
const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

/// Text of the synthetic tool result inserted for calls that never got one.
pub const INTERRUPTED_TOOL_RESULT: &str =
    "[talon] No result: the previous run ended before this tool call finished.";

/// Validate a session id: a hyphenated UUID (36 chars). Returns the
/// canonical (lower-case) form.
pub fn validate_session_id(id: &str) -> Option<String> {
    if id.len() != 36 {
        return None;
    }
    uuid::Uuid::try_parse(id)
        .ok()
        .map(|u| u.hyphenated().to_string())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Session {
        version: u32,
        id: String,
        #[serde(rename = "createdAt")]
        created_at: String,
    },
    Message {
        ts: String,
        message: ChatMessage,
    },
    Compaction {
        ts: String,
        #[serde(
            rename = "archivedTo",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        archived_to: Option<String>,
    },
}

/// A session's persistent transcript (or an in-memory, ephemeral one).
#[derive(Debug, Clone)]
pub struct SessionStore {
    id: String,
    /// `None` for ephemeral sessions: nothing is ever written.
    path: Option<PathBuf>,
}

impl SessionStore {
    /// A new persistent session in `dir` (the file is created on the first
    /// append).
    pub fn create(dir: &Path) -> Self {
        let id = uuid::Uuid::new_v4().hyphenated().to_string();
        Self {
            path: Some(dir.join(format!("{id}.jsonl"))),
            id,
        }
    }

    /// An ephemeral session: same API, never touches disk.
    pub fn ephemeral() -> Self {
        Self {
            id: uuid::Uuid::new_v4().hyphenated().to_string(),
            path: None,
        }
    }

    /// Open an existing session and load its history.
    ///
    /// Errors with [`AgentError::SessionNotFound`] when the id is invalid
    /// or the file does not exist.
    pub fn open(dir: &Path, id: &str) -> Result<(Self, Vec<ChatMessage>), AgentError> {
        let canonical = validate_session_id(id).ok_or_else(|| {
            AgentError::SessionNotFound(format!(
                "invalid session id {:?}",
                id.chars().take(64).collect::<String>()
            ))
        })?;
        let path = dir.join(format!("{canonical}.jsonl"));
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(AgentError::SessionNotFound(canonical));
            }
            Err(e) => return Err(AgentError::Session(format!("cannot stat session: {e}"))),
        };
        if !meta.is_file() {
            return Err(AgentError::Session(
                "session transcript is not a regular file".into(),
            ));
        }
        if meta.len() > MAX_SESSION_FILE_BYTES {
            return Err(AgentError::Session(format!(
                "session transcript exceeds {MAX_SESSION_FILE_BYTES} bytes"
            )));
        }
        let file = fs::File::open(&path)
            .map_err(|e| AgentError::Session(format!("cannot open session: {e}")))?;
        let messages = read_messages(BufReader::new(file.take(MAX_SESSION_FILE_BYTES)))?;
        Ok((
            Self {
                id: canonical,
                path: Some(path),
            },
            sanitize_history(messages),
        ))
    }

    /// The session id (canonical UUID).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether the transcript is written to disk.
    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    /// The transcript path (persistent sessions only).
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Append one message (creating the file with its header if needed).
    pub fn append(&self, message: &ChatMessage) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let line = encode(&Record::Message {
            ts: now_iso(),
            message: message.clone(),
        })?;
        let mut file = open_append(path)?;
        if file.metadata()?.len() == 0 {
            file.write_all(self.header()?.as_bytes())?;
        }
        file.write_all(line.as_bytes())?;
        file.flush()
    }

    /// Replace the transcript with `messages` (after compaction), atomically.
    pub fn rewrite(
        &self,
        messages: &[ChatMessage],
        archived_to: Option<&Path>,
    ) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("session path has no parent"))?;
        ensure_private_dir(dir)?;
        let tmp = dir.join(format!(".{}.jsonl.tmp", self.id));
        let _ = fs::remove_file(&tmp);
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            let mut buf = self.header()?;
            buf.push_str(&encode(&Record::Compaction {
                ts: now_iso(),
                archived_to: archived_to.map(|p| p.display().to_string()),
            })?);
            for m in messages {
                buf.push_str(&encode(&Record::Message {
                    ts: now_iso(),
                    message: m.clone(),
                })?);
            }
            file.write_all(buf.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    fn header(&self) -> std::io::Result<String> {
        encode(&Record::Session {
            version: SESSION_FORMAT_VERSION,
            id: self.id.clone(),
            created_at: now_iso(),
        })
    }
}

fn encode(record: &Record) -> std::io::Result<String> {
    let mut s = serde_json::to_string(record).map_err(std::io::Error::other)?;
    s.push('\n');
    Ok(s)
}

fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(std::io::Error::other(format!(
            "{} is not a directory",
            dir.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        }
        Err(e) => Err(e),
    }
}

fn open_append(path: &Path) -> std::io::Result<fs::File> {
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir)?;
    }
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.is_file() {
            return Err(std::io::Error::other(
                "session transcript is not a regular file",
            ));
        }
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

fn read_messages<R: BufRead>(mut reader: R) -> Result<Vec<ChatMessage>, AgentError> {
    let mut out = Vec::new();
    let mut line = Vec::new();
    let mut lineno = 0usize;
    loop {
        line.clear();
        let n = reader
            .read_until(b'\n', &mut line)
            .map_err(|e| AgentError::Session(format!("cannot read session: {e}")))?;
        if n == 0 {
            break;
        }
        lineno += 1;
        if line.len() > MAX_LINE_BYTES || line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&line) else {
            tracing::warn!(line = lineno, "skipping unparseable session line");
            continue;
        };
        if value.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        match serde_json::from_value::<Record>(value) {
            Ok(Record::Message { message, .. }) => out.push(message),
            Ok(_) => {}
            Err(e) => tracing::warn!(line = lineno, error = %e, "skipping invalid session message"),
        }
    }
    Ok(out)
}

/// Make a loaded history valid for the chat template:
/// - system messages are dropped (the system prompt is rebuilt each run);
/// - tool results that don't answer a pending call of the preceding
///   assistant message are dropped;
/// - calls that never got a result get [`INTERRUPTED_TOOL_RESULT`];
/// - malformed tool-call arguments are normalized to `{}`.
pub fn sanitize_history(messages: Vec<ChatMessage>) -> Vec<ChatMessage> {
    let mut out: Vec<ChatMessage> = Vec::with_capacity(messages.len());
    let mut pending: Vec<String> = Vec::new();
    let flush = |out: &mut Vec<ChatMessage>, pending: &mut Vec<String>| {
        for id in pending.drain(..) {
            out.push(ChatMessage::tool_result(id, INTERRUPTED_TOOL_RESULT));
        }
    };
    for mut m in messages {
        match m.role {
            Role::System => {}
            Role::Tool => {
                let id = m.tool_call_id.clone().unwrap_or_default();
                if let Some(pos) = pending.iter().position(|p| *p == id) {
                    pending.remove(pos);
                    out.push(m);
                }
            }
            Role::Assistant => {
                flush(&mut out, &mut pending);
                m.normalize_tool_arguments();
                let mut seen = HashSet::new();
                for call in &m.tool_calls {
                    if seen.insert(call.id.clone()) {
                        pending.push(call.id.clone());
                    }
                }
                out.push(m);
            }
            Role::User => {
                flush(&mut out, &mut pending);
                out.push(m);
            }
        }
    }
    flush(&mut out, &mut pending);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use talon_llm::ToolCall;

    #[test]
    fn id_validation() {
        let id = uuid::Uuid::new_v4().hyphenated().to_string();
        assert_eq!(validate_session_id(&id).as_deref(), Some(id.as_str()));
        assert_eq!(
            validate_session_id(&id.to_uppercase()).as_deref(),
            Some(id.as_str())
        );
        assert!(validate_session_id("../../etc/passwd").is_none());
        assert!(validate_session_id(&id.replace('-', "")).is_none());
        assert!(validate_session_id(&format!("{{{id}}}")).is_none());
        assert!(validate_session_id("").is_none());
        assert!(validate_session_id(&"a/".repeat(18)).is_none());
    }

    #[test]
    fn append_open_roundtrip_with_private_modes() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        let store = SessionStore::create(&sessions);
        assert!(store.is_persistent());
        store.append(&ChatMessage::user("hello")).unwrap();
        store
            .append(&ChatMessage::assistant_tool_calls(
                None,
                vec![ToolCall::new("c1", "bash", "{\"command\":\"ls\"}")],
            ))
            .unwrap();
        store
            .append(&ChatMessage::tool_result("c1", "file.txt"))
            .unwrap();
        store.append(&ChatMessage::assistant("done")).unwrap();
        let path = store.path().unwrap();
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = fs::metadata(&sessions).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700);

        let (opened, history) = SessionStore::open(&sessions, store.id()).unwrap();
        assert_eq!(opened.id(), store.id());
        assert_eq!(history.len(), 4);
        assert_eq!(history[3].text(), "done");
    }

    #[test]
    fn missing_and_invalid_sessions_are_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let err = SessionStore::open(dir.path(), &id).unwrap_err();
        assert!(matches!(err, AgentError::SessionNotFound(_)));
        assert!(err.to_string().contains("session not found"));
        let err = SessionStore::open(dir.path(), "../x").unwrap_err();
        assert!(matches!(err, AgentError::SessionNotFound(_)));
    }

    #[test]
    fn torn_lines_are_skipped_and_rewrite_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::create(dir.path());
        store.append(&ChatMessage::user("one")).unwrap();
        store.append(&ChatMessage::assistant("two")).unwrap();
        let path = store.path().unwrap().to_path_buf();
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"type\":\"message\",\"message\":{\"role\":\"us")
            .unwrap();
        drop(f);
        let (_, h) = SessionStore::open(dir.path(), store.id()).unwrap();
        assert_eq!(h.len(), 2);

        store
            .rewrite(
                &[ChatMessage::user("summary"), ChatMessage::assistant("ok")],
                Some(Path::new("/x/y.md")),
            )
            .unwrap();
        let (_, h) = SessionStore::open(dir.path(), store.id()).unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].text(), "summary");
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"archivedTo\":\"/x/y.md\""));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn ephemeral_never_writes() {
        let s = SessionStore::ephemeral();
        assert!(!s.is_persistent());
        s.append(&ChatMessage::user("x")).unwrap();
        s.rewrite(&[], None).unwrap();
        assert!(s.path().is_none());
        assert!(validate_session_id(s.id()).is_some());
    }

    #[test]
    fn symlinked_transcript_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let target = dir.path().join("elsewhere");
        fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(format!("{id}.jsonl"))).unwrap();
        assert!(matches!(
            SessionStore::open(dir.path(), &id),
            Err(AgentError::Session(_))
        ));
    }

    #[test]
    fn sanitize_repairs_pairs() {
        let msgs = vec![
            ChatMessage::system("old system"),
            ChatMessage::tool_result("orphan", "x"),
            ChatMessage::user("q"),
            ChatMessage::assistant_tool_calls(
                None,
                vec![
                    ToolCall::new("a", "t", "{}"),
                    ToolCall::new("b", "t", "{broken"),
                ],
            ),
            ChatMessage::tool_result("a", "ok"),
            ChatMessage::user("next"),
        ];
        let out = sanitize_history(msgs);
        let roles: Vec<Role> = out.iter().map(|m| m.role).collect();
        assert_eq!(
            roles,
            vec![
                Role::User,
                Role::Assistant,
                Role::Tool,
                Role::Tool,
                Role::User
            ]
        );
        assert_eq!(out[1].tool_calls[1].function.arguments, "{}");
        assert_eq!(out[3].tool_call_id.as_deref(), Some("b"));
        assert_eq!(out[3].text(), INTERRUPTED_TOOL_RESULT);

        // Trailing unanswered call is completed too.
        let out = sanitize_history(vec![ChatMessage::assistant_tool_calls(
            None,
            vec![ToolCall::new("z", "t", "{}")],
        )]);
        assert_eq!(out.len(), 2);
    }
}
