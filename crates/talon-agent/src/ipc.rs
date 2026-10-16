//! Follow-up input from the host: `<ipc>/input/*.json` files
//! (`IpcInput::Message`) and the `_close` sentinel.
//!
//! Files are consumed in name order (names are `<millis>-<rand>.json`, so
//! lexical order is arrival order) and deleted after reading, valid or not.
//! Only regular files up to [`MAX_INPUT_FILE_BYTES`] are read; temp files
//! (`*.json.tmp`) are left for the writer to rename. The names of the files
//! a turn consumed go back to the host with the turn's output frame, which
//! is how the host knows which follow-ups were answered.
//!
//! Messages the host wrote before `_close` are still read: the host stops
//! writing once it has written `_close`, so whatever is in the directory
//! when `_close` is seen was sent before it and is answered before the
//! session ends. The host clears the directory (stale messages and
//! `_close`) before it starts a container, so a `_close` present at start
//! was written for this container and is honoured.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use talon_core::protocol::{IPC_CLOSE_SENTINEL, IpcInput};
use tokio_util::sync::CancellationToken;

/// Follow-up files larger than this are discarded.
pub const MAX_INPUT_FILE_BYTES: u64 = 1024 * 1024;
/// At most this many files are consumed per drain (the rest wait).
const MAX_FILES_PER_DRAIN: usize = 256;

/// Reader for `<ipc>/input`.
#[derive(Debug, Clone)]
pub struct IpcInbox {
    dir: PathBuf,
}

/// One follow-up message read from the inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputMessage {
    /// The input file's name (reported back to the host).
    pub file: String,
    /// The message text.
    pub text: String,
}

/// What [`IpcInbox::wait_next`] returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// One or more follow-up messages.
    Messages {
        /// Their texts, joined with `\n`.
        text: String,
        /// The input files they came from.
        files: Vec<String>,
    },
    /// `_close` was found (and removed).
    Close,
    /// The cancellation token fired.
    Cancelled,
}

impl IpcInbox {
    /// Inbox reading `dir` (normally `/workspace/ipc/input`).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The input directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Create the directory if needed. A `_close` already there is kept:
    /// the host clears stale ones before it starts a container, so this one
    /// arrived while the container was starting.
    pub fn prepare(&self) {
        if let Err(e) = fs::create_dir_all(&self.dir) {
            tracing::warn!(error = %e, "cannot create IPC input directory");
        }
    }

    /// Whether `_close` exists (it is left in place).
    pub fn close_pending(&self) -> bool {
        fs::symlink_metadata(self.dir.join(IPC_CLOSE_SENTINEL)).is_ok()
    }

    /// If `_close` exists, remove it and return true.
    pub fn take_close(&self) -> bool {
        let path = self.dir.join(IPC_CLOSE_SENTINEL);
        if fs::symlink_metadata(&path).is_ok() {
            let _ = fs::remove_file(&path);
            true
        } else {
            false
        }
    }

    /// Consume every pending follow-up message (in arrival order).
    pub fn drain(&self) -> Vec<InputMessage> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(error = %e, "cannot read IPC input directory");
                }
                return Vec::new();
            }
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
            .collect();
        names.sort();
        names.truncate(MAX_FILES_PER_DRAIN);
        let mut out = Vec::new();
        for name in names {
            let path = self.dir.join(&name);
            match read_input_file(&path) {
                Ok(Some(text)) => out.push(InputMessage {
                    file: name.clone(),
                    text,
                }),
                Ok(None) => {}
                Err(reason) => tracing::warn!(file = %name, %reason, "discarding IPC input file"),
            }
            if let Err(e) = fs::remove_file(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(file = %name, error = %e, "cannot remove IPC input file");
                }
            }
        }
        out
    }

    /// Poll every `interval` until messages arrive, `_close` appears or
    /// `cancel` fires. Messages sent before `_close` come first; `_close`
    /// then ends the session on the next call.
    pub async fn wait_next(&self, interval: Duration, cancel: &CancellationToken) -> Inbound {
        loop {
            // `_close` first: every message written before it is already in
            // place when it is seen, so the drain below cannot miss one.
            let closing = self.close_pending();
            let messages = self.drain();
            if !messages.is_empty() {
                return joined(messages);
            }
            if closing {
                self.take_close();
                return Inbound::Close;
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.cancelled() => return Inbound::Cancelled,
            }
        }
    }
}

/// Several messages as one [`Inbound::Messages`].
pub fn joined(messages: Vec<InputMessage>) -> Inbound {
    let (texts, files): (Vec<String>, Vec<String>) =
        messages.into_iter().map(|m| (m.text, m.file)).unzip();
    Inbound::Messages {
        text: texts.join("\n"),
        files,
    }
}

fn read_input_file(path: &Path) -> Result<Option<String>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > MAX_INPUT_FILE_BYTES {
        return Err(format!("larger than {MAX_INPUT_FILE_BYTES} bytes"));
    }
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let input: IpcInput = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    match input {
        IpcInput::Message { text } if !text.trim().is_empty() => Ok(Some(text)),
        IpcInput::Message { .. } => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn drain_in_order_and_discards_bad_files() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = IpcInbox::new(dir.path());
        write(
            dir.path(),
            "2-b.json",
            r#"{"type":"message","text":"second"}"#,
        );
        write(
            dir.path(),
            "1-a.json",
            r#"{"type":"message","text":"first"}"#,
        );
        write(dir.path(), "3-c.json", "not json");
        write(dir.path(), "4-d.json", r#"{"type":"message","text":"  "}"#);
        write(
            dir.path(),
            "5-e.json.tmp",
            r#"{"type":"message","text":"later"}"#,
        );
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("6-f.json")).unwrap();
        let drained = inbox.drain();
        let texts: Vec<&str> = drained.iter().map(|m| m.text.as_str()).collect();
        let files: Vec<&str> = drained.iter().map(|m| m.file.as_str()).collect();
        assert_eq!(texts, vec!["first", "second"]);
        assert_eq!(files, vec!["1-a.json", "2-b.json"]);
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left, vec!["5-e.json.tmp"]);
        assert!(inbox.drain().is_empty());
    }

    #[test]
    fn oversized_files_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = IpcInbox::new(dir.path());
        let big = format!(
            r#"{{"type":"message","text":"{}"}}"#,
            "x".repeat(MAX_INPUT_FILE_BYTES as usize)
        );
        write(dir.path(), "1.json", &big);
        assert!(inbox.drain().is_empty());
        assert!(!dir.path().join("1.json").exists());
    }

    #[test]
    fn prepare_keeps_a_close_sent_during_startup() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let inbox = IpcInbox::new(&input);
        inbox.prepare();
        write(&input, IPC_CLOSE_SENTINEL, "");
        inbox.prepare();
        assert!(inbox.close_pending());
        assert!(inbox.take_close());
        assert!(!inbox.take_close());
        assert!(!inbox.close_pending());
        assert_eq!(inbox.dir(), input.as_path());
    }

    #[tokio::test]
    async fn wait_next_messages_close_and_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = IpcInbox::new(dir.path());
        let cancel = CancellationToken::new();
        let d = dir.path().to_path_buf();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            write(&d, "1.json", r#"{"type":"message","text":"a"}"#);
            write(&d, "2.json", r#"{"type":"message","text":"b"}"#);
        });
        let got = inbox.wait_next(Duration::from_millis(10), &cancel).await;
        writer.await.unwrap();
        assert_eq!(
            got,
            Inbound::Messages {
                text: "a\nb".into(),
                files: vec!["1.json".into(), "2.json".into()],
            }
        );

        // A message sent before `_close` is answered first.
        write(dir.path(), "3.json", r#"{"type":"message","text":"c"}"#);
        write(dir.path(), IPC_CLOSE_SENTINEL, "");
        assert_eq!(
            inbox.wait_next(Duration::from_millis(10), &cancel).await,
            Inbound::Messages {
                text: "c".into(),
                files: vec!["3.json".into()],
            }
        );
        assert_eq!(
            inbox.wait_next(Duration::from_millis(10), &cancel).await,
            Inbound::Close
        );
        assert!(!inbox.close_pending());

        cancel.cancel();
        let empty = tempfile::tempdir().unwrap();
        let inbox = IpcInbox::new(empty.path());
        assert_eq!(
            inbox.wait_next(Duration::from_millis(10), &cancel).await,
            Inbound::Cancelled
        );
    }
}
