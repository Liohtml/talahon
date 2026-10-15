//! Structured logging: `tracing-subscriber` with an `EnvFilter`
//! (`RUST_LOG`), human-readable or JSON output (`TALON_LOG_FORMAT=json`),
//! and **redaction of every line** before it reaches the terminal or the
//! service log file.
//!
//! The fmt layer formats one event into a buffer and writes it with a single
//! `write_all`; [`RedactingWriter`] collects that buffer and, when the
//! writer is dropped (end of the event), passes the text through the shared
//! [`Redactor`] and writes it to stdout/stderr in one locked write.

use std::io::{self, Write};
use std::sync::Arc;

use talon_security::redact::Redactor;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Output format of log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable lines.
    Pretty,
    /// One JSON object per line.
    Json,
}

impl LogFormat {
    /// `json` (case-insensitive) => [`LogFormat::Json`], anything else pretty.
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("json") => LogFormat::Json,
            _ => LogFormat::Pretty,
        }
    }
}

/// Where log lines go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTarget {
    /// stdout (the service log file under launchd/systemd).
    Stdout,
    /// stderr (CLI commands: stdout carries their machine-readable output).
    Stderr,
}

/// [`MakeWriter`] that redacts every event before writing it.
#[derive(Clone)]
pub struct RedactingMakeWriter {
    redactor: Arc<Redactor>,
    target: LogTarget,
}

impl RedactingMakeWriter {
    /// Writer factory for `target` using `redactor`.
    pub fn new(redactor: Arc<Redactor>, target: LogTarget) -> Self {
        Self { redactor, target }
    }
}

impl<'a> MakeWriter<'a> for RedactingMakeWriter {
    type Writer = RedactingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            buf: Vec::with_capacity(256),
            redactor: Arc::clone(&self.redactor),
            sink: Sink::Std(self.target),
        }
    }
}

enum Sink {
    Std(LogTarget),
    #[cfg(test)]
    Memory(Arc<std::sync::Mutex<Vec<u8>>>),
}

/// Buffers one formatted event; redacts and writes it on drop.
pub struct RedactingWriter {
    buf: Vec<u8>,
    redactor: Arc<Redactor>,
    sink: Sink,
}

impl RedactingWriter {
    #[cfg(test)]
    fn memory(redactor: Arc<Redactor>, out: Arc<std::sync::Mutex<Vec<u8>>>) -> Self {
        Self {
            buf: Vec::new(),
            redactor,
            sink: Sink::Memory(out),
        }
    }

    fn emit(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(&self.buf);
        let redacted = self.redactor.redact(&text);
        let bytes = redacted.as_bytes();
        // Logging must never fail the caller: write errors are dropped.
        match &self.sink {
            Sink::Std(LogTarget::Stdout) => {
                let _ = io::stdout().lock().write_all(bytes);
            }
            Sink::Std(LogTarget::Stderr) => {
                let _ = io::stderr().lock().write_all(bytes);
            }
            #[cfg(test)]
            Sink::Memory(out) => {
                if let Ok(mut out) = out.lock() {
                    out.extend_from_slice(bytes);
                }
            }
        }
        self.buf.clear();
    }
}

impl Write for RedactingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RedactingWriter {
    fn drop(&mut self) {
        self.emit();
    }
}

/// Install the global subscriber. `default_filter` applies when `RUST_LOG`
/// is unset or invalid. Calling it twice is harmless (the second call is
/// ignored).
pub fn init(format: LogFormat, target: LogTarget, default_filter: &str, redactor: Arc<Redactor>) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_filter))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let writer = RedactingMakeWriter::new(redactor, target);
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_target(true);
    let result = match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .try_init(),
        LogFormat::Pretty => builder.with_ansi(false).try_init(),
    };
    if let Err(e) = result {
        eprintln!("talon: logging already initialized: {e}");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn format_parsing() {
        assert_eq!(LogFormat::parse(Some("json")), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some(" JSON ")), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some("text")), LogFormat::Pretty);
        assert_eq!(LogFormat::parse(None), LogFormat::Pretty);
    }

    #[test]
    fn writer_redacts_registered_secrets_and_builtin_patterns() {
        let redactor = Arc::new(Redactor::with_secrets(&["sup3r-s3cret-value".to_string()]));
        let out = Arc::new(Mutex::new(Vec::new()));
        {
            let mut w = RedactingWriter::memory(redactor, Arc::clone(&out));
            w.write_all(b"token=sup3r-s3cret-value ").unwrap();
            w.write_all(b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\n")
                .unwrap();
        }
        let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert!(!text.contains("sup3r-s3cret-value"), "{text}");
        assert!(
            !text.contains("abcdefghijklmnopqrstuvwxyz0123456789"),
            "{text}"
        );
        assert!(text.contains("REDACTED"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn subscriber_events_pass_through_the_redactor() {
        let redactor = Arc::new(Redactor::with_secrets(&["leaky-api-key-42".to_string()]));
        let out = Arc::new(Mutex::new(Vec::new()));
        let make = {
            let out = Arc::clone(&out);
            let redactor = Arc::clone(&redactor);
            move || RedactingWriter::memory(Arc::clone(&redactor), Arc::clone(&out))
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(make)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(key = "leaky-api-key-42", "connecting with leaky-api-key-42");
        });
        let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert!(text.contains("connecting with"), "{text}");
        assert!(!text.contains("leaky-api-key-42"), "{text}");
    }
}
