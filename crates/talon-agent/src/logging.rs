//! `tracing` setup: logs go to **stderr only** (stdout carries the protocol
//! frames) and every formatted line passes through the secret
//! [`Redactor`] before it is written.
//!
//! The per-run gateway token from `ContainerInput.llm.token` is registered
//! with [`register_secret`] as soon as the input is parsed, so it is redacted
//! even if some error message were to echo it.
//!
//! Filter: `TALON_LOG`, else `RUST_LOG`, else `info`.

use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use talon_security::redact::Redactor;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

static REDACTOR: LazyLock<RwLock<Arc<Redactor>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Redactor::new())));
static SECRETS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Install the global subscriber (idempotent; later calls are no-ops).
pub fn init() {
    let filter = EnvFilter::try_from_env("TALON_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(RedactingStderr)
        .with_ansi(false)
        .try_init();
}

/// Redact `secret` (literally) from every future log line. Values shorter
/// than [`talon_security::redact::MIN_SECRET_LEN`] are ignored by the
/// redactor.
pub fn register_secret(secret: &str) {
    let secret = secret.trim();
    if secret.is_empty() {
        return;
    }
    let mut secrets = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    if secrets.iter().any(|s| s == secret) {
        return;
    }
    secrets.push(secret.to_string());
    let redactor = Arc::new(Redactor::with_secrets(&secrets));
    match REDACTOR.write() {
        Ok(mut r) => *r = redactor,
        Err(p) => *p.into_inner() = redactor,
    }
}

fn current() -> Arc<Redactor> {
    match REDACTOR.read() {
        Ok(r) => Arc::clone(&r),
        Err(p) => Arc::clone(&p.into_inner()),
    }
}

/// Redact `text` with the built-in detectors plus registered secrets.
pub fn redact(text: &str) -> String {
    current().redact(text).into_owned()
}

/// [`MakeWriter`] producing [`RedactingLine`]s.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedactingStderr;

/// Buffers one formatted event and writes it, redacted, to stderr on drop.
#[derive(Debug, Default)]
pub struct RedactingLine {
    buf: Vec<u8>,
}

impl Write for RedactingLine {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for RedactingLine {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(&self.buf);
        let redacted = current().redact(&text).into_owned();
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(redacted.as_bytes());
        let _ = err.flush();
    }
}

impl<'a> MakeWriter<'a> for RedactingStderr {
    type Writer = RedactingLine;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingLine {
            buf: Vec::with_capacity(256),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_secrets_are_redacted() {
        let token = "tlgw_9f8e7d6c5b4a39281706";
        assert!(redact(&format!("token={token}")).contains("REDACTED"));
        register_secret(token);
        register_secret(token); // idempotent
        let out = redact(&format!("calling gateway with {token} now"));
        assert!(!out.contains(token), "{out}");
        register_secret("   ");
    }

    #[test]
    fn line_writer_buffers() {
        let mut w = RedactingStderr.make_writer();
        w.write_all(b"hello ").unwrap();
        w.write_all(b"world\n").unwrap();
        w.flush().unwrap();
        assert_eq!(w.buf, b"hello world\n");
        w.buf.clear();
    }
}
