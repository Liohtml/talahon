//! Secret redaction for logs, audit details and outbound messages.
//!
//! Built-in detectors: bearer/JWT tokens, `sk-...`/`hf_...`/`ghp_...`/
//! `xox[bpa]-...`/AWS access keys (`AKIA...`), PEM private keys,
//! `password=`/`api_key=`/`secret=`/`token=` assignments, basic-auth URLs
//! (`https://user:pass@host`), plus any exact secret values registered via
//! [`Redactor::with_secrets`] (e.g. the vLLM key, HTTP API key, bot tokens).

use std::borrow::Cow;

#[derive(Debug, Clone, Default)]
pub struct Redactor {
    #[allow(dead_code)]
    secrets: Vec<String>,
}

#[allow(unused_variables, clippy::todo)]
impl Redactor {
    pub fn new() -> Self {
        todo!()
    }
    /// Also redact these literal values (ignores values shorter than 6 chars).
    pub fn with_secrets(secrets: &[String]) -> Self {
        todo!()
    }
    /// Replace every detected secret with `[REDACTED:<kind>]`.
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        todo!()
    }
    /// Redact all string leaves of a JSON value in place.
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        todo!()
    }
}
