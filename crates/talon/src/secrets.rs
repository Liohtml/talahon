//! Collect the host's secret values for the [`Redactor`].
//!
//! Every outbound chat message and every log line the host writes passes
//! through one [`Redactor`] primed with these literal values, on top of the
//! redactor's built-in detectors (bearer tokens, API-key shapes, PEM keys,
//! `password=` assignments, ...).

use std::sync::Arc;

use talon_core::env::{EnvFile, parse_env};
use talon_security::redact::Redactor;

/// Secret keys Talon itself reads (always registered when set, in `.env`
/// or the process environment).
pub const KNOWN_SECRET_KEYS: &[&str] = &[
    "TALON_VLLM_API_KEY",
    "TALON_ANTHROPIC_API_KEY",
    "HTTP_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "WEBHOOK_SECRET",
    "EMACS_AUTH_TOKEN",
    "ONECLI_API_KEY",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "OPENAI_API_KEY",
];

/// Substrings that mark any other `.env` key as secret.
const SECRET_KEY_MARKERS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE",
];

/// Whether an environment key names a secret (`*KEY*`, `*TOKEN*`,
/// `*SECRET*`, `*PASSWORD*`, ...).
pub fn is_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    KNOWN_SECRET_KEYS.contains(&upper.as_str())
        || SECRET_KEY_MARKERS.iter().any(|m| upper.contains(m))
}

/// Values that cannot be secrets (and would otherwise be scrubbed from
/// every log line): empty, numbers, booleans.
fn looks_like_secret_value(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty()
        && !v.chars().all(|c| c.is_ascii_digit() || c == '.')
        && !matches!(
            v.to_ascii_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "on" | "off"
        )
}

/// Secret values from `.env` (every key that [`is_secret_key`]) plus the
/// [`KNOWN_SECRET_KEYS`] from the process environment.
pub fn collect_secrets(env: &EnvFile) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(path) = env.path() {
        if let Ok(content) = std::fs::read_to_string(path) {
            out.extend(
                parse_env(&content)
                    .into_iter()
                    .filter(|(k, _)| is_secret_key(k))
                    .map(|(_, v)| v),
            );
        }
    }
    for key in KNOWN_SECRET_KEYS {
        if let Some(v) = env.file_value(key) {
            out.push(v.to_string());
        }
        if let Ok(v) = std::env::var(key) {
            out.push(v);
        }
    }
    out.retain(|v| looks_like_secret_value(v));
    out.sort();
    out.dedup();
    out
}

/// A shared redactor primed with [`collect_secrets`].
pub fn redactor_for(env: &EnvFile) -> Arc<Redactor> {
    Arc::new(Redactor::with_secrets(&collect_secrets(env)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_detection() {
        assert!(is_secret_key("TALON_VLLM_API_KEY"));
        assert!(is_secret_key("HTTP_API_KEY"));
        assert!(is_secret_key("MYSQL_PASSWORD"));
        assert!(is_secret_key("some_token"));
        assert!(!is_secret_key("TALON_VLLM_MODEL"));
        assert!(!is_secret_key("TZ"));
    }

    #[test]
    fn collects_secret_values_from_env_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "TALON_VLLM_API_KEY=vllm-secret-123456\nHTTP_API_KEY=http-secret-abcdef\n\
             TALON_VLLM_MODEL=qwen\nCUSTOM_DB_PASSWORD=hunter2hunter2\n\
             TALON_VLLM_MAX_TOKENS=131072\nSOME_TOKEN_REQUIRED=true\n",
        )
        .unwrap();
        let env = EnvFile::load(dir.path());
        let secrets = collect_secrets(&env);
        assert!(secrets.contains(&"vllm-secret-123456".to_string()));
        assert!(secrets.contains(&"http-secret-abcdef".to_string()));
        assert!(secrets.contains(&"hunter2hunter2".to_string()));
        assert!(!secrets.contains(&"qwen".to_string()));
        assert!(
            !secrets.contains(&"131072".to_string()),
            "numbers are not secrets"
        );
        assert!(!secrets.contains(&"true".to_string()));

        let redactor = redactor_for(&env);
        let out = redactor.redact("key is vllm-secret-123456 and model qwen");
        assert!(!out.contains("vllm-secret-123456"));
        assert!(out.contains("qwen"));
    }
}
