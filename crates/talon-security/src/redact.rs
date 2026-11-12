//! Secret redaction for logs, audit details and outbound messages.
//!
//! Built-in detectors: bearer/JWT tokens, `sk-...`/`hf_...`/`ghp_...`/
//! `xox[bpa]-...`/AWS access keys (`AKIA...`), PEM private keys,
//! `password=`/`api_key=`/`secret=`/`token=` assignments, basic-auth URLs
//! (`https://user:pass@host`), plus any exact secret values registered via
//! [`Redactor::with_secrets`] (e.g. the vLLM key, HTTP API key, bot tokens).
//!
//! Replacements keep enough context to stay readable:
//! `Authorization: Bearer [REDACTED:bearer]`, `password=[REDACTED:password]`,
//! `https://alice:[REDACTED:url_password]@host/`.
//!
//! Deliberately **not** redacted: hex digests (MD5/SHA*), GUIDs, base64 blobs
//! without a credential context, IP addresses — a SOC assistant must keep
//! those intact.

use std::borrow::Cow;
use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use regex::{Captures, Regex};

/// Minimum length of a literal secret registered via [`Redactor::with_secrets`].
pub const MIN_SECRET_LEN: usize = 6;

/// Maximum nesting depth walked by [`Redactor::redact_json`]; deeper
/// subtrees are replaced wholesale (fail closed).
const MAX_JSON_DEPTH: usize = 256;

/// Compile a built-in pattern. The patterns are static literals covered by
/// the unit tests, so construction cannot fail at runtime.
///
/// Word boundaries are made ASCII-only (`(?-u:\b)`) so the DFA engines stay
/// usable on non-ASCII text (Unicode `\b` forces the much slower PikeVM).
fn re(pattern: &str) -> Regex {
    #[allow(clippy::expect_used)]
    Regex::new(&pattern.replace(r"\b", r"(?-u:\b)")).expect("static redaction regex")
}

/// A PEM private key: the whole block when its `-----END` line is present,
/// else only the header (the key material after it is found by
/// [`unterminated_pem_len`]).
static PEM_PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)?",
    )
});

static URL_CREDENTIALS: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b([a-z][a-z0-9+.-]{0,30}://)([^/\s:@?#\[\]]+):([^/\s@?#]+)@"));

static JWT: LazyLock<Regex> =
    LazyLock::new(|| re(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"));

/// Scheme words of an `Authorization` header.
const AUTH_SCHEMES: &str = "bearer|basic|token|digest|negotiate|ntlm|apikey";

/// Whether `word` is one of [`AUTH_SCHEMES`].
fn is_auth_scheme(word: &str) -> bool {
    AUTH_SCHEMES
        .split('|')
        .any(|scheme| scheme.eq_ignore_ascii_case(word))
}

/// `Authorization: <scheme> <credential>` (header or JSON/quoted forms).
/// The credential cannot start with `=`: in `Authorization: apikey = <value>`
/// the `=` belongs to an `apikey = ...` assignment, not to a scheme. Repeated
/// scheme words (`Authorization: Token Bearer <credential>`) belong to the
/// prefix, so the first one cannot take the second as its credential.
static AUTH_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r#"(?i)(\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?({AUTH_SCHEMES})\s+(?:(?:{AUTH_SCHEMES})\s+)*)([A-Za-z0-9\-._~+/][A-Za-z0-9\-._~+/=]*)"#
    ))
});

/// Free-standing `Bearer <token>` (outside an Authorization header).
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(bearer\s+)([A-Za-z0-9\-._~+/]{8,}=*)"));

/// Free-standing `Basic <base64(user:pass)>`; verified by decoding.
static BASIC: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b(basic\s+)([A-Za-z0-9+/]{6,}={0,2})"));

/// Well-known token shapes: `(regex, kind)`.
static TOKEN_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        // Anthropic / OpenAI / generic `sk-` keys (sk-proj-..., sk-ant-api03-...)
        (re(r"\bsk-[A-Za-z0-9_-]{20,}"), "api_key"),
        // Stripe-style live/test keys
        (re(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"), "api_key"),
        // Hugging Face
        (re(r"\bhf_[A-Za-z0-9]{30,}"), "hf_token"),
        // GitHub classic + fine-grained
        (re(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), "github_token"),
        (re(r"\bgithub_pat_[A-Za-z0-9_]{50,}"), "github_token"),
        // GitLab
        (re(r"\bglpat-[A-Za-z0-9_-]{20,}"), "gitlab_token"),
        // Slack
        (re(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "slack_token"),
        (re(r"\bxapp-\d-[A-Za-z0-9-]{10,}"), "slack_token"),
        // AWS access key ids
        (
            re(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
            "aws_access_key",
        ),
        // Google API keys
        (re(r"\bAIza[0-9A-Za-z_-]{35}"), "google_api_key"),
        // Telegram bot tokens (also inside api.telegram.org/bot<token>/ URLs)
        (
            re(r"\b(?:bot)?\d{8,10}:AA[A-Za-z0-9_-]{33}"),
            "telegram_token",
        ),
        // npm
        (re(r"\bnpm_[A-Za-z0-9]{36}"), "npm_token"),
    ]
});

/// Key of a sensitive assignment: the keyword must end the key (so
/// `TokenElevationType=%%1936` or `PasswordLastSet: ...` from Windows events
/// are left alone).
const ASSIGNMENT_KEY: &str = r"[a-z0-9_.-]{0,40}?(?:password|passwd|passphrase|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|bot[_-]?token|client[_-]?secret|token|credentials?)s?";

/// Value of an assignment: double-quoted, single-quoted, bare, or a
/// double-quoted string that is cut off.
const ASSIGNMENT_VALUE: &str =
    r#""(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|[^\s,;&"'<>{}\[\]()]+|"[^"\r\n]+"#;

/// `key = value` / `"key": "value"` assignments with a sensitive key name.
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r#"(?i)\b({ASSIGNMENT_KEY})(["']?\s{{0,4}}(?:=|:)\s{{0,4}})({ASSIGNMENT_VALUE})"#
    ))
});

/// An assignment "value" that is itself a sensitive key: `password:` in
/// `credentials:\n  password: hunter2` / `token: password: hunter2`
/// (group 1: the separator came with it) or `"password"` in
/// `token = "password": "hunter2"`.
static NESTED_KEY: LazyLock<Regex> =
    LazyLock::new(|| re(&format!(r#"(?i)^["']?{ASSIGNMENT_KEY}["']?([=:])?$"#)));

/// The value after a [`NESTED_KEY`] that came with its separator.
static NESTED_VALUE: LazyLock<Regex> =
    LazyLock::new(|| re(&format!(r"^(\s{{0,4}})({ASSIGNMENT_VALUE})")));

/// Separator and value after a [`NESTED_KEY`] that came without one.
static NESTED_SEP_VALUE: LazyLock<Regex> =
    LazyLock::new(|| re(&format!(r"^(\s{{0,4}}[=:]\s{{0,4}})({ASSIGNMENT_VALUE})")));

/// Sensitive JSON object keys (whole-key match).
static SENSITIVE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^[a-z0-9_.-]{0,40}?(?:password|passwd|passphrase|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|bot[_-]?token|client[_-]?secret|token|credentials?|authorization|cookie)s?$",
    )
});

/// Values that are obviously not secrets and stay readable.
fn is_placeholder_value(v: &str) -> bool {
    let v = v.trim_matches(|c| c == '"' || c == '\'').trim();
    v.is_empty()
        || v.starts_with("[REDACTED")
        || v.starts_with('$')
        || v.starts_with('<')
        || v.chars()
            .all(|c| c == '*' || c == 'x' || c == 'X' || c == '.')
        || matches!(
            v.to_ascii_lowercase().as_str(),
            "null" | "none" | "nil" | "true" | "false" | "undefined" | "redacted" | "-" | "n/a"
        )
}

/// Keys that end in a sensitive keyword but are not secrets: .NET
/// `PublicKeyToken=31bf3856ad364e35` (ubiquitous in Windows telemetry) and
/// token *counts* such as `max_tokens` / `prompt_tokens`.
fn is_exempt_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.ends_with("publickeytoken") || k.ends_with("tokens")
}

/// Does `token` look like a random credential rather than an English word?
fn looks_random(token: &str) -> bool {
    let t = token.trim_end_matches('=');
    if t.len() < 8 {
        return false;
    }
    let digits = t.chars().filter(char::is_ascii_digit).count();
    let lower = t.chars().filter(char::is_ascii_lowercase).count();
    let upper = t.chars().filter(char::is_ascii_uppercase).count();
    let symbols = t.chars().filter(|c| "-._~+/".contains(*c)).count();
    let classes = [digits, lower, upper, symbols]
        .iter()
        .filter(|n| **n > 0)
        .count();
    (t.len() >= 16 && classes >= 2) || (digits > 0 && classes >= 2) || t.len() >= 32
}

/// Redacts secrets from free text and JSON.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    /// Literal secret values (deduplicated, longest first).
    secrets: Vec<String>,
    /// Automaton over `secrets` (leftmost-longest); `None` when empty.
    matcher: Option<AhoCorasick>,
}

impl Redactor {
    /// Redactor with only the built-in detectors.
    pub fn new() -> Self {
        Self::default()
    }

    /// Also redact these literal values (ignores values shorter than 6 chars).
    pub fn with_secrets(secrets: &[String]) -> Self {
        let mut list: Vec<String> = secrets
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| s.chars().count() >= MIN_SECRET_LEN)
            .collect();
        list.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        list.dedup();
        let matcher = if list.is_empty() {
            None
        } else {
            match AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&list)
            {
                Ok(m) => Some(m),
                Err(e) => {
                    tracing::error!(error = %e, "redactor: cannot build secret matcher");
                    None
                }
            }
        };
        Self {
            secrets: list,
            matcher,
        }
    }

    /// Number of literal secrets registered.
    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    /// Replace every detected secret with `[REDACTED:<kind>]`.
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut out: Cow<'a, str> = Cow::Borrowed(text);

        // 1. Exact registered secrets (most precise first).
        if let Some(m) = self.matcher.as_ref().filter(|m| m.is_match(out.as_ref())) {
            let replacements = vec!["[REDACTED:secret]"; m.patterns_len()];
            match m.try_replace_all(out.as_ref(), &replacements) {
                Ok(replaced) => out = Cow::Owned(replaced),
                Err(e) => {
                    // Unreachable with the default automaton; fail closed.
                    tracing::error!(error = %e, "redactor: secret matcher failed");
                    return Cow::Owned("[REDACTED:unavailable]".to_string());
                }
            }
        }

        // 2. PEM private keys (multi-line).
        redact_pem(&mut out);

        // 3. Credentials embedded in URLs.
        apply(&mut out, &URL_CREDENTIALS, |c| {
            // Already redacted by an earlier call: keep its label.
            if c[3].starts_with("[REDACTED:") {
                return c[0].to_string();
            }
            format!("{}{}:[REDACTED:url_password]@", &c[1], &c[2])
        });

        // 4. JWTs.
        apply(&mut out, &JWT, |_| "[REDACTED:jwt]".to_string());

        // 5. Authorization headers (any scheme).
        apply_resuming(&mut out, &AUTH_HEADER, 3, |c, rest| {
            // A lone scheme word is not a credential (it would also make a
            // second pass redact differently from the first), and neither is
            // the head of another credential.
            if is_auth_scheme(&c[3]) || is_credential_head(&c[3], rest) {
                return None;
            }
            Some(format!("{}[REDACTED:{}]", &c[1], auth_kind(&c[2])))
        });

        // 6. Free-standing bearer tokens.
        apply_resuming(&mut out, &BEARER, 2, |c, rest| {
            if is_credential_head(&c[2], rest) || !looks_random(&c[2]) {
                return None;
            }
            Some(format!("{}[REDACTED:bearer]", &c[1]))
        });

        // 7. Free-standing basic credentials (must decode to `user:pass`).
        apply(&mut out, &BASIC, |c| {
            if decodes_to_userpass(&c[2]) {
                format!("{}[REDACTED:basic_auth]", &c[1])
            } else {
                c[0].to_string()
            }
        });

        // 8. Vendor token shapes.
        for (pattern, kind) in TOKEN_PATTERNS.iter() {
            apply(&mut out, pattern, |_| format!("[REDACTED:{kind}]"));
        }

        // 9. key=value assignments.
        redact_assignments(&mut out);

        out
    }

    /// Redact all string leaves of a JSON value in place.
    ///
    /// Object members whose *key* names a secret (`password`, `api_key`,
    /// `token`, `authorization`, ...) have their string value replaced
    /// entirely. Subtrees nested deeper than an internal limit are replaced
    /// with `"[REDACTED:too_deep]"` (fail closed, no recursion overflow).
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        use serde_json::Value;
        // Iterative walk: (node, depth).
        let mut stack: Vec<(&mut Value, usize)> = vec![(value, 0)];
        while let Some((node, depth)) = stack.pop() {
            if depth > MAX_JSON_DEPTH {
                let old = std::mem::replace(node, Value::String("[REDACTED:too_deep]".to_string()));
                drop_iteratively(old);
                continue;
            }
            match node {
                Value::String(s) => {
                    if let Cow::Owned(new) = self.redact(s) {
                        *s = new;
                    }
                }
                Value::Array(items) => {
                    for item in items.iter_mut() {
                        stack.push((item, depth + 1));
                    }
                }
                Value::Object(map) => {
                    for (key, v) in map.iter_mut() {
                        if SENSITIVE_KEY.is_match(key)
                            && !is_exempt_key(key)
                            && let Value::String(s) = &mut *v
                        {
                            if !is_placeholder_value(s) {
                                *s = format!("[REDACTED:{}]", assignment_kind(key));
                            }
                            continue;
                        }
                        stack.push((v, depth + 1));
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
        }
    }
}

/// Drop a JSON tree without recursion (deeply nested values would otherwise
/// overflow the stack in `Drop`).
fn drop_iteratively(value: serde_json::Value) {
    use serde_json::Value;
    let mut stack = vec![value];
    while let Some(mut v) = stack.pop() {
        match &mut v {
            Value::Array(items) => stack.append(items),
            Value::Object(map) => {
                let map = std::mem::take(map);
                stack.extend(map.into_iter().map(|(_, v)| v));
            }
            _ => {}
        }
    }
}

/// Run one regex replacement pass, allocating only when something matched.
fn apply<F>(text: &mut Cow<'_, str>, pattern: &Regex, f: F)
where
    F: Fn(&Captures<'_>) -> String,
{
    if !pattern.is_match(text.as_ref()) {
        return;
    }
    let replaced = pattern.replace_all(text.as_ref(), |c: &Captures<'_>| f(c));
    if let Cow::Owned(s) = replaced {
        *text = Cow::Owned(s);
    }
}

/// Like [`apply`], but `f` also gets the text after the match, and a match
/// it declines (`None`) is not stepped over: the search resumes at the start
/// of capture group `resume`, the would-be credential, which may itself
/// start a credential the pattern (or a later pass) has to see.
fn apply_resuming<F>(text: &mut Cow<'_, str>, pattern: &Regex, resume: usize, f: F)
where
    F: Fn(&Captures<'_>, &str) -> Option<String>,
{
    if !pattern.is_match(text.as_ref()) {
        return;
    }
    let src = text.as_ref();
    let mut out = String::with_capacity(src.len());
    // `src[..copied]` is in `out`; the search continues at `at >= copied`.
    let (mut copied, mut at) = (0usize, 0usize);
    while at <= src.len() {
        let Some(c) = pattern.captures_at(src, at) else {
            break;
        };
        let Some(whole) = c.get(0) else { break };
        if let Some(replacement) = f(&c, &src[whole.end()..]) {
            out.push_str(&src[copied..whole.start()]);
            out.push_str(&replacement);
            copied = whole.end();
            at = whole.end();
        } else {
            // Past the start of this match, so the loop always ends.
            let next = c.get(resume).map_or(whole.end(), |g| g.start());
            at = next.max(whole.start() + 1);
            while !src.is_char_boundary(at) {
                at += 1;
            }
        }
    }
    if copied == 0 {
        return;
    }
    out.push_str(&src[copied..]);
    *text = Cow::Owned(out);
}

/// Whether a would-be credential, given the text after it, is really the
/// head of another credential syntax: a sensitive assignment key or an
/// `Authorization` header name, with its separator (`password: ...`,
/// `AWS_SECRET_ACCESS_KEY=...`, `Authorization: ...`). Redacting it would
/// hide that key from the pass that redacts its value. Anything else is a
/// credential, whatever punctuation follows it.
fn is_credential_head(candidate: &str, rest: &str) -> bool {
    let name = candidate.trim_end_matches('=');
    let separated = name.len() < candidate.len()
        || rest.trim_start_matches([' ', '\t']).starts_with([':', '=']);
    separated
        && (NESTED_KEY.is_match(name)
            || name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization"))
}

/// Replace PEM private keys. A block without its `-----END` line (a
/// truncated log line) is redacted as far as the text after the header
/// looks like key material.
fn redact_pem(text: &mut Cow<'_, str>) {
    if !PEM_PRIVATE_KEY.is_match(text.as_ref()) {
        return;
    }
    let src = text.as_ref();
    let mut out = String::with_capacity(src.len());
    let mut copied = 0usize;
    for m in PEM_PRIVATE_KEY.find_iter(src) {
        if m.start() < copied {
            // Inside the key material of the previous, unterminated block.
            continue;
        }
        let terminated = m.as_str().len() > 11 && m.as_str()[11..].contains("-----END ");
        let end = if terminated {
            m.end()
        } else {
            m.end() + unterminated_pem_len(&src[m.end()..])
        };
        out.push_str(&src[copied..m.start()]);
        out.push_str("[REDACTED:private_key]");
        copied = end;
    }
    out.push_str(&src[copied..]);
    *text = Cow::Owned(out);
}

/// Shortest base64 run that counts as key material when other text is
/// glued to it (`MIIEvQIBADANBgkqhkiG9w0"}`).
const MIN_GLUED_KEY_RUN: usize = 16;

/// Length of the key material after a PEM header that has no end marker.
///
/// Whitespace-separated words are taken while they consist of base64
/// characters only, plus the RFC 1421 header lines (`Proc-Type:`,
/// `DEK-Info:`). The scan stops at the first word that is anything else
/// and never inside one: taking the `api` of `api_key=<value>` or the
/// `password` of `password: <value>` would leave a value no later pass
/// recognises. Only a long base64 run is taken out of a longer word.
fn unterminated_pem_len(rest: &str) -> usize {
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=');
    let mut end = 0usize;
    let mut pos = 0usize;
    loop {
        let word_start = pos + rest[pos..].len() - rest[pos..].trim_start().len();
        let word = rest[word_start..]
            .split(char::is_whitespace)
            .next()
            .unwrap_or_default();
        if word.is_empty() {
            // Trailing whitespace belongs to the block.
            return rest.len();
        }
        if word.starts_with("Proc-Type:") || word.starts_with("DEK-Info:") {
            let line = rest[word_start..]
                .find('\n')
                .unwrap_or(rest.len() - word_start);
            pos = word_start + line;
            end = pos;
            continue;
        }
        let run = word.find(|c| !is_b64(c)).unwrap_or(word.len());
        if is_credential_head(&word[..run], &rest[word_start + run..]) {
            // `password = <value>` after the header: not key material.
            return end;
        }
        if run == word.len() {
            pos = word_start + word.len();
            end = pos;
            continue;
        }
        if run >= MIN_GLUED_KEY_RUN {
            end = word_start + run;
        }
        return end;
    }
}

/// Redact the values of `key = value` assignments with a sensitive key.
///
/// A plain `replace_all` is not enough: the "value" of one assignment can
/// be the key of the assignment that carries the secret
/// (`credentials:\n  password: hunter2`, `token: password: hunter2`,
/// `max_tokens = password=hunter2`), and the regex would step over that
/// inner assignment. So
/// - when a match is left alone (placeholder value, exempt key), the search
///   resumes at its value instead of after it, and
/// - when a redacted value was itself a sensitive key, the value that
///   follows it is redacted as well.
fn redact_assignments(text: &mut Cow<'_, str>) {
    if !ASSIGNMENT.is_match(text.as_ref()) {
        return;
    }
    let src = text.as_ref();
    let mut out = String::with_capacity(src.len());
    // `src[..copied]` is in `out`; the search continues at `at >= copied`.
    let (mut copied, mut at) = (0usize, 0usize);
    while let Some(c) = ASSIGNMENT.captures_at(src, at) {
        let (Some(whole), Some(key), Some(value)) = (c.get(0), c.get(1), c.get(3)) else {
            break;
        };
        if is_placeholder_value(value.as_str()) || is_exempt_key(key.as_str()) {
            at = value.start();
            continue;
        }
        out.push_str(&src[copied..value.start()]);
        push_redacted_value(&mut out, value.as_str(), assignment_kind(key.as_str()));
        at = whole.end();
        copied = at;

        let mut nested_key = value.as_str();
        while let Some(key_shape) = NESTED_KEY.captures(nested_key) {
            let follows = if key_shape.get(1).is_some() {
                &*NESTED_VALUE
            } else {
                &*NESTED_SEP_VALUE
            };
            let Some(inner) = follows.captures(&src[at..]) else {
                break;
            };
            let (Some(whole), Some(gap), Some(inner_value)) =
                (inner.get(0), inner.get(1), inner.get(2))
            else {
                break;
            };
            out.push_str(gap.as_str());
            push_redacted_value(&mut out, inner_value.as_str(), assignment_kind(nested_key));
            at += whole.len();
            copied = at;
            nested_key = inner_value.as_str();
        }
    }
    if copied > 0 {
        out.push_str(&src[copied..]);
        *text = Cow::Owned(out);
    }
}

/// Append `[REDACTED:<kind>]` in place of `value`, keeping its quotes.
fn push_redacted_value(out: &mut String, value: &str, kind: &str) {
    let quote = match value.chars().next() {
        Some(q @ ('"' | '\'')) if value.len() >= 2 && value.ends_with(q) => Some(q),
        _ => None,
    };
    out.extend(quote);
    out.push_str("[REDACTED:");
    out.push_str(kind);
    out.push(']');
    out.extend(quote);
}

fn auth_kind(scheme: &str) -> &'static str {
    match scheme.to_ascii_lowercase().as_str() {
        "bearer" => "bearer",
        "basic" => "basic_auth",
        _ => "authorization",
    }
}

fn assignment_kind(key: &str) -> &'static str {
    let k = key.to_ascii_lowercase();
    if k.contains("pass") {
        "password"
    } else if k.contains("private") {
        "private_key"
    } else if k.contains("key") {
        "api_key"
    } else if k.contains("token")
        || k.contains("authorization")
        || k.contains("cookie")
        || k.contains("session")
    {
        "token"
    } else if k.contains("credential") {
        "credentials"
    } else {
        "secret"
    }
}

fn decodes_to_userpass(b64: &str) -> bool {
    STANDARD
        .decode(b64.as_bytes())
        .ok()
        .and_then(|raw| String::from_utf8(raw).ok())
        .is_some_and(|s| s.contains(':') && s.len() >= 3 && !s.chars().any(char::is_control))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn r(text: &str) -> String {
        Redactor::new().redact(text).into_owned()
    }

    /// Secret-shaped fixtures are assembled at runtime so that no source
    /// literal trips repository secret scanners (push protection).
    fn cat(parts: &[&str]) -> String {
        parts.concat()
    }

    /// `-----BEGIN <label>-----` / `-----END <label>-----` built at runtime.
    fn pem_line(edge: &str, label: &str) -> String {
        format!("{d}{edge} {label}{d}", d = "-----")
    }

    #[test]
    fn all_static_patterns_compile() {
        LazyLock::force(&PEM_PRIVATE_KEY);
        LazyLock::force(&URL_CREDENTIALS);
        LazyLock::force(&JWT);
        LazyLock::force(&AUTH_HEADER);
        LazyLock::force(&BEARER);
        LazyLock::force(&BASIC);
        LazyLock::force(&TOKEN_PATTERNS);
        LazyLock::force(&ASSIGNMENT);
        LazyLock::force(&SENSITIVE_KEY);
    }

    #[test]
    fn untouched_text_is_borrowed() {
        let red = Redactor::new();
        let text = "Process C:\\Windows\\System32\\cmd.exe started by CORP\\alice";
        assert!(matches!(red.redact(text), Cow::Borrowed(_)));
    }

    #[test]
    fn literal_secrets() {
        let red = Redactor::with_secrets(&["supersecretvalue".into(), "short".into(), "  ".into()]);
        assert_eq!(red.secret_count(), 1);
        assert_eq!(
            red.redact("key is supersecretvalue!").as_ref(),
            "key is [REDACTED:secret]!"
        );
        // short values are ignored
        assert_eq!(red.redact("short").as_ref(), "short");
    }

    #[test]
    fn literal_secrets_longest_wins() {
        let red = Redactor::with_secrets(&["abcdef".into(), "abcdefghij".into()]);
        assert_eq!(
            red.redact("x abcdefghij y").as_ref(),
            "x [REDACTED:secret] y"
        );
    }

    #[test]
    fn bearer_header_keeps_scheme() {
        assert_eq!(
            r("Authorization: Bearer abc.def-ghi_123"),
            "Authorization: Bearer [REDACTED:bearer]"
        );
        assert_eq!(
            r(r#"{"authorization":"Bearer abcdef123456"}"#),
            r#"{"authorization":"Bearer [REDACTED:bearer]"}"#
        );
    }

    #[test]
    fn freestanding_bearer_requires_random_token() {
        assert_eq!(
            r("curl -H 'X: Bearer f8a9Z0q1w2e3r4t5y6u7'"),
            "curl -H 'X: Bearer [REDACTED:bearer]'"
        );
        // ordinary English is left alone
        let prose = "the bearer instruments were sold";
        assert_eq!(r(prose), prose);
    }

    #[test]
    fn basic_auth_header_and_freestanding() {
        let header = cat(&["Authorization: Basic ", "dXNlcjpw", "YXNzd29yZA=="]);
        assert_eq!(r(&header), "Authorization: Basic [REDACTED:basic_auth]");
        let free = cat(&["send Basic ", "dXNlcjpw", "YXNz now"]);
        assert_eq!(r(&free), "send Basic [REDACTED:basic_auth] now");
        let prose = "a basic understanding of networking";
        assert_eq!(r(prose), prose);
    }

    #[test]
    fn jwt() {
        let jwt = cat(&[
            "eyJ",
            "hbGciOiJIUzI1NiJ9",
            ".",
            "eyJ",
            "zdWIiOiIxMjM0NTY3ODkwIn0",
            ".",
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ]);
        assert_eq!(r(&format!("token {jwt} end")), "token [REDACTED:jwt] end");
    }

    #[test]
    fn vendor_tokens() {
        let alpha = "abcdefghijklmnopqrstuvwxyz";
        assert_eq!(
            r(&cat(&["sk", "-proj-", alpha, "012345"])),
            "[REDACTED:api_key]"
        );
        assert_eq!(
            r(&cat(&["sk", "-ant-api03-", "AbCdEfGhIjKlMnOpQrStUv"])),
            "[REDACTED:api_key]"
        );
        assert_eq!(
            r(&cat(&["hf", "_", alpha, "ABCDEFGH"])),
            "[REDACTED:hf_token]"
        );
        assert_eq!(
            r(&cat(&["gh", "p_", alpha, "ABCDEFGHIJ"])),
            "[REDACTED:github_token]"
        );
        assert_eq!(
            r(&cat(&["xo", "xb-", "123456789012-", "abcdefghijkl"])),
            "[REDACTED:slack_token]"
        );
        assert_eq!(
            r(&cat(&["xo", "xp-", "123456789012-", "abcdefghijkl"])),
            "[REDACTED:slack_token]"
        );
        assert_eq!(
            r(&cat(&["id ", "AK", "IA", "IOSFODNN7", "EXAMPLE", " ok"])),
            "id [REDACTED:aws_access_key] ok"
        );
        assert_eq!(
            r(&cat(&[
                "https://api.telegram.org/bot",
                "123456789",
                ":AA",
                "HdqTcvCH1vGWJxfSeofSAs0K5PALDsaw0",
                "/getMe"
            ])),
            "https://api.telegram.org/[REDACTED:telegram_token]/getMe"
        );
        assert_eq!(
            r(&cat(&[
                "AI",
                "za",
                "SyA1234567890",
                "abcdefghijklmnopqrstuv"
            ])),
            "[REDACTED:google_api_key]"
        );
    }

    #[test]
    fn pem_private_key() {
        let rsa = "RSA PRIVATE KEY";
        let pem = format!(
            "before\n{}\nMIIEowIBAAKCAQEA\nabc+/=\n{}\nafter",
            pem_line("BEGIN", rsa),
            pem_line("END", rsa)
        );
        assert_eq!(r(&pem), "before\n[REDACTED:private_key]\nafter");
        let ossh = "OPENSSH PRIVATE KEY";
        let openssh = format!(
            "{}\nb3BlbnNzaC1rZXktdjEAAAAA\n{}",
            pem_line("BEGIN", ossh),
            pem_line("END", ossh)
        );
        assert_eq!(r(&openssh), "[REDACTED:private_key]");
        // truncated key (no END line) is still redacted
        let trunc = format!("x {}\nMIIEvQIBADANBg", pem_line("BEGIN", "PRIVATE KEY"));
        assert_eq!(r(&trunc), "x [REDACTED:private_key]");
        // public keys / certificates are not secrets
        let cert = format!(
            "{}\nMIIB\n{}",
            pem_line("BEGIN", "CERTIFICATE"),
            pem_line("END", "CERTIFICATE")
        );
        assert_eq!(r(&cert), cert);
    }

    #[test]
    fn assignments() {
        assert_eq!(r("password=hunter2"), "password=[REDACTED:password]");
        assert_eq!(
            r("db_password: hunter2 x"),
            "db_password: [REDACTED:password] x"
        );
        assert_eq!(
            r("api_key=abc123&user=bob"),
            "api_key=[REDACTED:api_key]&user=bob"
        );
        assert_eq!(
            r("TALON_VLLM_API_KEY=abcdef"),
            "TALON_VLLM_API_KEY=[REDACTED:api_key]"
        );
        assert_eq!(
            r("client_secret = 'abc def'"),
            "client_secret = '[REDACTED:secret]'"
        );
        assert_eq!(
            r(r#"{"password":"p@ss \"quoted\"","user":"bob"}"#),
            r#"{"password":"[REDACTED:password]","user":"bob"}"#
        );
        assert_eq!(r("?token=abc123def"), "?token=[REDACTED:token]");
        assert_eq!(
            r("TELEGRAM_BOT_TOKEN=xyz987"),
            "TELEGRAM_BOT_TOKEN=[REDACTED:token]"
        );
    }

    #[test]
    fn assignments_leave_placeholders_and_windows_fields() {
        for keep in [
            "password=",
            "password: null",
            "token: ${TOKEN}",
            "secret=***",
            "password: [REDACTED]",
            "TokenElevationType=%%1936",
            "PasswordLastSet: 12/1/2020",
            "KeyLength: 0",
            "Token Elevation Type: TokenElevationTypeDefault (1)",
        ] {
            assert_eq!(r(keep), keep, "{keep}");
        }
    }

    #[test]
    fn auth_header_json_does_not_swallow_siblings() {
        assert_eq!(
            r(r#"{"authorization":"Bearer abc123","user":"bob"}"#),
            r#"{"authorization":"Bearer [REDACTED:bearer]","user":"bob"}"#
        );
    }

    #[test]
    fn exempt_keys_and_unterminated_quotes() {
        let net = "System.Management.Automation, PublicKeyToken=31bf3856ad364e35";
        assert_eq!(r(net), net);
        assert_eq!(
            r("max_tokens=4096 prompt_tokens: 12"),
            "max_tokens=4096 prompt_tokens: 12"
        );
        assert_eq!(r("password=\"hunter2"), "password=[REDACTED:password]");
        let mut v = serde_json::json!({"PublicKeyToken": "31bf3856ad364e35", "max_tokens": "10"});
        Redactor::new().redact_json(&mut v);
        assert_eq!(v["PublicKeyToken"], "31bf3856ad364e35");
        assert_eq!(v["max_tokens"], "10");
    }

    #[test]
    fn url_credentials_keep_user_and_host() {
        assert_eq!(
            r(&cat(&[
                "fetch https://alice",
                ":",
                "s3cr3t",
                "@example.com/x"
            ])),
            "fetch https://alice:[REDACTED:url_password]@example.com/x"
        );
        assert_eq!(
            r(&cat(&["postgres://app", ":", "pw%40x", "@db:5432/prod"])),
            "postgres://app:[REDACTED:url_password]@db:5432/prod"
        );
        // no password -> untouched
        let plain = "https://example.com:8443/path?a=b";
        assert_eq!(r(plain), plain);
    }

    #[test]
    fn soc_artifacts_are_preserved() {
        for keep in [
            "SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "MD5=d41d8cd98f00b204e9800998ecf8427e",
            "{4D36E96E-E325-11CE-BFC1-08002BE10318}",
            "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            "src 10.0.0.5 -> 8.8.8.8:443",
            "S-1-5-21-3623811015-3361044348-30300820-1013",
        ] {
            assert_eq!(r(keep), keep, "{keep}");
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = r("Authorization: Bearer abc123def456 password=x1y2z3");
        assert_eq!(r(&once), once);
    }

    #[test]
    fn redact_json_leaves_and_sensitive_keys() {
        let red = Redactor::with_secrets(&["literal-secret".into()]);
        let mut v = serde_json::json!({
            "password": "hunter2",
            "apiKey": "abc",
            "nested": [{"msg": "use literal-secret now"}, {"auth": "Bearer zz11yy22xx33"}],
            "count": 3,
            "token": null,
            "user": "bob"
        });
        red.redact_json(&mut v);
        assert_eq!(v["password"], "[REDACTED:password]");
        assert_eq!(v["apiKey"], "[REDACTED:api_key]");
        assert_eq!(v["nested"][0]["msg"], "use [REDACTED:secret] now");
        assert_eq!(v["nested"][1]["auth"], "Bearer [REDACTED:bearer]");
        assert_eq!(v["count"], 3);
        assert!(v["token"].is_null());
        assert_eq!(v["user"], "bob");
    }

    #[test]
    fn redact_json_deep_nesting_does_not_overflow() {
        let mut v = serde_json::Value::String("password=deep".into());
        for _ in 0..5_000 {
            v = serde_json::Value::Array(vec![v]);
        }
        Redactor::new().redact_json(&mut v);
        let s = v.to_string();
        assert!(s.contains("[REDACTED:too_deep]"));
        assert!(!s.contains("deep\""));
    }

    #[test]
    fn no_panic_on_odd_input() {
        let red = Redactor::with_secrets(&["äöüßäöü".into()]);
        let pem_begin = pem_line("BEGIN", "PRIVATE KEY");
        for s in [
            "",
            "\u{0}\u{1}",
            "bearer",
            "password=",
            "äöüßäöü password: ü",
            pem_begin.as_str(),
            "https://:@",
            "Authorization: Bearer",
        ] {
            let _ = red.redact(s);
        }
        assert_eq!(red.redact("x äöüßäöü y").as_ref(), "x [REDACTED:secret] y");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod proptests;
