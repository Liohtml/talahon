//! Authentication primitives (constant-time comparison, tokens, HMAC).
//!
//! Everything here fails closed: empty or malformed credentials never
//! authorize, and secret comparisons never short-circuit on the first
//! differing byte.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Minimum entropy (bytes) of tokens produced by [`generate_token`].
pub const MIN_TOKEN_BYTES: usize = 16;
/// Maximum entropy (bytes) of tokens produced by [`generate_token`].
pub const MAX_TOKEN_BYTES: usize = 1024;

/// Upper bound on the length of a presented credential we are willing to
/// process (headers are bounded upstream too; this is defence in depth).
const MAX_CREDENTIAL_LEN: usize = 8 * 1024;

/// Constant-time byte comparison (length leak only).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // `subtle` returns 0 for slices of different length without comparing
    // contents; equal-length slices are compared without early exit.
    bool::from(a.ct_eq(b))
}

/// Verify a presented API key. **Fails closed**: returns false when
/// `expected` is empty/whitespace (an unset key must never authorize, unlike
/// the TS release where an empty `HTTP_API_KEY` matched an empty header) or
/// when `provided` is `None`/empty.
///
/// Both values are hashed with SHA-256 before the constant-time comparison,
/// so not even the key length leaks through timing. Surrounding whitespace
/// is ignored on both sides (HTTP stacks trim header values anyway).
pub fn verify_api_key(provided: Option<&str>, expected: &str) -> bool {
    let expected = expected.trim();
    if expected.is_empty() {
        return false;
    }
    let Some(provided) = provided.map(str::trim) else {
        return false;
    };
    if provided.is_empty() || provided.len() > MAX_CREDENTIAL_LEN {
        return false;
    }
    let a = Sha256::digest(provided.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    constant_time_eq(&a, &b)
}

/// Extract a key from `X-Api-Key` or `Authorization: Bearer <key>` header
/// values (case-insensitive scheme).
///
/// `X-Api-Key` wins when it is present and non-empty. Values containing
/// control characters or inner whitespace, and oversized values, are
/// rejected (`None`).
pub fn extract_bearer(x_api_key: Option<&str>, authorization: Option<&str>) -> Option<String> {
    if let Some(k) = x_api_key.map(str::trim).filter(|k| !k.is_empty()) {
        return sane_credential(k).then(|| k.to_string());
    }
    let auth = authorization?.trim();
    let (scheme, rest) = auth.split_once([' ', '\t'])?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty() && sane_credential(token)).then(|| token.to_string())
}

fn sane_credential(s: &str) -> bool {
    s.len() <= MAX_CREDENTIAL_LEN && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Cryptographically random URL-safe token with `bytes` bytes of entropy.
///
/// `bytes` is clamped to [`MIN_TOKEN_BYTES`]..=[`MAX_TOKEN_BYTES`] so a
/// caller can never accidentally mint an empty or guessable token. The
/// result is unpadded base64url (`[A-Za-z0-9_-]`).
pub fn generate_token(bytes: usize) -> String {
    let n = bytes.clamp(MIN_TOKEN_BYTES, MAX_TOKEN_BYTES);
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

fn mac_for(key: &[u8]) -> Option<HmacSha256> {
    // HMAC accepts keys of any length; this never fails in practice.
    <HmacSha256 as Mac>::new_from_slice(key).ok()
}

/// Hex HMAC-SHA256.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    match mac_for(key) {
        Some(mut mac) => {
            mac.update(message);
            hex::encode(mac.finalize().into_bytes())
        }
        None => String::new(),
    }
}

/// Verify a hex (optionally `sha256=`-prefixed) HMAC-SHA256 signature in
/// constant time.
///
/// Fails closed on an empty key, a malformed/odd-length hex string or a
/// digest of the wrong length.
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], signature: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let sig = signature.trim();
    let sig = match sig.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("sha256=") => &sig[7..],
        _ => sig,
    };
    if sig.len() != 64 {
        return false;
    }
    let Ok(raw) = hex::decode(sig) else {
        return false;
    };
    let Some(mut mac) = mac_for(key) else {
        return false;
    };
    mac.update(message);
    // `verify_slice` compares in constant time.
    mac.verify_slice(&raw).is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn api_key_fails_closed_on_empty_expected() {
        assert!(!verify_api_key(Some(""), ""));
        assert!(!verify_api_key(Some("  "), "   "));
        assert!(!verify_api_key(None, ""));
        assert!(!verify_api_key(Some("anything"), " \t"));
    }

    #[test]
    fn api_key_fails_closed_on_missing_provided() {
        assert!(!verify_api_key(None, "secret-key"));
        assert!(!verify_api_key(Some(""), "secret-key"));
        assert!(!verify_api_key(Some("   "), "secret-key"));
    }

    #[test]
    fn api_key_matches_exactly() {
        assert!(verify_api_key(Some("secret-key"), "secret-key"));
        assert!(verify_api_key(Some(" secret-key "), "secret-key"));
        assert!(!verify_api_key(Some("secret-ke"), "secret-key"));
        assert!(!verify_api_key(Some("secret-key2"), "secret-key"));
        assert!(!verify_api_key(Some("SECRET-KEY"), "secret-key"));
        assert!(!verify_api_key(
            Some(&"x".repeat(MAX_CREDENTIAL_LEN + 1)),
            "x"
        ));
    }

    #[test]
    fn extract_prefers_x_api_key() {
        assert_eq!(
            extract_bearer(Some("k1"), Some("Bearer k2")).as_deref(),
            Some("k1")
        );
        assert_eq!(
            extract_bearer(Some("  "), Some("Bearer k2")).as_deref(),
            Some("k2")
        );
    }

    #[test]
    fn extract_bearer_scheme_is_case_insensitive() {
        assert_eq!(
            extract_bearer(None, Some("bearer abc")).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_bearer(None, Some("BEARER  abc ")).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_bearer(None, Some("Bearer\tabc")).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn extract_bearer_rejects_other_schemes_and_garbage() {
        let basic = ["Basic ", "dXNlcjpw", "YXNz"].concat();
        assert_eq!(extract_bearer(None, Some(&basic)), None);
        assert_eq!(extract_bearer(None, Some("Bearer")), None);
        assert_eq!(extract_bearer(None, Some("Bearer ")), None);
        assert_eq!(extract_bearer(None, Some("Bearerabc")), None);
        assert_eq!(extract_bearer(None, Some("Bearer a b")), None);
        assert_eq!(extract_bearer(None, Some("Bearer a\u{0}b")), None);
        assert_eq!(extract_bearer(Some("a\nb"), None), None);
        assert_eq!(extract_bearer(None, None), None);
    }

    #[test]
    fn tokens_are_random_urlsafe_and_clamped() {
        let a = generate_token(32);
        let b = generate_token(32);
        assert_ne!(a, b);
        assert_eq!(a.len(), 43); // 32 bytes -> 43 base64url chars
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // zero is clamped up to the minimum entropy
        assert_eq!(generate_token(0).len(), 22);
        assert!(generate_token(usize::MAX).len() <= 1366);
    }

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test case 2
        let sig = hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            sig,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_verify_roundtrip_and_prefix() {
        let sig = hmac_sha256_hex(b"k", b"body");
        assert!(verify_hmac_sha256(b"k", b"body", &sig));
        assert!(verify_hmac_sha256(b"k", b"body", &format!("sha256={sig}")));
        assert!(verify_hmac_sha256(b"k", b"body", &format!("SHA256={sig}")));
        assert!(verify_hmac_sha256(b"k", b"body", &sig.to_ascii_uppercase()));
        assert!(!verify_hmac_sha256(b"k", b"body2", &sig));
        assert!(!verify_hmac_sha256(b"k2", b"body", &sig));
    }

    #[test]
    fn hmac_verify_rejects_malformed() {
        assert!(!verify_hmac_sha256(b"k", b"body", ""));
        assert!(!verify_hmac_sha256(b"k", b"body", "sha256="));
        assert!(!verify_hmac_sha256(b"k", b"body", "zz"));
        assert!(!verify_hmac_sha256(b"k", b"body", &"0".repeat(63)));
        assert!(!verify_hmac_sha256(b"k", b"body", &"g".repeat(64)));
        let sig = hmac_sha256_hex(b"k", b"body");
        assert!(!verify_hmac_sha256(b"k", b"body", &sig[..62]));
        // empty key never verifies
        let empty_sig = hmac_sha256_hex(b"", b"body");
        assert!(!verify_hmac_sha256(b"", b"body", &empty_sig));
        // multibyte garbage must not panic on slicing
        assert!(!verify_hmac_sha256(b"k", b"body", "ääääsha256=xx"));
    }
}
