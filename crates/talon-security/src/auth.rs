//! Authentication primitives (constant-time comparison, tokens, HMAC).

/// Constant-time byte comparison (length leak only).
#[allow(unused_variables, clippy::todo)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    todo!()
}

/// Verify a presented API key. **Fails closed**: returns false when
/// `expected` is empty/whitespace (an unset key must never authorize, unlike
/// the TS release where an empty `HTTP_API_KEY` matched an empty header) or
/// when `provided` is `None`/empty.
#[allow(unused_variables, clippy::todo)]
pub fn verify_api_key(provided: Option<&str>, expected: &str) -> bool {
    todo!()
}

/// Extract a key from `X-Api-Key` or `Authorization: Bearer <key>` header
/// values (case-insensitive scheme).
#[allow(unused_variables, clippy::todo)]
pub fn extract_bearer(x_api_key: Option<&str>, authorization: Option<&str>) -> Option<String> {
    todo!()
}

/// Cryptographically random URL-safe token with `bytes` bytes of entropy.
#[allow(unused_variables, clippy::todo)]
pub fn generate_token(bytes: usize) -> String {
    todo!()
}

/// Hex HMAC-SHA256.
#[allow(unused_variables, clippy::todo)]
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    todo!()
}

/// Verify a hex (optionally `sha256=`-prefixed) HMAC-SHA256 signature in
/// constant time.
#[allow(unused_variables, clippy::todo)]
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], signature: &str) -> bool {
    todo!()
}
