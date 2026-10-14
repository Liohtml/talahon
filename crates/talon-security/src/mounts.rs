//! Additional-mount validation against the tamper-proof allowlist
//! (port of `src/mount-security.ts`, hardened).
//!
//! Rules: no allowlist file => every additional mount is rejected; host paths
//! are canonicalized (symlinks resolved) before matching allowed roots and
//! blocked patterns (`.ssh`, `.gnupg`, `.aws`, `.env`, `id_rsa`, `*.pem`,
//! `.docker`, `.kube`, credentials, ... are always blocked even if the file
//! omits them); container paths must be relative, without `..`, `:` or
//! control characters; non-main groups are forced read-only when
//! `non_main_read_only`; read-write requires `allow_read_write` on the root.

use std::path::{Path, PathBuf};

use talon_core::types::{AdditionalMount, MountAllowlist};

/// Patterns blocked regardless of the allowlist file.
pub const DEFAULT_BLOCKED_PATTERNS: &[&str] = &[
    ".ssh", ".gnupg", ".gpg", ".aws", ".azure", ".gcloud", ".kube", ".docker",
    ".env", "credentials", ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ed25519",
    "private_key", ".secret", "*.pem", "*.key", "*.p12", "*.pfx",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMount {
    /// Canonical host path.
    pub host_path: PathBuf,
    /// Full container path (`/workspace/extra/<name>`).
    pub container_path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountDecision {
    Allowed(ValidatedMount),
    Rejected { reason: String },
}

#[derive(Debug, Clone)]
pub struct MountValidator {
    #[allow(dead_code)]
    allowlist: Option<MountAllowlist>,
}

#[allow(unused_variables, clippy::todo)]
impl MountValidator {
    /// Load from disk. Missing/invalid file => validator that rejects all.
    pub fn load(path: &Path) -> Self {
        todo!()
    }

    pub fn from_allowlist(allowlist: Option<MountAllowlist>) -> Self {
        Self { allowlist }
    }

    pub fn validate(&self, mount: &AdditionalMount, is_main: bool) -> MountDecision {
        todo!()
    }

    /// Validate all; rejected mounts are logged (with reason) and dropped.
    pub fn validate_all(
        &self,
        mounts: &[AdditionalMount],
        group_name: &str,
        is_main: bool,
    ) -> Vec<ValidatedMount> {
        todo!()
    }
}

/// Example allowlist JSON for `talon setup`.
#[allow(clippy::todo)]
pub fn allowlist_template() -> String {
    todo!()
}
