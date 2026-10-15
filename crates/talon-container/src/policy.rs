//! Small local seams over `talon-security`.
//!
//! The container launcher talks to `talon-security` through two narrow
//! traits. Production wires the real
//! types (blanket impls below); unit tests inject fakes.

use std::borrow::Cow;

use talon_core::types::AdditionalMount;
use talon_security::mounts::{MountDecision, MountValidator};
use talon_security::redact::Redactor;

/// Validates one additional mount against the tamper-proof allowlist.
pub trait MountPolicy: Send + Sync {
    /// Decide whether `mount` may be attached to a container of a main /
    /// non-main group.
    fn validate(&self, mount: &AdditionalMount, is_main: bool) -> MountDecision;
}

impl MountPolicy for MountValidator {
    fn validate(&self, mount: &AdditionalMount, is_main: bool) -> MountDecision {
        MountValidator::validate(self, mount, is_main)
    }
}

/// Fail-closed policy that rejects every additional mount (used when no
/// allowlist is configured).
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllMounts;

impl MountPolicy for DenyAllMounts {
    fn validate(&self, _mount: &AdditionalMount, _is_main: bool) -> MountDecision {
        MountDecision::Rejected {
            reason: "no mount allowlist configured".to_string(),
        }
    }
}

/// Removes secrets from text before it reaches logs or audit details.
pub trait LogRedactor: Send + Sync {
    /// Return `text` with every detected secret replaced.
    fn redact_text<'a>(&self, text: &'a str) -> Cow<'a, str>;
}

impl LogRedactor for Redactor {
    fn redact_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.redact(text)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Fakes shared by the unit tests of this crate.

    use std::borrow::Cow;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use talon_core::types::AdditionalMount;
    use talon_security::mounts::{MountDecision, ValidatedMount};

    use super::{LogRedactor, MountPolicy};

    /// Allows every mount whose host path does not contain `deny`, mapping it
    /// to `/workspace/extra/<container_path or basename>`.
    #[derive(Debug, Default)]
    pub struct AllowAllMounts;

    impl MountPolicy for AllowAllMounts {
        fn validate(&self, mount: &AdditionalMount, is_main: bool) -> MountDecision {
            if mount.host_path.contains("deny") {
                return MountDecision::Rejected {
                    reason: "path matches blocked pattern".into(),
                };
            }
            let host = PathBuf::from(&mount.host_path);
            let name = mount.container_path.clone().unwrap_or_else(|| {
                host.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            MountDecision::Allowed(ValidatedMount {
                host_path: host,
                container_path: format!("/workspace/extra/{name}"),
                readonly: mount.readonly || !is_main,
            })
        }
    }

    /// Replaces `hunter2` with `[REDACTED]` and records every input.
    #[derive(Debug, Default)]
    pub struct RecordingRedactor {
        pub seen: Mutex<Vec<String>>,
    }

    impl LogRedactor for RecordingRedactor {
        fn redact_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
            if let Ok(mut v) = self.seen.lock() {
                v.push(text.to_string());
            }
            if text.contains("hunter2") {
                Cow::Owned(text.replace("hunter2", "[REDACTED]"))
            } else {
                Cow::Borrowed(text)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_rejects() {
        let m = AdditionalMount {
            host_path: "/srv/x".into(),
            container_path: None,
            readonly: true,
        };
        assert!(matches!(
            DenyAllMounts.validate(&m, true),
            MountDecision::Rejected { .. }
        ));
    }

    #[test]
    fn recording_redactor_redacts() {
        let r = testing::RecordingRedactor::default();
        assert_eq!(r.redact_text("pw=hunter2"), "pw=[REDACTED]");
        assert_eq!(r.redact_text("plain"), "plain");
        assert_eq!(r.seen.lock().unwrap().len(), 2);
    }
}
