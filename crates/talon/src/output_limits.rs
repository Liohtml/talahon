//! Caps on agent output before it is redacted, stored or delivered to a
//! chat channel (MYTH-07).
//!
//! A compromised container controls every frame it emits. Without caps a
//! run could stream arbitrarily large or arbitrarily many results into host
//! memory, the redactor and the chat channels. The orchestrator therefore
//! passes every frame through an [`OutputGuard`]:
//!
//! - **per frame / per turn**: result text is truncated to
//!   [`OutputLimits::max_result_bytes`] (64 KiB) with a note saying so. The
//!   agent emits exactly one result frame per turn, so this is also the
//!   per-turn cap of a well-behaved agent. Long results still reach
//!   CoPilot in full through the agent's own MCP write-back; only the copy
//!   delivered to the chat channel is shortened. Error texts are capped
//!   too, and session ids must pass [`is_valid_session_id`] (at most
//!   [`MAX_SESSION_ID_BYTES`] of `[A-Za-z0-9_-]`; N-5) or are dropped.
//! - **per run** (one container, including piped follow-ups): at most
//!   [`OutputLimits::max_run_frames`] frames and
//!   [`OutputLimits::max_run_result_bytes`] of (already truncated) result
//!   text. Exceeding either aborts the run: the container is stopped and
//!   the remaining frames are dropped.
//!
//! Frames reach the orchestrator through a bounded channel
//! ([`OUTPUT_CHANNEL_CAPACITY`]), so a slow consumer applies backpressure
//! to the container's stdout reader instead of buffering without bound.

use talon_core::protocol::ContainerOutput;

/// Capacity of the launcher -> orchestrator frame channel.
pub const OUTPUT_CHANNEL_CAPACITY: usize = 64;
/// Default per-frame result cap (bytes).
pub const DEFAULT_MAX_RESULT_BYTES: usize = 64 * 1024;
/// Default per-run cap on delivered result text (bytes).
pub const DEFAULT_MAX_RUN_RESULT_BYTES: usize = 4 * 1024 * 1024;
/// Default per-run frame cap.
pub const DEFAULT_MAX_RUN_FRAMES: usize = 1024;
/// Default per-frame error text cap (bytes).
pub const DEFAULT_MAX_ERROR_BYTES: usize = 8 * 1024;
/// Session ids longer than this are ignored (they are persisted in the
/// database, kept in memory, logged and sent back to the container on the
/// next run). The agent's own ids are 36-byte UUIDs.
pub const MAX_SESSION_ID_BYTES: usize = 128;
/// How far back from the cut point a whitespace boundary is searched, so
/// a truncation does not split a token (a partial secret would no longer
/// match the redactor).
const BOUNDARY_SEARCH_BYTES: usize = 1024;

/// Output caps (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputLimits {
    /// Longest result text delivered per frame (bytes, including the
    /// truncation note).
    pub max_result_bytes: usize,
    /// Most result text a run may deliver in total (bytes).
    pub max_run_result_bytes: usize,
    /// Most frames a run may emit.
    pub max_run_frames: usize,
    /// Longest error text kept per frame (bytes).
    pub max_error_bytes: usize,
}

impl Default for OutputLimits {
    fn default() -> Self {
        Self {
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
            max_run_result_bytes: DEFAULT_MAX_RUN_RESULT_BYTES,
            max_run_frames: DEFAULT_MAX_RUN_FRAMES,
            max_error_bytes: DEFAULT_MAX_ERROR_BYTES,
        }
    }
}

/// Whether `id` is acceptable as a session id reported by an agent:
/// 1..=[`MAX_SESSION_ID_BYTES`] bytes of `[A-Za-z0-9_-]` (N-5). Anything
/// else — oversized, path-like, control characters — is never persisted.
pub fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SESSION_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A session id reported by the agent, or `None` when it is absent, empty
/// or invalid (see [`is_valid_session_id`]; invalid ids are logged —
/// length only, never the id itself — and ignored).
pub fn sanitize_session_id(id: Option<String>) -> Option<String> {
    let id = id.filter(|id| !id.is_empty())?;
    if is_valid_session_id(&id) {
        Some(id)
    } else {
        tracing::warn!(
            bytes = id.len(),
            limit = MAX_SESSION_ID_BYTES,
            "agent reported an invalid session id (oversized or not [A-Za-z0-9_-]); ignored"
        );
        None
    }
}

/// Largest index `<= max` that is a char boundary of `text`, moved back to
/// just after a whitespace character when one is within reach.
fn cut_point(text: &str, max: usize) -> usize {
    let mut cut = max.min(text.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let floor = cut.saturating_sub(BOUNDARY_SEARCH_BYTES);
    match text[floor..cut].rfind(char::is_whitespace) {
        Some(rel) => floor + rel,
        None => cut,
    }
}

/// `text` limited to `max` bytes. Longer text is cut (at a whitespace
/// boundary when possible) and ends with a note saying how much was
/// omitted; the result, note included, is at most `max` bytes.
pub fn cap_text(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let note = format!(
        "\n\n[Talon: output truncated — the result was {} bytes; only the first part \
         (limit {max} bytes) is shown here]",
        text.len()
    );
    let budget = max.saturating_sub(note.len());
    if budget == 0 {
        let cut = cut_point(text, max);
        return text[..cut].to_string();
    }
    let cut = cut_point(text, budget);
    let mut out = String::with_capacity(cut + note.len());
    out.push_str(text[..cut].trim_end());
    out.push_str(&note);
    out
}

/// What to do with one frame.
#[derive(Debug, Clone, PartialEq)]
pub enum Admission {
    /// Deliver this (possibly capped) frame.
    Deliver(ContainerOutput),
    /// The run exceeded its caps: stop the container, drop the rest.
    Abort(String),
}

/// Per-run accounting of agent output (see the module docs).
#[derive(Debug, Clone)]
pub struct OutputGuard {
    limits: OutputLimits,
    frames: usize,
    result_bytes: usize,
    truncated: usize,
}

impl OutputGuard {
    /// A guard for one run.
    pub fn new(limits: OutputLimits) -> Self {
        Self {
            limits,
            frames: 0,
            result_bytes: 0,
            truncated: 0,
        }
    }

    /// Frames admitted so far.
    pub fn frames(&self) -> usize {
        self.frames
    }

    /// Result bytes admitted so far.
    pub fn result_bytes(&self) -> usize {
        self.result_bytes
    }

    /// Frames whose result was truncated.
    pub fn truncated(&self) -> usize {
        self.truncated
    }

    /// Cap one frame, or decide that the run must be aborted.
    pub fn admit(&mut self, mut output: ContainerOutput) -> Admission {
        self.frames += 1;
        if self.frames > self.limits.max_run_frames {
            return Admission::Abort(format!(
                "agent output exceeded the per-run limit of {} frames; run stopped",
                self.limits.max_run_frames
            ));
        }
        if let Some(result) = output.result.take() {
            let capped = if result.len() > self.limits.max_result_bytes {
                self.truncated += 1;
                tracing::warn!(
                    bytes = result.len(),
                    limit = self.limits.max_result_bytes,
                    "agent result exceeds the per-message limit; truncated"
                );
                cap_text(&result, self.limits.max_result_bytes)
            } else {
                result
            };
            self.result_bytes = self.result_bytes.saturating_add(capped.len());
            if self.result_bytes > self.limits.max_run_result_bytes {
                return Admission::Abort(format!(
                    "agent output exceeded the per-run limit of {} bytes; run stopped",
                    self.limits.max_run_result_bytes
                ));
            }
            output.result = Some(capped);
        }
        if let Some(error) = output.error.take() {
            output.error = Some(cap_text(&error, self.limits.max_error_bytes));
        }
        output.new_session_id = sanitize_session_id(output.new_session_id.take());
        Admission::Deliver(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(result: usize, run: usize, frames: usize) -> OutputLimits {
        OutputLimits {
            max_result_bytes: result,
            max_run_result_bytes: run,
            max_run_frames: frames,
            max_error_bytes: 200,
        }
    }

    #[test]
    fn short_text_is_untouched() {
        assert_eq!(cap_text("hello", 64), "hello");
        assert_eq!(cap_text("", 0), "");
    }

    #[test]
    fn long_text_is_truncated_with_a_note_within_the_limit() {
        let text = "word ".repeat(100_000);
        let capped = cap_text(&text, DEFAULT_MAX_RESULT_BYTES);
        assert!(capped.len() <= DEFAULT_MAX_RESULT_BYTES, "{}", capped.len());
        assert!(capped.contains("output truncated"));
        assert!(capped.contains(&text.len().to_string()));
        assert!(capped.starts_with("word word"));
    }

    #[test]
    fn truncation_respects_char_boundaries_and_token_boundaries() {
        let text = "é".repeat(50_000);
        let capped = cap_text(&text, 1001);
        assert!(capped.len() <= 1001);
        // Must not split a token when whitespace is near the cut point.
        let secret = "sk-SECRETSECRETSECRET";
        let text = format!("{} {secret} {}", "a ".repeat(200), "b".repeat(10_000));
        let capped = cap_text(&text, 600);
        assert!(capped.contains(secret), "{capped}");
        // A cut inside the token moves back to the preceding space.
        let start = text.find(secret).unwrap();
        let cut = cut_point(&text, start + 5);
        assert_eq!(cut, start - 1);
        assert!(!text[..cut].contains("sk-"));
        // Without whitespace in reach, the cut is at the char boundary.
        let solid = "z".repeat(5_000);
        assert_eq!(cut_point(&solid, 4_000), 4_000);
        // A tiny limit still yields at most `max` bytes.
        assert!(cap_text(&"x".repeat(100), 5).len() <= 5);
    }

    #[test]
    fn guard_truncates_frames_and_caps_errors_and_session_ids() {
        let mut guard = OutputGuard::new(limits(1000, 1_000_000, 10));
        let big = ContainerOutput::success(Some("x ".repeat(5_000)), Some("s".repeat(300)));
        let Admission::Deliver(out) = guard.admit(big) else {
            panic!("must deliver");
        };
        assert!(out.result.as_ref().unwrap().len() <= 1000);
        assert_eq!(out.new_session_id, None);
        assert_eq!(guard.truncated(), 1);

        let Admission::Deliver(err) = guard.admit(ContainerOutput::error("e".repeat(10_000)))
        else {
            panic!("must deliver");
        };
        assert!(err.error.unwrap().len() <= 200);

        let Admission::Deliver(ok) = guard.admit(ContainerOutput::success(
            Some("hi".into()),
            Some("sess-1".into()),
        )) else {
            panic!("must deliver");
        };
        assert_eq!(ok.result.as_deref(), Some("hi"));
        assert_eq!(ok.new_session_id.as_deref(), Some("sess-1"));
        assert_eq!(guard.frames(), 3);
    }

    #[test]
    fn session_ids_are_validated() {
        assert!(is_valid_session_id("3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5b"));
        assert!(is_valid_session_id("sess_1-A"));
        assert!(is_valid_session_id(&"a".repeat(MAX_SESSION_ID_BYTES)));
        assert!(!is_valid_session_id(&"a".repeat(MAX_SESSION_ID_BYTES + 1)));
        assert!(!is_valid_session_id(""));
        for bad in [
            "../../etc/passwd",
            "a/b",
            "a.b",
            "a b",
            "line\nbreak",
            "tab\t",
            "ümlaut",
            "id;rm",
            "\u{1b}[31m",
        ] {
            assert!(!is_valid_session_id(bad), "{bad:?} must be rejected");
        }
        assert_eq!(sanitize_session_id(None), None);
        assert_eq!(sanitize_session_id(Some(String::new())), None);
        assert_eq!(sanitize_session_id(Some("x/y".into())), None);
        assert_eq!(
            sanitize_session_id(Some("x".repeat(MAX_SESSION_ID_BYTES + 1))),
            None
        );
        assert_eq!(
            sanitize_session_id(Some("sess-1".into())).as_deref(),
            Some("sess-1")
        );
    }

    #[test]
    fn guard_drops_invalid_session_ids() {
        let mut guard = OutputGuard::new(limits(1000, 1_000_000, 10));
        for bad in [
            "s".repeat(MAX_SESSION_ID_BYTES + 1),
            "../sessions/x".to_string(),
            "id with spaces".to_string(),
            "evil\nlog line".to_string(),
        ] {
            let Admission::Deliver(out) =
                guard.admit(ContainerOutput::success(Some("ok".into()), Some(bad)))
            else {
                panic!("must deliver");
            };
            assert_eq!(out.new_session_id, None);
            // The rest of the frame is still delivered.
            assert_eq!(out.result.as_deref(), Some("ok"));
        }
        let max = "s".repeat(MAX_SESSION_ID_BYTES);
        let Admission::Deliver(out) =
            guard.admit(ContainerOutput::success(None, Some(max.clone())))
        else {
            panic!("must deliver");
        };
        assert_eq!(out.new_session_id, Some(max));
    }

    #[test]
    fn guard_aborts_when_the_run_exceeds_its_caps() {
        let mut guard = OutputGuard::new(limits(1000, 2500, 100));
        for _ in 0..2 {
            assert!(matches!(
                guard.admit(ContainerOutput::success(Some("y".repeat(1000)), None)),
                Admission::Deliver(_)
            ));
        }
        assert!(matches!(
            guard.admit(ContainerOutput::success(Some("y".repeat(1000)), None)),
            Admission::Abort(reason) if reason.contains("2500 bytes")
        ));

        let mut guard = OutputGuard::new(limits(1000, 1_000_000, 3));
        for _ in 0..3 {
            assert!(matches!(
                guard.admit(ContainerOutput::success(None, None)),
                Admission::Deliver(_)
            ));
        }
        assert!(matches!(
            guard.admit(ContainerOutput::success(None, None)),
            Admission::Abort(reason) if reason.contains("3 frames")
        ));
    }
}
