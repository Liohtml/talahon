//! The error type that ends an agent run.

use talon_llm::LlmError;

/// Everything that makes `talon-agent run` give up. Each variant is reported
/// to the host as one `ContainerOutput::error` frame (see [`crate::wire`]),
/// followed by a non-zero exit.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The stdin `ContainerInput` was empty, too large or malformed.
    #[error("invalid input: {0}")]
    Input(String),
    /// `ContainerInput.session_id` names a session that does not exist (or is
    /// not a valid id). The rendered message always contains
    /// `session not found`, which the host uses to clear stale session ids.
    #[error("session not found: {0}")]
    SessionNotFound(String),
    /// The session transcript could not be read or written.
    #[error("session error: {0}")]
    Session(String),
    /// Missing or unusable configuration (e.g. no LLM endpoint).
    #[error("configuration error: {0}")]
    Config(String),
    /// The model endpoint failed (after the client's own retries).
    #[error("{0}")]
    Llm(#[from] LlmError),
    /// The conversation does not fit the context window even after
    /// compaction (e.g. a single oversized prompt).
    #[error("context length exceeded and the conversation cannot be compacted further: {0}")]
    ContextOverflow(String),
    /// The run was cancelled (SIGTERM / SIGINT).
    #[error("agent run cancelled")]
    Cancelled,
    /// Local I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl AgentError {
    /// Short, content-free name of the variant (safe for logs/metrics).
    pub fn kind(&self) -> &'static str {
        match self {
            AgentError::Input(_) => "input",
            AgentError::SessionNotFound(_) => "session_not_found",
            AgentError::Session(_) => "session",
            AgentError::Config(_) => "config",
            AgentError::Llm(e) => e.kind(),
            AgentError::ContextOverflow(_) => "context_overflow",
            AgentError::Cancelled => "cancelled",
            AgentError::Io(_) => "io",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_session_message_matches_host_regex() {
        let e = AgentError::SessionNotFound("1234".into());
        let msg = e.to_string().to_lowercase();
        assert!(msg.contains("session not found"), "{msg}");
        assert_eq!(e.kind(), "session_not_found");
    }

    #[test]
    fn llm_errors_keep_their_kind() {
        let e = AgentError::from(LlmError::Timeout("x".into()));
        assert_eq!(e.kind(), "timeout");
        assert_eq!(AgentError::Cancelled.kind(), "cancelled");
    }
}
