//! stdin / stdout side of the host <-> container protocol
//! (`talon_core::protocol`): reading the `ContainerInput` once (bounded) and
//! emitting framed `ContainerOutput`s.

use std::io::Write as _;
use std::sync::Mutex;

use talon_core::protocol::{ContainerInput, ContainerOutput};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::AgentError;

/// Default upper bound for the stdin `ContainerInput` (16 MiB).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Read `reader` to EOF, failing once more than `max` bytes arrive.
pub async fn read_capped<R>(reader: R, max: usize) -> Result<Vec<u8>, AgentError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    reader.take(limit).read_to_end(&mut buf).await?;
    if buf.len() > max {
        return Err(AgentError::Input(format!(
            "ContainerInput exceeds the {max}-byte limit"
        )));
    }
    Ok(buf)
}

/// Parse the stdin bytes as a [`ContainerInput`].
pub fn parse_input(bytes: &[u8]) -> Result<ContainerInput, AgentError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(AgentError::Input("stdin was empty".into()));
    }
    // serde_json errors carry line/column only, never input content.
    serde_json::from_slice(bytes)
        .map_err(|e| AgentError::Input(format!("cannot parse ContainerInput: {e}")))
}

/// Where output frames go: stdout in production, memory in tests.
pub trait OutputSink: Send + Sync {
    /// Emit one frame. Must not fail loudly: a closed stdout means the host
    /// is gone and nothing useful can be done.
    fn emit(&self, output: &ContainerOutput);
}

/// Writes frames (`---TALON_OUTPUT_START---` .. `---TALON_OUTPUT_END---`) to
/// the process stdout and flushes after each one.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdoutSink;

impl OutputSink for StdoutSink {
    fn emit(&self, output: &ContainerOutput) {
        let framed = output.to_framed();
        let mut out = std::io::stdout().lock();
        if let Err(e) = out.write_all(framed.as_bytes()).and_then(|()| out.flush()) {
            tracing::error!(error = %e, "cannot write output frame to stdout");
        }
    }
}

/// Collects frames in memory (tests, embedding).
#[derive(Debug, Default)]
pub struct MemorySink {
    frames: Mutex<Vec<ContainerOutput>>,
}

impl MemorySink {
    /// Empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Frames emitted so far.
    pub fn frames(&self) -> Vec<ContainerOutput> {
        self.frames
            .lock()
            .map(|f| f.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
    }
}

impl OutputSink for MemorySink {
    fn emit(&self, output: &ContainerOutput) {
        match self.frames.lock() {
            Ok(mut f) => f.push(output.clone()),
            Err(p) => p.into_inner().push(output.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_capped_enforces_limit() {
        let data = [b'x'; 10];
        assert_eq!(read_capped(&data[..], 10).await.unwrap().len(), 10);
        let err = read_capped(&data[..], 9).await.unwrap_err();
        assert!(matches!(err, AgentError::Input(_)));
    }

    #[test]
    fn parse_input_variants() {
        assert!(matches!(parse_input(b"  \n"), Err(AgentError::Input(_))));
        assert!(matches!(parse_input(b"{nope"), Err(AgentError::Input(_))));
        let ok =
            parse_input(br#"{"prompt":"hi","groupFolder":"main","chatJid":"tg:1","isMain":true}"#)
                .unwrap();
        assert_eq!(ok.prompt, "hi");
        assert!(ok.is_main);
        assert!(!ok.ephemeral);
    }

    #[test]
    fn memory_sink_collects() {
        let sink = MemorySink::new();
        sink.emit(&ContainerOutput::success(Some("a".into()), None));
        sink.emit(&ContainerOutput::error("b"));
        let frames = sink.frames();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].error.as_deref(), Some("b"));
    }
}
