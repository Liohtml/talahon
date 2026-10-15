//! Incremental Server-Sent-Events decoder (WHATWG `text/event-stream`).
//!
//! Used by the client to parse vLLM streams and by the gateway to observe
//! the usage chunk of streams it passes through. Robust to events split at
//! any byte (including inside UTF-8 sequences and `\r\n` pairs), and bounded:
//! a peer that never sends a newline cannot make it buffer unboundedly.

use crate::error::LlmError;

/// One dispatched SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` field, if any.
    pub event: Option<String>,
    /// The concatenated `data:` lines (joined with `\n`).
    pub data: String,
}

/// Streaming SSE parser. Feed bytes with [`SseDecoder::push`].
#[derive(Debug)]
pub struct SseDecoder {
    buf: Vec<u8>,
    data: String,
    event: Option<String>,
    has_data: bool,
    max_event_bytes: usize,
}

/// Default bound for one SSE line / event (tool-call argument chunks are
/// small; a whole event above this is a broken or hostile server).
pub const DEFAULT_MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;

impl Default for SseDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_EVENT_BYTES)
    }
}

impl SseDecoder {
    /// A decoder that rejects lines/events larger than `max_event_bytes`.
    pub fn new(max_event_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            data: String::new(),
            event: None,
            has_data: false,
            max_event_bytes: max_event_bytes.max(1024),
        }
    }

    /// Feed a chunk; returns every event completed by it.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, LlmError> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        let mut start = 0usize;
        let mut i = 0usize;
        while i < self.buf.len() {
            let b = self.buf[i];
            if b == b'\n' || b == b'\r' {
                let line_end = i;
                let next = if b == b'\r' {
                    match self.buf.get(i + 1) {
                        Some(b'\n') => i + 2,
                        Some(_) => i + 1,
                        // A trailing '\r' may be the first half of "\r\n".
                        None => break,
                    }
                } else {
                    i + 1
                };
                let line = String::from_utf8_lossy(&self.buf[start..line_end]).into_owned();
                if let Some(ev) = self.process_line(&line)? {
                    events.push(ev);
                }
                start = next;
                i = next;
            } else {
                i += 1;
            }
        }
        self.buf.drain(..start);
        if self.buf.len() > self.max_event_bytes {
            return Err(LlmError::Stream(format!(
                "SSE line exceeds {} bytes",
                self.max_event_bytes
            )));
        }
        Ok(events)
    }

    /// Flush at end of input: dispatches a final event that was not
    /// terminated by a blank line.
    pub fn finish(&mut self) -> Result<Option<SseEvent>, LlmError> {
        if !self.buf.is_empty() {
            let rest = std::mem::take(&mut self.buf);
            let line = String::from_utf8_lossy(&rest).into_owned();
            let line = line.trim_end_matches('\r').to_string();
            if let Some(ev) = self.process_line(&line)? {
                return Ok(Some(ev));
            }
        }
        Ok(self.dispatch())
    }

    fn process_line(&mut self, line: &str) -> Result<Option<SseEvent>, LlmError> {
        if line.is_empty() {
            return Ok(self.dispatch());
        }
        if line.starts_with(':') {
            return Ok(None); // comment / keep-alive
        }
        let (field, value) = match line.find(':') {
            Some(pos) => {
                let v = &line[pos + 1..];
                (&line[..pos], v.strip_prefix(' ').unwrap_or(v))
            }
            None => (line, ""),
        };
        match field {
            "data" => {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
                if self.data.len() > self.max_event_bytes {
                    return Err(LlmError::Stream(format!(
                        "SSE event exceeds {} bytes",
                        self.max_event_bytes
                    )));
                }
            }
            "event" => self.event = Some(value.to_string()),
            _ => {} // id, retry, unknown fields: ignored
        }
        Ok(None)
    }

    fn dispatch(&mut self) -> Option<SseEvent> {
        let event = self.event.take();
        if !self.has_data {
            return None;
        }
        self.has_data = false;
        Some(SseEvent {
            event,
            data: std::mem::take(&mut self.data),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(chunks: &[&[u8]]) -> Vec<SseEvent> {
        let mut d = SseDecoder::default();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(d.push(c).unwrap());
        }
        out.extend(d.finish().unwrap());
        out
    }

    #[test]
    fn basic_events() {
        let evs = decode_all(&[b"data: {\"a\":1}\n\ndata: [DONE]\n\n"]);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].data, "{\"a\":1}");
        assert_eq!(evs[1].data, "[DONE]");
    }

    #[test]
    fn split_at_every_byte_and_crlf() {
        let raw =
            "event: x\r\ndata: héllo\r\ndata: wörld\r\n\r\n: keepalive\r\n\r\ndata:nospace\r\r";
        let bytes = raw.as_bytes();
        let chunks: Vec<&[u8]> = bytes.chunks(1).collect();
        let evs = decode_all(&chunks);
        assert_eq!(evs.len(), 2, "{evs:?}");
        assert_eq!(evs[0].event.as_deref(), Some("x"));
        assert_eq!(evs[0].data, "héllo\nwörld");
        assert_eq!(evs[1].data, "nospace");
        assert_eq!(evs[1].event, None);
    }

    #[test]
    fn unterminated_final_event_is_flushed() {
        let evs = decode_all(&[b"data: tail"]);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "tail");
    }

    #[test]
    fn oversized_line_is_rejected() {
        let mut d = SseDecoder::new(1024);
        let big = vec![b'a'; 4096];
        assert!(d.push(&big).is_err());
    }

    #[test]
    fn empty_data_lines_dispatch_nothing_without_data() {
        let evs = decode_all(&[b"event: ping\n\n", b"id: 5\n\n"]);
        assert!(evs.is_empty());
    }
}
