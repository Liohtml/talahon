//! Newline-delimited framing over any `AsyncRead`/`AsyncWrite`.
//!
//! The MCP stdio transport sends one JSON-RPC message per line. This module
//! provides a bounded, cancel-safe line reader (oversized lines are
//! discarded without being buffered, keeping only a small head and tail so
//! the message id can still be recovered) and the writer loop used by both
//! the client and the server. It works identically for child-process pipes,
//! `tokio::net::UnixStream` halves and `tokio::io::duplex` (tests).

use std::io;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Default upper bound for one incoming message (16 MiB). SIEM search
/// results can be large; anything beyond this is discarded.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// How many leading bytes of an oversized line are kept.
pub const OVERSIZE_PREFIX_BYTES: usize = 1024;
/// How many trailing bytes of an oversized line are kept.
pub const OVERSIZE_SUFFIX_BYTES: usize = 256;

const READ_BUFFER_BYTES: usize = 64 * 1024;

/// One frame produced by [`LineReader`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A complete line (without the trailing `\n` / `\r\n`), never blank.
    Line(Vec<u8>),
    /// A line longer than the limit. Its body was discarded.
    Oversize {
        /// Total length of the line in bytes (excluding the newline).
        len: usize,
        /// The first [`OVERSIZE_PREFIX_BYTES`] bytes.
        prefix: Vec<u8>,
        /// The last [`OVERSIZE_SUFFIX_BYTES`] bytes.
        suffix: Vec<u8>,
    },
}

#[derive(Debug, Default)]
struct OversizeState {
    len: usize,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl OversizeState {
    fn extend(&mut self, chunk: &[u8]) {
        self.len += chunk.len();
        if self.prefix.len() < OVERSIZE_PREFIX_BYTES {
            let take = (OVERSIZE_PREFIX_BYTES - self.prefix.len()).min(chunk.len());
            self.prefix.extend_from_slice(&chunk[..take]);
        }
        if chunk.len() >= OVERSIZE_SUFFIX_BYTES {
            self.suffix.clear();
            self.suffix
                .extend_from_slice(&chunk[chunk.len() - OVERSIZE_SUFFIX_BYTES..]);
        } else {
            self.suffix.extend_from_slice(chunk);
            if self.suffix.len() > OVERSIZE_SUFFIX_BYTES {
                let excess = self.suffix.len() - OVERSIZE_SUFFIX_BYTES;
                self.suffix.drain(..excess);
            }
        }
    }

    fn into_frame(self) -> Frame {
        Frame::Oversize {
            len: self.len,
            prefix: self.prefix,
            suffix: self.suffix,
        }
    }
}

/// Bounded line reader.
///
/// [`LineReader::next_frame`] is **cancel-safe**: all partially read data
/// lives in the reader itself, so it can be used inside `tokio::select!`.
#[derive(Debug)]
pub struct LineReader<R> {
    inner: BufReader<R>,
    max_line_bytes: usize,
    line: Vec<u8>,
    oversize: Option<OversizeState>,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    /// Wrap `reader`; lines longer than `max_line_bytes` become
    /// [`Frame::Oversize`].
    pub fn new(reader: R, max_line_bytes: usize) -> Self {
        Self {
            inner: BufReader::with_capacity(READ_BUFFER_BYTES, reader),
            max_line_bytes: max_line_bytes.max(1),
            line: Vec::new(),
            oversize: None,
        }
    }

    /// Next non-blank line, `Ok(None)` at EOF. A final line without a
    /// terminating newline is still returned.
    pub async fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        loop {
            let (consumed, found_newline) = {
                let buf = self.inner.fill_buf().await?;
                if buf.is_empty() {
                    return Ok(self.finish_line());
                }
                let (end, found) = match buf.iter().position(|&b| b == b'\n') {
                    Some(i) => (i, true),
                    None => (buf.len(), false),
                };
                let chunk = &buf[..end];
                match &mut self.oversize {
                    Some(o) => o.extend(chunk),
                    None if self.line.len() + chunk.len() > self.max_line_bytes => {
                        let mut o = OversizeState::default();
                        o.extend(&self.line);
                        o.extend(chunk);
                        self.line.clear();
                        self.line.shrink_to(READ_BUFFER_BYTES);
                        self.oversize = Some(o);
                    }
                    None => self.line.extend_from_slice(chunk),
                }
                (if found { end + 1 } else { end }, found)
            };
            self.inner.consume(consumed);
            if found_newline {
                if let Some(frame) = self.finish_line() {
                    return Ok(Some(frame));
                }
            }
        }
    }

    /// Take the buffered line (or oversize record); `None` if blank.
    fn finish_line(&mut self) -> Option<Frame> {
        if let Some(o) = self.oversize.take() {
            return Some(o.into_frame());
        }
        let mut line = std::mem::take(&mut self.line);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        Some(Frame::Line(line))
    }
}

/// Writer loop: drains `rx` and writes each pre-framed message (already
/// newline terminated) to `writer`, flushing after each. Ends when every
/// sender is dropped, when `stop` is cancelled (even in the middle of a
/// blocked write) or on a write error, which is returned. The writer is
/// shut down (half-closed for sockets) and dropped on exit, so a child's
/// stdin sees EOF.
pub async fn write_loop<W>(
    mut writer: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
    stop: CancellationToken,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let result = loop {
        let msg = tokio::select! {
            biased;
            _ = stop.cancelled() => break Ok(()),
            msg = rx.recv() => msg,
        };
        let Some(msg) = msg else {
            break Ok(());
        };
        let write = async {
            writer.write_all(&msg).await?;
            writer.flush().await
        };
        tokio::select! {
            biased;
            _ = stop.cancelled() => break Ok(()),
            res = write => {
                if let Err(e) = res {
                    break Err(e);
                }
            }
        }
    };
    // Best effort: half-close sockets; pipes are closed by the drop below.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), writer.shutdown()).await;
    drop(writer);
    result
}

/// Boxed reader half of a transport.
pub type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
/// Boxed writer half of a transport.
pub type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn frames(input: &[u8], max: usize) -> Vec<Frame> {
        let mut r = LineReader::new(input, max);
        let mut out = Vec::new();
        while let Some(f) = r.next_frame().await.unwrap() {
            out.push(f);
        }
        out
    }

    fn line(s: &str) -> Frame {
        Frame::Line(s.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn splits_lines_and_skips_blank() {
        let f = frames(b"a\n\n  \r\nb\r\nc", 100).await;
        assert_eq!(f, vec![line("a"), line("b"), line("c")]);
        assert!(frames(b"", 10).await.is_empty());
        assert!(frames(b"\n\n", 10).await.is_empty());
    }

    #[tokio::test]
    async fn exact_limit_is_accepted() {
        let f = frames(b"12345\n123456\nok\n", 5).await;
        assert_eq!(f.len(), 3);
        assert_eq!(f[0], line("12345"));
        assert!(matches!(&f[1], Frame::Oversize { len: 6, .. }));
        assert_eq!(f[2], line("ok"));
    }

    #[tokio::test]
    async fn oversize_keeps_head_and_tail() {
        let mut big = Vec::new();
        big.extend_from_slice(b"HEAD");
        big.extend(std::iter::repeat_n(b'x', 10_000));
        big.extend_from_slice(b"TAIL");
        let total = big.len();
        big.extend_from_slice(b"\nnext\n");
        let f = frames(&big, 100).await;
        assert_eq!(f.len(), 2);
        match &f[0] {
            Frame::Oversize {
                len,
                prefix,
                suffix,
            } => {
                assert_eq!(*len, total);
                assert!(prefix.starts_with(b"HEAD"));
                assert_eq!(prefix.len(), OVERSIZE_PREFIX_BYTES);
                assert!(suffix.ends_with(b"TAIL"));
                assert_eq!(suffix.len(), OVERSIZE_SUFFIX_BYTES);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(f[1], line("next"));
    }

    #[tokio::test]
    async fn oversize_at_eof_without_newline() {
        let f = frames(b"ok\nabcdefghij", 4).await;
        assert_eq!(f[0], line("ok"));
        assert!(matches!(&f[1], Frame::Oversize { len: 10, .. }));
    }

    #[tokio::test]
    async fn handles_partial_chunks_across_reads() {
        let (mut tx, rx) = tokio::io::duplex(8);
        let writer = tokio::spawn(async move {
            for piece in [&b"{\"a\""[..], b":1}", b"\n{\"b", b"\":2}\n", b"tail"] {
                tx.write_all(piece).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut r = LineReader::new(rx, 1024);
        let mut got = Vec::new();
        while let Some(f) = r.next_frame().await.unwrap() {
            got.push(f);
        }
        writer.await.unwrap();
        assert_eq!(
            got,
            vec![line("{\"a\":1}"), line("{\"b\":2}"), line("tail")]
        );
    }

    #[tokio::test]
    async fn next_frame_is_cancel_safe() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut r = LineReader::new(rx, 1024);
        tx.write_all(b"hello ").await.unwrap();
        // Poll once with a timeout so the partial line gets buffered, then
        // cancel the future.
        let res = tokio::time::timeout(std::time::Duration::from_millis(20), r.next_frame()).await;
        assert!(res.is_err());
        tx.write_all(b"world\n").await.unwrap();
        drop(tx);
        assert_eq!(r.next_frame().await.unwrap(), Some(line("hello world")));
        assert_eq!(r.next_frame().await.unwrap(), None);
    }

    #[tokio::test]
    async fn write_loop_writes_and_closes() {
        let (a, b) = tokio::io::duplex(1024);
        let (tx, rx) = mpsc::channel(4);
        let stop = CancellationToken::new();
        let task = tokio::spawn(write_loop(a, rx, stop.clone()));
        tx.send(b"one\n".to_vec()).await.unwrap();
        tx.send(b"two\n".to_vec()).await.unwrap();
        drop(tx);
        task.await.unwrap().unwrap();
        let mut r = LineReader::new(b, 100);
        assert_eq!(r.next_frame().await.unwrap(), Some(line("one")));
        assert_eq!(r.next_frame().await.unwrap(), Some(line("two")));
        // The writer half was dropped -> EOF.
        assert_eq!(r.next_frame().await.unwrap(), None);
    }

    #[tokio::test]
    async fn write_loop_stop_interrupts_blocked_write() {
        // Tiny duplex buffer and no reader: the write blocks forever.
        let (a, _b) = tokio::io::duplex(4);
        let (tx, rx) = mpsc::channel(4);
        let stop = CancellationToken::new();
        let task = tokio::spawn(write_loop(a, rx, stop.clone()));
        tx.send(vec![b'x'; 1024]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        stop.cancel();
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        assert!(res.is_ok(), "write loop did not stop");
    }

    #[tokio::test]
    async fn write_loop_reports_errors() {
        let (a, b) = tokio::io::duplex(4);
        drop(b);
        let (tx, rx) = mpsc::channel(4);
        let task = tokio::spawn(write_loop(a, rx, CancellationToken::new()));
        tx.send(b"hello world\n".to_vec()).await.unwrap();
        assert!(task.await.unwrap().is_err());
    }
}
