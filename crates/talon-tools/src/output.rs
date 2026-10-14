//! Output capping helpers shared by the tools.

use std::collections::VecDeque;

/// Largest index `<= idx` that lies on a UTF-8 character boundary of `s`.
pub(crate) fn floor_boundary(s: &str, idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    let mut i = idx;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Keep the first `max_bytes` of `s`, appending `marker` if anything was cut.
pub(crate) fn truncate_end(s: &str, max_bytes: usize, marker: &str) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let cut = floor_boundary(s, max_bytes);
    format!("{}{marker}", &s[..cut])
}

/// Byte sink that retains only the first and last part of a stream, so a
/// command printing gigabytes costs bounded memory.
#[derive(Debug)]
pub(crate) struct HeadTail {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    head_cap: usize,
    tail_cap: usize,
    total: u64,
}

impl HeadTail {
    /// Retain at most `cap` bytes: 2/3 from the start, 1/3 from the end.
    pub(crate) fn new(cap: usize) -> Self {
        let head_cap = cap * 2 / 3;
        Self {
            head: Vec::new(),
            tail: VecDeque::new(),
            head_cap,
            tail_cap: cap - head_cap,
            total: 0,
        }
    }

    /// Append a chunk.
    pub(crate) fn push(&mut self, data: &[u8]) {
        self.total = self.total.saturating_add(data.len() as u64);
        let room = self.head_cap.saturating_sub(self.head.len());
        let take = room.min(data.len());
        self.head.extend_from_slice(&data[..take]);
        let rest = &data[take..];
        if rest.is_empty() || self.tail_cap == 0 {
            return;
        }
        if rest.len() >= self.tail_cap {
            self.tail.clear();
            self.tail.extend(&rest[rest.len() - self.tail_cap..]);
        } else {
            self.tail.extend(rest);
            let excess = self.tail.len().saturating_sub(self.tail_cap);
            if excess > 0 {
                self.tail.drain(..excess);
            }
        }
    }

    /// Whether bytes were dropped.
    pub(crate) fn truncated(&self) -> bool {
        self.total > (self.head.len() + self.tail.len()) as u64
    }

    /// Render as (lossy) UTF-8 with an omission marker when truncated.
    pub(crate) fn render(&self) -> String {
        let head = String::from_utf8_lossy(&self.head);
        let tail_bytes: Vec<u8> = self.tail.iter().copied().collect();
        let tail = String::from_utf8_lossy(&tail_bytes);
        if self.truncated() {
            let omitted = self.total - (self.head.len() + self.tail.len()) as u64;
            format!("{head}\n\n[... {omitted} bytes omitted ...]\n\n{tail}")
        } else {
            format!("{head}{tail}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_tail_small_stream_is_verbatim() {
        let mut h = HeadTail::new(30);
        h.push(b"hello ");
        h.push(b"world");
        assert!(!h.truncated());
        assert_eq!(h.render(), "hello world");
        assert_eq!(h.total, 11);
    }

    #[test]
    fn head_tail_keeps_both_ends() {
        let mut h = HeadTail::new(30);
        for i in 0..1000 {
            h.push(format!("{i:04}\n").as_bytes());
        }
        assert!(h.truncated());
        let r = h.render();
        assert!(r.starts_with("0000\n0001\n"));
        assert!(r.trim_end().ends_with("0999"));
        assert!(r.contains("bytes omitted"));
    }

    #[test]
    fn head_tail_large_single_chunk() {
        let mut h = HeadTail::new(9);
        h.push(&[b'a'; 100]);
        h.push(b"xyz");
        let r = h.render();
        assert!(r.starts_with("aaaaaa"));
        assert!(r.ends_with("xyz"));
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let s = "äöü".repeat(100);
        let t = truncate_end(&s, 11, "…");
        assert!(t.ends_with('…'));
        assert_eq!(truncate_end("short", 50, "…"), "short");
        assert_eq!(floor_boundary("ä", 1), 0);
    }
}
