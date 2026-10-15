//! Text helpers for the Telegram Bot API, which measures lengths and entity
//! offsets in UTF-16 code units (like JavaScript strings).

/// Telegram's per-message text limit (UTF-16 code units).
pub const TELEGRAM_MAX_MESSAGE_LEN: usize = 4096;

/// Split `text` into chunks of at most `max_units` UTF-16 code units.
///
/// Chunks never split a character (surrogate pairs stay together). When a
/// chunk has to be cut, the cut prefers the last newline in the second half
/// of the window so paragraphs and code lines stay intact; otherwise it cuts
/// at the limit. Empty input yields no chunks.
pub fn chunk_text(text: &str, max_units: usize) -> Vec<&str> {
    // A surrogate pair needs two units; never loop without progress.
    let max_units = max_units.max(2);
    let mut chunks = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut units = 0usize;
        let mut cut = rest.len();
        // (byte index just after the newline, units up to and including it)
        let mut last_newline: Option<(usize, usize)> = None;
        for (idx, ch) in rest.char_indices() {
            let width = ch.len_utf16();
            if units + width > max_units {
                cut = idx;
                break;
            }
            units += width;
            if ch == '\n' {
                last_newline = Some((idx + ch.len_utf8(), units));
            }
        }
        if cut < rest.len() {
            if let Some((nl_end, nl_units)) = last_newline {
                if nl_units >= max_units / 2 {
                    cut = nl_end;
                }
            }
        }
        let (head, tail) = rest.split_at(cut);
        chunks.push(head);
        rest = tail;
    }
    chunks
}

/// Substring by UTF-16 code-unit `offset` and `length` (Telegram entity
/// coordinates). Returns `None` when the range is out of bounds.
pub fn utf16_slice(text: &str, offset: usize, length: usize) -> Option<String> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let end = offset.checked_add(length)?;
    let slice = units.get(offset..end)?;
    Some(String::from_utf16_lossy(slice))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_is_one_chunk() {
        assert_eq!(chunk_text("hello", 4096), vec!["hello"]);
        assert!(chunk_text("", 4096).is_empty());
    }

    #[test]
    fn splits_at_limit_without_newlines() {
        let text = "x".repeat(5000);
        let chunks = chunk_text(&text, TELEGRAM_MAX_MESSAGE_LEN);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], "x".repeat(4096));
        assert_eq!(chunks[1], "x".repeat(904));
    }

    #[test]
    fn exactly_limit_is_one_chunk() {
        let text = "y".repeat(4096);
        assert_eq!(chunk_text(&text, TELEGRAM_MAX_MESSAGE_LEN).len(), 1);
    }

    #[test]
    fn prefers_newline_in_second_half() {
        let text = format!("{}\n{}", "a".repeat(8), "b".repeat(8));
        let chunks = chunk_text(&text, 10);
        assert_eq!(chunks, vec!["aaaaaaaa\n", "bbbbbbbb"]);
        // A newline in the first half is ignored (would make tiny chunks).
        let text = format!("ab\n{}", "c".repeat(20));
        let chunks = chunk_text(&text, 10);
        assert_eq!(chunks[0], format!("ab\n{}", "c".repeat(7)));
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn counts_utf16_units_and_keeps_surrogate_pairs() {
        // Each emoji is 2 UTF-16 units / 4 UTF-8 bytes.
        let text = "😂".repeat(5);
        let chunks = chunk_text(&text, 3);
        assert!(chunks.iter().all(|c| c.encode_utf16().count() <= 3));
        assert_eq!(chunks.concat(), text);
        assert_eq!(chunks.len(), 5);
        // Mixed: never more than the limit, nothing lost.
        let text = "aé😂b".repeat(1000);
        let chunks = chunk_text(&text, 7);
        assert!(chunks.iter().all(|c| c.encode_utf16().count() <= 7));
        assert_eq!(chunks.concat(), text);
        // Degenerate limits still make progress.
        assert_eq!(chunk_text("😂😂", 0).concat(), "😂😂");
    }

    #[test]
    fn utf16_slice_matches_js_substring() {
        let text = "😂 @talonai_bot hi";
        // The emoji occupies units 0..2, the space 2, the mention 3..15.
        assert_eq!(utf16_slice(text, 3, 12).as_deref(), Some("@talonai_bot"));
        assert_eq!(utf16_slice("abc", 1, 5), None);
        assert_eq!(utf16_slice("abc", usize::MAX, 2), None);
        assert_eq!(utf16_slice("abc", 3, 0).as_deref(), Some(""));
    }
}
