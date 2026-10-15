//! Message chunking for channels with a per-message size limit (Telegram:
//! 4096). Blindly slicing the string every 4096 UTF-16 units could cut a
//! surrogate pair, a word, or a code block in half.
//!
//! [`split_message`] guarantees:
//! - every chunk is at most `max_len` long in the chosen [`LengthUnit`]
//!   (bytes by default; byte length is an upper bound for both the char and
//!   UTF-16 length, so a byte-sized chunk fits every channel limit);
//! - chunks are always valid UTF-8 (never split inside a character);
//! - cuts prefer paragraph breaks, then line breaks, then spaces;
//! - a fenced code block cut in two is closed at the end of the chunk and
//!   re-opened (with its info string, e.g. ```` ```rust ````) at the start of
//!   the next one, so every chunk renders correctly on its own.

/// Telegram's maximum message length.
pub const TELEGRAM_MAX_MESSAGE_LEN: usize = 4096;

/// How [`split_message_with`] measures length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LengthUnit {
    /// UTF-8 bytes (most conservative).
    #[default]
    Bytes,
    /// Unicode scalar values.
    Chars,
    /// UTF-16 code units (what Telegram and JavaScript count).
    Utf16,
}

impl LengthUnit {
    /// Length of `s` in this unit.
    pub fn measure(self, s: &str) -> usize {
        match self {
            LengthUnit::Bytes => s.len(),
            LengthUnit::Chars => s.chars().count(),
            LengthUnit::Utf16 => s.encode_utf16().count(),
        }
    }

    fn char_len(self, c: char) -> usize {
        match self {
            LengthUnit::Bytes => c.len_utf8(),
            LengthUnit::Chars => 1,
            LengthUnit::Utf16 => c.len_utf16(),
        }
    }
}

/// Split `text` into chunks of at most `max_len` UTF-8 bytes.
/// See the [module docs](self) for the guarantees.
pub fn split_message(text: &str, max_len: usize) -> Vec<String> {
    split_message_with(text, max_len, LengthUnit::Bytes)
}

/// Split `text` into chunks of at most `max_len` measured in `unit`.
///
/// Empty or whitespace-only input yields no chunks; other input that fits
/// is returned unchanged as a single chunk. `max_len` is clamped to at least 1. A single character
/// wider than `max_len` (e.g. a 4-byte emoji with `max_len < 4` bytes) is
/// emitted on its own so the split always makes progress.
pub fn split_message_with(text: &str, max_len: usize, unit: LengthUnit) -> Vec<String> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let max_len = max_len.max(1);
    if unit.measure(text) <= max_len {
        return vec![text.to_string()];
    }

    // Room reserved for "\n" + closing fence whenever the text has fences.
    let reserve = max_fence_len(text).map_or(0, |len| len + 1);
    let mut fence_aware = reserve > 0;
    let mut chunks = Vec::new();
    let mut rest = text;
    let mut fence: Option<Fence> = None;

    while !rest.is_empty() {
        let mut prefix = String::new();
        if fence_aware {
            if let Some(f) = &fence {
                prefix = format!("{}\n", f.opener);
            }
            // Too little room to re-open + close a fence and still make
            // reasonable progress: degrade to plain splitting.
            if unit.measure(&prefix) + reserve + MIN_FENCED_PAYLOAD > max_len {
                fence_aware = false;
                prefix.clear();
            }
        }
        let budget = max_len - unit.measure(&prefix);

        if unit.measure(rest) <= budget {
            push_chunk(&mut chunks, prefix + rest);
            break;
        }

        let window = if fence_aware {
            budget - reserve
        } else {
            budget
        };
        let (mut cut, mut next) = find_cut(rest, window, unit);
        if fence_aware {
            if let Some(line_start) = fence_line_backoff(rest, cut) {
                // Never cut through a fence line: end the chunk before it.
                cut = line_start - 1;
                next = line_start;
            }
        }
        let head = &rest[..cut];
        let state = if fence_aware {
            scan_fences(head, fence.take())
        } else {
            None
        };

        let mut chunk = prefix;
        chunk.push_str(head);
        if let Some(f) = &state {
            chunk.push('\n');
            chunk.push_str(&f.closer());
        }
        push_chunk(&mut chunks, chunk);

        rest = &rest[next..];
        if state.is_none() {
            // Outside code, the break itself carries no content.
            rest = rest.trim_start_matches(['\n', '\r']);
        }
        fence = state;
    }
    chunks
}

/// Minimum payload per chunk before fence re-opening is abandoned.
const MIN_FENCED_PAYLOAD: usize = 16;

fn push_chunk(chunks: &mut Vec<String>, chunk: String) {
    if !chunk.trim().is_empty() {
        chunks.push(chunk);
    }
}

/// Largest char-boundary index `i` such that `measure(s[..i]) <= window`.
fn floor_boundary(s: &str, window: usize, unit: LengthUnit) -> usize {
    let mut used = 0;
    for (idx, c) in s.char_indices() {
        let w = unit.char_len(c);
        if used + w > window {
            return idx;
        }
        used += w;
    }
    s.len()
}

/// Choose where to cut `rest` so the head fits in `window`. Returns
/// `(head_end, next_start)`; the separator between them is dropped.
fn find_cut(rest: &str, window: usize, unit: LengthUnit) -> (usize, usize) {
    let hard = floor_boundary(rest, window, unit);
    if hard == 0 {
        // A single character wider than the window: emit it alone.
        let first = rest.chars().next().map_or(rest.len(), char::len_utf8);
        return (first, first);
    }
    let candidate = &rest[..hard];
    let min = hard / 2;
    const SEPARATORS: [&str; 3] = ["\n\n", "\n", " "];
    for sep in SEPARATORS {
        if let Some(p) = candidate.rfind(sep) {
            if p > 0 && p >= min {
                return (p, p + sep.len());
            }
        }
    }
    for sep in SEPARATORS {
        if let Some(p) = candidate.rfind(sep) {
            if p > 0 {
                return (p, p + sep.len());
            }
        }
    }
    (hard, hard)
}

/// If `cut` falls strictly inside a fence line (that does not start at the
/// beginning of `rest`), return the byte index where that line starts.
fn fence_line_backoff(rest: &str, cut: usize) -> Option<usize> {
    let line_start = rest[..cut].rfind('\n').map_or(0, |p| p + 1);
    let line_end = rest[cut..].find('\n').map_or(rest.len(), |p| cut + p);
    if line_start == 0 || cut == line_start || cut == line_end {
        return None;
    }
    fence_line(&rest[line_start..line_end]).map(|_| line_start)
}

/// An open fenced code block.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fence {
    /// The full opening line (indent + marker + info string).
    opener: String,
    marker: char,
    len: usize,
}

impl Fence {
    fn closer(&self) -> String {
        std::iter::repeat_n(self.marker, self.len).collect()
    }
}

/// A fence line: up to 3 spaces of indentation, then 3+ backticks or tildes.
/// Returns `(marker, run_length, text_after_run, line_without_cr)`.
fn fence_line(raw: &str) -> Option<(char, usize, &str, &str)> {
    let line = raw.strip_suffix('\r').unwrap_or(raw);
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let t = &line[indent..];
    let marker = t.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let run = t.bytes().take_while(|&b| b == marker as u8).count();
    if run < 3 {
        return None;
    }
    Some((marker, run, &t[run..], line))
}

/// Track fence state across `text`, starting from `state`.
fn scan_fences(text: &str, mut state: Option<Fence>) -> Option<Fence> {
    for raw in text.split('\n') {
        let Some((marker, run, after, line)) = fence_line(raw) else {
            continue;
        };
        match &state {
            Some(open) => {
                if marker == open.marker && run >= open.len && after.trim().is_empty() {
                    state = None;
                }
            }
            None => {
                // A backtick fence's info string may not contain backticks
                // (CommonMark), so "```inline```" is not an opener.
                if marker == '`' && after.contains('`') {
                    continue;
                }
                state = Some(Fence {
                    opener: line.trim_end().to_string(),
                    marker,
                    len: run,
                });
            }
        }
    }
    state
}

/// Longest fence run in `text`, if it has any fence lines.
fn max_fence_len(text: &str) -> Option<usize> {
    text.split('\n')
        .filter_map(fence_line)
        .map(|(_, run, _, _)| run)
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fences_balanced(chunk: &str) -> bool {
        scan_fences(chunk, None).is_none()
    }

    fn strip_ws(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(split_message("", 10).is_empty());
    }

    #[test]
    fn short_text_is_one_unchanged_chunk() {
        assert_eq!(
            split_message("hello\n\nworld ", 4096),
            vec!["hello\n\nworld "]
        );
    }

    #[test]
    fn prefers_paragraph_breaks() {
        let p1 = "a".repeat(60);
        let p2 = "b".repeat(60);
        let text = format!("{p1}\n\n{p2}");
        assert_eq!(split_message(&text, 100), vec![p1, p2]);
    }

    #[test]
    fn falls_back_to_line_breaks() {
        let l1 = "a".repeat(60);
        let l2 = "b".repeat(60);
        let text = format!("{l1}\n{l2}");
        assert_eq!(split_message(&text, 100), vec![l1, l2]);
    }

    #[test]
    fn falls_back_to_spaces() {
        let text = "word ".repeat(50);
        let chunks = split_message(&text, 32);
        assert!(chunks.len() > 1);
        for c in &chunks {
            assert!(c.len() <= 32);
            assert!(!c.contains("wor ") && !c.starts_with("rd"), "{c:?}");
        }
        assert_eq!(strip_ws(&chunks.concat()), strip_ws(&text));
    }

    #[test]
    fn hard_split_never_breaks_utf8() {
        let text = "ä🦀ß".repeat(500);
        for max in [1, 2, 3, 4, 5, 7, 64, 4096] {
            let chunks = split_message(&text, max);
            assert_eq!(chunks.concat(), text, "max={max}");
            for c in &chunks {
                // Every char fits in 4 bytes, so only max < 4 may overflow
                // (single wide char emitted alone).
                if max >= 4 {
                    assert!(c.len() <= max, "max={max} chunk={c:?}");
                } else {
                    assert!(c.len() <= max || c.chars().count() == 1);
                }
            }
        }
    }

    #[test]
    fn utf16_unit_counts_surrogate_pairs() {
        let text = "🦀".repeat(10); // 20 UTF-16 units
        let chunks = split_message_with(&text, 5, LengthUnit::Utf16);
        assert!(chunks.iter().all(|c| LengthUnit::Utf16.measure(c) <= 5));
        assert_eq!(chunks.concat(), text);
        assert_eq!(chunks.len(), 5);
    }

    #[test]
    fn chars_unit() {
        let text = "ü".repeat(10);
        let chunks = split_message_with(&text, 4, LengthUnit::Chars);
        assert_eq!(chunks, vec!["üüüü", "üüüü", "üü"]);
    }

    #[test]
    fn code_block_is_closed_and_reopened() {
        let code: String = (0..40).map(|i| format!("let x{i} = {i};\n")).collect();
        let text = format!("Intro paragraph.\n\n```rust\n{code}```\n\nOutro.");
        let chunks = split_message(&text, 200);
        assert!(chunks.len() > 2);
        for c in &chunks {
            assert!(c.len() <= 200, "{} > 200: {c:?}", c.len());
            assert!(fences_balanced(c), "unbalanced chunk: {c:?}");
        }
        // Continuation chunks re-open with the language tag.
        assert!(chunks[1..].iter().any(|c| c.starts_with("```rust\n")));
        // All code lines survive.
        let joined = chunks.join("\n");
        for i in 0..40 {
            assert!(
                joined.contains(&format!("let x{i} = {i};")),
                "missing line {i}"
            );
        }
        assert!(chunks.last().unwrap().ends_with("Outro."));
    }

    #[test]
    fn tilde_and_long_fences() {
        let body = "x\n".repeat(80);
        let text = format!("~~~~py\n{body}~~~~\n");
        let chunks = split_message(&text, 60);
        for c in &chunks {
            assert!(c.len() <= 60);
            assert!(fences_balanced(c), "{c:?}");
        }
        assert!(chunks[1].starts_with("~~~~py\n"));
        assert!(chunks[0].ends_with("\n~~~~"));
    }

    #[test]
    fn never_cuts_through_a_fence_line() {
        let text = format!(
            "{}\n```python title=example.py\n{}```\nafter",
            "intro words ".repeat(5),
            "print(1)\n".repeat(12)
        );
        // Below ~47 bytes the opener + closer leave no room: degraded mode.
        for max in 47..140 {
            let chunks = split_message(&text, max);
            for c in &chunks {
                assert!(c.len() <= max, "max={max} chunk={c:?}");
                assert!(fences_balanced(c), "max={max} chunk={c:?}");
                if c.contains("```python") {
                    assert!(
                        c.contains("```python title=example.py\n"),
                        "max={max} chunk={c:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn inline_triple_backticks_are_not_fences() {
        assert!(scan_fences("use ```this``` inline", None).is_none());
        assert!(scan_fences("```this``` inline", None).is_none());
        assert!(scan_fences("```sh\necho", None).is_some());
        assert!(
            scan_fences("    ```sh", None).is_none(),
            "indented code is not a fence"
        );
    }

    #[test]
    fn tiny_limits_degrade_gracefully() {
        let text = format!("```verylonglanguagetag\n{}\n```", "y ".repeat(50));
        let chunks = split_message(&text, 20);
        for c in &chunks {
            assert!(c.len() <= 20, "{c:?}");
        }
        let norm = |s: &str| strip_ws(s).replace('`', "");
        assert_eq!(norm(&chunks.concat()), norm(&text));
    }

    #[test]
    fn telegram_limit_constant_works() {
        let text = "line of text\n".repeat(1000);
        let chunks = split_message(&text, TELEGRAM_MAX_MESSAGE_LEN);
        assert!(chunks.len() >= 3);
        assert!(chunks.iter().all(|c| c.len() <= TELEGRAM_MAX_MESSAGE_LEN));
        assert!(
            chunks
                .iter()
                .all(|c| c.trim_end().ends_with("line of text"))
        );
    }

    /// Deterministic pseudo-random inputs: invariants must hold for all.
    #[test]
    fn invariants_hold_on_generated_inputs() {
        let atoms = [
            "word", " ", "\n", "\n\n", "ü", "🦀", "```Q\n", "\n```\n", "**b**", "`c`", "~~~\n",
            "ab cd ef", "\t", "#",
        ];
        let mut seed: u64 = 0x5eed_1234_abcd_ef01;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..2000 {
            let len = (next() % 200) as usize;
            let text: String = (0..len)
                .map(|_| atoms[(next() % atoms.len() as u64) as usize])
                .collect();
            for unit in [LengthUnit::Bytes, LengthUnit::Chars, LengthUnit::Utf16] {
                let max = 8 + (next() % 120) as usize;
                let chunks = split_message_with(&text, max, unit);
                for c in &chunks {
                    assert!(
                        unit.measure(c) <= max,
                        "unit={unit:?} max={max} chunk={c:?}"
                    );
                    assert!(!c.trim().is_empty());
                }
                if text.trim().is_empty() {
                    assert!(chunks.is_empty());
                }
                // Content (ignoring whitespace, fence markers and the
                // re-opened info string `Q`) is kept.
                let norm = |s: &str| -> String { strip_ws(s).replace(['`', '~', 'Q'], "") };
                if max >= 40 && fences_balanced(&text) {
                    for c in &chunks {
                        assert!(fences_balanced(c), "max={max} unit={unit:?} chunk={c:?}");
                    }
                }
                if norm(&chunks.concat()) != norm(&text) {
                    panic!("max={max} unit={unit:?}\nTEXT={text:?}\nCHUNKS={chunks:#?}");
                }
            }
        }
    }
}
