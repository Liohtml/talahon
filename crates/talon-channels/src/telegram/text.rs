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

/// Characters after which `*` / `_` may open bold / italic (besides the
/// start of the text and whitespace).
const EMPHASIS_OPENERS: &[char] = &['(', '[', '{', '"', '\'', '«', '“', '‘'];
/// Characters before which `*` / `_` may close bold / italic (besides the
/// end of the text and whitespace).
const EMPHASIS_CLOSERS: &[char] = &[
    '.', ',', ';', ':', '!', '?', ')', ']', '}', '"', '\'', '»', '”', '’',
];

/// Render outbound text in the Telegram dialect (`*bold*`, `_italic_`,
/// `` `code` ``, fenced code blocks; see `talon_router::parse_text_styles`)
/// as Telegram HTML (`parse_mode: HTML`).
///
/// Telegram's legacy `Markdown` mode cannot carry arbitrary text: it read
/// `file_a and file_b` as italics (`filea and fileb`) and dropped the
/// backslash before every `*`, `_`, `` ` `` and `[` (`C:\Users\*\…`), so
/// indicators, paths and command lines arrived altered without any error.
/// HTML only needs `&`, `<` and `>` escaped. Emphasis markers count only at
/// word boundaries: the opening `*`/`_` follows the start of the text,
/// whitespace or an opening bracket or quote and precedes a non-space; the
/// closing one, on the same line, follows a non-space and precedes the end,
/// whitespace or punctuation. Anything else, unclosed markers included, is
/// kept as written.
pub fn markdown_to_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    let mut rest = text;
    while let Some((start, end, fenced)) = next_code(rest) {
        emphasis_to_html(&rest[..start].chars().collect::<Vec<_>>(), &mut out);
        let code = &rest[start..end];
        if fenced {
            push_code_block(&code[3..code.len() - 3], &mut out);
        } else {
            out.push_str("<code>");
            push_escaped(&code[1..code.len() - 1], &mut out);
            out.push_str("</code>");
        }
        rest = &rest[end..];
    }
    emphasis_to_html(&rest.chars().collect::<Vec<_>>(), &mut out);
    out
}

/// The next code region in `s`: `(start, end, fenced)` byte offsets of a
/// ```` ```…``` ```` block or a one-line, non-empty `` `…` `` span.
fn next_code(s: &str) -> Option<(usize, usize, bool)> {
    let mut from = 0;
    while let Some(rel) = s[from..].find('`') {
        let i = from + rel;
        if s[i..].starts_with("```") {
            if let Some(close) = s[i + 3..].find("```") {
                return Some((i, i + 3 + close + 3, true));
            }
        }
        let after = &s[i + 1..];
        if let Some(close) = after.find(['`', '\n']) {
            if close > 0 && after.as_bytes()[close] == b'`' {
                return Some((i, i + 1 + close + 1, false));
            }
        }
        from = i + 1;
    }
    None
}

/// A fenced block's inside: an optional language on the opening line, then
/// the code.
fn push_code_block(inner: &str, out: &mut String) {
    let (lang, body) = match inner.split_once('\n') {
        Some((first, body)) if is_code_language(first) => (Some(first), body),
        Some(("", body)) => (None, body),
        _ => (None, inner),
    };
    let body = body.strip_suffix('\n').unwrap_or(body);
    match lang {
        Some(lang) => {
            out.push_str("<pre><code class=\"language-");
            out.push_str(lang);
            out.push_str("\">");
            push_escaped(body, out);
            out.push_str("</code></pre>");
        }
        None => {
            out.push_str("<pre>");
            push_escaped(body, out);
            out.push_str("</pre>");
        }
    }
}

fn is_code_language(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '#' | '.'))
}

fn emphasis_to_html(c: &[char], out: &mut String) {
    let mut i = 0;
    while i < c.len() {
        let marker = c[i];
        if matches!(marker, '*' | '_') && can_open(c, i) {
            if let Some(j) = find_close(c, i) {
                let tag = if marker == '*' { "b" } else { "i" };
                out.push('<');
                out.push_str(tag);
                out.push('>');
                emphasis_to_html(&c[i + 1..j], out);
                out.push_str("</");
                out.push_str(tag);
                out.push('>');
                i = j + 1;
                continue;
            }
        }
        push_escaped_char(marker, out);
        i += 1;
    }
}

fn can_open(c: &[char], i: usize) -> bool {
    let before_ok = i == 0 || c[i - 1].is_whitespace() || EMPHASIS_OPENERS.contains(&c[i - 1]);
    before_ok
        && c.get(i + 1)
            .is_some_and(|&n| !n.is_whitespace() && n != c[i])
}

fn find_close(c: &[char], open: usize) -> Option<usize> {
    let marker = c[open];
    for j in open + 2..c.len() {
        if c[j] == '\n' {
            return None;
        }
        let after_ok = c
            .get(j + 1)
            .is_none_or(|&a| a.is_whitespace() || EMPHASIS_CLOSERS.contains(&a));
        if c[j] == marker && !c[j - 1].is_whitespace() && after_ok {
            return Some(j);
        }
    }
    None
}

fn push_escaped(s: &str, out: &mut String) {
    for ch in s.chars() {
        push_escaped_char(ch, out);
    }
}

fn push_escaped_char(ch: char, out: &mut String) {
    match ch {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        _ => out.push(ch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_keeps_indicators_and_paths_intact() {
        for text in [
            "file_a and file_b",
            r"C:\Users\*\AppData\Local\Temp\*.exe",
            "snake_case_name and __init__ and 2*3*4",
            "https://example.com/a_b_c/_x_/?q=*",
            "* a bullet\n- another",
            "_unclosed and *also",
        ] {
            assert_eq!(markdown_to_html(text), text, "{text}");
        }
    }

    #[test]
    fn html_escapes_markup() {
        assert_eq!(
            markdown_to_html("<script>alert(1)</script> & co"),
            "&lt;script&gt;alert(1)&lt;/script&gt; &amp; co"
        );
    }

    #[test]
    fn html_renders_emphasis_at_word_boundaries() {
        assert_eq!(
            markdown_to_html("*Summary*: host _web-01_ is (*clean*)."),
            "<b>Summary</b>: host <i>web-01</i> is (<b>clean</b>)."
        );
        assert_eq!(
            markdown_to_html("*bold _and italic_*"),
            "<b>bold <i>and italic</i></b>"
        );
        // Emphasis never spans lines.
        assert_eq!(markdown_to_html("*a\nb*"), "*a\nb*");
    }

    #[test]
    fn html_renders_code_verbatim() {
        assert_eq!(
            markdown_to_html("run `rm -rf *_old_*` <now>"),
            "run <code>rm -rf *_old_*</code> &lt;now&gt;"
        );
        assert_eq!(
            markdown_to_html("```powershell\nGet-Item C:\\a_b <x>\n```"),
            "<pre><code class=\"language-powershell\">Get-Item C:\\a_b &lt;x&gt;</code></pre>"
        );
        assert_eq!(markdown_to_html("```\n*x*\n```"), "<pre>*x*</pre>");
        assert_eq!(markdown_to_html("```a b\nc```"), "<pre>a b\nc</pre>");
        // Unclosed fences and empty spans are text.
        assert_eq!(markdown_to_html("```rust\nfn x()"), "```rust\nfn x()");
        assert_eq!(markdown_to_html("a `` b"), "a `` b");
    }

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
