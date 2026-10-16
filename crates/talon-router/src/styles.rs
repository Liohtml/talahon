//! Markdown -> channel-native text styles.
//!
//! The agent writes standard Markdown. Each channel dialect renders it
//! differently:
//!
//! | [`ChannelType`]            | conversion                                         |
//! |----------------------------|----------------------------------------------------|
//! | `Markdown`                 | passthrough                                        |
//! | `Signal`                   | passthrough (use [`parse_signal_styles`])          |
//! | `WhatsApp` / `Telegram`    | `*bold*`, `_italic_`, headings bold, `text (url)`  |
//! | `Slack`                    | as above, links as `<url|text>`                    |
//! | `Plain`                    | every marker stripped (via [`parse_signal_styles`])|
//!
//! Code (fenced blocks and inline code spans) is never touched by marker
//! substitution. The conversion rules are implemented as small linear
//! scanners (the `regex` crate has no lookbehind).

use serde::{Deserialize, Serialize};
use talon_core::channel::ChannelType;

/// Transform Markdown `text` into the native style syntax of `channel`.
pub fn parse_text_styles(text: &str, channel: ChannelType) -> String {
    if text.is_empty() {
        return String::new();
    }
    match channel {
        ChannelType::Markdown | ChannelType::Signal => text.to_string(),
        ChannelType::Plain => markdown_to_plain(text),
        ChannelType::WhatsApp | ChannelType::Telegram | ChannelType::Slack => {
            let slack = channel == ChannelType::Slack;
            split_protected_regions(text)
                .into_iter()
                .map(|seg| {
                    if seg.protected {
                        seg.content.to_string()
                    } else {
                        transform_segment(seg.content, slack)
                    }
                })
                .collect()
        }
    }
}

/// Strip every Markdown marker, producing plain text (links become
/// `text (url)`, headings and emphasis lose their markers, code fences are
/// removed but their content kept).
pub fn markdown_to_plain(text: &str) -> String {
    parse_signal_styles(text).text
}

// ---------------------------------------------------------------------------
// Marker substitution (WhatsApp / Telegram / Slack)
// ---------------------------------------------------------------------------

struct Segment<'a> {
    content: &'a str,
    protected: bool,
}

/// Split into alternating unprotected / protected (code) segments.
/// Protected = fenced blocks (```` ```…``` ````) and inline code (`` `…` ``,
/// single line, non-empty) — same as `/```[\s\S]*?```|`[^`\n]+`/g`.
fn split_protected_regions(text: &str) -> Vec<Segment<'_>> {
    fn push_code<'a>(
        segments: &mut Vec<Segment<'a>>,
        text: &'a str,
        last: usize,
        start: usize,
        end: usize,
    ) {
        if start > last {
            segments.push(Segment {
                content: &text[last..start],
                protected: false,
            });
        }
        segments.push(Segment {
            content: &text[start..end],
            protected: true,
        });
    }

    let b = text.as_bytes();
    let n = b.len();
    let mut segments = Vec::new();
    let mut last = 0;
    let mut i = 0;

    while i < n {
        if b[i] == b'`' {
            // Alternative 1: fenced block.
            if text[i..].starts_with("```") {
                if let Some(rel) = text[i + 3..].find("```") {
                    let end = i + 3 + rel + 3;
                    push_code(&mut segments, text, last, i, end);
                    last = end;
                    i = end;
                    continue;
                }
            }
            // Alternative 2: inline code.
            let mut j = i + 1;
            while j < n && b[j] != b'`' && b[j] != b'\n' {
                j += 1;
            }
            if j < n && b[j] == b'`' && j > i + 1 {
                push_code(&mut segments, text, last, i, j + 1);
                last = j + 1;
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }

    if last < n {
        segments.push(Segment {
            content: &text[last..],
            protected: false,
        });
    }
    if segments.is_empty() {
        segments.push(Segment {
            content: text,
            protected: false,
        });
    }
    segments
}

fn transform_segment(text: &str, slack: bool) -> String {
    // Order matters: italic before bold (the italic rule never matches
    // `**bold**`, but would re-convert `*bold*`).
    let t = convert_italic(text);
    let t = convert_bold(&t);
    let t = map_lines(&t, convert_heading_line);
    let t = convert_links(&t, slack);
    map_lines(&t, strip_rule_line)
}

/// Characters after which an emphasis marker may open (besides the start
/// and whitespace).
const EMPHASIS_OPENERS: &[char] = &['(', '[', '{', '"', '\'', '«', '“', '‘'];
/// Characters before which an emphasis marker may close (besides the end
/// and whitespace).
const EMPHASIS_CLOSERS: &[char] = &[
    '.', ',', ';', ':', '!', '?', ')', ']', '}', '"', '\'', '»', '”', '’',
];

/// A marker at `i` may open emphasis: it starts a word. `2*3*4` and
/// `C:\Users\*\…` keep their stars.
fn opens_at(c: &[char], i: usize) -> bool {
    i == 0 || c[i - 1].is_whitespace() || EMPHASIS_OPENERS.contains(&c[i - 1])
}

/// A marker ending just before `k` may close emphasis: it ends a word.
fn closes_before(c: &[char], k: usize) -> bool {
    c.get(k)
        .is_none_or(|&a| a.is_whitespace() || EMPHASIS_CLOSERS.contains(&a))
}

/// `*italic*` -> `_italic_` when the stars start and end a word (single
/// line, no space inside the markers).
fn convert_italic(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let n = c.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        if c[i] == '*'
            && opens_at(&c, i)
            && i + 1 < n
            && !c[i + 1].is_whitespace()
            && c[i + 1] != '*'
        {
            let mut j = i + 1;
            while j < n && c[j] != '*' && c[j] != '\n' {
                j += 1;
            }
            if j < n && c[j] == '*' && !c[j - 1].is_whitespace() && closes_before(&c, j + 1) {
                out.push('_');
                out.extend(&c[i + 1..j]);
                out.push('_');
                i = j + 1;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// `**bold**` -> `*bold*` when the markers start and end a word.
fn convert_bold(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let n = c.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        if c[i] == '*'
            && opens_at(&c, i)
            && i + 2 < n
            && c[i + 1] == '*'
            && !c[i + 2].is_whitespace()
            && c[i + 2] != '*'
        {
            let mut j = i + 2;
            while j < n && c[j] != '*' {
                j += 1;
            }
            if j + 1 < n && c[j + 1] == '*' && !c[j - 1].is_whitespace() && closes_before(&c, j + 2)
            {
                out.push('*');
                out.extend(&c[i + 2..j]);
                out.push('*');
                i = j + 2;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// Apply `f` to every line (separated by `\n`; a trailing `\r` is kept out of
/// the line content, like JavaScript's `$` in multiline mode).
fn map_lines(s: &str, f: fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(s.len());
    for (idx, raw) in s.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let (line, cr) = match raw.strip_suffix('\r') {
            Some(l) => (l, "\r"),
            None => (raw, ""),
        };
        match f(line) {
            Some(replaced) => out.push_str(&replaced),
            None => out.push_str(line),
        }
        out.push_str(cr);
    }
    out
}

/// `^#{1,6}\s+(.+)$` -> `*$1*`
fn convert_heading_line(line: &str) -> Option<String> {
    let hashes = line.bytes().take_while(|&b| b == b'#').count();
    if !(1..=6).contains(&hashes) {
        return None;
    }
    let rest = &line[hashes..];
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let content = rest.trim_start();
    if content.is_empty() {
        return None;
    }
    Some(format!("*{content}*"))
}

/// `^(-{3,}|\*{3,}|_{3,})$` -> empty line
fn strip_rule_line(line: &str) -> Option<String> {
    let first = line.chars().next()?;
    if matches!(first, '-' | '*' | '_') && line.len() >= 3 && line.chars().all(|c| c == first) {
        Some(String::new())
    } else {
        None
    }
}

/// `\[([^\]]+)\]\(([^)]+)\)` -> `$1 ($2)` (or `<$2|$1>` for Slack)
fn convert_links(s: &str, slack: bool) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut i = 0;
    while i < n {
        if b[i] == b'[' {
            if let Some(close_rel) = s[i + 1..].find(']') {
                let close = i + 1 + close_rel;
                if close > i + 1 && close + 1 < n && b[close + 1] == b'(' {
                    if let Some(paren_rel) = s[close + 2..].find(')') {
                        let paren = close + 2 + paren_rel;
                        if paren > close + 2 {
                            let text = &s[i + 1..close];
                            let url = &s[close + 2..paren];
                            out.push_str(&s[last..i]);
                            if slack {
                                out.push('<');
                                out.push_str(url);
                                out.push('|');
                                out.push_str(text);
                                out.push('>');
                            } else {
                                out.push_str(text);
                                out.push_str(" (");
                                out.push_str(url);
                                out.push(')');
                            }
                            i = paren + 1;
                            last = i;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

// ---------------------------------------------------------------------------
// Signal rich text
// ---------------------------------------------------------------------------

/// One of Signal's supported text styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalStyle {
    /// `**bold**` and headings.
    Bold,
    /// `*italic*` / `_italic_`.
    Italic,
    /// `~~strike~~`.
    Strikethrough,
    /// Inline code and fenced blocks.
    Monospace,
    /// Spoiler (never produced by the parser; part of the wire enum).
    Spoiler,
}

/// A styled range of the output text. Offsets are UTF-16 code units, which
/// is what signal-cli's JSON-RPC `send.textStyle` parameter expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalTextStyle {
    /// Style applied to the range.
    pub style: SignalStyle,
    /// Start offset (UTF-16 code units).
    pub start: usize,
    /// Length (UTF-16 code units).
    pub length: usize,
}

/// Result of [`parse_signal_styles`]: marker-free text plus style ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalText {
    /// Text with all Markdown markers removed.
    pub text: String,
    /// Style ranges over `text`.
    #[serde(rename = "textStyle")]
    pub text_style: Vec<SignalTextStyle>,
}

struct SignalOut {
    text: String,
    utf16_len: usize,
    styles: Vec<SignalTextStyle>,
}

impl SignalOut {
    fn push(&mut self, c: char) {
        self.text.push(c);
        self.utf16_len += c.len_utf16();
    }

    fn push_all(&mut self, cs: &[char]) {
        for &c in cs {
            self.push(c);
        }
    }

    fn push_styled(&mut self, style: SignalStyle, cs: &[char]) {
        let start = self.utf16_len;
        self.push_all(cs);
        let length = self.utf16_len - start;
        if length > 0 {
            self.styles.push(SignalTextStyle {
                style,
                start,
                length,
            });
        }
    }
}

fn find_char(s: &[char], c: char, from: usize) -> Option<usize> {
    s.get(from..)?
        .iter()
        .position(|&x| x == c)
        .map(|p| p + from)
}

fn find_seq(s: &[char], pat: &[char], from: usize) -> Option<usize> {
    if pat.is_empty() || from >= s.len() {
        return None;
    }
    s[from..]
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|p| p + from)
}

fn slice(s: &[char], start: usize, end: usize) -> &[char] {
    if start >= end || start >= s.len() {
        &[]
    } else {
        &s[start..end.min(s.len())]
    }
}

/// JavaScript `/\w/` (ASCII word character).
fn is_js_word(c: Option<char>) -> bool {
    matches!(c, Some(c) if c.is_ascii_alphanumeric() || c == '_')
}

/// Find the closing single `*` (not part of `**`, not preceded by a space).
fn find_closing_star(s: &[char], from: usize) -> Option<usize> {
    for i in from..s.len() {
        if s[i] == '\n' {
            return None;
        }
        if s[i] == '*' && s.get(i + 1) != Some(&'*') && i > 0 && s[i - 1] != ' ' {
            return Some(i);
        }
    }
    None
}

/// Find the closing `_` that is not part of `__` and ends a word.
fn find_closing_underscore(s: &[char], from: usize) -> Option<usize> {
    for i in from..s.len() {
        if s[i] == '\n' {
            return None;
        }
        if s[i] == '_' && s.get(i + 1) != Some(&'_') && !is_js_word(s.get(i + 1).copied()) {
            return Some(i);
        }
    }
    None
}

/// Length of a horizontal rule (`---`, `***`, `___`, trailing spaces and the
/// newline included) starting at `i`, if there is one.
fn horizontal_rule_len(s: &[char], i: usize) -> Option<usize> {
    let marker = *s.get(i)?;
    if !matches!(marker, '-' | '*' | '_') {
        return None;
    }
    let mut j = i;
    while j < s.len() && s[j] == marker {
        j += 1;
    }
    if j - i < 3 {
        return None;
    }
    while j < s.len() && s[j] == ' ' {
        j += 1;
    }
    match s.get(j) {
        None => Some(j - i),
        Some('\n') => Some(j + 1 - i),
        Some(_) => None,
    }
}

/// Parse Markdown into marker-free text plus Signal `textStyle` ranges.
///
/// Supported: `**bold**`, `*italic*`, `_italic_` (word-boundary guarded, so
/// `snake_case` survives), `~~strike~~`, `` `code` ``, fenced blocks,
/// `## heading` (bold), `[text](url)` -> `text (url)`, horizontal rules
/// (removed).
pub fn parse_signal_styles(raw: &str) -> SignalText {
    let s: Vec<char> = raw.chars().collect();
    let n = s.len();
    let mut out = SignalOut {
        text: String::with_capacity(raw.len()),
        utf16_len: 0,
        styles: Vec::new(),
    };
    let at = |i: usize| s.get(i).copied();
    let mut i = 0;

    while i < n {
        let c = s[i];

        // Fenced code block ```[lang]\n...\n```
        if c == '`' && at(i + 1) == Some('`') && at(i + 2) == Some('`') {
            if let Some(lang_nl) = find_char(&s, '\n', i + 3) {
                if let Some(close_at) = find_seq(&s, &['\n', '`', '`', '`'], lang_nl) {
                    out.push_styled(SignalStyle::Monospace, slice(&s, lang_nl + 1, close_at));
                    i = match find_char(&s, '\n', close_at + 4) {
                        Some(after) => after + 1,
                        None => n,
                    };
                    continue;
                }
            }
            // Malformed fence: copy literally.
            out.push(c);
            i += 1;
            continue;
        }

        // Inline code `text`
        if c == '`' {
            let end = find_char(&s, '`', i + 1);
            let nl = find_char(&s, '\n', i + 1);
            if let Some(end) = end {
                if nl.is_none_or(|nl| end < nl) {
                    out.push_styled(SignalStyle::Monospace, slice(&s, i + 1, end));
                    i = end + 1;
                    continue;
                }
            }
        }

        // Bold **text**
        if c == '*' && at(i + 1) == Some('*') && at(i + 2).is_some_and(|x| x != ' ') {
            if let Some(end) = find_seq(&s, &['*', '*'], i + 2) {
                if s[end - 1] != ' ' {
                    out.push_styled(SignalStyle::Bold, slice(&s, i + 2, end));
                    i = end + 2;
                    continue;
                }
            }
        }

        // Strikethrough ~~text~~
        if c == '~' && at(i + 1) == Some('~') && at(i + 2).is_some_and(|x| x != ' ') {
            if let Some(end) = find_seq(&s, &['~', '~'], i + 2) {
                out.push_styled(SignalStyle::Strikethrough, slice(&s, i + 2, end));
                i = end + 2;
                continue;
            }
        }

        // Italic *text* (single star)
        if c == '*' && at(i + 1).is_some_and(|x| x != '*' && x != ' ') {
            if let Some(end) = find_closing_star(&s, i + 1) {
                out.push_styled(SignalStyle::Italic, slice(&s, i + 1, end));
                i = end + 1;
                continue;
            }
        }

        // Italic _text_ (word boundaries only)
        if c == '_' && at(i + 1).is_some_and(|x| x != '_' && x != ' ') {
            let prev = if i > 0 { Some(s[i - 1]) } else { None };
            if !is_js_word(prev) {
                if let Some(end) = find_closing_underscore(&s, i + 1) {
                    out.push_styled(SignalStyle::Italic, slice(&s, i + 1, end));
                    i = end + 1;
                    continue;
                }
            }
        }

        // ATX heading ## text -> text (bold)
        if (i == 0 || s[i - 1] == '\n') && c == '#' {
            let mut j = i;
            while j < n && s[j] == '#' {
                j += 1;
            }
            if at(j) == Some(' ') {
                let line_end = find_char(&s, '\n', j + 1);
                let heading_end = line_end.unwrap_or(n);
                out.push_styled(SignalStyle::Bold, slice(&s, j + 1, heading_end));
                match line_end {
                    Some(le) => {
                        out.push('\n');
                        i = le + 1;
                    }
                    None => i = n,
                }
                continue;
            }
        }

        // Links [text](url) -> text (url)
        if c == '[' {
            if let Some(close_bracket) = find_char(&s, ']', i + 1) {
                if at(close_bracket + 1) == Some('(') {
                    if let Some(close_paren) = find_char(&s, ')', close_bracket + 2) {
                        out.push_all(slice(&s, i + 1, close_bracket));
                        out.push(' ');
                        out.push('(');
                        out.push_all(slice(&s, close_bracket + 2, close_paren));
                        out.push(')');
                        i = close_paren + 1;
                        continue;
                    }
                }
            }
        }

        // Horizontal rule --- / *** / ___
        if i == 0 || s[i - 1] == '\n' {
            if let Some(len) = horizontal_rule_len(&s, i) {
                i += len;
                continue;
            }
        }

        out.push(c);
        i += 1;
    }

    SignalText {
        text: out.text,
        text_style: out.styles,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ChannelType::*;

    fn style(style: SignalStyle, start: usize, length: usize) -> SignalTextStyle {
        SignalTextStyle {
            style,
            start,
            length,
        }
    }

    // --- passthrough --------------------------------------------------------

    #[test]
    fn markdown_channel_is_passthrough() {
        let md = "**bold** and *italic* and [link](https://example.com)";
        assert_eq!(parse_text_styles(md, Markdown), md);
    }

    #[test]
    fn signal_channel_is_passthrough() {
        let md = "**bold** and *italic* and [link](https://example.com)";
        assert_eq!(parse_text_styles(md, Signal), md);
    }

    #[test]
    fn empty_text_stays_empty() {
        assert_eq!(parse_text_styles("", Telegram), "");
    }

    // --- bold ---------------------------------------------------------------

    #[test]
    fn bold_on_whatsapp() {
        assert_eq!(parse_text_styles("**hello**", WhatsApp), "*hello*");
    }

    #[test]
    fn bold_on_telegram() {
        assert_eq!(
            parse_text_styles("say **this** now", Telegram),
            "say *this* now"
        );
    }

    #[test]
    fn bold_on_slack() {
        assert_eq!(parse_text_styles("**hello**", Slack), "*hello*");
    }

    #[test]
    fn lone_star_is_not_bold() {
        assert_eq!(parse_text_styles("a * b * c", WhatsApp), "a * b * c");
    }

    #[test]
    fn bold_may_span_lines() {
        assert_eq!(parse_text_styles("**a\nb**", Telegram), "*a\nb*");
    }

    // --- italic -------------------------------------------------------------

    #[test]
    fn italic_on_whatsapp() {
        assert_eq!(
            parse_text_styles("say *this* now", WhatsApp),
            "say _this_ now"
        );
    }

    #[test]
    fn italic_on_telegram() {
        assert_eq!(parse_text_styles("*italic*", Telegram), "_italic_");
    }

    #[test]
    fn bold_before_italic() {
        assert_eq!(
            parse_text_styles("**bold** *italic*", WhatsApp),
            "*bold* _italic_"
        );
    }

    #[test]
    fn stars_inside_words_are_kept() {
        for text in [
            "2*3*4",
            r"C:\Users\*\AppData\Local\*.tmp",
            "glob a*b*c and x**y**z",
        ] {
            assert_eq!(parse_text_styles(text, Telegram), text);
            assert_eq!(parse_text_styles(text, WhatsApp), text);
        }
        assert_eq!(
            parse_text_styles("(**bold**) and *it*.", Telegram),
            "(*bold*) and _it_."
        );
    }

    #[test]
    fn italic_does_not_span_lines() {
        assert_eq!(parse_text_styles("*a\nb*", Telegram), "*a\nb*");
    }

    #[test]
    fn italic_handles_multibyte_content() {
        assert_eq!(parse_text_styles("*grüße 🦀*", Telegram), "_grüße 🦀_");
    }

    // --- headings -----------------------------------------------------------

    #[test]
    fn h1_on_whatsapp() {
        assert_eq!(parse_text_styles("# Top", WhatsApp), "*Top*");
    }

    #[test]
    fn h2_on_telegram() {
        assert_eq!(
            parse_text_styles("## Hello World", Telegram),
            "*Hello World*"
        );
    }

    #[test]
    fn h3_on_telegram() {
        assert_eq!(parse_text_styles("### Section", Telegram), "*Section*");
    }

    #[test]
    fn headings_only_at_line_start() {
        let input = "not a ## heading in middle";
        assert_eq!(parse_text_styles(input, WhatsApp), input);
    }

    #[test]
    fn seven_hashes_is_not_a_heading() {
        assert_eq!(parse_text_styles("####### x", Telegram), "####### x");
    }

    #[test]
    fn hashtag_is_not_a_heading() {
        assert_eq!(parse_text_styles("#incident", Telegram), "#incident");
    }

    #[test]
    fn heading_keeps_crlf() {
        assert_eq!(parse_text_styles("## T\r\nx", Telegram), "*T*\r\nx");
    }

    // --- links --------------------------------------------------------------

    #[test]
    fn link_on_whatsapp() {
        assert_eq!(
            parse_text_styles("[Link](https://example.com)", WhatsApp),
            "Link (https://example.com)"
        );
    }

    #[test]
    fn link_on_telegram() {
        assert_eq!(
            parse_text_styles("[Link](https://example.com)", Telegram),
            "Link (https://example.com)"
        );
    }

    #[test]
    fn link_on_slack() {
        assert_eq!(
            parse_text_styles("[Click here](https://example.com)", Slack),
            "<https://example.com|Click here>"
        );
    }

    #[test]
    fn incomplete_links_are_left_alone() {
        assert_eq!(
            parse_text_styles("[a] (b) [](x) [y]()", Telegram),
            "[a] (b) [](x) [y]()"
        );
    }

    // --- horizontal rules ---------------------------------------------------

    #[test]
    fn strips_dash_rule_on_telegram() {
        assert_eq!(
            parse_text_styles("above\n---\nbelow", Telegram),
            "above\n\nbelow"
        );
    }

    #[test]
    fn strips_star_rule_on_whatsapp() {
        assert_eq!(
            parse_text_styles("above\n***\nbelow", WhatsApp),
            "above\n\nbelow"
        );
    }

    // --- code protection ----------------------------------------------------

    #[test]
    fn fenced_code_is_protected() {
        let input = "```\n**not bold**\n```";
        assert_eq!(parse_text_styles(input, WhatsApp), input);
    }

    #[test]
    fn inline_code_is_protected() {
        let input = "use `*star*` literally";
        assert_eq!(parse_text_styles(input, Telegram), input);
    }

    #[test]
    fn transforms_around_inline_code() {
        assert_eq!(
            parse_text_styles("**bold** and `*code*` and *italic*", WhatsApp),
            "*bold* and `*code*` and _italic_"
        );
    }

    #[test]
    fn transforms_around_fenced_block() {
        assert_eq!(
            parse_text_styles("**bold**\n```\n**raw**\n```\n*italic*", Telegram),
            "*bold*\n```\n**raw**\n```\n_italic_"
        );
    }

    #[test]
    fn unclosed_fence_is_not_protected() {
        assert_eq!(parse_text_styles("```\n**x**", Telegram), "```\n*x*");
    }

    // --- plain --------------------------------------------------------------

    #[test]
    fn plain_strips_all_markers() {
        assert_eq!(
            parse_text_styles(
                "## Title\n**bold** _it_ `code` [l](https://x.y)\n---\nend",
                Plain
            ),
            "Title\nbold it code l (https://x.y)\nend"
        );
    }

    // --- parse_signal_styles ------------------------------------------------

    #[test]
    fn signal_bold() {
        let r = parse_signal_styles("**hello**");
        assert_eq!(r.text, "hello");
        assert_eq!(r.text_style, vec![style(SignalStyle::Bold, 0, 5)]);
    }

    #[test]
    fn signal_italic_star() {
        let r = parse_signal_styles("*hello*");
        assert_eq!(r.text, "hello");
        assert_eq!(r.text_style, vec![style(SignalStyle::Italic, 0, 5)]);
    }

    #[test]
    fn signal_italic_underscore() {
        let r = parse_signal_styles("_hello_");
        assert_eq!(r.text, "hello");
        assert_eq!(r.text_style, vec![style(SignalStyle::Italic, 0, 5)]);
    }

    #[test]
    fn signal_strikethrough() {
        let r = parse_signal_styles("~~hello~~");
        assert_eq!(r.text, "hello");
        assert_eq!(r.text_style, vec![style(SignalStyle::Strikethrough, 0, 5)]);
    }

    #[test]
    fn signal_inline_code() {
        let r = parse_signal_styles("`code`");
        assert_eq!(r.text, "code");
        assert_eq!(r.text_style, vec![style(SignalStyle::Monospace, 0, 4)]);
    }

    #[test]
    fn signal_heading() {
        let r = parse_signal_styles("## Hello World");
        assert_eq!(r.text, "Hello World");
        assert_eq!(r.text_style, vec![style(SignalStyle::Bold, 0, 11)]);
    }

    #[test]
    fn signal_plain_text() {
        let r = parse_signal_styles("just plain text");
        assert_eq!(r.text, "just plain text");
        assert!(r.text_style.is_empty());
    }

    #[test]
    fn signal_offsets_in_mixed_text() {
        let r = parse_signal_styles("say **hi** now");
        assert_eq!(r.text, "say hi now");
        assert_eq!(r.text_style, vec![style(SignalStyle::Bold, 4, 2)]);
    }

    #[test]
    fn signal_multiple_styles() {
        let r = parse_signal_styles("**bold** and *italic*");
        assert_eq!(r.text, "bold and italic");
        assert_eq!(r.text_style[0], style(SignalStyle::Bold, 0, 4));
        assert_eq!(r.text_style[1], style(SignalStyle::Italic, 9, 6));
    }

    #[test]
    fn signal_links() {
        let r = parse_signal_styles("[Click here](https://example.com)");
        assert_eq!(r.text, "Click here (https://example.com)");
        assert!(r.text_style.is_empty());
    }

    #[test]
    fn signal_horizontal_rules() {
        let r = parse_signal_styles("above\n---\nbelow");
        assert_eq!(r.text, "above\nbelow");
        assert!(r.text_style.is_empty());
    }

    #[test]
    fn signal_fenced_block() {
        let r = parse_signal_styles("```\n**not bold**\n```");
        assert_eq!(r.text, "**not bold**");
        assert_eq!(r.text_style, vec![style(SignalStyle::Monospace, 0, 12)]);
    }

    #[test]
    fn signal_styles_outside_block() {
        let r = parse_signal_styles("**bold**\n```\nraw code\n```");
        assert!(r.text.contains("bold"));
        assert!(r.text.contains("raw code"));
        assert!(r.text_style.iter().any(|s| s.style == SignalStyle::Bold));
        assert!(
            r.text_style
                .iter()
                .any(|s| s.style == SignalStyle::Monospace)
        );
    }

    #[test]
    fn signal_snake_case_guard() {
        let r = parse_signal_styles("use snake_case_here");
        assert_eq!(r.text, "use snake_case_here");
        assert!(r.text_style.is_empty());
    }

    #[test]
    fn signal_offsets_are_utf16() {
        // 🦀 is two UTF-16 code units.
        let r = parse_signal_styles("🦀 **ü🦀**");
        assert_eq!(r.text, "🦀 ü🦀");
        assert_eq!(r.text_style, vec![style(SignalStyle::Bold, 3, 3)]);
    }

    #[test]
    fn signal_empty_fenced_block() {
        let r = parse_signal_styles("```\n```\nafter");
        assert_eq!(r.text, "after");
        assert!(r.text_style.is_empty());
    }

    #[test]
    fn signal_serializes_like_signal_cli() {
        let r = parse_signal_styles("**a**");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["textStyle"][0]["style"], "BOLD");
        assert_eq!(v["textStyle"][0]["start"], 0);
    }

    #[test]
    fn scanners_never_panic_on_odd_input() {
        let inputs = [
            "*",
            "**",
            "***",
            "_",
            "__",
            "~~",
            "`",
            "``",
            "```",
            "[",
            "[]",
            "[](",
            "](",
            "#",
            "# ",
            "*\n*",
            "**\n",
            "_a",
            "a_",
            "~~ ~~",
            "``` ```",
            "\n```\n",
            "🦀*🦀*",
            "*🦀",
        ];
        for input in inputs {
            for ch in [Markdown, Telegram, WhatsApp, Slack, Signal, Plain] {
                let _ = parse_text_styles(input, ch);
            }
            let _ = parse_signal_styles(input);
        }
    }
}
