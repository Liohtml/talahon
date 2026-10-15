//! Minimal, dependency-free HTML → readable text conversion for `web_fetch`.
//!
//! Not a full HTML parser: it removes scripts/styles/comments and other
//! non-content elements, turns block elements into line breaks, list items
//! into `- ` bullets and headings into `#` markers, appends absolute link
//! targets as `text (url)`, decodes character references and collapses
//! whitespace (except inside `<pre>`). Work is linear in the input size.

/// Elements whose entire content is dropped.
const SKIP_CONTENT: &[&str] = &[
    "script", "style", "noscript", "template", "svg", "head", "iframe", "object", "canvas",
    "select", "button",
];

/// Elements that start/end on their own line.
const BLOCK: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "dd",
    "details",
    "dialog",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "header",
    "hr",
    "main",
    "nav",
    "ol",
    "p",
    "section",
    "summary",
    "table",
    "tbody",
    "thead",
    "tfoot",
    "tr",
    "ul",
    "caption",
];

struct Tag {
    name: String,
    closing: bool,
    href: Option<String>,
    alt: Option<String>,
    /// Byte index just past the closing `>`.
    end: usize,
}

fn find_ci(hay: &str, from: usize, needle: &str) -> Option<usize> {
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || from >= h.len() || h.len() - from < n.len() {
        return None;
    }
    (from..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// Parse a tag starting at `start` (which holds `<`). `None` if this is not
/// a tag (a literal `<` in text).
fn parse_tag(s: &str, start: usize) -> Option<Tag> {
    let b = s.as_bytes();
    let mut i = start + 1;
    let closing = b.get(i) == Some(&b'/');
    if closing {
        i += 1;
    }
    let name_start = i;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'-' || b[i] == b':') {
        i += 1;
    }
    if i == name_start || !b[name_start].is_ascii_alphabetic() {
        return None;
    }
    let name = s[name_start..i].to_ascii_lowercase();
    let mut href = None;
    let mut alt = None;
    // Attributes until the unquoted '>'.
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return Some(Tag {
                name,
                closing,
                href,
                alt,
                end: b.len(),
            });
        }
        if b[i] == b'>' {
            return Some(Tag {
                name,
                closing,
                href,
                alt,
                end: i + 1,
            });
        }
        let an_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let attr = s[an_start..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = None;
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let vs = i + 1;
                let ve = b[vs..]
                    .iter()
                    .position(|&c| c == q)
                    .map(|p| vs + p)
                    .unwrap_or(b.len());
                value = Some(&s[vs..ve]);
                i = (ve + 1).min(b.len());
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                value = Some(&s[vs..i]);
            }
        }
        if attr.is_empty() && value.is_none() {
            // Stray character; skip it to guarantee progress.
            i += 1;
            continue;
        }
        match attr.as_str() {
            "href" => href = value.map(|v| decode_entities(v).trim().to_string()),
            "alt" => alt = value.map(|v| decode_entities(v).trim().to_string()),
            _ => {}
        }
    }
}

fn named_entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        "copy" => '©',
        "reg" => '®',
        "trade" => '™',
        "mdash" => '—',
        "ndash" => '–',
        "hellip" => '…',
        "laquo" => '«',
        "raquo" => '»',
        "lsquo" => '‘',
        "rsquo" => '’',
        "ldquo" => '“',
        "rdquo" => '”',
        "bull" => '•',
        "middot" => '·',
        "deg" => '°',
        "euro" => '€',
        "pound" => '£',
        "times" => '×',
        "auml" => 'ä',
        "ouml" => 'ö',
        "uuml" => 'ü',
        "Auml" => 'Ä',
        "Ouml" => 'Ö',
        "Uuml" => 'Ü',
        "szlig" => 'ß',
        "eacute" => 'é',
        _ => return None,
    })
}

/// Decode HTML character references (`&amp;`, `&#39;`, `&#x27;`, ...).
/// Unknown references are left as-is.
pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let semi = after
            .char_indices()
            .take(12)
            .find(|&(_, c)| c == ';')
            .map(|(i, _)| i);
        let decoded = semi.and_then(|end| {
            let name = &after[..end];
            let c = if let Some(num) = name.strip_prefix('#') {
                let v = if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    num.parse::<u32>().ok()
                };
                v.map(|v| match v {
                    0 => '\u{FFFD}',
                    v => char::from_u32(v).unwrap_or('\u{FFFD}'),
                })
            } else {
                named_entity(name)
            };
            c.map(|c| (c, end))
        });
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Extract the document `<title>` (decoded, whitespace-collapsed).
pub fn extract_title(html: &str) -> Option<String> {
    let start = find_ci(html, 0, "<title")?;
    let open_end = html[start..].find('>').map(|p| start + p + 1)?;
    let close = find_ci(html, open_end, "</title").unwrap_or(html.len());
    let t = collapse_ws(&decode_entities(&html[open_end..close]));
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

struct Writer {
    out: String,
}

impl Writer {
    fn at_line_start(&self) -> bool {
        self.out.is_empty() || self.out.ends_with('\n')
    }

    fn newline(&mut self) {
        while self.out.ends_with(' ') {
            self.out.pop();
        }
        if !self.out.is_empty() {
            self.out.push('\n');
        }
    }

    fn text(&mut self, t: &str) {
        for c in t.chars() {
            if c.is_whitespace() {
                if !self.at_line_start() && !self.out.ends_with(' ') {
                    self.out.push(' ');
                }
            } else {
                self.out.push(c);
            }
        }
    }
}

/// Convert an HTML document to readable plain text.
pub fn html_to_text(html: &str) -> String {
    let b = html.as_bytes();
    let mut w = Writer {
        out: String::with_capacity(html.len() / 3),
    };
    let mut pre_depth = 0usize;
    let mut links: Vec<Option<String>> = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'<' {
            let next = html[i..].find('<').map(|p| i + p).unwrap_or(b.len());
            let text = decode_entities(&html[i..next]);
            if pre_depth > 0 {
                w.out.push_str(&text);
            } else {
                w.text(&text);
            }
            i = next;
            continue;
        }
        let rest = &html[i..];
        if rest.starts_with("<!--") {
            i = html[i + 4..]
                .find("-->")
                .map(|p| i + 4 + p + 3)
                .unwrap_or(b.len());
            continue;
        }
        if rest.starts_with("<!") || rest.starts_with("<?") {
            i = html[i..].find('>').map(|p| i + p + 1).unwrap_or(b.len());
            continue;
        }
        let Some(tag) = parse_tag(html, i) else {
            // A literal '<' in text.
            w.text("<");
            i += 1;
            continue;
        };
        let self_closing = tag.end >= 2 && b[tag.end - 2] == b'/';
        i = tag.end;
        let name = tag.name.as_str();
        if !tag.closing && !self_closing && SKIP_CONTENT.contains(&name) {
            let close = format!("</{name}");
            i = match find_ci(html, i, &close) {
                Some(p) => html[p..].find('>').map(|q| p + q + 1).unwrap_or(b.len()),
                // `</head>` is optional in HTML: resume at <body>.
                None if name == "head" => find_ci(html, i, "<body").unwrap_or(i),
                None if matches!(name, "script" | "style") => b.len(),
                // Unclosed container: keep its content rather than dropping the rest.
                None => i,
            };
            continue;
        }
        match name {
            "br" => {
                while w.out.ends_with(' ') {
                    w.out.pop();
                }
                w.out.push('\n');
            }
            "li" if !tag.closing => {
                w.newline();
                w.out.push_str("- ");
            }
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                w.newline();
                w.newline();
                if !tag.closing {
                    let level = name[1..].parse::<usize>().unwrap_or(1);
                    w.out.push_str(&"#".repeat(level));
                    w.out.push(' ');
                }
            }
            "pre" => {
                w.newline();
                if tag.closing {
                    pre_depth = pre_depth.saturating_sub(1);
                } else {
                    pre_depth += 1;
                }
            }
            "td" | "th" if !tag.closing => {
                if !w.at_line_start() {
                    w.out.push_str(" | ");
                }
            }
            "a" => {
                if tag.closing {
                    if let Some(Some(href)) = links.pop() {
                        w.out.push_str(&format!(" ({href})"));
                    }
                } else {
                    let keep = tag.href.filter(|h| {
                        let l = h.to_ascii_lowercase();
                        l.starts_with("http://") || l.starts_with("https://")
                    });
                    links.push(keep);
                }
            }
            "img" => {
                if let Some(alt) = tag.alt.filter(|a| !a.is_empty()) {
                    w.text(&format!("[image: {alt}]"));
                }
            }
            n if BLOCK.contains(&n) => {
                w.newline();
                if n == "p" || n == "blockquote" || n == "table" {
                    w.newline();
                }
            }
            _ => {}
        }
    }

    // Final cleanup: trim line ends, collapse runs of blank lines.
    let mut out = String::with_capacity(w.out.len());
    let mut blank_run = 0;
    for line in w.out.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            blank_run += 1;
            if blank_run > 1 {
                continue;
            }
            out.push('\n');
        } else {
            blank_run = 0;
            out.push_str(line);
            out.push('\n');
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_scripts_styles_and_comments() {
        let html = r#"<html><head><title>T &amp; C</title><style>p{color:red}</style></head>
<body><script>alert("x")</script><!-- hidden --><p>Hello <b>world</b></p>
<SCRIPT type="text/javascript">var a = "</p>";</SCRIPT><p>Second</p></body></html>"#;
        let t = html_to_text(html);
        assert_eq!(t, "Hello world\n\nSecond");
        assert_eq!(extract_title(html).as_deref(), Some("T & C"));
    }

    #[test]
    fn structure_is_preserved() {
        let html = "<h1>Title</h1><p>Intro text\n   wrapped</p><ul><li>one</li><li>two</li></ul>\
                    <pre>  code\n    indented</pre><table><tr><td>a</td><td>b</td></tr></table>line<br>break";
        let t = html_to_text(html);
        assert!(t.starts_with("# Title\n\nIntro text wrapped"), "{t}");
        assert!(t.contains("- one\n- two"), "{t}");
        assert!(t.contains("  code\n    indented"), "{t}");
        assert!(t.contains("a | b"), "{t}");
        assert!(t.ends_with("line\nbreak"), "{t}");
    }

    #[test]
    fn links_and_images() {
        let html = r#"<p>See <a href="https://example.com/a?b=1&amp;c=2">the advisory</a> and <a href="/rel">rel</a>
<a href='javascript:void(0)'>js</a> <img src=x.png alt="diagram"></p>"#;
        let t = html_to_text(html);
        assert!(
            t.contains("the advisory (https://example.com/a?b=1&c=2)"),
            "{t}"
        );
        assert!(t.contains("rel js"), "{t}");
        assert!(t.contains("[image: diagram]"), "{t}");
    }

    #[test]
    fn self_closing_and_unclosed_skip_elements_keep_content() {
        assert_eq!(html_to_text("<p>a<svg/>b</p>"), "ab");
        assert_eq!(
            html_to_text("<html><head><title>x</title><body><p>visible</p>"),
            "visible"
        );
        assert_eq!(html_to_text("<p>keep</p><select><option>x"), "keep\n\nx");
    }

    #[test]
    fn entities() {
        assert_eq!(
            decode_entities("a &lt;b&gt; &#39;c&#x27; &nbsp;&euro;"),
            "a <b> 'c'  €"
        );
        assert_eq!(decode_entities("AT&T &bogus; &"), "AT&T &bogus; &");
        assert_eq!(decode_entities("&#0;&#x110000;"), "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn malformed_input_does_not_panic() {
        for s in [
            "<",
            "<a",
            "<a href=\"unterminated",
            "a < b > c",
            "<p attr=>x",
            "<!-- never closed",
            "<script>never closed",
            "</>",
            "<ä>ü</ä>",
            "<p\u{0}>",
            "<<<>>>",
            "<a =x>y</a>",
        ] {
            let _ = html_to_text(s);
        }
        assert_eq!(html_to_text("a < b and c > d"), "a < b and c > d");
    }
}
