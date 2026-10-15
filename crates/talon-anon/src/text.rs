//! Small string helpers shared by the token map, the detectors and the
//! sweep: word-boundary checks, non-overlapping match selection and
//! splicing replacements into a string.

use regex::{Captures, Regex};

/// A candidate replacement: byte range `[start, end)` plus an index whose
/// meaning is up to the caller (pattern / entry index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub start: usize,
    pub end: usize,
    pub idx: usize,
}

/// `true` for characters that make up "words" for token-boundary purposes:
/// Unicode alphanumerics and `_` (tokens look like `USER_12`).
pub(crate) fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The character immediately before byte offset `i`, if any.
pub(crate) fn char_before(text: &str, i: usize) -> Option<char> {
    text.get(..i)?.chars().next_back()
}

/// The character starting at byte offset `i`, if any.
pub(crate) fn char_after(text: &str, i: usize) -> Option<char> {
    text.get(i..)?.chars().next()
}

/// `true` when `[start, end)` is not glued to word characters on either
/// side (so `USER_1` never matches inside `USER_10` or `XUSER_1`).
pub(crate) fn word_bounded(text: &str, start: usize, end: usize) -> bool {
    !char_before(text, start).is_some_and(is_word_char)
        && !char_after(text, end).is_some_and(is_word_char)
}

/// Select the leftmost-longest, non-overlapping subset of `cands`.
pub(crate) fn select_matches(mut cands: Vec<Candidate>) -> Vec<Candidate> {
    cands.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out = Vec::with_capacity(cands.len());
    let mut last_end = 0usize;
    for c in cands {
        if c.start >= last_end && c.end > c.start {
            last_end = c.end;
            out.push(c);
        }
    }
    out
}

/// Replace every selected (sorted, non-overlapping) range with the string
/// produced by `rep`.
pub(crate) fn splice<'a, F>(text: &str, sel: &[Candidate], mut rep: F) -> String
where
    F: FnMut(&Candidate) -> &'a str,
{
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for c in sel {
        if c.start < last || c.end > text.len() {
            continue;
        }
        out.push_str(&text[last..c.start]);
        out.push_str(rep(c));
        last = c.end;
    }
    out.push_str(&text[last..]);
    out
}

/// `Regex::replace_all` with a callback that may decline a match
/// (`None` keeps the matched text). Returns `None` when nothing changed, so
/// callers can avoid allocating for the common no-PII case.
pub(crate) fn replace_matches<F>(re: &Regex, text: &str, mut f: F) -> Option<String>
where
    F: FnMut(&Captures<'_>) -> Option<String>,
{
    let mut out = String::new();
    let mut last = 0usize;
    let mut changed = false;
    for caps in re.captures_iter(text) {
        let Some(m) = caps.get(0) else { continue };
        if let Some(rep) = f(&caps) {
            if rep == m.as_str() {
                continue;
            }
            out.push_str(&text[last..m.start()]);
            out.push_str(&rep);
            last = m.end();
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    out.push_str(&text[last..]);
    Some(out)
}

/// Case-fold used for value lookups: trimmed + lowercased.
pub(crate) fn fold(value: &str) -> String {
    value.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries() {
        assert!(word_bounded("a USER_1 b", 2, 8));
        assert!(!word_bounded("USER_10", 0, 6));
        assert!(!word_bounded("XUSER_1", 1, 7));
        assert!(word_bounded("(USER_1)", 1, 7));
        assert!(word_bounded("USER_1", 0, 6));
        assert!(word_bounded("é USER_1.", 3, 9));
        assert!(!word_bounded("éUSER_1", 2, 8));
    }

    #[test]
    fn selection_prefers_leftmost_longest() {
        let c = vec![
            Candidate {
                start: 0,
                end: 3,
                idx: 0,
            },
            Candidate {
                start: 0,
                end: 5,
                idx: 1,
            },
            Candidate {
                start: 4,
                end: 6,
                idx: 2,
            },
            Candidate {
                start: 6,
                end: 8,
                idx: 3,
            },
        ];
        let s = select_matches(c);
        assert_eq!(s.iter().map(|c| c.idx).collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn splice_and_replace() {
        let sel = [Candidate {
            start: 2,
            end: 4,
            idx: 0,
        }];
        assert_eq!(splice("a bb c", &sel, |_| "X"), "a X c");
        let re = Regex::new(r"\d+").unwrap();
        assert_eq!(
            replace_matches(&re, "a1 b22 c3", |c| (c[0].len() == 2)
                .then(|| "N".to_string())),
            Some("a1 bN c3".to_string())
        );
        assert_eq!(replace_matches(&re, "abc", |_| Some("x".into())), None);
    }
}
