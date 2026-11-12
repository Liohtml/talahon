//! Request-path construction from model-supplied values.
//!
//! Index expressions, data-stream names and document ids come from the
//! model, i.e. from an untrusted source. Every such value becomes exactly
//! **one** path segment: it is validated, then percent-encoded so that it
//! can neither add a segment (`/`), start a query (`?`, `#`), smuggle an
//! already-encoded byte (`%`) nor address an OpenSearch API endpoint
//! (`_cat`, `_plugins`, ...) instead of an index.

use std::fmt;

/// Longest accepted index expression or data-stream pattern, in bytes.
pub const MAX_TARGET_BYTES: usize = 2048;
/// Longest accepted document id, in bytes (the OpenSearch limit).
pub const MAX_DOC_ID_BYTES: usize = 512;

/// Why a model-supplied path value was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The value is empty (or one element of a comma-separated list is).
    #[error("{what} must not be empty")]
    Empty {
        /// Which argument was rejected.
        what: &'static str,
    },
    /// The value is longer than the limit for its kind.
    #[error("{what} is longer than {limit} bytes")]
    TooLong {
        /// Which argument was rejected.
        what: &'static str,
        /// The limit in bytes.
        limit: usize,
    },
    /// The value contains a control character.
    #[error("{what} must not contain control characters")]
    ControlCharacter {
        /// Which argument was rejected.
        what: &'static str,
    },
    /// The value is `.` or `..`, which URL parsers resolve as a path step.
    #[error("{what} must not be '.' or '..'")]
    DotSegment {
        /// Which argument was rejected.
        what: &'static str,
    },
    /// The value starts with `_`, which addresses an API endpoint.
    #[error("{what} must not start with '_' (only '_all' is allowed)")]
    ReservedPrefix {
        /// Which argument was rejected.
        what: &'static str,
    },
}

/// One validated, percent-encoded path segment.
#[derive(Clone, PartialEq, Eq)]
pub struct Segment(String);

impl Segment {
    /// An index expression: a name, wildcard pattern or comma-separated
    /// list of those (`wazuh-alerts-4.x-*`, `a,b`, `_all`).
    pub fn index(raw: &str) -> Result<Self, PathError> {
        Self::target(raw, "index")
    }

    /// A data-stream name, wildcard pattern or comma-separated list.
    pub fn data_stream(raw: &str) -> Result<Self, PathError> {
        Self::target(raw, "name")
    }

    /// A document id.
    pub fn doc_id(raw: &str) -> Result<Self, PathError> {
        let what = "id";
        check_common(raw, what, MAX_DOC_ID_BYTES)?;
        Ok(Self(encode(raw, false)))
    }

    fn target(raw: &str, what: &'static str) -> Result<Self, PathError> {
        check_common(raw, what, MAX_TARGET_BYTES)?;
        for part in raw.split(',') {
            if part.is_empty() {
                return Err(PathError::Empty { what });
            }
            if part == "." || part == ".." {
                return Err(PathError::DotSegment { what });
            }
            // `-_x` is an exclusion of `_x`; judge the name behind the sign.
            let name = part.strip_prefix(['-', '+']).unwrap_or(part);
            if name.starts_with('_') && name != "_all" {
                return Err(PathError::ReservedPrefix { what });
            }
        }
        Ok(Self(encode(raw, true)))
    }

    /// The encoded segment, safe to place between two `/`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Segment").field(&self.0).finish()
    }
}

fn check_common(raw: &str, what: &'static str, limit: usize) -> Result<(), PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty { what });
    }
    if raw.len() > limit {
        return Err(PathError::TooLong { what, limit });
    }
    if raw.chars().any(char::is_control) {
        return Err(PathError::ControlCharacter { what });
    }
    if raw == "." || raw == ".." {
        return Err(PathError::DotSegment { what });
    }
    Ok(())
}

/// Percent-encode everything but RFC 3986 unreserved characters. With
/// `keep_list_syntax`, `*` and `,` (wildcards and lists, both legal in a
/// path segment) stay readable, as the Python client sends them.
fn encode(raw: &str, keep_list_syntax: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (keep_list_syntax && matches!(b, b'*' | b','));
        if keep {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
    }
    out
}

/// A request path made of fixed API words and validated [`Segment`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPath(String);

impl RequestPath {
    /// A path of fixed API words only, e.g. `["_cluster", "health"]`.
    pub fn fixed(words: &[&'static str]) -> Self {
        let mut path = Self(String::new());
        for word in words {
            path = path.word(word);
        }
        path
    }

    /// Start a path with a model-supplied segment.
    pub fn from_segment(segment: &Segment) -> Self {
        Self(String::new()).segment(segment)
    }

    /// Append a fixed API word (`_search`, `_doc`, ...).
    #[must_use]
    pub fn word(mut self, word: &'static str) -> Self {
        self.0.push('/');
        self.0.push_str(word);
        self
    }

    /// Append a model-supplied segment.
    #[must_use]
    pub fn segment(mut self, segment: &Segment) -> Self {
        self.0.push('/');
        self.0.push_str(segment.as_str());
        self
    }

    /// The path, starting with `/`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_keeps_wildcards_and_lists() {
        assert_eq!(
            Segment::index("wazuh-alerts-4.x-*").unwrap().as_str(),
            "wazuh-alerts-4.x-*"
        );
        assert_eq!(Segment::index("a,b").unwrap().as_str(), "a,b");
        assert_eq!(Segment::index("_all").unwrap().as_str(), "_all");
        assert_eq!(
            Segment::index(".kibana_1,-x*").unwrap().as_str(),
            ".kibana_1,-x*"
        );
    }

    #[test]
    fn index_encodes_like_the_python_client() {
        // Same bytes opensearch-py 2.8 puts on the wire for this value.
        assert_eq!(
            Segment::index("we ird/../x?y#z%41").unwrap().as_str(),
            "we%20ird%2F..%2Fx%3Fy%23z%2541"
        );
        assert_eq!(
            Segment::index("<logs-{now/d}>").unwrap().as_str(),
            "%3Clogs-%7Bnow%2Fd%7D%3E"
        );
        assert_eq!(Segment::index("idx-é").unwrap().as_str(), "idx-%C3%A9");
    }

    #[test]
    fn index_rejects_endpoints_and_path_steps() {
        for bad in [
            "_cat", "_search", "_plugins", "_cluster", "a,_nodes", "-_cat", "+_cat",
        ] {
            assert_eq!(
                Segment::index(bad),
                Err(PathError::ReservedPrefix { what: "index" }),
                "{bad}"
            );
        }
        for bad in [".", "..", "a,..", ".,b"] {
            assert_eq!(
                Segment::index(bad),
                Err(PathError::DotSegment { what: "index" }),
                "{bad}"
            );
        }
        for bad in ["", "a,,b", ",a", "a,"] {
            assert_eq!(
                Segment::index(bad),
                Err(PathError::Empty { what: "index" }),
                "{bad:?}"
            );
        }
        for bad in ["a\nb", "a\r\nX-Injected: 1", "a\0", "a\u{7f}", "a\u{85}"] {
            assert_eq!(
                Segment::index(bad),
                Err(PathError::ControlCharacter { what: "index" }),
                "{bad:?}"
            );
        }
        assert!(matches!(
            Segment::index(&"a".repeat(MAX_TARGET_BYTES + 1)),
            Err(PathError::TooLong { .. })
        ));
    }

    #[test]
    fn doc_id_is_one_opaque_segment() {
        assert_eq!(Segment::doc_id("AbC_-1").unwrap().as_str(), "AbC_-1");
        assert_eq!(
            Segment::doc_id("a/b c?d").unwrap().as_str(),
            "a%2Fb%20c%3Fd"
        );
        assert_eq!(
            Segment::doc_id("../_search").unwrap().as_str(),
            "..%2F_search"
        );
        assert_eq!(Segment::doc_id("a,b*").unwrap().as_str(), "a%2Cb%2A");
        assert_eq!(Segment::doc_id("%2e%2e").unwrap().as_str(), "%252e%252e");
        assert_eq!(
            Segment::doc_id(".."),
            Err(PathError::DotSegment { what: "id" })
        );
        assert_eq!(Segment::doc_id(""), Err(PathError::Empty { what: "id" }));
        assert!(matches!(
            Segment::doc_id(&"x".repeat(MAX_DOC_ID_BYTES + 1)),
            Err(PathError::TooLong { .. })
        ));
    }

    #[test]
    fn request_path_joins_words_and_segments() {
        let idx = Segment::index("wazuh-*").unwrap();
        let id = Segment::doc_id("a/b").unwrap();
        assert_eq!(
            RequestPath::from_segment(&idx)
                .word("_doc")
                .segment(&id)
                .as_str(),
            "/wazuh-*/_doc/a%2Fb"
        );
        assert_eq!(
            RequestPath::fixed(&["_cluster", "health"]).as_str(),
            "/_cluster/health"
        );
    }
}
