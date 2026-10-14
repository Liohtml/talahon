//! The session token map: original PII value <-> opaque token.
//!
//! Tokens have the form `<PREFIX>_<N>` (`USER_1`, `HOST_2`, `IP_INT_3`, ...)
//! and are allocated per prefix from monotonically increasing counters, so a
//! value keeps the same token for the whole session.
//!
//! The persisted JSON format is exactly the one written by the Python proxy
//! (`siem/anon_proxy/anon_proxy.py`), so existing `session_tokens.json`
//! files keep working in both directions:
//!
//! ```json
//! {
//!   "forward": { "john.doe": "USER_1", "192.168.1.100": "IP_INT_1" },
//!   "counters": { "USER": 1, "IP_INT": 1 }
//! }
//! ```
//!
//! Differences to the Python map (all backwards compatible):
//! - lookups are case-insensitive and whitespace-trimmed (`WS01` and `ws01`
//!   share a token; the first-seen spelling is what `deanonymize` restores);
//! - a value that already *is* an issued token is never re-tokenized, so
//!   anonymization is idempotent;
//! - de-anonymization is a single pass, longest token first, and only at
//!   token boundaries (`USER_1` never clobbers `USER_10`).

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use aho_corasick::AhoCorasick;
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;
use talon_core::{Error, Result};

use crate::text::{Candidate, fold, select_matches, splice, word_bounded};

static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);

fn next_epoch() -> u64 {
    NEXT_EPOCH.fetch_add(1, Ordering::Relaxed)
}

/// One `original -> token` mapping.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenEntry {
    /// The real (sensitive) value.
    pub original: String,
    /// The opaque token shown to the model.
    pub token: String,
}

impl fmt::Debug for TokenEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the original value: Debug output may end up in logs.
        f.debug_struct("TokenEntry")
            .field("token", &self.token)
            .field(
                "original",
                &format_args!("<{} chars redacted>", self.original.chars().count()),
            )
            .finish()
    }
}

/// Outcome of [`TokenMap::rebase_onto`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RebaseReport {
    /// In-memory entries that were missing on disk and were re-added.
    pub added: usize,
    /// In-memory entries that conflicted with the disk map (disk wins).
    pub conflicts: usize,
    /// Whether any in-memory counter was ahead of the disk counter.
    pub counters_raised: bool,
}

struct DeanonIndex {
    epoch: u64,
    len: usize,
    ac: Arc<AhoCorasick>,
}

/// Bidirectional, insertion-ordered token map.
pub struct TokenMap {
    entries: Vec<TokenEntry>,
    by_original: HashMap<String, usize>,
    by_folded: HashMap<String, usize>,
    by_token: HashMap<String, usize>,
    counters: Vec<(String, u64)>,
    epoch: u64,
    dirty: bool,
    deanon: Mutex<Option<DeanonIndex>>,
}

impl fmt::Debug for TokenMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenMap")
            .field("entries", &self.entries.len())
            .field("counters", &self.counters)
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl Default for TokenMap {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TokenMap {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            by_original: self.by_original.clone(),
            by_folded: self.by_folded.clone(),
            by_token: self.by_token.clone(),
            counters: self.counters.clone(),
            epoch: next_epoch(),
            dirty: self.dirty,
            deanon: Mutex::new(None),
        }
    }
}

/// Split `PREFIX_N` into `("PREFIX", N)`.
pub(crate) fn split_token(token: &str) -> Option<(&str, u64)> {
    let (prefix, n) = token.rsplit_once('_')?;
    if prefix.is_empty() || n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((prefix, n.parse().ok()?))
}

fn token_order(token: &str) -> (String, u64) {
    match split_token(token) {
        Some((p, n)) => (p.to_string(), n),
        None => (token.to_string(), u64::MAX),
    }
}

impl TokenMap {
    /// An empty map.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            by_original: HashMap::new(),
            by_folded: HashMap::new(),
            by_token: HashMap::new(),
            counters: Vec::new(),
            epoch: next_epoch(),
            dirty: false,
            deanon: Mutex::new(None),
        }
    }

    /// Number of mappings.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no value has been tokenized yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All mappings in insertion order.
    pub fn entries(&self) -> &[TokenEntry] {
        &self.entries
    }

    /// Per-prefix counters (`prefix -> last N issued`).
    pub fn counters(&self) -> impl Iterator<Item = (&str, u64)> {
        self.counters.iter().map(|(p, n)| (p.as_str(), *n))
    }

    /// Last number issued for `prefix` (0 if none).
    pub fn counter(&self, prefix: &str) -> u64 {
        self.counters
            .iter()
            .find(|(p, _)| p == prefix)
            .map_or(0, |(_, n)| *n)
    }

    fn set_counter(&mut self, prefix: &str, n: u64) {
        if let Some(slot) = self.counters.iter_mut().find(|(p, _)| p == prefix) {
            slot.1 = n;
        } else {
            self.counters.push((prefix.to_string(), n));
        }
    }

    /// Identity of the current entry set. Changes whenever the entries are
    /// replaced wholesale (load, rebase, clone); appends keep the epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// `true` when the map changed since it was loaded / last marked clean.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the map as persisted.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Token for `value` (exact match first, then trimmed/case-insensitive).
    pub fn token_for(&self, value: &str) -> Option<&str> {
        let idx = match self.by_original.get(value) {
            Some(i) => *i,
            None => *self.by_folded.get(&fold(value))?,
        };
        self.entries.get(idx).map(|e| e.token.as_str())
    }

    /// Original value for `token`.
    pub fn original_for(&self, token: &str) -> Option<&str> {
        let idx = *self.by_token.get(token)?;
        self.entries.get(idx).map(|e| e.original.as_str())
    }

    /// `true` if `s` is a token issued by this map.
    pub fn is_token(&self, s: &str) -> bool {
        self.by_token.contains_key(s)
    }

    /// Return the token for `value`, allocating `<prefix>_<n>` if needed.
    ///
    /// Blank values are returned unchanged (as in the Python proxy); a value
    /// that is itself an issued token is returned unchanged (idempotency).
    pub fn get_or_create(&mut self, value: &str, prefix: &str) -> String {
        if value.trim().is_empty() {
            return value.to_string();
        }
        if let Some(t) = self.token_for(value) {
            return t.to_string();
        }
        if self.by_token.contains_key(value) {
            return value.to_string();
        }
        let token = self.allocate(prefix);
        self.push_entry(value.to_string(), token.clone());
        token
    }

    fn allocate(&mut self, prefix: &str) -> String {
        let mut n = self.counter(prefix);
        // Bounded: at most `entries.len() + 1` numbers can be taken.
        for _ in 0..=self.entries.len() + 1 {
            n = n.checked_add(1).unwrap_or(1);
            let token = format!("{prefix}_{n}");
            if !self.by_token.contains_key(&token) {
                if n > self.counter(prefix) {
                    self.set_counter(prefix, n);
                }
                return token;
            }
        }
        // Unreachable in practice (pigeonhole); fall back to a unique suffix.
        format!("{prefix}_{}x{}", self.entries.len(), next_epoch())
    }

    fn push_entry(&mut self, original: String, token: String) {
        let idx = self.entries.len();
        self.by_folded.entry(fold(&original)).or_insert(idx);
        self.by_original.insert(original.clone(), idx);
        self.by_token.insert(token.clone(), idx);
        if let Some((p, n)) = split_token(&token) {
            if n > self.counter(p) {
                let p = p.to_string();
                self.set_counter(&p, n);
            }
        }
        self.entries.push(TokenEntry { original, token });
        self.dirty = true;
    }

    /// Insert a mapping verbatim (used when loading / merging). Returns
    /// `false` (and changes nothing) if the original or the token is already
    /// mapped differently, or if either side is empty.
    pub fn insert(&mut self, original: impl Into<String>, token: impl Into<String>) -> bool {
        let (original, token) = (original.into(), token.into());
        if original.trim().is_empty() || token.is_empty() {
            return false;
        }
        match (self.by_original.get(&original), self.by_token.get(&token)) {
            (Some(i), _) => self.entries.get(*i).is_some_and(|e| e.token == token),
            (None, Some(_)) => false,
            (None, None) => {
                self.push_entry(original, token);
                true
            }
        }
    }

    /// Parse the Python-compatible JSON format. Non-string tokens, blank
    /// originals and conflicting duplicates are skipped (with a warning);
    /// counters are raised to at least the highest issued token number.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes)?;
        let Value::Object(obj) = value else {
            return Err(Error::invalid("token map is not a JSON object"));
        };
        let mut pairs: Vec<(String, String)> = match obj.get("forward") {
            Some(Value::Object(fwd)) => fwd
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|t| (k.clone(), t.to_string())))
                .collect(),
            Some(Value::Null) | None => Vec::new(),
            Some(_) => return Err(Error::invalid("token map: \"forward\" is not an object")),
        };
        // serde_json maps are key-sorted; restore creation order from the
        // token numbers so "first seen wins" stays meaningful.
        pairs.sort_by_cached_key(|(_, t)| token_order(t));
        let total = pairs.len();
        let mut map = Self::new();
        for (original, token) in pairs {
            map.insert(original, token);
        }
        let skipped = total - map.len();
        if let Some(Value::Object(counters)) = obj.get("counters") {
            for (prefix, n) in counters {
                if let Some(n) = n.as_u64() {
                    if n > map.counter(prefix) {
                        map.set_counter(prefix, n);
                    }
                }
            }
        }
        if skipped > 0 {
            tracing::warn!(skipped, "token map: ignored invalid or conflicting entries");
        }
        map.dirty = false;
        Ok(map)
    }

    /// Serialize to the Python-compatible JSON format (2-space indent,
    /// insertion order).
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&MapFileRef {
            forward: ForwardRef(&self.entries),
            counters: CountersRef(&self.counters),
        })?)
    }

    /// Replace every issued token in `text` with its original value.
    ///
    /// Single pass, longest token first, only at token boundaries: `USER_1`
    /// does not match inside `USER_10`, and a restored value that happens to
    /// look like a token is never substituted again.
    pub fn deanonymize(&self, text: &str) -> String {
        if self.entries.is_empty() || text.is_empty() {
            return text.to_string();
        }
        let Some(ac) = self.deanon_index() else {
            return text.to_string();
        };
        let cands: Vec<Candidate> = ac
            .find_overlapping_iter(text)
            .filter(|m| word_bounded(text, m.start(), m.end()))
            .map(|m| Candidate {
                start: m.start(),
                end: m.end(),
                idx: m.pattern().as_usize(),
            })
            .collect();
        if cands.is_empty() {
            return text.to_string();
        }
        let sel = select_matches(cands);
        splice(text, &sel, |c| {
            self.entries.get(c.idx).map_or("", |e| e.original.as_str())
        })
    }

    fn deanon_index(&self) -> Option<Arc<AhoCorasick>> {
        let mut guard = self.deanon.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(idx) = guard.as_ref() {
            if idx.epoch == self.epoch && idx.len == self.entries.len() {
                return Some(Arc::clone(&idx.ac));
            }
        }
        match AhoCorasick::new(self.entries.iter().map(|e| e.token.as_str())) {
            Ok(ac) => {
                let ac = Arc::new(ac);
                *guard = Some(DeanonIndex {
                    epoch: self.epoch,
                    len: self.entries.len(),
                    ac: Arc::clone(&ac),
                });
                Some(ac)
            }
            Err(e) => {
                tracing::warn!(error = %e, "deanonymize: could not build token index");
                None
            }
        }
    }

    /// Rebase this (in-memory) map onto `disk`, which is authoritative.
    ///
    /// Entries only known in memory are appended when neither their original
    /// nor their token is taken on disk; conflicts keep the disk mapping.
    /// Counters become the per-prefix maximum. The result is marked dirty
    /// when it differs from `disk` (so it gets written back).
    pub fn rebase_onto(&mut self, mut disk: TokenMap) -> RebaseReport {
        let mut report = RebaseReport::default();
        for e in &self.entries {
            if let Some(&i) = disk.by_original.get(&e.original) {
                if disk.entries.get(i).is_some_and(|d| d.token != e.token) {
                    report.conflicts += 1;
                }
                continue;
            }
            if let Some(&i) = disk.by_token.get(&e.token) {
                let same_value = disk
                    .entries
                    .get(i)
                    .is_some_and(|d| fold(&d.original) == fold(&e.original));
                if !same_value {
                    report.conflicts += 1;
                }
                continue;
            }
            disk.push_entry(e.original.clone(), e.token.clone());
            report.added += 1;
        }
        for (prefix, n) in &self.counters {
            if *n > disk.counter(prefix) {
                disk.set_counter(prefix, *n);
                report.counters_raised = true;
            }
        }
        disk.dirty = report.added > 0 || report.counters_raised;
        disk.epoch = next_epoch();
        *self = disk;
        report
    }
}

#[derive(Serialize)]
struct MapFileRef<'a> {
    forward: ForwardRef<'a>,
    counters: CountersRef<'a>,
}

struct ForwardRef<'a>(&'a [TokenEntry]);

impl Serialize for ForwardRef<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for e in self.0 {
            m.serialize_entry(&e.original, &e.token)?;
        }
        m.end()
    }
}

struct CountersRef<'a>(&'a [(String, u64)]);

impl Serialize for CountersRef<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (p, n) in self.0 {
            m.serialize_entry(p, n)?;
        }
        m.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_per_prefix_and_is_consistent() {
        let mut m = TokenMap::new();
        assert_eq!(m.get_or_create("john.doe", "USER"), "USER_1");
        assert_eq!(m.get_or_create("jane", "USER"), "USER_2");
        assert_eq!(m.get_or_create("WS01", "HOST"), "HOST_1");
        assert_eq!(m.get_or_create("john.doe", "USER"), "USER_1");
        // value keyed: same value under another prefix keeps its token (Python semantics)
        assert_eq!(m.get_or_create("john.doe", "EMAIL"), "USER_1");
        assert_eq!(m.counter("USER"), 2);
        assert_eq!(m.counter("HOST"), 1);
        assert_eq!(m.len(), 3);
        assert!(m.is_dirty());
    }

    #[test]
    fn blank_values_are_untouched() {
        let mut m = TokenMap::new();
        assert_eq!(m.get_or_create("", "USER"), "");
        assert_eq!(m.get_or_create("   ", "USER"), "   ");
        assert!(m.is_empty());
    }

    #[test]
    fn case_insensitive_and_trimmed_lookup() {
        let mut m = TokenMap::new();
        assert_eq!(m.get_or_create("WS01", "HOST"), "HOST_1");
        assert_eq!(m.get_or_create("ws01", "HOST"), "HOST_1");
        assert_eq!(m.get_or_create(" Ws01 ", "HOST"), "HOST_1");
        assert_eq!(m.len(), 1);
        assert_eq!(m.original_for("HOST_1"), Some("WS01"));
    }

    #[test]
    fn tokens_are_not_retokenized() {
        let mut m = TokenMap::new();
        let t = m.get_or_create("alice", "USER");
        assert_eq!(m.get_or_create(&t, "USER"), t);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn python_format_round_trip() {
        let py = r#"{
  "forward": {
    "john.doe": "USER_1",
    "WORKSTATION-01": "HOST_1",
    "192.168.1.100": "IP_INT_1",
    "jane": "USER_2"
  },
  "counters": {
    "USER": 2,
    "HOST": 1,
    "IP_INT": 1
  }
}"#;
        let mut m = TokenMap::from_json_slice(py.as_bytes()).unwrap();
        assert!(!m.is_dirty());
        assert_eq!(m.len(), 4);
        assert_eq!(m.token_for("john.doe"), Some("USER_1"));
        assert_eq!(m.get_or_create("bob", "USER"), "USER_3");
        let out = m.to_json_string().unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["forward"]["bob"], "USER_3");
        assert_eq!(v["counters"]["USER"], 3);
        assert_eq!(v["counters"]["IP_INT"], 1);
        // 2-space indentation like json.dumps(indent=2)
        assert!(out.contains("\n  \"forward\": {\n    \""));
        let again = TokenMap::from_json_slice(out.as_bytes()).unwrap();
        assert_eq!(again.len(), 5);
        assert_eq!(again.token_for("bob"), Some("USER_3"));
    }

    #[test]
    fn load_is_lenient_and_counters_cover_tokens() {
        let raw = r#"{"forward": {"a": "USER_7", "b": 5, "": "USER_9", "c": "USER_7"}, "counters": {"USER": 2, "X": "bad"}}"#;
        let mut m = TokenMap::from_json_slice(raw.as_bytes()).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m.counter("USER"), 7);
        assert_eq!(m.get_or_create("d", "USER"), "USER_8");
        assert!(TokenMap::from_json_slice(b"[1,2]").is_err());
        assert!(TokenMap::from_json_slice(b"{not json").is_err());
        assert_eq!(TokenMap::from_json_slice(b"{}").unwrap().len(), 0);
    }

    #[test]
    fn allocation_skips_taken_tokens() {
        let mut m = TokenMap::new();
        assert!(m.insert("x", "USER_2"));
        m.set_counter("USER", 1);
        assert_eq!(m.get_or_create("y", "USER"), "USER_3");
        let mut big = TokenMap::new();
        big.set_counter("USER", u64::MAX);
        let t = big.get_or_create("z", "USER");
        assert_eq!(t, "USER_1");
    }

    #[test]
    fn deanonymize_longest_first_with_boundaries() {
        let mut m = TokenMap::new();
        for i in 1..=12 {
            m.get_or_create(&format!("user{i}"), "USER");
        }
        m.get_or_create("10.0.0.1", "IP_INT");
        let out = m.deanonymize("USER_1 USER_10 USER_12, USER_1x IP_INT_1:443 (USER_2) USER_13");
        assert_eq!(
            out,
            "user1 user10 user12, USER_1x 10.0.0.1:443 (user2) USER_13"
        );
    }

    #[test]
    fn deanonymize_is_single_pass() {
        let mut m = TokenMap::new();
        m.get_or_create("john", "USER"); // USER_1
        m.get_or_create("USER_1-PC", "HOST"); // original contains a token-like string
        assert_eq!(m.deanonymize("HOST_1 / USER_1"), "USER_1-PC / john");
        assert_eq!(
            m.deanonymize("HOST_1.DOMAIN_INT_9"),
            "USER_1-PC.DOMAIN_INT_9"
        );
    }

    #[test]
    fn rebase_merges_and_reports_conflicts() {
        let mut disk = TokenMap::new();
        disk.get_or_create("alice", "USER"); // USER_1
        disk.get_or_create("bob", "USER"); // USER_2
        let mut mem = TokenMap::new();
        mem.get_or_create("alice", "USER"); // USER_1 (agrees)
        mem.insert("carol", "USER_2"); // conflicts with bob
        mem.insert("dave", "USER_5"); // new
        mem.get_or_create("ws", "HOST");
        let r = mem.rebase_onto(disk);
        assert_eq!(r.added, 2);
        assert_eq!(r.conflicts, 1);
        assert!(mem.is_dirty());
        assert_eq!(mem.token_for("bob"), Some("USER_2"));
        assert_eq!(mem.token_for("dave"), Some("USER_5"));
        assert_eq!(mem.token_for("carol"), None);
        assert_eq!(mem.counter("USER"), 5);
        assert_eq!(mem.get_or_create("erin", "USER"), "USER_6");
    }

    #[test]
    fn debug_never_prints_originals() {
        let mut m = TokenMap::new();
        m.get_or_create("secret.person", "USER");
        let d = format!("{m:?} {:?}", m.entries());
        assert!(!d.contains("secret.person"));
        assert!(d.contains("USER_1"));
    }
}
