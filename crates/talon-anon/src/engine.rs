//! The anonymization engine.
//!
//! [`Anonymizer`] owns a [`TokenMap`] and a shared [`CompiledConfig`] and
//! rewrites JSON documents, MCP tool results and free text:
//!
//! 1. **Field-aware tokenization** (Python behaviour): a string under a
//!    configured field is replaced as a whole by its token. Preserved fields
//!    are left alone; everything else goes through the free-text detectors.
//!    Unlike the Python proxy, fields are matched on their full key path, so
//!    nested OpenSearch documents (`_source.data.win.eventdata.user`) and
//!    list elements under a field are covered as well.
//! 2. **Free-text detectors**: e-mail addresses, UNC hosts, `DOMAIN\user`,
//!    user profile / home paths, SIDs, MACs, internal IPv6/IPv4 addresses and
//!    host names under internal DNS domains.
//! 3. **Known-value sweep**: once a value has a token, every later
//!    occurrence in free text (e.g. a user name inside `full_log`) is
//!    replaced too. Documents are processed in two passes so field values
//!    found anywhere in a document are known before its free text is swept.
//!
//! Hashes, public IPs, public domains and rule metadata are never touched by
//! the detectors; tokens are never re-tokenized, so anonymization is
//! idempotent.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use regex::Captures;
use serde_json::Value;

use crate::config::{CategoryKind, CompiledConfig, FieldClass, key_atoms};
use crate::detect::{
    DOMAIN_USER_RE, EMAIL_RE, FILE_EXTENSION_TLDS, IPV4_RE, IPV6_CANDIDATE_RE, MAC_RE,
    PROFILE_DIRS, SID_RE, UNC_RE, UNIX_HOME_RE, WIN_PROFILE_END_RE, WIN_PROFILE_RE, in_spans,
    is_internal_ip, is_internal_ipv4, is_internal_ipv6, is_open_boundary, is_unc_boundary,
    parse_ip, parse_ipv4_lenient, url_spans,
};
use crate::text::{
    Candidate, char_after, char_before, fold, is_word_char, replace_matches, select_matches,
    splice, word_bounded,
};
use crate::tokens::TokenMap;

/// Maximum JSON nesting walked; deeper content is replaced (never leaked).
const MAX_DEPTH: usize = 160;
/// Maximum levels of JSON-inside-a-string that are parsed.
const MAX_NESTED_JSON: usize = 4;
/// Maximum embedded-JSON parse attempts per text block.
const MAX_EMBEDDED_ATTEMPTS: usize = 32;
/// New map entries tolerated before the sweep index is rebuilt.
const SWEEP_EXTRA_LIMIT: usize = 64;
/// Maximum aggregation hints collected from one request.
const MAX_HINTS: usize = 256;
/// Replacement for content nested deeper than [`MAX_DEPTH`].
pub const DEPTH_PLACEHOLDER: &str = "[talon-anon: nesting too deep, value removed]";

/// OpenSearch aggregation types whose bucket keys are field values.
const AGG_TYPES: &[&str] = &[
    "terms",
    "significant_terms",
    "rare_terms",
    "significant_text",
    "multi_terms",
];

/// Windows authorities whose principals are not personal data.
const WELL_KNOWN_AUTHORITIES: &[&str] = &[
    "nt authority",
    "nt service",
    "nt virtual machine",
    "iis apppool",
    "builtin",
    "window manager",
    "font driver host",
];

/// Request-derived hints mapping OpenSearch aggregation names to the field
/// they aggregate, so bucket keys (`aggregations.<name>.buckets[].key`) are
/// tokenized like the field itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldHints {
    aggs: HashMap<String, String>,
}

impl FieldHints {
    /// No hints.
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when no hint is known.
    pub fn is_empty(&self) -> bool {
        self.aggs.is_empty()
    }

    /// Record that aggregation `agg` aggregates `field`.
    pub fn insert(&mut self, agg: impl Into<String>, field: impl Into<String>) {
        if self.aggs.len() < MAX_HINTS {
            self.aggs.insert(agg.into(), field.into());
        }
    }

    /// Field aggregated by `agg`.
    pub fn get(&self, agg: &str) -> Option<&str> {
        self.aggs.get(agg).map(String::as_str)
    }

    /// Collect `{"<name>": {"terms": {"field": "<field>"}}}` pairs (also
    /// composite sources, also inside JSON-encoded string arguments) from a
    /// `tools/call` arguments object.
    pub fn from_arguments(args: &Value) -> Self {
        let mut h = Self::default();
        collect_hints(args, &mut h, 0);
        h
    }
}

fn collect_hints(v: &Value, h: &mut FieldHints, depth: usize) {
    if depth > 64 || h.aggs.len() >= MAX_HINTS {
        return;
    }
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                if let Value::Object(inner) = child {
                    for t in AGG_TYPES {
                        if let Some(f) = inner
                            .get(*t)
                            .and_then(|x| x.get("field"))
                            .and_then(Value::as_str)
                        {
                            h.insert(k.clone(), f);
                        }
                    }
                }
                collect_hints(child, h, depth + 1);
            }
        }
        Value::Array(a) => a.iter().for_each(|c| collect_hints(c, h, depth + 1)),
        Value::String(s) => {
            let t = s.trim_start();
            if depth < 8 && (t.starts_with('{') || t.starts_with('[')) {
                if let Ok(inner) = serde_json::from_str::<Value>(s) {
                    collect_hints(&inner, h, depth + 1);
                }
            }
        }
        _ => {}
    }
}

/// The key path of the value being visited.
#[derive(Default)]
struct FieldPath {
    keys: Vec<String>,
    atoms: Vec<String>,
    marks: Vec<usize>,
}

impl FieldPath {
    fn push(&mut self, key: &str) {
        self.keys.push(key.to_string());
        self.marks.push(self.atoms.len());
        key_atoms(key, &mut self.atoms);
    }

    fn pop(&mut self) {
        self.keys.pop();
        if let Some(m) = self.marks.pop() {
            self.atoms.truncate(m);
        }
    }
}

/// The field a bucket key / composite source stands for, if the request
/// told us.
fn hint_field<'h>(keys: &[String], hints: &'h FieldHints) -> Option<&'h str> {
    let n = keys.len();
    if n < 2 {
        return None;
    }
    let leaf = keys[n - 1].as_str();
    let parent = keys[n - 2].as_str();
    if (leaf == "key" || leaf == "key_as_string") && parent == "buckets" && n >= 3 {
        return hints.get(&keys[n - 3]);
    }
    if parent == "key" || parent == "after_key" {
        return hints.get(leaf);
    }
    None
}

enum Segment {
    Text(String),
    Json { value: Value, original: String },
}

/// A text block split into plain text and embedded JSON documents.
struct TextDoc {
    segments: Vec<Segment>,
}

fn is_structured(v: &Value) -> bool {
    match v {
        Value::Object(m) => !m.is_empty(),
        Value::Array(a) => a.iter().any(|x| x.is_object() || x.is_array()),
        _ => false,
    }
}

/// Split `text` into JSON documents (the whole text, or objects/arrays
/// embedded after a prefix such as `Search results: {...}`) and plain text.
fn parse_text_doc(text: &str) -> TextDoc {
    let trimmed = text.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
            if v.is_object() || v.is_array() {
                let lead_len = text.len() - text.trim_start().len();
                let trail_start = text.trim_end().len();
                let mut segments = Vec::with_capacity(3);
                if lead_len > 0 {
                    segments.push(Segment::Text(text[..lead_len].to_string()));
                }
                segments.push(Segment::Json {
                    value: v,
                    original: trimmed.to_string(),
                });
                if trail_start < text.len() {
                    segments.push(Segment::Text(text[trail_start..].to_string()));
                }
                return TextDoc { segments };
            }
        }
    }
    let bytes = text.as_bytes();
    let mut segments = Vec::new();
    let (mut cursor, mut i, mut attempts) = (0usize, 0usize, 0usize);
    while i < bytes.len() && attempts < MAX_EMBEDDED_ATTEMPTS {
        if bytes[i] == b'{' || bytes[i] == b'[' {
            attempts += 1;
            let mut stream = serde_json::Deserializer::from_str(&text[i..]).into_iter::<Value>();
            if let Some(Ok(v)) = stream.next() {
                let end = i + stream.byte_offset();
                if end > i && is_structured(&v) {
                    if cursor < i {
                        segments.push(Segment::Text(text[cursor..i].to_string()));
                    }
                    segments.push(Segment::Json {
                        value: v,
                        original: text[i..end].to_string(),
                    });
                    cursor = end;
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    if cursor < text.len() {
        segments.push(Segment::Text(text[cursor..].to_string()));
    }
    TextDoc { segments }
}

#[derive(Default)]
struct SweepIndex {
    epoch: u64,
    built_len: usize,
    ac: Option<AhoCorasick>,
    entry_of: Vec<usize>,
}

#[derive(Clone, Copy)]
enum BlockText {
    Text,
    Resource,
}

fn split_domain_user(v: &str) -> Option<(&str, &str, &str)> {
    let i = v.find('\\')?;
    let dom = &v[..i];
    let rest = &v[i..];
    let user = rest.trim_start_matches('\\');
    let sep = &rest[..rest.len() - user.len()];
    if dom.trim().is_empty()
        || user.trim().is_empty()
        || sep.len() > 2
        || dom.len() > 64
        || dom.contains(['/', ':'])
        || user.contains(['\\', '/'])
    {
        return None;
    }
    Some((dom, sep, user))
}

fn is_well_known_authority(dom: &str) -> bool {
    WELL_KNOWN_AUTHORITIES.contains(&fold(dom).as_str())
}

fn looks_like_dns_name(lower: &str) -> bool {
    !lower.is_empty()
        && lower.len() <= 253
        && lower.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn contains_ascii_ci(hay: &str, needle: &str) -> bool {
    let n = needle.as_bytes();
    hay.as_bytes()
        .windows(n.len())
        .any(|w| w.eq_ignore_ascii_case(n))
}

fn apply(cur: &mut Cow<'_, str>, f: impl FnOnce(&str) -> Option<String>) {
    if let Some(next) = f(cur) {
        *cur = Cow::Owned(next);
    }
}

/// The anonymizer: configuration + session token map.
pub struct Anonymizer {
    cfg: Arc<CompiledConfig>,
    map: TokenMap,
    sweep: SweepIndex,
}

impl fmt::Debug for Anonymizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anonymizer")
            .field("map", &self.map)
            .finish_non_exhaustive()
    }
}

impl Anonymizer {
    /// New anonymizer with an empty token map.
    pub fn new(cfg: Arc<CompiledConfig>) -> Self {
        Self::with_map(cfg, TokenMap::new())
    }

    /// New anonymizer continuing an existing token map.
    pub fn with_map(cfg: Arc<CompiledConfig>, map: TokenMap) -> Self {
        Self {
            cfg,
            map,
            sweep: SweepIndex::default(),
        }
    }

    /// The compiled configuration.
    pub fn config(&self) -> &Arc<CompiledConfig> {
        &self.cfg
    }

    /// The token map.
    pub fn map(&self) -> &TokenMap {
        &self.map
    }

    /// Mutable access to the token map (persistence, merging).
    pub fn map_mut(&mut self) -> &mut TokenMap {
        &mut self.map
    }

    /// Consume the anonymizer, returning its token map.
    pub fn into_map(self) -> TokenMap {
        self.map
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Free text: detectors + known-value sweep (the Python proxy's
    /// `_scan_patterns`, extended). JSON is not parsed; see
    /// [`Self::anonymize_text_content`] for that.
    pub fn anonymize_text(&mut self, text: &str) -> String {
        self.scan(text, true).unwrap_or_else(|| text.to_string())
    }

    /// Anonymize one value as if it appeared under `field` (underscore or
    /// dotted notation).
    pub fn anonymize_field(&mut self, field: &str, value: &str) -> String {
        let mut path = FieldPath::default();
        path.push(field);
        let class = self.classify(&path, &FieldHints::default());
        self.field_string(&class, value, 0)
            .unwrap_or_else(|| value.to_string())
    }

    /// Field-aware anonymization of a JSON value in place. Returns `true` if
    /// anything changed.
    pub fn anonymize_json(&mut self, value: &mut Value) -> bool {
        self.anonymize_json_with_hints(value, &FieldHints::default())
    }

    /// [`Self::anonymize_json`] with aggregation hints from the request.
    pub fn anonymize_json_with_hints(&mut self, value: &mut Value, hints: &FieldHints) -> bool {
        self.register_walk(value, &mut FieldPath::default(), hints, 0);
        self.rewrite_walk(value, &mut FieldPath::default(), hints, 0, 0)
    }

    /// MCP text content: the whole text as JSON (as in the Python proxy),
    /// JSON documents embedded in surrounding text, or plain text.
    pub fn anonymize_text_content(&mut self, text: &str, hints: &FieldHints) -> String {
        let mut doc = parse_text_doc(text);
        self.register_doc(&doc, hints);
        self.rewrite_doc(&mut doc, hints)
            .unwrap_or_else(|| text.to_string())
    }

    /// Anonymize MCP content blocks (the Python proxy's
    /// `anonymize_content_blocks`): `text` and `resource` blocks are
    /// rewritten, images/audio are passed through.
    pub fn anonymize_content_blocks(
        &mut self,
        content: &mut Vec<Value>,
        hints: &FieldHints,
    ) -> bool {
        let mut result = serde_json::json!({ "content": std::mem::take(content) });
        let changed = self.anonymize_tool_result(&mut result, hints);
        if let Some(Value::Array(c)) = result.get_mut("content").map(Value::take) {
            *content = c;
        }
        changed
    }

    /// Anonymize a `tools/call` result in place: `content` blocks (JSON in
    /// text parsed field-aware), `structuredContent`, and any other member.
    pub fn anonymize_tool_result(&mut self, result: &mut Value, hints: &FieldHints) -> bool {
        let Value::Object(obj) = result else {
            return self.anonymize_json_with_hints(result, hints);
        };
        let mut docs: Vec<(usize, BlockText, TextDoc)> = Vec::new();
        if let Some(Value::Array(content)) = obj.get("content") {
            for (i, block) in content.iter().enumerate() {
                match block.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(t) = block.get("text").and_then(Value::as_str) {
                            docs.push((i, BlockText::Text, parse_text_doc(t)));
                        }
                    }
                    Some("resource") => {
                        if let Some(t) = block
                            .get("resource")
                            .and_then(|r| r.get("text"))
                            .and_then(Value::as_str)
                        {
                            docs.push((i, BlockText::Resource, parse_text_doc(t)));
                        }
                    }
                    _ => {}
                }
            }
        }
        // Pass 1: learn every field value of every document.
        if let Some(sc) = obj.get("structuredContent") {
            self.register_walk(sc, &mut FieldPath::default(), hints, 0);
        }
        for (_, _, d) in &docs {
            self.register_doc(d, hints);
        }
        // Pass 2: rewrite.
        let mut changed = false;
        if let Some(sc) = obj.get_mut("structuredContent") {
            changed |= self.rewrite_walk(sc, &mut FieldPath::default(), hints, 0, 0);
        }
        let mut rewritten = Vec::new();
        for (i, kind, mut d) in docs {
            if let Some(text) = self.rewrite_doc(&mut d, hints) {
                rewritten.push((i, kind, text));
            }
        }
        for (key, member) in obj.iter_mut() {
            match key.as_str() {
                "structuredContent" | "isError" => {}
                "content" => {
                    let Value::Array(content) = member else {
                        changed |= self.anonymize_json(member);
                        continue;
                    };
                    for (i, kind, text) in rewritten.drain(..) {
                        let slot = match kind {
                            BlockText::Text => content.get_mut(i).and_then(|b| b.get_mut("text")),
                            BlockText::Resource => content
                                .get_mut(i)
                                .and_then(|b| b.get_mut("resource"))
                                .and_then(|r| r.get_mut("text")),
                        };
                        if let Some(slot) = slot {
                            *slot = Value::String(text);
                            changed = true;
                        }
                    }
                    for block in content.iter_mut() {
                        changed |= self.anonymize_block_extras(block);
                    }
                }
                _ => changed |= self.anonymize_json(member),
            }
        }
        changed
    }

    /// Replace issued tokens in `text` with their originals.
    pub fn deanonymize_text(&self, text: &str) -> String {
        self.map.deanonymize(text)
    }

    /// De-anonymize every string in a JSON value (JSON-encoded strings are
    /// parsed so restored values are escaped correctly). Keys are untouched.
    pub fn deanonymize_json(&self, value: &mut Value) -> bool {
        self.deanonymize_value(value, 0)
    }

    // ------------------------------------------------------------------
    // JSON walking
    // ------------------------------------------------------------------

    fn deanonymize_value(&self, value: &mut Value, nest: usize) -> bool {
        match value {
            Value::String(s) => {
                let t = s.trim_start();
                if nest < MAX_NESTED_JSON && (t.starts_with('{') || t.starts_with('[')) {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(s) {
                        if inner.is_object() || inner.is_array() {
                            if self.deanonymize_value(&mut inner, nest + 1) {
                                if let Ok(n) = serde_json::to_string(&inner) {
                                    *s = n;
                                    return true;
                                }
                            }
                            return false;
                        }
                    }
                }
                let n = self.map.deanonymize(s);
                if n != *s {
                    *s = n;
                    true
                } else {
                    false
                }
            }
            Value::Array(a) => a
                .iter_mut()
                .fold(false, |acc, v| self.deanonymize_value(v, nest) | acc),
            Value::Object(m) => m
                .values_mut()
                .fold(false, |acc, v| self.deanonymize_value(v, nest) | acc),
            _ => false,
        }
    }

    fn classify(&self, path: &FieldPath, hints: &FieldHints) -> FieldClass {
        if !hints.is_empty() {
            if let Some(field) = hint_field(&path.keys, hints) {
                let mut atoms = Vec::new();
                key_atoms(field, &mut atoms);
                let c = self.cfg.classify_atoms(&atoms);
                if c != FieldClass::Free {
                    return c;
                }
            }
        }
        self.cfg.classify_atoms(&path.atoms)
    }

    fn register_walk(&mut self, v: &Value, path: &mut FieldPath, hints: &FieldHints, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        match v {
            Value::Object(m) => {
                for (k, child) in m {
                    path.push(k);
                    self.register_walk(child, path, hints, depth + 1);
                    path.pop();
                }
            }
            Value::Array(a) => {
                for child in a {
                    self.register_walk(child, path, hints, depth + 1);
                }
            }
            Value::String(s) => {
                if let FieldClass::Categories(cats) = self.classify(path, hints) {
                    if let Some(c) = self.cfg.pick_category(&cats, s) {
                        let _ = self.tokenize_category(s, c);
                    }
                }
            }
            _ => {}
        }
    }

    fn rewrite_walk(
        &mut self,
        v: &mut Value,
        path: &mut FieldPath,
        hints: &FieldHints,
        depth: usize,
        nest: usize,
    ) -> bool {
        self.rewrite_node(v, path, hints, depth, nest, true)
    }

    /// `direct` is false for array elements (their path ends in the key of
    /// the enclosing array, not in their own key).
    fn rewrite_node(
        &mut self,
        v: &mut Value,
        path: &mut FieldPath,
        hints: &FieldHints,
        depth: usize,
        nest: usize,
        direct: bool,
    ) -> bool {
        if depth > MAX_DEPTH {
            // Too deep to inspect: drop the content rather than leak it.
            *v = Value::String(DEPTH_PLACEHOLDER.to_string());
            return true;
        }
        match v {
            Value::Object(m) => {
                let mut changed = false;
                for (k, child) in m.iter_mut() {
                    path.push(k);
                    changed |= self.rewrite_node(child, path, hints, depth + 1, nest, true);
                    path.pop();
                }
                // Keys can carry values too (keyed bucket aggregations,
                // IP-keyed maps): hinted keys are tokenized like their field,
                // other keys only go through the detectors (no sweep, so
                // ordinary field names are never rewritten).
                let key_class = match path.keys.last() {
                    Some(last) if direct && last == "buckets" && path.keys.len() >= 2 => hints
                        .get(&path.keys[path.keys.len() - 2])
                        .map(|f| {
                            let mut atoms = Vec::new();
                            key_atoms(f, &mut atoms);
                            self.cfg.classify_atoms(&atoms)
                        })
                        .filter(|c| *c != FieldClass::Free),
                    _ => None,
                };
                let keys: Vec<String> = m.keys().cloned().collect();
                for old in keys {
                    let new = match &key_class {
                        Some(c) => self.field_string(c, &old, MAX_NESTED_JSON),
                        None => self.scan(&old, false),
                    };
                    let Some(new) = new else { continue };
                    if let Some(val) = m.remove(&old) {
                        let mut key = new.clone();
                        let mut n = 2;
                        while m.contains_key(&key) {
                            key = format!("{new}#{n}");
                            n += 1;
                        }
                        m.insert(key, val);
                        changed = true;
                    }
                }
                changed
            }
            Value::Array(a) => a.iter_mut().fold(false, |acc, c| {
                self.rewrite_node(c, path, hints, depth + 1, nest, false) | acc
            }),
            Value::String(s) => {
                let class = self.classify(path, hints);
                match self.field_string(&class, s, nest) {
                    Some(new) => {
                        *s = new;
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        }
    }

    fn field_string(&mut self, class: &FieldClass, value: &str, nest: usize) -> Option<String> {
        match class {
            FieldClass::Verbatim => None,
            FieldClass::Preserve => {
                if self.cfg.scan.preserved_fields {
                    self.free_string(value, nest)
                } else {
                    None
                }
            }
            FieldClass::Categories(cats) => match self.cfg.pick_category(cats, value) {
                Some(c) => self.tokenize_category(value, c),
                None => self.free_string(value, nest),
            },
            FieldClass::Free => self.free_string(value, nest),
        }
    }

    /// A string value without a field-level rule: JSON documents encoded in
    /// strings are parsed (bounded), everything else goes to the detectors.
    fn free_string(&mut self, value: &str, nest: usize) -> Option<String> {
        let t = value.trim_start();
        if nest < MAX_NESTED_JSON && (t.starts_with('{') || t.starts_with('[')) {
            if let Ok(mut inner) = serde_json::from_str::<Value>(value) {
                if inner.is_object() || inner.is_array() {
                    let none = FieldHints::default();
                    self.register_walk(&inner, &mut FieldPath::default(), &none, 0);
                    if !self.rewrite_walk(&mut inner, &mut FieldPath::default(), &none, 0, nest + 1)
                    {
                        return None;
                    }
                    return match serde_json::to_string(&inner) {
                        Ok(s) => Some(s),
                        Err(_) => self.scan(value, true),
                    };
                }
            }
        }
        self.scan(value, true)
    }

    fn register_doc(&mut self, doc: &TextDoc, hints: &FieldHints) {
        for seg in &doc.segments {
            if let Segment::Json { value, .. } = seg {
                self.register_walk(value, &mut FieldPath::default(), hints, 0);
            }
        }
    }

    fn rewrite_doc(&mut self, doc: &mut TextDoc, hints: &FieldHints) -> Option<String> {
        let mut changed = false;
        let mut out = String::new();
        for seg in &mut doc.segments {
            match seg {
                Segment::Text(t) => match self.scan(t, true) {
                    Some(n) => {
                        changed = true;
                        out.push_str(&n);
                    }
                    None => out.push_str(t),
                },
                Segment::Json { value, original } => {
                    if self.rewrite_walk(value, &mut FieldPath::default(), hints, 0, 0) {
                        changed = true;
                        match serde_json::to_string(value) {
                            Ok(s) => out.push_str(&s),
                            Err(_) => {
                                let scanned = self
                                    .scan(original, true)
                                    .unwrap_or_else(|| original.clone());
                                out.push_str(&scanned);
                            }
                        }
                    } else {
                        out.push_str(original);
                    }
                }
            }
        }
        changed.then_some(out)
    }

    /// Non-text content blocks: images/audio pass through; resource URIs,
    /// resource links and unknown block types have their strings scanned.
    fn anonymize_block_extras(&mut self, block: &mut Value) -> bool {
        let kind = block
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let Value::Object(obj) = block else {
            return self.anonymize_json(block);
        };
        let mut changed = false;
        match kind.as_str() {
            "text" => {
                for (k, v) in obj.iter_mut() {
                    if k != "type" && k != "text" {
                        changed |= self.anonymize_json(v);
                    }
                }
            }
            "image" | "audio" => {}
            "resource" => {
                if let Some(Value::Object(res)) = obj.get_mut("resource") {
                    for (k, v) in res.iter_mut() {
                        if !matches!(k.as_str(), "text" | "blob" | "mimeType") {
                            changed |= self.anonymize_json(v);
                        }
                    }
                }
            }
            _ => {
                for (k, v) in obj.iter_mut() {
                    if !matches!(k.as_str(), "type" | "mimeType" | "data" | "blob") {
                        changed |= self.anonymize_json(v);
                    }
                }
            }
        }
        changed
    }

    // ------------------------------------------------------------------
    // Value tokenizers
    // ------------------------------------------------------------------

    fn tok(&mut self, value: &str, prefix: &str) -> Option<String> {
        if self.cfg.is_kept(value) || self.map.is_token(value) {
            return None;
        }
        Some(self.map.get_or_create(value, prefix))
    }

    fn tokenize_category(&mut self, value: &str, cat: usize) -> Option<String> {
        let cfg = Arc::clone(&self.cfg);
        let c = cfg.categories.get(cat)?;
        match c.kind {
            CategoryKind::User => self.tokenize_user(value, &c.prefix),
            CategoryKind::Host => self.tokenize_host(value, &c.prefix),
            CategoryKind::Other => self.tok(value, &c.prefix),
        }
    }

    fn tokenize_domain(&mut self, domain: &str) -> Option<String> {
        let cfg = Arc::clone(&self.cfg);
        self.tok(domain, &cfg.prefixes.domain)
    }

    /// User names: `DOMAIN\user` becomes `DOMAIN_INT_n\USER_m` so the bare
    /// user name shares its token with other fields.
    fn tokenize_user(&mut self, value: &str, prefix: &str) -> Option<String> {
        if self.cfg.is_kept(value) || self.map.is_token(value) {
            return None;
        }
        if let Some(t) = self.map.token_for(value) {
            return Some(t.to_string());
        }
        if let Some((dom, sep, user)) = split_domain_user(value) {
            if is_well_known_authority(dom) {
                return None;
            }
            let d = self.tokenize_domain(dom);
            let u = self.tok(user, prefix);
            if d.is_none() && u.is_none() {
                return None;
            }
            return Some(format!(
                "{}{}{}",
                d.as_deref().unwrap_or(dom),
                sep,
                u.as_deref().unwrap_or(user)
            ));
        }
        self.tok(value, prefix)
    }

    /// Host names: internal IPs get IP tokens, public IPs are kept, internal
    /// FQDNs become `HOST_n.DOMAIN_INT_m`, everything else one token.
    fn tokenize_host(&mut self, value: &str, prefix: &str) -> Option<String> {
        if self.cfg.is_kept(value) || self.map.is_token(value) {
            return None;
        }
        if let Some(t) = self.map.token_for(value) {
            return Some(t.to_string());
        }
        let t = value.trim();
        if let Some(ip) = parse_ip(t) {
            if !is_internal_ip(ip) {
                return None;
            }
            let cfg = Arc::clone(&self.cfg);
            return self.tok(value, &cfg.prefixes.ip);
        }
        if let Some(r) = self.tokenize_internal_fqdn(t) {
            return Some(r);
        }
        self.tok(value, prefix)
    }

    fn join_host_domain(
        &mut self,
        host: &str,
        domain: &str,
        cfg: &CompiledConfig,
    ) -> Option<String> {
        let h = self.tok(host, &cfg.prefixes.host);
        let d = self.tok(domain, &cfg.prefixes.domain);
        if h.is_none() && d.is_none() {
            return None;
        }
        Some(format!(
            "{}.{}",
            h.as_deref().unwrap_or(host),
            d.as_deref().unwrap_or(domain)
        ))
    }

    /// `ws01.corp.local` -> `HOST_1.DOMAIN_INT_1`, `corp.local` ->
    /// `DOMAIN_INT_1`; `None` if `name` is not under an internal domain.
    fn tokenize_internal_fqdn(&mut self, name: &str) -> Option<String> {
        let cfg = Arc::clone(&self.cfg);
        if !cfg.scan.internal_domains {
            return None;
        }
        let lower = name.to_ascii_lowercase();
        if !looks_like_dns_name(&lower) || self.map.is_token(name) {
            return None;
        }
        if let Some(t) = self.map.token_for(name) {
            return Some(t.to_string());
        }
        for d in &cfg.internal_domains {
            if lower == *d {
                return self.tok(name, &cfg.prefixes.domain);
            }
            if lower.len() > d.len() + 1
                && lower.ends_with(d.as_str())
                && lower.as_bytes()[lower.len() - d.len() - 1] == b'.'
            {
                let split = name.len() - d.len();
                return self.join_host_domain(&name[..split - 1], &name[split..], &cfg);
            }
        }
        for s in &cfg.internal_suffixes {
            if lower == *s {
                return None;
            }
            if lower.len() > s.len() + 1
                && lower.ends_with(s.as_str())
                && lower.as_bytes()[lower.len() - s.len() - 1] == b'.'
            {
                let k = s.split('.').count();
                let labels: Vec<&str> = name.split('.').collect();
                let n = labels.len();
                if n <= k + 1 {
                    return self.tok(name, &cfg.prefixes.domain);
                }
                let host_labels = n - (k + 1);
                let host_len =
                    labels[..host_labels].iter().map(|l| l.len()).sum::<usize>() + host_labels - 1;
                return self.join_host_domain(&name[..host_len], &name[host_len + 1..], &cfg);
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Free-text detectors
    // ------------------------------------------------------------------

    /// Run the enabled detectors (and optionally the sweep). `None` when
    /// nothing changed.
    fn scan(&mut self, text: &str, sweep: bool) -> Option<String> {
        if text.is_empty() {
            return None;
        }
        let s = self.cfg.scan;
        let mut cur: Cow<'_, str> = Cow::Borrowed(text);
        if s.emails {
            apply(&mut cur, |t| self.detect_emails(t));
        }
        if s.unc_paths {
            apply(&mut cur, |t| self.detect_unc(t));
        }
        if s.domain_users {
            apply(&mut cur, |t| self.detect_domain_users(t));
        }
        if s.user_paths {
            apply(&mut cur, |t| self.detect_profiles(t));
            apply(&mut cur, |t| self.detect_unix_home(t));
        }
        if s.sids {
            apply(&mut cur, |t| self.detect_sids(t));
        }
        if s.macs {
            apply(&mut cur, |t| self.detect_macs(t));
        }
        if s.inline_ips {
            apply(&mut cur, |t| self.detect_ipv6(t));
            apply(&mut cur, |t| self.detect_ipv4(t));
        }
        if s.internal_domains {
            apply(&mut cur, |t| self.detect_internal_fqdns(t));
        }
        if sweep && s.sweep {
            apply(&mut cur, |t| self.sweep(t));
        }
        match cur {
            Cow::Borrowed(_) => None,
            Cow::Owned(o) => Some(o),
        }
    }

    fn detect_emails(&mut self, text: &str) -> Option<String> {
        if !text.contains('@') {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        replace_matches(&EMAIL_RE, text, |c| {
            let m = c.get(0)?;
            let tld = m
                .as_str()
                .rsplit('.')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if FILE_EXTENSION_TLDS.contains(&tld.as_str()) {
                return None;
            }
            self.tok(m.as_str(), &cfg.prefixes.email)
        })
    }

    fn detect_unc(&mut self, text: &str) -> Option<String> {
        if !text.contains("\\\\") {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        replace_matches(&UNC_RE, text, |c| {
            let m = c.get(0)?;
            let host = c.get(1)?;
            if char_before(text, m.start()).is_some_and(|p| !is_unc_boundary(p)) {
                return None;
            }
            if char_after(text, host.end())
                .is_some_and(|n| n.is_alphanumeric() || "_$-".contains(n))
            {
                return None;
            }
            let new = self.tokenize_host(host.as_str(), &cfg.prefixes.host)?;
            Some(format!("{}{}", &text[m.start()..host.start()], new))
        })
    }

    fn detect_domain_users(&mut self, text: &str) -> Option<String> {
        if !text.contains('\\') {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        replace_matches(&DOMAIN_USER_RE, text, |c| {
            if c.get(1).is_some() {
                return None; // NT AUTHORITY\..., BUILTIN\...
            }
            let dom = c.get(2)?;
            let user = c.get(3)?;
            if char_before(text, dom.start()).is_some_and(|p| !is_open_boundary(p)) {
                return None;
            }
            if !dom.as_str().bytes().any(|b| b.is_ascii_uppercase()) {
                return None;
            }
            if char_after(text, user.end())
                .is_some_and(|n| n == '\\' || n == '/' || is_word_char(n))
            {
                return None;
            }
            let sep = &text[dom.end()..user.start()];
            let d = self.tokenize_domain(dom.as_str());
            let u = self.tok(user.as_str(), &cfg.prefixes.user);
            if d.is_none() && u.is_none() {
                return None;
            }
            Some(format!(
                "{}{}{}",
                d.as_deref().unwrap_or(dom.as_str()),
                sep,
                u.as_deref().unwrap_or(user.as_str())
            ))
        })
    }

    fn profile_replacement(
        &mut self,
        c: &Captures<'_>,
        spans: &[(usize, usize)],
        prefix: &str,
    ) -> Option<String> {
        let m = c.get(0)?;
        if in_spans(spans, m.start()) {
            return None;
        }
        let name = c.get(2)?.as_str();
        if PROFILE_DIRS.contains(&fold(name).as_str()) {
            return None;
        }
        let new = self.tok(name, prefix)?;
        Some(format!(
            "{}{}{}",
            c.get(1)?.as_str(),
            new,
            c.get(3).map_or("", |x| x.as_str())
        ))
    }

    fn detect_profiles(&mut self, text: &str) -> Option<String> {
        if !contains_ascii_ci(text, "users") {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        let mut cur: Cow<'_, str> = Cow::Borrowed(text);
        for re in [&*WIN_PROFILE_RE, &*WIN_PROFILE_END_RE] {
            let spans = url_spans(&cur);
            if let Some(next) = replace_matches(re, &cur, |c| {
                self.profile_replacement(c, &spans, &cfg.prefixes.user)
            }) {
                cur = Cow::Owned(next);
            }
        }
        match cur {
            Cow::Borrowed(_) => None,
            Cow::Owned(o) => Some(o),
        }
    }

    fn detect_unix_home(&mut self, text: &str) -> Option<String> {
        if !text.contains("/home/") {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        let spans = url_spans(text);
        replace_matches(&UNIX_HOME_RE, text, |c| {
            let m = c.get(0)?;
            if in_spans(&spans, m.start()) {
                return None;
            }
            let name = c.get(2)?;
            if char_after(text, name.end())
                .is_some_and(|n| n.is_alphanumeric() || "_@$-".contains(n))
            {
                return None;
            }
            let new = self.tok(name.as_str(), &cfg.prefixes.user)?;
            Some(format!("{}{}", c.get(1)?.as_str(), new))
        })
    }

    fn detect_sids(&mut self, text: &str) -> Option<String> {
        if !text.contains("S-1-") {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        replace_matches(&SID_RE, text, |c| {
            let core = c.get(1)?;
            let rid = c.get(2).map_or("", |m| m.as_str());
            let t = self.tok(core.as_str(), &cfg.prefixes.sid)?;
            Some(format!("{t}{rid}"))
        })
    }

    fn detect_macs(&mut self, text: &str) -> Option<String> {
        if !text.contains([':', '-', '.']) {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        replace_matches(&MAC_RE, text, |c| {
            let m = c.get(0)?;
            if char_before(text, m.start()).is_some_and(|p| matches!(p, ':' | '-' | '.')) {
                return None;
            }
            if let Some(n) = char_after(text, m.end()) {
                if matches!(n, ':' | '-' | '.')
                    && char_after(text, m.end() + 1).is_some_and(|x| x.is_ascii_hexdigit())
                {
                    return None;
                }
            }
            let hex: Vec<u8> = m
                .as_str()
                .bytes()
                .filter(u8::is_ascii_hexdigit)
                .map(|b| b.to_ascii_lowercase())
                .collect();
            if hex.iter().all(|&b| b == b'0') || hex.iter().all(|&b| b == b'f') {
                return None;
            }
            self.tok(m.as_str(), &cfg.prefixes.mac)
        })
    }

    fn detect_ipv6(&mut self, text: &str) -> Option<String> {
        // at least two colons
        text.bytes().filter(|&b| b == b':').nth(1)?;
        let cfg = Arc::clone(&self.cfg);
        replace_matches(&IPV6_CANDIDATE_RE, text, |c| {
            let m = c.get(0)?;
            let raw = m.as_str(); // ASCII only (see the pattern)
            let mut start = 0usize;
            let mut end = raw.len();
            if raw.starts_with(':') && !raw.starts_with("::") {
                start = 1;
            }
            while end > start && raw[..end].ends_with('.') {
                end -= 1;
            }
            if raw[start..end].ends_with(':') && !raw[start..end].ends_with("::") {
                end -= 1;
            }
            let core = raw.get(start..end)?;
            if core.is_empty() {
                return None;
            }
            if char_before(text, m.start() + start).is_some_and(is_word_char)
                || char_after(text, m.start() + end).is_some_and(is_word_char)
            {
                return None;
            }
            let addr: Ipv6Addr = core.split('%').next()?.parse().ok()?;
            if !is_internal_ipv6(addr) {
                return None;
            }
            let t = self.tok(core, &cfg.prefixes.ip)?;
            Some(format!("{}{}{}", &raw[..start], t, &raw[end..]))
        })
    }

    fn detect_ipv4(&mut self, text: &str) -> Option<String> {
        if !text.contains('.') {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        replace_matches(&IPV4_RE, text, |c| {
            let s = c.get(0)?.as_str();
            let ip = parse_ipv4_lenient(s)?;
            if !is_internal_ipv4(ip) {
                return None;
            }
            self.tok(s, &cfg.prefixes.ip)
        })
    }

    fn detect_internal_fqdns(&mut self, text: &str) -> Option<String> {
        if !text.contains('.') {
            return None;
        }
        let cfg = Arc::clone(&self.cfg);
        let re = cfg.fqdn_re.as_ref()?;
        replace_matches(re, text, |c| {
            let m = c.get(0)?;
            if char_before(text, m.start()).is_some_and(|p| is_word_char(p) || p == '-') {
                return None;
            }
            if let Some(n) = char_after(text, m.end()) {
                if n == '-'
                    || is_word_char(n)
                    || (n == '.'
                        && char_after(text, m.end() + 1).is_some_and(|x| x.is_ascii_alphanumeric()))
                {
                    return None;
                }
            }
            self.tokenize_internal_fqdn(m.as_str())
        })
    }

    // ------------------------------------------------------------------
    // Known-value sweep
    // ------------------------------------------------------------------

    fn sweepable(&self, original: &str) -> bool {
        let t = original.trim();
        t.chars().count() >= self.cfg.sweep_min_length
            && t.chars().any(char::is_alphabetic)
            && !self.cfg.is_kept(t)
    }

    fn ensure_sweep_index(&mut self) {
        let len = self.map.len();
        let epoch = self.map.epoch();
        let fresh = self.sweep.epoch == epoch
            && self.sweep.built_len <= len
            && len - self.sweep.built_len <= SWEEP_EXTRA_LIMIT;
        if fresh {
            return;
        }
        let mut patterns = Vec::new();
        let mut entry_of = Vec::new();
        for (i, e) in self.map.entries().iter().enumerate() {
            if self.sweepable(&e.original) {
                patterns.push(e.original.trim().to_string());
                entry_of.push(i);
            }
        }
        let ac = if patterns.is_empty() {
            None
        } else {
            match AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&patterns)
            {
                Ok(ac) => Some(ac),
                Err(e) => {
                    tracing::warn!(error = %e, "known-value sweep index unavailable");
                    None
                }
            }
        };
        self.sweep = SweepIndex {
            epoch,
            built_len: len,
            ac,
            entry_of,
        };
    }

    fn sweep(&mut self, text: &str) -> Option<String> {
        if self.map.is_empty() || text.len() < self.cfg.sweep_min_length {
            return None;
        }
        self.ensure_sweep_index();
        let entries = self.map.entries();
        let mut cands = Vec::new();
        if let Some(ac) = &self.sweep.ac {
            for m in ac.find_overlapping_iter(text) {
                if let Some(&idx) = self.sweep.entry_of.get(m.pattern().as_usize()) {
                    cands.push(Candidate {
                        start: m.start(),
                        end: m.end(),
                        idx,
                    });
                }
            }
        }
        if entries.len() > self.sweep.built_len {
            let lower = text.to_ascii_lowercase();
            for (idx, e) in entries.iter().enumerate().skip(self.sweep.built_len) {
                if !self.sweepable(&e.original) {
                    continue;
                }
                let needle = e.original.trim().to_ascii_lowercase();
                for (pos, _) in lower.match_indices(needle.as_str()) {
                    cands.push(Candidate {
                        start: pos,
                        end: pos + needle.len(),
                        idx,
                    });
                }
            }
        }
        cands.retain(|c| word_bounded(text, c.start, c.end));
        if cands.is_empty() {
            return None;
        }
        let sel = select_matches(cands);
        Some(splice(text, &sel, |c| {
            entries.get(c.idx).map_or("", |e| e.token.as_str())
        }))
    }
}

#[cfg(test)]
mod tests;
