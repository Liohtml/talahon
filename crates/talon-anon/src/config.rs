//! `fields.yaml`: which fields are tokenized, preserved or left verbatim, and
//! which free-text detectors run.
//!
//! The file format is the one read by the Python proxy; every key it knew is
//! interpreted the same way:
//!
//! ```yaml
//! categories:
//!   user:
//!     token_prefix: "USER"          # default: category name upper-cased
//!     fields: [data_win_eventdata_user, ...]
//! internal_ip_token_prefix: "IP_INT"
//! scan_user_paths: true             # C:\Users\<name>\, /home/<name>/, /Users/<name>/
//! scan_inline_ips: true             # internal IPv4 (and now IPv6) in any string
//! preserve_fields: [rule_id, ...]   # never tokenized as a whole
//! ```
//!
//! Additional (optional) keys understood by the Rust proxy — the Python proxy
//! ignores unknown keys, so an extended file stays compatible:
//!
//! - per category `value_pattern: <regex>` — when a field belongs to several
//!   categories, the first category whose pattern matches the value wins;
//!   otherwise the last category without a pattern applies (the Python rule
//!   "later categories override earlier ones"). E.g. `targetUserName` is
//!   `EMAIL_n` for `j@corp.com` but `USER_n` for `jdoe`.
//! - `verbatim_fields` — never touched at all (not even by the detectors).
//! - `scan_preserved_fields` (default `false`) — run the free-text detectors
//!   (internal IPs, user paths, ...) on preserved fields too.
//! - `keep_values` — values never tokenized (`SYSTEM`, `-`, ...).
//! - `internal_domains` / `internal_domain_suffixes` — DNS names treated as
//!   internal (`ws01.corp.local` -> `HOST_1.DOMAIN_INT_1`).
//! - `scan_emails`, `scan_domain_users`, `scan_unc_paths`, `scan_sids`,
//!   `scan_macs`, `scan_internal_domains` (all default `true`).
//! - `sweep_known_values` (default `true`), `sweep_min_length` (default 3):
//!   once a value is tokenized, later occurrences in free text are replaced.
//! - `user_token_prefix`, `host_token_prefix`, `email_token_prefix`,
//!   `domain_token_prefix`, `sid_token_prefix`, `mac_token_prefix`.
//!
//! Field names are matched on *atoms* (split on `.` and `_`, lower-cased), so
//! `data_win_eventdata_user` matches the flat CoPilot key, the dotted key
//! `data.win.eventdata.user` and the nested OpenSearch document
//! `{"data":{"win":{"eventdata":{"user":..}}}}` (also below `_source`).

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use talon_core::{Error, Result};
use yaml_rust2::{Yaml, YamlLoader, yaml::Hash};

use crate::text::fold;

/// The shipped field list (`crates/talon-anon/fields.yaml`, kept identical to
/// `siem/anon_proxy/fields.yaml`), embedded at build time. Used by
/// `talon-anon-proxy` when `--fields` is not given.
pub const DEFAULT_FIELDS_YAML: &str = include_str!("../fields.yaml");

/// Default prefix for internal IP addresses (Python: `internal_ip_token_prefix`).
pub const DEFAULT_IP_PREFIX: &str = "IP_INT";
/// Default prefix for user names found by the detectors.
pub const DEFAULT_USER_PREFIX: &str = "USER";
/// Default prefix for host names found by the detectors.
pub const DEFAULT_HOST_PREFIX: &str = "HOST";
/// Default prefix for e-mail addresses found by the detectors.
pub const DEFAULT_EMAIL_PREFIX: &str = "EMAIL";
/// Default prefix for internal (AD / DNS) domain names.
pub const DEFAULT_DOMAIN_PREFIX: &str = "DOMAIN_INT";
/// Default prefix for domain / Azure AD security identifiers.
pub const DEFAULT_SID_PREFIX: &str = "SID";
/// Default prefix for MAC addresses.
pub const DEFAULT_MAC_PREFIX: &str = "MAC";

/// DNS suffixes that are internal by definition (never delegated publicly).
pub const DEFAULT_INTERNAL_SUFFIXES: &[&str] = &[
    "local",
    "localdomain",
    "lan",
    "internal",
    "intranet",
    "corp",
    "home.arpa",
];

/// Placeholder values that carry no identity and are never tokenized.
pub const DEFAULT_KEEP_VALUES: &[&str] = &[
    "-",
    "--",
    "n/a",
    "none",
    "null",
    "nil",
    "unknown",
    "undefined",
    "localhost",
];

static PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Static pattern, verified by tests: cannot fail.
    Regex::new(r"^[A-Za-z][A-Za-z0-9_]{0,31}$").expect("static regex")
});

static DOMAIN_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Static pattern, verified by tests: cannot fail.
    Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
        .expect("static regex")
});

/// One `categories.<name>` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    /// YAML key of the category (`user`, `hostname`, ...).
    pub name: String,
    /// Token prefix (`USER` -> `USER_1`).
    pub token_prefix: String,
    /// Free-form description (informational).
    pub description: Option<String>,
    /// Field names in underscore notation.
    pub fields: Vec<String>,
    /// Optional regex the value must match for this category to apply.
    pub value_pattern: Option<String>,
}

/// Parsed `fields.yaml` (uncompiled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldsConfig {
    /// Categories in file order (order matters for multi-category fields).
    pub categories: Vec<Category>,
    /// Fields never tokenized as a whole.
    pub preserve_fields: Vec<String>,
    /// Fields never touched at all.
    pub verbatim_fields: Vec<String>,
    /// Values never tokenized (case-insensitive, trimmed). Extends
    /// [`DEFAULT_KEEP_VALUES`].
    pub keep_values: Vec<String>,
    /// Organisation domains treated as internal (`corp.example.com`).
    pub internal_domains: Vec<String>,
    /// DNS suffixes treated as internal.
    pub internal_domain_suffixes: Vec<String>,
    /// Prefix for internal IPs.
    pub internal_ip_token_prefix: String,
    /// Prefix for detector-found user names.
    pub user_token_prefix: String,
    /// Prefix for detector-found host names.
    pub host_token_prefix: String,
    /// Prefix for detector-found e-mail addresses.
    pub email_token_prefix: String,
    /// Prefix for internal domains.
    pub domain_token_prefix: String,
    /// Prefix for SIDs.
    pub sid_token_prefix: String,
    /// Prefix for MAC addresses.
    pub mac_token_prefix: String,
    /// User profile / home directory paths.
    pub scan_user_paths: bool,
    /// Internal IPv4/IPv6 addresses in any string.
    pub scan_inline_ips: bool,
    /// E-mail addresses in free text.
    pub scan_emails: bool,
    /// `DOMAIN\user` in free text.
    pub scan_domain_users: bool,
    /// UNC host names (`\\host\share`).
    pub scan_unc_paths: bool,
    /// Domain / Azure AD SIDs.
    pub scan_sids: bool,
    /// MAC addresses.
    pub scan_macs: bool,
    /// Host names under internal DNS domains.
    pub scan_internal_domains: bool,
    /// Run the detectors on preserved fields as well.
    pub scan_preserved_fields: bool,
    /// Replace already-tokenized values wherever they re-appear in free text.
    pub sweep_known_values: bool,
    /// Minimum length (chars) of a value for the sweep.
    pub sweep_min_length: usize,
}

impl Default for FieldsConfig {
    fn default() -> Self {
        Self {
            categories: Vec::new(),
            preserve_fields: Vec::new(),
            verbatim_fields: Vec::new(),
            keep_values: Vec::new(),
            internal_domains: Vec::new(),
            internal_domain_suffixes: DEFAULT_INTERNAL_SUFFIXES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            internal_ip_token_prefix: DEFAULT_IP_PREFIX.into(),
            user_token_prefix: DEFAULT_USER_PREFIX.into(),
            host_token_prefix: DEFAULT_HOST_PREFIX.into(),
            email_token_prefix: DEFAULT_EMAIL_PREFIX.into(),
            domain_token_prefix: DEFAULT_DOMAIN_PREFIX.into(),
            sid_token_prefix: DEFAULT_SID_PREFIX.into(),
            mac_token_prefix: DEFAULT_MAC_PREFIX.into(),
            scan_user_paths: true,
            scan_inline_ips: true,
            scan_emails: true,
            scan_domain_users: true,
            scan_unc_paths: true,
            scan_sids: true,
            scan_macs: true,
            scan_internal_domains: true,
            scan_preserved_fields: false,
            sweep_known_values: true,
            sweep_min_length: 3,
        }
    }
}

fn cfg_err(msg: impl Into<String>) -> Error {
    Error::Config(format!("fields.yaml: {}", msg.into()))
}

fn scalar_string(v: &Yaml) -> Option<String> {
    match v {
        Yaml::String(s) | Yaml::Real(s) => Some(s.clone()),
        Yaml::Integer(n) => Some(n.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Look up a string key in a YAML mapping.
fn lookup<'a>(m: &'a Hash, key: &str) -> Option<&'a Yaml> {
    m.get(&Yaml::String(key.to_string()))
}

fn get_list(m: &Hash, key: &str) -> Result<Option<Vec<String>>> {
    match lookup(m, key) {
        None | Some(Yaml::Null) => Ok(None),
        Some(Yaml::Array(seq)) => seq
            .iter()
            .map(|x| {
                scalar_string(x).ok_or_else(|| cfg_err(format!("`{key}` entries must be scalars")))
            })
            .collect::<Result<Vec<_>>>()
            .map(Some),
        Some(_) => Err(cfg_err(format!("`{key}` must be a list"))),
    }
}

fn get_bool(m: &Hash, key: &str) -> Result<Option<bool>> {
    match lookup(m, key) {
        None | Some(Yaml::Null) => Ok(None),
        Some(Yaml::Boolean(b)) => Ok(Some(*b)),
        Some(_) => Err(cfg_err(format!("`{key}` must be true or false"))),
    }
}

fn get_string(m: &Hash, key: &str) -> Result<Option<String>> {
    match lookup(m, key) {
        None | Some(Yaml::Null) => Ok(None),
        Some(v) => scalar_string(v)
            .map(Some)
            .ok_or_else(|| cfg_err(format!("`{key}` must be a string"))),
    }
}

fn get_usize(m: &Hash, key: &str) -> Result<Option<usize>> {
    match lookup(m, key) {
        None | Some(Yaml::Null) => Ok(None),
        Some(Yaml::Integer(n)) => usize::try_from(*n)
            .map(Some)
            .map_err(|_| cfg_err(format!("`{key}` must be a non-negative integer"))),
        Some(Yaml::Real(_)) => Err(cfg_err(format!("`{key}` must be a non-negative integer"))),
        Some(_) => Err(cfg_err(format!("`{key}` must be an integer"))),
    }
}

fn normalize_domain(raw: &str, key: &str) -> Result<String> {
    let d = raw.trim().trim_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 || !DOMAIN_NAME_RE.is_match(&d) {
        return Err(cfg_err(format!("`{key}` entry {raw:?} is not a DNS name")));
    }
    Ok(d)
}

impl FieldsConfig {
    /// Parse YAML text. An empty document yields the defaults (detectors
    /// only, like the Python proxy without a field list).
    pub fn from_yaml_str(text: &str) -> Result<Self> {
        let mut docs = YamlLoader::load_from_str(text).map_err(|e| cfg_err(e.to_string()))?;
        if docs.len() > 1 {
            return Err(cfg_err("expected a single YAML document"));
        }
        let root = docs.pop().unwrap_or(Yaml::Null);
        let mut cfg = Self::default();
        let top = match &root {
            Yaml::Null => return Ok(cfg),
            Yaml::Hash(m) => m,
            _ => return Err(cfg_err("top level must be a mapping")),
        };

        match lookup(top, "categories") {
            None | Some(Yaml::Null) => {}
            Some(Yaml::Hash(cats)) => {
                for (k, v) in cats {
                    let name = scalar_string(k)
                        .ok_or_else(|| cfg_err("category names must be scalars"))?;
                    let (prefix, description, fields, value_pattern) = match v {
                        Yaml::Null => (None, None, Vec::new(), None),
                        Yaml::Hash(cm) => (
                            get_string(cm, "token_prefix")?,
                            get_string(cm, "description")?,
                            get_list(cm, "fields")?.unwrap_or_default(),
                            get_string(cm, "value_pattern")?,
                        ),
                        _ => return Err(cfg_err(format!("category `{name}` must be a mapping"))),
                    };
                    cfg.categories.push(Category {
                        token_prefix: prefix.unwrap_or_else(|| name.to_uppercase()),
                        name,
                        description,
                        fields,
                        value_pattern,
                    });
                }
            }
            Some(_) => return Err(cfg_err("`categories` must be a mapping")),
        }

        if let Some(v) = get_list(top, "preserve_fields")? {
            cfg.preserve_fields = v;
        }
        if let Some(v) = get_list(top, "verbatim_fields")? {
            cfg.verbatim_fields = v;
        }
        if let Some(v) = get_list(top, "keep_values")? {
            cfg.keep_values = v;
        }
        if let Some(v) = get_list(top, "internal_domains")? {
            cfg.internal_domains = v;
        }
        if let Some(v) = get_list(top, "internal_domain_suffixes")? {
            cfg.internal_domain_suffixes = v;
        }
        for (key, slot) in [
            (
                "internal_ip_token_prefix",
                &mut cfg.internal_ip_token_prefix,
            ),
            ("user_token_prefix", &mut cfg.user_token_prefix),
            ("host_token_prefix", &mut cfg.host_token_prefix),
            ("email_token_prefix", &mut cfg.email_token_prefix),
            ("domain_token_prefix", &mut cfg.domain_token_prefix),
            ("sid_token_prefix", &mut cfg.sid_token_prefix),
            ("mac_token_prefix", &mut cfg.mac_token_prefix),
        ] {
            if let Some(v) = get_string(top, key)? {
                *slot = v;
            }
        }
        for (key, slot) in [
            ("scan_user_paths", &mut cfg.scan_user_paths),
            ("scan_inline_ips", &mut cfg.scan_inline_ips),
            ("scan_emails", &mut cfg.scan_emails),
            ("scan_domain_users", &mut cfg.scan_domain_users),
            ("scan_unc_paths", &mut cfg.scan_unc_paths),
            ("scan_sids", &mut cfg.scan_sids),
            ("scan_macs", &mut cfg.scan_macs),
            ("scan_internal_domains", &mut cfg.scan_internal_domains),
            ("scan_preserved_fields", &mut cfg.scan_preserved_fields),
            ("sweep_known_values", &mut cfg.sweep_known_values),
        ] {
            if let Some(v) = get_bool(top, key)? {
                *slot = v;
            }
        }
        if let Some(n) = get_usize(top, "sweep_min_length")? {
            cfg.sweep_min_length = n.max(1);
        }
        Ok(cfg)
    }

    /// Read and parse a `fields.yaml` file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::from_yaml_str(&text)
    }

    /// Validate and compile (regexes, field index).
    pub fn compile(&self) -> Result<CompiledConfig> {
        CompiledConfig::new(self)
    }
}

/// How a category's values are tokenized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CategoryKind {
    /// `DOMAIN\user` values are split into `DOMAIN_INT_n\USER_m`.
    User,
    /// IPs and internal FQDNs get IP / host+domain tokens.
    Host,
    /// Whole value -> one token.
    Other,
}

#[derive(Debug)]
pub(crate) struct CompiledCategory {
    pub(crate) prefix: String,
    pub(crate) kind: CategoryKind,
    pub(crate) value_pattern: Option<Regex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    Verbatim,
    Preserve,
    Category(usize),
}

#[derive(Debug)]
struct FieldRule {
    atoms: Vec<String>,
    kind: RuleKind,
}

/// Internal classification of a field path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FieldClass {
    Free,
    Verbatim,
    Preserve,
    Categories(Vec<usize>),
}

/// Public view of how a field is handled (see [`CompiledConfig::classify_field`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldDisposition {
    /// Not configured: only the free-text detectors apply.
    Free,
    /// Never touched.
    Verbatim,
    /// Never tokenized as a whole (detectors only if `scan_preserved_fields`).
    Preserve,
    /// Tokenized; candidate token prefixes in category order.
    Tokenize(Vec<String>),
}

/// Token prefixes used by the detectors.
#[derive(Debug, Clone)]
pub(crate) struct Prefixes {
    pub(crate) ip: String,
    pub(crate) user: String,
    pub(crate) host: String,
    pub(crate) email: String,
    pub(crate) domain: String,
    pub(crate) sid: String,
    pub(crate) mac: String,
}

/// Enabled detectors.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanFlags {
    pub(crate) user_paths: bool,
    pub(crate) inline_ips: bool,
    pub(crate) emails: bool,
    pub(crate) domain_users: bool,
    pub(crate) unc_paths: bool,
    pub(crate) sids: bool,
    pub(crate) macs: bool,
    pub(crate) internal_domains: bool,
    pub(crate) preserved_fields: bool,
    pub(crate) sweep: bool,
}

/// Validated, compiled configuration shared by all anonymizers.
#[derive(Debug)]
pub struct CompiledConfig {
    pub(crate) categories: Vec<CompiledCategory>,
    rules: Vec<FieldRule>,
    by_last: HashMap<String, Vec<usize>>,
    keep: HashSet<String>,
    pub(crate) prefixes: Prefixes,
    pub(crate) scan: ScanFlags,
    pub(crate) sweep_min_length: usize,
    /// Lower-cased, longest first.
    pub(crate) internal_domains: Vec<String>,
    /// Lower-cased, longest first.
    pub(crate) internal_suffixes: Vec<String>,
    pub(crate) fqdn_re: Option<Regex>,
}

/// Split a field name / JSON key into lower-cased atoms on `.` and `_`.
/// Leading underscores stay attached (`_id` -> `["_id"]`, so it does not
/// match every `*.id` key).
pub(crate) fn key_atoms(key: &str, out: &mut Vec<String>) {
    for part in key.split('.') {
        if part.is_empty() {
            continue;
        }
        let trimmed = part.trim_start_matches('_');
        let lead = &part[..part.len() - trimmed.len()];
        let mut first = true;
        for sub in trimmed.split('_').filter(|s| !s.is_empty()) {
            if first && !lead.is_empty() {
                out.push(format!("{lead}{sub}").to_lowercase());
            } else {
                out.push(sub.to_lowercase());
            }
            first = false;
        }
        if first {
            // the part consisted of underscores only
            out.push(part.to_string());
        }
    }
}

fn atoms_of(key: &str) -> Vec<String> {
    let mut v = Vec::new();
    key_atoms(key, &mut v);
    v
}

fn check_prefix(p: &str, key: &str) -> Result<()> {
    if PREFIX_RE.is_match(p) {
        Ok(())
    } else {
        Err(cfg_err(format!(
            "{key} {p:?} must match ^[A-Za-z][A-Za-z0-9_]{{0,31}}$"
        )))
    }
}

impl CompiledConfig {
    fn new(cfg: &FieldsConfig) -> Result<Self> {
        let prefixes = Prefixes {
            ip: cfg.internal_ip_token_prefix.clone(),
            user: cfg.user_token_prefix.clone(),
            host: cfg.host_token_prefix.clone(),
            email: cfg.email_token_prefix.clone(),
            domain: cfg.domain_token_prefix.clone(),
            sid: cfg.sid_token_prefix.clone(),
            mac: cfg.mac_token_prefix.clone(),
        };
        for (p, key) in [
            (&prefixes.ip, "internal_ip_token_prefix"),
            (&prefixes.user, "user_token_prefix"),
            (&prefixes.host, "host_token_prefix"),
            (&prefixes.email, "email_token_prefix"),
            (&prefixes.domain, "domain_token_prefix"),
            (&prefixes.sid, "sid_token_prefix"),
            (&prefixes.mac, "mac_token_prefix"),
        ] {
            check_prefix(p, key)?;
        }

        let mut categories = Vec::with_capacity(cfg.categories.len());
        let mut rules = Vec::new();
        for (idx, cat) in cfg.categories.iter().enumerate() {
            check_prefix(
                &cat.token_prefix,
                &format!("category `{}` token_prefix", cat.name),
            )?;
            let value_pattern =
                match &cat.value_pattern {
                    Some(p) => Some(Regex::new(p).map_err(|e| {
                        cfg_err(format!("category `{}` value_pattern: {e}", cat.name))
                    })?),
                    None => None,
                };
            let kind = if cat.token_prefix == prefixes.user {
                CategoryKind::User
            } else if cat.token_prefix == prefixes.host {
                CategoryKind::Host
            } else {
                CategoryKind::Other
            };
            categories.push(CompiledCategory {
                prefix: cat.token_prefix.clone(),
                kind,
                value_pattern,
            });
            for f in &cat.fields {
                let atoms = atoms_of(f);
                if !atoms.is_empty() {
                    rules.push(FieldRule {
                        atoms,
                        kind: RuleKind::Category(idx),
                    });
                }
            }
        }
        for (list, kind) in [
            (&cfg.preserve_fields, RuleKind::Preserve),
            (&cfg.verbatim_fields, RuleKind::Verbatim),
        ] {
            for f in list {
                let atoms = atoms_of(f);
                if !atoms.is_empty() {
                    rules.push(FieldRule { atoms, kind });
                }
            }
        }
        let mut by_last: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, r) in rules.iter().enumerate() {
            if let Some(last) = r.atoms.last() {
                by_last.entry(last.clone()).or_default().push(i);
            }
        }

        let keep = DEFAULT_KEEP_VALUES
            .iter()
            .map(|s| fold(s))
            .chain(cfg.keep_values.iter().map(|s| fold(s)))
            .filter(|s| !s.is_empty())
            .collect();

        let mut internal_domains = cfg
            .internal_domains
            .iter()
            .map(|d| normalize_domain(d, "internal_domains"))
            .collect::<Result<Vec<_>>>()?;
        let mut internal_suffixes = cfg
            .internal_domain_suffixes
            .iter()
            .map(|d| normalize_domain(d, "internal_domain_suffixes"))
            .collect::<Result<Vec<_>>>()?;
        internal_domains.sort_by_key(|d| std::cmp::Reverse(d.len()));
        internal_domains.dedup();
        internal_suffixes.sort_by_key(|d| std::cmp::Reverse(d.len()));
        internal_suffixes.dedup();

        let fqdn_re = if cfg.scan_internal_domains
            && !(internal_domains.is_empty() && internal_suffixes.is_empty())
        {
            let mut alts: Vec<String> = internal_domains
                .iter()
                .chain(internal_suffixes.iter())
                .map(|d| regex::escape(d))
                .collect();
            alts.sort_by_key(|a| std::cmp::Reverse(a.len()));
            let pattern = format!(
                r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)*(?:{})\b",
                alts.join("|")
            );
            Some(
                Regex::new(&pattern)
                    .map_err(|e| cfg_err(format!("internal domain pattern: {e}")))?,
            )
        } else {
            None
        };

        Ok(Self {
            categories,
            rules,
            by_last,
            keep,
            prefixes,
            scan: ScanFlags {
                user_paths: cfg.scan_user_paths,
                inline_ips: cfg.scan_inline_ips,
                emails: cfg.scan_emails,
                domain_users: cfg.scan_domain_users,
                unc_paths: cfg.scan_unc_paths,
                sids: cfg.scan_sids,
                macs: cfg.scan_macs,
                internal_domains: cfg.scan_internal_domains,
                preserved_fields: cfg.scan_preserved_fields,
                sweep: cfg.sweep_known_values,
            },
            sweep_min_length: cfg.sweep_min_length.max(1),
            internal_domains,
            internal_suffixes,
            fqdn_re,
        })
    }

    /// Parse and compile YAML text.
    pub fn from_yaml_str(text: &str) -> Result<Self> {
        FieldsConfig::from_yaml_str(text)?.compile()
    }

    /// Load and compile a `fields.yaml` file.
    pub fn load(path: &Path) -> Result<Self> {
        FieldsConfig::load(path)?.compile()
    }

    /// The embedded default ([`DEFAULT_FIELDS_YAML`]).
    pub fn builtin() -> Result<Self> {
        Self::from_yaml_str(DEFAULT_FIELDS_YAML)
    }

    /// Number of categories.
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }

    /// Number of configured field rules (category, preserve and verbatim).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// `true` if `value` is blank or listed in `keep_values` / the defaults.
    pub fn is_kept(&self, value: &str) -> bool {
        let f = fold(value);
        f.is_empty() || self.keep.contains(&f)
    }

    /// How a field (underscore, dotted, or nested path joined with `.`) is
    /// handled.
    pub fn classify_field(&self, field: &str) -> FieldDisposition {
        match self.classify_atoms(&atoms_of(field)) {
            FieldClass::Free => FieldDisposition::Free,
            FieldClass::Verbatim => FieldDisposition::Verbatim,
            FieldClass::Preserve => FieldDisposition::Preserve,
            FieldClass::Categories(c) => FieldDisposition::Tokenize(
                c.iter()
                    .filter_map(|i| self.categories.get(*i).map(|c| c.prefix.clone()))
                    .collect(),
            ),
        }
    }

    /// Classify a key path given as atoms.
    ///
    /// A rule matches when its atoms are a suffix of the path (the path may
    /// be longer, e.g. `_source.data.win...`), or when the whole path (at
    /// least two atoms) is a suffix of the rule (a partially nested document
    /// such as `{"eventdata": {"user": ..}}`). The longest match wins; on a
    /// tie verbatim beats preserve beats tokenize, as in the Python proxy.
    pub(crate) fn classify_atoms(&self, path: &[String]) -> FieldClass {
        let Some(last) = path.last() else {
            return FieldClass::Free;
        };
        let Some(cands) = self.by_last.get(last) else {
            return FieldClass::Free;
        };
        let n = path.len();
        let mut best: Option<(usize, bool)> = None;
        let mut hits: Vec<RuleKind> = Vec::new();
        for &ri in cands {
            let Some(rule) = self.rules.get(ri) else {
                continue;
            };
            let m = rule.atoms.len();
            let l = rule
                .atoms
                .iter()
                .rev()
                .zip(path.iter().rev())
                .take_while(|(a, b)| a == b)
                .count();
            let full = l == m;
            let partial = l == n && l >= 2;
            if !(full || partial) {
                continue;
            }
            let score = (l, full);
            match best {
                Some(b) if score < b => {}
                Some(b) if score == b => hits.push(rule.kind),
                _ => {
                    best = Some(score);
                    hits.clear();
                    hits.push(rule.kind);
                }
            }
        }
        if hits.is_empty() {
            return FieldClass::Free;
        }
        if hits.contains(&RuleKind::Verbatim) {
            return FieldClass::Verbatim;
        }
        if hits.contains(&RuleKind::Preserve) {
            return FieldClass::Preserve;
        }
        let mut cats: Vec<usize> = hits
            .iter()
            .filter_map(|k| match k {
                RuleKind::Category(c) => Some(*c),
                _ => None,
            })
            .collect();
        cats.sort_unstable();
        cats.dedup();
        FieldClass::Categories(cats)
    }

    /// Pick the category for `value` among `cats` (file order): the first
    /// whose `value_pattern` matches, else the *last* one without a pattern
    /// (the Python proxy let later categories override earlier ones), else
    /// the field's first category: a value in a field that only has
    /// patterned categories (`data_office365_UserId: "jdoe"`) is still that
    /// field's identifier and must not reach the model as free text.
    pub(crate) fn pick_category(&self, cats: &[usize], value: &str) -> Option<usize> {
        let mut fallback = None;
        for &c in cats {
            let Some(cat) = self.categories.get(c) else {
                continue;
            };
            match &cat.value_pattern {
                Some(re) if re.is_match(value) => return Some(c),
                Some(_) => {}
                None => fallback = Some(c),
            }
        }
        fallback.or_else(|| cats.iter().copied().find(|&c| c < self.categories.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED: &str = DEFAULT_FIELDS_YAML;

    #[test]
    fn builtin_config_compiles() {
        assert!(CompiledConfig::builtin().unwrap().category_count() >= 4);
    }

    /// The embedded copy and the runtime copy that `siem/anon-opensearch-mcp.sh`
    /// passes with `--fields` must not drift. Skipped outside the repository
    /// (a crate downloaded from crates.io has no `siem/` next to it).
    #[test]
    fn embedded_fields_match_siem_copy() {
        let siem = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../siem/anon_proxy/fields.yaml");
        if !siem.parent().is_some_and(std::path::Path::is_dir) {
            return;
        }
        let runtime = std::fs::read_to_string(&siem).unwrap();
        assert!(
            runtime == DEFAULT_FIELDS_YAML,
            "siem/anon_proxy/fields.yaml differs from crates/talon-anon/fields.yaml; \
             edit one and copy it over the other"
        );
    }

    #[test]
    fn static_regexes_compile() {
        assert!(PREFIX_RE.is_match("IP_INT"));
        assert!(DOMAIN_NAME_RE.is_match("corp.example.com"));
    }

    #[test]
    fn atoms() {
        assert_eq!(
            atoms_of("data_win_eventdata_targetUserName"),
            ["data", "win", "eventdata", "targetusername"]
        );
        assert_eq!(
            atoms_of("data.win.eventdata.user"),
            ["data", "win", "eventdata", "user"]
        );
        assert_eq!(atoms_of("_source"), ["_source"]);
        assert_eq!(atoms_of("_id"), ["_id"]);
        assert_eq!(atoms_of("@timestamp"), ["@timestamp"]);
        assert_eq!(atoms_of("__a_b"), ["__a", "b"]);
        assert_eq!(atoms_of("_"), ["_"]);
        assert!(atoms_of("").is_empty());
    }

    #[test]
    fn shipped_file_parses_and_compiles() {
        let cfg = FieldsConfig::from_yaml_str(SHIPPED).unwrap();
        let names: Vec<_> = cfg.categories.iter().map(|c| c.name.as_str()).collect();
        assert!(names.starts_with(&["user", "hostname", "email"]));
        assert_eq!(cfg.internal_ip_token_prefix, "IP_INT");
        assert!(cfg.scan_user_paths && cfg.scan_inline_ips);
        assert!(
            cfg.preserve_fields
                .iter()
                .any(|f| f == "data_win_eventdata_hashes")
        );
        let c = cfg.compile().unwrap();
        assert_eq!(
            c.classify_field("agent_name"),
            FieldDisposition::Tokenize(vec!["HOST".into()])
        );
        assert_eq!(
            c.classify_field("data_win_eventdata_hashes"),
            FieldDisposition::Verbatim
        );
        assert_eq!(
            c.classify_field("data_win_eventdata_commandLine"),
            FieldDisposition::Preserve
        );
        assert_eq!(c.classify_field("full_log"), FieldDisposition::Free);
    }

    #[test]
    fn python_defaults_for_empty_and_minimal_files() {
        let c = FieldsConfig::from_yaml_str("").unwrap();
        assert_eq!(c, FieldsConfig::default());
        let c = FieldsConfig::from_yaml_str("categories:\n  national_id:\n    fields: [ssn]\n")
            .unwrap();
        assert_eq!(c.categories[0].token_prefix, "NATIONAL_ID");
        let c =
            FieldsConfig::from_yaml_str("categories:\n  x: null\npreserve_fields: null\n").unwrap();
        assert!(c.categories[0].fields.is_empty());
    }

    #[test]
    fn yaml_edge_cases() {
        // Several documents are ambiguous: refuse instead of picking one.
        assert!(FieldsConfig::from_yaml_str("keep_values: [a]\n---\nkeep_values: [b]\n").is_err());
        // Only non-negative integers are lengths.
        assert!(FieldsConfig::from_yaml_str("sweep_min_length: -1").is_err());
        assert!(FieldsConfig::from_yaml_str("sweep_min_length: 2.5").is_err());
        assert_eq!(
            FieldsConfig::from_yaml_str("sweep_min_length: 0")
                .unwrap()
                .sweep_min_length,
            1
        );
        // Anchors and aliases resolve to the anchored list.
        let c = FieldsConfig::from_yaml_str(
            "preserve_fields: &shared [rule.id, rule.level]\nverbatim_fields: *shared\n",
        )
        .unwrap();
        assert_eq!(c.verbatim_fields, vec!["rule.id", "rule.level"]);
        // Numbers and booleans in lists are kept as their text.
        let c = FieldsConfig::from_yaml_str("keep_values: [42, 1.5, true]").unwrap();
        assert_eq!(c.keep_values, vec!["42", "1.5", "true"]);
    }

    #[test]
    fn invalid_files_are_rejected() {
        assert!(FieldsConfig::from_yaml_str("- a\n- b\n").is_err());
        assert!(FieldsConfig::from_yaml_str("categories: [a]").is_err());
        assert!(FieldsConfig::from_yaml_str("scan_user_paths: maybe").is_err());
        assert!(FieldsConfig::from_yaml_str("preserve_fields: abc").is_err());
        assert!(FieldsConfig::from_yaml_str(": : :\n  - [").is_err());
        assert!(
            CompiledConfig::from_yaml_str("categories:\n  u:\n    token_prefix: 'bad prefix'\n")
                .is_err()
        );
        assert!(
            CompiledConfig::from_yaml_str("categories:\n  u:\n    value_pattern: '('\n").is_err()
        );
        assert!(CompiledConfig::from_yaml_str("internal_domains: ['not a domain!']").is_err());
    }

    #[test]
    fn classification_matches_nested_dotted_and_flat_paths() {
        let c = CompiledConfig::from_yaml_str(
            "categories:\n  user:\n    token_prefix: USER\n    fields: [data_win_eventdata_user, user_name]\n  hostname:\n    token_prefix: HOST\n    fields: [agent_name]\npreserve_fields: [rule_id, _id, data_win_eventdata_image]\nverbatim_fields: [data_win_eventdata_hashes]\n",
        )
        .unwrap();
        let t = |s: &str| c.classify_field(s);
        let user = FieldDisposition::Tokenize(vec!["USER".into()]);
        assert_eq!(t("data_win_eventdata_user"), user);
        assert_eq!(t("DATA_WIN_EVENTDATA_USER"), user);
        assert_eq!(t("data.win.eventdata.user"), user);
        assert_eq!(t("hits.hits._source.data.win.eventdata.user"), user);
        assert_eq!(t("eventdata.user"), user, "partial nesting");
        assert_eq!(t("user"), FieldDisposition::Free, "bare leaf too generic");
        assert_eq!(t("winlog.user.name"), user);
        assert_eq!(t("rule.id"), FieldDisposition::Preserve);
        assert_eq!(t("_id"), FieldDisposition::Preserve);
        assert_eq!(
            t("agent.id"),
            FieldDisposition::Free,
            "_id must not match *.id"
        );
        assert_eq!(
            t("_source.agent.name"),
            FieldDisposition::Tokenize(vec!["HOST".into()])
        );
        assert_eq!(t("data.win.eventdata.hashes"), FieldDisposition::Verbatim);
        assert_eq!(t("eventdata_image"), FieldDisposition::Preserve);
    }

    #[test]
    fn preserve_wins_over_category_and_value_pattern_picks_category() {
        let c = CompiledConfig::from_yaml_str(
            "categories:\n  user:\n    token_prefix: USER\n    fields: [x_name, both]\n  email:\n    token_prefix: EMAIL\n    value_pattern: '@'\n    fields: [x_name]\npreserve_fields: [both]\n",
        )
        .unwrap();
        assert_eq!(c.classify_field("both"), FieldDisposition::Preserve);
        let FieldClass::Categories(cats) = c.classify_atoms(&atoms_of("x_name")) else {
            panic!("expected categories")
        };
        assert_eq!(c.pick_category(&cats, "jdoe"), Some(0));
        assert_eq!(c.pick_category(&cats, "j@corp.com"), Some(1));
        let only_pattern = CompiledConfig::from_yaml_str(
            "categories:\n  email:\n    token_prefix: EMAIL\n    value_pattern: '@'\n    fields: [mail]\n",
        )
        .unwrap();
        // A field whose only category has a pattern keeps that category for
        // values that don't match it: free text would leak them.
        assert_eq!(only_pattern.pick_category(&[0], "nope"), Some(0));
        assert_eq!(only_pattern.pick_category(&[0], "a@b.c"), Some(0));
    }

    #[test]
    fn keep_values_are_case_insensitive() {
        let c = CompiledConfig::from_yaml_str("keep_values: [SYSTEM, 'NT AUTHORITY']").unwrap();
        assert!(c.is_kept("system"));
        assert!(c.is_kept(" nt authority "));
        assert!(c.is_kept("-"));
        assert!(c.is_kept("   "));
        assert!(!c.is_kept("jdoe"));
    }

    #[test]
    fn category_kinds_follow_prefixes() {
        let c = CompiledConfig::from_yaml_str(
            "categories:\n  a: {token_prefix: USER, fields: [a]}\n  b: {token_prefix: HOST, fields: [b]}\n  c: {token_prefix: NID, fields: [c]}\n",
        )
        .unwrap();
        let kinds: Vec<_> = c.categories.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            [CategoryKind::User, CategoryKind::Host, CategoryKind::Other]
        );
    }
}
