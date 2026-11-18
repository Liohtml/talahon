//! Parsers of the three sources and their import into a [`Writer`].
//!
//! | Source | Format | Integrity |
//! |---|---|---|
//! | NVD JSON 2.0 data feeds (`nvdcve-2.0-<name>.json.gz`) | gzip, one JSON object with a `vulnerabilities` array | SHA-256 of the uncompressed JSON from the feed's `.meta` file |
//! | EPSS daily scores (`epss_scores-current.csv.gz`) | gzip, a `#model_version:…,score_date:…` line, a header, `cve,epss,percentile` rows | every row must parse |
//! | CISA KEV (`known_exploited_vulnerabilities.json`) | one JSON object | its `count` must equal the number of entries |
//!
//! Nothing here touches the network: every function reads from an
//! [`std::io::Read`]. The NVD feed is parsed as a stream, one CVE at a time,
//! so a 500 MB feed needs a few megabytes of memory. Every reader is capped
//! (`max_bytes` of *uncompressed* data), so a hostile or broken download
//! cannot fill memory or the disk.

use std::io::{BufRead, BufReader, Read};

use flate2::read::MultiGzDecoder;
use serde::Deserialize;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::model::{
    CpeMatch, CveRecord, EpssScore, KevEntry, MAX_CPE_MATCHES, MAX_DESCRIPTION_CHARS, MAX_METRICS,
    MAX_PRODUCTS, MAX_REFERENCES, Metric, Reference, clip, is_cve_id,
};
use crate::store::{
    META_EPSS_DATE, META_EPSS_MODEL, META_KEV_RELEASED, META_KEV_VERSION, StoreError, Writer,
};

/// A failed import. The working copy of the database must be discarded.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The data could not be read (I/O, gzip).
    #[error("reading {what}: {source}")]
    Read {
        /// Which source.
        what: &'static str,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The data is larger than allowed.
    #[error("{what} is larger than the limit of {limit} bytes")]
    TooLarge {
        /// Which source.
        what: &'static str,
        /// The limit, in uncompressed bytes.
        limit: u64,
    },
    /// The data is not in the expected format.
    #[error("{what} is malformed: {detail}")]
    Malformed {
        /// Which source.
        what: &'static str,
        /// What is wrong (never contains more than a short excerpt).
        detail: String,
    },
    /// The SHA-256 of the data is not the published one.
    #[error("{what}: SHA-256 is {actual}, the source publishes {expected}")]
    Checksum {
        /// Which source.
        what: &'static str,
        /// Published digest.
        expected: String,
        /// Digest of what was downloaded.
        actual: String,
    },
    /// The database refused a write.
    #[error(transparent)]
    Store(#[from] StoreError),
}

fn malformed(what: &'static str, detail: impl Into<String>) -> ImportError {
    ImportError::Malformed {
        what,
        detail: clip(&detail.into(), 200),
    }
}

/// A reader that hashes and counts what passes through and stops at a limit.
struct Guarded<R> {
    inner: R,
    hasher: Sha256,
    seen: u64,
    limit: u64,
    exceeded: bool,
}

impl<R: Read> Guarded<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            seen: 0,
            limit,
            exceeded: false,
        }
    }

    fn digest(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl<R: Read> Read for Guarded<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen += n as u64;
        if self.seen > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other("size limit exceeded"));
        }
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// The `.meta` file NVD publishes beside every feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedMeta {
    /// `lastModifiedDate` of the feed.
    pub last_modified: String,
    /// Size of the uncompressed JSON in bytes.
    pub size: u64,
    /// Size of the `.gz` file in bytes.
    pub gz_size: u64,
    /// SHA-256 of the uncompressed JSON, lower-case hex.
    pub sha256: String,
}

impl FeedMeta {
    /// Parse the `key:value` lines of a `.meta` file.
    ///
    /// # Errors
    /// A missing or malformed `size`, `gzSize` or `sha256`.
    pub fn parse(text: &str) -> Result<Self, ImportError> {
        const WHAT: &str = "NVD feed metadata";
        let mut last_modified = String::new();
        let mut size = None;
        let mut gz_size = None;
        let mut sha256 = None;
        for line in text.lines() {
            let Some((key, value)) = line.trim().split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "lastModifiedDate" => last_modified = clip(value, 64),
                "size" => size = value.parse::<u64>().ok(),
                "gzSize" => gz_size = value.parse::<u64>().ok(),
                "sha256" if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    sha256 = Some(value.to_ascii_lowercase());
                }
                _ => {}
            }
        }
        match (size, gz_size, sha256) {
            (Some(size), Some(gz_size), Some(sha256)) => Ok(Self {
                last_modified,
                size,
                gz_size,
                sha256,
            }),
            _ => Err(malformed(WHAT, "size, gzSize or sha256 is missing")),
        }
    }
}

// --- NVD ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawItem {
    cve: RawCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCve {
    id: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default)]
    vuln_status: Option<String>,
    #[serde(default)]
    descriptions: Vec<RawText>,
    #[serde(default)]
    metrics: serde_json::Map<String, Value>,
    #[serde(default)]
    weaknesses: Vec<RawWeakness>,
    #[serde(default)]
    configurations: Vec<RawConfiguration>,
    #[serde(default)]
    references: Vec<RawReference>,
    #[serde(default)]
    affected: Vec<RawAffected>,
}

#[derive(Debug, Deserialize)]
struct RawText {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct RawWeakness {
    #[serde(default)]
    description: Vec<RawText>,
}

#[derive(Debug, Deserialize)]
struct RawConfiguration {
    #[serde(default)]
    nodes: Vec<RawNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawNode {
    #[serde(default)]
    cpe_match: Vec<RawCpeMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCpeMatch {
    #[serde(default)]
    vulnerable: bool,
    #[serde(default)]
    criteria: String,
    #[serde(default)]
    version_start_including: Option<String>,
    #[serde(default)]
    version_start_excluding: Option<String>,
    #[serde(default)]
    version_end_including: Option<String>,
    #[serde(default)]
    version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawReference {
    #[serde(default)]
    url: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAffected {
    #[serde(default)]
    affected_data: Vec<RawAffectedProduct>,
}

#[derive(Debug, Deserialize)]
struct RawAffectedProduct {
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    product: Option<String>,
}

/// Vendor and product of a CPE 2.3 string (`cpe:2.3:<part>:<vendor>:<product>:…`),
/// lower case, CPE escapes removed. `None` for a wildcard or a string that
/// is not CPE 2.3.
pub fn cpe_vendor_product(criteria: &str) -> Option<(String, String)> {
    let mut fields = Vec::with_capacity(5);
    let mut current = String::new();
    let mut chars = criteria.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ':' => {
                fields.push(std::mem::take(&mut current));
                if fields.len() == 5 {
                    break;
                }
            }
            c => current.push(c),
        }
    }
    if fields.len() < 5 {
        fields.push(current);
    }
    if fields.len() < 5 || fields[0] != "cpe" || fields[1] != "2.3" {
        return None;
    }
    let vendor = fields[3].to_lowercase();
    let product = fields[4].to_lowercase();
    if matches!(vendor.as_str(), "" | "*" | "-") || matches!(product.as_str(), "" | "*" | "-") {
        return None;
    }
    Some((vendor, product))
}

fn text_of(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn metrics_of(raw: &serde_json::Map<String, Value>) -> Vec<Metric> {
    let mut out = Vec::new();
    // Newest scale first, so the cap keeps what matters.
    for key in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ] {
        for entry in raw.get(key).and_then(Value::as_array).into_iter().flatten() {
            let Some(data) = entry.get("cvssData") else {
                continue;
            };
            let Some(score) = data.get("baseScore").and_then(Value::as_f64) else {
                continue;
            };
            if !(0.0..=10.0).contains(&score) {
                continue;
            }
            // CVSS 2 carries the severity beside `cvssData`, not inside.
            let mut severity = text_of(data, "baseSeverity");
            if severity.is_empty() {
                severity = text_of(entry, "baseSeverity");
            }
            out.push(Metric {
                version: clip(&text_of(data, "version"), 8),
                score,
                severity: clip(&severity, 16),
                vector: clip(&text_of(data, "vectorString"), 200),
                source: clip(&text_of(entry, "source"), 100),
                kind: clip(&text_of(entry, "type"), 16),
            });
            if out.len() == MAX_METRICS {
                return out;
            }
        }
    }
    out
}

fn record_of(raw: RawCve) -> CveRecord {
    let description = raw
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .or_else(|| raw.descriptions.first())
        .map(|d| clip(d.value.trim(), MAX_DESCRIPTION_CHARS))
        .unwrap_or_default();

    let mut cwes: Vec<String> = Vec::new();
    for text in raw.weaknesses.iter().flat_map(|w| &w.description) {
        // `NVD-CWE-Other` / `NVD-CWE-noinfo` say nothing.
        if text.value.starts_with("CWE-") && !cwes.contains(&text.value) && cwes.len() < 16 {
            cwes.push(clip(&text.value, 16));
        }
    }

    let mut references: Vec<Reference> = Vec::new();
    for r in raw.references {
        if r.url.is_empty() || references.len() == MAX_REFERENCES {
            continue;
        }
        // NVD repeats a link once per source; merge the tags.
        if let Some(existing) = references.iter_mut().find(|e| e.url == r.url) {
            for tag in r.tags {
                if !existing.tags.contains(&tag) {
                    existing.tags.push(tag);
                }
            }
        } else {
            references.push(Reference {
                url: clip(&r.url, 500),
                tags: r.tags.iter().take(8).map(|t| clip(t, 40)).collect(),
            });
        }
    }

    let mut cpe = Vec::new();
    let mut cpe_total: u32 = 0;
    let mut products: Vec<(String, String)> = Vec::new();
    let mut add_product = |pair: (String, String)| {
        if products.len() < MAX_PRODUCTS && !products.contains(&pair) {
            products.push(pair);
        }
    };
    for m in raw
        .configurations
        .into_iter()
        .flat_map(|c| c.nodes)
        .flat_map(|n| n.cpe_match)
    {
        if !m.vulnerable {
            continue;
        }
        cpe_total = cpe_total.saturating_add(1);
        if let Some(pair) = cpe_vendor_product(&m.criteria) {
            add_product(pair);
        }
        if cpe.len() < MAX_CPE_MATCHES {
            let short = |v: Option<String>| v.map(|v| clip(&v, 64));
            cpe.push(CpeMatch {
                criteria: clip(&m.criteria, 300),
                version_start_including: short(m.version_start_including),
                version_start_excluding: short(m.version_start_excluding),
                version_end_including: short(m.version_end_including),
                version_end_excluding: short(m.version_end_excluding),
            });
        }
    }
    // What the CNA says is affected: all there is before NVD has analysed
    // the CVE and assigned CPE names.
    for p in raw.affected.into_iter().flat_map(|a| a.affected_data) {
        let (Some(vendor), Some(product)) = (p.vendor, p.product) else {
            continue;
        };
        let vendor = clip(vendor.trim(), 100).to_lowercase();
        let product = clip(product.trim(), 100).to_lowercase();
        if matches!(vendor.as_str(), "" | "n/a") || matches!(product.as_str(), "" | "n/a") {
            continue;
        }
        add_product((vendor, product));
    }

    CveRecord {
        id: raw.id,
        published: raw.published.map(|v| clip(&v, 40)),
        modified: raw.last_modified.map(|v| clip(&v, 40)),
        status: raw.vuln_status.map(|v| clip(&v, 40)),
        description,
        metrics: metrics_of(&raw.metrics),
        cwes,
        references,
        cpe,
        cpe_total,
        products,
    }
}

/// Feeds the elements of the top-level `vulnerabilities` array to a
/// callback, one at a time.
struct FeedVisitor<'a, F> {
    each: &'a mut F,
    failure: &'a mut Option<ImportError>,
}

impl<'de, F> Visitor<'de> for FeedVisitor<'_, F>
where
    F: FnMut(CveRecord) -> Result<(), ImportError>,
{
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an NVD feed object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Self { each, failure } = self;
        let mut found = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "vulnerabilities" {
                found = true;
                map.next_value_seed(ItemsSeed {
                    each: &mut *each,
                    failure: &mut *failure,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        if found {
            Ok(())
        } else {
            Err(serde::de::Error::missing_field("vulnerabilities"))
        }
    }
}

struct ItemsSeed<'a, F> {
    each: &'a mut F,
    failure: &'a mut Option<ImportError>,
}

impl<'de, F> DeserializeSeed<'de> for ItemsSeed<'_, F>
where
    F: FnMut(CveRecord) -> Result<(), ImportError>,
{
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, F> Visitor<'de> for ItemsSeed<'_, F>
where
    F: FnMut(CveRecord) -> Result<(), ImportError>,
{
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an array of vulnerabilities")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(item) = seq.next_element::<RawItem>()? {
            if !is_cve_id(&item.cve.id) {
                return Err(serde::de::Error::custom("an entry's id is not a CVE id"));
            }
            if let Err(e) = (self.each)(record_of(item.cve)) {
                *self.failure = Some(e);
                return Err(serde::de::Error::custom("import stopped"));
            }
        }
        Ok(())
    }
}

/// Parse an uncompressed NVD feed from `json`, calling `each` per CVE.
/// Returns the SHA-256 of the bytes read (lower-case hex).
///
/// # Errors
/// Unreadable, oversized or malformed data, or the first error of `each`.
pub fn parse_nvd_feed(
    json: impl Read,
    max_bytes: u64,
    mut each: impl FnMut(CveRecord) -> Result<(), ImportError>,
) -> Result<String, ImportError> {
    const WHAT: &str = "NVD feed";
    let mut guarded = Guarded::new(json, max_bytes);
    let mut failure = None;
    let parsed = {
        let mut de = serde_json::Deserializer::from_reader(BufReader::new(&mut guarded));
        de.deserialize_map(FeedVisitor {
            each: &mut each,
            failure: &mut failure,
        })
        // Reads to the end of the input, so the digest covers all of it.
        .and_then(|()| de.end())
    };
    if let Some(e) = failure {
        return Err(e);
    }
    if guarded.exceeded {
        return Err(ImportError::TooLarge {
            what: WHAT,
            limit: max_bytes,
        });
    }
    match parsed {
        Ok(()) => Ok(guarded.digest()),
        Err(e) if e.is_io() => Err(ImportError::Read {
            what: WHAT,
            source: e.into(),
        }),
        Err(e) => Err(malformed(WHAT, e.to_string())),
    }
}

/// What an NVD feed import did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvdImport {
    /// CVEs in the feed.
    pub seen: u64,
    /// CVEs inserted or updated (the rest was already stored and not older).
    pub written: u64,
    /// SHA-256 of the uncompressed feed, lower-case hex.
    pub sha256: String,
}

/// Import one gzip-compressed NVD feed in a single transaction. With
/// `expected_sha256` (from the feed's `.meta`), a feed with another digest
/// is refused and nothing of it is kept.
///
/// # Errors
/// See [`ImportError`]. After an error the working copy must be discarded.
pub fn import_nvd_feed(
    writer: &mut Writer,
    gz: impl Read,
    expected_sha256: Option<&str>,
    max_bytes: u64,
) -> Result<NvdImport, ImportError> {
    writer.batch(|batch| {
        let mut seen = 0;
        let mut written = 0;
        let sha256 = parse_nvd_feed(MultiGzDecoder::new(gz), max_bytes, |rec| {
            seen += 1;
            if batch.upsert_cve(&rec)? {
                written += 1;
            }
            Ok(())
        })?;
        if let Some(expected) = expected_sha256
            && !expected.eq_ignore_ascii_case(&sha256)
        {
            return Err(ImportError::Checksum {
                what: "NVD feed",
                expected: expected.to_ascii_lowercase(),
                actual: sha256,
            });
        }
        Ok(NvdImport {
            seen,
            written,
            sha256,
        })
    })
}

// --- EPSS --------------------------------------------------------------------

/// What an EPSS import did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpssImport {
    /// Scores stored.
    pub rows: u64,
    /// `score_date` of the file.
    pub score_date: Option<String>,
    /// `model_version` of the file.
    pub model_version: Option<String>,
}

fn parse_epss_line(line: &str) -> Result<EpssScore, ImportError> {
    const WHAT: &str = "EPSS scores";
    let mut fields = line.split(',');
    let (Some(id), Some(score), Some(percentile), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(malformed(WHAT, format!("unexpected row: {line}")));
    };
    let number = |text: &str| {
        text.trim()
            .parse::<f64>()
            .ok()
            .filter(|v| (0.0..=1.0).contains(v))
    };
    match (is_cve_id(id), number(score), number(percentile)) {
        (true, Some(score), Some(percentile)) => Ok(EpssScore {
            cve_id: id.to_string(),
            score,
            percentile,
        }),
        _ => Err(malformed(WHAT, format!("unexpected row: {line}"))),
    }
}

/// Replace the EPSS scores with those of the gzip-compressed daily file.
///
/// # Errors
/// See [`ImportError`]. After an error the working copy must be discarded.
pub fn import_epss(
    writer: &mut Writer,
    gz: impl Read,
    max_bytes: u64,
) -> Result<EpssImport, ImportError> {
    const WHAT: &str = "EPSS scores";
    let mut guarded = Guarded::new(MultiGzDecoder::new(gz), max_bytes);
    let mut score_date = None;
    let mut model_version = None;
    let mut header_seen = false;
    let stored = {
        let mut lines = BufReader::new(&mut guarded).lines();
        let scores = std::iter::from_fn(|| {
            loop {
                let line = match lines.next()? {
                    Ok(line) => line,
                    Err(source) => return Some(Err(ImportError::Read { what: WHAT, source })),
                };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some(comment) = line.strip_prefix('#') {
                    for part in comment.split(',') {
                        match part.split_once(':') {
                            Some(("model_version", v)) => model_version = Some(clip(v, 40)),
                            Some(("score_date", v)) => score_date = Some(clip(v, 40)),
                            _ => {}
                        }
                    }
                    continue;
                }
                if !header_seen {
                    header_seen = true;
                    if line != "cve,epss,percentile" {
                        return Some(Err(malformed(WHAT, format!("unexpected header: {line}"))));
                    }
                    continue;
                }
                return Some(parse_epss_line(line));
            }
        });
        writer.batch(|batch| batch.replace_epss(scores))
    };
    let rows = match stored {
        Ok(rows) => rows,
        Err(_) if guarded.exceeded => {
            return Err(ImportError::TooLarge {
                what: WHAT,
                limit: max_bytes,
            });
        }
        Err(e) => return Err(e),
    };
    if rows == 0 {
        return Err(malformed(WHAT, "the file holds no scores"));
    }
    if let Some(date) = &score_date {
        writer.set_meta(META_EPSS_DATE, date)?;
    }
    if let Some(model) = &model_version {
        writer.set_meta(META_EPSS_MODEL, model)?;
    }
    Ok(EpssImport {
        rows,
        score_date,
        model_version,
    })
}

// --- KEV ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawKev {
    #[serde(default)]
    catalog_version: Option<String>,
    #[serde(default)]
    date_released: Option<String>,
    #[serde(default)]
    count: Option<u64>,
    vulnerabilities: Vec<RawKevEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawKevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    vulnerability_name: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    short_description: String,
    #[serde(default)]
    required_action: String,
    #[serde(default)]
    due_date: String,
    #[serde(default)]
    known_ransomware_campaign_use: String,
    #[serde(default)]
    notes: String,
}

/// What a KEV import did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevImport {
    /// Entries stored.
    pub rows: u64,
    /// `catalogVersion` of the catalogue.
    pub catalog_version: Option<String>,
    /// `dateReleased` of the catalogue.
    pub date_released: Option<String>,
}

/// Replace the KEV catalogue with the one in `json`.
///
/// # Errors
/// See [`ImportError`]. After an error the working copy must be discarded.
pub fn import_kev(
    writer: &mut Writer,
    json: impl Read,
    max_bytes: u64,
) -> Result<KevImport, ImportError> {
    const WHAT: &str = "KEV catalogue";
    let mut guarded = Guarded::new(json, max_bytes);
    let mut body = Vec::new();
    if let Err(source) = guarded.read_to_end(&mut body) {
        return Err(if guarded.exceeded {
            ImportError::TooLarge {
                what: WHAT,
                limit: max_bytes,
            }
        } else {
            ImportError::Read { what: WHAT, source }
        });
    }
    let raw: RawKev = serde_json::from_slice(&body).map_err(|e| malformed(WHAT, e.to_string()))?;
    if raw.vulnerabilities.is_empty() {
        return Err(malformed(WHAT, "the catalogue is empty"));
    }
    if let Some(count) = raw.count
        && count != raw.vulnerabilities.len() as u64
    {
        return Err(malformed(
            WHAT,
            format!(
                "count says {count}, the file holds {} entries",
                raw.vulnerabilities.len()
            ),
        ));
    }
    let mut entries = Vec::with_capacity(raw.vulnerabilities.len());
    for e in raw.vulnerabilities {
        if !is_cve_id(&e.cve_id) {
            return Err(malformed(WHAT, "an entry's cveID is not a CVE id"));
        }
        entries.push(KevEntry {
            cve_id: e.cve_id,
            vendor: clip(&e.vendor_project, 200),
            product: clip(&e.product, 200),
            name: clip(&e.vulnerability_name, 300),
            date_added: clip(&e.date_added, 10),
            due_date: clip(&e.due_date, 10),
            description: clip(&e.short_description, 2_000),
            required_action: clip(&e.required_action, 2_000),
            ransomware: clip(&e.known_ransomware_campaign_use, 16),
            notes: clip(&e.notes, 1_000),
        });
    }
    let rows = writer.batch(|batch| batch.replace_kev(&entries))?;
    let catalog_version = raw.catalog_version.map(|v| clip(&v, 40));
    let date_released = raw.date_released.map(|v| clip(&v, 40));
    if let Some(v) = &catalog_version {
        writer.set_meta(META_KEV_VERSION, v)?;
    }
    if let Some(v) = &date_released {
        writer.set_meta(META_KEV_RELEASED, v)?;
    }
    Ok(KevImport {
        rows,
        catalog_version,
        date_released,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpe_fields() {
        assert_eq!(
            cpe_vendor_product("cpe:2.3:o:barracuda:load_balancer_adc_firmware:*:*:*:*:*:*:*:*"),
            Some(("barracuda".into(), "load_balancer_adc_firmware".into()))
        );
        // An escaped colon stays inside its field.
        assert_eq!(
            cpe_vendor_product("cpe:2.3:a:Acme:foo\\:bar:1.0:*:*:*:*:*:*:*"),
            Some(("acme".into(), "foo:bar".into()))
        );
        assert_eq!(cpe_vendor_product("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"), None);
        assert_eq!(cpe_vendor_product("cpe:/a:acme:foo"), None);
        assert_eq!(cpe_vendor_product("nonsense"), None);
    }

    #[test]
    fn feed_meta() {
        let meta = FeedMeta::parse(
            "lastModifiedDate:2026-11-17T08:00:07-05:00\r\nsize:73152584\r\nzipSize:6113924\r\n\
             gzSize:6113780\r\nsha256:504AF551EBD87E2C7050A2EBF96783FEC6C7AA325409D19A390BF389B42445E6\r\n",
        )
        .unwrap();
        assert_eq!(meta.size, 73_152_584);
        assert_eq!(meta.gz_size, 6_113_780);
        assert_eq!(
            meta.sha256,
            "504af551ebd87e2c7050a2ebf96783fec6c7aa325409d19a390bf389b42445e6"
        );
        assert_eq!(meta.last_modified, "2026-11-17T08:00:07-05:00");
        assert!(FeedMeta::parse("size:1\ngzSize:1\nsha256:zz\n").is_err());
        assert!(FeedMeta::parse("<html>blocked</html>").is_err());
    }

    #[test]
    fn epss_lines() {
        let s = parse_epss_line("CVE-1999-0001,0.04753,0.92032").unwrap();
        assert_eq!(s.cve_id, "CVE-1999-0001");
        assert!((s.score - 0.04753).abs() < 1e-9);
        for bad in [
            "CVE-1999-0001,1.5,0.5",
            "CVE-1999-0001,0.5",
            "x,0.1,0.1",
            "CVE-1999-0001,0.1,0.1,0.1",
            "CVE-1999-0001,NaN,0.1",
        ] {
            assert!(parse_epss_line(bad).is_err(), "{bad}");
        }
    }
}
