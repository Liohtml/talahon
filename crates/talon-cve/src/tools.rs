//! The MCP tools of `talahon-cve-mcp`.
//!
//! | Tool | Answers |
//! |---|---|
//! | `lookup_cve` | everything stored about up to 20 CVEs: description, CVSS, CWE, affected products and CPE matches, references, EPSS, KEV |
//! | `search_cves` | CVEs by words, vendor, product, CVSS, EPSS, KEV membership and publication date |
//! | `get_epss_score` | EPSS score and percentile of up to 100 CVEs |
//! | `check_kev` | whether up to 100 CVEs are in CISA KEV, with the entry |
//! | `list_kev` | KEV entries by date added, text and ransomware use |
//! | `data_status` | what the local copy holds and how old it is |
//!
//! The first four carry the names of the corresponding tools of the online
//! CVE server (`cve-mcp-server`), so prompts written for it keep working;
//! the arguments are this server's own (lists instead of one id per call).
//!
//! Every answer is JSON and names the age of the data (`data_as_of`); once
//! the data is older than the configured limit it carries a `warning`. A
//! missing database is an error that says what the operator must run. The
//! tools only read: the database is opened read-only per call and no tool
//! has a side effect.
//!
//! All text in the answers comes from public feeds and is, to the agent,
//! untrusted data like any other MCP result (the agent runtime fences MCP
//! results; nothing here is ever treated as an instruction).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};

use crate::Config;
use crate::model::{clip, is_cve_id};
use crate::store::{Reader, Search, Sort, Status, StoreError};

/// Names of the served tools, in `tools/list` order.
pub const TOOL_NAMES: [&str; 6] = [
    "lookup_cve",
    "search_cves",
    "get_epss_score",
    "check_kev",
    "list_kev",
    "data_status",
];

/// `instructions` of `initialize`.
pub const INSTRUCTIONS: &str = "Offline vulnerability data: a local copy of NVD (CVE records), \
     EPSS (exploitation probability) and CISA KEV (known exploited vulnerabilities), refreshed \
     daily by the host. No network access. Check `data_as_of` / `warning` in the answers: a CVE \
     published after that time is not in the copy.";

/// CVE ids per `lookup_cve` call at most.
pub const MAX_LOOKUP_IDS: usize = 20;
/// CVE ids per `get_epss_score` / `check_kev` call at most.
pub const MAX_SCORE_IDS: usize = 100;
/// Default and largest `limit` of `search_cves`.
pub const SEARCH_LIMITS: (usize, usize) = (10, 50);
/// Default and largest `limit` of `list_kev`.
pub const KEV_LIMITS: (usize, usize) = (20, 100);
/// Characters of a free-text argument at most.
pub const MAX_TEXT_CHARS: usize = 200;

/// Shown when the database file does not exist.
pub const NO_DATABASE: &str = "The local CVE database does not exist yet. Nothing can be looked \
     up. An operator has to run `talahon cve sync` on the Talahon host (and `talahon setup \
     cve-sync` for the daily refresh).";
/// Shown when the file was written by another layout version.
pub const WRONG_SCHEMA: &str = "The local CVE database was written by another Talahon version. \
     An operator has to run `talahon cve sync --full` on the Talahon host.";
/// Shown for any other failure to read the file.
pub const UNREADABLE: &str = "The local CVE database could not be read. An operator should run \
     `talahon doctor` on the Talahon host.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Lookup,
    Search,
    Epss,
    Kev,
    KevList,
    Status,
}

const KINDS: [Kind; 6] = [
    Kind::Lookup,
    Kind::Search,
    Kind::Epss,
    Kind::Kev,
    Kind::KevList,
    Kind::Status,
];

fn ids_schema(max: usize) -> Value {
    json!({
        "type": "array",
        "items": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,19}$"},
        "minItems": 1,
        "maxItems": max,
        "description": format!("CVE ids, e.g. [\"CVE-2021-44228\"]. At most {max}."),
    })
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Lookup => "lookup_cve",
            Self::Search => "search_cves",
            Self::Epss => "get_epss_score",
            Self::Kev => "check_kev",
            Self::KevList => "list_kev",
            Self::Status => "data_status",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Lookup => {
                "Look up CVEs in the local NVD copy: description, CVSS (headline and all \
                 assessments), CWE, affected products and CPE version ranges, references, plus \
                 the EPSS score and the CISA KEV entry. Offline: answers from the host's daily \
                 copy."
            }
            Self::Search => {
                "Search the local NVD copy. Combine any of: words (all must appear in the id, \
                 the description or a product name), vendor and product as written in CPE \
                 (lower case, underscores: vendor \"microsoft\", product \"exchange_server\"), \
                 a minimum CVSS score, a minimum EPSS probability, KEV membership, a \
                 publication date. Returns short hits; use lookup_cve for the details."
            }
            Self::Epss => {
                "EPSS for CVEs: the probability (0-1) that the CVE is exploited in the next 30 \
                 days, and its percentile among all scored CVEs. From the host's daily copy."
            }
            Self::Kev => {
                "Whether CVEs are in the CISA Known Exploited Vulnerabilities catalogue \
                 (exploitation observed in the wild), with date added, required action and \
                 known ransomware use. From the host's daily copy."
            }
            Self::KevList => {
                "List CISA KEV entries, newest first: optionally only those added on or after \
                 a date, matching text in vendor, product or name, or with known ransomware \
                 use."
            }
            Self::Status => {
                "What the local vulnerability data holds: number of CVEs, EPSS scores and KEV \
                 entries, the versions of the sources and when the host last refreshed them."
            }
        }
    }

    fn parameters(self) -> Value {
        match self {
            Self::Lookup => json!({
                "type": "object",
                "properties": {
                    "cve_ids": ids_schema(MAX_LOOKUP_IDS),
                    "include_references": {
                        "type": "boolean",
                        "description": "Include the reference links (default true).",
                    },
                },
                "required": ["cve_ids"],
            }),
            Self::Search => json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Words that must all appear."},
                    "vendor": {"type": "string", "description": "CPE vendor, e.g. \"apache\"."},
                    "product": {"type": "string", "description": "CPE product, e.g. \"log4j\"."},
                    "min_cvss": {"type": "number", "minimum": 0, "maximum": 10},
                    "min_epss": {"type": "number", "minimum": 0, "maximum": 1},
                    "kev_only": {"type": "boolean", "description": "Only CVEs in CISA KEV."},
                    "published_after": {
                        "type": "string",
                        "description": "Only CVEs published on or after this date (YYYY-MM-DD).",
                    },
                    "sort": {
                        "type": "string",
                        "enum": ["published", "cvss", "epss"],
                        "description": "Order: newest first (default), highest CVSS, highest EPSS.",
                    },
                    "limit": {
                        "type": "integer", "minimum": 1, "maximum": SEARCH_LIMITS.1,
                        "description": format!("Hits returned (default {}).", SEARCH_LIMITS.0),
                    },
                },
            }),
            Self::Epss | Self::Kev => json!({
                "type": "object",
                "properties": {"cve_ids": ids_schema(MAX_SCORE_IDS)},
                "required": ["cve_ids"],
            }),
            Self::KevList => json!({
                "type": "object",
                "properties": {
                    "added_after": {
                        "type": "string",
                        "description": "Only entries added on or after this date (YYYY-MM-DD).",
                    },
                    "query": {
                        "type": "string",
                        "description": "Text in vendor, product or vulnerability name.",
                    },
                    "ransomware_only": {
                        "type": "boolean",
                        "description": "Only entries with known ransomware campaign use.",
                    },
                    "limit": {
                        "type": "integer", "minimum": 1, "maximum": KEV_LIMITS.1,
                        "description": format!("Entries returned (default {}).", KEV_LIMITS.0),
                    },
                },
            }),
            Self::Status => json!({"type": "object", "properties": {}}),
        }
    }
}

/// One tool bound to the database.
pub struct CveTool {
    kind: Kind,
    reader: Reader,
    max_age_days: i64,
}

impl std::fmt::Debug for CveTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CveTool")
            .field("name", &self.kind.name())
            .finish()
    }
}

/// All tools, in `tools/list` order.
pub fn all_tools(config: &Config) -> Vec<Arc<dyn Tool>> {
    KINDS
        .iter()
        .map(|&kind| {
            Arc::new(CveTool {
                kind,
                reader: Reader::new(&config.db_path),
                max_age_days: config.max_age_days,
            }) as Arc<dyn Tool>
        })
        .collect()
}

/// The CVE ids of `args`: `cve_ids` (a list) or, as the online server takes
/// it, `cve_id` / `cve_ids` as one string of ids separated by commas or
/// spaces. Trimmed, upper-cased, de-duplicated, each checked against the
/// CVE format.
fn ids_arg(args: &Value, max: usize) -> Result<Vec<String>, String> {
    let raw: Vec<String> = match args.get("cve_ids").or_else(|| args.get("cve_id")) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "cve_ids must be a list of strings".to_string())
            })
            .collect::<Result<_, _>>()?,
        Some(Value::String(s)) => s
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect(),
        Some(_) => return Err("cve_ids must be a list of CVE ids".to_string()),
        None => return Err("cve_ids is required: a list of CVE ids".to_string()),
    };
    let mut ids: Vec<String> = Vec::new();
    for item in raw {
        let id = item.trim().to_ascii_uppercase();
        if !is_cve_id(&id) {
            return Err(format!(
                "not a CVE id: {:?} (expected the form CVE-2021-44228)",
                clip(&id, 40)
            ));
        }
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        return Err("cve_ids is empty".to_string());
    }
    if ids.len() > max {
        return Err(format!(
            "too many CVE ids: {} given, at most {max} per call",
            ids.len()
        ));
    }
    Ok(ids)
}

fn text_arg(args: &Value, name: &str) -> Result<Option<String>, String> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.chars().count() > MAX_TEXT_CHARS {
                return Err(format!("{name} is longer than {MAX_TEXT_CHARS} characters"));
            }
            Ok((!s.is_empty()).then(|| s.to_string()))
        }
        Some(_) => Err(format!("{name} must be a string")),
    }
}

fn bool_arg(args: &Value, name: &str, default: bool) -> Result<bool, String> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{name} must be true or false")),
    }
}

fn number_arg(args: &Value, name: &str, max: f64) -> Result<Option<f64>, String> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_f64() {
            Some(n) if (0.0..=max).contains(&n) => Ok(Some(n)),
            _ => Err(format!("{name} must be a number between 0 and {max}")),
        },
    }
}

fn limit_arg(args: &Value, (default, max): (usize, usize)) -> Result<usize, String> {
    match args.get("limit") {
        None | Some(Value::Null) => Ok(default),
        Some(v) => match v.as_u64() {
            Some(n) if n >= 1 => Ok((n as usize).min(max)),
            _ => Err(format!("limit must be a whole number between 1 and {max}")),
        },
    }
}

/// A `YYYY-MM-DD` date argument (a real calendar date).
fn date_arg(args: &Value, name: &str) -> Result<Option<String>, String> {
    let Some(text) = text_arg(args, name)? else {
        return Ok(None);
    };
    match chrono::NaiveDate::parse_from_str(&text, "%Y-%m-%d") {
        Ok(date) => Ok(Some(date.format("%Y-%m-%d").to_string())),
        Err(_) => Err(format!("{name} must be a date in the form YYYY-MM-DD")),
    }
}

/// A CPE vendor or product name: lower case, spaces as underscores.
fn cpe_name_arg(args: &Value, name: &str) -> Result<Option<String>, String> {
    Ok(text_arg(args, name)?.map(|s| s.to_lowercase().replace(' ', "_")))
}

fn search_arg(args: &Value) -> Result<Search, String> {
    let sort = match text_arg(args, "sort")?.as_deref() {
        None | Some("published") => Sort::Published,
        Some("cvss") => Sort::Cvss,
        Some("epss") => Sort::Epss,
        Some(_) => return Err("sort must be one of: published, cvss, epss".to_string()),
    };
    let search = Search {
        query: text_arg(args, "query")?,
        vendor: cpe_name_arg(args, "vendor")?,
        product: cpe_name_arg(args, "product")?,
        min_cvss: number_arg(args, "min_cvss", 10.0)?,
        min_epss: number_arg(args, "min_epss", 1.0)?,
        kev_only: bool_arg(args, "kev_only", false)?,
        published_after: date_arg(args, "published_after")?,
        sort,
        limit: limit_arg(args, SEARCH_LIMITS)?,
    };
    let has_words = search
        .query
        .as_deref()
        .is_some_and(|q| crate::store::fts_query(q).is_some());
    if !has_words
        && search.vendor.is_none()
        && search.product.is_none()
        && search.min_cvss.is_none()
        && search.min_epss.is_none()
        && !search.kev_only
        && search.published_after.is_none()
    {
        return Err(
            "give at least one of: query, vendor, product, min_cvss, min_epss, \
                    kev_only, published_after"
                .to_string(),
        );
    }
    Ok(search)
}

/// `data_as_of` and, when the copy is old or of unknown age, a `warning`.
fn freshness(status: &Status, max_age_days: i64, now: chrono::DateTime<chrono::Utc>) -> Value {
    let mut out = json!({"data_as_of": status.synced_at});
    match status.age_days(now) {
        Some(days) if days >= max_age_days => {
            out["warning"] = json!(format!(
                "The local copy is {days} days old (the daily refresh on the host is failing). \
                 Newer CVEs, scores and KEV entries are missing."
            ));
        }
        Some(_) => {}
        None => {
            out["warning"] = json!(
                "The local copy does not say when it was last refreshed; treat it as outdated."
            );
        }
    }
    out
}

fn answer(mut body: Value, status: &Status, max_age_days: i64) -> ToolOutput {
    if let (Some(map), Value::Object(fresh)) = (
        body.as_object_mut(),
        freshness(status, max_age_days, chrono::Utc::now()),
    ) {
        map.extend(fresh);
    }
    ToolOutput::ok(serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()))
}

fn store_failure(e: &StoreError) -> ToolOutput {
    match e {
        StoreError::Missing(_) => ToolOutput::err(NO_DATABASE),
        StoreError::Schema { .. } => ToolOutput::err(WRONG_SCHEMA),
        other => {
            // The detail (paths, SQLite text) is for the operator's log.
            tracing::error!(error = %other, "CVE database read failed");
            ToolOutput::err(UNREADABLE)
        }
    }
}

fn run(kind: Kind, reader: &Reader, max_age_days: i64, args: &Value) -> ToolOutput {
    // Arguments first: a bad call is reported as such even without a database.
    enum Call {
        Lookup(Vec<String>, bool),
        Search(Search),
        Epss(Vec<String>),
        Kev(Vec<String>),
        KevList(Option<String>, Option<String>, bool, usize),
        Status,
    }
    let call = (|| -> Result<Call, String> {
        Ok(match kind {
            Kind::Lookup => Call::Lookup(
                ids_arg(args, MAX_LOOKUP_IDS)?,
                bool_arg(args, "include_references", true)?,
            ),
            Kind::Search => Call::Search(search_arg(args)?),
            Kind::Epss => Call::Epss(ids_arg(args, MAX_SCORE_IDS)?),
            Kind::Kev => Call::Kev(ids_arg(args, MAX_SCORE_IDS)?),
            Kind::KevList => Call::KevList(
                date_arg(args, "added_after")?,
                text_arg(args, "query")?,
                bool_arg(args, "ransomware_only", false)?,
                limit_arg(args, KEV_LIMITS)?,
            ),
            Kind::Status => Call::Status,
        })
    })();
    let call = match call {
        Ok(call) => call,
        Err(message) => return ToolOutput::err(format!("Invalid arguments: {message}")),
    };
    let status = match reader.status() {
        Ok(status) => status,
        Err(e) => return store_failure(&e),
    };
    let body = match call {
        Call::Lookup(ids, refs) => reader.lookup(&ids, refs).map(|cves| json!({"cves": cves})),
        Call::Search(search) => reader.search(&search).map(|(hits, more)| {
            json!({
                "count": hits.len(),
                "more_available": more,
                "hits": hits,
            })
        }),
        Call::Epss(ids) => reader.epss(&ids).map(|scores| {
            json!({
                "epss_score_date": status.epss_score_date,
                "scores": scores,
            })
        }),
        Call::Kev(ids) => reader.kev(&ids).map(|results| {
            json!({
                "kev_catalog_version": status.kev_catalog_version,
                "results": results,
            })
        }),
        Call::KevList(after, text, ransomware, limit) => reader
            .kev_list(after.as_deref(), text.as_deref(), ransomware, limit)
            .map(|entries| {
                json!({
                    "kev_catalog_version": status.kev_catalog_version,
                    "count": entries.len(),
                    "entries": entries,
                })
            }),
        Call::Status => Ok(json!({
            "sources": {
                "nvd": {"cves": status.cve_count, "last_applied": status.nvd_synced_at},
                "epss": {
                    "scores": status.epss_count,
                    "score_date": status.epss_score_date,
                    "model_version": status.epss_model_version,
                },
                "cisa_kev": {
                    "entries": status.kev_count,
                    "catalog_version": status.kev_catalog_version,
                    "date_released": status.kev_date_released,
                },
            },
            "age_days": status.age_days(chrono::Utc::now()),
            "stale_after_days": max_age_days,
            "network_access": false,
        })),
    };
    match body {
        Ok(body) => answer(body, &status, max_age_days),
        Err(e) => store_failure(&e),
    }
}

#[async_trait]
impl Tool for CveTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.kind.name().to_string(),
            description: self.kind.description().to_string(),
            parameters: self.kind.parameters(),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        let (kind, reader, max_age_days) = (self.kind, self.reader.clone(), self.max_age_days);
        // SQLite is blocking; keep the protocol loop free.
        match tokio::task::spawn_blocking(move || run(kind, &reader, max_age_days, &args)).await {
            Ok(output) => output,
            Err(e) => {
                tracing::error!(error = %e, "CVE tool task failed");
                ToolOutput::err(UNREADABLE)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_normalised_and_checked() {
        assert_eq!(
            ids_arg(
                &json!({"cve_ids": [" cve-2021-44228 ", "CVE-2021-44228"]}),
                5
            )
            .unwrap(),
            vec!["CVE-2021-44228"]
        );
        assert_eq!(
            ids_arg(&json!({"cve_id": "CVE-2021-44228, CVE-2014-0160"}), 5).unwrap(),
            vec!["CVE-2021-44228", "CVE-2014-0160"]
        );
        for bad in [
            json!({}),
            json!({"cve_ids": []}),
            json!({"cve_ids": [1]}),
            json!({"cve_ids": 7}),
            json!({"cve_ids": ["CVE-2021-44228'; DROP TABLE cve;--"]}),
            json!({"cve_ids": ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"]}),
        ] {
            assert!(ids_arg(&bad, 2).is_err(), "{bad}");
        }
    }

    #[test]
    fn search_needs_a_filter_and_valid_values() {
        assert!(search_arg(&json!({})).is_err());
        assert!(search_arg(&json!({"query": "***"})).is_err());
        assert!(search_arg(&json!({"limit": 5})).is_err());
        assert!(search_arg(&json!({"query": "x", "limit": 0})).is_err());
        assert!(search_arg(&json!({"query": "x", "min_cvss": 11})).is_err());
        assert!(search_arg(&json!({"query": "x", "sort": "random"})).is_err());
        assert!(search_arg(&json!({"query": "x", "published_after": "2024-02-30"})).is_err());
        assert!(search_arg(&json!({"query": "x".repeat(MAX_TEXT_CHARS + 1)})).is_err());
        let s = search_arg(&json!({
            "vendor": "Microsoft", "product": "Exchange Server", "limit": 500, "sort": "epss",
            "published_after": "2024-01-05",
        }))
        .unwrap();
        assert_eq!(s.vendor.as_deref(), Some("microsoft"));
        assert_eq!(s.product.as_deref(), Some("exchange_server"));
        assert_eq!(s.limit, SEARCH_LIMITS.1);
        assert_eq!(s.sort, Sort::Epss);
    }

    #[test]
    fn freshness_warns_when_old_or_unknown() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-17T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let status = |synced: Option<&str>| Status {
            synced_at: synced.map(str::to_string),
            nvd_synced_at: None,
            cve_count: 0,
            epss_count: 0,
            epss_score_date: None,
            epss_model_version: None,
            kev_count: 0,
            kev_catalog_version: None,
            kev_date_released: None,
        };
        let fresh = freshness(&status(Some("2026-11-16T03:00:00Z")), 3, now);
        assert!(fresh.get("warning").is_none());
        let old = freshness(&status(Some("2026-11-10T03:00:00Z")), 3, now);
        assert!(old["warning"].as_str().unwrap().contains("7 days old"));
        let unknown = freshness(&status(None), 3, now);
        assert!(unknown["warning"].as_str().unwrap().contains("outdated"));
    }
}
