//! `talahon cve sync` and `talahon cve status`: the host side of the offline
//! vulnerability data (`talon-cve`).
//!
//! The agent containers have no route to the internet. Once a day the host
//! downloads three public sources, builds one SQLite file from them and puts
//! it where the containers mount it read-only:
//!
//! | Source | URL | Host |
//! |---|---|---|
//! | NVD CVE data feeds (JSON 2.0) | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<name>.json.gz` and `.meta` | `nvd.nist.gov` |
//! | EPSS daily scores | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | `epss.empiricalsecurity.com` |
//! | CISA KEV catalogue | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | `www.cisa.gov` |
//!
//! ## What a run does
//! 1. Takes the lock `<dir>/.cve-sync.lock` (a second run exits at once).
//! 2. Copies the current database to a working file beside it (or starts an
//!    empty one).
//! 3. **NVD.** A *full* pass asks for the `.meta` of every yearly feed (2002
//!    to this year) and downloads the feeds whose SHA-256 differs from the
//!    one imported last time, the first time all of them. An *incremental*
//!    pass downloads only the `modified` feed (every CVE published or changed
//!    in the last eight days). Incremental is used when NVD data was applied
//!    less than [`INCREMENTAL_MAX_AGE_DAYS`] days ago; `--full` forces a full
//!    pass. Every feed is checked against the SHA-256 of its `.meta`.
//! 4. **EPSS** and **KEV** are replaced as a whole.
//! 5. Checks the working file and renames it over the database.
//!
//! Any failure (a source unreachable, a checksum that does not match, a file
//! over its size limit, a full disk) ends the run with exit code 1 and
//! leaves the database exactly as it was: readers only ever see a complete
//! file.
//!
//! ## What a download may do
//! Only `https` (the test hook aside), only the three hosts above, a
//! redirect only to the same host (EPSS's `-current` name redirects to the
//! dated file), a size limit per file and a deadline per request. Nothing
//! from the downloads is executed or interpreted beyond the three parsers.
//!
//! No credential is sent: the feeds are public. The requests carry no
//! information about this installation beyond its IP address and a
//! `talahon/<version>` user agent.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow, bail};
use chrono::{DateTime, Datelike, Utc};
use talon_core::config::TalonConfig;
use talon_cve::import::{FeedMeta, import_epss, import_kev, import_nvd_feed};
use talon_cve::store::{
    META_NVD_FEED_PREFIX, META_NVD_SYNCED_AT, META_SYNCED_AT, Reader, StoreError, Table, Writer,
};
use talon_cve::{DB_PATH_ENV, DEFAULT_MAX_AGE_DAYS, MAX_AGE_ENV, default_db_path};
use talon_setup::StatusBlock;

use crate::cli::CveSyncArgs;

/// Hosts a sync may contact. Everything else is refused before a request is
/// made, and a redirect to another host is not followed.
pub const ALLOWED_HOSTS: [&str; 3] = ["nvd.nist.gov", "epss.empiricalsecurity.com", "www.cisa.gov"];
/// Directory of the NVD data feeds.
pub const NVD_FEED_BASE: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
/// The EPSS scores of today.
pub const EPSS_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
/// The CISA KEV catalogue.
pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// The oldest yearly NVD feed (it also holds the CVEs of 1999–2001).
pub const NVD_FIRST_YEAR: i32 = 2002;
/// NVD data older than this is refreshed with a full pass: the `modified`
/// feed covers eight days.
pub const INCREMENTAL_MAX_AGE_DAYS: i64 = 7;

/// Size limits of the downloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// A `.meta` file.
    pub meta: u64,
    /// A compressed NVD feed.
    pub nvd_gz: u64,
    /// An uncompressed NVD feed.
    pub nvd_json: u64,
    /// The compressed EPSS file.
    pub epss_gz: u64,
    /// The uncompressed EPSS file.
    pub epss_csv: u64,
    /// The KEV catalogue.
    pub kev: u64,
}

impl Default for Limits {
    /// Several times today's sizes (the largest yearly feed is about 47 MB
    /// compressed and 560 MB of JSON, EPSS 3 MB / 12 MB, KEV 2 MB).
    fn default() -> Self {
        Self {
            meta: 4 * 1024,
            nvd_gz: 512 * 1024 * 1024,
            nvd_json: 6 * 1024 * 1024 * 1024,
            epss_gz: 64 * 1024 * 1024,
            epss_csv: 512 * 1024 * 1024,
            kev: 64 * 1024 * 1024,
        }
    }
}

/// Where a sync downloads from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sources {
    /// Directory of the NVD feeds (no trailing slash).
    pub nvd_base: String,
    /// URL of the EPSS file.
    pub epss_url: String,
    /// URL of the KEV catalogue.
    pub kev_url: String,
    /// Hosts that may be contacted.
    pub allowed_hosts: Vec<String>,
    /// Refuse anything but `https`. Always true outside tests.
    pub https_only: bool,
    /// Years of the yearly NVD feeds.
    pub years: Vec<i32>,
    /// Size limits.
    pub limits: Limits,
    /// Deadline of one request, connect to last byte.
    pub request_timeout: Duration,
}

impl Sources {
    /// The public sources, with the yearly feeds up to the year of `now`.
    pub fn official(now: DateTime<Utc>) -> Self {
        Self {
            nvd_base: NVD_FEED_BASE.to_string(),
            epss_url: EPSS_URL.to_string(),
            kev_url: KEV_URL.to_string(),
            allowed_hosts: ALLOWED_HOSTS.iter().map(|h| (*h).to_string()).collect(),
            https_only: true,
            years: (NVD_FIRST_YEAR..=now.year().max(NVD_FIRST_YEAR)).collect(),
            limits: Limits::default(),
            request_timeout: Duration::from_secs(30 * 60),
        }
    }
}

/// `url` parsed, if a sync may contact it: `https` (unless the test hook
/// allows `http`), a host on the list, no credentials in the URL.
///
/// # Errors
/// The URL is not acceptable; the message names the reason, never more than
/// the host.
pub fn ensure_allowed(url: &str, sources: &Sources) -> anyhow::Result<reqwest::Url> {
    let parsed = reqwest::Url::parse(url).map_err(|_| anyhow!("not a URL"))?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if parsed.scheme() != "https" && (sources.https_only || parsed.scheme() != "http") {
        bail!("refusing {host}: only https is allowed");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("refusing {host}: a URL with credentials");
    }
    if !sources.allowed_hosts.iter().any(|h| h == &host) {
        bail!("refusing {host}: not one of the hosts a CVE sync may contact");
    }
    Ok(parsed)
}

/// Downloads with the rules of the module docs.
#[derive(Debug, Clone)]
struct Fetcher {
    client: reqwest::Client,
    sources: Sources,
}

impl Fetcher {
    fn new(sources: Sources) -> anyhow::Result<Self> {
        let allowed = sources.allowed_hosts.clone();
        let https_only = sources.https_only;
        // A redirect is followed only to the host it came from (and never
        // down to http): the list above is the complete set of hosts.
        let policy = reqwest::redirect::Policy::custom(move |attempt| {
            let same_host = attempt
                .previous()
                .last()
                .is_some_and(|prev| prev.host_str() == attempt.url().host_str());
            let host = attempt.url().host_str().unwrap_or_default();
            let scheme_ok = attempt.url().scheme() == "https" || !https_only;
            if attempt.previous().len() > 3 {
                attempt.error("too many redirects")
            } else if same_host && scheme_ok && allowed.iter().any(|h| h == host) {
                attempt.follow()
            } else {
                attempt.error("redirect to another host refused")
            }
        });
        let client = reqwest::Client::builder()
            .https_only(https_only)
            .redirect(policy)
            .connect_timeout(Duration::from_secs(20))
            .timeout(sources.request_timeout)
            .user_agent(concat!(
                "talahon/",
                env!("CARGO_PKG_VERSION"),
                " (cve sync)"
            ))
            .build()
            .context("building the HTTP client")?;
        Ok(Self { client, sources })
    }

    /// GET `url`; `Ok(None)` for a 404.
    async fn get(&self, url: &str, what: &str) -> anyhow::Result<Option<reqwest::Response>> {
        let parsed = ensure_allowed(url, &self.sources).with_context(|| what.to_string())?;
        let host = parsed.host_str().unwrap_or_default().to_string();
        let response = self
            .client
            .get(parsed)
            .send()
            .await
            // reqwest's message names the URL; keep to the host and cause.
            .map_err(|e| anyhow!("{what}: request to {host} failed ({})", describe(&e)))?;
        match response.status() {
            s if s.is_success() => Ok(Some(response)),
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            s => bail!("{what}: {host} answered {s}"),
        }
    }

    /// The body of `url` as text, at most `limit` bytes; `None` for a 404.
    async fn text(&self, url: &str, what: &str, limit: u64) -> anyhow::Result<Option<String>> {
        let Some(mut response) = self.get(url, what).await? else {
            return Ok(None);
        };
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| anyhow!("{what}: download failed ({})", describe(&e)))?
        {
            if (body.len() + chunk.len()) as u64 > limit {
                bail!("{what}: larger than the limit of {limit} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Some(String::from_utf8_lossy(&body).into_owned()))
    }

    /// Download `url` into `dest` (truncated first), at most `limit` bytes.
    /// Returns the number of bytes written.
    async fn download(
        &self,
        url: &str,
        what: &str,
        limit: u64,
        dest: &Path,
    ) -> anyhow::Result<u64> {
        let Some(mut response) = self.get(url, what).await? else {
            bail!("{what}: not found (404)");
        };
        if response.content_length().is_some_and(|n| n > limit) {
            bail!("{what}: larger than the limit of {limit} bytes");
        }
        let mut file =
            File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
        let mut written: u64 = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| anyhow!("{what}: download failed ({})", describe(&e)))?
        {
            written += chunk.len() as u64;
            if written > limit {
                bail!("{what}: larger than the limit of {limit} bytes");
            }
            file.write_all(&chunk)
                .with_context(|| format!("writing {}", dest.display()))?;
        }
        file.flush()
            .with_context(|| format!("writing {}", dest.display()))?;
        Ok(written)
    }
}

/// What went wrong with a request, without its URL.
fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".to_string()
    } else if e.is_redirect() {
        "redirect to another host refused".to_string()
    } else if e.is_connect() {
        "could not connect".to_string()
    } else {
        "transfer error".to_string()
    }
}

/// The database path: `TALAHON_CVE_DB` (environment or `.env`), else
/// `<project root>/cve-mcp/data/cve.sqlite`. A relative path is relative to
/// the project root.
pub fn db_path(config: &TalonConfig) -> PathBuf {
    match config.env.get(DB_PATH_ENV).filter(|v| !v.trim().is_empty()) {
        Some(path) => config.project_root.join(path.trim()),
        None => default_db_path(&config.project_root),
    }
}

/// Age in days from which the data counts as stale (`TALAHON_CVE_MAX_AGE_DAYS`).
pub fn max_age_days(config: &TalonConfig) -> i64 {
    config
        .env
        .get(MAX_AGE_ENV)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(DEFAULT_MAX_AGE_DAYS)
}

/// What a sync did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// `full` or `incremental`.
    pub mode: &'static str,
    /// NVD feeds downloaded and imported.
    pub nvd_feeds_imported: usize,
    /// NVD feeds whose checksum had not changed.
    pub nvd_feeds_unchanged: usize,
    /// CVEs inserted or updated.
    pub cves_written: u64,
    /// CVEs in the database.
    pub cve_count: u64,
    /// EPSS scores in the database.
    pub epss_count: u64,
    /// KEV entries in the database.
    pub kev_count: u64,
    /// Bytes downloaded.
    pub downloaded_bytes: u64,
    /// Size of the database file.
    pub db_bytes: u64,
}

/// Removes the working files when a run ends, however it ends.
struct Workspace {
    work_db: PathBuf,
    download: PathBuf,
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.work_db);
        let _ = std::fs::remove_file(&self.download);
    }
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Whether the existing database can be the base of this run, and when NVD
/// data was last applied to it.
fn existing_state(db: &Path) -> (bool, Option<DateTime<Utc>>) {
    match Reader::new(db).status() {
        Ok(status) => {
            let applied = status
                .nvd_synced_at
                .as_deref()
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc));
            (true, applied)
        }
        Err(StoreError::Missing(_)) => (false, None),
        Err(e) => {
            tracing::warn!(error = %e, "the existing CVE database is unusable; rebuilding it");
            (false, None)
        }
    }
}

/// Run one sync of the database at `db` from `sources`.
///
/// # Errors
/// Anything that prevented a complete, verified new database. The file at
/// `db` is then unchanged.
pub async fn sync(
    db: &Path,
    sources: Sources,
    force_full: bool,
    now: DateTime<Utc>,
) -> anyhow::Result<SyncReport> {
    let dir = db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("the database path has no directory"))?
        .to_path_buf();
    let name = db
        .file_name()
        .ok_or_else(|| anyhow!("the database path has no file name"))?
        .to_string_lossy()
        .into_owned();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    // The container reads the file as another user: public data, world-readable.
    set_mode(&dir, 0o755).with_context(|| format!("setting the mode of {}", dir.display()))?;

    let lock_path = dir.join(".cve-sync.lock");
    let lock =
        File::create(&lock_path).with_context(|| format!("creating {}", lock_path.display()))?;
    if rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
        bail!("another CVE sync is running (lock {})", lock_path.display());
    }

    let workspace = Workspace {
        work_db: dir.join(format!(".{name}.sync")),
        download: dir.join(format!(".{name}.download")),
    };
    let _ = std::fs::remove_file(&workspace.work_db);
    let _ = std::fs::remove_file(&workspace.download);

    let (usable, nvd_applied) = existing_state(db);
    if usable {
        std::fs::copy(db, &workspace.work_db)
            .with_context(|| format!("copying {} to a working file", db.display()))?;
        set_mode(&workspace.work_db, 0o600).context("setting the mode of the working file")?;
    }
    let incremental = usable
        && !force_full
        && nvd_applied.is_some_and(|t| (now - t).num_days() < INCREMENTAL_MAX_AGE_DAYS);

    let fetcher = Fetcher::new(sources.clone())?;
    let limits = sources.limits;
    let mut writer = Writer::open(&workspace.work_db).map_err(|e| anyhow!("{e}"))?;
    let mut report = SyncReport {
        mode: if incremental { "incremental" } else { "full" },
        nvd_feeds_imported: 0,
        nvd_feeds_unchanged: 0,
        cves_written: 0,
        cve_count: 0,
        epss_count: 0,
        kev_count: 0,
        downloaded_bytes: 0,
        db_bytes: 0,
    };

    // --- NVD ---
    let newest_year = sources.years.iter().copied().max();
    let feeds: Vec<String> = if incremental {
        vec!["modified".to_string()]
    } else {
        sources.years.iter().map(i32::to_string).collect()
    };
    for feed in &feeds {
        let what = format!("NVD feed {feed}");
        let base = format!("{}/nvdcve-2.0-{feed}", sources.nvd_base);
        let meta_text = fetcher
            .text(&format!("{base}.meta"), &what, limits.meta)
            .await?;
        let Some(meta_text) = meta_text else {
            // In the first days of January the new year's feed may not
            // exist yet; every other feed must.
            if !incremental && newest_year.is_some_and(|y| y.to_string() == *feed) {
                tracing::info!(feed = %feed, "feed not published yet; skipped");
                continue;
            }
            bail!("{what}: its .meta file was not found (404)");
        };
        let meta = FeedMeta::parse(&meta_text).map_err(|e| anyhow!("{what}: {e}"))?;
        let key = format!("{META_NVD_FEED_PREFIX}{feed}");
        if writer.meta(&key).map_err(|e| anyhow!("{e}"))?.as_deref() == Some(&meta.sha256) {
            report.nvd_feeds_unchanged += 1;
            continue;
        }
        if meta.gz_size > limits.nvd_gz || meta.size > limits.nvd_json {
            bail!("{what}: larger than the size limit");
        }
        let started = Instant::now();
        let bytes = fetcher
            .download(
                &format!("{base}.json.gz"),
                &what,
                limits.nvd_gz,
                &workspace.download,
            )
            .await?;
        report.downloaded_bytes += bytes;
        let file = File::open(&workspace.download).context("opening the downloaded feed")?;
        let sha = meta.sha256.clone();
        let (returned, outcome) = tokio::task::spawn_blocking(move || {
            let outcome = import_nvd_feed(&mut writer, file, Some(&sha), limits.nvd_json);
            (writer, outcome)
        })
        .await
        .context("the import task failed")?;
        writer = returned;
        let outcome = outcome.map_err(|e| anyhow!("{what}: {e}"))?;
        writer
            .set_meta(&key, &outcome.sha256)
            .map_err(|e| anyhow!("{e}"))?;
        report.nvd_feeds_imported += 1;
        report.cves_written += outcome.written;
        tracing::info!(
            feed = %feed, cves = outcome.seen, written = outcome.written, bytes,
            seconds = started.elapsed().as_secs(), "NVD feed imported"
        );
    }
    writer
        .set_meta(META_NVD_SYNCED_AT, &now.to_rfc3339())
        .map_err(|e| anyhow!("{e}"))?;

    // --- EPSS ---
    report.downloaded_bytes += fetcher
        .download(
            &sources.epss_url,
            "EPSS scores",
            limits.epss_gz,
            &workspace.download,
        )
        .await?;
    let file = File::open(&workspace.download).context("opening the downloaded EPSS file")?;
    let (returned, outcome) = tokio::task::spawn_blocking(move || {
        let outcome = import_epss(&mut writer, file, limits.epss_csv);
        (writer, outcome)
    })
    .await
    .context("the import task failed")?;
    writer = returned;
    let epss = outcome.map_err(|e| anyhow!("{e}"))?;
    tracing::info!(scores = epss.rows, "EPSS scores imported");

    // --- KEV ---
    report.downloaded_bytes += fetcher
        .download(
            &sources.kev_url,
            "KEV catalogue",
            limits.kev,
            &workspace.download,
        )
        .await?;
    let file = File::open(&workspace.download).context("opening the downloaded KEV catalogue")?;
    let (returned, outcome) = tokio::task::spawn_blocking(move || {
        let outcome = import_kev(&mut writer, file, limits.kev);
        (writer, outcome)
    })
    .await
    .context("the import task failed")?;
    writer = returned;
    let kev = outcome.map_err(|e| anyhow!("{e}"))?;
    tracing::info!(entries = kev.rows, "KEV catalogue imported");

    // --- finish and swap ---
    writer
        .set_meta(META_SYNCED_AT, &now.to_rfc3339())
        .map_err(|e| anyhow!("{e}"))?;
    report.cve_count = writer.count(Table::Cve).map_err(|e| anyhow!("{e}"))?;
    report.epss_count = writer.count(Table::Epss).map_err(|e| anyhow!("{e}"))?;
    report.kev_count = writer.count(Table::Kev).map_err(|e| anyhow!("{e}"))?;
    if report.cve_count == 0 {
        bail!("the new database holds no CVE; keeping the old one");
    }
    tokio::task::spawn_blocking(move || writer.finish())
        .await
        .context("the check of the new database failed")?
        .map_err(|e| anyhow!("the new database failed its check: {e}"))?;

    set_mode(&workspace.work_db, 0o644).context("setting the mode of the new database")?;
    let work = File::open(&workspace.work_db).context("opening the new database")?;
    work.sync_all().context("flushing the new database")?;
    report.db_bytes = work.metadata().map(|m| m.len()).unwrap_or(0);
    std::fs::rename(&workspace.work_db, db)
        .with_context(|| format!("moving the new database to {}", db.display()))?;
    if let Ok(d) = File::open(&dir) {
        let _ = d.sync_all();
    }
    drop(workspace);
    drop(lock);
    Ok(report)
}

/// `talahon cve sync`. Exit code 0 when the database was refreshed.
pub async fn sync_cmd(config: &TalonConfig, args: &CveSyncArgs) -> i32 {
    let db = db_path(config);
    let now = Utc::now();
    let started = Instant::now();
    let mut block = StatusBlock::new("CVE_SYNC").field("DATABASE", db.display());
    match sync(&db, Sources::official(now), args.full, now).await {
        Ok(report) => {
            block.set("STATUS", "success");
            block.set("MODE", report.mode);
            block.set("NVD_FEEDS_IMPORTED", report.nvd_feeds_imported);
            block.set("NVD_FEEDS_UNCHANGED", report.nvd_feeds_unchanged);
            block.set("CVES_WRITTEN", report.cves_written);
            block.set("CVES", report.cve_count);
            block.set("EPSS_SCORES", report.epss_count);
            block.set("KEV_ENTRIES", report.kev_count);
            block.set("DOWNLOADED_BYTES", report.downloaded_bytes);
            block.set("DATABASE_BYTES", report.db_bytes);
            block.set("SECONDS", started.elapsed().as_secs());
            println!("{block}");
            0
        }
        Err(e) => {
            block.set("STATUS", "failed");
            block.set("ERROR", format!("{e:#}").replace('\n', " "));
            block.set("NOTE", "the existing database was left unchanged");
            println!("{block}");
            1
        }
    }
}

/// The `CHECK_CVE` block and whether the data is usable and fresh.
pub fn status_block(
    config: &TalonConfig,
    now: DateTime<Utc>,
) -> (StatusBlock, Option<&'static str>) {
    let db = db_path(config);
    let limit = max_age_days(config);
    let mut block = StatusBlock::new("CHECK_CVE").field("DATABASE", db.display());
    match Reader::new(&db).status() {
        Ok(status) => {
            block.set("CVES", status.cve_count);
            block.set("EPSS_SCORES", status.epss_count);
            block.set("KEV_ENTRIES", status.kev_count);
            block.set("SYNCED_AT", status.synced_at.as_deref().unwrap_or("never"));
            let age = status.age_days(now);
            block.set(
                "AGE_DAYS",
                age.map_or_else(|| "unknown".to_string(), |d| d.to_string()),
            );
            block.set("STALE_AFTER_DAYS", limit);
            match age {
                Some(days) if days < limit => {
                    block.set("STATUS", "ok");
                    (block, None)
                }
                _ => {
                    block.set("STATUS", "stale");
                    (block, Some("cve_db_stale"))
                }
            }
        }
        Err(StoreError::Missing(_)) => {
            block.set("STATUS", "missing");
            (block, Some("cve_db_missing"))
        }
        Err(e) => {
            tracing::debug!(error = %e, "CVE database unreadable");
            block.set("STATUS", "unreadable");
            (block, Some("cve_db_unreadable"))
        }
    }
}

/// `talahon cve status`. Exit code 0 when the database exists and is fresh.
pub fn status_cmd(config: &TalonConfig) -> i32 {
    let (block, issue) = status_block(config, Utc::now());
    println!("{block}");
    i32::from(issue.is_some())
}

/// Whether the CVE wrapper is set to the offline server
/// (`TALAHON_CVE_MCP=offline` in `cve-mcp/.env`).
pub fn offline_selected(project_root: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(project_root.join("cve-mcp").join(".env")) else {
        return false;
    };
    let env = talon_core::env::EnvFile::from_str_content(&content);
    env.file_value("TALAHON_CVE_MCP")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("offline"))
}

#[cfg(test)]
mod tests {

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(data))
    }

    fn feed(entries: &[(&str, &str, &str)]) -> Vec<u8> {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|(id, modified, text)| {
                serde_json::json!({"cve": {
                    "id": id, "published": "2025-01-01T00:00:00.000", "lastModified": modified,
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": text}],
                    "metrics": {}, "references": [],
                }})
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({"format": "NVD_CVE", "vulnerabilities": items}))
            .unwrap()
    }

    fn meta(json: &[u8], gz_len: usize) -> String {
        format!(
            "lastModifiedDate:2026-11-17T03:00:00-05:00\r\nsize:{}\r\nzipSize:{gz_len}\r\ngzSize:{gz_len}\r\nsha256:{}\r\n",
            json.len(),
            sha256_hex(json).to_uppercase()
        )
    }

    const EPSS: &str = "#model_version:v1,score_date:2026-11-17T00:00:00Z\ncve,epss,percentile\nCVE-2025-0001,0.5,0.9\n";
    const KEV: &str = r#"{"catalogVersion":"2026.11.13","dateReleased":"2026-11-13T00:00:00Z","count":1,
        "vulnerabilities":[{"cveID":"CVE-2025-0001","vendorProject":"Acme","product":"Thing",
        "vulnerabilityName":"Acme Thing Flaw","dateAdded":"2025-02-01","shortDescription":"x",
        "requiredAction":"y","dueDate":"2025-02-22","knownRansomwareCampaignUse":"Unknown","notes":""}]}"#;

    async fn mount_feed(server: &MockServer, name: &str, json: &[u8]) {
        let body = gz(json);
        Mock::given(method("GET"))
            .and(path(format!("/nvd/nvdcve-2.0-{name}.meta")))
            .respond_with(ResponseTemplate::new(200).set_body_string(meta(json, body.len())))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/nvd/nvdcve-2.0-{name}.json.gz")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(server)
            .await;
    }

    async fn mount_epss_kev(server: &MockServer) {
        // As the real source: the `-current` name redirects to a dated file
        // on the same host.
        Mock::given(method("GET"))
            .and(path("/epss/current.csv.gz"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "dated.csv.gz"))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/epss/dated.csv.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gz(EPSS.as_bytes())))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(KEV))
            .mount(server)
            .await;
    }

    fn sources(server: &MockServer) -> Sources {
        Sources {
            nvd_base: format!("{}/nvd", server.uri()),
            epss_url: format!("{}/epss/current.csv.gz", server.uri()),
            kev_url: format!("{}/kev.json", server.uri()),
            allowed_hosts: vec!["127.0.0.1".to_string()],
            https_only: false,
            years: vec![2025, 2026],
            limits: Limits::default(),
            request_timeout: Duration::from_secs(20),
        }
    }

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    async fn requests_for(server: &MockServer, suffix: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().ends_with(suffix))
            .count()
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "cve.sqlite" && n != ".cve-sync.lock")
            .collect();
        names.sort();
        names
    }

    #[test]
    fn only_listed_https_hosts_are_contacted() {
        let official = Sources::official(at("2026-11-17T00:00:00Z"));
        assert_eq!(official.years.first(), Some(&2002));
        assert_eq!(official.years.last(), Some(&2026));
        for url in [NVD_FEED_BASE, EPSS_URL, KEV_URL] {
            assert!(ensure_allowed(url, &official).is_ok(), "{url}");
        }
        for url in [
            "http://nvd.nist.gov/feeds/x",
            "https://nvd.nist.gov.evil.example/x",
            "https://evil.example/nvd.nist.gov",
            "https://user:pw@nvd.nist.gov/x",
            "https://raw.githubusercontent.com/x",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(ensure_allowed(url, &official).is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn full_sync_then_incremental() {
        let server = MockServer::start().await;
        let y2025 = feed(&[("CVE-2025-0001", "2025-03-01T00:00:00.000", "first text")]);
        let y2026 = feed(&[("CVE-2026-0001", "2026-03-01T00:00:00.000", "second text")]);
        let modified = feed(&[
            ("CVE-2025-0001", "2026-11-17T00:00:00.000", "updated text"),
            ("CVE-2026-0002", "2026-11-17T00:00:00.000", "new text"),
        ]);
        mount_feed(&server, "2025", &y2025).await;
        mount_feed(&server, "2026", &y2026).await;
        mount_feed(&server, "modified", &modified).await;
        mount_epss_kev(&server).await;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("data").join("cve.sqlite");

        let first = sync(&db, sources(&server), false, at("2026-11-17T03:00:00Z"))
            .await
            .unwrap();
        assert_eq!(first.mode, "full");
        assert_eq!(
            (first.nvd_feeds_imported, first.nvd_feeds_unchanged),
            (2, 0)
        );
        assert_eq!(
            (first.cve_count, first.epss_count, first.kev_count),
            (2, 1, 1)
        );
        assert!(first.db_bytes > 0 && first.downloaded_bytes > 0);
        assert_eq!(requests_for(&server, "modified.json.gz").await, 0);
        assert!(
            leftovers(db.parent().unwrap()).is_empty(),
            "{:?}",
            leftovers(db.parent().unwrap())
        );
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
        let status = Reader::new(&db).status().unwrap();
        assert_eq!(
            status.synced_at.as_deref(),
            Some("2026-11-17T03:00:00+00:00")
        );

        // The next day: only the modified feed is downloaded.
        let second = sync(&db, sources(&server), false, at("2026-11-18T03:00:00Z"))
            .await
            .unwrap();
        assert_eq!(second.mode, "incremental");
        assert_eq!(
            (
                second.nvd_feeds_imported,
                second.cves_written,
                second.cve_count
            ),
            (1, 2, 3)
        );
        assert_eq!(requests_for(&server, "2025.json.gz").await, 1);
        assert_eq!(requests_for(&server, "modified.json.gz").await, 1);
        let found = Reader::new(&db)
            .lookup(&["CVE-2025-0001".to_string()], true)
            .unwrap();
        assert_eq!(found[0]["description"], "updated text");

        // Same modified feed again: nothing to import, EPSS/KEV still refreshed.
        let third = sync(&db, sources(&server), false, at("2026-11-19T03:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            (third.nvd_feeds_imported, third.nvd_feeds_unchanged),
            (0, 1)
        );
        assert_eq!(requests_for(&server, "modified.json.gz").await, 1);

        // After a gap longer than the modified feed covers: a full pass,
        // which downloads only the years whose checksum changed (none).
        let late = sync(&db, sources(&server), false, at("2026-12-10T03:00:00Z"))
            .await
            .unwrap();
        assert_eq!(late.mode, "full");
        assert_eq!((late.nvd_feeds_imported, late.nvd_feeds_unchanged), (0, 2));
        assert_eq!(requests_for(&server, "2025.json.gz").await, 1);
        // --full does the same on demand.
        let forced = sync(&db, sources(&server), true, at("2026-12-11T03:00:00Z"))
            .await
            .unwrap();
        assert_eq!(forced.mode, "full");
    }

    /// A database from a first sync, its bytes, and the server it came from.
    async fn synced(dir: &Path) -> (MockServer, PathBuf, Vec<u8>) {
        let server = MockServer::start().await;
        mount_feed(
            &server,
            "2025",
            &feed(&[("CVE-2025-0001", "2025-03-01T00:00:00.000", "a")]),
        )
        .await;
        mount_feed(
            &server,
            "2026",
            &feed(&[("CVE-2026-0001", "2026-03-01T00:00:00.000", "b")]),
        )
        .await;
        mount_epss_kev(&server).await;
        let db = dir.join("cve.sqlite");
        sync(&db, sources(&server), false, at("2026-11-01T03:00:00Z"))
            .await
            .unwrap();
        let bytes = std::fs::read(&db).unwrap();
        (server, db, bytes)
    }

    async fn assert_failed_run_changes_nothing(
        server: &MockServer,
        db: &Path,
        before: &[u8],
        sources: Sources,
        expect: &str,
    ) {
        let err = sync(db, sources, true, at("2026-11-17T03:00:00Z"))
            .await
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains(expect), "{text}");
        assert_eq!(std::fs::read(db).unwrap(), before, "the database changed");
        assert!(leftovers(db.parent().unwrap()).is_empty());
        // Messages never carry the full URL.
        assert!(!text.contains(&server.uri()), "{text}");
    }

    #[tokio::test]
    async fn wrong_checksum_leaves_the_old_database() {
        let dir = tempfile::tempdir().unwrap();
        let (server, db, before) = synced(dir.path()).await;
        server.reset().await;
        // 2025 now serves other content than its .meta announces.
        let announced = feed(&[("CVE-2025-0001", "2026-01-01T00:00:00.000", "announced")]);
        let served = gz(&feed(&[(
            "CVE-2025-0001",
            "2026-01-01T00:00:00.000",
            "tampered",
        )]));
        Mock::given(method("GET"))
            .and(path("/nvd/nvdcve-2.0-2025.meta"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(meta(&announced, served.len())),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/nvd/nvdcve-2.0-2025.json.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(served))
            .mount(&server)
            .await;
        mount_feed(
            &server,
            "2026",
            &feed(&[("CVE-2026-0001", "2026-03-01T00:00:00.000", "b")]),
        )
        .await;
        mount_epss_kev(&server).await;
        assert_failed_run_changes_nothing(&server, &db, &before, sources(&server), "SHA-256").await;
    }

    #[tokio::test]
    async fn a_failing_source_leaves_the_old_database() {
        let dir = tempfile::tempdir().unwrap();
        let (server, db, before) = synced(dir.path()).await;
        server.reset().await;
        mount_feed(
            &server,
            "2025",
            &feed(&[("CVE-2025-0001", "2026-01-01T00:00:00.000", "new")]),
        )
        .await;
        mount_feed(
            &server,
            "2026",
            &feed(&[("CVE-2026-0001", "2026-03-01T00:00:00.000", "b")]),
        )
        .await;
        // EPSS is fine, KEV answers 503.
        Mock::given(method("GET"))
            .and(path("/epss/current.csv.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gz(EPSS.as_bytes())))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        assert_failed_run_changes_nothing(&server, &db, &before, sources(&server), "KEV catalogue")
            .await;

        // A feed that is neither gzip nor JSON (an error page with status 200).
        server.reset().await;
        let page = b"<html>Access denied</html>";
        Mock::given(method("GET"))
            .and(path("/nvd/nvdcve-2.0-2025.meta"))
            .respond_with(ResponseTemplate::new(200).set_body_string(meta(page, page.len())))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/nvd/nvdcve-2.0-2025.json.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(page.to_vec()))
            .mount(&server)
            .await;
        assert_failed_run_changes_nothing(&server, &db, &before, sources(&server), "NVD feed 2025")
            .await;

        // A .meta that is an error page.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/nvd/nvdcve-2.0-2025.meta"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>blocked</html>"))
            .mount(&server)
            .await;
        assert_failed_run_changes_nothing(&server, &db, &before, sources(&server), "metadata")
            .await;
    }

    #[tokio::test]
    async fn redirect_to_another_host_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (server, db, before) = synced(dir.path()).await;
        let other = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gz(EPSS.as_bytes())))
            .mount(&other)
            .await;
        server.reset().await;
        mount_feed(
            &server,
            "2025",
            &feed(&[("CVE-2025-0001", "2025-03-01T00:00:00.000", "a")]),
        )
        .await;
        mount_feed(
            &server,
            "2026",
            &feed(&[("CVE-2026-0001", "2026-03-01T00:00:00.000", "b")]),
        )
        .await;
        // "localhost" is another host name than the allowed 127.0.0.1.
        let elsewhere = format!("http://localhost:{}/epss.csv.gz", other.address().port());
        Mock::given(method("GET"))
            .and(path("/epss/current.csv.gz"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", elsewhere.as_str()))
            .mount(&server)
            .await;
        assert_failed_run_changes_nothing(
            &server,
            &db,
            &before,
            sources(&server),
            "redirect to another host refused",
        )
        .await;
        assert!(
            other.received_requests().await.unwrap().is_empty(),
            "the other host was contacted"
        );
    }

    #[tokio::test]
    async fn oversized_downloads_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (server, db, before) = synced(dir.path()).await;
        server.reset().await;
        mount_feed(
            &server,
            "2025",
            &feed(&[(
                "CVE-2025-0001",
                "2026-01-01T00:00:00.000",
                &"x".repeat(5_000),
            )]),
        )
        .await;
        mount_feed(
            &server,
            "2026",
            &feed(&[("CVE-2026-0001", "2026-03-01T00:00:00.000", "b")]),
        )
        .await;
        mount_epss_kev(&server).await;
        // The compressed feed is over the limit.
        let mut small = sources(&server);
        small.limits.nvd_gz = 50;
        assert_failed_run_changes_nothing(&server, &db, &before, small, "size limit").await;
        // The decompressed feed is over the limit.
        let mut small = sources(&server);
        small.limits.nvd_json = 1_000;
        assert_failed_run_changes_nothing(&server, &db, &before, small, "limit").await;
        // KEV over the limit.
        let mut small = sources(&server);
        small.limits.kev = 10;
        assert_failed_run_changes_nothing(&server, &db, &before, small, "larger than the limit")
            .await;
    }

    #[tokio::test]
    async fn host_not_on_the_list_is_never_contacted() {
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        mount_epss_kev(&server).await;
        let mut s = sources(&server);
        s.allowed_hosts = vec!["nvd.nist.gov".to_string()];
        let err = sync(
            &dir.path().join("cve.sqlite"),
            s,
            false,
            at("2026-11-17T03:00:00Z"),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("not one of the hosts"),
            "{err:#}"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(!dir.path().join("cve.sqlite").exists());
    }

    #[tokio::test]
    async fn a_second_sync_is_refused_while_one_runs() {
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        let lock = File::create(dir.path().join(".cve-sync.lock")).unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let err = sync(
            &dir.path().join("cve.sqlite"),
            sources(&server),
            false,
            at("2026-11-17T03:00:00Z"),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("another CVE sync is running"),
            "{err:#}"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_missing_newest_year_is_tolerated_but_not_an_older_one() {
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        mount_feed(
            &server,
            "2025",
            &feed(&[("CVE-2025-0001", "2025-03-01T00:00:00.000", "a")]),
        )
        .await;
        mount_epss_kev(&server).await;
        // 2026 answers 404 (wiremock's default): early January.
        let report = sync(
            &dir.path().join("cve.sqlite"),
            sources(&server),
            false,
            at("2026-01-01T03:00:00Z"),
        )
        .await
        .unwrap();
        assert_eq!(report.nvd_feeds_imported, 1);
        // The other way round is an error.
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        mount_feed(
            &server,
            "2026",
            &feed(&[("CVE-2026-0001", "2026-03-01T00:00:00.000", "b")]),
        )
        .await;
        mount_epss_kev(&server).await;
        let err = sync(
            &dir.path().join("cve.sqlite"),
            sources(&server),
            false,
            at("2026-11-17T03:00:00Z"),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("NVD feed 2025"), "{err:#}");
    }

    #[test]
    fn status_block_and_offline_selection() {
        let dir = tempfile::tempdir().unwrap();
        let config =
            TalonConfig::from_env(dir.path(), talon_core::env::EnvFile::from_str_content(""));
        assert_eq!(db_path(&config), dir.path().join("cve-mcp/data/cve.sqlite"));
        let (block, issue) = status_block(&config, at("2026-11-17T03:00:00Z"));
        assert_eq!(issue, Some("cve_db_missing"));
        assert_eq!(block.get("STATUS"), Some("missing"));

        assert!(!offline_selected(dir.path()));
        std::fs::create_dir_all(dir.path().join("cve-mcp")).unwrap();
        let mut env = File::create(dir.path().join("cve-mcp/.env")).unwrap();
        writeln!(
            env,
            "# keys\nNVD_API_KEY=\nTALAHON_CVE_MCP=offline  # no network"
        )
        .unwrap();
        assert!(offline_selected(dir.path()));
    }
}
