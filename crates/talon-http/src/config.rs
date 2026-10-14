//! Configuration for the CoPilot HTTP channel.
//!
//! Non-secret settings are read with [`EnvFile::get`] (process env wins over
//! `.env`); the API key is a secret and is only ever read from the `.env`
//! file ([`EnvFile::file_value`]), like the TypeScript release did.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `HTTP_API_KEY` (`.env` only) | unset | Shared secret; unset => every request but `/health` is rejected |
//! | `COPILOT_HTTP_PORT` | `3100` | Listen port |
//! | `COPILOT_HTTP_BIND` | `0.0.0.0` | Listen address |
//! | `COPILOT_JID` | `http:copilot` | Base lane JID |
//! | `COPILOT_GROUP_FOLDER` | `copilot` | Group folder the lanes run in |
//! | `COPILOT_HTTP_CORS_ORIGINS` | empty | Comma-separated allowed browser origins (`*` allowed explicitly) |
//! | `COPILOT_HTTP_MAX_BODY_BYTES` | `262144` | Request body limit |
//! | `SESSION_IDLE_HOURS` | `24` | Idle time before a per-user lane is swept |
//! | `COPILOT_INVESTIGATION_DEDUP_MINUTES` | `10` | Repeat-trigger window (`0` disables) |
//! | `COPILOT_HTTP_AUTH_MAX_FAILURES` | `10` | Failed auths per IP before throttling |
//! | `COPILOT_HTTP_AUTH_WINDOW_SECS` | `300` | Throttle window |
//! | `COPILOT_PALACE_TIMEOUT_MS` | `30000` | `palace-call.sh` timeout |
//! | `COPILOT_HTTP_MAX_USER_LANES` | `256` | Cap on in-memory per-user lanes |
//! | `COPILOT_HTTP_MAX_STREAMS` | `256` | Cap on concurrently open SSE streams |

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono_tz::Tz;
use talon_core::config::TalonConfig;
use talon_core::env::EnvFile;
use talon_core::paths::is_valid_group_folder;
use talon_core::{Error, Result};

/// Default listen port (TS: `COPILOT_HTTP_PORT || 3100`).
pub const DEFAULT_PORT: u16 = 3100;
/// Default base lane JID.
pub const DEFAULT_BASE_JID: &str = "http:copilot";
/// Default group folder for every CoPilot lane.
pub const DEFAULT_GROUP_FOLDER: &str = "copilot";
/// Default request body limit (256 KiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;
/// Upper bound accepted for `COPILOT_HTTP_MAX_BODY_BYTES`.
pub const MAX_BODY_BYTES_CEILING: usize = 16 * 1024 * 1024;
/// Keys shorter than this trigger a startup warning.
pub const MIN_RECOMMENDED_KEY_LEN: usize = 16;

/// The shared API key. `Debug` never prints the value.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ApiKey(String);

impl ApiKey {
    /// Wrap a key value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// An unset key (every authenticated request is rejected).
    pub fn unset() -> Self {
        Self(String::new())
    }

    /// Whether a non-blank key is configured.
    pub fn is_configured(&self) -> bool {
        !self.0.trim().is_empty()
    }

    /// The raw key, for the constant-time comparison only. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length of the configured key in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_configured() {
            f.write_str("ApiKey(<redacted>)")
        } else {
            f.write_str("ApiKey(<unset>)")
        }
    }
}

/// Resolved configuration for the HTTP channel.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Listen address.
    pub bind: IpAddr,
    /// Listen port (`0` picks a free port; see `HttpChannel::local_addr`).
    pub port: u16,
    /// Shared secret callers present via `X-Api-Key` or `Authorization: Bearer`.
    pub api_key: ApiKey,
    /// Base lane JID (`http:copilot`).
    pub base_jid: String,
    /// Group folder every lane runs in.
    pub group_folder: String,
    /// Project root (`mempalace/`, `siem/`, ... live below it).
    pub project_root: PathBuf,
    /// `<project_root>/groups`.
    pub groups_dir: PathBuf,
    /// Timezone used for `once` task timestamps and cron evaluation.
    pub timezone: Tz,
    /// Allowed CORS origins (exact match, or `*`). Empty => no CORS headers.
    pub cors_origins: Vec<String>,
    /// Request body limit in bytes.
    pub max_body_bytes: usize,
    /// Idle time after which a per-user lane is swept.
    pub lane_idle: Duration,
    /// How often the idle-lane sweep runs.
    pub lane_sweep_interval: Duration,
    /// Interval between SSE keepalive comments.
    pub sse_keepalive: Duration,
    /// Repeat triggers for the same alert inside this window return the
    /// existing job. Zero disables de-duplication.
    pub dedup_window: Duration,
    /// Failed authentications per IP (inside `auth_window`) before 429s.
    pub auth_max_failures: u32,
    /// Auth-failure throttle window.
    pub auth_window: Duration,
    /// Path of `mempalace/palace-call.sh`.
    pub palace_script: PathBuf,
    /// Timeout for one palace call.
    pub palace_timeout: Duration,
    /// Max bytes of stdout accepted from a palace call.
    pub palace_max_output_bytes: usize,
    /// Max concurrently running palace calls.
    pub palace_max_concurrency: usize,
    /// Cap on in-memory per-user lanes.
    pub max_user_lanes: usize,
    /// Cap on SSE requests queued on a single lane.
    pub max_pending_per_lane: usize,
    /// Cap on concurrently open SSE streams across all lanes.
    pub max_streams: usize,
    /// Seed the (paused) 15-minute alert digest task on connect.
    pub seed_digest_task: bool,
}

impl HttpConfig {
    /// Defaults rooted at `project_root` (API key unset). Intended for tests
    /// and programmatic construction; production uses [`Self::from_talon_config`].
    pub fn new(project_root: impl Into<PathBuf>) -> Self {
        let project_root = project_root.into();
        Self {
            bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: DEFAULT_PORT,
            api_key: ApiKey::unset(),
            base_jid: DEFAULT_BASE_JID.to_string(),
            group_folder: DEFAULT_GROUP_FOLDER.to_string(),
            groups_dir: project_root.join("groups"),
            palace_script: project_root.join("mempalace").join("palace-call.sh"),
            project_root,
            timezone: chrono_tz::UTC,
            cors_origins: Vec::new(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            lane_idle: Duration::from_secs(24 * 3600),
            lane_sweep_interval: Duration::from_secs(15 * 60),
            sse_keepalive: Duration::from_secs(15),
            dedup_window: Duration::from_secs(10 * 60),
            auth_max_failures: 10,
            auth_window: Duration::from_secs(300),
            palace_timeout: Duration::from_secs(30),
            palace_max_output_bytes: 1024 * 1024,
            palace_max_concurrency: 4,
            max_user_lanes: 256,
            max_pending_per_lane: 8,
            max_streams: 256,
            seed_digest_task: true,
        }
    }

    /// Resolve from the host configuration.
    pub fn from_talon_config(cfg: &TalonConfig) -> Result<Self> {
        Self::from_env(&cfg.project_root, &cfg.groups_dir, cfg.timezone, &cfg.env)
    }

    /// Resolve from an [`EnvFile`] (see the module docs for the keys).
    pub fn from_env(
        project_root: &Path,
        groups_dir: &Path,
        timezone: Tz,
        env: &EnvFile,
    ) -> Result<Self> {
        let mut cfg = Self::new(project_root);
        cfg.groups_dir = groups_dir.to_path_buf();
        cfg.timezone = timezone;

        if let Some(port) = env.get("COPILOT_HTTP_PORT") {
            cfg.port = port.trim().parse::<u16>().map_err(|_| {
                Error::Config(format!("COPILOT_HTTP_PORT {port:?} is not a valid port"))
            })?;
        }
        if let Some(bind) = env.get("COPILOT_HTTP_BIND") {
            cfg.bind = bind.trim().parse::<IpAddr>().map_err(|_| {
                Error::Config(format!("COPILOT_HTTP_BIND {bind:?} is not an IP address"))
            })?;
        }
        if let Some(jid) = env.get("COPILOT_JID") {
            let jid = jid.trim().to_string();
            if !is_valid_base_jid(&jid) {
                return Err(Error::Config(format!(
                    "COPILOT_JID {jid:?} is not a valid JID"
                )));
            }
            cfg.base_jid = jid;
        }
        if let Some(folder) = env.get("COPILOT_GROUP_FOLDER") {
            let folder = folder.trim().to_string();
            if !is_valid_group_folder(&folder) {
                return Err(Error::Config(format!(
                    "COPILOT_GROUP_FOLDER {folder:?} is not a valid group folder"
                )));
            }
            cfg.group_folder = folder;
        }
        cfg.api_key = ApiKey::new(env.file_value("HTTP_API_KEY").unwrap_or_default().trim());
        if let Some(origins) = env.get("COPILOT_HTTP_CORS_ORIGINS") {
            cfg.cors_origins = parse_cors_origins(&origins)?;
        }
        cfg.max_body_bytes = (env.get_u64(
            "COPILOT_HTTP_MAX_BODY_BYTES",
            DEFAULT_MAX_BODY_BYTES as u64,
            1024,
        ) as usize)
            .min(MAX_BODY_BYTES_CEILING);
        cfg.lane_idle = Duration::from_secs(env.get_u64("SESSION_IDLE_HOURS", 24, 1) * 3600);
        cfg.dedup_window =
            Duration::from_secs(env.get_u64("COPILOT_INVESTIGATION_DEDUP_MINUTES", 10, 0) * 60);
        cfg.auth_max_failures =
            u32::try_from(env.get_u64("COPILOT_HTTP_AUTH_MAX_FAILURES", 10, 1)).unwrap_or(u32::MAX);
        cfg.auth_window = Duration::from_secs(env.get_u64("COPILOT_HTTP_AUTH_WINDOW_SECS", 300, 1));
        cfg.palace_timeout =
            Duration::from_millis(env.get_u64("COPILOT_PALACE_TIMEOUT_MS", 30_000, 1_000));
        cfg.max_user_lanes = env.get_u64("COPILOT_HTTP_MAX_USER_LANES", 256, 1) as usize;
        cfg.max_streams = env.get_u64("COPILOT_HTTP_MAX_STREAMS", 256, 1) as usize;
        Ok(cfg)
    }

    /// `<groups_dir>/<group_folder>`.
    pub fn group_dir(&self) -> PathBuf {
        self.groups_dir.join(&self.group_folder)
    }

    /// `<groups_dir>/<group_folder>/prompts`.
    pub fn prompts_dir(&self) -> PathBuf {
        self.group_dir().join("prompts")
    }

    /// `<groups_dir>/<group_folder>/evals`.
    pub fn evals_dir(&self) -> PathBuf {
        self.group_dir().join("evals")
    }
}

/// A base JID: 1-128 printable ASCII characters without whitespace, not
/// ending in `:` (sub-lanes are formed by appending `:<suffix>`).
fn is_valid_base_jid(jid: &str) -> bool {
    !jid.is_empty()
        && jid.len() <= 128
        && !jid.ends_with(':')
        && jid.bytes().all(|b| b.is_ascii_graphic())
}

/// Parse `COPILOT_HTTP_CORS_ORIGINS`: comma-separated `http(s)://host[:port]`
/// origins or `*`. Trailing slashes are dropped.
pub fn parse_cors_origins(raw: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let item = item.trim().trim_end_matches('/');
        if item.is_empty() {
            continue;
        }
        let host = item
            .strip_prefix("https://")
            .or_else(|| item.strip_prefix("http://"));
        let valid = item == "*"
            || matches!(host, Some(h) if !h.is_empty()
                && h.len() <= 253
                && h.bytes().all(|b| b.is_ascii_graphic() && b != b'/'));
        if !valid {
            return Err(Error::Config(format!(
                "COPILOT_HTTP_CORS_ORIGINS entry {item:?} is not an origin (scheme://host[:port]) or '*'"
            )));
        }
        out.push(item.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(content: &str) -> EnvFile {
        EnvFile::from_str_content(content)
    }

    #[test]
    fn defaults_match_the_ts_release() {
        let cfg = HttpConfig::new("/opt/talon");
        assert_eq!(cfg.port, 3100);
        assert_eq!(cfg.base_jid, "http:copilot");
        assert_eq!(cfg.group_folder, "copilot");
        assert_eq!(
            cfg.prompts_dir(),
            PathBuf::from("/opt/talon/groups/copilot/prompts")
        );
        assert_eq!(
            cfg.palace_script,
            PathBuf::from("/opt/talon/mempalace/palace-call.sh")
        );
        assert!(!cfg.api_key.is_configured());
        assert_eq!(cfg.dedup_window, Duration::from_secs(600));
        assert_eq!(cfg.sse_keepalive, Duration::from_secs(15));
    }

    #[test]
    fn api_key_comes_from_the_env_file_and_is_never_debug_printed() {
        let cfg = HttpConfig::from_env(
            Path::new("/x"),
            Path::new("/x/groups"),
            chrono_tz::UTC,
            &env("HTTP_API_KEY=super-secret-value-123\n"),
        )
        .unwrap();
        assert!(cfg.api_key.is_configured());
        assert_eq!(cfg.api_key.expose(), "super-secret-value-123");
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("super-secret"), "{dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn blank_key_is_unset() {
        let k = ApiKey::new("   ");
        assert!(!k.is_configured());
        assert_eq!(format!("{k:?}"), "ApiKey(<unset>)");
    }

    #[test]
    fn invalid_settings_are_rejected() {
        let bad = |content: &str| {
            HttpConfig::from_env(
                Path::new("/x"),
                Path::new("/x/g"),
                chrono_tz::UTC,
                &env(content),
            )
        };
        if std::env::var("COPILOT_GROUP_FOLDER").is_err() {
            assert!(bad("COPILOT_GROUP_FOLDER=../etc\n").is_err());
        }
        if std::env::var("COPILOT_HTTP_PORT").is_err() {
            assert!(bad("COPILOT_HTTP_PORT=99999\n").is_err());
        }
        if std::env::var("COPILOT_HTTP_BIND").is_err() {
            assert!(bad("COPILOT_HTTP_BIND=not-an-ip\n").is_err());
        }
        if std::env::var("COPILOT_HTTP_CORS_ORIGINS").is_err() {
            assert!(bad("COPILOT_HTTP_CORS_ORIGINS=javascript:alert(1)\n").is_err());
        }
    }

    #[test]
    fn numeric_settings_apply_with_bounds() {
        if std::env::var("COPILOT_INVESTIGATION_DEDUP_MINUTES").is_ok()
            || std::env::var("COPILOT_HTTP_MAX_BODY_BYTES").is_ok()
        {
            return;
        }
        let cfg = HttpConfig::from_env(
            Path::new("/x"),
            Path::new("/x/g"),
            chrono_tz::UTC,
            &env(
                "COPILOT_INVESTIGATION_DEDUP_MINUTES=0\nCOPILOT_HTTP_MAX_BODY_BYTES=999999999999\n",
            ),
        )
        .unwrap();
        assert_eq!(cfg.dedup_window, Duration::ZERO);
        assert_eq!(cfg.max_body_bytes, MAX_BODY_BYTES_CEILING);
    }

    #[test]
    fn cors_origins_parse() {
        assert_eq!(
            parse_cors_origins(" https://copilot.example.com/ , http://10.0.0.5:5173,*").unwrap(),
            vec![
                "https://copilot.example.com".to_string(),
                "http://10.0.0.5:5173".to_string(),
                "*".to_string()
            ]
        );
        assert!(parse_cors_origins("https://a.example/path").is_err());
        assert!(parse_cors_origins("ftp://a").is_err());
        assert!(parse_cors_origins("").unwrap().is_empty());
    }

    #[test]
    fn base_jid_validation() {
        assert!(is_valid_base_jid("http:copilot"));
        assert!(!is_valid_base_jid("http:copilot:"));
        assert!(!is_valid_base_jid("has space"));
        assert!(!is_valid_base_jid(""));
    }
}
