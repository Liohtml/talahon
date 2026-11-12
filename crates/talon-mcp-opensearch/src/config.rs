//! Server configuration from the environment.
//!
//! The variable names are those of the Python `opensearch-mcp-server`
//! (`siem/.env.example`), so the same `siem.env` drives either server:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `OPENSEARCH_HOSTS` | Comma-separated base URLs (default `https://localhost:9200`); later hosts are fail-over targets |
//! | `OPENSEARCH_USERNAME` / `OPENSEARCH_PASSWORD` | HTTP basic auth (sent only when both are set) |
//! | `VERIFY_CERTS` | `false` disables TLS certificate verification; **unset means verify** (the Python server defaults to *not* verifying) |
//! | `REQUEST_TIMEOUT` | Whole-request timeout in seconds (default 30, at most 600) |
//! | `OPENSEARCH_PROXY` | `http://` / `https://` proxy for all requests (SOCKS is not supported) |
//! | `OPENSEARCH_CA_CERTS` | PEM file with additional trusted CA certificates (Rust server only) |
//! | `TALON_OPENSEARCH_MAX_RESPONSE_BYTES` | Largest accepted response body (default 8 MiB) |
//!
//! The multi-cluster variables `OPENSEARCH_CLUSTERS` / `OPENSEARCH_CLUSTERS_FILE`
//! are not supported; the server refuses to start when one is set instead of
//! silently querying a different cluster.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

/// Default whole-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for `REQUEST_TIMEOUT`.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(600);
/// Default cap for one response body. A tool result is embedded in a
/// JSON-RPC line, whose escaping can roughly double it; 8 MiB stays below
/// the 16 MiB message limit of `talon-mcp` clients.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Bounds for `TALON_OPENSEARCH_MAX_RESPONSE_BYTES`.
pub const MIN_MAX_RESPONSE_BYTES: usize = 1024;
/// Upper bound for `TALON_OPENSEARCH_MAX_RESPONSE_BYTES`.
pub const MAX_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// A configuration problem. Messages never contain credentials or URLs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A variable has a value that cannot be used.
    #[error("{var}: {reason}")]
    Invalid {
        /// The environment variable.
        var: &'static str,
        /// What is wrong with it (never echoes the value).
        reason: String,
    },
    /// A variable of the Python server that this server does not implement.
    #[error("{var} is not supported by talon-opensearch-mcp; {hint}")]
    Unsupported {
        /// The environment variable.
        var: &'static str,
        /// What to do instead.
        hint: &'static str,
    },
}

fn invalid(var: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        var,
        reason: reason.into(),
    }
}

/// HTTP basic-auth credentials. `Debug` never prints the password.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// User name.
    pub username: String,
    /// Password.
    pub password: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Validated server configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// Base URLs without credentials, query or fragment; never empty.
    pub hosts: Vec<Url>,
    /// Basic-auth credentials, if configured.
    pub credentials: Option<Credentials>,
    /// Verify TLS certificates (default `true`).
    pub verify_certs: bool,
    /// Extra trusted CA certificates (PEM bundle).
    pub ca_certs: Option<PathBuf>,
    /// Whole-request timeout (connect, send, receive the full body).
    pub timeout: Duration,
    /// Largest accepted response body in bytes.
    pub max_response_bytes: usize,
    /// Proxy URL for all requests. May embed proxy credentials: never log it.
    pub proxy: Option<String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("hosts", &self.hosts_for_log())
            .field("credentials", &self.credentials)
            .field("verify_certs", &self.verify_certs)
            .field("ca_certs", &self.ca_certs)
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("proxy", &self.proxy.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Config {
    /// Read the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Read the configuration through `lookup` (tests, embedding).
    /// Empty and whitespace-only values count as unset.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |name: &str| {
            lookup(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        for var in ["OPENSEARCH_CLUSTERS", "OPENSEARCH_CLUSTERS_FILE"] {
            if get(var).is_some() {
                return Err(ConfigError::Unsupported {
                    var,
                    hint: "configure one cluster with OPENSEARCH_HOSTS or unset TALON_OPENSEARCH_MCP \
                           to use the Python server",
                });
            }
        }

        let mut url_credentials = None;
        let mut hosts = Vec::new();
        let raw_hosts =
            get("OPENSEARCH_HOSTS").unwrap_or_else(|| "https://localhost:9200".to_string());
        for raw in raw_hosts
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            let (url, creds) = parse_host(raw)?;
            if url_credentials.is_none() {
                url_credentials = creds;
            }
            hosts.push(url);
        }
        if hosts.is_empty() {
            return Err(invalid("OPENSEARCH_HOSTS", "no host given"));
        }

        // The password is taken verbatim (no trimming): spaces may be part of it.
        let password = lookup("OPENSEARCH_PASSWORD").filter(|p| !p.is_empty());
        let credentials = match (get("OPENSEARCH_USERNAME"), password) {
            (Some(username), Some(password)) => Some(Credentials { username, password }),
            (None, None) => url_credentials,
            // Like the Python server: basic auth needs both halves.
            _ => {
                tracing::warn!(
                    "only one of OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD is set; \
                     sending requests without authentication"
                );
                None
            }
        };

        let verify_certs = match get("VERIFY_CERTS").map(|v| v.to_ascii_lowercase()) {
            None => true,
            Some(v) if v == "true" => true,
            Some(v) if v == "false" => false,
            Some(_) => return Err(invalid("VERIFY_CERTS", "expected 'true' or 'false'")),
        };

        let timeout = match get("REQUEST_TIMEOUT") {
            None => DEFAULT_TIMEOUT,
            Some(v) => {
                let secs: f64 = v
                    .parse()
                    .map_err(|_| invalid("REQUEST_TIMEOUT", "expected a number of seconds"))?;
                if !secs.is_finite() || secs <= 0.0 {
                    return Err(invalid("REQUEST_TIMEOUT", "must be greater than zero"));
                }
                Duration::from_secs_f64(secs.min(MAX_TIMEOUT.as_secs_f64()))
            }
        };

        let max_response_bytes = match get("TALON_OPENSEARCH_MAX_RESPONSE_BYTES") {
            None => DEFAULT_MAX_RESPONSE_BYTES,
            Some(v) => {
                let n: usize = v.parse().map_err(|_| {
                    invalid(
                        "TALON_OPENSEARCH_MAX_RESPONSE_BYTES",
                        "expected a number of bytes",
                    )
                })?;
                if !(MIN_MAX_RESPONSE_BYTES..=MAX_MAX_RESPONSE_BYTES).contains(&n) {
                    return Err(invalid(
                        "TALON_OPENSEARCH_MAX_RESPONSE_BYTES",
                        format!(
                            "must be between {MIN_MAX_RESPONSE_BYTES} and {MAX_MAX_RESPONSE_BYTES}"
                        ),
                    ));
                }
                n
            }
        };

        let proxy = match get("OPENSEARCH_PROXY") {
            None => None,
            Some(p) => {
                let url =
                    Url::parse(&p).map_err(|_| invalid("OPENSEARCH_PROXY", "not a valid URL"))?;
                match url.scheme() {
                    "http" | "https" if url.host_str().is_some() => Some(p),
                    "socks5" | "socks5h" => {
                        return Err(ConfigError::Unsupported {
                            var: "OPENSEARCH_PROXY",
                            hint: "SOCKS proxies need the Python server (unset TALON_OPENSEARCH_MCP); \
                                   http:// and https:// proxies work",
                        });
                    }
                    _ => {
                        return Err(invalid(
                            "OPENSEARCH_PROXY",
                            "expected http://host:port or https://host:port",
                        ));
                    }
                }
            }
        };

        Ok(Self {
            hosts,
            credentials,
            verify_certs,
            ca_certs: get("OPENSEARCH_CA_CERTS").map(PathBuf::from),
            timeout,
            max_response_bytes,
            proxy,
        })
    }

    /// `scheme://host:port` of every host, for logs (no path, no credentials).
    pub fn hosts_for_log(&self) -> Vec<String> {
        self.hosts.iter().map(host_for_log).collect()
    }

    /// True when credentials would travel over plain HTTP.
    pub fn sends_credentials_in_clear(&self) -> bool {
        self.credentials.is_some() && self.hosts.iter().any(|h| h.scheme() == "http")
    }
}

/// `scheme://host[:port]` of `url`, for logs.
pub fn host_for_log(url: &Url) -> String {
    let host = url.host_str().unwrap_or("?");
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

/// Parse one `OPENSEARCH_HOSTS` entry into a credential-free base URL (no
/// trailing slash, query or fragment) and the credentials it embedded.
fn parse_host(raw: &str) -> Result<(Url, Option<Credentials>), ConfigError> {
    const VAR: &str = "OPENSEARCH_HOSTS";
    // Never echo `raw`: it may be `https://user:password@host`.
    let mut url = Url::parse(raw)
        .map_err(|_| invalid(VAR, "entry is not a valid URL (expected https://host:9200)"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid(VAR, "entry must start with https:// or http://"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid(VAR, "entry has no host"));
    }
    let credentials = match (url.username(), url.password()) {
        ("", _) | (_, None) => None,
        (user, Some(pass)) => Some(Credentials {
            username: percent_decode(user),
            password: percent_decode(pass),
        }),
    };
    let stripped = url.set_username("").is_ok() && url.set_password(None).is_ok();
    if !stripped {
        return Err(invalid(VAR, "entry has unusable embedded credentials"));
    }
    url.set_query(None);
    url.set_fragment(None);
    let trimmed = url.path().trim_end_matches('/').to_string();
    url.set_path(&trimmed);
    Ok((url, credentials))
}

/// Decode `%XX` escapes of URL userinfo; invalid escapes stay as written.
fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        char::from(b)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| {
                let hi = hex(*bytes.get(i + 1)?)?;
                let lo = hex(*bytes.get(i + 2)?)?;
                Some(hi << 4 | lo)
            })
            .flatten();
        match escaped {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        Config::from_lookup(move |name| {
            vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
        })
    }

    #[test]
    fn defaults_verify_tls_and_bound_everything() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.hosts_for_log(), ["https://localhost:9200"]);
        assert!(c.verify_certs);
        assert_eq!(c.credentials, None);
        assert_eq!(c.timeout, DEFAULT_TIMEOUT);
        assert_eq!(c.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(c.proxy, None);
        assert_eq!(c.ca_certs, None);
    }

    #[test]
    fn env_example_values_are_accepted() {
        let c = cfg(&[
            ("OPENSEARCH_HOSTS", "https://your-opensearch-host:9200"),
            ("OPENSEARCH_USERNAME", "admin"),
            ("OPENSEARCH_PASSWORD", " p w "),
            ("VERIFY_CERTS", "false"),
        ])
        .unwrap();
        assert!(!c.verify_certs);
        let creds = c.credentials.unwrap();
        assert_eq!(creds.username, "admin");
        assert_eq!(creds.password, " p w ");
    }

    #[test]
    fn verify_certs_is_strict() {
        assert!(cfg(&[("VERIFY_CERTS", "TRUE")]).unwrap().verify_certs);
        assert!(!cfg(&[("VERIFY_CERTS", "False")]).unwrap().verify_certs);
        assert!(cfg(&[("VERIFY_CERTS", "")]).unwrap().verify_certs);
        assert!(matches!(
            cfg(&[("VERIFY_CERTS", "0")]),
            Err(ConfigError::Invalid {
                var: "VERIFY_CERTS",
                ..
            })
        ));
    }

    #[test]
    fn hosts_are_normalized_and_stripped_of_credentials() {
        let c = cfg(&[(
            "OPENSEARCH_HOSTS",
            "https://us%40er:p%3Ass@a.example:9200/prefix/?x=1#f, http://b.example ,",
        )])
        .unwrap();
        assert_eq!(c.hosts.len(), 2);
        assert_eq!(c.hosts[0].as_str(), "https://a.example:9200/prefix");
        assert_eq!(c.hosts[1].as_str(), "http://b.example/");
        let creds = c.credentials.clone().unwrap();
        assert_eq!(creds.username, "us@er");
        assert_eq!(creds.password, "p:ss");
        assert!(c.sends_credentials_in_clear());
        let debug = format!("{c:?}");
        assert!(!debug.contains("p:ss") && !debug.contains("us@er") && !debug.contains("p%3Ass"));
    }

    #[test]
    fn env_credentials_win_over_url_credentials() {
        let c = cfg(&[
            ("OPENSEARCH_HOSTS", "https://u:p@a.example"),
            ("OPENSEARCH_USERNAME", "admin"),
            ("OPENSEARCH_PASSWORD", "secret"),
        ])
        .unwrap();
        assert_eq!(c.credentials.unwrap().username, "admin");
        assert!(
            cfg(&[("OPENSEARCH_USERNAME", "admin")])
                .unwrap()
                .credentials
                .is_none()
        );
    }

    #[test]
    fn bad_hosts_are_rejected_without_echoing_them() {
        for bad in ["ftp://x", "host:9200", "https://", "://"] {
            let err = cfg(&[("OPENSEARCH_HOSTS", bad)]).unwrap_err();
            assert!(matches!(err, ConfigError::Invalid { .. }), "{bad}");
        }
        let err = cfg(&[("OPENSEARCH_HOSTS", "nope://user:hunter2@x")]).unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
        assert!(cfg(&[("OPENSEARCH_HOSTS", " , ")]).is_err());
    }

    #[test]
    fn timeout_and_size_limits_are_bounded() {
        assert_eq!(
            cfg(&[("REQUEST_TIMEOUT", "2.5")]).unwrap().timeout,
            Duration::from_millis(2500)
        );
        assert_eq!(
            cfg(&[("REQUEST_TIMEOUT", "99999")]).unwrap().timeout,
            MAX_TIMEOUT
        );
        for bad in ["0", "-1", "abc", "inf", "NaN"] {
            assert!(cfg(&[("REQUEST_TIMEOUT", bad)]).is_err(), "{bad}");
        }
        assert_eq!(
            cfg(&[("TALON_OPENSEARCH_MAX_RESPONSE_BYTES", "4096")])
                .unwrap()
                .max_response_bytes,
            4096
        );
        for bad in ["1", "x", "99999999999"] {
            assert!(
                cfg(&[("TALON_OPENSEARCH_MAX_RESPONSE_BYTES", bad)]).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn unsupported_python_features_fail_closed() {
        for var in ["OPENSEARCH_CLUSTERS", "OPENSEARCH_CLUSTERS_FILE"] {
            assert!(matches!(
                cfg(&[(var, "{}")]),
                Err(ConfigError::Unsupported { .. })
            ));
        }
        assert!(matches!(
            cfg(&[("OPENSEARCH_PROXY", "socks5h://127.0.0.1:1080")]),
            Err(ConfigError::Unsupported { .. })
        ));
        assert!(cfg(&[("OPENSEARCH_PROXY", "gopher://x")]).is_err());
        let c = cfg(&[("OPENSEARCH_PROXY", "http://u:pw@proxy:3128")]).unwrap();
        assert!(c.proxy.is_some());
        assert!(!format!("{c:?}").contains("pw@"));
    }
}
