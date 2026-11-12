//! Server configuration from the environment.
//!
//! The variable names are those of the Python `mysql-mcp-server` and of
//! `mysql/mysql-mcp.sh`, so the same `mysql.env` drives either server:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `MYSQL_HOST` / `MYSQL_PORT` | Server address (default `localhost:3306`), always TCP |
//! | `MYSQL_USER` | User name (required) |
//! | `MYSQL_PASSWORD` or `MYSQL_PASS` | Password (required; may be empty) |
//! | `MYSQL_DATABASE` or `MYSQL_DB` | Default database (optional) |
//! | `MYSQL_SSL_MODE` | `PREFERRED` (default), `DISABLED`, `REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY`; see [`TlsMode`] |
//! | `MYSQL_SSL_CA` | PEM file with the CA certificate(s) to trust instead of the built-in roots |
//! | `MYSQL_SSL_HOSTNAME` | Name the server certificate must be valid for, when it differs from `MYSQL_HOST` (Rust server only) |
//! | `MYSQL_CONNECT_TIMEOUT` | Seconds for connect + TLS + login (default 10, at most 300) |
//! | `MYSQL_SQL_MODE` | Session `sql_mode` (default `TRADITIONAL`; set but empty keeps the server's) |
//! | `MYSQL_CHARSET` / `MYSQL_COLLATION` | Connection character set (`utf8mb4` only) and collation (default `utf8mb4_unicode_ci`) |
//! | `TALAHON_MYSQL_QUERY_TIMEOUT` | Seconds one statement may run (default 120, at most 3600) |
//! | `TALAHON_MYSQL_MAX_ROWS` | Rows returned at most (default 50000) |
//! | `TALAHON_MYSQL_MAX_RESULT_BYTES` | Result text returned at most (default 1 MiB) |
//!
//! Not implemented, and refused at start-up instead of being ignored:
//! the SSH tunnel (`MYSQL_SSH_ENABLE=true`) and the SSE transport
//! (`MCP_TRANSPORT=sse`).

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Default for `MYSQL_CONNECT_TIMEOUT` (the Python server's default).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for `MYSQL_CONNECT_TIMEOUT`.
pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(300);
/// Default for `TALAHON_MYSQL_QUERY_TIMEOUT`. Below the 300 s the Talahon MCP
/// client waits for a tool call, so the model gets this server's message.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(120);
/// Upper bound for `TALAHON_MYSQL_QUERY_TIMEOUT`.
pub const MAX_QUERY_TIMEOUT: Duration = Duration::from_secs(3600);
/// Default for `TALAHON_MYSQL_MAX_ROWS`.
pub const DEFAULT_MAX_ROWS: usize = 50_000;
/// Upper bound for `TALAHON_MYSQL_MAX_ROWS`.
pub const MAX_MAX_ROWS: usize = 1_000_000;
/// Default for `TALAHON_MYSQL_MAX_RESULT_BYTES`. The Talahon agent keeps at most
/// 200 kB of a tool result, so this only bounds what is buffered here.
pub const DEFAULT_MAX_RESULT_BYTES: usize = 1024 * 1024;
/// Lower bound for `TALAHON_MYSQL_MAX_RESULT_BYTES`.
pub const MIN_MAX_RESULT_BYTES: usize = 1024;
/// Upper bound for `TALAHON_MYSQL_MAX_RESULT_BYTES`: a result is embedded in
/// one JSON-RPC line, whose escaping can double it; 8 MiB stays below the
/// 16 MiB message limit of `talon-mcp` clients.
pub const MAX_MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;
/// Default session `sql_mode` (the Python server's default).
pub const DEFAULT_SQL_MODE: &str = "TRADITIONAL";
/// Default connection collation (the Python server's default).
pub const DEFAULT_COLLATION: &str = "utf8mb4_unicode_ci";

/// A configuration problem. Messages name variables, never their values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A required variable is not set.
    #[error("{var} is required{hint}")]
    Missing {
        /// The environment variable.
        var: &'static str,
        /// Extra advice (starts with a space or is empty).
        hint: &'static str,
    },
    /// A variable has a value that cannot be used.
    #[error("{var}: {reason}")]
    Invalid {
        /// The environment variable.
        var: &'static str,
        /// What is wrong with it (never echoes the value).
        reason: String,
    },
    /// A feature of the Python server that this server does not implement.
    #[error("{var} is not supported by talahon-mysql-mcp; {hint}")]
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

/// How the connection is protected (`MYSQL_SSL_MODE`).
///
/// | Mode | Encryption | Server certificate |
/// |---|---|---|
/// | `Disabled` | never | – |
/// | `Preferred` | when the server offers TLS, else plaintext | not verified |
/// | `Required`, `VerifyCa`, `VerifyIdentity` | always | chain and host name verified |
///
/// `Preferred` is what the Python server does when `MYSQL_SSL_MODE` is not
/// set: it stops passive eavesdropping but not an active attacker, who can
/// strip TLS or present any certificate.
///
/// The three verifying modes are the same here. They trust the
/// certificates in `MYSQL_SSL_CA` or, without it, the built-in Mozilla root
/// set (webpki-roots; the system trust store is never read), and the
/// certificate must be valid for `MYSQL_HOST`, or for `MYSQL_SSL_HOSTNAME`
/// when the server is reached under another name (an IP address, a
/// container alias). Unlike libmysqlclient, rustls cannot verify a chain
/// while ignoring the name, so `VERIFY_CA` checks the name too, and a
/// certificate without a subjectAltName (such as the one MySQL generates
/// for itself) is rejected. `REQUIRED` verifies because the Python server
/// maps it to `ssl_verify_cert=True`. TLS 1.2 and 1.3 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Plaintext only.
    Disabled,
    /// TLS when offered, without verification; plaintext otherwise.
    Preferred,
    /// TLS with a verified certificate (chain and host name).
    Required,
    /// TLS with a verified certificate (chain and host name).
    VerifyCa,
    /// TLS with a verified certificate (chain and host name).
    VerifyIdentity,
}

impl TlsMode {
    /// The `MYSQL_SSL_MODE` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "DISABLED",
            Self::Preferred => "PREFERRED",
            Self::Required => "REQUIRED",
            Self::VerifyCa => "VERIFY_CA",
            Self::VerifyIdentity => "VERIFY_IDENTITY",
        }
    }

    /// Whether the server certificate is verified.
    pub fn verifies(self) -> bool {
        matches!(self, Self::Required | Self::VerifyCa | Self::VerifyIdentity)
    }
}

/// Validated server configuration. `Debug` never prints the password.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// Host name or IP address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// User name.
    pub user: String,
    /// Password (may be empty).
    pub password: String,
    /// Default database, if any.
    pub database: Option<String>,
    /// TLS behaviour.
    pub tls: TlsMode,
    /// PEM file with the trusted CA certificates for the verifying modes.
    pub ssl_ca: Option<PathBuf>,
    /// Name the certificate must be valid for instead of `host`.
    pub ssl_hostname: Option<String>,
    /// Budget for connect, TLS handshake, login and session set-up.
    pub connect_timeout: Duration,
    /// Budget for one statement, including reading its result.
    pub query_timeout: Duration,
    /// Session `sql_mode`; `None` keeps the server's.
    pub sql_mode: Option<String>,
    /// Connection collation; `None` uses the default of `utf8mb4`.
    pub collation: Option<String>,
    /// Rows returned at most.
    pub max_rows: usize,
    /// Result text returned at most, in bytes.
    pub max_result_bytes: usize,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &"<redacted>")
            .field("password", &"<redacted>")
            .field("database", &self.database)
            .field("tls", &self.tls)
            .field("ssl_ca", &self.ssl_ca)
            .field("ssl_hostname", &self.ssl_hostname)
            .field("connect_timeout", &self.connect_timeout)
            .field("query_timeout", &self.query_timeout)
            .field("sql_mode", &self.sql_mode)
            .field("collation", &self.collation)
            .field("max_rows", &self.max_rows)
            .field("max_result_bytes", &self.max_result_bytes)
            .finish()
    }
}

/// `[A-Za-z0-9_]+`: safe to place in a `SET` statement.
fn is_word(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn seconds(
    var: &'static str,
    value: Option<String>,
    default: Duration,
    max: Duration,
) -> Result<Duration, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };
    let secs: u64 = value
        .parse()
        .map_err(|_| invalid(var, "expected a whole number of seconds"))?;
    if secs == 0 {
        return Err(invalid(var, "must be greater than zero"));
    }
    Ok(Duration::from_secs(secs).min(max))
}

fn bounded(
    var: &'static str,
    value: Option<String>,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };
    let n: usize = value
        .parse()
        .map_err(|_| invalid(var, "expected a whole number"))?;
    if n < min || n > max {
        return Err(invalid(var, format!("must be between {min} and {max}")));
    }
    Ok(n)
}

impl Config {
    /// Read the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Read the configuration through `lookup` (tests, embedding).
    /// Whitespace-only values count as unset, except for the password
    /// (taken verbatim) and `MYSQL_SQL_MODE` / `MYSQL_COLLATION` (where an
    /// empty value means "leave the server's default").
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        // A `TALAHON_*` setting that is unset (or blank) is looked up under
        // its pre-rename `TALON_*` name as well.
        let get = |name: &str| {
            talon_core::env::resolve_with(name, |key| {
                lookup(key)
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
            })
        };

        if get("MYSQL_SSH_ENABLE").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            return Err(ConfigError::Unsupported {
                var: "MYSQL_SSH_ENABLE",
                hint: "unset TALAHON_MYSQL_MCP to use the Python server for SSH tunnels",
            });
        }
        if get("MCP_TRANSPORT").is_some_and(|v| v.eq_ignore_ascii_case("sse")) {
            return Err(ConfigError::Unsupported {
                var: "MCP_TRANSPORT",
                hint: "only the stdio transport is available",
            });
        }

        let host = get("MYSQL_HOST").unwrap_or_else(|| "localhost".to_string());
        if host.chars().any(|c| c.is_whitespace() || c.is_control())
            || host.contains(['/', '@', '?', '#'])
        {
            return Err(invalid("MYSQL_HOST", "expected a host name or IP address"));
        }
        let port = match get("MYSQL_PORT") {
            None => 3306,
            Some(v) => v
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| invalid("MYSQL_PORT", "expected a port number (1-65535)"))?,
        };

        let user = get("MYSQL_USER").ok_or(ConfigError::Missing {
            var: "MYSQL_USER",
            hint: "",
        })?;
        // Verbatim: spaces may be part of a password, and the Python server
        // accepts an empty one.
        let password = lookup("MYSQL_PASSWORD")
            .or_else(|| lookup("MYSQL_PASS"))
            .ok_or(ConfigError::Missing {
                var: "MYSQL_PASSWORD",
                hint: " (MYSQL_PASS is accepted too; it may be empty for no password)",
            })?;
        let database = get("MYSQL_DATABASE").or_else(|| get("MYSQL_DB"));
        if database
            .as_deref()
            .is_some_and(|d| d.chars().any(char::is_control))
        {
            return Err(invalid("MYSQL_DATABASE", "contains control characters"));
        }

        let tls = match get("MYSQL_SSL_MODE").map(|v| v.to_ascii_uppercase()) {
            None => TlsMode::Preferred,
            Some(v) => match v.as_str() {
                "DISABLED" => TlsMode::Disabled,
                "PREFERRED" => TlsMode::Preferred,
                "REQUIRED" => TlsMode::Required,
                "VERIFY_CA" => TlsMode::VerifyCa,
                "VERIFY_IDENTITY" => TlsMode::VerifyIdentity,
                _ => {
                    return Err(invalid(
                        "MYSQL_SSL_MODE",
                        "expected DISABLED, PREFERRED, REQUIRED, VERIFY_CA or VERIFY_IDENTITY",
                    ));
                }
            },
        };
        let ssl_ca = get("MYSQL_SSL_CA").map(PathBuf::from);
        if let Some(path) = &ssl_ca
            && tls.verifies()
            && !path.is_file()
        {
            return Err(invalid("MYSQL_SSL_CA", "file not found"));
        }

        let ssl_hostname = get("MYSQL_SSL_HOSTNAME");
        if ssl_hostname.as_deref().is_some_and(|h| {
            !h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_'))
        }) {
            return Err(invalid(
                "MYSQL_SSL_HOSTNAME",
                "expected a host name or IP address",
            ));
        }

        match get("MYSQL_CHARSET").map(|v| v.to_ascii_lowercase()) {
            None => {}
            Some(v) if v == "utf8mb4" => {}
            Some(_) => {
                return Err(invalid(
                    "MYSQL_CHARSET",
                    "only utf8mb4 is supported (results are returned as UTF-8)",
                ));
            }
        }
        let collation = match lookup("MYSQL_COLLATION").map(|v| v.trim().to_string()) {
            None => Some(DEFAULT_COLLATION.to_string()),
            Some(v) if v.is_empty() => None,
            Some(v) => {
                if !is_word(&v) || !v.to_ascii_lowercase().starts_with("utf8mb4_") {
                    return Err(invalid(
                        "MYSQL_COLLATION",
                        "expected a utf8mb4_* collation name",
                    ));
                }
                Some(v)
            }
        };
        let sql_mode = match lookup("MYSQL_SQL_MODE").map(|v| v.trim().to_string()) {
            None => Some(DEFAULT_SQL_MODE.to_string()),
            Some(v) if v.is_empty() => None,
            Some(v) => {
                if !v.split(',').all(is_word) {
                    return Err(invalid(
                        "MYSQL_SQL_MODE",
                        "expected a comma-separated list of SQL mode names",
                    ));
                }
                Some(v)
            }
        };

        Ok(Self {
            host,
            port,
            user,
            password,
            database,
            tls,
            ssl_ca,
            ssl_hostname,
            connect_timeout: seconds(
                "MYSQL_CONNECT_TIMEOUT",
                get("MYSQL_CONNECT_TIMEOUT"),
                DEFAULT_CONNECT_TIMEOUT,
                MAX_CONNECT_TIMEOUT,
            )?,
            query_timeout: seconds(
                "TALAHON_MYSQL_QUERY_TIMEOUT",
                get("TALAHON_MYSQL_QUERY_TIMEOUT"),
                DEFAULT_QUERY_TIMEOUT,
                MAX_QUERY_TIMEOUT,
            )?,
            sql_mode,
            collation,
            max_rows: bounded(
                "TALAHON_MYSQL_MAX_ROWS",
                get("TALAHON_MYSQL_MAX_ROWS"),
                DEFAULT_MAX_ROWS,
                1,
                MAX_MAX_ROWS,
            )?,
            max_result_bytes: bounded(
                "TALAHON_MYSQL_MAX_RESULT_BYTES",
                get("TALAHON_MYSQL_MAX_RESULT_BYTES"),
                DEFAULT_MAX_RESULT_BYTES,
                MIN_MAX_RESULT_BYTES,
                MAX_MAX_RESULT_BYTES,
            )?,
        })
    }

    /// `host:port` for log lines and connection errors (no credentials).
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Whether the host is a loopback name or address.
    pub fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

    /// The statements run on every new connection, mirroring what
    /// `mysql-connector-python` sends for the Python server's settings.
    pub fn session_setup(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.push(match &self.collation {
            Some(c) => format!("SET NAMES 'utf8mb4' COLLATE '{c}'"),
            None => "SET NAMES 'utf8mb4'".to_string(),
        });
        out.push("SET @@session.autocommit = ON".to_string());
        if let Some(mode) = &self.sql_mode {
            out.push(format!("SET @@session.sql_mode = '{mode}'"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn load(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|name| map.get(name).cloned())
    }

    const BASE: [(&str, &str); 2] = [("MYSQL_USER", "talahon"), ("MYSQL_PASSWORD", "pw")];

    fn with(extra: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let mut vars = BASE.to_vec();
        vars.extend_from_slice(extra);
        load(&vars)
    }

    #[test]
    fn defaults() {
        let c = with(&[]).unwrap();
        assert_eq!(c.host, "localhost");
        assert_eq!(c.port, 3306);
        assert_eq!(c.user, "talahon");
        assert_eq!(c.password, "pw");
        assert_eq!(c.database, None);
        assert_eq!(c.tls, TlsMode::Preferred);
        assert_eq!(c.ssl_ca, None);
        assert_eq!(c.ssl_hostname, None);
        assert_eq!(c.connect_timeout, Duration::from_secs(10));
        assert_eq!(c.query_timeout, Duration::from_secs(120));
        assert_eq!(c.sql_mode.as_deref(), Some("TRADITIONAL"));
        assert_eq!(c.collation.as_deref(), Some("utf8mb4_unicode_ci"));
        assert_eq!(c.max_rows, 50_000);
        assert_eq!(c.max_result_bytes, 1024 * 1024);
        assert_eq!(c.address(), "localhost:3306");
        assert!(c.is_loopback());
        assert_eq!(
            c.session_setup(),
            [
                "SET NAMES 'utf8mb4' COLLATE 'utf8mb4_unicode_ci'",
                "SET @@session.autocommit = ON",
                "SET @@session.sql_mode = 'TRADITIONAL'",
            ]
        );
    }

    #[test]
    fn both_spellings_of_password_and_database() {
        let c = load(&[
            ("MYSQL_USER", "u"),
            ("MYSQL_PASS", " spaced pw "),
            ("MYSQL_DB", "copilot"),
            ("MYSQL_HOST", "db.internal"),
            ("MYSQL_PORT", "3307"),
        ])
        .unwrap();
        assert_eq!(c.password, " spaced pw ");
        assert_eq!(c.database.as_deref(), Some("copilot"));
        assert_eq!(c.address(), "db.internal:3307");
        assert!(!c.is_loopback());

        // The canonical names win.
        let c = load(&[
            ("MYSQL_USER", "u"),
            ("MYSQL_PASS", "old"),
            ("MYSQL_PASSWORD", "new"),
            ("MYSQL_DB", "a"),
            ("MYSQL_DATABASE", "b"),
        ])
        .unwrap();
        assert_eq!(c.password, "new");
        assert_eq!(c.database.as_deref(), Some("b"));
    }

    #[test]
    fn user_and_password_are_required_but_password_may_be_empty() {
        assert_eq!(
            load(&[("MYSQL_PASSWORD", "x")]).unwrap_err().to_string(),
            "MYSQL_USER is required"
        );
        let err = load(&[("MYSQL_USER", "u")]).unwrap_err();
        assert!(
            err.to_string().starts_with("MYSQL_PASSWORD is required"),
            "{err}"
        );
        assert_eq!(
            load(&[("MYSQL_USER", "u"), ("MYSQL_PASSWORD", "")])
                .unwrap()
                .password,
            ""
        );
    }

    #[test]
    fn tls_modes() {
        for (value, mode) in [
            ("DISABLED", TlsMode::Disabled),
            ("disabled", TlsMode::Disabled),
            ("PREFERRED", TlsMode::Preferred),
            ("Required", TlsMode::Required),
            ("VERIFY_CA", TlsMode::VerifyCa),
            ("verify_identity", TlsMode::VerifyIdentity),
        ] {
            let c = with(&[("MYSQL_SSL_MODE", value)]).unwrap();
            assert_eq!(c.tls, mode, "{value}");
            assert_eq!(c.tls.as_str(), value.to_ascii_uppercase());
        }
        assert!(!TlsMode::Preferred.verifies() && !TlsMode::Disabled.verifies());
        assert!(TlsMode::Required.verifies() && TlsMode::VerifyIdentity.verifies());
        let err = with(&[("MYSQL_SSL_MODE", "sometimes")]).unwrap_err();
        assert!(
            err.to_string().starts_with("MYSQL_SSL_MODE: expected"),
            "{err}"
        );
        assert!(!err.to_string().contains("sometimes"));
    }

    #[test]
    fn ca_file_must_exist_for_the_verifying_modes() {
        let err = with(&[
            ("MYSQL_SSL_MODE", "VERIFY_CA"),
            ("MYSQL_SSL_CA", "/nonexistent/ca.pem"),
        ])
        .unwrap_err();
        assert_eq!(err.to_string(), "MYSQL_SSL_CA: file not found");
        // Not used, so not checked.
        let c = with(&[("MYSQL_SSL_CA", "/nonexistent/ca.pem")]).unwrap();
        assert_eq!(c.ssl_ca, Some(PathBuf::from("/nonexistent/ca.pem")));
        let c = with(&[("MYSQL_SSL_HOSTNAME", "db.internal")]).unwrap();
        assert_eq!(c.ssl_hostname.as_deref(), Some("db.internal"));
    }

    #[test]
    fn invalid_values_are_rejected_without_echoing_them() {
        for (var, value) in [
            ("MYSQL_PORT", "abc"),
            ("MYSQL_PORT", "0"),
            ("MYSQL_PORT", "70000"),
            ("MYSQL_HOST", "db host"),
            ("MYSQL_HOST", "user@db-secret"),
            ("MYSQL_HOST", "db/secretpath"),
            ("MYSQL_SSL_HOSTNAME", "db internal"),
            ("MYSQL_SSL_HOSTNAME", "db/secretpath"),
            ("MYSQL_CONNECT_TIMEOUT", "soon"),
            ("MYSQL_CONNECT_TIMEOUT", "0"),
            ("MYSQL_CONNECT_TIMEOUT", "1.5"),
            ("TALAHON_MYSQL_QUERY_TIMEOUT", "-1"),
            ("TALAHON_MYSQL_MAX_ROWS", "0"),
            ("TALAHON_MYSQL_MAX_ROWS", "1000001"),
            ("TALAHON_MYSQL_MAX_ROWS", "many"),
            ("TALAHON_MYSQL_MAX_RESULT_BYTES", "10"),
            ("TALAHON_MYSQL_MAX_RESULT_BYTES", "999999999999"),
            ("MYSQL_CHARSET", "latin1"),
            ("MYSQL_COLLATION", "latin1_swedish_ci"),
            ("MYSQL_COLLATION", "utf8mb4_bin'; DROP TABLE x; --"),
            ("MYSQL_SQL_MODE", "ANSI'; DROP TABLE x; --"),
            ("MYSQL_SQL_MODE", "ANSI,,STRICT"),
            ("MYSQL_DATABASE", "a\u{1}b"),
        ] {
            let err = with(&[(var, value)]).unwrap_err();
            let text = err.to_string();
            assert!(text.starts_with(var), "{var}={value}: {text}");
            // ("0" and the like also occur in the stated bounds.)
            assert!(
                value.len() < 3 || !text.contains(value),
                "{var}: value echoed in {text}"
            );
        }
    }

    #[test]
    fn limits_under_the_old_talon_prefix_are_still_read() {
        // mysql/.env written before the rename.
        let c = with(&[
            ("TALON_MYSQL_QUERY_TIMEOUT", "45"),
            ("TALON_MYSQL_MAX_ROWS", "100"),
            ("TALON_MYSQL_MAX_RESULT_BYTES", "4096"),
        ])
        .unwrap();
        assert_eq!(c.query_timeout, Duration::from_secs(45));
        assert_eq!(c.max_rows, 100);
        assert_eq!(c.max_result_bytes, 4096);
        // Both spellings: the new one wins; a blank new one does not hide
        // the old one.
        let c = with(&[
            ("TALON_MYSQL_MAX_ROWS", "100"),
            ("TALAHON_MYSQL_MAX_ROWS", "7"),
            ("TALON_MYSQL_QUERY_TIMEOUT", "45"),
            ("TALAHON_MYSQL_QUERY_TIMEOUT", "  "),
        ])
        .unwrap();
        assert_eq!(c.max_rows, 7);
        assert_eq!(c.query_timeout, Duration::from_secs(45));
        // An invalid value under the old name is still an error.
        assert!(with(&[("TALON_MYSQL_MAX_ROWS", "many")]).is_err());
    }

    #[test]
    fn timeouts_and_limits() {
        let c = with(&[
            ("MYSQL_CONNECT_TIMEOUT", "3"),
            ("TALAHON_MYSQL_QUERY_TIMEOUT", "45"),
            ("TALAHON_MYSQL_MAX_ROWS", "100"),
            ("TALAHON_MYSQL_MAX_RESULT_BYTES", "4096"),
        ])
        .unwrap();
        assert_eq!(c.connect_timeout, Duration::from_secs(3));
        assert_eq!(c.query_timeout, Duration::from_secs(45));
        assert_eq!(c.max_rows, 100);
        assert_eq!(c.max_result_bytes, 4096);
        // Clamped, not rejected: a huge timeout is a typo, not an attack.
        let c = with(&[
            ("MYSQL_CONNECT_TIMEOUT", "99999"),
            ("TALAHON_MYSQL_QUERY_TIMEOUT", "99999"),
        ])
        .unwrap();
        assert_eq!(c.connect_timeout, MAX_CONNECT_TIMEOUT);
        assert_eq!(c.query_timeout, MAX_QUERY_TIMEOUT);
    }

    #[test]
    fn session_settings() {
        let c = with(&[
            ("MYSQL_SQL_MODE", "ANSI,STRICT_TRANS_TABLES"),
            ("MYSQL_COLLATION", "utf8mb4_general_ci"),
            ("MYSQL_CHARSET", "UTF8MB4"),
        ])
        .unwrap();
        assert_eq!(
            c.session_setup(),
            [
                "SET NAMES 'utf8mb4' COLLATE 'utf8mb4_general_ci'",
                "SET @@session.autocommit = ON",
                "SET @@session.sql_mode = 'ANSI,STRICT_TRANS_TABLES'",
            ]
        );
        // Set but empty: keep the server's defaults (as the Python server does).
        let c = with(&[("MYSQL_SQL_MODE", ""), ("MYSQL_COLLATION", " ")]).unwrap();
        assert_eq!(c.sql_mode, None);
        assert_eq!(c.collation, None);
        assert_eq!(
            c.session_setup(),
            ["SET NAMES 'utf8mb4'", "SET @@session.autocommit = ON"]
        );
    }

    #[test]
    fn unsupported_features_are_refused() {
        let err = with(&[("MYSQL_SSH_ENABLE", "TRUE")]).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Unsupported {
                var: "MYSQL_SSH_ENABLE",
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("not supported by talahon-mysql-mcp")
        );
        let err = with(&[("MCP_TRANSPORT", "sse")]).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Unsupported {
                var: "MCP_TRANSPORT",
                ..
            }
        ));
        assert!(with(&[("MYSQL_SSH_ENABLE", "false"), ("MCP_TRANSPORT", "stdio")]).is_ok());
    }

    #[test]
    fn debug_redacts_credentials() {
        let c = load(&[
            ("MYSQL_USER", "talahon-user"),
            ("MYSQL_PASSWORD", "hunter2-secret"),
        ])
        .unwrap();
        let text = format!("{c:?}");
        assert!(!text.contains("hunter2-secret"), "{text}");
        assert!(!text.contains("talahon-user"), "{text}");
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn loopback_detection() {
        for (host, loopback) in [
            ("127.0.0.1", true),
            ("::1", true),
            ("LOCALHOST", true),
            ("10.0.0.5", false),
            ("mysql", false),
        ] {
            assert_eq!(
                with(&[("MYSQL_HOST", host)]).unwrap().is_loopback(),
                loopback,
                "{host}"
            );
        }
    }
}
