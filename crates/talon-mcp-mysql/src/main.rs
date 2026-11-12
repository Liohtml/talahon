//! `talon-mysql-mcp` — native MySQL MCP server.
//!
//! Speaks line-delimited JSON-RPC (MCP) on stdin/stdout and the MySQL
//! protocol over TCP. Configuration comes from the environment (see
//! `talon_mcp_mysql::config`). Logs go to stderr only (`TALON_MYSQL_LOG` /
//! `RUST_LOG`, default `warn`) and never contain credentials, statements
//! or result data; stdout is the protocol.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use talon_mcp_mysql::{Config, MySqlBackend, TlsMode, build_server_with};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
talon-mysql-mcp — native MySQL MCP server (stdio)

Usage: talon-mysql-mcp [--check | --version | --help]

  --check     validate the configuration and exit (no connection is made)
  --version   print the version and exit

Environment:
  MYSQL_HOST, MYSQL_PORT   server address (default localhost:3306, TCP)
  MYSQL_USER               user name (required)
  MYSQL_PASSWORD           password (required, may be empty; or MYSQL_PASS)
  MYSQL_DATABASE           default database (or MYSQL_DB)
  MYSQL_SSL_MODE           PREFERRED (default): TLS if the server offers it, not verified
                           DISABLED: never TLS
                           REQUIRED, VERIFY_CA, VERIFY_IDENTITY: TLS always, the
                           certificate chain and host name are verified
  MYSQL_SSL_CA             PEM file with the CA to trust (default: built-in web roots)
  MYSQL_SSL_HOSTNAME       name in the server certificate, if it is not MYSQL_HOST
  MYSQL_CONNECT_TIMEOUT    seconds to connect and log in (default 10)
  MYSQL_SQL_MODE           session sql_mode (default TRADITIONAL)
  MYSQL_COLLATION          connection collation (default utf8mb4_unicode_ci)
  TALON_MYSQL_QUERY_TIMEOUT      seconds per statement (default 120)
  TALON_MYSQL_MAX_ROWS           rows returned at most (default 50000)
  TALON_MYSQL_MAX_RESULT_BYTES   result text returned at most (default 1048576)
  TALON_MYSQL_LOG          log filter for stderr, e.g. 'debug' (default warn)
";

fn init_logging() {
    let filter = std::env::var("TALON_MYSQL_LOG")
        .ok()
        .and_then(|f| EnvFilter::try_new(f).ok())
        .or_else(|| EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut check = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--version" | "-V" => {
                println!("talon-mysql-mcp {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => {
                eprint!("talon-mysql-mcp: unexpected argument\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    init_logging();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            // ConfigError messages never contain values, only variable names.
            eprintln!("talon-mysql-mcp: configuration error: {e}");
            return ExitCode::from(2);
        }
    };
    if !config.is_loopback() {
        match config.tls {
            TlsMode::Disabled => {
                tracing::warn!("MYSQL_SSL_MODE=DISABLED: credentials and data are sent unencrypted")
            }
            TlsMode::Preferred => tracing::info!(
                "MYSQL_SSL_MODE=PREFERRED: the server certificate is not verified; \
                 use VERIFY_IDENTITY with MYSQL_SSL_CA to authenticate the server"
            ),
            _ => {}
        }
    }
    for ignored in [
        "MYSQL_AUTH_PLUGIN",
        "MYSQL_RAISE_ON_WARNINGS",
        "MYSQL_USE_PURE",
    ] {
        if std::env::var_os(ignored).is_some_and(|v| !v.is_empty()) {
            tracing::warn!(
                variable = ignored,
                "not used by talon-mysql-mcp; ignoring it"
            );
        }
    }
    tracing::info!(
        server = %config.address(),
        database = config.database.as_deref().unwrap_or("(none)"),
        tls = config.tls.as_str(),
        "talon-mysql-mcp starting"
    );
    let backend = Arc::new(MySqlBackend::new(&config));
    let server = build_server_with(backend.clone());

    if check {
        eprintln!("talon-mysql-mcp: configuration OK");
        return ExitCode::SUCCESS;
    }

    let served = server.serve_stdio().await;
    // Calls that were still running at EOF have been dropped: let their
    // KILLs reach the server before the process goes away.
    backend.settle(Duration::from_secs(5)).await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "MCP transport failed");
            ExitCode::FAILURE
        }
    }
}
