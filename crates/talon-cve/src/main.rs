//! `talahon-cve-mcp` — offline CVE / EPSS / KEV MCP server.
//!
//! Speaks line-delimited JSON-RPC (MCP) on stdin/stdout and reads one SQLite
//! file. It makes no network connection: the data is downloaded by the host
//! (`talahon cve sync`). Logs go to stderr only (`TALAHON_CVE_LOG` /
//! `RUST_LOG`, default `warn`); stdout is the protocol.

use std::process::ExitCode;

use talon_cve::store::Reader;
use talon_cve::{Config, build_server};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
talahon-cve-mcp — offline CVE / EPSS / KEV MCP server (stdio, no network)

Usage: talahon-cve-mcp [--check | --version | --help]

  --check     open the database, print what it holds and exit
  --version   print the version and exit

Environment:
  TALAHON_CVE_DB             the SQLite file written by `talahon cve sync`
                             (default: cve.sqlite in the working directory)
  TALAHON_CVE_MAX_AGE_DAYS   age from which answers carry a staleness warning (default 3)
  TALAHON_CVE_LOG            log filter for stderr, e.g. 'debug' (default warn)
";

fn init_logging() {
    let filter = talon_core::env::process_var("TALAHON_CVE_LOG")
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
                println!("talahon-cve-mcp {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => {
                eprint!("talahon-cve-mcp: unexpected argument\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    init_logging();
    talon_core::env::flush_legacy_key_warnings();
    let config = Config::from_env();

    if check {
        return match Reader::new(&config.db_path).status() {
            Ok(status) => {
                eprintln!(
                    "talahon-cve-mcp: {} CVEs, {} EPSS scores, {} KEV entries, synced {}",
                    status.cve_count,
                    status.epss_count,
                    status.kev_count,
                    status.synced_at.as_deref().unwrap_or("never"),
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("talahon-cve-mcp: {e}");
                ExitCode::FAILURE
            }
        };
    }

    // A missing database is not fatal: the tools say what to do, and the
    // file may appear while the server runs.
    tracing::info!(db = %config.db_path.display(), "talahon-cve-mcp starting");
    match build_server(&config).serve_stdio().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "MCP transport failed");
            ExitCode::FAILURE
        }
    }
}
