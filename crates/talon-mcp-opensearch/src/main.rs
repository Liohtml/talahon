//! `talahon-opensearch-mcp` — native read-only OpenSearch MCP server.
//!
//! Speaks line-delimited JSON-RPC (MCP) on stdin/stdout and the OpenSearch
//! REST API over HTTP(S). Configuration comes from the environment (see
//! `talon_mcp_opensearch::config`). Logs go to stderr only
//! (`TALAHON_OPENSEARCH_LOG` / `RUST_LOG`, default `warn`); stdout is the
//! protocol.

use std::process::ExitCode;

use talon_mcp_opensearch::{Config, build_server};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
talahon-opensearch-mcp — native read-only OpenSearch MCP server (stdio)

Usage: talahon-opensearch-mcp [--check | --version | --help]

  --check     validate the configuration and exit (no request is made)
  --version   print the version and exit

Environment:
  OPENSEARCH_HOSTS       comma-separated base URLs (default https://localhost:9200)
  OPENSEARCH_USERNAME    basic-auth user
  OPENSEARCH_PASSWORD    basic-auth password
  VERIFY_CERTS           'false' disables TLS verification (default: verify)
  OPENSEARCH_CA_CERTS    PEM file with additional trusted CA certificates
  OPENSEARCH_PROXY       http(s) proxy for all requests
  REQUEST_TIMEOUT        request timeout in seconds (default 30)
  TALAHON_OPENSEARCH_MAX_RESPONSE_BYTES   response size limit (default 8388608)
  TALAHON_OPENSEARCH_LOG   log filter for stderr, e.g. 'debug' (default warn)
";

fn init_logging() {
    // `TALAHON_OPENSEARCH_LOG`, or its pre-rename alias `TALON_OPENSEARCH_LOG`.
    let filter = talon_core::env::process_var("TALAHON_OPENSEARCH_LOG")
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
                println!("talahon-opensearch-mcp {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => {
                eprint!("talahon-opensearch-mcp: unexpected argument\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    init_logging();
    talon_core::env::flush_legacy_key_warnings();

    let server = match Config::from_env().and_then(|config| {
        if config.sends_credentials_in_clear() {
            tracing::warn!("OPENSEARCH_HOSTS uses http://: credentials are sent unencrypted");
        }
        if !config.verify_certs {
            tracing::warn!("VERIFY_CERTS=false: TLS certificates are not verified");
        }
        tracing::info!(
            hosts = ?config.hosts_for_log(),
            authenticated = config.credentials.is_some(),
            "talahon-opensearch-mcp starting"
        );
        build_server(&config)
    }) {
        Ok(server) => server,
        Err(e) => {
            // ConfigError messages never contain values, only variable names.
            eprintln!("talahon-opensearch-mcp: configuration error: {e}");
            return ExitCode::from(2);
        }
    };

    if check {
        eprintln!("talahon-opensearch-mcp: configuration OK");
        return ExitCode::SUCCESS;
    }

    match server.serve_stdio().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "MCP transport failed");
            ExitCode::FAILURE
        }
    }
}
