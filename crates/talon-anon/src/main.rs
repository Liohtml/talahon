//! `talon-anon-proxy` — anonymizing MCP stdio proxy.
//!
//! ```text
//! talon-anon-proxy [--fields <yaml>] --map <file> -- <upstream cmd> [args...]
//! ```
//!
//! Speaks line-delimited JSON-RPC on stdin/stdout (the agent side) and runs
//! the upstream MCP server as a child process. Logs go to stderr only
//! (`TALON_ANON_LOG` / `RUST_LOG`, default `info`); stdout is the protocol.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use talon_anon::config::DEFAULT_FIELDS_YAML;
use talon_anon::session::lock_session;
use talon_anon::{AnonSession, CompiledConfig, ProxyOptions, ProxyOutcome, TokenMap, run_proxy};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "talon-anon-proxy",
    version,
    about = "Anonymizing MCP stdio proxy: tokenizes PII in upstream tool results and answers a local `deanonymize` tool",
    after_help = "Example:\n  talon-anon-proxy --fields siem/anon_proxy/fields.yaml --map \"$HOME/session_tokens.json\" -- siem/opensearch-mcp.sh"
)]
struct Cli {
    /// Field definitions (fields.yaml). Defaults to the copy embedded at build time.
    #[arg(long, env = "TALON_ANON_FIELDS", value_name = "YAML")]
    fields: Option<PathBuf>,

    /// Session token map (JSON, Python-compatible); created with mode 0600.
    #[arg(long, env = "TALON_ANON_MAP", value_name = "FILE")]
    map: PathBuf,

    /// Maximum size of one JSON-RPC message in bytes.
    #[arg(long, default_value_t = 32 * 1024 * 1024, value_name = "BYTES")]
    max_line_bytes: usize,

    /// Seconds to wait for the upstream to finish after the client disconnects.
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    shutdown_grace_secs: u64,

    /// Forward `tools/call` arguments as written by the model (do not
    /// replace tokens with the original values before calling the upstream).
    #[arg(long)]
    no_deanonymize_arguments: bool,

    /// Validate the field definitions and the token map, then exit.
    #[arg(long)]
    check: bool,

    /// Upstream MCP server command and arguments (after `--`).
    #[arg(
        last = true,
        value_name = "UPSTREAM",
        required_unless_present = "check"
    )]
    upstream: Vec<OsString>,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("TALON_ANON_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}

fn load_config(cli: &Cli) -> Result<CompiledConfig, String> {
    match &cli.fields {
        Some(path) => CompiledConfig::load(path).map_err(|e| e.to_string()),
        None => CompiledConfig::from_yaml_str(DEFAULT_FIELDS_YAML)
            .map_err(|e| format!("built-in fields.yaml: {e}")),
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (term, int, hup) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    );
    match (term, int, hup) {
        (Ok(mut term), Ok(mut int), Ok(mut hup)) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
                _ = hup.recv() => {}
            }
        }
        _ => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// `--check`: validate without side effects (a corrupt map is reported,
/// not quarantined).
fn check_map(map: &std::path::Path, cfg: &CompiledConfig) -> u8 {
    let tokens = match std::fs::read(map) {
        Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => 0,
        Ok(bytes) => match TokenMap::from_json_slice(&bytes) {
            Ok(m) => m.len(),
            Err(e) => {
                tracing::error!(path = %map.display(), error = %e, "token map is invalid");
                return 1;
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            tracing::error!(path = %map.display(), error = %e, "token map is unreadable");
            return 1;
        }
    };
    tracing::info!(
        categories = cfg.category_count(),
        field_rules = cfg.rule_count(),
        tokens,
        "configuration OK"
    );
    0
}

async fn run(cli: Cli) -> u8 {
    let cfg = match load_config(&cli) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "invalid field definitions");
            return 2;
        }
    };
    if cli.check {
        return check_map(&cli.map, &cfg);
    }
    let session = AnonSession::open(Arc::clone(&cfg), &cli.map).into_shared();

    let Some((program, args)) = cli.upstream.split_first() else {
        tracing::error!("no upstream command given (use `-- <command> [args...]`)");
        return 2;
    };
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, program = %program.to_string_lossy(), "cannot start the upstream MCP server");
            return if e.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            };
        }
    };
    let (Some(child_in), Some(child_out)) = (child.stdin.take(), child.stdout.take()) else {
        tracing::error!("upstream pipes unavailable");
        let _ = child.start_kill();
        return 1;
    };
    tracing::info!(
        pid = child.id().unwrap_or_default(),
        "upstream MCP server started"
    );

    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("signal received; shutting down");
            cancel.cancel();
        });
    }

    let opts = ProxyOptions {
        max_line_bytes: cli.max_line_bytes.max(1024),
        shutdown_grace: Duration::from_secs(cli.shutdown_grace_secs),
        deanonymize_arguments: !cli.no_deanonymize_arguments,
        ..ProxyOptions::default()
    };
    let outcome = run_proxy(
        Arc::clone(&session),
        opts,
        tokio::io::stdin(),
        tokio::io::stdout(),
        child_in,
        child_out,
        cancel,
    )
    .await;

    {
        let session = Arc::clone(&session);
        let flushed = tokio::task::spawn_blocking(move || lock_session(&session).flush()).await;
        if let Ok(Err(e)) = flushed {
            tracing::warn!(error = %e, "final token map flush failed");
        }
    }

    let status = match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
        Ok(Ok(s)) => Some(s),
        _ => {
            let _ = child.start_kill();
            tokio::time::timeout(Duration::from_secs(2), child.wait())
                .await
                .ok()
                .and_then(Result::ok)
        }
    };
    tracing::info!(?outcome, status = ?status, "proxy stopped");
    match outcome {
        ProxyOutcome::UpstreamClosed => status
            .and_then(|s| s.code())
            .map_or(1, |c| u8::try_from(c).unwrap_or(1)),
        ProxyOutcome::ClientClosed | ProxyOutcome::ClientOutputClosed | ProxyOutcome::Cancelled => {
            0
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return ExitCode::from(1);
        }
    };
    let code = rt.block_on(run(cli));
    // tokio's stdin reader may sit in a blocking read; don't wait for it.
    rt.shutdown_timeout(Duration::from_millis(200));
    ExitCode::from(code)
}
