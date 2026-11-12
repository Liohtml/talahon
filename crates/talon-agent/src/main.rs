//! `talahon-agent` — the in-container runtime binary.
//!
//! ```text
//! talahon-agent supervise [run options] [--socket-dir DIR] [--mcp-home-root DIR] [--agent-bin PATH]
//! talahon-agent run       [--group-dir DIR] [--global-dir DIR] [--project-dir DIR] [--extra-dir DIR]
//!                       [--ipc-dir DIR] [--state-dir DIR] [--mcp-config FILE] [--mcp-socket-dir DIR]
//!                       [--max-iterations N] [--self-check BOOL] [--compact-threshold F]
//!                       [--ipc-poll-ms MS] [--tool-timeout-secs S] [--max-input-bytes N]
//! ```
//!
//! stdin: one `ContainerInput` JSON document; stdout: `ContainerOutput`
//! frames only; stderr: logs. See the library docs for details.

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use talon_agent::config::RunArgs;
use talon_agent::supervise::SuperviseArgs;

#[derive(Debug, Parser)]
#[command(
    name = "talahon-agent",
    version,
    about = "Talahon in-container agent runtime (vLLM agent loop + privileged MCP supervisor)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Root supervisor: start MCP servers as their mcp-* users, run the
    /// agent unprivileged, tear down on exit.
    Supervise(SuperviseArgs),
    /// The unprivileged agent loop.
    Run(RunArgs),
}

/// `clap` knows no alias for `env`: an argument whose `TALAHON_*` variable is
/// unset reads the pre-rename `TALON_*` name instead when that one is set.
fn with_legacy_env(cmd: clap::Command) -> clap::Command {
    cmd.mut_args(|arg| {
        match arg
            .get_env()
            .and_then(|key| key.to_str())
            .and_then(talon_core::env::legacy_process_key_in_use)
        {
            // `clap` wants a `'static` name; one short string per aliased
            // variable for the life of the process.
            Some(legacy) => arg.env(&*Box::leak(legacy.into_boxed_str())),
            None => arg,
        }
    })
    .mut_subcommands(with_legacy_env)
}

fn parse_cli() -> Cli {
    let matches = with_legacy_env(Cli::command()).get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

#[tokio::main]
async fn main() {
    talon_agent::logging::init();
    let cli = parse_cli();
    let code = match cli.command {
        Command::Supervise(args) => {
            talon_agent::supervise::supervise_main(args.into_config()).await
        }
        Command::Run(args) => talon_agent::run::run_main(args.into_config()).await,
    };
    std::process::exit(code);
}
