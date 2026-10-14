//! `talon-agent` — the in-container runtime binary.
//!
//! ```text
//! talon-agent supervise [run options] [--socket-dir DIR] [--mcp-home-root DIR] [--agent-bin PATH]
//! talon-agent run       [--group-dir DIR] [--global-dir DIR] [--project-dir DIR] [--extra-dir DIR]
//!                       [--ipc-dir DIR] [--state-dir DIR] [--mcp-config FILE] [--mcp-socket-dir DIR]
//!                       [--max-iterations N] [--self-check BOOL] [--compact-threshold F]
//!                       [--ipc-poll-ms MS] [--tool-timeout-secs S] [--max-input-bytes N]
//! ```
//!
//! stdin: one `ContainerInput` JSON document; stdout: `ContainerOutput`
//! frames only; stderr: logs. See the library docs for details.

use clap::{Parser, Subcommand};
use talon_agent::config::RunArgs;
use talon_agent::supervise::SuperviseArgs;

#[derive(Debug, Parser)]
#[command(
    name = "talon-agent",
    version,
    about = "Talon in-container agent runtime (vLLM agent loop + privileged MCP supervisor)"
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

#[tokio::main]
async fn main() {
    talon_agent::logging::init();
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Supervise(args) => {
            talon_agent::supervise::supervise_main(args.into_config()).await
        }
        Command::Run(args) => talon_agent::run::run_main(args.into_config()).await,
    };
    std::process::exit(code);
}
