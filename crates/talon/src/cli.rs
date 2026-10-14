//! Command-line interface (`clap` derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// `talon` — automated AI SOC analyst for SOCFortress CoPilot.
#[derive(Debug, Parser)]
#[command(name = "talon", version, about, long_about = None)]
pub struct Cli {
    /// Talon project directory (holds `.env`, `groups/`, `store/`, `data/`).
    /// Defaults to the current directory.
    #[arg(long, global = true, env = "TALON_PROJECT_ROOT", value_name = "DIR")]
    pub project_root: Option<PathBuf>,

    /// Subcommand; `run` when omitted.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Run the orchestrator (default).
    Run,
    /// Run a setup step (`timezone`, `environment`, `vllm`, `container`,
    /// `groups`, `register`, `mounts`, `service`, `verify`).
    Setup(SetupArgs),
    /// Diagnose the environment: container runtime, image, vLLM, LLM
    /// gateway, directories, audit chain.
    Doctor,
    /// Inspect the hash-chained audit log.
    Audit {
        /// Audit subcommand.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Print the version.
    Version,
}

/// Arguments of `talon setup`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct SetupArgs {
    /// Step name.
    pub step: String,
    /// Step arguments, passed through verbatim (e.g. `--tz Europe/Berlin`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// `talon audit` subcommands.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum AuditCommand {
    /// Recompute the hash chain; exit code 1 if it was tampered with.
    Verify,
    /// Print recent audit events (oldest first) as JSON lines.
    Tail {
        /// Number of events.
        #[arg(short = 'n', long = "lines", default_value_t = 50)]
        lines: usize,
        /// Only events whose kind starts with this prefix (e.g. `ipc.`).
        #[arg(long)]
        kind: Option<String>,
    },
}

impl Cli {
    /// The subcommand to run (`run` when none was given).
    pub fn command(&self) -> &Command {
        self.command.as_ref().unwrap_or(&Command::Run)
    }

    /// Project root: `--project-root`, `TALON_PROJECT_ROOT`, else the
    /// current directory.
    pub fn resolve_project_root(&self) -> std::io::Result<PathBuf> {
        match &self.project_root {
            Some(p) if p.is_absolute() => Ok(p.clone()),
            Some(p) => Ok(std::env::current_dir()?.join(p)),
            None => std::env::current_dir(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn defaults_to_run() {
        let cli = parse(&["talon"]);
        assert_eq!(cli.command(), &Command::Run);
        assert_eq!(parse(&["talon", "run"]).command(), &Command::Run);
    }

    #[test]
    fn setup_passes_hyphenated_args_through() {
        let cli = parse(&[
            "talon",
            "setup",
            "timezone",
            "--tz",
            "Europe/Berlin",
            "--force",
        ]);
        assert_eq!(
            cli.command(),
            &Command::Setup(SetupArgs {
                step: "timezone".into(),
                args: vec!["--tz".into(), "Europe/Berlin".into(), "--force".into()],
            })
        );
    }

    #[test]
    fn audit_subcommands() {
        assert_eq!(
            parse(&["talon", "audit", "verify"]).command(),
            &Command::Audit {
                command: AuditCommand::Verify
            }
        );
        assert_eq!(
            parse(&["talon", "audit", "tail", "-n", "5", "--kind", "ipc."]).command(),
            &Command::Audit {
                command: AuditCommand::Tail {
                    lines: 5,
                    kind: Some("ipc.".into())
                }
            }
        );
        assert_eq!(
            parse(&["talon", "audit", "tail"]).command(),
            &Command::Audit {
                command: AuditCommand::Tail {
                    lines: 50,
                    kind: None
                }
            }
        );
    }

    #[test]
    fn project_root_flag_is_global() {
        let cli = parse(&["talon", "doctor", "--project-root", "/srv/talon"]);
        assert_eq!(cli.command(), &Command::Doctor);
        assert_eq!(
            cli.resolve_project_root().unwrap(),
            PathBuf::from("/srv/talon")
        );
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert!(Cli::try_parse_from(["talon", "frobnicate"]).is_err());
    }
}
