//! Command-line interface (`clap` derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// `talon` — automated AI SOC analyst for CoPilot.
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
#[derive(Debug, Subcommand, PartialEq)]
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
    /// Score investigation quality against the golden set
    /// (`evals/golden/`): offline from saved reports, or online through a
    /// running Talon.
    Eval {
        /// Eval subcommand.
        #[command(subcommand)]
        command: EvalCommand,
    },
    /// Print the version.
    Version,
}

/// `talon eval` subcommands.
#[derive(Debug, Subcommand, PartialEq)]
pub enum EvalCommand {
    /// Offline: score already-produced reports (`<case id>.json`) against
    /// the golden cases. Exit code 1 when the pass rate is below
    /// `--min-pass-rate`, 2 on unusable input.
    Score(EvalScoreArgs),
    /// Online: submit every golden case to a running Talon
    /// (`POST /investigate`), wait for each verdict, then score. The
    /// case's alert must already exist in the CoPilot stack Talon is
    /// connected to.
    Run(EvalRunArgs),
}

/// Options shared by the `talon eval` modes.
#[derive(Debug, Args, PartialEq)]
pub struct EvalCommonArgs {
    /// Directory of golden case files (default: `<project root>/evals/golden`).
    #[arg(long, value_name = "DIR")]
    pub cases: Option<PathBuf>,
    /// Print the summary as JSON instead of a table.
    #[arg(long)]
    pub json: bool,
    /// Lowest acceptable fraction of passing cases, `0.0`–`1.0`.
    #[arg(long, value_name = "FRACTION", default_value_t = 1.0, value_parser = parse_pass_rate)]
    pub min_pass_rate: f64,
}

/// Arguments of `talon eval score`.
#[derive(Debug, Args, PartialEq)]
pub struct EvalScoreArgs {
    /// Directory holding one `<case id>.json` per case: a triage report, or
    /// an investigation record as returned by `GET /investigations/{id}`.
    #[arg(long, value_name = "DIR")]
    pub reports: PathBuf,
    /// Shared options.
    #[command(flatten)]
    pub common: EvalCommonArgs,
}

/// Arguments of `talon eval run`.
#[derive(Debug, Args, PartialEq)]
pub struct EvalRunArgs {
    /// Base URL of the Talon HTTP API (default:
    /// `http://<COPILOT_HTTP_BIND>:<COPILOT_HTTP_PORT>` from the project's
    /// `.env`). The API key is always `HTTP_API_KEY` from `.env`.
    #[arg(long, value_name = "URL")]
    pub url: Option<String>,
    /// Seconds to wait for each investigation's verdict.
    #[arg(long, value_name = "SECONDS", default_value_t = 900, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_secs: u64,
    /// Seconds between status polls.
    #[arg(long, value_name = "SECONDS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..))]
    pub poll_secs: u64,
    /// JSON file mapping case ids to the alert ids they are seeded under
    /// in the target stack (`{"<case id>": 4711, ...}`); overrides the
    /// case's `request.alert_id`.
    #[arg(long, value_name = "FILE")]
    pub alert_map: Option<PathBuf>,
    /// Customer code to submit instead of each case's
    /// `request.customer_code`.
    #[arg(long, value_name = "CODE")]
    pub customer_code: Option<String>,
    /// Write each investigation record to `<DIR>/<case id>.json`, in the
    /// form `talon eval score --reports <DIR>` reads.
    #[arg(long, value_name = "DIR")]
    pub save_dir: Option<PathBuf>,
    /// Score the existing job when Talon de-duplicates a trigger instead of
    /// failing the case (the verdict may predate the change under test).
    #[arg(long)]
    pub allow_deduplicated: bool,
    /// Shared options.
    #[command(flatten)]
    pub common: EvalCommonArgs,
}

fn parse_pass_rate(raw: &str) -> Result<f64, String> {
    match raw.trim().parse::<f64>() {
        Ok(v) if (0.0..=1.0).contains(&v) => Ok(v),
        _ => Err("expected a fraction between 0.0 and 1.0".to_string()),
    }
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
    fn eval_subcommands() {
        let Some(Command::Eval {
            command: EvalCommand::Score(score),
        }) = parse(&["talon", "eval", "score", "--reports", "out"]).command
        else {
            panic!("expected eval score");
        };
        assert_eq!(score.reports, PathBuf::from("out"));
        assert_eq!(score.common.cases, None);
        assert!(!score.common.json);
        assert!((score.common.min_pass_rate - 1.0).abs() < f64::EPSILON);

        let Some(Command::Eval {
            command: EvalCommand::Run(run),
        }) = parse(&[
            "talon",
            "eval",
            "run",
            "--cases",
            "c",
            "--json",
            "--min-pass-rate",
            "0.8",
            "--timeout-secs",
            "60",
            "--alert-map",
            "map.json",
            "--allow-deduplicated",
        ])
        .command
        else {
            panic!("expected eval run");
        };
        assert_eq!(run.common.cases, Some(PathBuf::from("c")));
        assert!(run.common.json && run.allow_deduplicated);
        assert!((run.common.min_pass_rate - 0.8).abs() < f64::EPSILON);
        assert_eq!((run.timeout_secs, run.poll_secs), (60, 5));
        assert_eq!(run.alert_map, Some(PathBuf::from("map.json")));
        assert_eq!(
            (run.url, run.save_dir, run.customer_code),
            (None, None, None)
        );

        let bad: [&[&str]; 5] = [
            &["talon", "eval"],
            &["talon", "eval", "score"],
            &[
                "talon",
                "eval",
                "score",
                "--reports",
                "o",
                "--min-pass-rate",
                "1.5",
            ],
            &[
                "talon",
                "eval",
                "score",
                "--reports",
                "o",
                "--min-pass-rate",
                "NaN",
            ],
            &["talon", "eval", "run", "--timeout-secs", "0"],
        ];
        for args in bad {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
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
