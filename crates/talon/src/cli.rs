//! Command-line interface (`clap` derive).

use std::path::PathBuf;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};

/// Make every argument that reads a `TALAHON_*` variable read its
/// pre-rename `TALON_*` name instead when `legacy_in_use` says only that one
/// is set (`clap` knows no alias for `env`). Applied to subcommands too.
pub fn with_legacy_env(
    cmd: clap::Command,
    legacy_in_use: &dyn Fn(&str) -> Option<String>,
) -> clap::Command {
    cmd.mut_args(|arg| {
        match arg
            .get_env()
            .and_then(|key| key.to_str())
            .and_then(legacy_in_use)
        {
            // `clap` wants a `'static` name; one short string per aliased
            // variable for the life of the process.
            Some(legacy) => arg.env(&*Box::leak(legacy.into_boxed_str())),
            None => arg,
        }
    })
    .mut_subcommands(|sub| with_legacy_env(sub, legacy_in_use))
}

/// `talahon` — automated AI SOC analyst for CoPilot.
#[derive(Debug, Parser)]
#[command(name = "talahon", version, about, long_about = None)]
pub struct Cli {
    /// Talahon project directory (holds `.env`, `groups/`, `store/`, `data/`).
    /// Defaults to the current directory.
    #[arg(long, global = true, env = "TALAHON_PROJECT_ROOT", value_name = "DIR")]
    pub project_root: Option<PathBuf>,

    /// Subcommand; `run` when omitted.
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// [`Parser::parse`] that also honours the `TALON_*` spelling of the
    /// environment variables behind the arguments (see [`with_legacy_env`]).
    pub fn parse_with_legacy_env() -> Self {
        let cmd = with_legacy_env(
            <Self as CommandFactory>::command(),
            &talon_core::env::legacy_process_key_in_use,
        );
        let matches = cmd.get_matches();
        Self::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
    }
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
    /// running Talahon.
    Eval {
        /// Eval subcommand.
        #[command(subcommand)]
        command: EvalCommand,
    },
    /// Print the version.
    Version,
}

/// `talahon eval` subcommands.
#[derive(Debug, Subcommand, PartialEq)]
pub enum EvalCommand {
    /// Offline: score already-produced reports (`<case id>.json`) against
    /// the golden cases. Exit code 1 when the pass rate is below
    /// `--min-pass-rate`, 2 on unusable input.
    Score(EvalScoreArgs),
    /// Online: submit every golden case to a running Talahon
    /// (`POST /investigate`), wait for each verdict, then score. The
    /// case's alert must already exist in the CoPilot stack Talahon is
    /// connected to.
    Run(EvalRunArgs),
}

/// Options shared by the `talahon eval` modes.
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

/// Arguments of `talahon eval score`.
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

/// Arguments of `talahon eval run`.
#[derive(Debug, Args, PartialEq)]
pub struct EvalRunArgs {
    /// Base URL of the Talahon HTTP API (default:
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
    /// form `talahon eval score --reports <DIR>` reads.
    #[arg(long, value_name = "DIR")]
    pub save_dir: Option<PathBuf>,
    /// Score the existing job when Talahon de-duplicates a trigger instead of
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

/// Arguments of `talahon setup`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct SetupArgs {
    /// Step name.
    pub step: String,
    /// Step arguments, passed through verbatim (e.g. `--tz Europe/Berlin`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// `talahon audit` subcommands.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum AuditCommand {
    /// Verify the chain (and, with `TALAHON_AUDIT_KEY`, its MACs and the
    /// truncation checkpoint); exit code 1 if anything does not verify.
    Verify,
    /// Print the newest row's id, hash and sequence number, for anchoring
    /// the chain on a system this host cannot write.
    Head,
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

    /// Project root: `--project-root`, `TALAHON_PROJECT_ROOT`, else the
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
    fn env_backed_arguments_read_the_old_name_when_only_that_is_set() {
        let env_of = |cmd: &clap::Command| {
            cmd.get_arguments()
                .find(|a| a.get_id() == "project_root")
                .and_then(|a| a.get_env())
                .and_then(|e| e.to_str())
                .map(str::to_string)
        };
        // Nothing set under the old name: the argument keeps its variable.
        let cmd = with_legacy_env(<Cli as CommandFactory>::command(), &|_| None);
        assert_eq!(env_of(&cmd).as_deref(), Some("TALAHON_PROJECT_ROOT"));
        // Only TALON_PROJECT_ROOT is set: that is what the argument reads.
        let asked = std::sync::Mutex::new(Vec::new());
        let cmd = with_legacy_env(<Cli as CommandFactory>::command(), &|key| {
            asked.lock().unwrap().push(key.to_string());
            talon_core::env::legacy_key(key)
        });
        assert_eq!(env_of(&cmd).as_deref(), Some("TALON_PROJECT_ROOT"));
        assert!(
            asked
                .lock()
                .unwrap()
                .contains(&"TALAHON_PROJECT_ROOT".to_string())
        );
        // Subcommands are still intact.
        assert!(cmd.get_subcommands().any(|c| c.get_name() == "doctor"));
    }

    #[test]
    fn defaults_to_run() {
        let cli = parse(&["talahon"]);
        assert_eq!(cli.command(), &Command::Run);
        assert_eq!(parse(&["talahon", "run"]).command(), &Command::Run);
    }

    #[test]
    fn setup_passes_hyphenated_args_through() {
        let cli = parse(&[
            "talahon",
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
            parse(&["talahon", "audit", "verify"]).command(),
            &Command::Audit {
                command: AuditCommand::Verify
            }
        );
        assert_eq!(
            parse(&["talahon", "audit", "head"]).command(),
            &Command::Audit {
                command: AuditCommand::Head
            }
        );
        assert_eq!(
            parse(&["talahon", "audit", "tail", "-n", "5", "--kind", "ipc."]).command(),
            &Command::Audit {
                command: AuditCommand::Tail {
                    lines: 5,
                    kind: Some("ipc.".into())
                }
            }
        );
        assert_eq!(
            parse(&["talahon", "audit", "tail"]).command(),
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
        }) = parse(&["talahon", "eval", "score", "--reports", "out"]).command
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
            "talahon",
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
            &["talahon", "eval"],
            &["talahon", "eval", "score"],
            &[
                "talahon",
                "eval",
                "score",
                "--reports",
                "o",
                "--min-pass-rate",
                "1.5",
            ],
            &[
                "talahon",
                "eval",
                "score",
                "--reports",
                "o",
                "--min-pass-rate",
                "NaN",
            ],
            &["talahon", "eval", "run", "--timeout-secs", "0"],
        ];
        for args in bad {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn project_root_flag_is_global() {
        let cli = parse(&["talahon", "doctor", "--project-root", "/srv/talahon"]);
        assert_eq!(cli.command(), &Command::Doctor);
        assert_eq!(
            cli.resolve_project_root().unwrap(),
            PathBuf::from("/srv/talahon")
        );
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert!(Cli::try_parse_from(["talahon", "frobnicate"]).is_err());
    }
}
