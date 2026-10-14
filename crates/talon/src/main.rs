//! `talon` host binary. See the library docs (`talon` crate) for the
//! architecture; this file only parses the command line, sets up logging
//! and dispatches.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use talon::cli::{AuditCommand, Cli, Command};
use talon::logging::{self, LogFormat, LogTarget};
use talon_core::config::TalonConfig;
use talon_core::env::EnvFile;

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// Load `.env`, install logging (redacting, format from
/// `TALON_LOG_FORMAT`) and resolve the configuration.
fn bootstrap(
    root: &Path,
    target: LogTarget,
    default_filter: &str,
) -> (Arc<TalonConfig>, Arc<talon_security::redact::Redactor>) {
    let env = EnvFile::load(root);
    let format = LogFormat::parse(env.get("TALON_LOG_FORMAT").as_deref());
    let redactor = talon::secrets::redactor_for(&env);
    logging::init(format, target, default_filter, redactor.clone());
    (Arc::new(TalonConfig::from_env(root, env)), redactor)
}

async fn dispatch(cli: Cli, root: PathBuf) -> i32 {
    match cli.command() {
        Command::Version => {
            println!("talon {}", talon::VERSION);
            0
        }
        Command::Run => {
            let (config, redactor) = bootstrap(&root, LogTarget::Stdout, "info");
            match talon::app::run(config, redactor).await {
                Ok(()) => 0,
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "Failed to start Talon");
                    1
                }
            }
        }
        Command::Setup(args) => {
            let _ = bootstrap(&root, LogTarget::Stderr, "info");
            let ctx = talon_setup::SetupContext::detect(&root);
            match talon_setup::run_step_by_name(&args.step, &args.args, &ctx).await {
                Ok(outcome) => {
                    println!("{}", outcome.render());
                    outcome.exit_code
                }
                Err(unknown) => {
                    eprintln!("{unknown}");
                    1
                }
            }
        }
        Command::Doctor => {
            let (config, _) = bootstrap(&root, LogTarget::Stderr, "warn");
            talon::doctor::run(&root, &config).await
        }
        Command::Audit { command } => {
            let (config, _) = bootstrap(&root, LogTarget::Stderr, "warn");
            let result = match command {
                AuditCommand::Verify => talon::audit_cmd::verify(&config),
                AuditCommand::Tail { lines, kind } => {
                    talon::audit_cmd::tail(&config, *lines, kind.as_deref())
                }
            };
            result.unwrap_or_else(|e| {
                eprintln!("talon audit: {e:#}");
                1
            })
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = match cli.resolve_project_root() {
        Ok(root) => root,
        Err(e) => {
            eprintln!("talon: cannot determine the project directory: {e}");
            return ExitCode::from(1);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("talon")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("talon: cannot start the async runtime: {e}");
            return ExitCode::from(1);
        }
    };
    exit_code(runtime.block_on(dispatch(cli, root)))
}
