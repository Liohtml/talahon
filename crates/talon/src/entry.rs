//! Entry point shared by the `talahon` binary and its deprecated `talon`
//! alias: parse the command line, set up logging and dispatch.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use crate::cli::{AuditCommand, Cli, Command, EvalCommand};
use crate::logging::{self, LogFormat, LogTarget};
use talon_core::config::TalonConfig;
use talon_core::env::EnvFile;

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// How the binary was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokedAs {
    /// `talahon`.
    Current,
    /// The deprecated `talon` alias (the alias binary or a link named so).
    Legacy,
}

impl InvokedAs {
    /// From `argv[0]`: [`InvokedAs::Legacy`] when its file name is
    /// [`LEGACY_BINARY_NAME`] (with or without `.exe`).
    pub fn from_arg0(arg0: Option<&OsStr>) -> Self {
        let stem = arg0
            .map(Path::new)
            .and_then(Path::file_stem)
            .and_then(OsStr::to_str);
        if stem == Some(LEGACY_BINARY_NAME) {
            InvokedAs::Legacy
        } else {
            InvokedAs::Current
        }
    }
}

/// Name of the host binary.
pub const BINARY_NAME: &str = "talahon";
/// Its name up to 2.x, still installed as an alias for one major version.
pub const LEGACY_BINARY_NAME: &str = "talon";

/// The one-line notice for a start under the old name.
pub const LEGACY_NAME_NOTICE: &str = "talon: this command is now called `talahon`; the `talon` name is \
     deprecated and will be removed in the next major version";

/// Tell the operator once that `talon` is now `talahon`.
///
/// Called after logging is set up, and only by commands whose output is
/// read by people or goes to the service log: `version` (and clap's
/// `--help` / `--version`) print nothing extra, their stdout is what scripts
/// compare. With `TALAHON_LOG_FORMAT=json` the notice is a regular (JSON)
/// log record, so a consumer of the log stream never sees a foreign line;
/// otherwise it is one plain line on stderr.
fn legacy_name_notice(invoked: InvokedAs, format: LogFormat) {
    if invoked != InvokedAs::Legacy {
        return;
    }
    match format {
        LogFormat::Json => tracing::warn!(
            deprecated = LEGACY_BINARY_NAME,
            replacement = BINARY_NAME,
            "{LEGACY_NAME_NOTICE}"
        ),
        LogFormat::Pretty => eprintln!("{LEGACY_NAME_NOTICE}"),
    }
}

/// Load `.env`, install logging (redacting, format from
/// `TALAHON_LOG_FORMAT`) and resolve the configuration.
fn bootstrap(
    root: &Path,
    target: LogTarget,
    default_filter: &str,
    invoked: InvokedAs,
) -> (Arc<TalonConfig>, Arc<talon_security::redact::Redactor>) {
    let env = EnvFile::load(root);
    let format = LogFormat::parse(env.get("TALAHON_LOG_FORMAT").as_deref());
    let redactor = crate::secrets::redactor_for(&env);
    logging::init(format, target, default_filter, redactor.clone());
    legacy_name_notice(invoked, format);
    let config = Arc::new(TalonConfig::from_env(root, env));
    // Old `TALON_*` keys read before the logger existed are reported now;
    // later ones as they are first read.
    talon_core::env::flush_legacy_key_warnings();
    (config, redactor)
}

async fn dispatch(cli: Cli, root: PathBuf, invoked: InvokedAs) -> i32 {
    match cli.command() {
        Command::Version => {
            println!("{BINARY_NAME} {}", crate::VERSION);
            0
        }
        Command::Run => {
            let (config, redactor) = bootstrap(&root, LogTarget::Stdout, "info", invoked);
            match crate::app::run(config, redactor).await {
                Ok(()) => 0,
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "Failed to start Talahon");
                    1
                }
            }
        }
        Command::Setup(args) => {
            let _ = bootstrap(&root, LogTarget::Stderr, "info", invoked);
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
            let (config, _) = bootstrap(&root, LogTarget::Stderr, "warn", invoked);
            crate::doctor::run(&root, &config).await
        }
        Command::Eval { command } => {
            let (config, _) = bootstrap(&root, LogTarget::Stderr, "warn", invoked);
            match command {
                EvalCommand::Score(args) => crate::eval_cmd::score(&root, args),
                EvalCommand::Run(args) => crate::eval_cmd::run(&root, &config, args).await,
            }
        }
        Command::Audit { command } => {
            let (config, _) = bootstrap(&root, LogTarget::Stderr, "warn", invoked);
            let result = match command {
                AuditCommand::Verify => crate::audit_cmd::verify(&config),
                AuditCommand::Head => crate::audit_cmd::head(&config),
                AuditCommand::Tail { lines, kind } => {
                    crate::audit_cmd::tail(&config, *lines, kind.as_deref())
                }
            };
            result.unwrap_or_else(|e| {
                eprintln!("{BINARY_NAME} audit: {e:#}");
                1
            })
        }
    }
}

/// Entry point of the `talahon` binary and of its deprecated `talon` alias:
/// parse the command line, set up logging and dispatch. `alias` is what the
/// calling binary was built as; a link named `talon` counts as the alias too.
pub fn main(alias: InvokedAs) -> ExitCode {
    let invoked = match alias {
        InvokedAs::Legacy => InvokedAs::Legacy,
        InvokedAs::Current => InvokedAs::from_arg0(std::env::args_os().next().as_deref()),
    };
    let cli = Cli::parse_with_legacy_env();
    let root = match cli.resolve_project_root() {
        Ok(root) => root,
        Err(e) => {
            eprintln!("{BINARY_NAME}: cannot determine the project directory: {e}");
            return ExitCode::from(1);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("talahon")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{BINARY_NAME}: cannot start the async runtime: {e}");
            return ExitCode::from(1);
        }
    };
    exit_code(runtime.block_on(dispatch(cli, root, invoked)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_old_binary_name_is_recognised_from_arg0() {
        for legacy in ["talon", "/usr/local/bin/talon", "./talon", "talon.exe"] {
            assert_eq!(
                InvokedAs::from_arg0(Some(OsStr::new(legacy))),
                InvokedAs::Legacy,
                "{legacy}"
            );
        }
        for current in [
            "talahon",
            "/opt/talahon/bin/talahon",
            "/opt/talon/bin/talahon",
            "talon-agent",
            "",
        ] {
            assert_eq!(
                InvokedAs::from_arg0(Some(OsStr::new(current))),
                InvokedAs::Current,
                "{current}"
            );
        }
        assert_eq!(InvokedAs::from_arg0(None), InvokedAs::Current);
    }

    #[test]
    fn the_notice_is_one_line_and_names_both_commands() {
        assert_eq!(LEGACY_NAME_NOTICE.lines().count(), 1);
        assert!(LEGACY_NAME_NOTICE.contains("`talahon`"));
        assert!(LEGACY_NAME_NOTICE.contains("`talon`"));
        assert!(LEGACY_NAME_NOTICE.contains("next major version"));
    }
}
