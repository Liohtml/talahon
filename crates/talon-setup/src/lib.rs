//! # talon-setup — install, verify and service management
//!
//! **Owner: agent A11.** See `docs/RUST_ARCHITECTURE.md` §A11.
//!
//! Library behind `talon setup <step> [args...]` (port of `setup/*.ts`).
//! Every step prints one machine-readable status block (see [`status`]) that
//! the setup skill parses, and returns an exit code:
//!
//! | step          | block               | purpose                                              |
//! |---------------|---------------------|------------------------------------------------------|
//! | `timezone`    | `TIMEZONE`          | resolve + persist `TZ`                               |
//! | `environment` | `CHECK_ENVIRONMENT` | runtime, image, vLLM, gateway port, dirs, disk       |
//! | `vllm`        | `CHECK_VLLM`        | `GET <base>/v1/models`, model served                 |
//! | `container`   | `SETUP_CONTAINER`   | build + smoke-test the agent image                   |
//! | `groups`      | `SYNC_GROUPS`       | chat discovery report, `--list`                      |
//! | `register`    | `REGISTER_CHANNEL`  | register a chat, create its folder / `CLAUDE.md`     |
//! | `mounts`      | `CONFIGURE_MOUNTS`  | write the mount allowlist                            |
//! | `service`     | `SETUP_SERVICE`     | systemd (hardened) / launchd / nohup                 |
//! | `verify`      | `VERIFY`            | end-to-end health                                    |
//!
//! Host usage:
//!
//! ```no_run
//! # async fn demo(project_root: &std::path::Path, step: &str, args: &[String]) {
//! let ctx = talon_setup::SetupContext::detect(project_root);
//! match talon_setup::run_step_by_name(step, args, &ctx).await {
//!     Ok(outcome) => {
//!         println!("{}", outcome.render());
//!         std::process::exit(outcome.exit_code);
//!     }
//!     Err(unknown) => {
//!         eprintln!("{unknown}");
//!         std::process::exit(1);
//!     }
//! }
//! # }
//! ```
//!
//! External commands go through [`CommandRunner`] (argv only, never a
//! shell) so every step is unit-testable; secrets (`TALON_VLLM_API_KEY`,
//! channel tokens) are used but never printed.

#![warn(missing_docs)]

pub mod checks;
pub mod context;
pub mod fsutil;
pub mod platform;
pub mod runner;
pub mod status;
pub mod steps;

pub use checks::{VllmCheck, VllmStatus, check_vllm, models_url};
pub use context::{SETUP_LOG, SetupContext, StdinSource};
pub use platform::{Platform, PlatformInfo, ServiceManager};
pub use runner::{CommandOutput, CommandRunner, CommandSpec, SystemCommandRunner};
pub use status::{StatusBlock, StepOutcome, parse_status_blocks};
pub use steps::service::{Hardening, ServiceSpec, launchd_plist, nohup_wrapper, systemd_unit};
pub use steps::{Step, StepArgs, UnknownStep, run_step, run_step_by_name};
