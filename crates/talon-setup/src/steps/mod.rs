//! The setup steps (one module each) and the
//! dispatcher the host CLI (`talon setup <step> [args...]`) calls.

pub mod container;
pub mod egress;
pub mod environment;
pub mod groups;
pub mod mounts;
pub mod register;
pub mod service;
pub mod timezone;
pub mod verify;
pub mod vllm;

use crate::context::{SETUP_LOG, SetupContext};
use crate::status::{StatusBlock, StepOutcome};

/// Command-line arguments of one step (`--flag`, `--key value`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepArgs {
    args: Vec<String>,
}

impl StepArgs {
    /// Wrap raw arguments; bare `--` separators are dropped (so
    /// `--step x -- --flag` is accepted).
    pub fn new<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            args: args
                .into_iter()
                .map(Into::into)
                .filter(|a| a != "--")
                .collect(),
        }
    }

    /// `--name` is present.
    pub fn flag(&self, name: &str) -> bool {
        self.args.iter().any(|a| a == name)
    }

    /// The argument following the first `--name`, if any.
    pub fn value(&self, name: &str) -> Option<&str> {
        let idx = self.args.iter().position(|a| a == name)?;
        self.args.get(idx + 1).map(String::as_str)
    }

    /// The argument following every occurrence of `--name` (repeatable
    /// options such as `--allow`).
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == name)
            .filter_map(|(i, _)| self.args.get(i + 1).map(String::as_str))
            .collect()
    }

    /// Raw arguments.
    pub fn raw(&self) -> &[String] {
        &self.args
    }
}

/// A setup step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// Detect / persist the timezone (`TIMEZONE`).
    Timezone,
    /// Environment report (`CHECK_ENVIRONMENT`).
    Environment,
    /// vLLM reachability + model check (`CHECK_VLLM`).
    Vllm,
    /// Build + smoke-test the agent image (`SETUP_CONTAINER`).
    Container,
    /// Chat/group discovery and listing (`SYNC_GROUPS`).
    Groups,
    /// Register a chat as a group (`REGISTER_CHANNEL`).
    Register,
    /// Write the mount allowlist (`CONFIGURE_MOUNTS`).
    Mounts,
    /// Generate / apply the agent-network firewall (`SETUP_EGRESS`).
    Egress,
    /// Install the systemd / launchd service (`SETUP_SERVICE`).
    Service,
    /// End-to-end health report (`VERIFY`).
    Verify,
}

impl Step {
    /// All steps in the order the setup skill runs them.
    pub const ALL: [Step; 10] = [
        Step::Timezone,
        Step::Environment,
        Step::Vllm,
        Step::Container,
        Step::Groups,
        Step::Register,
        Step::Mounts,
        Step::Egress,
        Step::Service,
        Step::Verify,
    ];

    /// CLI name (`environment`, `vllm`, ...).
    pub fn name(&self) -> &'static str {
        match self {
            Step::Timezone => "timezone",
            Step::Environment => "environment",
            Step::Vllm => "vllm",
            Step::Container => "container",
            Step::Groups => "groups",
            Step::Register => "register",
            Step::Mounts => "mounts",
            Step::Egress => "egress",
            Step::Service => "service",
            Step::Verify => "verify",
        }
    }

    /// Parse a CLI name.
    pub fn parse(name: &str) -> Option<Step> {
        Step::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Comma-separated list of step names (usage text).
    pub fn names() -> String {
        Step::ALL.map(|s| s.name()).join(", ")
    }
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Run `step`. Internal errors become a `<STEP>` block with
/// `STATUS: failed` and exit code 1.
pub async fn run_step(step: Step, args: &StepArgs, ctx: &SetupContext) -> StepOutcome {
    let result = match step {
        Step::Timezone => timezone::run(args, ctx).await,
        Step::Environment => environment::run(args, ctx).await,
        Step::Vllm => vllm::run(args, ctx).await,
        Step::Container => container::run(args, ctx).await,
        Step::Groups => groups::run(args, ctx).await,
        Step::Register => register::run(args, ctx).await,
        Step::Mounts => mounts::run(args, ctx).await,
        Step::Egress => egress::run(args, ctx).await,
        Step::Service => service::run(args, ctx).await,
        Step::Verify => verify::run(args, ctx).await,
    };
    match result {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(step = %step, error = %e, "Setup step failed");
            StepOutcome::with_code(
                StatusBlock::new(step.name().to_uppercase())
                    .field("STATUS", "failed")
                    .field("ERROR", format!("{e:#}"))
                    .field("LOG", SETUP_LOG),
                1,
            )
        }
    }
}

/// Error returned by [`run_step_by_name`] for an unknown step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownStep(pub String);

impl std::fmt::Display for UnknownStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Unknown step: {}. Available steps: {}",
            self.0,
            Step::names()
        )
    }
}

impl std::error::Error for UnknownStep {}

/// Parse `name` and run it with raw `args`.
///
/// # Errors
/// [`UnknownStep`] when `name` is not a step.
pub async fn run_step_by_name(
    name: &str,
    args: &[String],
    ctx: &SetupContext,
) -> Result<StepOutcome, UnknownStep> {
    let step = Step::parse(name).ok_or_else(|| UnknownStep(name.to_string()))?;
    Ok(run_step(step, &StepArgs::new(args.iter().cloned()), ctx).await)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runner::mock::MockRunner;

    #[test]
    fn args_parsing() {
        let a = StepArgs::new(["--", "--tz", "Europe/Berlin", "--force"]);
        assert_eq!(a.value("--tz"), Some("Europe/Berlin"));
        assert!(a.flag("--force"));
        assert!(!a.flag("--empty"));
        assert_eq!(a.value("--force"), None);
        assert_eq!(a.raw().len(), 3);
    }

    #[test]
    fn repeated_values() {
        let a = StepArgs::new(["--allow", "10.0.0.1", "--apply", "--allow", "10.0.0.2"]);
        assert_eq!(a.values("--allow"), vec!["10.0.0.1", "10.0.0.2"]);
        assert!(a.values("--nope").is_empty());
        // A trailing option without a value contributes nothing.
        assert!(StepArgs::new(["--allow"]).values("--allow").is_empty());
    }

    #[test]
    fn step_names_round_trip() {
        for s in Step::ALL {
            assert_eq!(Step::parse(s.name()), Some(s));
        }
        assert_eq!(Step::parse("nope"), None);
        assert!(Step::names().contains("verify"));
        assert_eq!(Step::parse("egress"), Some(Step::Egress));
        assert_eq!(Step::Egress.to_string(), "egress");
        // Firewall setup runs before the service is installed.
        let pos = |s: Step| Step::ALL.iter().position(|x| *x == s).unwrap();
        assert!(pos(Step::Egress) < pos(Step::Service));
    }

    #[tokio::test]
    async fn unknown_step_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        let err = run_step_by_name("bogus", &[], &ctx).await.unwrap_err();
        assert!(err.to_string().contains("Unknown step: bogus"));
    }
}
