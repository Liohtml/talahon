//! # talon-container — hardened container runtime
//!
//! **Owner: agent A08.** See `docs/RUST_ARCHITECTURE.md` §A08 and §3.3.
//!
//! Host-side launcher for the per-run agent container:
//!
//! - [`runtime`]: docker/podman detection, `ensure_running`, orphan cleanup
//!   by the `talon.managed=true` label, `stop` / `kill`, host-gateway args and
//!   [`runtime::detect_gateway_bind_addr`] for the LLM gateway.
//! - [`mounts`]: bind-mount construction (group rw, global ro, project ro
//!   with `.env*` shadowed, sessions at `/home/agent/.talon`, IPC, allowlisted
//!   extras refused near host secrets and scanned for credential files,
//!   per-MCP secret staging + shadowing by canonical host path, read-only
//!   `.mcp.json`, `CLAUDE.md` and `prompts/`, symlinked lane directories
//!   refused).
//! - [`palace`]: the hardened one-shot `run` for host-side MemPalace calls.
//! - [`args`]: the hardened `run` argument vector of §3.3 (capabilities,
//!   read-only rootfs, tmpfs, limits, env overlay without secrets, blocked
//!   hosts).
//! - [`parser`]: incremental, injection-proof stdout frame parser.
//! - [`process`]: injectable process-spawn layer (fakes in tests).
//! - [`runner`]: [`runner::ContainerRunner`] — spawn, stdin input, frame
//!   streaming, timeouts, graceful stop / kill, exit mapping, audit, run logs
//!   and the [`runner::ContainerHandle`] for the group queue.
//! - [`snapshot`]: atomic `current_tasks.json` / `available_groups.json`
//!   (per-lane task filtering via [`snapshot::write_lane_tasks_snapshot`]).
//! - [`policy`]: narrow seams over `talon-security` (mount validator,
//!   redactor).
//!
//! The image side (`container/Dockerfile`, `container/entrypoint.sh`,
//! `container/build.sh`) and the MCP wrapper scripts implement the other half
//! of the §3.3 contract.

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod args;
pub mod mounts;
pub mod palace;
pub mod parser;
pub mod policy;
pub mod process;
pub mod runner;
pub mod runtime;
pub mod snapshot;

pub use args::{ResourceLimits, RunAs, build_run_args, container_name};
pub use mounts::{
    GROUP_INSTRUCTIONS_FILE, GROUP_MEMORY_FILE, GROUP_PROMPTS_DIR, ISOLATED_MCPS, MountLayout,
    MountOptions, MountRequest, SecretScanLimits, VolumeMount, build_mounts,
};
pub use palace::{MCP_PALACE_GID, MCP_PALACE_UID, PalaceRunSpec, build_palace_run_args};
pub use parser::{OutputParser, ParseEvent};
pub use policy::{DenyAllMounts, LogRedactor, MountPolicy};
pub use process::{ProcessSpawner, TokioProcessSpawner};
pub use runner::{
    ContainerHandle, ContainerRunner, MAX_SESSION_ID_BYTES, OutputHandler, PreparedRun, RunOutcome,
    RunResult, RunSpec, RunnerConfig, StartError, StartedContainer, is_valid_session_id,
    noop_handler,
};
pub use runtime::{
    AGENT_NETWORK, ContainerRuntime, HostPlatform, RuntimeKind, detect_gateway_bind_addr,
};
pub use snapshot::{write_groups_snapshot, write_lane_tasks_snapshot, write_tasks_snapshot};
