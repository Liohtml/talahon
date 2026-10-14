//! Runtime configuration: filesystem layout, loop limits, and the CLI/env
//! interface of the `talon-agent` binary.
//!
//! Every path defaults to its container location
//! (`talon_core::protocol::container_paths`) and can be overridden by a flag
//! or an environment variable (tests, dev mode):
//!
//! | flag | env | default |
//! |------|-----|---------|
//! | `--group-dir` | `TALON_AGENT_GROUP_DIR` | `/workspace/group` |
//! | `--global-dir` | `TALON_AGENT_GLOBAL_DIR` | `/workspace/global` |
//! | `--project-dir` | `TALON_AGENT_PROJECT_DIR` | `/workspace/project` |
//! | `--extra-dir` | `TALON_AGENT_EXTRA_DIR` | `/workspace/extra` |
//! | `--ipc-dir` | `TALON_AGENT_IPC_DIR` | `/workspace/ipc` |
//! | `--state-dir` | `TALON_AGENT_STATE_DIR` | `/home/agent/.talon` |
//! | `--mcp-config` | `TALON_AGENT_MCP_CONFIG` | `<group-dir>/.mcp.json` |
//! | `--mcp-socket-dir` | `TALON_MCP_SOCKET_DIR` | unset (spawn MCP servers directly) |
//! | `--max-iterations` | `TALON_AGENT_MAX_ITERATIONS` | `50` |
//! | `--self-check` | `TALON_AGENT_SELF_CHECK` | `true` |
//! | `--compact-threshold` | `TALON_AGENT_COMPACT_THRESHOLD` | `0.75` |
//! | `--ipc-poll-ms` | `TALON_AGENT_IPC_POLL_MS` | `500` |
//! | `--tool-timeout-secs` | `TALON_AGENT_TOOL_TIMEOUT_SECS` | `900` |
//! | `--max-input-bytes` | `TALON_AGENT_MAX_INPUT_BYTES` | 16 MiB |

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::builder::BoolishValueParser;
use talon_core::protocol::container_paths;

use crate::wire::DEFAULT_MAX_INPUT_BYTES;

/// Where things live inside the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPaths {
    /// The group folder (cwd, writable, persistent).
    pub group: PathBuf,
    /// Shared read-only global memory.
    pub global: PathBuf,
    /// Project root (main group only, read-only).
    pub project: PathBuf,
    /// Additional mounts root.
    pub extra: PathBuf,
    /// IPC namespace root (`input/`, `messages/`, `tasks/`, snapshots).
    pub ipc: PathBuf,
    /// Per-lane persistent agent state (`sessions/` and `conversations/`
    /// live here).
    pub state: PathBuf,
    /// The group's MCP server definitions.
    pub mcp_config: PathBuf,
}

impl Default for AgentPaths {
    fn default() -> Self {
        Self {
            group: PathBuf::from(container_paths::GROUP),
            global: PathBuf::from(container_paths::GLOBAL),
            project: PathBuf::from(container_paths::PROJECT),
            extra: PathBuf::from(container_paths::EXTRA),
            ipc: PathBuf::from(container_paths::IPC),
            state: PathBuf::from(container_paths::AGENT_STATE),
            mcp_config: PathBuf::from(container_paths::MCP_JSON),
        }
    }
}

impl AgentPaths {
    /// The container layout re-rooted under `root` (`<root>/group`,
    /// `<root>/global`, ...). Used by tests and dev setups.
    pub fn under(root: &Path) -> Self {
        let group = root.join("group");
        Self {
            mcp_config: group.join(".mcp.json"),
            group,
            global: root.join("global"),
            project: root.join("project"),
            extra: root.join("extra"),
            ipc: root.join("ipc"),
            state: root.join("state"),
        }
    }

    /// `<state>/sessions` — one `<uuid>.jsonl` per session.
    pub fn sessions_dir(&self) -> PathBuf {
        self.state.join("sessions")
    }

    /// `<ipc>/input` — follow-up messages and the `_close` sentinel.
    pub fn ipc_input(&self) -> PathBuf {
        self.ipc.join("input")
    }

    /// `<state>/conversations` — Markdown archives written before
    /// compaction. Lives in the per-lane state mount (never the group
    /// folder, which every lane on the folder shares), mode 0700.
    pub fn conversations(&self) -> PathBuf {
        self.state.join("conversations")
    }

    /// `<group>/MEMORY.md` — the agent-writable group notes (loaded fenced
    /// into the first user message of each run).
    pub fn memory(&self) -> PathBuf {
        self.group.join(crate::prompt::MEMORY_FILE)
    }
}

/// Limits and switches of the agent loop.
#[derive(Debug, Clone, PartialEq)]
pub struct LoopSettings {
    /// Model calls with tools per turn before a final, tool-less answer is
    /// forced.
    pub max_iterations: u32,
    /// Identical tool call (name + arguments) count that triggers a nudge.
    pub loop_nudge_at: u32,
    /// Identical tool call count that stops the turn.
    pub loop_stop_at: u32,
    /// Compact when the prompt exceeds this fraction of the context window.
    pub compact_ratio: f64,
    /// User turns kept verbatim by automatic compaction.
    pub keep_recent_turns: usize,
    /// Verify the final answer of investigations against tool evidence.
    pub self_check: bool,
    /// Safety-net timeout for a single tool call.
    pub tool_timeout: Duration,
    /// IPC input polling interval while idle.
    pub ipc_poll: Duration,
}

impl Default for LoopSettings {
    fn default() -> Self {
        Self {
            max_iterations: 50,
            loop_nudge_at: 3,
            loop_stop_at: 5,
            compact_ratio: 0.75,
            keep_recent_turns: 2,
            self_check: true,
            tool_timeout: Duration::from_secs(900),
            ipc_poll: Duration::from_millis(500),
        }
    }
}

/// Everything `talon-agent run` needs besides the `ContainerInput`.
#[derive(Debug, Clone, PartialEq)]
pub struct RunConfig {
    /// Filesystem layout.
    pub paths: AgentPaths,
    /// Loop limits.
    pub settings: LoopSettings,
    /// Connect to MCP servers exposed by the supervisor here; `None` = spawn
    /// them as children (dev / degraded mode).
    pub mcp_socket_dir: Option<PathBuf>,
    /// Upper bound for the stdin input.
    pub max_input_bytes: usize,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            paths: AgentPaths::default(),
            settings: LoopSettings::default(),
            mcp_socket_dir: None,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
        }
    }
}

/// CLI/env options of `talon-agent run` (also accepted by `supervise`).
#[derive(Debug, Clone, clap::Args)]
pub struct RunArgs {
    /// Group folder (cwd of the agent and its tools).
    #[arg(long, env = "TALON_AGENT_GROUP_DIR", default_value = container_paths::GROUP)]
    pub group_dir: PathBuf,
    /// Shared global memory (read-only).
    #[arg(long, env = "TALON_AGENT_GLOBAL_DIR", default_value = container_paths::GLOBAL)]
    pub global_dir: PathBuf,
    /// Project root (main group only, read-only).
    #[arg(long, env = "TALON_AGENT_PROJECT_DIR", default_value = container_paths::PROJECT)]
    pub project_dir: PathBuf,
    /// Additional mounts root.
    #[arg(long, env = "TALON_AGENT_EXTRA_DIR", default_value = container_paths::EXTRA)]
    pub extra_dir: PathBuf,
    /// IPC namespace root.
    #[arg(long, env = "TALON_AGENT_IPC_DIR", default_value = container_paths::IPC)]
    pub ipc_dir: PathBuf,
    /// Persistent per-lane agent state (sessions, conversation archives).
    #[arg(long, env = "TALON_AGENT_STATE_DIR", default_value = container_paths::AGENT_STATE)]
    pub state_dir: PathBuf,
    /// MCP server definitions (default `<group-dir>/.mcp.json`).
    #[arg(long, env = "TALON_AGENT_MCP_CONFIG")]
    pub mcp_config: Option<PathBuf>,
    /// Unix-socket directory of supervisor-managed MCP servers.
    #[arg(long, env = "TALON_MCP_SOCKET_DIR")]
    pub mcp_socket_dir: Option<PathBuf>,
    /// Tool-calling iterations per turn before a final answer is forced.
    #[arg(long, env = "TALON_AGENT_MAX_ITERATIONS", default_value_t = 50)]
    pub max_iterations: u32,
    /// Self-check pass for investigation answers.
    #[arg(long, env = "TALON_AGENT_SELF_CHECK", default_value_t = true, value_parser = BoolishValueParser::new(), action = clap::ArgAction::Set)]
    pub self_check: bool,
    /// Compaction threshold as a fraction of the context window (0.3 - 0.95).
    #[arg(long, env = "TALON_AGENT_COMPACT_THRESHOLD", default_value_t = 0.75)]
    pub compact_threshold: f64,
    /// IPC polling interval in milliseconds.
    #[arg(long, env = "TALON_AGENT_IPC_POLL_MS", default_value_t = 500)]
    pub ipc_poll_ms: u64,
    /// Safety-net timeout per tool call, seconds.
    #[arg(long, env = "TALON_AGENT_TOOL_TIMEOUT_SECS", default_value_t = 900)]
    pub tool_timeout_secs: u64,
    /// Maximum size of the stdin ContainerInput.
    #[arg(long, env = "TALON_AGENT_MAX_INPUT_BYTES", default_value_t = DEFAULT_MAX_INPUT_BYTES)]
    pub max_input_bytes: usize,
}

impl RunArgs {
    /// Resolve into a [`RunConfig`] (values clamped to sane ranges).
    pub fn into_config(self) -> RunConfig {
        let mcp_config = self
            .mcp_config
            .unwrap_or_else(|| self.group_dir.join(".mcp.json"));
        let settings = LoopSettings {
            max_iterations: self.max_iterations.clamp(1, 1_000),
            self_check: self.self_check,
            compact_ratio: if self.compact_threshold.is_finite() {
                self.compact_threshold.clamp(0.3, 0.95)
            } else {
                0.75
            },
            ipc_poll: Duration::from_millis(self.ipc_poll_ms.clamp(10, 60_000)),
            tool_timeout: Duration::from_secs(self.tool_timeout_secs.clamp(10, 3_600)),
            ..LoopSettings::default()
        };
        RunConfig {
            paths: AgentPaths {
                group: self.group_dir,
                global: self.global_dir,
                project: self.project_dir,
                extra: self.extra_dir,
                ipc: self.ipc_dir,
                state: self.state_dir,
                mcp_config,
            },
            settings,
            mcp_socket_dir: self.mcp_socket_dir.filter(|p| !p.as_os_str().is_empty()),
            max_input_bytes: self.max_input_bytes.clamp(1024, 256 * 1024 * 1024),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Cli {
        #[command(flatten)]
        run: RunArgs,
    }

    #[test]
    fn defaults_are_container_paths() {
        let p = AgentPaths::default();
        assert_eq!(p.group, PathBuf::from("/workspace/group"));
        assert_eq!(
            p.sessions_dir(),
            PathBuf::from("/home/agent/.talon/sessions")
        );
        assert_eq!(p.ipc_input(), PathBuf::from("/workspace/ipc/input"));
        assert_eq!(
            p.conversations(),
            PathBuf::from("/home/agent/.talon/conversations")
        );
        assert_eq!(p.memory(), PathBuf::from("/workspace/group/MEMORY.md"));
        assert_eq!(p.mcp_config, PathBuf::from("/workspace/group/.mcp.json"));
    }

    #[test]
    fn under_reroots() {
        let p = AgentPaths::under(Path::new("/tmp/x"));
        assert_eq!(p.mcp_config, PathBuf::from("/tmp/x/group/.mcp.json"));
        assert_eq!(p.state, PathBuf::from("/tmp/x/state"));
    }

    #[test]
    fn cli_flags_resolve_and_clamp() {
        let cli = Cli::try_parse_from([
            "t",
            "--group-dir",
            "/g",
            "--max-iterations",
            "0",
            "--self-check",
            "false",
            "--compact-threshold",
            "2.0",
            "--ipc-poll-ms",
            "1",
        ])
        .unwrap();
        let cfg = cli.run.into_config();
        assert_eq!(cfg.paths.group, PathBuf::from("/g"));
        assert_eq!(cfg.paths.mcp_config, PathBuf::from("/g/.mcp.json"));
        assert_eq!(cfg.settings.max_iterations, 1);
        assert!(!cfg.settings.self_check);
        assert!((cfg.settings.compact_ratio - 0.95).abs() < f64::EPSILON);
        assert_eq!(cfg.settings.ipc_poll, Duration::from_millis(10));
        assert_eq!(cfg.mcp_socket_dir, None);
    }

    #[test]
    fn cli_defaults() {
        let cli = Cli::try_parse_from(["t", "--mcp-socket-dir", "/run/talon/mcp"]).unwrap();
        let cfg = cli.run.into_config();
        assert_eq!(cfg.settings.max_iterations, 50);
        assert!(cfg.settings.self_check);
        assert_eq!(cfg.mcp_socket_dir, Some(PathBuf::from("/run/talon/mcp")));
        assert_eq!(cfg.max_input_bytes, DEFAULT_MAX_INPUT_BYTES);
    }
}
