//! Process-wide configuration for the host (`talon`).
//!
//! Resolved once at startup from the process environment and `.env`
//! (process env wins for non-secret keys). Secrets are *not* stored here;
//! read them with [`EnvFile::file_value`] at the point of use.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono_tz::Tz;

use crate::env::EnvFile;
use crate::provider::load_provider_env_defaults;
use crate::time::{is_valid_timezone, parse_tz};
use crate::trigger::default_trigger;
use crate::types::ContainerConfig;

#[derive(Debug, Clone)]
pub struct TalonConfig {
    pub assistant_name: String,
    pub assistant_has_own_number: bool,
    /// Default trigger (`@<assistant_name>`).
    pub default_trigger: String,

    pub project_root: PathBuf,
    /// SQLite + other durable state (`store/`).
    pub store_dir: PathBuf,
    /// Group folders (`groups/`).
    pub groups_dir: PathBuf,
    /// Runtime data: IPC namespaces, sessions (`data/`).
    pub data_dir: PathBuf,
    /// `~/.config/talon` (falls back to `~/.config/nanoclaw` if only that exists).
    pub config_dir: PathBuf,
    pub mount_allowlist_path: PathBuf,
    pub sender_allowlist_path: PathBuf,

    pub container_image: String,
    /// Container runtime binary (`docker` / `podman`).
    pub container_runtime: String,
    pub container_timeout: Duration,
    pub container_max_output_bytes: usize,
    /// How long an idle container is kept alive after its last result.
    pub idle_timeout: Duration,
    pub max_concurrent_containers: usize,
    pub max_messages_per_prompt: usize,

    pub poll_interval: Duration,
    pub scheduler_poll_interval: Duration,
    pub ipc_poll_interval: Duration,

    pub timezone: Tz,
    pub timezone_name: String,

    /// Host LLM gateway listen port (containers reach vLLM through it).
    pub llm_gateway_port: u16,
    /// Bind address for host-side services containers must reach.
    pub llm_gateway_bind: String,
    pub onecli_url: String,

    /// vLLM defaults from `.env`, merged per group at launch time.
    pub provider_defaults: ContainerConfig,

    /// Raw env view for crates that need their own keys.
    pub env: EnvFile,
}

impl TalonConfig {
    /// Resolve configuration rooted at `project_root`.
    pub fn load(project_root: &Path) -> Self {
        let env = EnvFile::load(project_root);
        Self::from_env(project_root, env)
    }

    pub fn from_env(project_root: &Path, env: EnvFile) -> Self {
        let assistant_name = env.get("ASSISTANT_NAME").unwrap_or_else(|| "Andy".into());
        let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| "/root".into());
        let talon_cfg = home.join(".config").join("talon");
        let legacy_cfg = home.join(".config").join("nanoclaw");
        let config_dir = if !talon_cfg.exists() && legacy_cfg.exists() {
            legacy_cfg
        } else {
            talon_cfg
        };

        let tz_name = [
            env.get("TZ"),
            Some("UTC".to_string()),
        ]
        .into_iter()
        .flatten()
        .find(|tz| is_valid_timezone(tz))
        .unwrap_or_else(|| "UTC".into());

        let ms = |key: &str, default: u64, min: u64| Duration::from_millis(env.get_u64(key, default, min));

        Self {
            default_trigger: default_trigger(&assistant_name),
            assistant_has_own_number: env.get_bool("ASSISTANT_HAS_OWN_NUMBER"),
            project_root: project_root.to_path_buf(),
            store_dir: project_root.join("store"),
            groups_dir: project_root.join("groups"),
            data_dir: project_root.join("data"),
            mount_allowlist_path: config_dir.join("mount-allowlist.json"),
            sender_allowlist_path: config_dir.join("sender-allowlist.json"),
            config_dir,
            container_image: env.get("CONTAINER_IMAGE").unwrap_or_else(|| "talon-agent:latest".into()),
            container_runtime: env.get("CONTAINER_RUNTIME").unwrap_or_else(|| "docker".into()),
            container_timeout: ms("CONTAINER_TIMEOUT", 1_800_000, 10_000),
            container_max_output_bytes: env.get_u64("CONTAINER_MAX_OUTPUT_SIZE", 10 * 1024 * 1024, 64 * 1024)
                as usize,
            idle_timeout: ms("IDLE_TIMEOUT", 1_800_000, 1_000),
            max_concurrent_containers: env.get_u64("MAX_CONCURRENT_CONTAINERS", 5, 1) as usize,
            max_messages_per_prompt: env.get_u64("MAX_MESSAGES_PER_PROMPT", 10, 1) as usize,
            poll_interval: ms("POLL_INTERVAL", 2_000, 100),
            scheduler_poll_interval: ms("SCHEDULER_POLL_INTERVAL", 60_000, 1_000),
            ipc_poll_interval: ms("IPC_POLL_INTERVAL", 1_000, 100),
            timezone: parse_tz(&tz_name),
            timezone_name: tz_name,
            llm_gateway_port: env.get_u64("TALON_LLM_GATEWAY_PORT", 3001, 1) as u16,
            llm_gateway_bind: env.get("TALON_LLM_GATEWAY_BIND").unwrap_or_else(|| "127.0.0.1".into()),
            onecli_url: env.get("ONECLI_URL").unwrap_or_else(|| "http://localhost:10254".into()),
            provider_defaults: load_provider_env_defaults(&env),
            assistant_name,
            env,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = TalonConfig::from_env(Path::new("/opt/talon"), EnvFile::from_str_content(""));
        assert_eq!(cfg.groups_dir, PathBuf::from("/opt/talon/groups"));
        assert!(cfg.max_concurrent_containers >= 1);
        assert!(cfg.default_trigger.starts_with('@'));
    }

    #[test]
    fn env_file_values_apply() {
        let cfg = TalonConfig::from_env(
            Path::new("/x"),
            EnvFile::from_str_content("MAX_CONCURRENT_CONTAINERS=0\nCONTAINER_IMAGE=img:1\n"),
        );
        assert_eq!(cfg.max_concurrent_containers, 1);
        // process env may override CONTAINER_IMAGE in CI; only check when unset
        if std::env::var("CONTAINER_IMAGE").is_err() {
            assert_eq!(cfg.container_image, "img:1");
        }
    }
}
