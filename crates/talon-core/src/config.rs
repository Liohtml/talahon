//! Process-wide configuration for the host (`talahon`).
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
    /// `~/.config/talahon`.
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

    /// True while `ASSISTANT_NAME` is not set (process environment or
    /// `.env`): the assistant goes by the built-in default name, and default
    /// triggers also accept the name it had before the rename
    /// ([`crate::trigger::trigger_pattern`]).
    pub fn assistant_name_is_default(&self) -> bool {
        self.env.get("ASSISTANT_NAME").is_none()
    }

    /// The trigger regex of a group with trigger `trigger` (empty: the
    /// default trigger) under this configuration.
    pub fn trigger_pattern(&self, trigger: &str) -> regex::Regex {
        crate::trigger::trigger_pattern(
            trigger,
            &self.assistant_name,
            self.assistant_name_is_default(),
        )
    }

    /// Resolve the configuration for `project_root` from an already loaded
    /// `.env`.
    pub fn from_env(project_root: &Path, env: EnvFile) -> Self {
        let assistant_name = env
            .get("ASSISTANT_NAME")
            .unwrap_or_else(|| crate::trigger::DEFAULT_ASSISTANT_NAME.into());
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| "/root".into());
        // `~/.config/talahon`, or the pre-rename `~/.config/talon` when only
        // that exists; never both (see `paths::resolve_config_dir`).
        let config_dir = crate::paths::resolve_config_dir(&home).path;

        let process_tz = std::env::var("TZ").ok();
        let tz_name = resolve_timezone(env.file_value("TZ"), process_tz.as_deref());

        let ms = |key: &str, default: u64, min: u64| {
            Duration::from_millis(env.get_u64(key, default, min))
        };

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
            container_image: env
                .get("CONTAINER_IMAGE")
                .unwrap_or_else(|| "talahon-agent:latest".into()),
            container_runtime: env
                .get("CONTAINER_RUNTIME")
                .unwrap_or_else(|| "docker".into()),
            container_timeout: ms("CONTAINER_TIMEOUT", 1_800_000, 10_000),
            container_max_output_bytes: env.get_u64(
                "CONTAINER_MAX_OUTPUT_SIZE",
                10 * 1024 * 1024,
                64 * 1024,
            ) as usize,
            idle_timeout: ms("IDLE_TIMEOUT", 1_800_000, 1_000),
            max_concurrent_containers: env.get_u64("MAX_CONCURRENT_CONTAINERS", 5, 1) as usize,
            max_messages_per_prompt: env.get_u64("MAX_MESSAGES_PER_PROMPT", 10, 1) as usize,
            poll_interval: ms("POLL_INTERVAL", 2_000, 100),
            scheduler_poll_interval: ms("SCHEDULER_POLL_INTERVAL", 60_000, 1_000),
            ipc_poll_interval: ms("IPC_POLL_INTERVAL", 1_000, 100),
            timezone: parse_tz(&tz_name),
            timezone_name: tz_name,
            llm_gateway_port: env.get_u64("TALAHON_LLM_GATEWAY_PORT", 3001, 1) as u16,
            llm_gateway_bind: env
                .get("TALAHON_LLM_GATEWAY_BIND")
                .unwrap_or_else(|| "127.0.0.1".into()),
            onecli_url: env
                .get("ONECLI_URL")
                .unwrap_or_else(|| "http://localhost:10254".into()),
            provider_defaults: load_provider_env_defaults(&env),
            assistant_name,
            env,
        }
    }
}

/// The timezone Talahon runs in: `TZ` from `.env` (what `talahon setup
/// timezone` writes), else the process's `TZ`, else UTC — the first one
/// that is a valid IANA name, so an invalid value never hides a valid one.
/// Same precedence as the setup step.
pub fn resolve_timezone(env_file: Option<&str>, process: Option<&str>) -> String {
    [env_file, process]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|tz| is_valid_timezone(tz))
        .unwrap_or("UTC")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timezone_precedence_matches_setup() {
        assert_eq!(
            resolve_timezone(Some("Europe/Berlin"), Some("UTC")),
            "Europe/Berlin"
        );
        // An invalid value never hides a valid one.
        assert_eq!(
            resolve_timezone(Some("Europe/Berlin"), Some("IST-2")),
            "Europe/Berlin"
        );
        assert_eq!(
            resolve_timezone(Some("Mars/Base"), Some("Asia/Tokyo")),
            "Asia/Tokyo"
        );
        assert_eq!(resolve_timezone(None, Some("bogus")), "UTC");
        assert_eq!(resolve_timezone(None, None), "UTC");
    }

    #[test]
    fn default_triggers_accept_the_old_name_only_while_no_name_is_set() {
        if std::env::var("ASSISTANT_NAME").is_ok_and(|v| !v.is_empty()) {
            return; // the process environment overrides `.env`
        }
        let cfg = |content: &str| {
            TalonConfig::from_env(
                Path::new("/opt/talahon"),
                EnvFile::from_str_content(content),
            )
        };
        // ASSISTANT_NAME not set: the assistant is "Talahon", and chats that
        // address "@Talon" (no trigger, or registered as `@Talon` /
        // `@Talahon`) keep working.
        let unset = cfg("");
        assert_eq!(unset.assistant_name, "Talahon");
        assert_eq!(unset.default_trigger, "@Talahon");
        assert!(unset.assistant_name_is_default());
        for trigger in ["", "@Talon", "@Talahon"] {
            let re = unset.trigger_pattern(trigger);
            assert!(re.is_match("@Talahon status"), "{trigger:?}");
            assert!(re.is_match("@talon status"), "{trigger:?}");
        }
        assert!(!unset.trigger_pattern("@soc").is_match("@Talon status"));

        // Set explicitly — to the new name, the old one or anything else:
        // exactly the configured trigger, as before.
        let new = cfg("ASSISTANT_NAME=Talahon\n");
        assert!(!new.assistant_name_is_default());
        assert!(new.trigger_pattern("").is_match("@Talahon status"));
        assert!(!new.trigger_pattern("").is_match("@Talon status"));
        assert!(!new.trigger_pattern("@Talon").is_match("@Talahon status"));
        let old = cfg("ASSISTANT_NAME=Talon\n");
        assert_eq!(old.default_trigger, "@Talon");
        assert!(old.trigger_pattern("").is_match("@Talon status"));
        assert!(!old.trigger_pattern("").is_match("@Talahon status"));
        let nova = cfg("ASSISTANT_NAME=Nova\n");
        assert!(nova.trigger_pattern("").is_match("@Nova status"));
        assert!(!nova.trigger_pattern("").is_match("@Talon status"));
        assert!(!nova.trigger_pattern("").is_match("@Talahon status"));
    }

    #[test]
    fn defaults_are_sane() {
        let cfg = TalonConfig::from_env(Path::new("/opt/talahon"), EnvFile::from_str_content(""));
        assert_eq!(cfg.groups_dir, PathBuf::from("/opt/talahon/groups"));
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
