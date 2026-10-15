//! `talon doctor`: one command that explains why Talon can or cannot run.
//!
//! Prints machine-readable blocks (same format as `talon setup`):
//! `CHECK_ENVIRONMENT` and `CHECK_VLLM` from `talon-setup`, then
//! `CHECK_GATEWAY` (bind address the LLM gateway would use and whether
//! containers can reach it), `CHECK_EXPOSURE` (vLLM API key requirement,
//! HTTP API bind address — MYTH-05), `CHECK_NETWORK` (the dedicated agent
//! network exists — MYTH-05), `AUDIT_VERIFY`, and a final `DOCTOR`
//! summary with one hint per problem. Exit code 0 when no problem was
//! found.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use talon_container::runtime::network_inspect_args;
use talon_container::{ContainerRuntime, HostPlatform, RunnerConfig};
use talon_core::config::TalonConfig;
use talon_core::provider::effective_vllm;
use talon_db::{Db, DbOptions, default_db_path};
use talon_http::HttpConfig;
use talon_setup::checks::check_port;
use talon_setup::{SetupContext, StatusBlock, Step, StepArgs, run_step};

use crate::app::{ApiKeyPolicy, DEFAULT_CONTAINER_HOST, api_key_policy, gateway_bind_ip};

/// Operator hint for an issue code.
pub fn hint(issue: &str) -> &'static str {
    match issue {
        "container_runtime_missing" => "install docker or podman (CONTAINER_RUNTIME selects one)",
        "container_runtime_not_running" => {
            "start the container daemon (`docker info` must succeed)"
        }
        "configured_runtime_unavailable" => {
            "CONTAINER_RUNTIME is not installed; another runtime was found and will be used"
        }
        "image_missing" => {
            "build the agent image: ./container/build.sh (or `talon setup container`)"
        }
        "vllm_not_configured" => {
            "set TALON_VLLM_BASE_URL and TALON_VLLM_MODEL in .env (see .env.example); without them \
             the LLM gateway does not start and every agent run fails"
        }
        "vllm_invalid_url" => "TALON_VLLM_BASE_URL must be an http(s) URL, e.g. http://vllm:8000",
        "vllm_unreachable" => {
            "vLLM is not reachable from this host (network, firewall, server down)"
        }
        "vllm_auth_failed" => {
            "vLLM rejected the key: set TALON_VLLM_API_KEY in .env to vLLM's --api-key"
        }
        "vllm_api_key_unset" => {
            "TALON_VLLM_API_KEY is not set, so the LLM gateway refuses to start (without a key \
             containers could call vLLM directly and bypass the gateway): start vLLM with \
             --api-key and put the same value in .env; only if containers provably cannot reach \
             vLLM, set TALON_VLLM_ALLOW_NO_API_KEY=true"
        }
        "vllm_model_missing" => {
            "TALON_VLLM_MODEL is not served by vLLM (compare with --served-model-name / MODELS)"
        }
        "vllm_http_error" | "vllm_invalid_response" => {
            "vLLM answered /v1/models unexpectedly; check TALON_VLLM_BASE_URL points at vLLM"
        }
        "gateway_port_in_use" => {
            "TALON_LLM_GATEWAY_PORT is in use (expected while talon is running; otherwise pick another port)"
        }
        "gateway_port_unavailable" | "gateway_bind_unavailable" => {
            "the LLM gateway cannot bind its address: set TALON_LLM_GATEWAY_BIND to a local address"
        }
        "gateway_bind_loopback" => {
            "on Linux, containers cannot reach a gateway bound to 127.0.0.1: set \
             TALON_LLM_GATEWAY_BIND to the docker bridge address (e.g. 172.17.0.1)"
        }
        "agent_network_missing" => {
            "the agent container network (talon-agents) does not exist: run `talon setup egress` \
             (creates it with inter-container traffic disabled plus the egress firewall rules); \
             `talon run` also creates the network at startup, but not the firewall rules"
        }
        "agent_network_unchecked" => {
            "the agent container network could not be inspected (is the container runtime running?)"
        }
        "dirs_not_writable" => {
            "store/, data/, groups/ and logs/ must be writable by the service user"
        }
        "low_disk_space" => "free some disk space (images, logs, data/)",
        "http_api_public_bind" => {
            "the CoPilot HTTP API listens on every interface (COPILOT_HTTP_BIND=0.0.0.0 / ::): \
             bind it to 127.0.0.1 or the private address CoPilot uses, and firewall the port"
        }
        "http_config_invalid" => {
            "a COPILOT_HTTP_* setting is invalid (see CHECK_EXPOSURE ERROR); `talon run` refuses to start"
        }
        "http_api_key_unset" => {
            "HTTP_API_KEY is not set: the CoPilot HTTP API rejects every request (openssl rand -hex 32)"
        }
        "audit_chain_tampered" => {
            "the audit log hash chain is broken: investigate with `talon audit tail` before trusting it"
        }
        _ => "see the blocks above",
    }
}

fn issues_of(block: Option<&StatusBlock>) -> Vec<String> {
    block
        .and_then(|b| b.get("ISSUES"))
        .filter(|v| *v != "none" && !v.is_empty())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

/// `CHECK_GATEWAY` block plus issue codes.
async fn gateway_block(config: &TalonConfig) -> (StatusBlock, Vec<String>) {
    let mut issues = Vec::new();
    let mut block = StatusBlock::new("CHECK_GATEWAY");
    let explicit = config.env.get("TALON_LLM_GATEWAY_BIND").is_some();
    block.set(
        "BIND_SOURCE",
        if explicit { "explicit" } else { "detected" },
    );
    let runtime = ContainerRuntime::detect(&config.container_runtime).ok();
    let ip: Option<IpAddr> = match &runtime {
        Some(rt) => match gateway_bind_ip(config, rt).await {
            Ok(ip) => Some(ip),
            Err(e) => {
                block.set("ERROR", format!("{e:#}"));
                issues.push("gateway_bind_unavailable".to_string());
                None
            }
        },
        None => config
            .env
            .get("TALON_LLM_GATEWAY_BIND")
            .and_then(|v| v.trim().parse().ok())
            .or(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))),
    };
    if let Some(ip) = ip {
        block.set("BIND", ip);
        block.set("PORT", config.llm_gateway_port);
        let port = check_port(&ip.to_string(), config.llm_gateway_port).await;
        block.set("PORT_STATUS", port.as_str());
        match port.as_str() {
            "free" => {}
            "in_use" => issues.push("gateway_port_in_use".to_string()),
            _ => issues.push("gateway_bind_unavailable".to_string()),
        }
        let linux = runtime
            .as_ref()
            .is_some_and(|rt| rt.platform() == HostPlatform::Linux);
        if linux && ip.is_loopback() {
            issues.push("gateway_bind_loopback".to_string());
        }
    }
    let host = config
        .env
        .get("TALON_LLM_GATEWAY_HOST")
        .unwrap_or_else(|| DEFAULT_CONTAINER_HOST.to_string());
    block.set(
        "CONTAINER_URL",
        format!("http://{host}:{}/v1", config.llm_gateway_port),
    );
    block.set(
        "STATUS",
        if issues.is_empty() {
            "success"
        } else {
            "failed"
        },
    );
    (block, issues)
}

/// `CHECK_EXPOSURE` block plus issue codes: the vLLM API key requirement
/// (only when vLLM is configured — otherwise `vllm_not_configured` already
/// says what is missing) and the HTTP API bind address (MYTH-05).
pub fn exposure_block(config: &TalonConfig) -> (StatusBlock, Vec<String>) {
    let mut issues = Vec::new();
    let mut block = StatusBlock::new("CHECK_EXPOSURE");
    let key = match api_key_policy(config) {
        ApiKeyPolicy::Present => "set",
        ApiKeyPolicy::MissingAllowed => "unset_allowed",
        ApiKeyPolicy::Missing => {
            if effective_vllm(&config.provider_defaults).is_some() {
                issues.push("vllm_api_key_unset".to_string());
            }
            "unset"
        }
    };
    block.set("VLLM_API_KEY", key);
    match HttpConfig::from_talon_config(config) {
        Ok(http) => {
            block.set("HTTP_BIND", http.bind);
            block.set("HTTP_PORT", http.port);
            block.set("HTTP_TLS_TERMINATED", http.tls_terminated);
            if http.bind.is_unspecified() {
                issues.push("http_api_public_bind".to_string());
            }
        }
        Err(e) => {
            block.set("ERROR", e);
            issues.push("http_config_invalid".to_string());
        }
    }
    block.set(
        "STATUS",
        if issues.is_empty() {
            "success"
        } else {
            "failed"
        },
    );
    (block, issues)
}

/// How long `<runtime> network inspect` may take.
const NETWORK_INSPECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Result of `<runtime> network inspect <name>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkState {
    /// The network exists.
    Exists,
    /// The runtime says there is no such network.
    Missing,
    /// The inspection failed for another reason.
    Unknown,
}

/// Classify a `network inspect` outcome.
pub fn classify_network_inspect(success: bool, stderr: &str) -> NetworkState {
    if success {
        return NetworkState::Exists;
    }
    let err = stderr.to_ascii_lowercase();
    if err.contains("no such network")
        || err.contains("not found")
        || err.contains("unable to find network")
    {
        NetworkState::Missing
    } else {
        NetworkState::Unknown
    }
}

async fn inspect_network(bin: &str, name: &str) -> Result<NetworkState, String> {
    let child = tokio::process::Command::new(bin)
        .args(network_inspect_args(name))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(NETWORK_INSPECT_TIMEOUT, child).await {
        Ok(Ok(out)) => Ok(classify_network_inspect(
            out.status.success(),
            &String::from_utf8_lossy(&out.stderr),
        )),
        Ok(Err(e)) => Err(format!("cannot run {bin}: {e}")),
        Err(_) => Err(format!("{bin} network inspect timed out")),
    }
}

/// `CHECK_NETWORK` block plus issue codes: the network agent containers
/// run on (`TALON_CONTAINER_NETWORK`, default `talon-agents`) must exist.
/// Skipped without a container runtime (reported by the environment step).
async fn network_block(config: &TalonConfig) -> Option<(StatusBlock, Vec<String>)> {
    let runtime = ContainerRuntime::detect(&config.container_runtime).ok()?;
    let mut block = StatusBlock::new("CHECK_NETWORK");
    let mut issues = Vec::new();
    match RunnerConfig::from_talon_config(config).default_network {
        None => {
            block.set("NETWORK", "runtime-default");
            block.set(
                "NOTE",
                "TALON_CONTAINER_NETWORK selects the runtime default bridge: containers can reach \
                 each other and `talon setup egress` rules do not apply",
            );
        }
        Some(network) => {
            block.set("NETWORK", &network);
            match inspect_network(runtime.bin(), &network).await {
                Ok(NetworkState::Exists) => block.set("EXISTS", "yes"),
                Ok(NetworkState::Missing) => {
                    block.set("EXISTS", "no");
                    issues.push("agent_network_missing".to_string());
                }
                Ok(NetworkState::Unknown) => {
                    block.set("EXISTS", "unknown");
                    issues.push("agent_network_unchecked".to_string());
                }
                Err(e) => {
                    block.set("EXISTS", "unknown");
                    block.set("ERROR", e);
                    issues.push("agent_network_unchecked".to_string());
                }
            }
        }
    }
    block.set(
        "STATUS",
        if issues.is_empty() {
            "success"
        } else {
            "failed"
        },
    );
    Some((block, issues))
}

/// `AUDIT_VERIFY` block plus issue codes (skipped without a database).
fn audit_block(config: &TalonConfig) -> Option<(StatusBlock, Vec<String>)> {
    let path = default_db_path(&config.store_dir);
    if !path.exists() {
        return None;
    }
    let db = match Db::open_with_options(
        &path,
        &DbOptions {
            assistant_name: config.assistant_name.clone(),
        },
    ) {
        Ok(db) => db,
        Err(e) => {
            return Some((
                StatusBlock::new("AUDIT_VERIFY")
                    .field("STATUS", "failed")
                    .field("ERROR", e),
                vec!["audit_chain_tampered".to_string()],
            ));
        }
    };
    match crate::audit_cmd::verify_block(&db) {
        Ok((block, true)) => Some((block, Vec::new())),
        Ok((block, false)) => Some((block, vec!["audit_chain_tampered".to_string()])),
        Err(e) => Some((
            StatusBlock::new("AUDIT_VERIFY")
                .field("STATUS", "failed")
                .field("ERROR", format!("{e:#}")),
            Vec::new(),
        )),
    }
}

/// The final `DOCTOR` block.
pub fn summary_block(issues: &[String]) -> StatusBlock {
    let mut block = StatusBlock::new("DOCTOR").field("VERSION", crate::VERSION);
    if issues.is_empty() {
        block.set("ISSUES", "none");
        block.set("STATUS", "success");
        return block;
    }
    block.set("ISSUES", issues.join(","));
    for (i, issue) in issues.iter().enumerate() {
        block.set(
            &format!("HINT_{}", i + 1),
            format!("{issue}: {}", hint(issue)),
        );
    }
    block.set("STATUS", "failed");
    block
}

/// Run every check and print the blocks. Returns the exit code.
pub async fn run(project_root: &Path, config: &TalonConfig) -> i32 {
    let ctx = SetupContext::detect(project_root);
    let no_args = StepArgs::new(Vec::<String>::new());
    let mut issues: Vec<String> = Vec::new();

    let env = run_step(Step::Environment, &no_args, &ctx).await;
    println!("{}", env.render());
    issues.extend(issues_of(env.block.as_ref()));

    let vllm = run_step(Step::Vllm, &no_args, &ctx).await;
    println!("{}", vllm.render());

    let (gateway, gw_issues) = gateway_block(config).await;
    println!("{gateway}");
    // The environment step already probed 127.0.0.1:<port>; the gateway
    // block probes the real bind address, which supersedes it.
    issues.retain(|i| !i.starts_with("gateway_port_"));
    issues.extend(gw_issues);

    let (exposure, exposure_issues) = exposure_block(config);
    println!("{exposure}");
    issues.extend(exposure_issues);

    if let Some((network, network_issues)) = network_block(config).await {
        println!("{network}");
        issues.extend(network_issues);
    }

    if config.env.file_value("HTTP_API_KEY").is_none() {
        issues.push("http_api_key_unset".to_string());
    }

    if let Some((block, audit_issues)) = audit_block(config) {
        println!("{block}");
        issues.extend(audit_issues);
    }

    let mut seen = std::collections::HashSet::new();
    issues.retain(|i| seen.insert(i.clone()));
    println!("{}", summary_block(&issues));
    if issues.is_empty() { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_parsing_and_summary() {
        let block = StatusBlock::new("CHECK_ENVIRONMENT")
            .field("ISSUES", "image_missing,vllm_not_configured");
        let issues = issues_of(Some(&block));
        assert_eq!(issues, vec!["image_missing", "vllm_not_configured"]);
        assert!(issues_of(Some(&StatusBlock::new("X").field("ISSUES", "none"))).is_empty());
        assert!(issues_of(None).is_empty());

        let summary = summary_block(&issues);
        assert_eq!(summary.get("STATUS"), Some("failed"));
        assert!(
            summary
                .get("HINT_2")
                .unwrap()
                .contains("TALON_VLLM_BASE_URL")
        );
        assert_eq!(summary_block(&[]).get("STATUS"), Some("success"));
    }

    fn cfg(content: &str) -> TalonConfig {
        TalonConfig::from_env(
            Path::new("/tmp/talon-doctor-test"),
            talon_core::env::EnvFile::from_str_content(content),
        )
    }

    /// The process environment overrides `.env` for non-secret keys.
    fn env_overridden(keys: &[&str]) -> bool {
        keys.iter().any(|k| std::env::var(k).is_ok())
    }

    #[test]
    fn exposure_flags_missing_vllm_key_and_public_http_bind() {
        if env_overridden(&[
            "TALON_VLLM_BASE_URL",
            "TALON_VLLM_MODEL",
            "TALON_VLLM_ALLOW_NO_API_KEY",
            "COPILOT_HTTP_BIND",
        ]) {
            return;
        }
        const VLLM: &str = "TALON_VLLM_BASE_URL=http://vllm:8000\nTALON_VLLM_MODEL=q\n";

        let (block, issues) = exposure_block(&cfg(&format!("{VLLM}COPILOT_HTTP_BIND=0.0.0.0\n")));
        assert_eq!(issues, vec!["vllm_api_key_unset", "http_api_public_bind"]);
        assert_eq!(block.get("VLLM_API_KEY"), Some("unset"));
        assert_eq!(block.get("STATUS"), Some("failed"));
        let summary = summary_block(&issues);
        assert!(
            summary
                .get("HINT_1")
                .unwrap()
                .contains("TALON_VLLM_API_KEY")
        );
        assert!(summary.get("HINT_2").unwrap().contains("127.0.0.1"));

        let (_, issues) = exposure_block(&cfg(&format!("{VLLM}COPILOT_HTTP_BIND=::\n")));
        assert!(issues.contains(&"http_api_public_bind".to_string()));

        let (block, issues) = exposure_block(&cfg(&format!(
            "{VLLM}TALON_VLLM_API_KEY=k\nCOPILOT_HTTP_BIND=127.0.0.1\n"
        )));
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(block.get("VLLM_API_KEY"), Some("set"));
        assert_eq!(block.get("STATUS"), Some("success"));

        let (block, issues) = exposure_block(&cfg(&format!(
            "{VLLM}TALON_VLLM_ALLOW_NO_API_KEY=true\nCOPILOT_HTTP_BIND=10.0.0.5\n"
        )));
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(block.get("VLLM_API_KEY"), Some("unset_allowed"));

        // Without vLLM, `vllm_not_configured` (environment step) covers it.
        let (_, issues) = exposure_block(&cfg("COPILOT_HTTP_BIND=127.0.0.1\n"));
        assert!(issues.is_empty(), "{issues:?}");

        let (block, issues) = exposure_block(&cfg("COPILOT_HTTP_BIND=not-an-ip\n"));
        assert_eq!(issues, vec!["http_config_invalid"]);
        assert!(block.get("ERROR").is_some());
    }

    #[test]
    fn network_inspect_classification() {
        assert_eq!(classify_network_inspect(true, ""), NetworkState::Exists);
        assert_eq!(
            classify_network_inspect(
                false,
                "Error response from daemon: network talon-agents not found"
            ),
            NetworkState::Missing
        );
        assert_eq!(
            classify_network_inspect(false, "Error: No such network: talon-agents"),
            NetworkState::Missing
        );
        assert_eq!(
            classify_network_inspect(
                false,
                "Error: unable to find network with name or ID talon-agents"
            ),
            NetworkState::Missing
        );
        assert_eq!(
            classify_network_inspect(false, "Cannot connect to the Docker daemon"),
            NetworkState::Unknown
        );
    }

    #[tokio::test]
    async fn network_inspect_runs_the_runtime_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = tmp.path().join("fake-docker");
        std::fs::write(
            &fake,
            "#!/bin/sh\n[ \"$1 $2 $3\" = \"network inspect talon-agents\" ] && exit 0\n\
             echo \"Error: No such network: $3\" >&2\nexit 1\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = fake.to_string_lossy();
        assert_eq!(
            inspect_network(&bin, "talon-agents").await,
            Ok(NetworkState::Exists)
        );
        assert_eq!(
            inspect_network(&bin, "other").await,
            Ok(NetworkState::Missing)
        );
        assert!(inspect_network("/nonexistent/docker", "x").await.is_err());
    }

    #[test]
    fn every_known_issue_has_a_specific_hint() {
        for issue in [
            "container_runtime_missing",
            "image_missing",
            "vllm_not_configured",
            "vllm_auth_failed",
            "gateway_bind_loopback",
            "vllm_api_key_unset",
            "agent_network_missing",
            "agent_network_unchecked",
            "http_api_public_bind",
            "http_config_invalid",
            "http_api_key_unset",
            "audit_chain_tampered",
        ] {
            assert_ne!(hint(issue), hint("unknown_issue"), "{issue}");
        }
    }
}
