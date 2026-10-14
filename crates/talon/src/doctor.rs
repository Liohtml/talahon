//! `talon doctor`: one command that explains why Talon can or cannot run.
//!
//! Prints machine-readable blocks (same format as `talon setup`):
//! `CHECK_ENVIRONMENT` and `CHECK_VLLM` from `talon-setup`, then
//! `CHECK_GATEWAY` (bind address the LLM gateway would use and whether
//! containers can reach it), `AUDIT_VERIFY`, and a final `DOCTOR` summary
//! with one hint per problem. Exit code 0 when no problem was found.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use talon_container::{ContainerRuntime, HostPlatform};
use talon_core::config::TalonConfig;
use talon_db::{Db, DbOptions, default_db_path};
use talon_setup::checks::check_port;
use talon_setup::{SetupContext, StatusBlock, Step, StepArgs, run_step};

use crate::app::{DEFAULT_CONTAINER_HOST, gateway_bind_ip};

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
        "dirs_not_writable" => {
            "store/, data/, groups/ and logs/ must be writable by the service user"
        }
        "low_disk_space" => "free some disk space (images, logs, data/)",
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

    #[test]
    fn every_known_issue_has_a_specific_hint() {
        for issue in [
            "container_runtime_missing",
            "image_missing",
            "vllm_not_configured",
            "vllm_auth_failed",
            "gateway_bind_loopback",
            "http_api_key_unset",
            "audit_chain_tampered",
        ] {
            assert_ne!(hint(issue), hint("unknown_issue"), "{issue}");
        }
    }
}
