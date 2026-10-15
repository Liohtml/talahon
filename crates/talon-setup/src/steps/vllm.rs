//! Step `vllm` (new; replaces the Anthropic/Ollama credential checks):
//! verify that the configured vLLM server answers `GET <base>/v1/models`
//! and serves `TALON_VLLM_MODEL` (and `TALON_VLLM_FAST_MODEL` if set).
//!
//! The API key (`TALON_VLLM_API_KEY`, `.env` only) is used for the probe but
//! only ever reported as `set` / `unset`.

use super::StepArgs;
use crate::checks::{VllmCheck, VllmStatus, check_configured_vllm, redact_url};
use crate::context::{SETUP_LOG, SetupContext};
use crate::status::{StatusBlock, StepOutcome};

/// Maximum number of model ids listed in the block.
const MAX_LISTED_MODELS: usize = 10;

/// Add the vLLM fields shared by `vllm`, `environment` and `verify`.
pub(crate) fn add_vllm_fields(
    block: &mut StatusBlock,
    config: Option<&(String, String, Option<String>)>,
    api_key_set: bool,
    check: &VllmCheck,
) {
    match config {
        Some((base, model, fast)) => {
            block.set("VLLM_BASE_URL", redact_url(base));
            block.set("VLLM_MODEL", model);
            if let Some(fast) = fast {
                block.set("VLLM_FAST_MODEL", fast);
            }
        }
        None => {
            block.set("VLLM_BASE_URL", "unset");
            block.set("VLLM_MODEL", "unset");
        }
    }
    block.set("VLLM_API_KEY", if api_key_set { "set" } else { "unset" });
    block.set("VLLM", check.status.as_str());
    if let Some(present) = check.fast_model_present {
        block.set("VLLM_FAST_MODEL_PRESENT", present);
    }
    if let Some(code) = check.http_status {
        block.set("VLLM_HTTP_STATUS", code);
    }
}

/// Run the step.
///
/// # Errors
/// Never fails internally; problems are reported in the block.
pub async fn run(_args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    let (config, check) = check_configured_vllm(ctx).await;
    let api_key_set = ctx.config.env.file_value("TALON_VLLM_API_KEY").is_some();

    let mut block = StatusBlock::new("CHECK_VLLM");
    add_vllm_fields(&mut block, config.as_ref(), api_key_set, &check);
    let listed: Vec<&str> = check
        .models
        .iter()
        .take(MAX_LISTED_MODELS)
        .map(String::as_str)
        .collect();
    block.set("MODELS", listed.join(","));
    let ok = check.status == VllmStatus::Ok;
    block.set("STATUS", if ok { "success" } else { "failed" });
    if let Some(err) = &check.error {
        block.set("ERROR", err);
    } else if !ok {
        block.set("ERROR", check.status.as_str());
    }
    block.set("LOG", SETUP_LOG);
    Ok(StepOutcome::with_code(block, if ok { 0 } else { 1 }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::runner::mock::MockRunner;

    #[tokio::test]
    async fn not_configured_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        // Skip when the process environment configures vLLM (CI override).
        if ctx.config.provider_defaults.vllm.is_some() {
            return;
        }
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("VLLM"), Some("not_configured"));
        assert_eq!(b.status(), Some("failed"));
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn configured_server_is_probed_with_key_from_env_file() {
        if std::env::var_os("TALON_VLLM_BASE_URL").is_some() {
            return;
        }
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer s3cret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{"id": "qwen"}]
            })))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let base = format!("{}/v1/", server.uri());
        std::fs::write(
            dir.path().join(".env"),
            format!(
                "TALON_VLLM_BASE_URL={base}\nTALON_VLLM_MODEL=qwen\nTALON_VLLM_API_KEY=s3cret\n"
            ),
        )
        .unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        let out = run(&StepArgs::default(), &ctx).await.unwrap();
        let rendered = out.render();
        assert!(!rendered.contains("s3cret"), "{rendered}");
        let b = out.block.unwrap();
        assert_eq!(b.get("VLLM"), Some("ok"), "{rendered}");
        assert_eq!(b.get("VLLM_API_KEY"), Some("set"));
        assert_eq!(b.get("MODELS"), Some("qwen"));
        assert_eq!(out.exit_code, 0);
    }
}
