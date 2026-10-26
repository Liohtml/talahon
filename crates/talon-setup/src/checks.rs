//! Environment probes: container runtime, image, vLLM, gateway port,
//! writable directories, disk space and settings that expose the host to
//! agent containers.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use talon_core::env::EnvFile;
use talon_core::provider::{effective_vllm, provider_kind};
use talon_core::types::ProviderKind;

use crate::context::SetupContext;
use crate::fsutil::ensure_writable_dir;
use crate::runner::{CommandRunner, CommandSpec};

/// Minimum free disk space (MiB) in the project directory: the agent image,
/// group workspaces and the SQLite store need room.
pub const MIN_FREE_DISK_MB: u64 = 2048;

/// Container runtimes Talon supports.
pub const SUPPORTED_RUNTIMES: &[&str] = &["docker", "podman"];

// ---------------------------------------------------------------------------
// Container runtime
// ---------------------------------------------------------------------------

/// State of one container runtime binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    /// Installed and the daemon/service answers `info`.
    Running,
    /// Binary present, `info` fails (daemon down, no permission).
    InstalledNotRunning,
    /// Not on `PATH`.
    NotFound,
}

impl RuntimeState {
    /// `running` | `installed_not_running` | `not_found`.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeState::Running => "running",
            RuntimeState::InstalledNotRunning => "installed_not_running",
            RuntimeState::NotFound => "not_found",
        }
    }
}

/// Probe `runtime` (`docker` / `podman`) with `<runtime> info`.
pub async fn runtime_state(runner: &dyn CommandRunner, runtime: &str) -> RuntimeState {
    if runner.which(runtime).is_none() {
        return RuntimeState::NotFound;
    }
    // Plain `info` (no --format: docker and podman expose different fields);
    // it exits non-zero when the daemon/service is unreachable.
    let out = runner.run(&CommandSpec::new(runtime, ["info"])).await;
    if out.success() {
        RuntimeState::Running
    } else {
        RuntimeState::InstalledNotRunning
    }
}

/// Result of [`detect_runtime`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReport {
    /// State per supported runtime, in [`SUPPORTED_RUNTIMES`] order.
    pub states: Vec<(String, RuntimeState)>,
    /// The runtime to use: the configured one if running, otherwise any
    /// running one.
    pub selected: Option<String>,
}

impl RuntimeReport {
    /// State of `runtime`.
    pub fn state(&self, runtime: &str) -> RuntimeState {
        self.states
            .iter()
            .find(|(r, _)| r == runtime)
            .map_or(RuntimeState::NotFound, |(_, s)| *s)
    }
}

/// Probe all supported runtimes, preferring `preferred`.
pub async fn detect_runtime(runner: &dyn CommandRunner, preferred: &str) -> RuntimeReport {
    let mut states = Vec::new();
    for rt in SUPPORTED_RUNTIMES {
        states.push(((*rt).to_string(), runtime_state(runner, rt).await));
    }
    let running = |rt: &str| {
        states
            .iter()
            .any(|(r, s)| r == rt && *s == RuntimeState::Running)
    };
    let selected = if running(preferred) {
        Some(preferred.to_string())
    } else {
        SUPPORTED_RUNTIMES
            .iter()
            .find(|rt| running(rt))
            .map(|rt| (*rt).to_string())
    };
    RuntimeReport { states, selected }
}

/// Whether `image` exists locally for `runtime`.
pub async fn image_present(runner: &dyn CommandRunner, runtime: &str, image: &str) -> bool {
    runner
        .run(&CommandSpec::new(
            runtime,
            ["image", "inspect", "--format", "{{.Id}}", image],
        ))
        .await
        .success()
}

// ---------------------------------------------------------------------------
// vLLM
// ---------------------------------------------------------------------------

/// Outcome class of a vLLM probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VllmStatus {
    /// Reachable and the configured model is served.
    Ok,
    /// `TALON_VLLM_BASE_URL` / `TALON_VLLM_MODEL` not set.
    NotConfigured,
    /// The base URL is not a valid http(s) URL.
    InvalidUrl,
    /// Connection failed or timed out.
    Unreachable,
    /// 401 / 403 — `TALON_VLLM_API_KEY` missing or wrong.
    AuthFailed,
    /// Any other non-2xx status.
    HttpError,
    /// 2xx but not an OpenAI-style model list.
    InvalidResponse,
    /// Reachable, but the configured model is not in the list.
    ModelMissing,
}

impl VllmStatus {
    /// Status-block value.
    pub fn as_str(&self) -> &'static str {
        match self {
            VllmStatus::Ok => "ok",
            VllmStatus::NotConfigured => "not_configured",
            VllmStatus::InvalidUrl => "invalid_url",
            VllmStatus::Unreachable => "unreachable",
            VllmStatus::AuthFailed => "auth_failed",
            VllmStatus::HttpError => "http_error",
            VllmStatus::InvalidResponse => "invalid_response",
            VllmStatus::ModelMissing => "model_missing",
        }
    }
}

/// Result of [`check_vllm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VllmCheck {
    /// Overall classification.
    pub status: VllmStatus,
    /// Served model ids (`data[].id`).
    pub models: Vec<String>,
    /// HTTP status, when a response arrived.
    pub http_status: Option<u16>,
    /// Short error description (never contains the API key).
    pub error: Option<String>,
    /// The fast model is served (`None` when no fast model is configured).
    pub fast_model_present: Option<bool>,
}

impl VllmCheck {
    fn status(status: VllmStatus, error: Option<String>) -> Self {
        Self {
            status,
            models: Vec::new(),
            http_status: None,
            error,
            fast_model_present: None,
        }
    }
}

/// Maximum accepted size of the `/v1/models` response.
const MAX_MODELS_BODY: usize = 1024 * 1024;

/// `<base>/v1/models` for a base URL with or without a trailing `/v1`.
/// Returns `None` unless the URL is absolute http(s).
pub fn models_url(base_url: &str) -> Option<String> {
    let trimmed = base_url.trim().trim_end_matches('/');
    let root = trimmed.strip_suffix("/v1").unwrap_or(trimmed);
    let url = reqwest::Url::parse(&format!("{root}/v1/models")).ok()?;
    if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() {
        Some(url.to_string())
    } else {
        None
    }
}

/// Remove `user:password@` from a URL for display.
pub fn redact_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut u) => {
            if !u.username().is_empty() || u.password().is_some() {
                let _ = u.set_username("");
                let _ = u.set_password(None);
            }
            u.to_string().trim_end_matches('/').to_string()
        }
        Err(_) => "<invalid>".to_string(),
    }
}

/// Probe a vLLM server: `GET <base>/v1/models` (bearer auth when
/// `api_key` is set), then check that `model` (and `fast_model`) are
/// served.
pub async fn check_vllm(
    base_url: &str,
    model: &str,
    fast_model: Option<&str>,
    api_key: Option<&str>,
    timeout: Duration,
) -> VllmCheck {
    check_provider(
        ProviderKind::Vllm,
        base_url,
        model,
        fast_model,
        api_key,
        timeout,
    )
    .await
}

/// Probe the configured provider's model list: `GET <base>/v1/models` with
/// `Authorization: Bearer` (vLLM) or `x-api-key` + `anthropic-version`
/// (Anthropic — its `/v1/models` has the same `{"data":[{"id":..}]}`
/// shape, so the checks are identical).
pub async fn check_provider(
    kind: ProviderKind,
    base_url: &str,
    model: &str,
    fast_model: Option<&str>,
    api_key: Option<&str>,
    timeout: Duration,
) -> VllmCheck {
    if base_url.trim().is_empty() || model.trim().is_empty() {
        return VllmCheck::status(VllmStatus::NotConfigured, None);
    }
    let Some(url) = models_url(base_url) else {
        return VllmCheck::status(
            VllmStatus::InvalidUrl,
            Some("base URL must be http(s)://host[:port]".into()),
        );
    };
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return VllmCheck::status(VllmStatus::Unreachable, Some(e.without_url().to_string()));
        }
    };
    let mut req = client.get(&url).header("accept", "application/json");
    if let Some(key) = api_key.filter(|k| !k.is_empty()) {
        req = match kind {
            ProviderKind::Anthropic => req
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01"),
            ProviderKind::Vllm | ProviderKind::Unsupported => req.bearer_auth(key),
        };
    }
    let mut resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let kind = if e.is_timeout() {
                "timeout"
            } else {
                "connection failed"
            };
            return VllmCheck::status(
                VllmStatus::Unreachable,
                Some(format!("{kind}: {}", e.without_url())),
            );
        }
    };
    let code = resp.status();
    let mut check = VllmCheck::status(VllmStatus::Ok, None);
    check.http_status = Some(code.as_u16());
    if code == reqwest::StatusCode::UNAUTHORIZED || code == reqwest::StatusCode::FORBIDDEN {
        check.status = VllmStatus::AuthFailed;
        check.error = Some(format!("HTTP {}", code.as_u16()));
        return check;
    }
    if !code.is_success() {
        check.status = VllmStatus::HttpError;
        check.error = Some(format!("HTTP {}", code.as_u16()));
        return check;
    }

    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > MAX_MODELS_BODY {
                    check.status = VllmStatus::InvalidResponse;
                    check.error = Some("response too large".into());
                    return check;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                check.status = VllmStatus::Unreachable;
                check.error = Some(format!("read failed: {}", e.without_url()));
                return check;
            }
        }
    }

    let parsed: Option<Vec<String>> = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("data")?.as_array().map(|items| {
                items
                    .iter()
                    .filter_map(|m| m.get("id").and_then(|id| id.as_str()).map(str::to_string))
                    .collect()
            })
        });
    let Some(models) = parsed else {
        check.status = VllmStatus::InvalidResponse;
        check.error = Some("expected an OpenAI-style {\"data\":[{\"id\":...}]} model list".into());
        return check;
    };
    check.models = models;
    let served = |name: &str| check.models.iter().any(|m| m == name);
    check.fast_model_present = fast_model.filter(|f| !f.is_empty()).map(served);
    if !served(model) {
        check.status = VllmStatus::ModelMissing;
        check.error = Some(format!("model {model:?} is not served"));
    }
    check
}

/// Probe the vLLM server configured in the context (`TALON_VLLM_*`, API
/// key from `.env` only).
pub async fn check_configured_vllm(
    ctx: &SetupContext,
) -> (Option<(String, String, Option<String>)>, VllmCheck) {
    let Some(v) = effective_vllm(&ctx.config.provider_defaults) else {
        return (None, VllmCheck::status(VllmStatus::NotConfigured, None));
    };
    let kind = provider_kind(&ctx.config.provider_defaults).unwrap_or(ProviderKind::Vllm);
    let api_key = ctx.config.env.file_value(kind.api_key_env());
    let check = check_provider(
        kind,
        &v.base_url,
        &v.model,
        v.fast_model.as_deref(),
        api_key,
        ctx.http_timeout,
    )
    .await;
    (
        Some((v.base_url.clone(), v.model.clone(), v.fast_model.clone())),
        check,
    )
}

// ---------------------------------------------------------------------------
// Ports, directories, disk
// ---------------------------------------------------------------------------

/// Whether a TCP port can be bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortStatus {
    /// Bind succeeded.
    Free,
    /// Address already in use (Talon itself, or another service).
    InUse,
    /// The bind address is not local / not permitted.
    Unavailable(String),
}

impl PortStatus {
    /// `free` | `in_use` | `unavailable`.
    pub fn as_str(&self) -> &'static str {
        match self {
            PortStatus::Free => "free",
            PortStatus::InUse => "in_use",
            PortStatus::Unavailable(_) => "unavailable",
        }
    }
}

/// Try to bind `bind:port` and release it immediately.
pub async fn check_port(bind: &str, port: u16) -> PortStatus {
    match tokio::net::TcpListener::bind((bind, port)).await {
        Ok(listener) => {
            drop(listener);
            PortStatus::Free
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => PortStatus::InUse,
        Err(e) => PortStatus::Unavailable(e.to_string()),
    }
}

/// Directories Talon writes at runtime.
pub fn runtime_dirs(ctx: &SetupContext) -> Vec<PathBuf> {
    vec![
        ctx.config.store_dir.clone(),
        ctx.config.data_dir.clone(),
        ctx.config.groups_dir.clone(),
        ctx.logs_dir(),
    ]
}

/// Create each directory and verify it is writable. Returns the failures.
pub fn check_writable_dirs(dirs: &[PathBuf]) -> Vec<(PathBuf, String)> {
    dirs.iter()
        .filter_map(|d| {
            ensure_writable_dir(d)
                .err()
                .map(|e| (d.clone(), e.to_string()))
        })
        .collect()
}

/// Free space (MiB) on the filesystem holding `path`, via `df -Pk`.
pub async fn disk_free_mb(runner: &dyn CommandRunner, path: &Path) -> Option<u64> {
    let out = runner
        .run(&CommandSpec::new(
            "df",
            ["-Pk".to_string(), path.to_string_lossy().into_owned()],
        ))
        .await;
    if !out.success() {
        return None;
    }
    parse_df_available_kb(&out.stdout).map(|kb| kb / 1024)
}

/// Available KiB from POSIX `df -Pk` output (4th column of the last line).
pub fn parse_df_available_kb(output: &str) -> Option<u64> {
    let line = output.lines().rev().find(|l| !l.trim().is_empty())?;
    line.split_whitespace().nth(3)?.parse().ok()
}

// ---------------------------------------------------------------------------
// Exposure to agent containers (MYTH-05)
// ---------------------------------------------------------------------------

/// Issue code: `TALON_VLLM_API_KEY` is unset.
pub const ISSUE_VLLM_API_KEY_UNSET: &str = "vllm_api_key_unset";
/// Issue code: `COPILOT_HTTP_BIND` listens on every interface.
pub const ISSUE_HTTP_BIND_ALL_INTERFACES: &str = "http_bind_all_interfaces";

/// The `.env` key holding the configured provider's upstream API key.
pub fn api_key_env(ctx: &SetupContext) -> &'static str {
    provider_kind(&ctx.config.provider_defaults)
        .unwrap_or(ProviderKind::Vllm)
        .api_key_env()
}

/// `TALON_VLLM_API_KEY` is set (non-blank) in `.env` — the only place the
/// secret is read from.
pub fn vllm_api_key_set(env: &EnvFile) -> bool {
    env.file_value("TALON_VLLM_API_KEY")
        .is_some_and(|k| !k.trim().is_empty())
}

/// `value` is an unspecified ("any") address: `0.0.0.0`, `::`, `[::]`.
pub fn binds_all_interfaces(value: &str) -> bool {
    value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_unspecified())
}

/// Settings that weaken the containment of agent containers, as issue
/// codes for the `environment` / `verify` blocks:
///
/// - [`ISSUE_VLLM_API_KEY_UNSET`]: without an API key on the vLLM server,
///   anything that can reach it — agent containers included, if egress is
///   not firewalled (`talon setup egress`) — can call the model directly,
///   bypassing the LLM gateway's token, model and parameter checks.
/// - [`ISSUE_HTTP_BIND_ALL_INTERFACES`]: `COPILOT_HTTP_BIND` is `0.0.0.0` /
///   `::`, so the HTTP API also listens on the docker bridge (reachable from
///   agent containers) and on every other network the host is on.
pub fn exposure_issues(env: &EnvFile) -> Vec<&'static str> {
    let mut issues = Vec::new();
    if !vllm_api_key_set(env) {
        issues.push(ISSUE_VLLM_API_KEY_UNSET);
    }
    if env
        .get("COPILOT_HTTP_BIND")
        .is_some_and(|b| binds_all_interfaces(&b))
    {
        issues.push(ISSUE_HTTP_BIND_ALL_INTERFACES);
    }
    issues
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::runner::CommandOutput;
    use crate::runner::mock::MockRunner;

    #[test]
    fn unspecified_bind_addresses() {
        for any in ["0.0.0.0", "::", "[::]", " 0.0.0.0 ", "0:0:0:0:0:0:0:0"] {
            assert!(binds_all_interfaces(any), "{any}");
        }
        for specific in ["127.0.0.1", "::1", "172.17.0.1", "", "*", "localhost"] {
            assert!(!binds_all_interfaces(specific), "{specific}");
        }
    }

    #[test]
    fn exposure_issues_from_env() {
        let env = EnvFile::from_str_content("TALON_VLLM_API_KEY=k\n");
        assert!(vllm_api_key_set(&env));
        assert!(!exposure_issues(&env).contains(&ISSUE_VLLM_API_KEY_UNSET));
        for unset in ["", "TALON_VLLM_API_KEY=\n", "TALON_VLLM_API_KEY=   \n"] {
            let env = EnvFile::from_str_content(unset);
            assert!(!vllm_api_key_set(&env), "{unset:?}");
            assert!(exposure_issues(&env).contains(&ISSUE_VLLM_API_KEY_UNSET));
        }
        // COPILOT_HTTP_BIND may come from the process env, which wins.
        if std::env::var_os("COPILOT_HTTP_BIND").is_none() {
            let env =
                EnvFile::from_str_content("TALON_VLLM_API_KEY=k\nCOPILOT_HTTP_BIND=0.0.0.0\n");
            assert_eq!(exposure_issues(&env), vec![ISSUE_HTTP_BIND_ALL_INTERFACES]);
            let env = EnvFile::from_str_content("TALON_VLLM_API_KEY=k\nCOPILOT_HTTP_BIND=::\n");
            assert_eq!(exposure_issues(&env), vec![ISSUE_HTTP_BIND_ALL_INTERFACES]);
            let env =
                EnvFile::from_str_content("TALON_VLLM_API_KEY=k\nCOPILOT_HTTP_BIND=127.0.0.1\n");
            assert!(exposure_issues(&env).is_empty());
            let env = EnvFile::from_str_content("TALON_VLLM_API_KEY=k\n");
            assert!(exposure_issues(&env).is_empty());
        }
    }

    #[test]
    fn models_url_variants() {
        assert_eq!(
            models_url("http://v:8000").as_deref(),
            Some("http://v:8000/v1/models")
        );
        assert_eq!(
            models_url("http://v:8000/").as_deref(),
            Some("http://v:8000/v1/models")
        );
        assert_eq!(
            models_url("http://v:8000/v1").as_deref(),
            Some("http://v:8000/v1/models")
        );
        assert_eq!(
            models_url("https://h/v1/").as_deref(),
            Some("https://h/v1/models")
        );
        assert_eq!(models_url("ftp://h"), None);
        assert_eq!(models_url("not a url"), None);
        assert_eq!(models_url("file:///etc/passwd"), None);
    }

    #[test]
    fn url_redaction() {
        assert_eq!(redact_url("http://u:secret@h:8000/v1"), "http://h:8000/v1");
        assert_eq!(redact_url("http://h:8000"), "http://h:8000");
        assert_eq!(redact_url("::"), "<invalid>");
    }

    fn models_body(ids: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "object": "list",
            "data": ids.iter().map(|id| serde_json::json!({"id": id, "object": "model"})).collect::<Vec<_>>()
        })
    }

    #[tokio::test]
    async fn vllm_ok_with_api_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer k123"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(models_body(&["Qwen/Qwen3-32B", "small"])),
            )
            .mount(&server)
            .await;
        let r = check_vllm(
            &server.uri(),
            "Qwen/Qwen3-32B",
            Some("small"),
            Some("k123"),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(r.status, VllmStatus::Ok, "{r:?}");
        assert_eq!(r.models.len(), 2);
        assert_eq!(r.fast_model_present, Some(true));
        assert_eq!(r.http_status, Some(200));
    }

    #[tokio::test]
    async fn vllm_model_missing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(models_body(&["other"])))
            .mount(&server)
            .await;
        let base = format!("{}/v1/", server.uri());
        let r = check_vllm(&base, "qwen", Some("fast"), None, Duration::from_secs(5)).await;
        assert_eq!(r.status, VllmStatus::ModelMissing);
        assert_eq!(r.fast_model_present, Some(false));
        assert_eq!(r.models, vec!["other"]);
    }

    #[tokio::test]
    async fn vllm_auth_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let r = check_vllm(
            &server.uri(),
            "m",
            None,
            Some("wrong"),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(r.status, VllmStatus::AuthFailed);
        assert!(!r.error.unwrap_or_default().contains("wrong"));
    }

    #[tokio::test]
    async fn vllm_http_error_and_bad_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let r = check_vllm(&server.uri(), "m", None, None, Duration::from_secs(5)).await;
        assert_eq!(r.status, VllmStatus::HttpError);
        assert_eq!(r.http_status, Some(503));

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>hi</html>"))
            .mount(&server)
            .await;
        let r = check_vllm(&server.uri(), "m", None, None, Duration::from_secs(5)).await;
        assert_eq!(r.status, VllmStatus::InvalidResponse);
    }

    #[tokio::test]
    async fn vllm_unreachable_and_unconfigured() {
        // A bound but non-listening socket reserves a port that refuses
        // connections for the duration of the test.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = reserved.local_addr().unwrap().port();
        let r = check_vllm(
            &format!("http://127.0.0.1:{port}"),
            "m",
            None,
            None,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(r.status, VllmStatus::Unreachable);
        assert_eq!(
            check_vllm("", "m", None, None, Duration::from_secs(1))
                .await
                .status,
            VllmStatus::NotConfigured
        );
        assert_eq!(
            check_vllm("gopher://x", "m", None, None, Duration::from_secs(1))
                .await
                .status,
            VllmStatus::InvalidUrl
        );
    }

    #[tokio::test]
    async fn port_checks() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(check_port("127.0.0.1", port).await, PortStatus::InUse);
        drop(listener);
        // Port 0 always binds; a concrete freed port could be grabbed by a
        // concurrently running test.
        assert_eq!(check_port("127.0.0.1", 0).await, PortStatus::Free);
        assert!(matches!(
            check_port("203.0.113.7", port).await,
            PortStatus::Unavailable(_)
        ));
    }

    #[test]
    fn df_parsing() {
        let out = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n/dev/sda1        102400000  50000000  52400000      49% /\n";
        assert_eq!(parse_df_available_kb(out), Some(52_400_000));
        assert_eq!(parse_df_available_kb("garbage"), None);
    }

    #[tokio::test]
    async fn disk_free_with_real_df() {
        let dir = tempfile::tempdir().unwrap();
        let mb = disk_free_mb(&crate::runner::SystemCommandRunner, dir.path()).await;
        assert!(mb.is_some());
    }

    #[test]
    fn writable_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "x").unwrap();
        let failures = check_writable_dirs(&[dir.path().join("ok"), file.join("sub")]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, file.join("sub"));
    }

    #[tokio::test]
    async fn runtime_detection_prefers_configured() {
        let runner = MockRunner::new();
        runner.install("docker").install("podman");
        runner.on("docker info", CommandOutput::ok("27.0"));
        runner.on("podman info", CommandOutput::ok("5.0"));
        let report = detect_runtime(&runner, "podman").await;
        assert_eq!(report.selected.as_deref(), Some("podman"));

        let runner = MockRunner::new();
        runner.install("docker").install("podman");
        runner.on("docker info", CommandOutput::failed(1, "Cannot connect"));
        runner.on("podman info", CommandOutput::ok("5.0"));
        let report = detect_runtime(&runner, "docker").await;
        assert_eq!(report.state("docker"), RuntimeState::InstalledNotRunning);
        assert_eq!(report.selected.as_deref(), Some("podman"));

        let runner = MockRunner::new();
        let report = detect_runtime(&runner, "docker").await;
        assert_eq!(report.state("docker"), RuntimeState::NotFound);
        assert_eq!(report.selected, None);
        assert!(runner.calls().is_empty(), "must not run missing binaries");
    }

    #[tokio::test]
    async fn image_presence() {
        let runner = Arc::new(MockRunner::new());
        runner.on("docker image inspect", CommandOutput::ok("sha256:abc"));
        assert!(image_present(runner.as_ref(), "docker", "talon-agent:latest").await);
        assert!(!image_present(runner.as_ref(), "podman", "talon-agent:latest").await);
    }
}
