//! `talon-agent run`: the unprivileged agent process.
//!
//! 1. read the `ContainerInput` from stdin (bounded) and register the
//!    gateway token with the log redactor;
//! 2. clear a stale `_close`, open/resume/create the session (a missing
//!    session -> error frame containing `session not found`);
//! 3. build the first prompt (scheduled-task prefix, pending IPC input);
//! 4. `/compact` as the whole prompt -> compact the session and report;
//! 5. scheduled task with a script -> pre-flight; `wakeAgent=false` ->
//!    `success(null)` and exit;
//! 6. tools: built-in (+ `register_group` for main), fenced intel tools,
//!    MCP tools (sockets from the supervisor, or spawned in dev mode);
//! 7. system prompt, then the [`Agent`] session loop until `_close`.
//!
//! Every error ends with one `ContainerOutput::error` frame and exit code 1.

use std::path::Path;
use std::sync::Arc;

use talon_core::env::EnvFile;
use talon_core::protocol::{ContainerInput, ContainerOutput};
use talon_core::tool::{Tool, ToolContext};
use talon_llm::{ChatBackend, ChatMessage, VllmClient};
use talon_security::egress::EgressPolicy;
use talon_tools::{BuiltinOptions, WebFetchOptions, builtin_tools};
use tokio_util::sync::CancellationToken;

use crate::agent::{Agent, AgentParts, ArchiveOptions, CompactMode};
use crate::config::{AgentPaths, RunConfig};
use crate::error::AgentError;
use crate::ipc::IpcInbox;
use crate::model::ModelSettings;
use crate::prompt::{self, SUBMIT_TRIAGE_REPORT, SystemPromptInputs};
use crate::session::SessionStore;
use crate::tools::{FencedTool, ToolRegistry};
use crate::wire::{OutputSink, StdoutSink, parse_input, read_capped};
use crate::{logging, mcp, script};

/// Reply to `/compact` when it worked.
pub const COMPACTED_MESSAGE: &str = "Conversation compacted.";
/// Reply to `/compact` when there is nothing to compact.
pub const NOTHING_TO_COMPACT_MESSAGE: &str = "Nothing to compact: the conversation is empty.";

/// Entry point of `talon-agent run`: reads stdin, runs, returns the exit
/// code (0 ok, 1 error).
pub async fn run_main(config: RunConfig) -> i32 {
    warn_if_root();
    let output: Arc<dyn OutputSink> = Arc::new(StdoutSink);
    let bytes = match read_capped(tokio::io::stdin(), config.max_input_bytes).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "cannot read input");
            output.emit(&ContainerOutput::error(e.to_string()));
            return 1;
        }
    };
    run_bytes(&bytes, config, output).await
}

/// Run with already-read stdin bytes (used by the supervisor fallback).
pub async fn run_bytes(bytes: &[u8], config: RunConfig, output: Arc<dyn OutputSink>) -> i32 {
    let input = match parse_input(bytes) {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(error = %e, "invalid input");
            output.emit(&ContainerOutput::error(e.to_string()));
            return 1;
        }
    };
    let cancel = CancellationToken::new();
    spawn_signal_handler(cancel.clone());
    match execute(input, &config, None, output, cancel).await {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn warn_if_root() {
    if rustix::process::geteuid().is_root() {
        tracing::warn!(
            "talon-agent run is running as root; the container should drop privileges via `supervise`"
        );
    }
}

/// Cancel `token` on SIGTERM / SIGINT.
pub fn spawn_signal_handler(token: CancellationToken) {
    use tokio::signal::unix::{SignalKind, signal};
    tokio::spawn(async move {
        let (Ok(mut term), Ok(mut int)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            tracing::warn!("cannot install signal handlers");
            return;
        };
        tokio::select! {
            _ = term.recv() => tracing::info!("SIGTERM received; cancelling"),
            _ = int.recv() => tracing::info!("SIGINT received; cancelling"),
        }
        token.cancel();
    });
}

/// Run one container session for `input`. `backend` overrides the vLLM
/// client built from `input.llm` (tests). Emits the error frame itself.
pub async fn execute(
    input: ContainerInput,
    config: &RunConfig,
    backend: Option<Arc<dyn ChatBackend>>,
    output: Arc<dyn OutputSink>,
    cancel: CancellationToken,
) -> Result<(), AgentError> {
    let mut session: Option<SessionStore> = None;
    let result = execute_inner(&input, config, backend, &output, cancel, &mut session).await;
    if let Err(e) = &result {
        tracing::error!(kind = e.kind(), error = %e, "agent run failed");
        let mut frame = ContainerOutput::error(logging::redact(&e.to_string()));
        if !matches!(e, AgentError::SessionNotFound(_)) {
            // Report the session only if it exists on disk (resumable).
            frame.new_session_id = session
                .as_ref()
                .filter(|s| s.path().is_some_and(Path::exists))
                .map(|s| s.id().to_string());
        }
        output.emit(&frame);
    }
    result
}

async fn execute_inner(
    input: &ContainerInput,
    config: &RunConfig,
    backend: Option<Arc<dyn ChatBackend>>,
    output: &Arc<dyn OutputSink>,
    cancel: CancellationToken,
    session_out: &mut Option<SessionStore>,
) -> Result<(), AgentError> {
    if let Some(llm) = &input.llm {
        logging::register_secret(&llm.token);
    }
    let paths = &config.paths;
    tracing::info!(
        group = %input.group_folder,
        is_main = input.is_main,
        scheduled = input.is_scheduled_task,
        ephemeral = input.ephemeral,
        resume = input.session_id.is_some(),
        prompt_chars = input.prompt.len(),
        "received input"
    );
    let timezone = prompt::effective_timezone(input);
    let inbox = IpcInbox::new(paths.ipc_input());
    inbox.prepare();

    let (store, history) = open_session(input, paths)?;
    *session_out = Some(store.clone());
    tracing::info!(session = %store.id(), persistent = store.is_persistent(), messages = history.len(), "session ready");

    let mut first_prompt = if input.is_scheduled_task {
        prompt::scheduled_prompt(&input.prompt)
    } else {
        input.prompt.clone()
    };
    let pending = inbox.drain();
    if !pending.is_empty() {
        tracing::info!(
            count = pending.len(),
            "draining pending IPC messages into the initial prompt"
        );
        first_prompt.push('\n');
        first_prompt.push_str(&pending.join("\n"));
    }

    let archive = ArchiveOptions {
        dir: Some(paths.conversations()),
        assistant_name: input
            .assistant_name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| prompt::DEFAULT_ASSISTANT_NAME.to_string()),
        timezone: talon_core::time::parse_tz(&timezone),
    };
    let tool_ctx = tool_context(input, paths, cancel.clone());

    if first_prompt.trim() == "/compact" {
        let backend = make_backend(backend, input)?;
        return compact_command(CompactCommand {
            backend,
            model: model_settings(input),
            store,
            history,
            archive,
            tool_ctx,
            inbox,
            output: Arc::clone(output),
            config,
        })
        .await;
    }

    if input.is_scheduled_task {
        if let Some(script) = input.script.as_deref().filter(|s| !s.trim().is_empty()) {
            tracing::info!("running the task pre-flight script");
            match script::run_task_script(script, &paths.group, &cancel).await {
                Some(r) if r.wake_agent => {
                    tracing::info!("task script asked to wake the agent");
                    first_prompt = prompt::script_prompt(r.data.as_ref(), &input.prompt);
                }
                other => {
                    tracing::info!(
                        reason = if other.is_some() {
                            "wakeAgent=false"
                        } else {
                            "script error or no output"
                        },
                        "task script decided not to wake the agent"
                    );
                    output.emit(&ContainerOutput::success(None, None));
                    return Ok(());
                }
            }
        }
    }

    let backend = make_backend(backend, input)?;
    let model = model_settings(input);

    // Tools: built-in first, then intel, then MCP (which may not shadow them).
    let mut tools: Vec<Arc<dyn Tool>> = builtin_tools(&builtin_options(input, &timezone));
    tools.extend(intel_tools());
    let reserved: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
    let mcp_config = mcp::load_mcp_config(&paths.mcp_config);
    let mcp = mcp::start_mcp(mcp_config, config.mcp_socket_dir.as_deref(), reserved).await;
    if let Some(m) = &mcp.manager {
        tools.extend(m.tools());
    }
    let registry = Arc::new(ToolRegistry::new(tools));
    tracing::info!(tools = registry.len(), "tools ready");

    let investigation = prompt::is_investigation(input);
    let system_prompt = prompt::build_system_prompt(&SystemPromptInputs {
        assistant_name: archive.assistant_name.clone(),
        group_folder: input.group_folder.clone(),
        is_main: input.is_main,
        paths: paths.clone(),
        mcp_instructions: mcp
            .manager
            .as_ref()
            .map(talon_mcp::McpManager::instructions)
            .unwrap_or_default(),
        unavailable_mcp_servers: mcp.unavailable.clone(),
    });
    tracing::debug!(chars = system_prompt.len(), "system prompt built");

    if investigation {
        first_prompt.push_str("\n\n");
        first_prompt.push_str(&prompt::investigation_note(
            registry.contains(SUBMIT_TRIAGE_REPORT),
        ));
    }

    let mut agent = Agent::new(AgentParts {
        backend,
        model,
        tools: registry,
        tool_ctx,
        system_prompt,
        output: Arc::clone(output),
        inbox,
        store,
        history,
        settings: config.settings.clone(),
        archive,
        investigation,
    });
    let first = agent.with_turn_header(&first_prompt);
    let result = agent.run_session(first).await;
    if let Some(m) = &mcp.manager {
        m.shutdown_all().await;
    }
    result
}

fn open_session(
    input: &ContainerInput,
    paths: &AgentPaths,
) -> Result<(SessionStore, Vec<ChatMessage>), AgentError> {
    if input.ephemeral {
        if input.session_id.is_some() {
            tracing::warn!("ephemeral run: ignoring the session id to resume");
        }
        return Ok((SessionStore::ephemeral(), Vec::new()));
    }
    match input.session_id.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(id) => SessionStore::open(&paths.sessions_dir(), id.trim()),
        None => Ok((SessionStore::create(&paths.sessions_dir()), Vec::new())),
    }
}

fn make_backend(
    backend: Option<Arc<dyn ChatBackend>>,
    input: &ContainerInput,
) -> Result<Arc<dyn ChatBackend>, AgentError> {
    if let Some(b) = backend {
        return Ok(b);
    }
    let llm = input
        .llm
        .as_ref()
        .ok_or_else(|| AgentError::Config("ContainerInput has no llm endpoint".into()))?;
    Ok(Arc::new(VllmClient::from_endpoint(llm)?))
}

fn model_settings(input: &ContainerInput) -> ModelSettings {
    input.llm.as_ref().map_or_else(
        || ModelSettings::new("default", 0),
        ModelSettings::from_endpoint,
    )
}

fn tool_context(
    input: &ContainerInput,
    paths: &AgentPaths,
    cancel: CancellationToken,
) -> ToolContext {
    ToolContext {
        cwd: paths.group.clone(),
        allowed_roots: prompt::writable_roots(paths),
        read_only_roots: prompt::read_only_roots(paths, input.is_main),
        group_folder: input.group_folder.clone(),
        chat_jid: input.chat_jid.clone(),
        is_main: input.is_main,
        ipc_dir: paths.ipc.clone(),
        cancel,
    }
}

fn builtin_options(input: &ContainerInput, timezone: &str) -> BuiltinOptions {
    BuiltinOptions {
        web_fetch: Some(WebFetchOptions {
            egress: EgressPolicy::from_env(&EnvFile::default()),
            ..WebFetchOptions::default()
        }),
        register_group: input.is_main,
        ..BuiltinOptions::default()
    }
    .with_timezone_name(timezone)
}

/// The intel tools, each fenced as untrusted output except
/// `submit_triage_report` (which returns the model's own report).
pub fn intel_tools() -> Vec<Arc<dyn Tool>> {
    talon_intel::intel_tools(talon_intel::IntelToolOptions::default())
        .into_iter()
        .map(|t| {
            let name = t.spec().name;
            if name == SUBMIT_TRIAGE_REPORT {
                t
            } else {
                Arc::new(FencedTool::new(t, format!("intel:{name}"))) as Arc<dyn Tool>
            }
        })
        .collect()
}

struct CompactCommand<'a> {
    backend: Arc<dyn ChatBackend>,
    model: ModelSettings,
    store: SessionStore,
    history: Vec<ChatMessage>,
    archive: ArchiveOptions,
    tool_ctx: ToolContext,
    inbox: IpcInbox,
    output: Arc<dyn OutputSink>,
    config: &'a RunConfig,
}

async fn compact_command(cmd: CompactCommand<'_>) -> Result<(), AgentError> {
    tracing::info!(messages = cmd.history.len(), "handling /compact");
    let output = Arc::clone(&cmd.output);
    let mut agent = Agent::new(AgentParts {
        backend: cmd.backend,
        model: cmd.model,
        tools: Arc::new(ToolRegistry::new(Vec::new())),
        tool_ctx: cmd.tool_ctx,
        system_prompt: String::new(),
        output: cmd.output,
        inbox: cmd.inbox,
        store: cmd.store,
        history: cmd.history,
        settings: cmd.config.settings.clone(),
        archive: cmd.archive,
        investigation: false,
    });
    let compacted = agent.compact(CompactMode::All).await?;
    let message = if compacted {
        COMPACTED_MESSAGE
    } else {
        NOTHING_TO_COMPACT_MESSAGE
    };
    output.emit(&ContainerOutput::success(
        Some(message.to_string()),
        agent.reported_session_id(),
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use talon_core::protocol::OutputStatus;
    use talon_llm::{ChatResponse, ScriptedBackend};

    use crate::wire::MemorySink;

    fn input(prompt: &str) -> ContainerInput {
        serde_json::from_value(serde_json::json!({
            "prompt": prompt,
            "groupFolder": "testgroup",
            "chatJid": "tg:1",
            "isMain": false,
            "timezone": "UTC"
        }))
        .unwrap()
    }

    struct Env {
        dir: tempfile::TempDir,
        config: RunConfig,
        sink: Arc<MemorySink>,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let paths = AgentPaths::under(dir.path());
        std::fs::create_dir_all(&paths.group).unwrap();
        std::fs::create_dir_all(paths.ipc_input()).unwrap();
        let mut config = RunConfig {
            paths,
            ..RunConfig::default()
        };
        config.settings.ipc_poll = std::time::Duration::from_millis(10);
        Env {
            dir,
            config,
            sink: Arc::new(MemorySink::new()),
        }
    }

    fn text(t: &str) -> Result<ChatResponse, talon_llm::LlmError> {
        Ok(ChatResponse::from_message(ChatMessage::assistant(t)))
    }

    async fn run(
        env: &Env,
        input: ContainerInput,
        backend: Arc<ScriptedBackend>,
    ) -> Result<(), AgentError> {
        execute(
            input,
            &env.config,
            Some(backend),
            env.sink.clone(),
            CancellationToken::new(),
        )
        .await
    }

    fn close_soon(env: &Env) {
        let close = env.config.paths.ipc_input().join("_close");
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            std::fs::write(close, "").unwrap();
        });
    }

    #[tokio::test]
    async fn full_run_creates_a_resumable_session() {
        let env = env();
        let backend = Arc::new(ScriptedBackend::new([text("hello there")]));
        close_soon(&env);
        run(&env, input("hi"), backend.clone()).await.unwrap();
        let frames = env.sink.frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].status, OutputStatus::Success);
        assert_eq!(frames[0].result.as_deref(), Some("hello there"));
        let id = frames[0].new_session_id.clone().unwrap();
        let req = &backend.requests()[0];
        // Built-in + intel tools; no register_group for non-main groups.
        let names: Vec<&str> = req.offered_tool_names().collect();
        assert!(names.contains(&"bash"));
        assert!(names.contains(&"extract_iocs"));
        assert!(names.contains(&SUBMIT_TRIAGE_REPORT));
        assert!(!names.contains(&"register_group"));
        assert!(req.messages[0].text().contains("## Untrusted data"));
        assert!(
            req.messages[1]
                .text()
                .starts_with("[Current date and time:")
        );
        assert!(req.messages[1].text().ends_with("hi"));

        // Resume with the returned id.
        let backend2 = Arc::new(ScriptedBackend::new([text("again")]));
        let mut second = input("more");
        second.session_id = Some(id.clone());
        close_soon(&env);
        run(&env, second, backend2.clone()).await.unwrap();
        assert_eq!(backend2.requests()[0].messages.len(), 4);
        assert_eq!(
            env.sink.frames()[1].new_session_id.as_deref(),
            Some(id.as_str())
        );
    }

    #[tokio::test]
    async fn missing_session_reports_session_not_found() {
        let env = env();
        let backend = Arc::new(ScriptedBackend::new([]));
        let mut i = input("hi");
        i.session_id = Some(uuid::Uuid::new_v4().to_string());
        let err = run(&env, i, backend.clone()).await.unwrap_err();
        assert!(matches!(err, AgentError::SessionNotFound(_)));
        let frames = env.sink.frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].status, OutputStatus::Error);
        assert!(
            frames[0]
                .error
                .as_deref()
                .unwrap()
                .contains("session not found")
        );
        assert!(frames[0].new_session_id.is_none());
        assert!(backend.requests().is_empty());
    }

    #[tokio::test]
    async fn script_wake_false_exits_without_the_model() {
        let env = env();
        let backend = Arc::new(ScriptedBackend::new([]));
        let mut i = input("check things");
        i.is_scheduled_task = true;
        i.script = Some("echo '{\"wakeAgent\": false}'".into());
        run(&env, i, backend.clone()).await.unwrap();
        let frames = env.sink.frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].status, OutputStatus::Success);
        assert!(frames[0].result.is_none());
        assert!(backend.requests().is_empty());
    }

    #[tokio::test]
    async fn script_wake_true_enriches_the_prompt() {
        let env = env();
        let backend = Arc::new(ScriptedBackend::new([text("sweep done")]));
        let mut i = input("summarize new alerts");
        i.is_scheduled_task = true;
        i.script = Some("echo '{\"wakeAgent\": true, \"data\": {\"new\": 3}}'".into());
        close_soon(&env);
        run(&env, i, backend.clone()).await.unwrap();
        let user = backend.requests()[0].messages[1].text().to_string();
        assert!(user.contains("[SCHEDULED TASK]\n\nScript output:\n<untrusted_data"));
        assert!(user.contains("\"new\": 3"));
        assert!(user.contains("Instructions:\nsummarize new alerts"));
    }

    #[tokio::test]
    async fn scheduled_prefix_and_pending_ipc_and_investigation_note() {
        let env = env();
        std::fs::write(
            env.config.paths.ipc_input().join("1.json"),
            r#"{"type":"message","text":"pending note"}"#,
        )
        .unwrap();
        // Stale _close from a previous run must be ignored.
        std::fs::write(env.config.paths.ipc_input().join("_close"), "").unwrap();
        let backend = Arc::new(ScriptedBackend::new([text("ok")]));
        let mut i = input("sweep");
        i.group_folder = "copilot".into();
        i.is_scheduled_task = true;
        i.ephemeral = true;
        close_soon(&env);
        run(&env, i, backend.clone()).await.unwrap();
        let user = backend.requests()[0].messages[1].text().to_string();
        assert!(user.contains(prompt::SCHEDULED_TASK_PREFIX));
        assert!(user.contains("sweep\npending note"));
        assert!(user.contains("[Investigation mode]"));
        assert!(user.contains(SUBMIT_TRIAGE_REPORT));
        // Ephemeral: no session id, nothing on disk.
        assert!(env.sink.frames()[0].new_session_id.is_none());
        assert!(!env.config.paths.sessions_dir().exists());
    }

    #[tokio::test]
    async fn compact_command_compacts_and_reports() {
        let env = env();
        // Session with history.
        let backend = Arc::new(ScriptedBackend::new([text("first answer")]));
        close_soon(&env);
        run(&env, input("first"), backend).await.unwrap();
        let id = env.sink.frames()[0].new_session_id.clone().unwrap();

        let backend = Arc::new(ScriptedBackend::new([text("Title: Greeting\n\nSaid hi.")]));
        let mut i = input("/compact");
        i.session_id = Some(id.clone());
        run(&env, i, backend.clone()).await.unwrap();
        let frames = env.sink.frames();
        let last = frames.last().unwrap();
        assert_eq!(last.result.as_deref(), Some(COMPACTED_MESSAGE));
        assert_eq!(last.new_session_id.as_deref(), Some(id.as_str()));
        assert_eq!(backend.requests()[0].model, "default");
        let archives = std::fs::read_dir(env.config.paths.conversations())
            .unwrap()
            .count();
        assert_eq!(archives, 1);

        // Fresh session: nothing to compact.
        let backend = Arc::new(ScriptedBackend::new([]));
        run(&env, input("  /compact "), backend).await.unwrap();
        assert_eq!(
            env.sink.frames().last().unwrap().result.as_deref(),
            Some(NOTHING_TO_COMPACT_MESSAGE)
        );
    }

    #[tokio::test]
    async fn missing_endpoint_is_a_config_error() {
        let env = env();
        let err = execute(
            input("hi"),
            &env.config,
            None,
            env.sink.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AgentError::Config(_)));
        assert_eq!(env.sink.frames()[0].status, OutputStatus::Error);
        let _ = env.dir.path();
    }

    #[test]
    fn intel_tools_are_fenced_except_submit() {
        let tools = intel_tools();
        assert!(tools.len() >= 7);
        assert!(tools.iter().any(|t| t.spec().name == SUBMIT_TRIAGE_REPORT));
    }

    #[tokio::test]
    async fn bad_stdin_bytes_produce_an_error_frame() {
        let sink = Arc::new(MemorySink::new());
        let code = run_bytes(b"{oops", RunConfig::default(), sink.clone()).await;
        assert_eq!(code, 1);
        assert_eq!(sink.frames()[0].status, OutputStatus::Error);
    }
}
