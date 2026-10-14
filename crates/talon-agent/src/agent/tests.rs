use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use talon_core::tool::{Tool, ToolOutput, ToolSpec};
use talon_llm::{ResponseFormat, ScriptedBackend, ToolCall};

use super::*;
use crate::compact::SUMMARY_PREFIX;
use crate::tools::test_tools::{RecordWriteTool, SlowReadTool, ctx};
use crate::wire::MemorySink;

fn call(id: &str, name: &str, args: &str) -> ToolCall {
    ToolCall::new(id, name, args)
}

fn tool_resp(calls: Vec<ToolCall>) -> Result<ChatResponse, LlmError> {
    Ok(ChatResponse::from_message(
        ChatMessage::assistant_tool_calls(None, calls),
    ))
}

fn text_resp(text: &str) -> Result<ChatResponse, LlmError> {
    Ok(ChatResponse::from_message(ChatMessage::assistant(text)))
}

fn with_usage(
    r: Result<ChatResponse, LlmError>,
    prompt: u64,
    completion: u64,
    cached: u64,
) -> Result<ChatResponse, LlmError> {
    r.map(|mut resp| {
        resp.usage = Usage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            cached_tokens: cached,
        };
        resp
    })
}

/// Records submitted reports.
#[derive(Default)]
struct FakeSubmit {
    calls: Mutex<Vec<Value>>,
}

#[async_trait]
impl Tool for FakeSubmit {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: SUBMIT_TRIAGE_REPORT.into(),
            description: "submit the report".into(),
            parameters: json!({"type":"object","properties":{"report":{"type":"object"}},"required":["report"]}),
        }
    }
    async fn call(&self, args: Value, _ctx: &ToolContext) -> ToolOutput {
        if args
            .pointer("/report/verdict")
            .and_then(Value::as_str)
            .is_none()
        {
            return ToolOutput::err("missing verdict");
        }
        self.calls.lock().unwrap().push(args);
        ToolOutput::ok("# Report")
    }
}

fn report_json(verdict: &str) -> Value {
    json!({
        "alert_id": "1",
        "verdict": verdict,
        "confidence": 40,
        "severity": "medium",
        "summary": "Host A shows malware X activity.",
        "iocs": [],
        "mitre": [],
        "timeline": [],
        "evidence": [],
        "recommended_actions": []
    })
}

struct Harness {
    dir: tempfile::TempDir,
    backend: Arc<ScriptedBackend>,
    sink: Arc<MemorySink>,
    slow: Arc<SlowReadTool>,
    write: Arc<RecordWriteTool>,
}

impl Harness {
    fn new(responses: Vec<Result<ChatResponse, LlmError>>) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            backend: Arc::new(ScriptedBackend::new(responses)),
            sink: Arc::new(MemorySink::new()),
            slow: Arc::new(SlowReadTool::default()),
            write: Arc::new(RecordWriteTool::default()),
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn inbox_dir(&self) -> PathBuf {
        self.root().join("ipc").join("input")
    }

    fn sessions(&self) -> PathBuf {
        self.root().join("sessions")
    }

    fn conversations(&self) -> PathBuf {
        self.root().join("conversations")
    }

    fn parts(&self, extra_tools: Vec<Arc<dyn Tool>>) -> AgentParts {
        let mut tools: Vec<Arc<dyn Tool>> = vec![
            self.slow.clone() as Arc<dyn Tool>,
            self.write.clone() as Arc<dyn Tool>,
        ];
        tools.extend(extra_tools);
        std::fs::create_dir_all(self.inbox_dir()).unwrap();
        AgentParts {
            backend: self.backend.clone(),
            model: {
                let mut m = ModelSettings::new("main-model", 32_768);
                m.fast_model = "fast-model".into();
                m
            },
            tools: Arc::new(ToolRegistry::new(tools)),
            tool_ctx: ctx(self.root()),
            system_prompt: "SYSTEM".into(),
            output: self.sink.clone(),
            inbox: IpcInbox::new(self.inbox_dir()),
            store: SessionStore::create(&self.sessions()),
            history: Vec::new(),
            settings: LoopSettings {
                ipc_poll: Duration::from_millis(10),
                ..LoopSettings::default()
            },
            archive: ArchiveOptions {
                dir: Some(self.conversations()),
                assistant_name: "Andy".into(),
                timezone: chrono_tz::UTC,
            },
            investigation: false,
        }
    }

    fn agent(&self) -> Agent {
        Agent::new(self.parts(vec![]))
    }

    fn write_ipc(&self, name: &str, body: &str) {
        std::fs::write(self.inbox_dir().join(name), body).unwrap();
    }
}

fn roles(msgs: &[ChatMessage]) -> Vec<Role> {
    msgs.iter().map(|m| m.role).collect()
}

#[tokio::test]
async fn tool_call_round_trip() {
    let h = Harness::new(vec![
        tool_resp(vec![call("c1", "slow_read", r#"{"q":"alerts"}"#)]),
        text_resp("Found the alerts."),
    ]);
    let mut agent = h.agent();
    let out = agent.run_turn("check alerts".into()).await.unwrap();
    assert_eq!(out.result.as_deref(), Some("Found the alerts."));
    assert_eq!(out.iterations, 2);
    assert_eq!(out.tool_calls, 1);
    assert!(!out.forced);
    assert_eq!(
        roles(agent.history()),
        vec![Role::User, Role::Assistant, Role::Tool, Role::Assistant]
    );
    assert_eq!(agent.history()[2].text(), "read alerts");
    let reqs = h.backend.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].messages[0].role, Role::System);
    assert_eq!(reqs[0].messages[0].text(), "SYSTEM");
    assert_eq!(reqs[0].tool_choice, Some(ToolChoice::Auto));
    assert_eq!(reqs[0].parallel_tool_calls, Some(true));
    assert_eq!(reqs[0].tools.len(), 2);
    // Prefix stability: the second request extends the first.
    assert_eq!(reqs[1].messages[..2], reqs[0].messages[..2]);
    assert_eq!(reqs[1].tools, reqs[0].tools);
    // Persisted.
    let (_, loaded) = SessionStore::open(&h.sessions(), agent.session_id()).unwrap();
    assert_eq!(loaded.len(), 4);
}

#[tokio::test]
async fn parallel_read_only_calls_in_one_response() {
    let h = Harness::new(vec![
        tool_resp(vec![
            call("a", "slow_read", r#"{"q":"1"}"#),
            call("b", "slow_read", r#"{"q":"2"}"#),
            call("c", "record_write", r#"{"v":"x"}"#),
        ]),
        text_resp("ok"),
    ]);
    let mut agent = h.agent();
    agent.run_turn("go".into()).await.unwrap();
    assert_eq!(h.slow.max.load(Ordering::SeqCst), 2);
    let tool_msgs: Vec<_> = agent
        .history()
        .iter()
        .filter(|m| m.role == Role::Tool)
        .map(|m| (m.tool_call_id.clone().unwrap(), m.text().to_string()))
        .collect();
    assert_eq!(
        tool_msgs,
        vec![
            ("a".to_string(), "read 1".to_string()),
            ("b".to_string(), "read 2".to_string()),
            ("c".to_string(), "wrote x".to_string()),
        ]
    );
}

#[tokio::test]
async fn unknown_tools_and_malformed_arguments_go_back_to_the_model() {
    let h = Harness::new(vec![
        tool_resp(vec![
            call("a", "does_not_exist", "{}"),
            call("b", "slow_read", "{\"q\": \"x"),
            call("", "slow_read", r#"{"q":"fine"}"#),
        ]),
        text_resp("recovered"),
    ]);
    let mut agent = h.agent();
    let out = agent.run_turn("go".into()).await.unwrap();
    assert_eq!(out.result.as_deref(), Some("recovered"));
    let hist = agent.history();
    let assistant = &hist[1];
    assert_eq!(assistant.tool_calls[1].function.arguments, "{}");
    assert!(!assistant.tool_calls[2].id.is_empty());
    assert!(hist[2].text().contains("unknown tool 'does_not_exist'"));
    assert!(hist[3].text().contains("invalid JSON arguments"));
    assert_eq!(hist[4].text(), "read fine");
    assert_eq!(
        hist[4].tool_call_id.as_deref(),
        Some(assistant.tool_calls[2].id.as_str())
    );
    assert_eq!(h.slow.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn loop_detection_nudges_then_stops() {
    let same = || tool_resp(vec![call("x", "slow_read", r#"{"q":"same"}"#)]);
    let h = Harness::new(vec![
        same(),
        same(),
        same(),
        same(),
        same(),
        text_resp("giving up"),
    ]);
    let mut agent = h.agent();
    let out = agent.run_turn("loop".into()).await.unwrap();
    assert!(out.forced);
    assert_eq!(out.result.as_deref(), Some("giving up"));
    // 4 executions; the 5th repetition is not executed.
    assert_eq!(h.slow.calls.load(Ordering::SeqCst), 4);
    let tool_texts: Vec<String> = agent
        .history()
        .iter()
        .filter(|m| m.role == Role::Tool)
        .map(|m| m.text().to_string())
        .collect();
    assert_eq!(tool_texts.len(), 5);
    assert!(!tool_texts[1].contains("[talon] Note"));
    assert!(tool_texts[2].contains("call #3"));
    assert!(tool_texts[3].contains("call #4"));
    assert!(tool_texts[4].contains("Not executed"));
    let reqs = h.backend.requests();
    assert_eq!(reqs.len(), 6);
    assert_eq!(reqs[5].tool_choice, Some(ToolChoice::None));
    assert!(
        reqs[5]
            .messages
            .iter()
            .any(|m| m.text() == prompt::FORCE_FINAL_LOOP)
    );
}

#[tokio::test]
async fn max_iterations_forces_a_final_answer() {
    let h = Harness::new(vec![
        tool_resp(vec![call("1", "slow_read", r#"{"q":"1"}"#)]),
        tool_resp(vec![call("2", "slow_read", r#"{"q":"2"}"#)]),
        // The forced request still gets a tool call: it must be ignored.
        tool_resp(vec![call("3", "slow_read", r#"{"q":"3"}"#)]),
    ]);
    let mut parts = h.parts(vec![]);
    parts.settings.max_iterations = 2;
    let mut agent = Agent::new(parts);
    let out = agent.run_turn("dig".into()).await.unwrap();
    assert!(out.forced);
    assert_eq!(out.iterations, 2);
    assert_eq!(out.result.as_deref(), Some(prompt::EMPTY_ANSWER_FALLBACK));
    assert_eq!(h.slow.calls.load(Ordering::SeqCst), 2);
    let last = agent.history().last().unwrap();
    assert!(last.tool_calls.is_empty());
    let reqs = h.backend.requests();
    assert_eq!(reqs[2].tool_choice, Some(ToolChoice::None));
    assert!(
        reqs[2]
            .messages
            .iter()
            .any(|m| m.text() == prompt::FORCE_FINAL_BUDGET)
    );
}

#[tokio::test]
async fn threshold_compaction_summarizes_archives_and_rewrites() {
    let h = Harness::new(vec![
        text_resp("Title: Old alert work\n\nThe user asked about alerts 1-6."),
        text_resp("fresh answer"),
    ]);
    let mut parts = h.parts(vec![]);
    parts.model.max_context_tokens = 2_000;
    let store = parts.store.clone();
    let mut history = Vec::new();
    for i in 0..6 {
        history.push(ChatMessage::user(format!(
            "question {i} {}",
            "q".repeat(1_000)
        )));
        history.push(ChatMessage::assistant(format!(
            "answer {i} {}",
            "a".repeat(1_000)
        )));
    }
    for m in &history {
        store.append(m).unwrap();
    }
    parts.history = history;
    let mut agent = Agent::new(parts);
    let out = agent.run_turn("new question".into()).await.unwrap();
    assert_eq!(out.compactions, 1);
    assert_eq!(out.result.as_deref(), Some("fresh answer"));
    let reqs = h.backend.requests();
    assert_eq!(reqs[0].model, "fast-model");
    assert!(reqs[0].tools.is_empty());
    assert!(reqs[0].messages[1].text().contains("question 0"));
    assert_eq!(reqs[1].model, "main-model");
    assert!(reqs[1].messages[1].text().starts_with(SUMMARY_PREFIX));
    assert!(reqs[1].messages[1].text().contains("alerts 1-6"));
    assert_eq!(reqs[1].messages[2].text(), compact::SUMMARY_ACK);
    // The last two user turns are kept verbatim.
    assert!(reqs[1].messages[3].text().starts_with("question 5"));
    assert!(!reqs[0].messages[1].text().contains("question 5"));
    assert_eq!(reqs[1].messages.last().unwrap().text(), "new question");
    // Archive written with the summary title.
    let archived: Vec<_> = std::fs::read_dir(h.conversations())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(archived.len(), 1);
    assert!(archived[0].ends_with("-old-alert-work.md"), "{archived:?}");
    let md = std::fs::read_to_string(h.conversations().join(&archived[0])).unwrap();
    assert!(md.contains("**Andy**: answer 0"));
    // Transcript rewritten: summary + ack + kept turn + new turn.
    let (_, loaded) = SessionStore::open(&h.sessions(), agent.session_id()).unwrap();
    assert_eq!(loaded.len(), 6);
    assert!(loaded[0].text().starts_with(SUMMARY_PREFIX));
    assert_eq!(loaded[5].text(), "fresh answer");
}

#[tokio::test]
async fn context_overflow_compacts_and_retries_once() {
    let h = Harness::new(vec![
        Err(LlmError::ContextLengthExceeded("too long".into())),
        Err(LlmError::Http {
            status: 500,
            message: "summarizer down".into(),
            retry_after: None,
        }),
        text_resp("after retry"),
    ]);
    let mut parts = h.parts(vec![]);
    parts.history = vec![
        ChatMessage::user("old question"),
        ChatMessage::assistant("old answer"),
    ];
    let mut agent = Agent::new(parts);
    let out = agent.run_turn("q".into()).await.unwrap();
    assert_eq!(out.result.as_deref(), Some("after retry"));
    assert_eq!(out.compactions, 1);
    let reqs = h.backend.requests();
    assert_eq!(reqs.len(), 3);
    assert_eq!(reqs[1].model, "fast-model");
    // The mechanical fallback summary was used.
    assert!(reqs[2].messages[1].text().contains("- User: old question"));
}

#[tokio::test]
async fn repeated_overflow_is_fatal() {
    let h = Harness::new(vec![
        Err(LlmError::ContextLengthExceeded("a".into())),
        text_resp("summary"),
        Err(LlmError::ContextLengthExceeded("b".into())),
    ]);
    let mut parts = h.parts(vec![]);
    parts.history = vec![ChatMessage::user("x"), ChatMessage::assistant("y")];
    let mut agent = Agent::new(parts);
    let err = agent.run_turn("q".into()).await.unwrap_err();
    assert!(matches!(err, AgentError::ContextOverflow(_)), "{err:?}");

    // Nothing to compact at all.
    let h = Harness::new(vec![Err(LlmError::ContextLengthExceeded("c".into()))]);
    let mut agent = h.agent();
    let err = agent.run_turn("only message".into()).await.unwrap_err();
    assert!(matches!(err, AgentError::ContextOverflow(_)));
}

#[tokio::test]
async fn compact_all_for_the_compact_command() {
    let h = Harness::new(vec![text_resp("Title: T\n\nall of it")]);
    let mut parts = h.parts(vec![]);
    parts.history = vec![ChatMessage::user("a"), ChatMessage::assistant("b")];
    let mut agent = Agent::new(parts);
    assert!(agent.compact(CompactMode::All).await.unwrap());
    assert_eq!(roles(agent.history()), vec![Role::User, Role::Assistant]);
    assert!(agent.history()[0].text().contains("all of it"));

    let h = Harness::new(vec![]);
    let mut agent = h.agent();
    assert!(!agent.compact(CompactMode::All).await.unwrap());
}

#[tokio::test]
async fn session_resume_continues_the_conversation() {
    let h = Harness::new(vec![text_resp("one")]);
    let mut agent = h.agent();
    agent.run_turn("first".into()).await.unwrap();
    let id = agent.session_id().to_string();
    drop(agent);

    let (store, history) = SessionStore::open(&h.sessions(), &id).unwrap();
    assert_eq!(history.len(), 2);
    let backend2 = Arc::new(ScriptedBackend::new([text_resp("two")]));
    let mut parts = h.parts(vec![]);
    parts.backend = backend2.clone();
    parts.store = store;
    parts.history = history;
    let mut agent = Agent::new(parts);
    agent.run_turn("second".into()).await.unwrap();
    let req = &backend2.requests()[0];
    let texts: Vec<&str> = req.messages.iter().map(ChatMessage::text).collect();
    assert_eq!(texts, vec!["SYSTEM", "first", "one", "second"]);
    let (_, history) = SessionStore::open(&h.sessions(), &id).unwrap();
    assert_eq!(history.len(), 4);
}

#[tokio::test]
async fn ipc_follow_up_is_piped_into_the_active_turn() {
    let h = Harness::new(vec![
        tool_resp(vec![call("1", "slow_read", r#"{"q":"a"}"#)]),
        text_resp("answered both"),
    ]);
    let mut agent = h.agent();
    h.write_ipc(
        "1-a.json",
        r#"{"type":"message","text":"also check host B"}"#,
    );
    agent.run_turn("check host A".into()).await.unwrap();
    let reqs = h.backend.requests();
    // First request: only the original prompt (iteration 0 does not drain).
    assert_eq!(reqs[0].messages.len(), 2);
    let second: Vec<(Role, &str)> = reqs[1]
        .messages
        .iter()
        .map(|m| (m.role, m.text()))
        .collect();
    assert_eq!(second[3], (Role::Tool, "read a"));
    assert_eq!(second[4], (Role::User, "also check host B"));
    assert!(!h.inbox_dir().join("1-a.json").exists());
}

#[tokio::test]
async fn session_emits_frames_handles_follow_ups_and_close() {
    let h = Harness::new(vec![
        with_usage(
            tool_resp(vec![call("1", "slow_read", r#"{"q":"a"}"#)]),
            100,
            10,
            40,
        ),
        with_usage(text_resp("first answer"), 100, 10, 40),
        text_resp("second answer"),
    ]);
    let mut agent = h.agent();
    h.write_ipc("1.json", r#"{"type":"message","text":"follow-up"}"#);
    let inbox = h.inbox_dir();
    let closer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        std::fs::write(inbox.join("_close"), "").unwrap();
    });
    // The pending message is piped into turn 1 at the first iteration
    // boundary (after the tool round trip); afterwards only _close arrives.
    tokio::time::timeout(Duration::from_secs(5), agent.run_session("hello".into()))
        .await
        .unwrap()
        .unwrap();
    closer.await.unwrap();
    let frames = h.sink.frames();
    assert_eq!(frames.len(), 1, "{frames:?}");
    let f = &frames[0];
    assert_eq!(f.result.as_deref(), Some("first answer"));
    assert_eq!(f.new_session_id.as_deref(), Some(agent.session_id()));
    let usage = f.usage.unwrap();
    assert_eq!(usage.input_tokens, Some(120));
    assert_eq!(usage.cache_read_input_tokens, Some(80));
    assert_eq!(usage.output_tokens, Some(20));
    // The follow-up was absorbed by the running turn.
    assert!(agent.history().iter().any(|m| m.text() == "follow-up"));
}

#[tokio::test]
async fn idle_follow_up_starts_a_new_turn_then_close_ends() {
    let h = Harness::new(vec![text_resp("first"), text_resp("second")]);
    let mut parts = h.parts(vec![]);
    parts.store = SessionStore::ephemeral();
    let mut agent = Agent::new(parts);
    h.write_ipc("1.json", r#"{"type":"message","text":"next please"}"#);
    let inbox = h.inbox_dir();
    let closer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        std::fs::write(inbox.join("_close"), "").unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), agent.run_session("hi".into()))
        .await
        .unwrap()
        .unwrap();
    closer.await.unwrap();
    let frames = h.sink.frames();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].result.as_deref(), Some("first"));
    assert_eq!(frames[1].result.as_deref(), Some("second"));
    // Ephemeral sessions report no id and write nothing.
    assert!(frames.iter().all(|f| f.new_session_id.is_none()));
    assert!(!h.sessions().exists());
    // The follow-up turn starts with the time header.
    let reqs = h.backend.requests();
    let last_user = reqs[1].messages.last().unwrap().text();
    assert!(
        last_user.starts_with("[Current date and time:"),
        "{last_user}"
    );
    assert!(last_user.ends_with("next please"));
}

#[tokio::test]
async fn close_during_turn_finishes_the_turn_and_ends() {
    let h = Harness::new(vec![
        tool_resp(vec![call("1", "slow_read", r#"{"q":"a"}"#)]),
        text_resp("done"),
    ]);
    let mut agent = h.agent();
    h.write_ipc("_close", "");
    h.write_ipc("1.json", r#"{"type":"message","text":"late"}"#);
    tokio::time::timeout(Duration::from_secs(5), agent.run_session("work".into()))
        .await
        .unwrap()
        .unwrap();
    let frames = h.sink.frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].result.as_deref(), Some("done"));
    // Messages after _close are left for the next container.
    assert!(h.inbox_dir().join("1.json").exists());
}

#[tokio::test]
async fn investigation_self_check_and_guided_report() {
    let h = Harness::new(vec![
        tool_resp(vec![call("1", "slow_read", r#"{"q":"event"}"#)]),
        text_resp("Draft: host A is compromised by malware X (confirmed)."),
        text_resp("Verified: host A shows malware X activity; compromise unconfirmed."),
        text_resp(&report_json("needs_escalation").to_string()),
    ]);
    let submit = Arc::new(FakeSubmit::default());
    let mut parts = h.parts(vec![submit.clone() as Arc<dyn Tool>]);
    parts.investigation = true;
    let mut agent = Agent::new(parts);
    let out = agent.run_turn("investigate alert 1".into()).await.unwrap();
    assert_eq!(
        out.result.as_deref(),
        Some("Verified: host A shows malware X activity; compromise unconfirmed.")
    );
    let reqs = h.backend.requests();
    assert_eq!(reqs.len(), 4);
    assert_eq!(reqs[2].tool_choice, Some(ToolChoice::None));
    assert_eq!(
        reqs[2].messages.last().unwrap().text(),
        prompt::SELF_CHECK_PROMPT
    );
    assert!(matches!(
        reqs[3].response_format,
        Some(ResponseFormat::JsonSchema { .. })
    ));
    assert!(reqs[3].tools.is_empty());
    let submitted = submit.calls.lock().unwrap().clone();
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0]["report"], report_json("needs_escalation"));
    // The history holds the verified answer, not the draft.
    assert_eq!(
        agent.history().last().unwrap().text(),
        out.result.as_deref().unwrap()
    );
}

#[tokio::test]
async fn investigation_report_submitted_by_the_model_skips_guided_decoding() {
    let h = Harness::new(vec![
        tool_resp(vec![call(
            "1",
            SUBMIT_TRIAGE_REPORT,
            &json!({ "report": report_json("false_positive") }).to_string(),
        )]),
        text_resp("Benign: scheduled backup job."),
        // Self-check reply too short to be a full answer: draft kept.
        text_resp("OK"),
    ]);
    let submit = Arc::new(FakeSubmit::default());
    let mut parts = h.parts(vec![submit.clone() as Arc<dyn Tool>]);
    parts.investigation = true;
    let mut agent = Agent::new(parts);
    let out = agent.run_turn("investigate".into()).await.unwrap();
    assert_eq!(out.result.as_deref(), Some("Benign: scheduled backup job."));
    assert_eq!(h.backend.requests().len(), 3);
    assert_eq!(submit.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn self_check_disabled_and_chat_turns_skip_it() {
    let h = Harness::new(vec![
        tool_resp(vec![call("1", "slow_read", r#"{"q":"x"}"#)]),
        text_resp("answer"),
    ]);
    let mut parts = h.parts(vec![]);
    parts.investigation = true;
    parts.settings.self_check = false;
    let mut agent = Agent::new(parts);
    agent.run_turn("investigate".into()).await.unwrap();
    // No submit tool registered: no report request either.
    assert_eq!(h.backend.requests().len(), 2);
}

#[tokio::test]
async fn cancellation_stops_the_turn() {
    let h = Harness::new(vec![text_resp("never")]);
    let parts = h.parts(vec![]);
    parts.tool_ctx.cancel.cancel();
    let mut agent = Agent::new(parts);
    let err = agent.run_turn("x".into()).await.unwrap_err();
    assert!(matches!(err, AgentError::Cancelled));
    assert_eq!(h.backend.requests().len(), 0);
}

#[tokio::test]
async fn llm_errors_propagate() {
    let h = Harness::new(vec![Err(LlmError::Unauthorized {
        status: 401,
        message: "expired".into(),
    })]);
    let mut agent = h.agent();
    let err = agent.run_turn("x".into()).await.unwrap_err();
    assert!(matches!(
        err,
        AgentError::Llm(LlmError::Unauthorized { .. })
    ));
    assert!(format!("{agent:?}").contains("Agent"));
    assert_eq!(agent.system_prompt(), "SYSTEM");
}

#[tokio::test]
async fn text_tool_calls_are_recovered_by_the_backend() {
    // Hermes-style tool call written as text (vLLM without a tool parser).
    let h = Harness::new(vec![
        text_resp("<tool_call>{\"name\":\"slow_read\",\"arguments\":{\"q\":\"t\"}}</tool_call>"),
        text_resp("done"),
    ]);
    let mut agent = h.agent();
    let out = agent.run_turn("x".into()).await.unwrap();
    assert_eq!(out.tool_calls, 1);
    assert_eq!(h.slow.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn forced_answers_never_contain_tool_markup() {
    let h = Harness::new(vec![
        tool_resp(vec![call("1", "slow_read", r#"{"q":"1"}"#)]),
        text_resp(
            "<tool_call>{\"name\":\"slow_read\",\"arguments\":{\"q\":\"2\"}}</tool_call>\nSummary so far: host A is clean.",
        ),
    ]);
    let mut parts = h.parts(vec![]);
    parts.settings.max_iterations = 1;
    let mut agent = Agent::new(parts);
    let out = agent.run_turn("dig".into()).await.unwrap();
    assert!(out.forced);
    assert_eq!(
        out.result.as_deref(),
        Some("Summary so far: host A is clean.")
    );
    assert_eq!(h.slow.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn empty_final_answer_reports_no_result() {
    let h = Harness::new(vec![Ok(ChatResponse::from_message(
        ChatMessage::assistant_tool_calls(None, vec![]),
    ))]);
    let mut agent = h.agent();
    let out = agent
        .run_turn("send it via send_message".into())
        .await
        .unwrap();
    assert!(out.result.is_none());
    let last = agent.history().last().unwrap();
    assert_eq!(last.role, Role::Assistant);
    assert_eq!(last.content.as_deref(), Some(""));
}
