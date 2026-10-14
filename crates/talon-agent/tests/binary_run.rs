//! End-to-end tests of the `talon-agent run` binary against a wiremock fake
//! vLLM (OpenAI-compatible SSE streaming) with a temporary workspace.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use talon_core::protocol::{ContainerOutput, OUTPUT_END_MARKER, OUTPUT_START_MARKER, OutputStatus};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TOKEN: &str = "tlgw-test-token-0123456789abcdef";

fn sse(chunks: &[Value]) -> String {
    let mut body: String = chunks.iter().map(|c| format!("data: {c}\n\n")).collect();
    body.push_str("data: [DONE]\n\n");
    body
}

fn tool_call_stream() -> String {
    sse(&[
        json!({"id":"c1","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"write_file","arguments":""}}]},"finish_reason":null}]}),
        json!({"id":"c1","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":\"notes.txt\","}}]},"finish_reason":null}]}),
        json!({"id":"c1","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"content\":\"hello from talon\"}"}}]},"finish_reason":null}]}),
        json!({"id":"c1","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}),
        json!({"id":"c1","object":"chat.completion.chunk","model":"test-model","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":30,"prompt_tokens_details":{"cached_tokens":64}}}),
    ])
}

fn text_stream(text: &str) -> String {
    sse(&[
        json!({"id":"c2","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}),
        json!({"id":"c2","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{"content":text},"finish_reason":null}]}),
        json!({"id":"c2","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
        json!({"id":"c2","object":"chat.completion.chunk","model":"test-model","choices":[],"usage":{"prompt_tokens":200,"completion_tokens":10,"prompt_tokens_details":{"cached_tokens":150}}}),
    ])
}

/// Answers with a tool call first, then a final text.
struct ScriptedVllm {
    calls: Arc<AtomicUsize>,
}

impl Respond for ScriptedVllm {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let body = match n {
            0 => tool_call_stream(),
            1 => text_stream("Wrote the note."),
            _ => text_stream("unexpected extra call"),
        };
        ResponseTemplate::new(200).set_body_raw(body, "text/event-stream")
    }
}

struct Workspace {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        for sub in ["group", "global", "ipc/input", "state", "extra"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::write(
            root.join("group/CLAUDE.md"),
            "# Test group\nAlways be brief.",
        )
        .unwrap();
        Self { _dir: dir, root }
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn spawn(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_talon-agent"))
            .arg("run")
            .env("TALON_AGENT_GROUP_DIR", self.p("group"))
            .env("TALON_AGENT_GLOBAL_DIR", self.p("global"))
            .env("TALON_AGENT_PROJECT_DIR", self.p("project"))
            .env("TALON_AGENT_EXTRA_DIR", self.p("extra"))
            .env("TALON_AGENT_IPC_DIR", self.p("ipc"))
            .env("TALON_AGENT_STATE_DIR", self.p("state"))
            .env("TALON_AGENT_IPC_POLL_MS", "20")
            .env("TALON_LOG", "debug")
            .env_remove("TALON_MCP_SOCKET_DIR")
            .env_remove("TALON_AGENT_MCP_CONFIG")
            .current_dir(self.p("group"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }
}

fn input(server: &MockServer, extra: Value) -> Vec<u8> {
    let mut v = json!({
        "prompt": "<messages><message sender=\"alice\">write a note</message></messages>",
        "groupFolder": "testgroup",
        "chatJid": "tg:42",
        "isMain": false,
        "assistantName": "Andy",
        "timezone": "Europe/Berlin",
        "llm": {
            "baseUrl": format!("{}/v1", server.uri()),
            "token": TOKEN,
            "model": "test-model",
            "fastModel": "test-fast",
            "maxContextTokens": 32768
        }
    });
    if let (Value::Object(base), Value::Object(more)) = (&mut v, extra) {
        base.extend(more);
    }
    serde_json::to_vec(&v).unwrap()
}

async fn feed(child: &mut Child, bytes: Vec<u8>) {
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&bytes).await.unwrap();
    stdin.shutdown().await.unwrap();
}

/// Read stdout until `count` frames were parsed.
async fn read_frames<R: tokio::io::AsyncRead + Unpin>(
    lines: &mut tokio::io::Lines<BufReader<R>>,
    count: usize,
) -> Vec<ContainerOutput> {
    let mut frames = Vec::new();
    let mut inside = false;
    let mut buf = String::new();
    while frames.len() < count {
        let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
            .await
            .expect("timed out waiting for an output frame")
            .unwrap()
            .expect("stdout closed before the expected frames");
        if line == OUTPUT_START_MARKER {
            inside = true;
            buf.clear();
        } else if line == OUTPUT_END_MARKER {
            inside = false;
            frames.push(serde_json::from_str(&buf).unwrap());
        } else if inside {
            buf.push_str(&line);
        } else {
            panic!("unexpected non-frame stdout line: {line}");
        }
    }
    frames
}

async fn finish(mut child: Child) -> (std::process::ExitStatus, String) {
    let mut stderr = child.stderr.take().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("agent did not exit")
        .unwrap();
    let mut err = String::new();
    stderr.read_to_string(&mut err).await.unwrap();
    (status, err)
}

fn session_file(state: &Path, id: &str) -> PathBuf {
    state.join("sessions").join(format!("{id}.jsonl"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_binary_against_fake_vllm() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ScriptedVllm {
            calls: calls.clone(),
        })
        .mount(&server)
        .await;

    let ws = Workspace::new();
    let mut child = ws.spawn();
    feed(&mut child, input(&server, json!({}))).await;
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let frames = read_frames(&mut lines, 1).await;

    let frame = &frames[0];
    assert_eq!(frame.status, OutputStatus::Success, "{frame:?}");
    assert_eq!(frame.result.as_deref(), Some("Wrote the note."));
    let id = frame.new_session_id.clone().expect("session id");
    let usage = frame.usage.expect("usage");
    assert_eq!(usage.input_tokens, Some(320 - 214));
    assert_eq!(usage.cache_read_input_tokens, Some(214));
    assert_eq!(usage.output_tokens, Some(40));

    // The tool really ran in the group folder.
    assert_eq!(
        std::fs::read_to_string(ws.p("group/notes.txt")).unwrap(),
        "hello from talon"
    );

    // End the session.
    std::fs::write(ws.p("ipc/input/_close"), "").unwrap();
    let (status, stderr) = finish(child).await;
    assert!(status.success(), "exit {status:?}\n{stderr}");
    assert!(!stderr.contains(TOKEN), "token leaked into logs");
    assert!(lines.next_line().await.unwrap().is_none());

    // Session transcript: private and complete.
    let file = session_file(&ws.p("state"), &id);
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let transcript = std::fs::read_to_string(&file).unwrap();
    assert_eq!(transcript.lines().count(), 5, "{transcript}");

    // What vLLM saw.
    let requests = server.received_requests().await.unwrap();
    let chats: Vec<&Request> = requests
        .iter()
        .filter(|r| r.url.path() == "/v1/chat/completions")
        .collect();
    assert_eq!(chats.len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let auth = chats[0]
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(auth, format!("Bearer {TOKEN}"));
    let first: Value = serde_json::from_slice(&chats[0].body).unwrap();
    assert_eq!(first["model"], "test-model");
    assert_eq!(first["stream"], true);
    assert_eq!(first["tool_choice"], "auto");
    assert_eq!(first["parallel_tool_calls"], true);
    let tools: Vec<&str> = first["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["function"]["name"].as_str().unwrap())
        .collect();
    assert!(tools.contains(&"write_file"));
    assert!(tools.contains(&"submit_triage_report"));
    assert!(!tools.contains(&"register_group"));
    let system = first["messages"][0]["content"].as_str().unwrap();
    assert!(system.starts_with("You are Andy"));
    assert!(system.contains("Always be brief."));
    let user = first["messages"][1]["content"].as_str().unwrap();
    assert!(user.starts_with("[Current date and time:"));
    assert!(user.contains("(Europe/Berlin"));
    let second: Value = serde_json::from_slice(&chats[1].body).unwrap();
    // Same system prompt and tools (prefix caching).
    assert_eq!(second["messages"][0], first["messages"][0]);
    assert_eq!(second["tools"], first["tools"]);
    let msgs = second["messages"].as_array().unwrap();
    assert_eq!(msgs[2]["role"], "assistant");
    assert_eq!(msgs[2]["tool_calls"][0]["function"]["name"], "write_file");
    assert_eq!(msgs[3]["role"], "tool");
    assert_eq!(msgs[3]["tool_call_id"], "call_1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_session_reports_session_not_found() {
    let server = MockServer::start().await;
    let ws = Workspace::new();
    let mut child = ws.spawn();
    let id = "7f1d4a7e-3c55-4a8e-9f1b-2b1e5a3c9d10";
    feed(&mut child, input(&server, json!({ "sessionId": id }))).await;
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let frames = read_frames(&mut lines, 1).await;
    assert_eq!(frames[0].status, OutputStatus::Error);
    assert!(
        frames[0]
            .error
            .as_deref()
            .unwrap()
            .contains("session not found")
    );
    let (status, _) = finish(child).await;
    assert_eq!(status.code(), Some(1));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_without_wake_never_calls_the_model() {
    let server = MockServer::start().await;
    let ws = Workspace::new();
    let mut child = ws.spawn();
    feed(
        &mut child,
        input(
            &server,
            json!({
                "isScheduledTask": true,
                "script": "echo checking >&2; echo '{\"wakeAgent\": false}'"
            }),
        ),
    )
    .await;
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let frames = read_frames(&mut lines, 1).await;
    assert_eq!(frames[0].status, OutputStatus::Success);
    assert!(frames[0].result.is_none());
    let (status, _) = finish(child).await;
    assert!(status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_stdin_is_an_error_frame() {
    let ws = Workspace::new();
    let mut child = ws.spawn();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"{\"prompt\": 5").await.unwrap();
    drop(stdin);
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let frames = read_frames(&mut lines, 1).await;
    assert_eq!(frames[0].status, OutputStatus::Error);
    assert!(
        frames[0]
            .error
            .as_deref()
            .unwrap()
            .contains("invalid input")
    );
    let (status, _) = finish(child).await;
    assert_eq!(status.code(), Some(1));
}
