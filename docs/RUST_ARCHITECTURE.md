# Talon 2.0 — Rust Architecture

Talon 2.0 is a ground-up Rust rewrite of the TypeScript Talon/NanoClaw fork.
It keeps the operational model (host orchestrator + one hardened container per
agent run, CoPilot HTTP API, scheduled sweeps, MCP tool servers) and changes
three things:

1. **Language/runtime:** a Cargo workspace replaces Node.js on the host *and*
   inside the container (the Claude Agent SDK is replaced by a native agent
   loop in `talon-agent`).
2. **Model provider:** **vLLM** (OpenAI-compatible `/v1/chat/completions` with
   tool calling and structured outputs). Ollama and the Anthropic SDK path are
   gone. Containers never hold the vLLM API key: they talk to a host-side
   **LLM gateway** with a short-lived per-run token.
3. **Security & intelligence:** privilege-separated container runtime,
   prompt-injection fencing, secret redaction, SSRF-safe egress, hash-chained
   audit log, deterministic IOC/MITRE/triage engine, structured verdicts via
   guided decoding.

---

## 1. Workspace map

```
crates/
  talon-core       frozen contract: types, protocol, Channel/Tool traits, config, schedule, paths, audit sink
  talon-db         SQLite store (schema-compatible with src/db.ts) + audit chain, investigations, IOC sightings
  talon-security   policy engine: mounts, senders, IPC authz, injection guard, redaction, egress, auth
  talon-llm        vLLM client (+ fallback tool-call parsing) and host LLM gateway
  talon-mcp        MCP JSON-RPC client/server, .mcp.json loader, Tool adapter, manager
  talon-tools      built-in agent tools (bash, files, grep/glob, web_fetch, IPC task tools, todo)
  talon-intel      IOC extraction, MITRE ATT&CK mapping, triage scoring, correlation, report schema
  talon-anon       PII anonymizer + `talon-anon-proxy` MCP proxy binary
  talon-container  hardened docker/podman launcher, mounts, output-marker parser, snapshots, image files
  talon-scheduler  GroupQueue (per-lane serialization, global concurrency) + task scheduler loop
  talon-ipc        host-side IPC watcher (authorized, audited, hardened file handling)
  talon-router     message formatting, Markdown->channel dialects, chunking, session commands
  talon-setup      setup/verify/service-install logic used by `talon setup ...`
  talon-channels   Telegram, outbound webhook, Emacs bridge
  talon-http       CoPilot HTTP API (investigations, SSE chat lanes, status, palace)
  talon-agent      in-container runtime: `talon-agent supervise` (root) + `talon-agent run` (unprivileged)
  talon            host binary: orchestrator + CLI
```

Dependency rule: everything depends on `talon-core`. Other edges:

```
talon-db        <- talon-scheduler, talon-ipc, talon-http, talon-setup, talon
talon-security  <- talon-llm, talon-tools, talon-container, talon-ipc, talon-channels, talon-http, talon-setup, talon-agent, talon
talon-llm, talon-mcp, talon-tools, talon-intel <- talon-agent
everything      <- talon (host)
```

`talon-core`, and the **public signatures** already present in `talon-db`
and `talon-security`, are a frozen contract. Implementations fill in the
`todo!()` bodies; additions are fine, changes/removals are not.

---

## 2. Rules for every agent (parallel development)

Fifteen agents work in **one shared working tree** at the same time.

- **Only edit files inside the directories you own** (listed in your section).
  Never edit `talon-core`, the root `Cargo.toml`, `Cargo.lock` by hand, or
  another agent's crate. If you need something from another crate that is not
  there yet, write a small local adapter/trait in your own crate and say so in
  your final report.
- New dependencies: prefer `{ workspace = true }` entries already declared in
  the root `Cargo.toml`. If you need a crate that isn't declared, add it to
  **your own** `Cargo.toml` with an explicit version.
- Build/test **only your package**: `cargo check -p <crate>`,
  `cargo test -p <crate>`, `cargo clippy -p <crate> --all-targets -- -D warnings`,
  `cargo fmt -p <crate>`. Never run workspace-wide cargo commands, `cargo clean`,
  or `cargo update`. Cargo serializes builds on a lock ("Blocking waiting for
  file lock") — that is normal, just wait.
- If a compile error comes from a crate you don't own, it is another agent's
  work in progress: retry a bit later, don't "fix" it.
- **Do not `git commit`, `git add`, `git stash` or `git checkout`.** The lead
  integrates and commits.
- The TypeScript sources in `src/`, `container/agent-runner/`, `setup/` are the
  behavioural reference. Port behaviour faithfully (including the tests in
  `*.test.ts` — port them to Rust tests), then harden and improve.
- Quality bar: no `unsafe`, no `unwrap()/expect()` outside tests (except on
  provably infallible static values, with a comment), no panics on external
  input, `tracing` for logs (never log secrets or full prompts at `info`),
  doc comments on every public item, unit tests for every module, clippy clean
  with `-D warnings`, rustfmt clean.
- Async: tokio. Long-running loops take a `tokio_util::sync::CancellationToken`.
  Blocking work (SQLite, filesystem walks) is short or goes through
  `spawn_blocking`.
- Finish with a short report: public API summary, what you ported, what you
  improved, known gaps, test count.

---

## 3. Cross-cutting contracts

### 3.1 Host <-> container protocol
Defined in `talon_core::protocol` (stdin `ContainerInput` JSON then EOF;
stdout `ContainerOutput` frames between `---TALON_OUTPUT_START---` /
`---TALON_OUTPUT_END---`; IPC directories `input/`, `messages/`, `tasks/`,
snapshots `current_tasks.json`, `available_groups.json`; `_close` sentinel).
IPC files are written atomically (`*.json.tmp` + rename), named with
`talon_core::protocol::ipc_file_name()`.

### 3.2 Model access (vLLM via host gateway)
- Host reads `TALON_VLLM_*` (see `talon_core::provider`) and the secret
  `TALON_VLLM_API_KEY` (via `EnvFile::file_value`).
- Host starts `talon_llm::gateway` on `TALON_LLM_GATEWAY_BIND:TALON_LLM_GATEWAY_PORT`
  (default `127.0.0.1:3001`; on Linux docker the host must bind the docker
  bridge address so `host.docker.internal` reaches it — `talon-container`
  exposes a helper that detects it).
- Per container run, host issues a gateway token (TTL = container timeout)
  and puts an `LlmEndpoint { base_url: "http://host.docker.internal:<port>/v1", token, model, ... }`
  into `ContainerInput.llm`. **Never** into env vars. Token is revoked when the
  run ends.

### 3.3 Container privilege separation
```
docker run --rm -i --name talon-<folder>-<millis> --label talon.managed=true
  --cap-drop=ALL --cap-add=CHOWN,SETUID,SETGID,FOWNER,DAC_OVERRIDE,KILL
  --security-opt=no-new-privileges --read-only
  --tmpfs /tmp:rw,nosuid,nodev,size=1g --tmpfs /run:rw,nosuid,nodev,size=16m
  --tmpfs /etc/mcp-secrets:rw,nosuid,nodev,noexec,size=1m,mode=0711
  --tmpfs /home/agent:rw,nosuid,nodev,size=256m
  --pids-limit 512 --memory 4g --cpus 2          (overridable per group)
  -e TZ=.. -e RUN_UID=.. -e RUN_GID=..           (no secrets in env)
  --add-host host.docker.internal:host-gateway   (Linux)
  --add-host <blocked>:127.0.0.1 ...
  <mounts> talon-agent:latest
```
- Image users: `agent` (remapped to `RUN_UID/RUN_GID`), and one system user
  per isolated MCP: `mcp-siem`, `mcp-mysql`, `mcp-wazuh`, `mcp-copilot`,
  `mcp-shuffle`, `mcp-velociraptor`, `mcp-cve`, `mcp-palace`, plus
  `mcp-default` for servers without a `runAs`. No sudo in the image.
- `/usr/local/bin/talon-entrypoint` (root): remap `agent` uid/gid, copy
  `/etc/mcp-staging/<id>.*` -> `/etc/mcp-secrets/<id>.*` (owner `mcp-<id>`,
  0600), then `exec talon-agent supervise`. If not root: `exec talon-agent run`.
- `talon-agent supervise` (root, tiny, no LLM logic): reads the whole
  `ContainerInput` from stdin, parses `/workspace/group/.mcp.json`, spawns each
  MCP server as its `runAs` user (`^mcp-[a-z0-9_-]{1,32}$`, must exist; else
  `mcp-default`) with a minimal env (PATH, LANG, TZ, HOME=/tmp + the server's
  `env`), exposes each server's stdio on a unix socket
  `/run/talon/mcp/<server>.sock` (dir 0750 root:agent, socket owned by
  `agent`), then spawns `talon-agent run` as `agent` (RUN_UID/RUN_GID) with the
  input on its stdin and `TALON_MCP_SOCKET_DIR=/run/talon/mcp`, relays its
  stdout/stderr, and tears everything down when it exits.
- `talon-agent run`: connects to the sockets (or, without
  `TALON_MCP_SOCKET_DIR`, spawns servers itself — degraded/dev mode).
- MCP wrapper scripts (`siem/*.sh`, `mysql/*.sh`, `*-mcp/*.sh`,
  `mempalace/*.sh`) source `/etc/mcp-secrets/<id>.env` directly when running
  as `mcp-<id>` (no sudo), and fall back to the local `.env` in dev mode.
- `.mcp.json` server entries gain an optional `"runAs": "mcp-siem"` field.

### 3.4 Untrusted data
Everything that originates outside Talon (SIEM documents, alert fields, MCP
tool results, fetched web pages, chat messages from non-main users) is
untrusted. Tool results that carry such data are passed through
`talon_security::injection::fence_untrusted(source, text)` before reaching
the model; the system prompt includes `fencing_instructions()`; detections
at `RiskLevel::High` are audited (`injection.detected`).

### 3.5 Audit
`talon_core::audit::AuditSink`. Crates accept `SharedAuditSink` in their
constructors and record decisions with `talon_core::audit::event(...)`.
Kinds: `http.auth.failed`, `http.investigate`, `ipc.message.denied`,
`ipc.task.{allowed,denied}`, `ipc.register_group`, `mount.rejected`,
`container.launch`, `container.exit`, `gateway.auth.failed`,
`gateway.request`, `injection.detected`, `egress.denied`, `tool.call`.

---

## 4. Agent assignments

### Phase 1 (parallel)

#### A01 — `crates/talon-db/`
Implement the API in `src/lib.rs` (port `src/db.ts` + `src/db.test.ts`,
`src/db-migration.test.ts`). Store `RegisteredGroup` exactly like the TS
version (columns + `container_config` JSON; lane-only fields that TS kept in
memory may be persisted as JSON in a new nullable `lane_config` column).
New tables: `audit_log` (hash chain, `verify_audit_chain`), `investigations`,
`ioc_sightings` (indexed on `(ioc_type, value)`). Migration tests must open
a database created by the TS schema. Concurrency test: clone `Db` across
threads.

#### A02 — `crates/talon-llm/`
1. **Client** (`client`, `types`): OpenAI-compatible chat completions for
   vLLM. Types: `ChatMessage { role, content, tool_calls, tool_call_id, name,
   reasoning_content }`, `ToolCall`, `ChatRequest` (model, messages, tools from
   `talon_core::tool::ToolSpec`, `tool_choice`, `parallel_tool_calls`,
   temperature/top_p/max_tokens/stop/seed, `response_format` incl.
   `json_schema` for guided decoding, `chat_template_kwargs` for
   `enable_thinking`), `ChatResponse { message, finish_reason, usage }`,
   `Usage { prompt_tokens, completion_tokens, cached_tokens }` +
   `impl From<&Usage> for talon_core::protocol::SessionUsage`.
   `VllmClient::chat`, `chat_stream` (SSE, with an accumulator that assembles
   tool-call deltas into a final `ChatResponse`), `list_models`, `health`,
   `tokenize` (vLLM `/tokenize`, fall back to a ~4 chars/token estimate).
   Retries with exponential backoff + jitter on connect errors/429/5xx,
   honouring `Retry-After`; per-request timeout; typed errors.
2. **Fallback tool-call parser**: when a model emits tool calls as text
   (Hermes `<tool_call>{...}</tool_call>`, Mistral `[TOOL_CALLS][...]`,
   Llama `<|python_tag|>`, fenced ```json {"name":..,"arguments":..}``` blocks)
   and the server did not parse them, recover them. Split `<think>...</think>`
   into `reasoning_content`. Validate tool names against the offered tools.
3. **Gateway** (`gateway`): axum reverse proxy used by the host. `GatewayConfig
   { bind, upstream_base_url, upstream_api_key: Option<String>,
   allowed_models, default_model, max_body_bytes, max_output_tokens_cap,
   requests_per_minute, request_timeout }`, `LlmGateway::start(config, audit)
   -> GatewayHandle { addr(), issue_token(label, ttl) -> String, revoke(token),
   shutdown(), stats() }`. Routes: `POST /v1/chat/completions` (streaming SSE
   passthrough), `GET /v1/models`, `POST /tokenize`; everything else 404.
   Tokens stored as SHA-256 digests, compared via lookup; client
   `Authorization` replaced by the upstream key; `model` pinned to the allowed
   list (unknown -> default model); `max_tokens` clamped; per-token rate
   limit; body size limit; usage counted per label; audit on auth failure.
   Tests with `wiremock` as the fake vLLM.

#### A03 — `crates/talon-mcp/`
JSON-RPC 2.0 line-delimited transport generic over `AsyncRead + AsyncWrite`
(child stdio **and** `tokio::net::UnixStream` for the supervisor sockets).
`McpClient` (`spawn(name, &ServerConfig)`, `connect_unix(name, path)`,
`initialize` with protocol `2025-06-18` + graceful version negotiation,
`list_tools` with cursor pagination, `call_tool(name, args, timeout)`,
`ping`, handles server->client requests (`ping`, `roots/list` -> empty,
others -> method-not-found) and `notifications/tools/list_changed`, stderr
-> `tracing`, max message size, request timeouts, kill-on-drop, graceful
`shutdown`). `McpConfigFile` parser for `.mcp.json` (`mcpServers.{name}.
{command, args?, env?, cwd?, runAs?}`). `McpToolAdapter: talon_core::tool::
Tool` exposing remote tools as `mcp__<server>__<tool>` (sanitized to
`^[a-zA-Z0-9_-]{1,64}$`, collision-safe), converting results (text, JSON
`structuredContent`, image/resource placeholders) to `ToolOutput`, with an
optional result post-processor hook (the agent uses it for fencing).
`McpManager` starts all servers concurrently with per-server failure
isolation and exposes the aggregated tool list. Also a minimal `McpServer`
(stdio) builder for serving `Tool`s, used in tests and available to other
crates. Port nothing from TS (it used the SDK) — follow the MCP spec.

#### A04 — `crates/talon-tools/`
Built-in tools implementing `talon_core::tool::Tool`, plus
`pub fn builtin_tools(opts: &BuiltinOptions) -> Vec<Arc<dyn Tool>>`:
- `bash`: `bash -c` with cwd, timeout (default 120 s, max 600 s), process
  group kill on timeout/cancel, **scrubbed env** (allowlist PATH, HOME, LANG,
  LC_*, TZ, TERM, USER), stdout+stderr capped (head/tail truncation with a
  marker), exit code reported.
- `read_file` (line numbers, offset/limit, size cap, binary detection),
  `write_file` (atomic), `edit_file` (exact replace; unique unless
  `replace_all`), `list_dir`, `glob`, `grep` (regex, include glob, context,
  result caps). All path access goes through a path guard: canonicalize,
  must stay inside `ToolContext.allowed_roots`, writes refused under
  `read_only_roots`, symlink escapes refused.
- `web_fetch`: `talon_security::egress::EgressPolicy::resolve_and_check`
  on every hop (manual redirects, max 5), size/time caps, HTML -> readable
  text, output fenced with `fence_untrusted("web", ..)`.
- `todo_write` (in-memory plan the model maintains; returned in full).
- IPC tools (port `container/agent-runner/src/ipc-mcp-stdio.ts` exactly,
  same names/descriptions/validation): `send_message`, `schedule_task`,
  `list_tasks`, `pause_task`, `resume_task`, `cancel_task`, `update_task`,
  `register_group` (main only), writing `talon_core::protocol` files
  atomically under `ToolContext.ipc_dir`. Validate schedules with
  `talon_core::schedule::validate`.

#### A05 — `crates/talon-intel/`
Pure, offline SOC intelligence, all exposed as library APIs **and** as
`Tool`s via `pub fn intel_tools(opts) -> Vec<Arc<dyn Tool>>`:
- `ioc`: extract + normalize + classify IOCs from text and JSON (IPv4/IPv6
  with private/public/reserved classification, domains with TLD sanity —
  don't flag `svchost.exe`, URLs, emails, MD5/SHA1/SHA256/SHA512 (also from
  Sysmon `Hashes=SHA256=..,MD5=..`), CVE, MITRE ids, Windows/Unix paths,
  registry keys, user-agents), refang defanged forms (`hxxp`, `[.]`,
  `(dot)`, `[@]`), dedupe with counts and source field paths.
- `mitre`: embedded technique table (id, name, tactics) for the common
  enterprise techniques; mappings from Sysmon event ids, Wazuh `rule.groups`
  and `rule.mitre.id`, and command-line heuristics (encoded PowerShell,
  LOLBins: certutil, mshta, rundll32, regsvr32, bitsadmin, wmic, schtasks,
  vssadmin/wbadmin deletion, lsass access, net user/group, whoami /all, ...)
  with explanations.
- `cmdline`: suspicious command-line analyzer (obfuscation, entropy,
  base64 decode of `-enc`, download cradles).
- `triage`: deterministic risk scoring (0-100 + severity + rationale) from
  rule level, groups, MITRE tactics, IOC classes, asset criticality, prior
  sightings count; designed as a grounded prior for the LLM.
- `correlate`: cluster alerts by shared host/user/IOC within a time window.
- `report`: `TriageReport` (verdict: `true_positive | false_positive |
  benign_true_positive | needs_escalation | inconclusive`, confidence,
  severity, summary, iocs, mitre, timeline, evidence, recommended_actions),
  `json_schema()` (for vLLM guided decoding), validation, Markdown rendering.
- Tools: `extract_iocs`, `map_mitre`, `analyze_command_line`, `score_alert`,
  `correlate_alerts`, `submit_triage_report` (validates, writes
  `<cwd>/reports/<id>.json` + `.md`, returns the Markdown).
- Port the knowledge in `groups/copilot/prompts/*.txt` (Sysmon event guides)
  into structured hints `investigation_hints(rule_groups, event_id)` that
  the agent can inject.

#### A06 — `crates/talon-anon/` (+ `siem/anon-opensearch-mcp.sh`, `siem/anon_proxy/fields.yaml`)
Port `siem/anon_proxy/anon_proxy.py` to Rust (library + `talon-anon-proxy`
binary): same `fields.yaml` format, same token classes (`USER_n`, `HOST_n`,
`IP_INT_n`, `EMAIL_n`) plus `DOMAIN_INT_n`, `SID_n`, `MAC_n`; consistent
per-session mapping persisted atomically (0600) to the map file; free-text
detectors (RFC1918/ULA IPs, emails, `DOMAIN\user`, UNC `\\host\share`,
`C:\Users\<name>\` and `/home/<name>/` paths); never touch hashes, public
IPs/domains, rule metadata. `deanonymize` restores longest-first.
Proxy: `talon-anon-proxy --fields <yaml> --map <file> -- <upstream cmd...>`;
forwards JSON-RPC lines both ways, appends a `deanonymize` tool to
`tools/list`, answers it locally, anonymizes `tools/call` results (text
content — parsing embedded JSON — and `structuredContent`), handles partial
lines, oversize messages and upstream crashes. Update the wrapper script to
launch the Rust proxy (keep a Python fallback if the binary is absent).

#### A07 — `crates/talon-security/`
Implement every stub (see module docs). Port `src/mount-security.ts`,
`src/sender-allowlist.ts` and their tests, and the authorization rules of
`src/ipc.ts` (+ `src/ipc-auth.test.ts`). Injection scanner with a
well-tested rule set (English + German phrasing, role tags like
`<|im_start|>system`, `</untrusted_data`, `### system`, tool-call JSON,
hidden unicode, base64-wrapped instructions, markdown image exfiltration
`![](http://x/?q=...)`). Redactor detectors per module docs. Egress policy
with exhaustive IPv4/IPv6 special-range tests (incl. IPv4-mapped IPv6,
`0.0.0.0`, decimal/octal IP host forms rejected by the URL parser or
normalized). Fuzz-style property tests where cheap.

#### A08 — `crates/talon-container/` (+ `container/`, MCP wrapper scripts)
Port `src/container-runner.ts`, `src/container-runtime.ts` (+ tests):
- `ContainerRuntime` (binary detection docker/podman, `ensure_running`,
  `cleanup_orphans` by label `talon.managed=true`, `stop(name)`,
  `host_gateway_args`, `detect_gateway_bind_addr()` for the LLM gateway).
- `build_mounts(...)` exactly per TS semantics (group rw, global ro, project
  ro + `.env` shadowed with a host-side `/dev/null` bind for main, sessions
  dir at `/home/agent/.talon`, IPC dir, validated additional mounts via
  `talon_security::mounts::MountValidator`, per-MCP secret staging + shadowing
  from `ISOLATED_MCPS`).
- `build_run_args(...)` with the hardening flags of §3.3, resource limits
  from `ContainerConfig`, blocked hosts, env overlay (reject keys that look
  like secrets: `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*` -> audit + drop).
- `ContainerRunner::run(spec, on_output) -> RunResult`: spawn, write input
  JSON to stdin then close, stream-parse stdout frames (marker parser robust
  to partial chunks, interleaved noise, oversize -> error), stderr to
  tracing (redacted), hard timeout + idle-reset semantics as in TS, graceful
  `docker stop` then kill, exit-code mapping, max output size, audit
  `container.launch` / `container.exit`. Return a handle usable by the
  queue (`name()`, `stop()`).
- `write_tasks_snapshot`, `write_groups_snapshot` (atomic, main sees all,
  others only own).
- Rewrite `container/Dockerfile` (multi-stage: `rust:1-bookworm` builder
  compiling `talon-agent` + `talon-anon-proxy` from the workspace, runtime
  `debian:bookworm-slim` with the Python MCP venvs from the old Dockerfile,
  chromium kept optional via build arg, users of §3.3, no sudo, no node),
  `container/entrypoint.sh` (§3.3), `container/build.sh` (build context =
  repo root). Update the MCP wrapper scripts to the no-sudo model.

#### A09 — `crates/talon-scheduler/`
1. `GroupQueue` — port `src/group-queue.ts` + tests: per-JID serialization,
   global `max_concurrent`, FIFO waiting list, pending message checks vs
   pending tasks (tasks first), `enqueue_message_check`, `enqueue_task`,
   `send_message` (writes IPC input file when the lane's container is
   active; returns false otherwise), `close_stdin` (`_close` sentinel),
   `notify_idle`, `register_process(jid, Arc<dyn RunningContainer>, ipc_key)`,
   retry with exponential backoff (cap), `status() -> QueueStatus`,
   graceful `shutdown(grace)`. The queue calls back into the host through a
   trait (`LaneProcessor`: `process_messages(jid) -> bool`,
   `run_task(jid, task_id) -> ()`).
2. `TaskScheduler` — port `src/task-scheduler.ts` + tests: poll loop
   (interval + `Notify` wake-up), due tasks via `talon-db`, enqueue into the
   queue, execution via a host-implemented `TaskExecutor` trait
   (`execute(task, group) -> TaskExecution { result, error, duration }`),
   next run via `talon_core::schedule::compute_next_run`, run logs,
   completion of `once` tasks, missed-run catch-up policy (run once, don't
   burst), group/isolated context handling flags passed to the executor.

#### A10 — `crates/talon-ipc/`
Port `src/ipc.ts` (+ `src/ipc-auth.test.ts` behaviour): `IpcWatcher::new(
config, db, host: Arc<dyn IpcHost>, audit)`, `run(cancel)`. Polling scan of
`data/ipc/<key>/{messages,tasks}` (map ipc_key -> owning group via the
registered groups; unknown keys are ignored), hardened: `symlink_metadata`
regular files only, size cap (256 KiB), JSON parse with depth limit, files
processed in name order, bad files moved to `data/ipc/errors/` (bounded),
per-namespace rate limit per scan. Authorization strictly via
`talon_security::ipc_authz`, every decision audited. Task operations via
`talon-db` + `talon_core::schedule` (timezone from config). `IpcHost` trait:
`send_message`, `registered_groups`, `register_group`, `sync_groups`,
`available_groups`, `write_groups_snapshot`, `on_tasks_changed`.

#### A11 — `crates/talon-router/` and `crates/talon-setup/`
Router: port `src/router.ts`, `src/text-styles.ts`, `src/formatting.test.ts`,
`src/routing.test.ts`, `src/session-commands.ts` (+ tests): `escape_xml`,
`format_messages` (XML envelope, timezone-aware times, reply context),
`strip_internal_tags`, `format_outbound(text, ChannelType)`,
`parse_text_styles` (code regions protected), `split_message(text, max_len)`
(code-fence aware, for Telegram 4096), session commands
(`extract_session_command`, `is_session_command_allowed`,
`handle_session_command` with a deps trait).
Setup: port `setup/*.ts` (+ tests) into a library the host CLI dispatches
to: environment checks (container runtime, image present, vLLM reachable via
`/v1/models`, gateway port free, disk space), group registration, mount
allowlist template, timezone, systemd user unit / launchd plist generation
and install, `verify` report. Output machine-readable status blocks like the
TS version.

#### A12 — `crates/talon-channels/`
Port `src/channels/telegram.ts`, `webhook.ts`, `emacs.ts` (+ tests) as
`talon_core::channel::Channel` impls using `reqwest`/`axum` directly (no bot
framework): Telegram Bot API long polling with offset persistence, chunked
sends (4096), parse-mode fallback to plain text on 400, typing action,
chat metadata, mention/trigger translation; outbound webhook with
`X-Talon-Signature: sha256=<hmac>` (secret from `.env`), egress policy
check, retries with backoff; Emacs bridge on 127.0.0.1 with a bearer token.
`pub fn build_channels(host, env, audit) -> Vec<Arc<dyn Channel>>` that
returns only channels whose credentials are configured.

#### A13 — `crates/talon-http/`
Port `src/channels/http.ts` (+ `http.test.ts`) to axum as a `Channel`:
`/health`, `/status`, `/session/reset`, `/investigate`, `/evals/*`,
`/templates`, `/palace/{lesson,search,forget}` (port `src/palace-client.ts`:
spawns `mempalace/palace-call.sh` with timeout), `/message` (SSE with
keepalive, per-lane writers, per-user lanes `http:copilot:u:<id>`,
investigate lane `http:copilot:investigate`, idle-lane sweep), CORS
preflight; seed the paused digest task. New: `GET /investigations`,
`GET /investigations/{id}` (talon-db), `GET /metrics` (Prometheus text:
queue, investigations, uptime). Security: fail-closed API key
(`talon_security::auth`), constant-time, per-IP rate limit on auth
failures, body limits, strict input validation (template override path
traversal, alert id numeric, customer code charset), security headers,
audit events, investigation dedup (same alert within N minutes ->
return existing job).

### Phase 2 (after phase 1 lands)

#### A14 — `crates/talon-agent/`
The in-container runtime (replaces `container/agent-runner`): `supervise`
and `run` modes per §3.3; vLLM agent loop (system prompt = global
CLAUDE.md + group CLAUDE.md + fencing instructions + tool guidance +
time/timezone; tools = built-in + intel + MCP), streaming, parallel
read-only tool calls, tool-result fencing/truncation, loop detection, max
turns, sessions as JSONL under `/home/agent/.talon/sessions/` (resume by
id), automatic context compaction with the fast model (archive transcript
to `/workspace/group/conversations/`), `/compact` command, IPC follow-ups
and `_close`, scheduled-task scripts, output frames + usage, structured
investigation verdicts via guided decoding.

#### A15 — `crates/talon/`
Host orchestrator + CLI (`talon run`, `talon setup ...`, `talon audit
verify`, `talon doctor`): event-driven message loop, lane processing,
sessions, LLM gateway, container runner, queue, scheduler, IPC watcher,
channels, redaction of outbound text, graceful shutdown; plus CI workflow,
service units and `.env` examples.

### Review
**Mythos** — an independent adversarial security reviewer audits the
integrated workspace (threat model: malicious SIEM content, malicious chat
user, compromised agent container, network attacker on the HTTP API) and
its findings are fixed before merge.
