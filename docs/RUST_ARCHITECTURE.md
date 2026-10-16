# Talon — Rust Architecture

Talon runs one host orchestrator and one hardened container per agent run,
serves the CoPilot HTTP API, runs scheduled sweeps and talks to the SIEM and
intel sources through MCP tool servers. Three design decisions shape it:

1. **Rust end to end:** a Cargo workspace on the host *and* inside the
   container, with a native agent loop in `talon-agent`.
2. **Model provider:** **vLLM** (OpenAI-compatible `/v1/chat/completions` with
   tool calling and structured outputs). Containers never hold the vLLM API
   key: they talk to a host-side **LLM gateway** with a short-lived per-run
   token.
3. **Security & intelligence:** privilege-separated container runtime,
   prompt-injection fencing, secret redaction, SSRF-safe egress, hash-chained
   audit log, deterministic IOC/MITRE/triage engine, structured verdicts via
   guided decoding.

---

## 1. Workspace map

```
crates/
  talon-core       frozen contract: types, protocol, Channel/Tool traits, config, schedule, paths, audit sink
  talon-db         SQLite store + audit chain, investigations, IOC sightings
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

## 2. Engineering rules

- No `unsafe` (workspace lint `unsafe_code = "forbid"`), no
  `unwrap()/expect()` outside tests (except on provably infallible static
  values, with a comment), no panics on external input.
- `tracing` for logs; never log secrets or full prompts at `info`. All log
  output passes through the redactor.
- Doc comments on every public item, unit tests for every module, clippy clean
  with `-D warnings`, rustfmt clean. CI enforces fmt, clippy and the full test
  suite with `--locked`.
- Async: tokio. Long-running loops take a `tokio_util::sync::CancellationToken`.
  Blocking work (SQLite, filesystem walks) is short or goes through
  `spawn_blocking`.
- `talon-core` is the cross-crate contract. Change it deliberately and update
  host and agent together.

---

## 3. Cross-cutting contracts

### 3.1 Host <-> container protocol
Defined in `talon_core::protocol` (stdin `ContainerInput` JSON then EOF;
stdout `ContainerOutput` frames between `---TALON_OUTPUT_START---` /
`---TALON_OUTPUT_END---`; IPC directories `input/`, `messages/`, `tasks/`,
snapshots `current_tasks.json`, `available_groups.json`; `_close` sentinel).
IPC files are written atomically (`*.json.tmp` + rename), named with
`talon_core::protocol::ipc_file_name()`.

Follow-ups and the end of a container:
- The host empties `input/` (leftover messages, a stale `_close`) before it
  starts a container; a leftover message was never answered and is sent
  again from the message store.
- Each success frame ends one turn and names the `input/` files that turn
  consumed (`ContainerOutput.consumed_inputs`). The host keeps a ledger per
  message run and persists the cursor through which everything was
  answered; a follow-up whose turn died, or that the container never read,
  runs again (`orchestrator/ledger.rs`).
- Messages written before `_close` are still answered: the host stops
  writing once `_close` is written, and the agent checks for `_close` before
  it drains `input/`.

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

## 4. How it was built

The workspace was built by fifteen agents working in parallel, one per crate,
against the frozen `talon-core` contract, then integrated and put through
three rounds of adversarial security review ("Mythos"; threat model:
malicious SIEM content, malicious chat user, compromised agent container,
network attacker on the HTTP API). Findings and fixes are in
[MYTHOS_REVIEW.md](MYTHOS_REVIEW.md).
