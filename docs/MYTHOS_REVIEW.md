# Mythos security review — findings and remediation plan

Independent adversarial review of the Talon 2.0 Rust workspace. Most findings
were confirmed with temporary proof-of-concept tests. This file is the shared
work order for the fix agents; each finding lists its owners.

| ID | Sev | Finding | Owners |
|---|---|---|---|
| MYTH-01 | critical | Host code execution via agent-writable MemPalace data (ChromaDB `index_metadata.pickle` is unpickled by host `/palace/*` calls and by `mcp-palace`) | F3 (entrypoint chown, palace run args), F6 (command palace runner, no host exec by default), F5 (container palace runner) |
| MYTH-02 | high | Non-main lane can redirect host IPC input writes into main's `input/` (TOCTOU symlink/rename race in `talon-scheduler/src/ipc_input.rs`) | F1 |
| MYTH-03 | high | Cross-analyst / cross-customer actions: IPC authorization keyed on group folder while all CoPilot lanes share folder `copilot`; webhook lane shares keys with `http:copilot`; shared `conversations/` and unfiltered `current_tasks.json` | F2 (authz by lane, task ownership, no scripts from non-main), F7 (webhook keys), F3+F5 (per-lane task snapshot), F8 (per-lane archives) |
| MYTH-04 | high | Host secrets exposed through allowlisted parent mounts (project root mount leaves `.env`, MCP `.env`, `store/` visible); main may set `additionalMounts` via IPC | F3 (secret-area refusal + shadowing by canonical host path), F2 (drop containerConfig from IPC `register_group`), lead (README allowlist) |
| MYTH-05 | high | Container egress unrestricted (metadata, internal services, vLLM without key, internet); HTTP API binds 0.0.0.0 by default | F3 (dedicated `talon-agents` network, ICC off), F9 (`talon setup egress` firewall rules), F5 (require vLLM API key, doctor), F6 (default bind 127.0.0.1) |
| MYTH-06 | high | Slowloris FD exhaustion on HTTP API / gateway / Emacs bridge | lead (`talon-net`), F4, F6, F7 (use it), F9 (`LimitNOFILE`) |
| MYTH-07 | medium | Host memory exhaustion: unbounded frame channels, timeout reset per frame, uncapped results, 16 MiB gateway bodies × concurrency | F3, F5, F4 |
| MYTH-08 | medium | Gateway denylist lets nested/unknown vLLM fields through (`chat_template_kwargs.chat_template`, media URLs, `guided_regex`, grammar, `ignore_eos`, ...); no `cache_salt` | F4 |
| MYTH-09 | medium | Agent-writable `groups/<folder>/CLAUDE.md` becomes the trusted system prompt for every lane; Emacs lane writes main's folder via symlink | F3 (read-only bind), F8 (separate fenced `MEMORY.md`), F7 (Emacs own folder) |
| MYTH-10 | low | Host reads of agent-written files follow directory symlinks / race to FIFOs (`load_verdict`, `/templates`, `/evals`, Emacs CLAUDE.md bootstrap) | F5, F6, F7 |
| MYTH-11 | low | Unthrottled audit rows / log forging via control characters from IPC | F2 |
| MYTH-12 | low | User-id normalization merges lanes (`bob.smith` == `bobsmith`, case-insensitive FS) | F6 |
| MYTH-13 | info | Main's MCP servers under `/workspace/project` always refused by the supervisor | F8 |

Residual risks accepted for now: prompt injection is inherent (bash is always
available, so containment matters more than detection); the raw `opensearch`
MCP is exposed next to `opensearch_anon`; the audit chain is unkeyed and its
tail can be truncated by someone with host DB write access; no global vLLM
fairness between lanes.
