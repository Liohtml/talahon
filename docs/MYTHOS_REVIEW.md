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

## Round 2 — verification and new findings

Verification of round 1: MYTH-01, -02, -10, -13 fixed; MYTH-04, -07, -08,
-12 fixed with low residuals; MYTH-03, -05, -06, -09, -11 partially fixed
(remaining parts tracked below as N-1…N-4). Round-2 work order:

| ID | Sev | Finding | Owners |
|---|---|---|---|
| N-1 | medium | Scheduler `resolve_group` falls back to the smallest JID of the same folder when a task's lane is unregistered (every host restart for per-user lanes), so an analyst's own task runs as the anonymous base lane with its session and IPC namespace | G1 (talon-scheduler) |
| N-2 | medium | Shared `groups/copilot` folder: any lane can overwrite `reports/<job_id>.json` (forged verdicts, poisoned IOC sightings), rewrite `prompts/*.txt` that investigations follow, and forge `evals/` | G3 (prompts read-only bind), G5 (reports in lane-private state dir), G7 (host reads verdicts from the investigation lane's state dir), G6 (evals from the investigation lane's state dir), lead (CLAUDE.md paths) |
| N-3 | medium | Unbounded task creation from one lane (320 every-minute cron tasks × 250 KiB in <1 s; applied ops bypass the audit rate limit; snapshots load all tasks) | G2 (per-lane quotas, prompt cap, min interval, rate limit, filtered task query), G7 (filtered snapshot query) |
| N-4 | medium | HTTP/2 prior-knowledge connections are never timed out → connection slots exhausted without auth | lead (talon-net: HTTP/1 only, idle timeouts, lower per-IP cap) |
| N-5 | low | Oversized `newSessionId` bypasses the session-id cap (DB/memory/log bloat) | G3 (runner), G7 (host) |
| N-6 | low | Gateway forwards JSON-schema contents verbatim (regex/huge bounds → possible vLLM DoS); cache salt per folder, not per lane | G4 (schema keyword allowlist + bounds), G7 (token label = lane ipc key) |
| N-7 | low | Entrypoint palace lock-down walks an `mcp-palace`-owned tree as root after staging secrets (TOCTOU); host secret scan cannot list the 0700 palace dir and refuses the mount (functional regression) | G3 |
| N-8 | low | Lane-key hash only 32 bits → collisions for ids > 40 chars | G6 |
| N-9 | low | Secret scan depth 3, skips `.git` (deep `.env`, `.git/config` exposed); agents can make rw-mount scans fail | G3 |
| N-10 | info | Read-only is not immutable: main's `/workspace/project` view includes agent-writable `groups/`, `data/`, `store/` | G5 (supervisor refuses commands there) |
