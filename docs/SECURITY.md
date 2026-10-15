# Talon 2.0 Security Model

Talon investigates attacker-controlled data with an LLM that can run tools.
The design assumes that **any successful prompt injection gives the attacker
full control of the agent inside its container** — detection helps, but
containment is what protects the host, the credentials and other tenants.

## Trust model

| Entity | Trust | Notes |
|---|---|---|
| Operator (host shell, `.env`, `~/.config/talon/`) | Trusted | Only the operator configures mounts, networks, providers and MCP servers |
| Main group | Privileged, not trusted with secrets | Can manage tasks and register lanes, never change container config or read host secrets |
| Every other lane (each CoPilot analyst, investigation lane, webhook lane, Telegram chats) | Untrusted | Isolated principal; can only act on itself |
| Agent inside a container | Untrusted | Assume arbitrary code execution as the agent uid |
| SIEM events, alert fields, web pages, MCP tool output | Hostile input | Fenced before reaching the model |
| MCP servers | Semi-trusted code | Each runs as its own `mcp-*` user with only its own secrets |
| vLLM server | Trusted service | Reached only through the authenticated host gateway |

## Boundaries

### 1. Host ↔ container
- One container per lane run: `--cap-drop=ALL` plus the minimal capabilities
  the root supervisor needs, `no-new-privileges`, read-only rootfs with tmpfs,
  `--init`, pid/memory/cpu limits, no sudo, no setuid binaries, no node.
- Mounts are built by the host only. The tamper-proof allowlist
  (`~/.config/talon/mount-allowlist.json`) controls extra mounts; mounts that
  equal or contain the project root, `store/`, `data/`, `groups/` or `.env`
  are refused; MCP directories are recognised by canonical host path, always
  mounted read-only, and their credential files are shadowed and staged for
  the matching `mcp-*` user; credential-named files in any other mount are
  shadowed.
- `groups/<folder>/CLAUDE.md` and `.mcp.json` are bind-mounted read-only (the
  host creates placeholders when missing), so an agent cannot rewrite its own
  trusted instructions or the commands the supervisor runs as `mcp-*` users.
  Agent-writable notes live in `MEMORY.md`, which is fenced as untrusted.
- Group, session and IPC lane directories must be real directories; symlinks
  refuse the launch.
- Output from the container is parsed with frame/byte budgets and bounded
  queues; runaway runs are stopped.

### 2. Privilege separation inside the container
- `talon-agent supervise` (root, no LLM code) starts each MCP server from the
  read-only `.mcp.json` as its own `mcp-*` user with a private HOME,
  `PYTHONSAFEPATH`, a non-writable cwd and a minimal environment; commands
  must resolve to regular files on read-only mounts.
- Each server is exposed on a one-shot unix socket; the agent (`talon-agent
  run`) runs unprivileged with a cleared environment and cannot read MCP
  secrets (`/etc/mcp-secrets/<id>.*`, 0600) or other users' process
  environments.
- MemPalace data is owned by `mcp-palace` (0700): the agent can neither read
  nor plant files (e.g. pickles) there. Host-side `/palace/*` calls run in a
  one-shot hardened container as `mcp-palace`, never on the host.

### 3. Model access
- The vLLM API key is held only by the host LLM gateway; the gateway refuses
  to start without one (explicit opt-out only).
- Each run gets a short-lived token (stored as SHA-256, revoked at run end,
  extendable for long chats) delivered over stdin — not visible in
  `docker inspect` or child environments.
- The gateway forwards only an allowlist of request fields: no chat-template
  overrides, grammar/regex decoding, media URLs or vLLM internals; models are
  pinned, output tokens clamped, a per-lane `cache_salt` separates prefix
  caches; per-token and global concurrency/rate limits, body and JSON-size
  limits.

### 4. Lanes and IPC
- The principal for container → host requests is the lane's IPC namespace,
  derived from the directory, never from file contents.
- Non-main lanes may only message and schedule into their own lane, may not
  attach scripts, and may only modify tasks they created (`task_owners`).
  Host-created tasks (investigations, the alert digest) are immutable for
  lanes. `register_group` is main-only, can never create or modify a main
  lane and never accepts container configuration.
- Host file handling in agent-writable directories uses `openat`/`O_NOFOLLOW`
  directory descriptors, regular-file and size checks, claim-before-dispatch,
  and bounded quarantine — including host writes into IPC input directories.
- Audit rows are rate-limited per namespace with suppression summaries;
  control and bidi characters are neutralized.

### 5. Network
- Containers run on the `talon-agents` bridge (`br-talon`) with
  inter-container traffic disabled.
- `talon setup egress` installs nft/iptables rules: cloud metadata and
  link-local addresses are always blocked, the host is reachable only on the
  LLM gateway port, and destinations can be restricted to the MCP backends.
- `web_fetch` and outbound webhooks additionally resolve and pin every hop
  against all special IPv4/IPv6 ranges.
- All Talon listeners (HTTP API, gateway, Emacs bridge) use header-read
  timeouts and global/per-IP connection caps; the HTTP API binds loopback by
  default and requires a constant-time-checked API key.

### 6. Untrusted content
- SIEM data, tool results and fetched pages are wrapped in nonce-fenced
  `<untrusted_data>` envelopes the model is told never to obey; a heuristic
  scanner (EN/DE, normalized, base64/exfil decoding) flags and audits
  high-risk content.
- The anonymizing proxy tokenizes PII in SIEM results before they reach the
  model context.
- Outbound text and all logs pass through a secret redactor.

### 7. Audit
- Security decisions (auth failures, IPC allow/deny, mount rejections,
  container launches, gateway denials, injection detections) are written to an
  append-only, SHA-256 hash-chained table. `talon audit verify` detects
  modified or deleted rows.

## Adversarial review

Talon 2.0 was reviewed by an independent adversarial reviewer ("Mythos");
findings, proofs of concept and their fixes are tracked in
[MYTHOS_REVIEW.md](MYTHOS_REVIEW.md).

## Residual risks

- Prompt injection cannot be prevented, only contained: assume a compromised
  agent per lane.
- The raw `opensearch` MCP server is available next to `opensearch_anon`, and
  `deanonymize` returns real values; anonymization limits exposure in model
  context and logs, it is not a confidentiality boundary against the model.
- The audit chain is unkeyed; an attacker with write access to the host
  database can truncate its tail. Anchor `audit_chain_head()` externally if
  required.
- Egress firewall rules must be (re)applied by the operator and do not survive
  a reboot by themselves.
- There is no global fairness for vLLM capacity between lanes beyond the
  gateway's concurrency limits.

## Reporting

Report vulnerabilities in this repository privately through GitHub's
**Security → Report a vulnerability** (private vulnerability reporting), not
as a public issue. Include affected versions, a reproduction and the impact.
Issues in CoPilot or other SOCFortress components belong to SOCFortress
(info@socfortress.co).
