<h1 align="center">

<a href="https://www.socfortress.co"><img src="assets/talon-final-1024.png" alt="Talon" width="400"></a>

Talon

[![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white)](https://socfortress.medium.com/)
[![YouTube Channel Subscribers](https://img.shields.io/youtube/channel/subscribers/UC4EUQtTxeC8wGrKRafI6pZg)](https://www.youtube.com/@taylorwalton_socfortress/videos)
[![Discord Shield](https://discordapp.com/api/guilds/871419379999469568/widget.png?style=shield)](https://discord.gg/UN3pNBzaEQ)
[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/taylorwalton)

[![Get in Touch](https://img.shields.io/badge/📧%20Get%20in%20Touch-Friendly%20Support%20Awaits!-blue?style=for-the-badge)](https://www.socfortress.co/contact_form.html)

</h1>

<h4 align="center">

Talon is an automated AI SOC analyst built by <a href="https://www.socfortress.co">SOCfortress</a> for the <a href="https://github.com/socfortress/CoPilot">CoPilot</a> stack. It runs as a background service alongside CoPilot — pulling raw events from your Wazuh/OpenSearch SIEM, enriching them with threat intelligence, correlating across your environment, and writing structured investigation reports with severity assessments and recommended actions directly back into CoPilot.<br><br><strong>Talon 2.0</strong> is a ground-up rewrite in <strong>Rust</strong>, runs entirely on your own <strong>vLLM</strong> model server, and is hardened end to end.

📚 <strong>Docs:</strong> <a href="https://docs.socfortress.co">docs.socfortress.co</a>

</h4>

---

---

## What It Does

- **Automated Tier 1/2 investigations** — every alert is investigated end-to-end: SIEM raw event → offline IOC/MITRE/command-line analysis → threat intel (CVE MCP: VirusTotal, Shodan, AbuseIPDB, GreyNoise, NVD/EPSS/KEV, …) → environment correlation → **structured verdict** (true/false positive, severity, confidence, evidence, recommended actions)
- **Self-hosted model** — the agent loop is native Rust talking to **vLLM** (OpenAI-compatible API, tool calling, guided JSON decoding). No cloud LLM, no Node.js, no SDK: SIEM data never leaves your infrastructure
- **Two trigger paths** — real-time `POST /investigate` from CoPilot and a scheduled sweep as a safety net, with duplicate-trigger deduplication
- **Writes back to CoPilot** — job status, report and enriched IOCs via CoPilot's REST API (MCP tools); verdicts and IOC sightings are also kept locally for correlation across alerts
- **Built-in SOC intelligence** — deterministic, offline engine: low-false-positive IOC extraction (16 types, defang-aware), 265-entry MITRE ATT&CK mapping (Sysmon/Windows event IDs, Wazuh rule groups, command-line evidence), LOLBin/obfuscation analysis with PowerShell decoding, explainable 0–100 triage scoring, alert correlation
- **Privacy by design** — the anonymizing MCP proxy (now in Rust) tokenizes usernames, hosts, internal IPs/domains, SIDs, MACs and profile paths before results reach the model; `deanonymize` restores them for the final report
- **Security-first architecture** — prompt-injection fencing for all untrusted data, privilege-separated containers, per-run LLM tokens, SSRF-safe egress, secret redaction, hash-chained audit log (see [Security](#security))

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       CoPilot (FastAPI)                          │
│  Alert created ─▶ POST /investigate     write-back via MCP tools │
└───────────────┬──────────────────────────────────▲───────────────┘
                │ HTTPS + API key                   │
┌───────────────▼──────────────────────────────────┴───────────────┐
│ talon (host, Rust)                                               │
│  talon-http      CoPilot API: /investigate /message (SSE) /status│
│                  /investigations /metrics /palace /evals         │
│  talon-channels  Telegram · signed webhook · Emacs bridge        │
│  talon-scheduler per-lane queue + cron/interval/once tasks       │
│  talon-ipc       audited, authorized container→host requests     │
│  talon-llm       LLM gateway: per-run tokens ─────────────┐      │
│  talon-db        SQLite: messages, tasks, sessions,       │      │
│                  investigations, IOC sightings, audit log │      │
└───────────────┬───────────────────────────────────────────┼──────┘
                │ docker run (hardened, one per lane/turn)  │
┌───────────────▼───────────────────────────────┐   ┌───────▼──────┐
│ talon-agent container                          │   │  vLLM server │
│  supervise (root, no LLM)                      │   │  (your GPUs) │
│   ├─ MCP servers as mcp-siem, mcp-mysql, …     │   └──────────────┘
│   │  (secrets readable only by their own user) │
│   └─ run (unprivileged agent loop) ────────────┼──▶ gateway ──▶ vLLM
│       tools: bash, files, grep, web_fetch,     │
│       intel tools, mcp__<server>__<tool>       │
└────────────────────────────────────────────────┘
   MCP servers: opensearch / opensearch_anon (anonymizing proxy) · mysql ·
   copilot · wazuh · velociraptor · shuffle · cve · mempalace
```

| Crate | Responsibility |
|---|---|
| `talon` | Host binary: orchestrator, CLI (`run`, `setup`, `doctor`, `audit`) |
| `talon-core` | Shared types, host↔container protocol, traits, config, scheduling |
| `talon-agent` | In-container runtime: root supervisor + unprivileged vLLM agent loop |
| `talon-llm` | vLLM client (streaming, tool-call recovery, guided decoding) + host gateway |
| `talon-mcp` | Native Model Context Protocol client/server/manager |
| `talon-tools` | Built-in agent tools with path guard and SSRF-safe `web_fetch` |
| `talon-intel` | IOC / MITRE / command-line / triage / correlation engine + report schema |
| `talon-anon` | PII anonymizer and `talon-anon-proxy` |
| `talon-security` | Policies: injection guard, redaction, egress, mounts, senders, IPC authz, auth |
| `talon-container` | Hardened docker/podman launcher, mounts, output parser |
| `talon-scheduler` | Group queue and task scheduler |
| `talon-ipc` | Host-side IPC watcher |
| `talon-http`, `talon-channels`, `talon-router` | Channels and message formatting |
| `talon-db` | SQLite store (schema-compatible with Talon 1.x) |
| `talon-setup` | Setup / verify / service installation logic |

Design details: [docs/RUST_ARCHITECTURE.md](docs/RUST_ARCHITECTURE.md).

---

## Security

Talon treats every alert field, log line, web page and tool result as attacker-controlled.

| Layer | Defence |
|---|---|
| Prompt injection | Untrusted data is wrapped in randomly-nonced `<untrusted_data>` envelopes the model is told never to obey; a ~75-rule EN/DE scanner (normalization, base64/exfil decoders, tuned to stay silent on real SIEM telemetry) flags and audits high-risk content |
| Model credentials | The vLLM key stays on the host gateway; each container run gets a short-lived token (SHA-256 stored, revoked at end) passed over stdin, never env. The gateway pins models, clamps tokens, strips dangerous vLLM parameters and rate-limits per run |
| Container | `--cap-drop=ALL` (+ minimal caps for the supervisor), `no-new-privileges`, read-only rootfs + tmpfs, `--init`, pid/memory/cpu limits, no sudo/node in the image, fail-closed host blocks |
| Privilege separation | Root supervisor launches each MCP server as its own `mcp-*` user from read-only config with a private HOME; the agent runs unprivileged and cannot read MCP secrets or their process environments |
| Host ↔ container | Identity derived from the IPC directory, strict authorization (non-main lanes only touch their own tasks), `openat`/`O_NOFOLLOW` file handling, size/depth limits, claim-before-dispatch, every decision audited |
| Egress | `web_fetch` and webhooks check every hop against all private/special IPv4/IPv6 ranges and cloud metadata endpoints, pin DNS to vetted addresses, refuse redirects to internal hosts |
| HTTP API | Fail-closed constant-time API key, per-IP throttling, allowlist CORS, body limits, strict input validation, security headers |
| Secrets in output | Logs and outbound messages pass through a redactor (bearer/JWT/vendor keys/PEM/basic-auth + every configured secret value) |
| Audit | Append-only SQLite audit log with a SHA-256 hash chain: `talon audit verify` detects tampering |

---

## Deployment Guide

### Prerequisites

- Linux host (macOS works for development) with Docker (or Podman)
- Rust 1.85+ (`rustup`), to build the host binary
- A **vLLM** server reachable from the host (see [docs/PROVIDER_SELECTION.md](docs/PROVIDER_SELECTION.md))
- A running OpenSearch / Wazuh SIEM and CoPilot instance (MySQL/MariaDB + FastAPI)

### 1. Build

```bash
git clone https://github.com/taylorwalton/talon.git /opt/talon
cd /opt/talon
cargo build --release
sudo install -m 0755 target/release/talon /usr/local/bin/talon
CONTAINER_RUNTIME=docker ./container/build.sh      # builds talon-agent:latest
```

### 2. Start vLLM

```bash
vllm serve Qwen/Qwen3-32B --enable-auto-tool-choice --tool-call-parser hermes \
  --reasoning-parser qwen3 --enable-prefix-caching --max-model-len 131072 \
  --api-key "$(openssl rand -hex 32)"
```

Model and parser choices per family: [docs/PROVIDER_SELECTION.md](docs/PROVIDER_SELECTION.md).

### 3. Create `.env`

```bash
cp .env.example .env && chmod 600 .env
# Set at least: TALON_VLLM_BASE_URL, TALON_VLLM_MODEL, TALON_VLLM_MAX_CONTEXT,
#               TALON_VLLM_API_KEY (if vLLM uses --api-key), HTTP_API_KEY
talon setup vllm        # checks that the models are served
```

### 4. Create the mount allowlist

Controls which host directories may be mounted into agent containers. It lives outside the project root (`~/.config/talon/`, legacy `~/.config/nanoclaw/` is still read) so agents cannot modify it. Without it, no additional mounts are allowed. **List each directory explicitly — never allowlist the project root or a parent of it**: Talon refuses mounts that contain the project root, `store/`, `data/`, `groups/` or `.env`, and shadows secret files inside every allowed mount.

```bash
mkdir -p ~/.config/talon && chmod 700 ~/.config/talon
T=$(pwd)
ro() { printf '    { "path": "%s/%s", "allowReadWrite": false },\n' "$T" "$1"; }
{
  echo '{ "allowedRoots": ['
  for d in siem mysql copilot-mcp wazuh-mcp velociraptor-mcp shuffle-mcp cve-mcp mempalace; do ro "$d"; done
  printf '    { "path": "%s/mempalace-data", "allowReadWrite": true,\n      "description": "MemPalace data, owned by mcp-palace inside containers" }\n' "$T"
  echo '  ],'
  echo '  "blockedPatterns": [],'
  echo '  "nonMainReadOnly": false'
  echo '}'
} > ~/.config/talon/mount-allowlist.json
chmod 600 ~/.config/talon/mount-allowlist.json
```

MCP directories are always mounted read-only, whatever the allowlist says, and their `.env`/credential files are shadowed and staged for their `mcp-*` user only. `nonMainReadOnly` is `false` only so that `mempalace-data` can stay writable: inside the container it is handed to the `mcp-palace` user (mode 0700), so the agent itself can neither read nor modify it. Because of that ownership change, back up `mempalace-data/` with `sudo`.

### 5. Configure the MCP servers

Each MCP server keeps its credentials in its own directory. Inside the container they are readable only by that server's user.

| Directory | Setup | Credentials |
|---|---|---|
| `siem/` | `bash siem/setup.sh` | `OPENSEARCH_HOSTS`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD` |
| `mysql/` | `bash mysql/setup.sh` | `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASS`, `MYSQL_DB` |
| `copilot-mcp/` | `bash copilot-mcp/setup.sh` | `COPILOT_URL`, `COPILOT_USERNAME`, `COPILOT_PASSWORD` |
| `wazuh-mcp/` | `bash wazuh-mcp/setup.sh` | `WAZUH_PROD_URL`, `WAZUH_PROD_USERNAME`, `WAZUH_PROD_PASSWORD` |
| `velociraptor-mcp/` | `bash velociraptor-mcp/setup.sh` + `api.config.yaml` | Velociraptor API client config |
| `shuffle-mcp/` (optional) | `bash shuffle-mcp/setup.sh` | `SHUFFLE_URL`, `SHUFFLE_API_KEY` |
| `cve-mcp/` (optional) | `bash cve-mcp/setup.sh` | `NVD_API_KEY`, optional VirusTotal/Shodan/AbuseIPDB/GreyNoise/urlscan keys |
| `mempalace/` (optional) | `bash mempalace/setup.sh` | — (local ChromaDB + SQLite in `mempalace-data/`) |

Services on the Talon host are reachable from containers as `host.docker.internal`. Which servers a group uses, and as which user, is defined in `groups/<group>/.mcp.json` (`"runAs": "mcp-siem"` etc.).

### 6. Register groups and install the service

```bash
talon setup environment                 # runtime, image, vLLM, gateway, disk
talon setup register --jid http:copilot --name CoPilot --folder copilot \
  --trigger @Talon --no-trigger-required
talon setup service                     # systemd user unit (hardened) or launchd plist
talon doctor                            # everything in one report
```

Manual alternative: `systemctl --user enable --now talon` with `ExecStart=/usr/local/bin/talon run` and `WorkingDirectory=/opt/talon`, or `launchd/com.talon.plist` on macOS.

### 7. Verify

```bash
curl http://localhost:3100/health                         # unauthenticated
export TALON_API_KEY=...                                   # HTTP_API_KEY from .env
curl -s -N -X POST http://localhost:3100/message \
  -H "Content-Type: application/json" -H "x-api-key: $TALON_API_KEY" \
  -d '{"message": "Check SIEM cluster health", "sender": "test"}'
curl -s -H "x-api-key: $TALON_API_KEY" http://localhost:3100/status
talon audit tail -n 20
```

---

## Operations

| Command | Purpose |
|---|---|
| `talon run` | Run the service (default) |
| `talon doctor` | Diagnose runtime, image, vLLM, gateway, directories, audit chain |
| `talon setup <step>` | `timezone`, `environment`, `vllm`, `container`, `groups`, `register`, `mounts`, `service`, `verify` |
| `talon audit verify` | Recompute the audit hash chain (exit 1 on tampering) |
| `talon audit tail -n 50 --kind ipc.` | Recent audit events as JSON lines |

HTTP API (all but `/health` require `X-Api-Key` or `Authorization: Bearer`):

| Endpoint | Purpose |
|---|---|
| `POST /investigate` | `{alert_id, customer_code, triggered_by?, template_override?}` → queued investigation (deduplicated per alert) |
| `GET /investigations`, `GET /investigations/{id}` | Investigation status and structured verdicts |
| `POST /message` | Analyst chat (SSE stream), per-user lanes via `user_id` |
| `POST /session/reset` | `{scope, user_id?}` with scope `chat`, `investigate` or `all` |
| `GET /status`, `GET /metrics` | Queue, lanes, sessions, tasks; Prometheus metrics |
| `GET /templates`, `GET /evals/{alert_id}` | Investigation templates and eval records |
| `POST /palace/lesson`, `GET /palace/search`, `POST /palace/forget` | MemPalace memory |

Logs: `RUST_LOG=info` (JSON with `TALON_LOG_FORMAT=json`); every line is redacted.

---

## Per-Deployment Configuration

| File | Purpose |
|------|---------|
| `.env` | vLLM, gateway, HTTP API key, channels — `chmod 600`, gitignored |
| `<mcp-dir>/.env` | Per-MCP credentials (siem, mysql, copilot-mcp, wazuh-mcp, velociraptor-mcp, shuffle-mcp, cve-mcp) — gitignored |
| `groups/copilot/CLAUDE.md` | SOC agent identity and investigation workflow; append client context (assets, known-good ranges, crown jewels) at the bottom |
| `groups/copilot/.mcp.json` | MCP servers and their `runAs` users (mounted read-only into containers) |
| `groups/copilot/prompts/` | Per-alert-type investigation templates — add `.txt` files, no code changes |
| `siem/anon_proxy/fields.yaml` | PII field definitions for the anonymizing proxy |
| `~/.config/talon/mount-allowlist.json` | Mount policy — outside the repo, tamper-proof |
| `~/.config/talon/sender-allowlist.json` | Optional per-chat sender allowlist (`TALON_SENDER_ALLOWLIST_REQUIRED=true` to fail closed) |
| `mempalace-data/` | MemPalace data — back up separately |

---

## Documentation

| Doc | Contents |
|-----|---------|
| [docs/RUST_ARCHITECTURE.md](docs/RUST_ARCHITECTURE.md) | Talon 2.0 architecture, crate map, security contracts |
| [docs/PROVIDER_SELECTION.md](docs/PROVIDER_SELECTION.md) | vLLM setup, model/parser choice, gateway, settings |
| [docs/COPILOT_INTEGRATION.md](docs/COPILOT_INTEGRATION.md) | CoPilot integration, MySQL schema, MCP tool reference |
| [docs/ANON_PROXY.md](docs/ANON_PROXY.md) | Anonymizing proxy: flow, token types, `fields.yaml` |
| [docs/SECURITY.md](docs/SECURITY.md) | Security model and trust boundaries |
| [groups/copilot/prompts/README.md](groups/copilot/prompts/README.md) | Writing investigation templates |

Talon 1.x (TypeScript, Claude Agent SDK, Ollama) documentation such as `docs/SPEC.md` and `docs/REQUIREMENTS.md` describes the previous release.

---

## Help

You can reach us on [Discord](https://discord.gg/UN3pNBzaEQ) or by [📧](mailto:info@socfortress.co) if you have any question, issue, or idea!

Check out the full SOCfortress video tutorial series on [![YouTube](https://img.shields.io/badge/YouTube-%23FF0000.svg?style=for-the-badge&logo=YouTube&logoColor=white)](https://www.youtube.com/@taylorwalton_socfortress/videos)
