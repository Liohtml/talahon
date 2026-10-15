# Changelog

All notable changes to Talon are documented in this file. Entries before 2.0.0 refer to the TypeScript release that was based on NanoClaw.

## [2.0.0] - 2026-10-14 — Talon 2.0 (Rust rewrite)

- [BREAKING] Complete rewrite in Rust (Cargo workspace under `crates/`): host orchestrator `talon` and in-container runtime `talon-agent` replace the Node.js host and the Claude Agent SDK runner. Existing `store/messages.db` databases are migrated in place.
- [BREAKING] Model provider is now **vLLM** (OpenAI-compatible API, tool calling, guided JSON decoding). Ollama and Anthropic modes are removed; configure `TALON_VLLM_*` (see `docs/PROVIDER_SELECTION.md`).
- [BREAKING] CLI: `talon run | setup <step> | doctor | audit verify|tail | version`. Service label `com.talon` / unit `talon`.
- [BREAKING] Unset `HTTP_API_KEY` now rejects every request except `/health`; the Emacs bridge requires `EMACS_AUTH_TOKEN`; webhooks to private addresses need `WEBHOOK_ALLOWED_HOSTS`.
- Host LLM gateway with per-run tokens (the vLLM key never enters a container), model pinning, parameter stripping, rate limits.
- Privilege-separated container: root supervisor runs each MCP server as its own `mcp-*` user; agent runs unprivileged; cap-drop ALL, no-new-privileges, read-only rootfs, `--init`, resource limits; no sudo or node in the image.
- Prompt-injection fencing and detection, secret redaction, SSRF-safe egress, hardened IPC, hash-chained audit log (`talon audit verify`).
- New offline intelligence engine (`talon-intel`): IOC extraction, MITRE ATT&CK mapping, command-line analysis, triage scoring, correlation, structured `submit_triage_report` verdicts.
- Anonymizing proxy rewritten in Rust (`talon-anon-proxy`) with more token classes and detectors; map format unchanged.
- New HTTP endpoints: `GET /investigations`, `GET /investigations/{id}`, `GET /metrics`; investigation deduplication.
- Independent adversarial security review (three rounds, see `docs/MYTHOS_REVIEW.md`) with all findings fixed.
- Removed the TypeScript implementation (`src/`, `container/agent-runner/`, `setup/`, npm tooling), the Ollama MCP wrapper, OneCLI scripts and the NanoClaw skills that patched TypeScript sources; they remain available in the git history.
- [UPGRADE] Reset `groups/*/prompts/` and `groups/copilot/notifications.md` from git after upgrading (they are read-only inside containers now; anything planted earlier would be trusted). Per-user CoPilot sessions start fresh (new lane keys). `sudo chown -R 61008:61008 mempalace-data`.

## [1.2.36] - 2026-03-26

- [BREAKING] Replaced pino logger with built-in logger. WhatsApp users must re-merge the WhatsApp fork to pick up the Baileys logger compatibility fix: `git fetch whatsapp main && git merge whatsapp/main`. If the `whatsapp` remote is not configured: `git remote add whatsapp https://github.com/qwibitai/nanoclaw-whatsapp.git`.

## [1.2.35] - 2026-03-26

- [BREAKING] OneCLI Agent Vault replaces the built-in credential proxy. Check your runtime: `grep CONTAINER_RUNTIME_BIN src/container-runtime.ts` — if it shows `'container'` you are on Apple Container, if `'docker'` you are on Docker. Docker users: run `/init-onecli` to install OneCLI and migrate `.env` credentials to the vault. Apple Container users: re-merge the skill branch (`git fetch upstream skill/apple-container && git merge upstream/skill/apple-container`) then run `/convert-to-apple-container` and follow all instructions (configures credential proxy networking) — do NOT run `/init-onecli`, it requires Docker.

## [1.2.21] - 2026-03-22

- Added opt-in diagnostics via PostHog with explicit user consent (Yes / No / Never ask again)

## [1.2.20] - 2026-03-21

- Added ESLint configuration with error-handling rules

## [1.2.19] - 2026-03-19

- Reduced `docker stop` timeout for faster container restarts (`-t 1` flag)

## [1.2.18] - 2026-03-19

- User prompt content no longer logged on container errors — only input metadata
- Added Japanese README translation

## [1.2.17] - 2026-03-18

- Added `/capabilities` and `/status` container-agent skills

## [1.2.16] - 2026-03-18

- Tasks snapshot now refreshes immediately after IPC task mutations

## [1.2.15] - 2026-03-16

- Fixed remote-control prompt auto-accept to prevent immediate exit
- Added `KillMode=process` so remote-control survives service restarts

## [1.2.14] - 2026-03-14

- Added `/remote-control` command for host-level Claude Code access from within containers

## [1.2.13] - 2026-03-14

**Breaking:** Skills are now git branches, channels are separate fork repos.

- Skills live as `skill/*` git branches merged via `git merge`
- Added Docker Sandboxes support
- Fixed setup registration to use correct CLI commands

## [1.2.12] - 2026-03-08

- Added `/compact` skill for manual context compaction
- Enhanced container environment isolation via credential proxy

## [1.2.11] - 2026-03-08

- Added PDF reader, image vision, and WhatsApp reactions skills
- Fixed task container to close promptly when agent uses IPC-only messaging

## [1.2.10] - 2026-03-06

- Added `LIMIT` to unbounded message history queries for better performance

## [1.2.9] - 2026-03-06

- Agent prompts now include timezone context for accurate time references

## [1.2.8] - 2026-03-06

- Fixed misleading `send_message` tool description for scheduled tasks

## [1.2.7] - 2026-03-06

- Added `/add-ollama` skill for local model inference
- Added `update_task` tool and return task ID from `schedule_task`

## [1.2.6] - 2026-03-04

- Updated `claude-agent-sdk` to 0.2.68

## [1.2.5] - 2026-03-04

- CI formatting fix

## [1.2.4] - 2026-03-04

- Fixed `_chatJid` rename to `chatJid` in `onMessage` callback

## [1.2.3] - 2026-03-04

- Added sender allowlist for per-chat access control

## [1.2.2] - 2026-03-04

- Added `/use-local-whisper` skill for local voice transcription
- Atomic task claims prevent scheduled tasks from executing twice

## [1.2.1] - 2026-03-02

- Version bump (no functional changes)

## [1.2.0] - 2026-03-02

**Breaking:** WhatsApp removed from core, now a skill. Run `/add-whatsapp` to re-add.

- Channel registry: channels self-register at startup via `registerChannel()` factory pattern
- `isMain` flag replaces folder-name-based main group detection
- `ENABLED_CHANNELS` removed — channels detected by credential presence
- Prevent scheduled tasks from executing twice when container runtime exceeds poll interval

## [1.1.6] - 2026-03-01

- Added CJK font support for Chromium screenshots

## [1.1.5] - 2026-03-01

- Fixed wrapped WhatsApp message normalization

## [1.1.4] - 2026-03-01

- Added third-party model support
- Added `/update-nanoclaw` skill for syncing with upstream

## [1.1.3] - 2026-02-25

- Added `/add-slack` skill
- Restructured Gmail skill for new architecture

## [1.1.2] - 2026-02-24

- Improved error handling for WhatsApp Web version fetch

## [1.1.1] - 2026-02-24

- Added Qodo skills and codebase intelligence
- Fixed WhatsApp 405 connection failures

## [1.1.0] - 2026-02-23

- Added `/update` skill to pull upstream changes from within Claude Code
- Enhanced container environment isolation via credential proxy
