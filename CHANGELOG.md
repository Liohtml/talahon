# Changelog

All notable changes to Talon are documented in this file.

## [2.0.4] - 2026-10-16

- fix: message flow, Telegram and scheduling bugs carried over from the old version (#11)

## [2.0.3] - 2026-10-16

- fix(http): CoPilot workflow and HTTP API bugs carried over from the old version (#10)

## [2.0.2] - 2026-10-16

- fix(anon): close PII leaks in the anonymizing proxy (#9)

## [2.0.1] - 2026-10-16

- fix: lost messages, DST cron loop, fail-open sender allowlist, .env inline comments (#8)
- docs: CoPilot integration reflects the Rust CoPilot side and the real endpoints (#7)
- ci: publish from the CRATES environment (#6)

## [2.0.0] - 2026-10-14

- Rust workspace (`crates/`): host orchestrator `talon` and in-container runtime `talon-agent` with a native agent loop.
- Model provider **vLLM** (OpenAI-compatible API, tool calling, guided JSON decoding); configure `TALON_VLLM_*` (see `docs/PROVIDER_SELECTION.md`).
- CLI: `talon run | setup <step> | doctor | audit verify|tail | version`. Service label `com.talon` / unit `talon`.
- Fail-closed defaults: an unset `HTTP_API_KEY` rejects every request except `/health`; the Emacs bridge requires `EMACS_AUTH_TOKEN`; webhooks to private addresses need `WEBHOOK_ALLOWED_HOSTS`.
- Host LLM gateway with per-run tokens (the vLLM key never enters a container), model pinning, parameter stripping, rate limits.
- Privilege-separated container: root supervisor runs each MCP server as its own `mcp-*` user; agent runs unprivileged; cap-drop ALL, no-new-privileges, read-only rootfs, `--init`, resource limits; no sudo in the image.
- Prompt-injection fencing and detection, secret redaction, SSRF-safe egress, hardened IPC, hash-chained audit log (`talon audit verify`).
- Offline intelligence engine (`talon-intel`): IOC extraction, MITRE ATT&CK mapping, command-line analysis, triage scoring, correlation, structured `submit_triage_report` verdicts.
- Anonymizing MCP proxy in Rust (`talon-anon-proxy`).
- HTTP API: `POST /investigate`, `GET /investigations`, `GET /investigations/{id}`, `POST /message` (SSE), `GET /status`, `GET /metrics`, templates, evals and MemPalace endpoints; investigation deduplication.
- Independent adversarial security review (three rounds, see `docs/MYTHOS_REVIEW.md`) with all findings fixed.
- Published on crates.io as `talahon-*` (`cargo install talahon` installs `talon`); every merge to `main` is versioned (Conventional Commits) and released automatically.
- Dependencies: `rustls` 0.23.46 (RUSTSEC-2026-0346 to -0349); `fields.yaml` is parsed with `yaml-rust2` (safe Rust) instead of the unmaintained `serde_yaml`/`unsafe-libyaml`. CI checks advisories with `cargo deny`.
