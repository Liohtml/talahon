# Talahon

Automated AI SOC analyst for the CoPilot SOC stack, written in Rust. See [README.md](README.md) for setup and [docs/RUST_ARCHITECTURE.md](docs/RUST_ARCHITECTURE.md) for the architecture and security contracts.

## Quick Context

One host process (`talahon`) receives alerts and chat through channels (CoPilot HTTP API, Telegram, signed webhook, Emacs), queues work per lane, and runs each agent turn in a hardened container. Inside the container `talahon-agent supervise` (root, no LLM) starts the MCP servers as separate `mcp-*` users, then `talahon-agent run` executes the agent loop unprivileged against a self-hosted **vLLM** server reached only through the host LLM gateway. Each group has an isolated folder (`groups/<folder>/`), session store and IPC namespace.

## Key Paths

| Path | Purpose |
|------|---------|
| `crates/talon/` | Host binary: orchestrator (`src/orchestrator/`), CLI, wiring (`src/app.rs`) |
| `crates/talon-core/` | Shared contract: types, host↔container protocol, `Channel`/`Tool` traits, config, schedules |
| `crates/talon-agent/` | In-container runtime: `supervise.rs` (privileged), `run.rs` + `agent/` (vLLM loop), `prompt.rs` |
| `crates/talon-llm/` | vLLM client and host LLM gateway |
| `crates/talon-container/` | `docker run` args, mounts, output parser |
| `crates/talon-security/` | Injection guard, redaction, egress, mounts, senders, IPC authz, auth |
| `crates/talon-intel/` | IOC / MITRE / triage / report engine and intel tools |
| `crates/talon-http/` | CoPilot HTTP API channel (its contract is pinned on the CoPilot side in [Liohtml/CoPilot](https://github.com/Liohtml/CoPilot) `crates/copilot-talon/src/contract.rs`; change both together) |
| `container/` | Agent image (`Dockerfile`, `entrypoint.sh`, `build.sh`) |
| `groups/{name}/AGENT.md` | Per-group agent instructions (trusted, read-only in containers; a legacy `CLAUDE.md` is still read). Agent notes live in `MEMORY.md` |
| `groups/copilot/prompts/` | Alert-type investigation templates |
| `siem/`, `mysql/`, `*-mcp/`, `mempalace/` | MCP server wrappers (+ gitignored `.env` credentials) |

## Development

Run commands directly — don't tell the user to run them.

```bash
cargo build --workspace                                # build everything
cargo test --workspace                                 # all tests
cargo clippy --workspace --all-targets -- -D warnings  # lint (CI gate)
cargo fmt --all                                        # format (CI checks --check)
./container/build.sh                                   # rebuild the agent image
cargo run -p talahon -- doctor                         # diagnose a local install
```

Packages are named `talahon-*` on crates.io (directories and Rust crate names stay `talon-*` / `talon_*`), so `-p` takes `talahon-core`, not `talon-core`. Every merge to `main` is versioned and published automatically (`.github/workflows/release.yml`, `scripts/release.py`): use Conventional Commit titles, never edit `CHANGELOG.md` or the version by hand.

The user-facing surface is **Talahon** (`talahon` binaries, `TALAHON_*` settings, `talahon.service`, image `talahon-agent`, `~/.config/talahon`). The pre-rename names (`talon`, `TALON_*`, `talon.service`, `~/.config/talon`, `@Talon`) are aliases for one major version, see "Upgrading from Talon 2.x" in the README. When you add a setting, read it through `talon_core::env` (`EnvFile::get` / `file_value`, `process_var`), never `std::env::var("TALAHON_…")`, so the `TALON_*` alias keeps working. Internal identifiers stay `talon`: crate names, the `talon-agents` network and firewall objects, in-container paths (`/run/talon`, `/home/agent/.talon`), wire markers, metric names, the HTTP API.

Rules of the codebase: no `unsafe` (workspace lint), no `unwrap`/`expect` outside tests, public items documented, untrusted data fenced with `talon_security::injection::fence_untrusted`, security decisions audited via `talon_core::audit`. `talon-core` is the cross-crate contract: change it deliberately and update both host and agent.

Service management:

```bash
systemctl --user restart talahon                       # Linux
launchctl kickstart -k gui/$(id -u)/com.talahon        # macOS
```

## Model Provider

vLLM (`TALAHON_VLLM_*`, the default) or the Anthropic Messages API (`TALAHON_PROVIDER=anthropic`, `TALAHON_ANTHROPIC_*`), see [docs/PROVIDER_SELECTION.md](docs/PROVIDER_SELECTION.md). The agent always speaks the OpenAI-compatible API to the host gateway; for Anthropic the gateway translates (`crates/talon-llm/src/anthropic/`). The upstream API key stays on the host gateway; containers receive a per-run token over stdin.

## Skills

`.claude/skills/` contains only generic helpers (`get-qodo-rules`, `qodo-pr-resolver`). Add features directly in the relevant crate. For installation and troubleshooting use `talahon setup <step>` and `talahon doctor`.

## Container Build Cache

The container buildkit caches the build context aggressively. `--no-cache` alone does not invalidate COPY steps; prune the builder, then re-run `./container/build.sh` for a truly clean rebuild.
