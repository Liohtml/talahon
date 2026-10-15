# Talon 2.0

Automated AI SOC analyst for the CoPilot SOC stack, written in Rust. See [README.md](README.md) for setup and [docs/RUST_ARCHITECTURE.md](docs/RUST_ARCHITECTURE.md) for the architecture and security contracts.

## Quick Context

One host process (`talon`) receives alerts and chat through channels (CoPilot HTTP API, Telegram, signed webhook, Emacs), queues work per lane, and runs each agent turn in a hardened container. Inside the container `talon-agent supervise` (root, no LLM) starts the MCP servers as separate `mcp-*` users, then `talon-agent run` executes the agent loop unprivileged against a self-hosted **vLLM** server reached only through the host LLM gateway. Each group has an isolated folder (`groups/<folder>/`), session store and IPC namespace.

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
| `groups/{name}/CLAUDE.md` | Per-group agent instructions and memory |
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

Rules of the codebase: no `unsafe` (workspace lint), no `unwrap`/`expect` outside tests, public items documented, untrusted data fenced with `talon_security::injection::fence_untrusted`, security decisions audited via `talon_core::audit`. `talon-core` is the cross-crate contract: change it deliberately and update both host and agent.

Service management:

```bash
systemctl --user restart talon                       # Linux
launchctl kickstart -k gui/$(id -u)/com.talon        # macOS
```

## Model Provider

vLLM only (`TALON_VLLM_*` in `.env`, see [docs/PROVIDER_SELECTION.md](docs/PROVIDER_SELECTION.md)). The vLLM API key stays on the host gateway; containers receive a per-run token over stdin.

## Skills

`.claude/skills/` contains only generic helpers (`get-qodo-rules`, `qodo-pr-resolver`). Add features directly in the relevant crate. For installation and troubleshooting use `talon setup <step>` and `talon doctor`.

## Container Build Cache

The container buildkit caches the build context aggressively. `--no-cache` alone does not invalidate COPY steps; prune the builder, then re-run `./container/build.sh` for a truly clean rebuild.
