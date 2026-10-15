# Contributing to Talon

Talon processes live SOC alert data and runs with access to customer SIEM
environments. Contributions are welcome, and every change is reviewed with a
security-first lens.

## Before you start

1. **Check for existing work.** Search open pull requests and issues first.
2. **One thing per PR.** One fix, one capability, one improvement — don't mix
   unrelated changes.
3. **No real customer data.** Never put alert data, credentials, hostnames,
   IP addresses or customer names into issues, PRs, fixtures or example output.
4. **Security issues are not public issues.** Report them privately (see
   [docs/SECURITY.md](docs/SECURITY.md#reporting)).

## What we accept

**Welcome:**
- Bug fixes and security fixes
- Detection and enrichment improvements in `talon-intel` (IOC types, MITRE
  mappings, triage scoring) with tests
- Anonymizer improvements (`talon-anon`, `siem/anon_proxy/fields.yaml`)
- New investigation templates in `groups/copilot/prompts/` (no code needed)
- Investigation workflow improvements in `groups/copilot/CLAUDE.md`
- New channels or MCP integrations that follow the existing security contracts
- Documentation fixes

**Not accepted:**
- Changes that weaken a security boundary: the mount allowlist, container
  hardening, the LLM gateway, lane isolation, prompt-injection fencing or the
  anonymizing proxy
- Cloud model providers that send SIEM data off the operator's infrastructure
- `unsafe` code

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
./container/build.sh            # when you touch container/ or talon-agent
```

CI runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
--locked -- -D warnings` and `cargo test --workspace --locked`; all three must
pass.

### Code rules

- No `unsafe` (workspace lint) and no `unwrap`/`expect` outside tests.
- Document public items.
- Treat everything that comes from an alert, a log line, a web page, a tool
  result or a container as hostile: fence it with
  `talon_security::injection::fence_untrusted` before it reaches the model,
  and never derive identity or permissions from its contents.
- Record security decisions through `talon_core::audit`.
- `talon-core` is the host ↔ container contract. Change it deliberately and
  update both the host (`talon`) and the agent (`talon-agent`) in the same PR.
- Add tests for every behaviour change; security fixes need a regression test
  that fails without the fix.

## Investigation templates

Templates in `groups/copilot/prompts/` are plain text and need no code
changes. See [groups/copilot/prompts/README.md](groups/copilot/prompts/README.md)
for naming, the variables that are substituted and how the agent selects a
template.

## Pull requests

- Describe what changed and why, and how you tested it.
- Keep the PR description free of credentials, internal hostnames and
  customer data.
- Update `CHANGELOG.md` for user-visible changes and the docs for changed
  behaviour or configuration.
