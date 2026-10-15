## Type of change

- [ ] **Fix** — bug fix
- [ ] **Security** — hardening or vulnerability fix
- [ ] **Feature** — new capability (channel, tool, MCP integration, intel)
- [ ] **Investigation content** — templates or workflow in `groups/copilot/`
- [ ] **Refactor / performance**
- [ ] **Documentation**

## Description


## Testing

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Container image rebuilt (`./container/build.sh`) if `container/` or `talon-agent` changed

## Security checklist

- [ ] Untrusted data is fenced before it reaches the model
- [ ] No security boundary is weakened (mounts, container flags, gateway, lane isolation)
- [ ] No credentials, customer data or internal hostnames in code, fixtures or this description
