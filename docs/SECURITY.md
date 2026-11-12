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
- `groups/<folder>/AGENT.md` and `.mcp.json` are bind-mounted read-only (the
  host creates placeholders when missing), so an agent cannot rewrite its own
  trusted instructions or the commands the supervisor runs as `mcp-*` users.
  Agent-writable notes live in `MEMORY.md`, which is fenced as untrusted.
- The instructions have two candidate names: `AGENT.md`, and `CLAUDE.md` for
  installations from before the rename (used while `AGENT.md` has no
  content). Neither may be plantable, or an agent could create the name that
  is not in use and have the host prefer it on the next run. So on every run
  the host binds the one source file read-only over **both**
  `/workspace/group/AGENT.md` and `/workspace/group/CLAUDE.md`; the unused
  name exists on the host only as a host-created stub that is never a source
  (empty files and the host's own marker texts carry no instructions). A
  symlink, directory, FIFO or other non-regular file under either name
  refuses the launch, as does a file that appears or changes between the
  host's decision and the binds (`mount.rejected`). Inside the container the
  root supervisor refuses to start the agent unless both paths are read-only
  mount points, and the agent reads only `AGENT.md` in the group folder.
  Template copies (`register_group`, `talon setup register`, the Emacs
  bootstrap) follow the same precedence, create `AGENT.md` only in a folder
  that has neither name, and never replace either. If both names have
  content, `AGENT.md` wins, the run is audited
  (`instructions.legacy_ignored`) and `talon doctor` reports it.
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
- Requests in flight are counted per lane across all of the lane's tokens,
  and one lane may hold at most `TALON_LLM_GATEWAY_LANE_SHARE` percent of the
  global cap (default 75 %: 24 of 32). A flooding or compromised lane is
  refused with `429` (audit reason `lane_share_exceeded`) while the remaining
  slots stay available to the other lanes; see
  [PROVIDER_SELECTION.md](PROVIDER_SELECTION.md#capacity-between-lanes) for
  the exact guarantee.

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
  append-only, hash-chained table. `talon audit verify` detects modified or
  deleted rows.
- **Unkeyed (default).** Each row stores
  `sha256(prev_hash || canonical_json(event))`. This catches inconsistent
  edits, but whoever can write the database can recompute every hash after
  an edit, or delete the newest rows. `talon doctor` and `talon audit verify`
  print a hint while the chain is unkeyed.
- **Keyed (`TALON_AUDIT_KEY` in `.env`, at least 32 characters,
  `openssl rand -hex 32`).** New rows store
  `HMAC-SHA-256(key, seq || prev_hash || canonical_json(event))`, where `seq`
  is the row's position in the chain. Without the key a row can neither be
  forged nor recomputed. The key is read from `.env` only, never enters a
  container, is registered with the redactor and is never logged.
  - *Transition.* Existing rows stay unkeyed and valid. Every row records
    its scheme; the first keyed row (an `audit.chain.keyed` event) MACs the
    hash and the number of the unkeyed rows before it, which freezes them.
    An unkeyed row after a keyed one is a downgrade and fails verification
    (this also covers a row appended by an older Talon release).
  - *Fail closed.* Keyed rows cannot be verified without the key, or with
    another one: `talon audit verify` fails (`CHAIN: unverifiable` /
    `tampered`), and `talon run` refuses to start when the newest row is
    keyed but the key is missing or does not authenticate it, instead of
    running without a working audit log.
  - *Truncation checkpoint.* After every keyed append Talon atomically
    rewrites `store/audit.checkpoint` (host-only, never mounted): sequence
    number and hash of the newest row, MAC'd with the key. `talon audit
    verify` fails when the checkpoint is ahead of the table (`CHAIN:
    truncated`), missing, or does not verify. The next append that finds
    such a mismatch first records an `audit.checkpoint.anomaly` event in the
    keyed chain (reason `ahead`, `missing`, `invalid` or `mismatch`) and only
    then re-anchors the checkpoint, so a truncation stays on record;
    `talon audit verify` shows the count as `CHECKPOINT_ANOMALIES`. Restoring
    the database from a backup looks the same and is recorded the same way.
- **External anchor.** `talon audit head` prints id, hash, scheme and
  sequence number of the newest row (the same values are logged at startup
  and shutdown). Shipping them to a system the host cannot write is the only
  complete defence against rollback; see the residual risks.

#### Audit key

- Generate it once (`openssl rand -hex 32`), put it in `.env`
  (`chmod 600`), restart Talon, and keep a copy somewhere that is not the
  Talon host's database backup.
- There is no key rotation: rows are verified with the one configured key.
- If the key is lost, the keyed rows can no longer be verified or extended.
  Archive the table and start a new chain under a new key (stop Talon
  first):

  ```sql
  -- sqlite3 store/messages.db
  DROP TRIGGER audit_log_no_update;
  DROP TRIGGER audit_log_no_delete;
  DROP INDEX idx_audit_log_kind;
  DROP INDEX idx_audit_log_timestamp;
  ALTER TABLE audit_log RENAME TO audit_log_lost_key;
  ```

  then delete `store/audit.checkpoint` and start Talon with the new key.

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
- The audit chain is unkeyed unless `TALON_AUDIT_KEY` is set; an unkeyed
  chain can be recomputed or truncated by anyone with write access to the
  host database. With the key, what remains is:
  - An attacker who can read `.env` holds the key and can rewrite the log
    and the checkpoint at will. The key protects against database write
    access, not against a compromised host account.
  - An attacker who can write the database *and* `store/audit.checkpoint`
    but lacks the key can roll both back to an earlier state for which they
    kept a copy of the checkpoint file (the pair is consistent, nothing
    detects it), but cannot produce a checkpoint for any other state.
  - The same attacker can replace every keyed row by an unkeyed chain and
    delete the checkpoint; `talon audit verify` then only warns that a key
    is configured but no row is keyed, which is also the legitimate state
    before the first keyed event.
  - The checkpoint is written after the row is committed: a crash in
    between leaves it one row behind (reported as `CHECKPOINT_LAG`), and
    truncating exactly that lag is not detected.
  - Rows written before the key was configured are only frozen from the
    transition on; edits made earlier are not detectable.

  Anchor `talon audit head` on a system the host cannot write (append-only
  log store, another host) if these matter.
- The `AGENT.md` name was not protected before the rename: an `AGENT.md` an
  agent created in its group folder under an older version is
  indistinguishable from one the operator wrote, and takes precedence over
  `CLAUDE.md` after the upgrade. Check `ls groups/*/AGENT.md` before
  upgrading; afterwards `talon doctor` (`instructions_legacy_ignored`) and
  the `instructions.legacy_ignored` audit event point at every folder where
  both files have content.
- Egress firewall rules are opt-in and must be applied by the operator; they
  survive a reboot only when applied with `--persist` (systemd hosts).
- Model capacity is shared between lanes by a per-lane ceiling on requests
  in flight, not by a scheduler: one lane cannot take the whole gateway, but
  several lanes saturating it at once (two at the default 75 % share) can
  still fill it, and request slots do not account for how many tokens a
  request makes the model server process. Lower
  `TALON_LLM_GATEWAY_LANE_SHARE` if more lanes must be isolated from each
  other.

## Reporting

Report vulnerabilities in this repository privately through GitHub's
**Security → Report a vulnerability** (private vulnerability reporting), not
as a public issue. Include affected versions, a reproduction and the impact.
Vulnerabilities in CoPilot or in the MCP servers Talon installs belong to
those projects.
