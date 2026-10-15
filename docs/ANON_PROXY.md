# Anonymizing MCP Proxy

This document explains the anonymizing OpenSearch MCP proxy — what problem it solves, how it works step by step, and how to extend it.

Since Talon 2.0 the proxy is a Rust binary, **`talon-anon-proxy`** (crate `crates/talon-anon`). The original Python implementation (`siem/anon_proxy/anon_proxy.py`) remains as a fallback; both read the same `fields.yaml` and the same token-map format.

---

## The Problem

When the SOC agent investigates an alert, it calls OpenSearch to retrieve the raw SIEM event. That event contains sensitive data:

- Usernames and account names (`john.doe`, `CORP\jsmith`)
- Internal hostnames (`WORKSTATION-01`, `DC-PROD-02`, `dc01.corp.local`)
- Internal IP addresses (`192.168.1.100`, `fd00::1`)
- Email addresses (`john.doe@company.com`)
- Domain SIDs and MAC addresses

In the standard MCP flow, tool results are returned directly into the model's context window — meaning this raw sensitive data is sent to the model provider as part of every investigation.

The anonymizing proxy intercepts those results before they reach the model and replaces PII values with opaque tokens. The model reasons about `USER_1`, `HOST_1`, and `IP_INT_1` instead of real names and addresses.

---

## How It Works — Step by Step

```
┌──────────────────────────────────────────────────────────────────┐
│                         Model / agent                            │
│                                                                  │
│  "Fetch the raw event for alert 1234"                            │
│                        │                                         │
│  mcp__opensearch_anon__get_document(index, id)                   │
└────────────────────────┼─────────────────────────────────────────┘
                         │ JSON-RPC request (stdin)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│            talon-anon-proxy  (runs in the container)             │
│                                                                  │
│  1. Tracks the request id → method (and aggregation fields)      │
│  2. Replaces tokens in the arguments with the real values        │
│     (so the model can search for USER_1)                         │
│  3. Forwards it to opensearch-mcp.sh (child process)             │
└──────────────────────────────────────────────────────────────────┘
                         │ JSON-RPC request (child stdin)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│           opensearch-mcp-server  (child process)                 │
│  Fetches the raw event from OpenSearch, returns the document     │
└──────────────────────────────────────────────────────────────────┘
                         │ raw document (child stdout)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│              talon-anon-proxy  (intercepts response)             │
│                                                                  │
│  4. Parses the result (JSON text, JSON embedded in text,         │
│     structuredContent) and walks every field (two passes)        │
│  5. For each value, checks fields.yaml:                          │
│     • Known PII field?   → replace value with TOKEN_N            │
│     • Preserved field?   → kept (detectors only, see below)      │
│     • Verbatim field?    → untouched                             │
│     • Other string?      → free-text detectors + known values    │
│  6. Writes new mappings to the token map (atomic, 0600)          │
│  7. Returns the anonymized result to the agent                   │
└──────────────────────────────────────────────────────────────────┘
                         │ anonymized document (stdout)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                         Model / agent                            │
│                                                                  │
│  Receives:                                                       │
│    data_win_eventdata_user:  USER_1          ← was john.doe      │
│    agent_name:               HOST_1          ← was WORKSTATION-01│
│    data_win_eventdata_destinationIp: 8.8.8.8 ← preserved         │
│    data_win_eventdata_hashes: SHA256=abc123  ← preserved         │
│    rule_level: 12                            ← preserved         │
│                                                                  │
│  Reasons about tokens, runs threat intel on preserved IOCs,      │
│  writes the report draft using tokens                            │
└──────────────────────────────────────────────────────────────────┘
```

---

## Token Types

| Token format | Replaces | Example |
|---|---|---|
| `USER_1`, `USER_2`, … | Usernames, account names | `john.doe` → `USER_1` |
| `HOST_1`, `HOST_2`, … | Hostnames, computer names, UNC hosts | `WORKSTATION-01` → `HOST_1` |
| `EMAIL_1`, `EMAIL_2`, … | Email addresses / UPNs | `j.doe@corp.com` → `EMAIL_1` |
| `IP_INT_1`, `IP_INT_2`, … | Internal IPv4/IPv6 addresses | `192.168.1.100` → `IP_INT_1` |
| `DOMAIN_INT_1`, … | AD / internal DNS domains | `CORP\jsmith` → `DOMAIN_INT_1\USER_2` |
| `SID_1`, … | Domain / Azure AD SIDs (the RID is kept) | `S-1-5-21-…-…-…-500` → `SID_1-500` |
| `MAC_1`, … | MAC addresses | `00:1a:2b:3c:4d:5e` → `MAC_1` |

Tokens are **consistent within a session** — the same original value always maps to the same token (lookups are case-insensitive, so `WS01` and `ws01` share a token). `john.doe` seen in ten different events is always `USER_1`, making correlation across events still possible. Composite values keep their structure: `ws01.corp.local` → `HOST_1.DOMAIN_INT_1`, `CORP\jsmith` → `DOMAIN_INT_1\USER_2`, and the bare `jsmith` elsewhere is also `USER_2`.

Anonymization is idempotent: a token is never tokenized again.

---

## What Is Preserved (Never Anonymized)

These values pass through unchanged because they are needed for threat intelligence and analysis:

| Value | Why preserved |
|---|---|
| `data_win_eventdata_hashes` and other hashes | VirusTotal / MalwareBazaar hash lookups |
| External IPs (`8.8.8.8`, `2606:4700::1`, …) | Shodan / AbuseIPDB / VT lookups |
| Public domains (`data_win_eventdata_destinationHostname`, `queryName`) | C2 domain reputation checks |
| `data_win_eventdata_image` / `parentImage` / `commandLine` | Process path / command-line analysis |
| `rule_*` fields | MITRE mapping, severity, classification |
| `data_win_system_eventID` | Alert type detection |
| Timestamps, `_id`, `_index` | Event sequencing, document pointers |
| Well-known principals (`SYSTEM`, `NT AUTHORITY\…`, `BUILTIN\…`, `Administrator`, `-`) | Analytic meaning, identify nobody (`keep_values`) |

`preserve_fields` are never replaced *as a whole*. With `scan_preserved_fields: true` (the shipped setting) the free-text detectors still run on them, so `C:\Users\john.doe\` inside a preserved command line or an internal source IP in `data_srcip` is tokenized — the detectors never touch hashes, public IPs or public domains. Fields listed in `verbatim_fields` (hashes, rule ids/levels/groups/MITRE, event IDs, timestamps, `_id`, `_index`) are never touched at all. `rule_description` is preserved but scanned, because Wazuh descriptions can interpolate event fields (`… from $(srcip)`).

---

## Field Matching

Field names in `fields.yaml` use underscore notation. The Rust proxy matches them on *atoms* (split on `.` and `_`, case-insensitive), so one entry covers all document shapes:

| Shape | Example key path |
|---|---|
| CoPilot flat | `data_win_eventdata_targetUserName` |
| Dotted | `data.win.eventdata.targetUserName` |
| Nested OpenSearch hit | `hits.hits[]._source.data.win.eventdata.targetUserName` |
| Partially nested | `{"eventdata": {"targetUserName": …}}` (≥ 2 trailing atoms) |

List elements inherit their field (`related.user: ["alice", "bob"]` → two `USER_n`). When a field is listed in several categories, the first category whose optional `value_pattern` matches wins; otherwise the last category without a pattern (the Python rule). The shipped file uses this so `targetUserName` becomes `EMAIL_n` for `j.doe@corp.com` but `USER_n` for `jdoe`.

**Aggregations:** bucket keys are values of the aggregated field. The proxy remembers `{"<agg>": {"terms": {"field": "agent.name"}}}` from the request (also composite sources and JSON-encoded bodies) and tokenizes `aggregations.<agg>.buckets[].key` like `agent.name`.

---

## Free-Text Detectors

Every string that is not a configured field is scanned (all can be switched off in `fields.yaml`):

| Detector | Example | Result |
|---|---|---|
| E-mail (`scan_emails`) | `mail john.doe@acme.com` | `mail EMAIL_1` |
| UNC host (`scan_unc_paths`) | `\\fileserver01\share` | `\\HOST_1\share` |
| `DOMAIN\user` (`scan_domain_users`) | `Logon by CORP\jsmith` | `Logon by DOMAIN_INT_1\USER_1` |
| Profile paths (`scan_user_paths`) | `C:\Users\john.doe\AppData`, `/home/bob/`, `/Users/alice/` | `C:\Users\USER_1\AppData`, … |
| SIDs (`scan_sids`) | `S-1-5-21-1-2-3-1104` | `SID_1-1104` (well-known SIDs kept) |
| MACs (`scan_macs`) | `00:1A:2B:3C:4D:5E` | `MAC_1` |
| Internal IPs (`scan_inline_ips`) | `connected to 10.0.1.55`, `fe80::1%eth0` | `connected to IP_INT_1`, `IP_INT_2` |
| Internal DNS names (`scan_internal_domains`) | `dc01.corp.local` | `HOST_1.DOMAIN_INT_1` |

Internal IPs are RFC 1918, loopback, link-local, CGNAT `100.64/10`, the other IANA special-purpose ranges the Python `ipaddress.is_private` covers, IPv6 ULA / link-local / site-local, and IPv4-mapped forms of those. `0.0.0.0` and `255.255.255.255` are kept. Internal DNS names are names under `internal_domains` (your organisation's domains) or under suffixes that are internal by definition (`local`, `localdomain`, `lan`, `internal`, `intranet`, `corp`, `home.arpa`). Path detectors ignore web URLs (`https://github.com/Users/x/` is untouched).

**Known-value sweep:** once a value has a token, every later occurrence in free text — e.g. a user name inside `full_log`, a host name in a message — is replaced too, at word boundaries (`ann` does not match inside `annual`). Each document is processed in two passes, so a field value anywhere in the document is known before its free text is swept. Values shorter than `sweep_min_length` (3) or without letters are not swept.

JSON keys are scanned by the detectors as well (keyed aggregations, IP-keyed maps), but never swept, so ordinary field names are never rewritten. JSON documents inside strings (e.g. `full_log`) are parsed and walked.

---

## De-anonymization Before Report Delivery

After analysis is complete, the agent calls the built-in `deanonymize` tool to restore original values in the report draft before it reaches the analyst:

```
Step 1 — Investigation (tokens in context)
  USER_1 connected to IP_INT_1 and ran a suspicious command.
  USER_1 is a member of the Domain Admins group.

Step 2 — Call deanonymize(text="<full report draft>")

Step 3 — De-anonymized output returned to model
  john.doe connected to 192.168.1.100 and ran a suspicious command.
  john.doe is a member of the Domain Admins group.

Step 4 — Submit to CoPilot and send to analyst
```

The tool is answered by the proxy itself and never forwarded to OpenSearch. Replacement is a single pass, longest token first, and only at token boundaries: `USER_1` never clobbers `USER_10`, and a restored value that happens to look like a token is not substituted again.

**Tool arguments:** tokens in `tools/call` arguments are replaced with the real values before the request is forwarded (JSON-encoded string arguments are parsed so restored values are escaped correctly). The model can therefore correlate with `search_documents(query="user.name:USER_1")`; OpenSearch receives the real name and the results come back tokenized. Disable with `--no-deanonymize-arguments`.

---

## Session Token Map

The token map holds the real values. It is written atomically (temp file + fsync + rename) with mode `0600`, and its parent directory is created (`0700`) if needed.

| Situation | Location |
|---|---|
| `TALON_ANON_MAP` set | that path |
| Default (container) | `$HOME/session_tokens.json` — inside the agent container the supervisor gives each MCP server a private, writable tmpfs `HOME` (`/run/talon/home/<server>`, `0700`), readable only by `mcp-siem`, not by the agent |
| Dev mode, `$HOME` not writable | `/workspace/group/session_tokens.json` (the pre-2.0 location) |
| Python fallback | always `/workspace/group/session_tokens.json` |

The format is unchanged from the Python proxy, so existing maps keep working in both directions:

```json
{
  "forward": {
    "john.doe": "USER_1",
    "WORKSTATION-01": "HOST_1",
    "192.168.1.100": "IP_INT_1"
  },
  "counters": {
    "USER": 1,
    "HOST": 1,
    "IP_INT": 1
  }
}
```

The `forward` map is used for anonymization (original → token) and the reverse is computed on demand for de-anonymization (token → original).

Robustness:
- Several proxies may share one map file: every change runs under a lock file (`<map>.lock`, stale locks are broken) and starts by re-reading the file, so two proxies never hand out the same token for different values.
- Tokens are written to disk *before* the anonymized response that contains them is released.
- A corrupt map is moved aside to `<map>.corrupt-<unix-seconds>`, never silently overwritten.
- If the map cannot be written (read-only directory), the proxy keeps working with an in-memory map and logs a warning.

---

## Running the Proxy

```
talon-anon-proxy [--fields <fields.yaml>] --map <session_tokens.json> -- <upstream command> [args...]

  --fields <YAML>              field definitions (default: the copy embedded at build time; env TALON_ANON_FIELDS)
  --map <FILE>                 token map (env TALON_ANON_MAP)
  --max-line-bytes <BYTES>     maximum JSON-RPC message size (default 32 MiB)
  --shutdown-grace-secs <SECS> wait for the upstream after the client disconnects (default 10)
  --no-deanonymize-arguments   forward tool arguments exactly as written by the model
  --check                      validate fields.yaml and the token map, then exit
```

`siem/anon-opensearch-mcp.sh` (the MCP server command in `.mcp.json`) finds the binary (`$TALON_ANON_PROXY_BIN`, `PATH`, `/usr/local/bin`, `target/{release,debug}`), resolves the map path as above and runs `talon-anon-proxy --fields anon_proxy/fields.yaml --map … -- opensearch-mcp.sh`. Without the binary it falls back to the Python proxy.

Protocol behaviour:
- stdout carries only JSON-RPC; logs go to stderr (`TALON_ANON_LOG` / `RUST_LOG`, default `info`) and never contain real values — only counts, sizes, ids and method names.
- `tools/list` results get the `deanonymize` tool appended (on the last page, once).
- `tools/call` results are anonymized: `text` content (whole-text JSON, JSON embedded after a prefix such as `Search results: {…}`, or plain text), `resource` text and URIs, `structuredContent`, and any other member. Images/audio pass through.
- Upstream error messages, responses to unknown ids, and server-initiated notifications/requests (logging, progress) are anonymized as well. `initialize`, `ping` and list results pass through unchanged.
- Non-JSON output of the upstream (stray prints) is dropped and logged, never forwarded raw.
- Oversize messages are never forwarded; the waiting request gets a JSON-RPC error (`-32001` for responses, `-32600` for requests) when its id can be recovered.
- If the upstream exits, every pending request gets a JSON-RPC error (`-32000`) and the proxy exits with the upstream's exit code. When the agent closes stdin, the upstream's stdin is closed, its remaining responses are relayed for the grace period, and the proxy exits 0. SIGTERM/SIGINT/SIGHUP shut down the same way.
- Invalid JSON from the client is answered with `-32700`.

---

## File Layout

```
crates/talon-anon/           ← Rust proxy (library + talon-anon-proxy binary)
siem/
  opensearch-mcp.sh          ← raw OpenSearch MCP server (used for non-sensitive queries)
  anon-opensearch-mcp.sh     ← anonymizing wrapper (use for all document/search queries)
  anon_proxy/
    anon_proxy.py            ← Python fallback proxy
    fields.yaml              ← field definitions (git-pullable, embedded into the binary at build time)
```

The proxy is registered as a second MCP server in `groups/copilot/.mcp.json`:

```json
{
  "mcpServers": {
    "opensearch":      { "command": "/workspace/extra/siem/opensearch-mcp.sh" },
    "opensearch_anon": { "command": "/workspace/extra/siem/anon-opensearch-mcp.sh" },
    "mysql":           { "command": "/workspace/extra/mysql/mysql-mcp.sh" },
    "copilot":         { "command": "/workspace/extra/copilot-mcp/copilot-mcp.sh" }
  }
}
```

The agent uses `mcp__opensearch_anon__*` for all document retrieval and search queries, and falls back to `mcp__opensearch__*` only for non-sensitive operations like `get_index` and `list_indices`.

---

## Adding New Fields to Anonymize

Field definitions live in `siem/anon_proxy/fields.yaml`. To add a new field:

1. Open `siem/anon_proxy/fields.yaml`
2. Find the right category (`user`, `hostname`, `email`, `domain`) or add a new one
3. Add the field name in **underscore notation** (Wazuh/CoPilot convention)
4. Validate: `talon-anon-proxy --fields siem/anon_proxy/fields.yaml --map /tmp/check.json --check`
5. Commit and push — other deployments run `git pull` to receive the update

Example — adding Azure AD fields:

```yaml
categories:
  user:
    token_prefix: "USER"
    fields:
      - data_win_eventdata_user
      - data_win_eventdata_targetUserName
      # new:
      - data_azure_ad_userPrincipalName
      - data_azure_ad_displayName
```

To add a **new category** (e.g., for credit card numbers or national IDs):

```yaml
categories:
  # ... existing categories ...

  national_id:
    token_prefix: "NID"
    description: "National ID / SSN equivalents"
    fields:
      - data_custom_national_id
      - data_custom_ssn
```

Tokens for the new category will be `NID_1`, `NID_2`, etc. (Prefixes must match `^[A-Za-z][A-Za-z0-9_]{0,31}$`.)

To **preserve** a field that might otherwise be anonymized, add it to `preserve_fields`; to exempt it from the free-text detectors as well, also add it to `verbatim_fields`:

```yaml
preserve_fields:
  - my_custom_external_ip_field
verbatim_fields:
  - my_custom_external_ip_field
```

Other optional keys (ignored by the Python fallback):

| Key | Default | Meaning |
|---|---|---|
| `value_pattern` (per category) | — | Regex the value must match for this category |
| `internal_domains` | `[]` | Your organisation's DNS domains (names under them are tokenized) |
| `internal_domain_suffixes` | `local, localdomain, lan, internal, intranet, corp, home.arpa` | Internal-by-definition suffixes |
| `keep_values` | (built-in placeholders `-`, `n/a`, …) | Values never tokenized, case-insensitive |
| `scan_preserved_fields` | `false` (shipped: `true`) | Run detectors on preserved fields |
| `verbatim_fields` | `[]` | Never touched at all |
| `scan_emails`, `scan_domain_users`, `scan_unc_paths`, `scan_sids`, `scan_macs`, `scan_internal_domains` | `true` | Free-text detectors |
| `sweep_known_values`, `sweep_min_length` | `true`, `3` | Known-value sweep |
| `user_token_prefix`, `host_token_prefix`, `email_token_prefix`, `domain_token_prefix`, `sid_token_prefix`, `mac_token_prefix` | `USER`, `HOST`, `EMAIL`, `DOMAIN_INT`, `SID`, `MAC` | Prefixes used by the detectors |

`fields.yaml` is embedded into the binary at build time (the container build copies it); a file passed with `--fields` always takes precedence.

---

## How the Proxy Fits Into a Full Investigation

```
Alert created in CoPilot
        │
        ▼
Step 0  Check for existing job → register new job → update to "running"
        │
        ▼
Step 1  MySQL: pull alert + asset metadata (index_name, index_id)
        │
        ▼
Step 2  opensearch_anon: get_document → raw event returned anonymized
        opensearch:      get_index    → field mappings (not sensitive)
        │
        ▼
Step 2.5 Detect alert type from rule.groups / eventID
         Load prompt template from /workspace/group/prompts/<type>.txt
        │
        ▼
Step 3  Extract IOCs from anonymized event
        (hashes, external IPs, domains are preserved — usable as-is)
        (usernames/hosts appear as USER_1 / HOST_1)
        │
        ▼
Step 4  Threat intel: VirusTotal, Shodan, AbuseIPDB
        (external IOCs were never anonymized, queries work normally)
        │
        ▼
Step 5  opensearch_anon: search_documents — correlation queries
        (queries may use tokens — the proxy restores them for OpenSearch;
         results consistently use the same tokens from Step 2)
        │
        ▼
Step 6a opensearch_anon: deanonymize(text=<full report draft>)
        USER_1 → john.doe, HOST_1 → WORKSTATION-01, IP_INT_1 → 192.168.1.100
        │
        ▼
Step 6b UpdateAiAnalystJobTool → SubmitAiAnalystReportTool → SubmitAiAnalystIocsTool
        │
        ▼
Step 6c send_message → analyst receives accurate, fully resolved report
```

---

## Limitations

- Free-text detection cannot recognise a bare, never-seen name (`alice` in prose without any field, path or `DOMAIN\` context); it is caught only once the value has been seen in a configured field (known-value sweep).
- Host names in public-looking DNS domains are tokenized only via configured fields or `internal_domains`.
- Tokens are case-insensitive per value: `Bob` and `bob` share a token and de-anonymize to the first-seen spelling.
- JSON-RPC batches are supported, but a batch that mixes `deanonymize` with forwarded calls is answered in two batch responses.
