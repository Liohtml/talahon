# Offline CVE data

Vulnerability lookups without internet access for the agent.

By default the `cve` MCP server is the online
[cve-mcp-server](https://github.com/mukul975/cve-mcp-server): it runs inside
the agent container and calls public APIs, so the container needs a route to
the internet. In offline mode the **host** downloads the public vulnerability
data once a day and the container reads a local copy:

```
host                                             agent container (no internet)
────                                             ──────────────────────────────
talahon cve sync  ── HTTPS ──> nvd.nist.gov      talahon-cve-mcp  (user mcp-cve)
 (systemd user timer, daily)   epss.empiricalsecurity.com   │ reads, never writes
        │                      www.cisa.gov                 ▼
        └── writes ──> cve-mcp/data/cve.sqlite ── read-only mount ──> /workspace/extra/cve-mcp/data/cve.sqlite
```

`talahon-cve-mcp` links no HTTP client and opens no socket. The only process
that talks to the internet is `talahon cve sync` on the host.

## Set up

Three commands on the Talahon host, in the project directory:

```bash
talahon cve sync                                      # first download (see "Size and duration")
talahon setup cve-sync                                # daily refresh: systemd user timer, no sudo
echo 'TALAHON_CVE_MCP=offline' >> cve-mcp/.env        # agents use the local copy from now on
```

`cve-mcp/` must be in the mount allowlist and in the group's additional
mounts (it is, if the online CVE server was configured before; see step 4 of
the deployment guide). The image must contain `talahon-cve-mcp` (rebuild with
`container/build.sh` after upgrading). `talahon doctor` then shows a
`CHECK_CVE` block and reports a missing or outdated database.

To go back, remove the line from `cve-mcp/.env`; `talahon setup cve-sync
--remove` removes the timer.

## Firewall

The **host** (not the containers) needs outbound HTTPS (TCP 443) to exactly
these three names. A redirect to any other host is refused, so nothing else
is needed:

| Host | What is fetched |
|---|---|
| `nvd.nist.gov` | `/feeds/json/cve/2.0/nvdcve-2.0-<year>.json.gz`, `nvdcve-2.0-modified.json.gz` and the `.meta` file of each |
| `epss.empiricalsecurity.com` | `/epss_scores-current.csv.gz` (redirects to the dated file on the same host) |
| `www.cisa.gov` | `/sites/default/files/feeds/known_exploited_vulnerabilities.json` |

No API key or account is used, and the requests carry nothing about the
installation except its IP address and the user agent `talahon/<version>`.
The agent network needs no internet rule for the CVE server any more
(`talahon setup egress` without `--keep-internet`).

## What a sync does

- **First run, `--full`, or after more than 7 days without a successful
  run:** reads the `.meta` file of every yearly NVD feed (2002 to the current
  year) and downloads the feeds whose checksum differs from the one imported
  last time.
- **Daily run:** downloads only NVD's `modified` feed (every CVE published or
  changed in the last eight days).
- EPSS and KEV are small and are replaced as a whole on every run.
- Every NVD feed is verified against the SHA-256 in its `.meta` file. EPSS
  and KEV publish no checksum; they are checked for shape (header, value
  ranges, KEV's own entry count) and size.
- Limits: `https` only, the three hosts above only, a size limit per file
  (compressed and decompressed), a deadline per request.
- The new database is built in a working file beside the old one, checked
  (`PRAGMA quick_check`) and renamed over it. If anything fails (a source
  unreachable, a checksum mismatch, a full disk) the run exits with code 1
  and the existing database stays untouched. Readers never see a
  half-written file.
- A second run started while one is in progress exits immediately.

`talahon cve status` prints what the database holds and exits 1 if it is
missing or older than `TALAHON_CVE_MAX_AGE_DAYS` (default 3).

## Size and duration

Measured on @@MEASURED_ON@@:

| | First run (full) | Daily run |
|---|---|---|
| Download | @@FULL_DL@@ | @@INC_DL@@ |
| Duration | @@FULL_TIME@@ | @@INC_TIME@@ |
| Peak memory | @@FULL_RSS@@ | @@INC_RSS@@ |

The database is @@DB_SIZE@@ (@@CVES@@ CVEs, @@EPSS@@ EPSS scores, @@KEV@@ KEV
entries). During a run the directory briefly holds two copies plus one
download, so plan for about three times the database size in
`cve-mcp/data/`.

## Tools

All tools only read. Every answer names the time of the data (`data_as_of`)
and carries a `warning` once it is older than `TALAHON_CVE_MAX_AGE_DAYS`.

| Tool | Arguments | Answers |
|---|---|---|
| `lookup_cve` | `cve_ids` (1–20), `include_references` | Description, CVSS (headline and all assessments), CWE, affected products and CPE version ranges, references, EPSS, KEV entry |
| `search_cves` | `query`, `vendor`, `product`, `min_cvss`, `min_epss`, `kev_only`, `published_after`, `sort`, `limit` (≤ 50) | Short hits; words are matched in id, description and product names |
| `get_epss_score` | `cve_ids` (1–100) | EPSS probability and percentile |
| `check_kev` | `cve_ids` (1–100) | Whether each CVE is in CISA KEV, with the entry |
| `list_kev` | `added_after`, `query`, `ransomware_only`, `limit` (≤ 100) | KEV entries, newest first |
| `data_status` | — | Counts, source versions, age of the data |

`lookup_cve`, `search_cves`, `get_epss_score` and `check_kev` have the names
of the online server's tools, so existing prompts keep working; they also
accept its single `cve_id` argument. The online server's other tools (IP,
domain and hash reputation, exploit search, GitHub advisories, MITRE
ATT&CK) need the internet and do not exist offline.

## Settings

| Setting | Where | Meaning |
|---|---|---|
| `TALAHON_CVE_MCP` | `cve-mcp/.env` | `offline` selects the local server; unset or `online` the online one. With `offline` there is no fallback to the online server |
| `TALAHON_CVE_MAX_AGE_DAYS` | `cve-mcp/.env` (tools), `.env` (`cve status`, `doctor`) | Days after which the data counts as outdated (default 3) |
| `TALAHON_CVE_DB` | `.env` | Path of the database on the host (default `cve-mcp/data/cve.sqlite`). Keep the default unless the directory is mounted into the containers some other way |

## Trust

The database content is public text written by thousands of parties
(descriptions, vendor names, links). To the agent it is untrusted data like
every MCP result and is fenced as such; a CVE description cannot give the
agent instructions. The importers bound every field, and the server builds
no SQL from tool arguments.
