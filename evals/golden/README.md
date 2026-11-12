# Golden set

Alerts with a known expected outcome. `talahon eval` scores what an
investigation produced for each of them, so a prompt, model or provider
change can be checked for regressions in investigation quality.

Not to be confused with the *eval records* the investigation agent writes to
its lane-private `evals/` directory (`GET /evals/{alert_id}`): those are
per-run telemetry, this directory is the reference the runs are judged
against.

Everything in here is synthetic: RFC 5737 documentation addresses
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example.com` /
`example.net` / `example.org` names, invented hosts, users and hashes.

## Case file

One JSON file per case, named `<id>.json`. Unknown fields are rejected.

```json
{
  "id": "sysmon1-office-powershell-download",
  "description": "What the case exercises.",
  "alert_type": "sysmon_event_1",
  "request": { "alert_id": 900001, "customer_code": "golden" },
  "alert": { "rule_groups": "windows, sysmon", "data_win_system_eventID": "1" },
  "expect": {
    "verdict": "true_positive",
    "also_acceptable": ["needs_escalation"],
    "severity": { "min": "high", "max": "critical" },
    "required_iocs": [{ "type": "domain", "value": "cdn-update.example.com" }],
    "forbidden_iocs": ["198.51.100.23"],
    "forbidden_strings": ["mimikatz.exe"],
    "forbidden_patterns": ["\\b(USER|HOST|IP_INT)_\\d+\\b"],
    "required_mitre": ["T1059"]
  }
}
```

| Field | Meaning |
|---|---|
| `id` | `^[a-z0-9][a-z0-9_-]{0,63}$`, equal to the file stem. Reports are keyed by it. |
| `alert_type` | Stem of the template in `groups/copilot/prompts/` the alert belongs to. Informational. |
| `request` | The body of `POST /investigate` (`alert_id`, `customer_code`, optional `template_override`); `triggered_by` is always `manual`. |
| `alert` | The raw SIEM event (Graylog-flattened Wazuh fields) the expectations were derived from. See "Online runs". |
| `expect.verdict` | Expected verdict: `true_positive`, `false_positive`, `benign_true_positive`, `needs_escalation`, `inconclusive`. The row of the confusion matrix. |
| `expect.also_acceptable` | Further verdicts that pass. |
| `expect.severity` | Inclusive range, `informational` < `low` < `medium` < `high` < `critical`. |
| `expect.required_iocs` | Must be listed in the report's `iocs`. Compared refanged and case-insensitively: equal for `ip`, `domain`, `hash`; contained in the reported value for `process`, `url`, `user`, `command`. Without `type`, any type matches. |
| `expect.forbidden_iocs` | Must appear nowhere in the report, neither in `iocs` nor in any text. Use plausible values that are *not* in the alert, to catch invented indicators. Matched at token boundaries. |
| `expect.forbidden_strings` | Literal, case-sensitive substrings that must not occur in any string of the report. |
| `expect.forbidden_patterns` | Regular expressions that must not match any string of the report, e.g. leaked anonymization tokens (`USER_1`, `HOST_2`). |
| `expect.required_mitre` | ATT&CK ids that must be cited. `T1059` is satisfied by `T1059.001`; a sub-technique id must match exactly. |

A case passes when every check passes: `report_present`, `schema` (the
report is a valid `TriageReport`), `verdict`, `severity`, and one check per
listed expectation. Keep expectations to what any correct investigation must
contain; every extra required indicator makes the case more brittle.

## Offline scoring

```bash
talahon eval score --reports <dir> [--cases evals/golden] [--json] [--min-pass-rate 1.0]
```

`<dir>` holds one `<case id>.json` per case: either the structured verdict
(the `TriageReport` JSON `submit_triage_report` writes) or the investigation
record returned by `GET /investigations/{id}`. A case without a file counts
as failed. Exit code `0` when the pass rate reaches `--min-pass-rate`
(default: every case), `1` when it does not, `2` on unusable input.

## Online runs

```bash
talahon eval run [--url http://127.0.0.1:3100] [--alert-map map.json] [--customer-code CODE]
               [--timeout-secs 900] [--poll-secs 5] [--save-dir out/] [--json] [--min-pass-rate 1.0]
```

Submits each case to a running Talahon through the CoPilot HTTP API
(`POST /investigate`, then `GET /investigations/{id}` until the job is
`completed` or `failed`), one case at a time, and scores the verdict Talahon
recorded. The API key is `HTTP_API_KEY` from the project's `.env`.
`--save-dir` keeps the investigation records in the layout
`talahon eval score --reports` reads.

What you have to provide:

- **The alerts must exist in the target stack.** `POST /investigate` takes an
  alert *reference*; the agent then loads the event from CoPilot's MySQL and
  the SIEM itself. `talahon eval run` does not seed anything. Index each
  case's `alert` document into the eval stack's SIEM, create the matching
  CoPilot alert and asset rows (`index_name`, `index_id`), and pass the
  resulting ids with `--alert-map` (`{"<case id>": <alert id>}`) unless they
  equal `request.alert_id`.
- **Use a dedicated eval instance.** An online run is a real investigation:
  it writes jobs, reports and IOCs back to CoPilot, records IOC sightings
  and may file MemPalace lessons, which later runs then recall.
- **Disable de-duplication** on that instance
  (`COPILOT_INVESTIGATION_DEDUP_MINUTES=0`). Otherwise a repeated trigger
  returns the previous job; the harness fails such a case rather than score
  a verdict that predates the change under test (`--allow-deduplicated`
  overrides this).

A case whose verdict does not arrive within `--timeout-secs` fails; its job
keeps running in Talahon (the API has no cancel).

## Adding a case

1. Write `<id>.json` with a synthetic alert for one of the templates in
   `groups/copilot/prompts/`.
2. Derive the expectations from the alert alone: required indicators must
   occur in it, forbidden ones must not.
3. `cargo test -p talahon --lib eval_cmd` checks the shipped set: valid
   files, unique alert ids, an existing template, expectations consistent
   with the alert, and that an ideal answer passes while an empty one fails.
