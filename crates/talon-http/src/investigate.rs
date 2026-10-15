//! Investigation jobs and the seeded alert-digest task.
//!
//! `POST /investigate` registers a `once` scheduled task on the
//! investigation lane (due immediately) plus an [`Investigation`] row, then
//! wakes the scheduler. Running it through the task scheduler instead of the
//! chat message loop makes the job durable across restarts and lets the
//! host correlate task id == job id when it records the outcome.

use std::time::Duration;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use talon_core::schedule;
use talon_core::time::{parse_iso, to_iso};
use talon_core::types::{ContextMode, ScheduleType, ScheduledTask, TaskStatus};
use talon_core::{Error, Result};
use talon_db::Investigation;

use crate::store::HttpStore;

/// Id of the seeded 15-minute alert digest task.
pub const DIGEST_TASK_ID: &str = "copilot-alert-digest-15m";
/// JID the digest posts to (owned by the outbound webhook channel).
pub const WEBHOOK_JID: &str = "webhook:copilot";
/// Digest schedule.
pub const DIGEST_CRON: &str = "*/15 * * * *";
/// Investigation status written when a job is queued.
pub const STATUS_QUEUED: &str = "queued";
/// Terminal failure status; failed jobs never de-duplicate a new trigger.
pub const STATUS_FAILED: &str = "failed";

/// A validated investigation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigationRequest {
    /// CoPilot's numeric alert id.
    pub alert_id: u64,
    /// Customer code (`^[A-Za-z0-9_-]{1,64}$`).
    pub customer_code: String,
    /// Trigger label (`webhook` by default).
    pub triggered_by: String,
    /// Template filename forced by the caller.
    pub template_override: Option<String>,
}

/// `copilot-inv-<alert_id>-<millis>`
pub fn job_id(alert_id: u64, millis: i64) -> String {
    format!("copilot-inv-{alert_id}-{millis}")
}

/// Whether `existing` should be returned instead of starting a new job for
/// `req` at `now`: same alert, customer and template, not failed, created
/// within `window`. A zero window disables de-duplication. A different
/// template override is a deliberate replay and always runs.
pub fn is_duplicate(
    existing: &Investigation,
    req: &InvestigationRequest,
    window: Duration,
    now: DateTime<Utc>,
) -> bool {
    if window.is_zero()
        || existing.status == STATUS_FAILED
        || existing.alert_id != req.alert_id.to_string()
        || existing.customer_code != req.customer_code
        || existing.template != req.template_override
    {
        return false;
    }
    let Some(created) = parse_iso(&existing.created_at) else {
        return false;
    };
    let Ok(window) = chrono::Duration::from_std(window) else {
        return true;
    };
    created > now - window && created <= now + chrono::Duration::minutes(5)
}

/// The `once` task that runs an investigation on `chat_jid`, due now.
pub fn investigation_task(
    id: &str,
    group_folder: &str,
    chat_jid: &str,
    prompt: String,
    tz: Tz,
    now: DateTime<Utc>,
) -> Result<ScheduledTask> {
    let local = now
        .with_timezone(&tz)
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    let next_run = schedule::first_run(ScheduleType::Once, &local, tz, now)?;
    Ok(ScheduledTask {
        id: id.to_string(),
        group_folder: group_folder.to_string(),
        chat_jid: chat_jid.to_string(),
        prompt,
        script: None,
        schedule_type: ScheduleType::Once,
        schedule_value: local,
        context_mode: ContextMode::Isolated,
        next_run: Some(next_run),
        last_run: None,
        last_result: None,
        status: TaskStatus::Active,
        created_at: to_iso(now),
    })
}

/// The investigation row stored alongside the task.
pub fn investigation_record(
    id: &str,
    req: &InvestigationRequest,
    now: DateTime<Utc>,
) -> Investigation {
    let ts = to_iso(now);
    Investigation {
        id: id.to_string(),
        alert_id: req.alert_id.to_string(),
        customer_code: req.customer_code.clone(),
        triggered_by: req.triggered_by.clone(),
        status: STATUS_QUEUED.to_string(),
        template: req.template_override.clone(),
        created_at: ts.clone(),
        updated_at: ts,
        verdict: None,
        error: None,
    }
}

/// Prompt for a targeted investigation (port of the TS template plus the
/// structured-verdict step; every interpolated value is validated before it
/// gets here).
pub fn investigation_prompt(req: &InvestigationRequest, job_id: &str) -> String {
    let alert_id = req.alert_id;
    let customer_code = &req.customer_code;
    let triggered_by = &req.triggered_by;
    let override_line = req
        .template_override
        .as_deref()
        .map(|t| format!("\n- template_override: {t}"))
        .unwrap_or_default();
    let step_override_instruction = req
        .template_override
        .as_deref()
        .map(|t| {
            format!(
                "3a. TEMPLATE OVERRIDE — the caller selected template \"{t}\". Skip Step 2.5 template detection entirely. Read /workspace/group/prompts/{t} directly and follow it. Record selection_method=\"override\" when writing the eval JSON.\n"
            )
        })
        .unwrap_or_default();

    format!(
        r#"You are running a targeted SOC investigation triggered by CoPilot. Follow the full investigation workflow from CLAUDE.md.

Alert to investigate:
- alert_id: {alert_id}
- customer_code: {customer_code}
- job_id: {job_id}
- triggered_by: {triggered_by}{override_line}

Steps:
1. Skip Step 0 deduplication — this job has already been registered by the caller with id="{job_id}". Call UpdateAiAnalystJobTool(job_id="{job_id}", status="running") immediately.
2. Resolve the alert source and target document via MySQL before any OpenSearch query. The alert_id passed here is CoPilot's internal DB counter and is NOT a field on raw SIEM documents — searching OpenSearch for it returns nothing, and falling back to a time-window query will pick up unrelated noise (typically the agent's own container-startup events) and produce a report about the wrong event. Run exactly this query via mcp__mysql__mysql_query:

     SELECT a.id, a.alert_name, a.source, a.alert_creation_time,
            a.customer_code, ast.asset_name, ast.agent_id,
            ast.index_name, ast.index_id
     FROM incident_management_alert a
     LEFT JOIN incident_management_asset ast ON ast.alert_linked = a.id
     WHERE a.id = {alert_id} AND a.customer_code = "{customer_code}";

   Treat the returned (index_name, index_id) as the authoritative pointer to the raw event for every subsequent SIEM lookup. The 'source' column ("wazuh", "office365", "misp", …) tells you which OpenSearch index family the event lives in. If the row is missing, ast.index_name is empty, or the source is unrecognised, mark the job 'failed' with a descriptive error_message rather than guessing from timestamps.
3. Follow Steps 2–6 from CLAUDE.md exactly (fetch raw event + index mapping, detect alert type, load template, extract IOCs, threat intel, SIEM correlation).
{step_override_instruction}3b. Complete Step 5.5 from CLAUDE.md: call score_alert, verify every claim against the evidence you collected, then call submit_triage_report with report_id="{job_id}". Use the severity_assessment label and the Markdown it returns for step 4b. Talon records this structured verdict on the investigation.
4. Write back to CoPilot — call these three tools in order. The four body fields on SubmitAiAnalystReportTool (severity_assessment, summary, report_markdown, recommended_actions) carry the entire human-readable investigation output; a call missing any of them persists a blank row that surfaces as an empty report in CoPilot. Pass all of them every time, even on trivial false positives.

   a. mcp__copilot__UpdateAiAnalystJobTool(job_id="{job_id}", status="completed", template_used=<template key or null>)

   b. mcp__copilot__SubmitAiAnalystReportTool — returns report_id:
        job_id="{job_id}"
        alert_id={alert_id}
        customer_code="{customer_code}"
        severity_assessment=<Critical|High|Medium|Low|Informational>
        summary=<1-2 sentence tl;dr>
        report_markdown=<full structured markdown report>
        recommended_actions=<action list>

   c. mcp__copilot__SubmitAiAnalystIocsTool(report_id=<from 4b>, alert_id={alert_id}, customer_code="{customer_code}", iocs=[...])

5. Write the eval JSON to /home/agent/.talon/evals/{alert_id}-{job_id}.json as instructed in CLAUDE.md Step 6 (create the directory if needed). That directory is private to this investigation lane; never write evals under /workspace/group.
6. Send the full investigation report via send_message."#
    )
}

/// The paused 15-minute alert digest task, seeded once per database.
pub fn digest_task(group_folder: &str, tz: Tz, now: DateTime<Utc>) -> Result<ScheduledTask> {
    let next_run = schedule::first_run(ScheduleType::Cron, DIGEST_CRON, tz, now)?;
    Ok(ScheduledTask {
        id: DIGEST_TASK_ID.to_string(),
        group_folder: group_folder.to_string(),
        chat_jid: WEBHOOK_JID.to_string(),
        prompt: DIGEST_PROMPT.to_string(),
        script: None,
        schedule_type: ScheduleType::Cron,
        schedule_value: DIGEST_CRON.to_string(),
        context_mode: ContextMode::Group,
        next_run: Some(next_run),
        last_run: None,
        last_result: None,
        status: TaskStatus::Paused,
        created_at: to_iso(now),
    })
}

/// Create the digest task unless it already exists. Returns true if it was
/// created. Never touches an existing task (an operator may have resumed or
/// edited it).
pub fn seed_digest_task(
    store: &dyn HttpStore,
    group_folder: &str,
    tz: Tz,
    now: DateTime<Utc>,
) -> Result<bool> {
    if store.get_task_by_id(DIGEST_TASK_ID)?.is_some() {
        return Ok(false);
    }
    let task = digest_task(group_folder, tz, now)?;
    store.create_task(&task)?;
    Ok(true)
}

/// Create the task and the investigation row; on a failure to record the
/// investigation, the task is removed again so the two never drift apart.
pub(crate) fn persist_investigation(
    store: &dyn HttpStore,
    task: &ScheduledTask,
    inv: &Investigation,
) -> Result<()> {
    if store.get_task_by_id(&task.id)?.is_some() {
        return Err(Error::invalid(format!("task {} already exists", task.id)));
    }
    store.create_task(task)?;
    if let Err(e) = store.upsert_investigation(inv) {
        if let Err(del) = store.delete_task(&task.id) {
            tracing::error!(task = %task.id, err = %del, "failed to roll back investigation task");
        }
        return Err(e);
    }
    Ok(())
}

/// Verbatim port of the TS digest prompt.
pub const DIGEST_PROMPT: &str = r#"You are running as a scheduled SOC monitor. Follow these steps exactly for each alert.

1. Query MySQL for OPEN alerts with no completed AI investigation:

   SELECT a.id, a.alert_name, a.source, a.alert_creation_time,
          a.customer_code, ast.asset_name, ast.agent_id,
          ast.index_name, ast.index_id
   FROM incident_management_alert a
   JOIN incident_management_asset ast ON ast.alert_linked = a.id
   WHERE a.status = 'OPEN'
     AND a.alert_creation_time >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
     AND ast.index_name != ''
     AND ast.index_id != ''
   ORDER BY a.alert_creation_time DESC;

2. If no rows are returned, stop here. Do not send any message.

3. For each alert:

   a. DEDUPLICATION — call ListAiAnalystJobsByAlertTool(alert_id=<id>).
      If a job with status "completed" already exists, skip this alert.

   b. REGISTER JOB — call CreateAiAnalystJobTool:
        id="copilot-inv-<alert_id>-<unix_timestamp>"
        alert_id=<id>, customer_code=<code>, triggered_by="scheduled"
      Then immediately call UpdateAiAnalystJobTool(job_id=<id>, status="running").

   c. FETCH INDEX MAPPING + RAW EVENT in parallel:
      - get_document(index_name, index_id) → full raw alert event
      - get_index(index_name) → field mapping (confirms field names and types)
      Use the mapping before writing any OpenSearch query.

   d. DETECT ALERT TYPE from the raw event:
      - List available templates: ls /workspace/group/prompts/
      - Compare the template filenames with the alert summary
        (rule_description, rule_groups, data_win_system_eventID, agent_name)
        and pick the best matching filename, or none if nothing fits
        (selection_method="hints")
      - Fallback: match rule_groups values or data_win_system_eventID
        against the available filenames (selection_method="fallback")

      NOTE: Graylog flattens all fields with underscores — use
      rule_groups, rule_description, data_win_system_eventID, agent_name.
      Never use dot notation for raw document fields.

   e. LOAD TEMPLATE — Read /workspace/group/prompts/<filename>.
      If found, follow its steps substituting:
        {{ alert }} → raw OpenSearch event JSON
        {{ event_id }} → numeric event ID
        {{ pipeline | default('wazuh') }} → wazuh
        {{ virustotal_results }} → VT results after threat intel
      If no template, use the default steps below.

   f. DEFAULT INVESTIGATION (when no template matches):
      - Extract IOCs: IPs (data_win_eventdata_destinationIp, data_srcip, data_dstip),
        domains (data_win_eventdata_queryName, data_win_eventdata_destinationHostname),
        hashes (data_win_eventdata_hashes), processes (data_win_eventdata_image,
        data_win_eventdata_parentImage), commands (data_win_eventdata_commandLine)
      - For each external IP/domain: WebSearch "<value>" site:virustotal.com
      - For each SHA256 hash: WebFetch https://www.virustotal.com/gui/file/<hash>
      - Check rule_level, rule_description, rule_mitre_tactic

   g. WRITE BACK TO COPILOT — call in order:
      1. UpdateAiAnalystJobTool(job_id=<id>, status="completed",
           template_used=<alert_type or null>)
      2. SubmitAiAnalystReportTool(
           job_id=<id>, alert_id=<id>, customer_code=<code>,
           severity_assessment=<Critical|High|Medium|Low|Informational>,
           summary=<1-2 sentence tl;dr>,
           report_markdown=<full markdown report>,
           recommended_actions=<action list>)
         → note the returned report_id
      3. SubmitAiAnalystIocsTool(
           report_id=<from step 2>, alert_id=<id>, customer_code=<code>,
           iocs=[{ ioc_value, ioc_type, vt_verdict, vt_score, details }, ...])
         ioc_type: ip|domain|hash|process|url|user|command
         vt_verdict: malicious|suspicious|clean|unknown

   h. SEND REPORT via send_message:
      🔍 **SOC Investigation** — <alert_name>
      Customer: <customer_code> | Asset: <asset_name> | Created: <alert_creation_time>
      **Severity**: <assessment> | **Template**: <alert_type or "default">

      **Alert Summary**: rule description, MITRE tactic/technique
      **IOC Analysis**: table of IOCs with type and VT verdict
      **Severity Assessment**: reasoning
      **Recommended Actions**: specific actionable steps

      On any error during write-back, call UpdateAiAnalystJobTool with
      status="failed" and error_message=<exception details>."#;

#[cfg(test)]
mod tests {
    use super::*;

    fn req(template: Option<&str>) -> InvestigationRequest {
        InvestigationRequest {
            alert_id: 1234,
            customer_code: "acme".into(),
            triggered_by: "webhook".into(),
            template_override: template.map(str::to_string),
        }
    }

    fn now() -> DateTime<Utc> {
        parse_iso("2026-10-14T12:00:00.000Z").unwrap()
    }

    #[test]
    fn job_ids_follow_the_ts_format() {
        assert_eq!(
            job_id(1234, 1714000000000),
            "copilot-inv-1234-1714000000000"
        );
    }

    #[test]
    fn prompt_carries_the_job_and_alert() {
        let p = investigation_prompt(&req(None), "copilot-inv-1234-1");
        assert!(p.contains("- alert_id: 1234\n- customer_code: acme\n- job_id: copilot-inv-1234-1\n- triggered_by: webhook\n\nSteps:"));
        assert!(p.contains(r#"WHERE a.id = 1234 AND a.customer_code = "acme";"#));
        assert!(p.contains(
            "5. Write the eval JSON to /home/agent/.talon/evals/1234-copilot-inv-1234-1.json as instructed"
        ));
        assert!(!p.contains("/workspace/group/evals"));
        assert!(!p.contains("TEMPLATE OVERRIDE"));
        assert!(p.contains("SIEM correlation).\n3b. Complete Step 5.5"));
        assert!(p.contains(r#"submit_triage_report with report_id="copilot-inv-1234-1""#));
        assert!(p.contains("for step 4b. Talon records this structured verdict on the investigation.\n4. Write back"));
    }

    #[test]
    fn prompt_includes_the_template_override() {
        let p = investigation_prompt(&req(Some("sysmon_event_1.txt")), "j");
        assert!(p.contains("- triggered_by: webhook\n- template_override: sysmon_event_1.txt\n"));
        assert!(p.contains(
            "3a. TEMPLATE OVERRIDE — the caller selected template \"sysmon_event_1.txt\"."
        ));
        assert!(p.contains("Read /workspace/group/prompts/sysmon_event_1.txt directly"));
        assert!(p.contains(
            "selection_method=\"override\" when writing the eval JSON.\n3b. Complete Step 5.5"
        ));
    }

    #[test]
    fn once_task_is_due_now_on_the_investigation_lane() {
        let t = investigation_task(
            "copilot-inv-1-5",
            "copilot",
            "http:copilot:investigate",
            "p".into(),
            chrono_tz::Europe::Berlin,
            now(),
        )
        .unwrap();
        assert_eq!(t.schedule_type, ScheduleType::Once);
        assert_eq!(t.schedule_value, "2026-10-14T14:00:00");
        assert_eq!(t.next_run.as_deref(), Some("2026-10-14T12:00:00.000Z"));
        assert_eq!(t.context_mode, ContextMode::Isolated);
        assert_eq!(t.status, TaskStatus::Active);
        assert_eq!(t.chat_jid, "http:copilot:investigate");
        schedule::validate(
            t.schedule_type,
            &t.schedule_value,
            chrono_tz::Europe::Berlin,
        )
        .unwrap();
    }

    #[test]
    fn dedup_rules() {
        let window = Duration::from_secs(600);
        let mut existing = investigation_record("j1", &req(None), now());
        let later = now() + chrono::Duration::minutes(5);
        assert!(is_duplicate(&existing, &req(None), window, later));
        // Outside the window.
        assert!(!is_duplicate(
            &existing,
            &req(None),
            window,
            now() + chrono::Duration::minutes(11)
        ));
        // Disabled.
        assert!(!is_duplicate(&existing, &req(None), Duration::ZERO, later));
        // A different template is a replay.
        assert!(!is_duplicate(&existing, &req(Some("x.txt")), window, later));
        // Different customer.
        let mut other = req(None);
        other.customer_code = "beta".into();
        assert!(!is_duplicate(&existing, &other, window, later));
        // Failed jobs never block a retry.
        existing.status = STATUS_FAILED.into();
        assert!(!is_duplicate(&existing, &req(None), window, later));
        // Completed jobs inside the window are returned.
        existing.status = "completed".into();
        assert!(is_duplicate(&existing, &req(None), window, later));
        // Garbage timestamps never dedup.
        existing.created_at = "yesterday".into();
        assert!(!is_duplicate(&existing, &req(None), window, later));
    }

    #[test]
    fn digest_task_is_paused_and_scheduled() {
        let t = digest_task("copilot", chrono_tz::UTC, now()).unwrap();
        assert_eq!(t.id, DIGEST_TASK_ID);
        assert_eq!(t.status, TaskStatus::Paused);
        assert_eq!(t.chat_jid, WEBHOOK_JID);
        assert_eq!(t.context_mode, ContextMode::Group);
        assert_eq!(t.schedule_value, "*/15 * * * *");
        assert_eq!(t.next_run.as_deref(), Some("2026-10-14T12:15:00.000Z"));
        assert!(
            t.prompt
                .starts_with("You are running as a scheduled SOC monitor.")
        );
        assert!(t.prompt.contains("{{ alert }} → raw OpenSearch event JSON"));
        assert!(t.prompt.ends_with("error_message=<exception details>."));
    }
}
