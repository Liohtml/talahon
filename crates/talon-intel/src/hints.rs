//! Investigation hints distilled from `groups/copilot/prompts/*.txt` (the
//! per-alert-type Sysmon / Windows guides) plus Windows Security, Defender
//! and Wazuh rule-group knowledge.
//!
//! [`investigation_hints`] returns short, field-specific instructions the
//! agent can inject into its context; [`template_candidates`] reproduces the
//! template fallback selection of the CoPilot workflow (rule group name →
//! `sysmon_event_<id>.txt` → description keyword).
//!
//! Field names use Graylog's underscore flattening
//! (`data_win_eventdata_commandLine`), as in the CoPilot environment.

/// Templates shipped in `groups/copilot/prompts/`.
pub const KNOWN_TEMPLATES: &[&str] = &[
    "sysmon_event_1.txt",
    "sysmon_event_2.txt",
    "sysmon_event_3.txt",
    "sysmon_event_6.txt",
    "sysmon_event_7.txt",
    "sysmon_event_10.txt",
    "sysmon_event_11.txt",
    "sysmon_event_12.txt",
    "sysmon_event_13.txt",
    "sysmon_event_14.txt",
    "sysmon_event_15.txt",
    "sysmon_event_16.txt",
    "sysmon_event_17.txt",
    "sysmon_event_18.txt",
    "sysmon_event_22.txt",
    "windows_autoruns.txt",
    "windows_defender.txt",
    "windows_sigcheck.txt",
];

/// Velociraptor artifacts recommended for suspicious process activity
/// (from `sysmon_event_1.txt`, cheapest first).
const VELOCIRAPTOR_PROCESS: &str = "If suspicious after the steps above, collect live evidence with Velociraptor (resolve the client via mcp__velociraptor__GetAgentInfo(hostname=<asset_name>)): P1 Windows.System.Pslist (still running? process tree) and Windows.Forensics.Prefetch (prior executions); P2 Windows.Sysinternals.Autoruns (persistence) and Windows.Forensics.UserAssist (user-initiated?); P3 Windows.Detection.Yara.Process, Windows.Memory.ProcessDump, Windows.NTFS.MFT (reserve for confirmed malicious).";

fn sysmon_hints(event_id: u32) -> Option<Vec<&'static str>> {
    let h: Vec<&'static str> = match event_id {
        1 => vec![
            "Sysmon 1 (process creation): read data_win_eventdata_commandLine and data_win_eventdata_parentCommandLine to establish the execution context.",
            "Check the parent/child pair (data_win_eventdata_parentImage -> data_win_eventdata_image): Office apps (WINWORD/EXCEL/OUTLOOK) spawning powershell/cmd/wscript/mshta is a classic macro-driven chain; wmiprvse.exe or services.exe spawning shells indicates remote WMI/service execution.",
            "Check the image path: system binary names (svchost.exe, lsass.exe) outside C:\\Windows\\System32 or in AppData/Temp/Users\\Public indicate masquerading.",
            "Decode any base64 in the command line (-enc/-EncodedCommand is UTF-16LE) and analyse the payload; analyze_command_line does this deterministically.",
            "Extract hashes from data_win_eventdata_hashes (SHA256 preferred) and look them up on VirusTotal; note data_win_eventdata_user, integrityLevel and currentDirectory.",
            VELOCIRAPTOR_PROCESS,
        ],
        2 => vec![
            "Sysmon 2 (file creation time changed): attackers timestomp backdoors to look like they were installed with the OS.",
            "Compare data_win_eventdata_creationUtcTime with data_win_eventdata_previousCreationUtcTime for data_win_eventdata_targetFilename; many installers, browsers and sync clients change creation times legitimately.",
            "Suspicious when an executable/script in a user-writable path is backdated, or the modifying image is unusual for that file.",
        ],
        3 => vec![
            "Sysmon 3 (network connection): check data_win_eventdata_destinationIp, destinationHostname, destinationPort and protocol together with data_win_eventdata_image.",
            "Ask whether the port is normal for the image: powershell.exe, rundll32.exe, regsvr32.exe, mshta.exe, certutil.exe or binaries in AppData making outbound connections are suspicious; check data_win_eventdata_initiated.",
            "Enrich external destination IPs (AbuseIPDB / GreyNoise / VirusTotal / Shodan) and look for the same destination from other agents.",
        ],
        6 => vec![
            "Sysmon 6 (driver loaded): check data_win_eventdata_imageLoaded, signed, signature, signatureStatus and hashes.",
            "Unsigned, revoked or expired signatures, and drivers loaded from user-writable paths, are suspicious; known vulnerable signed drivers are loaded for privilege escalation (bring-your-own-vulnerable-driver) - check the hash against LOLDrivers.",
        ],
        7 => vec![
            "Sysmon 7 (image loaded): check data_win_eventdata_imageLoaded and signatureStatus/signed against data_win_eventdata_image.",
            "An unsigned DLL loaded by a signed binary from the same (non-system) directory suggests DLL side-loading; System.Management.Automation.dll loaded by a non-PowerShell process suggests unmanaged PowerShell.",
        ],
        8 => vec![
            "Sysmon 8 (CreateRemoteThread): check data_win_eventdata_sourceImage, targetImage, startModule and startFunction; threads started in another process are a process-injection primitive.",
        ],
        10 => vec![
            "Sysmon 10 (process access): check data_win_eventdata_sourceImage, targetImage, grantedAccess and callTrace.",
            "targetImage lsass.exe opened by a non-system tool (procdump, rundll32 + comsvcs.dll, unknown binaries) with GrantedAccess such as 0x1010, 0x1410, 0x1438, 0x143a or 0x1fffff indicates credential dumping (T1003.001); MsMpEng.exe, csrss.exe, wininit.exe and EDR agents are expected accessors.",
            "UNKNOWN entries in data_win_eventdata_callTrace indicate calls from injected/unbacked memory.",
        ],
        11 => vec![
            "Sysmon 11 (file created): check data_win_eventdata_targetFilename and data_win_eventdata_image.",
            "Executables/scripts written to Startup folders, Temp, Downloads, AppData or ProgramData - especially by Office, browsers, script hosts or LOLBins - are typical malware drops; Startup-folder writes are persistence (T1547.001).",
        ],
        12 => vec![
            "Sysmon 12 (registry key/value created or deleted): check data_win_eventdata_targetObject and data_win_eventdata_image.",
            "Sysmon abbreviates root keys: HKLM = HKEY_LOCAL_MACHINE, HKU = HKEY_USERS, HKCR = HKEY_LOCAL_MACHINE\\Classes; HKLM\\System\\CurrentControlSet maps to ControlSet00x.",
            "Focus on autostart locations: Run/RunOnce, Services, Winlogon (Userinit/Shell), Image File Execution Options, AppInit_DLLs, COM InprocServer32 under HKCU.",
        ],
        13 => vec![
            "Sysmon 13 (registry value set): check data_win_eventdata_targetObject, data_win_eventdata_details (the value written) and data_win_eventdata_image.",
            "Red flags: Run-key values pointing to user-writable paths or script hosts, encoded PowerShell in values, Defender policy values such as DisableAntiSpyware / DisableRealtimeMonitoring.",
        ],
        14 => vec![
            "Sysmon 14 (registry key/value renamed): check data_win_eventdata_targetObject and data_win_eventdata_newName; renames can hide or swap persistence entries.",
        ],
        15 => vec![
            "Sysmon 15 (FileCreateStreamHash): check data_win_eventdata_image, targetFilename, hash and contents.",
            "Zone.Identifier streams are the browser's mark of the web (contents show HostUrl/ReferrerUrl of the download source); other named streams holding executable content indicate payloads hidden in alternate data streams (T1564.004).",
        ],
        16 => vec![
            "Sysmon 16 (Sysmon configuration changed): check data_win_eventdata_configuration, configurationFileHash and who changed it; unexpected changes may be an attacker blinding Sysmon (T1562). Verify against change management.",
        ],
        17 => vec![
            "Sysmon 17 (named pipe created): check data_win_eventdata_pipeName and data_win_eventdata_image; malware uses named pipes for IPC/C2.",
            "Known offensive defaults: \\PSEXESVC (PsExec), \\msagent_*, \\MSSE-*-server, \\postex_*, \\status_* (Cobalt Strike).",
        ],
        18 => vec![
            "Sysmon 18 (named pipe connected): check data_win_eventdata_image, pipeName and eventType; pipe connections over SMB from remote hosts indicate lateral movement or C2 relaying.",
        ],
        19..=21 => vec![
            "Sysmon 19/20/21 (WMI filter/consumer/binding): WMI event subscriptions are a stealthy persistence mechanism (T1546.003); inspect the consumer's command line / script and the filter query.",
        ],
        22 => vec![
            "Sysmon 22 (DNS query): check data_win_eventdata_queryName, queryResults and data_win_eventdata_image.",
            "Non-browser processes (powershell, rundll32, regsvr32, mshta, unknown binaries in AppData) resolving rare, newly registered or DGA-looking domains are suspicious; enrich the domain (VirusTotal, urlscan, passive DNS) and search which other endpoints queried it.",
        ],
        23 | 26 => vec![
            "Sysmon 23/26 (file deleted): check data_win_eventdata_targetFilename and image; deletion of dropped tools, logs or shadow copies right after execution indicates clean-up (T1070.004).",
        ],
        25 => vec![
            "Sysmon 25 (process tampering): the process image was replaced or altered in memory (process hollowing / herpaderping, T1055.012); treat as high suspicion and collect memory.",
        ],
        _ => return None,
    };
    Some(h)
}

fn windows_hints(event_id: u32) -> Option<Vec<&'static str>> {
    let h: Vec<&'static str> = match event_id {
        4624 => vec![
            "4624 (successful logon): check LogonType (3 network, 10 RemoteInteractive/RDP), data_win_eventdata_ipAddress, workstationName and authenticationPackageName; NTLM network logons from unusual sources suggest pass-the-hash.",
        ],
        4625 => vec![
            "4625 (failed logon): check data_win_eventdata_targetUserName, ipAddress, LogonType and status/subStatus (0xC000006A wrong password, 0xC0000064 unknown user, 0xC0000234 locked out).",
            "Many accounts from one source = password spraying; many attempts on one account = brute force; aggregate by source IP and account over the last 24h.",
        ],
        4648 => vec![
            "4648 (logon with explicit credentials): check subject vs target account and target server; runas/PsExec-style credential use for lateral movement.",
        ],
        4672 => vec![
            "4672 (special privileges assigned): expected for administrators; correlate with the preceding 4624 to see where the privileged logon came from.",
        ],
        4688 => vec![
            "4688 (process creation): analyse NewProcessName, ParentProcessName and CommandLine like Sysmon 1 (parent/child, path, encoded content).",
        ],
        4697 | 7045 => vec![
            "Service installed (4697/7045): check the service name and ImagePath; services pointing to user-writable paths, cmd/powershell command lines or random names indicate persistence or remote execution (PsExec-style).",
        ],
        4698 => vec![
            "4698 (scheduled task created): inspect the task XML (command, arguments, run-as user, triggers); tasks running from AppData/Temp/Public or launching script hosts are suspicious.",
        ],
        4720 => vec![
            "4720 (user account created): verify who created it (subjectUserName) and whether it matches a change ticket; check for immediate group additions (4728/4732/4756).",
        ],
        4728 | 4732 | 4756 => vec![
            "Group membership added (4728/4732/4756): check the group (Domain Admins, Administrators, Enterprise Admins) and the actor; unexpected privileged group changes are account manipulation (T1098).",
        ],
        4740 => vec![
            "4740 (account locked out): find the caller computer and correlate with 4625/4771 bursts to separate brute force from stale credentials.",
        ],
        4768 | 4769 | 4771 => vec![
            "Kerberos (4768/4769/4771): 4769 service tickets with TicketEncryptionType 0x17 (RC4) for service accounts suggest Kerberoasting; 4768 without pre-authentication suggests AS-REP roasting; 4771 bursts indicate password guessing.",
        ],
        4104 => vec![
            "4104 (PowerShell script block): read the ScriptBlockText; look for download cradles, AMSI bypasses, reflection/Assembly.Load and obfuscation (analyze_command_line works on script text too).",
        ],
        1102 => vec![
            "1102 (Security log cleared): log clearing is anti-forensics (T1070.001); identify the account and look for activity just before the clear on the same host.",
        ],
        5140 | 5145 => vec![
            "Share access (5140/5145): access to C$, ADMIN$ or IPC$ from workstations indicates lateral movement or remote execution (T1021.002).",
        ],
        _ => return None,
    };
    Some(h)
}

fn defender_hints(event_id: Option<u32>) -> Vec<&'static str> {
    let mut h = vec![
        "Microsoft Defender: check data_win_eventdata_fWLink (threat encyclopedia link), data_win_eventdata_path, threatName, severityName, processName and the action taken.",
        "Determine whether the threat was remediated (quarantined/removed) or only detected/allowed, and whether the file path is in a user profile, download or temp folder.",
    ];
    match event_id {
        Some(1116) => h.push("1116 = malware detected; look for the matching 1117 (action taken) or 1118/1119 (action failed)."),
        Some(1117) => h.push("1117 = action taken against malware; confirm the action succeeded and hunt for the initial infection vector."),
        Some(1118 | 1119) => h.push("1118/1119 = remediation failed; treat the host as actively infected."),
        Some(5001) => h.push("5001 = real-time protection disabled: defense evasion unless explained by change management (T1562.001)."),
        Some(5007) => h.push("5007 = Defender configuration changed: check for new exclusions (paths, processes, extensions) added by attackers."),
        Some(5010 | 5012) => h.push("5010/5012 = scanning disabled: defense evasion unless explained by change management."),
        _ => {}
    }
    h
}

fn group_hints(groups: &[String]) -> Vec<&'static str> {
    let mut h = Vec::new();
    let has = |pred: &dyn Fn(&str) -> bool| groups.iter().any(|g| pred(&g.to_ascii_lowercase()));
    if has(&|g| g == "windows_autoruns" || g == "autoruns") {
        h.push("Autoruns: check data_ImagePath and data_EntryLocation; unsigned entries, entries in user-writable paths, recently added entries and VirusTotal detections deserve scrutiny.");
    }
    if has(&|g| g == "windows_sigcheck" || g == "sigcheck") {
        h.push("Sigcheck: check data_Path and data_VTdetection; unsigned binaries or any VirusTotal positives on system paths are suspicious.");
    }
    if has(&|g| g.contains("authentication_fail") || g.contains("brute") || g == "invalid_login") {
        h.push("Authentication failures: aggregate by source IP and target account; distinguish password spraying (many accounts) from brute force (one account) and check for a subsequent success from the same source.");
    }
    if has(&|g| g == "syscheck" || g.starts_with("syscheck_")) {
        h.push("File integrity (syscheck): check syscheck.path, the before/after hashes, syscheck.diff and audit (whodata) fields to see who changed what; compare with maintenance windows.");
    }
    if has(&|g| g == "rootcheck") {
        h.push("Rootcheck: verify the reported anomaly (hidden process/port/file) manually; many rootcheck hits are benign configuration findings.");
    }
    if has(&|g| g.contains("vulnerability")) {
        h.push("Vulnerability finding: enrich the CVE with mcp__cve__lookup_cve, EPSS and CISA KEV status; prioritise internet-facing assets and KEV-listed CVEs.");
    }
    if has(&|g| {
        g == "web"
            || g == "accesslog"
            || g.contains("web_scan")
            || g.contains("sql_injection")
            || g == "attack"
    }) {
        h.push("Web alert: check the request URL, method, status code (2xx on an attack payload means it may have succeeded) and data_srcip; look for follow-up requests from the same source.");
    }
    if has(&|g| g == "sshd" || g == "ssh") {
        h.push("SSH: check data_srcip, the user and authentication method; a success after many failures from the same IP is a likely compromise.");
    }
    if has(&|g| g == "sudo") {
        h.push("sudo: check the invoking user, target user and command; privilege use outside administrators' normal patterns is suspicious.");
    }
    if has(&|g| g == "ids" || g == "suricata") {
        h.push("IDS alert: check the signature, direction (src/dst), payload excerpt and whether the internal host responded; enrich the external endpoint.");
    }
    if has(&|g| g == "virustotal") {
        h.push("VirusTotal integration alert: check data.virustotal.positives/total and the file path; confirm the detection names agree on a family before calling it malicious.");
    }
    if has(&|g| g == "yara") {
        h.push("YARA match: identify the rule name and matched file/process; validate that the rule is specific (not a generic packer rule).");
    }
    h
}

/// Investigation hints for an alert type, distilled from the CoPilot
/// prompt templates. Returns the matching template file(s) first, then
/// event-specific guidance, rule-group guidance and general next steps.
pub fn investigation_hints(rule_groups: &[String], event_id: Option<u32>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let groups_l: Vec<String> = rule_groups
        .iter()
        .map(|g| g.trim().to_ascii_lowercase())
        .collect();
    let is_sysmon = groups_l.iter().any(|g| g.contains("sysmon"));
    let is_defender = groups_l.iter().any(|g| g.contains("defender"));
    let is_security = groups_l
        .iter()
        .any(|g| g.contains("windows_security") || g.contains("authentication"));
    let event_id = event_id.or_else(|| {
        groups_l.iter().find_map(|g| {
            let rest = g.strip_prefix("sysmon_eid")?;
            rest.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .ok()
        })
    });

    let templates = template_candidates(rule_groups, event_id, None);
    if !templates.is_empty() {
        out.push(format!(
            "Investigation template: read /workspace/group/prompts/{} and follow its steps.",
            templates.join(" or prompts/")
        ));
    }

    if is_defender {
        out.extend(defender_hints(event_id).into_iter().map(String::from));
    } else if let Some(id) = event_id {
        let specific = if is_sysmon || (id <= 29 && !is_security) {
            sysmon_hints(id)
        } else {
            windows_hints(id)
        };
        if let Some(h) = specific {
            out.extend(h.into_iter().map(String::from));
        }
    }
    out.extend(group_hints(rule_groups).into_iter().map(String::from));

    out.push("MITRE techniques tagged on a rule are context, not proof: confirm them against the event fields before reporting a true positive.".to_string());
    out.push("Correlate: other alerts on the same agent within +/-1h, the same IOC on other agents, and persistence (registry, scheduled task, service) on the host (correlate_alerts helps).".to_string());
    out.push("Enrich only external indicators and hashes (extract_iocs marks them enrichable); internal IPs and host names stay internal.".to_string());

    let mut seen = std::collections::HashSet::new();
    out.retain(|h| seen.insert(h.clone()));
    out
}

/// Template file names matching an alert, per the CoPilot fallback rules:
/// a rule group equal to a template stem, then `sysmon_event_<id>.txt`,
/// then a template stem keyword in the rule description.
pub fn template_candidates(
    rule_groups: &[String],
    event_id: Option<u32>,
    rule_description: Option<&str>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |name: String| {
        if KNOWN_TEMPLATES.contains(&name.as_str()) && !out.contains(&name) {
            out.push(name);
        }
    };
    for g in rule_groups {
        add(format!("{}.txt", g.trim().to_ascii_lowercase()));
    }
    let is_defender = rule_groups
        .iter()
        .any(|g| g.to_ascii_lowercase().contains("defender"));
    if let Some(id) = event_id {
        if !is_defender {
            add(format!("sysmon_event_{id}.txt"));
        }
    }
    if let Some(desc) = rule_description {
        let d = desc.to_ascii_lowercase();
        for (kw, file) in [
            ("defender", "windows_defender.txt"),
            ("autoruns", "windows_autoruns.txt"),
            ("sigcheck", "windows_sigcheck.txt"),
        ] {
            if d.contains(kw) {
                add(file.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn sysmon_process_creation() {
        let h = investigation_hints(
            &s(&["sysmon", "sysmon_eid1_detections", "windows"]),
            Some(1),
        );
        assert!(h[0].contains("prompts/sysmon_event_1.txt"));
        assert!(
            h.iter()
                .any(|x| x.contains("data_win_eventdata_parentCommandLine"))
        );
        assert!(h.iter().any(|x| x.contains("Windows.System.Pslist")));
        assert!(h.iter().any(|x| x.contains("-enc")));
    }

    #[test]
    fn event_id_from_group_and_lsass_guidance() {
        let h = investigation_hints(&s(&["sysmon", "sysmon_eid10_detections"]), None);
        assert!(h[0].contains("sysmon_event_10.txt"));
        assert!(
            h.iter()
                .any(|x| x.contains("0x1fffff") && x.contains("T1003.001"))
        );
    }

    #[test]
    fn every_template_event_has_hints() {
        for t in KNOWN_TEMPLATES {
            if let Some(id) = t
                .strip_prefix("sysmon_event_")
                .and_then(|r| r.strip_suffix(".txt"))
                .and_then(|n| n.parse::<u32>().ok())
            {
                assert!(sysmon_hints(id).is_some(), "no hints for sysmon {id}");
                let h = investigation_hints(&s(&["sysmon"]), Some(id));
                assert!(h[0].contains(t), "{t}: {h:?}");
            }
        }
    }

    #[test]
    fn windows_security_and_defender() {
        let h = investigation_hints(
            &s(&["windows", "windows_security", "authentication_failed"]),
            Some(4625),
        );
        assert!(h.iter().any(|x| x.contains("0xC000006A")));
        assert!(h.iter().any(|x| x.contains("password spraying")));
        assert!(!h.iter().any(|x| x.contains("prompts/")), "{h:?}");

        let h = investigation_hints(&s(&["windows", "windows_defender"]), Some(5001));
        assert!(h[0].contains("windows_defender.txt"));
        assert!(h.iter().any(|x| x.contains("fWLink")));
        assert!(
            h.iter()
                .any(|x| x.contains("real-time protection disabled"))
        );
        assert!(!h.iter().any(|x| x.contains("sysmon_event_5001")));
    }

    #[test]
    fn unknown_alert_gets_generic_hints_only() {
        let h = investigation_hints(&s(&["ossec"]), None);
        assert_eq!(h.len(), 3);
        assert!(h.iter().all(|x| !x.contains("prompts/")));
    }

    #[test]
    fn template_fallback_selection() {
        assert_eq!(
            template_candidates(&s(&["windows_autoruns"]), None, None),
            vec!["windows_autoruns.txt"]
        );
        assert_eq!(
            template_candidates(&s(&["sysmon"]), Some(22), Some("Defender stuff")),
            vec!["sysmon_event_22.txt", "windows_defender.txt"]
        );
        assert!(template_candidates(&s(&["sysmon"]), Some(5), None).is_empty());
        assert_eq!(
            template_candidates(&[], None, Some("Sigcheck: unsigned binary")),
            vec!["windows_sigcheck.txt"]
        );
    }
}
