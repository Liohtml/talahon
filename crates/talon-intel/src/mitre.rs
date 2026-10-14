//! MITRE ATT&CK (Enterprise) knowledge: embedded technique table and
//! mappings from Wazuh `rule.mitre.id`, Sysmon / Windows event ids, Wazuh
//! `rule.groups`, alert field context and command-line heuristics.
//!
//! Every mapping carries a [`Confidence`] and a human-readable explanation so
//! the model (and the analyst) can see *why* a technique was suggested. Event
//! ids and rule groups only yield low/medium-confidence *candidates*; explicit
//! rule tags and unambiguous field evidence yield high confidence.

use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::alert::AlertFields;
use crate::cmdline::{self, CommandLineAnalysis, ProcessContext};
use crate::common::Confidence;

/// ATT&CK Enterprise tactics, in kill-chain order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tactic {
    /// TA0043
    Reconnaissance,
    /// TA0042
    ResourceDevelopment,
    /// TA0001
    InitialAccess,
    /// TA0002
    Execution,
    /// TA0003
    Persistence,
    /// TA0004
    PrivilegeEscalation,
    /// TA0005
    DefenseEvasion,
    /// TA0006
    CredentialAccess,
    /// TA0007
    Discovery,
    /// TA0008
    LateralMovement,
    /// TA0009
    Collection,
    /// TA0011
    CommandAndControl,
    /// TA0010
    Exfiltration,
    /// TA0040
    Impact,
}

impl Tactic {
    /// All tactics in kill-chain order.
    pub const ALL: [Tactic; 14] = [
        Tactic::Reconnaissance,
        Tactic::ResourceDevelopment,
        Tactic::InitialAccess,
        Tactic::Execution,
        Tactic::Persistence,
        Tactic::PrivilegeEscalation,
        Tactic::DefenseEvasion,
        Tactic::CredentialAccess,
        Tactic::Discovery,
        Tactic::LateralMovement,
        Tactic::Collection,
        Tactic::CommandAndControl,
        Tactic::Exfiltration,
        Tactic::Impact,
    ];

    /// ATT&CK tactic id (`TA0006`).
    pub fn id(self) -> &'static str {
        match self {
            Tactic::Reconnaissance => "TA0043",
            Tactic::ResourceDevelopment => "TA0042",
            Tactic::InitialAccess => "TA0001",
            Tactic::Execution => "TA0002",
            Tactic::Persistence => "TA0003",
            Tactic::PrivilegeEscalation => "TA0004",
            Tactic::DefenseEvasion => "TA0005",
            Tactic::CredentialAccess => "TA0006",
            Tactic::Discovery => "TA0007",
            Tactic::LateralMovement => "TA0008",
            Tactic::Collection => "TA0009",
            Tactic::CommandAndControl => "TA0011",
            Tactic::Exfiltration => "TA0010",
            Tactic::Impact => "TA0040",
        }
    }

    /// Display name as used by ATT&CK and Wazuh `rule.mitre.tactic`
    /// (`"Credential Access"`).
    pub fn name(self) -> &'static str {
        match self {
            Tactic::Reconnaissance => "Reconnaissance",
            Tactic::ResourceDevelopment => "Resource Development",
            Tactic::InitialAccess => "Initial Access",
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege Escalation",
            Tactic::DefenseEvasion => "Defense Evasion",
            Tactic::CredentialAccess => "Credential Access",
            Tactic::Discovery => "Discovery",
            Tactic::LateralMovement => "Lateral Movement",
            Tactic::Collection => "Collection",
            Tactic::CommandAndControl => "Command and Control",
            Tactic::Exfiltration => "Exfiltration",
            Tactic::Impact => "Impact",
        }
    }

    /// Parse a tactic name (any case, spaces / `-` / `_`), or id (`TA0005`).
    pub fn parse(s: &str) -> Option<Self> {
        let norm: String = s
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        Tactic::ALL.iter().copied().find(|t| {
            let n: String = t
                .name()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            n == norm || t.id().eq_ignore_ascii_case(s.trim())
        })
    }
}

impl fmt::Display for Tactic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Serialize for Tactic {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for Tactic {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Tactic::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown tactic {s:?}")))
    }
}

/// One ATT&CK technique or sub-technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Technique {
    /// `T1059` or `T1059.001`.
    pub id: &'static str,
    /// Official name (sub-techniques without the parent prefix).
    pub name: &'static str,
    /// Tactics the technique belongs to.
    pub tactics: &'static [Tactic],
}

impl Technique {
    /// Parent technique id (`T1059.001` → `T1059`).
    pub fn parent_id(&self) -> &'static str {
        parent_id(self.id)
    }

    /// `true` for sub-techniques.
    pub fn is_subtechnique(&self) -> bool {
        self.id.contains('.')
    }

    /// `"PowerShell"` → `"Command and Scripting Interpreter: PowerShell"`.
    pub fn full_name(&self) -> String {
        if self.is_subtechnique() {
            match technique(self.parent_id()) {
                Some(p) => format!("{}: {}", p.name, self.name),
                None => self.name.to_string(),
            }
        } else {
            self.name.to_string()
        }
    }
}

/// Parent part of a technique id.
pub fn parent_id(id: &str) -> &str {
    id.split('.').next().unwrap_or(id)
}

use Tactic::*;

const RECON: &[Tactic] = &[Reconnaissance];
const RESDEV: &[Tactic] = &[ResourceDevelopment];
const IA: &[Tactic] = &[InitialAccess];
const EXEC: &[Tactic] = &[Execution];
const PERS: &[Tactic] = &[Persistence];
const PE: &[Tactic] = &[PrivilegeEscalation];
const DE: &[Tactic] = &[DefenseEvasion];
const CA: &[Tactic] = &[CredentialAccess];
const DISC: &[Tactic] = &[Discovery];
const LM: &[Tactic] = &[LateralMovement];
const COLL: &[Tactic] = &[Collection];
const C2: &[Tactic] = &[CommandAndControl];
const EXFIL: &[Tactic] = &[Exfiltration];
const IMPACT: &[Tactic] = &[Impact];
const EXEC_PERS_PE: &[Tactic] = &[Execution, Persistence, PrivilegeEscalation];
const PERS_PE: &[Tactic] = &[Persistence, PrivilegeEscalation];
const PERS_PE_DE: &[Tactic] = &[Persistence, PrivilegeEscalation, DefenseEvasion];
const PE_DE: &[Tactic] = &[PrivilegeEscalation, DefenseEvasion];
const DE_PERS: &[Tactic] = &[DefenseEvasion, Persistence];
const VALID_ACCOUNTS: &[Tactic] = &[
    DefenseEvasion,
    Persistence,
    PrivilegeEscalation,
    InitialAccess,
];
const PERS_IA: &[Tactic] = &[Persistence, InitialAccess];
const CA_DE_PERS: &[Tactic] = &[CredentialAccess, DefenseEvasion, Persistence];
const DE_LM: &[Tactic] = &[DefenseEvasion, LateralMovement];
const DE_DISC: &[Tactic] = &[DefenseEvasion, Discovery];
const COLL_CA: &[Tactic] = &[Collection, CredentialAccess];
const CA_DISC: &[Tactic] = &[CredentialAccess, Discovery];
const EXEC_LM: &[Tactic] = &[Execution, LateralMovement];
const LM_IA: &[Tactic] = &[LateralMovement, InitialAccess];

const fn t(id: &'static str, name: &'static str, tactics: &'static [Tactic]) -> Technique {
    Technique { id, name, tactics }
}

/// Embedded technique table (common Enterprise techniques seen in SOC
/// alerting). Sub-techniques inherit their parent's tactics.
static TECHNIQUES: &[Technique] = &[
    // Reconnaissance / Resource Development
    t("T1595", "Active Scanning", RECON),
    t("T1595.001", "Scanning IP Blocks", RECON),
    t("T1595.002", "Vulnerability Scanning", RECON),
    t("T1592", "Gather Victim Host Information", RECON),
    t("T1589", "Gather Victim Identity Information", RECON),
    t("T1590", "Gather Victim Network Information", RECON),
    t("T1583", "Acquire Infrastructure", RESDEV),
    t("T1584", "Compromise Infrastructure", RESDEV),
    t("T1587", "Develop Capabilities", RESDEV),
    t("T1588", "Obtain Capabilities", RESDEV),
    t("T1608", "Stage Capabilities", RESDEV),
    // Initial Access
    t("T1566", "Phishing", IA),
    t("T1566.001", "Spearphishing Attachment", IA),
    t("T1566.002", "Spearphishing Link", IA),
    t("T1566.003", "Spearphishing via Service", IA),
    t("T1190", "Exploit Public-Facing Application", IA),
    t("T1133", "External Remote Services", PERS_IA),
    t("T1078", "Valid Accounts", VALID_ACCOUNTS),
    t("T1078.001", "Default Accounts", VALID_ACCOUNTS),
    t("T1078.002", "Domain Accounts", VALID_ACCOUNTS),
    t("T1078.003", "Local Accounts", VALID_ACCOUNTS),
    t("T1078.004", "Cloud Accounts", VALID_ACCOUNTS),
    t("T1189", "Drive-by Compromise", IA),
    t("T1195", "Supply Chain Compromise", IA),
    t("T1199", "Trusted Relationship", IA),
    t("T1200", "Hardware Additions", IA),
    t("T1091", "Replication Through Removable Media", LM_IA),
    // Execution
    t("T1059", "Command and Scripting Interpreter", EXEC),
    t("T1059.001", "PowerShell", EXEC),
    t("T1059.002", "AppleScript", EXEC),
    t("T1059.003", "Windows Command Shell", EXEC),
    t("T1059.004", "Unix Shell", EXEC),
    t("T1059.005", "Visual Basic", EXEC),
    t("T1059.006", "Python", EXEC),
    t("T1059.007", "JavaScript", EXEC),
    t("T1047", "Windows Management Instrumentation", EXEC),
    t("T1053", "Scheduled Task/Job", EXEC_PERS_PE),
    t("T1053.002", "At", EXEC_PERS_PE),
    t("T1053.003", "Cron", EXEC_PERS_PE),
    t("T1053.005", "Scheduled Task", EXEC_PERS_PE),
    t("T1569", "System Services", EXEC),
    t("T1569.002", "Service Execution", EXEC),
    t("T1204", "User Execution", EXEC),
    t("T1204.001", "Malicious Link", EXEC),
    t("T1204.002", "Malicious File", EXEC),
    t("T1203", "Exploitation for Client Execution", EXEC),
    t("T1106", "Native API", EXEC),
    t("T1559", "Inter-Process Communication", EXEC),
    t("T1559.001", "Component Object Model", EXEC),
    t("T1559.002", "Dynamic Data Exchange", EXEC),
    t("T1129", "Shared Modules", EXEC),
    t("T1072", "Software Deployment Tools", EXEC_LM),
    // Persistence
    t("T1547", "Boot or Logon Autostart Execution", PERS_PE),
    t("T1547.001", "Registry Run Keys / Startup Folder", PERS_PE),
    t("T1547.004", "Winlogon Helper DLL", PERS_PE),
    t("T1547.005", "Security Support Provider", PERS_PE),
    t("T1547.009", "Shortcut Modification", PERS_PE),
    t("T1543", "Create or Modify System Process", PERS_PE),
    t("T1543.002", "Systemd Service", PERS_PE),
    t("T1543.003", "Windows Service", PERS_PE),
    t("T1546", "Event Triggered Execution", PERS_PE),
    t("T1546.001", "Change Default File Association", PERS_PE),
    t(
        "T1546.003",
        "Windows Management Instrumentation Event Subscription",
        PERS_PE,
    ),
    t("T1546.007", "Netsh Helper DLL", PERS_PE),
    t("T1546.008", "Accessibility Features", PERS_PE),
    t("T1546.010", "AppInit DLLs", PERS_PE),
    t("T1546.011", "Application Shimming", PERS_PE),
    t(
        "T1546.012",
        "Image File Execution Options Injection",
        PERS_PE,
    ),
    t("T1546.013", "PowerShell Profile", PERS_PE),
    t("T1546.015", "Component Object Model Hijacking", PERS_PE),
    t("T1136", "Create Account", PERS),
    t("T1136.001", "Local Account", PERS),
    t("T1136.002", "Domain Account", PERS),
    t("T1098", "Account Manipulation", PERS_PE),
    t("T1098.004", "SSH Authorized Keys", PERS_PE),
    t("T1505", "Server Software Component", PERS),
    t("T1505.003", "Web Shell", PERS),
    t("T1574", "Hijack Execution Flow", PERS_PE_DE),
    t("T1037", "Boot or Logon Initialization Scripts", PERS_PE),
    t("T1037.001", "Logon Script (Windows)", PERS_PE),
    t("T1137", "Office Application Startup", PERS),
    t("T1197", "BITS Jobs", DE_PERS),
    t("T1556", "Modify Authentication Process", CA_DE_PERS),
    // Privilege Escalation
    t("T1548", "Abuse Elevation Control Mechanism", PE_DE),
    t("T1548.001", "Setuid and Setgid", PE_DE),
    t("T1548.002", "Bypass User Account Control", PE_DE),
    t("T1548.003", "Sudo and Sudo Caching", PE_DE),
    t("T1068", "Exploitation for Privilege Escalation", PE),
    t("T1055", "Process Injection", PE_DE),
    t("T1055.001", "Dynamic-link Library Injection", PE_DE),
    t("T1055.002", "Portable Executable Injection", PE_DE),
    t("T1055.003", "Thread Execution Hijacking", PE_DE),
    t("T1055.004", "Asynchronous Procedure Call", PE_DE),
    t("T1055.012", "Process Hollowing", PE_DE),
    t("T1134", "Access Token Manipulation", PE_DE),
    t("T1134.001", "Token Impersonation/Theft", PE_DE),
    t("T1484.001", "Group Policy Modification", PE_DE),
    // Defense Evasion
    t("T1027", "Obfuscated Files or Information", DE),
    t("T1027.002", "Software Packing", DE),
    t("T1027.010", "Command Obfuscation", DE),
    t("T1140", "Deobfuscate/Decode Files or Information", DE),
    t("T1070", "Indicator Removal", DE),
    t("T1070.001", "Clear Windows Event Logs", DE),
    t("T1070.003", "Clear Command History", DE),
    t("T1070.004", "File Deletion", DE),
    t("T1070.005", "Network Share Connection Removal", DE),
    t("T1070.006", "Timestomp", DE),
    t("T1562", "Impair Defenses", DE),
    t("T1562.001", "Disable or Modify Tools", DE),
    t("T1562.002", "Disable Windows Event Logging", DE),
    t("T1562.004", "Disable or Modify System Firewall", DE),
    t("T1562.006", "Indicator Blocking", DE),
    t("T1218", "System Binary Proxy Execution", DE),
    t("T1218.001", "Compiled HTML File", DE),
    t("T1218.002", "Control Panel", DE),
    t("T1218.003", "CMSTP", DE),
    t("T1218.004", "InstallUtil", DE),
    t("T1218.005", "Mshta", DE),
    t("T1218.007", "Msiexec", DE),
    t("T1218.008", "Odbcconf", DE),
    t("T1218.009", "Regsvcs/Regasm", DE),
    t("T1218.010", "Regsvr32", DE),
    t("T1218.011", "Rundll32", DE),
    t("T1218.012", "Verclsid", DE),
    t("T1218.013", "Mavinject", DE),
    t("T1218.014", "MMC", DE),
    t("T1216", "System Script Proxy Execution", DE),
    t("T1216.001", "PubPrn", DE),
    t("T1127", "Trusted Developer Utilities Proxy Execution", DE),
    t("T1127.001", "MSBuild", DE),
    t("T1202", "Indirect Command Execution", DE),
    t("T1220", "XSL Script Processing", DE),
    t("T1036", "Masquerading", DE),
    t("T1036.004", "Masquerade Task or Service", DE),
    t("T1036.007", "Double File Extension", DE),
    t("T1564", "Hide Artifacts", DE),
    t("T1564.001", "Hidden Files and Directories", DE),
    t("T1564.003", "Hidden Window", DE),
    t("T1564.004", "NTFS File Attributes", DE),
    t("T1222", "File and Directory Permissions Modification", DE),
    t(
        "T1222.001",
        "Windows File and Directory Permissions Modification",
        DE,
    ),
    t("T1112", "Modify Registry", DE),
    t("T1497", "Virtualization/Sandbox Evasion", DE_DISC),
    t("T1620", "Reflective Code Loading", DE),
    t("T1553", "Subvert Trust Controls", DE),
    t("T1553.004", "Install Root Certificate", DE),
    t("T1553.005", "Mark-of-the-Web Bypass", DE),
    t("T1014", "Rootkit", DE),
    t("T1006", "Direct Volume Access", DE),
    t("T1480", "Execution Guardrails", DE),
    t("T1211", "Exploitation for Defense Evasion", DE),
    t("T1207", "Rogue Domain Controller", DE),
    t("T1550", "Use Alternate Authentication Material", DE_LM),
    t("T1550.002", "Pass the Hash", DE_LM),
    t("T1550.003", "Pass the Ticket", DE_LM),
    // Credential Access
    t("T1003", "OS Credential Dumping", CA),
    t("T1003.001", "LSASS Memory", CA),
    t("T1003.002", "Security Account Manager", CA),
    t("T1003.003", "NTDS", CA),
    t("T1003.004", "LSA Secrets", CA),
    t("T1003.005", "Cached Domain Credentials", CA),
    t("T1003.006", "DCSync", CA),
    t("T1003.008", "/etc/passwd and /etc/shadow", CA),
    t("T1110", "Brute Force", CA),
    t("T1110.001", "Password Guessing", CA),
    t("T1110.002", "Password Cracking", CA),
    t("T1110.003", "Password Spraying", CA),
    t("T1110.004", "Credential Stuffing", CA),
    t("T1555", "Credentials from Password Stores", CA),
    t("T1555.003", "Credentials from Web Browsers", CA),
    t("T1555.004", "Windows Credential Manager", CA),
    t("T1558", "Steal or Forge Kerberos Tickets", CA),
    t("T1558.001", "Golden Ticket", CA),
    t("T1558.003", "Kerberoasting", CA),
    t("T1558.004", "AS-REP Roasting", CA),
    t("T1552", "Unsecured Credentials", CA),
    t("T1552.001", "Credentials In Files", CA),
    t("T1552.002", "Credentials in Registry", CA),
    t("T1552.004", "Private Keys", CA),
    t("T1056", "Input Capture", COLL_CA),
    t("T1056.001", "Keylogging", COLL_CA),
    t(
        "T1557",
        "Adversary-in-the-Middle",
        &[CredentialAccess, Collection],
    ),
    t(
        "T1557.001",
        "LLMNR/NBT-NS Poisoning and SMB Relay",
        &[CredentialAccess, Collection],
    ),
    t("T1212", "Exploitation for Credential Access", CA),
    t("T1539", "Steal Web Session Cookie", CA),
    t("T1040", "Network Sniffing", CA_DISC),
    t("T1187", "Forced Authentication", CA),
    // Discovery
    t("T1087", "Account Discovery", DISC),
    t("T1087.001", "Local Account", DISC),
    t("T1087.002", "Domain Account", DISC),
    t("T1069", "Permission Groups Discovery", DISC),
    t("T1069.001", "Local Groups", DISC),
    t("T1069.002", "Domain Groups", DISC),
    t("T1082", "System Information Discovery", DISC),
    t("T1083", "File and Directory Discovery", DISC),
    t("T1016", "System Network Configuration Discovery", DISC),
    t("T1049", "System Network Connections Discovery", DISC),
    t("T1033", "System Owner/User Discovery", DISC),
    t("T1057", "Process Discovery", DISC),
    t("T1018", "Remote System Discovery", DISC),
    t("T1135", "Network Share Discovery", DISC),
    t("T1046", "Network Service Discovery", DISC),
    t("T1482", "Domain Trust Discovery", DISC),
    t("T1012", "Query Registry", DISC),
    t("T1007", "System Service Discovery", DISC),
    t("T1518", "Software Discovery", DISC),
    t("T1518.001", "Security Software Discovery", DISC),
    t("T1124", "System Time Discovery", DISC),
    t("T1201", "Password Policy Discovery", DISC),
    t("T1614", "System Location Discovery", DISC),
    // Lateral Movement
    t("T1021", "Remote Services", LM),
    t("T1021.001", "Remote Desktop Protocol", LM),
    t("T1021.002", "SMB/Windows Admin Shares", LM),
    t("T1021.003", "Distributed Component Object Model", LM),
    t("T1021.004", "SSH", LM),
    t("T1021.006", "Windows Remote Management", LM),
    t("T1570", "Lateral Tool Transfer", LM),
    t("T1210", "Exploitation of Remote Services", LM),
    t("T1534", "Internal Spearphishing", LM),
    t("T1563", "Remote Service Session Hijacking", LM),
    t("T1563.002", "RDP Hijacking", LM),
    // Collection
    t("T1005", "Data from Local System", COLL),
    t("T1039", "Data from Network Shared Drive", COLL),
    t("T1560", "Archive Collected Data", COLL),
    t("T1560.001", "Archive via Utility", COLL),
    t("T1113", "Screen Capture", COLL),
    t("T1115", "Clipboard Data", COLL),
    t("T1114", "Email Collection", COLL),
    t("T1119", "Automated Collection", COLL),
    t("T1074", "Data Staged", COLL),
    t("T1074.001", "Local Data Staging", COLL),
    t("T1123", "Audio Capture", COLL),
    t("T1125", "Video Capture", COLL),
    // Command and Control
    t("T1071", "Application Layer Protocol", C2),
    t("T1071.001", "Web Protocols", C2),
    t("T1071.002", "File Transfer Protocols", C2),
    t("T1071.003", "Mail Protocols", C2),
    t("T1071.004", "DNS", C2),
    t("T1105", "Ingress Tool Transfer", C2),
    t("T1090", "Proxy", C2),
    t("T1090.003", "Multi-hop Proxy", C2),
    t("T1572", "Protocol Tunneling", C2),
    t("T1573", "Encrypted Channel", C2),
    t("T1571", "Non-Standard Port", C2),
    t("T1095", "Non-Application Layer Protocol", C2),
    t("T1568", "Dynamic Resolution", C2),
    t("T1568.002", "Domain Generation Algorithms", C2),
    t("T1102", "Web Service", C2),
    t("T1132", "Data Encoding", C2),
    t("T1001", "Data Obfuscation", C2),
    t("T1008", "Fallback Channels", C2),
    // Exfiltration
    t("T1041", "Exfiltration Over C2 Channel", EXFIL),
    t("T1048", "Exfiltration Over Alternative Protocol", EXFIL),
    t(
        "T1048.003",
        "Exfiltration Over Unencrypted Non-C2 Protocol",
        EXFIL,
    ),
    t("T1567", "Exfiltration Over Web Service", EXFIL),
    t("T1567.002", "Exfiltration to Cloud Storage", EXFIL),
    t("T1020", "Automated Exfiltration", EXFIL),
    t("T1029", "Scheduled Transfer", EXFIL),
    t("T1030", "Data Transfer Size Limits", EXFIL),
    t("T1052", "Exfiltration Over Physical Medium", EXFIL),
    // Impact
    t("T1486", "Data Encrypted for Impact", IMPACT),
    t("T1490", "Inhibit System Recovery", IMPACT),
    t("T1489", "Service Stop", IMPACT),
    t("T1485", "Data Destruction", IMPACT),
    t("T1529", "System Shutdown/Reboot", IMPACT),
    t("T1531", "Account Access Removal", IMPACT),
    t("T1491", "Defacement", IMPACT),
    t("T1496", "Resource Hijacking", IMPACT),
    t("T1498", "Network Denial of Service", IMPACT),
    t("T1499", "Endpoint Denial of Service", IMPACT),
    t("T1561", "Disk Wipe", IMPACT),
];

static INDEX: LazyLock<HashMap<&'static str, &'static Technique>> =
    LazyLock::new(|| TECHNIQUES.iter().map(|t| (t.id, t)).collect());

/// Look up a technique by id (case-insensitive, trimmed).
pub fn technique(id: &str) -> Option<&'static Technique> {
    let id = id.trim().to_ascii_uppercase();
    INDEX.get(id.as_str()).copied()
}

/// The embedded technique table.
pub fn techniques() -> &'static [Technique] {
    TECHNIQUES
}

/// `true` when `id` has the shape of a technique id (`T1234` / `T1234.001`).
pub fn is_technique_id(id: &str) -> bool {
    let b = id.as_bytes();
    let base_ok =
        b.len() >= 5 && (b[0] == b'T' || b[0] == b't') && b[1..5].iter().all(u8::is_ascii_digit);
    match b.len() {
        5 => base_ok,
        9 => base_ok && b[5] == b'.' && b[6..9].iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

/// Tactics of a technique id; falls back to the parent technique for
/// sub-techniques missing from the table.
pub fn tactics_for(id: &str) -> Vec<Tactic> {
    technique(id)
        .or_else(|| technique(parent_id(id)))
        .map(|t| t.tactics.to_vec())
        .unwrap_or_default()
}

/// Where a mapping came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingSource {
    /// Wazuh `rule.mitre.id` tag.
    WazuhRule,
    /// Sysmon / Windows event id.
    EventId,
    /// Wazuh `rule.groups`.
    RuleGroup,
    /// Specific alert field content (target image, registry key, ...).
    Field,
    /// Command-line / process-tree heuristics.
    CommandLine,
}

/// A suggested technique for an alert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MitreMapping {
    /// Technique id.
    pub technique_id: String,
    /// Technique name (`None` when not in the embedded table).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tactics of the technique.
    pub tactics: Vec<Tactic>,
    /// Highest confidence among the merged sources.
    pub confidence: Confidence,
    /// Distinct sources.
    pub sources: Vec<MappingSource>,
    /// Why the technique was suggested.
    pub explanations: Vec<String>,
}

impl MitreMapping {
    fn new(
        id: &str,
        confidence: Confidence,
        source: MappingSource,
        why: impl Into<String>,
    ) -> Self {
        let id = id.trim().to_ascii_uppercase();
        let tech = technique(&id);
        MitreMapping {
            name: tech.map(|t| t.full_name()),
            tactics: tactics_for(&id),
            technique_id: id,
            confidence,
            sources: vec![source],
            explanations: vec![why.into()],
        }
    }
}

/// Merge mappings by technique id (max confidence, union of sources and
/// explanations) and sort by confidence, kill-chain order, then id.
pub fn merge_mappings(items: Vec<MitreMapping>) -> Vec<MitreMapping> {
    let mut out: Vec<MitreMapping> = Vec::new();
    for m in items {
        if let Some(existing) = out.iter_mut().find(|e| e.technique_id == m.technique_id) {
            existing.confidence = existing.confidence.max(m.confidence);
            for s in m.sources {
                if !existing.sources.contains(&s) {
                    existing.sources.push(s);
                }
            }
            for e in m.explanations {
                if !existing.explanations.contains(&e) && existing.explanations.len() < 6 {
                    existing.explanations.push(e);
                }
            }
        } else {
            out.push(m);
        }
    }
    out.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.tactics.first().cmp(&b.tactics.first()))
            .then_with(|| a.technique_id.cmp(&b.technique_id))
    });
    out
}

/// Mappings for explicit Wazuh `rule.mitre.id` tags (high confidence).
pub fn map_rule_ids(ids: &[String]) -> Vec<MitreMapping> {
    ids.iter()
        .filter(|id| is_technique_id(id.trim()))
        .map(|id| {
            let known = technique(id).is_some();
            MitreMapping::new(
                id,
                Confidence::High,
                MappingSource::WazuhRule,
                if known {
                    "tagged on the Wazuh rule that fired".to_string()
                } else {
                    "tagged on the Wazuh rule that fired (not in the embedded table; look it up)"
                        .to_string()
                },
            )
        })
        .collect()
}

/// Kind of Windows event source, used to disambiguate event ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    /// `Microsoft-Windows-Sysmon/Operational`.
    Sysmon,
    /// Security / System / PowerShell channels.
    Windows,
    /// Microsoft Defender Antivirus.
    Defender,
}

struct EventMap {
    id: u32,
    technique: &'static str,
    confidence: Confidence,
    why: &'static str,
}

const fn em(
    id: u32,
    technique: &'static str,
    confidence: Confidence,
    why: &'static str,
) -> EventMap {
    EventMap {
        id,
        technique,
        confidence,
        why,
    }
}

use crate::common::Confidence::{High as H, Low as L, Medium as M};

static SYSMON_EVENTS: &[EventMap] = &[
    em(
        1,
        "T1059",
        L,
        "Sysmon 1 process creation: command interpreters are the most common execution vector; confirm from the command line",
    ),
    em(
        2,
        "T1070.006",
        M,
        "Sysmon 2 file creation time changed: timestomping hides when a file was dropped",
    ),
    em(
        3,
        "T1071",
        L,
        "Sysmon 3 network connection: candidate C2 over an application-layer protocol; check destination and process",
    ),
    em(
        6,
        "T1014",
        L,
        "Sysmon 6 driver loaded: unsigned or unusual drivers may be rootkits",
    ),
    em(
        6,
        "T1068",
        L,
        "Sysmon 6 driver loaded: vulnerable signed drivers are loaded for privilege escalation (BYOVD)",
    ),
    em(
        7,
        "T1574",
        L,
        "Sysmon 7 image loaded: unsigned/unexpected DLLs loaded by trusted binaries suggest DLL hijacking or side-loading",
    ),
    em(
        8,
        "T1055",
        M,
        "Sysmon 8 CreateRemoteThread: thread creation in another process is a classic injection primitive",
    ),
    em(
        9,
        "T1006",
        M,
        "Sysmon 9 raw access read: direct volume reads bypass file-system access controls (e.g. NTDS/SAM theft)",
    ),
    em(
        10,
        "T1003.001",
        L,
        "Sysmon 10 process access: handles opened to lsass.exe are used for credential dumping",
    ),
    em(
        11,
        "T1105",
        L,
        "Sysmon 11 file created: dropped executables/scripts may be ingress tool transfer",
    ),
    em(12, "T1112", L, "Sysmon 12 registry object added/deleted"),
    em(13, "T1112", L, "Sysmon 13 registry value set"),
    em(14, "T1112", L, "Sysmon 14 registry key/value renamed"),
    em(
        15,
        "T1564.004",
        L,
        "Sysmon 15 alternate data stream created: ADS can hide payloads (Zone.Identifier streams are benign MOTW)",
    ),
    em(
        16,
        "T1562.001",
        M,
        "Sysmon 16 Sysmon configuration changed: attackers modify or blind monitoring tools",
    ),
    em(
        17,
        "T1559",
        L,
        "Sysmon 17 named pipe created: pipes are used for IPC by C2 frameworks",
    ),
    em(18, "T1559", L, "Sysmon 18 named pipe connected"),
    em(
        19,
        "T1546.003",
        H,
        "Sysmon 19 WMI event filter registered: WMI event subscription persistence",
    ),
    em(
        20,
        "T1546.003",
        H,
        "Sysmon 20 WMI event consumer registered: WMI event subscription persistence",
    ),
    em(
        21,
        "T1546.003",
        H,
        "Sysmon 21 WMI consumer bound to filter: WMI event subscription persistence",
    ),
    em(
        22,
        "T1071.004",
        L,
        "Sysmon 22 DNS query: candidate DNS-based C2 / beaconing; check the queried domain and process",
    ),
    em(
        23,
        "T1070.004",
        L,
        "Sysmon 23 file deleted (archived): deletion of tools or evidence",
    ),
    em(24, "T1115", L, "Sysmon 24 clipboard changed"),
    em(
        25,
        "T1055.012",
        M,
        "Sysmon 25 process tampering: image replaced in memory (process hollowing / herpaderping)",
    ),
    em(
        26,
        "T1070.004",
        L,
        "Sysmon 26 file deleted: deletion of tools or evidence",
    ),
];

static WINDOWS_EVENTS: &[EventMap] = &[
    em(
        4625,
        "T1110",
        L,
        "4625 failed logon: bursts across accounts or from one source indicate brute force / password spraying",
    ),
    em(
        4771,
        "T1110",
        L,
        "4771 Kerberos pre-authentication failed: repeated failures indicate password guessing",
    ),
    em(
        4740,
        "T1110",
        L,
        "4740 account locked out: often the result of password guessing",
    ),
    em(
        4648,
        "T1078",
        L,
        "4648 logon with explicit credentials: check for credential misuse / runas lateral movement",
    ),
    em(4720, "T1136", M, "4720 user account created"),
    em(
        4728,
        "T1098",
        M,
        "4728 member added to a security-enabled global group",
    ),
    em(
        4732,
        "T1098",
        M,
        "4732 member added to a security-enabled local group",
    ),
    em(
        4756,
        "T1098",
        M,
        "4756 member added to a security-enabled universal group",
    ),
    em(
        1102,
        "T1070.001",
        H,
        "1102 the Security audit log was cleared",
    ),
    em(4698, "T1053.005", M, "4698 scheduled task created"),
    em(
        4697,
        "T1543.003",
        M,
        "4697 service installed (Security log)",
    ),
    em(
        7045,
        "T1543.003",
        M,
        "7045 new service installed (System log)",
    ),
    em(
        4769,
        "T1558.003",
        L,
        "4769 Kerberos service ticket requested: RC4 (0x17) tickets for service accounts suggest Kerberoasting",
    ),
    em(4104, "T1059.001", M, "4104 PowerShell script block logged"),
    em(
        4103,
        "T1059.001",
        L,
        "4103 PowerShell module/pipeline execution logged",
    ),
    em(
        4688,
        "T1059",
        L,
        "4688 process creation (Security log): confirm from the command line",
    ),
    em(
        5140,
        "T1021.002",
        L,
        "5140 network share accessed: admin shares (C$, ADMIN$) are used for lateral movement",
    ),
    em(
        5145,
        "T1021.002",
        L,
        "5145 network share object checked: admin-share access for lateral movement",
    ),
];

static DEFENDER_EVENTS: &[EventMap] = &[
    em(
        5001,
        "T1562.001",
        H,
        "Defender 5001 real-time protection disabled",
    ),
    em(
        5007,
        "T1562.001",
        L,
        "Defender 5007 configuration changed: check for new exclusions or disabled features",
    ),
    em(
        5010,
        "T1562.001",
        M,
        "Defender 5010 scanning for malware/spyware disabled",
    ),
    em(
        5012,
        "T1562.001",
        M,
        "Defender 5012 scanning for viruses disabled",
    ),
];

/// Candidate techniques for an event id from the given source.
pub fn map_event_id(event_id: u32, source: EventSource) -> Vec<MitreMapping> {
    let table = match source {
        EventSource::Sysmon => SYSMON_EVENTS,
        EventSource::Windows => WINDOWS_EVENTS,
        EventSource::Defender => DEFENDER_EVENTS,
    };
    table
        .iter()
        .filter(|e| e.id == event_id)
        .map(|e| MitreMapping::new(e.technique, e.confidence, MappingSource::EventId, e.why))
        .collect()
}

struct GroupMap {
    /// Exact group name, or substring when prefixed with `~`.
    pattern: &'static str,
    technique: &'static str,
    confidence: Confidence,
    why: &'static str,
}

const fn gm(
    pattern: &'static str,
    technique: &'static str,
    confidence: Confidence,
    why: &'static str,
) -> GroupMap {
    GroupMap {
        pattern,
        technique,
        confidence,
        why,
    }
}

static GROUPS: &[GroupMap] = &[
    gm(
        "authentication_failures",
        "T1110",
        M,
        "rule group authentication_failures: multiple failed logins",
    ),
    gm("~brute", "T1110", M, "rule group indicates brute force"),
    gm(
        "authentication_failed",
        "T1110",
        L,
        "rule group authentication_failed: single failures only matter in volume",
    ),
    gm("invalid_login", "T1110", L, "rule group invalid_login"),
    gm(
        "web_scan",
        "T1595",
        M,
        "rule group web_scan: automated scanning of a web service",
    ),
    gm("recon", "T1595", L, "rule group recon"),
    gm(
        "sql_injection",
        "T1190",
        M,
        "rule group sql_injection: exploitation attempt against a public-facing app",
    ),
    gm("~shellshock", "T1190", M, "Shellshock exploitation attempt"),
    gm("exploit_attempt", "T1190", L, "rule group exploit_attempt"),
    gm(
        "rootcheck",
        "T1014",
        L,
        "rule group rootcheck: rootkit / anomaly detection",
    ),
    gm(
        "adduser",
        "T1136",
        M,
        "rule group adduser: account creation",
    ),
    gm("account_changed", "T1098", L, "rule group account_changed"),
    gm(
        "group_changed",
        "T1098",
        L,
        "rule group group_changed: group membership modified",
    ),
    gm(
        "sudo",
        "T1548.003",
        L,
        "rule group sudo: privilege elevation via sudo",
    ),
    gm("powershell", "T1059.001", L, "rule group powershell"),
    gm("wmi", "T1047", L, "rule group wmi"),
    gm("rdp", "T1021.001", L, "rule group rdp"),
];

/// Candidate techniques for Wazuh `rule.groups`.
pub fn map_rule_groups(groups: &[String]) -> Vec<MitreMapping> {
    let mut out = Vec::new();
    for g in groups {
        let g = g.trim().to_ascii_lowercase();
        for m in GROUPS {
            let hit = match m.pattern.strip_prefix('~') {
                Some(sub) => g.contains(sub),
                None => g == m.pattern,
            };
            if hit {
                out.push(MitreMapping::new(
                    m.technique,
                    m.confidence,
                    MappingSource::RuleGroup,
                    m.why,
                ));
            }
        }
    }
    out
}

/// Techniques implied by command-line / process-tree findings.
pub fn map_command_line_analysis(a: &CommandLineAnalysis) -> Vec<MitreMapping> {
    let mut out = Vec::new();
    for f in &a.findings {
        let conf = if f.weight >= 60 {
            Confidence::High
        } else if f.weight >= 30 {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        for t in &f.techniques {
            out.push(MitreMapping::new(
                t,
                conf,
                MappingSource::CommandLine,
                format!(
                    "{}: {}",
                    f.title,
                    crate::common::truncate_chars(&f.evidence, 120)
                ),
            ));
        }
    }
    out
}

/// Techniques implied by a command line alone.
pub fn map_command_line(cmd: &str) -> Vec<MitreMapping> {
    merge_mappings(map_command_line_analysis(&cmdline::analyze_command_line(
        cmd,
    )))
}

fn contains_ci(hay: &Option<String>, needles: &[&str]) -> bool {
    hay.as_deref().is_some_and(|h| {
        let h = h.to_ascii_lowercase();
        needles.iter().any(|n| h.contains(n))
    })
}

/// Field-level evidence (high/medium confidence) for specific event types.
fn map_fields(f: &AlertFields, event: Option<u32>, sysmon: bool) -> Vec<MitreMapping> {
    let mut out = Vec::new();
    let field = MappingSource::Field;
    let ev = if sysmon { event } else { None };
    if ev == Some(10) && contains_ci(&f.target_image, &["\\lsass.exe"]) {
        out.push(MitreMapping::new(
            "T1003.001",
            Confidence::High,
            field,
            format!(
                "process {} opened a handle to lsass.exe (GrantedAccess {})",
                f.source_image.as_deref().unwrap_or("?"),
                f.granted_access.as_deref().unwrap_or("?")
            ),
        ));
    }
    if matches!(ev, Some(12..=14)) || f.target_object.is_some() {
        let obj = &f.target_object;
        if contains_ci(obj, &["\\currentversion\\run", "\\policies\\explorer\\run"]) {
            out.push(MitreMapping::new(
                "T1547.001",
                Confidence::High,
                field,
                "registry Run/RunOnce autostart key modified",
            ));
        }
        if contains_ci(obj, &["\\image file execution options\\"]) {
            out.push(MitreMapping::new(
                "T1546.012",
                Confidence::High,
                field,
                "Image File Execution Options key modified (debugger/global flag hijack)",
            ));
        }
        if contains_ci(
            obj,
            &[
                "\\winlogon\\userinit",
                "\\winlogon\\shell",
                "\\winlogon\\notify",
            ],
        ) {
            out.push(MitreMapping::new(
                "T1547.004",
                Confidence::High,
                field,
                "Winlogon Userinit/Shell/Notify value modified",
            ));
        }
        if contains_ci(obj, &["\\system\\currentcontrolset\\services\\"])
            && contains_ci(obj, &["imagepath", "servicedll"])
        {
            out.push(MitreMapping::new(
                "T1543.003",
                Confidence::Medium,
                field,
                "service ImagePath/ServiceDll modified",
            ));
        }
        if contains_ci(obj, &["\\appinit_dlls"]) {
            out.push(MitreMapping::new(
                "T1546.010",
                Confidence::High,
                field,
                "AppInit_DLLs value modified",
            ));
        }
        if contains_ci(
            obj,
            &["\\windows defender\\", "\\microsoft\\windows defender"],
        ) && contains_ci(obj, &["disable", "exclusions"])
        {
            out.push(MitreMapping::new(
                "T1562.001",
                Confidence::High,
                field,
                "Microsoft Defender policy / exclusions modified via registry",
            ));
        }
        if contains_ci(obj, &["\\inprocserver32"])
            && contains_ci(obj, &["hkcu\\", "hku\\", "\\software\\classes\\clsid"])
        {
            out.push(MitreMapping::new(
                "T1546.015",
                Confidence::Medium,
                field,
                "per-user COM InprocServer32 registration (COM hijacking)",
            ));
        }
        if contains_ci(
            obj,
            &[
                "\\control\\lsa\\security packages",
                "\\control\\lsa\\authentication packages",
            ],
        ) {
            out.push(MitreMapping::new(
                "T1547.005",
                Confidence::High,
                field,
                "LSA security/authentication package list modified",
            ));
        }
    }
    if ev == Some(11) || f.target_filename.is_some() {
        if contains_ci(&f.target_filename, &["\\start menu\\programs\\startup\\"]) {
            out.push(MitreMapping::new(
                "T1547.001",
                Confidence::High,
                field,
                "file written to a Startup folder",
            ));
        }
        if contains_ci(&f.target_filename, &["\\windows\\system32\\tasks\\"]) {
            out.push(MitreMapping::new(
                "T1053.005",
                Confidence::Medium,
                field,
                "scheduled task definition file written",
            ));
        }
    }
    if ev == Some(15) && contains_ci(&f.target_filename, &[":zone.identifier"]) {
        out.push(MitreMapping::new(
            "T1105",
            Confidence::Low,
            field,
            "Zone.Identifier stream: file downloaded from the Internet (mark of the web)",
        ));
    }
    if ev == Some(8) {
        out.push(MitreMapping::new(
            "T1055",
            Confidence::Medium,
            field,
            format!(
                "{} created a thread in {}",
                f.source_image.as_deref().unwrap_or("?"),
                f.target_image.as_deref().unwrap_or("?")
            ),
        ));
    }
    if matches!(ev, Some(6 | 7))
        && (contains_ci(&f.signed, &["false"])
            || contains_ci(
                &f.signature_status,
                &["unavailable", "expired", "revoked", "invalid"],
            ))
    {
        let id = if ev == Some(6) { "T1014" } else { "T1574" };
        out.push(MitreMapping::new(
            id,
            Confidence::Medium,
            field,
            format!(
                "unsigned or invalidly signed module loaded: {}",
                f.image_loaded.as_deref().unwrap_or("?")
            ),
        ));
    }
    if matches!(ev, Some(17 | 18)) {
        if let Some(p) = &f.pipe_name {
            let l = p.to_ascii_lowercase();
            let cs = ["\\msagent_", "\\postex_", "\\status_"];
            if cs.iter().any(|n| l.contains(n)) || (l.contains("\\msse-") && l.ends_with("-server"))
            {
                out.push(MitreMapping::new(
                    "T1071",
                    Confidence::Medium,
                    field,
                    format!("named pipe {p} matches a default Cobalt Strike pipe pattern"),
                ));
            }
            if l.contains("psexesvc") {
                out.push(MitreMapping::new(
                    "T1569.002",
                    Confidence::Medium,
                    field,
                    "PsExec service pipe (PSEXESVC)",
                ));
            }
        }
    }
    out
}

/// All mappings for an alert: rule tags, event id, rule groups, field
/// evidence and process / command-line heuristics, merged and sorted.
pub fn map_alert(fields: &AlertFields) -> Vec<MitreMapping> {
    let mut all = map_rule_ids(&fields.mitre_ids);
    let sysmon = fields.is_sysmon();
    let event = fields.effective_event_id();
    if let Some(id) = event {
        let source = if fields.is_defender() {
            EventSource::Defender
        } else if sysmon
            || (id <= 29
                && !fields
                    .rule_groups
                    .iter()
                    .any(|g| g.contains("windows_security")))
        {
            EventSource::Sysmon
        } else {
            EventSource::Windows
        };
        all.extend(map_event_id(id, source));
    }
    all.extend(map_rule_groups(&fields.rule_groups));
    all.extend(map_fields(
        fields,
        event,
        sysmon || event.is_some_and(|e| e <= 29),
    ));
    if fields.command_line.is_some() || fields.image.is_some() {
        let a = cmdline::analyze_process(&ProcessContext::from_fields(fields));
        all.extend(map_command_line_analysis(&a));
    }
    merge_mappings(all)
}

/// Distinct tactics covered by a set of mappings, in kill-chain order.
pub fn tactics_of(mappings: &[MitreMapping]) -> Vec<Tactic> {
    let mut v: Vec<Tactic> = mappings
        .iter()
        .flat_map(|m| m.tactics.iter().copied())
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

    #[test]
    fn table_is_well_formed() {
        let mut seen = HashSet::new();
        for t in TECHNIQUES {
            assert!(is_technique_id(t.id), "bad id {}", t.id);
            assert!(seen.insert(t.id), "duplicate {}", t.id);
            assert!(!t.name.is_empty());
            assert!(!t.tactics.is_empty(), "{} has no tactic", t.id);
            if t.is_subtechnique() {
                // Sub-techniques inherit their parent's tactics.
                if let Some(p) = technique(t.parent_id()) {
                    assert_eq!(p.tactics, t.tactics, "{} tactics differ from parent", t.id);
                }
            }
        }
        assert!(TECHNIQUES.len() >= 200, "{}", TECHNIQUES.len());
    }

    #[test]
    fn well_known_entries() {
        let check = |id: &str, name: &str, tactic: Tactic| {
            let t = technique(id).unwrap_or_else(|| panic!("{id} missing"));
            assert_eq!(t.name, name);
            assert!(t.tactics.contains(&tactic), "{id}");
        };
        check("T1059.001", "PowerShell", Execution);
        check("T1003.001", "LSASS Memory", CredentialAccess);
        check(
            "T1547.001",
            "Registry Run Keys / Startup Folder",
            Persistence,
        );
        check("T1053.005", "Scheduled Task", PrivilegeEscalation);
        check("T1218.011", "Rundll32", DefenseEvasion);
        check("T1490", "Inhibit System Recovery", Impact);
        check("T1071.004", "DNS", CommandAndControl);
        check("T1078", "Valid Accounts", InitialAccess);
        check("t1105", "Ingress Tool Transfer", CommandAndControl);
        assert_eq!(
            technique("T1059.001").map(|t| t.full_name()),
            Some("Command and Scripting Interpreter: PowerShell".to_string())
        );
        assert!(technique("T9999").is_none());
        assert_eq!(tactics_for("T1059.999"), vec![Execution]);
    }

    #[test]
    fn tactic_parse_and_serde() {
        assert_eq!(Tactic::parse("Credential Access"), Some(CredentialAccess));
        assert_eq!(
            Tactic::parse("command-and-control"),
            Some(CommandAndControl)
        );
        assert_eq!(Tactic::parse("TA0005"), Some(DefenseEvasion));
        assert_eq!(Tactic::parse("defense_evasion"), Some(DefenseEvasion));
        assert_eq!(Tactic::parse("nope"), None);
        assert_eq!(
            serde_json::to_value(LateralMovement).unwrap(),
            json!("Lateral Movement")
        );
        let t: Tactic = serde_json::from_value(json!("privilege escalation")).unwrap();
        assert_eq!(t, PrivilegeEscalation);
        assert!(Reconnaissance < Impact);
    }

    #[test]
    fn id_shape() {
        assert!(is_technique_id("T1059"));
        assert!(is_technique_id("T1059.001"));
        assert!(!is_technique_id("T105"));
        assert!(!is_technique_id("T1059.01"));
        assert!(!is_technique_id("X1059"));
    }

    #[test]
    fn lsass_access_maps_high() {
        let alert = json!({
            "rule": {"level": 12, "groups": ["sysmon", "sysmon_eid10_detections"], "mitre": {"id": ["T1003.001"]}},
            "data": {"win": {"system": {"eventID": "10", "channel": "Microsoft-Windows-Sysmon/Operational"},
                     "eventdata": {"sourceImage": "C:\\Users\\bob\\Desktop\\procdump64.exe",
                                   "targetImage": "C:\\Windows\\system32\\lsass.exe",
                                   "grantedAccess": "0x1fffff"}}}
        });
        let m = map_alert(&AlertFields::from_json(&alert));
        let top = &m[0];
        assert_eq!(top.technique_id, "T1003.001");
        assert_eq!(top.confidence, Confidence::High);
        assert!(top.sources.contains(&MappingSource::WazuhRule));
        assert!(top.sources.contains(&MappingSource::Field));
        assert!(top.sources.contains(&MappingSource::EventId));
    }

    #[test]
    fn registry_run_key_and_windows_events() {
        let alert = json!({
            "rule_groups": "sysmon,sysmon_eid13_detections",
            "data_win_system_eventID": "13",
            "data_win_eventdata_targetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "data_win_eventdata_details": "C:\\Users\\Public\\upd.exe"
        });
        let m = map_alert(&AlertFields::from_json(&alert));
        assert!(
            m.iter()
                .any(|x| x.technique_id == "T1547.001" && x.confidence == Confidence::High)
        );
        assert!(m.iter().any(|x| x.technique_id == "T1112"));

        let sec = json!({"rule": {"groups": ["windows", "windows_security"]},
                         "data": {"win": {"system": {"eventID": "1102"}}}});
        let m = map_alert(&AlertFields::from_json(&sec));
        assert_eq!(m[0].technique_id, "T1070.001");
        let def = json!({"rule": {"groups": ["windows", "windows_defender"]},
                         "data": {"win": {"system": {"eventID": "5001"}}}});
        let m = map_alert(&AlertFields::from_json(&def));
        assert_eq!(m[0].technique_id, "T1562.001");
    }

    #[test]
    fn rule_groups_and_unknown_rule_ids() {
        let m = map_rule_groups(&["sshd".into(), "authentication_failures".into()]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].technique_id, "T1110");
        let m = map_rule_ids(&["T1659".into(), "bogus".into()]);
        assert_eq!(m.len(), 1);
        assert!(m[0].name.is_none());
        assert!(m[0].explanations[0].contains("not in the embedded table"));
    }

    #[test]
    fn command_line_mapping_and_merge() {
        let m = map_command_line("vssadmin.exe delete shadows /all /quiet");
        assert_eq!(m[0].technique_id, "T1490");
        assert_eq!(m[0].confidence, Confidence::High);
        let merged = merge_mappings(vec![
            MitreMapping::new("T1105", Confidence::Low, MappingSource::EventId, "a"),
            MitreMapping::new("T1105", Confidence::High, MappingSource::CommandLine, "b"),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].confidence, Confidence::High);
        assert_eq!(merged[0].sources.len(), 2);
        assert_eq!(tactics_of(&merged), vec![CommandAndControl]);
    }

    #[test]
    fn cobalt_strike_pipe() {
        let alert = json!({"rule": {"groups": ["sysmon", "sysmon_eid17_detections"]},
            "data": {"win": {"system": {"eventID": "17"}, "eventdata": {"pipeName": "\\postex_8b2c", "image": "C:\\Windows\\System32\\rundll32.exe"}}}});
        let m = map_alert(&AlertFields::from_json(&alert));
        assert!(
            m.iter()
                .any(|x| x.technique_id == "T1071" && x.confidence == Confidence::Medium)
        );
    }
}
