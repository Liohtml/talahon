//! Step `egress` (new, MYTH-05): firewall rules that contain the network
//! traffic of the agent containers.
//!
//! ```text
//! talon setup egress [--apply] [--uninstall] [--allow <cidr[:port]>]...
//!                    [--keep-internet] [--gateway-port N] [--nft|--iptables]
//! ```
//!
//! Agent containers run on the dedicated docker network [`AGENT_NETWORK`]
//! (Linux bridge [`AGENT_BRIDGE`], inter-container communication disabled),
//! which the host creates at startup. Docker itself lets those containers
//! reach everything the host can route to: cloud metadata endpoints,
//! internal services, vLLM without going through the gateway, and every
//! service listening on the host. This step generates a reviewed firewall
//! script for the bridge and prints it (script, then the `SETUP_EGRESS`
//! block). With `--apply` and root it installs the rules; without root it
//! says how to.
//!
//! Rules for traffic entering from the bridge:
//!
//! 1. **Forwarded traffic** (iptables: chain [`EGRESS_CHAIN`] jumped to
//!    from `DOCKER-USER`; nftables: table `inet talon_egress`, forward
//!    hook): link-local destinations ([`METADATA_DESTINATIONS`]: the cloud
//!    metadata service `169.254.169.254`, `169.254.0.0/16`, `fe80::/10`,
//!    AWS's `fd00:ec2::254`) are always dropped; established/related
//!    traffic and the `--allow` destinations pass; then
//!    - **allowlist mode** (the default when `--allow` is given): everything
//!      else is dropped — agents reach only the listed destinations and the
//!      LLM gateway;
//!    - **block-private mode** (no `--allow`, or `--keep-internet`):
//!      private destinations ([`PRIVATE_DESTINATIONS`]: RFC 1918, CGNAT,
//!      ULA) are dropped and internet egress is kept.
//!
//!    Trade-off: the MCP servers inside the container query the SIEM
//!    (OpenSearch), MySQL, Wazuh and CoPilot, which normally live on
//!    private addresses. Both modes block them unless the operator lists
//!    them with `--allow <ip>[/len][:port]`. The same holds for the upstream
//!    DNS servers Docker's embedded resolver forwards to from the container
//!    namespace (reported as `BLOCKED_DNS_RESOLVERS`; allow them with
//!    `--allow <ip>:53`).
//! 2. **Traffic to the host** (iptables: chain [`INPUT_CHAIN`] jumped to
//!    from `INPUT`; nftables: input hook): only established/related
//!    traffic, the LLM gateway port (tcp, default 3001) and IPv6 neighbour
//!    discovery pass. Everything else — the HTTP API, vLLM on the host,
//!    SSH, databases — is dropped.
//!
//! "Pass" never means "accepted past Docker's own rules": the iptables
//! chain `RETURN`s, so Docker's network isolation and ICC rules still apply,
//! and an nftables `accept` in a separate table does not skip other tables'
//! chains (while a `drop` is final).
//!
//! Re-running is idempotent: the nftables table is replaced atomically in
//! one transaction; the iptables chains are flushed and rebuilt behind a
//! temporary DROP for the bridge (fail closed while reloading — if a
//! command fails, agents stay cut off until the step succeeds or
//! `--uninstall` runs). Rules do not survive a reboot on their own: re-run
//! `talon setup egress --apply` from a boot-time root unit, or persist them
//! with the distribution's mechanism.
//!
//! The generator ([`egress_plan`], [`render_script`]) is pure. Applying
//! ([`apply_plan`]) goes through the [`CommandRunner`] with argv only —
//! the nftables ruleset is loaded from a file in a private (0700)
//! temporary directory — never through a shell.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use talon_core::provider::effective_vllm;

use super::StepArgs;
use super::service::shell_quote;
use crate::checks::vllm_api_key_set;
use crate::context::{SETUP_LOG, SetupContext};
use crate::platform::Platform;
use crate::runner::{CommandOutput, CommandRunner, CommandSpec};
use crate::status::{StatusBlock, StepOutcome};

/// Docker network the agent containers run on (created by the host).
pub const AGENT_NETWORK: &str = "talon-agents";
/// Linux bridge interface of [`AGENT_NETWORK`].
pub const AGENT_BRIDGE: &str = "br-talon";
/// Comment on the iptables jump rules installed by this step.
pub const RULE_COMMENT: &str = "talon-egress";
/// Comment on the temporary fail-closed DROP rules used while reloading.
pub const RELOAD_COMMENT: &str = "talon-egress-reload";
/// iptables chain for traffic forwarded from the bridge.
pub const EGRESS_CHAIN: &str = "TALON-EGRESS";
/// iptables chain for traffic from the bridge to the host.
pub const INPUT_CHAIN: &str = "TALON-INPUT";
/// Docker's chain for user rules (evaluated before Docker's own).
pub const DOCKER_USER_CHAIN: &str = "DOCKER-USER";
/// nftables table (family `inet`).
pub const NFT_TABLE: &str = "talon_egress";
/// Priority of the nftables base chains (before the `filter` priority 0
/// used by iptables-nft and firewalld).
pub const NFT_PRIORITY: i32 = -10;
/// Status block name.
pub const BLOCK: &str = "SETUP_EGRESS";

/// Upper bound for "delete every copy of a rule" loops when applying.
const MAX_DELETE_REPEATS: usize = 256;
/// Here-document delimiter of the rendered nftables script.
const HEREDOC: &str = "TALON_EGRESS_RULES";

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// An IP network (`addr/prefix`, host bits cleared).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

const fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Cidr {
    Cidr {
        addr: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        prefix,
    }
}

const fn v6(s: [u16; 8], prefix: u8) -> Cidr {
    Cidr {
        addr: IpAddr::V6(Ipv6Addr::new(
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        )),
        prefix,
    }
}

/// Always dropped: link-local ranges, which hold the cloud metadata
/// services (`169.254.169.254`, AWS IPv6 `fd00:ec2::254`).
pub const METADATA_DESTINATIONS: [Cidr; 3] = [
    v4(169, 254, 0, 0, 16),
    v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254], 128),
];

/// Dropped in block-private mode unless allowed: RFC 1918, CGNAT
/// (`100.64.0.0/10`) and IPv6 unique-local (`fc00::/7`) destinations.
pub const PRIVATE_DESTINATIONS: [Cidr; 5] = [
    v4(10, 0, 0, 0, 8),
    v4(172, 16, 0, 0, 12),
    v4(192, 168, 0, 0, 16),
    v4(100, 64, 0, 0, 10),
    v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
];

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let m = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & m))
        }
        IpAddr::V6(a) => {
            let m = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & m))
        }
    }
}

impl Cidr {
    /// Network of `addr/prefix` (host bits cleared); `None` when the prefix
    /// is too long for the address family.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        (prefix <= max_prefix(addr)).then(|| Self {
            addr: mask(addr, prefix),
            prefix,
        })
    }

    /// Parse `addr` or `addr/len`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.split_once('/') {
            Some((addr, len)) => {
                if len.is_empty() || len.len() > 3 || !len.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                Self::new(addr.parse().ok()?, len.parse().ok()?)
            }
            None => {
                let addr: IpAddr = s.parse().ok()?;
                Self::new(addr, max_prefix(addr))
            }
        }
    }

    /// Network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// IPv4 network.
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// `ip` lies inside the network (same family only).
    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.is_ipv4() && mask(ip, self.prefix) == self.addr
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|p| *p != 0)
}

/// One `--allow` destination: a network, optionally restricted to one
/// destination port (tcp and udp).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllowEntry {
    /// Destination network.
    pub net: Cidr,
    /// Destination port (tcp + udp); `None` allows every port and protocol.
    pub port: Option<u16>,
}

impl AllowEntry {
    /// Parse `ip`, `ip/len`, `ip:port`, `ip/len:port`, `[ipv6]:port` or
    /// `[ipv6/len]:port`. (A bare IPv6 address never carries a port —
    /// `fd00::5:443` is an address; write `[fd00::5]:443`.)
    ///
    /// # Errors
    /// A description of the expected syntax.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        let invalid = || {
            format!(
                "invalid --allow entry {raw:?}: expected <ip>[/len][:port] or [<ipv6>[/len]]:port"
            )
        };
        let (net, port) = if let Some(rest) = s.strip_prefix('[') {
            let (inner, after) = rest.split_once(']').ok_or_else(invalid)?;
            let port = if after.is_empty() {
                None
            } else {
                Some(after.strip_prefix(':').ok_or_else(invalid)?)
            };
            (inner, port)
        } else if let Some((addr, rest)) = s.split_once('/') {
            match rest.split_once(':') {
                Some((len, port)) => (&s[..addr.len() + 1 + len.len()], Some(port)),
                None => (s, None),
            }
        } else if s.parse::<IpAddr>().is_ok() {
            (s, None)
        } else {
            match s.rsplit_once(':') {
                Some((addr, port)) if !addr.contains(':') => (addr, Some(port)),
                _ => return Err(invalid()),
            }
        };
        let net = Cidr::parse(net).ok_or_else(invalid)?;
        let port = match port {
            None => None,
            Some(p) => Some(parse_port(p).ok_or_else(invalid)?),
        };
        Ok(Self { net, port })
    }

    /// Traffic to `ip:port` matches this entry.
    pub fn matches(&self, ip: IpAddr, port: u16) -> bool {
        self.net.contains(ip) && self.port.is_none_or(|p| p == port)
    }
}

impl fmt::Display for AllowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            None => write!(f, "{}", self.net),
            Some(p) if self.net.is_ipv4() => write!(f, "{}:{p}", self.net),
            Some(p) => write!(f, "[{}]:{p}", self.net),
        }
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// What happens to forwarded traffic that matches no allow entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    /// Dropped: agents reach only the allowed destinations.
    Allowlist,
    /// Dropped only for private destinations; internet egress is kept.
    BlockPrivate,
}

impl EgressMode {
    /// `allowlist` | `block-private`.
    pub fn as_str(&self) -> &'static str {
        match self {
            EgressMode::Allowlist => "allowlist",
            EgressMode::BlockPrivate => "block-private",
        }
    }
}

/// The firewall policy for the agent bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Default verdict for forwarded traffic.
    pub mode: EgressMode,
    /// LLM gateway port on the host (tcp), the only host port agents reach.
    pub gateway_port: u16,
    /// Allowed destinations (deduplicated, in the given order).
    pub allow: Vec<AllowEntry>,
}

impl EgressPolicy {
    /// Allowlist mode when `allow` is non-empty (unless `keep_internet`),
    /// block-private mode otherwise.
    pub fn new(allow: Vec<AllowEntry>, gateway_port: u16, keep_internet: bool) -> Self {
        let mut unique: Vec<AllowEntry> = Vec::with_capacity(allow.len());
        for entry in allow {
            if !unique.contains(&entry) {
                unique.push(entry);
            }
        }
        let mode = if unique.is_empty() || keep_internet {
            EgressMode::BlockPrivate
        } else {
            EgressMode::Allowlist
        };
        Self {
            mode,
            gateway_port,
            allow: unique,
        }
    }

    /// Whether the rules let an agent open a connection to `ip:port` on
    /// another machine (forwarded traffic; the host itself only exposes
    /// the gateway port).
    pub fn permits(&self, ip: IpAddr, port: u16) -> bool {
        if METADATA_DESTINATIONS.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if self.allow.iter().any(|a| a.matches(ip, port)) {
            return true;
        }
        match self.mode {
            EgressMode::Allowlist => false,
            EgressMode::BlockPrivate => !PRIVATE_DESTINATIONS.iter().any(|c| c.contains(ip)),
        }
    }
}

/// Firewall implementation the rules are generated for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// nftables (own `inet` table; independent of Docker's chains).
    Nft,
    /// iptables + ip6tables (`DOCKER-USER` / `INPUT` jumps).
    Iptables,
}

impl Backend {
    /// `nft` | `iptables`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Backend::Nft => "nft",
            Backend::Iptables => "iptables",
        }
    }

    /// The program the backend needs.
    pub fn program(&self) -> &'static str {
        self.as_str()
    }

    /// The CLI flag selecting this backend.
    pub fn flag(&self) -> &'static str {
        match self {
            Backend::Nft => "--nft",
            Backend::Iptables => "--iptables",
        }
    }
}

/// Install (replace) or remove the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressAction {
    /// Install or replace the rules.
    Install,
    /// Remove every rule, chain and table this step created.
    Uninstall,
}

impl EgressAction {
    /// `install` | `uninstall`.
    pub fn as_str(&self) -> &'static str {
        match self {
            EgressAction::Install => "install",
            EgressAction::Uninstall => "uninstall",
        }
    }
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// One command of an iptables plan (argv, program first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwStep {
    /// Must succeed.
    Run(Vec<String>),
    /// Failure is expected and ignored (e.g. "chain already exists").
    Try(Vec<String>),
    /// Run `then` (which must succeed) unless `check` succeeds.
    Ensure {
        /// Probe (`-C`): the rule already exists.
        check: Vec<String>,
        /// Command creating it.
        then: Vec<String>,
    },
    /// Repeat until it fails (delete every copy of a rule).
    DeleteAll(Vec<String>),
}

/// A group of iptables commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwSection {
    /// Heading (`IPv4 (iptables)`).
    pub title: String,
    /// Probe; when it fails the section is skipped (IPv6 disabled).
    pub guard: Option<Vec<String>>,
    /// Commands in order.
    pub steps: Vec<FwStep>,
}

/// Everything needed to install or remove the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallPlan {
    /// nftables ruleset, loaded atomically with `nft -f <file>`.
    Nft {
        /// The ruleset text.
        ruleset: String,
    },
    /// iptables / ip6tables commands.
    Iptables {
        /// IPv4 section, then the (guarded) IPv6 section.
        sections: Vec<FwSection>,
    },
}

/// Build the plan for `policy`.
pub fn egress_plan(policy: &EgressPolicy, backend: Backend, action: EgressAction) -> FirewallPlan {
    match backend {
        Backend::Nft => FirewallPlan::Nft {
            ruleset: nft_ruleset(policy, action),
        },
        Backend::Iptables => FirewallPlan::Iptables {
            sections: [Family::V4, Family::V6]
                .into_iter()
                .map(|f| iptables_section(policy, action, f))
                .collect(),
        },
    }
}

fn nft_family(c: &Cidr) -> &'static str {
    if c.is_ipv4() { "ip" } else { "ip6" }
}

/// `{ a, b }` for several elements, `a` for one.
fn nft_set(items: &[String]) -> String {
    match items {
        [one] => one.clone(),
        _ => format!("{{ {} }}", items.join(", ")),
    }
}

/// `daddr` match rules for `nets`, one per address family.
fn nft_daddr_rules(nets: &[Cidr], verdict: &str) -> Vec<String> {
    let mut rules = Vec::new();
    for (family, v4) in [("ip", true), ("ip6", false)] {
        let items: Vec<String> = nets
            .iter()
            .filter(|c| c.is_ipv4() == v4)
            .map(Cidr::to_string)
            .collect();
        if !items.is_empty() {
            rules.push(format!("{family} daddr {} {verdict}", nft_set(&items)));
        }
    }
    rules
}

/// Rules of the nftables `agent_egress` chain (forwarded traffic).
pub fn nft_egress_rules(policy: &EgressPolicy) -> Vec<String> {
    let mut rules = nft_daddr_rules(&METADATA_DESTINATIONS, "counter drop");
    rules.push("ct state established,related accept".into());
    for entry in &policy.allow {
        let daddr = format!("{} daddr {}", nft_family(&entry.net), entry.net);
        match entry.port {
            None => rules.push(format!("{daddr} accept")),
            Some(port) => {
                for proto in ["tcp", "udp"] {
                    rules.push(format!("{daddr} {proto} dport {port} accept"));
                }
            }
        }
    }
    match policy.mode {
        EgressMode::Allowlist => rules.push("counter drop".into()),
        EgressMode::BlockPrivate => {
            rules.extend(nft_daddr_rules(&PRIVATE_DESTINATIONS, "counter drop"));
        }
    }
    rules
}

/// Rules of the nftables `agent_input` chain (traffic to the host).
pub fn nft_input_rules(policy: &EgressPolicy) -> Vec<String> {
    vec![
        "ct state established,related accept".into(),
        format!("tcp dport {} accept", policy.gateway_port),
        "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept".into(),
        "counter drop".into(),
    ]
}

/// The nftables ruleset. The leading `add` + `delete` pair makes the load
/// an atomic replace (and makes `delete` succeed on the first run).
pub fn nft_ruleset(policy: &EgressPolicy, action: EgressAction) -> String {
    let mut out = format!("add table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n");
    if action == EgressAction::Uninstall {
        return out;
    }
    let chain = |out: &mut String, name: &str, header: Option<&str>, rules: &[String]| {
        out.push_str(&format!("\tchain {name} {{\n"));
        if let Some(h) = header {
            out.push_str(&format!("\t\t{h}\n"));
        }
        for r in rules {
            out.push_str(&format!("\t\t{r}\n"));
        }
        out.push_str("\t}\n");
    };
    out.push_str(&format!("table inet {NFT_TABLE} {{\n"));
    chain(
        &mut out,
        "forward",
        Some(&format!(
            "type filter hook forward priority {NFT_PRIORITY}; policy accept;"
        )),
        &[format!("iifname \"{AGENT_BRIDGE}\" jump agent_egress")],
    );
    chain(&mut out, "agent_egress", None, &nft_egress_rules(policy));
    chain(
        &mut out,
        "input",
        Some(&format!(
            "type filter hook input priority {NFT_PRIORITY}; policy accept;"
        )),
        &[format!("iifname \"{AGENT_BRIDGE}\" jump agent_input")],
    );
    chain(&mut out, "agent_input", None, &nft_input_rules(policy));
    out.push_str("}\n");
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn program(self) -> &'static str {
        match self {
            Family::V4 => "iptables",
            Family::V6 => "ip6tables",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Family::V4 => "IPv4 (iptables)",
            Family::V6 => "IPv6 (ip6tables)",
        }
    }

    fn has(self, c: &Cidr) -> bool {
        c.is_ipv4() == (self == Family::V4)
    }
}

fn iptables_section(policy: &EgressPolicy, action: EgressAction, family: Family) -> FwSection {
    // Every interpolated value is a constant, a `Cidr` or a number — none
    // contains whitespace — so splitting on whitespace yields the argv.
    let cmd = |args: &str| -> Vec<String> {
        [family.program(), "-w"]
            .into_iter()
            .chain(args.split_whitespace())
            .map(str::to_string)
            .collect()
    };
    let tagged = |comment: &str, target: &str| {
        format!("-i {AGENT_BRIDGE} -m comment --comment {comment} -j {target}")
    };
    let jump_egress = tagged(RULE_COMMENT, EGRESS_CHAIN);
    let jump_input = tagged(RULE_COMMENT, INPUT_CHAIN);
    let reload_drop = tagged(RELOAD_COMMENT, "DROP");
    let (egress, input, user) = (EGRESS_CHAIN, INPUT_CHAIN, DOCKER_USER_CHAIN);

    let mut steps = Vec::new();
    match action {
        EgressAction::Uninstall => {
            steps.push(FwStep::DeleteAll(cmd(&format!("-D {user} {jump_egress}"))));
            steps.push(FwStep::DeleteAll(cmd(&format!("-D INPUT {jump_input}"))));
            steps.push(FwStep::DeleteAll(cmd(&format!("-D {user} {reload_drop}"))));
            steps.push(FwStep::DeleteAll(cmd(&format!("-D INPUT {reload_drop}"))));
            for chain in [egress, input] {
                steps.push(FwStep::Try(cmd(&format!("-F {chain}"))));
                steps.push(FwStep::Try(cmd(&format!("-X {chain}"))));
            }
        }
        EgressAction::Install => {
            // Docker creates DOCKER-USER; create it if Docker has not run yet.
            steps.push(FwStep::Try(cmd(&format!("-N {user}"))));
            // Fail closed while the chains are rebuilt.
            steps.push(FwStep::Run(cmd(&format!("-I {user} 1 {reload_drop}"))));
            steps.push(FwStep::Run(cmd(&format!("-I INPUT 1 {reload_drop}"))));

            // Forwarded traffic from the bridge. Allowed traffic RETURNs to
            // Docker's own chains (isolation, ICC) instead of ACCEPTing.
            steps.push(FwStep::Try(cmd(&format!("-N {egress}"))));
            steps.push(FwStep::Run(cmd(&format!("-F {egress}"))));
            for net in METADATA_DESTINATIONS.iter().filter(|c| family.has(c)) {
                steps.push(FwStep::Run(cmd(&format!("-A {egress} -d {net} -j DROP"))));
            }
            steps.push(FwStep::Run(cmd(&format!(
                "-A {egress} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
            ))));
            for entry in policy.allow.iter().filter(|e| family.has(&e.net)) {
                let net = entry.net;
                match entry.port {
                    None => {
                        steps.push(FwStep::Run(cmd(&format!("-A {egress} -d {net} -j RETURN"))));
                    }
                    Some(port) => {
                        for proto in ["tcp", "udp"] {
                            steps.push(FwStep::Run(cmd(&format!(
                                "-A {egress} -d {net} -p {proto} --dport {port} -j RETURN"
                            ))));
                        }
                    }
                }
            }
            match policy.mode {
                EgressMode::Allowlist => {
                    steps.push(FwStep::Run(cmd(&format!("-A {egress} -j DROP"))));
                }
                EgressMode::BlockPrivate => {
                    for net in PRIVATE_DESTINATIONS.iter().filter(|c| family.has(c)) {
                        steps.push(FwStep::Run(cmd(&format!("-A {egress} -d {net} -j DROP"))));
                    }
                }
            }

            // Traffic from the bridge to the host: the LLM gateway only.
            steps.push(FwStep::Try(cmd(&format!("-N {input}"))));
            steps.push(FwStep::Run(cmd(&format!("-F {input}"))));
            steps.push(FwStep::Run(cmd(&format!(
                "-A {input} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
            ))));
            steps.push(FwStep::Run(cmd(&format!(
                "-A {input} -p tcp --dport {} -j ACCEPT",
                policy.gateway_port
            ))));
            if family == Family::V6 {
                for kind in ["neighbour-solicitation", "neighbour-advertisement"] {
                    steps.push(FwStep::Run(cmd(&format!(
                        "-A {input} -p icmpv6 --icmpv6-type {kind} -j ACCEPT"
                    ))));
                }
            }
            steps.push(FwStep::Run(cmd(&format!("-A {input} -j DROP"))));

            // Hook the chains in (once), then lift the reload DROPs.
            steps.push(FwStep::Ensure {
                check: cmd(&format!("-C {user} {jump_egress}")),
                then: cmd(&format!("-I {user} 2 {jump_egress}")),
            });
            steps.push(FwStep::Ensure {
                check: cmd(&format!("-C INPUT {jump_input}")),
                then: cmd(&format!("-I INPUT 2 {jump_input}")),
            });
            steps.push(FwStep::DeleteAll(cmd(&format!("-D {user} {reload_drop}"))));
            steps.push(FwStep::DeleteAll(cmd(&format!("-D INPUT {reload_drop}"))));
        }
    }
    FwSection {
        title: family.title().to_string(),
        guard: (family == Family::V6).then(|| cmd("-n -L INPUT")),
        steps,
    }
}

// ---------------------------------------------------------------------------
// Script rendering
// ---------------------------------------------------------------------------

/// Shell word: unquoted when it only contains safe characters.
fn sh_word(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:,=+-".contains(c));
    if safe { s.to_string() } else { shell_quote(s) }
}

fn sh_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| sh_word(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One iptables step as a POSIX shell line.
pub fn render_step(step: &FwStep) -> String {
    match step {
        FwStep::Run(a) => sh_join(a),
        FwStep::Try(a) => format!("{} 2>/dev/null || true", sh_join(a)),
        FwStep::Ensure { check, then } => {
            format!("{} 2>/dev/null || {}", sh_join(check), sh_join(then))
        }
        FwStep::DeleteAll(a) => format!("while {} 2>/dev/null; do :; done", sh_join(a)),
    }
}

/// One iptables section as shell lines (guarded by `if`).
pub fn render_section(section: &FwSection) -> Vec<String> {
    let mut lines = vec![format!("# --- {} ---", section.title)];
    match &section.guard {
        None => lines.extend(section.steps.iter().map(render_step)),
        Some(guard) => {
            lines.push(format!("if {} >/dev/null 2>&1; then", sh_join(guard)));
            lines.extend(
                section
                    .steps
                    .iter()
                    .map(|s| format!("  {}", render_step(s))),
            );
            lines.push("else".into());
            lines.push(format!(
                "  echo {} >&2",
                shell_quote(&format!(
                    "talon-egress: {} unavailable, rules skipped",
                    section.title
                ))
            ));
            lines.push("fi".into());
        }
    }
    lines
}

fn header(policy: &EgressPolicy, backend: Backend, action: EgressAction) -> Vec<String> {
    let mut h = Vec::new();
    if action == EgressAction::Uninstall {
        h.push("talon-egress: remove the firewall rules for Talon agent containers".into());
        h.push(format!("(bridge {AGENT_BRIDGE})."));
        h.push("Generated by `talon setup egress --uninstall`.".into());
        return h;
    }
    h.push("talon-egress: firewall rules for Talon agent containers".into());
    h.push(format!(
        "(docker network {AGENT_NETWORK}, bridge {AGENT_BRIDGE}, inter-container traffic off)."
    ));
    h.push("Generated by `talon setup egress`; re-run it instead of editing this script.".into());
    h.push("Idempotent: running it again replaces the rules.".into());
    h.push(String::new());
    match policy.mode {
        EgressMode::Allowlist => {
            h.push(
                "Mode allowlist: agents reach only the allowed destinations below and the".into(),
            );
            h.push("LLM gateway; everything else is dropped.".into());
        }
        EgressMode::BlockPrivate => {
            h.push(
                "Mode block-private: internet egress is kept; private destinations (RFC 1918,"
                    .into(),
            );
            h.push("CGNAT 100.64.0.0/10, ULA fc00::/7) are dropped unless allowed below.".into());
        }
    }
    h.push("Trade-off: MCP servers query the SIEM, MySQL, Wazuh and CoPilot, usually on".into());
    h.push("private addresses - list them (and private DNS resolvers, port 53) with".into());
    h.push("`talon setup egress --allow <ip>[/len][:port]`.".into());
    h.push("Always dropped: link-local and cloud metadata (169.254.0.0/16 incl.".into());
    h.push("169.254.169.254, fe80::/10, fd00:ec2::254).".into());
    h.push(format!(
        "Host services reachable from {AGENT_BRIDGE}: only tcp/{} (LLM gateway).",
        policy.gateway_port
    ));
    if policy.allow.is_empty() {
        h.push("Allowed destinations: none".into());
    } else {
        h.push("Allowed destinations (a port means tcp+udp to that port only):".into());
        h.extend(policy.allow.iter().map(|a| format!("  {a}")));
    }
    h.push(format!(
        "Remove with: talon setup egress --uninstall --apply {}",
        backend.flag()
    ));
    h
}

/// The complete POSIX `sh` script for `policy` (what the step prints and,
/// command for command, what `--apply` executes). It ends with `exit 0`,
/// so text after it is never executed.
pub fn render_script(policy: &EgressPolicy, backend: Backend, action: EgressAction) -> String {
    let mut lines = vec!["#!/bin/sh".to_string()];
    lines.extend(header(policy, backend, action).into_iter().map(|l| {
        if l.is_empty() {
            "#".to_string()
        } else {
            format!("# {l}")
        }
    }));
    lines.push("set -eu".into());
    match egress_plan(policy, backend, action) {
        FirewallPlan::Nft { ruleset } => {
            lines.push(String::new());
            lines.push(format!("nft -f - <<'{HEREDOC}'"));
            lines.extend(ruleset.lines().map(str::to_string));
            lines.push(HEREDOC.into());
        }
        FirewallPlan::Iptables { sections } => {
            for section in &sections {
                lines.push(String::new());
                lines.extend(render_section(section));
            }
        }
    }
    lines.push(String::new());
    lines.push("exit 0".into());
    let mut script = lines.join("\n");
    script.push('\n');
    script
}

// ---------------------------------------------------------------------------
// Applying
// ---------------------------------------------------------------------------

/// Result of [`apply_plan`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Commands executed.
    pub commands: usize,
    /// Sections skipped because their guard failed (IPv6 unavailable).
    pub skipped_sections: Vec<String>,
}

/// A command of the plan failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyError {
    /// The failing command line.
    pub command: String,
    /// stderr / spawn error (truncated).
    pub detail: String,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` failed: {}", self.command, self.detail)
    }
}

impl std::error::Error for ApplyError {}

fn failure_detail(out: &CommandOutput) -> String {
    let text = if let Some(e) = &out.spawn_error {
        format!("could not start: {e}")
    } else if out.timed_out {
        "timed out".to_string()
    } else {
        let stderr = out.stderr.trim();
        let code = out
            .exit_code
            .map_or_else(|| "signal".to_string(), |c| c.to_string());
        if stderr.is_empty() {
            format!("exit {code}")
        } else {
            format!("exit {code}: {stderr}")
        }
    };
    text.chars().take(400).collect()
}

async fn run_argv(runner: &dyn CommandRunner, argv: &[String]) -> Option<CommandOutput> {
    let (program, args) = argv.split_first()?;
    Some(
        runner
            .run(&CommandSpec::new(program, args.iter().cloned()))
            .await,
    )
}

async fn must_run(
    runner: &dyn CommandRunner,
    argv: &[String],
    report: &mut ApplyReport,
) -> Result<(), ApplyError> {
    report.commands += 1;
    match run_argv(runner, argv).await {
        Some(out) if out.success() => Ok(()),
        Some(out) => Err(ApplyError {
            command: argv.join(" "),
            detail: failure_detail(&out),
        }),
        None => Err(ApplyError {
            command: String::new(),
            detail: "empty command".into(),
        }),
    }
}

async fn try_run(runner: &dyn CommandRunner, argv: &[String], report: &mut ApplyReport) -> bool {
    report.commands += 1;
    run_argv(runner, argv).await.is_some_and(|o| o.success())
}

fn write_private_file(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()
}

/// Execute `plan` (argv only, no shell). nftables: the ruleset is written
/// to a file in a fresh 0700 temporary directory and loaded with
/// `nft -f` (one atomic transaction). iptables: commands run in order with
/// the semantics of [`FwStep`]; the first failing required command stops
/// the run (the reload DROPs then keep the bridge closed).
///
/// # Errors
/// The failing command and its stderr.
pub async fn apply_plan(
    runner: &dyn CommandRunner,
    plan: &FirewallPlan,
) -> Result<ApplyReport, ApplyError> {
    let mut report = ApplyReport::default();
    match plan {
        FirewallPlan::Nft { ruleset } => {
            let io_err = |e: std::io::Error| ApplyError {
                command: "write nftables ruleset".into(),
                detail: e.to_string(),
            };
            let dir = tempfile::Builder::new()
                .prefix("talon-egress-")
                .tempdir()
                .map_err(io_err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                    .map_err(io_err)?;
            }
            let path = dir.path().join("talon-egress.nft");
            write_private_file(&path, ruleset).map_err(io_err)?;
            let argv = vec![
                "nft".to_string(),
                "-f".to_string(),
                path.to_string_lossy().into_owned(),
            ];
            must_run(runner, &argv, &mut report).await?;
            // `dir` is removed when dropped.
        }
        FirewallPlan::Iptables { sections } => {
            for section in sections {
                if let Some(guard) = &section.guard {
                    if !try_run(runner, guard, &mut report).await {
                        tracing::warn!(section = %section.title, "firewall section skipped (guard failed)");
                        report.skipped_sections.push(section.title.clone());
                        continue;
                    }
                }
                for step in &section.steps {
                    match step {
                        FwStep::Run(argv) => must_run(runner, argv, &mut report).await?,
                        FwStep::Try(argv) => {
                            try_run(runner, argv, &mut report).await;
                        }
                        FwStep::Ensure { check, then } => {
                            if !try_run(runner, check, &mut report).await {
                                must_run(runner, then, &mut report).await?;
                            }
                        }
                        FwStep::DeleteAll(argv) => {
                            for _ in 0..MAX_DELETE_REPEATS {
                                if !try_run(runner, argv, &mut report).await {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Host facts
// ---------------------------------------------------------------------------

/// Non-loopback `nameserver` addresses of a `resolv.conf` (zone ids
/// stripped, deduplicated).
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(value) = parts.next() else { continue };
        let value = value.split('%').next().unwrap_or(value);
        if let Ok(ip) = value.parse::<IpAddr>() {
            if !ip.is_loopback() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Upstream DNS servers from the first readable `resolv.conf` candidate.
pub fn host_dns_resolvers(paths: &[PathBuf]) -> Vec<IpAddr> {
    paths
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|text| parse_resolv_conf(&text))
        .unwrap_or_default()
}

/// The vLLM server address when `TALON_VLLM_BASE_URL` has an IP literal
/// host.
fn vllm_ip_endpoint(ctx: &SetupContext) -> Option<(IpAddr, u16)> {
    let v = effective_vllm(&ctx.config.provider_defaults)?;
    let url = reqwest::Url::parse(v.base_url.trim()).ok()?;
    let host = url.host_str()?;
    let ip: IpAddr = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()?;
    Some((ip, url.port_or_known_default()?))
}

/// Pick the backend: nftables when `nft` is installed, else iptables.
/// Returns the backend and whether its program was found.
pub fn detect_backend(runner: &dyn CommandRunner) -> (Backend, bool) {
    if runner.which("nft").is_some() {
        (Backend::Nft, true)
    } else if runner.which("iptables").is_some() {
        (Backend::Iptables, true)
    } else {
        (Backend::Nft, false)
    }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// Parsed command-line options of the step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressOptions {
    /// `--apply`: install the rules (root only).
    pub apply: bool,
    /// `--uninstall`: remove instead of install.
    pub action: EgressAction,
    /// `--nft` / `--iptables` (auto-detected when `None`).
    pub backend: Option<Backend>,
    /// `--gateway-port N` (default: `TALON_LLM_GATEWAY_PORT`, 3001).
    pub gateway_port: u16,
    /// `--allow` entries (repeatable, comma-separated lists accepted).
    pub allow: Vec<AllowEntry>,
    /// `--keep-internet`: block-private mode even with `--allow`.
    pub keep_internet: bool,
}

/// An invalid argument (`ERROR` code + offending value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError {
    /// Machine-readable code (`invalid_allow_entry`, ...).
    pub code: &'static str,
    /// The offending argument.
    pub value: String,
}

impl EgressOptions {
    /// Parse the step arguments. Unknown arguments are rejected (a typo in
    /// a firewall option must not silently widen the rules).
    ///
    /// # Errors
    /// The first invalid argument.
    pub fn from_args(args: &StepArgs, default_gateway_port: u16) -> Result<Self, ArgError> {
        let mut opts = Self {
            apply: false,
            action: EgressAction::Install,
            backend: None,
            gateway_port: default_gateway_port,
            allow: Vec::new(),
            keep_internet: false,
        };
        let err = |code: &'static str, value: &str| ArgError {
            code,
            value: value.to_string(),
        };
        let raw = args.raw();
        let mut i = 0;
        while let Some(arg) = raw.get(i) {
            match arg.as_str() {
                "--apply" => opts.apply = true,
                "--uninstall" => opts.action = EgressAction::Uninstall,
                "--keep-internet" => opts.keep_internet = true,
                "--nft" | "--iptables" => {
                    let b = if arg == "--nft" {
                        Backend::Nft
                    } else {
                        Backend::Iptables
                    };
                    if opts.backend.is_some_and(|x| x != b) {
                        return Err(err("conflicting_backends", arg));
                    }
                    opts.backend = Some(b);
                }
                "--allow" | "--gateway-port" => {
                    i += 1;
                    let value = raw.get(i).ok_or_else(|| err("missing_value", arg))?;
                    if arg == "--allow" {
                        for part in value.split(',').filter(|p| !p.trim().is_empty()) {
                            let entry = AllowEntry::parse(part)
                                .map_err(|_| err("invalid_allow_entry", part))?;
                            opts.allow.push(entry);
                        }
                    } else {
                        opts.gateway_port =
                            parse_port(value).ok_or_else(|| err("invalid_gateway_port", value))?;
                    }
                }
                other => return Err(err("unknown_argument", other)),
            }
            i += 1;
        }
        Ok(opts)
    }

    /// The policy these options describe.
    pub fn policy(&self) -> EgressPolicy {
        EgressPolicy::new(self.allow.clone(), self.gateway_port, self.keep_internet)
    }

    /// Canonical arguments reproducing these options with `--apply`.
    pub fn apply_args(&self, backend: Backend) -> Vec<String> {
        let mut args = vec!["--apply".to_string(), backend.flag().to_string()];
        if self.action == EgressAction::Uninstall {
            args.push("--uninstall".into());
            return args;
        }
        args.push("--gateway-port".into());
        args.push(self.gateway_port.to_string());
        for entry in &self.policy().allow {
            args.push("--allow".into());
            args.push(entry.to_string());
        }
        if self.keep_internet && !self.allow.is_empty() {
            args.push("--keep-internet".into());
        }
        args
    }
}

// ---------------------------------------------------------------------------
// Step
// ---------------------------------------------------------------------------

fn list_or_none<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn outcome(script: &str, block: StatusBlock, exit_code: i32) -> StepOutcome {
    StepOutcome {
        lines: script.lines().map(str::to_string).collect(),
        block: Some(block),
        exit_code,
    }
}

/// Run the step.
///
/// Arguments: `--apply`, `--uninstall`, `--allow <cidr[:port]>` (repeatable),
/// `--keep-internet`, `--gateway-port N`, `--nft` | `--iptables`.
///
/// Exit codes: 0 printed / applied, 1 apply failed or needs root, 4 invalid
/// arguments.
///
/// # Errors
/// Never fails internally; problems are reported in the block.
pub async fn run(args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    let opts = match EgressOptions::from_args(args, ctx.config.llm_gateway_port) {
        Ok(o) => o,
        Err(e) => {
            return Ok(StepOutcome::with_code(
                StatusBlock::new(BLOCK)
                    .field("STATUS", "failed")
                    .field("ERROR", e.code)
                    .field("INVALID_ARGUMENT", e.value)
                    .field("LOG", SETUP_LOG),
                4,
            ));
        }
    };
    let runner = ctx.runner.as_ref();
    let (backend, available) = match opts.backend {
        Some(b) => (b, runner.which(b.program()).is_some()),
        None => detect_backend(runner),
    };
    let policy = opts.policy();
    let linux = ctx.platform.platform == Platform::Linux;
    let script = render_script(&policy, backend, opts.action);

    let bridge_present = linux
        && runner
            .run(&CommandSpec::new(
                "ip",
                ["-o", "link", "show", "dev", AGENT_BRIDGE],
            ))
            .await
            .success();

    let mut warnings: Vec<&str> = Vec::new();
    if !linux {
        warnings.push("unsupported_platform");
    }
    if !available {
        warnings.push("backend_not_found");
    }
    let mut block = StatusBlock::new(BLOCK)
        .field("ACTION", opts.action.as_str())
        .field("BACKEND", backend.as_str())
        .field("BACKEND_AVAILABLE", available)
        .field("NETWORK", AGENT_NETWORK)
        .field("BRIDGE", AGENT_BRIDGE)
        .field("BRIDGE_PRESENT", bridge_present);
    if opts.action == EgressAction::Install {
        block.set("MODE", policy.mode.as_str());
        block.set("GATEWAY_PORT", policy.gateway_port);
        block.set("ALLOW", list_or_none(&policy.allow));
        let blocked_dns: Vec<IpAddr> = host_dns_resolvers(&ctx.resolv_conf_paths)
            .into_iter()
            .filter(|ip| !policy.permits(*ip, 53))
            .collect();
        if !blocked_dns.is_empty() {
            warnings.push("dns_resolver_blocked");
        }
        block.set("BLOCKED_DNS_RESOLVERS", list_or_none(&blocked_dns));
        if !vllm_api_key_set(&ctx.config.env)
            && vllm_ip_endpoint(ctx)
                .is_some_and(|(ip, port)| !ip.is_loopback() && policy.permits(ip, port))
        {
            warnings.push("vllm_reachable_from_agents");
        }
    }
    block.set("WARNINGS", list_or_none(&warnings));

    let mut apply_cmd = vec![
        "sudo".to_string(),
        shell_quote(&ctx.talon_binary.to_string_lossy()),
    ];
    apply_cmd.extend(["setup".to_string(), "egress".to_string()]);
    // `[ipv6]:port` entries must not be glob-expanded by the operator's shell.
    apply_cmd.extend(opts.apply_args(backend).iter().map(|a| sh_word(a)));
    let next_step = format!(
        "review the script above, then run as root: {}",
        apply_cmd.join(" ")
    );

    if !opts.apply {
        block.set("APPLIED", false);
        block.set("NEXT_STEP", next_step);
        block.set("STATUS", "success");
        block.set("LOG", SETUP_LOG);
        return Ok(outcome(&script, block, 0));
    }

    block.set("APPLIED", false);
    let refuse = |mut block: StatusBlock, status: &str, error: &str| {
        block.set("STATUS", status);
        block.set("ERROR", error);
        block.set("LOG", SETUP_LOG);
        block
    };
    if !linux {
        return Ok(outcome(
            &script,
            refuse(block, "failed", "unsupported_platform"),
            1,
        ));
    }
    if !ctx.platform.is_root() {
        block.set("NEXT_STEP", next_step);
        return Ok(outcome(
            &script,
            refuse(block, "needs_root", "root_required"),
            1,
        ));
    }
    if !available {
        return Ok(outcome(
            &script,
            refuse(block, "failed", "backend_not_found"),
            1,
        ));
    }

    tracing::info!(
        backend = backend.as_str(),
        action = opts.action.as_str(),
        mode = policy.mode.as_str(),
        "Applying agent egress firewall"
    );
    let plan = egress_plan(&policy, backend, opts.action);
    match apply_plan(runner, &plan).await {
        Ok(report) => {
            ctx.append_log(
                "egress",
                &format!(
                    "{} via {} ({} commands)\n{script}",
                    opts.action.as_str(),
                    backend.as_str(),
                    report.commands
                ),
            );
            block.set("APPLIED", true);
            if !report.skipped_sections.is_empty() {
                block.set("SKIPPED", report.skipped_sections.join(","));
            }
            block.set("STATUS", "success");
            block.set("LOG", SETUP_LOG);
            Ok(outcome(&script, block, 0))
        }
        Err(e) => {
            tracing::error!(error = %e, "Applying the egress firewall failed");
            ctx.append_log("egress (failed)", &e.to_string());
            block.set("FAILED_COMMAND", &e.command);
            block.set("DETAIL", &e.detail);
            Ok(outcome(&script, refuse(block, "failed", "apply_failed"), 1))
        }
    }
}

#[cfg(test)]
mod tests;
