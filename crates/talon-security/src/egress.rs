//! Outbound URL policy (SSRF guard) for `web_fetch` and webhooks.
//!
//! Default policy: only `http`/`https`; deny loopback, link-local
//! (169.254.0.0/16 incl. cloud metadata), RFC1918, CGNAT, ULA, multicast,
//! unspecified, `localhost`/`*.internal`/`metadata.google.internal` hostnames,
//! non-default ports unless allowed, userinfo in URL. Hostnames are resolved
//! and *every* resolved address is checked (DNS-rebinding safe callers should
//! connect to the returned addresses).
//!
//! # Address classes ([`classify_ip`])
//!
//! | class | ranges | allowed when |
//! |---|---|---|
//! | [`IpCategory::Global`] | everything else in `0/0` and `2000::/3` | always |
//! | [`IpCategory::Private`] | `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT), `198.18/15`, `fc00::/7`, `fec0::/10`, `64:ff9b:1::/48` | `allow_private`, or the host/IP is allowlisted |
//! | [`IpCategory::Loopback`] | `127/8`, `::1` | `allow_private` **and** the host/IP is allowlisted explicitly (not via `*.suffix`) |
//! | [`IpCategory::Forbidden`] | `0/8`, `169.254/16`, `192.0.0/24`, `192.0.2/24`, `192.88.99/24`, `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4` (incl. broadcast), `100.100.100.200`, `::`, `::/8` (IPv4-compatible/translated), `100::/64`, `2001::/23` (incl. Teredo), `2001:db8::/32`, `2002::/16` (6to4), `3fff::/20`, `5f00::/16`, `fe80::/10`, `ff00::/8`, `fd00:ec2::254`, anything outside `2000::/3` | never |
//!
//! IPv4-mapped IPv6 (`::ffff:a.b.c.d`) and the NAT64 well-known prefix
//! (`64:ff9b::/96`) are classified by their embedded IPv4 address.
//!
//! # Host names
//!
//! Hosts are lower-cased, IDNA-normalized (by the URL parser) and stripped of
//! trailing dots. Numeric host forms (`2130706433`, `0x7f.1`, `017700000001`,
//! `127.1`) are normalized to dotted IPv4 by the WHATWG parser before any
//! check. Built-in name rules:
//! - cloud metadata names (`metadata.google.internal`, `metadata`,
//!   `metadata.goog`, `instance-data`, ...) are always denied;
//! - `localhost`, `*.localhost`, `localhost.localdomain`, `ip6-localhost`,
//!   `ip6-loopback` behave like loopback addresses;
//! - `*.internal`, `*.local`, `*.localdomain`, `*.home.arpa`, `*.lan`,
//!   `*.intranet`, `*.corp`, `*.test`, `*.invalid`, `*.example`, `*.onion`
//!   and single-label names (`http://intranet/`) are internal: denied unless
//!   `allow_private` or allowlisted.
//!
//! # Host patterns (`allow_hosts` / `deny_hosts`)
//!
//! `example.com` (exact), `*.example.com` or `.example.com` (the domain and
//! all subdomains), IP addresses, CIDR blocks (`10.1.0.0/16`), each
//! optionally with a `:port` (`ti.corp.example:8443`, `[::1]:8080`). A
//! pattern without a port matches any port. Deny always wins over allow;
//! allowlisted hosts may use non-default ports.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use talon_core::{Error, Result};
use url::{Host, Url};

/// Maximum accepted URL length.
pub const MAX_URL_LEN: usize = 8 * 1024;
/// DNS resolution timeout used by [`EgressPolicy::resolve_and_check`].
pub const DNS_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum number of resolved addresses considered.
const MAX_RESOLVED: usize = 32;
/// Ports usable without an allowlist entry.
const DEFAULT_PORTS: &[u16] = &[80, 443];

/// Outbound URL policy. `Default` is the strict policy (no allow/deny
/// entries, private addresses denied).
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    /// Hosts always allowed (exact or `*.suffix`).
    pub allow_hosts: Vec<String>,
    /// Hosts always denied (exact or `*.suffix`).
    pub deny_hosts: Vec<String>,
    /// Permit private / internal addresses (e.g. for an internal TI server).
    pub allow_private: bool,
}

/// Coarse class of a destination address (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpCategory {
    /// Publicly routable unicast.
    Global,
    /// Private / internal ranges.
    Private,
    /// Loopback.
    Loopback,
    /// Never a valid destination.
    Forbidden,
}

/// Classify an address (IPv4-mapped and NAT64 addresses by their embedded
/// IPv4 address).
pub fn classify_ip(ip: IpAddr) -> IpCategory {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

const fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

/// Ordered (first match wins) IPv4 table: (network, prefix length, class).
const V4_TABLE: &[(u32, u32, IpCategory)] = &[
    (v4(100, 100, 100, 200), 32, IpCategory::Forbidden), // Alibaba Cloud metadata
    (v4(0, 0, 0, 0), 8, IpCategory::Forbidden),          // "this network", 0.0.0.0
    (v4(10, 0, 0, 0), 8, IpCategory::Private),
    (v4(100, 64, 0, 0), 10, IpCategory::Private), // CGNAT
    (v4(127, 0, 0, 0), 8, IpCategory::Loopback),
    (v4(169, 254, 0, 0), 16, IpCategory::Forbidden), // link-local, AWS/GCP/Azure metadata
    (v4(172, 16, 0, 0), 12, IpCategory::Private),
    (v4(192, 0, 0, 0), 24, IpCategory::Forbidden), // IETF protocol assignments
    (v4(192, 0, 2, 0), 24, IpCategory::Forbidden), // TEST-NET-1
    (v4(192, 88, 99, 0), 24, IpCategory::Forbidden), // 6to4 relay anycast
    (v4(192, 168, 0, 0), 16, IpCategory::Private),
    (v4(198, 18, 0, 0), 15, IpCategory::Private), // benchmarking
    (v4(198, 51, 100, 0), 24, IpCategory::Forbidden), // TEST-NET-2
    (v4(203, 0, 113, 0), 24, IpCategory::Forbidden), // TEST-NET-3
    (v4(224, 0, 0, 0), 4, IpCategory::Forbidden), // multicast
    (v4(240, 0, 0, 0), 4, IpCategory::Forbidden), // reserved + broadcast
];

fn in_v4(n: u32, net: u32, prefix: u32) -> bool {
    prefix == 0 || (n >> (32 - prefix)) == (net >> (32 - prefix))
}

fn classify_v4(ip: Ipv4Addr) -> IpCategory {
    let n = u32::from(ip);
    V4_TABLE
        .iter()
        .find(|(net, prefix, _)| in_v4(n, *net, *prefix))
        .map_or(IpCategory::Global, |(_, _, c)| *c)
}

fn in_v6(n: u128, net: u128, prefix: u32) -> bool {
    prefix == 0 || (n >> (128 - prefix)) == (net >> (128 - prefix))
}

const fn v6(segs: [u16; 8]) -> u128 {
    let mut out: u128 = 0;
    let mut i = 0;
    while i < 8 {
        out = (out << 16) | segs[i] as u128;
        i += 1;
    }
    out
}

/// Ordered IPv6 table for addresses without an embedded IPv4 address.
const V6_TABLE: &[(u128, u32, IpCategory)] = &[
    (v6([0, 0, 0, 0, 0, 0, 0, 0]), 128, IpCategory::Forbidden), // ::
    (v6([0, 0, 0, 0, 0, 0, 0, 1]), 128, IpCategory::Loopback),  // ::1
    (
        v6([0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254]),
        128,
        IpCategory::Forbidden,
    ), // AWS IMDS
    (v6([0, 0, 0, 0, 0, 0, 0, 0]), 8, IpCategory::Forbidden),   // ::/8 (compat, translated)
    (v6([0x100, 0, 0, 0, 0, 0, 0, 0]), 64, IpCategory::Forbidden), // discard-only
    (v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 23, IpCategory::Forbidden), // IETF (Teredo, ...)
    (
        v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
        32,
        IpCategory::Forbidden,
    ), // documentation
    (v6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16, IpCategory::Forbidden), // 6to4
    (v6([0x3fff, 0, 0, 0, 0, 0, 0, 0]), 20, IpCategory::Forbidden), // documentation
    (v6([0x5f00, 0, 0, 0, 0, 0, 0, 0]), 16, IpCategory::Forbidden), // SRv6 SIDs
    (v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7, IpCategory::Private), // ULA
    (v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10, IpCategory::Forbidden), // link-local
    (v6([0xfec0, 0, 0, 0, 0, 0, 0, 0]), 10, IpCategory::Private), // site-local (deprecated)
    (v6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8, IpCategory::Forbidden), // multicast
    (v6([0x2000, 0, 0, 0, 0, 0, 0, 0]), 3, IpCategory::Global), // global unicast
];

const NAT64_WKP: u128 = v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]);
const NAT64_LOCAL: u128 = v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]);

fn classify_v6(ip: Ipv6Addr) -> IpCategory {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return classify_v4(mapped);
    }
    let n = u128::from(ip);
    // Truncation is intended: the low 32 bits carry the embedded IPv4.
    let embedded = Ipv4Addr::from((n & 0xffff_ffff) as u32);
    if in_v6(n, NAT64_WKP, 96) {
        return classify_v4(embedded);
    }
    if in_v6(n, NAT64_LOCAL, 48) {
        return classify_v4(embedded).max(IpCategory::Private);
    }
    V6_TABLE
        .iter()
        .find(|(net, prefix, _)| in_v6(n, *net, *prefix))
        .map_or(IpCategory::Forbidden, |(_, _, c)| *c)
}

/// Cloud metadata host names: never reachable.
const METADATA_NAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
    "metadata.azure.com",
    "metadata.packet.net",
    "metadata.platformequinix.com",
];

/// Names that mean "this machine".
const LOCALHOST_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
];

/// Suffixes of internal-only names.
const INTERNAL_SUFFIXES: &[&str] = &[
    "internal",
    "local",
    "localdomain",
    "home.arpa",
    "lan",
    "intranet",
    "corp",
    "test",
    "invalid",
    "example",
    "onion",
];

fn has_suffix(host: &str, suffix: &str) -> bool {
    host == suffix
        || (host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
}

/// Normalized destination host.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NormHost {
    Domain(String),
    Ip(IpAddr),
}

impl NormHost {
    fn label(&self) -> String {
        match self {
            NormHost::Domain(d) => d.clone(),
            NormHost::Ip(ip) => ip.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
enum HostPattern {
    Exact { host: String, port: Option<u16> },
    Suffix { suffix: String, port: Option<u16> },
    Ip { ip: IpAddr, port: Option<u16> },
    Net(IpNet),
}

/// How strongly the destination is allowlisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AllowMatch {
    None,
    Wildcard,
    Explicit,
}

fn normalize_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_pattern(raw: &str) -> Option<HostPattern> {
    let raw = raw.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    if let Ok(net) = raw.parse::<IpNet>() {
        return Some(HostPattern::Net(net));
    }
    // split an optional port
    let (host, port): (String, Option<u16>) = if let Some(rest) = raw.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        (inner.to_string(), port)
    } else if raw.matches(':').count() == 1 {
        let (h, p) = raw.split_once(':')?;
        (h.to_string(), Some(p.parse().ok()?))
    } else {
        (raw.clone(), None)
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(HostPattern::Ip {
            ip: ip.to_canonical(),
            port,
        });
    }
    let (wild, name) = if let Some(s) = host.strip_prefix("*.") {
        (true, s)
    } else if let Some(s) = host.strip_prefix('.') {
        (true, s)
    } else {
        (false, host.as_str())
    };
    let name = normalize_domain(name);
    if name.is_empty() {
        return None;
    }
    // IDNA-normalize like the URL parser does; numeric forms become IPs.
    let name = match Host::parse(&name) {
        Ok(Host::Domain(d)) => normalize_domain(&d),
        Ok(Host::Ipv4(ip)) if !wild => {
            return Some(HostPattern::Ip {
                ip: IpAddr::V4(ip),
                port,
            });
        }
        Ok(Host::Ipv6(ip)) if !wild => {
            return Some(HostPattern::Ip {
                ip: IpAddr::V6(ip).to_canonical(),
                port,
            });
        }
        _ => name,
    };
    Some(if wild {
        HostPattern::Suffix { suffix: name, port }
    } else {
        HostPattern::Exact { host: name, port }
    })
}

impl HostPattern {
    fn port_ok(want: Option<u16>, port: u16) -> bool {
        want.is_none_or(|p| p == port)
    }

    fn matches_host(&self, host: &NormHost, port: u16) -> bool {
        match (self, host) {
            (HostPattern::Exact { host: h, port: p }, NormHost::Domain(d)) => {
                h == d && Self::port_ok(*p, port)
            }
            (HostPattern::Suffix { suffix, port: p }, NormHost::Domain(d)) => {
                has_suffix(d, suffix) && Self::port_ok(*p, port)
            }
            (HostPattern::Ip { ip, port: p }, NormHost::Ip(addr)) => {
                *ip == addr.to_canonical() && Self::port_ok(*p, port)
            }
            (HostPattern::Net(net), NormHost::Ip(addr)) => net_contains(net, *addr),
            _ => false,
        }
    }

    fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            HostPattern::Ip { ip: p, .. } => *p == ip.to_canonical(),
            HostPattern::Net(net) => net_contains(net, ip),
            _ => false,
        }
    }

    fn strength(&self) -> AllowMatch {
        match self {
            HostPattern::Suffix { .. } => AllowMatch::Wildcard,
            _ => AllowMatch::Explicit,
        }
    }
}

fn net_contains(net: &IpNet, ip: IpAddr) -> bool {
    net.contains(&ip) || net.contains(&ip.to_canonical())
}

/// Result of the syntactic/host-policy stage.
#[derive(Debug)]
struct Checked {
    url: Url,
    host: NormHost,
    port: u16,
    allow: AllowMatch,
}

fn deny(msg: impl Into<String>) -> Error {
    Error::security(format!("egress denied: {}", msg.into()))
}

impl EgressPolicy {
    /// Policy from `TALON_EGRESS_ALLOW` / `TALON_EGRESS_DENY` (comma lists)
    /// and `TALON_EGRESS_ALLOW_PRIVATE`.
    pub fn from_env(env: &talon_core::env::EnvFile) -> Self {
        let list = |key: &str| -> Vec<String> {
            env.get(key)
                .map(|v| {
                    v.split([',', ';', ' ', '\t', '\n'])
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_ascii_lowercase)
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            allow_hosts: list("TALON_EGRESS_ALLOW"),
            deny_hosts: list("TALON_EGRESS_DENY"),
            allow_private: env.get_bool("TALON_EGRESS_ALLOW_PRIVATE"),
        }
    }

    fn allow_patterns(&self) -> impl Iterator<Item = HostPattern> + '_ {
        self.allow_hosts.iter().filter_map(|p| parse_pattern(p))
    }

    fn deny_patterns(&self) -> impl Iterator<Item = HostPattern> + '_ {
        self.deny_hosts.iter().filter_map(|p| parse_pattern(p))
    }

    /// Is this IP acceptable as a destination?
    ///
    /// Without host context: global addresses pass; private ones need
    /// `allow_private` or an allowlisted IP/CIDR; loopback needs both;
    /// forbidden ranges and denied IPs/CIDRs never pass.
    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        self.check_ip(ip, AllowMatch::None).is_ok()
    }

    fn check_ip(&self, ip: IpAddr, host_allow: AllowMatch) -> Result<()> {
        if self.deny_patterns().any(|p| p.matches_ip(ip)) {
            return Err(deny(format!("address {ip} is denied by policy")));
        }
        let ip_allow = if self.allow_patterns().any(|p| p.matches_ip(ip)) {
            AllowMatch::Explicit
        } else {
            AllowMatch::None
        };
        let allow = host_allow.max(ip_allow);
        match classify_ip(ip) {
            IpCategory::Global => Ok(()),
            IpCategory::Private if self.allow_private || allow > AllowMatch::None => Ok(()),
            IpCategory::Private => Err(deny(format!("private address {ip}"))),
            IpCategory::Loopback if self.allow_private && allow == AllowMatch::Explicit => Ok(()),
            IpCategory::Loopback => Err(deny(format!("loopback address {ip}"))),
            IpCategory::Forbidden => {
                Err(deny(format!("reserved/link-local/metadata address {ip}")))
            }
        }
    }

    fn evaluate(&self, raw: &str) -> Result<Checked> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_URL_LEN {
            return Err(Error::invalid("URL is empty or too long"));
        }
        let url = Url::parse(raw).map_err(|e| Error::invalid(format!("invalid URL: {e}")))?;
        match url.scheme() {
            "http" | "https" => {}
            other => return Err(deny(format!("scheme {other:?} is not allowed"))),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(deny("credentials (userinfo) in URL are not allowed"));
        }
        let host = match url.host() {
            None => return Err(deny("URL has no host")),
            Some(Host::Ipv4(ip)) => NormHost::Ip(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => NormHost::Ip(IpAddr::V6(ip)),
            Some(Host::Domain(d)) => {
                let d = normalize_domain(d);
                if d.is_empty() {
                    return Err(deny("empty host"));
                }
                match d.parse::<IpAddr>() {
                    Ok(ip) => NormHost::Ip(ip),
                    Err(_) => NormHost::Domain(d),
                }
            }
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| deny("URL has no port"))?;
        if port == 0 {
            return Err(deny("port 0"));
        }
        let label = host.label();

        if self.deny_patterns().any(|p| p.matches_host(&host, port)) {
            return Err(deny(format!("host {label} is denied by policy")));
        }
        let allow = self
            .allow_patterns()
            .filter(|p| p.matches_host(&host, port))
            .map(|p| p.strength())
            .max()
            .unwrap_or(AllowMatch::None);

        match &host {
            NormHost::Domain(d) => {
                if METADATA_NAMES.contains(&d.as_str()) {
                    return Err(deny(format!("cloud metadata host {label}")));
                }
                let is_localhost =
                    LOCALHOST_NAMES.contains(&d.as_str()) || has_suffix(d, "localhost");
                if is_localhost && !(self.allow_private && allow == AllowMatch::Explicit) {
                    return Err(deny(format!("loopback host {label}")));
                }
                let internal =
                    !d.contains('.') || INTERNAL_SUFFIXES.iter().any(|s| has_suffix(d, s));
                if internal && !is_localhost && !self.allow_private && allow == AllowMatch::None {
                    return Err(deny(format!("internal host name {label}")));
                }
            }
            NormHost::Ip(ip) => self.check_ip(*ip, allow)?,
        }

        if !DEFAULT_PORTS.contains(&port) && allow == AllowMatch::None {
            return Err(deny(format!("port {port} on {label} is not allowed")));
        }
        Ok(Checked {
            url,
            host,
            port,
            allow,
        })
    }

    /// Validate a URL syntactically and by host policy (no DNS).
    pub fn check_url(&self, url: &str) -> Result<url::Url> {
        self.evaluate(url).map(|c| c.url)
    }

    /// `check_url` + resolve + verify every address. Returns the addresses
    /// the caller should connect to.
    pub async fn resolve_and_check(&self, url: &str) -> Result<(url::Url, Vec<SocketAddr>)> {
        self.resolve_and_check_with(url, |host, port| async move {
            let addrs =
                tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host.as_str(), port)))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS timeout")
                    })??;
            Ok::<Vec<SocketAddr>, std::io::Error>(addrs.collect())
        })
        .await
    }

    /// Like [`EgressPolicy::resolve_and_check`] with a caller-supplied
    /// resolver `(host, port) -> addresses` (custom DNS, tests). The resolver
    /// is not called for IP-literal hosts.
    pub async fn resolve_and_check_with<F, Fut>(
        &self,
        url: &str,
        resolve: F,
    ) -> Result<(url::Url, Vec<SocketAddr>)>
    where
        F: FnOnce(String, u16) -> Fut,
        Fut: Future<Output = std::io::Result<Vec<SocketAddr>>>,
    {
        let checked = self.evaluate(url)?;
        let label = checked.host.label();
        let mut addrs: Vec<SocketAddr> = match &checked.host {
            NormHost::Ip(ip) => vec![SocketAddr::new(*ip, checked.port)],
            NormHost::Domain(d) => resolve(d.clone(), checked.port)
                .await
                .map_err(|e| Error::other(format!("DNS resolution failed for {label}: {e}")))?,
        };
        let mut seen = std::collections::HashSet::new();
        addrs.retain(|a| seen.insert(*a));
        if addrs.is_empty() {
            return Err(Error::NotFound(format!("no addresses for {label}")));
        }
        if addrs.len() > MAX_RESOLVED {
            addrs.truncate(MAX_RESOLVED);
        }
        // Every address must pass: a single bad answer (DNS rebinding,
        // mixed public/private records) rejects the request.
        for addr in &mut addrs {
            self.check_ip(addr.ip(), checked.allow)
                .map_err(|e| Error::security(format!("{e} (resolved from {label})")))?;
            // Normalize IPv4-mapped answers so callers connect over IPv4,
            // and pin the port to the one that was checked.
            *addr = SocketAddr::new(addr.ip().to_canonical(), checked.port);
        }
        Ok((checked.url, addrs))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn strict() -> EgressPolicy {
        EgressPolicy::default()
    }

    fn private() -> EgressPolicy {
        EgressPolicy {
            allow_private: true,
            ..Default::default()
        }
    }

    #[test]
    fn ipv4_classification() {
        use IpCategory::*;
        for (a, c) in [
            ("8.8.8.8", Global),
            ("1.1.1.1", Global),
            ("93.184.216.34", Global),
            ("0.0.0.0", Forbidden),
            ("0.1.2.3", Forbidden),
            ("10.0.0.1", Private),
            ("10.255.255.255", Private),
            ("100.64.0.1", Private),
            ("100.127.255.255", Private),
            ("100.128.0.0", Global),
            ("100.63.255.255", Global),
            ("100.100.100.200", Forbidden),
            ("127.0.0.1", Loopback),
            ("127.255.255.254", Loopback),
            ("169.254.169.254", Forbidden),
            ("169.254.0.1", Forbidden),
            ("172.15.255.255", Global),
            ("172.16.0.1", Private),
            ("172.31.255.255", Private),
            ("172.32.0.0", Global),
            ("192.0.0.170", Forbidden),
            ("192.0.2.1", Forbidden),
            ("192.88.99.1", Forbidden),
            ("192.168.1.1", Private),
            ("198.18.0.1", Private),
            ("198.19.255.255", Private),
            ("198.51.100.7", Forbidden),
            ("203.0.113.9", Forbidden),
            ("224.0.0.1", Forbidden),
            ("239.255.255.250", Forbidden),
            ("240.0.0.1", Forbidden),
            ("255.255.255.255", Forbidden),
            ("223.255.255.255", Global),
        ] {
            assert_eq!(classify_ip(ip(a)), c, "{a}");
        }
    }

    #[test]
    fn ipv6_classification() {
        use IpCategory::*;
        for (a, c) in [
            ("2606:4700:4700::1111", Global),
            ("2001:4860:4860::8888", Global),
            ("::", Forbidden),
            ("::1", Loopback),
            ("::ffff:127.0.0.1", Loopback),
            ("::ffff:10.0.0.1", Private),
            ("::ffff:169.254.169.254", Forbidden),
            ("::ffff:8.8.8.8", Global),
            ("::ffff:0.0.0.0", Forbidden),
            ("::127.0.0.1", Forbidden),
            ("::8.8.8.8", Forbidden),
            ("::ffff:0:7f00:1", Forbidden),    // IPv4-translated
            ("64:ff9b::7f00:1", Loopback),     // NAT64 -> 127.0.0.1
            ("64:ff9b::a9fe:a9fe", Forbidden), // NAT64 -> 169.254.169.254
            ("64:ff9b::808:808", Global),      // NAT64 -> 8.8.8.8
            ("64:ff9b::a00:1", Private),       // NAT64 -> 10.0.0.1
            ("64:ff9b:1::808:808", Private),
            ("64:ff9b:1::7f00:1", Loopback),
            ("100::1", Forbidden),
            ("2001::1", Forbidden), // Teredo
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", Forbidden),
            ("2001:db8::1", Forbidden),
            ("2002:7f00:1::1", Forbidden), // 6to4 embedding 127.0.0.1
            ("3fff::1", Forbidden),
            ("5f00::1", Forbidden),
            ("fc00::1", Private),
            ("fd12:3456::1", Private),
            ("fd00:ec2::254", Forbidden),
            ("fe80::1", Forbidden),
            ("febf::1", Forbidden),
            ("fec0::1", Private),
            ("ff02::1", Forbidden),
            ("ff05::1:3", Forbidden),
            ("4000::1", Forbidden), // unallocated
            ("1::1", Forbidden),
        ] {
            assert_eq!(classify_ip(ip(a)), c, "{a}");
        }
    }

    #[test]
    fn is_ip_allowed_matrix() {
        let s = strict();
        assert!(s.is_ip_allowed(ip("8.8.8.8")));
        assert!(!s.is_ip_allowed(ip("10.0.0.1")));
        assert!(!s.is_ip_allowed(ip("127.0.0.1")));
        assert!(!s.is_ip_allowed(ip("169.254.169.254")));
        let p = private();
        assert!(p.is_ip_allowed(ip("10.0.0.1")));
        assert!(p.is_ip_allowed(ip("fd12::1")));
        assert!(!p.is_ip_allowed(ip("127.0.0.1"))); // loopback needs explicit allow
        assert!(!p.is_ip_allowed(ip("169.254.169.254")));
        assert!(!p.is_ip_allowed(ip("fd00:ec2::254")));
        assert!(!p.is_ip_allowed(ip("100.100.100.200")));
        let explicit = EgressPolicy {
            allow_hosts: vec!["127.0.0.1".into(), "10.9.0.0/16".into()],
            allow_private: true,
            ..Default::default()
        };
        assert!(explicit.is_ip_allowed(ip("127.0.0.1")));
        assert!(explicit.is_ip_allowed(ip("::ffff:127.0.0.1")));
        assert!(!explicit.is_ip_allowed(ip("127.0.0.2")));
        // CIDR allow lets a private range through without allow_private
        let cidr = EgressPolicy {
            allow_hosts: vec!["10.9.0.0/16".into()],
            ..Default::default()
        };
        assert!(cidr.is_ip_allowed(ip("10.9.1.1")));
        assert!(!cidr.is_ip_allowed(ip("10.8.1.1")));
        let denied = EgressPolicy {
            deny_hosts: vec!["8.8.0.0/16".into()],
            ..Default::default()
        };
        assert!(!denied.is_ip_allowed(ip("8.8.8.8")));
        assert!(!denied.is_ip_allowed(ip("::ffff:8.8.8.8")));
        assert!(denied.is_ip_allowed(ip("1.1.1.1")));
    }

    #[test]
    fn basic_public_urls_pass() {
        let s = strict();
        for u in [
            "https://example.com/",
            "http://example.com/path?q=1#frag",
            "https://EXAMPLE.com.",
            "http://example.com:443/",
            "https://example.com:80/",
            "https://8.8.8.8/",
            "https://[2606:4700:4700::1111]/",
            "https://bücher.de/",
        ] {
            assert!(s.check_url(u).is_ok(), "{u}");
        }
        assert_eq!(
            s.check_url("https://bücher.de/").unwrap().host_str(),
            Some("xn--bcher-kva.de")
        );
    }

    #[test]
    fn schemes_and_userinfo_rejected() {
        let s = strict();
        for u in [
            "ftp://example.com/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "javascript:alert(1)",
            "data:text/plain,hi",
            "ws://example.com/",
            "https://user@example.com/",
            "",
            "not a url",
            "//example.com/",
        ] {
            assert!(s.check_url(u).is_err(), "{u}");
        }
        // userinfo forms are assembled at runtime (no credential-shaped
        // literals in the source for secret scanners to trip on)
        for parts in [
            ["https://user", ":", "pass", "@example.com/"],
            ["https://", ":", "pass", "@example.com/"],
            ["http://127.0.0.1", ":", "80", "@evil.com/"],
        ] {
            let u = parts.concat();
            assert!(s.check_url(&u).is_err(), "{u}");
        }
        assert!(
            s.check_url(&format!("https://example.com/{}", "a".repeat(MAX_URL_LEN)))
                .is_err()
        );
    }

    #[test]
    fn loopback_and_numeric_host_forms_rejected() {
        let s = strict();
        for u in [
            "http://127.0.0.1/",
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0x7f.1/",
            "http://017700000001/",
            "http://0177.0.0.1/",
            "http://127.000.000.001/",
            "http://127.0.0.1./",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:7f00:1]/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
            "http://[64:ff9b::127.0.0.1]/",
            "http://[::127.0.0.1]/",
            "http://localhost/",
            "http://LOCALHOST/",
            "http://localhost./",
            "http://localhost.:8080/",
            "http://foo.localhost/",
            "http://a.b.localhost./",
            "http://localhost.localdomain/",
            "http://ip6-localhost/",
            "http://①②⑦.0.0.1/",
            "http://127。0。0。1/",
        ] {
            assert!(s.check_url(u).is_err(), "{u}");
        }
    }

    #[test]
    fn backslash_and_authority_confusion() {
        let s = strict();
        // WHATWG treats `\\` as `/` for http(s): the host is 127.0.0.1.
        for u in [
            "http:\\\\127.0.0.1\\x",
            "http:/\\127.0.0.1/",
            "http://127.0.0.1\\@evil.example/",
            "http://127.0.0.1#@evil.example/",
            "http://127.0.0.1?@evil.example/",
            " http://127.0.0.1/ ",
            "http://127.0.0.1\t/",
        ] {
            assert!(s.check_url(u).is_err(), "{u}");
        }
        // ...and the reverse resolves to the public host (same parser as reqwest)
        let u = s.check_url("http://evil.example.net\\@127.0.0.1/").unwrap();
        assert_eq!(u.host_str(), Some("evil.example.net"));
    }

    #[test]
    fn unspecified_metadata_and_special_rejected() {
        for policy in [strict(), private()] {
            for u in [
                "http://0.0.0.0/",
                "http://0/",
                "http://0.0.0.0:8080/",
                "http://[::]/",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::ffff:169.254.169.254]/",
                "http://[64:ff9b::a9fe:a9fe]/",
                "http://[fd00:ec2::254]/",
                "http://100.100.100.200/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://METADATA.GOOGLE.INTERNAL./",
                "http://metadata/",
                "http://instance-data/",
                "http://255.255.255.255/",
                "http://224.0.0.1/",
                "http://[ff02::1]/",
                "http://[fe80::1]/",
                "http://192.0.2.1/",
                "http://[2001:db8::1]/",
                "http://[2002:7f00:1::]/",
                "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/",
            ] {
                assert!(
                    policy.check_url(u).is_err(),
                    "{u} allow_private={}",
                    policy.allow_private
                );
            }
        }
    }

    #[test]
    fn private_ranges_need_allow_private() {
        let s = strict();
        let p = private();
        for u in [
            "http://10.0.0.5/",
            "http://172.16.3.4/",
            "http://192.168.1.1/",
            "http://100.64.1.1/",
            "http://[fd12:3456::1]/",
            "http://[::ffff:10.0.0.5]/",
            "http://ti.corp.internal/",
            "http://printer.local/",
            "http://router.home.arpa/",
            "http://nas.lan/",
            "http://intranet/",
            "http://jira.corp/",
            "http://something.onion/",
        ] {
            assert!(s.check_url(u).is_err(), "strict {u}");
            assert!(p.check_url(u).is_ok(), "private {u}");
        }
        // localhost stays denied with only allow_private
        assert!(p.check_url("http://localhost/").is_err());
        assert!(p.check_url("http://127.0.0.1/").is_err());
    }

    #[test]
    fn explicit_loopback_allow_needs_allow_private() {
        let mut policy = EgressPolicy {
            allow_hosts: vec!["localhost".into(), "[::1]:8080".into()],
            ..Default::default()
        };
        assert!(policy.check_url("http://localhost:3001/").is_err());
        policy.allow_private = true;
        assert!(policy.check_url("http://localhost:3001/").is_ok());
        assert!(policy.check_url("http://[::1]:8080/").is_ok());
        assert!(policy.check_url("http://[::1]:8081/").is_err());
        assert!(policy.check_url("http://127.0.0.1/").is_err());
        // wildcard patterns never grant loopback
        let wild = EgressPolicy {
            allow_hosts: vec!["*.localhost".into()],
            allow_private: true,
            ..Default::default()
        };
        assert!(wild.check_url("http://app.localhost/").is_err());
    }

    #[test]
    fn ports() {
        let s = strict();
        assert!(s.check_url("https://example.com:8443/").is_err());
        assert!(s.check_url("http://example.com:22/").is_err());
        assert!(s.check_url("http://example.com:0/").is_err());
        let allow = EgressPolicy {
            allow_hosts: vec!["*.example.com".into(), "ti.example.org:8443".into()],
            ..Default::default()
        };
        assert!(allow.check_url("https://api.example.com:8443/").is_ok());
        assert!(allow.check_url("https://example.com:9000/").is_ok());
        assert!(allow.check_url("https://ti.example.org:8443/").is_ok());
        assert!(allow.check_url("https://ti.example.org:8444/").is_err());
        // the default port stays usable for a public host
        assert!(allow.check_url("https://ti.example.org/").is_ok());
    }

    #[test]
    fn deny_list_wins() {
        let policy = EgressPolicy {
            allow_hosts: vec!["*.evil.com".into()],
            deny_hosts: vec!["*.evil.com".into(), "bad.org".into(), "1.2.3.4".into()],
            allow_private: false,
        };
        assert!(policy.check_url("https://a.evil.com/").is_err());
        assert!(policy.check_url("https://evil.com/").is_err());
        assert!(policy.check_url("https://EVIL.COM./").is_err());
        assert!(policy.check_url("https://notevil.com/").is_ok());
        assert!(policy.check_url("https://bad.org/").is_err());
        assert!(policy.check_url("https://sub.bad.org/").is_ok());
        assert!(policy.check_url("http://1.2.3.4/").is_err());
        assert!(policy.check_url("http://[::ffff:1.2.3.4]/").is_err());
    }

    #[test]
    fn allowlisted_internal_host() {
        let policy = EgressPolicy {
            allow_hosts: vec!["ti.corp.internal".into()],
            ..Default::default()
        };
        assert!(policy.check_url("https://ti.corp.internal/api").is_ok());
        assert!(policy.check_url("https://other.corp.internal/api").is_err());
    }

    #[test]
    fn pattern_parsing() {
        assert!(parse_pattern("").is_none());
        assert!(parse_pattern("   ").is_none());
        assert!(parse_pattern("*.").is_none());
        assert!(parse_pattern("[::1").is_none());
        assert!(parse_pattern("host:notaport").is_none());
        assert!(matches!(
            parse_pattern("10.0.0.0/8"),
            Some(HostPattern::Net(_))
        ));
        assert!(matches!(
            parse_pattern("127.1"),
            Some(HostPattern::Ip { .. })
        ));
        assert!(matches!(
            parse_pattern(".example.com"),
            Some(HostPattern::Suffix { .. })
        ));
        assert!(matches!(
            parse_pattern("Example.COM.:8443"),
            Some(HostPattern::Exact { ref host, port: Some(8443) }) if host == "example.com"
        ));
        assert!(matches!(
            parse_pattern("[::1]:8080"),
            Some(HostPattern::Ip {
                port: Some(8080),
                ..
            })
        ));
        assert!(matches!(
            parse_pattern("::1"),
            Some(HostPattern::Ip { port: None, .. })
        ));
    }

    #[test]
    fn suffix_matching_is_label_aligned() {
        assert!(has_suffix("a.example.com", "example.com"));
        assert!(has_suffix("example.com", "example.com"));
        assert!(!has_suffix("badexample.com", "example.com"));
        assert!(!has_suffix("com", "example.com"));
    }

    #[test]
    fn from_env_parses_lists() {
        let env = talon_core::env::EnvFile::from_str_content(
            "TALON_EGRESS_ALLOW=ti.example.com, *.Corp.example\nTALON_EGRESS_DENY=bad.com;evil.org\nTALON_EGRESS_ALLOW_PRIVATE=true\n",
        );
        if std::env::var("TALON_EGRESS_ALLOW").is_err()
            && std::env::var("TALON_EGRESS_DENY").is_err()
            && std::env::var("TALON_EGRESS_ALLOW_PRIVATE").is_err()
        {
            let p = EgressPolicy::from_env(&env);
            assert_eq!(p.allow_hosts, vec!["ti.example.com", "*.corp.example"]);
            assert_eq!(p.deny_hosts, vec!["bad.com", "evil.org"]);
            assert!(p.allow_private);
            let empty = EgressPolicy::from_env(&talon_core::env::EnvFile::from_str_content(""));
            assert!(empty.allow_hosts.is_empty() && !empty.allow_private);
        }
    }

    fn fake(
        addrs: &'static [&'static str],
    ) -> impl FnOnce(String, u16) -> std::future::Ready<std::io::Result<Vec<SocketAddr>>> {
        move |_host, port| {
            std::future::ready(Ok(addrs
                .iter()
                .map(|a| SocketAddr::new(a.parse().unwrap(), port))
                .collect()))
        }
    }

    #[tokio::test]
    async fn resolve_checks_every_address() {
        let s = strict();
        let (url, addrs) = s
            .resolve_and_check_with(
                "https://example.com/x",
                fake(&["93.184.216.34", "2606:2800:220:1::1"]),
            )
            .await
            .unwrap();
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().all(|a| a.port() == 443));
        // DNS rebinding: one bad answer poisons the lot
        assert!(
            s.resolve_and_check_with(
                "https://rebind.example.com/",
                fake(&["93.184.216.34", "127.0.0.1"])
            )
            .await
            .is_err()
        );
        for bad in [
            &["169.254.169.254"][..],
            &["::ffff:10.0.0.1"],
            &["0.0.0.0"],
            &["fd00:ec2::254"],
        ] {
            let addrs: &'static [&'static str] = bad;
            assert!(
                s.resolve_and_check_with("https://x.example.com/", fake(addrs))
                    .await
                    .is_err()
            );
        }
        // empty answer
        assert!(
            s.resolve_and_check_with("https://x.example.com/", fake(&[]))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn resolve_private_answers_follow_policy() {
        assert!(
            strict()
                .resolve_and_check_with("https://ti.example.com/", fake(&["10.1.2.3"]))
                .await
                .is_err()
        );
        assert!(
            private()
                .resolve_and_check_with("https://ti.example.com/", fake(&["10.1.2.3"]))
                .await
                .is_ok()
        );
        let allow = EgressPolicy {
            allow_hosts: vec!["ti.example.com".into()],
            ..Default::default()
        };
        assert!(
            allow
                .resolve_and_check_with("https://ti.example.com/", fake(&["10.1.2.3"]))
                .await
                .is_ok()
        );
        // allowlisting a name never unlocks loopback without allow_private
        assert!(
            allow
                .resolve_and_check_with("https://ti.example.com/", fake(&["127.0.0.1"]))
                .await
                .is_err()
        );
        // a deny CIDR applies to resolved addresses
        let deny = EgressPolicy {
            deny_hosts: vec!["93.184.0.0/16".into()],
            ..Default::default()
        };
        assert!(
            deny.resolve_and_check_with("https://example.com/", fake(&["93.184.216.34"]))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn resolve_normalizes_mapped_answers_and_skips_dns_for_ips() {
        let (_, addrs) = strict()
            .resolve_and_check_with(
                "https://example.com/",
                fake(&["::ffff:93.184.216.34", "93.184.216.34"]),
            )
            .await
            .unwrap();
        assert_eq!(
            addrs,
            vec!["93.184.216.34:443".parse::<SocketAddr>().unwrap(); 2]
        );
        let (_, addrs) = strict()
            .resolve_and_check_with("http://8.8.8.8/", |_h: String, _p: u16| async {
                Err::<Vec<SocketAddr>, _>(std::io::Error::other("resolver must not be called"))
            })
            .await
            .unwrap();
        assert_eq!(addrs, vec!["8.8.8.8:80".parse::<SocketAddr>().unwrap()]);
        let err = strict()
            .resolve_and_check_with("http://example.com/", |_h: String, _p: u16| async {
                Err::<Vec<SocketAddr>, _>(std::io::Error::other("nxdomain"))
            })
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn real_resolver_with_hosts_file() {
        // `localhost` resolves via /etc/hosts without network access.
        let policy = EgressPolicy {
            allow_hosts: vec!["localhost".into()],
            allow_private: true,
            ..Default::default()
        };
        if let Ok((_, addrs)) = policy.resolve_and_check("http://localhost:3001/").await {
            assert!(
                addrs
                    .iter()
                    .all(|a| a.ip().is_loopback() && a.port() == 3001)
            );
        }
        assert!(
            strict()
                .resolve_and_check("http://localhost/")
                .await
                .is_err()
        );
        assert!(
            strict()
                .resolve_and_check("http://10.0.0.1/")
                .await
                .is_err()
        );
        let (_, addrs) = strict().resolve_and_check("http://1.1.1.1/").await.unwrap();
        assert_eq!(addrs.len(), 1);
    }
}
