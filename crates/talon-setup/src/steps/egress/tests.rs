use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::*;
use crate::runner::mock::MockRunner;
use crate::steps::run_step_by_name;

fn entry(s: &str) -> AllowEntry {
    AllowEntry::parse(s).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn private_policy() -> EgressPolicy {
    EgressPolicy::new(Vec::new(), 3001, false)
}

/// Allowlist with an IPv4 host:port, an IPv4 network and an IPv6 net:port.
fn allowlist_policy() -> EgressPolicy {
    EgressPolicy::new(
        vec![
            entry("10.0.0.5:9200"),
            entry("10.1.0.0/16"),
            entry("[fd00:1::/64]:443"),
        ],
        3101,
        false,
    )
}

fn sections(policy: &EgressPolicy, action: EgressAction) -> Vec<FwSection> {
    match egress_plan(policy, Backend::Iptables, action) {
        FirewallPlan::Iptables { sections } => sections,
        FirewallPlan::Nft { .. } => panic!("expected iptables plan"),
    }
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

// --- addresses ------------------------------------------------------------

#[test]
fn cidr_parsing_normalizes_and_validates() {
    assert_eq!(Cidr::parse("10.1.2.3/8").unwrap().to_string(), "10.0.0.0/8");
    assert_eq!(Cidr::parse("10.1.2.3").unwrap().to_string(), "10.1.2.3/32");
    assert_eq!(
        Cidr::parse("fd00:ec2::254").unwrap().to_string(),
        "fd00:ec2::254/128"
    );
    assert_eq!(
        Cidr::parse("fd00:1:2::/33").unwrap().to_string(),
        "fd00:1::/33"
    );
    assert_eq!(Cidr::parse("0.0.0.0/0").unwrap().prefix(), 0);
    for bad in [
        "10.0.0.0/33",
        "fe80::/129",
        "10.0.0.0/",
        "10.0.0.0/a",
        "10.0.0.0/+8",
        "10.0.0.256",
        "/8",
        "",
        "host.example",
        "fe80::1%eth0",
        "10.0.0.0/0008",
    ] {
        assert!(Cidr::parse(bad).is_none(), "{bad}");
    }
    // The constants are already normalized.
    for c in METADATA_DESTINATIONS
        .iter()
        .chain(PRIVATE_DESTINATIONS.iter())
    {
        assert_eq!(Cidr::parse(&c.to_string()), Some(*c));
    }
}

#[test]
fn cidr_contains_respects_family_and_prefix() {
    let net = Cidr::parse("172.16.0.0/12").unwrap();
    assert!(net.contains(ip("172.31.255.255")));
    assert!(!net.contains(ip("172.32.0.0")));
    assert!(!net.contains(ip("::ffff:172.16.0.1")));
    let all = Cidr::parse("0.0.0.0/0").unwrap();
    assert!(all.contains(ip("8.8.8.8")));
    assert!(!all.contains(ip("2001:db8::1")));
    let ula = Cidr::parse("fc00::/7").unwrap();
    assert!(ula.contains(ip("fd00:ec2::254")));
    assert!(!ula.contains(ip("fe80::1")));
}

#[test]
fn allow_entry_syntax() {
    for (input, display, port) in [
        ("10.0.0.5", "10.0.0.5/32", None),
        ("10.0.0.5:9200", "10.0.0.5/32:9200", Some(9200)),
        ("10.0.0.0/24", "10.0.0.0/24", None),
        ("10.0.0.9/24:3306", "10.0.0.0/24:3306", Some(3306)),
        (" 192.168.1.1:53 ", "192.168.1.1/32:53", Some(53)),
        ("[10.0.0.5]:80", "10.0.0.5/32:80", Some(80)),
        ("fd00::5", "fd00::5/128", None),
        // A bare IPv6 address never carries a port.
        ("fd00::5:443", "fd00::5:443/128", None),
        ("[fd00::5]:443", "[fd00::5/128]:443", Some(443)),
        ("[fd00:1::/64]:443", "[fd00:1::/64]:443", Some(443)),
        ("fd00:1::/64:443", "[fd00:1::/64]:443", Some(443)),
        ("[2001:db8::/32]", "2001:db8::/32", None),
    ] {
        let e = AllowEntry::parse(input).unwrap_or_else(|err| panic!("{input}: {err}"));
        assert_eq!(e.to_string(), display, "{input}");
        assert_eq!(e.port, port, "{input}");
        // Display round-trips.
        assert_eq!(AllowEntry::parse(&e.to_string()), Ok(e), "{input}");
    }
}

#[test]
fn allow_entry_rejects_garbage() {
    for bad in [
        "",
        "10.0.0.5:",
        "10.0.0.5:0",
        "10.0.0.5:65536",
        "10.0.0.5:http",
        "10.0.0.5:-1",
        "10.0.0.5/24:",
        "10.0.0.0/40:80",
        "[fd00::5]443",
        "[fd00::5",
        "fd00::zz",
        "siem.internal:9200",
        "10.0.0.5;rm -rf /",
        "$(id)",
        "10.0.0.5 :80",
    ] {
        let err = AllowEntry::parse(bad).unwrap_err();
        assert!(err.contains("--allow"), "{bad}: {err}");
    }
}

#[test]
fn allow_entry_matching() {
    let e = entry("10.0.0.0/24:9200");
    assert!(e.matches(ip("10.0.0.7"), 9200));
    assert!(!e.matches(ip("10.0.0.7"), 9201));
    assert!(!e.matches(ip("10.0.1.7"), 9200));
    assert!(entry("10.0.0.0/24").matches(ip("10.0.0.7"), 1));
}

// --- policy ---------------------------------------------------------------

#[test]
fn policy_mode_selection_and_dedup() {
    assert_eq!(private_policy().mode, EgressMode::BlockPrivate);
    assert_eq!(allowlist_policy().mode, EgressMode::Allowlist);
    let keep = EgressPolicy::new(vec![entry("10.0.0.5")], 3001, true);
    assert_eq!(keep.mode, EgressMode::BlockPrivate);
    // --keep-internet without entries is plain block-private.
    assert_eq!(
        EgressPolicy::new(Vec::new(), 3001, true),
        EgressPolicy::new(Vec::new(), 3001, false)
    );
    let dup = EgressPolicy::new(
        vec![entry("10.0.0.5"), entry("10.0.0.5/32"), entry("10.0.0.6")],
        3001,
        false,
    );
    assert_eq!(dup.allow, vec![entry("10.0.0.5"), entry("10.0.0.6")]);
    assert_eq!(EgressMode::Allowlist.as_str(), "allowlist");
    assert_eq!(EgressMode::BlockPrivate.as_str(), "block-private");
}

#[test]
fn block_private_keeps_internet_and_blocks_internal() {
    let p = private_policy();
    for public in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "172.32.0.1"] {
        assert!(p.permits(ip(public), 443), "{public}");
    }
    for blocked in [
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "fe80::1",
        "10.20.30.40",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.254",
        "fd12:3456::1",
    ] {
        assert!(!p.permits(ip(blocked), 443), "{blocked}");
    }
    // Allow entries punch holes, port-specific ones only for their port.
    let p = EgressPolicy::new(vec![entry("10.0.0.5:9200")], 3001, true);
    assert!(p.permits(ip("10.0.0.5"), 9200));
    assert!(!p.permits(ip("10.0.0.5"), 22));
    assert!(p.permits(ip("8.8.8.8"), 53));
}

#[test]
fn allowlist_blocks_everything_else_and_metadata_always() {
    let p = allowlist_policy();
    assert!(p.permits(ip("10.0.0.5"), 9200));
    assert!(!p.permits(ip("10.0.0.5"), 9300));
    assert!(p.permits(ip("10.1.200.3"), 22));
    assert!(p.permits(ip("fd00:1::7"), 443));
    assert!(!p.permits(ip("fd00:1::7"), 80));
    assert!(!p.permits(ip("8.8.8.8"), 443));
    assert!(!p.permits(ip("2001:4860:4860::8888"), 443));
    // Metadata can never be allowed, not even explicitly or via 0.0.0.0/0.
    let p = EgressPolicy::new(
        vec![entry("169.254.169.254"), entry("0.0.0.0/0"), entry("::/0")],
        3001,
        false,
    );
    assert!(!p.permits(ip("169.254.169.254"), 80));
    assert!(!p.permits(ip("fd00:ec2::254"), 80));
    assert!(!p.permits(ip("fe80::1"), 80));
    assert!(p.permits(ip("8.8.8.8"), 80));
}

// --- nftables -------------------------------------------------------------

#[test]
fn nft_ruleset_block_private_exact() {
    let expected = "add table inet talon_egress\n\
delete table inet talon_egress\n\
table inet talon_egress {\n\
\tchain forward {\n\
\t\ttype filter hook forward priority -10; policy accept;\n\
\t\tiifname \"br-talon\" jump agent_egress\n\
\t}\n\
\tchain agent_egress {\n\
\t\tip daddr 169.254.0.0/16 counter drop\n\
\t\tip6 daddr { fe80::/10, fd00:ec2::254/128 } counter drop\n\
\t\tct state established,related accept\n\
\t\tip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } counter drop\n\
\t\tip6 daddr fc00::/7 counter drop\n\
\t}\n\
\tchain input {\n\
\t\ttype filter hook input priority -10; policy accept;\n\
\t\tiifname \"br-talon\" jump agent_input\n\
\t}\n\
\tchain agent_input {\n\
\t\tct state established,related accept\n\
\t\ttcp dport 3001 accept\n\
\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept\n\
\t\tcounter drop\n\
\t}\n\
}\n";
    assert_eq!(
        nft_ruleset(&private_policy(), EgressAction::Install),
        expected
    );
}

#[test]
fn nft_ruleset_allowlist_exact() {
    let expected = "add table inet talon_egress\n\
delete table inet talon_egress\n\
table inet talon_egress {\n\
\tchain forward {\n\
\t\ttype filter hook forward priority -10; policy accept;\n\
\t\tiifname \"br-talon\" jump agent_egress\n\
\t}\n\
\tchain agent_egress {\n\
\t\tip daddr 169.254.0.0/16 counter drop\n\
\t\tip6 daddr { fe80::/10, fd00:ec2::254/128 } counter drop\n\
\t\tct state established,related accept\n\
\t\tip daddr 10.0.0.5/32 tcp dport 9200 accept\n\
\t\tip daddr 10.0.0.5/32 udp dport 9200 accept\n\
\t\tip daddr 10.1.0.0/16 accept\n\
\t\tip6 daddr fd00:1::/64 tcp dport 443 accept\n\
\t\tip6 daddr fd00:1::/64 udp dport 443 accept\n\
\t\tcounter drop\n\
\t}\n\
\tchain input {\n\
\t\ttype filter hook input priority -10; policy accept;\n\
\t\tiifname \"br-talon\" jump agent_input\n\
\t}\n\
\tchain agent_input {\n\
\t\tct state established,related accept\n\
\t\ttcp dport 3101 accept\n\
\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept\n\
\t\tcounter drop\n\
\t}\n\
}\n";
    assert_eq!(
        nft_ruleset(&allowlist_policy(), EgressAction::Install),
        expected
    );
}

#[test]
fn nft_block_private_with_allow_entries_puts_holes_before_drops() {
    let p = EgressPolicy::new(vec![entry("10.0.0.5:9200")], 3001, true);
    assert_eq!(
        nft_egress_rules(&p),
        vec![
            "ip daddr 169.254.0.0/16 counter drop",
            "ip6 daddr { fe80::/10, fd00:ec2::254/128 } counter drop",
            "ct state established,related accept",
            "ip daddr 10.0.0.5/32 tcp dport 9200 accept",
            "ip daddr 10.0.0.5/32 udp dport 9200 accept",
            "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } counter drop",
            "ip6 daddr fc00::/7 counter drop",
        ]
    );
}

#[test]
fn nft_uninstall_exact() {
    assert_eq!(
        nft_ruleset(&allowlist_policy(), EgressAction::Uninstall),
        "add table inet talon_egress\ndelete table inet talon_egress\n"
    );
}

// --- iptables -------------------------------------------------------------

const V4_RELOAD: [&str; 3] = [
    "iptables -w -N DOCKER-USER 2>/dev/null || true",
    "iptables -w -I DOCKER-USER 1 -i br-talon -m comment --comment talon-egress-reload -j DROP",
    "iptables -w -I INPUT 1 -i br-talon -m comment --comment talon-egress-reload -j DROP",
];

const V4_HOOKS: [&str; 4] = [
    "iptables -w -C DOCKER-USER -i br-talon -m comment --comment talon-egress -j TALON-EGRESS 2>/dev/null || iptables -w -I DOCKER-USER 2 -i br-talon -m comment --comment talon-egress -j TALON-EGRESS",
    "iptables -w -C INPUT -i br-talon -m comment --comment talon-egress -j TALON-INPUT 2>/dev/null || iptables -w -I INPUT 2 -i br-talon -m comment --comment talon-egress -j TALON-INPUT",
    "while iptables -w -D DOCKER-USER -i br-talon -m comment --comment talon-egress-reload -j DROP 2>/dev/null; do :; done",
    "while iptables -w -D INPUT -i br-talon -m comment --comment talon-egress-reload -j DROP 2>/dev/null; do :; done",
];

#[test]
fn iptables_ipv4_block_private_exact() {
    let s = sections(&private_policy(), EgressAction::Install);
    let mut expected = vec!["# --- IPv4 (iptables) ---"];
    expected.extend(V4_RELOAD);
    expected.extend([
        "iptables -w -N TALON-EGRESS 2>/dev/null || true",
        "iptables -w -F TALON-EGRESS",
        "iptables -w -A TALON-EGRESS -d 169.254.0.0/16 -j DROP",
        "iptables -w -A TALON-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
        "iptables -w -A TALON-EGRESS -d 10.0.0.0/8 -j DROP",
        "iptables -w -A TALON-EGRESS -d 172.16.0.0/12 -j DROP",
        "iptables -w -A TALON-EGRESS -d 192.168.0.0/16 -j DROP",
        "iptables -w -A TALON-EGRESS -d 100.64.0.0/10 -j DROP",
        "iptables -w -N TALON-INPUT 2>/dev/null || true",
        "iptables -w -F TALON-INPUT",
        "iptables -w -A TALON-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "iptables -w -A TALON-INPUT -p tcp --dport 3001 -j ACCEPT",
        "iptables -w -A TALON-INPUT -j DROP",
    ]);
    expected.extend(V4_HOOKS);
    assert_eq!(render_section(&s[0]), expected);
    assert_eq!(s[0].guard, None);
}

#[test]
fn iptables_ipv6_block_private_exact() {
    let s = sections(&private_policy(), EgressAction::Install);
    assert_eq!(s.len(), 2);
    let expected = vec![
        "# --- IPv6 (ip6tables) ---",
        "if ip6tables -w -n -L INPUT >/dev/null 2>&1; then",
        "  ip6tables -w -N DOCKER-USER 2>/dev/null || true",
        "  ip6tables -w -I DOCKER-USER 1 -i br-talon -m comment --comment talon-egress-reload -j DROP",
        "  ip6tables -w -I INPUT 1 -i br-talon -m comment --comment talon-egress-reload -j DROP",
        "  ip6tables -w -N TALON-EGRESS 2>/dev/null || true",
        "  ip6tables -w -F TALON-EGRESS",
        "  ip6tables -w -A TALON-EGRESS -d fe80::/10 -j DROP",
        "  ip6tables -w -A TALON-EGRESS -d fd00:ec2::254/128 -j DROP",
        "  ip6tables -w -A TALON-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
        "  ip6tables -w -A TALON-EGRESS -d fc00::/7 -j DROP",
        "  ip6tables -w -N TALON-INPUT 2>/dev/null || true",
        "  ip6tables -w -F TALON-INPUT",
        "  ip6tables -w -A TALON-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "  ip6tables -w -A TALON-INPUT -p tcp --dport 3001 -j ACCEPT",
        "  ip6tables -w -A TALON-INPUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT",
        "  ip6tables -w -A TALON-INPUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT",
        "  ip6tables -w -A TALON-INPUT -j DROP",
        "  ip6tables -w -C DOCKER-USER -i br-talon -m comment --comment talon-egress -j TALON-EGRESS 2>/dev/null || ip6tables -w -I DOCKER-USER 2 -i br-talon -m comment --comment talon-egress -j TALON-EGRESS",
        "  ip6tables -w -C INPUT -i br-talon -m comment --comment talon-egress -j TALON-INPUT 2>/dev/null || ip6tables -w -I INPUT 2 -i br-talon -m comment --comment talon-egress -j TALON-INPUT",
        "  while ip6tables -w -D DOCKER-USER -i br-talon -m comment --comment talon-egress-reload -j DROP 2>/dev/null; do :; done",
        "  while ip6tables -w -D INPUT -i br-talon -m comment --comment talon-egress-reload -j DROP 2>/dev/null; do :; done",
        "else",
        "  echo 'talon-egress: IPv6 (ip6tables) unavailable, rules skipped' >&2",
        "fi",
    ];
    assert_eq!(render_section(&s[1]), expected);
}

#[test]
fn iptables_allowlist_rules_exact() {
    let s = sections(&allowlist_policy(), EgressAction::Install);
    let egress_rules = |section: &FwSection| -> Vec<String> {
        section
            .steps
            .iter()
            .map(render_step)
            .filter(|l| l.contains(" -A TALON-EGRESS ") || l.contains(" -A TALON-INPUT "))
            .collect()
    };
    assert_eq!(
        egress_rules(&s[0]),
        vec![
            "iptables -w -A TALON-EGRESS -d 169.254.0.0/16 -j DROP",
            "iptables -w -A TALON-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
            "iptables -w -A TALON-EGRESS -d 10.0.0.5/32 -p tcp --dport 9200 -j RETURN",
            "iptables -w -A TALON-EGRESS -d 10.0.0.5/32 -p udp --dport 9200 -j RETURN",
            "iptables -w -A TALON-EGRESS -d 10.1.0.0/16 -j RETURN",
            "iptables -w -A TALON-EGRESS -j DROP",
            "iptables -w -A TALON-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "iptables -w -A TALON-INPUT -p tcp --dport 3101 -j ACCEPT",
            "iptables -w -A TALON-INPUT -j DROP",
        ]
    );
    assert_eq!(
        egress_rules(&s[1]),
        vec![
            "ip6tables -w -A TALON-EGRESS -d fe80::/10 -j DROP",
            "ip6tables -w -A TALON-EGRESS -d fd00:ec2::254/128 -j DROP",
            "ip6tables -w -A TALON-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
            "ip6tables -w -A TALON-EGRESS -d fd00:1::/64 -p tcp --dport 443 -j RETURN",
            "ip6tables -w -A TALON-EGRESS -d fd00:1::/64 -p udp --dport 443 -j RETURN",
            "ip6tables -w -A TALON-EGRESS -j DROP",
            "ip6tables -w -A TALON-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "ip6tables -w -A TALON-INPUT -p tcp --dport 3101 -j ACCEPT",
            "ip6tables -w -A TALON-INPUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT",
            "ip6tables -w -A TALON-INPUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT",
            "ip6tables -w -A TALON-INPUT -j DROP",
        ]
    );
    // Allowed traffic RETURNs (Docker's isolation/ICC rules still apply);
    // nothing in the forward chain ACCEPTs.
    for section in &s {
        for step in &section.steps {
            let line = render_step(step);
            if line.contains("TALON-EGRESS -") && line.contains(" -A ") {
                assert!(!line.ends_with("-j ACCEPT"), "{line}");
            }
        }
    }
}

#[test]
fn iptables_uninstall_exact() {
    let s = sections(&allowlist_policy(), EgressAction::Uninstall);
    assert_eq!(
        render_section(&s[0]),
        vec![
            "# --- IPv4 (iptables) ---",
            "while iptables -w -D DOCKER-USER -i br-talon -m comment --comment talon-egress -j TALON-EGRESS 2>/dev/null; do :; done",
            "while iptables -w -D INPUT -i br-talon -m comment --comment talon-egress -j TALON-INPUT 2>/dev/null; do :; done",
            "while iptables -w -D DOCKER-USER -i br-talon -m comment --comment talon-egress-reload -j DROP 2>/dev/null; do :; done",
            "while iptables -w -D INPUT -i br-talon -m comment --comment talon-egress-reload -j DROP 2>/dev/null; do :; done",
            "iptables -w -F TALON-EGRESS 2>/dev/null || true",
            "iptables -w -X TALON-EGRESS 2>/dev/null || true",
            "iptables -w -F TALON-INPUT 2>/dev/null || true",
            "iptables -w -X TALON-INPUT 2>/dev/null || true",
        ]
    );
    let v6 = render_section(&s[1]);
    assert_eq!(v6[1], "if ip6tables -w -n -L INPUT >/dev/null 2>&1; then");
    assert!(v6.contains(&"  ip6tables -w -X TALON-INPUT 2>/dev/null || true".to_string()));
    assert!(!v6.iter().any(|l| l.contains(" -A ")));
}

// --- scripts --------------------------------------------------------------

fn all_scripts() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, policy) in [
        ("private", private_policy()),
        ("allowlist", allowlist_policy()),
    ] {
        for backend in [Backend::Nft, Backend::Iptables] {
            for action in [EgressAction::Install, EgressAction::Uninstall] {
                out.push((
                    format!("{name}-{}-{}", backend.as_str(), action.as_str()),
                    render_script(&policy, backend, action),
                ));
            }
        }
    }
    out
}

#[test]
fn scripts_are_wrapped_and_end_with_exit() {
    for (name, script) in all_scripts() {
        assert!(script.starts_with("#!/bin/sh\n# talon-egress: "), "{name}");
        assert!(script.contains("\nset -eu\n"), "{name}");
        assert!(script.ends_with("\nexit 0\n"), "{name}");
        // Every line before `set -eu` is a comment.
        let head: Vec<&str> = script
            .split("\nset -eu\n")
            .next()
            .unwrap()
            .lines()
            .collect();
        assert!(head.iter().all(|l| l.starts_with('#')), "{name}");
    }
    let nft = render_script(&private_policy(), Backend::Nft, EgressAction::Install);
    let body = format!(
        "nft -f - <<'TALON_EGRESS_RULES'\n{}TALON_EGRESS_RULES\n\nexit 0\n",
        nft_ruleset(&private_policy(), EgressAction::Install)
    );
    assert!(nft.ends_with(&body), "{nft}");
}

#[test]
fn scripts_are_valid_posix_sh() {
    let dir = tempfile::tempdir().unwrap();
    for (name, script) in all_scripts() {
        let path = dir.path().join(format!("{name}.sh"));
        std::fs::write(&path, &script).unwrap();
        let out = std::process::Command::new("sh")
            .arg("-n")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn script_header_documents_mode_and_trade_off() {
    let script = render_script(&allowlist_policy(), Backend::Nft, EgressAction::Install);
    let header: Vec<&str> = lines(&script)
        .into_iter()
        .take_while(|l| *l != "set -eu")
        .collect();
    let text = header.join("\n");
    assert!(text.contains("Mode allowlist"), "{text}");
    assert!(text.contains("SIEM, MySQL, Wazuh and CoPilot"), "{text}");
    assert!(text.contains("169.254.169.254"), "{text}");
    assert!(text.contains("only tcp/3101 (LLM gateway)"), "{text}");
    assert!(text.contains("#   10.0.0.5/32:9200\n#   10.1.0.0/16\n#   [fd00:1::/64]:443"));
    assert!(text.contains("talon setup egress --uninstall --apply --nft"));

    let script = render_script(&private_policy(), Backend::Iptables, EgressAction::Install);
    assert!(script.contains("# Mode block-private: internet egress is kept"));
    assert!(script.contains("# Allowed destinations: none"));
    assert!(script.contains("--uninstall --apply --iptables"));

    let script = render_script(&private_policy(), Backend::Nft, EgressAction::Uninstall);
    assert!(script.contains("# talon-egress: remove the firewall rules"));
    assert!(!script.contains("Mode "));
}

// --- arguments ------------------------------------------------------------

fn parse(args: &[&str]) -> Result<EgressOptions, ArgError> {
    EgressOptions::from_args(&StepArgs::new(args.iter().copied()), 3001)
}

#[test]
fn options_parse_everything() {
    let o = parse(&[
        "--apply",
        "--iptables",
        "--allow",
        "10.0.0.5:9200,10.0.0.6:3306",
        "--allow",
        "[fd00::7]:55000",
        "--gateway-port",
        "3101",
        "--keep-internet",
    ])
    .unwrap();
    assert!(o.apply);
    assert_eq!(o.backend, Some(Backend::Iptables));
    assert_eq!(o.action, EgressAction::Install);
    assert_eq!(o.gateway_port, 3101);
    assert_eq!(
        o.allow,
        vec![
            entry("10.0.0.5:9200"),
            entry("10.0.0.6:3306"),
            entry("[fd00::7]:55000")
        ]
    );
    assert!(o.keep_internet);
    assert_eq!(o.policy().mode, EgressMode::BlockPrivate);
    assert_eq!(
        o.apply_args(Backend::Iptables),
        vec![
            "--apply",
            "--iptables",
            "--gateway-port",
            "3101",
            "--allow",
            "10.0.0.5/32:9200",
            "--allow",
            "10.0.0.6/32:3306",
            "--allow",
            "[fd00::7/128]:55000",
            "--keep-internet",
        ]
    );

    let o = parse(&[]).unwrap();
    assert!(!o.apply);
    assert_eq!(o.backend, None);
    assert_eq!(o.gateway_port, 3001);
    assert_eq!(o.policy().mode, EgressMode::BlockPrivate);
    assert_eq!(
        o.apply_args(Backend::Nft),
        vec!["--apply", "--nft", "--gateway-port", "3001"]
    );

    let o = parse(&["--uninstall", "--nft", "--nft"]).unwrap();
    assert_eq!(o.action, EgressAction::Uninstall);
    assert_eq!(
        o.apply_args(Backend::Nft),
        vec!["--apply", "--nft", "--uninstall"]
    );
}

#[test]
fn options_reject_bad_input() {
    for (args, code, value) in [
        (vec!["--alow", "10.0.0.5"], "unknown_argument", "--alow"),
        (vec!["10.0.0.5"], "unknown_argument", "10.0.0.5"),
        (vec!["--allow"], "missing_value", "--allow"),
        (vec!["--gateway-port"], "missing_value", "--gateway-port"),
        (
            vec!["--allow", "10.0.0.5,siem.local"],
            "invalid_allow_entry",
            "siem.local",
        ),
        (vec!["--gateway-port", "0"], "invalid_gateway_port", "0"),
        (
            vec!["--gateway-port", "70000"],
            "invalid_gateway_port",
            "70000",
        ),
        (vec!["--gateway-port", "x1"], "invalid_gateway_port", "x1"),
        (
            vec!["--nft", "--iptables"],
            "conflicting_backends",
            "--iptables",
        ),
    ] {
        let err = parse(&args).unwrap_err();
        assert_eq!((err.code, err.value.as_str()), (code, value), "{args:?}");
    }
}

// --- host facts -----------------------------------------------------------

#[test]
fn resolv_conf_parsing() {
    let text = "# generated\nnameserver 127.0.0.53\nnameserver 10.0.0.2\n\
                nameserver   fe80::1%eth0\nnameserver 8.8.8.8 # comment\n\
                nameserver 10.0.0.2\nsearch corp.example\nnameserver bogus\noptions edns0\n";
    assert_eq!(
        parse_resolv_conf(text),
        vec![ip("10.0.0.2"), ip("fe80::1"), ip("8.8.8.8")]
    );
    assert!(parse_resolv_conf("nameserver ::1\n").is_empty());
}

#[test]
fn first_readable_resolv_conf_wins() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.conf");
    let b = dir.path().join("b.conf");
    std::fs::write(&b, "nameserver 192.168.1.1\n").unwrap();
    assert_eq!(
        host_dns_resolvers(&[a.clone(), b.clone()]),
        vec![ip("192.168.1.1")]
    );
    std::fs::write(&a, "nameserver 1.1.1.1\n").unwrap();
    assert_eq!(host_dns_resolvers(&[a, b]), vec![ip("1.1.1.1")]);
    assert!(host_dns_resolvers(&[]).is_empty());
}

#[test]
fn backend_detection_prefers_nft() {
    let runner = MockRunner::new();
    assert_eq!(detect_backend(&runner), (Backend::Nft, false));
    runner.install("iptables");
    assert_eq!(detect_backend(&runner), (Backend::Iptables, true));
    runner.install("nft");
    assert_eq!(detect_backend(&runner), (Backend::Nft, true));
}

// --- applying -------------------------------------------------------------

type Respond = dyn Fn(&CommandSpec) -> CommandOutput + Send + Sync;

/// Runner answering through a closure (stateful responses, file checks).
struct FnRunner {
    respond: Box<Respond>,
    calls: Mutex<Vec<String>>,
    installed: Vec<&'static str>,
}

impl FnRunner {
    fn new(
        installed: Vec<&'static str>,
        respond: impl Fn(&CommandSpec) -> CommandOutput + Send + Sync + 'static,
    ) -> Self {
        Self {
            respond: Box::new(respond),
            calls: Mutex::new(Vec::new()),
            installed,
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl CommandRunner for FnRunner {
    async fn run(&self, spec: &CommandSpec) -> CommandOutput {
        self.calls.lock().unwrap().push(spec.display());
        (self.respond)(spec)
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        self.installed
            .contains(&program)
            .then(|| PathBuf::from(format!("/usr/sbin/{program}")))
    }
}

/// Ruleset path, content, file mode and directory mode seen by `nft -f`.
type Seen = (PathBuf, String, u32, u32);

#[tokio::test]
async fn nft_apply_loads_ruleset_from_private_temp_file() {
    let seen: Arc<Mutex<Option<Seen>>> = Arc::new(Mutex::new(None));
    let seen2 = Arc::clone(&seen);
    let runner = FnRunner::new(vec!["nft"], move |spec| {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(spec.program, "nft");
        assert_eq!(spec.args[0], "-f");
        let path = PathBuf::from(&spec.args[1]);
        let content = std::fs::read_to_string(&path).unwrap();
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        *seen2.lock().unwrap() = Some((path, content, file_mode, dir_mode));
        CommandOutput::ok("")
    });
    let policy = allowlist_policy();
    let plan = egress_plan(&policy, Backend::Nft, EgressAction::Install);
    let report = apply_plan(&runner, &plan).await.unwrap();
    assert_eq!(report.commands, 1);
    let (path, content, file_mode, dir_mode) = seen.lock().unwrap().clone().unwrap();
    assert_eq!(content, nft_ruleset(&policy, EgressAction::Install));
    assert_eq!(file_mode, 0o600);
    assert_eq!(dir_mode, 0o700);
    assert!(!path.exists(), "temporary ruleset must be removed");
    assert!(!path.parent().unwrap().exists());
    // No shell anywhere.
    assert!(runner.calls().iter().all(|c| c.starts_with("nft -f ")));
}

#[tokio::test]
async fn nft_apply_failure_is_reported() {
    let runner = FnRunner::new(vec!["nft"], |_| {
        CommandOutput::failed(1, "Error: Could not process rule: Operation not permitted")
    });
    let plan = egress_plan(&private_policy(), Backend::Nft, EgressAction::Install);
    let err = apply_plan(&runner, &plan).await.unwrap_err();
    assert!(err.command.starts_with("nft -f "), "{err}");
    assert!(
        err.detail.contains("exit 1: Error: Could not process rule"),
        "{err}"
    );
}

#[tokio::test]
async fn iptables_apply_semantics() {
    // Reload DROPs: two stale copies are deleted before -D starts failing;
    // the jump into DOCKER-USER already exists (-C succeeds).
    let deletes = Arc::new(Mutex::new(0usize));
    let deletes2 = Arc::clone(&deletes);
    let runner = FnRunner::new(vec!["iptables"], move |spec| {
        let line = spec.display();
        if line.starts_with("iptables -w -D DOCKER-USER") && line.contains("talon-egress-reload") {
            let mut n = deletes2.lock().unwrap();
            *n += 1;
            return if *n <= 3 {
                CommandOutput::ok("")
            } else {
                CommandOutput::failed(1, "Bad rule")
            };
        }
        if line.starts_with("iptables -w -N") {
            return CommandOutput::failed(1, "Chain already exists.");
        }
        if line.starts_with("iptables -w -C DOCKER-USER") {
            return CommandOutput::ok("");
        }
        if line.starts_with("iptables -w -C INPUT") || line.starts_with("iptables -w -D INPUT") {
            return CommandOutput::failed(1, "Bad rule");
        }
        if line.starts_with("ip6tables -w -n -L INPUT") {
            return CommandOutput::failed(3, "can't initialize ip6tables table `filter'");
        }
        CommandOutput::ok("")
    });
    let plan = egress_plan(&private_policy(), Backend::Iptables, EgressAction::Install);
    let report = apply_plan(&runner, &plan).await.unwrap();
    assert_eq!(
        report.skipped_sections,
        vec!["IPv6 (ip6tables)".to_string()]
    );
    let calls = runner.calls();
    assert_eq!(*deletes.lock().unwrap(), 4);
    // -C DOCKER-USER succeeded: no second jump inserted; -C INPUT failed:
    // the jump is inserted at position 2 (below the reload DROP).
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("iptables -w -I DOCKER-USER 2"))
    );
    assert!(
        calls.contains(
            &"iptables -w -I INPUT 2 -i br-talon -m comment --comment talon-egress -j TALON-INPUT"
                .to_string()
        )
    );
    // Nothing ran for IPv6 except the guard; nothing through a shell.
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("ip6tables")).count(),
        1
    );
    assert!(
        calls
            .iter()
            .all(|c| c.starts_with("iptables -w ") || c.starts_with("ip6tables -w "))
    );
    assert_eq!(report.commands, calls.len());
    // The reload DROP is inserted before the chain is flushed and removed
    // only after the jumps are in place.
    let pos = |needle: &str| calls.iter().position(|c| c.starts_with(needle)).unwrap();
    assert!(pos("iptables -w -I DOCKER-USER 1") < pos("iptables -w -F TALON-EGRESS"));
    assert!(pos("iptables -w -I INPUT 2") < pos("iptables -w -D DOCKER-USER"));
}

#[tokio::test]
async fn iptables_apply_stops_at_first_failure_and_stays_closed() {
    let runner = FnRunner::new(vec!["iptables"], |spec| {
        if spec
            .display()
            .starts_with("iptables -w -A TALON-EGRESS -m conntrack")
        {
            CommandOutput::failed(2, "iptables v1.8.10: Couldn't load match `conntrack'")
        } else {
            CommandOutput::ok("")
        }
    });
    let plan = egress_plan(&private_policy(), Backend::Iptables, EgressAction::Install);
    let err = apply_plan(&runner, &plan).await.unwrap_err();
    assert_eq!(
        err.command,
        "iptables -w -A TALON-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    );
    assert!(err.detail.contains("Couldn't load match"));
    let calls = runner.calls();
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("iptables -w -I DOCKER-USER 1"))
    );
    // Fail closed: the temporary DROPs were not lifted.
    assert!(!calls.iter().any(|c| c.starts_with("iptables -w -D")));
    assert_eq!(calls.last().unwrap(), &err.command);
}

// --- step -----------------------------------------------------------------

fn ctx(dir: &Path, runner: Arc<dyn CommandRunner>) -> SetupContext {
    let mut ctx = SetupContext::new(dir, dir, runner);
    ctx.config.llm_gateway_port = 3001;
    ctx.talon_binary = PathBuf::from("/opt/talon/bin/talon");
    ctx
}

async fn step(ctx: &SetupContext, args: &[&str]) -> StepOutcome {
    run(&StepArgs::new(args.iter().copied()), ctx)
        .await
        .unwrap()
}

#[tokio::test]
async fn prints_script_and_block_without_applying() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::new());
    runner.install("nft");
    let c = ctx(dir.path(), runner.clone());
    let out = step(
        &c,
        &["--allow", "10.0.0.5:9200", "--allow", "[fd00::7]:443"],
    )
    .await;
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.lines[0], "#!/bin/sh");
    assert_eq!(out.lines.last().map(String::as_str), Some("exit 0"));
    let b = out.block.clone().unwrap();
    assert_eq!(b.step(), "SETUP_EGRESS");
    assert_eq!(b.get("ACTION"), Some("install"));
    assert_eq!(b.get("BACKEND"), Some("nft"));
    assert_eq!(b.get("BACKEND_AVAILABLE"), Some("true"));
    assert_eq!(b.get("NETWORK"), Some("talon-agents"));
    assert_eq!(b.get("BRIDGE"), Some("br-talon"));
    assert_eq!(b.get("BRIDGE_PRESENT"), Some("false"));
    assert_eq!(b.get("MODE"), Some("allowlist"));
    assert_eq!(b.get("GATEWAY_PORT"), Some("3001"));
    assert_eq!(b.get("ALLOW"), Some("10.0.0.5/32:9200,[fd00::7/128]:443"));
    assert_eq!(b.get("BLOCKED_DNS_RESOLVERS"), Some("none"));
    assert_eq!(b.get("WARNINGS"), Some("none"));
    assert_eq!(b.get("APPLIED"), Some("false"));
    assert_eq!(
        b.get("NEXT_STEP"),
        Some(
            "review the script above, then run as root: sudo '/opt/talon/bin/talon' setup egress --apply --nft --gateway-port 3001 --allow 10.0.0.5/32:9200 --allow '[fd00::7/128]:443'"
        )
    );
    assert_eq!(b.status(), Some("success"));
    // Script first, block last; the block parses back.
    let text = out.render();
    assert!(text.starts_with("#!/bin/sh\n"));
    assert!(text.contains("\tchain agent_egress {\n"));
    assert!(text.contains("exit 0\n=== NANOCLAW SETUP: SETUP_EGRESS ==="));
    assert_eq!(crate::status::parse_status_blocks(&text), vec![b]);
    // Nothing was changed.
    assert_eq!(runner.calls(), vec!["ip -o link show dev br-talon"]);
}

#[tokio::test]
async fn apply_without_root_explains_instead() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::new());
    runner.install("nft");
    runner.on(
        "ip -o link show dev br-talon",
        CommandOutput::ok("7: br-talon: <...>"),
    );
    let mut c = ctx(dir.path(), runner.clone());
    c.platform.uid = Some(1000);
    let out = step(&c, &["--apply"]).await;
    assert_eq!(out.exit_code, 1);
    let b = out.block.unwrap();
    assert_eq!(b.status(), Some("needs_root"));
    assert_eq!(b.get("ERROR"), Some("root_required"));
    assert_eq!(b.get("APPLIED"), Some("false"));
    assert_eq!(b.get("BRIDGE_PRESENT"), Some("true"));
    assert_eq!(b.get("MODE"), Some("block-private"));
    assert!(
        b.get("NEXT_STEP")
            .unwrap()
            .contains("sudo '/opt/talon/bin/talon' setup egress --apply --nft")
    );
    assert!(!runner.called("nft"));
    assert!(!out.lines.is_empty(), "the script is still printed");
}

#[tokio::test]
async fn apply_as_root_with_iptables_runs_the_plan() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::new());
    runner.install("iptables");
    for prefix in ["iptables -w -I", "iptables -w -F", "iptables -w -A"] {
        runner.on(prefix, CommandOutput::ok(""));
    }
    let mut c = ctx(dir.path(), runner.clone());
    c.platform.uid = Some(0);
    let out = step(&c, &["--apply", "--allow", "192.168.10.20:3306"]).await;
    let b = out.block.unwrap();
    assert_eq!(out.exit_code, 0, "{b:?}");
    assert_eq!(b.get("BACKEND"), Some("iptables"));
    assert_eq!(b.get("APPLIED"), Some("true"));
    assert_eq!(b.get("SKIPPED"), Some("IPv6 (ip6tables)"));
    assert_eq!(b.status(), Some("success"));
    assert_eq!(b.get("NEXT_STEP"), None);
    let calls = runner.calls();
    assert!(
        calls.contains(
            &"iptables -w -A TALON-EGRESS -d 192.168.10.20/32 -p tcp --dport 3306 -j RETURN"
                .to_string()
        )
    );
    assert!(calls.contains(&"iptables -w -A TALON-EGRESS -j DROP".to_string()));
    assert!(!calls.iter().any(|c| c.starts_with("sh ")));
    let log = std::fs::read_to_string(dir.path().join("logs/setup.log")).unwrap();
    assert!(log.contains("install via iptables"));
}

#[tokio::test]
async fn apply_failure_is_reported_in_the_block() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::new());
    runner.install("nft");
    runner.on(
        "nft -f",
        CommandOutput::failed(
            1,
            "Error: Could not process rule: No such file or directory",
        ),
    );
    let mut c = ctx(dir.path(), runner);
    c.platform.uid = Some(0);
    let out = step(&c, &["--apply"]).await;
    assert_eq!(out.exit_code, 1);
    let b = out.block.unwrap();
    assert_eq!(b.status(), Some("failed"));
    assert_eq!(b.get("ERROR"), Some("apply_failed"));
    assert_eq!(b.get("APPLIED"), Some("false"));
    assert!(b.get("FAILED_COMMAND").unwrap().starts_with("nft -f "));
    assert!(b.get("DETAIL").unwrap().contains("Could not process rule"));
}

#[tokio::test]
async fn uninstall_applies_table_removal() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(FnRunner::new(vec!["nft"], |spec| {
        if spec.program == "nft" {
            let rules = std::fs::read_to_string(&spec.args[1]).unwrap();
            assert_eq!(
                rules,
                "add table inet talon_egress\ndelete table inet talon_egress\n"
            );
            CommandOutput::ok("")
        } else {
            CommandOutput::failed(1, "")
        }
    }));
    let mut c = ctx(dir.path(), runner.clone());
    c.platform.uid = Some(0);
    let out = step(
        &c,
        &["--uninstall", "--apply", "--nft", "--allow", "10.0.0.5"],
    )
    .await;
    assert_eq!(out.exit_code, 0);
    let b = out.block.unwrap();
    assert_eq!(b.get("ACTION"), Some("uninstall"));
    assert_eq!(b.get("APPLIED"), Some("true"));
    assert_eq!(b.get("MODE"), None);
    assert_eq!(b.get("ALLOW"), None);
    assert_eq!(runner.calls().len(), 2);
}

#[tokio::test]
async fn invalid_arguments_exit_4() {
    let dir = tempfile::tempdir().unwrap();
    let c = ctx(dir.path(), Arc::new(MockRunner::new()));
    let out = step(&c, &["--allow", "10.0.0.5:99999"]).await;
    assert_eq!(out.exit_code, 4);
    assert!(out.lines.is_empty());
    let b = out.block.unwrap();
    assert_eq!(b.step(), "SETUP_EGRESS");
    assert_eq!(b.status(), Some("failed"));
    assert_eq!(b.get("ERROR"), Some("invalid_allow_entry"));
    assert_eq!(b.get("INVALID_ARGUMENT"), Some("10.0.0.5:99999"));
    let out = step(&c, &["--bridge", "eth0"]).await;
    assert_eq!(out.block.unwrap().get("ERROR"), Some("unknown_argument"));
}

#[tokio::test]
async fn unsupported_platform_and_missing_backend() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::new());
    let mut c = ctx(dir.path(), runner.clone());
    c.platform.uid = Some(0);
    // No firewall tool installed.
    let out = step(&c, &[]).await;
    let b = out.block.unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(b.get("BACKEND"), Some("nft"));
    assert_eq!(b.get("BACKEND_AVAILABLE"), Some("false"));
    assert_eq!(b.get("WARNINGS"), Some("backend_not_found"));
    let out = step(&c, &["--apply"]).await;
    assert_eq!(out.exit_code, 1);
    assert_eq!(out.block.unwrap().get("ERROR"), Some("backend_not_found"));

    // macOS (Docker Desktop): containers live in a VM, host rules don't apply.
    let runner = Arc::new(MockRunner::new());
    runner.install("nft");
    c.runner = runner.clone();
    c.platform.platform = Platform::MacOs;
    let out = step(&c, &[]).await;
    assert_eq!(
        out.block.unwrap().get("WARNINGS"),
        Some("unsupported_platform")
    );
    let out = step(&c, &["--apply"]).await;
    assert_eq!(out.exit_code, 1);
    assert_eq!(
        out.block.unwrap().get("ERROR"),
        Some("unsupported_platform")
    );
    assert!(!runner.called("nft"));
    assert!(!runner.called("ip "));
}

#[tokio::test]
async fn blocked_dns_resolvers_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let resolv = dir.path().join("resolv.conf");
    std::fs::write(
        &resolv,
        "nameserver 127.0.0.53\nnameserver 10.0.0.2\nnameserver 8.8.8.8\n",
    )
    .unwrap();
    let mut c = ctx(dir.path(), Arc::new(MockRunner::new()));
    c.resolv_conf_paths = vec![dir.path().join("missing.conf"), resolv];

    // Block-private: only the private resolver is cut off.
    let b = step(&c, &["--nft"]).await.block.unwrap();
    assert_eq!(b.get("BLOCKED_DNS_RESOLVERS"), Some("10.0.0.2"));
    assert_eq!(
        b.get("WARNINGS"),
        Some("backend_not_found,dns_resolver_blocked")
    );
    // Allowing it clears the warning.
    let b = step(&c, &["--allow", "10.0.0.2:53", "--keep-internet"])
        .await
        .block
        .unwrap();
    assert_eq!(b.get("BLOCKED_DNS_RESOLVERS"), Some("none"));
    // Allowlist mode cuts off every resolver that is not listed.
    let b = step(&c, &["--allow", "10.0.0.5:9200"]).await.block.unwrap();
    assert_eq!(b.get("BLOCKED_DNS_RESOLVERS"), Some("10.0.0.2,8.8.8.8"));
}

#[tokio::test]
async fn vllm_reachable_without_key_is_warned() {
    if std::env::var_os("TALON_VLLM_BASE_URL").is_some()
        || std::env::var_os("TALON_VLLM_MODEL").is_some()
    {
        return; // process env would override the test .env
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".env"),
        "TALON_VLLM_BASE_URL=http://10.9.0.7:8000/v1\nTALON_VLLM_MODEL=qwen\n",
    )
    .unwrap();
    let runner = Arc::new(MockRunner::new());
    runner.install("nft");
    let c = ctx(dir.path(), runner);
    let warnings = |out: StepOutcome| out.block.unwrap().get("WARNINGS").unwrap().to_string();
    assert_eq!(
        warnings(step(&c, &["--allow", "10.9.0.0/24"]).await),
        "vllm_reachable_from_agents"
    );
    assert_eq!(
        warnings(step(&c, &["--allow", "10.9.0.7:9200"]).await),
        "none"
    );
    assert_eq!(warnings(step(&c, &[]).await), "none");

    // With an API key the server rejects direct calls: no warning.
    std::fs::write(
        dir.path().join(".env"),
        "TALON_VLLM_BASE_URL=http://10.9.0.7:8000/v1\nTALON_VLLM_MODEL=qwen\nTALON_VLLM_API_KEY=k\n",
    )
    .unwrap();
    let mut c = c;
    c.reload_config();
    assert_eq!(
        warnings(step(&c, &["--allow", "10.9.0.0/24"]).await),
        "none"
    );
}

#[tokio::test]
async fn dispatched_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let c = ctx(dir.path(), Arc::new(MockRunner::new()));
    let out = run_step_by_name("egress", &["--iptables".to_string()], &c)
        .await
        .unwrap();
    let b = out.block.unwrap();
    assert_eq!(b.step(), "SETUP_EGRESS");
    assert_eq!(b.get("BACKEND"), Some("iptables"));
    assert!(out.lines.iter().any(|l| l == "# --- IPv4 (iptables) ---"));
}
