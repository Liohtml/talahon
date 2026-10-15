//! Free-text detector primitives: compiled patterns, IP classification and
//! helpers. The detectors themselves (which allocate tokens) live in
//! [`crate::engine`].
//!
//! Every static pattern below is a compile-time constant exercised by the
//! unit tests, so the `expect` on construction cannot fire.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Regex;

fn re(pattern: &str) -> Regex {
    // Only called with the static patterns of this module (see module docs).
    Regex::new(pattern).expect("static regex")
}

/// IPv4 dotted quad (the Python proxy's pattern, ASCII digits only).
pub(crate) static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    )
});

/// IPv6 candidate: a run of hex digits, colons and dots containing at least
/// two colons, with an optional zone id. Candidates are validated by
/// parsing.
pub(crate) static IPV6_CANDIDATE_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"[0-9A-Fa-f:.]*:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z_.-]{1,32})?"));

/// E-mail address.
pub(crate) static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"[A-Za-z0-9_%+-][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
    )
});

/// UNC root `\\host` (also JSON-escaped `\\\\host`). Group 1 = host.
pub(crate) static UNC_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\\{2,4}([A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*)",
    )
});

/// Well-known Windows authorities whose `AUTH\name` principals are not
/// personal data (group 1), or `DOMAIN\user` (groups 2 and 3). The domain
/// must be upper-case NetBIOS style to avoid matching ordinary paths.
pub(crate) static DOMAIN_USER_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i:(NT AUTHORITY|NT SERVICE|NT VIRTUAL MACHINE|IIS APPPOOL|BUILTIN|Window Manager|Font Driver Host)\\{1,2}[^\s\\]*)",
        r"|([A-Z0-9][A-Z0-9_-]{0,14})\\{1,2}([A-Za-z0-9_$-](?:[A-Za-z0-9._$-]{0,62}[A-Za-z0-9_$-])?)",
    ))
});

/// Windows / macOS user profile path where the name is followed by a
/// separator (spaces allowed in the name). Groups: 1 prefix, 2 name, 3 sep.
pub(crate) static WIN_PROFILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r#"((?:(?i:\b[a-z]:|%[a-z_]+%)[\\/]{1,2}(?i:users)|[\\/]{1,2}Users)[\\/]{1,2})"#,
        r#"([^\\/:*?"<>|\r\n\t]{1,64})([\\/])"#,
    ))
});

/// Profile path at the end of a value (`USERPROFILE=C:\Users\jdoe`).
/// Groups: 1 prefix, 2 name, 3 terminator (may be empty at end of text).
pub(crate) static WIN_PROFILE_END_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r#"((?:(?i:\b[a-z]:|%[a-z_]+%)[\\/]{1,2}(?i:users)|[\\/]{1,2}Users)[\\/]{1,2})"#,
        r#"([^\\/:*?"<>|\s,;'()\[\]]{1,64})([\s"',;)\]]|$)"#,
    ))
});

/// Unix home directory. Groups: 1 `/home/`, 2 name.
pub(crate) static UNIX_HOME_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(/home/)([A-Za-z0-9_@-](?:[A-Za-z0-9._@-]{0,62}[A-Za-z0-9_@$-])?)"));

/// Domain (`S-1-5-21-a-b-c`) or Azure AD (`S-1-12-1-a-b-c-d`) SID; group 1
/// is the identifying part, group 2 an optional RID that is kept.
pub(crate) static SID_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b(S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}|S-1-12-1-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10})(-[0-9]{1,10})?\b",
    )
});

/// MAC address (colon, hyphen or Cisco dotted notation).
pub(crate) static MAC_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"\b(?:[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}",
        r"|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}",
        r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})\b",
    ))
});

/// URL with a scheme (used to keep path detectors away from web URLs).
pub(crate) static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?i)\b([a-z][a-z0-9+.-]{1,15})://[^\s"'<>`]+"#));

/// Profile directory names that are not user names.
pub(crate) const PROFILE_DIRS: &[&str] = &[
    "public",
    "default",
    "default user",
    "all users",
    "defaultuser0",
];

/// "TLDs" that are really file extensions (`icon@2x.png` is not an e-mail).
pub(crate) const FILE_EXTENSION_TLDS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "svg", "bmp", "ico", "exe", "dll", "sys", "js", "css", "txt",
    "log", "json", "xml", "html", "htm", "zip", "ps1", "bat", "cmd", "vbs", "tmp", "dat",
];

/// Characters that may precede a free-standing `DOMAIN\user`.
pub(crate) fn is_open_boundary(c: char) -> bool {
    c.is_whitespace() || "\"'=(,;[{<>|:`".contains(c)
}

/// Characters that may precede a UNC root. Unlike [`is_open_boundary`],
/// `:` is excluded so a JSON-escaped `C:\\Windows` is not a UNC path.
pub(crate) fn is_unc_boundary(c: char) -> bool {
    c != ':' && is_open_boundary(c)
}

/// Parse a dotted quad, accepting leading zeros as decimal (`010.0.0.1`).
pub(crate) fn parse_ipv4_lenient(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut n = 0usize;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let v: u16 = part.parse().ok()?;
        octets[n] = u8::try_from(v).ok()?;
        n += 1;
    }
    (n == 4).then(|| Ipv4Addr::from(octets))
}

/// Internal IPv4: the Python proxy's set (`is_private or is_loopback or
/// is_link_local`: RFC 1918, loopback, link-local, this-network, IETF
/// protocol assignments, documentation, benchmarking, reserved 240/4) plus
/// CGNAT `100.64/10`, minus the information-free `0.0.0.0` and
/// `255.255.255.255`.
pub fn is_internal_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified() || ip.is_broadcast() {
        return false;
    }
    let o = ip.octets();
    matches!(
        o,
        [10, ..] | [127, ..] | [0, ..] | [169, 254, ..] | [192, 168, ..]
    ) || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0 && (o[3] < 8 || o[3] == 170 || o[3] == 171))
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 240
}

/// Internal IPv6: loopback, ULA `fc00::/7`, link-local `fe80::/10`,
/// site-local `fec0::/10`, documentation `2001:db8::/32`, and IPv4-mapped
/// addresses whose IPv4 part is internal.
pub fn is_internal_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() {
        return false;
    }
    if ip.is_loopback() {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_internal_ipv4(v4);
    }
    let s = ip.segments();
    (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || (s[0] == 0x2001 && s[1] == 0x0db8)
}

/// Parse an IPv4 (lenient) or IPv6 address (zone id allowed).
pub(crate) fn parse_ip(s: &str) -> Option<IpAddr> {
    if let Some(v4) = parse_ipv4_lenient(s) {
        return Some(IpAddr::V4(v4));
    }
    let core = s.split('%').next().unwrap_or(s);
    core.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

/// `true` for internal addresses of either family.
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_ipv4(v4),
        IpAddr::V6(v6) => is_internal_ipv6(v6),
    }
}

/// Byte ranges of non-`file://` URLs in `text`.
pub(crate) fn url_spans(text: &str) -> Vec<(usize, usize)> {
    if !text.contains("://") {
        return Vec::new();
    }
    URL_RE
        .captures_iter(text)
        .filter_map(|c| {
            let m = c.get(0)?;
            let scheme = c.get(1)?.as_str();
            (!scheme.eq_ignore_ascii_case("file")).then(|| (m.start(), m.end()))
        })
        .collect()
}

/// `true` when byte offset `pos` lies inside one of `spans`.
pub(crate) fn in_spans(spans: &[(usize, usize)], pos: usize) -> bool {
    spans.iter().any(|&(s, e)| pos >= s && pos < e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Ipv4Addr {
        parse_ipv4_lenient(s).unwrap()
    }

    #[test]
    fn all_static_patterns_compile() {
        for r in [
            &*IPV4_RE,
            &*IPV6_CANDIDATE_RE,
            &*EMAIL_RE,
            &*UNC_RE,
            &*DOMAIN_USER_RE,
            &*WIN_PROFILE_RE,
            &*WIN_PROFILE_END_RE,
            &*UNIX_HOME_RE,
            &*SID_RE,
            &*MAC_RE,
            &*URL_RE,
        ] {
            assert!(!r.as_str().is_empty());
        }
    }

    #[test]
    fn ipv4_classification_matches_python_plus_cgnat() {
        // (address, internal) — Python 3.13 `is_private or is_loopback or is_link_local`,
        // except 0.0.0.0 / 255.255.255.255 (no identity) and 100.64/10 (added).
        let table = [
            ("0.0.0.0", false),
            ("0.1.2.3", true),
            ("10.1.1.1", true),
            ("100.64.0.1", true),
            ("100.128.0.1", false),
            ("127.0.0.1", true),
            ("169.254.1.1", true),
            ("172.16.0.1", true),
            ("172.31.255.255", true),
            ("172.32.0.1", false),
            ("192.0.0.1", true),
            ("192.0.2.1", true),
            ("192.168.1.1", true),
            ("198.18.0.1", true),
            ("198.51.100.1", true),
            ("203.0.113.1", true),
            ("240.0.0.1", true),
            ("255.255.255.255", false),
            ("224.0.0.1", false),
            ("8.8.8.8", false),
            ("1.1.1.1", false),
        ];
        for (a, want) in table {
            assert_eq!(is_internal_ipv4(v4(a)), want, "{a}");
        }
    }

    #[test]
    fn ipv6_classification() {
        let table = [
            ("fd00::1", true),
            ("fc12:3456::1", true),
            ("fe80::1", true),
            ("::1", true),
            ("2001:db8::1", true),
            ("::ffff:10.0.0.1", true),
            ("::ffff:8.8.8.8", false),
            ("2606:4700::1", false),
            ("::", false),
        ];
        for (a, want) in table {
            assert_eq!(is_internal_ipv6(a.parse().unwrap()), want, "{a}");
        }
    }

    #[test]
    fn lenient_ipv4_parsing() {
        assert_eq!(
            parse_ipv4_lenient("010.000.000.001"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(parse_ipv4_lenient("256.1.1.1"), None);
        assert_eq!(parse_ipv4_lenient("1.2.3"), None);
        assert_eq!(parse_ipv4_lenient("1.2.3.4.5"), None);
        assert_eq!(parse_ipv4_lenient("1.2.3.x"), None);
        assert_eq!(parse_ipv4_lenient("١.٢.٣.٤"), None);
        assert!(matches!(parse_ip("fe80::1%eth0"), Some(IpAddr::V6(_))));
        assert!(parse_ip("not-an-ip").is_none());
    }

    #[test]
    fn ipv4_regex_finds_python_matches() {
        let found: Vec<_> = IPV4_RE
            .find_iter("a 10.0.0.1, 8.8.8.8:53 v1.2.3.4 999.1.1.1 10.0.19041.1")
            .map(|m| m.as_str())
            .collect();
        assert_eq!(found, ["10.0.0.1", "8.8.8.8"]);
    }

    #[test]
    fn url_spans_skip_file_urls() {
        let t = "see https://evil.com/home/x/ and file:///home/bob/x";
        let spans = url_spans(t);
        assert_eq!(spans.len(), 1);
        assert!(in_spans(&spans, t.find("/home/x").unwrap()));
        assert!(!in_spans(&spans, t.find("/home/bob").unwrap()));
    }
}
