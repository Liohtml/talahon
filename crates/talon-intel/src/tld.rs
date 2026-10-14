//! Embedded top-level-domain knowledge used for domain sanity checks.
//!
//! The list is intentionally curated rather than the full IANA root zone:
//! every delegated ccTLD, the legacy gTLDs and the new gTLDs that show up in
//! threat-intel feeds. A candidate whose TLD is not listed is not reported as
//! a domain from free text (that is what keeps `svchost.exe`,
//! `System.Management.Automation.dll` or `data.win.eventdata.image` out of the
//! IOC list); values from fields that are known to hold host names bypass the
//! list and are classified as internal instead.

use std::collections::HashSet;
use std::sync::LazyLock;

/// Country-code TLDs (delegated, in use).
const CC_TLDS: &[&str] = &[
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au", "aw", "ax",
    "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt",
    "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr",
    "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg", "er",
    "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gd", "ge", "gf", "gg", "gh", "gi",
    "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht",
    "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je", "jm", "jo", "jp", "ke",
    "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr",
    "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo",
    "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne", "nf", "ng",
    "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm",
    "pn", "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd",
    "se", "sg", "sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "su", "sv", "sx", "sy",
    "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw",
    "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws",
    "ye", "yt", "za", "zm", "zw",
];

/// Legacy generic TLDs plus widely used / frequently abused new gTLDs.
const G_TLDS: &[&str] = &[
    // legacy / sponsored
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "arpa",
    "info",
    "biz",
    "name",
    "pro",
    "aero",
    "coop",
    "museum",
    "mobi",
    "asia",
    "tel",
    "travel",
    "jobs",
    "cat",
    "post",
    "xxx",
    // new gTLDs common in benign and malicious traffic
    "xyz",
    "top",
    "online",
    "site",
    "club",
    "shop",
    "store",
    "app",
    "dev",
    "cloud",
    "live",
    "tech",
    "space",
    "website",
    "fun",
    "icu",
    "vip",
    "work",
    "link",
    "click",
    "buzz",
    "cyou",
    "rest",
    "bar",
    "uno",
    "win",
    "bid",
    "loan",
    "download",
    "racing",
    "review",
    "stream",
    "trade",
    "date",
    "men",
    "party",
    "science",
    "faith",
    "accountant",
    "cricket",
    "webcam",
    "monster",
    "quest",
    "sbs",
    "cfd",
    "lol",
    "best",
    "today",
    "world",
    "life",
    "email",
    "network",
    "services",
    "solutions",
    "digital",
    "company",
    "center",
    "support",
    "systems",
    "tools",
    "zone",
    "host",
    "press",
    "pics",
    "wiki",
    "ink",
    "blog",
    "news",
    "media",
    "agency",
    "studio",
    "design",
    "global",
    "group",
    "team",
    "art",
    "one",
    "page",
    "run",
    "social",
    "chat",
    "games",
    "ltd",
    "llc",
    "inc",
    "bond",
    "autos",
    "boats",
    "homes",
    "beauty",
    "hair",
    "skin",
    "makeup",
    "lat",
    "surf",
    "mom",
    "kim",
    "ren",
    "wang",
    "xin",
    "gdn",
    "country",
    "cam",
    "guru",
    "ninja",
    "rocks",
    "plus",
    "pub",
    "red",
    "blue",
    "pink",
    "black",
    "green",
    "gold",
    "money",
    "finance",
    "bank",
    "health",
    "care",
    "academy",
    "education",
    "school",
    "university",
    "city",
    "land",
    "estate",
    "house",
    "realty",
    "energy",
    "events",
    "exposed",
    "codes",
    "direct",
    "software",
    "technology",
    "computer",
    "domains",
    "new",
    "zip",
    "mov",
];

/// Pseudo / special-use TLDs worth recognising.
const SPECIAL_TLDS: &[&str] = &["onion"];

/// Suffixes that denote internal / non-public name spaces.
const INTERNAL_SUFFIXES: &[&str] = &[
    "local",
    "lan",
    "internal",
    "intranet",
    "corp",
    "home",
    "localdomain",
    "localhost",
    "private",
    "home.arpa",
    "test",
    "example",
    "invalid",
];

/// TLDs that collide with common file extensions (`setup.py`, `update.zip`,
/// `install.sh`, `notes.md`, `lib.so`, `invoice.one`, ...). Two-label
/// candidates with these TLDs are only accepted from host-name fields.
const FILE_EXTENSION_TLDS: &[&str] = &[
    "zip", "mov", "py", "pl", "pm", "sh", "rs", "md", "so", "ps", "cc", "ai", "ax", "gs", "ms",
    "in", "ml", "mk", "am", "tf", "as", "ws", "bz", "one", "app", "new", "sc", "st",
];

static KNOWN: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    CC_TLDS
        .iter()
        .chain(G_TLDS)
        .chain(SPECIAL_TLDS)
        .copied()
        .collect()
});

static FILE_EXT: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| FILE_EXTENSION_TLDS.iter().copied().collect());

/// `true` when `tld` (lowercase, no dot) is a recognised public TLD.
pub(crate) fn is_known_tld(tld: &str) -> bool {
    KNOWN.contains(tld) || (tld.starts_with("xn--") && tld.len() > 4)
}

/// `true` when `tld` is also a common file extension.
pub(crate) fn is_file_extension_tld(tld: &str) -> bool {
    FILE_EXT.contains(tld)
}

/// `true` when the (lowercase) host name lives in an internal name space.
pub(crate) fn is_internal_name(host: &str) -> bool {
    INTERNAL_SUFFIXES
        .iter()
        .any(|s| host == *s || host.ends_with(&format!(".{s}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tlds() {
        for t in ["com", "ru", "xyz", "top", "onion", "io", "de", "xn--p1ai"] {
            assert!(is_known_tld(t), "{t}");
        }
        for t in [
            "exe", "dll", "sys", "ps1", "bat", "tmp", "log", "txt", "local", "lan", "dat",
        ] {
            assert!(!is_known_tld(t), "{t}");
        }
    }

    #[test]
    fn ambiguous_and_internal() {
        assert!(is_file_extension_tld("zip"));
        assert!(is_file_extension_tld("py"));
        assert!(!is_file_extension_tld("com"));
        assert!(is_internal_name("dc01.corp.local"));
        assert!(is_internal_name("printer.home.arpa"));
        assert!(!is_internal_name("evil.com"));
        assert!(!is_internal_name("localization.com"));
    }
}
