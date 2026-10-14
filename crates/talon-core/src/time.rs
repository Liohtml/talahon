//! Timestamp helpers. Talon stores timestamps as ISO-8601 strings with
//! millisecond precision and a `Z` suffix — byte-identical to JavaScript's
//! `Date.prototype.toISOString()` — so string comparison == time comparison.

use chrono::{DateTime, SecondsFormat, Utc};

/// `2026-10-14T07:47:00.123Z`
pub fn now_iso() -> String {
    to_iso(Utc::now())
}

pub fn to_iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse any RFC 3339 timestamp into UTC.
pub fn parse_iso(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Resolve an IANA timezone name, falling back to UTC.
pub fn parse_tz(name: &str) -> chrono_tz::Tz {
    name.parse::<chrono_tz::Tz>().unwrap_or(chrono_tz::UTC)
}

pub fn is_valid_timezone(name: &str) -> bool {
    name.parse::<chrono_tz::Tz>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_format_matches_js() {
        let t = parse_iso("2026-01-02T03:04:05.006Z").unwrap();
        assert_eq!(to_iso(t), "2026-01-02T03:04:05.006Z");
        assert_eq!(now_iso().len(), 24);
    }

    #[test]
    fn timezone_validation() {
        assert!(is_valid_timezone("Europe/Berlin"));
        assert!(!is_valid_timezone("Mars/Base"));
    }
}
