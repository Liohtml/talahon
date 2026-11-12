//! Text rendering compatible with the Python server.
//!
//! `mysql-mcp-server` 0.4.5 prints every cell with Python's `str()` on the
//! value `mysql-connector-python` (C extension) hands it, so a `TIME` shows
//! up as `datetime.timedelta` text (`1 day, 1:00:00`), a `BLOB` as a `bytes`
//! literal (`b'\x00AB'`), a `DOUBLE` as a Python float (`1e-07`) and so on.
//! Prompts and workflows were written against that text, so this module
//! reproduces it. Every function is pure; the expected strings in the tests
//! were captured from the Python server against MySQL 8.0.

use std::fmt::Write as _;

use serde_json::Value;

/// `str(int(text))`: the canonical decimal form (no leading zeros, as for a
/// `ZEROFILL` column). `None` when `text` is not an integer.
pub fn int_str(text: &str) -> Option<String> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some("0".to_string());
    }
    Some(if negative {
        format!("-{trimmed}")
    } else {
        trimmed.to_string()
    })
}

/// A `BIT(n)` value (big-endian bytes) as the unsigned integer Python shows.
/// `None` for more than 8 bytes (not a valid `BIT`).
pub fn bit_str(bytes: &[u8]) -> Option<String> {
    if bytes.len() > 8 {
        return None;
    }
    let value = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    Some(value.to_string())
}

/// `repr(float)`: shortest round-trip digits, scientific notation below
/// `1e-4` and from `1e16` on, always a fraction or an exponent.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-inf" } else { "inf" }.to_string();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .to_string();
    }
    // Rust's `{:e}` prints the shortest digits that round-trip: "1.2345e-7".
    let sci = format!("{:e}", value.abs());
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let mut out = String::new();
    if value < 0.0 {
        out.push('-');
    }
    if !(-4..16).contains(&exponent) {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let sign = if exponent < 0 { '-' } else { '+' };
        let _ = write!(out, "e{sign}{:02}", exponent.unsigned_abs());
    } else if exponent < 0 {
        out.push_str("0.");
        for _ in 0..(-exponent - 1) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        let int_len = usize::try_from(exponent).unwrap_or(0) + 1;
        if digits.len() <= int_len {
            out.push_str(&digits);
            for _ in digits.len()..int_len {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            out.push_str(&digits[..int_len]);
            out.push('.');
            out.push_str(&digits[int_len..]);
        }
    }
    out
}

/// `str(float(text))` for a `FLOAT` / `DOUBLE` cell. `None` when `text`
/// is not a number.
pub fn float_str(text: &str) -> Option<String> {
    let value: f64 = text.trim().parse().ok()?;
    Some(float_repr(value))
}

/// `str(decimal.Decimal(text))` for a `DECIMAL` cell: the digits as sent,
/// except that values with an adjusted exponent below `-6` switch to
/// scientific notation (`0.0000001` is `1E-7`, a zero `DECIMAL(10,7)` is
/// `0E-7`). `None` when `text` is not a plain decimal number.
pub fn decimal_str(text: &str) -> Option<String> {
    let (sign, body) = match text.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", text.strip_prefix('+').unwrap_or(text)),
    };
    let (int_part, frac_part) = body.split_once('.').unwrap_or((body, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let all = format!("{int_part}{frac_part}");
    let coefficient = match all.trim_start_matches('0') {
        "" => "0",
        rest => rest,
    };
    let exp = -i64::try_from(frac_part.len()).ok()?;
    let len = i64::try_from(coefficient.len()).ok()?;
    let left_digits = exp + len;
    let dot_place = if left_digits > -6 { left_digits } else { 1 };
    let mut out = String::from(sign);
    if dot_place <= 0 {
        out.push_str("0.");
        for _ in 0..(-dot_place) {
            out.push('0');
        }
        out.push_str(coefficient);
    } else if dot_place >= len {
        out.push_str(coefficient);
        for _ in len..dot_place {
            out.push('0');
        }
    } else {
        let split = usize::try_from(dot_place).ok()?;
        out.push_str(&coefficient[..split]);
        out.push('.');
        out.push_str(&coefficient[split..]);
    }
    if left_digits != dot_place {
        let _ = write!(out, "E{:+}", left_digits - dot_place);
    }
    Some(out)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn digits(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 9 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Microseconds from the digits after the decimal point (`"5"` is 500000).
fn micros(fraction: &str) -> Option<u32> {
    if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut padded: String = fraction.chars().take(6).collect();
    while padded.len() < 6 {
        padded.push('0');
    }
    padded.parse().ok()
}

fn parse_date(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.splitn(3, '-');
    let year = digits(parts.next()?)?;
    let month = digits(parts.next()?)?;
    let day = digits(parts.next()?)?;
    let valid = (1..=9999).contains(&year)
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month);
    valid.then_some((year, month, day))
}

/// `str(datetime.date)` for a `DATE` cell. Dates Python cannot represent
/// (`0000-00-00`, a zero month or day) are `None`, which the connector
/// turns into SQL `NULL`.
pub fn date_str(text: &str) -> Option<String> {
    let (year, month, day) = parse_date(text)?;
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// `str(datetime.datetime)` for a `DATETIME` / `TIMESTAMP` cell: a space
/// between date and time, and six fractional digits only when the
/// fraction is not zero. `None` as for [`date_str`].
pub fn datetime_str(text: &str) -> Option<String> {
    let (date, time) = match text.split_once(' ') {
        Some((d, t)) => (d, t),
        None => (text, "00:00:00"),
    };
    let (year, month, day) = parse_date(date)?;
    let (clock, fraction) = match time.split_once('.') {
        Some((c, f)) => (c, Some(f)),
        None => (time, None),
    };
    let mut parts = clock.splitn(3, ':');
    let hour = digits(parts.next()?)?;
    let minute = digits(parts.next()?)?;
    let second = digits(parts.next()?)?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let usec = match fraction {
        Some(f) => micros(f)?,
        None => 0,
    };
    let mut out = format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}");
    if usec != 0 {
        let _ = write!(out, ".{usec:06}");
    }
    Some(out)
}

/// `str(datetime.timedelta)` for a `TIME` cell (`[-]H+:MM:SS[.ffffff]`).
/// Python normalises to days + a non-negative remainder, so `25:00:00` is
/// `1 day, 1:00:00` and `-00:00:05` is `-1 day, 23:59:55`.
pub fn time_str(text: &str) -> Option<String> {
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (clock, fraction) = match body.split_once('.') {
        Some((c, f)) => (c, Some(f)),
        None => (body, None),
    };
    let mut parts = clock.splitn(3, ':');
    let hours = i64::from(digits(parts.next()?)?);
    let minutes = i64::from(digits(parts.next()?)?);
    let seconds = i64::from(digits(parts.next()?)?);
    let usec = match fraction {
        Some(f) => i64::from(micros(f)?),
        None => 0,
    };
    let mut total = ((hours * 60 + minutes) * 60 + seconds) * 1_000_000 + usec;
    if negative {
        total = -total;
    }
    const DAY: i64 = 86_400_000_000;
    let days = total.div_euclid(DAY);
    let rest = total.rem_euclid(DAY);
    let (secs, usec) = (rest / 1_000_000, rest % 1_000_000);
    let mut out = String::new();
    if days != 0 {
        let plural = if days.abs() == 1 { "" } else { "s" };
        let _ = write!(out, "{days} day{plural}, ");
    }
    let _ = write!(
        out,
        "{}:{:02}:{:02}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    );
    if usec != 0 {
        let _ = write!(out, ".{usec:06}");
    }
    Some(out)
}

/// `repr(bytes)`: `b'...'` with `\xNN` for everything outside printable
/// ASCII, double quotes when the value contains `'` but no `"`.
pub fn bytes_repr(bytes: &[u8]) -> String {
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::with_capacity(bytes.len() + 3);
    out.push('b');
    out.push(char::from(quote));
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b if b == quote => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out.push(char::from(quote));
    out
}

/// `repr(str)`: single quotes (double when the text contains `'` but no
/// `"`), backslash escapes for control characters. Printable non-ASCII
/// text is kept. (Python also escapes the unprintable Unicode categories
/// beyond the C0/C1 controls; those are passed through here.)
pub fn str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if u32::from(c) < 0x20 || (0x7f..0xa0).contains(&u32::from(c)) => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `str(set)` for a `SET` cell (`x,z` is `{'x', 'z'}`, the empty set is
/// `set()`). Python's element order changes from process to process (string
/// hashing is randomised); this keeps the order the server sent, which is
/// the column's definition order.
pub fn set_str(text: &str) -> String {
    if text.is_empty() {
        return "set()".to_string();
    }
    let mut seen: Vec<&str> = Vec::new();
    for member in text.split(',') {
        if !seen.contains(&member) {
            seen.push(member);
        }
    }
    let members: Vec<String> = seen.into_iter().map(str_repr).collect();
    format!("{{{}}}", members.join(", "))
}

/// `repr()` of a JSON value as Python sees it after `json.loads`
/// (`None`, `True`, `['a', 1]`, `{'k': 2.5}`), used in argument errors.
pub fn json_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                n.to_string()
            } else {
                n.as_f64().map_or_else(|| n.to_string(), float_repr)
            }
        }
        Value::String(s) => str_repr(s),
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(json_repr).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Object(map) => {
            let items: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", str_repr(k), json_repr(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

/// `str.isspace()` for the characters `str.strip()` removes.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `text.strip()`.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn integers_are_canonical() {
        assert_eq!(int_str("-128").as_deref(), Some("-128"));
        assert_eq!(
            int_str("18446744073709551615").as_deref(),
            Some("18446744073709551615")
        );
        assert_eq!(int_str("00042").as_deref(), Some("42"));
        assert_eq!(int_str("-007").as_deref(), Some("-7"));
        assert_eq!(int_str("0000").as_deref(), Some("0"));
        assert_eq!(int_str("-0").as_deref(), Some("0"));
        assert_eq!(int_str(""), None);
        assert_eq!(int_str("1.5"), None);
        assert_eq!(int_str("abc"), None);
    }

    #[test]
    fn bits_are_unsigned_integers() {
        assert_eq!(bit_str(&[1]).as_deref(), Some("1"));
        assert_eq!(bit_str(&[0xa5]).as_deref(), Some("165"));
        assert_eq!(bit_str(&[0xff; 8]).as_deref(), Some("18446744073709551615"));
        assert_eq!(bit_str(&[]).as_deref(), Some("0"));
        assert_eq!(bit_str(&[0; 9]), None);
    }

    #[test]
    fn floats_match_python_repr() {
        // (server text, Python output) as captured from the Python server.
        for (text, expected) in [
            ("1.5", "1.5"),
            ("1e20", "1e+20"),
            ("0.1", "0.1"),
            ("3.141592653589793", "3.141592653589793"),
            ("1e-7", "1e-07"),
            ("100", "100.0"),
            ("1", "1.0"),
            ("1e30", "1e+30"),
            ("1.2345678901234568e17", "1.2345678901234568e+17"),
            ("1e-10", "1e-10"),
            ("16777200", "16777200.0"),
            ("1.17549e-38", "1.17549e-38"),
            ("3.40282e38", "3.40282e+38"),
            ("0.3", "0.3"),
            ("1e15", "1000000000000000.0"),
            ("1e16", "1e+16"),
            ("1e17", "1e+17"),
            ("0.0001", "0.0001"),
            ("0.00001", "1e-05"),
            ("0", "0.0"),
            ("-0", "-0.0"),
            ("-2.5", "-2.5"),
            ("123456.789", "123456.789"),
            ("-1.5e-300", "-1.5e-300"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("0.00012345", "0.00012345"),
            ("9999999999999998", "9999999999999998.0"),
        ] {
            assert_eq!(float_str(text).as_deref(), Some(expected), "{text}");
        }
        assert_eq!(float_str("abc"), None);
        assert_eq!(float_repr(f64::INFINITY), "inf");
        assert_eq!(float_repr(f64::NEG_INFINITY), "-inf");
        assert_eq!(float_repr(f64::NAN), "nan");
    }

    #[test]
    fn decimals_match_python_str() {
        for (text, expected) in [
            ("-12345678901234.123456", "-12345678901234.123456"),
            ("0.000000", "0.000000"),
            ("1.100000", "1.100000"),
            ("1.50", "1.50"),
            ("0.3333", "0.3333"),
            ("5.0000", "5.0000"),
            ("1.500", "1.500"),
            ("0.0", "0.0"),
            ("-0.0", "-0.0"),
            ("42", "42"),
            ("0", "0"),
            ("007.10", "7.10"),
            // Adjusted exponent below -6: Python switches to scientific.
            ("0.0000000", "0E-7"),
            ("0.0000001", "1E-7"),
            ("0.00000010", "1.0E-7"),
            ("0.0000001234", "1.234E-7"),
            ("-0.0000000001", "-1E-10"),
            ("0.000001", "0.000001"),
            ("0.0000010", "0.0000010"),
            ("0.00000100", "0.00000100"),
            ("123.0000000", "123.0000000"),
        ] {
            assert_eq!(decimal_str(text).as_deref(), Some(expected), "{text}");
        }
        assert_eq!(decimal_str(""), None);
        assert_eq!(decimal_str("."), None);
        assert_eq!(decimal_str("1e5"), None);
        assert_eq!(decimal_str("abc"), None);
    }

    #[test]
    fn dates_and_datetimes() {
        assert_eq!(date_str("2025-01-02").as_deref(), Some("2025-01-02"));
        assert_eq!(date_str("1000-01-01").as_deref(), Some("1000-01-01"));
        assert_eq!(date_str("2024-02-29").as_deref(), Some("2024-02-29"));
        assert_eq!(date_str("0900-02-28").as_deref(), Some("0900-02-28"));
        // Not representable in Python: the connector yields None.
        assert_eq!(date_str("0000-00-00"), None);
        assert_eq!(date_str("2025-00-10"), None);
        assert_eq!(date_str("2025-02-30"), None);
        assert_eq!(date_str("2023-02-29"), None);
        assert_eq!(date_str("1900-02-29"), None);
        assert_eq!(date_str("2000-02-29").as_deref(), Some("2000-02-29"));
        assert_eq!(date_str("garbage"), None);

        assert_eq!(
            datetime_str("2025-01-02 03:04:05").as_deref(),
            Some("2025-01-02 03:04:05")
        );
        assert_eq!(
            datetime_str("2025-01-02 03:04:05.123456").as_deref(),
            Some("2025-01-02 03:04:05.123456")
        );
        assert_eq!(
            datetime_str("2025-01-02 03:04:05.120").as_deref(),
            Some("2025-01-02 03:04:05.120000")
        );
        assert_eq!(
            datetime_str("2025-01-02 03:04:05.000000").as_deref(),
            Some("2025-01-02 03:04:05")
        );
        assert_eq!(
            datetime_str("2025-01-01 10:00:00.5").as_deref(),
            Some("2025-01-01 10:00:00.500000")
        );
        assert_eq!(
            datetime_str("9999-12-31 23:59:59").as_deref(),
            Some("9999-12-31 23:59:59")
        );
        assert_eq!(
            datetime_str("2025-01-02").as_deref(),
            Some("2025-01-02 00:00:00")
        );
        assert_eq!(datetime_str("0000-00-00 00:00:00"), None);
        assert_eq!(datetime_str("2025-01-02 24:00:00"), None);
        assert_eq!(datetime_str("2025-01-02 03:04"), None);
    }

    #[test]
    fn times_are_timedeltas() {
        for (text, expected) in [
            ("01:02:03", "1:02:03"),
            ("00:00:00", "0:00:00"),
            ("838:59:59", "34 days, 22:59:59"),
            ("-838:59:59.000000", "-35 days, 1:00:01"),
            ("25:00:00.5", "1 day, 1:00:00.500000"),
            ("-00:00:01.5", "-1 day, 23:59:58.500000"),
            ("25:00:00", "1 day, 1:00:00"),
            ("-25:01:01", "-2 days, 22:58:59"),
            ("-02:30:15", "-1 day, 21:29:45"),
            ("00:00:00.25", "0:00:00.250000"),
            ("100:00:00", "4 days, 4:00:00"),
            ("24:00:00", "1 day, 0:00:00"),
            ("00:00:05", "0:00:05"),
            ("-00:00:05", "-1 day, 23:59:55"),
            ("-30:00:05.120000", "-2 days, 17:59:54.880000"),
            ("-24:00:00", "-1 day, 0:00:00"),
            ("-48:00:00", "-2 days, 0:00:00"),
            ("12:34:56.000001", "12:34:56.000001"),
        ] {
            assert_eq!(time_str(text).as_deref(), Some(expected), "{text}");
        }
        assert_eq!(time_str("garbage"), None);
        assert_eq!(time_str("1:2"), None);
    }

    #[test]
    fn bytes_literals() {
        assert_eq!(bytes_repr(b"\x00\xffAB"), r"b'\x00\xffAB'");
        assert_eq!(bytes_repr(b""), "b''");
        assert_eq!(bytes_repr(b"abcd"), "b'abcd'");
        assert_eq!(bytes_repr(b"x\x00\x00\x00"), r"b'x\x00\x00\x00'");
        // 0x00 0x01 0x02 0xff 0xfe ' " \
        assert_eq!(
            bytes_repr(b"\x00\x01\x02\xff\xfe'\"\\"),
            "b'\\x00\\x01\\x02\\xff\\xfe\\'\"\\\\'"
        );
        assert_eq!(bytes_repr(b"it's"), "b\"it's\"");
        assert_eq!(bytes_repr(b"tab\there\r\n"), r"b'tab\there\r\n'");
        assert_eq!(bytes_repr(b"\x7f~ "), r"b'\x7f~ '");
        assert_eq!(bytes_repr("é".as_bytes()), r"b'\xc3\xa9'");
    }

    #[test]
    fn str_and_set_repr() {
        assert_eq!(str_repr("abc"), "'abc'");
        assert_eq!(str_repr("it's"), "\"it's\"");
        assert_eq!(str_repr("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(str_repr("x\ny\\"), "'x\\ny\\\\'");
        assert_eq!(str_repr("é✓"), "'é✓'");
        assert_eq!(str_repr("\u{1}\u{85}"), "'\\x01\\x85'");
        assert_eq!(set_str(""), "set()");
        assert_eq!(set_str("x"), "{'x'}");
        assert_eq!(set_str("x,z"), "{'x', 'z'}");
        assert_eq!(set_str("x,y,z"), "{'x', 'y', 'z'}");
    }

    #[test]
    fn json_values_as_python() {
        assert_eq!(json_repr(&json!(null)), "None");
        assert_eq!(json_repr(&json!(true)), "True");
        assert_eq!(json_repr(&json!(false)), "False");
        assert_eq!(json_repr(&json!(123)), "123");
        assert_eq!(json_repr(&json!(-1)), "-1");
        assert_eq!(json_repr(&json!(2.5)), "2.5");
        assert_eq!(json_repr(&json!(2.0)), "2.0");
        assert_eq!(json_repr(&json!(1e30)), "1e+30");
        assert_eq!(json_repr(&json!("3")), "'3'");
        assert_eq!(json_repr(&json!(["SELECT 1"])), "['SELECT 1']");
        assert_eq!(json_repr(&json!([1, "a", null])), "[1, 'a', None]");
        assert_eq!(json_repr(&json!({"k": [true]})), "{'k': [True]}");
        assert_eq!(json_repr(&json!([])), "[]");
        assert_eq!(json_repr(&json!({})), "{}");
    }

    #[test]
    fn strip_like_python() {
        assert_eq!(strip("  \n show tables \t"), "show tables");
        assert_eq!(strip("\u{1c}x\u{1f}"), "x");
        assert_eq!(strip("\u{a0}x\u{3000}"), "x");
        assert_eq!(strip(""), "");
    }
}
