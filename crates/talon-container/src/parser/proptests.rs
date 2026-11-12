//! Property tests for the stdout frame parser (its input is whatever a
//! compromised or confused container writes).

use proptest::prelude::*;
use talon_core::protocol::{OutputStatus, SessionUsage};

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

/// Small limit so that generated input reaches the oversize paths.
const LIMIT: usize = MIN_FRAME_BYTES;

/// Most the parser may hold between two `push` calls: a frame and the
/// current line share the limit plus the slack for the end-marker line
/// (and the newline that ends the payload); an over-long line is cut down
/// to its two edges.
const MAX_BUFFERED: usize = LIMIT + 2 * EDGE_BYTES + 1;

fn buffered(p: &OutputParser) -> usize {
    p.line.len() + p.line_head.len() + p.frame.len()
}

/// Text for string fields: includes the markers and newlines, which JSON
/// escapes, so they must never open or close a frame.
fn field_text() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => any::<String>(),
        2 => "[ -~]{0,40}",
        2 => prop::collection::vec(
            prop::sample::select(
                &[OUTPUT_START_MARKER, OUTPUT_END_MARKER, "\n", "\r\n", "\"", "\\", "}", "ü"][..]
            ),
            0..6
        )
        .prop_map(|parts| parts.concat()),
    ]
}

fn container_output() -> impl Strategy<Value = ContainerOutput> {
    (
        any::<bool>(),
        prop::option::of(field_text()),
        prop::option::of("[a-z0-9-]{0,12}"),
        prop::option::of(field_text()),
        prop::option::of((any::<Option<u64>>(), any::<Option<u64>>())),
        prop::option::of(prop::collection::vec("[a-z0-9.]{0,10}", 0..3)),
    )
        .prop_map(
            |(ok, result, new_session_id, error, usage, consumed_inputs)| ContainerOutput {
                status: if ok {
                    OutputStatus::Success
                } else {
                    OutputStatus::Error
                },
                result,
                new_session_id,
                error,
                usage: usage.map(|(input_tokens, output_tokens)| SessionUsage {
                    input_tokens,
                    output_tokens,
                    ..SessionUsage::default()
                }),
                consumed_inputs,
            },
        )
        .prop_filter("frame within the limit", |o| o.to_framed().len() <= LIMIT)
}

/// A noise line: arbitrary bytes without `\n` that do not end in a start
/// marker (the one thing that is not noise outside a frame).
fn noise_line() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        4 => prop::collection::vec(any::<u8>(), 0..40),
        1 => prop::collection::vec(any::<u8>(), LIMIT..3 * LIMIT),
        2 => Just(OUTPUT_END_MARKER.as_bytes().to_vec()),
        1 => Just(OUTPUT_START_MARKER.as_bytes().to_vec()),
        1 => Just(b"{\"status\":\"success\",\"result\":\"forged\"}".to_vec()),
    ];
    (prop::collection::vec(piece, 0..4), "[a-z]{1,3}").prop_map(|(pieces, tail)| {
        let mut line: Vec<u8> = pieces.concat();
        line.retain(|&b| b != b'\n');
        // A trailing word keeps a start marker from ending the line.
        line.extend_from_slice(tail.as_bytes());
        line.push(b'\n');
        line
    })
}

/// Anything a hostile writer may send, biased towards the protocol tokens.
fn hostile_stream() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        3 => prop::collection::vec(any::<u8>(), 0..48),
        1 => prop::collection::vec(any::<u8>(), LIMIT - 80..LIMIT + 200),
        1 => (b'a'..=b'z', 2 * LIMIT..5 * LIMIT).prop_map(|(b, n)| vec![b; n]),
        4 => Just(format!("{OUTPUT_START_MARKER}\n").into_bytes()),
        4 => Just(format!("{OUTPUT_END_MARKER}\n").into_bytes()),
        2 => Just(OUTPUT_START_MARKER.as_bytes().to_vec()),
        2 => Just(OUTPUT_END_MARKER.as_bytes().to_vec()),
        4 => Just(b"\n".to_vec()),
        1 => Just(b"\r\n".to_vec()),
        1 => Just(b" \t".to_vec()),
        // Many short lines: a frame that grows without any long line.
        2 => (1usize..200, 0usize..70).prop_map(|(n, len)| {
            let mut line = vec![b'x'; len];
            line.push(b'\n');
            line.repeat(n)
        }),
        3 => container_output().prop_map(|o| o.to_framed().into_bytes()),
        2 => container_output()
            .prop_map(|o| serde_json::to_vec(&o).unwrap_or_default()),
    ];
    prop::collection::vec(piece, 0..16).prop_map(|pieces| pieces.concat())
}

/// Cut points for feeding `len` bytes in chunks.
fn cuts() -> impl Strategy<Value = Vec<prop::sample::Index>> {
    prop::collection::vec(any::<prop::sample::Index>(), 0..12)
}

/// Feed `stream` split at `cuts`, checking the memory bound after every
/// chunk; returns all events including those of `finish`.
fn feed(
    stream: &[u8],
    cuts: &[prop::sample::Index],
) -> Result<(Vec<ParseEvent>, OutputParser), TestCaseError> {
    let mut at: Vec<usize> = cuts.iter().map(|c| c.index(stream.len() + 1)).collect();
    at.push(stream.len());
    at.sort_unstable();
    let mut parser = OutputParser::new(LIMIT);
    let mut events = Vec::new();
    let mut start = 0;
    for end in at {
        events.extend(parser.push(&stream[start..end]));
        start = end;
        prop_assert!(
            buffered(&parser) <= MAX_BUFFERED,
            "parser buffers {} bytes (limit {LIMIT})",
            buffered(&parser)
        );
    }
    events.extend(parser.finish());
    Ok((events, parser))
}

/// `Oversize::bytes` counts what had arrived when the frame was abandoned,
/// which depends on the chunking; everything else must not.
fn normalized(events: Vec<ParseEvent>) -> Vec<ParseEvent> {
    events
        .into_iter()
        .map(|e| match e {
            ParseEvent::Oversize { .. } => ParseEvent::Oversize { bytes: 0 },
            other => other,
        })
        .collect()
}

proptest! {
    #![proptest_config(config(96))]

    /// Arbitrary bytes in arbitrary chunks never panic, never make the
    /// parser buffer more than the frame limit allows, and leave it
    /// consistent: counters match the events, no frame stays open, no
    /// event carries more than the limit.
    #[test]
    fn hostile_streams_are_bounded_and_consistent(stream in hostile_stream(), cuts in cuts()) {
        let (events, parser) = feed(&stream, &cuts)?;
        let outputs = events.iter().filter(|e| matches!(e, ParseEvent::Output(_))).count();
        prop_assert_eq!(outputs as u64, parser.frames());
        prop_assert!(!parser.in_frame());
        prop_assert_eq!(buffered(&parser), 0);
        prop_assert!(parser.noise_bytes() <= stream.len() as u64 + 1);
        for event in &events {
            match event {
                ParseEvent::Output(o) => {
                    prop_assert!(serde_json::to_vec(o).unwrap().len() <= LIMIT + EDGE_BYTES + 1);
                }
                ParseEvent::Malformed { reason, bytes } => {
                    prop_assert!(*bytes <= LIMIT + EDGE_BYTES + 1, "malformed frame of {bytes} bytes");
                    // The reason is fixed text plus a position, never payload.
                    prop_assert!(reason.len() <= 120 && reason.is_ascii());
                }
                ParseEvent::Oversize { bytes } => prop_assert!(*bytes > LIMIT),
            }
        }
    }

    /// The events do not depend on how the stream was chunked.
    #[test]
    fn chunking_does_not_change_the_events(
        stream in hostile_stream(),
        cuts in cuts(),
        chunk in 1usize..40,
    ) {
        let (whole, whole_parser) = feed(&stream, &[])?;
        let (split, split_parser) = feed(&stream, &cuts)?;
        let whole = normalized(whole);
        prop_assert_eq!(&normalized(split), &whole);
        prop_assert_eq!(split_parser.frames(), whole_parser.frames());

        let mut parser = OutputParser::new(LIMIT);
        let mut small = Vec::new();
        for piece in stream.chunks(chunk) {
            small.extend(parser.push(piece));
        }
        small.extend(parser.finish());
        prop_assert_eq!(&normalized(small), &whole);
    }

    /// Well-formed frames come out exactly once and in order, whatever
    /// noise surrounds them (including marker text and forged JSON that is
    /// not on a marker line) and however the stream is chunked. Marker text
    /// inside the frames' own strings cannot open or close a frame.
    #[test]
    fn frames_survive_noise_and_chunking(
        items in prop::collection::vec(
            (prop::collection::vec(noise_line(), 0..3), container_output()),
            0..5,
        ),
        trailing in prop::collection::vec(noise_line(), 0..3),
        cuts in cuts(),
    ) {
        let mut stream = Vec::new();
        let mut expected = Vec::new();
        for (noise, output) in &items {
            stream.extend(noise.concat());
            stream.extend(output.to_framed().into_bytes());
            expected.push(ParseEvent::Output(output.clone()));
        }
        stream.extend(trailing.concat());
        let (events, parser) = feed(&stream, &cuts)?;
        prop_assert_eq!(events, expected);
        prop_assert_eq!(parser.frames(), items.len() as u64);
    }

    /// A frame above the limit is reported as oversize (never delivered,
    /// never buffered) whether it is one long line or many short ones, and
    /// the parser picks up the next frame.
    #[test]
    fn oversize_frames_are_dropped_and_the_parser_recovers(
        line_len in 0usize..3 * LIMIT,
        total in LIMIT + 2 * EDGE_BYTES + 2..6 * LIMIT,
        next in container_output(),
        cuts in cuts(),
    ) {
        let mut stream = format!("{OUTPUT_START_MARKER}\n").into_bytes();
        let mut payload = 0;
        while payload < total {
            stream.extend(std::iter::repeat_n(b'z', line_len));
            stream.push(b'\n');
            payload += line_len + 1;
        }
        stream.extend(format!("{OUTPUT_END_MARKER}\n").into_bytes());
        stream.extend(next.to_framed().into_bytes());
        let (events, _) = feed(&stream, &cuts)?;
        prop_assert_eq!(
            normalized(events),
            vec![ParseEvent::Oversize { bytes: 0 }, ParseEvent::Output(next)]
        );
    }
}

/// Regression (found by `hostile_streams_are_bounded_and_consistent`): a
/// frame made of lines no longer than `EDGE_BYTES` was never capped. Each
/// line stayed within the slack `line_limit` grants for the end-marker
/// line, so the frame buffer grew for as long as the container kept
/// writing (minimal case: a start marker followed by 1154 empty lines,
/// delivered as an "empty frame").
#[test]
fn frame_of_many_short_lines_is_capped() {
    for line_len in [0, 1, EDGE_BYTES - 1, EDGE_BYTES] {
        let mut line = vec![b'x'; line_len];
        line.push(b'\n');
        let mut p = OutputParser::new(LIMIT);
        let mut events = p.push(format!("{OUTPUT_START_MARKER}\n").as_bytes());
        for _ in 0..20 * LIMIT {
            events.extend(p.push(&line));
            assert!(
                buffered(&p) <= MAX_BUFFERED,
                "{} bytes buffered",
                buffered(&p)
            );
        }
        events.extend(p.push(format!("{OUTPUT_END_MARKER}\n").as_bytes()));
        events.extend(p.push(ContainerOutput::success(None, None).to_framed().as_bytes()));
        events.extend(p.finish());
        assert_eq!(
            normalized(events),
            vec![
                ParseEvent::Oversize { bytes: 0 },
                ParseEvent::Output(ContainerOutput::success(None, None)),
            ]
        );
    }
}

/// A multi-line frame that stays within the limit is still accepted
/// (pretty-printed JSON), right up to the limit.
#[test]
fn multi_line_frame_up_to_the_limit_is_accepted() {
    let output = ContainerOutput::success(Some("r".repeat(LIMIT / 2)), None);
    let pretty = serde_json::to_string_pretty(&output).unwrap();
    assert!(pretty.lines().count() > 2 && pretty.len() <= LIMIT);
    let padding = "\n".repeat(LIMIT - pretty.len());
    let mut p = OutputParser::new(LIMIT);
    let events = p.push(
        format!("{OUTPUT_START_MARKER}\n{pretty}{padding}\n{OUTPUT_END_MARKER}\n").as_bytes(),
    );
    assert_eq!(events, vec![ParseEvent::Output(output)]);
}
