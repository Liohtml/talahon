//! The host binary under its current name (`talahon`) and under the alias it
//! keeps for one major version (`talon`): same behaviour, plus a one-line
//! deprecation notice on stderr for the alias — except where the output is
//! what another program compares (`version`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

const TALAHON: &str = env!("CARGO_BIN_EXE_talahon");
const TALON: &str = env!("CARGO_BIN_EXE_talon");
const NOTICE: &str = "talon: this command is now called `talahon`";

fn run(bin: &str, root: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin);
    cmd.args(args).current_dir(root);
    for key in [
        "TALAHON_PROJECT_ROOT",
        "TALON_PROJECT_ROOT",
        "TALAHON_LOG_FORMAT",
        "TALON_LOG_FORMAT",
        "RUST_LOG",
    ] {
        cmd.env_remove(key);
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn version_is_identical_and_silent_under_both_names() {
    let dir = tempfile::tempdir().unwrap();
    let new = run(TALAHON, dir.path(), &["version"], &[]);
    let old = run(TALON, dir.path(), &["version"], &[]);
    assert!(new.status.success() && old.status.success());
    assert_eq!(new.stdout, old.stdout);
    assert!(text(&new.stdout).starts_with("talahon "));
    // Scripts compare this output: no notice, on either stream.
    assert_eq!(text(&old.stderr), "");
    assert_eq!(text(&new.stderr), "");
}

#[test]
fn the_old_name_prints_one_deprecation_notice_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    // An unknown setup step: no side effects, same result under both names.
    let args = ["setup", "no-such-step"];
    let new = run(TALAHON, dir.path(), &args, &[]);
    let old = run(TALON, dir.path(), &args, &[]);
    assert_eq!(new.status.code(), Some(1));
    assert_eq!(old.status.code(), Some(1));
    assert_eq!(new.stdout, old.stdout, "stdout must not differ");
    assert!(!text(&new.stderr).contains(NOTICE));

    let stderr = text(&old.stderr);
    assert_eq!(stderr.matches(NOTICE).count(), 1, "{stderr}");
    let line = stderr.lines().find(|l| l.contains(NOTICE)).unwrap();
    assert!(line.starts_with("talon: "), "a plain line: {line}");
    assert!(line.contains("next major version"), "{line}");
    // Apart from the notice the alias says what `talahon` says (log lines
    // carry timestamps, so the comparison is by count).
    assert_eq!(
        stderr.lines().filter(|l| !l.contains(NOTICE)).count(),
        text(&new.stderr).lines().count()
    );
}

#[test]
fn with_json_logs_the_notice_is_a_json_record() {
    let dir = tempfile::tempdir().unwrap();
    for (key, deprecated_key) in [
        ("TALAHON_LOG_FORMAT", false),
        // The old spelling of the setting works too (and is reported).
        ("TALON_LOG_FORMAT", true),
    ] {
        let old = run(
            TALON,
            dir.path(),
            &["setup", "no-such-step"],
            &[(key, "json")],
        );
        let stderr = text(&old.stderr);
        let notices: Vec<&str> = stderr.lines().filter(|l| l.contains(NOTICE)).collect();
        assert_eq!(notices.len(), 1, "{stderr}");
        let record: serde_json::Value = serde_json::from_str(notices[0])
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", notices[0]));
        assert_eq!(record["level"], "WARN");
        // Every log line of the stream stays parseable.
        for line in stderr.lines().filter(|l| l.starts_with('{')) {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
        let key_warning = "TALON_LOG_FORMAT is deprecated: rename it to TALAHON_LOG_FORMAT";
        assert_eq!(
            stderr.matches(key_warning).count(),
            usize::from(deprecated_key),
            "{stderr}"
        );
    }
}

#[test]
fn the_old_project_root_variable_is_still_read() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "TALAHON_LOG_FORMAT=json\n").unwrap();
    // Started somewhere else: only TALON_PROJECT_ROOT points at the project
    // whose `.env` asks for JSON logs.
    let out = run(
        TALAHON,
        elsewhere.path(),
        &["audit", "verify"],
        &[("TALON_PROJECT_ROOT", dir.path().to_str().unwrap())],
    );
    let stderr = text(&out.stderr);
    let warning = "TALON_PROJECT_ROOT is deprecated: rename it to TALAHON_PROJECT_ROOT";
    let lines: Vec<&str> = stderr.lines().filter(|l| l.contains(warning)).collect();
    assert_eq!(lines.len(), 1, "{stderr}");
    assert!(
        lines[0].starts_with('{'),
        "the project's .env was used: {stderr}"
    );
    // The new name wins when both are set: no JSON, no warning.
    let out = run(
        TALAHON,
        elsewhere.path(),
        &["audit", "verify"],
        &[
            ("TALON_PROJECT_ROOT", dir.path().to_str().unwrap()),
            ("TALAHON_PROJECT_ROOT", elsewhere.path().to_str().unwrap()),
        ],
    );
    assert!(!text(&out.stderr).contains(warning));
}
