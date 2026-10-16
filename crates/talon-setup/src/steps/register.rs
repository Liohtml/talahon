//! Step `register`: register a chat (JID) as
//! a group, create its folder and `CLAUDE.md`, and optionally rename the
//! assistant.
//!
//! Arguments: `--jid`, `--name`, `--trigger`, `--folder` (required),
//! `--channel` (default: inferred from the JID), `--no-trigger-required`,
//! `--is-main`, `--assistant-name`.
//!
//! Hardening: every input is validated (no
//! control characters, bounded lengths, quote-free assistant name), the
//! group folder is resolved traversal-safe, re-registering keeps an existing
//! group's container config and lane settings, and `CLAUDE.md` files are
//! never written through symlinks (group folders are agent-writable).

use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use regex::{NoExpand, Regex};
use talon_core::paths::{group_folder_path, is_valid_group_folder};
use talon_core::time::now_iso;
use talon_core::types::RegisteredGroup;

use super::StepArgs;
use crate::context::{SETUP_LOG, SetupContext};
use crate::fsutil::{
    exists_nofollow, file_mode, is_real_dir, is_regular_file_nofollow, read_env_value,
    upsert_env_line, write_atomic,
};
use crate::status::{StatusBlock, StepOutcome};

/// The assistant name the shipped `CLAUDE.md` templates use.
pub const DEFAULT_ASSISTANT_NAME: &str = "Talon";

const MAX_JID_LEN: usize = 256;
const MAX_NAME_LEN: usize = 200;
const MAX_TRIGGER_LEN: usize = 64;
const MAX_ASSISTANT_NAME_LEN: usize = 64;

/// Parsed `register` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    /// Chat id, e.g. `tg:-1001234567890` or `http:copilot`.
    pub jid: String,
    /// Display name.
    pub name: String,
    /// Trigger word, e.g. `@Talon`.
    pub trigger: String,
    /// Group folder under `groups/`.
    pub folder: String,
    /// Channel name (reporting only).
    pub channel: String,
    /// Whether non-main messages need the trigger.
    pub requires_trigger: bool,
    /// Register as the main control group.
    pub is_main: bool,
    /// Assistant name to apply to `CLAUDE.md` files and `.env`; empty
    /// keeps the current one.
    pub assistant_name: String,
}

/// Channel name implied by a JID prefix.
pub fn infer_channel(jid: &str) -> &'static str {
    if jid.starts_with("tg:") {
        "telegram"
    } else if jid.starts_with("http:") {
        "http"
    } else if jid.starts_with("webhook") {
        "webhook"
    } else if jid.starts_with("emacs") {
        "emacs"
    } else if jid.ends_with("@g.us") || jid.ends_with("@s.whatsapp.net") {
        "whatsapp"
    } else {
        "unknown"
    }
}

impl RegisterRequest {
    /// Parse step arguments.
    pub fn from_args(args: &StepArgs) -> Self {
        let get = |k: &str| args.value(k).unwrap_or("").trim().to_string();
        let jid = get("--jid");
        let channel = match args.value("--channel") {
            Some(c) if !c.trim().is_empty() => c.trim().to_lowercase(),
            _ => infer_channel(&jid).to_string(),
        };
        let assistant_name = args
            .value("--assistant-name")
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        Self {
            name: get("--name"),
            trigger: get("--trigger"),
            folder: get("--folder"),
            requires_trigger: !args.flag("--no-trigger-required"),
            is_main: args.flag("--is-main"),
            jid,
            channel,
            assistant_name,
        }
    }

    /// Validate; returns the status-block error code on failure.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.jid.is_empty()
            || self.name.is_empty()
            || self.trigger.is_empty()
            || self.folder.is_empty()
        {
            return Err("missing_required_args");
        }
        if !is_valid_group_folder(&self.folder) {
            return Err("invalid_folder");
        }
        let has_control = |s: &str| s.chars().any(char::is_control);
        if self.jid.len() > MAX_JID_LEN
            || has_control(&self.jid)
            || self.jid.contains(char::is_whitespace)
        {
            return Err("invalid_jid");
        }
        if self.name.chars().count() > MAX_NAME_LEN || has_control(&self.name) {
            return Err("invalid_name");
        }
        if self.trigger.chars().count() > MAX_TRIGGER_LEN || has_control(&self.trigger) {
            return Err("invalid_trigger");
        }
        if self.assistant_name.chars().count() > MAX_ASSISTANT_NAME_LEN
            || has_control(&self.assistant_name)
            || self.assistant_name.contains(['"', '\\', '$', '`'])
        {
            return Err("invalid_assistant_name");
        }
        Ok(())
    }
}

fn failed(error: &str) -> StepOutcome {
    StepOutcome::with_code(
        StatusBlock::new("REGISTER_CHANNEL")
            .field("STATUS", "failed")
            .field("ERROR", error)
            .field("LOG", SETUP_LOG),
        4,
    )
}

/// Create `groups/<folder>/logs` and, if the folder has no `CLAUDE.md`
/// yet, copy the main (`groups/main`) or global (`groups/global`) template.
/// An existing `CLAUDE.md` (or anything at that path, including a symlink)
/// is never overwritten. Returns whether a template was copied.
///
/// # Errors
/// Invalid folder names and I/O errors.
pub fn prepare_group_folder(
    groups_dir: &Path,
    folder: &str,
    is_main: bool,
) -> anyhow::Result<bool> {
    let group_dir = group_folder_path(groups_dir, folder)?;
    std::fs::create_dir_all(group_dir.join("logs"))
        .with_context(|| format!("creating {}", group_dir.display()))?;
    let dest = group_dir.join("CLAUDE.md");
    if exists_nofollow(&dest) {
        return Ok(false);
    }
    let template = groups_dir
        .join(if is_main { "main" } else { "global" })
        .join("CLAUDE.md");
    if !is_regular_file_nofollow(&template) {
        return Ok(false);
    }
    let content =
        std::fs::read(&template).with_context(|| format!("reading {}", template.display()))?;
    write_atomic(&dest, &content, file_mode(&template))?;
    tracing::info!(file = %dest.display(), template = %template.display(), "Created CLAUDE.md from template");
    Ok(true)
}

/// Replace assistant name `old_name` in `content` with `new_name`: the first
/// `# <old>` heading line and every `You are <old>`.
pub fn rename_assistant(content: &str, old_name: &str, new_name: &str) -> String {
    // The name is escaped, so the pattern always compiles.
    let heading = Regex::new(&format!(r"(?m)^# {}$", regex::escape(old_name)));
    let content = match heading {
        Ok(re) => re
            .replacen(content, 1, NoExpand(&format!("# {new_name}")))
            .into_owned(),
        Err(_) => content.to_string(),
    };
    content.replace(
        &format!("You are {old_name}"),
        &format!("You are {new_name}"),
    )
}

/// Apply [`rename_assistant`] to `groups/*/CLAUDE.md`, skipping symlinked
/// folders and files. Returns the files changed.
///
/// # Errors
/// I/O errors reading the groups directory or writing a file.
pub fn apply_assistant_name(
    groups_dir: &Path,
    old_name: &str,
    new_name: &str,
) -> io::Result<Vec<PathBuf>> {
    let mut changed = Vec::new();
    let entries = match std::fs::read_dir(groups_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(changed),
        Err(e) => return Err(e),
    };
    let mut dirs: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    dirs.sort();
    for dir in dirs {
        if !is_real_dir(&dir) {
            continue;
        }
        let md = dir.join("CLAUDE.md");
        if !is_regular_file_nofollow(&md) {
            continue;
        }
        let content = std::fs::read_to_string(&md)?;
        let updated = rename_assistant(&content, old_name, new_name);
        if updated != content {
            write_atomic(&md, updated.as_bytes(), file_mode(&md))?;
            tracing::info!(file = %md.display(), "Updated CLAUDE.md");
            changed.push(md);
        }
    }
    Ok(changed)
}

/// Run the step.
///
/// # Errors
/// Database and filesystem failures.
pub async fn run(args: &StepArgs, ctx: &SetupContext) -> anyhow::Result<StepOutcome> {
    let req = RegisterRequest::from_args(args);
    if let Err(code) = req.validate() {
        return Ok(failed(code));
    }
    tracing::info!(jid = %req.jid, folder = %req.folder, channel = %req.channel, "Registering channel");

    std::fs::create_dir_all(&ctx.config.data_dir).context("creating data dir")?;
    std::fs::create_dir_all(&ctx.config.store_dir).context("creating store dir")?;

    let jid = req.jid.clone();
    let mut group = RegisteredGroup {
        name: req.name.clone(),
        folder: req.folder.clone(),
        trigger: req.trigger.clone(),
        added_at: now_iso(),
        container_config: None,
        requires_trigger: Some(req.requires_trigger),
        is_main: req.is_main,
        session_key: None,
        ipc_key: None,
        ephemeral_session: false,
        trusted_session_commands: false,
    };
    let preserved = ctx
        .with_db(move |db| {
            let existing = db.get_registered_group(&jid)?;
            let preserved = existing.is_some();
            if let Some(old) = existing {
                group.added_at = old.added_at;
                group.container_config = old.container_config;
                group.session_key = old.session_key;
                group.ipc_key = old.ipc_key;
                group.ephemeral_session = old.ephemeral_session;
                group.trusted_session_commands = old.trusted_session_commands;
            }
            db.set_registered_group(&jid, &group)?;
            Ok(preserved)
        })
        .await
        .context("writing registration to the database")?;
    tracing::info!("Wrote registration to SQLite");

    let template_copied = prepare_group_folder(&ctx.config.groups_dir, &req.folder, req.is_main)?;

    // The name in use: what an earlier run wrote to `.env`, else the one
    // the templates ship with. Without `--assistant-name` it stays.
    let current = read_env_value(&ctx.env_path(), "ASSISTANT_NAME")
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| DEFAULT_ASSISTANT_NAME.to_string());
    let wanted = if req.assistant_name.is_empty() {
        current.clone()
    } else {
        req.assistant_name.clone()
    };
    let mut name_updated = false;
    if wanted != current {
        apply_assistant_name(&ctx.config.groups_dir, &current, &wanted)?;
        upsert_env_line(&ctx.env_path(), "ASSISTANT_NAME", &format!("\"{wanted}\""))
            .context("writing ASSISTANT_NAME to .env")?;
        tracing::info!("Set ASSISTANT_NAME in .env");
        name_updated = true;
    }
    if wanted != DEFAULT_ASSISTANT_NAME {
        // A folder just created from a template still has the shipped name.
        apply_assistant_name(&ctx.config.groups_dir, DEFAULT_ASSISTANT_NAME, &wanted)?;
    }

    Ok(StepOutcome::ok(
        StatusBlock::new("REGISTER_CHANNEL")
            .field("JID", &req.jid)
            .field("NAME", &req.name)
            .field("FOLDER", &req.folder)
            .field("CHANNEL", &req.channel)
            .field("TRIGGER", &req.trigger)
            .field("REQUIRES_TRIGGER", req.requires_trigger)
            .field("IS_MAIN", req.is_main)
            .field("ASSISTANT_NAME", &wanted)
            .field("NAME_UPDATED", name_updated)
            .field("TEMPLATE_COPIED", template_copied)
            .field("UPDATED_EXISTING", preserved)
            .field("STATUS", "success")
            .field("LOG", SETUP_LOG),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use talon_db::Db;

    use super::*;
    use crate::runner::mock::MockRunner;

    fn args(extra: &[&str]) -> StepArgs {
        let mut v = vec![
            "--jid",
            "tg:-100123",
            "--name",
            "SOC Team",
            "--trigger",
            "@Talon",
            "--folder",
            "soc-team",
        ];
        v.extend_from_slice(extra);
        StepArgs::new(v)
    }

    // --- argument parsing / validation --------------------------------------

    #[test]
    fn parses_arguments_with_defaults() {
        let r = RegisterRequest::from_args(&args(&[]));
        assert_eq!(r.jid, "tg:-100123");
        assert_eq!(r.channel, "telegram");
        assert!(r.requires_trigger);
        assert!(!r.is_main);
        assert_eq!(r.assistant_name, "", "no name: keep the current one");
        let r = RegisterRequest::from_args(&args(&[
            "--no-trigger-required",
            "--is-main",
            "--channel",
            "HTTP",
        ]));
        assert!(!r.requires_trigger);
        assert!(r.is_main);
        assert_eq!(r.channel, "http");
    }

    #[test]
    fn channel_inference() {
        assert_eq!(infer_channel("tg:42"), "telegram");
        assert_eq!(infer_channel("http:copilot"), "http");
        assert_eq!(infer_channel("123@g.us"), "whatsapp");
        assert_eq!(infer_channel("x"), "unknown");
    }

    #[test]
    fn validation_codes() {
        let ok = RegisterRequest::from_args(&args(&[]));
        assert_eq!(ok.validate(), Ok(()));
        let r = RegisterRequest {
            jid: String::new(),
            ..ok.clone()
        };
        assert_eq!(r.validate(), Err("missing_required_args"));
        let r = RegisterRequest {
            folder: "../etc".into(),
            ..ok.clone()
        };
        assert_eq!(r.validate(), Err("invalid_folder"));
        let r = RegisterRequest {
            folder: "global".into(),
            ..ok.clone()
        };
        assert_eq!(r.validate(), Err("invalid_folder"));
        let r = RegisterRequest {
            jid: "a b".into(),
            ..ok.clone()
        };
        assert_eq!(r.validate(), Err("invalid_jid"));
        let r = RegisterRequest {
            name: "x\ny".into(),
            ..ok.clone()
        };
        assert_eq!(r.validate(), Err("invalid_name"));
        let r = RegisterRequest {
            assistant_name: "Nova\"\nTALON_X=1".into(),
            ..ok.clone()
        };
        assert_eq!(r.validate(), Err("invalid_assistant_name"));
        // Apostrophes and SQL metacharacters are fine (parameterized SQL).
        let r = RegisterRequest {
            name: "O'Brien's Group; DROP TABLE x; --".into(),
            ..ok
        };
        assert_eq!(r.validate(), Ok(()));
    }

    #[tokio::test]
    async fn invalid_input_exits_4() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = SetupContext::new(dir.path(), dir.path(), Arc::new(MockRunner::new()));
        let out = run(&StepArgs::new(["--jid", "x"]), &ctx).await.unwrap();
        assert_eq!(out.exit_code, 4);
        assert_eq!(
            out.block.unwrap().get("ERROR"),
            Some("missing_required_args")
        );
        let bad_folder = StepArgs::new([
            "--jid",
            "tg:1",
            "--name",
            "n",
            "--trigger",
            "@A",
            "--folder",
            "a/b",
        ]);
        let out = run(&bad_folder, &ctx).await.unwrap();
        assert_eq!(out.block.unwrap().get("ERROR"), Some("invalid_folder"));
        assert!(!ctx.db_path().exists(), "nothing written on invalid input");
    }

    // --- templating ------------------------------------------------------------

    #[test]
    fn rename_replaces_heading_and_intro() {
        assert_eq!(
            rename_assistant(
                "# Talon\n\nYou are Talon, a personal assistant.",
                "Talon",
                "Nova"
            ),
            "# Nova\n\nYou are Nova, a personal assistant."
        );
    }

    #[test]
    fn rename_handles_regex_special_names() {
        let out = rename_assistant("# Talon\n\nYou are Talon.", "Talon", "C.L.A.U.D.E");
        assert!(out.contains("# C.L.A.U.D.E"));
        assert!(out.contains("You are C.L.A.U.D.E."));
        // `$` in a name is not a capture reference (rejected by validation
        // anyway, but the renamer must stay literal).
        assert_eq!(rename_assistant("# Talon", "Talon", "$1"), "# $1");
        // An old name with regex metacharacters is matched literally.
        assert_eq!(
            rename_assistant("# C.L.A.U.D.E\n# CxLxAxUxDxE", "C.L.A.U.D.E", "Nova"),
            "# Nova\n# CxLxAxUxDxE"
        );
    }

    struct Fixture {
        _tmp: tempfile::TempDir,
        groups: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let groups = tmp.path().join("groups");
        std::fs::create_dir_all(groups.join("main")).unwrap();
        std::fs::create_dir_all(groups.join("global")).unwrap();
        std::fs::write(
            groups.join("main/CLAUDE.md"),
            "# Talon\n\nYou are Talon, a personal assistant.\n\n## Admin Context\n\nThis is the **main channel**.",
        )
        .unwrap();
        std::fs::write(
            groups.join("global/CLAUDE.md"),
            "# Talon\n\nYou are Talon, a personal assistant.",
        )
        .unwrap();
        Fixture { _tmp: tmp, groups }
    }

    fn simulate(f: &Fixture, folder: &str, is_main: bool, name: &str) {
        prepare_group_folder(&f.groups, folder, is_main).unwrap();
        if name != DEFAULT_ASSISTANT_NAME {
            apply_assistant_name(&f.groups, DEFAULT_ASSISTANT_NAME, name).unwrap();
        }
    }

    fn read(f: &Fixture, folder: &str) -> String {
        std::fs::read_to_string(f.groups.join(folder).join("CLAUDE.md")).unwrap()
    }

    #[test]
    fn copies_global_template_for_non_main() {
        let f = fixture();
        simulate(&f, "telegram_dev-team", false, "Talon");
        let c = read(&f, "telegram_dev-team");
        assert!(c.contains("You are Talon"));
        assert!(!c.contains("Admin Context"));
        assert!(f.groups.join("telegram_dev-team/logs").is_dir());
    }

    #[test]
    fn copies_main_template_for_main() {
        let f = fixture();
        simulate(&f, "whatsapp_main", true, "Talon");
        assert!(read(&f, "whatsapp_main").contains("Admin Context"));
    }

    #[test]
    fn each_channel_can_have_its_own_main() {
        let f = fixture();
        for folder in [
            "whatsapp_main",
            "telegram_main",
            "slack_main",
            "discord_main",
        ] {
            simulate(&f, folder, true, "Talon");
        }
        for folder in [
            "whatsapp_main",
            "telegram_main",
            "slack_main",
            "discord_main",
        ] {
            let c = read(&f, folder);
            assert!(c.contains("Admin Context"));
            assert!(c.contains("You are Talon"));
        }
    }

    #[test]
    fn non_main_groups_get_global_template() {
        let f = fixture();
        simulate(&f, "whatsapp_main", true, "Talon");
        for folder in ["telegram_friends", "slack_engineering", "discord_general"] {
            simulate(&f, folder, false, "Talon");
        }
        assert!(read(&f, "whatsapp_main").contains("Admin Context"));
        for folder in ["telegram_friends", "slack_engineering", "discord_general"] {
            let c = read(&f, folder);
            assert!(c.contains("You are Talon"));
            assert!(!c.contains("Admin Context"));
        }
    }

    #[test]
    fn custom_name_propagates_everywhere() {
        let f = fixture();
        simulate(&f, "whatsapp_main", true, "Talon");
        simulate(&f, "telegram_main", true, "Talon");
        simulate(&f, "slack_devs", false, "Talon");
        simulate(&f, "discord_main", true, "Luna");
        for folder in [
            "main",
            "global",
            "whatsapp_main",
            "telegram_main",
            "slack_devs",
            "discord_main",
        ] {
            let c = read(&f, folder);
            assert!(c.contains("# Luna"), "{folder}");
            assert!(c.contains("You are Luna"), "{folder}");
            assert!(!c.contains("Talon"), "{folder}");
        }
    }

    #[test]
    fn never_overwrites_existing_claude_md() {
        let f = fixture();
        simulate(&f, "slack_main", true, "Talon");
        std::fs::write(
            f.groups.join("slack_main/CLAUDE.md"),
            "# Gambi\n\nCustom persona with workspace rules and family context.",
        )
        .unwrap();
        simulate(&f, "slack_main", true, "Talon");
        let c = read(&f, "slack_main");
        assert!(c.contains("Custom persona"));
        assert!(!c.contains("Admin Context"));
    }

    #[test]
    fn never_overwrites_when_promoted_to_main() {
        let f = fixture();
        simulate(&f, "whatsapp_casa", false, "Talon");
        std::fs::write(
            f.groups.join("whatsapp_casa/CLAUDE.md"),
            "# Casa\n\nFamily group with PARA system, task management, shopping lists.",
        )
        .unwrap();
        simulate(&f, "whatsapp_casa", true, "Talon");
        let c = read(&f, "whatsapp_casa");
        assert!(c.contains("PARA system"));
        assert!(!c.contains("Admin Context"));
    }

    #[test]
    fn preserves_custom_files_across_channels() {
        let f = fixture();
        simulate(&f, "whatsapp_main", true, "Talon");
        simulate(&f, "discord_main", false, "Talon");
        std::fs::write(
            f.groups.join("discord_main/CLAUDE.md"),
            "# Gambi HQ — Research Assistant\n\nResearch workflows for Laura and Ethan.",
        )
        .unwrap();
        simulate(&f, "discord_main", true, "Talon");
        assert!(read(&f, "discord_main").contains("Research Assistant"));
        assert!(read(&f, "whatsapp_main").contains("Admin Context"));
    }

    #[test]
    fn missing_templates_are_fine() {
        let f = fixture();
        std::fs::remove_file(f.groups.join("global/CLAUDE.md")).unwrap();
        std::fs::remove_file(f.groups.join("main/CLAUDE.md")).unwrap();
        simulate(&f, "discord_general", false, "Talon");
        assert!(!f.groups.join("discord_general/CLAUDE.md").exists());
    }

    #[test]
    fn symlinked_claude_md_is_neither_followed_nor_replaced() {
        let f = fixture();
        let outside = f.groups.parent().unwrap().join("authorized_keys");
        std::fs::write(&outside, "You are Talon ssh-ed25519 AAAA").unwrap();
        std::fs::create_dir_all(f.groups.join("evil")).unwrap();
        std::os::unix::fs::symlink(&outside, f.groups.join("evil/CLAUDE.md")).unwrap();
        // Template copy must not write through the (dangling or not) link.
        simulate(&f, "evil", false, "Talon");
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "You are Talon ssh-ed25519 AAAA"
        );
        // Renaming skips the symlink too.
        simulate(&f, "other", false, "Nova");
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "You are Talon ssh-ed25519 AAAA"
        );
        assert!(read(&f, "other").contains("You are Nova"));
    }

    // --- end to end (with the real talon-db) ---------------------------------

    #[tokio::test]
    async fn registers_group_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("groups/global")).unwrap();
        std::fs::write(
            root.join("groups/global/CLAUDE.md"),
            "# Talon\n\nYou are Talon.",
        )
        .unwrap();
        std::fs::write(root.join(".env"), "SOME_KEY=value\n").unwrap();
        let ctx = SetupContext::new(root, root, Arc::new(MockRunner::new()));

        let out = run(&args(&["--assistant-name", "Nova"]), &ctx)
            .await
            .unwrap();
        let b = out.block.clone().unwrap();
        assert_eq!(b.status(), Some("success"), "{}", out.render());
        assert_eq!(b.get("NAME_UPDATED"), Some("true"));
        assert_eq!(b.get("CHANNEL"), Some("telegram"));
        assert_eq!(b.get("UPDATED_EXISTING"), Some("false"));
        assert!(
            std::fs::read_to_string(root.join("groups/soc-team/CLAUDE.md"))
                .unwrap()
                .contains("You are Nova")
        );
        assert!(
            std::fs::read_to_string(root.join(".env"))
                .unwrap()
                .contains("ASSISTANT_NAME=\"Nova\"")
        );

        let db = Db::open(&ctx.db_path()).unwrap();
        let g = db.get_registered_group("tg:-100123").unwrap().unwrap();
        assert_eq!(g.folder, "soc-team");
        assert_eq!(g.trigger, "@Talon");
        assert_eq!(g.requires_trigger, Some(true));
        assert!(!g.is_main);
        drop(db);

        // Re-registering keeps added_at and updates fields — and, without
        // --assistant-name, the name.
        let out = run(&args(&["--no-trigger-required", "--is-main"]), &ctx)
            .await
            .unwrap();
        let b = out.block.unwrap();
        assert_eq!(b.get("UPDATED_EXISTING"), Some("true"));
        assert_eq!(b.get("ASSISTANT_NAME"), Some("Nova"));
        assert_eq!(b.get("NAME_UPDATED"), Some("false"));
        let md = root.join("groups/soc-team/CLAUDE.md");
        assert!(
            std::fs::read_to_string(&md)
                .unwrap()
                .contains("You are Nova")
        );
        let db = Db::open(&ctx.db_path()).unwrap();
        let g2 = db.get_registered_group("tg:-100123").unwrap().unwrap();
        assert_eq!(g2.added_at, g.added_at);
        assert!(g2.is_main);
        assert_eq!(g2.requires_trigger, Some(false));
        drop(db);

        // A second rename replaces the current name, not only the shipped one.
        let out = run(&args(&["--assistant-name", "Atlas"]), &ctx)
            .await
            .unwrap();
        assert_eq!(out.block.unwrap().get("NAME_UPDATED"), Some("true"));
        let content = std::fs::read_to_string(&md).unwrap();
        assert!(content.contains("You are Atlas"), "{content}");
        assert!(!content.contains("Nova"), "{content}");
        assert!(
            std::fs::read_to_string(root.join(".env"))
                .unwrap()
                .contains("ASSISTANT_NAME=\"Atlas\"")
        );
    }
}
