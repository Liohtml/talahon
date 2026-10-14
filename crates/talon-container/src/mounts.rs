//! Volume mount construction (port of `buildVolumeMounts` in
//! `src/container-runner.ts`, hardened).
//!
//! Layout inside the container:
//!
//! | container path                 | host source                              | mode |
//! |--------------------------------|------------------------------------------|------|
//! | `/workspace/project` (main)    | project root                             | ro   |
//! | `/workspace/project/.env`      | `/dev/null` (shadow, if `.env` exists)    | ro   |
//! | `/workspace/project/<mcp>/…`   | `/dev/null` (shadow per isolated MCP)     | ro   |
//! | `/workspace/group`             | `groups/<folder>`                        | rw   |
//! | `/workspace/group/.mcp.json`   | `groups/<folder>/.mcp.json`              | ro   |
//! | `/workspace/global`            | `groups/global` (if present)             | ro   |
//! | `/home/agent/.talon`           | `data/sessions/<session_key>`            | rw   |
//! | `/home/agent/.talon/skills`    | `container/skills` (if present)          | ro   |
//! | `/workspace/ipc`               | `data/ipc/<ipc_key>`                     | rw   |
//! | `/workspace/extra/<name>`      | allowlisted additional mounts            | ro/rw|
//! | `/workspace/extra/<mcp>/.env`  | `/dev/null` (shadow)                     | ro   |
//! | `/etc/mcp-staging/<id>.<file>` | the MCP's secret file (root-only dir)    | ro   |
//!
//! Hardening over the TypeScript version:
//! - `.mcp.json` is always bind-mounted read-only (created empty if absent):
//!   the root supervisor spawns whatever it lists as privileged `mcp-*`
//!   users, so the agent must never be able to edit it.
//! - Directories of isolated MCPs are forced read-only (their wrapper
//!   scripts run as the `mcp-<id>` user that can read the secrets).
//! - For the main group, secrets of isolated MCPs living under the project
//!   root are shadowed and staged too (TS leaked them via the project mount).
//! - `store/` is no longer mounted read-write for main by default (the audit
//!   chain lives there); opt in with [`MountOptions::main_store_writable`].
//! - Agent-writable IPC sub-directories that were replaced by symlinks are
//!   recreated as real directories; ownership is fixed with `lchown` (never
//!   `chmod 0777`) when the host runs as root.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use talon_core::audit::{AuditSink, event};
use talon_core::config::TalonConfig;
use talon_core::paths::{group_folder_path, group_ipc_path, group_sessions_path};
use talon_core::protocol::container_paths;
use talon_core::types::RegisteredGroup;
use talon_core::{Error, Result};
use talon_security::mounts::{MountDecision, ValidatedMount};

use crate::args::{RunAs, is_mount_path_safe};
use crate::policy::MountPolicy;

/// Host path used to shadow files inside the container.
pub const DEV_NULL: &str = "/dev/null";
/// Root-only (0700) directory in the image where secret files are staged.
pub const MCP_STAGING_DIR: &str = "/etc/mcp-staging";
/// tmpfs (0711) the entrypoint copies staged secrets into.
pub const MCP_SECRETS_DIR: &str = "/etc/mcp-secrets";
/// Where `container/skills` is exposed (read-only).
pub const SKILLS_CONTAINER_PATH: &str = "/home/agent/.talon/skills";
/// Prefix for allowlisted additional mounts.
pub const EXTRA_PREFIX: &str = "/workspace/extra/";
/// Per-group MCP configuration file name.
pub const MCP_JSON_FILE: &str = ".mcp.json";
/// Content written when a group has no `.mcp.json` yet.
pub const EMPTY_MCP_JSON: &str = "{\n  \"mcpServers\": {}\n}\n";
/// IPC sub-directories created for every lane.
pub const IPC_SUBDIRS: [&str; 3] = ["messages", "tasks", "input"];

/// One bind mount handed to the container runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    /// Source on the host.
    pub host_path: PathBuf,
    /// Absolute target inside the container.
    pub container_path: String,
    /// Mounted read-only.
    pub readonly: bool,
}

impl VolumeMount {
    /// Read-only bind mount.
    pub fn ro(host: impl Into<PathBuf>, container: impl Into<String>) -> Self {
        Self {
            host_path: host.into(),
            container_path: container.into(),
            readonly: true,
        }
    }

    /// Read-write bind mount.
    pub fn rw(host: impl Into<PathBuf>, container: impl Into<String>) -> Self {
        Self {
            host_path: host.into(),
            container_path: container.into(),
            readonly: false,
        }
    }

    /// A `/dev/null` shadow over `container`.
    pub fn shadow(container: impl Into<String>) -> Self {
        Self::ro(DEV_NULL, container)
    }

    /// `true` for `/dev/null` shadows.
    pub fn is_shadow(&self) -> bool {
        self.host_path == Path::new(DEV_NULL)
    }

    /// `host -> container (ro)` for logs.
    pub fn describe(&self) -> String {
        format!(
            "{} -> {}{}",
            self.host_path.display(),
            self.container_path,
            if self.readonly { " (ro)" } else { "" }
        )
    }
}

/// An MCP server whose credentials are isolated to a dedicated `mcp-<id>`
/// user inside the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsolatedMcp {
    /// Short id: user `mcp-<id>`, secret files `/etc/mcp-secrets/<id>.<file>`.
    pub id: &'static str,
    /// Directory name (`/workspace/extra/<dir>`, `<project>/<dir>`).
    pub dir: &'static str,
    /// Credential files besides `.env` (e.g. velociraptor's mTLS config).
    pub extra_files: &'static [&'static str],
}

impl IsolatedMcp {
    /// The container user the MCP server runs as.
    pub fn user(&self) -> String {
        format!("mcp-{}", self.id)
    }

    /// `/workspace/extra/<dir>`.
    pub fn extra_mount_path(&self) -> String {
        format!("{EXTRA_PREFIX}{}", self.dir)
    }

    /// All credential files: `.env` first, then the extras.
    pub fn secret_files(&self) -> impl Iterator<Item = &'static str> {
        std::iter::once(".env").chain(self.extra_files.iter().copied())
    }
}

/// MCP servers with credential isolation (TS `ISOLATED_MCPS` + MemPalace).
pub const ISOLATED_MCPS: &[IsolatedMcp] = &[
    IsolatedMcp {
        id: "siem",
        dir: "siem",
        extra_files: &[],
    },
    IsolatedMcp {
        id: "mysql",
        dir: "mysql",
        extra_files: &[],
    },
    IsolatedMcp {
        id: "wazuh",
        dir: "wazuh-mcp",
        extra_files: &[],
    },
    IsolatedMcp {
        id: "copilot",
        dir: "copilot-mcp",
        extra_files: &[],
    },
    IsolatedMcp {
        id: "shuffle",
        dir: "shuffle-mcp",
        extra_files: &[],
    },
    IsolatedMcp {
        id: "velociraptor",
        dir: "velociraptor-mcp",
        extra_files: &["api.config.yaml"],
    },
    IsolatedMcp {
        id: "cve",
        dir: "cve-mcp",
        extra_files: &[],
    },
    IsolatedMcp {
        id: "palace",
        dir: "mempalace",
        extra_files: &[],
    },
];

/// `/etc/mcp-staging/<id>.<file without leading dot>` (TS naming:
/// `siem.env`, `velociraptor.api.config.yaml`).
pub fn mcp_staging_path(id: &str, file: &str) -> String {
    format!("{MCP_STAGING_DIR}/{id}.{}", file.trim_start_matches('.'))
}

/// Host directories the mounts are built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountLayout {
    /// Talon checkout (main's `/workspace/project`).
    pub project_root: PathBuf,
    /// `groups/`.
    pub groups_dir: PathBuf,
    /// `data/` (IPC namespaces, sessions).
    pub data_dir: PathBuf,
}

impl MountLayout {
    /// Standard layout under `project_root`.
    pub fn new(project_root: impl Into<PathBuf>) -> Self {
        let project_root = project_root.into();
        Self {
            groups_dir: project_root.join("groups"),
            data_dir: project_root.join("data"),
            project_root,
        }
    }

    /// Layout from the resolved host configuration.
    pub fn from_config(cfg: &TalonConfig) -> Self {
        Self {
            project_root: cfg.project_root.clone(),
            groups_dir: cfg.groups_dir.clone(),
            data_dir: cfg.data_dir.clone(),
        }
    }
}

/// Knobs that deviate from the secure defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountOptions {
    /// Mount `<project>/store` read-write for the main group (TS behaviour).
    /// Off by default: it holds the hash-chained audit log.
    pub main_store_writable: bool,
    /// Expose `<project>/container/skills` read-only at
    /// [`SKILLS_CONTAINER_PATH`].
    pub mount_skills: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            main_store_writable: false,
            mount_skills: true,
        }
    }
}

/// Everything [`build_mounts`] needs.
pub struct MountRequest<'a> {
    /// Host directory layout.
    pub layout: &'a MountLayout,
    /// The group whose container is being prepared.
    pub group: &'a RegisteredGroup,
    /// Main-group privileges (project mount).
    pub is_main: bool,
    /// Allowlist check for additional mounts.
    pub policy: &'a dyn MountPolicy,
    /// When the host runs as root: give the writable directories to this
    /// uid/gid (the in-container `agent`).
    pub chown_to: Option<RunAs>,
    /// Non-default behaviour.
    pub options: &'a MountOptions,
    /// Receives `mount.rejected` events.
    pub audit: Option<&'a dyn AuditSink>,
}

fn audit_rejected(req: &MountRequest<'_>, target: &str, reason: &str, extra: serde_json::Value) {
    tracing::warn!(group = %req.group.name, target, reason, "mount rejected");
    if let Some(audit) = req.audit {
        audit.record(event(
            "mount.rejected",
            &req.group.folder,
            Some(target),
            "denied",
            serde_json::json!({ "reason": reason, "isMain": req.is_main, "detail": extra }),
        ));
    }
}

/// Create (if needed) an operator-controlled directory and return its
/// canonical path. Symlinks here are the operator's choice and are followed.
fn ensure_dir(path: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path)?;
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(Error::Container(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    Ok(canonical)
}

/// Ensure `parent/name` is a real directory (not a symlink). The parent is
/// writable by the agent, so a planted symlink is removed and replaced.
fn ensure_real_subdir(parent: &Path, name: &str) -> Result<PathBuf> {
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(meta) => {
            tracing::warn!(
                path = %path.display(),
                symlink = meta.file_type().is_symlink(),
                "replacing non-directory IPC entry with a real directory"
            );
            fs::remove_file(&path)?;
            fs::create_dir(&path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if !fs::symlink_metadata(&path)?.is_dir() {
                    return Err(Error::security(format!(
                        "{} appeared as a non-directory",
                        path.display()
                    )));
                }
            }
            Err(e) => return Err(e.into()),
        },
        Err(e) => return Err(e.into()),
    }
    Ok(path)
}

fn chown_path(path: &Path, owner: Option<RunAs>) {
    let Some(owner) = owner else { return };
    if let Err(err) = std::os::unix::fs::lchown(path, Some(owner.uid), Some(owner.gid)) {
        tracing::warn!(path = %path.display(), %err, "failed to chown mount directory");
    }
}

/// A credential file found under an MCP / project directory.
struct SecretFile {
    /// File to stage (symlinks resolved).
    host: PathBuf,
    /// Path relative to the mount root that must be shadowed, when the file
    /// is reachable inside that mount.
    visible_rel: Option<PathBuf>,
}

fn resolve_secret_file(root: &Path, file: &str) -> Option<SecretFile> {
    let candidate = root.join(file);
    let meta = fs::symlink_metadata(&candidate).ok()?;
    let ft = meta.file_type();
    if ft.is_file() {
        return Some(SecretFile {
            host: candidate,
            visible_rel: Some(PathBuf::from(file)),
        });
    }
    if !ft.is_symlink() {
        tracing::warn!(path = %candidate.display(), "secret path is not a regular file; ignored");
        return None;
    }
    let target = match fs::canonicalize(&candidate) {
        Ok(t) if t.is_file() => t,
        _ => {
            tracing::warn!(path = %candidate.display(), "secret symlink is dangling or not a file; ignored");
            return None;
        }
    };
    let visible_rel = fs::canonicalize(root)
        .ok()
        .and_then(|r| target.strip_prefix(&r).ok().map(Path::to_path_buf))
        .filter(|rel| rel.components().all(|c| matches!(c, Component::Normal(_))));
    Some(SecretFile {
        host: target,
        visible_rel,
    })
}

#[derive(Default)]
struct ShadowState {
    shadowed: HashSet<String>,
    staged: HashSet<String>,
}

impl ShadowState {
    fn shadow(&mut self, mounts: &mut Vec<VolumeMount>, container_path: String) {
        if self.shadowed.insert(container_path.clone()) {
            mounts.push(VolumeMount::shadow(container_path));
        }
    }

    fn stage(&mut self, mounts: &mut Vec<VolumeMount>, host: PathBuf, staging: String) {
        if self.staged.insert(staging.clone()) {
            mounts.push(VolumeMount::ro(host, staging));
        }
    }
}

fn join_container(root: &str, rel: &Path) -> String {
    format!("{}/{}", root.trim_end_matches('/'), rel.to_string_lossy())
}

/// Shadow + stage the credential files of `mcp` found under `host_root`
/// (mounted at `container_root`).
fn stage_mcp(
    mounts: &mut Vec<VolumeMount>,
    state: &mut ShadowState,
    mcp: &IsolatedMcp,
    host_root: &Path,
    container_root: &str,
) {
    for file in mcp.secret_files() {
        let Some(secret) = resolve_secret_file(host_root, file) else {
            continue;
        };
        if let Some(rel) = &secret.visible_rel {
            state.shadow(mounts, join_container(container_root, rel));
        }
        state.stage(mounts, secret.host, mcp_staging_path(mcp.id, file));
    }
}

/// Bind `.mcp.json` read-only, creating an empty one if the group has none.
fn protect_mcp_json(req: &MountRequest<'_>, group_dir: &Path) -> Result<VolumeMount> {
    let path = group_dir.join(MCP_JSON_FILE);
    let target = format!("{}/{MCP_JSON_FILE}", container_paths::GROUP);
    let check = |meta: &fs::Metadata| -> Result<()> {
        if meta.file_type().is_file() {
            return Ok(());
        }
        let kind = if meta.file_type().is_symlink() {
            "symlink"
        } else if meta.is_dir() {
            "directory"
        } else {
            "special file"
        };
        audit_rejected(
            req,
            &path.to_string_lossy(),
            "group .mcp.json must be a regular file",
            serde_json::json!({ "found": kind }),
        );
        Err(Error::security(format!(
            "{} is a {kind}; .mcp.json must be a regular file",
            path.display()
        )))
    };
    match fs::symlink_metadata(&path) {
        Ok(meta) => check(&meta)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&path)
            {
                Ok(mut f) => f.write_all(EMPTY_MCP_JSON.as_bytes())?,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    check(&fs::symlink_metadata(&path)?)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) => return Err(e.into()),
    }
    Ok(VolumeMount::ro(path, target))
}

/// Largest `.mcp.json` inspected for referenced directories.
const MAX_MCP_JSON_BYTES: u64 = 1024 * 1024;

/// Names of `/workspace/extra/<name>` directories that the group's
/// `.mcp.json` references in a server's `command`, `args` or `cwd`. The root
/// supervisor executes those as privileged `mcp-*` users, so they are always
/// mounted read-only. Commands in agent-writable locations are logged.
pub fn mcp_referenced_extra_dirs(mcp_json: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    let too_big = fs::metadata(mcp_json)
        .map(|m| m.len() > MAX_MCP_JSON_BYTES)
        .unwrap_or(true);
    if too_big {
        return out;
    }
    let Ok(text) = fs::read_to_string(mcp_json) else {
        return out;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        tracing::warn!(path = %mcp_json.display(), "group .mcp.json is not valid JSON");
        return out;
    };
    let Some(servers) = value.get("mcpServers").and_then(|v| v.as_object()) else {
        return out;
    };
    for (server, cfg) in servers {
        let strings = cfg
            .get("command")
            .into_iter()
            .chain(cfg.get("cwd"))
            .chain(
                cfg.get("args")
                    .and_then(|a| a.as_array())
                    .into_iter()
                    .flatten(),
            )
            .filter_map(|v| v.as_str());
        for s in strings {
            if let Some(rest) = s.strip_prefix(EXTRA_PREFIX) {
                if let Some(name) = rest.split('/').next().filter(|n| !n.is_empty()) {
                    out.insert(name.to_string());
                }
            } else if [
                container_paths::GROUP,
                container_paths::IPC,
                "/tmp",
                "/home/agent",
            ]
            .iter()
            .any(|p| s == *p || s.starts_with(&format!("{p}/")))
            {
                tracing::warn!(
                    server = %server,
                    path = %s,
                    "MCP server references an agent-writable path; it will run with MCP privileges"
                );
            }
        }
    }
    out
}

/// Defence in depth on what the mount validator returned.
fn check_validated(v: &ValidatedMount) -> std::result::Result<(), String> {
    if !v.host_path.is_absolute() {
        return Err("host path must be absolute".into());
    }
    let host = v.host_path.to_string_lossy();
    if !is_mount_path_safe(&host) {
        return Err("host path contains characters not allowed in a mount spec".into());
    }
    let cp = v.container_path.as_str();
    let Some(rest) = cp.strip_prefix(EXTRA_PREFIX) else {
        return Err(format!("container path must be under {EXTRA_PREFIX}"));
    };
    if rest.is_empty()
        || !Path::new(rest)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err("container path must be a plain relative name".into());
    }
    if !is_mount_path_safe(cp) {
        return Err("container path contains characters not allowed in a mount spec".into());
    }
    Ok(())
}

/// Build the bind mounts for one container run. Creates the lane's
/// directories as a side effect. See the module docs for the layout.
pub fn build_mounts(req: &MountRequest<'_>) -> Result<Vec<VolumeMount>> {
    let layout = req.layout;
    let group = req.group;
    let mut mounts: Vec<VolumeMount> = Vec::new();
    let mut shadows = ShadowState::default();

    let group_dir = ensure_dir(&group_folder_path(&layout.groups_dir, &group.folder)?)?;
    chown_path(&group_dir, req.chown_to);

    if req.is_main {
        // Project root read-only so the agent cannot modify host code.
        let project = fs::canonicalize(&layout.project_root)?;
        mounts.push(VolumeMount::ro(&project, container_paths::PROJECT));
        // Shadow .env (credentials are injected by the host, never exposed).
        if let Some(env) = resolve_secret_file(&project, ".env") {
            if let Some(rel) = env.visible_rel {
                shadows.shadow(&mut mounts, join_container(container_paths::PROJECT, &rel));
            }
        }
        if req.options.main_store_writable {
            let store = ensure_dir(&project.join("store"))?;
            mounts.push(VolumeMount::rw(
                store,
                format!("{}/store", container_paths::PROJECT),
            ));
        }
    }

    mounts.push(VolumeMount::rw(&group_dir, container_paths::GROUP));
    let mcp_json = protect_mcp_json(req, &group_dir)?;
    let mcp_dirs = mcp_referenced_extra_dirs(&mcp_json.host_path);
    mounts.push(mcp_json);

    let global_dir = layout.groups_dir.join("global");
    if global_dir.is_dir() {
        mounts.push(VolumeMount::ro(
            fs::canonicalize(&global_dir)?,
            container_paths::GLOBAL,
        ));
    }

    // Per-lane agent state (sessions, transcripts).
    let sessions_dir = ensure_dir(&group_sessions_path(&layout.data_dir, group.session_key())?)?;
    chown_path(&sessions_dir, req.chown_to);
    mounts.push(VolumeMount::rw(&sessions_dir, container_paths::AGENT_STATE));

    if req.options.mount_skills {
        let skills = layout.project_root.join("container").join("skills");
        if fs::symlink_metadata(&skills)
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            mounts.push(VolumeMount::ro(
                fs::canonicalize(&skills)?,
                SKILLS_CONTAINER_PATH,
            ));
        }
    }

    // Per-lane IPC namespace.
    let ipc_dir = ensure_dir(&group_ipc_path(&layout.data_dir, group.ipc_key())?)?;
    chown_path(&ipc_dir, req.chown_to);
    for sub in IPC_SUBDIRS {
        let dir = ensure_real_subdir(&ipc_dir, sub)?;
        chown_path(&dir, req.chown_to);
    }
    mounts.push(VolumeMount::rw(&ipc_dir, container_paths::IPC));

    // Additional mounts, validated against the external allowlist.
    let additional = group
        .container_config
        .as_ref()
        .map(|c| c.additional_mounts.as_slice())
        .unwrap_or_default();
    for requested in additional {
        match req.policy.validate(requested, req.is_main) {
            MountDecision::Allowed(validated) => {
                if let Err(reason) = check_validated(&validated) {
                    audit_rejected(
                        req,
                        &requested.host_path,
                        &reason,
                        serde_json::json!({ "containerPath": validated.container_path }),
                    );
                    continue;
                }
                if mounts
                    .iter()
                    .any(|m| m.container_path == validated.container_path)
                {
                    audit_rejected(
                        req,
                        &requested.host_path,
                        "duplicate container path",
                        serde_json::json!({ "containerPath": validated.container_path }),
                    );
                    continue;
                }
                // MCP directories hold the wrapper scripts the supervisor
                // runs as mcp-* users: never writable, whatever the allowlist
                // says.
                let mut readonly = validated.readonly;
                let name = validated
                    .container_path
                    .strip_prefix(EXTRA_PREFIX)
                    .unwrap_or_default();
                let is_mcp_dir =
                    ISOLATED_MCPS.iter().any(|m| m.dir == name) || mcp_dirs.contains(name);
                if !readonly && is_mcp_dir {
                    tracing::warn!(
                        group = %group.name,
                        container_path = %validated.container_path,
                        "MCP directory forced read-only"
                    );
                    readonly = true;
                }
                mounts.push(VolumeMount {
                    host_path: validated.host_path,
                    container_path: validated.container_path,
                    readonly,
                });
            }
            MountDecision::Rejected { reason } => {
                audit_rejected(
                    req,
                    &requested.host_path,
                    &reason,
                    serde_json::json!({ "containerPath": requested.container_path }),
                );
            }
        }
    }

    // Per-MCP credential isolation: shadow the visible copy with /dev/null
    // and stage the real file under the root-only staging dir, from which
    // the entrypoint copies it to /etc/mcp-secrets/<id>.<file> (0600,
    // owner mcp-<id>). Added after the directory mounts so they win.
    for mcp in ISOLATED_MCPS {
        let extra = mcp.extra_mount_path();
        let host_root = mounts
            .iter()
            .find(|m| m.container_path == extra)
            .map(|m| m.host_path.clone());
        if let Some(host_root) = host_root {
            stage_mcp(&mut mounts, &mut shadows, mcp, &host_root, &extra);
        }
    }
    if req.is_main {
        let project = fs::canonicalize(&layout.project_root)?;
        for mcp in ISOLATED_MCPS {
            let host_root = project.join(mcp.dir);
            if host_root.is_dir() {
                let container_root = format!("{}/{}", container_paths::PROJECT, mcp.dir);
                stage_mcp(&mut mounts, &mut shadows, mcp, &host_root, &container_root);
            }
        }
    }

    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, symlink};

    use talon_core::audit::MemoryAuditSink;
    use talon_core::types::{AdditionalMount, ContainerConfig};

    use super::*;
    use crate::policy::DenyAllMounts;
    use crate::policy::testing::AllowAllMounts;

    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        layout: MountLayout,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(root.join("groups/global")).unwrap();
        fs::create_dir_all(root.join("container/skills/status")).unwrap();
        let layout = MountLayout::new(&root);
        Fixture {
            _tmp: tmp,
            root,
            layout,
        }
    }

    fn group(folder: &str, is_main: bool) -> RegisteredGroup {
        RegisteredGroup {
            name: format!("Group {folder}"),
            folder: folder.into(),
            trigger: "@Andy".into(),
            added_at: "2026-01-01T00:00:00.000Z".into(),
            container_config: None,
            requires_trigger: None,
            is_main,
            session_key: None,
            ipc_key: None,
            ephemeral_session: false,
            trusted_session_commands: false,
        }
    }

    fn build(
        fx: &Fixture,
        g: &RegisteredGroup,
        is_main: bool,
        policy: &dyn MountPolicy,
        audit: Option<&dyn AuditSink>,
    ) -> Result<Vec<VolumeMount>> {
        let options = MountOptions::default();
        build_mounts(&MountRequest {
            layout: &fx.layout,
            group: g,
            is_main,
            policy,
            chown_to: None,
            options: &options,
            audit,
        })
    }

    fn find<'a>(mounts: &'a [VolumeMount], cp: &str) -> Option<&'a VolumeMount> {
        mounts.iter().find(|m| m.container_path == cp)
    }

    #[test]
    fn non_main_layout() {
        let fx = fixture();
        let g = group("team", false);
        let mounts = build(&fx, &g, false, &DenyAllMounts, None).unwrap();

        assert!(find(&mounts, "/workspace/project").is_none());
        let grp = find(&mounts, "/workspace/group").unwrap();
        assert!(!grp.readonly);
        assert_eq!(grp.host_path, fx.root.join("groups/team"));
        assert!(find(&mounts, "/workspace/global").unwrap().readonly);
        let state = find(&mounts, "/home/agent/.talon").unwrap();
        assert_eq!(state.host_path, fx.root.join("data/sessions/team"));
        assert!(!state.readonly);
        assert!(find(&mounts, SKILLS_CONTAINER_PATH).unwrap().readonly);
        let ipc = find(&mounts, "/workspace/ipc").unwrap();
        assert_eq!(ipc.host_path, fx.root.join("data/ipc/team"));
        for sub in IPC_SUBDIRS {
            assert!(fx.root.join("data/ipc/team").join(sub).is_dir());
        }
        // .mcp.json is created and mounted read-only.
        let mcp = find(&mounts, "/workspace/group/.mcp.json").unwrap();
        assert!(mcp.readonly);
        assert_eq!(
            fs::read_to_string(fx.root.join("groups/team/.mcp.json")).unwrap(),
            EMPTY_MCP_JSON
        );
        // No shadows or staging without MCP mounts.
        assert!(!mounts.iter().any(|m| m.is_shadow()));
    }

    #[test]
    fn global_only_when_present() {
        let fx = fixture();
        fs::remove_dir_all(fx.root.join("groups/global")).unwrap();
        let mounts = build(&fx, &group("team", false), false, &DenyAllMounts, None).unwrap();
        assert!(find(&mounts, "/workspace/global").is_none());
    }

    #[test]
    fn main_gets_readonly_project_with_env_shadow() {
        let fx = fixture();
        let g = group("main", true);
        // No .env => no shadow.
        let mounts = build(&fx, &g, true, &DenyAllMounts, None).unwrap();
        let project = find(&mounts, "/workspace/project").unwrap();
        assert!(project.readonly);
        assert_eq!(project.host_path, fx.root);
        assert!(find(&mounts, "/workspace/project/.env").is_none());
        assert!(find(&mounts, "/workspace/project/store").is_none());

        fs::write(fx.root.join(".env"), "TALON_VLLM_API_KEY=x").unwrap();
        let mounts = build(&fx, &g, true, &DenyAllMounts, None).unwrap();
        let shadow = find(&mounts, "/workspace/project/.env").unwrap();
        assert!(shadow.is_shadow() && shadow.readonly);
        // Order: project before its shadow.
        let pi = mounts
            .iter()
            .position(|m| m.container_path == "/workspace/project");
        let si = mounts
            .iter()
            .position(|m| m.container_path == "/workspace/project/.env");
        assert!(pi < si);
    }

    #[test]
    fn main_store_writable_is_opt_in() {
        let fx = fixture();
        let options = MountOptions {
            main_store_writable: true,
            mount_skills: false,
        };
        let g = group("main", true);
        let mounts = build_mounts(&MountRequest {
            layout: &fx.layout,
            group: &g,
            is_main: true,
            policy: &DenyAllMounts,
            chown_to: None,
            options: &options,
            audit: None,
        })
        .unwrap();
        assert!(!find(&mounts, "/workspace/project/store").unwrap().readonly);
        assert!(find(&mounts, SKILLS_CONTAINER_PATH).is_none());
    }

    #[test]
    fn session_and_ipc_keys_are_used() {
        let fx = fixture();
        let mut g = group("copilot", false);
        g.session_key = Some("copilot-u-7".into());
        g.ipc_key = Some("copilot-u-7".into());
        let mounts = build(&fx, &g, false, &DenyAllMounts, None).unwrap();
        assert_eq!(
            find(&mounts, "/home/agent/.talon").unwrap().host_path,
            fx.root.join("data/sessions/copilot-u-7")
        );
        assert_eq!(
            find(&mounts, "/workspace/ipc").unwrap().host_path,
            fx.root.join("data/ipc/copilot-u-7")
        );
        g.ipc_key = Some("../escape".into());
        assert!(build(&fx, &g, false, &DenyAllMounts, None).is_err());
    }

    #[test]
    fn invalid_folder_is_rejected() {
        let fx = fixture();
        assert!(build(&fx, &group("../x", false), false, &DenyAllMounts, None).is_err());
        assert!(build(&fx, &group("global", false), false, &DenyAllMounts, None).is_err());
    }

    #[test]
    fn additional_mounts_validated_and_rejections_audited() {
        let fx = fixture();
        let data = fx.root.join("srv-data");
        fs::create_dir_all(&data).unwrap();
        let mut g = group("team", false);
        g.container_config = Some(ContainerConfig {
            additional_mounts: vec![
                AdditionalMount {
                    host_path: data.to_string_lossy().into(),
                    container_path: None,
                    readonly: true,
                },
                AdditionalMount {
                    host_path: "/srv/deny-me".into(),
                    container_path: None,
                    readonly: true,
                },
                AdditionalMount {
                    host_path: "/srv/a,target=/etc".into(),
                    container_path: Some("evil".into()),
                    readonly: true,
                },
                AdditionalMount {
                    host_path: "/srv/b".into(),
                    container_path: Some("../../etc".into()),
                    readonly: true,
                },
            ],
            ..Default::default()
        });
        let audit = MemoryAuditSink::default();
        let mounts = build(&fx, &g, false, &AllowAllMounts, Some(&audit)).unwrap();
        assert!(find(&mounts, "/workspace/extra/srv-data").unwrap().readonly);
        assert_eq!(
            mounts
                .iter()
                .filter(|m| m.container_path.starts_with(EXTRA_PREFIX))
                .count(),
            1
        );
        let events = audit.snapshot();
        assert_eq!(events.len(), 3);
        assert!(
            events
                .iter()
                .all(|e| e.kind == "mount.rejected" && e.outcome == "denied")
        );
        assert_eq!(events[0].target.as_deref(), Some("/srv/deny-me"));

        // Everything is rejected under the deny-all policy.
        let audit = MemoryAuditSink::default();
        let mounts = build(&fx, &g, false, &DenyAllMounts, Some(&audit)).unwrap();
        assert!(
            !mounts
                .iter()
                .any(|m| m.container_path.starts_with(EXTRA_PREFIX))
        );
        assert_eq!(audit.snapshot().len(), 4);
    }

    #[test]
    fn isolated_mcp_secrets_are_shadowed_and_staged() {
        let fx = fixture();
        let siem = fx.root.join("ext/siem");
        let velo = fx.root.join("ext/velociraptor-mcp");
        let cve = fx.root.join("ext/cve-mcp");
        for d in [&siem, &velo, &cve] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(siem.join(".env"), "OPENSEARCH_PASSWORD=x").unwrap();
        fs::write(velo.join(".env"), "VELOCIRAPTOR_API_KEY=api.config.yaml").unwrap();
        fs::write(velo.join("api.config.yaml"), "client_cert: x").unwrap();
        // cve has no .env => nothing staged.
        let mount = |p: &PathBuf| AdditionalMount {
            host_path: p.to_string_lossy().into(),
            container_path: None,
            readonly: false,
        };
        let mut g = group("copilot", true);
        g.container_config = Some(ContainerConfig {
            additional_mounts: vec![mount(&siem), mount(&velo), mount(&cve)],
            ..Default::default()
        });
        let mounts = build(&fx, &g, true, &AllowAllMounts, None).unwrap();

        // MCP directories forced read-only even though rw was requested.
        assert!(find(&mounts, "/workspace/extra/siem").unwrap().readonly);
        assert!(
            find(&mounts, "/workspace/extra/velociraptor-mcp")
                .unwrap()
                .readonly
        );

        assert!(
            find(&mounts, "/workspace/extra/siem/.env")
                .unwrap()
                .is_shadow()
        );
        let staged = find(&mounts, "/etc/mcp-staging/siem.env").unwrap();
        assert_eq!(staged.host_path, siem.join(".env"));
        assert!(staged.readonly);
        assert!(
            find(&mounts, "/workspace/extra/velociraptor-mcp/api.config.yaml")
                .unwrap()
                .is_shadow()
        );
        assert_eq!(
            find(&mounts, "/etc/mcp-staging/velociraptor.api.config.yaml")
                .unwrap()
                .host_path,
            velo.join("api.config.yaml")
        );
        assert!(find(&mounts, "/etc/mcp-staging/cve.env").is_none());

        // Shadows come after the directory mount they cover.
        let dir_i = mounts
            .iter()
            .position(|m| m.container_path == "/workspace/extra/siem")
            .unwrap();
        let sh_i = mounts
            .iter()
            .position(|m| m.container_path == "/workspace/extra/siem/.env")
            .unwrap();
        assert!(dir_i < sh_i);
        // No duplicate container paths at all.
        let mut seen = HashSet::new();
        assert!(mounts.iter().all(|m| seen.insert(m.container_path.clone())));
    }

    #[test]
    fn main_project_mcp_secrets_are_shadowed_and_staged_once() {
        let fx = fixture();
        fs::create_dir_all(fx.root.join("mysql")).unwrap();
        fs::write(fx.root.join("mysql/.env"), "MYSQL_PASS=x").unwrap();
        fs::create_dir_all(fx.root.join("siem")).unwrap();
        fs::write(fx.root.join("siem/.env"), "X=1").unwrap();
        let mut g = group("main", true);
        // siem also mounted as an extra dir from the same host path.
        g.container_config = Some(ContainerConfig {
            additional_mounts: vec![AdditionalMount {
                host_path: fx.root.join("siem").to_string_lossy().into(),
                container_path: None,
                readonly: true,
            }],
            ..Default::default()
        });
        let mounts = build(&fx, &g, true, &AllowAllMounts, None).unwrap();
        assert!(
            find(&mounts, "/workspace/project/mysql/.env")
                .unwrap()
                .is_shadow()
        );
        assert!(
            find(&mounts, "/workspace/project/siem/.env")
                .unwrap()
                .is_shadow()
        );
        assert!(
            find(&mounts, "/workspace/extra/siem/.env")
                .unwrap()
                .is_shadow()
        );
        assert_eq!(
            mounts
                .iter()
                .filter(|m| m.container_path == "/etc/mcp-staging/siem.env")
                .count(),
            1
        );
        assert!(find(&mounts, "/etc/mcp-staging/mysql.env").is_some());
        // Non-main never sees project secrets staged.
        let mounts = build(&fx, &group("team", false), false, &AllowAllMounts, None).unwrap();
        assert!(find(&mounts, "/etc/mcp-staging/mysql.env").is_none());
    }

    #[test]
    fn secret_symlinks_are_resolved() {
        let fx = fixture();
        let siem = fx.root.join("ext/siem");
        fs::create_dir_all(siem.join("conf")).unwrap();
        fs::write(siem.join("conf/real.env"), "A=1").unwrap();
        symlink("conf/real.env", siem.join(".env")).unwrap();
        let mut g = group("team", false);
        g.container_config = Some(ContainerConfig {
            additional_mounts: vec![AdditionalMount {
                host_path: siem.to_string_lossy().into(),
                container_path: None,
                readonly: true,
            }],
            ..Default::default()
        });
        let mounts = build(&fx, &g, false, &AllowAllMounts, None).unwrap();
        // The resolved target is what gets shadowed and staged.
        assert!(
            find(&mounts, "/workspace/extra/siem/conf/real.env")
                .unwrap()
                .is_shadow()
        );
        assert_eq!(
            find(&mounts, "/etc/mcp-staging/siem.env")
                .unwrap()
                .host_path,
            siem.join("conf/real.env")
        );

        // Dangling symlink: nothing staged.
        fs::remove_file(siem.join("conf/real.env")).unwrap();
        let mounts = build(&fx, &g, false, &AllowAllMounts, None).unwrap();
        assert!(find(&mounts, "/etc/mcp-staging/siem.env").is_none());
    }

    #[test]
    fn mcp_json_symlink_refuses_launch() {
        let fx = fixture();
        let dir = fx.root.join("groups/team");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("evil.json"), "{}").unwrap();
        symlink("evil.json", dir.join(".mcp.json")).unwrap();
        let audit = MemoryAuditSink::default();
        let err = build(
            &fx,
            &group("team", false),
            false,
            &DenyAllMounts,
            Some(&audit),
        )
        .unwrap_err();
        assert!(err.to_string().contains("regular file"));
        assert_eq!(audit.snapshot()[0].kind, "mount.rejected");

        // Existing regular file is kept as-is.
        fs::remove_file(dir.join(".mcp.json")).unwrap();
        fs::write(dir.join(".mcp.json"), "{\"mcpServers\":{\"x\":{}}}").unwrap();
        build(&fx, &group("team", false), false, &DenyAllMounts, None).unwrap();
        assert!(
            fs::read_to_string(dir.join(".mcp.json"))
                .unwrap()
                .contains("\"x\"")
        );
    }

    #[test]
    fn existing_mcp_json_is_bound_read_only_over_group_mount() {
        let fx = fixture();
        for (folder, is_main) in [("main", true), ("team", false)] {
            let dir = fx.root.join("groups").join(folder);
            fs::create_dir_all(&dir).unwrap();
            let cfg = "{\"mcpServers\":{\"mysql\":{\"command\":\"/workspace/project/mysql/mysql-mcp.sh\"}}}";
            fs::write(dir.join(".mcp.json"), cfg).unwrap();
            let mounts =
                build(&fx, &group(folder, is_main), is_main, &DenyAllMounts, None).unwrap();
            let gi = mounts
                .iter()
                .position(|m| m.container_path == "/workspace/group")
                .unwrap();
            let mi = mounts
                .iter()
                .position(|m| m.container_path == "/workspace/group/.mcp.json")
                .unwrap();
            assert!(
                gi < mi,
                "the file bind must come after (shadow) the rw group mount"
            );
            assert!(!mounts[gi].readonly);
            assert!(mounts[mi].readonly);
            assert_eq!(mounts[mi].host_path, dir.join(".mcp.json"));
            // Content untouched.
            assert_eq!(fs::read_to_string(dir.join(".mcp.json")).unwrap(), cfg);
        }
    }

    #[test]
    fn mcp_referenced_extra_dirs_are_forced_read_only() {
        let fx = fixture();
        let ollama = fx.root.join("ext/ollama");
        let data = fx.root.join("ext/mempalace-data");
        fs::create_dir_all(&ollama).unwrap();
        fs::create_dir_all(&data).unwrap();
        let dir = fx.root.join("groups/team");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(".mcp.json"),
            r#"{"mcpServers":{
                "ollama":{"command":"/workspace/extra/ollama/ollama-mcp.sh"},
                "evil":{"command":"/workspace/group/x.sh","args":["--cfg","/workspace/extra/ollama/c.yaml"]}
            }}"#,
        )
        .unwrap();
        let rw = |p: &PathBuf| AdditionalMount {
            host_path: p.to_string_lossy().into(),
            container_path: None,
            readonly: false,
        };
        let mut g = group("team", true);
        g.container_config = Some(ContainerConfig {
            additional_mounts: vec![rw(&ollama), rw(&data)],
            ..Default::default()
        });
        let mounts = build(&fx, &g, true, &AllowAllMounts, None).unwrap();
        assert!(find(&mounts, "/workspace/extra/ollama").unwrap().readonly);
        // A data directory that is not an MCP command location stays writable.
        assert!(
            !find(&mounts, "/workspace/extra/mempalace-data")
                .unwrap()
                .readonly
        );

        let names = mcp_referenced_extra_dirs(&dir.join(".mcp.json"));
        assert_eq!(names.len(), 1);
        assert!(names.contains("ollama"));
        fs::write(dir.join(".mcp.json"), "not json").unwrap();
        assert!(mcp_referenced_extra_dirs(&dir.join(".mcp.json")).is_empty());
        assert!(mcp_referenced_extra_dirs(&dir.join("missing.json")).is_empty());
    }

    #[test]
    fn planted_ipc_symlinks_are_replaced() {
        let fx = fixture();
        let outside = fx.root.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let ipc = fx.root.join("data/ipc/team");
        fs::create_dir_all(&ipc).unwrap();
        symlink(&outside, ipc.join("input")).unwrap();
        fs::write(ipc.join("tasks"), "not a dir").unwrap();
        build(&fx, &group("team", false), false, &DenyAllMounts, None).unwrap();
        for sub in IPC_SUBDIRS {
            let meta = fs::symlink_metadata(ipc.join(sub)).unwrap();
            assert!(meta.is_dir(), "{sub} must be a real dir");
        }
        assert!(outside.is_dir());
    }

    #[test]
    fn chown_is_attempted_for_writable_dirs() {
        // As non-root we can only "chown" to our own ids; verify no error and
        // ownership unchanged.
        let fx = fixture();
        let me = fs::metadata(&fx.root).unwrap();
        let owner = RunAs {
            uid: me.uid(),
            gid: me.gid(),
        };
        let g = group("team", false);
        let options = MountOptions::default();
        build_mounts(&MountRequest {
            layout: &fx.layout,
            group: &g,
            is_main: false,
            policy: &DenyAllMounts,
            chown_to: Some(owner),
            options: &options,
            audit: None,
        })
        .unwrap();
        assert_eq!(
            fs::metadata(fx.root.join("data/ipc/team/input"))
                .unwrap()
                .uid(),
            owner.uid
        );
    }

    #[test]
    fn describe_and_helpers() {
        let m = VolumeMount::ro("/a", "/b");
        assert_eq!(m.describe(), "/a -> /b (ro)");
        assert_eq!(VolumeMount::rw("/a", "/b").describe(), "/a -> /b");
        assert!(VolumeMount::shadow("/x").is_shadow());
        assert_eq!(mcp_staging_path("cve", ".env"), "/etc/mcp-staging/cve.env");
        let palace = ISOLATED_MCPS.iter().find(|m| m.id == "palace").unwrap();
        assert_eq!(palace.user(), "mcp-palace");
        assert_eq!(palace.extra_mount_path(), "/workspace/extra/mempalace");
    }
}
