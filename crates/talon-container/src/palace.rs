//! Hardened one-shot container for host-side MemPalace calls (MYTH-01).
//!
//! The host's `/palace/*` endpoints used to run `mempalace/palace-call.sh` on
//! the host, which unpickles ChromaDB's `index_metadata.pickle` from
//! `mempalace-data/` — a directory agent containers could write. Now:
//!
//! - agent containers can no longer read or write palace data (the
//!   entrypoint gives `/workspace/extra/mempalace-data` to `mcp-palace`,
//!   mode 0700, before dropping privileges), and
//! - host palace calls run in a throw-away container as the unprivileged
//!   `mcp-palace` uid ([`MCP_PALACE_UID`]) with no capabilities, a read-only
//!   root filesystem, tight limits, the palace code mounted read-only and only
//!   the palace data mounted writable.
//!
//! ```text
//! run --rm -i --init --name <name>
//!   --label talon.managed=true --label talon.role=palace
//!   --cap-drop=ALL --security-opt=no-new-privileges --read-only
//!   --tmpfs /tmp:rw,nosuid,nodev,size=256m --user 61008:61008
//!   --pids-limit 128 --memory 2g --memory-swap 2g --cpus 1 [--network <net>]
//!   -e HOME=/tmp
//!   --mount type=bind,source=<project>/mempalace-data,target=/workspace/extra/mempalace-data
//!   --mount type=bind,source=<project>/mempalace,target=/workspace/extra/mempalace,readonly
//!   --entrypoint /workspace/extra/mempalace/palace-call.sh <image>
//! ```
//!
//! The host pipes the JSON request to stdin and reads the JSON response from
//! stdout.

use std::fs;
use std::path::{Path, PathBuf};

use talon_core::{Error, Result};

use crate::args::{is_valid_image, mount_args, validate_network};
use crate::mounts::VolumeMount;
use crate::runtime::{MANAGED_LABEL, is_valid_container_name};

/// uid of the image's `mcp-palace` account (`container/Dockerfile`:
/// `palace:61008`; a unit test keeps the two in sync).
pub const MCP_PALACE_UID: u32 = 61008;
/// gid of the image's `mcp-palace` group.
pub const MCP_PALACE_GID: u32 = 61008;
/// Label marking palace one-shot containers.
pub const PALACE_ROLE_LABEL: &str = "talon.role=palace";
/// Palace data directory under the project root.
pub const PALACE_DATA_DIR: &str = "mempalace-data";
/// Palace code directory (wrapper scripts) under the project root.
pub const PALACE_CODE_DIR: &str = "mempalace";
/// Where palace data is mounted (agent containers and palace one-shots).
pub const PALACE_DATA_CONTAINER_PATH: &str = "/workspace/extra/mempalace-data";
/// Where the palace code is mounted (read-only).
pub const PALACE_CODE_CONTAINER_PATH: &str = "/workspace/extra/mempalace";
/// One-shot helper script (reads a JSON request on stdin).
pub const PALACE_CALL_SCRIPT: &str = "palace-call.sh";
/// `--tmpfs` for the palace one-shot.
pub const PALACE_TMPFS: &str = "/tmp:rw,nosuid,nodev,size=256m";
/// `--pids-limit` for the palace one-shot.
pub const PALACE_PIDS_LIMIT: u32 = 128;
/// `--memory` / `--memory-swap` for the palace one-shot.
pub const PALACE_MEMORY: &str = "2g";
/// `--cpus` for the palace one-shot.
pub const PALACE_CPUS: &str = "1";

/// Inputs for [`build_palace_run_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PalaceRunSpec {
    /// Agent image (the palace venv lives at `/opt/mempalace`).
    pub image: String,
    /// Talon checkout holding `mempalace/` and `mempalace-data/`.
    pub project_root: PathBuf,
    /// Container name (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`).
    pub name: String,
    /// `--network`; `None` = the runtime default.
    pub network: Option<String>,
}

/// Canonical directory `<root>/<name>`, refusing anything that is not a
/// directory.
fn canonical_dir(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(name);
    let canonical = fs::canonicalize(&path).map_err(|e| {
        Error::Container(format!(
            "palace directory {} is not accessible: {e}",
            path.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(Error::Container(format!(
            "palace path {} is not a directory",
            path.display()
        )));
    }
    Ok(canonical)
}

/// The full `run` argument vector (after the runtime binary) for one
/// host-side palace call. See the module docs for the exact layout.
pub fn build_palace_run_args(spec: &PalaceRunSpec) -> Result<Vec<String>> {
    if !is_valid_container_name(&spec.name) {
        return Err(Error::invalid(format!(
            "invalid palace container name {:?}",
            spec.name
        )));
    }
    if !is_valid_image(&spec.image) {
        return Err(Error::Config(format!(
            "invalid container image {:?}",
            spec.image
        )));
    }
    let network = match spec.network.as_deref().map(str::trim) {
        None => None,
        Some(n) => {
            validate_network(n).map_err(|reason| {
                Error::Config(format!("invalid palace network {n:?}: {reason}"))
            })?;
            Some(n)
        }
    };
    if !spec.project_root.is_absolute() {
        return Err(Error::Config(format!(
            "palace project root must be absolute: {}",
            spec.project_root.display()
        )));
    }
    let project = fs::canonicalize(&spec.project_root)?;
    let data = canonical_dir(&project, PALACE_DATA_DIR)?;
    let code = canonical_dir(&project, PALACE_CODE_DIR)?;
    // The entrypoint must be a real file inside the read-only code mount (a
    // symlink would be resolved inside the container).
    let script = code.join(PALACE_CALL_SCRIPT);
    if !fs::symlink_metadata(&script)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
    {
        return Err(Error::Container(format!(
            "{} is missing or not a regular file",
            script.display()
        )));
    }
    let data_mount = mount_args(&VolumeMount::rw(data, PALACE_DATA_CONTAINER_PATH))?;
    let code_mount = mount_args(&VolumeMount::ro(code, PALACE_CODE_CONTAINER_PATH))?;

    let user = format!("{MCP_PALACE_UID}:{MCP_PALACE_GID}");
    let pids = PALACE_PIDS_LIMIT.to_string();
    let entrypoint = format!("{PALACE_CODE_CONTAINER_PATH}/{PALACE_CALL_SCRIPT}");
    let mut args: Vec<String> = [
        "run",
        "--rm",
        "-i",
        "--init",
        "--name",
        &spec.name,
        "--label",
        MANAGED_LABEL,
        "--label",
        PALACE_ROLE_LABEL,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs",
        PALACE_TMPFS,
        "--user",
        &user,
        "--pids-limit",
        &pids,
        "--memory",
        PALACE_MEMORY,
        "--memory-swap",
        PALACE_MEMORY,
        "--cpus",
        PALACE_CPUS,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(net) = network {
        args.push("--network".to_string());
        args.push(net.to_string());
    }
    args.push("-e".to_string());
    args.push("HOME=/tmp".to_string());
    args.extend(data_mount);
    args.extend(code_mount);
    args.push("--entrypoint".to_string());
    args.push(entrypoint);
    args.push(spec.image.clone());
    Ok(args)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    struct Fx {
        _tmp: tempfile::TempDir,
        root: PathBuf,
    }

    fn fixture() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(root.join("mempalace-data/palace")).unwrap();
        fs::create_dir_all(root.join("mempalace")).unwrap();
        fs::write(root.join("mempalace/palace-call.sh"), "#!/bin/sh\n").unwrap();
        Fx { _tmp: tmp, root }
    }

    fn spec(root: &Path, network: Option<&str>) -> PalaceRunSpec {
        PalaceRunSpec {
            image: "talon-agent:latest".into(),
            project_root: root.to_path_buf(),
            name: "talon-palace-1700000000000".into(),
            network: network.map(str::to_string),
        }
    }

    #[test]
    fn palace_run_args_exact_list() {
        let fx = fixture();
        let root = fx.root.to_string_lossy();
        let data_spec = format!(
            "type=bind,source={root}/mempalace-data,target=/workspace/extra/mempalace-data"
        );
        let code_spec =
            format!("type=bind,source={root}/mempalace,target=/workspace/extra/mempalace,readonly");
        let head = sv(&[
            "run",
            "--rm",
            "-i",
            "--init",
            "--name",
            "talon-palace-1700000000000",
            "--label",
            "talon.managed=true",
            "--label",
            "talon.role=palace",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m",
            "--user",
            "61008:61008",
            "--pids-limit",
            "128",
            "--memory",
            "2g",
            "--memory-swap",
            "2g",
            "--cpus",
            "1",
        ]);
        let tail = sv(&[
            "-e",
            "HOME=/tmp",
            "--mount",
            &data_spec,
            "--mount",
            &code_spec,
            "--entrypoint",
            "/workspace/extra/mempalace/palace-call.sh",
            "talon-agent:latest",
        ]);

        let args = build_palace_run_args(&spec(&fx.root, None)).unwrap();
        let mut expected = head.clone();
        expected.extend(tail.clone());
        assert_eq!(args, expected);

        let args = build_palace_run_args(&spec(&fx.root, Some("none"))).unwrap();
        let mut expected = head;
        expected.extend(sv(&["--network", "none"]));
        expected.extend(tail);
        assert_eq!(args, expected);
        // Never privileged, never root.
        assert!(!args.iter().any(|a| a.starts_with("--cap-add")));
        assert!(!args.iter().any(|a| a == "0:0" || a == "root"));
    }

    #[test]
    fn palace_run_args_validate_inputs() {
        let fx = fixture();
        let mut s = spec(&fx.root, None);
        s.name = "-it".into();
        assert!(build_palace_run_args(&s).is_err());
        let mut s = spec(&fx.root, None);
        s.image = "--privileged".into();
        assert!(build_palace_run_args(&s).is_err());
        for net in ["host", "container:abc", "bad name"] {
            assert!(build_palace_run_args(&spec(&fx.root, Some(net))).is_err());
        }
        let mut s = spec(&fx.root, None);
        s.project_root = PathBuf::from("relative/root");
        assert!(build_palace_run_args(&s).is_err());

        // Unsafe characters in the (canonical) host path are refused.
        let odd = fx.root.join("a,b");
        fs::create_dir_all(odd.join("mempalace-data")).unwrap();
        fs::create_dir_all(odd.join("mempalace")).unwrap();
        fs::write(odd.join("mempalace/palace-call.sh"), "").unwrap();
        assert!(build_palace_run_args(&spec(&odd, None)).is_err());

        // Missing data dir / script, or a symlinked script, are refused.
        fs::remove_dir_all(fx.root.join("mempalace-data")).unwrap();
        assert!(build_palace_run_args(&spec(&fx.root, None)).is_err());
        fs::create_dir_all(fx.root.join("mempalace-data")).unwrap();
        fs::remove_file(fx.root.join("mempalace/palace-call.sh")).unwrap();
        assert!(build_palace_run_args(&spec(&fx.root, None)).is_err());
        fs::write(fx.root.join("elsewhere.sh"), "").unwrap();
        symlink(
            fx.root.join("elsewhere.sh"),
            fx.root.join("mempalace/palace-call.sh"),
        )
        .unwrap();
        assert!(build_palace_run_args(&spec(&fx.root, None)).is_err());
    }

    #[test]
    fn palace_data_symlink_is_resolved() {
        let fx = fixture();
        let real = fx.root.join("store-elsewhere");
        fs::create_dir_all(&real).unwrap();
        fs::remove_dir_all(fx.root.join("mempalace-data")).unwrap();
        symlink(&real, fx.root.join("mempalace-data")).unwrap();
        let args = build_palace_run_args(&spec(&fx.root, None)).unwrap();
        let expected = format!(
            "type=bind,source={},target=/workspace/extra/mempalace-data",
            real.display()
        );
        assert!(args.contains(&expected));
    }

    // --- N-7: container/entrypoint.sh palace step ---

    fn entrypoint_text() -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../container/entrypoint.sh");
        fs::read_to_string(path).unwrap()
    }

    /// The `secure_palace_data` function from the entrypoint, verbatim.
    fn palace_function(script: &str) -> String {
        let start = script.find("\nsecure_palace_data() {\n").unwrap() + 1;
        let len = script[start..].find("\n}\n").unwrap() + 3;
        script[start..start + len].to_string()
    }

    #[test]
    fn entrypoint_is_valid_bash() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../container/entrypoint.sh");
        match std::process::Command::new("bash")
            .arg("-n")
            .arg(&path)
            .output()
        {
            Ok(out) => assert!(
                out.status.success(),
                "bash -n failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => eprintln!("bash not available ({e}); syntax check skipped"),
        }
    }

    #[test]
    fn entrypoint_secures_palace_before_staging_secrets() {
        let script = entrypoint_text();
        let call = script.find("\nsecure_palace_data\n").unwrap();
        let staging_loop = script.find("for staged in \"$STAGING_DIR\"/*").unwrap();
        let first_secret_write = script.find("install -m 0600").unwrap();
        let supervise = script.find("exec \"$AGENT_BIN\" supervise").unwrap();
        assert!(
            call < staging_loop,
            "palace step must run before secrets are staged"
        );
        assert!(call < first_secret_write);
        assert!(call < supervise);
        assert!(
            !script[..call].contains("$SECRETS_DIR\""),
            "no secret before the walk"
        );

        // The tree is walked only in the migration branch, after the
        // already-secured early return, and never follows symlinks.
        let func = palace_function(&script);
        let secured = func
            .find("if [ \"$state\" = \"$puid:$pgid:700\" ]; then")
            .unwrap();
        let early_return = func[secured..].find("return 0").unwrap() + secured;
        let migration = func.find("one-time migration").unwrap();
        let first_find = func.find("find ").unwrap();
        assert!(early_return < first_find && migration < first_find);
        for line in func.lines().filter(|l| l.contains("find ")) {
            assert!(line.contains("find -P"), "{line}");
            assert!(line.contains("-xdev"), "{line}");
            assert!(line.contains("-mindepth 1"), "{line}");
        }
        assert!(!func.contains("chown -R") && !func.contains("chmod -R"));
    }

    /// Runs the entrypoint's `secure_palace_data` on `dir` with `id` stubbed
    /// to report uid/gid [`MCP_PALACE_UID`] for `mcp-palace`.
    fn run_palace_step(scratch: &Path, dir: &Path) -> std::process::Output {
        let harness = format!(
            "set -euo pipefail\nPALACE_DATA=$1\nPALACE_USER=mcp-palace\n\
             log() {{ printf 'talon-entrypoint: %s\\n' \"$*\" >&2; }}\n\
             die() {{ log \"FATAL: $*\"; exit 70; }}\n\
             id() {{ case \"$1\" in -u|-g) echo {MCP_PALACE_UID} ;; *) command id \"$@\" ;; esac; }}\n\
             {}\nsecure_palace_data\n",
            palace_function(&entrypoint_text())
        );
        let script = scratch.join("harness.sh");
        fs::write(&script, harness).unwrap();
        std::process::Command::new("bash")
            .arg(&script)
            .arg(dir)
            .output()
            .unwrap()
    }

    #[test]
    fn entrypoint_palace_step_never_walks_a_secured_tree() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
        if !rustix::process::geteuid().is_root() {
            eprintln!("not root: entrypoint palace behaviour test skipped");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let p = MCP_PALACE_UID;
        let owner_mode = |path: &Path| {
            let m = fs::symlink_metadata(path).unwrap();
            (m.uid(), m.gid(), m.mode() & 0o7777)
        };
        let set_mode = |path: &Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };

        // One-time migration of a host-created directory.
        let data = root.join("data");
        let outside = root.join("outside");
        fs::create_dir_all(data.join("palace/sub")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(data.join("palace/sub/chroma.sqlite3"), "db").unwrap();
        fs::write(outside.join("target"), "host file").unwrap();
        fs::write(outside.join("shared"), "shared inode").unwrap();
        fs::hard_link(outside.join("shared"), data.join("hardlinked")).unwrap();
        symlink(outside.join("target"), data.join("link")).unwrap();
        for d in [&data, &data.join("palace"), &data.join("palace/sub")] {
            set_mode(d, 0o755);
        }
        set_mode(&data.join("palace/sub/chroma.sqlite3"), 0o644);
        set_mode(&outside.join("target"), 0o644);
        set_mode(&outside.join("shared"), 0o644);
        let out = run_palace_step(&root, &data);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("one-time migration"));
        assert_eq!(owner_mode(&data), (p, p, 0o700));
        assert_eq!(owner_mode(&data.join("palace")), (p, p, 0o700));
        assert_eq!(owner_mode(&data.join("palace/sub")), (p, p, 0o700));
        assert_eq!(
            owner_mode(&data.join("palace/sub/chroma.sqlite3")),
            (p, p, 0o600)
        );
        // Symlinks: re-owned themselves, their targets never touched.
        assert_eq!(fs::symlink_metadata(data.join("link")).unwrap().uid(), p);
        assert_eq!(owner_mode(&outside.join("target")), (0, 0, 0o644));
        // Hard-linked inodes are left alone.
        assert_eq!(owner_mode(&outside.join("shared")), (0, 0, 0o644));

        // Already secured: nothing below the top directory is touched, even
        // things mcp-palace could have swapped in.
        let canary = data.join("palace/canary");
        fs::write(&canary, "x").unwrap();
        set_mode(&canary, 0o644);
        let out = run_palace_step(&root, &data);
        assert!(out.status.success());
        assert!(
            out.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(owner_mode(&canary), (0, 0, 0o644));

        // Owned by mcp-palace but drifted (group / mode): top directory only.
        chown(&data, Some(p), Some(0)).unwrap();
        set_mode(&data, 0o755);
        let out = run_palace_step(&root, &data);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("top directory only"));
        assert_eq!(owner_mode(&data), (p, p, 0o700));
        assert_eq!(owner_mode(&canary), (0, 0, 0o644));

        // A symlinked data path is fatal; a missing one is fine.
        let linked = root.join("linked");
        symlink(&data, &linked).unwrap();
        assert_eq!(run_palace_step(&root, &linked).status.code(), Some(70));
        assert!(
            run_palace_step(&root, &root.join("missing"))
                .status
                .success()
        );
    }

    #[test]
    fn palace_uid_matches_dockerfile() {
        let dockerfile = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../container/Dockerfile");
        let text = fs::read_to_string(dockerfile).unwrap();
        assert!(
            text.contains(&format!("palace:{MCP_PALACE_UID}")),
            "container/Dockerfile must create mcp-palace with uid {MCP_PALACE_UID}"
        );
        assert_eq!(MCP_PALACE_UID, MCP_PALACE_GID);
    }
}
