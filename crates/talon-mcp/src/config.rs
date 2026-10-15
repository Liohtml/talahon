//! `.mcp.json` parsing and validation.
//!
//! Format (Claude Code compatible, plus Talon's `runAs`):
//!
//! ```json
//! { "mcpServers": {
//!     "opensearch": {
//!       "command": "/workspace/extra/siem/opensearch-mcp.sh",
//!       "args": ["--flag"], "env": {"K": "V"}, "cwd": "/tmp",
//!       "runAs": "mcp-siem"
//! } } }
//! ```
//!
//! Parsing isolates failures per server: a malformed entry is recorded in
//! [`McpConfigFile::invalid`] and the remaining servers still load.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::McpError;

/// Fallback system user for servers without (or with an invalid) `runAs`.
pub const DEFAULT_RUN_AS: &str = "mcp-default";

/// Maximum accepted size of a `.mcp.json` file.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Linux `sun_path` is 108 bytes including the trailing NUL.
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;

/// Environment variables a group-controlled `.mcp.json` must not set for a
/// server launched under a privileged identity (they inject code into the
/// interpreter or dynamic loader).
pub const DANGEROUS_ENV_KEYS: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "IFS",
    "PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "PYTHONINSPECT",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "NODE_OPTIONS",
    "NODE_PATH",
    "GCONV_PATH",
    "HOSTALIASES",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "GIT_SSH_COMMAND",
];

/// One server entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    /// Transport type (`"stdio"` or absent). Remote transports (`http`,
    /// `sse`) are parsed but rejected by [`ServerConfig::validate_for_spawn`].
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Executable to run.
    #[serde(default)]
    pub command: String,
    /// Arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Extra environment variables (scalars are coerced to strings).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// System user the supervisor runs the server as
    /// (`^mcp-[a-z0-9_-]{1,32}$`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    /// Remote URL (unsupported; kept for diagnostics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl ServerConfig {
    /// Stdio server running `command` with `args`.
    pub fn new(
        command: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            command: command.into(),
            args: args.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Parse one entry from JSON (leniently coercing scalar env values).
    pub fn from_value(value: &Value) -> Result<Self, McpError> {
        let Value::Object(obj) = value else {
            return Err(McpError::Config("server entry is not an object".into()));
        };
        let mut obj = obj.clone();
        if let Some(Value::Object(env)) = obj.get_mut("env") {
            for (k, v) in env.iter_mut() {
                match v {
                    Value::String(_) => {}
                    Value::Number(_) | Value::Bool(_) => *v = Value::String(v.to_string()),
                    _ => {
                        return Err(McpError::Config(format!(
                            "env value for '{k}' must be a string"
                        )));
                    }
                }
            }
        }
        serde_json::from_value(Value::Object(obj)).map_err(|e| McpError::Config(e.to_string()))
    }

    /// Validate a server that will be connected to (any launch mode).
    pub fn validate_name(name: &str) -> Result<(), McpError> {
        if is_valid_server_name(name) {
            Ok(())
        } else {
            Err(McpError::Config(format!(
                "invalid server name '{name}' (allowed: letters, digits, '_', '-', '.', max 64, must start with a letter or digit)"
            )))
        }
    }

    /// Validate a server that this process will spawn over stdio.
    pub fn validate_for_spawn(&self, name: &str) -> Result<(), McpError> {
        Self::validate_name(name)?;
        match self.transport.as_deref() {
            None | Some("stdio") => {}
            Some(other) => {
                return Err(McpError::Config(format!(
                    "server '{name}': transport '{other}' is not supported (only stdio)"
                )));
            }
        }
        if self.command.trim().is_empty() {
            return Err(McpError::Config(format!(
                "server '{name}': missing command"
            )));
        }
        if self.command.contains('\0') || self.args.iter().any(|a| a.contains('\0')) {
            return Err(McpError::Config(format!(
                "server '{name}': command/args contain a NUL byte"
            )));
        }
        for (k, v) in &self.env {
            if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
                return Err(McpError::Config(format!(
                    "server '{name}': invalid environment variable '{k}'"
                )));
            }
        }
        if let Some(user) = &self.run_as {
            if !is_valid_run_as(user) {
                return Err(McpError::Config(format!(
                    "server '{name}': invalid runAs '{user}' (must match ^mcp-[a-z0-9_-]{{1,32}}$)"
                )));
            }
        }
        Ok(())
    }

    /// The system user to run as: a valid `runAs`, else [`DEFAULT_RUN_AS`].
    pub fn effective_run_as(&self) -> &str {
        match self.run_as.as_deref() {
            Some(u) if is_valid_run_as(u) => u,
            _ => DEFAULT_RUN_AS,
        }
    }

    /// Extra checks for a launch under a privileged identity (the
    /// supervisor running servers as `mcp-*` users that can read secrets).
    /// `.mcp.json` lives in the group folder, which the agent can write, so
    /// the supervisor must not run arbitrary commands with those
    /// identities. Requires:
    /// - stdio entry that passes [`Self::validate_for_spawn`];
    /// - an absolute `command` that canonicalizes to a regular file inside
    ///   one of `allowed_roots` (which should be read-only mounts);
    /// - no environment override from [`DANGEROUS_ENV_KEYS`] or `LD_*` /
    ///   `DYLD_*`.
    ///
    /// Returns the canonical command path, which the caller should execute
    /// instead of `command`.
    pub fn check_privileged_launch(
        &self,
        name: &str,
        allowed_roots: &[PathBuf],
    ) -> Result<PathBuf, McpError> {
        self.validate_for_spawn(name)?;
        let cmd = Path::new(&self.command);
        if !cmd.is_absolute() {
            return Err(McpError::Config(format!(
                "server '{name}': command must be an absolute path for a privileged launch"
            )));
        }
        let canonical = std::fs::canonicalize(cmd).map_err(|e| {
            McpError::Config(format!("server '{name}': cannot resolve command: {e}"))
        })?;
        let meta = std::fs::metadata(&canonical)
            .map_err(|e| McpError::Config(format!("server '{name}': cannot stat command: {e}")))?;
        if !meta.is_file() {
            return Err(McpError::Config(format!(
                "server '{name}': command is not a regular file"
            )));
        }
        let inside = allowed_roots.iter().any(|root| {
            std::fs::canonicalize(root)
                .map(|r| canonical.starts_with(r))
                .unwrap_or(false)
        });
        if !inside {
            return Err(McpError::Config(format!(
                "server '{name}': command {} is outside the allowed MCP directories",
                canonical.display()
            )));
        }
        for key in self.env.keys() {
            let upper = key.to_ascii_uppercase();
            if upper.starts_with("LD_")
                || upper.starts_with("DYLD_")
                || DANGEROUS_ENV_KEYS.contains(&upper.as_str())
            {
                return Err(McpError::Config(format!(
                    "server '{name}': environment variable '{key}' is not allowed for a privileged launch"
                )));
            }
        }
        Ok(canonical)
    }
}

/// A parsed `.mcp.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfigFile {
    /// Valid server entries, sorted by name.
    #[serde(default)]
    pub mcp_servers: BTreeMap<String, ServerConfig>,
    /// Entries that could not be parsed: name -> error.
    #[serde(skip)]
    pub invalid: BTreeMap<String, String>,
}

impl McpConfigFile {
    /// Parse JSON text. Fails only if the document itself is unusable (not
    /// JSON, not an object, `mcpServers` not an object); bad entries are
    /// collected in [`Self::invalid`].
    pub fn parse(text: &str) -> Result<Self, McpError> {
        let root: Value = serde_json::from_str(text)
            .map_err(|e| McpError::Config(format!("invalid JSON: {e}")))?;
        let Value::Object(root) = root else {
            return Err(McpError::Config("top level is not a JSON object".into()));
        };
        let mut file = Self::default();
        let servers = match root.get("mcpServers") {
            None | Some(Value::Null) => return Ok(file),
            Some(Value::Object(servers)) => servers,
            Some(_) => return Err(McpError::Config("'mcpServers' is not an object".into())),
        };
        for (name, entry) in servers {
            match ServerConfig::from_value(entry) {
                Ok(cfg) => {
                    file.mcp_servers.insert(name.clone(), cfg);
                }
                Err(e) => {
                    tracing::warn!(server = %name, error = %e, "ignoring invalid .mcp.json entry");
                    file.invalid.insert(name.clone(), e.to_string());
                }
            }
        }
        Ok(file)
    }

    /// Read and parse a file (max [`MAX_CONFIG_BYTES`]).
    pub fn load(path: &Path) -> Result<Self, McpError> {
        let file = std::fs::File::open(path)
            .map_err(|e| McpError::Config(format!("cannot open {}: {e}", path.display())))?;
        let mut text = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| McpError::Config(format!("cannot read {}: {e}", path.display())))?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(McpError::Config(format!(
                "{} exceeds {MAX_CONFIG_BYTES} bytes",
                path.display()
            )));
        }
        Self::parse(&text)
    }

    /// Like [`Self::load`] but returns `Ok(None)` when the file does not exist.
    pub fn load_optional(path: &Path) -> Result<Option<Self>, McpError> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Self::load(path).map(Some),
        }
    }

    /// Iterate over valid servers in name order.
    pub fn servers(&self) -> impl Iterator<Item = (&str, &ServerConfig)> {
        self.mcp_servers.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of valid servers.
    pub fn len(&self) -> usize {
        self.mcp_servers.len()
    }

    /// True if no valid server is configured.
    pub fn is_empty(&self) -> bool {
        self.mcp_servers.is_empty()
    }
}

/// `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$` — safe as a file name component.
pub fn is_valid_server_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// `^mcp-[a-z0-9_-]{1,32}$`.
pub fn is_valid_run_as(user: &str) -> bool {
    let Some(rest) = user.strip_prefix("mcp-") else {
        return false;
    };
    (1..=32).contains(&rest.len())
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Path of the unix socket the supervisor exposes for `server`:
/// `<dir>/<server>.sock`. Both sides must use this function.
pub fn socket_path(dir: &Path, server: &str) -> Result<PathBuf, McpError> {
    ServerConfig::validate_name(server)?;
    let path = dir.join(format!("{server}.sock"));
    if path.as_os_str().len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(McpError::Config(format!(
            "socket path {} is too long for a unix socket",
            path.display()
        )));
    }
    Ok(path)
}

/// A system account from `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemUser {
    /// Login name.
    pub name: String,
    /// Numeric user id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
    /// Home directory.
    pub home: PathBuf,
}

/// Look `name` up in `/etc/passwd` (no NSS; container images use files).
pub fn lookup_system_user(name: &str) -> std::io::Result<Option<SystemUser>> {
    let text = std::fs::read_to_string("/etc/passwd")?;
    Ok(lookup_user_in_passwd(&text, name))
}

/// Parse passwd-format `text` and find `name`.
pub fn lookup_user_in_passwd(text: &str, name: &str) -> Option<SystemUser> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|line| {
            let mut f = line.split(':');
            let user = f.next()?;
            if user != name {
                return None;
            }
            let _pw = f.next()?;
            let uid = f.next()?.parse().ok()?;
            let gid = f.next()?.parse().ok()?;
            let _gecos = f.next()?;
            let home = PathBuf::from(f.next()?);
            Some(SystemUser {
                name: user.to_string(),
                uid,
                gid,
                home,
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COPILOT: &str = r#"{
      "mcpServers": {
        "opensearch": { "command": "/workspace/extra/siem/opensearch-mcp.sh" },
        "opensearch_anon": { "command": "/workspace/extra/siem/anon-opensearch-mcp.sh" },
        "mysql": { "command": "/workspace/extra/mysql/mysql-mcp.sh", "runAs": "mcp-mysql" },
        "cve": { "command": "/workspace/extra/cve-mcp/cve-mcp.sh", "args": ["--x", "1"],
                 "env": {"A": "b", "N": 5, "B": true}, "cwd": "/tmp" }
      }
    }"#;

    #[test]
    fn parses_real_config_shape() {
        let f = McpConfigFile::parse(COPILOT).unwrap();
        assert_eq!(f.len(), 4);
        assert!(f.invalid.is_empty());
        let names: Vec<_> = f.servers().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["cve", "mysql", "opensearch", "opensearch_anon"]);
        let cve = &f.mcp_servers["cve"];
        assert_eq!(cve.args, vec!["--x", "1"]);
        assert_eq!(cve.env["N"], "5");
        assert_eq!(cve.env["B"], "true");
        assert_eq!(cve.cwd.as_deref(), Some(Path::new("/tmp")));
        assert_eq!(f.mcp_servers["mysql"].effective_run_as(), "mcp-mysql");
        assert_eq!(
            f.mcp_servers["opensearch"].effective_run_as(),
            DEFAULT_RUN_AS
        );
        for (name, cfg) in f.servers() {
            cfg.validate_for_spawn(name).unwrap();
        }
    }

    #[test]
    fn parses_repo_config_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../groups");
        for group in ["copilot", "main"] {
            let path = root.join(group).join(".mcp.json");
            if let Some(f) = McpConfigFile::load_optional(&path).unwrap() {
                assert!(!f.is_empty(), "{group}");
                assert!(f.invalid.is_empty());
            }
        }
    }

    #[test]
    fn isolates_bad_entries() {
        let f = McpConfigFile::parse(
            r#"{"mcpServers": {
                "good": {"command": "x"},
                "bad_args": {"command": "x", "args": "notalist"},
                "bad_env": {"command": "x", "env": {"K": {"nested": 1}}},
                "not_obj": 5
            }}"#,
        )
        .unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f.invalid.len(), 3);
        assert!(f.invalid["bad_env"].contains("must be a string"));
    }

    #[test]
    fn document_level_errors() {
        assert!(McpConfigFile::parse("not json").is_err());
        assert!(McpConfigFile::parse("[]").is_err());
        assert!(McpConfigFile::parse(r#"{"mcpServers": []}"#).is_err());
        assert!(McpConfigFile::parse("{}").unwrap().is_empty());
        assert!(
            McpConfigFile::parse(r#"{"mcpServers": null}"#)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn spawn_validation() {
        let ok = ServerConfig::new("/bin/true", ["a"]);
        ok.validate_for_spawn("srv").unwrap();
        assert!(ok.validate_for_spawn("../evil").is_err());
        assert!(
            ServerConfig::new("", Vec::<String>::new())
                .validate_for_spawn("s")
                .is_err()
        );
        assert!(
            ServerConfig::new("a\0b", Vec::<String>::new())
                .validate_for_spawn("s")
                .is_err()
        );
        let http = ServerConfig {
            transport: Some("http".into()),
            url: Some("https://x".into()),
            ..ServerConfig::default()
        };
        let err = http.validate_for_spawn("remote").unwrap_err().to_string();
        assert!(err.contains("not supported"), "{err}");
        let mut stdio = ServerConfig::new("x", Vec::<String>::new());
        stdio.transport = Some("stdio".into());
        stdio.validate_for_spawn("s").unwrap();
        let mut bad_env = ServerConfig::new("x", Vec::<String>::new());
        bad_env.env.insert("A=B".into(), "v".into());
        assert!(bad_env.validate_for_spawn("s").is_err());
        let mut bad_user = ServerConfig::new("x", Vec::<String>::new());
        bad_user.run_as = Some("root".into());
        assert!(bad_user.validate_for_spawn("s").is_err());
        assert_eq!(bad_user.effective_run_as(), DEFAULT_RUN_AS);
    }

    #[test]
    fn name_rules() {
        for ok in [
            "a",
            "opensearch_anon",
            "cve-mcp",
            "x.y",
            "A1",
            &"a".repeat(64),
        ] {
            assert!(is_valid_server_name(ok), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            "-x",
            "_x",
            "a/b",
            "a b",
            "ä",
            &"a".repeat(65),
        ] {
            assert!(!is_valid_server_name(bad), "{bad}");
        }
        for ok in [
            "mcp-siem",
            "mcp-default",
            "mcp-a_b-1",
            &format!("mcp-{}", "a".repeat(32)),
        ] {
            assert!(is_valid_run_as(ok), "{ok}");
        }
        for bad in [
            "mcp-",
            "siem",
            "mcp-SIEM",
            "mcp-a.b",
            "root",
            &format!("mcp-{}", "a".repeat(33)),
        ] {
            assert!(!is_valid_run_as(bad), "{bad}");
        }
    }

    #[test]
    fn socket_paths() {
        let p = socket_path(Path::new("/run/talon/mcp"), "opensearch").unwrap();
        assert_eq!(p, Path::new("/run/talon/mcp/opensearch.sock"));
        assert!(socket_path(Path::new("/run"), "../x").is_err());
        let long = "/a".repeat(60);
        assert!(socket_path(Path::new(&long), "srv").is_err());
    }

    #[test]
    fn privileged_launch_checks() {
        let dir = tempfile::tempdir().unwrap();
        let allowed = dir.path().join("extra");
        std::fs::create_dir(&allowed).unwrap();
        let script = allowed.join("srv.sh");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        let outside = dir.path().join("evil.sh");
        std::fs::write(&outside, "#!/bin/sh\n").unwrap();
        let roots = vec![allowed.clone()];

        let cfg = ServerConfig::new(script.to_string_lossy(), Vec::<String>::new());
        let canonical = cfg.check_privileged_launch("srv", &roots).unwrap();
        assert_eq!(canonical, std::fs::canonicalize(&script).unwrap());

        let cfg = ServerConfig::new(outside.to_string_lossy(), Vec::<String>::new());
        assert!(cfg.check_privileged_launch("srv", &roots).is_err());

        // Traversal out of the allowed root is resolved and rejected.
        let sneaky = allowed.join("../evil.sh");
        let cfg = ServerConfig::new(sneaky.to_string_lossy(), Vec::<String>::new());
        assert!(cfg.check_privileged_launch("srv", &roots).is_err());

        // Symlink inside the root pointing outside is rejected.
        #[cfg(unix)]
        {
            let link = allowed.join("link.sh");
            std::os::unix::fs::symlink(&outside, &link).unwrap();
            let cfg = ServerConfig::new(link.to_string_lossy(), Vec::<String>::new());
            assert!(cfg.check_privileged_launch("srv", &roots).is_err());
        }

        let cfg = ServerConfig::new("srv.sh", Vec::<String>::new());
        assert!(cfg.check_privileged_launch("srv", &roots).is_err());

        let cfg = ServerConfig::new(allowed.to_string_lossy(), Vec::<String>::new());
        assert!(cfg.check_privileged_launch("srv", &roots).is_err());

        for key in [
            "LD_PRELOAD",
            "ld_library_path",
            "PYTHONPATH",
            "BASH_ENV",
            "PATH",
        ] {
            let mut cfg = ServerConfig::new(script.to_string_lossy(), Vec::<String>::new());
            cfg.env.insert(key.into(), "x".into());
            assert!(cfg.check_privileged_launch("srv", &roots).is_err(), "{key}");
        }
        let mut cfg = ServerConfig::new(script.to_string_lossy(), Vec::<String>::new());
        cfg.env.insert("OPENSEARCH_URL".into(), "x".into());
        cfg.check_privileged_launch("srv", &roots).unwrap();
    }

    #[test]
    fn load_limits_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("none.json");
        assert!(McpConfigFile::load_optional(&missing).unwrap().is_none());
        assert!(McpConfigFile::load(&missing).is_err());
        let big = dir.path().join("big.json");
        std::fs::write(&big, vec![b' '; (MAX_CONFIG_BYTES + 10) as usize]).unwrap();
        assert!(McpConfigFile::load(&big).is_err());
        let ok = dir.path().join("ok.json");
        std::fs::write(&ok, COPILOT).unwrap();
        assert_eq!(McpConfigFile::load_optional(&ok).unwrap().unwrap().len(), 4);
    }

    #[test]
    fn passwd_lookup() {
        let passwd = "# comment\nroot:x:0:0:root:/root:/bin/bash\nmcp-siem:x:901:901::/nonexistent:/usr/sbin/nologin\nbroken:x:abc\n";
        let u = lookup_user_in_passwd(passwd, "mcp-siem").unwrap();
        assert_eq!((u.uid, u.gid), (901, 901));
        assert_eq!(u.home, Path::new("/nonexistent"));
        assert!(lookup_user_in_passwd(passwd, "broken").is_none());
        assert!(lookup_user_in_passwd(passwd, "nobody").is_none());
        // Real system: root exists on any Linux box running the tests.
        if let Ok(Some(root)) = lookup_system_user("root") {
            assert_eq!(root.uid, 0);
        }
    }

    #[test]
    fn serializes_back() {
        let f = McpConfigFile::parse(COPILOT).unwrap();
        let text = serde_json::to_string(&f).unwrap();
        let again = McpConfigFile::parse(&text).unwrap();
        assert_eq!(f, again);
        assert!(text.contains("\"runAs\":\"mcp-mysql\""));
    }
}
