//! MCP integration for the agent: loading `.mcp.json`, connecting to the
//! supervisor's sockets (or spawning servers in dev mode), reserving the
//! built-in tool names and fencing every MCP result as untrusted data.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use talon_mcp::config::MAX_CONFIG_BYTES;
use talon_mcp::{ManagerOptions, McpConfigFile, McpManager, socket_path};

use crate::tools::fence_result;

/// Load `.mcp.json`. A missing, empty or unparseable file means "no
/// servers" (logged); invalid entries are kept in `invalid`.
pub fn load_mcp_config(path: &Path) -> McpConfigFile {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), error = %e, "cannot open MCP config; no MCP servers");
            }
            return McpConfigFile::default();
        }
    };
    let mut text = String::new();
    if let Err(e) = file.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut text) {
        tracing::warn!(path = %path.display(), error = %e, "cannot read MCP config; no MCP servers");
        return McpConfigFile::default();
    }
    if text.len() as u64 > MAX_CONFIG_BYTES {
        tracing::warn!(path = %path.display(), "MCP config too large; no MCP servers");
        return McpConfigFile::default();
    }
    if text.trim().is_empty() {
        return McpConfigFile::default();
    }
    match McpConfigFile::parse(&text) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "invalid MCP config; no MCP servers");
            McpConfigFile::default()
        }
    }
}

/// The started servers plus the names of servers that are unavailable.
pub struct McpSetup {
    /// Running manager (`None` when no server is configured).
    pub manager: Option<McpManager>,
    /// Servers that are configured but unusable this run.
    pub unavailable: Vec<String>,
}

impl std::fmt::Debug for McpSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpSetup")
            .field("running", &self.manager.as_ref().map(|m| m.servers().len()))
            .field("unavailable", &self.unavailable)
            .finish()
    }
}

/// Start (dev: spawn) or connect to (production: `socket_dir`) the servers
/// of `config`. `reserved` tool names (built-in and intel tools) can never
/// be taken by MCP tools. Every result is fenced as untrusted.
pub async fn start_mcp(
    mut config: McpConfigFile,
    socket_dir: Option<&Path>,
    reserved: Vec<String>,
) -> McpSetup {
    let mut unavailable: Vec<String> = config.invalid.keys().cloned().collect();
    if let Some(dir) = socket_dir {
        // Servers the supervisor refused have no socket.
        let refused: Vec<String> = config
            .mcp_servers
            .keys()
            .filter(|name| {
                socket_path(dir, name)
                    .map(|p| std::fs::symlink_metadata(p).is_err())
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        for name in &refused {
            tracing::warn!(server = %name, "no supervisor socket for MCP server (refused or failed to start)");
            config.mcp_servers.remove(name);
        }
        unavailable.extend(refused);
        config.invalid.clear();
    }
    if config.mcp_servers.is_empty() {
        unavailable.sort();
        unavailable.dedup();
        return McpSetup {
            manager: None,
            unavailable,
        };
    }
    let mut options = ManagerOptions::default().with_socket_dir(socket_dir.map(Path::to_path_buf));
    options.reserved_tool_names = reserved;
    options.adapter.post_processor = Some(Arc::new(|server: &str, tool: &str, text: String| {
        let _ = tool;
        fence_result(&format!("mcp:{server}"), &text)
    }));
    let manager = McpManager::start(&config, options).await;
    for failure in manager.failures() {
        tracing::warn!(server = %failure.name, error = %crate::logging::redact(&failure.error), "MCP server unavailable");
        unavailable.push(failure.name.clone());
    }
    tracing::info!(
        servers = manager.servers().len(),
        tools = manager.tools().len(),
        unavailable = unavailable.len(),
        "MCP ready"
    );
    unavailable.sort();
    unavailable.dedup();
    McpSetup {
        manager: Some(manager),
        unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_empty_and_invalid_configs_mean_no_servers() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".mcp.json");
        assert!(load_mcp_config(&p).is_empty());
        std::fs::write(&p, "").unwrap();
        assert!(load_mcp_config(&p).is_empty());
        std::fs::write(&p, "{ not json").unwrap();
        assert!(load_mcp_config(&p).is_empty());
        std::fs::write(&p, r#"{"mcpServers":{}}"#).unwrap();
        assert!(load_mcp_config(&p).is_empty());
        std::fs::write(
            &p,
            r#"{"mcpServers":{"siem":{"command":"/x","runAs":"mcp-siem"},"bad":7}}"#,
        )
        .unwrap();
        let c = load_mcp_config(&p);
        assert_eq!(c.len(), 1);
        assert!(c.invalid.contains_key("bad"));
    }

    #[tokio::test]
    async fn socket_mode_skips_servers_without_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let cfg =
            McpConfigFile::parse(r#"{"mcpServers":{"siem":{"command":"/x"},"bad":7}}"#).unwrap();
        let setup = start_mcp(cfg, Some(dir.path()), vec!["bash".into()]).await;
        assert!(setup.manager.is_none());
        assert_eq!(
            setup.unavailable,
            vec!["bad".to_string(), "siem".to_string()]
        );
        assert!(format!("{setup:?}").contains("siem"));
    }

    #[tokio::test]
    async fn spawn_mode_reports_failures() {
        let cfg = McpConfigFile::parse(
            r#"{"mcpServers":{"ghost":{"command":"/nonexistent/talon-test-binary"}}}"#,
        )
        .unwrap();
        let setup = start_mcp(cfg, None, vec![]).await;
        let manager = setup.manager.unwrap();
        assert!(manager.tools().is_empty());
        assert_eq!(setup.unavailable, vec!["ghost".to_string()]);
        manager.shutdown_all().await;
    }
}
