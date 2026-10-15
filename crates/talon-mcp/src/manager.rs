//! Starts every server of a `.mcp.json` concurrently and aggregates their
//! tools. One server failing (bad entry, spawn error, handshake timeout,
//! crash) never affects the others; failures are reported via
//! [`McpManager::failures`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use talon_core::tool::Tool;

use crate::adapter::{AdapterOptions, McpToolAdapter, ToolNameAllocator};
use crate::client::{ClientOptions, McpClient};
use crate::config::{McpConfigFile, ServerConfig, socket_path};
use crate::error::McpError;
use crate::process::SpawnOptions;
use crate::types::McpTool;

/// How servers are reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchMode {
    /// Spawn each server as a child process (dev / degraded mode).
    Spawn,
    /// Connect to `<dir>/<server>.sock` exposed by the privileged
    /// supervisor (`TALON_MCP_SOCKET_DIR`).
    UnixSockets {
        /// Socket directory.
        dir: PathBuf,
    },
}

/// Options for [`McpManager::start`].
#[derive(Debug, Clone)]
pub struct ManagerOptions {
    /// Spawn or connect.
    pub launch: LaunchMode,
    /// Client tunables (timeouts, limits).
    pub client: ClientOptions,
    /// Process options for [`LaunchMode::Spawn`].
    pub spawn: SpawnOptions,
    /// Adapter options (timeouts, output cap, post-processor).
    pub adapter: AdapterOptions,
    /// Budget per server for connect + initialize + tools/list
    /// (default 60 s).
    pub start_timeout: Duration,
    /// Tool names MCP tools must not take (the built-in tools).
    pub reserved_tool_names: Vec<String>,
}

impl Default for ManagerOptions {
    fn default() -> Self {
        Self {
            launch: LaunchMode::Spawn,
            client: ClientOptions::default(),
            spawn: SpawnOptions::default(),
            adapter: AdapterOptions::default(),
            start_timeout: Duration::from_secs(60),
            reserved_tool_names: Vec::new(),
        }
    }
}

impl ManagerOptions {
    /// Spawn mode when `socket_dir` is `None`, socket mode otherwise
    /// (convenience for `TALON_MCP_SOCKET_DIR`).
    pub fn with_socket_dir(mut self, socket_dir: Option<PathBuf>) -> Self {
        self.launch = match socket_dir {
            Some(dir) => LaunchMode::UnixSockets { dir },
            None => LaunchMode::Spawn,
        };
        self
    }
}

/// A server that started successfully.
#[derive(Debug, Clone)]
pub struct ConnectedServer {
    /// Server name.
    pub name: String,
    /// The live client.
    pub client: Arc<McpClient>,
    /// Tools as listed by the server.
    pub tools: Vec<McpTool>,
    tools_generation: u64,
}

/// A server that could not be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFailure {
    /// Server name.
    pub name: String,
    /// Error description (may contain server-provided text).
    pub error: String,
}

/// Per-server status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatus {
    /// Server name.
    pub name: String,
    /// Connected and not closed.
    pub connected: bool,
    /// Number of tools exposed.
    pub tool_count: usize,
    /// Failure / close reason.
    pub error: Option<String>,
}

/// All MCP servers of one agent run.
#[derive(Debug)]
pub struct McpManager {
    servers: Vec<ConnectedServer>,
    failures: Vec<ServerFailure>,
    adapters: Vec<Arc<McpToolAdapter>>,
    options: ManagerOptions,
}

impl McpManager {
    /// Start (or connect to) every valid server in `config` concurrently.
    /// Never fails as a whole: per-server problems end up in
    /// [`Self::failures`] (including entries the parser rejected).
    pub async fn start(config: &McpConfigFile, options: ManagerOptions) -> Self {
        let mut failures: Vec<ServerFailure> = config
            .invalid
            .iter()
            .map(|(name, error)| ServerFailure {
                name: name.clone(),
                error: error.clone(),
            })
            .collect();
        let starts = config.servers().map(|(name, cfg)| {
            let options = &options;
            async move { (name.to_string(), start_one(name, cfg, options).await) }
        });
        let mut servers = Vec::new();
        for (name, result) in join_all(starts).await {
            match result {
                Ok((client, tools)) => {
                    tracing::info!(server = %name, tools = tools.len(), "MCP server ready");
                    let tools_generation = client.tools_generation();
                    servers.push(ConnectedServer {
                        name,
                        client,
                        tools,
                        tools_generation,
                    });
                }
                Err(e) => {
                    tracing::warn!(server = %name, error = %e, "MCP server failed to start");
                    failures.push(ServerFailure {
                        name,
                        error: e.to_string(),
                    });
                }
            }
        }
        failures.sort_by(|a, b| a.name.cmp(&b.name));
        let mut manager = Self {
            servers,
            failures,
            adapters: Vec::new(),
            options,
        };
        manager.rebuild_adapters();
        manager
    }

    fn rebuild_adapters(&mut self) {
        let mut allocator = ToolNameAllocator::new();
        for name in &self.options.reserved_tool_names {
            allocator.reserve(name);
        }
        self.adapters = self
            .servers
            .iter()
            .flat_map(|s| {
                McpToolAdapter::wrap_all(&s.client, &s.tools, &mut allocator, &self.options.adapter)
            })
            .collect();
    }

    /// All MCP tools as `Arc<dyn Tool>` (deterministic order: server name,
    /// then the server's tool order).
    pub fn tools(&self) -> Vec<Arc<dyn Tool>> {
        self.adapters
            .iter()
            .map(|a| Arc::clone(a) as Arc<dyn Tool>)
            .collect()
    }

    /// The adapters (with server/tool metadata).
    pub fn adapters(&self) -> &[Arc<McpToolAdapter>] {
        &self.adapters
    }

    /// Successfully started servers.
    pub fn servers(&self) -> &[ConnectedServer] {
        &self.servers
    }

    /// Servers that failed to start (sorted by name).
    pub fn failures(&self) -> &[ServerFailure] {
        &self.failures
    }

    /// The client of a started server.
    pub fn client(&self, name: &str) -> Option<&Arc<McpClient>> {
        self.servers
            .iter()
            .find(|s| s.name == name)
            .map(|s| &s.client)
    }

    /// `(server, instructions)` for servers that sent instructions
    /// (untrusted text — fence before showing it to the model).
    pub fn instructions(&self) -> Vec<(String, String)> {
        self.servers
            .iter()
            .filter_map(|s| {
                s.client
                    .instructions()
                    .map(|i| (s.name.clone(), i.to_string()))
            })
            .collect()
    }

    /// Status of every configured server, sorted by name.
    pub fn statuses(&self) -> Vec<ServerStatus> {
        let mut out: Vec<ServerStatus> = self
            .servers
            .iter()
            .map(|s| {
                let closed = s.client.closed_reason();
                ServerStatus {
                    name: s.name.clone(),
                    connected: closed.is_none(),
                    tool_count: s.tools.len(),
                    error: closed,
                }
            })
            .chain(self.failures.iter().map(|f| ServerStatus {
                name: f.name.clone(),
                connected: false,
                tool_count: 0,
                error: Some(f.error.clone()),
            }))
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Re-list tools of servers that sent `notifications/tools/list_changed`
    /// since the last listing and rebuild the adapters. Returns true if
    /// anything was re-listed. A failing re-list keeps the old tools.
    pub async fn refresh_tools(&mut self) -> bool {
        let stale: Vec<usize> = self
            .servers
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                !s.client.is_closed() && s.client.tools_generation() != s.tools_generation
            })
            .map(|(i, _)| i)
            .collect();
        if stale.is_empty() {
            return false;
        }
        let relists = stale.iter().map(|&i| {
            let client = Arc::clone(&self.servers[i].client);
            async move {
                let generation = client.tools_generation();
                (i, generation, client.list_tools().await)
            }
        });
        let mut changed = false;
        for (i, generation, result) in join_all(relists).await {
            let server = &mut self.servers[i];
            match result {
                Ok(tools) => {
                    tracing::info!(server = %server.name, tools = tools.len(), "MCP tool list refreshed");
                    server.tools = tools;
                    server.tools_generation = generation;
                    changed = true;
                }
                Err(e) => {
                    tracing::warn!(server = %server.name, error = %e, "MCP tool list refresh failed");
                }
            }
        }
        if changed {
            self.rebuild_adapters();
        }
        changed
    }

    /// Gracefully shut down every server concurrently.
    pub async fn shutdown_all(&self) {
        join_all(self.servers.iter().map(|s| s.client.shutdown())).await;
    }
}

async fn start_one(
    name: &str,
    cfg: &ServerConfig,
    options: &ManagerOptions,
) -> Result<(Arc<McpClient>, Vec<McpTool>), McpError> {
    let connect_and_list = async {
        let client = match &options.launch {
            LaunchMode::Spawn => {
                cfg.validate_for_spawn(name)?;
                McpClient::spawn_with(name, cfg, &options.spawn, options.client.clone()).await?
            }
            LaunchMode::UnixSockets { dir } => {
                let path = socket_path(dir, name)?;
                connect_socket(name, &path, options.client.clone()).await?
            }
        };
        // On any error below the client is dropped, killing the process.
        client.initialize().await?;
        let tools = client.list_tools().await?;
        Ok::<_, McpError>((Arc::new(client), tools))
    };
    match tokio::time::timeout(options.start_timeout, connect_and_list).await {
        Ok(result) => result,
        Err(_) => Err(McpError::Timeout {
            server: name.to_string(),
            method: "startup".to_string(),
            timeout: options.start_timeout,
        }),
    }
}

#[cfg(unix)]
async fn connect_socket(
    name: &str,
    path: &std::path::Path,
    options: ClientOptions,
) -> Result<McpClient, McpError> {
    McpClient::connect_unix(name, path, options).await
}

#[cfg(not(unix))]
async fn connect_socket(
    name: &str,
    _path: &std::path::Path,
    _options: ClientOptions,
) -> Result<McpClient, McpError> {
    Err(McpError::Config(format!(
        "server '{name}': unix sockets are not supported on this platform"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_dir_switches_mode() {
        let o = ManagerOptions::default().with_socket_dir(Some("/run/talon/mcp".into()));
        assert_eq!(
            o.launch,
            LaunchMode::UnixSockets {
                dir: "/run/talon/mcp".into()
            }
        );
        let o = o.with_socket_dir(None);
        assert_eq!(o.launch, LaunchMode::Spawn);
    }

    #[tokio::test]
    async fn empty_config_and_invalid_entries() {
        let cfg = McpConfigFile::parse(
            r#"{"mcpServers": {"bad": 5, "remote": {"type": "http", "url": "https://x"}, "bad name": {"command": "x"}}}"#,
        )
        .unwrap();
        let m = McpManager::start(&cfg, ManagerOptions::default()).await;
        assert!(m.tools().is_empty());
        assert!(m.servers().is_empty());
        let names: Vec<_> = m.failures().iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["bad", "bad name", "remote"]);
        let st = m.statuses();
        assert_eq!(st.len(), 3);
        assert!(st.iter().all(|s| !s.connected && s.error.is_some()));
        assert!(m.instructions().is_empty());
        m.shutdown_all().await;
    }

    #[tokio::test]
    async fn missing_binary_is_isolated() {
        let cfg = McpConfigFile::parse(
            r#"{"mcpServers": {"ghost": {"command": "/nonexistent/definitely-not-here"}}}"#,
        )
        .unwrap();
        let m = McpManager::start(&cfg, ManagerOptions::default()).await;
        assert_eq!(m.failures().len(), 1);
        assert!(
            m.failures()[0].error.contains("failed to start"),
            "{}",
            m.failures()[0].error
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_socket_is_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = McpConfigFile::parse(r#"{"mcpServers": {"siem": {"command": "x"}}}"#).unwrap();
        let opts = ManagerOptions::default().with_socket_dir(Some(dir.path().to_path_buf()));
        let m = McpManager::start(&cfg, opts).await;
        assert_eq!(m.failures().len(), 1);
        assert!(m.failures()[0].error.contains("failed to connect"));
    }
}
