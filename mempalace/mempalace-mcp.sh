#!/usr/bin/env bash
# MemPalace MCP server wrapper for Talon.
#
# Gives the SOC agent persistent semantic memory — past investigations, asset
# metadata, false-positive records and IOC history in a local ChromaDB +
# SQLite knowledge graph, retrieved by semantic search.
#
# Palace data lives in mempalace-data/palace/ (mounted read-write at
# /workspace/extra/mempalace-data; the account running this server must be
# able to write there).
#
# Execution model (docs/RUST_ARCHITECTURE.md §3.3 — no sudo anywhere):
#
#   1. Talon agent container. `talon-agent supervise` starts this script
#      directly as `mcp-palace` (`"runAs": "mcp-palace"` in .mcp.json). An
#      optional mempalace/.env is staged at /etc/mcp-secrets/palace.env
#      (owner mcp-palace, mode 0600).
#   2. Dev / host. Source mempalace/.env next to this script when present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd /
export PYTHONSAFEPATH=1

ISOLATED_ENV="/etc/mcp-secrets/palace.env"
TAG="[mempalace-mcp]"

_err() { echo "$TAG ERROR: $*" >&2; }

_load_env() {
    set -a
    # shellcheck source=/dev/null
    source "$1"
    set +a
}

# Check if a binary is native to the current OS (handles a macOS venv
# mounted into the Linux container).
_is_native_exec() {
    local bin="$1"
    [[ -x "$bin" ]] || return 1
    if [[ "$(uname -s)" == "Linux" ]]; then
        local magic
        magic=$(head -c 4 "$bin" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        [[ "$magic" == "7f454c46" ]] || return 1
    fi
    return 0
}

LOCAL_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
SYSTEM_PYTHON="/opt/mempalace/bin/python3"

if [[ -e "$ISOLATED_ENV" ]]; then
    # === Container: isolated mcp-palace account ===
    if [[ "$(id -u)" == "0" ]]; then
        _err "refusing to run as root; the supervisor must start this server as mcp-palace"
        exit 1
    fi
    if [[ ! -r "$ISOLATED_ENV" ]]; then
        _err "$ISOLATED_ENV is not readable by uid $(id -u); set \"runAs\": \"mcp-palace\" in .mcp.json"
        exit 1
    fi
    _load_env "$ISOLATED_ENV"
    PYTHON="$SYSTEM_PYTHON"
elif [[ -d /etc/mcp-secrets ]]; then
    # === Container without a palace .env: image install only ===
    PYTHON="$SYSTEM_PYTHON"
else
    # === Dev / host ===
    if [[ -f "$SCRIPT_DIR/.env" ]]; then
        _load_env "$SCRIPT_DIR/.env"
    fi
    if _is_native_exec "$LOCAL_PYTHON"; then
        PYTHON="$LOCAL_PYTHON"
    else
        PYTHON="$SYSTEM_PYTHON"
    fi
fi

if [[ ! -x "$PYTHON" ]]; then
    _err "python3 for mempalace not found ($PYTHON)."
    _err "  In a container: rebuild the image (container/build.sh)"
    _err "  On the host: run mempalace/setup.sh"
    exit 1
fi

# Palace data directory — persistent, read-write, outside the config dir.
#   Container: /workspace/extra/mempalace-data/palace
#   Host:      set MEMPALACE_PALACE_PATH (e.g. <project>/mempalace-data/palace)
PALACE_PATH="${MEMPALACE_PALACE_PATH:-/workspace/extra/mempalace-data/palace}"
export MEMPALACE_PALACE_PATH="$PALACE_PATH"

if ! mkdir -p "$PALACE_PATH" 2>/dev/null || [[ ! -w "$PALACE_PATH" ]]; then
    _err "palace directory $PALACE_PATH is not writable by uid $(id -u)."
    _err "  Make mempalace-data/ writable for the account running this server."
    exit 1
fi

# Auto-initialize the palace on first run: the MCP server opens the ChromaDB
# collection at import time without create=True, so it must exist first.
SENTINEL="$PALACE_PATH/.initialized"
if [[ ! -f "$SENTINEL" ]]; then
    echo "$TAG Initializing palace at $PALACE_PATH..." >&2
    "$PYTHON" - <<'PYEOF'
import sys
try:
    import chromadb
    from mempalace.palace_graph import MempalaceConfig
    from mempalace.knowledge_graph import KnowledgeGraph

    config = MempalaceConfig()
    client = chromadb.PersistentClient(path=config.palace_path)
    client.get_or_create_collection(config.collection_name)
    KnowledgeGraph()
    print(f"[mempalace-mcp] Palace initialized at {config.palace_path}", file=sys.stderr)
except Exception as e:
    # Non-fatal: the MCP server may still start and handle init errors itself.
    print(f"[mempalace-mcp] Warning: init returned: {e}", file=sys.stderr)
PYEOF
    touch "$SENTINEL"
fi

exec "$PYTHON" -m mempalace.mcp_server
