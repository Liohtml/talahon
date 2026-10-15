#!/usr/bin/env bash
# Shuffle MCP server wrapper for Talon.
#
# Execution model (docs/RUST_ARCHITECTURE.md §3.3 — no sudo anywhere):
#
#   1. Talon agent container. `talon-agent supervise` starts this script
#      directly as `mcp-shuffle` (`"runAs": "mcp-shuffle"` in .mcp.json). The
#      credentials were staged at /etc/mcp-secrets/shuffle.env (owner
#      mcp-shuffle, mode 0600); the visible shuffle-mcp/.env is shadowed with
#      /dev/null. Only the image's system install is executed here.
#
#   2. Dev / host. Source shuffle-mcp/.env next to this script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd /
export PYTHONSAFEPATH=1

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/shuffle-mcp-server"
SYSTEM_MCP="/opt/shuffle-mcp/bin/shuffle-mcp-server"
ISOLATED_ENV="/etc/mcp-secrets/shuffle.env"
TAG="[shuffle-mcp]"

_err() { echo "$TAG ERROR: $*" >&2; }

_load_env() {
    set -a
    # shellcheck source=/dev/null
    source "$1"
    set +a
}

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

# === Container: isolated mcp-shuffle account ===
if [[ -e "$ISOLATED_ENV" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
        _err "refusing to run as root; the supervisor must start this server as mcp-shuffle"
        exit 1
    fi
    if [[ ! -r "$ISOLATED_ENV" ]]; then
        _err "$ISOLATED_ENV is not readable by uid $(id -u); set \"runAs\": \"mcp-shuffle\" in .mcp.json"
        exit 1
    fi
    _load_env "$ISOLATED_ENV"
    if [[ ! -x "$SYSTEM_MCP" ]]; then
        _err "shuffle-mcp-server is not installed in the image (rebuild: container/build.sh)"
        exit 1
    fi
    exec "$SYSTEM_MCP"
fi

# === Dev / host: local .env ===
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    _load_env "$SCRIPT_DIR/.env"
else
    _err ".env not found at $SCRIPT_DIR/.env"
    _err "Run setup.sh first and fill in your Shuffle credentials."
    exit 1
fi

if _is_native_exec "$LOCAL_MCP"; then
    exec "$LOCAL_MCP"
elif [[ -x "$SYSTEM_MCP" ]]; then
    exec "$SYSTEM_MCP"
else
    _err "shuffle-mcp-server not found."
    _err "  In a container: rebuild the image (container/build.sh)"
    _err "  On the host: run shuffle-mcp/setup.sh"
    exit 1
fi
