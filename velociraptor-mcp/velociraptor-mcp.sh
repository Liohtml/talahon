#!/usr/bin/env bash
# Velociraptor MCP server wrapper for Talon.
#
# Velociraptor uses mTLS for gRPC — api.config.yaml IS the client certificate
# and key. Both .env (which references the cert path) and api.config.yaml are
# protected by the per-MCP isolation.
#
# Execution model (docs/RUST_ARCHITECTURE.md §3.3 — no sudo anywhere):
#
#   1. Talon agent container. `talon-agent supervise` starts this script
#      directly as `mcp-velociraptor` (`"runAs": "mcp-velociraptor"` in
#      .mcp.json). The entrypoint staged
#        /etc/mcp-secrets/velociraptor.env              (owner mcp-velociraptor, 0600)
#        /etc/mcp-secrets/velociraptor.api.config.yaml  (owner mcp-velociraptor, 0600)
#      and the visible copies are shadowed with /dev/null. VELOCIRAPTOR_API_KEY
#      is forced to the isolated cert path whatever the .env says.
#
#   2. Dev / host. Source velociraptor-mcp/.env and resolve a relative
#      VELOCIRAPTOR_API_KEY against this directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd /
export PYTHONSAFEPATH=1

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/velociraptor-mcp-server"
SYSTEM_MCP="/opt/velociraptor-mcp/bin/velociraptor-mcp-server"
ISOLATED_ENV="/etc/mcp-secrets/velociraptor.env"
ISOLATED_CERT="/etc/mcp-secrets/velociraptor.api.config.yaml"
TAG="[velociraptor-mcp]"

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

# === Container: isolated mcp-velociraptor account ===
if [[ -e "$ISOLATED_ENV" || -e "$ISOLATED_CERT" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
        _err "refusing to run as root; the supervisor must start this server as mcp-velociraptor"
        exit 1
    fi
    for f in "$ISOLATED_ENV" "$ISOLATED_CERT"; do
        if [[ ! -e "$f" ]]; then
            _err "$f was not staged (copy it into velociraptor-mcp/ on the host)"
            exit 1
        fi
        if [[ ! -r "$f" ]]; then
            _err "$f is not readable by uid $(id -u); set \"runAs\": \"mcp-velociraptor\" in .mcp.json"
            exit 1
        fi
    done
    _load_env "$ISOLATED_ENV"
    # The original cert location is shadowed: always use the isolated copy.
    export VELOCIRAPTOR_API_KEY="$ISOLATED_CERT"
    if [[ ! -x "$SYSTEM_MCP" ]]; then
        _err "velociraptor-mcp-server is not installed in the image (rebuild: container/build.sh)"
        exit 1
    fi
    exec "$SYSTEM_MCP"
fi

# === Dev / host: local .env ===
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    _load_env "$SCRIPT_DIR/.env"
else
    _err ".env not found at $SCRIPT_DIR/.env"
    _err "Run setup.sh first and fill in your Velociraptor credentials."
    exit 1
fi

# Resolve a relative VELOCIRAPTOR_API_KEY so the same .env works on the
# macOS host and in Linux containers.
if [[ "${VELOCIRAPTOR_API_KEY:-}" != /* ]]; then
    export VELOCIRAPTOR_API_KEY="$SCRIPT_DIR/${VELOCIRAPTOR_API_KEY:-api.config.yaml}"
fi
if [[ ! -f "$VELOCIRAPTOR_API_KEY" ]]; then
    _err "api.config.yaml not found at $VELOCIRAPTOR_API_KEY"
    _err "Copy your Velociraptor api.config.yaml into the velociraptor-mcp/ directory."
    exit 1
fi

if _is_native_exec "$LOCAL_MCP"; then
    exec "$LOCAL_MCP"
elif [[ -x "$SYSTEM_MCP" ]]; then
    exec "$SYSTEM_MCP"
else
    _err "velociraptor-mcp-server not found."
    _err "  In a container: rebuild the image (container/build.sh)"
    _err "  On the host: run velociraptor-mcp/setup.sh"
    exit 1
fi
