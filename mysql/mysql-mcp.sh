#!/usr/bin/env bash
# MySQL MCP server wrapper for Talahon.
#
# Execution model (docs/RUST_ARCHITECTURE.md §3.3 — no sudo anywhere):
#
#   1. Talahon agent container. `talahon-agent supervise` starts this script
#      directly as `mcp-mysql` (`"runAs": "mcp-mysql"` in .mcp.json). The
#      credentials were staged at /etc/mcp-secrets/mysql.env (owner mcp-mysql,
#      mode 0600); the visible mysql/.env is shadowed with /dev/null. The
#      image ships the Python `mysql_mcp_server` (/opt/mysql-mcp).
#
#   2. Dev / host. Source mysql/.env next to this script; prefer a local
#      venv, then the image install.
#
# .env keys: MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASS (or
# MYSQL_PASSWORD), MYSQL_DB (or MYSQL_DATABASE). Both spellings are
# accepted and exported.
#
# Server implementation:
#
#   default                the Python `mysql-mcp-server` (PyPI)
#   TALAHON_MYSQL_MCP=rust   the native `talahon-mysql-mcp` binary
#                          (crates/talon-mcp-mysql): same tools, arguments
#                          and result text, no Python cold start, bounded
#                          statements (timeouts, row and byte limits).
#                          Opt-in; set it in the env file loaded below or in
#                          the server's environment. Looked up in
#                          /usr/local/bin, then PATH, and in dev mode also in
#                          the repo's target/{release,debug}. If the binary
#                          is missing the Python server is used.
#
# Started by the agent runtime as an MCP server command; not for direct use.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# Never let an (agent-writable) working directory shadow Python modules.
cd /
export PYTHONSAFEPATH=1

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/mysql_mcp_server"
SYSTEM_MCP="/opt/mysql-mcp/bin/mysql_mcp_server"
ISOLATED_ENV="/etc/mcp-secrets/mysql.env"
NATIVE_NAME="talahon-mysql-mcp"
# The binary's name up to 2.x (an image built before the rename has only this).
LEGACY_NATIVE_NAME="talon-mysql-mcp"
TAG="[mysql-mcp]"

_err() { echo "$TAG ERROR: $*" >&2; }
_warn() { echo "$TAG WARNING: $*" >&2; }

_load_env() {
    set -a
    # shellcheck source=/dev/null
    source "$1"
    set +a
    # Accept both spellings of the password and database keys.
    if [[ -n "${MYSQL_PASS:-}" && -z "${MYSQL_PASSWORD:-}" ]]; then export MYSQL_PASSWORD="$MYSQL_PASS"; fi
    if [[ -n "${MYSQL_PASSWORD:-}" && -z "${MYSQL_PASS:-}" ]]; then export MYSQL_PASS="$MYSQL_PASSWORD"; fi
    if [[ -n "${MYSQL_DB:-}" && -z "${MYSQL_DATABASE:-}" ]]; then export MYSQL_DATABASE="$MYSQL_DB"; fi
    if [[ -n "${MYSQL_DATABASE:-}" && -z "${MYSQL_DB:-}" ]]; then export MYSQL_DB="$MYSQL_DATABASE"; fi
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

# Exec the native Rust server if it was asked for (TALAHON_MYSQL_MCP=rust, from
# the env file just loaded or the environment) and a binary exists. Extra
# arguments are further directories to search (dev mode only). Returns when
# the Python server should be used.
_maybe_exec_native() {
    # TALON_MYSQL_MCP is the pre-rename spelling: still read, the new name wins.
    local choice="${TALAHON_MYSQL_MCP:-${TALON_MYSQL_MCP:-}}"
    [[ "$choice" == "rust" ]] || return 0
    if [[ -z "${TALAHON_MYSQL_MCP:-}" ]]; then
        _warn "TALON_MYSQL_MCP is deprecated; rename it to TALAHON_MYSQL_MCP"
    fi
    local candidates=() name on_path dir
    # Every place under the current name first, then under the old one.
    for name in "$NATIVE_NAME" "$LEGACY_NATIVE_NAME"; do
        candidates+=("/usr/local/bin/$name")
        on_path="$(command -v "$name" 2>/dev/null || true)"
        [[ -n "$on_path" ]] && candidates+=("$on_path")
        for dir in "$@"; do
            candidates+=("$dir/$name")
        done
    done
    local c
    for c in "${candidates[@]}"; do
        if _is_native_exec "$c"; then
            exec "$c"
        fi
    done
    _warn "TALAHON_MYSQL_MCP=rust but $NATIVE_NAME was not found; using the Python server"
    return 0
}

# === Container: isolated mcp-mysql account ===
if [[ -e "$ISOLATED_ENV" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
        _err "refusing to run as root; the supervisor must start this server as mcp-mysql"
        exit 1
    fi
    if [[ ! -r "$ISOLATED_ENV" ]]; then
        _err "$ISOLATED_ENV is not readable by uid $(id -u); set \"runAs\": \"mcp-mysql\" in .mcp.json"
        exit 1
    fi
    _load_env "$ISOLATED_ENV"
    _maybe_exec_native
    if [[ ! -x "$SYSTEM_MCP" ]]; then
        _err "mysql_mcp_server is not installed in the image (rebuild: container/build.sh)"
        exit 1
    fi
    exec "$SYSTEM_MCP"
fi

# === Dev / host: local .env ===
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    _load_env "$SCRIPT_DIR/.env"
else
    _err ".env not found at $SCRIPT_DIR/.env"
    _err "Run setup.sh first and fill in your MySQL credentials."
    exit 1
fi

_maybe_exec_native "$REPO_DIR/target/release" "$REPO_DIR/target/debug"

if _is_native_exec "$LOCAL_MCP"; then
    exec "$LOCAL_MCP"
elif [[ -x "$SYSTEM_MCP" ]]; then
    exec "$SYSTEM_MCP"
else
    _err "no MySQL MCP server found."
    _err "  In a container: rebuild the image (container/build.sh)"
    _err "  On the host: python3 -m venv $SCRIPT_DIR/.venv && $SCRIPT_DIR/.venv/bin/pip install mysql-mcp-server"
    exit 1
fi
