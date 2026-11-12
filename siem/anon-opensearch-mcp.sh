#!/usr/bin/env bash
# Anonymizing OpenSearch MCP proxy for Talon
#
# Wraps opensearch-mcp.sh and anonymizes tool results before they reach the
# model. Sensitive field values are replaced with consistent tokens
# (USER_1, HOST_1, IP_INT_1, EMAIL_1, DOMAIN_INT_1, SID_1, MAC_1). A built-in
# `deanonymize` tool reverses the substitution for report writing.
#
# Implementation: the Rust proxy `talon-anon-proxy` (crates/talon-anon). If
# the binary is not available the server refuses to start: SIEM data is never
# served without anonymization.
#
# Field definitions live in anon_proxy/fields.yaml — git pull to get updates.
#
# Token map (holds the real values; written atomically with mode 0600):
#   $TALON_ANON_MAP                      if set
#   $HOME/session_tokens.json            default (in the container HOME is the
#                                        server's private tmpfs /run/talon/home/<server>)
#   /workspace/group/session_tokens.json dev-mode fallback when $HOME is not writable
#
# Environment overrides:
#   TALON_ANON_PROXY_BIN   path to the talon-anon-proxy binary
#   TALON_ANON_FIELDS      field definitions (default: anon_proxy/fields.yaml)
#   TALON_ANON_MAP         token map file
#   TALON_ANON_LOG         log filter for the Rust proxy (stderr), e.g. "debug"
#
# This script is the MCP server command. Do not run it directly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
UPSTREAM="$SCRIPT_DIR/opensearch-mcp.sh"
FIELDS="${TALON_ANON_FIELDS:-$SCRIPT_DIR/anon_proxy/fields.yaml}"

# Check if a binary is native to the current OS (handles macOS venv in Linux container)
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

# ── Rust proxy ────────────────────────────────────────────────────────────

_find_rust_proxy() {
    local candidates=()
    [[ -n "${TALON_ANON_PROXY_BIN:-}" ]] && candidates+=("$TALON_ANON_PROXY_BIN")
    local on_path
    on_path="$(command -v talon-anon-proxy 2>/dev/null || true)"
    [[ -n "$on_path" ]] && candidates+=("$on_path")
    candidates+=(
        "/usr/local/bin/talon-anon-proxy"
        "$REPO_DIR/target/release/talon-anon-proxy"
        "$REPO_DIR/target/debug/talon-anon-proxy"
    )
    local c
    for c in "${candidates[@]}"; do
        if _is_native_exec "$c"; then
            printf '%s\n' "$c"
            return 0
        fi
    done
    return 1
}

_token_map_path() {
    if [[ -n "${TALON_ANON_MAP:-}" ]]; then
        printf '%s\n' "$TALON_ANON_MAP"
    elif [[ -n "${HOME:-}" && -d "$HOME" && -w "$HOME" ]]; then
        printf '%s\n' "$HOME/session_tokens.json"
    elif [[ -d /workspace/group && -w /workspace/group ]]; then
        printf '%s\n' "/workspace/group/session_tokens.json"
    else
        # Last resort: a private per-user directory (the proxy creates it 0700).
        printf '%s\n' "${TMPDIR:-/tmp}/talon-anon-$(id -u)/session_tokens.json"
    fi
}

if RUST_PROXY="$(_find_rust_proxy)"; then
    MAP="$(_token_map_path)"
    args=(--map "$MAP")
    # Without a readable fields file the proxy uses the copy embedded at build time.
    [[ -r "$FIELDS" ]] && args=(--fields "$FIELDS" "${args[@]}")
    exec "$RUST_PROXY" "${args[@]}" -- "$UPSTREAM"
fi

echo "[anon-opensearch-mcp] ERROR: talon-anon-proxy not found; refusing to serve SIEM data without it." >&2
echo "[anon-opensearch-mcp]   Tried: \$TALON_ANON_PROXY_BIN, PATH, /usr/local/bin, $REPO_DIR/target/{release,debug}" >&2
echo "[anon-opensearch-mcp]   In a container: rebuild the image (container/build.sh)" >&2
echo "[anon-opensearch-mcp]   On the host: cargo build --release -p talahon-anon" >&2
exit 1
