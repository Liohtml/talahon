#!/bin/bash -p
# talon-entrypoint — agent container entrypoint (docs/RUST_ARCHITECTURE.md §3.3).
#
# Installed as /usr/local/bin/talon-entrypoint. The host starts the container
# as root with --cap-drop=ALL plus CHOWN,SETUID,SETGID,FOWNER,DAC_OVERRIDE,KILL,
# no-new-privileges and a read-only root filesystem. As root this script:
#
#   1. validates RUN_UID / RUN_GID (numeric, never 0, never an mcp-* id),
#   2. remaps the `agent` user to RUN_UID/RUN_GID when /etc/passwd is
#      writable (under --read-only the supervisor uses the numeric ids),
#   3. hands the agent its tmpfs home (/home/agent, 0700),
#   4. copies every staged secret /etc/mcp-staging/<id>.<file> (root-only
#      host bind mounts) to /etc/mcp-secrets/<id>.<file>, owner mcp-<id>,
#      mode 0600 — only that MCP's user can read it,
#   4b. hands MemPalace data (/workspace/extra/mempalace-data) to
#      mcp-palace, top directory 0700, nothing group/world accessible, so
#      the agent can neither read nor plant files there (e.g. a malicious
#      ChromaDB index_metadata.pickle — MYTH-01). Symlinks are never
#      followed; a writable mount that cannot be secured is fatal,
#   5. execs `talon-agent supervise`, which reads the ContainerInput from
#      stdin, runs each MCP server as its mcp-* user and the agent as `agent`.
#
# Not root (dev / degraded mode): exec `talon-agent run` directly.
#
# This script never reads stdin (the supervisor does) and never writes to
# stdout (stdout carries the output frames); diagnostics go to stderr.
#
# `bash -p`: BASH_ENV/ENV are not sourced and exported functions,
# SHELLOPTS/BASHOPTS/CDPATH/GLOBIGNORE from the environment are ignored.

set -euo pipefail
umask 077
ulimit -c 0 2>/dev/null || true   # no core dumps that could contain secrets

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Defence in depth: the host already refuses these in the env overlay.
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT BASH_ENV ENV CDPATH GLOBIGNORE \
      PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONUSERBASE \
      PERL5LIB PERL5OPT RUBYOPT NODE_OPTIONS GLIBC_TUNABLES 2>/dev/null || true

readonly AGENT_BIN=/usr/local/bin/talon-agent
readonly STAGING_DIR=/etc/mcp-staging
readonly SECRETS_DIR=/etc/mcp-secrets
readonly PALACE_DATA=/workspace/extra/mempalace-data
readonly PALACE_USER=mcp-palace
readonly MAX_ID=4294967294

log() { printf 'talon-entrypoint: %s\n' "$*" >&2; }
die() {
    log "FATAL: $*"
    exit 70
}

if [ "$(id -u)" != "0" ]; then
    exec "$AGENT_BIN" run
fi

# --- 1. RUN_UID / RUN_GID ----------------------------------------------------
normalize_id() {
    # $1 = name, $2 = value; prints the decimal value or dies.
    case "$2" in
        '' | *[!0-9]*) die "$1 must be a non-negative integer (got '${2}')" ;;
    esac
    [ "${#2}" -le 10 ] || die "$1 out of range"
    local v=$((10#$2))
    [ "$v" -le "$MAX_ID" ] || die "$1 out of range"
    [ "$v" -ne 0 ] || die "$1=0 refused: the agent never runs as root"
    printf '%s' "$v"
}

agent_uid=$(id -u agent) || die "image has no 'agent' user"
agent_gid=$(id -g agent) || die "image has no 'agent' group"
RUN_UID=$(normalize_id RUN_UID "${RUN_UID:-$agent_uid}")
RUN_GID=$(normalize_id RUN_GID "${RUN_GID:-$agent_gid}")

# An agent sharing an MCP account's uid/gid could read that MCP's secrets.
while IFS=: read -r name _ uid gid _; do
    case "$name" in
        mcp-*)
            [ "$uid" != "$RUN_UID" ] || die "RUN_UID $RUN_UID collides with $name"
            [ "$gid" != "$RUN_GID" ] || die "RUN_GID $RUN_GID collides with $name"
            ;;
    esac
done </etc/passwd
while IFS=: read -r name _ gid _; do
    case "$name" in
        mcp-*) [ "$gid" != "$RUN_GID" ] || die "RUN_GID $RUN_GID collides with group $name" ;;
    esac
done </etc/group

# --- 2. remap `agent` ----------------------------------------------------------
if [ "$RUN_UID" != "$agent_uid" ] || [ "$RUN_GID" != "$agent_gid" ]; then
    if [ -w /etc/passwd ] && [ -w /etc/group ]; then
        groupmod -o -g "$RUN_GID" agent || log "groupmod failed; continuing with numeric ids"
        usermod -o -u "$RUN_UID" -g "$RUN_GID" agent 2>/dev/null ||
            log "usermod failed; continuing with numeric ids"
    else
        log "read-only root filesystem: agent runs as ${RUN_UID}:${RUN_GID} without a passwd remap"
    fi
fi

# --- 3. agent home (tmpfs; /home/agent/.talon is the host sessions mount) ---
if [ -d /home/agent ]; then
    chown "$RUN_UID:$RUN_GID" /home/agent 2>/dev/null || log "cannot chown /home/agent"
    chmod 0700 /home/agent 2>/dev/null || true
fi

# --- 4. per-MCP secrets ----------------------------------------------------------
if [ -d "$STAGING_DIR" ]; then
    if [ ! -d "$SECRETS_DIR" ]; then
        install -d -m 0711 -o root -g root "$SECRETS_DIR" ||
            die "$SECRETS_DIR missing and cannot be created"
    fi
    chown root:root "$SECRETS_DIR"
    chmod 0711 "$SECRETS_DIR"
    for staged in "$STAGING_DIR"/*; do
        [ -e "$staged" ] || continue
        base=${staged##*/}
        mcp_id=${base%%.*}
        case "$mcp_id" in
            '' | *[!a-z0-9_-]*)
                log "skipping staged file with an invalid MCP id: $base"
                continue
                ;;
        esac
        if [ "${#mcp_id}" -gt 32 ]; then
            log "skipping staged file with an over-long MCP id: $base"
            continue
        fi
        user="mcp-$mcp_id"
        if ! id -u "$user" >/dev/null 2>&1; then
            log "no account $user in the image; $base not staged"
            continue
        fi
        if [ -L "$staged" ] || [ ! -f "$staged" ]; then
            log "staged secret $base is not a regular file; skipped"
            continue
        fi
        dst="$SECRETS_DIR/$base"
        rm -f -- "$dst"
        install -m 0600 -o "$user" -g "$user" -- "$staged" "$dst" ||
            die "failed to stage $base for $user"
    done
fi

# --- 4b. MemPalace data: mcp-palace only ------------------------------------------
# Runs as root BEFORE privileges are dropped. The host only mounts the palace
# data at this exact path (talon-container refuses other names / overlaps).
secure_palace_data() {
    local dir=$PALACE_DATA puid pgid state hardlinked
    if [ -L "$dir" ]; then
        die "$dir is a symlink; refusing to start"
    fi
    [ -d "$dir" ] || return 0
    puid=$(id -u "$PALACE_USER") || die "image has no $PALACE_USER user"
    pgid=$(id -g "$PALACE_USER") || die "image has no $PALACE_USER group"
    case "$puid:$pgid" in
        0:* | *:0) die "$PALACE_USER must not be root" ;;
    esac
    if [ ! -w "$dir" ]; then
        # access(2) reports EROFS even for root: a read-only mount cannot be
        # planted into, and cannot be re-owned either.
        log "$dir is mounted read-only; leaving ownership unchanged"
        return 0
    fi
    # Files with several hard links may be inodes shared with other host
    # files: never re-own or re-mode them (and the 0700 top directory keeps
    # the agent away from them anyway).
    # (`|| true`: `head` closing the pipe early is not an error.)
    hardlinked=$(find -P "$dir" -xdev -type f -links +1 -print 2>/dev/null | head -n 5 | tr '\n' ' ') || true
    if [ -n "$hardlinked" ]; then
        log "palace data contains hard-linked files (left untouched): $hardlinked"
    fi
    # -P: never follow symlinks; -xdev: stay on the mounted filesystem;
    # chown -h: change a symlink itself, never its target; chmod skips
    # symlinks entirely (it would follow them).
    if ! find -P "$dir" -xdev ! \( -type f -links +1 \) \
        -exec chown -h -- "$puid:$pgid" {} + 2>/dev/null; then
        die "cannot give $dir to $PALACE_USER"
    fi
    if ! find -P "$dir" -xdev ! -type l ! \( -type f -links +1 \) \
        -exec chmod u+rwX,go-rwx -- {} + 2>/dev/null; then
        die "cannot restrict permissions under $dir"
    fi
    chmod 0700 -- "$dir" || die "cannot chmod $dir"
    state=$(stat -c '%u:%g:%a' -- "$dir") || die "cannot stat $dir"
    [ "$state" = "$puid:$pgid:700" ] ||
        die "$dir is $state after securing it (expected $puid:$pgid:700)"
}
secure_palace_data

# --- 5. hand over to the supervisor ---------------------------------------------
install -d -m 0755 -o root -g root /run/talon 2>/dev/null || true
export RUN_UID RUN_GID
exec "$AGENT_BIN" supervise
