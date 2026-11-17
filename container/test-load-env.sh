#!/usr/bin/env bash
# Checks `_load_env` of every MCP wrapper: values are read literally (a `$`,
# a backtick or a `;` is data, nothing is executed) with the same rules as
# talon_core::env::parse_env. Run from anywhere; exits non-zero on a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/.env" <<'ENV'
# a comment
PLAIN=abc
DOLLAR=pa$$w0rd$HOME
BACKTICK=a`touch INJECTED`b
SUBSHELL=$(touch INJECTED)
SEMI=a;touch INJECTED
export EXPORTED="two words"
SINGLE='x $y' # trailing comment
DOUBLE="a # b"   # comment
INLINE=131072	# tokens
HASH=abc#123
SPACED = padded  
EMPTY=
ENV
printf 'CRLF=dos\r\nLAST=no-newline' >> "$TMP/.env"

fail=0
check() { # name expected actual
    if [[ "$2" != "$3" ]]; then
        echo "FAIL $wrapper: $1: expected [$2], got [$3]" >&2
        fail=1
    fi
}

count=0
for wrapper in "$ROOT"/*/*-mcp.sh; do
    body="$(sed -n '/^_load_env() {$/,/^}$/p' "$wrapper")"
    [[ -n "$body" ]] || continue
    count=$((count + 1))
    if grep -qE '^\s*(source|\.)\s' <<<"$body"; then
        echo "FAIL $wrapper: _load_env sources the file" >&2
        fail=1
        continue
    fi
    out="$(cd "$TMP" && env -i HOME=/home/x bash -c "set -euo pipefail
$body
_load_env '$TMP/.env'
for k in PLAIN DOLLAR BACKTICK SUBSHELL SEMI EXPORTED SINGLE DOUBLE INLINE HASH SPACED EMPTY CRLF LAST; do
    printf '%s=[%s]\n' \"\$k\" \"\${!k-UNSET}\"
done")"
    get() { sed -n "s/^$1=\[\(.*\)\]$/\1/p" <<<"$out"; }
    check PLAIN 'abc' "$(get PLAIN)"
    check DOLLAR 'pa$$w0rd$HOME' "$(get DOLLAR)"
    check BACKTICK 'a`touch INJECTED`b' "$(get BACKTICK)"
    check SUBSHELL '$(touch INJECTED)' "$(get SUBSHELL)"
    check SEMI 'a;touch INJECTED' "$(get SEMI)"
    check EXPORTED 'two words' "$(get EXPORTED)"
    check SINGLE 'x $y' "$(get SINGLE)"
    check DOUBLE 'a # b' "$(get DOUBLE)"
    check INLINE '131072' "$(get INLINE)"
    check HASH 'abc#123' "$(get HASH)"
    check SPACED 'padded' "$(get SPACED)"
    check EMPTY '' "$(get EMPTY)"
    check CRLF 'dos' "$(get CRLF)"
    check LAST 'no-newline' "$(get LAST)"
    if [[ -e "$TMP/INJECTED" ]]; then
        echo "FAIL $wrapper: the .env file ran a command" >&2
        rm -f "$TMP/INJECTED"
        fail=1
    fi
done

if [[ "$count" -lt 8 ]]; then
    echo "FAIL: only $count wrappers with _load_env found (expected at least 8)" >&2
    fail=1
fi
[[ "$fail" -eq 0 ]] && echo "ok: $count wrappers read .env literally"
exit "$fail"
