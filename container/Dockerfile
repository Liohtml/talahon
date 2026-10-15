# Talon agent container image (talon-agent:latest)
#
# Build with the REPOSITORY ROOT as context:
#
#   ./container/build.sh [tag]
#   docker build -f container/Dockerfile -t talon-agent:latest .
#
# The context is filtered by container/Dockerfile.dockerignore (allowlist:
# only the Cargo workspace, the anon-proxy field list and the files below are
# sent — never .env, store/, data/, groups/ or target/).
#
# Stages
#   rust-builder  compiles talon-agent + talon-anon-proxy from the workspace
#   py-builder    builds the Python MCP server virtualenvs under /opt
#   runtime       debian:bookworm-slim: no compilers, no node, no sudo
#
# Runtime contract (docs/RUST_ARCHITECTURE.md §3.3). The host launches:
#
#   docker run --rm -i --cap-drop=ALL --cap-add=CHOWN,SETUID,SETGID,FOWNER,
#     DAC_OVERRIDE,KILL --security-opt=no-new-privileges --read-only
#     --tmpfs /tmp --tmpfs /run --tmpfs /etc/mcp-secrets(0711) --tmpfs /home/agent
#     -e TZ -e RUN_UID -e RUN_GID ... talon-agent:latest
#
# and /usr/local/bin/talon-entrypoint (root) stages per-MCP secrets into
# /etc/mcp-secrets (owner mcp-<id>, 0600), locks MemPalace data to
# mcp-palace and execs `talon-agent supervise`, which runs every MCP server
# as its mcp-* user and the agent as `agent`.

ARG RUST_IMAGE=rust:1-bookworm
ARG DEBIAN_IMAGE=debian:bookworm-slim

# ---------------------------------------------------------------------------
# 1. Rust binaries
# ---------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS rust-builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    cargo build --release --locked --bin talon-agent --bin talon-anon-proxy; \
    install -D -m 0755 target/release/talon-agent /out/talon-agent; \
    install -D -m 0755 target/release/talon-anon-proxy /out/talon-anon-proxy

# ---------------------------------------------------------------------------
# 2. Python MCP servers (built here so the runtime has no compilers)
# ---------------------------------------------------------------------------
FROM ${DEBIAN_IMAGE} AS py-builder

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates git python3 python3-venv python3-dev build-essential; \
    rm -rf /var/lib/apt/lists/*

# OpenSearch (SIEM) MCP server + pyyaml for the Python anon-proxy fallback.
RUN python3 -m venv /opt/opensearch-mcp \
    && /opt/opensearch-mcp/bin/pip install --quiet opensearch-mcp-server pyyaml

# MySQL MCP server (Python). Env: MYSQL_HOST/PORT/USER/PASSWORD/DATABASE —
# the wrapper also accepts MYSQL_PASS/MYSQL_DB.
RUN python3 -m venv /opt/mysql-mcp \
    && /opt/mysql-mcp/bin/pip install --quiet mysql-mcp-server

# pymysql for the mysql-query helper (locked to mcp-mysql below).
RUN python3 -m venv /opt/mysql-tools \
    && /opt/mysql-tools/bin/pip install --quiet pymysql \
    && mkdir -p /opt/mysql-tools/lib

RUN python3 -m venv /opt/copilot-mcp \
    && /opt/copilot-mcp/bin/pip install --quiet \
       "git+https://github.com/socfortress/copilot-mcp-server.git"

RUN python3 -m venv /opt/wazuh-mcp \
    && /opt/wazuh-mcp/bin/pip install --quiet \
       "git+https://github.com/socfortress/wazuh-mcp-server.git"

RUN python3 -m venv /opt/velociraptor-mcp \
    && /opt/velociraptor-mcp/bin/pip install --quiet \
       "git+https://github.com/socfortress/velociraptor-mcp-server.git"

# Shuffle: interactive access to Shuffle's app catalog mid-investigation.
RUN python3 -m venv /opt/shuffle-mcp \
    && /opt/shuffle-mcp/bin/pip install --quiet \
       "git+https://github.com/socfortress/shuffle-mcp-server.git"

# CVE / threat-intel server (CVE, EPSS, KEV, exploit availability, IP
# reputation, VirusTotal, urlscan, MITRE ATT&CK, GitHub advisories).
RUN python3 -m venv /opt/cve-mcp \
    && /opt/cve-mcp/bin/pip install --quiet \
       "git+https://github.com/mukul975/cve-mcp-server.git"

# MemPalace (semantic memory; chromadb is large — keep this layer last).
RUN python3 -m venv /opt/mempalace \
    && /opt/mempalace/bin/pip install --quiet \
       "chromadb>=0.5.0,<0.7" "pyyaml>=6.0" mempalace

# Byte-compile everything now: the runtime root filesystem is read-only.
RUN python3 -m compileall -q /opt >/dev/null || true

# ---------------------------------------------------------------------------
# 3. Runtime
# ---------------------------------------------------------------------------
FROM ${DEBIAN_IMAGE} AS runtime

# Optional headless browser for web tooling (adds ~400 MB).
ARG INSTALL_CHROMIUM=false

LABEL org.opencontainers.image.title="talon-agent" \
      org.opencontainers.image.description="Talon SOC analyst agent runtime (privilege-separated)" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates bash coreutils findutils grep sed gawk curl git jq less \
        procps util-linux passwd python3; \
    if [ "$INSTALL_CHROMIUM" = "true" ]; then \
        apt-get install -y --no-install-recommends \
            chromium fonts-liberation fonts-noto-color-emoji; \
    fi; \
    # No privilege-escalation helpers in the image, ever.
    apt-get purge -y --allow-remove-essential sudo 2>/dev/null || true; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Users (§3.3). `agent` is remapped to RUN_UID/RUN_GID at start-up. Every
# isolated MCP server gets its own system account; `mcp-default` runs servers
# without a `runAs`. MCP ids live in a high range so they cannot collide with
# host user ids (the entrypoint refuses RUN_UID/RUN_GID equal to any of them).
# mcp-palace's 61008 is also used by the host for its one-shot palace
# container (`--user 61008:61008`, talon_container::palace::MCP_PALACE_UID;
# a unit test keeps both in sync) and owns /workspace/extra/mempalace-data
# (the entrypoint re-owns it, 0700, before dropping privileges).
RUN set -eux; \
    groupadd -g 1000 agent; \
    useradd -u 1000 -g 1000 -M -d /home/agent -s /bin/bash agent; \
    for spec in siem:61001 mysql:61002 wazuh:61003 copilot:61004 shuffle:61005 \
                velociraptor:61006 cve:61007 palace:61008 default:61009; do \
        id="${spec%%:*}"; num="${spec##*:}"; \
        groupadd -r -g "$num" "mcp-$id"; \
        useradd -r -u "$num" -g "$num" -M -d /nonexistent -s /usr/sbin/nologin "mcp-$id"; \
    done; \
    # Staging dir for host bind mounts of secret files: root only.
    install -d -m 0700 -o root -g root /etc/mcp-staging; \
    # Secrets dir (a 0711 tmpfs at runtime): traversable, not listable.
    install -d -m 0711 -o root -g root /etc/mcp-secrets; \
    install -d -m 0755 /workspace /workspace/group /workspace/global \
        /workspace/project /workspace/extra /workspace/ipc /run/talon; \
    install -d -m 0700 -o agent -g agent /home/agent

COPY --from=py-builder /opt/ /opt/
COPY --from=rust-builder /out/talon-agent /usr/local/bin/talon-agent
COPY --from=rust-builder /out/talon-anon-proxy /usr/local/bin/talon-anon-proxy
COPY container/entrypoint.sh /usr/local/bin/talon-entrypoint
COPY container/mysql-tools/mysql_query.py /opt/mysql-tools/lib/mysql_query.py
COPY container/mysql-tools/mysql-query /usr/local/bin/mysql-query

RUN set -eux; \
    chown -R root:root /usr/local/bin /opt; \
    chmod 0755 /usr/local/bin/talon-entrypoint /usr/local/bin/talon-agent \
        /usr/local/bin/talon-anon-proxy /usr/local/bin/mysql-query; \
    chmod -R go-w /opt; \
    # pymysql + helper usable by mcp-mysql only.
    chown -R mcp-mysql:mcp-mysql /opt/mysql-tools; \
    chmod -R go-rwx /opt/mysql-tools; \
    # Strip setuid/setgid bits (inert under no-new-privileges anyway).
    find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true; \
    ! command -v sudo

WORKDIR /workspace/group

# Starts as root by design (secret staging + privilege separation); the
# entrypoint drops to `agent` / mcp-* users via talon-agent supervise.
ENTRYPOINT ["/usr/local/bin/talon-entrypoint"]
