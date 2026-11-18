#!/usr/bin/env bash
# Build the Talahon agent container image.
#
#   ./container/build.sh [tag]
#
# The build context is the REPOSITORY ROOT (the Rust workspace is compiled in
# the image); container/Dockerfile.dockerignore limits what is sent.
#
# Environment:
#   CONTAINER_RUNTIME  docker (default) | podman | <path>
#   TALAHON_IMAGE_NAME image name (default: talahon-agent)
#   INSTALL_CHROMIUM   true | false (default: false)
#   http_proxy / https_proxy / no_proxy (and upper-case) are forwarded as
#   build args when set (e.g. inside Docker Sandboxes).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# TALON_IMAGE_NAME is the pre-rename spelling of TALAHON_IMAGE_NAME: still
# read (the new name wins), removed in the next major version.
if [[ -z "${TALAHON_IMAGE_NAME:-}" && -n "${TALON_IMAGE_NAME:-}" ]]; then
    echo "build.sh: TALON_IMAGE_NAME is deprecated, use TALAHON_IMAGE_NAME" >&2
fi
IMAGE_NAME="${TALAHON_IMAGE_NAME:-${TALON_IMAGE_NAME:-talahon-agent}}"
TAG="${1:-latest}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
INSTALL_CHROMIUM="${INSTALL_CHROMIUM:-false}"

case "$INSTALL_CHROMIUM" in
    true | false) ;;
    *)
        echo "INSTALL_CHROMIUM must be 'true' or 'false'" >&2
        exit 2
        ;;
esac
if [[ ! "$IMAGE_NAME" =~ ^[a-z0-9][a-z0-9._/-]*$ ]]; then
    echo "invalid image name: $IMAGE_NAME" >&2
    exit 2
fi
if [[ ! "$TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
    echo "invalid tag: $TAG" >&2
    exit 2
fi
if ! command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1; then
    echo "container runtime '$CONTAINER_RUNTIME' not found (set CONTAINER_RUNTIME)" >&2
    exit 1
fi
if [[ ! -f "$REPO_ROOT/Cargo.toml" || ! -f "$REPO_ROOT/Cargo.lock" ]]; then
    echo "Cargo workspace not found at $REPO_ROOT" >&2
    exit 1
fi

build_args=(--build-arg "INSTALL_CHROMIUM=$INSTALL_CHROMIUM")
for var in http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY; do
    if [[ -n "${!var:-}" ]]; then
        build_args+=(--build-arg "$var=${!var}")
    fi
done

extra_args=()
case "$(basename "$CONTAINER_RUNTIME")" in
    podman* | buildah*)
        extra_args+=(--ignorefile "$SCRIPT_DIR/Dockerfile.dockerignore")
        ;;
    *)
        # RUN --mount cache mounts need BuildKit (default since Docker 23).
        # That is all the build needs: no buildx-only feature is used.
        export DOCKER_BUILDKIT=1
        # Docker 23 and later drive BuildKit through the buildx plugin,
        # which distribution packages often ship separately (Debian/Ubuntu:
        # docker.io without docker-buildx). Without it the build dies with
        # "BuildKit is enabled but the buildx component is missing or
        # broken". Older Docker (e.g. Debian 12's docker.io 20.10) has
        # BuildKit built into the CLI, and the podman-docker shim builds
        # with podman ("podman version ..."): neither needs buildx. A client
        # whose version cannot be read is not stopped here either; the
        # build itself then says what is missing.
        client_version="$("$CONTAINER_RUNTIME" --version 2>/dev/null || true)"
        if [[ "$client_version" =~ ^Docker\ version\ ([0-9]+)\. ]] &&
            ((10#${BASH_REMATCH[1]} >= 23)) &&
            ! "$CONTAINER_RUNTIME" buildx version >/dev/null 2>&1; then
            echo "docker buildx is not available, but the image build needs BuildKit." >&2
            echo "Install the buildx plugin and re-run:" >&2
            echo "  Debian/Ubuntu (distribution packages): sudo apt-get install docker-buildx" >&2
            echo "  Docker's own repository:               sudo apt-get install docker-buildx-plugin" >&2
            echo "  other systems: https://docs.docker.com/go/buildx/" >&2
            exit 1
        fi
        ;;
esac

echo "Building Talahon agent image ${IMAGE_NAME}:${TAG}"
echo "  runtime:  ${CONTAINER_RUNTIME}"
echo "  context:  ${REPO_ROOT}"
echo "  chromium: ${INSTALL_CHROMIUM}"

"$CONTAINER_RUNTIME" build \
    -f "$SCRIPT_DIR/Dockerfile" \
    -t "${IMAGE_NAME}:${TAG}" \
    "${build_args[@]}" \
    ${extra_args[@]+"${extra_args[@]}"} \
    "$REPO_ROOT"

cat <<EOF

Build complete: ${IMAGE_NAME}:${TAG}

The image expects the hardened launch done by the Talahon host (talon-container).
Quick smoke test (degraded: no LLM endpoint in the input):
  echo '{"prompt":"What is 2+2?","groupFolder":"test","chatJid":"test@g.us","isMain":false}' | \\
    ${CONTAINER_RUNTIME} run -i --rm --read-only --cap-drop=ALL \\
      --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID --cap-add=FOWNER \\
      --cap-add=DAC_OVERRIDE --cap-add=KILL --security-opt=no-new-privileges \\
      --tmpfs /tmp --tmpfs /run --tmpfs /etc/mcp-secrets:mode=0711 --tmpfs /home/agent \\
      ${IMAGE_NAME}:${TAG}
EOF
