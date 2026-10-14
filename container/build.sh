#!/usr/bin/env bash
# Build the Talon agent container image.
#
#   ./container/build.sh [tag]
#
# The build context is the REPOSITORY ROOT (the Rust workspace is compiled in
# the image); container/Dockerfile.dockerignore limits what is sent.
#
# Environment:
#   CONTAINER_RUNTIME  docker (default) | podman | <path>
#   TALON_IMAGE_NAME   image name (default: talon-agent)
#   INSTALL_CHROMIUM   true | false (default: false)
#   http_proxy / https_proxy / no_proxy (and upper-case) are forwarded as
#   build args when set (e.g. inside Docker Sandboxes).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_NAME="${TALON_IMAGE_NAME:-talon-agent}"
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
        export DOCKER_BUILDKIT=1
        ;;
esac

echo "Building Talon agent image ${IMAGE_NAME}:${TAG}"
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

The image expects the hardened launch done by the Talon host (talon-container).
Quick smoke test (degraded: no LLM endpoint in the input):
  echo '{"prompt":"What is 2+2?","groupFolder":"test","chatJid":"test@g.us","isMain":false}' | \\
    ${CONTAINER_RUNTIME} run -i --rm --read-only --cap-drop=ALL \\
      --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID --cap-add=FOWNER \\
      --cap-add=DAC_OVERRIDE --cap-add=KILL --security-opt=no-new-privileges \\
      --tmpfs /tmp --tmpfs /run --tmpfs /etc/mcp-secrets:mode=0711 --tmpfs /home/agent \\
      ${IMAGE_NAME}:${TAG}
EOF
