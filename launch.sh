#!/usr/bin/env bash
# Game Launcher MITM Proxy — startup script
# Usage: ./launch.sh [OPTIONS]
#
# Options:
#   --port PORT         Proxy listen port (default: 8080)
#   --config FILE       Config file path (default: config.yaml)
#   --cert-dir DIR      TLS certificate directory (default: ~/.mitmproxy)
#   --upstream URL      Upstream proxy URL (e.g. http://corp-proxy:3128)
#   --web               Enable mitmweb UI on port 8081
#   --dump              Use mitmdump (no interactive TUI)
#   --game PATH         Path to game launcher executable to launch after proxy starts
#   -h, --help          Show this help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/config.yaml"
ADDON="${SCRIPT_DIR}/addon.py"
PORT=8080
CERT_DIR="${HOME}/.mitmproxy"
UPSTREAM=""
USE_WEB=false
USE_DUMP=false
GAME_PATH=""

# ── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)       PORT="$2"; shift 2 ;;
        --config)     CONFIG="$2"; shift 2 ;;
        --cert-dir)   CERT_DIR="$2"; shift 2 ;;
        --upstream)   UPSTREAM="$2"; shift 2 ;;
        --web)        USE_WEB=true; shift ;;
        --dump)       USE_DUMP=true; shift ;;
        --game)       GAME_PATH="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ── Dependency checks ────────────────────────────────────────────────────────
check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "Error: '$1' not found. Install with: pip install mitmproxy" >&2
        exit 1
    fi
}

if $USE_WEB; then
    check_dep mitmweb
    MITM_CMD=mitmweb
elif $USE_DUMP; then
    check_dep mitmdump
    MITM_CMD=mitmdump
else
    check_dep mitmproxy
    MITM_CMD=mitmproxy
fi

# ── Build mitmproxy argument list ────────────────────────────────────────────
MITM_ARGS=(
    --listen-host 0.0.0.0
    --listen-port "$PORT"
    --set confdir="$CERT_DIR"
    --scripts "$ADDON"
    --set addon_config="$CONFIG"
)

if [[ -n "$UPSTREAM" ]]; then
    MITM_ARGS+=(--upstream "$UPSTREAM")
fi

if $USE_WEB; then
    MITM_ARGS+=(--web-host 127.0.0.1 --web-port 8081)
fi

# ── Certificate notice ───────────────────────────────────────────────────────
echo "========================================"
echo "  Game Launcher MITM Proxy"
echo "========================================"
echo "  Listen : 0.0.0.0:${PORT}"
echo "  Config : ${CONFIG}"
echo "  Certs  : ${CERT_DIR}"
[[ -n "$UPSTREAM" ]] && echo "  Upstream: ${UPSTREAM}"
$USE_WEB && echo "  Web UI : http://127.0.0.1:8081"
echo "========================================"
echo ""
echo "  To trust the CA certificate, install:"
echo "  ${CERT_DIR}/mitmproxy-ca-cert.pem"
echo ""

# ── Start proxy ──────────────────────────────────────────────────────────────
start_proxy() {
    "$MITM_CMD" "${MITM_ARGS[@]}" &
    PROXY_PID=$!
    echo "Proxy started (PID: ${PROXY_PID})"
}

# ── Launch game with proxy env vars ─────────────────────────────────────────
launch_game() {
    if [[ -z "$GAME_PATH" ]]; then
        return
    fi

    if [[ ! -x "$GAME_PATH" ]]; then
        echo "Warning: game path not executable: $GAME_PATH" >&2
        return
    fi

    echo "Waiting for proxy to be ready..."
    local attempts=0
    until curl -s --proxy "http://127.0.0.1:${PORT}" http://mitm.it/ &>/dev/null || [[ $attempts -ge 10 ]]; do
        sleep 1
        ((attempts++))
    done

    echo "Launching game: ${GAME_PATH}"
    env \
        HTTP_PROXY="http://127.0.0.1:${PORT}" \
        HTTPS_PROXY="http://127.0.0.1:${PORT}" \
        http_proxy="http://127.0.0.1:${PORT}" \
        https_proxy="http://127.0.0.1:${PORT}" \
        SSL_CERT_FILE="${CERT_DIR}/mitmproxy-ca-cert.pem" \
        REQUESTS_CA_BUNDLE="${CERT_DIR}/mitmproxy-ca-cert.pem" \
        NODE_EXTRA_CA_CERTS="${CERT_DIR}/mitmproxy-ca-cert.pem" \
        "$GAME_PATH" &
    GAME_PID=$!
    echo "Game started (PID: ${GAME_PID})"
}

# ── Cleanup on exit ──────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "Shutting down..."
    [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null || true
    [[ -n "${GAME_PID:-}" ]]  && kill "$GAME_PID"  2>/dev/null || true
}
trap cleanup EXIT INT TERM

start_proxy
launch_game

# Keep script alive; forward signals to proxy
wait "$PROXY_PID"
