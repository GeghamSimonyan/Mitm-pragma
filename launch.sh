#!/usr/bin/env bash
# Game Launcher MITM Proxy — prag.digitain.tools
# Usage: ./launch.sh [OPTIONS]
#
# Options:
#   --port PORT          Proxy listen port         (default: 8080)
#   --config FILE        Config file path           (default: config.yaml)
#   --cert FILE          TLS certificate PEM        (default: auto-generated CA)
#   --key  FILE          TLS private-key PEM        (default: auto-generated CA)
#   --cert-dir DIR       mitmproxy CA directory     (default: ~/.mitmproxy)
#   --no-verify-ssl      Skip upstream cert verification (default: skipped)
#   --verify-ssl         Enforce upstream cert verification
#   --web                Enable mitmweb UI on port 8081
#   --dump               Use mitmdump (non-interactive)
#   --game PATH          Game launcher to start after proxy is ready
#   -h, --help           Show this help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/config.yaml"
ADDON="${SCRIPT_DIR}/addon.py"
DOMAIN="prag.digitain.tools"
PORT=8080
CERT_DIR="${HOME}/.mitmproxy"
CERT_FILE=""
KEY_FILE=""
VERIFY_UPSTREAM=false    # SSL: skip upstream verification by default (MITM-friendly)
USE_WEB=false
USE_DUMP=false
GAME_PATH=""

PROXY_PID=""
GAME_PID=""

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)          PORT="$2";        shift 2 ;;
        --config)        CONFIG="$2";      shift 2 ;;
        --cert)          CERT_FILE="$2";   shift 2 ;;
        --key)           KEY_FILE="$2";    shift 2 ;;
        --cert-dir)      CERT_DIR="$2";    shift 2 ;;
        --no-verify-ssl) VERIFY_UPSTREAM=false; shift ;;
        --verify-ssl)    VERIFY_UPSTREAM=true;  shift ;;
        --web)           USE_WEB=true;     shift ;;
        --dump)          USE_DUMP=true;    shift ;;
        --game)          GAME_PATH="$2";   shift 2 ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ── Dependency check ──────────────────────────────────────────────────────────
require() {
    command -v "$1" &>/dev/null || {
        echo "Error: '$1' not found.  Run: pip install mitmproxy" >&2
        exit 1
    }
}

if $USE_WEB; then
    require mitmweb;    MITM_CMD=mitmweb
elif $USE_DUMP; then
    require mitmdump;   MITM_CMD=mitmdump
else
    require mitmproxy;  MITM_CMD=mitmproxy
fi

# ── SSL certificate resolution ────────────────────────────────────────────────
#
# Priority:
#   1. --cert / --key flags
#   2. certs/<domain>-fullchain.pem + certs/<domain>.key  (in repo)
#   3. Auto-generated mitmproxy CA  (generated on first run)
#
resolve_certs() {
    local repo_cert="${SCRIPT_DIR}/certs/${DOMAIN}-fullchain.pem"
    local repo_key="${SCRIPT_DIR}/certs/${DOMAIN}.key"

    if [[ -z "$CERT_FILE" && -f "$repo_cert" && -f "$repo_key" ]]; then
        CERT_FILE="$repo_cert"
        KEY_FILE="$repo_key"
        echo "  SSL cert : ${CERT_FILE}  (repo)"
    elif [[ -n "$CERT_FILE" && -f "$CERT_FILE" ]]; then
        echo "  SSL cert : ${CERT_FILE}  (--cert flag)"
    else
        echo "  SSL cert : auto-generated mitmproxy CA"
        echo "             (trust ${CERT_DIR}/mitmproxy-ca-cert.pem)"
        CERT_FILE=""
        KEY_FILE=""
    fi
}

# ── Build mitmproxy args ──────────────────────────────────────────────────────
build_args() {
    MITM_ARGS=(
        --listen-host 0.0.0.0
        --listen-port "$PORT"
        --set confdir="$CERT_DIR"
        --scripts "$ADDON"
    )

    # Upstream SSL verification
    if ! $VERIFY_UPSTREAM; then
        MITM_ARGS+=(--ssl-insecure)
    fi

    # Real TLS cert for the proxy's MITM interception (overrides per-domain CA)
    if [[ -n "$CERT_FILE" ]]; then
        # mitmproxy uses this cert for all SNI names (wildcard approach)
        MITM_ARGS+=(--certs "*=${CERT_FILE}")
        if [[ -n "$KEY_FILE" ]]; then
            # Combine cert + key into what mitmproxy expects
            MITM_ARGS+=(--set ssl_verify_upstream_trusted_ca="${CERT_FILE}")
        fi
    fi

    if $USE_WEB; then
        MITM_ARGS+=(--web-host 127.0.0.1 --web-port 8081)
    fi
}

# ── Print banner ──────────────────────────────────────────────────────────────
print_banner() {
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   Game Launcher MITM Proxy           ║"
    echo "  ║   ${DOMAIN}        ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""
    echo "  Listen   : 0.0.0.0:${PORT}"
    echo "  Config   : ${CONFIG}"
    echo "  CA dir   : ${CERT_DIR}"
    echo "  Upstream TLS verify: ${VERIFY_UPSTREAM}"
    $USE_WEB && echo "  Web UI   : http://127.0.0.1:8081"
    echo ""
    echo "  Configure the game launcher:"
    echo "    HTTP_PROXY=http://${DOMAIN}:${PORT}"
    echo "    HTTPS_PROXY=http://${DOMAIN}:${PORT}"
    echo ""
}

# ── Start proxy ───────────────────────────────────────────────────────────────
start_proxy() {
    "$MITM_CMD" "${MITM_ARGS[@]}" &
    PROXY_PID=$!
    echo "  Proxy started (PID: ${PROXY_PID}, cmd: ${MITM_CMD})"
}

# ── Wait for proxy readiness ──────────────────────────────────────────────────
wait_for_proxy() {
    local attempts=0 max=15
    echo "  Waiting for proxy on port ${PORT}..."
    while [[ $attempts -lt $max ]]; do
        if curl -s --max-time 1 \
                --proxy "http://127.0.0.1:${PORT}" \
                http://mitm.it/ &>/dev/null; then
            echo "  Proxy ready."
            return 0
        fi
        sleep 1
        (( attempts++ )) || true
    done
    echo "  Warning: proxy did not respond after ${max}s." >&2
    return 1
}

# ── Launch game ───────────────────────────────────────────────────────────────
launch_game() {
    [[ -z "$GAME_PATH" ]] && return

    if [[ ! -x "$GAME_PATH" ]]; then
        echo "Warning: not executable: $GAME_PATH" >&2
        return
    fi

    wait_for_proxy || true

    local ca_pem="${CERT_DIR}/mitmproxy-ca-cert.pem"

    echo "  Launching: ${GAME_PATH}"
    env \
        HTTP_PROXY="http://127.0.0.1:${PORT}" \
        HTTPS_PROXY="http://127.0.0.1:${PORT}" \
        http_proxy="http://127.0.0.1:${PORT}" \
        https_proxy="http://127.0.0.1:${PORT}" \
        SSL_CERT_FILE="${ca_pem}" \
        REQUESTS_CA_BUNDLE="${ca_pem}" \
        NODE_EXTRA_CA_CERTS="${ca_pem}" \
        JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=${PORT}" \
        "$GAME_PATH" &
    GAME_PID=$!
    echo "  Game started (PID: ${GAME_PID})"
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "Shutting down…"
    [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
    [[ -n "$GAME_PID"  ]] && kill "$GAME_PID"  2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Main ──────────────────────────────────────────────────────────────────────
resolve_certs
build_args
print_banner
start_proxy
launch_game

wait "$PROXY_PID"
