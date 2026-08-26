#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run_agent.sh — ZeroWatch Linux Agent Launcher
#
# Usage:
#   chmod +x run_agent.sh
#   ./run_agent.sh [OPTIONS]
#
# Options:
#   --prod        Connect to production  (https://zerowatch.deepcytes.io)
#   --demo        Connect to demo/test   (https://zerowatch-testing.eastasia.cloudapp.azure.com)
#   --dev         Connect to local dev   (http://localhost:3001)
#   --server URL  Connect to custom URL
#   --daemon      Run as background daemon (nohup)
#   --help        Show this help
#
# Examples:
#   ./run_agent.sh --prod
#   ./run_agent.sh --dev
#   ./run_agent.sh --server https://my-server.io
#   ./run_agent.sh --prod --daemon
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ── Defaults ──────────────────────────────────────────────────────────────────
SERVER_PRESET=""
CUSTOM_SERVER_URL=""
DAEMON_MODE=false
BASE_API_URL=""

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prod)    SERVER_PRESET="prod";   shift ;;
        --demo)    SERVER_PRESET="demo";   shift ;;
        --dev)     SERVER_PRESET="dev";    shift ;;
        --server)
            SERVER_PRESET="custom"
            CUSTOM_SERVER_URL="${2:-}"
            if [[ -z "${CUSTOM_SERVER_URL}" ]]; then
                echo "[ERROR] --server requires a URL argument."
                exit 1
            fi
            shift 2
            ;;
        --daemon)  DAEMON_MODE=true; shift ;;
        --help|-h)
            head -27 "${BASH_SOURCE[0]}" | tail -22
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown option: $1"
            echo "        Run with --help to see available options."
            exit 1
            ;;
    esac
done

# Detect OS platform
OS_NAME="$(uname -s)"
AGENT_PLATFORM="Linux"
if [[ "${OS_NAME}" == "Darwin" ]]; then
    AGENT_PLATFORM="macOS"
fi

# ── Interactive server selection if not preset ────────────────────────────────
if [[ -z "${SERVER_PRESET}" ]]; then
    echo "════════════════════════════════════════════════════════════"
    echo " ZeroWatch ${AGENT_PLATFORM} Agent — Select Target Server"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo "  [1] Production  - https://zerowatch.deepcytes.io"
    echo "  [2] Demo/Test   - https://zerowatch-testing.eastasia.cloudapp.azure.com"
    echo "  [3] Development - http://localhost:3001"
    echo ""
    read -rp "Enter choice (1/2/3): " SERVER_CHOICE
    case "${SERVER_CHOICE}" in
        1) SERVER_PRESET="prod" ;;
        2) SERVER_PRESET="demo" ;;
        3) SERVER_PRESET="dev"  ;;
        *)
            echo "[ERROR] Invalid choice: ${SERVER_CHOICE}"
            exit 1
            ;;
    esac
fi

# ── Resolve server URL ────────────────────────────────────────────────────────
case "${SERVER_PRESET}" in
    prod)   RAW_SERVER_URL="https://zerowatch.deepcytes.io" ;;
    demo)   RAW_SERVER_URL="https://zerowatch-testing.eastasia.cloudapp.azure.com" ;;
    dev)    RAW_SERVER_URL="http://localhost:3001" ;;
    custom) RAW_SERVER_URL="${CUSTOM_SERVER_URL}" ;;
    *)
        echo "[ERROR] Unknown server preset: ${SERVER_PRESET}"
        exit 1
        ;;
esac

# Ensure /api suffix
if [[ "${RAW_SERVER_URL}" != */api ]]; then
    BASE_API_URL="${RAW_SERVER_URL}/api"
else
    BASE_API_URL="${RAW_SERVER_URL}"
fi

echo "════════════════════════════════════════════════════════════"
echo " ZeroWatch ${AGENT_PLATFORM} Agent — Launcher"
echo " Server: ${BASE_API_URL}"
echo " Preset: ${SERVER_PRESET}"
echo " Daemon: ${DAEMON_MODE}"
echo "════════════════════════════════════════════════════════════"
echo ""

# ── Find Python ───────────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3.14 python3; do
    if command -v "${candidate}" &>/dev/null; then
        PYTHON="${candidate}"
        break
    fi
done

if [[ -z "${PYTHON}" ]]; then
    echo "[ERROR] Python 3.11+ not found. Install with:"
    echo "        sudo apt install python3.11  (Ubuntu/Debian)"
    echo "        sudo dnf install python3.11  (Fedora/RHEL)"
    exit 1
fi

PY_VER=$("${PYTHON}" -c "import sys; print(sys.version_info.major * 100 + sys.version_info.minor)")
if [[ "${PY_VER}" -lt 311 ]]; then
    echo "[ERROR] Python 3.11+ required. Found: $("${PYTHON}" --version)"
    exit 1
fi

echo "[OK] Using Python: $("${PYTHON}" --version) -> ${PYTHON}"
echo ""

# ── Install dependencies ──────────────────────────────────────────────────────
echo "[1/3] Installing Python dependencies..."
if [[ "${AGENT_PLATFORM}" == "macOS" ]]; then
    REQS_FILE="${SCRIPT_DIR}/requirements-common.txt"
else
    REQS_FILE="${SCRIPT_DIR}/requirements-linux.txt"
fi

if [[ ! -f "${REQS_FILE}" ]]; then
    REQS_FILE="${SCRIPT_DIR}/requirements.txt"
fi

if [[ -f "${REQS_FILE}" ]]; then
    "${PYTHON}" -m pip install -q --break-system-packages \
        -r "${REQS_FILE}" 2>/dev/null || \
    "${PYTHON}" -m pip install -q -r "${REQS_FILE}" 2>/dev/null || \
    echo "[WARN] pip install failed — continuing (deps may already be installed)"
else
    echo "[WARN] No requirements file found — skipping pip install"
fi
echo ""

# ── Write build-time server config (mirrors build_agent.bat step 2/5) ─────────
echo "[2/3] Writing server config..."
BUILD_CFG="${SCRIPT_DIR}/agent_build_config.py"
RELEASE_VERSION="${ZEROWATCH_AGENT_VERSION:-}"
if [[ -z "${RELEASE_VERSION}" ]]; then
    RELEASE_VERSION="$(${PYTHON} -c 'import json,urllib.request; r=urllib.request.Request("https://api.github.com/repos/manavdc/Zerowatch-EXE/releases/latest", headers={"User-Agent":"zerowatch-agent-launcher"}); print(json.loads(urllib.request.urlopen(r, timeout=8).read()).get("tag_name", "0.0.0").lstrip("v"))' 2>/dev/null || true)"
fi
if [[ -z "${RELEASE_VERSION}" ]]; then
    RELEASE_VERSION="0.0.0"
fi
cat > "${BUILD_CFG}" <<PYEOF
# Auto-generated by run_agent.sh — do not edit manually
FORCED_BASE_API_URL = "${BASE_API_URL}"
FORCED_AGENT_VERSION = "${RELEASE_VERSION}"
PYEOF
echo "      Server config written to: agent_build_config.py (version ${RELEASE_VERSION})"
echo ""

# ── Validate certificate pins (mirrors build_agent.bat step 2.5/5) ────────────
echo "[2.5/3] Running certificate pin validation..."
if [[ -f "${SCRIPT_DIR}/verify_pins.py" ]]; then
    "${PYTHON}" "${SCRIPT_DIR}/verify_pins.py" "${SERVER_PRESET}"
else
    echo "[WARN] verify_pins.py not found — skipping pin check"
fi
echo ""

# ── Launch agent ──────────────────────────────────────────────────────────────
AGENT_SCRIPT="${SCRIPT_DIR}/sentinel_agent.py"
if [[ ! -f "${AGENT_SCRIPT}" ]]; then
    echo "[ERROR] sentinel_agent.py not found at: ${AGENT_SCRIPT}"
    rm -f "${BUILD_CFG}"
    exit 1
fi

echo "[3/3] Launching ZeroWatch ${AGENT_PLATFORM} Agent..."
echo "      Press Ctrl+C to stop."
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "[Shutdown] Cleaning up..."
    rm -f "${BUILD_CFG}"
    exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

if [[ "${DAEMON_MODE}" == true ]]; then
    LOG_DIR="${SCRIPT_DIR}/state/logs"
    mkdir -p "${LOG_DIR}"
    LOG_FILE="${LOG_DIR}/agent.log"

    echo "[Daemon] Starting in background..."
    echo "[Daemon] Log output: ${LOG_FILE}"
    echo "[Daemon] PID file:   ${SCRIPT_DIR}/state/agent.pid"
    echo ""

    nohup "${PYTHON}" -u "${AGENT_SCRIPT}" --daemon \
        >> "${LOG_FILE}" 2>&1 &

    AGENT_PID=$!
    echo "${AGENT_PID}" > "${SCRIPT_DIR}/state/agent.pid"
    echo "[Daemon] Agent started with PID: ${AGENT_PID}"
    echo "[Daemon] Monitor with: tail -f ${LOG_FILE}"
    echo "[Daemon] Stop with:    kill \$(cat state/agent.pid)"
else
    # Foreground mode — Python output goes directly to terminal
    exec "${PYTHON}" -u "${AGENT_SCRIPT}"
fi
