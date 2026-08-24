#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# macos/build/build_agent.sh
# ZeroWatch macOS Agent — Nuitka standalone build script
#
# Usage (run from the repo root or from macos/build/):
#   chmod +x macos/build/build_agent.sh
#   ./macos/build/build_agent.sh [--prod | --demo | --dev | --server URL]
#
# Requirements (on a macOS machine with Python 3.11+ and Xcode Command Line Tools):
#   pip3 install -r requirements-common.txt    # installs nuitka>=2.0 etc.
#
# Output:
#   dist/macos/zerowatch-agent-macos   (single self-contained binary)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/dist/macos"
BINARY_NAME="zerowatch-agent-macos"
MAIN_SCRIPT="${REPO_ROOT}/sentinel_agent.py"

# ── Parse arguments ───────────────────────────────────────────────────────────
SERVER_PRESET=""
CUSTOM_SERVER_URL=""

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
        --help|-h)
            echo "Usage: ./build_agent.sh [OPTIONS]"
            echo "Options:"
            echo "  --prod        Pin to production (https://zerowatch.deepcytes.io)"
            echo "  --demo        Pin to demo/test (https://zerowatch-testing.eastasia.cloudapp.azure.com)"
            echo "  --dev         Pin to local dev (http://localhost:3001)"
            echo "  --server URL  Pin to custom URL"
            echo "  --help, -h    Show this help"
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Interactive server selection if not preset ────────────────────────────────
if [[ -z "${SERVER_PRESET}" ]]; then
    echo "Select target server for this binary:"
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
echo " ZeroWatch macOS Agent — Nuitka Build"
echo " Repository: ${REPO_ROOT}"
echo " Server:     ${BASE_API_URL}"
echo " Preset:     ${SERVER_PRESET}"
echo " Output:     ${OUTPUT_DIR}/${BINARY_NAME}"
echo "════════════════════════════════════════════════════════════"

# ── Verify Python version ─────────────────────────────────────────────────────
python3 --version
PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [[ "$PYTHON_MAJOR" -lt 3 || "$PYTHON_MINOR" -lt 11 ]]; then
    echo "ERROR: Python 3.11+ required (found ${PYTHON_MAJOR}.${PYTHON_MINOR})"
    exit 1
fi

# ── Verify tkinter is available ───────────────────────────────────────────────
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo ""
    echo "ERROR: tkinter not found in Python installation."
    echo "       Install Python with Tk support via Homebrew: brew install python-tk"
    exit 1
fi
echo "[OK] tkinter available."

# ── Install dependencies ──────────────────────────────────────────────────────
echo ""
echo "[1/4] Installing dependencies..."
REQ_FILE="${REPO_ROOT}/requirements-common.txt"
if [[ -f "${REPO_ROOT}/requirements.txt" ]]; then
    REQ_FILE="${REPO_ROOT}/requirements.txt"
fi
pip3 install -q -r "${REQ_FILE}" || true

# ── Validating certificate pinning configuration ──────────────────────────────
echo ""
echo "[1.5/4] Validating certificate pinning configuration..."
python3 "${REPO_ROOT}/verify_pins.py" "${SERVER_PRESET}"

# ── Create output directory ───────────────────────────────────────────────────
mkdir -p "${OUTPUT_DIR}"

# ── Run Nuitka Build ──────────────────────────────────────────────────────────
echo ""
echo "[2/4] Running Nuitka standalone build..."
BUILD_DIR="/tmp/zerowatch-macos-build"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Copy source tree to temporary build directory
cp -r "${REPO_ROOT}/common"    "${BUILD_DIR}/"
cp -r "${REPO_ROOT}/linux"     "${BUILD_DIR}/"
cp -r "${REPO_ROOT}/macos"     "${BUILD_DIR}/"
cp -r "${REPO_ROOT}/windows"   "${BUILD_DIR}/"
cp -r "${REPO_ROOT}/platforms" "${BUILD_DIR}/"
cp -r "${REPO_ROOT}/scanner"   "${BUILD_DIR}/"
cp -r "${REPO_ROOT}/resources" "${BUILD_DIR}/"
cp    "${REPO_ROOT}/sentinel_agent.py"       "${BUILD_DIR}/"
cp    "${REPO_ROOT}/sentinel_agent_macos.py" "${BUILD_DIR}/"
cp    "${REPO_ROOT}/cert_pinning.py"          "${BUILD_DIR}/"

# ── Write build-time server config ────────────────────────────────────────────
echo ""
echo "[2.1/4] Writing build-time server config..."
cat > "${BUILD_DIR}/agent_build_config.py" <<PYEOF
# Auto-generated by build_agent.sh — do not edit manually
FORCED_BASE_API_URL = "${BASE_API_URL}"
PYEOF

cd "${BUILD_DIR}"

python3 -m nuitka \
    --standalone \
    --onefile \
    --enable-plugin=tk-inter \
    --output-dir="${BUILD_DIR}/dist" \
    --output-filename="${BINARY_NAME}" \
    --include-package=common \
    --include-package=linux \
    --include-package=macos \
    --include-package=windows \
    --include-package=platforms \
    --include-package=scanner \
    --include-module=cert_pinning \
    --include-module=sentinel_agent_macos \
    --macos-app-icon="${BUILD_DIR}/resources/favicon.png" \
    --include-data-dir=resources=resources \
    --assume-yes-for-downloads \
    --remove-output \
    --python-flag=no_site \
    --warn-unusual-code \
    "${BUILD_DIR}/sentinel_agent.py"

# Copy the built binary back to the workspace output directory
cp "${BUILD_DIR}/dist/${BINARY_NAME}" "${OUTPUT_DIR}/${BINARY_NAME}"

# Cleanup
rm -rf "${BUILD_DIR}"
rm -rf "${OUTPUT_DIR}/sentinel_agent.build" "${OUTPUT_DIR}/sentinel_agent.dist"

echo ""
echo "[3/4] Setting executable permissions..."
chmod +x "${OUTPUT_DIR}/${BINARY_NAME}"

# ── Print result ──────────────────────────────────────────────────────────────
echo ""
echo "[4/4] Build complete!"
echo ""
ls -lh "${OUTPUT_DIR}/${BINARY_NAME}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " HOW TO DISTRIBUTE & RUN ON A MAC OS MACHINE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Send the binary to target Mac: ${OUTPUT_DIR}/${BINARY_NAME}"
echo ""
echo "2. Make it executable and run (opens Tkinter GUI):"
echo "     chmod +x ${BINARY_NAME}"
echo "     ./${BINARY_NAME}"
echo ""
echo "3. Run in background / daemon mode:"
echo "     sudo ./${BINARY_NAME} --daemon"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
