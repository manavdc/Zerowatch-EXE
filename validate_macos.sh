#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ZeroWatch macOS One-Shot Native Validation Launcher
# ─────────────────────────────────────────────────────────────────────────────

set -e

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE} ZeroWatch macOS One-Shot Native Validation Launcher${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""
echo -e " This script will perform a complete, non-destructive diagnostic"
echo -e " validation of the ZeroWatch macOS Endpoint Agent."
echo ""
echo -e " Operations performed:"
echo -e "   • System environment & hardware discovery"
echo -e "   • Software inventory (.app bundles, pkgutil, Homebrew)"
echo -e "   • Static Mach-O binary & manifest scanning"
echo -e "   • macOS Keychain (Security.framework) read/write validation"
echo -e "   • Temporary test LaunchDaemon registration & cleanup"
echo -e "   • POSIX signal & event logging checks"
echo -e "   • Complete native unit test suite"
echo ""
echo -e "${YELLOW} Safety Guarantee:${NC}"
echo -e "   • All test data is isolated and automatically cleaned up."
echo -e "   • System settings, SIP, and user files are NOT modified."
echo -e "   • Diagnostic report contains NO passwords or raw secrets."
echo ""

# Check python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: python3 could not be found. Please install Python 3.11+ to proceed.${NC}"
    exit 1
fi

# Check root / sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}WARNING: Running without sudo.${NC}"
    echo -e "Some tests (System Keychain, LaunchDaemon) require root privileges and will be skipped."
    echo -e "For full validation, re-run with: ${GREEN}sudo ./validate_macos.sh${NC}"
    echo ""
    read -p "Do you want to continue without root privileges? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# Ensure script is executed from Endpoint-Agent directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo -e "${GREEN}Starting ZeroWatch validation suite...${NC}\n"

# Run Python validation module
python3 -m macos.validation.validate_macos

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo -e "\n${GREEN}Validation completed successfully.${NC}"
else
    echo -e "\n${RED}Validation completed with errors (exit code $exit_code).${NC}"
fi
