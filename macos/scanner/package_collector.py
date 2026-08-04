"""
macos/scanner/package_collector.py
─────────────────────────────────────────────────────────────────────────────
macOS software inventory collectors.

Provides independent collection functions for each inventory source:
  - collect_app_bundles()   .app Info.plist in /Applications et al.
  - collect_pkgutil()       macOS package receipts via pkgutil
  - collect_homebrew()      Homebrew formulae & casks (JSON output)
  - collect_macports()      MacPorts installed ports (port list installed)
  - collect_os_release()    macOS version as an OS SoftwareItem

Each function:
  - Returns List[SoftwareItem]
  - Returns [] if the source is unavailable or yields no data
  - Never raises — internal errors are logged at WARNING/DEBUG level
  - Uses the shared SoftwareItem model without modification

Source Tag Strategy:
  macOS source strings are defined locally in this module because:
    1. Per Phase 6B rules, common/scanner/models.py must not be modified
       until backend compatibility is confirmed.
    2. These source strings must eventually be validated for backend
       CVE matching requirements before promotion to common/.

  Proposed tags (report these to backend team for validation):
    SOURCE_APP_BUNDLE      = "app_bundle"
    SOURCE_MACOS_PKG       = "macos_pkg"
    SOURCE_HOMEBREW_FORMULA = "homebrew_formula"
    SOURCE_HOMEBREW_CASK   = "homebrew_cask"
    SOURCE_MACPORTS        = "macports"
    SOURCE_MACOS_OS        = "os"   ← reuses Linux convention for the OS item

  Deduplication:
    Uses the existing SoftwareItem.dedup_key() which normalises:
      name.lower() + version.lower() within ecosystem buckets.
    An app_bundle and a homebrew_cask for the same application
    (e.g. Google Chrome) will likely dedup to the same key if they
    produce the same normalized name + version.
"""

from __future__ import annotations

import json
import logging
import os
import plistlib
import platform
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from common.scanner.models import SoftwareItem
from common.utils.time_ import utc_now_iso

logger = logging.getLogger("macos.scanner.package_collector")

_SUBPROCESS_TIMEOUT = 60  # seconds


# ── Local macOS source tag constants ─────────────────────────────────────────
# NOTE: Not promoted to common/scanner/models.py until backend validation
# confirms these values are accepted by the CVE matching pipeline.

SOURCE_APP_BUNDLE       = "app_bundle"
SOURCE_MACOS_PKG        = "macos_pkg"
SOURCE_HOMEBREW_FORMULA = "homebrew_formula"
SOURCE_HOMEBREW_CASK    = "homebrew_cask"
SOURCE_MACPORTS         = "macports"
# "os" is reused from Linux convention — already in production use.


# ── Subprocess helper ─────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = _SUBPROCESS_TIMEOUT) -> str:
    """
    Run a command and return stdout on success, empty string on failure.
    Ensures: array invocation, timeout, stderr capture, no shell=True.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"},
        )
        if result.returncode == 0:
            return result.stdout
        logger.debug("Command %s exited %d: %s", cmd, result.returncode, result.stderr[:200])
        return ""
    except FileNotFoundError:
        logger.debug("Command not found: %s", cmd[0])
        return ""
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out (%ds): %s", timeout, cmd)
        return ""
    except OSError as exc:
        logger.debug("Command %s failed: %s", cmd, exc)
        return ""


# ── A. Application Bundles ────────────────────────────────────────────────────

_APP_DIRS = [
    "/Applications",
    "/System/Applications",
]

_USER_APP_DIR = os.path.expanduser("~/Applications")


def _app_dirs_to_scan() -> List[str]:
    """Return all candidate .app scan directories that exist."""
    dirs = list(_APP_DIRS)
    if os.path.isdir(_USER_APP_DIR):
        dirs.append(_USER_APP_DIR)
    return [d for d in dirs if os.path.isdir(d)]


def _read_plist(plist_path: str) -> Optional[dict]:
    """
    Read and parse an Info.plist file using plistlib (standard library).
    Returns the dict on success, None on any failure.
    Handles both binary and XML plist formats.
    """
    try:
        with open(plist_path, "rb") as fh:
            return plistlib.load(fh)
    except plistlib.InvalidFileException as exc:
        logger.debug("Malformed plist %s: %s — skipping", plist_path, exc)
        return None
    except OSError as exc:
        logger.debug("Cannot read plist %s: %s", plist_path, exc)
        return None
    except Exception as exc:
        logger.debug("Unexpected plist read error %s: %s", plist_path, exc)
        return None


def _plist_to_software_item(plist: dict, app_dir_name: str, plist_path: str) -> Optional[SoftwareItem]:
    """
    Extract SoftwareItem fields from a parsed Info.plist dict.

    Name precedence:  CFBundleDisplayName → CFBundleName → CFBundleExecutable → dirname
    Version:          CFBundleShortVersionString → CFBundleVersion → ""
    Vendor:           CFBundleIdentifier domain prefix (e.g. "com.google" → "Google")
    """
    # ── Name ─────────────────────────────────────────────────────────────────
    name = (
        plist.get("CFBundleDisplayName")
        or plist.get("CFBundleName")
        or plist.get("CFBundleExecutable")
        or os.path.splitext(app_dir_name)[0]  # strip .app suffix
    )
    if not name or not str(name).strip():
        return None
    name = str(name).strip()

    # ── Version ───────────────────────────────────────────────────────────────
    version = str(
        plist.get("CFBundleShortVersionString")
        or plist.get("CFBundleVersion")
        or ""
    ).strip()

    # ── Vendor (best-effort from bundle ID) ───────────────────────────────────
    bundle_id = str(plist.get("CFBundleIdentifier") or "").strip()
    vendor = ""
    if bundle_id:
        parts = bundle_id.split(".")
        if len(parts) >= 2:
            # "com.apple.Safari" → "apple",  "com.google.Chrome" → "google"
            # Capitalise first letter for presentation
            vendor = parts[1].capitalize()

    return SoftwareItem(
        name=name,
        version=version,
        vendor=vendor,
        source=SOURCE_APP_BUNDLE,
        category="software",
        install_location=os.path.dirname(plist_path),
        scan_path=plist_path,
        last_seen=utc_now_iso(),
    )


def _scan_app_dir(base_dir: str) -> List[SoftwareItem]:
    """Scan one directory for .app bundles; return SoftwareItems."""
    items: List[SoftwareItem] = []
    try:
        with os.scandir(base_dir) as it:
            for entry in it:
                if not entry.name.endswith(".app"):
                    continue
                plist_path = os.path.join(entry.path, "Contents", "Info.plist")
                if not os.path.isfile(plist_path):
                    continue
                plist = _read_plist(plist_path)
                if plist is None:
                    continue
                item = _plist_to_software_item(plist, entry.name, plist_path)
                if item is not None and item.is_valid():
                    items.append(item)
    except PermissionError as exc:
        logger.debug("Permission denied scanning %s: %s", base_dir, exc)
    except OSError as exc:
        logger.warning("Error scanning app dir %s: %s", base_dir, exc)
    return items


def collect_app_bundles() -> List[SoftwareItem]:
    """
    Scan all known Application directories for .app bundles.
    Reads Info.plist via plistlib — no external processes.
    """
    items: List[SoftwareItem] = []
    for app_dir in _app_dirs_to_scan():
        try:
            batch = _scan_app_dir(app_dir)
            items.extend(batch)
            logger.debug("App bundles in %s: %d found", app_dir, len(batch))
        except Exception as exc:
            logger.warning("collect_app_bundles failed for %s: %s", app_dir, exc)
    logger.info("collect_app_bundles: %d total app bundle items", len(items))
    return items


# ── B. pkgutil package receipts ───────────────────────────────────────────────

def _pkgutil_path() -> Optional[str]:
    return shutil.which("pkgutil") or (
        "/usr/sbin/pkgutil" if os.path.isfile("/usr/sbin/pkgutil") else None
    )


def _pkgutil_list() -> List[str]:
    """Return a list of all installed package IDs."""
    pkgutil = _pkgutil_path()
    if not pkgutil:
        return []
    output = _run([pkgutil, "--pkgs"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _pkgutil_info(pkg_id: str) -> Optional[dict]:
    """
    Query pkgutil --pkg-info for a given package identifier.
    Returns parsed key-value dict or None.
    """
    pkgutil = _pkgutil_path()
    if not pkgutil:
        return None
    output = _run([pkgutil, "--pkg-info", pkg_id], timeout=10)
    if not output:
        return None
    info = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip().lower()] = value.strip()
    return info if info else None


# Filter receipts that represent internal OS components, not scannable
# third-party applications. These are predominantly Apple system packages
# that do not produce useful CVE-matching data at the receipt level.
_PKGUTIL_SKIP_PREFIXES = (
    "com.apple.pkg.",          # Most Apple OS packages
    "com.apple.configdata.",
    "com.apple.installer.",
)

def _is_meaningful_pkg(pkg_id: str) -> bool:
    """Return True if a package receipt is likely a meaningful third-party pkg."""
    return not any(pkg_id.startswith(pfx) for pfx in _PKGUTIL_SKIP_PREFIXES)


def collect_pkgutil() -> List[SoftwareItem]:
    """
    Collect installed packages from macOS package receipts via pkgutil.

    Limitation documented: Apple OS packages (com.apple.pkg.*) are
    intentionally skipped — they represent OS components already captured
    by the OS item, not independently installable third-party software.
    Third-party installers (e.g. Zoom, Docker, Chrome) produce receipts
    with distinct prefixes (com.zoom.*, com.docker.*, com.google.*).
    """
    pkg_ids = _pkgutil_list()
    if not pkg_ids:
        return []

    items: List[SoftwareItem] = []
    skipped = 0

    for pkg_id in pkg_ids:
        if not _is_meaningful_pkg(pkg_id):
            skipped += 1
            continue
        try:
            info = _pkgutil_info(pkg_id)
            if not info:
                continue

            version = info.get("version", "")
            # Package ID as name: "com.docker.docker" → keep as-is (best canonical name)
            name = info.get("package-id") or pkg_id

            items.append(SoftwareItem(
                name=name,
                version=version,
                vendor="",  # pkgutil does not expose vendor; vendor is in the .app if present
                source=SOURCE_MACOS_PKG,
                category="software",
                install_location=info.get("location", ""),
                last_seen=utc_now_iso(),
            ))
        except Exception as exc:
            logger.debug("pkgutil info failed for %s: %s", pkg_id, exc)

    logger.info(
        "collect_pkgutil: %d meaningful receipts (skipped %d Apple OS pkgs)",
        len(items), skipped,
    )
    return items


# ── C. Homebrew ───────────────────────────────────────────────────────────────

# Explicit paths — not assumed to be in $PATH when running as a daemon
_BREW_PATHS = [
    "/opt/homebrew/bin/brew",   # Apple Silicon
    "/usr/local/bin/brew",       # Intel
    "/home/linuxbrew/.linuxbrew/bin/brew",  # Linuxbrew (guard for cross-platform)
]


def _find_brew() -> Optional[str]:
    """Return path to brew executable or None."""
    for p in _BREW_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which("brew")  # Final fallback for interactive shells


def _brew_json_info(brew: str) -> str:
    """Run `brew info --json=v2 --installed` and return stdout."""
    return _run([brew, "info", "--json=v2", "--installed"], timeout=60)


def collect_homebrew() -> List[SoftwareItem]:
    """
    Collect Homebrew formulae and casks.

    Uses `brew info --json=v2 --installed` which returns structured JSON
    instead of human-oriented terminal output. Falls back gracefully
    if Homebrew is not installed.
    """
    brew = _find_brew()
    if not brew:
        logger.debug("Homebrew not found — skipping Homebrew collection")
        return []

    raw = _brew_json_info(brew)
    if not raw:
        logger.warning("brew info returned no output")
        return []

    items: List[SoftwareItem] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("brew info JSON parse failed: %s", exc)
        return []

    # ── Formulae ──────────────────────────────────────────────────────────────
    for formula in data.get("formulae", []):
        try:
            name = formula.get("name") or formula.get("full_name") or ""
            if not name:
                continue
            # installed versions — may be a list of {"version": ...} dicts
            installed = formula.get("installed", [])
            version = installed[0].get("version", "") if installed else ""

            items.append(SoftwareItem(
                name=name,
                version=version,
                vendor="Homebrew",
                source=SOURCE_HOMEBREW_FORMULA,
                category="software",
                last_seen=utc_now_iso(),
            ))
        except Exception as exc:
            logger.debug("Homebrew formula parse failed: %s", exc)

    # ── Casks ─────────────────────────────────────────────────────────────────
    for cask in data.get("casks", []):
        try:
            name = cask.get("name")
            # 'name' field in casks is a list; token/full_name is the ID
            if isinstance(name, list):
                display_name = name[0] if name else ""
            else:
                display_name = str(name) if name else ""
            if not display_name:
                display_name = cask.get("token") or cask.get("full_name") or ""
            if not display_name:
                continue

            version = str(cask.get("installed") or cask.get("version") or "")

            items.append(SoftwareItem(
                name=display_name,
                version=version,
                vendor="Homebrew",
                source=SOURCE_HOMEBREW_CASK,
                category="software",
                last_seen=utc_now_iso(),
            ))
        except Exception as exc:
            logger.debug("Homebrew cask parse failed: %s", exc)

    logger.info(
        "collect_homebrew: %d formulae + casks",
        len(items),
    )
    return items


# ── D. MacPorts ───────────────────────────────────────────────────────────────

_MACPORTS_PATH = "/opt/local/bin/port"


def collect_macports() -> List[SoftwareItem]:
    """
    Collect MacPorts installed ports.

    MacPorts is lower-priority and optional. If not installed, returns [].
    Uses `port -q list installed` which produces:
        portname @version_revision arch
    """
    port_bin = _MACPORTS_PATH if os.path.isfile(_MACPORTS_PATH) else shutil.which("port")
    if not port_bin:
        logger.debug("MacPorts not found — skipping")
        return []

    output = _run([port_bin, "-q", "list", "installed"])
    if not output:
        return []

    items: List[SoftwareItem] = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0].strip()
        version = ""
        # Version in format @2.7.18_0
        if len(parts) > 1 and parts[1].startswith("@"):
            version = parts[1].lstrip("@").split("_")[0]  # strip revision suffix

        if not name:
            continue
        items.append(SoftwareItem(
            name=name,
            version=version,
            vendor="MacPorts",
            source=SOURCE_MACPORTS,
            category="software",
            last_seen=utc_now_iso(),
        ))

    logger.info("collect_macports: %d ports", len(items))
    return items


# ── E. macOS OS version item ──────────────────────────────────────────────────

def collect_os_release() -> List[SoftwareItem]:
    """
    Produce a single SoftwareItem representing the macOS operating system.

    Uses platform.mac_ver() — the most reliable, zero-subprocess method.
    Source "os" matches Linux convention already in production.
    Category "os" matches Windows convention already in production.
    """
    try:
        release, _versiontuple, machine = platform.mac_ver()
        # release may be empty in some sandboxed contexts — check sw_vers as fallback
        if not release:
            release = _run(
                [shutil.which("sw_vers") or "/usr/bin/sw_vers", "-productVersion"],
                timeout=5,
            ).strip()

        arch = machine or platform.machine()

        name = "macOS"
        if release:
            name = f"macOS {release}"  # e.g. "macOS 14.5"

        return [SoftwareItem(
            name=name,
            version=release,
            vendor="Apple",
            source="os",        # Reuses Linux convention: source="os", category="os"
            category="os",
            last_seen=utc_now_iso(),
        )]
    except Exception as exc:
        logger.warning("collect_os_release failed: %s", exc)
        return []
