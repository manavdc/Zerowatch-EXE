"""
linux/scanner/package_collector.py
─────────────────────────────────────────────────────────────────────────────
Linux package manager collectors.

Supports: dpkg (Debian/Ubuntu), rpm (RHEL/Fedora/Rocky/SUSE),
          pacman (Arch), snap, flatpak, kernel modules, OS release.

Each collector:
  - Detects its tool safely (shutil.which or proc-file check)
  - Returns an empty list if the tool is unavailable — never raises
  - Normalises results into SoftwareItem using the correct source tag
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import List

from common.scanner.models import (
    SoftwareItem,
    SOURCE_DEB_PACKAGE,
    SOURCE_RPM_PACKAGE,
    SOURCE_PACMAN_PKG,
    SOURCE_SNAP_APP,
    SOURCE_FLATPAK_APP,
    SOURCE_KERNEL_MODULE,
)

logger = logging.getLogger("linux.scanner.package_collector")

_SUBPROCESS_TIMEOUT = 60  # seconds


def _run(cmd: List[str]) -> str:
    """Run command and return stdout; return '' on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            env={**os.environ, "LANG": "C"},
        )
        return result.stdout or ""
    except FileNotFoundError:
        return ""
    except Exception as exc:
        logger.debug("Command %s failed: %s", cmd, exc)
        return ""


# ── dpkg (Debian / Ubuntu / Mint) ────────────────────────────────────────────

def collect_dpkg() -> List[SoftwareItem]:
    """Collect installed packages via dpkg-query."""
    if not shutil.which("dpkg-query"):
        return []
    logger.debug("Collecting dpkg packages...")
    output = _run([
        "dpkg-query",
        "-W",
        "-f=${Status}\t${Package}\t${Version}\t${Maintainer}\t${Architecture}\n",
    ])
    items: List[SoftwareItem] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        status, name, version, maintainer = parts[0], parts[1], parts[2], parts[3]
        # Only include installed packages (status starts with "install ok installed")
        if not status.strip().startswith("install ok"):
            continue
        name = name.strip()
        version = version.strip()
        maintainer = maintainer.strip()
        if not name:
            continue
        items.append(SoftwareItem(
            name=name,
            version=version,
            vendor=maintainer,
            source=SOURCE_DEB_PACKAGE,
            category="software",
        ))
    logger.debug("dpkg collected %d packages", len(items))
    return items


# ── rpm (RHEL / Fedora / Rocky / AlmaLinux / SUSE) ───────────────────────────

def collect_rpm() -> List[SoftwareItem]:
    """Collect installed packages via rpm query."""
    if not shutil.which("rpm"):
        return []
    logger.debug("Collecting rpm packages...")
    output = _run([
        "rpm", "-qa",
        "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n",
    ])
    items: List[SoftwareItem] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else ""
        vendor = parts[2].strip() if len(parts) > 2 else ""
        if not name:
            continue
        items.append(SoftwareItem(
            name=name,
            version=version,
            vendor=vendor,
            source=SOURCE_RPM_PACKAGE,
            category="software",
        ))
    logger.debug("rpm collected %d packages", len(items))
    return items


# ── pacman (Arch Linux / Manjaro) ────────────────────────────────────────────

def collect_pacman() -> List[SoftwareItem]:
    """Collect installed packages via pacman."""
    if not shutil.which("pacman"):
        return []
    logger.debug("Collecting pacman packages...")
    # pacman -Q output: "name version" per line
    output = _run(["pacman", "-Q"])
    items: List[SoftwareItem] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, version = parts[0].strip(), parts[1].strip()
        if not name:
            continue
        items.append(SoftwareItem(
            name=name,
            version=version,
            vendor="",
            source=SOURCE_PACMAN_PKG,
            category="software",
        ))
    logger.debug("pacman collected %d packages", len(items))
    return items


# ── snap ─────────────────────────────────────────────────────────────────────

def collect_snap() -> List[SoftwareItem]:
    """Collect installed snap packages."""
    if not shutil.which("snap"):
        return []
    logger.debug("Collecting snap packages...")
    # snap list --unicode=never output:
    # Name          Version       Rev    Tracking       Publisher  Notes
    output = _run(["snap", "list", "--unicode=never"])
    items: List[SoftwareItem] = []
    lines = output.splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0].strip()
        version = parts[1].strip()
        publisher = parts[4].strip() if len(parts) > 4 else ""
        if not name or name == "Name":
            continue
        items.append(SoftwareItem(
            name=name,
            version=version,
            vendor=publisher,
            source=SOURCE_SNAP_APP,
            category="software",
        ))
    logger.debug("snap collected %d packages", len(items))
    return items


# ── flatpak ───────────────────────────────────────────────────────────────────

def collect_flatpak() -> List[SoftwareItem]:
    """Collect installed flatpak applications."""
    if not shutil.which("flatpak"):
        return []
    logger.debug("Collecting flatpak packages...")
    output = _run([
        "flatpak", "list", "--app",
        "--columns=application,version,origin",
    ])
    items: List[SoftwareItem] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 1:
            continue
        app_id = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else ""
        origin = parts[2].strip() if len(parts) > 2 else ""
        if not app_id:
            continue
        # Use the last segment of the app ID as the human-readable name
        name = app_id.split(".")[-1] if "." in app_id else app_id
        items.append(SoftwareItem(
            name=name,
            version=version,
            vendor=origin,
            source=SOURCE_FLATPAK_APP,
            category="software",
            install_location=app_id,
        ))
    logger.debug("flatpak collected %d packages", len(items))
    return items


# ── kernel modules ────────────────────────────────────────────────────────────

def collect_kernel_modules() -> List[SoftwareItem]:
    """Collect loaded kernel modules from /proc/modules."""
    modules_path = "/proc/modules"
    if not os.path.exists(modules_path):
        return []
    logger.debug("Collecting kernel modules...")
    items: List[SoftwareItem] = []
    try:
        with open(modules_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if not parts:
                    continue
                name = parts[0].strip()
                if not name:
                    continue
                items.append(SoftwareItem(
                    name=name,
                    version="",
                    vendor="",
                    source=SOURCE_KERNEL_MODULE,
                    category="driver",
                ))
    except OSError as exc:
        logger.debug("Failed reading /proc/modules: %s", exc)
    logger.debug("kernel modules collected %d entries", len(items))
    return items


# ── OS release ────────────────────────────────────────────────────────────────

def collect_os_release() -> List[SoftwareItem]:
    """Read /etc/os-release and return a single OS SoftwareItem."""
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        if not os.path.exists(path):
            continue
        fields: dict = {}
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        key, _, value = line.partition("=")
                        fields[key.strip()] = value.strip().strip('"')
        except OSError:
            continue

        name = fields.get("PRETTY_NAME") or fields.get("NAME") or "Linux"
        version = fields.get("VERSION") or fields.get("VERSION_ID") or ""
        vendor = fields.get("ID_LIKE") or fields.get("ID") or ""

        return [SoftwareItem(
            name=name,
            version=version,
            vendor=vendor,
            source="os",
            category="os",
        )]
    return []
