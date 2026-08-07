"""
linux/scanner/binary_inspector.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of BinaryInspector interface.

Identification strategy (most authoritative first):
  1. dpkg -S <path>   → package name → dpkg-query for version  (Debian/Ubuntu)
  2. rpm -qf <path>   → package info                           (RHEL/Fedora)
  3. Fallback: basename of the file with empty version

Package ownership is preferred over ELF string extraction because it is:
  - Authoritative (same database used for CVE matching)
  - Fast (subprocess with short output)
  - Version-accurate (reflects the installed package version)

Raw ELF string parsing (e.g. scanning for "version" strings) is intentionally
NOT implemented here because it produces too many false positives and
unreliable version strings. Package database correlation is the correct approach.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any, List, Optional

from common.scanner.interfaces import BinaryInspector
from common.scanner.models import (
    SoftwareItem,
    SOURCE_ELF_BINARY,
    SOURCE_ELF_LIB,
    SOURCE_DEB_PACKAGE,
    SOURCE_RPM_PACKAGE,
)
from common.scanner.state_cache import ScanCache

logger = logging.getLogger("linux.scanner.binary_inspector")

_SUBPROCESS_TIMEOUT = 10  # seconds — intentionally short for per-file lookups


def _dpkg_owner(filepath: str) -> Optional[dict]:
    """
    Use dpkg -S to find which package owns the given file.
    Returns {'name': str, 'version': str, 'vendor': str} or None.
    """
    if not shutil.which("dpkg"):
        return None
    try:
        result = subprocess.run(
            ["dpkg", "-S", filepath],
            capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
            env={**os.environ, "LANG": "C"},
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        # Output: "packagename: /path/to/file"
        pkg_name = result.stdout.split(":")[0].strip()
        if not pkg_name:
            return None

        # Now get the version
        ver_result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}\t${Maintainer}", pkg_name],
            capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
            env={**os.environ, "LANG": "C"},
        )
        if ver_result.returncode == 0 and ver_result.stdout.strip():
            parts = ver_result.stdout.strip().split("\t")
            version = parts[0].strip()
            vendor = parts[1].strip() if len(parts) > 1 else ""
        else:
            version, vendor = "", ""

        return {"name": pkg_name, "version": version, "vendor": vendor, "source": SOURCE_DEB_PACKAGE}
    except Exception as exc:
        logger.debug("dpkg -S %s failed: %s", filepath, exc)
        return None


def _rpm_owner(filepath: str) -> Optional[dict]:
    """
    Use rpm -qf to find which package owns the given file.
    Returns {'name': str, 'version': str, 'vendor': str} or None.
    """
    if not shutil.which("rpm"):
        return None
    try:
        result = subprocess.run(
            ["rpm", "-qf", filepath, "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}"],
            capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
            env={**os.environ, "LANG": "C"},
        )
        if result.returncode != 0 or "not owned" in result.stdout.lower():
            return None
        parts = result.stdout.strip().split("\t")
        if not parts[0].strip():
            return None
        return {
            "name": parts[0].strip(),
            "version": parts[1].strip() if len(parts) > 1 else "",
            "vendor": parts[2].strip() if len(parts) > 2 else "",
            "source": SOURCE_RPM_PACKAGE,
        }
    except Exception as exc:
        logger.debug("rpm -qf %s failed: %s", filepath, exc)
        return None


def _pacman_owner(filepath: str) -> Optional[dict]:
    """
    Use pacman -Qo (Arch / Manjaro) to find which package owns the given file.
    Output format: "/path/to/file is owned by packagename version"
    Returns {'name': str, 'version': str, 'vendor': str} or None.
    """
    if not shutil.which("pacman"):
        return None
    try:
        result = subprocess.run(
            ["pacman", "-Qo", filepath],
            capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
            env={**os.environ, "LANG": "C"},
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        # Format: "/usr/bin/python3 is owned by python 3.11.5-1"
        parts = result.stdout.strip().rsplit(" ", 2)
        if len(parts) < 3:
            return None
        pkg_name = parts[-2].strip()
        version  = parts[-1].strip()
        if not pkg_name:
            return None
        return {"name": pkg_name, "version": version, "vendor": "Arch Linux", "source": SOURCE_ELF_BINARY}
    except Exception as exc:
        logger.debug("pacman -Qo %s failed: %s", filepath, exc)
        return None


def _apk_owner(filepath: str) -> Optional[dict]:
    """
    Use apk info --who-owns (Alpine Linux) to find which package owns the given file.
    Output format: "/path/to/file is owned by packagename-version"
    Returns {'name': str, 'version': str, 'vendor': str} or None.
    """
    if not shutil.which("apk"):
        return None
    try:
        result = subprocess.run(
            ["apk", "info", "--who-owns", filepath],
            capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
            env={**os.environ, "LANG": "C"},
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        # Format: "/usr/bin/python3 is owned by python3-3.11.5-r0"
        token = result.stdout.strip().rsplit(" ", 1)[-1]  # e.g. "python3-3.11.5-r0"
        # Split package name from version: last two hyphen-segments are version
        parts = token.rsplit("-", 2)
        if len(parts) == 3:
            pkg_name = parts[0]
            version  = f"{parts[1]}-{parts[2]}"
        else:
            pkg_name = token
            version  = ""
        if not pkg_name:
            return None
        return {"name": pkg_name, "version": version, "vendor": "Alpine Linux", "source": SOURCE_ELF_BINARY}
    except Exception as exc:
        logger.debug("apk info --who-owns %s failed: %s", filepath, exc)
        return None


def _source_for_path(filepath: str) -> str:
    """Determine ELF source tag from filename."""
    name = os.path.basename(filepath).lower()
    if ".so" in name:
        return SOURCE_ELF_LIB
    return SOURCE_ELF_BINARY


def inspect_elf_file(
    filepath: str,
    cache: Optional[ScanCache] = None,
) -> List[SoftwareItem]:
    """
    Inspect a single ELF file and return SoftwareItems.
    Uses package ownership as the primary data source.
    """
    try:
        st = os.stat(filepath)
        mtime_ns = st.st_mtime_ns
        size_bytes = st.st_size
    except OSError as exc:
        logger.debug("stat failed for %s: %s", filepath, exc)
        return []

    if cache is not None:
        cached = cache.lookup(filepath, mtime_ns, size_bytes)
        if cached is not None:
            return cached

    # Try package ownership — dpkg (Debian/Ubuntu) → rpm (RHEL/Fedora) →
    # pacman (Arch/Manjaro) → apk (Alpine) — first match wins.
    owner = _dpkg_owner(filepath) or _rpm_owner(filepath) or _pacman_owner(filepath) or _apk_owner(filepath)

    if owner:
        item = SoftwareItem(
            name=owner["name"],
            version=owner.get("version", ""),
            vendor=owner.get("vendor", ""),
            source=owner.get("source", SOURCE_ELF_BINARY),
            category="software",
            install_location=os.path.dirname(filepath),
            scan_path=filepath,
        )
        result = [item]
    else:
        # Fallback: use the filename as a minimal identifier
        # Only do this for standalone executables (not .so libraries),
        # and only when we have no package database.
        source = _source_for_path(filepath)
        if source == SOURCE_ELF_LIB:
            # Libraries without a package owner: skip (too many false positives)
            if cache is not None:
                cache.store(filepath, mtime_ns, size_bytes, [], layer=1)
            return []

        name = os.path.splitext(os.path.basename(filepath))[0]
        item = SoftwareItem(
            name=name,
            version="",
            vendor="",
            source=source,
            category="software",
            install_location=os.path.dirname(filepath),
            scan_path=filepath,
        )
        result = [item]

    if cache is not None:
        cache.store(filepath, mtime_ns, size_bytes, result, layer=1)

    return result


class LinuxBinaryInspector(BinaryInspector):
    """Linux implementation of BinaryInspector using package ownership correlation."""

    def inspect_binary(self, filepath: str, cache: Optional[Any] = None) -> List[SoftwareItem]:
        return inspect_elf_file(filepath, cache=cache)
