"""
scanner/layer0_registry.py
─────────────────────────────────────────────────────────────────────────────
Layer 0: Authoritative registry-based software discovery.

This layer produces the highest-confidence inventory items because the
Registry Uninstall keys are the canonical source for installed software
on Windows.

WHAT IS COVERED
───────────────
1. Installed software (HKLM + HKCU Uninstall keys, 32-bit and 64-bit)
   → Reuses/wraps the existing get_installed_software_registry() from
     sentinel_agent.py via a thin adapter.  No code is duplicated.

2. Windows Store / UWP apps
   → AppModel registry paths (HKCU + HKLM), zero subprocess.

3. Driver inventory
   → HKLM\SYSTEM\CurrentControlSet\Services — only entries with
     ImagePath pointing to a .sys file are included.

4. OS version
   → A single SoftwareItem capturing the Windows version so the
     backend can map it to the Microsoft:Windows CPE.

DESIGN NOTES
────────────
• All functions are pure registry readers — zero file I/O, zero
  subprocess calls.
• Each function returns List[SoftwareItem] and is independently
  callable so the orchestrator can run them selectively.
• The existing get_installed_software_registry() function is called
  directly via a callable reference injected at construction time.
  This avoids circular imports (layer0 cannot import sentinel_agent)
  while preserving exact parity with the original scan logic.

WINDOWS STORE APP STRATEGY
────────────────────────────
The plan's HKCU AppModel approach is implemented here but with an
important refinement: the package name format used by Windows is
"Publisher.ProductName_Version_Arch__Token", which means we can
extract both product name AND version without WMI or PowerShell.

DRIVER STRATEGY
───────────────
The Services hive contains thousands of entries.  Only those with:
  Start = 0, 1, 2, or 3  (boot, system, auto, demand — excludes disabled)
  ImagePath ending with .sys OR containing \SystemRoot\System32\drivers
are emitted.  The DisplayName or ImagePath basename becomes the `name`.
"""

from __future__ import annotations

import logging
import os
import re
import winreg
from typing import Callable, List, Optional

from .models import (
    SoftwareItem,
    SOURCE_REGISTRY,
    SOURCE_WINDOWS_STORE,
    SOURCE_DRIVER,
)

logger = logging.getLogger("scanner.layer0")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc_now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ).isoformat()


def _reg_str(key_handle, value_name: str) -> str:
    """Read a registry string value; return '' on any error."""
    try:
        return str(winreg.QueryValueEx(key_handle, value_name)[0]).strip()
    except OSError:
        return ""


def _reg_dword(key_handle, value_name: str, default: int = -1) -> int:
    try:
        val, _ = winreg.QueryValueEx(key_handle, value_name)
        return int(val)
    except OSError:
        return default


def _read_reg_key_value(hive, path: str, value: str) -> Optional[str]:
    """Helper to read a single registry value from a given hive + path."""
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        result = _reg_str(key, value)
        winreg.CloseKey(key)
        return result or None
    except OSError:
        return None


# ── 1. Installed software (wraps existing scanner) ────────────────────────────

def get_software_from_registry(
    existing_scanner_fn: Callable[[], List[dict]],
) -> List[SoftwareItem]:
    """
    Wraps the existing get_installed_software_registry() function from
    sentinel_agent.py and converts its output to List[SoftwareItem].

    Parameters
    ──────────
    existing_scanner_fn
        A reference to sentinel_agent.get_installed_software_registry.
        Injected by the orchestrator to avoid circular imports.
    """
    raw = existing_scanner_fn()
    items: List[SoftwareItem] = []
    for d in raw:
        item = SoftwareItem.from_legacy_dict(d)
        if item.is_valid():
            items.append(item)
    logger.debug("Registry scanner: %d software items", len(items))
    return items


# ── 2. Windows Store / UWP apps ───────────────────────────────────────────────

# Pattern: PublisherName.ProductName_Version_Architecture__Token
# e.g.: Microsoft.MicrosoftEdge.Stable_120.0.2210.121_x64__8wekyb3d8bbwe
_STORE_PKG_RE = re.compile(
    r"^(?P<publisher>[^.]+)\.(?P<product>.+?)_"
    r"(?P<version>[\d.]+)_"
    r"(?P<arch>[^_]+)__",
)

_STORE_PATHS = [
    # Per-user packages (most reliable)
    (
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Classes\Local Settings\Software\Microsoft"
        r"\Windows\CurrentVersion\AppModel\Repository\Packages",
    ),
    # Machine-wide packages
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion"
        r"\AppModel\StateRepository\Cache\Package\Index\PackageFamilyName",
    ),
]


def get_windows_store_apps() -> List[SoftwareItem]:
    """
    Discovers UWP / Windows Store applications from the AppModel
    registry hive.  Produces zero subprocess calls.
    """
    items: List[SoftwareItem] = []
    seen: set = set()

    for hive, path in _STORE_PATHS:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except OSError:
            continue

        try:
            count = winreg.QueryInfoKey(key)[0]
            for i in range(count):
                try:
                    pkg_name = winreg.EnumKey(key, i)
                    m = _STORE_PKG_RE.match(pkg_name)
                    if not m:
                        continue

                    product  = m.group("product").replace(".", " ")
                    version  = m.group("version")
                    publisher = m.group("publisher")

                    # Filter Microsoft system framework packages that have no CVE record
                    if publisher.lower() in ("microsoft",) and any(
                        noise in product.lower()
                        for noise in (
                            "vclibs", "directx", "net.native",
                            "vclibsuap", "windowsappruntime",
                            "xaml",
                        )
                    ):
                        continue

                    ident = f"{product.lower()}::{version}"
                    if ident in seen:
                        continue
                    seen.add(ident)

                    items.append(SoftwareItem(
                        name=product,
                        version=version,
                        vendor=publisher,
                        source=SOURCE_WINDOWS_STORE,
                        category="software",
                        last_seen=_utc_now_iso(),
                    ))
                except OSError:
                    pass
        finally:
            winreg.CloseKey(key)

    logger.debug("Windows Store scanner: %d apps", len(items))
    return items


# ── 3. Driver inventory ───────────────────────────────────────────────────────

_SERVICES_PATH = r"SYSTEM\CurrentControlSet\Services"

# Service Start types that indicate an actively loaded driver:
#   0 = Boot, 1 = System, 2 = Auto, 3 = Demand
# We exclude 4 (Disabled) intentionally.
_ACTIVE_START_TYPES = {0, 1, 2, 3}


def get_driver_inventory() -> List[SoftwareItem]:
    """
    Enumerates kernel-mode drivers from the Services registry hive.
    Includes only services with a .sys ImagePath to avoid emitting
    service-process entries (svchost etc.) as "drivers".

    Uses GetFileVersionInfoSizeW to read driver version — same Win32 API
    that Layer 1 uses for PE binaries, keeping the approach consistent.
    """
    items: List[SoftwareItem] = []
    seen: set = set()

    try:
        svc_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            _SERVICES_PATH,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
    except OSError as exc:
        logger.warning("Cannot open Services key: %s", exc)
        return items

    try:
        count = winreg.QueryInfoKey(svc_key)[0]
        for i in range(count):
            try:
                svc_name = winreg.EnumKey(svc_key, i)
                sub = winreg.OpenKey(svc_key, svc_name, 0, winreg.KEY_READ)
                try:
                    start_type = _reg_dword(sub, "Start", -1)
                    if start_type not in _ACTIVE_START_TYPES:
                        continue

                    image_path = _reg_str(sub, "ImagePath")
                    if not image_path:
                        continue

                    # Expand environment variables (%SystemRoot%, etc.)
                    image_path = os.path.expandvars(image_path)

                    # Only kernel .sys drivers
                    low = image_path.lower()
                    if not (low.endswith(".sys") or "\\drivers\\" in low):
                        continue

                    # Prefer DisplayName, fall back to service key name
                    display_name = _reg_str(sub, "DisplayName") or svc_name

                    # Strip leading \SystemRoot\ or similar
                    resolved = _resolve_driver_path(image_path)

                    # Try to read version from the actual .sys file on disk
                    version = _read_pe_file_version(resolved) if resolved else ""

                    ident = f"{display_name.lower()}::{version}"
                    if ident in seen:
                        continue
                    seen.add(ident)

                    items.append(SoftwareItem(
                        name=display_name,
                        version=version,
                        vendor=_read_pe_company_name(resolved) if resolved else "",
                        source=SOURCE_DRIVER,
                        category="driver",
                        install_location=resolved or "",
                        scan_path=resolved or "",
                        last_seen=_utc_now_iso(),
                    ))
                finally:
                    winreg.CloseKey(sub)
            except OSError:
                pass
    finally:
        winreg.CloseKey(svc_key)

    logger.debug("Driver scanner: %d drivers", len(items))
    return items


def _resolve_driver_path(image_path: str) -> Optional[str]:
    """
    Resolve a driver ImagePath to an absolute filesystem path.
    Handles common prefixes: \\SystemRoot\\, \\??\\ , system32\\...
    """
    p = image_path.strip().strip('"')

    # \SystemRoot\ → C:\Windows
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    if p.startswith("\\SystemRoot\\"):
        p = os.path.join(sysroot, p[len("\\SystemRoot\\"):])
    elif p.startswith("System32\\") or p.startswith("system32\\"):
        p = os.path.join(sysroot, p)
    elif p.startswith("\\??\\"):
        p = p[4:]  # Strip NT object prefix

    # Make sure it looks like an absolute path now
    if os.path.isabs(p) and os.path.exists(p):
        return p
    return None


# ── 4. OS version ─────────────────────────────────────────────────────────────

_WINNT_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def get_os_software_item() -> Optional[SoftwareItem]:
    """
    Returns a SoftwareItem representing the OS version, compatible with
    the Microsoft:Windows CPE.

    Reads from the same registry path as the existing get_os_info()
    in sentinel_agent.py (no duplication of logic — we call the same
    keys and expose the result in SoftwareItem format).
    """
    try:
        import sys as _sys
        product_name = (
            _read_reg_key_value(
                winreg.HKEY_LOCAL_MACHINE, _WINNT_PATH, "ProductName"
            )
            or "Windows"
        )
        display_version = (
            _read_reg_key_value(
                winreg.HKEY_LOCAL_MACHINE, _WINNT_PATH, "DisplayVersion"
            )
            or _read_reg_key_value(
                winreg.HKEY_LOCAL_MACHINE, _WINNT_PATH, "ReleaseId"
            )
            or ""
        )
        current_build = (
            _read_reg_key_value(
                winreg.HKEY_LOCAL_MACHINE, _WINNT_PATH, "CurrentBuild"
            )
            or ""
        )
        ubr = (
            _read_reg_key_value(
                winreg.HKEY_LOCAL_MACHINE, _WINNT_PATH, "UBR"
            )
            or ""
        )

        # Full version string: "22H2 (Build 22621.3155)" format
        version_parts = [v for v in [display_version, current_build] if v]
        if ubr:
            version_parts.append(ubr)
        version = ".".join(version_parts) if version_parts else "Unknown"

        return SoftwareItem(
            name="Microsoft Windows",
            version=version,
            vendor="Microsoft",
            source=SOURCE_REGISTRY,
            category="os",
            last_seen=_utc_now_iso(),
        )
    except Exception as exc:
        logger.warning("OS version read failed: %s", exc)
        return None


# ── PE version helpers (shared with layer1) ───────────────────────────────────
# These are defined here so that layer0 (driver scanner) can read version
# info from .sys files without creating a circular dependency on layer1.
# layer1_paths.py imports these from here.

import ctypes
import ctypes.wintypes as wt
import struct


def _read_pe_file_version(filepath: str) -> str:
    """
    Read the FileVersion string from a PE VERSIONINFO resource.
    Uses Win32 VerQueryValueW — single kernel call, reads only the
    VERSIONINFO block, not the full binary.
    Returns '' on any failure.
    """
    try:
        ver_dll = ctypes.windll.version
        size = ver_dll.GetFileVersionInfoSizeW(filepath, None)
        if not size:
            return ""
        data = ctypes.create_string_buffer(size)
        if not ver_dll.GetFileVersionInfoW(filepath, 0, size, data):
            return ""

        # Query fixed-info block for VS_FIXEDFILEINFO
        pfi = ctypes.c_void_p()
        pfi_len = ctypes.c_uint()
        if ver_dll.VerQueryValueW(
            data, "\\", ctypes.byref(pfi), ctypes.byref(pfi_len)
        ):
            # VS_FIXEDFILEINFO layout: dwSignature(4) dwStrucVersion(4)
            # dwFileVersionMS(4) dwFileVersionLS(4) ...
            if pfi_len.value >= 16:
                raw = ctypes.string_at(pfi, pfi_len.value)
                ms = struct.unpack_from("<I", raw, 8)[0]
                ls = struct.unpack_from("<I", raw, 12)[0]
                major = (ms >> 16) & 0xFFFF
                minor = ms & 0xFFFF
                patch = (ls >> 16) & 0xFFFF
                build = ls & 0xFFFF
                return f"{major}.{minor}.{patch}.{build}"
    except Exception:
        pass
    return ""


def _read_pe_string_version(filepath: str, string_name: str) -> str:
    """
    Read a named string from a PE VERSIONINFO StringFileInfo block.
    string_name: 'FileDescription', 'CompanyName', 'ProductName',
                 'ProductVersion', etc.
    Returns '' on any failure.
    """
    try:
        ver_dll = ctypes.windll.version
        size = ver_dll.GetFileVersionInfoSizeW(filepath, None)
        if not size:
            return ""
        data = ctypes.create_string_buffer(size)
        if not ver_dll.GetFileVersionInfoW(filepath, 0, size, data):
            return ""

        sub_block = f"\\StringFileInfo\\040904B0\\{string_name}"
        pval = ctypes.c_wchar_p()
        pval_len = ctypes.c_uint()
        if ver_dll.VerQueryValueW(
            data, sub_block, ctypes.byref(pval), ctypes.byref(pval_len)
        ):
            return (pval.value or "").strip()

        # Fallback: try 040904E4 (common alternative code page)
        sub_block2 = f"\\StringFileInfo\\040904E4\\{string_name}"
        if ver_dll.VerQueryValueW(
            data, sub_block2, ctypes.byref(pval), ctypes.byref(pval_len)
        ):
            return (pval.value or "").strip()
    except Exception:
        pass
    return ""


def _read_pe_company_name(filepath: str) -> str:
    return _read_pe_string_version(filepath, "CompanyName")


def _read_pe_product_name(filepath: str) -> str:
    return _read_pe_string_version(filepath, "ProductName")


def _read_pe_product_version(filepath: str) -> str:
    """
    ProductVersion string is usually more human-readable than
    the numeric FileVersion (e.g. '120.0.6099.130' vs '120.0.6099.130').
    We prefer ProductVersion string; fall back to numeric FileVersion.
    """
    v = _read_pe_string_version(filepath, "ProductVersion")
    if v:
        return v
    return _read_pe_file_version(filepath)
