"""
windows/scanner/layer0_registry.py
─────────────────────────────────────────────────────────────────────────────
Layer 0: Windows Registry & Store App software discovery.
Contains all Win32 registry reading and driver enumeration logic.
"""

from __future__ import annotations

import logging
import os
import re
import winreg
from typing import Callable, List, Optional

from common.scanner.models import (
    SoftwareItem,
    SOURCE_REGISTRY,
    SOURCE_WINDOWS_STORE,
    SOURCE_DRIVER,
)
from common.utils.time_ import utc_now_iso

logger = logging.getLogger("windows.scanner.layer0")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _reg_str(key_handle, value_name: str) -> str:
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
    raw = existing_scanner_fn()
    items: List[SoftwareItem] = []
    for d in raw:
        item = SoftwareItem.from_legacy_dict(d)
        if item.is_valid():
            items.append(item)
    logger.debug("Registry scanner: %d software items", len(items))
    return items


# ── 2. Windows Store / UWP apps ───────────────────────────────────────────────

_STORE_PKG_RE = re.compile(
    r"^(?P<publisher>[^.]+)\.(?P<product>.+?)_"
    r"(?P<version>[\d.]+)_"
    r"(?P<arch>[^_]+)__",
)

_STORE_PATHS = [
    (
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Classes\Local Settings\Software\Microsoft"
        r"\Windows\CurrentVersion\AppModel\Repository\Packages",
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion"
        r"\AppModel\StateRepository\Cache\Package\Index\PackageFamilyName",
    ),
]


def get_windows_store_apps() -> List[SoftwareItem]:
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
                        last_seen=utc_now_iso(),
                    ))
                except OSError:
                    pass
        finally:
            winreg.CloseKey(key)

    logger.debug("Windows Store scanner: %d apps", len(items))
    return items


# ── 3. Driver inventory ───────────────────────────────────────────────────────

_SERVICES_PATH = r"SYSTEM\CurrentControlSet\Services"
_ACTIVE_START_TYPES = {0, 1, 2, 3}


def get_driver_inventory() -> List[SoftwareItem]:
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

                    image_path = os.path.expandvars(image_path)
                    low = image_path.lower()
                    if not (low.endswith(".sys") or "\\drivers\\" in low):
                        continue

                    display_name = _reg_str(sub, "DisplayName") or svc_name
                    resolved = _resolve_driver_path(image_path)
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
                        last_seen=utc_now_iso(),
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
    p = image_path.strip().strip('"')
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    if p.startswith("\\SystemRoot\\"):
        p = os.path.join(sysroot, p[len("\\SystemRoot\\"):])
    elif p.startswith("System32\\") or p.startswith("system32\\"):
        p = os.path.join(sysroot, p)
    elif p.startswith("\\??\\"):
        p = p[4:]

    if os.path.isabs(p) and os.path.exists(p):
        return p
    return None


# ── 4. OS version ─────────────────────────────────────────────────────────────

_WINNT_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def get_os_software_item() -> Optional[SoftwareItem]:
    try:
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
            last_seen=utc_now_iso(),
        )
    except Exception as exc:
        logger.warning("OS version read failed: %s", exc)
        return None


# ── PE version helpers (shared with layer1) ───────────────────────────────────

import ctypes
import ctypes.wintypes as wt
import struct


def _read_pe_file_version(filepath: str) -> str:
    try:
        ver_dll = ctypes.windll.version
        size = ver_dll.GetFileVersionInfoSizeW(filepath, None)
        if not size:
            return ""
        data = ctypes.create_string_buffer(size)
        if not ver_dll.GetFileVersionInfoW(filepath, 0, size, data):
            return ""

        pfi = ctypes.c_void_p()
        pfi_len = ctypes.c_uint()
        if ver_dll.VerQueryValueW(
            data, "\\", ctypes.byref(pfi), ctypes.byref(pfi_len)
        ):
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
    v = _read_pe_string_version(filepath, "ProductVersion")
    if v:
        return v
    return _read_pe_file_version(filepath)
