"""
windows/hardware/fingerprint.py
─────────────────────────────────────────────────────────────────────────────
Windows hardware fingerprinting and device ID generation.
"""

from __future__ import annotations
import hashlib
import os
import winreg
from typing import Dict


def get_machine_guid() -> str:
    """Reads MachineGuid from HKLM\\SOFTWARE\\Microsoft\\Cryptography."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
        val, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return str(val).strip()
    except Exception:
        return "UNKNOWN_GUID"


def generate_device_id() -> str:
    """Generates a stable hardware device ID for Windows endpoints."""
    guid = get_machine_guid()
    raw = f"win::{guid}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
