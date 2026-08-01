"""
windows/persistence/startup_manager.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation of PersistenceManager interface.
Implements Windows Registry Run keys (HKLM/HKCU) and Task Scheduler (schtasks) registration.
"""

from __future__ import annotations
import logging
import os
import subprocess
import winreg
from typing import List, Optional

from common.persistence.interfaces import PersistenceManager

logger = logging.getLogger("windows.persistence.startup")


def register_startup_registry(exe_path: str, daemon_cmd: str = "--daemon") -> bool:
    """Adds SentinelAgent to Registry Run keys (HKLM first, fallback to HKCU)."""
    cmd_str = f'"{exe_path}" {daemon_cmd}'.strip()
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(
            key,
            "SentinelAgent",
            0,
            winreg.REG_SZ,
            cmd_str,
        )
        winreg.CloseKey(key)
        logger.info("Registry startup registered (HKLM): %s", exe_path)
        return True
    except Exception as e:
        logger.warning("HKLM startup registration failed: %s", e)

    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(
            key,
            "SentinelAgent",
            0,
            winreg.REG_SZ,
            cmd_str,
        )
        winreg.CloseKey(key)
        logger.info("Registry startup registered (HKCU): %s", exe_path)
        return True
    except Exception as e:
        logger.warning("HKCU startup registration failed: %s", e)
        return False


def unregister_startup_registry() -> bool:
    """Removes SentinelAgent from Registry Run keys."""
    success = False
    for hive, path in [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "SentinelAgent")
            winreg.CloseKey(key)
            success = True
        except Exception:
            pass
    return success


class WindowsPersistenceManager(PersistenceManager):
    """Windows implementation of PersistenceManager interface."""

    def register_startup(self, exe_path: str, daemon_args: Optional[List[str]] = None) -> bool:
        daemon_cmd = " ".join(daemon_args) if daemon_args else "--daemon"
        return register_startup_registry(exe_path, daemon_cmd=daemon_cmd)

    def unregister_startup(self) -> bool:
        return unregister_startup_registry()

    def is_persistence_active(self) -> bool:
        for hive, path in [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ]:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                winreg.QueryValueEx(key, "SentinelAgent")
                winreg.CloseKey(key)
                return True
            except Exception:
                pass
        return False
