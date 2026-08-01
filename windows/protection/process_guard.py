"""
windows/protection/process_guard.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation of ProcessGuard interface.
Implements win32security DACL process hardening and SetConsoleCtrlHandler signal protection.
"""

from __future__ import annotations
import ctypes
import logging
import os
import signal
from typing import Any

from common.protection.interfaces import ProcessGuard

logger = logging.getLogger("windows.protection.process_guard")


def harden_process_acl() -> bool:
    """Denies PROCESS_TERMINATE permission for Everyone on the current process."""
    try:
        import win32security
        import ntsecuritycon as con
        import win32api
        import win32con

        handle = win32api.OpenProcess(
            win32con.PROCESS_ALL_ACCESS, False, os.getpid()
        )
        sd = win32security.GetSecurityInfo(
            handle, win32security.SE_KERNEL_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()

        everyone = win32security.CreateWellKnownSid(
            win32security.WinWorldSid, None
        )

        dacl.AddAccessDeniedAce(
            win32security.ACL_REVISION,
            getattr(con, "PROCESS_TERMINATE", 0x0001),
            everyone
        )

        win32security.SetSecurityInfo(
            handle, win32security.SE_KERNEL_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None, None, dacl, None
        )
        logger.info("DACL hardening applied — PROCESS_TERMINATE denied for Everyone.")
        return True
    except ImportError:
        logger.warning("pywin32 not available — DACL hardening SKIPPED.")
        return False
    except Exception as e:
        logger.warning("DACL hardening failed: %s", e)
        return False


def install_ctrl_handler() -> Any:
    """Intercepts Ctrl+C, Ctrl+Break, console close, logoff, and shutdown events."""
    HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

    @HandlerRoutine
    def _ctrl_handler(event):
        CTRL_C = 0; CTRL_BREAK = 1; CTRL_CLOSE = 2; CTRL_LOGOFF = 5; CTRL_SHUTDOWN = 6
        if event in (CTRL_C, CTRL_BREAK, CTRL_CLOSE, CTRL_LOGOFF, CTRL_SHUTDOWN):
            logger.info("Console control event %s intercepted. Suppressing.", event)
            return True
        return False

    ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler, True)
    signal.signal(signal.SIGINT, lambda *_: None)
    signal.signal(signal.SIGTERM, lambda *_: None)

    logger.info("Console Ctrl handler and signal handlers installed.")
    return _ctrl_handler


class WindowsProcessGuard(ProcessGuard):
    """Windows implementation of ProcessGuard interface."""

    def apply_process_protection(self) -> bool:
        return harden_process_acl()

    def register_signal_protection(self) -> Any:
        return install_ctrl_handler()

    def verify_kill_code(self, password: str) -> bool:
        # Implemented by ZeroWatchClient.verify_kill
        return False
