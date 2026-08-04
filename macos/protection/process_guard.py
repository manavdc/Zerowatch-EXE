"""
macos/protection/process_guard.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation of ProcessGuard interface.

Platform differences from Windows (explicitly documented):

  apply_process_protection():
    Windows uses Win32 DACL (Discretionary Access Control List) to deny
    PROCESS_TERMINATE permission at the kernel object level.
    macOS has NO equivalent per-process ACL mechanism available to non-kernel
    code. Attempting to simulate this behavior would be misleading.
    Process resilience on macOS is provided at the service-manager level by
    launchd KeepAlive=True — the daemon is automatically restarted by launchd
    if it exits unexpectedly, including after a SIGKILL.
    This method returns True (non-fatal) with a clear log message.
    Startup code must NOT abort if this returns True.
    ── INTERFACE NOTE: This method is architecturally Windows-oriented.
       macOS provides no semantically equivalent mechanism at the process level.
       This is documented here rather than redesigning the shared interface.

  register_signal_protection():
    Darwin is POSIX-compliant. SIGTERM, SIGINT, and SIGHUP are registered
    identically to the Linux implementation.
    Darwin-specific signals (SIGINFO, etc.) are not handled in Phase 6D.
    Signal handlers must be lightweight — no I/O, no network, no filesystem.
    SIGTERM/SIGINT set a threading.Event; the main scan loop polls this event.

  verify_kill_code():
    Not implemented at the platform level on any platform (Windows, Linux, or
    macOS). Authentication is handled by ZeroWatchClient.verify_kill().
    Returns False (consistent with Windows and Linux implementations).

NATIVE VALIDATION: NOT PERFORMED. Signal handler installation is tested with
mocks. Real macOS behavior will be validated on native hardware.
"""

from __future__ import annotations

import logging
import signal
import threading
from typing import Any

from common.protection.interfaces import ProcessGuard

logger = logging.getLogger("macos.protection.process_guard")

# ── Module-level shutdown event (shared across threads) ───────────────────────

_shutdown_event = threading.Event()


def get_shutdown_event() -> threading.Event:
    """
    Return the shared shutdown event.

    Other threads (scan loop, network loop, etc.) should poll:
        while not get_shutdown_event().is_set():
            ...
    This allows a clean, non-abrupt shutdown when SIGTERM or SIGINT is received.
    """
    return _shutdown_event


# ── Signal handlers ───────────────────────────────────────────────────────────

def _handle_shutdown(sig: int, frame: Any) -> None:
    """
    Lightweight SIGTERM/SIGINT handler.
    Only sets the shutdown event — no I/O, no network, no filesystem operations.
    """
    try:
        sig_name = signal.Signals(sig).name
    except (ValueError, AttributeError):
        sig_name = str(sig)
    logger.info("[SIGNAL] Received %s — requesting graceful shutdown", sig_name)
    _shutdown_event.set()


def _handle_hup(sig: int, frame: Any) -> None:
    """
    SIGHUP handler.
    Logged and ignored in daemon mode. Can be extended for config reload.
    SIGHUP has no standard meaning on macOS outside of terminal hangup.
    launchd does not send SIGHUP for normal lifecycle events.
    """
    logger.info("[SIGNAL] Received SIGHUP — ignoring in daemon mode")


# ── Signal installation ───────────────────────────────────────────────────────

def install_signal_handlers() -> dict:
    """
    Install POSIX signal handlers for SIGTERM, SIGINT, and SIGHUP.

    Darwin supports the full POSIX signal set. These three are the most
    relevant for a background daemon:
      SIGTERM — standard termination request (launchd Stop, `kill`)
      SIGINT  — keyboard interrupt (Ctrl+C in terminal during development)
      SIGHUP  — terminal hangup / ignored in daemon context

    Returns a dict of {signal_name: handler} for reference.
    Raises ValueError (from signal.signal) if called from a non-main thread.
    This is caught and logged rather than propagated.
    """
    handlers = {}
    try:
        signal.signal(signal.SIGTERM, _handle_shutdown)
        handlers["SIGTERM"] = _handle_shutdown

        signal.signal(signal.SIGINT, _handle_shutdown)
        handlers["SIGINT"] = _handle_shutdown

        # SIGHUP is POSIX/Darwin only — not available on Windows
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, _handle_hup)
            handlers["SIGHUP"] = _handle_hup

        logger.info("macOS POSIX signal handlers installed (SIGTERM, SIGINT%s)",
                    ", SIGHUP" if hasattr(signal, "SIGHUP") else "")
    except (OSError, ValueError) as exc:
        # ValueError: signal only callable from the main thread
        logger.warning(
            "Signal handler installation failed (may be a non-main thread): %s", exc
        )

    return handlers


# ── MacOSProcessGuard ─────────────────────────────────────────────────────────

class MacOSProcessGuard(ProcessGuard):
    """
    macOS implementation of ProcessGuard.

    apply_process_protection():
        No-op (documented). Returns True. macOS process hardening is provided
        by launchd KeepAlive rather than per-process ACL.

    register_signal_protection():
        Installs POSIX signal handlers: SIGTERM → shutdown event, SIGINT →
        shutdown event, SIGHUP → ignored.

    verify_kill_code():
        Returns False. Backend authentication is handled by ZeroWatchClient.
    """

    def __init__(self) -> None:
        self._handlers: dict = {}
        self._handlers_installed = False

    def apply_process_protection(self) -> bool:
        """
        macOS has no per-process DACL/ACL mechanism equivalent to Windows.
        Process resilience is provided by launchd KeepAlive=True in the
        LaunchDaemon plist.

        This method returns True (non-fatal) so that startup code which calls
        apply_process_protection() does not abort on macOS.

        ── INTERFACE NOTE ────────────────────────────────────────────────────
        The ProcessGuard.apply_process_protection() contract is semantically
        Windows-specific (Win32 DACL). On macOS and Linux, it is documented
        as a no-op that returns True. This is intentional and consistent with
        the Linux implementation. Do not redesign the shared interface based
        on this finding.
        ────────────────────────────────────────────────────────────────────
        """
        logger.info(
            "apply_process_protection: macOS does not support per-process DACL "
            "hardening. Process protection is delegated to launchd "
            "(KeepAlive=True in LaunchDaemon plist). This is expected behaviour."
        )
        return True

    def register_signal_protection(self) -> Any:
        """
        Install POSIX signal handlers on Darwin.

        If already installed, this method returns the existing handlers without
        re-registering (idempotent).

        Returns the handlers dict for reference by callers.
        """
        if self._handlers_installed:
            logger.debug("Signal handlers already installed — skipping re-registration")
            return self._handlers

        self._handlers = install_signal_handlers()
        self._handlers_installed = bool(self._handlers)
        return self._handlers

    def verify_kill_code(self, password: str) -> bool:
        """
        Not implemented at the platform level.
        Authentication is performed by ZeroWatchClient.verify_kill().
        Consistent with Windows and Linux implementations (both return False).
        """
        return False
