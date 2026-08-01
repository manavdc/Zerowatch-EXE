"""
linux/protection/process_guard.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of ProcessGuard interface.

Signal handling:
  SIGTERM — Graceful shutdown request (systemd Stop / kill)
  SIGINT  — Keyboard interrupt (Ctrl+C in terminal)
  SIGHUP  — Log rotation / config reload signal (ignored in daemon mode)

Linux vs Windows differences (documented):
  - Linux does NOT have a DACL equivalent for per-process access control.
    apply_process_protection() logs this clearly and returns True so startup
    does not abort — the agent relies on systemd's process isolation instead.
  - Linux does NOT have SetConsoleCtrlHandler. POSIX signals are used instead.
  - Anti-termination hardening on Linux is provided at the service manager level
    (systemd Restart=on-failure) rather than by the process itself.
"""

from __future__ import annotations

import logging
import signal
import threading
from typing import Any

from common.protection.interfaces import ProcessGuard

logger = logging.getLogger("linux.protection.process_guard")

# Global shutdown event shared across threads
_shutdown_event = threading.Event()


def get_shutdown_event() -> threading.Event:
    """Return the shared shutdown event for other threads to poll."""
    return _shutdown_event


class LinuxProcessGuard(ProcessGuard):
    """Linux implementation of ProcessGuard using POSIX signal handlers."""

    def apply_process_protection(self) -> bool:
        """
        Linux has no per-process DACL mechanism.
        Process protection is provided by systemd Restart=on-failure.
        This method logs the difference and returns True (non-fatal).
        """
        logger.info(
            "apply_process_protection: Linux does not support per-process DACL "
            "hardening. Process protection is delegated to systemd "
            "(Restart=on-failure). This is expected behaviour."
        )
        return True

    def register_signal_protection(self) -> Any:
        """
        Install POSIX signal handlers for SIGTERM, SIGINT, and SIGHUP.

        SIGTERM / SIGINT — Set the global shutdown event; the main loop
                           checks this flag and exits cleanly.
        SIGHUP           — Log the event; can be extended for config reload.

        Returns the installed handlers dict for reference.
        """
        def _handle_shutdown(sig: int, frame: Any) -> None:
            sig_name = signal.Signals(sig).name
            logger.info("[SIGNAL] Received %s — requesting graceful shutdown", sig_name)
            _shutdown_event.set()

        def _handle_hup(sig: int, frame: Any) -> None:
            logger.info("[SIGNAL] Received SIGHUP — ignoring in daemon mode")

        try:
            signal.signal(signal.SIGTERM, _handle_shutdown)
            signal.signal(signal.SIGINT,  _handle_shutdown)
            signal.signal(signal.SIGHUP,  _handle_hup)
            logger.info("POSIX signal handlers installed (SIGTERM, SIGINT, SIGHUP)")
        except (OSError, ValueError) as exc:
            # ValueError raised if called from non-main thread
            logger.warning("Signal handler installation failed: %s", exc)

        return {
            "SIGTERM": _handle_shutdown,
            "SIGINT":  _handle_shutdown,
            "SIGHUP":  _handle_hup,
        }

    def verify_kill_code(self, password: str) -> bool:
        # Implemented by ZeroWatchClient.verify_kill (same as Windows)
        return False
