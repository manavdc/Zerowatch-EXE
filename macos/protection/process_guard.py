"""
macos/protection/process_guard.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation stub of ProcessGuard interface.
Pending Phase 6B implementation.

Note: Kept strictly as a stub per Phase 6A directives. POSIX signal handling
portability will be evaluated in Phase 6B.
"""

from __future__ import annotations

import logging
from typing import Any

from common.protection.interfaces import ProcessGuard

logger = logging.getLogger("macos.protection.process_guard")


class MacOSProcessGuard(ProcessGuard):
    """macOS implementation stub of ProcessGuard interface."""

    def apply_process_protection(self) -> bool:
        raise NotImplementedError("MacOSProcessGuard is scheduled for Phase 6B.")

    def register_signal_protection(self) -> Any:
        raise NotImplementedError("MacOSProcessGuard is scheduled for Phase 6B.")

    def verify_kill_code(self, password: str) -> bool:
        raise NotImplementedError("MacOSProcessGuard is scheduled for Phase 6B.")
