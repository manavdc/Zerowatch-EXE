"""
macos/protection/event_logger.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation stub of EventLogger interface.
Pending Phase 6B implementation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from common.protection.interfaces import EventLogger

logger = logging.getLogger("macos.protection.event_logger")


class MacOSEventLogger(EventLogger):
    """
    macOS implementation stub of EventLogger interface.

    Planned Phase 6B Strategy:
      - macOS Unified Logging System (`os_log` / `log` stream)
      - ASL / Syslog fallback
    """

    def log_event(self, event_type: str, details: Dict[str, Any]) -> bool:
        raise NotImplementedError("MacOSEventLogger is scheduled for Phase 6B.")

    def log_critical(self, source: str, event_id: int, message: str) -> None:
        raise NotImplementedError("MacOSEventLogger is scheduled for Phase 6B.")
