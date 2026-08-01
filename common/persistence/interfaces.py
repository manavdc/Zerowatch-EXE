"""
common/persistence/interfaces.py
─────────────────────────────────────────────────────────────────────────────
Abstract Base Class for agent startup persistence mechanisms.
Defines required registration and unregistration interfaces.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Optional


class PersistenceManager(ABC):
    """Abstract interface for auto-start boot persistence (Run Key / Task Scheduler / systemd / launchd)."""

    @abstractmethod
    def register_startup(self, exe_path: str, daemon_args: Optional[List[str]] = None) -> bool:
        """Register agent executable for automatic startup on system boot / user logon."""
        ...

    @abstractmethod
    def unregister_startup(self) -> bool:
        """Remove agent executable from system automatic startup mechanisms."""
        ...
