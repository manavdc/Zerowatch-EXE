"""
common/protection/interfaces.py
─────────────────────────────────────────────────────────────────────────────
Abstract Base Classes for Process Self-Defense, Termination Guarding,
and OS Audit Event Logging.
All methods describe abstract system capabilities rather than platform-specific mechanics.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class ProcessGuard(ABC):
    """Abstract interface for process termination hardening, signal interception, and kill verification."""

    @abstractmethod
    def apply_process_protection(self) -> bool:
        """Harden process memory/handle access permissions to impede unauthorized termination."""
        ...

    @abstractmethod
    def register_signal_protection(self) -> Any:
        """Intercept system termination signals (e.g. SIGINT/SIGTERM or Windows CTRL events)."""
        ...

    @abstractmethod
    def verify_kill_code(self, password: str) -> bool:
        """Validate administrative termination password against backend/local authority."""
        ...


class EventLogger(ABC):
    """Abstract interface for security event logging and OS audit sinks."""

    @abstractmethod
    def log_event(self, event_type: str, details: Dict[str, Any]) -> bool:
        """Log structured security audit event."""
        ...

    @abstractmethod
    def log_critical(self, source: str, event_id: int, message: str) -> None:
        """Write critical event entry to OS audit log / system event subsystem."""
        ...
