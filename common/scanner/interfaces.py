"""
common/scanner/interfaces.py
─────────────────────────────────────────────────────────────────────────────
Abstract Base Classes (ABCs) for Endpoint Agent Scanner & Hardware components.
Defines required interface contracts based on existing Windows implementations.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

from common.scanner.models import SoftwareItem


class SoftwareCollector(ABC):
    """Abstract interface for platform-native installed software enumeration."""

    @abstractmethod
    def collect_software(self) -> List[SoftwareItem]:
        """Collect and return installed software items from native OS package databases."""
        ...


class HardwareCollector(ABC):
    """Abstract interface for platform hardware inventory and device fingerprinting."""

    @abstractmethod
    def collect_fingerprint(self) -> Dict[str, Any]:
        """Collect platform-specific raw hardware fingerprint identifiers."""
        ...

    @abstractmethod
    def generate_device_id(self, fingerprint: Dict[str, Any]) -> str:
        """Derive a deterministic device ID string from raw hardware fingerprint."""
        ...

    @abstractmethod
    def get_hardware_inventory(self) -> List[Dict[str, Any]]:
        """Collect hardware components as flat records for inventory reporting."""
        ...

    @abstractmethod
    def get_detailed_hardware_profile(self) -> Dict[str, Any]:
        """Build structured hardware profile matching backend schema."""
        ...


class BinaryInspector(ABC):
    """Abstract interface for inspecting binary metadata (PE / ELF / Mach-O)."""

    @abstractmethod
    def inspect_binary(self, filepath: str, cache: Optional[Any] = None) -> List[SoftwareItem]:
        """Inspect a binary executable/library file and return identified software items."""
        ...


class FilesystemWalker(ABC):
    """Abstract interface for platform drive and filesystem traversal."""

    @abstractmethod
    def walk_drives(self, extra_dirs: Optional[List[str]] = None) -> Generator[Tuple[str, Any], None, None]:
        """Traverse fixed local drives yielding (filepath, entry_kind) tuples."""
        ...


class FileWatcher(ABC):
    """Abstract interface for real-time or polling system change monitoring."""

    @abstractmethod
    def start_monitoring(self, interval: int, callback: Callable[[List[dict], List[dict]], None]) -> None:
        """Start background change monitoring loop."""
        ...

    @abstractmethod
    def stop_monitoring(self) -> None:
        """Stop background change monitoring loop."""
        ...
