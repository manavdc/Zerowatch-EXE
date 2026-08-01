"""
common/platform.py
─────────────────────────────────────────────────────────────────────────────
Abstract base container representing an operating system platform contract.
Exposes standard interfaces for software scanning, hardware collection,
secure storage, process defense, signal handling, persistence, and event logging.
"""

from __future__ import annotations
from abc import ABC

from common.scanner.interfaces import (
    SoftwareCollector,
    HardwareCollector,
    BinaryInspector,
    FilesystemWalker,
)
from common.crypto.interfaces import SecureStore
from common.persistence.interfaces import PersistenceManager
from common.protection.interfaces import ProcessGuard, EventLogger


class Platform(ABC):
    """Abstract Base Class representing an operating system platform container."""

    software_collector: SoftwareCollector
    binary_inspector: BinaryInspector
    filesystem_walker: FilesystemWalker
    hardware_collector: HardwareCollector
    secure_store: SecureStore
    persistence_manager: PersistenceManager
    process_guard: ProcessGuard
    event_logger: EventLogger
