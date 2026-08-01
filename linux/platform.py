"""
linux/platform.py
─────────────────────────────────────────────────────────────────────────────
Linux Platform composition implementation.
Instantiates all Linux implementations of abstract interfaces.
"""

from __future__ import annotations
from typing import Callable, List, Optional

from common.platform import Platform
from linux.scanner.software_collector import LinuxSoftwareCollector
from linux.scanner.binary_inspector import LinuxBinaryInspector
from linux.scanner.filesystem_walker import LinuxFilesystemWalker
from linux.hardware.hardware_collector import LinuxHardwareCollector
from linux.crypto.secure_store import LinuxSecureStore
from linux.persistence.startup_manager import LinuxPersistenceManager
from linux.protection.process_guard import LinuxProcessGuard
from linux.protection.event_logger import LinuxEventLogger


class LinuxPlatform(Platform):
    """Linux implementation of the Platform container."""

    def __init__(
        self,
        existing_registry_fn: Optional[Callable[[], List[dict]]] = None,
    ):
        # existing_registry_fn is Windows-only; accepted here for interface
        # compatibility with PlatformFactory.create() signature but unused.
        self.software_collector  = LinuxSoftwareCollector()
        self.binary_inspector    = LinuxBinaryInspector()
        self.filesystem_walker   = LinuxFilesystemWalker()
        self.hardware_collector  = LinuxHardwareCollector()
        self.secure_store        = LinuxSecureStore()
        self.persistence_manager = LinuxPersistenceManager()
        self.process_guard       = LinuxProcessGuard()
        self.event_logger        = LinuxEventLogger()
