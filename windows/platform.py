"""
windows/platform.py
─────────────────────────────────────────────────────────────────────────────
Windows Platform composition implementation.
Instantiates all Windows implementations of abstract interfaces.
"""

from __future__ import annotations
from typing import Callable, List

from common.platform import Platform
from windows.scanner import (
    WindowsSoftwareCollector,
    WindowsBinaryInspector,
    WindowsFilesystemWalker,
)
from windows.crypto import DPAPISecureStore
from windows.protection import WindowsProcessGuard, WindowsEventLogger
from windows.persistence import WindowsPersistenceManager
from windows.hardware import WindowsHardwareCollector


class WindowsPlatform(Platform):
    """Windows implementation of the Platform container."""

    def __init__(self, registry_fn: Callable[[], List[dict]]):
        self.software_collector  = WindowsSoftwareCollector(registry_fn)
        self.binary_inspector    = WindowsBinaryInspector()
        self.filesystem_walker   = WindowsFilesystemWalker()
        self.secure_store        = DPAPISecureStore()
        self.process_guard       = WindowsProcessGuard()
        self.event_logger        = WindowsEventLogger()
        self.persistence_manager = WindowsPersistenceManager()
        self.hardware_collector  = WindowsHardwareCollector()
