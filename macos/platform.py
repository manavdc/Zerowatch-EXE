"""
macos/platform.py
─────────────────────────────────────────────────────────────────────────────
macOS Platform composition implementation.
Instantiates macOS implementations of abstract interfaces.

Phase 6B Status:
  ✅ software_collector  — functional (app bundles, pkgutil, Homebrew, MacPorts, OS)
  ✅ hardware_collector  — functional (sysctl, platform.mac_ver, system_profiler GPU)
  ❌ binary_inspector    — future (Mach-O / pkgutil --file-info)
  ❌ filesystem_walker   — future (APFS volume traversal)
  ❌ secure_store        — future (macOS Keychain)
  ❌ persistence_manager — future (launchd plist)
  ❌ process_guard       — future (POSIX signals on Darwin)
  ❌ event_logger        — future (macOS Unified Logging / os_log)

NOTE: PlatformFactory darwin branch remains DISABLED (raises NotImplementedError)
until all capabilities required by normal ZeroWatch agent startup are implemented.
"""

from __future__ import annotations
from typing import Callable, List, Optional

from common.platform import Platform
from macos.scanner.software_collector import MacOSSoftwareCollector
from macos.scanner.binary_inspector import MacOSBinaryInspector
from macos.scanner.filesystem_walker import MacOSFilesystemWalker
from macos.hardware.hardware_collector import MacOSHardwareCollector
from macos.crypto.secure_store import MacOSSecureStore
from macos.persistence.startup_manager import MacOSPersistenceManager
from macos.protection.process_guard import MacOSProcessGuard
from macos.protection.event_logger import MacOSEventLogger


class MacOSPlatform(Platform):
    """
    macOS implementation of the Platform container interface.

    Phase 6B wires software_collector and hardware_collector as functional.
    All other components remain NotImplementedError stubs.
    """

    def __init__(
        self,
        existing_registry_fn: Optional[Callable[[], List[dict]]] = None,
    ):
        # existing_registry_fn is Windows-only; accepted here for interface
        # compatibility with PlatformFactory.create() signature but unused on macOS.
        self.software_collector  = MacOSSoftwareCollector()
        self.binary_inspector    = MacOSBinaryInspector()
        self.filesystem_walker   = MacOSFilesystemWalker()
        self.hardware_collector  = MacOSHardwareCollector()
        self.secure_store        = MacOSSecureStore()
        self.persistence_manager = MacOSPersistenceManager()
        self.process_guard       = MacOSProcessGuard()
        self.event_logger        = MacOSEventLogger()
