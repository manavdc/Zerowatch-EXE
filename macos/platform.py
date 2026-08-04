"""
macos/platform.py
─────────────────────────────────────────────────────────────────────────────
macOS Platform composition implementation.
Instantiates macOS implementations of abstract interfaces.

Phase 6E Status:
  ✅ software_collector   — functional (app bundles, pkgutil, Homebrew, MacPorts, OS)
  ✅ hardware_collector   — functional (sysctl, platform.mac_ver, system_profiler GPU)
  ✅ binary_inspector     — functional (Mach-O static inspection, ownership hierarchy)
  ✅ filesystem_walker    — functional (curated roots, Mach-O detection, symlink safety)
  ✅ persistence_manager  — functional (launchd LaunchDaemon plist, bootstrap/bootout)
  ✅ process_guard        — functional (POSIX SIGTERM/SIGINT/SIGHUP, shutdown event)
  ✅ event_logger         — functional (Python logging + syslog/ASL, injection safety)
  ✅ secure_store         — implementation complete (Keychain tagged-reference design)
                            ❗ NATIVE VALIDATION REQUIRED before production use

NOTE: PlatformFactory darwin branch remains DISABLED (raises NotImplementedError).
      Implementation complete ≠ production ready.
      All capabilities must be validated on real macOS hardware before activation.

NATIVE VALIDATION NOT PERFORMED:
  - launchctl bootstrap/bootout
  - launchd Keychain access (LaunchDaemon context)
  - System keychain accessibility and unlock behavior
  - syslog/ASL routing on macOS Ventura/Sonoma
  - POSIX signal delivery under launchd
  - Keychain UI prompt behavior
  - SIP/TCC filesystem permissions
  All will be validated during Phase 6F (Native macOS Validation).
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

    Phase 6E: All components are now implemented.
    secure_store uses the tagged-reference Keychain design.
    All components require native macOS hardware validation before production.
    """

    def __init__(
        self,
        existing_registry_fn: Optional[Callable[[], List[dict]]] = None,
    ):
        # existing_registry_fn is Windows-only; accepted for interface
        # compatibility with PlatformFactory.create() signature but unused on macOS.
        self.software_collector  = MacOSSoftwareCollector()
        self.binary_inspector    = MacOSBinaryInspector()
        self.filesystem_walker   = MacOSFilesystemWalker()
        self.hardware_collector  = MacOSHardwareCollector()
        self.secure_store        = MacOSSecureStore()          # ✅ Phase 6E
        self.persistence_manager = MacOSPersistenceManager()   # ✅ Phase 6D
        self.process_guard       = MacOSProcessGuard()         # ✅ Phase 6D
        self.event_logger        = MacOSEventLogger()          # ✅ Phase 6D
