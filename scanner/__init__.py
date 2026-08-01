"""
scanner/__init__.py
─────────────────────────────────────────────────────────────────────────────
Public surface for the scanner package.
Exposes ScanOrchestrator, Windows adapters (on Windows only), and SoftwareItem models.
"""

import sys
from .orchestrator import ScanOrchestrator
from common.scanner.models import (
    SoftwareItem,
    SOURCE_REGISTRY, SOURCE_WINDOWS_STORE, SOURCE_DRIVER,
    SOURCE_PE_BINARY, SOURCE_PE_DLL, SOURCE_PE_SYS,
)

if sys.platform == "win32":
    from .adapters import (
        WindowsSoftwareCollector,
        WindowsBinaryInspector,
        WindowsFilesystemWalker,
    )
    __all__ = [
        "ScanOrchestrator",
        "WindowsSoftwareCollector",
        "WindowsBinaryInspector",
        "WindowsFilesystemWalker",
        "SoftwareItem",
        "SOURCE_REGISTRY",
        "SOURCE_WINDOWS_STORE",
        "SOURCE_DRIVER",
        "SOURCE_PE_BINARY",
        "SOURCE_PE_DLL",
        "SOURCE_PE_SYS",
    ]
else:
    __all__ = [
        "ScanOrchestrator",
        "SoftwareItem",
        "SOURCE_REGISTRY",
        "SOURCE_WINDOWS_STORE",
        "SOURCE_DRIVER",
        "SOURCE_PE_BINARY",
        "SOURCE_PE_DLL",
        "SOURCE_PE_SYS",
    ]
