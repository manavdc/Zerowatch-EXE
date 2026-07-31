"""
scanner/__init__.py
─────────────────────────────────────────────────────────────────────────────
Public surface for the scanner package.
Exposes ScanOrchestrator, Windows adapters, and SoftwareItem models.
"""

from .orchestrator import ScanOrchestrator
from .adapters import (
    WindowsSoftwareCollector,
    WindowsBinaryInspector,
    WindowsFilesystemWalker,
)
from common.scanner.models import (
    SoftwareItem,
    SOURCE_REGISTRY, SOURCE_WINDOWS_STORE, SOURCE_DRIVER,
    SOURCE_PE_BINARY, SOURCE_PE_DLL, SOURCE_PE_SYS,
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
