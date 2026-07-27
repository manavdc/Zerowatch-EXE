"""
scanner/__init__.py
─────────────────────────────────────────────────────────────────────────────
Public surface for the scanner package.

Only the orchestrator is exposed here.  Callers in sentinel_agent.py
import ScanOrchestrator and nothing else; all inner modules are
considered private implementation details.
"""

from .orchestrator import ScanOrchestrator
from .models import (
    SoftwareItem,
    SOURCE_REGISTRY, SOURCE_WINDOWS_STORE, SOURCE_DRIVER,
    SOURCE_PE_BINARY, SOURCE_PE_DLL, SOURCE_PE_SYS,
)

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
