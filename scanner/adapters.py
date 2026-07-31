"""
scanner/adapters.py
─────────────────────────────────────────────────────────────────────────────
FORWARDING WRAPPER FOR BACKWARD COMPATIBILITY
Relocated to windows.scanner.
"""

from typing import Callable, List
from common.scanner.interfaces import SoftwareCollector, BinaryInspector, FilesystemWalker
from windows.scanner import (
    WindowsSoftwareCollector,
    WindowsBinaryInspector,
    WindowsFilesystemWalker,
)


def create_default_windows_collectors(registry_fn: Callable[[], List[dict]]) -> tuple[SoftwareCollector, BinaryInspector, FilesystemWalker]:
    """Factory helper to build default Windows collector implementations."""
    return (
        WindowsSoftwareCollector(registry_fn),
        WindowsBinaryInspector(),
        WindowsFilesystemWalker(),
    )


__all__ = [
    "WindowsSoftwareCollector",
    "WindowsBinaryInspector",
    "WindowsFilesystemWalker",
    "create_default_windows_collectors",
]
