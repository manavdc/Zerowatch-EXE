"""
windows/scanner package
Windows-specific scanner collectors, binary inspectors, and drive walkers.
"""

from .software_collector import WindowsSoftwareCollector
from .binary_inspector import WindowsBinaryInspector
from .filesystem_walker import WindowsFilesystemWalker
from .layer0_registry import (
    get_software_from_registry,
    get_windows_store_apps,
    get_driver_inventory,
    get_os_software_item,
)
from .layer1_paths import inspect_pe_file
from .fs_walker import walk_drives, EntryKind

__all__ = [
    "WindowsSoftwareCollector",
    "WindowsBinaryInspector",
    "WindowsFilesystemWalker",
    "get_software_from_registry",
    "get_windows_store_apps",
    "get_driver_inventory",
    "get_os_software_item",
    "inspect_pe_file",
    "walk_drives",
    "EntryKind",
]
