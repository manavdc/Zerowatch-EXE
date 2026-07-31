"""
scanner/adapters.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation adapters for SoftwareCollector, BinaryInspector,
and FilesystemWalker interfaces.
"""

from __future__ import annotations
import logging
from typing import Any, Callable, Generator, List, Optional, Tuple

from common.scanner.interfaces import (
    SoftwareCollector,
    BinaryInspector,
    FilesystemWalker,
)
from common.scanner.models import SoftwareItem
from .layer0_registry import (
    get_software_from_registry,
    get_windows_store_apps,
    get_driver_inventory,
    get_os_software_item,
)
from .layer1_paths import inspect_pe_file
from .fs_walker import walk_drives

logger = logging.getLogger("scanner.adapters")


class WindowsSoftwareCollector(SoftwareCollector):
    """Windows implementation of SoftwareCollector using Registry, Store AppModel, Drivers & OS APIs."""

    def __init__(self, registry_fn: Callable[[], List[dict]]):
        self._registry_fn = registry_fn

    def collect_software(self) -> List[SoftwareItem]:
        items: List[SoftwareItem] = []
        try:
            items.extend(get_software_from_registry(self._registry_fn))
        except Exception as exc:
            logger.error("Layer 0 registry scan failed: %s", exc)

        try:
            items.extend(get_windows_store_apps())
        except Exception as exc:
            logger.warning("Layer 0 Store scan failed: %s", exc)

        try:
            os_item = get_os_software_item()
            if os_item:
                items.append(os_item)
        except Exception as exc:
            logger.warning("Layer 0 OS version failed: %s", exc)

        try:
            items.extend(get_driver_inventory())
        except Exception as exc:
            logger.warning("Layer 0 driver scan failed: %s", exc)

        return items


class WindowsBinaryInspector(BinaryInspector):
    """Windows implementation of BinaryInspector using Win32 GetFileVersionInfoW PE VersionInfo."""

    def inspect_binary(self, filepath: str, cache: Optional[Any] = None) -> List[SoftwareItem]:
        return inspect_pe_file(filepath, cache=cache)


class WindowsFilesystemWalker(FilesystemWalker):
    """Windows implementation of FilesystemWalker traversing fixed drives via GetLogicalDriveStringsW."""

    def walk_filesystem(self, extra_dirs: Optional[List[str]] = None) -> Generator[Tuple[str, Any], None, None]:
        return walk_drives(extra_dirs=extra_dirs)


def create_default_windows_collectors(registry_fn: Callable[[], List[dict]]) -> tuple[SoftwareCollector, BinaryInspector, FilesystemWalker]:
    """Factory helper to build default Windows collector implementations."""
    return (
        WindowsSoftwareCollector(registry_fn),
        WindowsBinaryInspector(),
        WindowsFilesystemWalker(),
    )
