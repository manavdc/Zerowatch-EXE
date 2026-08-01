"""
windows/scanner/software_collector.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation of SoftwareCollector interface.
"""

from __future__ import annotations
import logging
from typing import Callable, List

from common.scanner.interfaces import SoftwareCollector
from common.scanner.models import SoftwareItem
from windows.scanner.layer0_registry import (
    get_software_from_registry,
    get_windows_store_apps,
    get_driver_inventory,
    get_os_software_item,
)

logger = logging.getLogger("windows.scanner.software_collector")


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
