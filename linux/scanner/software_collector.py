"""
linux/scanner/software_collector.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of SoftwareCollector interface.
Aggregates all package-manager and OS-layer collectors.
"""

from __future__ import annotations

import logging
from typing import List

from common.scanner.interfaces import SoftwareCollector
from common.scanner.models import SoftwareItem
from linux.scanner.package_collector import (
    collect_dpkg,
    collect_rpm,
    collect_pacman,
    collect_snap,
    collect_flatpak,
    collect_kernel_modules,
    collect_os_release,
)

logger = logging.getLogger("linux.scanner.software_collector")


class LinuxSoftwareCollector(SoftwareCollector):
    """
    Linux implementation of SoftwareCollector.

    Collects installed software from all available package managers:
      - dpkg  (Debian / Ubuntu / Mint)
      - rpm   (RHEL / Fedora / Rocky / SUSE)
      - pacman (Arch / Manjaro)
      - snap
      - flatpak
      - kernel modules (/proc/modules)
      - OS release (/etc/os-release)

    Each collector fails silently if the package manager is absent.
    """

    def collect_software(self) -> List[SoftwareItem]:
        items: List[SoftwareItem] = []

        collectors = [
            ("dpkg",           collect_dpkg),
            ("rpm",            collect_rpm),
            ("pacman",         collect_pacman),
            ("snap",           collect_snap),
            ("flatpak",        collect_flatpak),
            ("kernel_modules", collect_kernel_modules),
            ("os_release",     collect_os_release),
        ]

        for name, fn in collectors:
            try:
                result = fn()
                items.extend(result)
                if result:
                    logger.debug("[%s] collected %d items", name, len(result))
            except Exception as exc:
                logger.warning("Layer 0 [%s] collection failed: %s", name, exc)

        logger.info("LinuxSoftwareCollector: %d total software items collected", len(items))
        return items
