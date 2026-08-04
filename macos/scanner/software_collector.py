"""
macos/scanner/software_collector.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation of SoftwareCollector interface.
Aggregates all package-manager and application-layer collectors.
"""

from __future__ import annotations

import logging
from typing import List

from common.scanner.interfaces import SoftwareCollector
from common.scanner.models import SoftwareItem
from macos.scanner.package_collector import (
    collect_app_bundles,
    collect_pkgutil,
    collect_homebrew,
    collect_macports,
    collect_os_release,
)

logger = logging.getLogger("macos.scanner.software_collector")


class MacOSSoftwareCollector(SoftwareCollector):
    """
    macOS implementation of SoftwareCollector.

    Collects installed software from all available macOS sources:
      - Application bundles (/Applications, /System/Applications, ~/Applications)
      - Package receipts (pkgutil)
      - Homebrew formulae & casks (optional — skipped if not installed)
      - MacPorts ports (optional — skipped if not installed)
      - macOS operating system version

    Each collector fails independently — a Homebrew failure does not
    prevent application bundle or pkgutil results from being returned.

    Deduplication:
      The shared SoftwareItem.dedup_key() is used by the orchestrator
      at a higher level. The collectors here do not perform their own
      deduplication — that would require knowledge of source priority
      rankings that belong to the orchestrator layer.
    """

    def collect_software(self) -> List[SoftwareItem]:
        items: List[SoftwareItem] = []

        collectors = [
            ("app_bundles", collect_app_bundles),
            ("pkgutil",     collect_pkgutil),
            ("homebrew",    collect_homebrew),
            ("macports",    collect_macports),
            ("os_release",  collect_os_release),
        ]

        for name, fn in collectors:
            try:
                result = fn()
                items.extend(result)
                if result:
                    logger.debug("[%s] collected %d items", name, len(result))
            except Exception as exc:
                logger.warning(
                    "macOS software collector [%s] failed: %s", name, exc
                )

        logger.info(
            "MacOSSoftwareCollector: %d total software items collected", len(items)
        )
        return items
