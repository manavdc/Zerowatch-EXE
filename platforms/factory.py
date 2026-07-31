"""
platforms/factory.py
─────────────────────────────────────────────────────────────────────────────
Central PlatformFactory responsible for detecting OS platform at runtime
and instantiating the appropriate native Platform container.
"""

from __future__ import annotations
import logging
import sys
from typing import Callable, List, Optional

from common.platform import Platform

logger = logging.getLogger("platforms.factory")


class PlatformFactory:
    """Factory responsible for detecting OS and instantiating the platform container."""

    @staticmethod
    def create(
        existing_registry_fn: Optional[Callable[[], List[dict]]] = None,
    ) -> Platform:
        """
        Detect OS platform and return an initialized Platform instance.

        Supported Platforms:
          - Windows (sys.platform == "win32")

        Extension Points (Future Phases):
          - Linux   (sys.platform.startswith("linux"))
          - macOS   (sys.platform == "darwin")
        """
        plat = sys.platform

        if plat == "win32":
            from windows.platform import WindowsPlatform
            reg_fn = existing_registry_fn or (lambda: [])
            logger.info("Initializing WindowsPlatform for win32 host...")
            return WindowsPlatform(reg_fn)

        elif plat.startswith("linux"):
            # Extension point: LinuxPlatform implementation (Phase 5)
            logger.error("LinuxPlatform selected but not yet implemented.")
            raise NotImplementedError(
                "Linux platform support is scheduled for Phase 5. "
                "LinuxPlatform implementation pending."
            )

        elif plat == "darwin":
            # Extension point: MacPlatform implementation (Phase 5)
            logger.error("MacPlatform selected but not yet implemented.")
            raise NotImplementedError(
                "macOS platform support is scheduled for Phase 5. "
                "MacPlatform implementation pending."
            )

        else:
            raise NotImplementedError(f"Unsupported operating system platform: {plat}")
