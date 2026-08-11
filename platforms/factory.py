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
    _cached_platform: Optional[Platform] = None

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
        if PlatformFactory._cached_platform is not None:
            return PlatformFactory._cached_platform

        plat = sys.platform

        if plat == "win32":
            from windows.platform import WindowsPlatform
            reg_fn = existing_registry_fn or (lambda: [])
            logger.info("Initializing WindowsPlatform for win32 host...")
            PlatformFactory._cached_platform = WindowsPlatform(reg_fn)
            return PlatformFactory._cached_platform

        elif plat.startswith("linux"):
            from linux.platform import LinuxPlatform
            logger.info("Initializing LinuxPlatform for linux host...")
            PlatformFactory._cached_platform = LinuxPlatform(existing_registry_fn or (lambda: []))
            return PlatformFactory._cached_platform

        elif plat == "darwin":
            from macos.platform import MacOSPlatform
            logger.info("Initializing MacOSPlatform for darwin host...")
            PlatformFactory._cached_platform = MacOSPlatform(existing_registry_fn or (lambda: []))
            return PlatformFactory._cached_platform

        else:
            raise NotImplementedError(f"Unsupported operating system platform: {plat}")

