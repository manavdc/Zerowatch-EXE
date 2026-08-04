"""
macos/scanner/filesystem_walker.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation of FilesystemWalker interface.
"""

from __future__ import annotations

import logging
from typing import Generator, List, Optional, Tuple

from common.scanner.interfaces import FilesystemWalker
from macos.scanner.fs_walker import walk_filesystem, EntryKind, ScanStats

logger = logging.getLogger("macos.scanner.filesystem_walker")


class MacOSFilesystemWalker(FilesystemWalker):
    """
    macOS implementation of FilesystemWalker.

    Traverses macOS software-relevant filesystem locations yielding
    (filepath, EntryKind) tuples for:
      - Mach-O binaries (EntryKind.BINARY)
      - .dylib dynamic libraries (EntryKind.BINARY)
      - Dependency manifests (EntryKind.MANIFEST)

    Scan roots (checked for existence at walk time):
      System: /Applications, /System/Applications, /Library, /usr/local, /opt
      User:   ~/Applications, ~/Developer, ~/Projects, ~/src, ~/Code, ~/.local
      Volumes: additional local APFS/HFS+ volumes under /Volumes

    Does NOT follow symbolic links (directory symlinks skipped entirely).
    Does NOT attempt to bypass SIP, TCC, or Full Disk Access restrictions.
    Permission-denied directories are silently skipped and counted.
    """

    def __init__(self) -> None:
        self._last_stats: Optional[ScanStats] = None

    def walk_filesystem(
        self,
        extra_dirs: Optional[List[str]] = None,
    ) -> Generator[Tuple[str, EntryKind], None, None]:
        """
        Traverse macOS filesystem locations.

        Args:
            extra_dirs: Additional directories beyond the standard roots.
                        Passed through from the ScanOrchestrator's
                        extra_scan_dirs configuration.

        Yields:
            (filepath, EntryKind) tuples.
        """
        stats = ScanStats()
        self._last_stats = stats
        yield from walk_filesystem(extra_dirs=extra_dirs, stats=stats)

    @property
    def last_scan_stats(self) -> Optional[ScanStats]:
        """Return counters from the most recent walk_filesystem() call."""
        return self._last_stats
