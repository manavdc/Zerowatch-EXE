"""
windows/scanner/filesystem_walker.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation of FilesystemWalker interface.
"""

from __future__ import annotations
import logging
from typing import Any, Generator, List, Optional, Tuple

from common.scanner.interfaces import FilesystemWalker
from windows.scanner.fs_walker import walk_drives

logger = logging.getLogger("windows.scanner.filesystem_walker")


class WindowsFilesystemWalker(FilesystemWalker):
    """Windows implementation of FilesystemWalker traversing fixed drives via GetLogicalDriveStringsW."""

    def walk_filesystem(self, extra_dirs: Optional[List[str]] = None) -> Generator[Tuple[str, Any], None, None]:
        return walk_drives(extra_dirs=extra_dirs)
