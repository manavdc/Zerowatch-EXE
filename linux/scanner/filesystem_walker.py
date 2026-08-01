"""
linux/scanner/filesystem_walker.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of FilesystemWalker interface.
"""

from __future__ import annotations

import logging
from typing import Generator, List, Optional, Tuple

from common.scanner.interfaces import FilesystemWalker
from linux.scanner.fs_walker import walk_filesystem, EntryKind

logger = logging.getLogger("linux.scanner.filesystem_walker")


class LinuxFilesystemWalker(FilesystemWalker):
    """
    Linux implementation of FilesystemWalker.
    Traverses all real local filesystem mounts, yielding vulnerability-relevant
    ELF binaries, shared libraries, and dependency manifests.
    """

    def walk_filesystem(
        self,
        extra_dirs: Optional[List[str]] = None,
    ) -> Generator[Tuple[str, EntryKind], None, None]:
        yield from walk_filesystem(extra_dirs=extra_dirs)
