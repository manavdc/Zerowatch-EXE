"""
macos/scanner/filesystem_walker.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation stub of FilesystemWalker interface.
Pending Phase 6B implementation.
"""

from __future__ import annotations

import logging
from typing import Generator, List, Optional, Tuple

from common.scanner.interfaces import FilesystemWalker

logger = logging.getLogger("macos.scanner.filesystem_walker")


class MacOSFilesystemWalker(FilesystemWalker):
    """
    macOS implementation stub of FilesystemWalker.

    Planned Phase 6B traversal strategy:
      - Traverses mounted local volumes (apfs, hfs)
      - Skips virtual/dev mount points (/dev, /System/Volumes/Data/dev)
      - Identifies Mach-O binaries, .dylib, .framework, and manifest files
      - Respects macOS privacy/TCC and SIP boundaries where restricted
    """

    def walk_filesystem(
        self,
        extra_dirs: Optional[List[str]] = None,
    ) -> Generator[Tuple[str, Any], None, None]:
        raise NotImplementedError("MacOSFilesystemWalker is scheduled for Phase 6B.")
        yield  # type: ignore[unreachable]
