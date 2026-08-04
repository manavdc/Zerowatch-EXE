"""
macos/scanner/binary_inspector.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation stub of BinaryInspector interface.
Pending Phase 6B implementation.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from common.scanner.interfaces import BinaryInspector
from common.scanner.models import SoftwareItem

logger = logging.getLogger("macos.scanner.binary_inspector")


class MacOSBinaryInspector(BinaryInspector):
    """
    macOS implementation stub of BinaryInspector.

    Planned Phase 6B strategy:
      - Inspect Mach-O binaries and dynamic libraries (.dylib)
      - Correlate with pkgutil --file-info
      - Extract code signature / bundle identifiers via codesign
    """

    def inspect_binary(self, filepath: str, cache: Optional[Any] = None) -> List[SoftwareItem]:
        raise NotImplementedError("MacOSBinaryInspector is scheduled for Phase 6B.")
