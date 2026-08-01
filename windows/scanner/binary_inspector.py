"""
windows/scanner/binary_inspector.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation of BinaryInspector interface.
"""

from __future__ import annotations
import logging
from typing import Any, List, Optional

from common.scanner.interfaces import BinaryInspector
from common.scanner.models import SoftwareItem
from windows.scanner.layer1_paths import inspect_pe_file

logger = logging.getLogger("windows.scanner.binary_inspector")


class WindowsBinaryInspector(BinaryInspector):
    """Windows implementation of BinaryInspector using Win32 GetFileVersionInfoW PE VersionInfo."""

    def inspect_binary(self, filepath: str, cache: Optional[Any] = None) -> List[SoftwareItem]:
        return inspect_pe_file(filepath, cache=cache)
