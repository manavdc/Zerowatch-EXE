"""
macos/scanner/binary_inspector.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation of BinaryInspector interface.

Identification strategy (most authoritative first):

  1. .app bundle ownership
     Binary is inside SomeName.app/Contents/ → read Info.plist
     Source: app_bundle

  2. Homebrew Cellar ownership
     Binary is under /opt/homebrew/Cellar/<formula>/<version>/...
     Source: homebrew_formula

  3. pkgutil ownership index
     Pre-built dict mapping file path → (pkg_id, version)
     Built once per scan session — O(1) lookup after that.
     Source: macos_pkg

  4. Filename fallback
     No owner found → use basename as name
     Dylibs without an owner are SKIPPED (too many false positives).
     Source: macho_binary

This inspector is completely STATIC. It never executes the binary.
All metadata comes from:
  - plistlib (Info.plist parsing — stdlib)
  - Path structure analysis (Cellar layout)
  - pkgutil receipt database (prebuilt index)
  - Mach-O header magic (read 4–32 bytes only)
"""

from __future__ import annotations

import logging
import os
from typing import Any, List, Optional

from common.scanner.interfaces import BinaryInspector
from common.scanner.models import SoftwareItem
from common.scanner.state_cache import ScanCache
from macos.scanner.macho import detect_macho, MachOKind
from macos.scanner.ownership import (
    PkgutilOwnershipIndex,
    resolve_app_bundle_owner,
    resolve_homebrew_owner,
    resolve_standalone,
)

logger = logging.getLogger("macos.scanner.binary_inspector")


def inspect_macho_file(
    filepath: str,
    cache: Optional[ScanCache] = None,
    ownership_index: Optional[PkgutilOwnershipIndex] = None,
) -> List[SoftwareItem]:
    """
    Inspect a single Mach-O / .dylib file.

    Cache key: (path, mtime_ns, size_bytes) — same contract as Windows/Linux.
    Ownership index: shared across all calls within a single scan session.
    """
    try:
        st = os.stat(filepath)
        mtime_ns   = st.st_mtime_ns
        size_bytes = st.st_size
    except OSError as exc:
        logger.debug("stat failed for %s: %s", filepath, exc)
        return []

    # ── Cache lookup ──────────────────────────────────────────────────────────
    if cache is not None:
        cached = cache.lookup(filepath, mtime_ns, size_bytes)
        if cached is not None:
            return cached

    # ── Detect Mach-O kind ────────────────────────────────────────────────────
    kind = detect_macho(filepath)
    if kind is None:
        # File was classified as BINARY by the walker (e.g. .dylib extension),
        # but header read fails (truncated, permissions, not actually Mach-O).
        if cache is not None:
            cache.store(filepath, mtime_ns, size_bytes, [], layer=1)
        return []

    # ── 1. .app bundle owner ──────────────────────────────────────────────────
    item = resolve_app_bundle_owner(filepath)
    if item is not None:
        result = [item]
        if cache is not None:
            cache.store(filepath, mtime_ns, size_bytes, result, layer=1)
        return result

    # ── 2. Homebrew Cellar ────────────────────────────────────────────────────
    item = resolve_homebrew_owner(filepath)
    if item is not None:
        result = [item]
        if cache is not None:
            cache.store(filepath, mtime_ns, size_bytes, result, layer=1)
        return result

    # ── 3. pkgutil ownership index ────────────────────────────────────────────
    if ownership_index is not None:
        item = ownership_index.lookup(filepath)
        if item is not None:
            result = [item]
            if cache is not None:
                cache.store(filepath, mtime_ns, size_bytes, result, layer=1)
            return result

    # ── 4. Filename fallback ──────────────────────────────────────────────────
    item = resolve_standalone(filepath, kind)
    result = [item] if item is not None else []

    if cache is not None:
        cache.store(filepath, mtime_ns, size_bytes, result, layer=1)

    return result


class MacOSBinaryInspector(BinaryInspector):
    """
    macOS implementation of BinaryInspector using static ownership resolution.

    Maintains a shared pkgutil ownership index across all inspect_binary()
    calls within a scan session for O(1) per-file lookups.
    """

    def __init__(self) -> None:
        # Ownership index is built lazily on first use.
        # Shared across all inspect_binary() calls on this inspector instance.
        self._ownership_index = PkgutilOwnershipIndex()

    def inspect_binary(
        self, filepath: str, cache: Optional[Any] = None
    ) -> List[SoftwareItem]:
        return inspect_macho_file(
            filepath,
            cache=cache,
            ownership_index=self._ownership_index,
        )
