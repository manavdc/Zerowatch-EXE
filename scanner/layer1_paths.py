"""
scanner/layer1_paths.py
─────────────────────────────────────────────────────────────────────────────
Layer 1: Portable application and binary discovery.

PURPOSE
───────
Discover software that is NOT in the registry: portable executables,
standalone tools dropped in Downloads / Desktop / custom directories,
DLLs that are the actual versioned component (e.g. OpenSSL's libcrypto),
and SYS kernel modules not captured by the Services hive.

APPROACH: PE VERSIONINFO, NOT FULL FILE READS
──────────────────────────────────────────────
The Win32 GetFileVersionInfoW API reads only the VERSIONINFO resource
block embedded near the start of the PE header.  On a typical EXE this
costs ~50–200 µs including the kernel transition.  It does NOT read the
entire binary into memory.

We use the helpers defined in layer0_registry.py (_read_pe_product_name,
_read_pe_product_version, _read_pe_company_name) to maintain a single
implementation.

WHAT IS SKIPPED
───────────────
• Files with no VERSIONINFO resource → return None, no item emitted.
• Files where ProductName is empty and FileDescription is empty →
  no useful identity to send to the backend.
• Files already discovered by Layer 0 registry scan → the orchestrator
  deduplicates by name::version so duplicates are harmless, but we avoid
  unnecessary work by checking the cache first.

CACHE INTEGRATION
─────────────────
The scan cache is checked before opening any binary.  If mtime_ns and
size_bytes match the stored values, the cached items are returned without
calling VerQueryValue.

CONCURRENCY
───────────
This module is designed to be called from a ThreadPoolExecutor worker.
All functions are stateless and thread-safe.  The cache uses per-thread
SQLite connections (handled by ScanCache internally).
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from .models import SoftwareItem, SOURCE_PE_BINARY, SOURCE_PE_DLL, SOURCE_PE_SYS
from .layer0_registry import (
    _read_pe_product_name,
    _read_pe_product_version,
    _read_pe_company_name,
)
from .state_cache import ScanCache

logger = logging.getLogger("scanner.layer1")

# ── Source tag by extension ───────────────────────────────────────────────────

def _source_for_extension(ext: str) -> str:
    ext = ext.lower()
    if ext == ".sys":
        return SOURCE_PE_SYS
    if ext == ".dll":
        return SOURCE_PE_DLL
    return SOURCE_PE_BINARY


# ── Core inspection function ──────────────────────────────────────────────────

def inspect_pe_file(
    filepath: str,
    cache: Optional[ScanCache] = None,
) -> List[SoftwareItem]:
    """
    Inspect a single PE binary (EXE / DLL / SYS) for version identity.

    Returns a list (0 or 1 item) so callers can use extend() uniformly.

    Cache lookup is performed first; if the file is unchanged and the
    cache has an entry, the cached result is returned without any Win32
    API calls.
    """
    try:
        st = os.stat(filepath)
        mtime_ns   = st.st_mtime_ns
        size_bytes = st.st_size
    except OSError as exc:
        logger.debug("stat failed for %s: %s", filepath, exc)
        return []

    # ── Cache lookup ───────────────────────────────────────────────────────
    if cache is not None:
        cached = cache.lookup(filepath, mtime_ns, size_bytes)
        if cached is not None:
            return cached

    # ── PE VERSIONINFO query ───────────────────────────────────────────────
    product_name    = _read_pe_product_name(filepath)
    product_version = _read_pe_product_version(filepath)
    company_name    = _read_pe_company_name(filepath)

    ext = os.path.splitext(filepath)[1].lower()

    if not product_name:
        # Filename fallback: only for standalone executables.
        # EXE filenames are strong product identifiers (putty.exe → "putty",
        # nmap.exe → "nmap") that the backend's normalizeProduct() can match.
        # DLL / SYS filenames without metadata are implementation details
        # that don't map reliably to CPE names — emit nothing for them.
        if ext != ".exe":
            if cache is not None:
                cache.store(filepath, mtime_ns, size_bytes, [], layer=1)
            return []
        # Use the stem as the name with no version.
        # The backend will attempt fuzzy normalization against its products DB.
        product_name = os.path.splitext(os.path.basename(filepath))[0]
        product_version = ""
        company_name = ""

    source = _source_for_extension(ext)


    item = SoftwareItem(
        name=product_name,
        version=product_version or "",
        vendor=company_name or "",
        source=source,
        category="software",
        install_location=os.path.dirname(filepath),
        scan_path=filepath,
    )

    result = [item]

    if cache is not None:
        cache.store(filepath, mtime_ns, size_bytes, result, layer=1)

    return result


# ── Batch processor ───────────────────────────────────────────────────────────

def process_binary_batch(
    paths: List[str],
    cache: Optional[ScanCache] = None,
) -> List[SoftwareItem]:
    """
    Process a list of binary paths and return all discovered items.
    Called by the orchestrator's ThreadPoolExecutor workers.
    """
    items: List[SoftwareItem] = []
    for path in paths:
        try:
            items.extend(inspect_pe_file(path, cache=cache))
        except Exception as exc:
            logger.debug("Binary inspect error %s: %s", path, exc)
    return items
