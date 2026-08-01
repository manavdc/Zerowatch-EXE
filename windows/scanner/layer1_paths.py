"""
windows/scanner/layer1_paths.py
─────────────────────────────────────────────────────────────────────────────
Layer 1: Windows PE binary inspection (GetFileVersionInfoW).
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from common.scanner.models import SoftwareItem, SOURCE_PE_BINARY, SOURCE_PE_DLL, SOURCE_PE_SYS
from common.scanner.state_cache import ScanCache
from windows.scanner.layer0_registry import (
    _read_pe_product_name,
    _read_pe_product_version,
    _read_pe_company_name,
)

logger = logging.getLogger("windows.scanner.layer1")

def _source_for_extension(ext: str) -> str:
    ext = ext.lower()
    if ext == ".sys":
        return SOURCE_PE_SYS
    if ext == ".dll":
        return SOURCE_PE_DLL
    return SOURCE_PE_BINARY


def inspect_pe_file(
    filepath: str,
    cache: Optional[ScanCache] = None,
) -> List[SoftwareItem]:
    try:
        st = os.stat(filepath)
        mtime_ns   = st.st_mtime_ns
        size_bytes = st.st_size
    except OSError as exc:
        logger.debug("stat failed for %s: %s", filepath, exc)
        return []

    if cache is not None:
        cached = cache.lookup(filepath, mtime_ns, size_bytes)
        if cached is not None:
            return cached

    product_name    = _read_pe_product_name(filepath)
    product_version = _read_pe_product_version(filepath)
    company_name    = _read_pe_company_name(filepath)

    ext = os.path.splitext(filepath)[1].lower()

    if not product_name:
        if ext != ".exe":
            if cache is not None:
                cache.store(filepath, mtime_ns, size_bytes, [], layer=1)
            return []
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


def process_binary_batch(
    paths: List[str],
    cache: Optional[ScanCache] = None,
) -> List[SoftwareItem]:
    items: List[SoftwareItem] = []
    for path in paths:
        try:
            items.extend(inspect_pe_file(path, cache=cache))
        except Exception as exc:
            logger.debug("Binary inspect error %s: %s", path, exc)
    return items
