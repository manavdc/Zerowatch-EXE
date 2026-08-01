"""
scanner/state_cache.py (Forwarding adapter to common.scanner.state_cache)
─────────────────────────────────────────────────────────────────────────────
Preserves backward compatibility for legacy imports while using the portable
common.scanner.state_cache package.
"""

from common.scanner.state_cache import (
    ScanCache,
    SCHEMA_VERSION,
)

__all__ = [
    "ScanCache",
    "SCHEMA_VERSION",
]
