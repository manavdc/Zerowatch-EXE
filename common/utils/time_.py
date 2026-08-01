"""
common/utils/time_.py
─────────────────────────────────────────────────────────────────────────────
Platform-independent UTC ISO timestamp helpers.
"""

from __future__ import annotations
import datetime

def utc_now_iso() -> str:
    """Return current UTC time in ISO-8601 string format formatted with Z suffix."""
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
