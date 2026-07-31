"""
cert_pinning.py (Forwarding adapter to common.cert.pinning)
─────────────────────────────────────────────────────────────────────────────
Preserves backward compatibility for legacy imports while using the portable
common.cert.pinning module.
"""

from common.cert.pinning import (
    PinError,
    get_spki_sha256,
    is_loopback,
    is_pin_failure,
    is_valid_sha256_base64,
    _verify_pin,
    PinnedSSLContext,
    SPKIPinningAdapter,
    build_pinning_adapter,
    log_pin_failure_event,
    PinnedSession,
)

PIN_MISMATCH_DETECTED = False

__all__ = [
    "PinError",
    "get_spki_sha256",
    "is_loopback",
    "is_pin_failure",
    "is_valid_sha256_base64",
    "_verify_pin",
    "PinnedSSLContext",
    "SPKIPinningAdapter",
    "build_pinning_adapter",
    "PIN_MISMATCH_DETECTED",
    "log_pin_failure_event",
    "PinnedSession",
]
