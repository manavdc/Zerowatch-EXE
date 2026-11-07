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
    _verify_socket_pins,
    PinnedSSLContext,
    SPKIPinningAdapter,
    build_pinning_adapter,
    log_pin_failure_event,
    PinnedSession,
    get_pin_mismatch_detected,
    set_pin_mismatch_detected,
    reset_pin_mismatch,
    get_pin_mismatch_remaining_cooldown,
)

PIN_MISMATCH_DETECTED = False
_LAST_PIN_FAILURE_TIME = 0.0

# ─────────────────────────────────────────────────────────────────────────────
# OTA Update Trust Anchor
# ─────────────────────────────────────────────────────────────────────────────
# Base64-encoded raw Ed25519 public key (32 bytes) used to verify the
# cryptographic signature on release-manifest.json before any OTA binary
# is downloaded or staged.
OTA_ED25519_PUBLIC_KEY_B64 = "JwdNVR9ZJ8sG63bZ1iWUW2yt+TJwElvf/czhnW2bQQY="

__all__ = [
    "PinError",
    "get_spki_sha256",
    "is_loopback",
    "is_pin_failure",
    "is_valid_sha256_base64",
    "_verify_pin",
    "_verify_socket_pins",
    "PinnedSSLContext",
    "SPKIPinningAdapter",
    "build_pinning_adapter",
    "PIN_MISMATCH_DETECTED",
    "get_pin_mismatch_detected",
    "set_pin_mismatch_detected",
    "reset_pin_mismatch",
    "get_pin_mismatch_remaining_cooldown",
    "log_pin_failure_event",
    "PinnedSession",
    "OTA_ED25519_PUBLIC_KEY_B64",
]
