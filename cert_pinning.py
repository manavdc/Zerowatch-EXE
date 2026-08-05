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

# ─────────────────────────────────────────────────────────────────────────────
# OTA Update Trust Anchor
# ─────────────────────────────────────────────────────────────────────────────
# Base64-encoded raw Ed25519 public key (32 bytes) used to verify the
# cryptographic signature on release-manifest.json before any OTA binary
# is downloaded or staged.
#
# The matching private key is stored OFFLINE and is used exclusively by the
# GitHub Actions release workflow (.github/workflows/release.yml) to sign
# each release manifest. The public key embedded here is the only in-agent
# trust anchor for all OTA updates.
#
# ⚠ REPLACE THIS PLACEHOLDER WITH THE REAL PUBLIC KEY BEFORE PRODUCTION.
# Generate keypair with:
#   python -c "
#   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
#   import base64
#   k = Ed25519PrivateKey.generate()
#   print('PUBLIC  (embed this):', base64.b64encode(k.public_key().public_bytes_raw()).decode())
#   print('PRIVATE (keep offline):', k.private_bytes_raw().hex())
#   "
# ─────────────────────────────────────────────────────────────────────────────
OTA_ED25519_PUBLIC_KEY_B64 = "A05PfsGyjAJZJAP2u4qbqaUJUObMJkETbPeBcVecky0="

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
    "OTA_ED25519_PUBLIC_KEY_B64",
]
