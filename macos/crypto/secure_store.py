"""
macos/crypto/secure_store.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation stub of SecureStore interface.
Pending Phase 6B implementation.

Note: No fallback implementation is copied here. Native macOS Keychain
storage design and verification will be performed on actual macOS hardware
in Phase 6B.
"""

from __future__ import annotations

import logging
from typing import Optional

from common.crypto.interfaces import SecureStore

logger = logging.getLogger("macos.crypto.secure_store")


class MacOSSecureStore(SecureStore):
    """
    macOS implementation stub of SecureStore.

    Planned Phase 6B Strategy:
      - Native Keychain integration via macOS `security` CLI or `keyring` library
    """

    def encrypt(self, data: bytes) -> Optional[bytes]:
        raise NotImplementedError("MacOSSecureStore is scheduled for Phase 6B.")

    def decrypt(self, encrypted_bytes: bytes) -> Optional[bytes]:
        raise NotImplementedError("MacOSSecureStore is scheduled for Phase 6B.")
