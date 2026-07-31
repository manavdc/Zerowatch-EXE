"""
common/crypto/interfaces.py
─────────────────────────────────────────────────────────────────────────────
Abstract Base Class for platform-native secure credential storage.
Defines required encryption and decryption methods.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional


class SecureStore(ABC):
    """Abstract interface for platform secret storage (DPAPI / Keychain / SecretService)."""

    @abstractmethod
    def encrypt(self, data: bytes) -> Optional[bytes]:
        """Encrypt raw byte data using OS-protected key storage."""
        ...

    @abstractmethod
    def decrypt(self, encrypted_bytes: bytes) -> Optional[bytes]:
        """Decrypt protected byte data using OS-protected key storage."""
        ...
