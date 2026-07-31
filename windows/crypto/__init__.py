"""
windows/crypto package
DPAPI secure store implementations.
"""

from .dpapi_store import DPAPISecureStore, encrypt_data, decrypt_data

__all__ = ["DPAPISecureStore", "encrypt_data", "decrypt_data"]
