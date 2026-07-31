"""
windows/crypto/dpapi_store.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation of SecureStore using DPAPI (CryptProtectData / CryptUnprotectData).
"""

from __future__ import annotations
import ctypes
import ctypes.wintypes as wt
import logging
from typing import Optional

from common.crypto.interfaces import SecureStore

logger = logging.getLogger("windows.crypto.dpapi")


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def encrypt_data(data_bytes: bytes) -> Optional[bytes]:
    """Encrypts data using Windows DPAPI (CRYPTPROTECT_LOCAL_MACHINE)."""
    flags = 0x4
    in_buffer = ctypes.create_string_buffer(data_bytes)
    in_blob = DATA_BLOB(len(data_bytes), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    out_blob = DATA_BLOB()

    try:
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "ZeroWatchAgentCreds",
            None,
            None,
            None,
            flags,
            ctypes.byref(out_blob),
        )
        if not ok:
            return None

        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception as e:
        logger.error("DPAPI Encryption failed: %s", e)
        return None


def decrypt_data(encrypted_bytes: bytes) -> Optional[bytes]:
    """Decrypts data using Windows DPAPI."""
    in_buffer = ctypes.create_string_buffer(encrypted_bytes)
    in_blob = DATA_BLOB(len(encrypted_bytes), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    out_blob = DATA_BLOB()

    try:
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        )
        if not ok:
            return None

        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception as e:
        logger.error("DPAPI Decryption failed: %s", e)
        return None


class DPAPISecureStore(SecureStore):
    """Windows implementation of SecureStore using DPAPI."""

    def encrypt(self, data: bytes) -> Optional[bytes]:
        return encrypt_data(data)

    def decrypt(self, encrypted_bytes: bytes) -> Optional[bytes]:
        return decrypt_data(encrypted_bytes)
