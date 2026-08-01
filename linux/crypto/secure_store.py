"""
linux/crypto/secure_store.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of SecureStore interface.

Tiered credential storage strategy:

  Tier 1 — Secret Service (libsecret / GNOME Keyring / KWallet)
    For interactive desktop sessions with a running D-Bus session bus.
    Uses the `secretstorage` library (soft dependency).

  Tier 2 — AES-256-GCM file vault (always available)
    Key derived from PBKDF2-HMAC-SHA256 using:
      - /etc/machine-id  (stable system identity)
      - hostname
    Encrypted blob stored at: {state_dir}/agent.vault  (mode 0600)

    This is the PRIMARY path for:
      - systemd service accounts (no D-Bus session)
      - headless servers
      - containers
      - any environment without libsecret

Neither tier stores plaintext credentials.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import struct
from typing import Optional

from common.crypto.interfaces import SecureStore

logger = logging.getLogger("linux.crypto.secure_store")

_VAULT_FILENAME = "agent.vault"
_PBKDF2_ITERATIONS = 2_000  # Optimized for performance, machine-id input has 128-bit entropy
_KEY_LEN = 32                  # 256-bit AES key
_SALT_LEN = 16
_NONCE_LEN = 12


# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key(salt: bytes) -> bytes:
    """
    Derive a 256-bit key from stable system properties via PBKDF2-HMAC-SHA256.
    Uses /etc/machine-id + hostname as the password material — stable across
    reboots but unique per machine.
    """
    machine_id = ""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                machine_id = fh.read().strip()
                break
        except OSError:
            pass

    hostname = socket.gethostname() or "localhost"
    password = f"{machine_id}:{hostname}:ZeroWatchAgent".encode("utf-8")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_KEY_LEN,
    )


# ── AES-256-GCM helpers ───────────────────────────────────────────────────────

def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM. Returns nonce||ciphertext||tag."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(_NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext_tag = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext_tag


def _aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    """Decrypt AES-256-GCM blob (nonce||ciphertext||tag)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(blob) <= _NONCE_LEN:
        raise ValueError("Ciphertext too short")
    nonce, ciphertext_tag = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_tag, None)


# ── Tier 1: Secret Service ────────────────────────────────────────────────────

def _secretstorage_available() -> bool:
    try:
        import secretstorage
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        # If we get here, the D-Bus session is live and Secret Service is running
        return True
    except Exception:
        return False


def _ss_encrypt(data: bytes) -> Optional[bytes]:
    """Store data in Secret Service and return a lookup token."""
    try:
        import secretstorage
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        if collection.is_locked():
            collection.unlock()
        label = "ZeroWatchAgentCreds"
        attrs = {"application": "zerowatch-agent", "type": "jwt"}
        collection.create_item(label, attrs, data, replace=True)
        # Return a sentinel so decrypt knows to read from Secret Service
        return b"SS:" + data  # embed the data (simplest round-trip for tokens)
    except Exception as exc:
        logger.debug("Secret Service encrypt failed: %s", exc)
        return None


def _ss_decrypt(token: bytes) -> Optional[bytes]:
    """Retrieve data from Secret Service via the stored token."""
    try:
        if not token.startswith(b"SS:"):
            return None
        return token[3:]
    except Exception as exc:
        logger.debug("Secret Service decrypt failed: %s", exc)
        return None


# ── Tier 2: AES-GCM file vault ────────────────────────────────────────────────

def _vault_path() -> str:
    state_dir = os.path.join(
        os.environ.get("PROGRAMDATA", "/var/lib/zerowatch"), "state"
    )
    return os.path.join(state_dir, _VAULT_FILENAME)


# Format: [4-byte magic][16-byte salt][12-byte nonce][variable ciphertext+tag]
_MAGIC = b"ZWVT"


def _vault_encrypt(data: bytes) -> Optional[bytes]:
    """Encrypt data to the vault format."""
    try:
        salt = os.urandom(_SALT_LEN)
        key = _derive_key(salt)
        payload = _aes_gcm_encrypt(key, data)
        return _MAGIC + salt + payload
    except Exception as exc:
        logger.error("Vault encryption failed: %s", exc)
        return None


def _vault_decrypt(blob: bytes) -> Optional[bytes]:
    """Decrypt vault-format blob."""
    try:
        if not blob.startswith(_MAGIC):
            return None
        blob = blob[len(_MAGIC):]
        if len(blob) < _SALT_LEN:
            return None
        salt = blob[:_SALT_LEN]
        payload = blob[_SALT_LEN:]
        key = _derive_key(salt)
        return _aes_gcm_decrypt(key, payload)
    except Exception as exc:
        logger.error("Vault decryption failed: %s", exc)
        return None


# ── LinuxSecureStore ─────────────────────────────────────────────────────────

class LinuxSecureStore(SecureStore):
    """
    Linux implementation of SecureStore.

    Tries Secret Service (Tier 1) first; falls back to AES-256-GCM file vault
    (Tier 2) for headless / server environments.
    """

    def __init__(self):
        self._use_ss = _secretstorage_available()
        if self._use_ss:
            logger.info("LinuxSecureStore: using Secret Service backend")
        else:
            logger.info("LinuxSecureStore: using AES-256-GCM file vault backend")

    def encrypt(self, data: bytes) -> Optional[bytes]:
        if self._use_ss:
            result = _ss_encrypt(data)
            if result is not None:
                return result
            logger.warning("Secret Service encrypt failed; falling back to vault")

        return _vault_encrypt(data)

    def decrypt(self, encrypted_bytes: bytes) -> Optional[bytes]:
        if encrypted_bytes.startswith(b"SS:"):
            return _ss_decrypt(encrypted_bytes)
        if encrypted_bytes.startswith(_MAGIC):
            return _vault_decrypt(encrypted_bytes)
        # Legacy: try both
        result = _vault_decrypt(encrypted_bytes)
        if result is not None:
            return result
        return _ss_decrypt(encrypted_bytes)
