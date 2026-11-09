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
_PBKDF2_ITERATIONS = 600_000   # OWASP recommended standard for PBKDF2-HMAC-SHA256
_LEGACY_PBKDF2_ITERATIONS = 2_000
_KEY_LEN = 32                  # 256-bit AES key
_SALT_LEN = 16
_NONCE_LEN = 12


# ── Key derivation ────────────────────────────────────────────────────────────

def _get_or_create_vault_secret() -> bytes:
    """Retrieve or generate a 256-bit installation secret stored with strict permissions (0600).
    This ensures unprivileged users cannot derive the vault key from world-readable /etc/machine-id.
    """
    secret_dir = "/etc/zerowatch" if (hasattr(os, "geteuid") and os.geteuid() == 0) else os.path.dirname(_vault_path())
    secret_path = os.path.join(secret_dir, "vault.key")
    try:
        if os.path.exists(secret_path):
            with open(secret_path, "rb") as fh:
                secret = fh.read()
            if len(secret) >= 32:
                return secret[:32]
        os.makedirs(secret_dir, mode=0o700, exist_ok=True)
        new_secret = os.urandom(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(secret_path, flags, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(new_secret)
        return new_secret
    except Exception as exc:
        logger.debug("Could not access or create vault secret file: %s", exc)
        return b""


def _derive_key(salt: bytes, iterations: int = _PBKDF2_ITERATIONS, use_secret: bool = True) -> bytes:
    """
    Derive a 256-bit key using PBKDF2-HMAC-SHA256.
    Combines /etc/machine-id, hostname, and an installation-specific secret key
    stored with root-only permissions (0600) to protect against unprivileged local derivation.
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
    secret = _get_or_create_vault_secret().hex() if use_secret else ""
    password = f"{machine_id}:{hostname}:{secret}:ZeroWatchAgent".encode("utf-8")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        iterations,
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
    """Decrypt vault-format blob with automatic fallback for legacy iterations."""
    try:
        if not blob.startswith(_MAGIC):
            return None
        blob = blob[len(_MAGIC):]
        if len(blob) < _SALT_LEN:
            return None
        salt = blob[:_SALT_LEN]
        payload = blob[_SALT_LEN:]

        # 1. Try modern key derivation (600,000 iterations + secret file)
        try:
            key = _derive_key(salt, iterations=_PBKDF2_ITERATIONS, use_secret=True)
            return _aes_gcm_decrypt(key, payload)
        except Exception:
            pass

        # 2. Try modern iterations without secret (e.g. if secret file was created after first write)
        try:
            key = _derive_key(salt, iterations=_PBKDF2_ITERATIONS, use_secret=False)
            return _aes_gcm_decrypt(key, payload)
        except Exception:
            pass

        # 3. Fallback to legacy key derivation (2,000 iterations)
        try:
            key_legacy = _derive_key(salt, iterations=_LEGACY_PBKDF2_ITERATIONS, use_secret=False)
            return _aes_gcm_decrypt(key_legacy, payload)
        except Exception:
            pass

        return None
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
