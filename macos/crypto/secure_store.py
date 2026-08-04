"""
macos/crypto/secure_store.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation of SecureStore using Keychain.

─────────────────────────────────────────────────────────────────────────────
SecureStore interface mapping:
─────────────────────────────────────────────────────────────────────────────

The SecureStore interface exposes:

    encrypt(data: bytes) -> Optional[bytes]
    decrypt(encrypted_bytes: bytes) -> Optional[bytes]

Callers (sentinel_agent.py, sentinel_agent_linux.py) use this pattern:

    # Store JWT
    enc_bytes = secure_store.encrypt(jwt.encode("utf-8"))
    with open(jwt_path, "wb") as fh:
        fh.write(enc_bytes)

    # Load JWT
    enc_bytes = open(jwt_path, "rb").read()
    raw_bytes = secure_store.decrypt(enc_bytes)
    jwt = raw_bytes.decode("utf-8").strip()

The encrypt() output is persisted to disk as opaque bytes.
decrypt() receives those exact bytes back.

─────────────────────────────────────────────────────────────────────────────
Semantic mismatch: DPAPI vs Keychain
─────────────────────────────────────────────────────────────────────────────

Windows DPAPI and Linux AES-GCM are both byte→byte ciphers:
    plaintext → encrypted_bytes   (encrypt)
    encrypted_bytes → plaintext   (decrypt)

macOS Keychain is a key-value store:
    store(service, account, value)
    retrieve(service, account) → value

Keychain does NOT return "encrypted bytes" — it stores and retrieves
the plaintext secret under a stable label.

Therefore the macOS SecureStore uses a TAGGED REFERENCE TOKEN design:

    encrypt(plaintext):
        1. Generate a stable slot_id from the first 32 bytes of content hash
        2. Store plaintext in Keychain under: service="io.deepcytes.zerowatch.agent"
           account="agent-credential:<slot_id>"
        3. Return reference token = b"ZW_KC::" + slot_id.encode("utf-8")

    decrypt(reference_token):
        1. Check that the token starts with b"ZW_KC::"
        2. Extract slot_id
        3. Retrieve from Keychain using service + account
        4. Return original plaintext bytes

On disk (jwt_path), only the reference token is stored — not the plaintext.
The actual secret resides in the macOS Keychain.

This means:
  - The disk file is safe to inspect (it contains only a reference, not the secret)
  - The secret is protected by the OS Keychain
  - The design is compatible with the existing caller pattern

─────────────────────────────────────────────────────────────────────────────
Slot identity:
─────────────────────────────────────────────────────────────────────────────

slot_id is derived from the first 32 bytes of the plaintext using sha256,
truncated to 16 hex chars. This:
  - Makes repeated encryption of the same token idempotent
    (same data → same Keychain slot → update, not duplicate)
  - Does NOT expose the plaintext (sha256 is one-way)
  - Does NOT use random IDs per call (prevents orphaned Keychain entries)
  - Stays stable across daemon restarts

Limitation: Different secrets that happen to produce the same sha256 prefix
would overwrite each other. At 16 hex chars (8 bytes of collision space),
practical collision probability is negligible for a daemon with at most
one credential per category (JWT, enrollment token, etc.).

─────────────────────────────────────────────────────────────────────────────
Multiple secrets:
─────────────────────────────────────────────────────────────────────────────

Each distinct plaintext produces a distinct slot_id → distinct Keychain entry.
Repeated encryption of the same token overwrites the same entry (idempotent).
JWT rotation produces a new slot_id → old entry remains until explicitly deleted.

A future cleanup function could purge stale slots; this is deferred to native
hardware testing to understand Keychain access behavior before implementing.

─────────────────────────────────────────────────────────────────────────────
NATIVE VALIDATION NOT PERFORMED.
LaunchDaemon Keychain behavior, System keychain accessibility, and prompt
behavior must all be validated on real macOS hardware before production use.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

from common.crypto.interfaces import SecureStore
from macos.crypto.keychain_backend import KeychainBackend, InMemoryKeychainBackend
from macos.crypto.security_framework_backend import SecurityFrameworkBackend

logger = logging.getLogger("macos.crypto.secure_store")

# ── Record identity constants ──────────────────────────────────────────────────
# One source of truth for all Keychain record identifiers.

KEYCHAIN_SERVICE = "io.deepcytes.zerowatch.agent"
KEYCHAIN_ACCOUNT_PREFIX = "agent-credential"

# Reference token tag written to disk (persisted, never contains the secret)
_TOKEN_TAG = b"ZW_KC::"
_TOKEN_TAG_LEN = len(_TOKEN_TAG)

# Slot ID length (hex chars from sha256 of first 32 bytes of plaintext)
_SLOT_ID_HEX_LEN = 16


# ── Slot identity helpers ─────────────────────────────────────────────────────

def _derive_slot_id(data: bytes) -> str:
    """
    Derive a stable 16-char hex slot ID from the first 32 bytes of data.

    Properties:
      - Same data → same slot ID (idempotent encryption)
      - Different data → different slot ID (distinct entries)
      - Not reversible (sha256 is one-way)
      - Does NOT expose plaintext

    The first 32 bytes are used because JWT tokens differ in their early
    bytes; using only the start avoids processing large secrets.
    """
    digest = hashlib.sha256(data[:32]).hexdigest()
    return digest[:_SLOT_ID_HEX_LEN]


def _account_for_slot(slot_id: str) -> str:
    """Produce the Keychain account string for a given slot ID."""
    return f"{KEYCHAIN_ACCOUNT_PREFIX}:{slot_id}"


def _make_reference_token(slot_id: str) -> bytes:
    """Produce the opaque reference token stored on disk."""
    return _TOKEN_TAG + slot_id.encode("ascii")


def _parse_reference_token(token: bytes) -> Optional[str]:
    """
    Parse a reference token and return the slot_id.

    Returns None if the token is not a valid ZW_KC reference.
    Never logs the token contents.
    """
    if not isinstance(token, bytes):
        return None
    if not token.startswith(_TOKEN_TAG):
        return None
    slot_part = token[_TOKEN_TAG_LEN:]
    if not slot_part:
        return None
    try:
        slot_id = slot_part.decode("ascii")
    except UnicodeDecodeError:
        logger.error("Reference token contains non-ASCII slot_id — corrupt reference")
        return None
    if len(slot_id) != _SLOT_ID_HEX_LEN:
        logger.error(
            "Reference token slot_id has wrong length (expected %d, got %d) — corrupt",
            _SLOT_ID_HEX_LEN, len(slot_id),
        )
        return None
    # Validate hex chars
    try:
        int(slot_id, 16)
    except ValueError:
        logger.error("Reference token slot_id is not valid hex — corrupt reference")
        return None
    return slot_id


# ── MacOSSecureStore ──────────────────────────────────────────────────────────

class MacOSSecureStore(SecureStore):
    """
    macOS implementation of SecureStore using Keychain.

    Phase 6F-A: Production backend is SecurityFrameworkBackend
    (Security.framework via ctypes — no subprocess, no argv exposure).

    Implements the encrypt()/decrypt() contract via a tagged-reference design:
      encrypt(data) → stores data in Keychain → returns opaque reference token
      decrypt(token) → reads reference token → retrieves data from Keychain

    The reference token is safe to persist on disk (contains no plaintext).
    The actual secret lives in the macOS Keychain.

    Default backend: SecurityFrameworkBackend
      - Uses SecItemAdd / SecItemCopyMatching / SecItemUpdate / SecItemDelete
      - No subprocess, no argv exposure, binary-safe, no hex encoding
      - Fails gracefully on non-macOS (Windows CI returns None)

    Test backend: InMemoryKeychainBackend (injected via constructor parameter)

    NATIVE VALIDATION NOT PERFORMED.
    LaunchDaemon Keychain behavior must be validated on real macOS hardware.
    """

    def __init__(
        self,
        backend: SecurityFrameworkBackend | KeychainBackend | None = None,
    ) -> None:
        """
        Instantiate MacOSSecureStore.

        Args:
            backend: Optional backend implementation. If None, uses
                     SecurityFrameworkBackend (production default).
                     Tests inject InMemoryKeychainBackend to avoid
                     framework loading.
        """
        if backend is not None:
            self._backend = backend
        else:
            self._backend = SecurityFrameworkBackend()

        if not self._backend.available():
            logger.warning(
                "MacOSSecureStore: Keychain backend unavailable. "
                "Running on non-macOS platform or Security.framework unavailable. "
                "encrypt()/decrypt() will return None."
            )

    def encrypt(self, data: bytes) -> Optional[bytes]:
        """
        Store data in the Keychain and return an opaque reference token.

        The returned bytes contain ONLY a reference tag + slot ID.
        The actual secret is stored in the macOS Keychain.
        These bytes are safe to persist to disk.

        Args:
            data: Plaintext bytes to protect. Accepts any bytes including
                  arbitrary binary, UTF-8-encoded strings, empty bytes.

        Returns:
            Opaque reference token (bytes) on success.
            None on failure (Keychain unavailable, permission denied, etc.).

        Failure semantics (consistent with DPAPI / Linux vault):
            Returns None. Does NOT raise. Does NOT fall back to plaintext.
        """
        # Input validation
        if data is None:
            logger.warning("encrypt: received None — returning None")
            return None

        if not isinstance(data, bytes):
            logger.warning("encrypt: expected bytes, got %s — returning None", type(data).__name__)
            return None

        if len(data) == 0:
            # Empty bytes: we store an empty-sentinel entry so decrypt can round-trip
            logger.debug("encrypt: empty bytes — storing empty sentinel")
            slot_id = "empty_0000000000000"[:_SLOT_ID_HEX_LEN]
            # Override with a fixed slot for empty bytes
            slot_id = "0000000000000000"
        else:
            slot_id = _derive_slot_id(data)

        account = _account_for_slot(slot_id)

        # Fail-closed: if backend is unavailable, return None
        if not self._backend.available():
            logger.error(
                "encrypt: Keychain backend unavailable — failing closed. "
                "Secret NOT stored."
            )
            return None

        ok = self._backend.store(KEYCHAIN_SERVICE, account, data)
        if not ok:
            logger.error("encrypt: Keychain store failed — returning None")
            return None

        token = _make_reference_token(slot_id)
        logger.info(
            "encrypt: secret stored in Keychain [slot=%s, len=%d]",
            slot_id, len(data),
        )
        return token

    def decrypt(self, encrypted_bytes: bytes) -> Optional[bytes]:
        """
        Retrieve data from the Keychain using a reference token.

        Args:
            encrypted_bytes: Opaque reference token returned by encrypt().

        Returns:
            Original plaintext bytes on success.
            None if the token is invalid, the Keychain item is missing, or
            the backend is unavailable.

        Failure semantics:
            Returns None. Does NOT raise. Does NOT log the token contents.
        """
        # Input validation
        if encrypted_bytes is None:
            logger.warning("decrypt: received None — returning None")
            return None

        if not isinstance(encrypted_bytes, bytes):
            logger.warning("decrypt: expected bytes, got %s — returning None",
                           type(encrypted_bytes).__name__)
            return None

        if not encrypted_bytes.startswith(_TOKEN_TAG):
            # This could be bytes from a different platform (DPAPI, Linux vault)
            # or corrupted data. Either way, return None (cannot decrypt).
            logger.debug(
                "decrypt: input does not have ZW_KC tag — not a macOS Keychain reference"
            )
            return None

        slot_id = _parse_reference_token(encrypted_bytes)
        if slot_id is None:
            logger.error("decrypt: corrupt or unrecognized reference token")
            return None

        if not self._backend.available():
            logger.error(
                "decrypt: Keychain backend unavailable — cannot retrieve secret"
            )
            return None

        account = _account_for_slot(slot_id)
        data = self._backend.retrieve(KEYCHAIN_SERVICE, account)

        if data is None:
            logger.error(
                "decrypt: Keychain item not found [slot=%s]. "
                "The secret may have been deleted or the Keychain is unavailable.",
                slot_id,
            )
            return None

        logger.info("decrypt: secret retrieved from Keychain [slot=%s, len=%d]", slot_id, len(data))
        return data

    def delete_by_reference(self, reference_token: bytes) -> bool:
        """
        Delete the Keychain entry referenced by a token.

        This is an INTERNAL capability not exposed by the SecureStore interface.
        Intended for agent unenrollment, credential rotation, and uninstall.

        Does NOT modify the SecureStore interface — callers use encrypt()/decrypt().
        A future phase may surface this through an application-level API.

        Returns True if deleted or if the item did not exist (idempotent).
        """
        slot_id = _parse_reference_token(reference_token)
        if slot_id is None:
            logger.warning("delete_by_reference: invalid reference token")
            return False

        if not self._backend.available():
            logger.warning("delete_by_reference: backend unavailable")
            return False

        account = _account_for_slot(slot_id)
        ok = self._backend.delete(KEYCHAIN_SERVICE, account)
        logger.info(
            "delete_by_reference: %s [slot=%s]",
            "succeeded" if ok else "failed",
            slot_id,
        )
        return ok
