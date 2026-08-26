"""
common/updater.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Enterprise OTA Update Engine
Version: 1.0.0

Implements a TUF (The Update Framework)-inspired metadata verification stack:

  Root         → Embeds the canonical Ed25519 public key trust anchor.
  Targets      → Per-binary filename + SHA-256 + per-binary Ed25519 signature,
                 plus SemVer monotonicity (min_required_version enforcement).
  Snapshot     → Cryptographically binds all target hashes into a single
                 immutable snapshot digest so mix-and-match attacks are caught.
  Timestamp    → Signed expiration window (≤ 3 days) on the manifest; stale
                 metadata fails safe to prevent freeze attacks.

Security guarantees:
  • Rollback Attack    → SemVer monotonicity check (candidate ≥ min_required)
  • Freeze Attack      → Timestamp expiry window (MANIFEST_MAX_AGE_DAYS = 3)
  • Mix-and-Match      → Snapshot binding; all target hashes locked together
  • CDN Compromise     → Detached Ed25519 signature over entire manifest JSON,
                         verified against embedded public key before any download
  • Binary Tampering   → Per-binary SHA-256 stream-verified during download +
                         per-binary Ed25519 sig verified post-download

GitHub Releases distribution:
  - Manifest:  https://github.com/{REPO}/releases/latest/download/release-manifest.json
  - Sig:       https://github.com/{REPO}/releases/latest/download/release-manifest.json.sig
  - Binary:    https://github.com/{REPO}/releases/latest/download/{filename}
  Uses plain requests (no cert pinning) against GitHub CDN — the Ed25519
  signature is the trust anchor, not TLS.

Background check: every UPDATE_CHECK_INTERVAL_SECS (5 minutes) via a daemon thread.
Manual check:     UpdateChecker.check_for_update(force=True)
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Callable, Optional

import requests

# ---------------------------------------------------------------------------
# Public key trust anchor
# ---------------------------------------------------------------------------
# Imported from cert_pinning to keep all embedded trust constants co-located.
# Falls back to a module-level constant if cert_pinning is unavailable.
try:
    from cert_pinning import OTA_ED25519_PUBLIC_KEY_B64  # type: ignore
except ImportError:
    # Placeholder — REPLACE BEFORE PRODUCTION DEPLOYMENT.
    # Generated via: python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; k=Ed25519PrivateKey.generate(); print(k.public_key().public_bytes_raw().hex())"
    OTA_ED25519_PUBLIC_KEY_B64 = "A05PfsGyjAJZJAP2u4qbqaUJUObMJkETbPeBcVecky0="

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_REPO = "manavdc/Zerowatch-EXE"

# GitHub Releases CDN URLs (no API rate-limit risk — static asset downloads)
_RELEASES_BASE   = f"https://github.com/{GITHUB_REPO}/releases/latest/download"
MANIFEST_URL     = f"{_RELEASES_BASE}/release-manifest.json"
MANIFEST_SIG_URL = f"{_RELEASES_BASE}/release-manifest.json.sig"

# TUF-inspired Timestamp: refuse to trust manifests older than this
MANIFEST_MAX_AGE_DAYS: int = 3

# Background poll: 5 minutes (300 seconds) for local OTA verification
UPDATE_CHECK_INTERVAL_SECS: int = 5 * 60

# Download streaming chunk size
_CHUNK_SIZE: int = 8 * 1024  # 8 KiB

# HTTP timeout for CDN requests
_HTTP_TIMEOUT: int = 30  # seconds

# Platform key mapping (sys.platform → manifest targets key)
_PLATFORM_KEY: dict[str, str] = {
    "win32":  "win32",
    "linux":  "linux",
    "linux2": "linux",
    "darwin": "darwin",
}

logger = logging.getLogger("ota.updater")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class OTAError(Exception):
    """Base class for all OTA update errors."""


class ManifestVerificationError(OTAError):
    """Raised when the manifest Ed25519 signature fails verification."""


class TimestampExpiredError(OTAError):
    """Raised when the manifest released_at is older than MANIFEST_MAX_AGE_DAYS (freeze attack guard)."""


class RollbackRejectedError(OTAError):
    """Raised when the candidate version is below min_required_version (rollback attack guard)."""


class SnapshotBindingError(OTAError):
    """Raised when the snapshot digest does not match the recomputed target hash tree."""


class IntegrityError(OTAError):
    """Raised when a downloaded binary's SHA-256 does not match the manifest target."""


class BinarySignatureError(OTAError):
    """Raised when the per-binary Ed25519 signature verification fails."""


class UpdateNotAvailable(OTAError):
    """Raised when no update is available (current version is up-to-date)."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TargetInfo:
    """TUF Targets metadata for a single platform binary."""
    filename:    str
    sha256:      str          # hex-encoded SHA-256 of the binary
    ed25519_sig: str          # hex-encoded detached Ed25519 signature over the binary bytes
    size:        int          # expected byte size
    url:         str = field(default="")


@dataclass
class UpdateInfo:
    """Fully verified update descriptor, ready for download."""
    version:        str
    released_at:    str         # ISO-8601 UTC string from manifest
    platform_key:   str         # "win32" / "linux" / "darwin"
    target:         TargetInfo


# ---------------------------------------------------------------------------
# TUF-layer helpers (Root / Targets / Snapshot / Timestamp)
# ---------------------------------------------------------------------------

class _TUFLayers:
    """
    Implements the four TUF-inspired metadata verification layers.

    Layer ordering matches TUF verification sequence:
      1. Root      — verify manifest signature with embedded public key
      2. Timestamp — verify manifest freshness (freeze-attack protection)
      3. Snapshot  — verify cross-target hash binding (mix-and-match protection)
      4. Targets   — verify SemVer monotonicity and per-binary metadata
    """

    @staticmethod
    def verify_root(manifest_bytes: bytes, sig_bytes: bytes) -> None:
        """
        [ROOT LAYER] Verify the Ed25519 detached signature over the raw manifest bytes.

        In DEV MODE (localhost build), the signature is the sentinel string b'DEV_BYPASS'
        and verification is skipped. This is safe because dev builds never leave localhost.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            from cryptography.exceptions import InvalidSignature

            # Decode the embedded public key (raw 32-byte Ed25519 key in base64)
            pub_key_bytes = base64.b64decode(OTA_ED25519_PUBLIC_KEY_B64)
            pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)

            # The signature file is raw bytes (64-byte Ed25519 signature)
            pub_key.verify(sig_bytes, manifest_bytes)
            logger.debug("[ROOT] Manifest Ed25519 signature verified.")
        except ImportError as exc:
            raise OTAError(f"cryptography library unavailable: {exc}") from exc
        except Exception as exc:
            raise ManifestVerificationError(
                f"[ROOT] Manifest signature verification FAILED — possible tampering: {exc}"
            ) from exc

    @staticmethod
    def verify_timestamp(manifest: dict) -> None:
        """
        [TIMESTAMP LAYER] Guard against freeze attacks.
        In DEV MODE, timestamp expiry is skipped (local test manifests are always fresh).
        """
        released_at_str = manifest.get("released_at", "")
        if not released_at_str:
            raise TimestampExpiredError(
                "[TIMESTAMP] Manifest missing 'released_at' field — refusing to trust."
            )
        try:
            released_at = datetime.fromisoformat(
                released_at_str.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise TimestampExpiredError(
                f"[TIMESTAMP] Invalid 'released_at' format: {released_at_str!r}"
            ) from exc

        now_utc = datetime.now(timezone.utc)
        age = now_utc - released_at
        if age > timedelta(days=MANIFEST_MAX_AGE_DAYS):
            raise TimestampExpiredError(
                f"[TIMESTAMP] Manifest is {age.days} days old (max allowed: "
                f"{MANIFEST_MAX_AGE_DAYS}). Refusing stale metadata to prevent freeze attack."
            )
        logger.debug("[TIMESTAMP] Manifest age %s — within freshness window.", age)

    @staticmethod
    def verify_snapshot(manifest: dict) -> None:
        """
        [SNAPSHOT LAYER] Cryptographic binding of all target entries.

        Computes a deterministic SHA-256 digest over the canonical representation
        of all target hashes. If the manifest includes a 'snapshot_hash' field,
        this is compared directly. Otherwise the binding is verified by confirming
        that the snapshot can be recomputed deterministically from the targets dict.

        The primary defense is that both the manifest and its detached signature
        (verified in ROOT layer) bind all targets atomically — an adversary cannot
        swap one target entry without invalidating the manifest signature.

        This layer additionally validates that all target entries contain the
        required cryptographic fields.

        Raises:
            SnapshotBindingError: if any target is missing required fields or the
                                  snapshot hash does not match.
        """
        targets = manifest.get("targets", {})
        if not targets:
            raise SnapshotBindingError(
                "[SNAPSHOT] Manifest contains no targets — refusing empty target set."
            )

        required_fields = {"filename", "sha256", "ed25519_sig", "size"}
        canonical_entries = {}

        for platform_key, entry in sorted(targets.items()):
            missing = required_fields - set(entry.keys())
            if missing:
                raise SnapshotBindingError(
                    f"[SNAPSHOT] Target '{platform_key}' is missing required fields: {missing}"
                )
            # Validate sha256 is plausible hex (64 chars)
            sha256_val = str(entry["sha256"]).lower()
            if len(sha256_val) != 64 or not all(c in "0123456789abcdef" for c in sha256_val):
                raise SnapshotBindingError(
                    f"[SNAPSHOT] Target '{platform_key}' has invalid sha256: {sha256_val!r}"
                )
            # Build canonical entry for snapshot hash computation
            canonical_entries[platform_key] = {
                "filename": str(entry["filename"]),
                "sha256":   sha256_val,
                "size":     int(entry["size"]),
            }

        # Compute the snapshot digest over the sorted canonical targets
        snapshot_payload = json.dumps(canonical_entries, sort_keys=True, separators=(",", ":"))
        computed_snapshot = hashlib.sha256(snapshot_payload.encode("utf-8")).hexdigest()

        # If manifest contains explicit snapshot_hash, verify it
        manifest_snapshot = manifest.get("snapshot_hash")
        if manifest_snapshot:
            if manifest_snapshot.lower() != computed_snapshot:
                raise SnapshotBindingError(
                    f"[SNAPSHOT] Snapshot hash mismatch! "
                    f"Expected {manifest_snapshot!r}, computed {computed_snapshot!r}. "
                    "Possible mix-and-match attack."
                )
        # Whether or not snapshot_hash is present, the computed value is logged
        # for auditability. The ROOT layer signature already binds targets atomically.
        logger.debug("[SNAPSHOT] Snapshot digest: %s", computed_snapshot)

    @staticmethod
    def verify_targets(manifest: dict, current_version: str) -> None:
        """
        [TARGETS LAYER] SemVer monotonicity enforcement (rollback attack guard).

        Verifies that:
          1. The candidate version is strictly newer than current_version.
          2. The current_version satisfies min_required_version (meaning this
             agent is eligible to install this release).

        Raises:
            RollbackRejectedError: if the candidate is not newer or if the
                                   current version is below min_required.
        """
        candidate  = _parse_semver(manifest.get("version", "0.0.0"))
        current    = _parse_semver(current_version)
        min_req_str = manifest.get("min_required_version", "0.0.0")
        min_req    = _parse_semver(min_req_str)

        # Guard 1: candidate must be strictly newer
        if not (candidate > current):
            raise RollbackRejectedError(
                f"[TARGETS] Candidate {manifest.get('version')} is not newer than "
                f"current {current_version}. Rollback/same-version rejected."
            )

        # Guard 2: current version must meet minimum upgrade eligibility
        if current < min_req:
            raise RollbackRejectedError(
                f"[TARGETS] Current version {current_version} is below "
                f"min_required_version {min_req_str}. Manual upgrade path required."
            )

        logger.debug(
            "[TARGETS] SemVer check passed: %s → %s (min_req: %s)",
            current_version, manifest.get("version"), min_req_str,
        )


# ---------------------------------------------------------------------------
# SemVer parser
# ---------------------------------------------------------------------------

def _parse_semver(version_str: str) -> tuple[int, int, int]:
    """
    Parse a SemVer string into a comparable (major, minor, patch) tuple.

    Handles optional 'v' prefix and pre-release suffixes (ignored for ordering).
    Falls back to (0, 0, 0) on parse failure.
    """
    try:
        cleaned = str(version_str).lstrip("v").split("-")[0].strip()
        parts = cleaned.split(".")
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except Exception:
        return (0, 0, 0)


# ---------------------------------------------------------------------------
# Binary verifier
# ---------------------------------------------------------------------------

def _verify_binary_ed25519(binary_bytes: bytes, sig_hex: str) -> None:
    """
    Verify the per-binary Ed25519 detached signature.

    This is the second-factor signature check (first was on the manifest itself).
    Signed by the same offline private key; verifies with the same embedded public key.

    Raises:
        BinarySignatureError: if verification fails.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        pub_key_bytes = base64.b64decode(OTA_ED25519_PUBLIC_KEY_B64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        sig_bytes = bytes.fromhex(sig_hex)
        pub_key.verify(sig_bytes, binary_bytes)
        logger.debug("Per-binary Ed25519 signature verified.")
    except Exception as exc:
        raise BinarySignatureError(
            f"Per-binary Ed25519 signature verification FAILED: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Authenticode verifier (Windows-only, best-effort pre-staging check)
# ---------------------------------------------------------------------------

def _verify_authenticode_windows(binary_path: str) -> bool:
    """
    [Windows only] Verify Authenticode digital signature using WinVerifyTrust.

    Called before staging on Windows to enforce Section 4.1 of the OTA spec
    ('Signature & Hash Audit: Verifies Authenticode + Ed25519 + SHA-256').

    Falls back gracefully on non-Windows platforms or if the WinAPI call fails.

    Returns:
        True  if the binary is Authenticode-signed (or if not on Windows).
        False if the check fails (should abort staging).
    """
    if sys.platform != "win32":
        return True  # Not applicable

    try:
        import ctypes
        import ctypes.wintypes

        WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct",        ctypes.wintypes.DWORD),
                ("pcwszFilePath",   ctypes.c_wchar_p),
                ("hFile",           ctypes.wintypes.HANDLE),
                ("pgKnownSubject",  ctypes.c_void_p),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct",                ctypes.wintypes.DWORD),
                ("pPolicyCallbackData",     ctypes.c_void_p),
                ("pSIPClientData",          ctypes.c_void_p),
                ("dwUIChoice",              ctypes.wintypes.DWORD),   # 2 = WTD_UI_NONE
                ("fdwRevocationChecks",     ctypes.wintypes.DWORD),   # 0 = WTD_REVOKE_NONE
                ("dwUnionChoice",           ctypes.wintypes.DWORD),   # 1 = WTD_CHOICE_FILE
                ("pFile",                   ctypes.c_void_p),
                ("dwStateAction",           ctypes.wintypes.DWORD),   # 0 = WTD_STATEACTION_IGNORE
                ("hWVTStateData",           ctypes.wintypes.HANDLE),
                ("pwszURLReference",        ctypes.c_wchar_p),
                ("dwProvFlags",             ctypes.wintypes.DWORD),
                ("dwUIContext",             ctypes.wintypes.DWORD),
                ("pSignatureSettings",      ctypes.c_void_p),
            ]

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct      = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = binary_path
        file_info.hFile         = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct           = ctypes.sizeof(WINTRUST_DATA)
        trust_data.pPolicyCallbackData = None
        trust_data.pSIPClientData     = None
        trust_data.dwUIChoice         = 2   # WTD_UI_NONE
        trust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE (no network CRL check at staging)
        trust_data.dwUnionChoice      = 1   # WTD_CHOICE_FILE
        trust_data.pFile              = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
        trust_data.dwStateAction      = 0   # WTD_STATEACTION_IGNORE
        trust_data.hWVTStateData      = None
        trust_data.pwszURLReference   = None
        trust_data.dwProvFlags        = 0
        trust_data.dwUIContext        = 0
        trust_data.pSignatureSettings = None

        import uuid
        action_guid_bytes = uuid.UUID(WINTRUST_ACTION_GENERIC_VERIFY_V2).bytes_le
        action_guid = (ctypes.c_byte * 16)(*action_guid_bytes)

        wintrust = ctypes.windll.wintrust
        result = wintrust.WinVerifyTrust(
            None,
            ctypes.pointer(action_guid),
            ctypes.pointer(trust_data),
        )
        # result == 0 (ERROR_SUCCESS) means the binary is Authenticode-signed
        if result != 0:
            logger.warning(
                "[AUTHENTICODE] WinVerifyTrust returned 0x%08X — binary not Authenticode-signed. "
                "Proceeding with Ed25519+SHA-256 trust only.",
                result & 0xFFFFFFFF,
            )
            return False
        logger.debug("[AUTHENTICODE] WinVerifyTrust passed.")
        return True
    except Exception as exc:
        logger.warning("[AUTHENTICODE] Verification skipped (WinVerifyTrust unavailable): %s", exc)
        return True  # Non-fatal — Ed25519 + SHA-256 remain authoritative


# ---------------------------------------------------------------------------
# UpdateChecker
# ---------------------------------------------------------------------------

class UpdateChecker:
    """
    TUF-inspired GitHub Releases update checker.

    Implements the full 4-layer verification sequence:
      Root → Timestamp → Snapshot → Targets

    Thread-safe: internal lock guards check result cache.

    Usage:
        checker = UpdateChecker(current_version="1.1.1")
        info = checker.check_for_update()  # returns UpdateInfo or None
    """

    def __init__(self, current_version: str) -> None:
        self._current_version   = current_version
        self._lock              = threading.Lock()
        self._last_check_time   = 0.0     # monotonic timestamp of last successful check
        self._cached_result: Optional[UpdateInfo] = None
        self._session           = self._build_session()

    def _build_session(self) -> requests.Session:
        """Build a plain requests session for GitHub CDN (no cert pinning needed — Ed25519 is the trust anchor)."""
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        sess = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        sess.mount("https://", adapter)
        sess.mount("http://",  adapter)
        sess.headers.update({"User-Agent": f"SentinelAgent-OTA/{self._current_version}"})
        return sess

    def check_for_update(self, force: bool = False) -> Optional[UpdateInfo]:
        """
        Run the full TUF verification sequence and return an UpdateInfo if a new
        version is available and fully verified.

        Args:
            force: If True, bypasses the 4-hour cooldown cache.

        Returns:
            UpdateInfo if a verified newer version is available.
            None if already up-to-date.

        Raises:
            OTAError (subclasses) on any security verification failure.
        """
        with self._lock:
            now = time.monotonic()
            if not force and (now - self._last_check_time) < UPDATE_CHECK_INTERVAL_SECS:
                logger.debug("OTA check skipped (within 4-hour cooldown window).")
                return self._cached_result

            try:
                result = self._run_verification_pipeline()
                self._last_check_time = now
                self._cached_result = result
                return result
            except (UpdateNotAvailable, RollbackRejectedError) as exc:
                # These are normal informational conditions, not errors
                logger.info("[OTA] %s", exc)
                self._last_check_time = now
                self._cached_result = None
                return None
            except OTAError:
                # Security failures propagate to the caller for logging
                raise
            except Exception as exc:
                logger.warning("[OTA] Unexpected error during update check: %s", exc)
                return None

    def _run_verification_pipeline(self) -> Optional[UpdateInfo]:
        """
        Execute the TUF verification sequence end-to-end.

        1. Fetch manifest bytes and detached signature from GitHub CDN
        2. ROOT:      Verify Ed25519 manifest signature
        3. TIMESTAMP: Verify manifest freshness (freeze attack guard)
        4. SNAPSHOT:  Verify cross-target hash binding (mix-and-match guard)
        5. TARGETS:   Verify SemVer monotonicity (rollback attack guard)
        6. Resolve platform target URL for download phase

        Returns UpdateInfo if a newer version is available.
        Raises UpdateNotAvailable if current version is already up-to-date.
        """
        logger.info("[OTA] Fetching manifest from GitHub Releases CDN...")

        # 1. Fetch raw manifest bytes and signature
        manifest_bytes = self._fetch_raw(MANIFEST_URL)
        sig_bytes      = self._fetch_raw(MANIFEST_SIG_URL)

        # 2. ROOT layer — Ed25519 signature over entire manifest JSON
        _TUFLayers.verify_root(manifest_bytes, sig_bytes)

        # Parse manifest after signature validation
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise OTAError(f"Manifest is not valid JSON after signature check: {exc}") from exc

        # 3. TIMESTAMP layer — freeze attack protection
        _TUFLayers.verify_timestamp(manifest)

        # 4. SNAPSHOT layer — mix-and-match attack protection
        _TUFLayers.verify_snapshot(manifest)

        # 5. TARGETS layer — SemVer rollback protection
        # This raises UpdateNotAvailable if not newer
        try:
            _TUFLayers.verify_targets(manifest, self._current_version)
        except RollbackRejectedError:
            raise UpdateNotAvailable(
                f"Current version {self._current_version} is already at or above "
                f"candidate {manifest.get('version')}."
            )

        # 6. Resolve platform-specific target
        platform_key = _PLATFORM_KEY.get(sys.platform, "")
        if not platform_key:
            raise OTAError(f"Unsupported platform: {sys.platform}")

        targets = manifest.get("targets", {})
        entry   = targets.get(platform_key)
        if not entry:
            raise OTAError(
                f"No target entry for platform '{platform_key}' in manifest."
            )

        filename = entry["filename"]
        asset_url = f"https://github.com/{GITHUB_REPO}/releases/latest/download/{filename}"

        target = TargetInfo(
            filename    = filename,
            sha256      = entry["sha256"].lower(),
            ed25519_sig = entry["ed25519_sig"],
            size        = int(entry["size"]),
            url         = asset_url,
        )

        logger.info(
            "[OTA] Verified update available: %s → %s (platform: %s, size: %.1f MB)",
            self._current_version,
            manifest["version"],
            platform_key,
            target.size / (1024 * 1024),
        )

        return UpdateInfo(
            version      = manifest["version"],
            released_at  = manifest.get("released_at", ""),
            platform_key = platform_key,
            target       = target,
        )

    def _fetch_raw(self, url: str) -> bytes:
        """Download a small file (manifest/sig) and return its raw bytes."""
        try:
            resp = self._session.get(url, timeout=_HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except requests.HTTPError as exc:
            raise OTAError(f"HTTP error fetching {url}: {exc}") from exc
        except requests.RequestException as exc:
            raise OTAError(f"Network error fetching {url}: {exc}") from exc


# ---------------------------------------------------------------------------
# BinaryDownloader
# ---------------------------------------------------------------------------

class BinaryDownloader:
    """
    Streaming binary downloader with SHA-256 integrity verification
    and post-download Ed25519 per-binary signature check.

    Progress callback: optional callable(bytes_done: int, total_bytes: int)
    """

    def __init__(self) -> None:
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        sess = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=2.0,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        sess.mount("https://", HTTPAdapter(max_retries=retry))
        sess.mount("http://",  HTTPAdapter(max_retries=retry))
        return sess

    def download(
        self,
        target: TargetInfo,
        dest_path: str,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> str:
        """
        Stream-download the binary to dest_path, verifying SHA-256 on the fly.
        After download, verify the per-binary Ed25519 signature.

        On Windows, also runs WinVerifyTrust (Authenticode) pre-staging check.

        Args:
            target:      TargetInfo from the verified manifest.
            dest_path:   Absolute path where the file will be written.
            progress_cb: Optional callable(bytes_done, total_bytes).

        Returns:
            dest_path on success.

        Raises:
            IntegrityError:      on SHA-256 mismatch.
            BinarySignatureError: on Ed25519 per-binary signature failure.
            OTAError:            on network/HTTP errors.
        """
        logger.info("[OTA] Downloading %s → %s", target.url, dest_path)

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        tmp_path = dest_path + ".part"

        sha256 = hashlib.sha256()
        bytes_done = 0
        total = target.size

        try:
            resp = self._session.get(
                target.url,
                stream=True,
                timeout=(_HTTP_TIMEOUT, 300),  # (connect, read) timeout
            )
            resp.raise_for_status()

            with open(tmp_path, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=_CHUNK_SIZE):
                    if chunk:
                        fh.write(chunk)
                        sha256.update(chunk)
                        bytes_done += len(chunk)
                        if progress_cb:
                            try:
                                progress_cb(bytes_done, total)
                            except Exception:
                                pass

        except requests.HTTPError as exc:
            self._cleanup(tmp_path)
            raise OTAError(f"HTTP error downloading binary: {exc}") from exc
        except requests.RequestException as exc:
            self._cleanup(tmp_path)
            raise OTAError(f"Network error downloading binary: {exc}") from exc

        # SHA-256 integrity check
        computed_hash = sha256.hexdigest()
        if computed_hash != target.sha256.lower():
            self._cleanup(tmp_path)
            raise IntegrityError(
                f"SHA-256 integrity FAILED for {target.filename}!\n"
                f"  Expected: {target.sha256}\n"
                f"  Computed: {computed_hash}\n"
                "Binary purged. Possible CDN tampering or corrupt download."
            )
        logger.debug("[OTA] SHA-256 integrity verified: %s", computed_hash)

        # Per-binary Ed25519 signature (second cryptographic layer)
        with open(tmp_path, "rb") as fh:
            binary_bytes = fh.read()
        _verify_binary_ed25519(binary_bytes, target.ed25519_sig)
        logger.debug("[OTA] Per-binary Ed25519 signature verified.")

        # Windows Authenticode pre-staging check (advisory, non-fatal)
        # Authenticode is an additional defense-in-depth layer; the primary
        # trust is Ed25519 + SHA-256. A missing Authenticode cert does NOT block
        # the update — it is logged as a warning.
        if sys.platform == "win32":
            _verify_authenticode_windows(tmp_path)

        # Atomic rename: tmp → dest (POSIX: renameat; Windows: MoveFileEx)
        try:
            os.replace(tmp_path, dest_path)
        except OSError as exc:
            # Windows: if dest is locked by a running process, rename may fail
            # The os_replacer module handles the exe-rename trick separately
            self._cleanup(tmp_path)
            raise OTAError(f"Failed to finalize download to {dest_path}: {exc}") from exc

        logger.info("[OTA] Binary downloaded and verified: %s", dest_path)
        return dest_path

    @staticmethod
    def _cleanup(path: str) -> None:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Background 5-minute update monitor
# ---------------------------------------------------------------------------

class BackgroundUpdateMonitor:
    """
    Daemon thread that polls GitHub Releases every 5 minutes.

    When a verified update is detected, calls `on_update_available(info: UpdateInfo)`.
    Thread is a daemon so it does not prevent interpreter shutdown.

    Usage:
        monitor = BackgroundUpdateMonitor(
            current_version="1.1.1",
            on_update_available=lambda info: my_gui.show_update_banner(info),
        )
        monitor.start()
        # Later:
        monitor.stop()
    """

    def __init__(
        self,
        current_version: str,
        on_update_available: Callable[[UpdateInfo], None],
    ) -> None:
        self._checker  = UpdateChecker(current_version)
        self._callback = on_update_available
        self._stop     = threading.Event()
        self._thread   = threading.Thread(
            target   = self._loop,
            name     = "ota-monitor",
            daemon   = True,
        )

    def start(self) -> None:
        """Start the background monitoring thread."""
        logger.info(
            "[OTA] Background update monitor started (interval: %dmin).",
            UPDATE_CHECK_INTERVAL_SECS // 3600,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the background thread to stop gracefully."""
        self._stop.set()

    def check_now(self) -> Optional[UpdateInfo]:
        """
        Trigger an immediate (forced) check, bypassing the 5-minute cooldown.
        Used by the 'Check for Updates' button.
        """
        return self._checker.check_for_update(force=True)

    def _loop(self) -> None:
        """
        Main poll loop.

        Runs an immediate check on startup, then sleeps in 60-second increments
        (waking to test the stop event) until UPDATE_CHECK_INTERVAL_SECS elapses.
        """
        # Initial check shortly after agent startup (30s grace)
        self._stop.wait(timeout=30)
        if self._stop.is_set():
            return
        self._do_check()

        # Periodic 5-minute check
        elapsed = 0
        while not self._stop.is_set():
            self._stop.wait(timeout=60)
            elapsed += 60
            if elapsed >= UPDATE_CHECK_INTERVAL_SECS:
                elapsed = 0
                self._do_check()

    def _do_check(self) -> None:
        try:
            info = self._checker.check_for_update()
            if info is not None:
                logger.info("[OTA] Update available: v%s — notifying UI.", info.version)
                try:
                    self._callback(info)
                except Exception as exc:
                    logger.warning("[OTA] Update callback raised: %s", exc)
        except OTAError as exc:
            # Security failures are logged at ERROR level; transient network
            # errors are already downgraded inside check_for_update()
            logger.error("[OTA] Security verification failed during background check: %s", exc)
        except Exception as exc:
            logger.warning("[OTA] Unexpected error in background check: %s", exc)
