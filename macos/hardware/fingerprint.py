"""
macos/hardware/fingerprint.py
─────────────────────────────────────────────────────────────────────────────
macOS hardware fingerprinting and stable device ID generation.

Identity Hierarchy (most-stable first):
  1. IOPlatformUUID — hardware-level UUID from IOKit/IOPlatformExpertDevice.
     Survives OS reinstalls and is stable to the physical motherboard.
     Read via: ioreg -rd1 -c IOPlatformExpertDevice

  2. IOPlatformSerialNumber — factory serial number.
     NOTE: Serial numbers are unique but can theoretically be reset by
     Apple service; they should not be shared without privacy review.
     Used as fallback only when IOPlatformUUID is unavailable.

  3. hostname-hash — last resort.
     Unstable (changes on rename), produces a different device ID after
     each restart if hostname changes. Reported as a warning, not used
     silently to avoid creating phantom ZeroWatch device registrations.

Device ID format:  sha256("mac::{primary_id}")
  - Mirrors Linux  sha256("lin::{machine-id}") convention.
  - Mirrors Windows sha256("win::{MachineGuid}") convention.
  - Backend sees a 64-character hex string; prefix is embedded inside
    the hash input, not exposed to the backend.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import socket
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger("macos.hardware.fingerprint")

_SUBPROCESS_TIMEOUT = 10  # seconds — intentionally short


# ── ioreg helpers ─────────────────────────────────────────────────────────────

def _run_ioreg() -> str:
    """
    Run `ioreg -rd1 -c IOPlatformExpertDevice` and return stdout.
    Returns empty string on any failure.
    """
    ioreg = shutil.which("ioreg") or "/usr/sbin/ioreg"
    try:
        result = subprocess.run(
            [ioreg, "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        return result.stdout if result.returncode == 0 else ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("ioreg execution failed: %s", exc)
        return ""


def _extract_ioreg_property(output: str, key: str) -> Optional[str]:
    """
    Extract a string property from ioreg output.
    ioreg output format:  "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    """
    # Match:  "<key>" = "<value>"  (ioreg uses C-string quoting for ASCII values)
    pattern = re.compile(
        r'"' + re.escape(key) + r'"\s*=\s*"([^"]+)"',
        re.IGNORECASE,
    )
    m = pattern.search(output)
    if m:
        value = m.group(1).strip()
        return value if value else None
    return None


# ── Public identity functions ─────────────────────────────────────────────────

def get_ioreg_uuid() -> Optional[str]:
    """
    Read IOPlatformUUID from IOKit via ioreg.

    Returns:
        UUID string (e.g. "A1B2C3D4-E5F6-...") or None if unavailable.
    """
    output = _run_ioreg()
    if not output:
        return None
    uuid = _extract_ioreg_property(output, "IOPlatformUUID")
    if uuid and len(uuid) >= 8:
        logger.debug("IOPlatformUUID acquired: %s", uuid[:8] + "...")
        return uuid
    return None


def get_ioreg_serial() -> Optional[str]:
    """
    Read IOPlatformSerialNumber from IOKit via ioreg.

    Note: Serial numbers are unique per device but are considered
    semi-sensitive identifying information. Used only as fallback.

    Returns:
        Serial number string or None if unavailable.
    """
    output = _run_ioreg()
    if not output:
        return None
    serial = _extract_ioreg_property(output, "IOPlatformSerialNumber")
    if serial and len(serial) >= 4:
        logger.debug("IOPlatformSerialNumber acquired (redacted)")
        return serial
    return None


def get_primary_identity() -> Tuple[str, str]:
    """
    Return (identity_value, source_name) for the most stable identity available.

    Hierarchy:
      1. IOPlatformUUID      → ("XXXXXXXX-...", "ioreg_uuid")
      2. IOPlatformSerialNumber → ("CXXXXXXX...", "ioreg_serial")
      3. hostname-hash       → ("hostname:XXXX", "hostname_fallback")  [WARNING logged]
    """
    uuid = get_ioreg_uuid()
    if uuid:
        return uuid, "ioreg_uuid"

    serial = get_ioreg_serial()
    if serial:
        logger.warning(
            "IOPlatformUUID unavailable — falling back to IOPlatformSerialNumber. "
            "Device ID may differ from IOPlatformUUID-based IDs on the same machine."
        )
        return serial, "ioreg_serial"

    hostname = socket.gethostname() or "unknown-mac"
    logger.warning(
        "No IOKit identity available — falling back to hostname '%s'. "
        "This is UNSTABLE: renaming the Mac will generate a new ZeroWatch device. "
        "Native macOS testing required.",
        hostname,
    )
    return f"hostname:{hostname}", "hostname_fallback"


def generate_device_id() -> str:
    """
    Generate a deterministic, stable device ID for this macOS endpoint.

    Returns a 64-character hex SHA-256 digest derived from the best
    available hardware identity. The prefix 'mac::' is embedded inside
    the hash input for namespace separation from Windows ('win::') and
    Linux ('lin::').

    Raises:
        RuntimeError: if no identity is available at all (should not
                      occur in practice as hostname fallback is always present).
    """
    identity, source = get_primary_identity()
    raw = f"mac::{identity}"
    device_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    logger.info(
        "macOS device ID generated (source=%s, id_prefix=%s...)",
        source,
        device_id[:8],
    )
    return device_id
