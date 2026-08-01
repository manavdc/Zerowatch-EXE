"""
linux/hardware/fingerprint.py
─────────────────────────────────────────────────────────────────────────────
Linux hardware fingerprinting and stable device ID generation.

Identity priority:
  1. /etc/machine-id  (systemd-generated, stable, persists reinstalls of same installation)
  2. /sys/class/dmi/id/product_uuid  (BIOS UUID — stable across OS reinstalls)
  3. sha256(hostname)  (last resort for containers / minimal systems)

Device ID format: sha256("lin::{primary_id}") — prefixed to distinguish
from Windows device IDs ("win::{...}") without changing the backend
device ID schema.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
from typing import Optional

logger = logging.getLogger("linux.hardware.fingerprint")


def get_machine_id() -> Optional[str]:
    """Read /etc/machine-id (preferred stable Linux identity)."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                mid = fh.read().strip()
                if mid and len(mid) >= 16:
                    return mid
        except OSError:
            continue
    return None


def get_dmi_product_uuid() -> Optional[str]:
    """Read BIOS/DMI product UUID from sysfs (root access may be needed)."""
    try:
        with open("/sys/class/dmi/id/product_uuid", "r", encoding="utf-8") as fh:
            uuid = fh.read().strip()
            if uuid and uuid.upper() not in ("", "NONE", "NOT APPLICABLE",
                                              "00000000-0000-0000-0000-000000000000"):
                return uuid
    except OSError:
        pass
    return None


def get_primary_identity() -> str:
    """
    Returns the most stable identity string available for this Linux machine.
    Falls back gracefully through the identity chain.
    """
    mid = get_machine_id()
    if mid:
        logger.debug("Using /etc/machine-id as primary identity")
        return mid

    dmi = get_dmi_product_uuid()
    if dmi:
        logger.debug("Using DMI product UUID as primary identity")
        return dmi

    hostname = socket.gethostname() or "unknown-host"
    logger.warning("No machine-id or DMI UUID available; falling back to hostname hash")
    return f"hostname:{hostname}"


def generate_device_id() -> str:
    """
    Generate a deterministic, stable device ID for this Linux endpoint.
    Returns a hex SHA-256 digest prefixed with 'lin::' for namespace separation.
    """
    primary = get_primary_identity()
    raw = f"lin::{primary}"
    device_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return device_id
