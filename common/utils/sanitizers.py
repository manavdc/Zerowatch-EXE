"""
common/utils/sanitizers.py
─────────────────────────────────────────────────────────────────────────────
Platform-independent string sanitization and normalization utilities.
"""

from __future__ import annotations

USERNAME_MAX_LENGTH = 20
ASSETNAME_MAX_LENGTH = 20
HOSTNAME_MAX_LENGTH = 64
ORGANIZATION_NAME_MAX_LENGTH = 80


def sanitize_username(value: str | None, fallback: str = "Unknown") -> str:
    username = str(value or "").strip()
    if not username:
        username = fallback
    return username[:USERNAME_MAX_LENGTH]


def sanitize_asset_name(value: str | None, fallback: str = "Unknown") -> str:
    asset_name = str(value or "").strip()
    if not asset_name:
        asset_name = fallback
    return asset_name[:ASSETNAME_MAX_LENGTH]


def sanitize_hostname(value: str | None, fallback: str = "Unknown") -> str:
    hostname = str(value or "").strip()
    if not hostname:
        hostname = fallback
    return hostname[:HOSTNAME_MAX_LENGTH]


def sanitize_organization_name(value: str | None, fallback: str = "Unknown") -> str:
    organization_name = str(value or "").strip()
    if not organization_name:
        organization_name = fallback
    return organization_name[:ORGANIZATION_NAME_MAX_LENGTH]
