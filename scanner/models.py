"""
scanner/models.py
─────────────────────────────────────────────────────────────────────────────
Canonical data model for a discovered software component.

Every scanner layer (registry, PE binary, manifest parser, etc.) must
produce instances of SoftwareItem.  The orchestrator merges them,
deduplicates, and serialises them to the exact dict format that
ZeroWatchClient.sync_full() / sync_delta() already consume, so the
backend API contract is never broken.

Design notes
────────────
• Plain dataclass – no external dependencies, pickles cleanly, can be
  trivially serialised to JSON via asdict().
• All string fields default to "" instead of None so callers never need
  to guard against None when building dedup keys or sort keys.
• `source` is a free-form tag.  Existing value "registry" is preserved;
  new values from other layers are purely additive and the backend
  already ignores unknown source tags.
• `scan_path` is for internal/cache use only and is NOT sent to the
  backend.  It tells the cache which on-disk file produced this item so
  that the incremental scanner can invalidate precisely the right entries
  when a file changes.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field, asdict
from typing import ClassVar, Dict, Optional


# ── Source tag constants ──────────────────────────────────────────────────────
# These must be treated as an open set; do not use an Enum so that future
# layers can add tags without touching this file.

SOURCE_REGISTRY          = "registry"
SOURCE_WINDOWS_STORE     = "windows_store"
SOURCE_DRIVER            = "driver"
SOURCE_PE_BINARY         = "pe_binary"
SOURCE_PE_DLL            = "pe_dll"
SOURCE_PE_SYS            = "pe_sys"
SOURCE_NPM_MANIFEST      = "npm_manifest"
SOURCE_NPM_LOCKFILE      = "npm_lockfile"
SOURCE_PIP_REQUIREMENTS  = "pip_requirements"
SOURCE_PIP_LOCKFILE      = "pip_lockfile"
SOURCE_PYPROJECT         = "pyproject"
SOURCE_MAVEN             = "maven"
SOURCE_GRADLE            = "gradle"
SOURCE_NUGET             = "nuget"
SOURCE_GO_MOD            = "go_mod"
SOURCE_CARGO             = "cargo"
SOURCE_GEM               = "gem"
SOURCE_COMPOSER          = "composer"
SOURCE_JAR               = "jar_manifest"
SOURCE_ZIP_ARCHIVE       = "zip_archive"


# ── Item dataclass ────────────────────────────────────────────────────────────

@dataclass
class SoftwareItem:
    """One discovered software component, from any scan layer."""

    # --- Core identity (sent to backend) ---
    name:         str = ""
    version:      str = ""
    vendor:       str = ""

    # --- Enrichment metadata (sent to backend where present) ---
    source:       str = SOURCE_REGISTRY   # Which scanner layer produced this
    category:     str = "software"        # software | driver | os | hardware
    install_date: Optional[str] = None    # ISO-8601 UTC or None
    install_location: str = ""            # install path if known

    # --- Internal / cache fields (NOT sent to backend) ---
    scan_path:    str = ""    # Absolute path of the file that produced this item
    change_type:  str = "initial"  # initial | added | removed
    last_seen:    str = field(
        default_factory=lambda: datetime.datetime.now(
            datetime.timezone.utc
        ).replace(microsecond=0).isoformat()
    )

    # ── Normalisation helpers ─────────────────────────────────────────────────

    # Maps a source tag prefix to a short ecosystem bucket used in dedup keys.
    # All npm-family sources (npm_manifest, npm_lockfile) share one bucket so
    # the same package reported by package.json AND package-lock.json still
    # deduplicates. Packages from completely different ecosystems (npm vs pip)
    # that happen to share a name and version are kept separate because they
    # are different software with independent CVE exposure.
    _ECOSYSTEM_MAP: ClassVar[Dict[str, str]] = {
        "npm":              "npm",
        "pip":              "pip",
        "pyproject":        "pip",
        "maven":            "maven",
        "gradle":           "maven",    # Gradle declares the same GAV coordinates
        "cargo":            "cargo",
        "go_mod":           "go",
        "gem":              "gem",
        "composer":         "composer",
        "nuget":            "nuget",
        "jar":              "jar",
        "zip":              "zip",
    }

    @classmethod
    def _ecosystem_bucket(cls, source: str) -> str:
        """
        Derive a short ecosystem label from the source tag.
        
        Rules:
        - npm_manifest  → npm
        - npm_lockfile  → npm   (same bucket — both report the same packages)
        - pip_requirements → pip
        - pip_lockfile  → pip
        - registry / windows_store / os → 'system'  (OS-managed; high priority)
        - pe_binary / pe_dll / pe_sys  → 'pe'       (binary inspection)
        - driver                       → 'driver'
        Everything else maps to its own source name so nothing is lost.
        """
        src = (source or "").lower()
        # System-level sources
        if src in ("registry", "windows_store", "os"):
            return "system"
        if src in ("driver", "pe_sys"):
            return "driver"
        if src in ("pe_binary", "pe_dll"):
            return "pe"
        # Ecosystem prefix match
        for prefix, bucket in cls._ECOSYSTEM_MAP.items():
            if src.startswith(prefix):
                return bucket
        return src  # Fallback: use the source tag verbatim

    def dedup_key(self) -> str:
        """
        Stable dedup key used for merging items from multiple scanner layers.
        Lower-cased so "Firefox" and "firefox" collapse to the same entry.
        Version is included so that a version upgrade is treated as a new item.
        Ecosystem is included so that an npm package and a pip package that
        share the same name and version are NOT incorrectly merged — they are
        completely different software with independent CVE histories.

        Format: {ecosystem}::{name}::{version}
        Examples:
          npm::lodash::4.17.21
          pip::requests::2.31.0
          system::python::3.11.5
          pe::nmap::7.94
        """
        eco = self._ecosystem_bucket(self.source)
        n = (self.name or "").strip().lower()
        v = (self.version or "").strip().lower()
        return f"{eco}::{n}::{v}"

    def is_valid(self) -> bool:
        """A SoftwareItem is only worth keeping if it has a non-empty name."""
        return bool((self.name or "").strip())

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_api_dict(self) -> dict:
        """
        Serialise to the dict format consumed by ZeroWatchClient.sync_full()
        and ZeroWatchClient.sync_delta().

        Fields that sync_full already projects:
            name, version, vendor, install_date, source
        Additional fields passed through (backend accepts extras silently):
            category, install_location
        Internal fields (scan_path, change_type, last_seen) are excluded
        from the API payload but kept on the object for cache use.
        """
        return {
            "name":             self.name,
            "version":          self.version,
            "vendor":           self.vendor,
            "source":           self.source,
            "category":         self.category,
            "install_date":     self.install_date,
            "install_location": self.install_location,
            "last_seen":        self.last_seen,
            "change_type":      self.change_type,
        }

    def to_cache_dict(self) -> dict:
        """Full serialisation for SQLite storage (includes scan_path)."""
        d = self.to_api_dict()
        d["scan_path"] = self.scan_path
        return d

    @staticmethod
    def from_cache_dict(d: dict) -> "SoftwareItem":
        return SoftwareItem(
            name             = d.get("name", ""),
            version          = d.get("version", ""),
            vendor           = d.get("vendor", ""),
            source           = d.get("source", SOURCE_REGISTRY),
            category         = d.get("category", "software"),
            install_date     = d.get("install_date"),
            install_location = d.get("install_location", ""),
            scan_path        = d.get("scan_path", ""),
            change_type      = d.get("change_type", "initial"),
            last_seen        = d.get("last_seen", ""),
        )

    @staticmethod
    def from_legacy_dict(d: dict) -> "SoftwareItem":
        """
        Convert the existing dict format returned by
        get_installed_software_registry() / get_hardware_inventory()
        into a SoftwareItem, preserving all fields.
        """
        return SoftwareItem(
            name             = d.get("name", ""),
            version          = d.get("version", ""),
            vendor           = d.get("vendor") or d.get("publisher", ""),
            source           = d.get("source", SOURCE_REGISTRY),
            category         = d.get("category", "software"),
            install_date     = d.get("install_date"),
            install_location = d.get("install_location", ""),
            scan_path        = "",
            change_type      = d.get("change_type", "initial"),
            last_seen        = d.get("last_seen", ""),
        )
