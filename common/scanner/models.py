"""
common/scanner/models.py
─────────────────────────────────────────────────────────────────────────────
Canonical data model for a discovered software component.

Every scanner layer (registry, PE binary, manifest parser, etc.) produces
instances of SoftwareItem. The orchestrator merges them, deduplicates, and
serialises them to the exact dict format that ZeroWatchClient.sync_full() /
sync_delta() consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import ClassVar, Dict, Optional
from common.utils.time_ import utc_now_iso


# ── Source tag constants ──────────────────────────────────────────────────────

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

# ── Linux source tags ─────────────────────────────────────────────────────────
SOURCE_DEB_PACKAGE       = "deb_package"
SOURCE_RPM_PACKAGE       = "rpm_package"
SOURCE_PACMAN_PKG        = "pacman_package"
SOURCE_SNAP_APP          = "snap_app"
SOURCE_FLATPAK_APP       = "flatpak_app"
SOURCE_KERNEL_MODULE     = "kernel_module"
SOURCE_ELF_BINARY        = "elf_binary"
SOURCE_ELF_LIB           = "elf_lib"


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
    last_seen:    str = field(default_factory=utc_now_iso)

    # ── Normalisation helpers ─────────────────────────────────────────────────

    _ECOSYSTEM_MAP: ClassVar[Dict[str, str]] = {
        "npm":              "npm",
        "pip":              "pip",
        "pyproject":        "pip",
        "maven":            "maven",
        "gradle":           "maven",
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
        src = (source or "").lower()
        if src in ("registry", "windows_store", "os"):
            return "system"
        if src in ("driver", "pe_sys"):
            return "driver"
        if src in ("pe_binary", "pe_dll"):
            return "pe"
        for prefix, bucket in cls._ECOSYSTEM_MAP.items():
            if src.startswith(prefix):
                return bucket
        return src

    def dedup_key(self) -> str:
        eco = self._ecosystem_bucket(self.source)
        n = (self.name or "").strip().lower()
        v = (self.version or "").strip().lower()
        return f"{eco}::{n}::{v}"

    def is_valid(self) -> bool:
        return bool((self.name or "").strip())

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_api_dict(self) -> dict:
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
