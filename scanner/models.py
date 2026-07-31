"""
scanner/models.py (Forwarding adapter to common.scanner.models)
─────────────────────────────────────────────────────────────────────────────
Preserves backward compatibility for legacy imports while using the portable
common.scanner.models package.
"""

from common.scanner.models import (
    SoftwareItem,
    SOURCE_REGISTRY,
    SOURCE_WINDOWS_STORE,
    SOURCE_DRIVER,
    SOURCE_PE_BINARY,
    SOURCE_PE_DLL,
    SOURCE_PE_SYS,
    SOURCE_NPM_MANIFEST,
    SOURCE_NPM_LOCKFILE,
    SOURCE_PIP_REQUIREMENTS,
    SOURCE_PIP_LOCKFILE,
    SOURCE_PYPROJECT,
    SOURCE_MAVEN,
    SOURCE_GRADLE,
    SOURCE_NUGET,
    SOURCE_GO_MOD,
    SOURCE_CARGO,
    SOURCE_GEM,
    SOURCE_COMPOSER,
    SOURCE_JAR,
    SOURCE_ZIP_ARCHIVE,
)

__all__ = [
    "SoftwareItem",
    "SOURCE_REGISTRY",
    "SOURCE_WINDOWS_STORE",
    "SOURCE_DRIVER",
    "SOURCE_PE_BINARY",
    "SOURCE_PE_DLL",
    "SOURCE_PE_SYS",
    "SOURCE_NPM_MANIFEST",
    "SOURCE_NPM_LOCKFILE",
    "SOURCE_PIP_REQUIREMENTS",
    "SOURCE_PIP_LOCKFILE",
    "SOURCE_PYPROJECT",
    "SOURCE_MAVEN",
    "SOURCE_GRADLE",
    "SOURCE_NUGET",
    "SOURCE_GO_MOD",
    "SOURCE_CARGO",
    "SOURCE_GEM",
    "SOURCE_COMPOSER",
    "SOURCE_JAR",
    "SOURCE_ZIP_ARCHIVE",
]
