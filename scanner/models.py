"""
scanner/models.py (Forwarding adapter to common.scanner.models)
─────────────────────────────────────────────────────────────────────────────
Preserves backward compatibility for legacy imports while using the portable
common.scanner.models package.
"""

from common.scanner.models import (
    SoftwareItem,
    # Windows
    SOURCE_REGISTRY,
    SOURCE_WINDOWS_STORE,
    SOURCE_DRIVER,
    SOURCE_PE_BINARY,
    SOURCE_PE_DLL,
    SOURCE_PE_SYS,
    # Manifests / L2 (all platforms)
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
    # Linux
    SOURCE_DEB_PACKAGE,
    SOURCE_RPM_PACKAGE,
    SOURCE_PACMAN_PKG,
    SOURCE_SNAP_APP,
    SOURCE_FLATPAK_APP,
    SOURCE_KERNEL_MODULE,
    SOURCE_ELF_BINARY,
    SOURCE_ELF_LIB,
    # macOS
    SOURCE_APP_BUNDLE,
    SOURCE_MACOS_PKG,
    SOURCE_HOMEBREW_FORMULA,
    SOURCE_HOMEBREW_CASK,
    SOURCE_MACPORTS,
    SOURCE_MACHO_BINARY,
    SOURCE_DYLIB,
)

__all__ = [
    "SoftwareItem",
    # Windows
    "SOURCE_REGISTRY",
    "SOURCE_WINDOWS_STORE",
    "SOURCE_DRIVER",
    "SOURCE_PE_BINARY",
    "SOURCE_PE_DLL",
    "SOURCE_PE_SYS",
    # Manifests / L2
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
    # Linux
    "SOURCE_DEB_PACKAGE",
    "SOURCE_RPM_PACKAGE",
    "SOURCE_PACMAN_PKG",
    "SOURCE_SNAP_APP",
    "SOURCE_FLATPAK_APP",
    "SOURCE_KERNEL_MODULE",
    "SOURCE_ELF_BINARY",
    "SOURCE_ELF_LIB",
    # macOS
    "SOURCE_APP_BUNDLE",
    "SOURCE_MACOS_PKG",
    "SOURCE_HOMEBREW_FORMULA",
    "SOURCE_HOMEBREW_CASK",
    "SOURCE_MACPORTS",
    "SOURCE_MACHO_BINARY",
    "SOURCE_DYLIB",
]
