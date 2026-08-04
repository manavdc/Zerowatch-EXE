"""
macos/scanner/ownership.py
─────────────────────────────────────────────────────────────────────────────
macOS binary ownership resolution.

Strategy (most authoritative first):

  1. .app bundle — if a binary is inside SomeName.app/Contents/MacOS/,
     resolve the owning .app bundle's Info.plist (reuses Phase 6B parser).
     Produces a SoftwareItem with source=SOURCE_APP_BUNDLE.

  2. Homebrew Cellar — if the binary is under /opt/homebrew/Cellar/ or
     /usr/local/Cellar/, extract product name and version from the path
     structure: Cellar/<formula>/<version>/...
     Produces a SoftwareItem with source=SOURCE_HOMEBREW_FORMULA.

  3. pkgutil ownership index — a pre-built in-memory mapping from
     file path → package receipt (pkg_id, version). Built once at startup
     or on demand, then used for all file lookups without spawning a
     subprocess per file.

  4. Filename fallback — standalone Mach-O with no owner identified.
     Produces a minimal SoftwareItem.

Performance considerations:
  - The pkgutil ownership index is built once per scan session by reading
    `pkgutil --files <pkg_id>` for each installed package receipt.
    This is O(packages) subprocesses at build time, but O(1) dict lookups
    afterwards. Since a typical macOS system has ~50–200 meaningful
    third-party packages, and the build runs once per agent lifetime (until
    the cache is invalidated), this is acceptable.
  - The ownership index is NOT rebuilt for every scan — it is built lazily
    on first call and cached in memory for the lifetime of the object.
  - Homebrew Cellar resolution is pure path parsing — no subprocess.
  - .app bundle resolution is pure plistlib parsing — no subprocess.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from common.scanner.models import SoftwareItem
from common.utils.time_ import utc_now_iso
from macos.scanner.package_collector import (
    _read_plist,
    _plist_to_software_item,
    SOURCE_APP_BUNDLE,
    SOURCE_HOMEBREW_FORMULA,
    SOURCE_MACOS_PKG,
    _pkgutil_path,
    _is_meaningful_pkg,
)
from macos.scanner.macho import MachOKind

logger = logging.getLogger("macos.scanner.ownership")

_SUBPROCESS_TIMEOUT = 30

# macOS source constants — local until promoted to common/scanner/models.py
SOURCE_MACHO_BINARY = "macho_binary"
SOURCE_DYLIB        = "dylib"


# ── 1. .app Bundle Resolution ─────────────────────────────────────────────────

_APP_BUNDLE_RE = re.compile(
    r"(?P<bundle_root>.*\.app)/Contents/",
    re.IGNORECASE,
)


def resolve_app_bundle_owner(filepath: str) -> Optional[SoftwareItem]:
    """
    If `filepath` is inside a .app bundle, find the owning bundle's Info.plist
    and extract a SoftwareItem from it.

    Example:
      /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
      → reads /Applications/Google Chrome.app/Contents/Info.plist
      → SoftwareItem(name="Google Chrome", version="125.0.6422.60", ...)
    """
    m = _APP_BUNDLE_RE.search(filepath.replace(os.sep, "/"))
    if not m:
        return None

    # Reconstruct the bundle root with the original OS path separators
    bundle_root_fwd = m.group("bundle_root")
    # Map back: replace the forward-slash version prefix with original path chars
    bundle_root = filepath[:filepath.replace(os.sep, "/").index(bundle_root_fwd) + len(bundle_root_fwd)]
    plist_path = os.path.join(bundle_root, "Contents", "Info.plist")

    if not os.path.isfile(plist_path):
        return None

    plist = _read_plist(plist_path)
    if plist is None:
        return None

    bundle_dir_name = os.path.basename(bundle_root)
    item = _plist_to_software_item(plist, bundle_dir_name, plist_path)
    return item


# ── 2. Homebrew Cellar Resolution ─────────────────────────────────────────────

_CELLAR_PATHS = (
    "/opt/homebrew/Cellar/",   # Apple Silicon
    "/usr/local/Cellar/",       # Intel
)

_CELLAR_PATH_RE = re.compile(
    r"/(?:opt/homebrew|usr/local)/Cellar/([^/]+)/([^/]+)/",
    re.IGNORECASE,
)


def resolve_homebrew_owner(filepath: str) -> Optional[SoftwareItem]:
    """
    If `filepath` is under the Homebrew Cellar, extract product/version
    from the path structure.

    Example:
      /opt/homebrew/Cellar/openssl@3/3.3.0/bin/openssl
      → SoftwareItem(name="openssl@3", version="3.3.0", vendor="Homebrew", ...)
    """
    m = _CELLAR_PATH_RE.search(filepath.replace(os.sep, "/"))
    if not m:
        return None

    formula = m.group(1).strip()
    version  = m.group(2).strip()

    if not formula or not version:
        return None

    return SoftwareItem(
        name=formula,
        version=version,
        vendor="Homebrew",
        source=SOURCE_HOMEBREW_FORMULA,
        category="software",
        install_location=os.path.dirname(filepath),
        scan_path=filepath,
        last_seen=utc_now_iso(),
    )


# ── 3. pkgutil Ownership Index ────────────────────────────────────────────────

class PkgutilOwnershipIndex:
    """
    Pre-built in-memory index mapping file path → (pkg_id, version).

    Built lazily on first use by calling `pkgutil --files <pkg_id>` once
    per installed meaningful package. After construction, all lookups are
    O(1) dictionary operations — no subprocess per file.

    The index only covers packages that pass the `_is_meaningful_pkg` filter
    (excludes com.apple.pkg.* OS component receipts).
    """

    def __init__(self) -> None:
        self._index: Optional[Dict[str, Tuple[str, str]]] = None

    def _build_pkg_list(self) -> List[Tuple[str, str]]:
        """Return list of (pkg_id, version) for meaningful installed packages."""
        pkgutil = _pkgutil_path()
        if not pkgutil:
            return []
        try:
            result = subprocess.run(
                [pkgutil, "--pkgs"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return []
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []

        packages = []
        for line in result.stdout.splitlines():
            pkg_id = line.strip()
            if not pkg_id or not _is_meaningful_pkg(pkg_id):
                continue
            # Get version from pkgutil --pkg-info
            try:
                info_result = subprocess.run(
                    [pkgutil, "--pkg-info", pkg_id],
                    capture_output=True, text=True, timeout=10,
                )
                version = ""
                if info_result.returncode == 0:
                    for info_line in info_result.stdout.splitlines():
                        if "version:" in info_line.lower():
                            _, _, ver = info_line.partition(":")
                            version = ver.strip()
                            break
                packages.append((pkg_id, version))
            except Exception:
                packages.append((pkg_id, ""))
        return packages

    def build(self) -> int:
        """
        Build the file→package index.
        Returns number of files indexed.
        """
        pkgutil = _pkgutil_path()
        if not pkgutil:
            self._index = {}
            return 0

        pkg_list = self._build_pkg_list()
        index: Dict[str, Tuple[str, str]] = {}

        for pkg_id, version in pkg_list:
            try:
                files_result = subprocess.run(
                    [pkgutil, "--files", pkg_id],
                    capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
                )
                if files_result.returncode != 0:
                    continue
                for fline in files_result.stdout.splitlines():
                    # pkgutil --files outputs relative paths; prefix with /
                    rel = fline.strip()
                    if not rel:
                        continue
                    abs_path = "/" + rel if not rel.startswith("/") else rel
                    index[abs_path] = (pkg_id, version)
            except Exception as exc:
                logger.debug("pkgutil --files failed for %s: %s", pkg_id, exc)

        self._index = index
        logger.info("pkgutil ownership index built: %d files indexed", len(index))
        return len(index)

    def lookup(self, filepath: str) -> Optional[SoftwareItem]:
        """
        Look up a file path in the ownership index.
        Returns SoftwareItem if found, None otherwise.
        """
        if self._index is None:
            self.build()
        if not self._index:
            return None

        entry = self._index.get(filepath)
        if entry is None:
            return None

        pkg_id, version = entry
        return SoftwareItem(
            name=pkg_id,
            version=version,
            vendor="",
            source=SOURCE_MACOS_PKG,
            category="software",
            install_location=os.path.dirname(filepath),
            scan_path=filepath,
            last_seen=utc_now_iso(),
        )


# ── 4. Fallback: filename-based ───────────────────────────────────────────────

def resolve_standalone(filepath: str, kind: MachOKind) -> Optional[SoftwareItem]:
    """
    Minimal fallback for Mach-O files with no package or bundle owner.

    Libraries (.dylib) without an owner are skipped — too many false positives.
    Executables and bundles get a name derived from the basename.
    """
    from macos.scanner.macho import MachOKind as K
    if kind == K.DYLIB:
        # Anonymous dylibs produce too many noise items — skip
        return None

    name = os.path.splitext(os.path.basename(filepath))[0]
    if not name:
        return None

    source = SOURCE_DYLIB if kind == K.DYLIB else SOURCE_MACHO_BINARY
    return SoftwareItem(
        name=name,
        version="",
        vendor="",
        source=source,
        category="software",
        install_location=os.path.dirname(filepath),
        scan_path=filepath,
        last_seen=utc_now_iso(),
    )
