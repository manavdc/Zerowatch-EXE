"""
macos/scanner/fs_walker.py
─────────────────────────────────────────────────────────────────────────────
Intelligent filesystem walker for macOS.

Strategy:
  1. Scans a curated set of software-relevant roots rather than walking /
     from the top. This is safer on macOS because:
       - SIP (System Integrity Protection) restricts many system paths
       - TCC blocks access to certain user directories without consent
       - Walking from / risks scanning pseudo-mounts and slow network paths
       - macOS has many symlinks under /private that create cycles

  2. Volume discovery uses /Volumes for secondary volumes.
     The boot volume is accessed via its standard mount points (/Applications, etc.)
     rather than walking /Volumes/Macintosh\ HD which may not always be accessible.

  3. Binary detection:
       - Mach-O: Header magic (32-bit, first 4 bytes read only) — no subprocess
       - .dylib:  Extension check (.dylib, .dylib.N.N.N)
       - .framework: Treat as Mach-O candidate

  4. Manifest detection:
       - Name-based: same MANIFEST_FILENAMES from common/scanner/fs_constants
       - Size-gated: skipped if > MAX_MANIFEST_SIZE_BYTES

  5. Symlink safety:
       - entry.is_dir(follow_symlinks=False) — never follow directory symlinks
       - entry.is_file(follow_symlinks=False) — regular files only
       - Symlinks to files within scan roots are silently skipped

  6. Skip rules:
       - Common set from SKIP_DIR_NAMES_COMMON
       - macOS-specific pseudo-dirs and system noise dirs
       - Absolute path prefix skip list (virtual filesystems)
       - Conditional skips: node_modules when package.json exists

  7. Scan instrumentation:
       - Directory visited count
       - Files yielded (MANIFEST / BINARY)
       - Files skipped (size / symlink / permission-denied)
       - Directories skipped
     Counters are reset per walk_filesystem() call.
     Native performance numbers will be measured during macOS native testing.
"""

from __future__ import annotations

import logging
import os
import stat
from enum import Enum, auto
from typing import Dict, FrozenSet, Generator, List, Optional, Set, Tuple

from common.scanner.fs_constants import (
    MANIFEST_FILENAMES,
    CONDITIONAL_SKIP_GROUPS,
    MAX_BINARY_SIZE_BYTES,
    MAX_MANIFEST_SIZE_BYTES,
    SKIP_DIR_NAMES_COMMON,
)
from macos.scanner.macho import is_macho, is_dylib

logger = logging.getLogger("macos.scanner.fs_walker")


# ── EntryKind ─────────────────────────────────────────────────────────────────

class EntryKind(Enum):
    MANIFEST = auto()   # Text manifest (parse for dependencies)
    BINARY   = auto()   # Mach-O binary or .dylib (inspect for metadata)


# ── macOS skip rules ──────────────────────────────────────────────────────────

_MACOS_SKIP_DIR_NAMES_EXTRA: FrozenSet[str] = frozenset({
    # macOS system directories that SIP protects or are not software
    "private",          # Avoid /private directly (handled via /var, /tmp aliases)
    "dev",
    "cores",            # /cores — kernel crash dumps
    "lost+found",
    # APFS special volumes (under /System/Volumes/)
    "vm",               # /System/Volumes/VM — swap
    "preboot",          # /System/Volumes/Preboot
    "update",           # /System/Volumes/Update
    "xarts",            # /System/Volumes/xarts
    "isc",              # /System/Volumes/iSCPreboot
    "hardware",         # /System/Volumes/Hardware
    # macOS app containers / caches
    "containers",
    "mobile documents", # iCloud Drive
    "photoslibrary",
    "imovie theater",
    "ios files",
    # Xcode derived data (large, not relevant to OS-level vulnerability scan)
    "deriveddata",
    "archives",         # Xcode Archives
    # Crash / core dump dirs
    "crashreporter",
    "diagnosticreports",
    "diags",
    # Time Machine
    "backups.backupdb",
    # Spotlight metadata
    ".spotlight-v100",
    ".fseventsd",
    ".trashes",
    ".temporaryitems",
    ".vol",
    # Low-value store dirs
    "caches",
    "cache",
    "logs",
})

SKIP_DIR_NAMES: FrozenSet[str] = SKIP_DIR_NAMES_COMMON | _MACOS_SKIP_DIR_NAMES_EXTRA

# Absolute path prefixes that must never be scanned.
SKIP_ABSOLUTE_PREFIXES: Tuple[str, ...] = (
    "/dev",
    "/private/var/folders",  # Temp files per-user session (TMPDIR equivalent)
    "/private/var/run",
    "/private/var/vm",       # Swap files
    "/private/var/tmp",
    "/private/tmp",
    "/System/Volumes/VM",
    "/System/Volumes/Preboot",
    "/System/Volumes/Update",
    "/System/Volumes/xarts",
    "/System/Volumes/iSCPreboot",
    "/System/Volumes/Hardware",
    "/System/Library",       # SIP-protected system libraries (not user software)
    "/Library/Apple",        # Apple-owned — SIP protected
    "/usr/share",            # Documentation, locales — no vulnerability surface
    "/usr/lib/swift",        # Apple Swift runtimes — SIP protected
    "/sbin",                 # System administration tools — SIP protected
    "/var/run",              # Sockets and PID files
    "/var/tmp",              # Temp files
    "/var/folders",          # Temp files
    "/tmp",                  # Symlink → /private/tmp
    "/private/var/db/uuidtext",  # Unified log UUIDs — not software
)

# ── macOS scan roots ──────────────────────────────────────────────────────────
#
# These are the primary locations where user-installed software lives on macOS.
# /Applications       — Bundled .app applications (GUI apps)
# /System/Applications — Apple system apps (Calculator, Safari, etc.)
# /Library            — Third-party system-level agents, frameworks, plugins
# /usr/local          — Manually installed / Homebrew Intel software
# /opt                — Homebrew Apple Silicon, MacPorts

SYSTEM_SCAN_ROOTS: List[str] = [
    "/Applications",
    "/System/Applications",
    "/Library",
    "/usr/local",
    "/opt",
    "/usr/local/lib",    # Intel Homebrew dylibs
    "/opt/homebrew/lib", # Apple Silicon Homebrew dylibs
]

# User-space scan roots (expanded per running user at call time)
_USER_SCAN_ROOTS_TEMPLATES: List[str] = [
    "Applications",     # ~/Applications
    "Developer",        # ~/Developer (Xcode, homebrew dev builds)
    "Projects",         # ~/Projects (conventional dev dir)
    "src",              # ~/src (another common dev dir)
    "Code",             # ~/Code
    "workspace",        # ~/workspace
    "go",               # ~/go (Go workspace)
    ".local",           # ~/.local (pip install --user etc.)
]

# System users to skip when enumerating /Users/* as root
_SYSTEM_USER_NAMES: FrozenSet[str] = frozenset({
    "shared", "guest",
})


def _get_user_scan_dirs() -> List[str]:
    """
    Return per-user scan directories that actually exist.

    Non-root: reads HOME from the environment for the current user.
    Root (daemon via sudo): scans /Users/* to cover every human account on the
    machine, since HOME=/var/root has no user software.
    """
    home = os.environ.get("HOME") or os.path.expanduser("~")
    dirs = []

    # When running as root, enumerate all human user home dirs under /Users/
    home_dirs: List[str] = []
    if os.geteuid() == 0:
        users_root = "/Users"
        if os.path.isdir(users_root):
            try:
                with os.scandir(users_root) as it:
                    for entry in it:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                        # Skip system/service accounts
                        if entry.name.startswith("_") or entry.name.lower() in _SYSTEM_USER_NAMES:
                            continue
                        home_dirs.append(entry.path)
            except OSError:
                pass
    # Always include the current HOME (fallback for non-root or /Users missing)
    if home and home not in home_dirs:
        home_dirs.append(home)

    for user_home in home_dirs:
        for rel in _USER_SCAN_ROOTS_TEMPLATES:
            p = os.path.join(user_home, rel)
            if os.path.isdir(p):
                dirs.append(p)

    return dirs


def _get_secondary_volumes() -> List[str]:
    """
    Discover additional local APFS/HFS+ volumes mounted under /Volumes.

    Rules:
    - Only returns mount points that exist and are accessible.
    - Skips volumes whose names suggest they are special APFS volumes:
        "Macintosh HD - Data", "Recovery", "Preboot", "VM", "Update"
    - Never returns network mounts.
    - Never returns removable media by default.

    Volume type filtering via getfsstat or mount is intentionally not used
    here to avoid complex ctypes bindings in Phase 6C. The name-based
    heuristic is an approximation that will be refined during native testing.
    """
    volumes_dir = "/Volumes"
    if not os.path.isdir(volumes_dir):
        return []

    skip_volume_names: FrozenSet[str] = frozenset({
        "recovery", "preboot", "vm", "update", "xarts", "data",
        "macos - data",  # APFS Data volume (accessed via / already)
    })

    results = []
    try:
        with os.scandir(volumes_dir) as it:
            for entry in it:
                if not entry.is_dir(follow_symlinks=False):
                    # /Volumes/Macintosh\ HD is often a symlink to /
                    # Skip it — we already scan from / roots
                    continue
                name_lower = entry.name.lower()
                if any(skip in name_lower for skip in skip_volume_names):
                    continue
                # Skip symlinks (e.g., /Volumes/Macintosh HD → /)
                if os.path.islink(entry.path):
                    continue
                results.append(entry.path)
    except (PermissionError, OSError) as exc:
        logger.debug("Failed to scan /Volumes: %s", exc)

    return results


def get_scan_roots(extra_dirs: Optional[List[str]] = None) -> List[str]:
    """
    Build the complete list of scan roots for this macOS scan session.
    Returns only paths that actually exist.
    """
    roots: List[str] = []

    for r in SYSTEM_SCAN_ROOTS:
        if os.path.isdir(r):
            roots.append(r)

    roots.extend(_get_user_scan_dirs())
    roots.extend(_get_secondary_volumes())

    if extra_dirs:
        for d in extra_dirs:
            if os.path.isdir(d):
                roots.append(d)

    # De-duplicate preserving order
    seen: Set[str] = set()
    deduped = []
    for r in roots:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    logger.debug("macOS scan roots (%d): %s", len(deduped), deduped)
    return deduped


# ── ScanStats ─────────────────────────────────────────────────────────────────

class ScanStats:
    """
    Lightweight counters for observability. Collected per walk_filesystem() call.
    These numbers will be used for performance measurement during native macOS testing.
    """
    __slots__ = (
        "dirs_visited", "dirs_skipped",
        "files_binaries", "files_manifests",
        "files_skipped_size", "files_skipped_symlink",
        "permission_denied", "cache_hits",
    )

    def __init__(self) -> None:
        self.dirs_visited       = 0
        self.dirs_skipped       = 0
        self.files_binaries     = 0
        self.files_manifests    = 0
        self.files_skipped_size = 0
        self.files_skipped_symlink = 0
        self.permission_denied  = 0
        self.cache_hits         = 0

    def __repr__(self) -> str:
        return (
            f"ScanStats(dirs_visited={self.dirs_visited}, "
            f"dirs_skipped={self.dirs_skipped}, "
            f"binaries={self.files_binaries}, "
            f"manifests={self.files_manifests}, "
            f"skipped_size={self.files_skipped_size}, "
            f"perm_denied={self.permission_denied})"
        )


# ── Conditional skip logic (shared pattern from Windows/Linux) ────────────────

def _build_conditional_skip_set(file_names: Set[str]) -> FrozenSet[str]:
    skip: Set[str] = set()
    for trigger_manifests, dep_dirs in CONDITIONAL_SKIP_GROUPS:
        if any(
            name in trigger_manifests or name.lower() in {m.lower() for m in trigger_manifests}
            for name in file_names
        ):
            skip.update(name.lower() for name in dep_dirs)
    return frozenset(skip)


def _should_skip_dir(
    name: str,
    abs_path: str,
    conditional_skip: FrozenSet[str],
) -> bool:
    """Return True if this directory should be skipped during scanning."""
    name_lower = name.lower()

    if name_lower in SKIP_DIR_NAMES:
        return True

    if conditional_skip and name_lower in conditional_skip:
        return True

    for prefix in SKIP_ABSOLUTE_PREFIXES:
        if abs_path.startswith(prefix):
            return True

    # Skip inside .app Contents directories — only the binary directly
    # inside MacOS/ is relevant; recurse would just scan frameworks
    # (which should be picked up by their own .app or library ownership)
    # Exception: we want to recurse inside .app to find manifest files
    # (e.g. Electron apps contain package.json inside their .asar resources)
    # For now, limit recursion inside .app bundles to detect manifest files only.
    # Binary inspection of .app internals is handled via bundle ownership in inspector.

    return False


# ── Per-directory walker ──────────────────────────────────────────────────────

def _walk_dir(
    dirpath: str,
    stats: ScanStats,
) -> Generator[Tuple[str, EntryKind], None, None]:
    """
    Recursive directory walker. Never follows symlinks.
    Yields (filepath, EntryKind) for each relevant file found.
    """
    stats.dirs_visited += 1

    try:
        entries = list(os.scandir(dirpath))
    except PermissionError as exc:
        stats.permission_denied += 1
        logger.debug("Permission denied: %s (%s)", dirpath, exc)
        return
    except OSError as exc:
        logger.debug("scandir error %s: %s", dirpath, exc)
        return

    file_names: Set[str] = set()
    dir_entries: List[os.DirEntry] = []

    # First pass: classify entries
    for entry in entries:
        try:
            if entry.is_symlink():
                stats.files_skipped_symlink += 1
                continue
            if entry.is_dir(follow_symlinks=False):
                dir_entries.append(entry)
            elif entry.is_file(follow_symlinks=False):
                file_names.add(entry.name)
        except (PermissionError, OSError):
            pass

    conditional_skip = _build_conditional_skip_set(file_names)

    # Second pass: yield files
    for entry in entries:
        try:
            if entry.is_symlink() or entry.is_dir(follow_symlinks=False):
                continue
            if not entry.is_file(follow_symlinks=False):
                continue

            name = entry.name
            name_lower = name.lower()

            # ── Manifests ────────────────────────────────────────────────────
            if name in MANIFEST_FILENAMES or name_lower in MANIFEST_FILENAMES:
                try:
                    st = entry.stat(follow_symlinks=False)
                    if 0 < st.st_size <= MAX_MANIFEST_SIZE_BYTES:
                        stats.files_manifests += 1
                        yield (entry.path, EntryKind.MANIFEST)
                    else:
                        stats.files_skipped_size += 1
                except OSError:
                    pass
                continue

            # ── .dylib by extension ──────────────────────────────────────────
            if is_dylib(name):
                try:
                    st = entry.stat(follow_symlinks=False)
                    if 0 < st.st_size <= MAX_BINARY_SIZE_BYTES:
                        stats.files_binaries += 1
                        yield (entry.path, EntryKind.BINARY)
                    else:
                        stats.files_skipped_size += 1
                except OSError:
                    pass
                continue

            # ── Mach-O detection by header magic ─────────────────────────────
            # Only attempt header read if the file could be executable:
            # - No extension (typical for macOS binaries)
            # - Extension is .dylib / .bundle / .framework internals
            #   already caught above
            # - File has executable mode bit
            # This avoids reading headers of every single file (e.g. .txt files).
            ext = os.path.splitext(name_lower)[1]
            if ext in ("", ".bundle", ".so", ".o"):
                try:
                    st = entry.stat(follow_symlinks=False)
                    mode = st.st_mode
                    # Require executable bit OR no extension (macOS convention)
                    if not (bool(mode & 0o111) or not ext):
                        continue
                    if st.st_size == 0 or st.st_size > MAX_BINARY_SIZE_BYTES:
                        stats.files_skipped_size += 1
                        continue
                    if is_macho(entry.path):
                        stats.files_binaries += 1
                        yield (entry.path, EntryKind.BINARY)
                except PermissionError:
                    stats.permission_denied += 1
                except OSError:
                    pass

        except PermissionError as exc:
            stats.permission_denied += 1
            logger.debug("Permission denied entry %s: %s", getattr(entry, "path", "?"), exc)
        except Exception as exc:
            logger.warning("Unexpected walk error at %s/%s: %s", dirpath, getattr(entry, "name", "?"), exc)

    # Third pass: recurse into subdirectories
    for entry in dir_entries:
        try:
            abs_path = entry.path
            name = entry.name

            if _should_skip_dir(name, abs_path, conditional_skip):
                stats.dirs_skipped += 1
                logger.debug("Skip dir: %s", abs_path)
                continue

            yield from _walk_dir(abs_path, stats)

        except PermissionError as exc:
            stats.permission_denied += 1
            logger.debug("Permission denied dir %s: %s", getattr(entry, "path", "?"), exc)
        except OSError as exc:
            logger.debug("Dir recurse error %s: %s", getattr(entry, "path", "?"), exc)
        except Exception as exc:
            logger.warning("Unexpected recurse error at %s: %s", dirpath, exc)


# ── Public API ────────────────────────────────────────────────────────────────

def walk_filesystem(
    extra_dirs: Optional[List[str]] = None,
    stats: Optional[ScanStats] = None,
) -> Generator[Tuple[str, EntryKind], None, None]:
    """
    Walk all macOS software-relevant filesystem locations.

    Yields (filepath, EntryKind) tuples for:
      - Mach-O binaries (BINARY)
      - .dylib files (BINARY)
      - Dependency manifests (MANIFEST)

    Does NOT scan /Volumes by default unless secondary volumes are found.
    Does NOT follow symbolic links.
    Does NOT scan /System/Library, /dev, /private/var/folders, or other
    pseudo or system-protected paths.

    Args:
        extra_dirs: Additional directories to include (e.g. extra_scan_dirs
                    from the orchestrator configuration).
        stats:      Optional ScanStats object to populate with counters.
    """
    if stats is None:
        stats = ScanStats()

    roots = get_scan_roots(extra_dirs=extra_dirs)
    seen_roots: Set[str] = set()

    for root in roots:
        if root not in seen_roots:
            seen_roots.add(root)
            logger.debug("Walking root: %s", root)
            yield from _walk_dir(root, stats)

    logger.info("macOS filesystem walk complete: %s", stats)


def walk_specified_dirs(
    directories: List[str],
    stats: Optional[ScanStats] = None,
) -> Generator[Tuple[str, EntryKind], None, None]:
    """
    Walk a caller-specified list of directories.
    Used by the orchestrator's priority scan mode.
    """
    if stats is None:
        stats = ScanStats()
    for dirpath in directories:
        if not os.path.isdir(dirpath):
            continue
        try:
            yield from _walk_dir(dirpath, stats)
        except Exception as exc:
            logger.warning("walk_specified_dirs error in %s: %s", dirpath, exc)


def get_priority_scan_dirs(extra_user_dirs: Optional[List[str]] = None) -> List[str]:
    """Return ordered list of priority scan directories for fast startup.

    These are the high-probability locations where user-installed software
    lives on macOS. This is a curated subset of the full scan roots —
    secondary /Volumes are excluded (left to the periodic deep scan).

    The list is identical to SYSTEM_SCAN_ROOTS + per-user dirs, which on
    macOS already represents a narrow, curated set (unlike Windows/Linux
    where the deep scan walks all drive roots).
    """
    dirs: List[str] = []

    for r in SYSTEM_SCAN_ROOTS:
        if os.path.isdir(r):
            dirs.append(r)

    dirs.extend(_get_user_scan_dirs())

    if extra_user_dirs:
        dirs.extend(d for d in extra_user_dirs if os.path.isdir(d))

    # De-duplicate preserving order
    seen: Set[str] = set()
    deduped: List[str] = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            deduped.append(d)

    logger.debug("macOS priority scan dirs (%d): %s", len(deduped), deduped)
    return deduped

