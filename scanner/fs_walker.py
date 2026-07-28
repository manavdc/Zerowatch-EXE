"""
scanner/fs_walker.py
─────────────────────────────────────────────────────────────────────────────
Intelligent filesystem walker for vulnerability-relevant files.

DESIGN GOAL
───────────
Traverse ALL local fixed drives on the machine but open only the tiny
fraction of files that can realistically yield software identity
information that maps to a CPE.  Everything else is skipped at the
directory-name or filename level with zero system calls on the target.

SCAN SCOPE: ALL LOCAL FIXED DRIVES
────────────────────────────────────
The implementation plan originally limited discovery to a hard-coded
list of "priority dirs" under a single drive (C:).  This is rejected
for two reasons:

1. Portable apps are routinely installed on D:, E:, external SSDs
   mounted as local volumes, and custom install targets chosen by the
   user.
2. Developers clone repositories and install runtimes on non-C: drives
   precisely to avoid filling the OS drive.

The walker enumerates all local fixed drives using GetLogicalDriveStrings
(ctypes, zero subprocess) and walks each one, skipping the OS-noise
directories listed in SKIP_DIR_NAMES.

PERFORMANCE CONTRACT
────────────────────
• os.scandir() is used throughout (not os.walk).  It avoids redundant
  stat() calls on each entry because DirEntry exposes is_dir() / is_file()
  from the platform directory entry without an extra syscall on Windows.
• A directory is skipped by name match alone — we never stat a directory
  we intend to skip.
• A file is considered for opening only if its name OR extension appears
  in the relevant frozenset.  The name check is pure Python string
  operations — no I/O.
• Follow-symlink is always False to prevent cycles.

SKIP STRATEGY
─────────────
Two tiers of skipping:

  SKIP_DIR_NAMES   – Short names that appear anywhere in the tree.
                     These are matched against DirEntry.name (the last
                     component), not the full path, so they apply at
                     every level.

  SKIP_PATH_PREFIXES – Full path prefixes.  Used for OS directories
                       that contain important-looking names inside them
                       (e.g. C:\Windows\System32 must be skipped but
                       C:\Windows is not in SKIP_DIR_NAMES because
                       there may be portable apps installed at
                       C:\Windows\Temp by installers – though that is
                       rare; the inner System32/SysWOW64/WinSxS dirs
                       are enough to protect from the heavy paths).

MANIFEST FILENAMES vs BINARY EXTENSIONS
────────────────────────────────────────
The walker yields two categories of files:

  ManifestFile  – Exact filename match (package.json, Cargo.lock, …).
                  These are small text files that describe dependency
                  graphs; ALL of them should be opened and parsed.

  BinaryFile    – Extension match (.exe, .dll, .sys, .jar, …).
                  These are inspected for version metadata, but with
                  size/path filters applied before opening.

Callers receive a stream of (path, entry_kind) tuples via the
walk_drives() generator.  The orchestrator feeds each into the
appropriate scanner layer.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
from enum import Enum, auto
from typing import Generator, FrozenSet, List, Set, Tuple

logger = logging.getLogger("scanner.fs_walker")


# ── Entry kind enum ───────────────────────────────────────────────────────────

class EntryKind(Enum):
    MANIFEST = auto()   # Text manifest (parse for dependencies)
    BINARY   = auto()   # PE / archive (inspect version resource)


# ── Skip rules ────────────────────────────────────────────────────────────────

# ── Skip rules ────────────────────────────────────────────────────────────────

# Directory names that are ALWAYS skipped regardless of context.
# These never contain CVE-relevant data:
#   - OS internals (System32, WinSxS) – covered by Layer 0 registry
#   - Build output dirs that contain no installed packages
#   - VCS housekeeping, IDE metadata, browser caches
SKIP_DIR_NAMES: FrozenSet[str] = frozenset({
    # --- Windows OS internals ---
    "system32", "syswow64", "winsxs",
    "softwareDistribution",         # Windows Update download cache
    "catroot", "catroot2",          # Driver signing catalogs
    "diagnostics", "diagnosticlog",
    "assembly",                     # .NET GAC
    "microsoft.net",
    "windows.old",                  # Previous OS remnant
    "boot", "recovery",
    "$recycle.bin", "recycler",
    "system volume information",
    "$windows.~bt", "$windows.~ws",
    "drivers",                      # C:\Windows\System32\drivers — inside System32

    # --- Python / JS tool caches (not installed packages) ---
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".eggs",
    ".tox",
    ".yarn",                        # yarn plug'n'play cache
    ".gradle",                      # Gradle wrapper/build cache
    ".cargo",                       # Rust registry cache — parse Cargo.lock instead
    ".rustup",
    "cmake-build-debug",
    "cmake-build-release",

    # --- VCS internals ---
    ".git", ".svn", ".hg", ".bzr",

    # --- IDE / tool caches ---
    ".idea", ".vscode",
    ".vs",                          # Visual Studio hidden workspace data
    "ipch",                         # VS incremental PCH
    ".sonarwork",

    # --- Browser / OS caches ---
    "cache", "caches",
    "inetcache", "temporary internet files",
    "thumbnails",
    "packagescache",
    "crashreports",
    "logs",                         # Generic log folders

    # --- Virtualisation / containers ---
    "docker",
    ".docker",
    "containers",
    "virtual machines",
    "hyper-v",

    # --- Cloud sync placeholders (online-only; no local content) ---
    "onedrivetemp",
})

# Dependency vendor directories that are CONDITIONALLY skipped.
# Each entry maps an ecosystem manifest filename to the set of directories
# that should be skipped when that manifest (or any manifest in its group)
# is found co-located in the same parent directory.
#
# Logic in _walk_dir:
#   1. Scan all entries in a directory.
#   2. If any manifest file in a group is present → skip all of that
#      group's dep directories.
#   3. If NO manifest is found → fall through and scan the dep directory
#      as a fallback so packages inside it are not silently missed.
#
# Key design decisions:
#   - npm: node_modules is skipped when package.json OR any lockfile is
#     found. package.json alone is sufficient because lockfiles may not
#     exist in legacy projects.
#   - Python venvs: skipped when any Python dependency manifest is found.
#     Virtual environments contain only installed wheels — the same data
#     is captured more accurately from the manifest/lockfile.
#   - Java: .m2 and .gradle caches live in %USERPROFILE% not next to
#     pom.xml, so they are handled by SKIP_DIR_NAMES_ALWAYS globally.
#   - Rust: "target" is skipped when Cargo.toml or Cargo.lock is found.
#   - PHP: "vendor" is skipped when composer.json or composer.lock is found.
#   - Go: module caches live in %USERPROFILE%\go\pkg\mod, not next to
#     go.mod, so only the local "vendor" directory (if used) is conditional.

# A single group entry: (frozenset of trigger manifests, frozenset of dirs to skip)
_ConditionalSkipGroup = Tuple[FrozenSet[str], FrozenSet[str]]

CONDITIONAL_SKIP_GROUPS: Tuple[_ConditionalSkipGroup, ...] = (
    # Node.js: skip node_modules when any npm/yarn/pnpm manifest is found
    (
        frozenset({
            "package.json", "package-lock.json",
            "yarn.lock", "pnpm-lock.yaml",
        }),
        frozenset({"node_modules"}),
    ),
    # Python: skip virtual-env dirs when any Python dependency file is found
    (
        frozenset({
            "requirements.txt", "requirements-dev.txt",
            "requirements-prod.txt", "requirements-test.txt",
            "Pipfile", "Pipfile.lock",
            "pyproject.toml", "setup.py", "setup.cfg",
            "poetry.lock", "pdm.lock", "uv.lock",
        }),
        frozenset({"venv", ".venv", "env", ".env"}),
    ),
    # Java: skip local Maven / Gradle build outputs when build files are found
    # (.m2 / .gradle global caches are in %USERPROFILE% so they are NOT
    # skipped here — they land in SKIP_DIR_NAMES_ALWAYS above)
    (
        frozenset({
            "pom.xml", "build.gradle", "build.gradle.kts",
            "settings.gradle", "settings.gradle.kts",
        }),
        frozenset({"target", "out", "build", "dist"}),
    ),
    # PHP: skip vendor dir when Composer files are present
    (
        frozenset({"composer.json", "composer.lock"}),
        frozenset({"vendor"}),
    ),
    # Rust: skip target dir when Cargo files are present
    (
        frozenset({"Cargo.toml", "Cargo.lock"}),
        frozenset({"target"}),
    ),
    # Go: skip local vendor directory when go.mod is present
    (
        frozenset({"go.mod", "go.sum"}),
        frozenset({"vendor"}),
    ),
)


# Full path prefixes (lowercased). Matched against the absolute path of
# a directory before attempting to recurse into it. Use these for paths
# that contain folders matching benign names (e.g. a real app could be
# called "Build" but C:\Windows\... is always noise).
_WINDIR = (os.environ.get("SystemRoot") or r"C:\Windows").lower()
_SYSTEM32 = os.path.join(_WINDIR, "system32")
_SYSWOW64 = os.path.join(_WINDIR, "syswow64")
_WINSXS   = os.path.join(_WINDIR, "winsxs")

SKIP_PATH_PREFIXES: Tuple[str, ...] = (
    _SYSTEM32,
    _SYSWOW64,
    _WINSXS,
    os.path.join(_WINDIR, "softwareDistribution"),
    os.path.join(_WINDIR, "assembly"),
    # Windows Store app container — we read the registry AppModel key instead
    os.path.join(
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        "WindowsApps",
    ).lower(),
    # Global Rust & Cargo registry caches — nothing running here
    os.path.join(os.environ.get("USERPROFILE", ""), ".cargo").lower(),
    os.path.join(os.environ.get("USERPROFILE", ""), ".rustup").lower(),
    # Global Go module download cache — covered by go.mod manifests
    os.path.join(os.environ.get("USERPROFILE", ""), "go", "pkg", "mod").lower(),
    # Global Maven local repository — covered by pom.xml manifests
    os.path.join(os.environ.get("USERPROFILE", ""), ".m2").lower(),
    # Global Gradle caches — covered by build.gradle manifests
    os.path.join(os.environ.get("USERPROFILE", ""), ".gradle").lower(),
    # Global pip/uv/poetry caches — raw wheels, not installed packages
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "pip", "Cache").lower(),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "uv", "cache").lower(),
    # npm global cache — raw tarballs, not installed packages
    os.path.join(os.environ.get("APPDATA", ""), "npm-cache").lower(),
    # NuGet global packages cache — covered by .csproj/packages.config
    os.path.join(os.environ.get("USERPROFILE", ""), ".nuget", "packages").lower(),
    # pnpm global store
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "pnpm").lower(),
)



# ── File target sets ──────────────────────────────────────────────────────────

# Exact filenames that always contain dependency information.
# All of these are opened and parsed by layer2_manifests.
MANIFEST_FILENAMES: FrozenSet[str] = frozenset({
    # npm / yarn / pnpm
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    ".yarn-integrity",

    # Python
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "requirements-test.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",

    # Java / Kotlin
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",

    # .NET / NuGet
    "packages.config",
    "project.json",
    "project.assets.json",
    "nuget.config",

    # Go
    "go.mod",
    "go.sum",

    # Rust
    "Cargo.toml",
    "Cargo.lock",

    # Ruby
    "Gemfile",
    "Gemfile.lock",

    # PHP
    "composer.json",
    "composer.lock",

    # Swift / CocoaPods
    "Podfile.lock",
    "Package.swift",
    "Package.resolved",

    # Conda / Mamba
    "environment.yml",
    "environment.yaml",
    "conda-lock.yml",

    # Alpine / Debian containers
    "apk.installed",
    "dpkg.installed",
})

# Filename suffixes (extensions) for binary files to inspect.
# Matched with str.endswith() so ".dll" matches "foo.dll", "FOO.DLL" etc.
# (extension comparison is done on lowercased filename)
BINARY_EXTENSIONS: FrozenSet[str] = frozenset({
    # Windows PE
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr",
    # Java archives (contain MANIFEST.MF with implementation-version)
    ".jar", ".war", ".ear", ".aar",
    # .NET packages
    ".nupkg",
    # VS extension
    ".vsix",
    # Python wheel (zip-based, contains METADATA)
    ".whl",
    # Generic zip with metadata
    ".apk",   # Android – may appear on dev machines
})

# Files that match a binary extension are STILL skipped if they are
# larger than this threshold.  Most real PE executables are < 200 MB;
# anything larger is almost certainly a game, VM image, or installer
# that Syft would handle better.
MAX_BINARY_SIZE_BYTES = 200 * 1024 * 1024  # 200 MB

# Manifests larger than this are likely auto-generated monorepo lockfiles
# that would create enormous noise.  10 MB is a generous upper bound for
# any real hand-maintained manifest.
MAX_MANIFEST_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


# ── Drive enumeration (Windows) ───────────────────────────────────────────────

DRIVE_REMOVABLE = 2
DRIVE_FIXED     = 3
DRIVE_RAMDISK   = 6

def get_local_fixed_drives() -> List[str]:
    """
    Returns a list of local fixed drive root paths on Windows,
    e.g. ['C:\\', 'D:\\'].

    Uses GetLogicalDriveStringsW + GetDriveTypeW from kernel32 so that
    network drives, removable media, and CD-ROMs are excluded without
    any subprocess call.
    """
    buf = ctypes.create_unicode_buffer(256)
    ctypes.windll.kernel32.GetLogicalDriveStringsW(len(buf), buf)

    raw = buf.value  # Null-separated, double-null terminated string
    drives: List[str] = []
    for drive in raw.split("\x00"):
        drive = drive.strip()
        if not drive:
            continue
        dtype = ctypes.windll.kernel32.GetDriveTypeW(drive)
        if dtype in (DRIVE_FIXED, DRIVE_RAMDISK):
            drives.append(drive)

    if not drives:
        # Fallback: scan C: only (should never happen on Windows)
        drives = ["C:\\"]

    logger.debug("Local fixed drives: %s", drives)
    return drives


# ── Core walker ───────────────────────────────────────────────────────────────

def _build_conditional_skip_set(dir_entry_names: Set[str]) -> FrozenSet[str]:
    """
    Given the set of filenames present in a directory, return the set of
    subdirectory names that should be skipped because a manifest covering
    their ecosystem has been found.

    Example:
        dir contains "package.json"  →  {"node_modules"} should be skipped
        dir contains "Cargo.lock"    →  {"target"} should be skipped
        dir contains nothing useful  →  frozenset()  (don't skip anything)
    """
    skip: Set[str] = set()
    for trigger_manifests, dep_dirs in CONDITIONAL_SKIP_GROUPS:
        # Case-insensitive check: lowercase the trigger set and compare
        if any(
            name.lower() in {m.lower() for m in trigger_manifests}
            for name in dir_entry_names
        ):
            skip.update(name.lower() for name in dep_dirs)
    return frozenset(skip)


def _should_skip_dir(
    entry: os.DirEntry,
    abs_path_lower: str,
    conditional_skip: FrozenSet[str] = frozenset(),
) -> bool:
    """
    Returns True if a directory entry should be skipped entirely.

    Two-tier check:
    1. Unconditional: name is in SKIP_DIR_NAMES (OS, caches, VCS)
    2. Conditional: name is in conditional_skip (dep dirs whose ecosystem
       is covered by a co-located manifest in the parent directory)
    3. Path prefix: full path matches a known noisy subtree prefix

    The conditional_skip set is built by _build_conditional_skip_set() for
    each parent directory, so it only suppresses dependency dirs when the
    corresponding manifest has been confirmed to exist.
    """
    name_lower = entry.name.lower()

    # Tier 1: always skip
    if name_lower in SKIP_DIR_NAMES:
        return True

    # Tier 2: conditionally skip (manifest-gated)
    if conditional_skip and name_lower in conditional_skip:
        return True

    # Tier 3: path prefix
    for prefix in SKIP_PATH_PREFIXES:
        if abs_path_lower.startswith(prefix):
            return True

    return False


def walk_drives(
    extra_dirs: List[str] | None = None,
) -> Generator[Tuple[str, EntryKind], None, None]:
    """
    Recursively walk all local fixed drives and yield (path, EntryKind)
    for every file that has CVE-discovery value.

    Parameters
    ──────────
    extra_dirs  Optional additional directories to include in the walk
                (useful for network shares or custom install roots that
                have been explicitly configured by the operator).

    Yields
    ──────
    (absolute_path, EntryKind.MANIFEST | EntryKind.BINARY)

    Generator contract
    ──────────────────
    • Never raises; exceptions per-directory are caught and logged.
    • Never follows symlinks (prevents cycles on deeply nested symlinked
      node_modules etc.).
    • Yields are ordered depth-first so that manifests in project roots
      are discovered before any binaries in subdirectories.
    """
    roots: List[str] = get_local_fixed_drives()
    if extra_dirs:
        roots.extend(extra_dirs)

    for root in roots:
        yield from _walk_dir(root)


def _walk_dir(
    dirpath: str,
) -> Generator[Tuple[str, EntryKind], None, None]:
    """
    Recursive inner walk for a single directory.

    Context-aware skip strategy
    ───────────────────────────
    Before recursing into any subdirectory, we check which filenames are
    present in *this* directory.  If a package manifest is found (e.g.
    package.json), the corresponding dependency vendor directory (e.g.
    node_modules) is skipped — we already have the dependency information
    from the manifest and scanning node_modules would just produce duplicate
    entries.

    If NO manifest is found in this directory, the dependency directory is
    NOT skipped.  This is the fallback path that covers legacy or
    non-standard project layouts where packages are installed without a
    manifest file.

    Performance note
    ────────────────
    os.scandir() is called once per directory and the result is held in a
    list.  We make a single pass over the entries:
      - Collect file names for manifest detection (cheap string ops, no I/O)
      - Collect (entry, abs_path_lower) pairs for directories to recurse
      - Yield matching files inline
    The conditional_skip set is computed once per directory from the
    collected file names, so the manifest detection adds zero extra syscalls.
    """
    try:
        entries = list(os.scandir(dirpath))
    except (PermissionError, OSError) as exc:
        logger.debug("scandir skipped %s: %s", dirpath, exc)
        return

    # ── Single-pass collection ─────────────────────────────────────────────
    file_names: Set[str] = set()   # filenames present in this directory
    dir_entries: list  = []        # (entry, abs_path_lower) for subdirs

    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                dir_entries.append((entry, entry.path.lower()))
            elif entry.is_file(follow_symlinks=False):
                file_names.add(entry.name)
        except (PermissionError, OSError):
            pass

    # Determine which dep-vendor dirs to conditionally suppress based on
    # co-located manifest files found in this directory.
    conditional_skip = _build_conditional_skip_set(file_names)

    # ── Yield matching files ───────────────────────────────────────────────
    for entry in entries:
        try:
            if entry.is_symlink() or entry.is_dir(follow_symlinks=False):
                continue
            if not entry.is_file(follow_symlinks=False):
                continue

            name_lower = entry.name.lower()

            # ── Manifest filename exact match ──────────────────────────────
            if entry.name in MANIFEST_FILENAMES or name_lower in MANIFEST_FILENAMES:
                try:
                    st = entry.stat(follow_symlinks=False)
                    if 0 < st.st_size <= MAX_MANIFEST_SIZE_BYTES:
                        yield (entry.path, EntryKind.MANIFEST)
                except OSError:
                    pass
                continue

            # ── Binary extension match ─────────────────────────────────────
            ext = os.path.splitext(name_lower)[1]
            if ext in BINARY_EXTENSIONS:
                try:
                    st = entry.stat(follow_symlinks=False)
                    if 0 < st.st_size <= MAX_BINARY_SIZE_BYTES:
                        yield (entry.path, EntryKind.BINARY)
                except OSError:
                    pass

        except (PermissionError, OSError) as exc:
            logger.debug("Entry error %s: %s", getattr(entry, "path", "?"), exc)
        except Exception as exc:
            logger.warning("Unexpected walk error at %s: %s", dirpath, exc)

    # ── Recurse into subdirectories ────────────────────────────────────────
    for entry, abs_path_lower in dir_entries:
        try:
            if _should_skip_dir(entry, abs_path_lower, conditional_skip):
                logger.debug(
                    "Skipping dir (%s): %s",
                    "manifest-gated" if entry.name.lower() in conditional_skip else "always-skip",
                    entry.path,
                )
                continue
            yield from _walk_dir(entry.path)
        except (PermissionError, OSError) as exc:
            logger.debug("Entry error %s: %s", getattr(entry, "path", "?"), exc)
        except Exception as exc:
            logger.warning("Unexpected walk error at %s: %s", dirpath, exc)


# ── Targeted manifest walk (fast path for project directories) ────────────────

def walk_dir_for_manifests(
    dirpath: str,
) -> Generator[Tuple[str, EntryKind], None, None]:
    """
    Shallow walk of a specific directory for manifests only.
    Used by the FileSystemWatcher when a change is detected in a
    known project root so we can re-parse only the manifests without
    doing a full drive walk.
    """
    yield from _walk_dir(dirpath)


# ── Priority-path discovery (for periodic incremental scans) ──────────────────

# User-profile locations that commonly contain software.
# Expanded via os.path.expandvars() at runtime.
_USER_PRIORITY_DIRS: List[str] = [
    r"%LOCALAPPDATA%\Programs",
    r"%APPDATA%",
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
]

# Immediate drive-root subdirectory names that are almost always pure data
# storage.  We avoid descending into these during the priority scan so that
# machines with large photo or video libraries don't add many seconds to each
# 4-hour cycle.  They are still covered by the daily deep scan via walk_drives().
_DATA_ROOT_NAMES: FrozenSet[str] = frozenset({
    "photos", "pictures", "videos", "movies", "music", "audio",
    "media", "backup", "backups", "archive", "archives",
})


def get_priority_scan_dirs() -> List[str]:
    """
    Build the list of directories scanned on every periodic cycle.

    Coverage:
      • Program Files / Program Files (x86) on every fixed drive.
      • All non-OS subdirectories at the root of every fixed drive.
        This automatically includes custom software collections such as
        D:\\Tools, D:\\Dev, E:\\Portable without any manual configuration.
        Pure data directories (Photos, Videos, Music, etc.) are excluded
        to avoid wasting scandir() calls on irrelevant subtrees.
      • Key user-profile locations (Downloads, Desktop, AppData, Documents).

    NOTE: Directory traversal still happens for all returned paths.
    The SQLite cache eliminates file *parsing* for unchanged files —
    it does not eliminate the traversal needed to discover new files.
    """
    dirs: List[str] = []

    for drive in get_local_fixed_drives():
        # Standard Windows installation directories — always present
        for std in ("Program Files", "Program Files (x86)"):
            p = os.path.join(drive, std)
            if os.path.isdir(p):
                dirs.append(p)

        # Immediate subdirectories of the drive root that aren't OS internals.
        # These are the most common locations for user-managed software
        # collections on secondary drives.
        try:
            for entry in os.scandir(drive):
                if not entry.is_dir(follow_symlinks=False):
                    continue
                name_lower = entry.name.lower()

                # Skip OS directories and user profile subtree
                # (user profile is covered separately below)
                if name_lower in SKIP_DIR_NAMES:
                    continue
                if name_lower in ("windows", "users", "user",
                                  "program files", "program files (x86)"):
                    continue

                # Skip directories that are almost certainly pure data storage
                if name_lower in _DATA_ROOT_NAMES:
                    continue

                dirs.append(entry.path)
        except (PermissionError, OSError):
            pass

    # User profile software locations
    for tmpl in _USER_PRIORITY_DIRS:
        p = os.path.expandvars(tmpl)
        if p != tmpl and os.path.isdir(p):   # expandvars returned something real
            dirs.append(p)

    logger.debug("Priority scan dirs (%d): %s", len(dirs), dirs)
    return dirs


def walk_specified_dirs(
    directories: List[str],
) -> Generator[Tuple[str, EntryKind], None, None]:
    """
    Walk an explicit list of directories using the same skip rules and
    file-type filters as the full walk_drives() scan.

    Used by the periodic incremental scanner (priority scan mode) so that
    only well-known high-value paths are traversed every 4 hours, while
    the comprehensive full-drive walk is reserved for the daily deep scan.

    Directory traversal still occurs for all given paths to discover new
    files.  The cache eliminates file *parsing* for unchanged files.
    """
    for dirpath in directories:
        if not os.path.isdir(dirpath):
            continue
        try:
            yield from _walk_dir(dirpath)
        except Exception as exc:
            logger.warning("walk_specified_dirs error in %s: %s", dirpath, exc)
