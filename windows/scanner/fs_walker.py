"""
windows/scanner/fs_walker.py
─────────────────────────────────────────────────────────────────────────────
Intelligent filesystem walker for vulnerability-relevant files on Windows.
Enumerates local fixed drives using GetLogicalDriveStringsW and GetDriveTypeW.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
from enum import Enum, auto
from typing import Generator, FrozenSet, List, Set, Tuple

from common.scanner.fs_constants import (
    MANIFEST_FILENAMES,
    CONDITIONAL_SKIP_GROUPS,
    MAX_BINARY_SIZE_BYTES,
    MAX_MANIFEST_SIZE_BYTES,
    SKIP_DIR_NAMES_COMMON,
)

logger = logging.getLogger("windows.scanner.fs_walker")


class EntryKind(Enum):
    MANIFEST = auto()   # Text manifest (parse for dependencies)
    BINARY   = auto()   # PE / archive (inspect version resource)


# ── Skip rules ────────────────────────────────────────────────────────────────

# Windows-specific skip directories (merged with common ones at runtime)
_WIN_SKIP_DIR_NAMES_EXTRA: FrozenSet[str] = frozenset({
    "system32", "syswow64", "winsxs",
    "softwareDistribution",
    "catroot", "catroot2",
    "diagnostics", "diagnosticlog",
    "assembly",
    "microsoft.net",
    "windows.old",
    "boot", "recovery",
    "$recycle.bin", "recycler",
    "system volume information",
    "$windows.~bt", "$windows.~ws",
    "drivers",
    ".vs",
    "ipch",
    "inetcache", "temporary internet files",
    "thumbnails",
    "packagescache",
    "containers",
    "virtual machines",
    "hyper-v",
    "onedrivetemp",
})

SKIP_DIR_NAMES: FrozenSet[str] = SKIP_DIR_NAMES_COMMON | _WIN_SKIP_DIR_NAMES_EXTRA

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
    os.path.join(
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        "WindowsApps",
    ).lower(),
    os.path.join(os.environ.get("USERPROFILE", ""), ".cargo").lower(),
    os.path.join(os.environ.get("USERPROFILE", ""), ".rustup").lower(),
    os.path.join(os.environ.get("USERPROFILE", ""), "go", "pkg", "mod").lower(),
    os.path.join(os.environ.get("USERPROFILE", ""), ".m2").lower(),
    os.path.join(os.environ.get("USERPROFILE", ""), ".gradle").lower(),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "pip", "Cache").lower(),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "uv", "cache").lower(),
    os.path.join(os.environ.get("APPDATA", ""), "npm-cache").lower(),
    os.path.join(os.environ.get("USERPROFILE", ""), ".nuget", "packages").lower(),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "pnpm").lower(),
)


# Imported from common.scanner.fs_constants:
# MANIFEST_FILENAMES, CONDITIONAL_SKIP_GROUPS, MAX_BINARY_SIZE_BYTES, MAX_MANIFEST_SIZE_BYTES

BINARY_EXTENSIONS: FrozenSet[str] = frozenset({
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr",
    ".jar", ".war", ".ear", ".aar",
    ".nupkg",
    ".vsix",
    ".whl",
    ".apk",
})


DRIVE_REMOVABLE = 2
DRIVE_FIXED     = 3
DRIVE_RAMDISK   = 6

def get_local_fixed_drives() -> List[str]:
    buf = ctypes.create_unicode_buffer(256)
    ctypes.windll.kernel32.GetLogicalDriveStringsW(len(buf), buf)

    raw = buf.value
    drives: List[str] = []
    for drive in raw.split("\x00"):
        drive = drive.strip()
        if not drive:
            continue
        dtype = ctypes.windll.kernel32.GetDriveTypeW(drive)
        if dtype in (DRIVE_FIXED, DRIVE_RAMDISK):
            drives.append(drive)

    if not drives:
        drives = ["C:\\"]

    logger.debug("Local fixed drives: %s", drives)
    return drives


def _build_conditional_skip_set(dir_entry_names: Set[str]) -> FrozenSet[str]:
    skip: Set[str] = set()
    for trigger_manifests, dep_dirs in CONDITIONAL_SKIP_GROUPS:
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
    name_lower = entry.name.lower()

    if name_lower in SKIP_DIR_NAMES:
        return True

    if conditional_skip and name_lower in conditional_skip:
        return True

    for prefix in SKIP_PATH_PREFIXES:
        if abs_path_lower.startswith(prefix):
            return True

    return False


def walk_drives(
    extra_dirs: List[str] | None = None,
) -> Generator[Tuple[str, EntryKind], None, None]:
    roots: List[str] = get_local_fixed_drives()
    if extra_dirs:
        roots.extend(extra_dirs)

    for root in roots:
        yield from _walk_dir(root)


def _walk_dir(
    dirpath: str,
) -> Generator[Tuple[str, EntryKind], None, None]:
    try:
        entries = list(os.scandir(dirpath))
    except (PermissionError, OSError) as exc:
        logger.debug("scandir skipped %s: %s", dirpath, exc)
        return

    file_names: Set[str] = set()
    dir_entries: list  = []

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

    conditional_skip = _build_conditional_skip_set(file_names)

    for entry in entries:
        try:
            if entry.is_symlink() or entry.is_dir(follow_symlinks=False):
                continue
            if not entry.is_file(follow_symlinks=False):
                continue

            name_lower = entry.name.lower()

            if entry.name in MANIFEST_FILENAMES or name_lower in MANIFEST_FILENAMES:
                try:
                    st = entry.stat(follow_symlinks=False)
                    if 0 < st.st_size <= MAX_MANIFEST_SIZE_BYTES:
                        yield (entry.path, EntryKind.MANIFEST)
                except OSError:
                    pass
                continue

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


def walk_dir_for_manifests(
    dirpath: str,
) -> Generator[Tuple[str, EntryKind], None, None]:
    yield from _walk_dir(dirpath)


_USER_PRIORITY_DIRS: List[str] = [
    r"%LOCALAPPDATA%\Programs",
    r"%APPDATA%\npm",
    r"%LOCALAPPDATA%\npm",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Downloads",
]

_DATA_ROOT_NAMES: FrozenSet[str] = frozenset({
    "photos", "pictures", "videos", "movies", "music", "audio",
    "media", "backup", "backups", "archive", "archives",
})


def get_priority_scan_dirs() -> List[str]:
    dirs: List[str] = []

    for drive in get_local_fixed_drives():
        for std in ("Program Files", "Program Files (x86)"):
            p = os.path.join(drive, std)
            if os.path.isdir(p):
                dirs.append(p)

    for tmpl in _USER_PRIORITY_DIRS:
        p = os.path.expandvars(tmpl)
        if p != tmpl and os.path.isdir(p):
            dirs.append(p)

    logger.debug("Priority scan dirs (%d): %s", len(dirs), dirs)
    return dirs


def walk_specified_dirs(
    directories: List[str],
) -> Generator[Tuple[str, EntryKind], None, None]:
    for dirpath in directories:
        if not os.path.isdir(dirpath):
            continue
        try:
            yield from _walk_dir(dirpath)
        except Exception as exc:
            logger.warning("walk_specified_dirs error in %s: %s", dirpath, exc)
