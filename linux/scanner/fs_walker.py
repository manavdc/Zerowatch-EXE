"""
linux/scanner/fs_walker.py
─────────────────────────────────────────────────────────────────────────────
Intelligent filesystem walker for vulnerability-relevant files on Linux.

Strategy:
  1. Reads /proc/mounts to identify real (non-pseudo) filesystems.
  2. Skips pseudo-FS mount points: /proc, /sys, /dev, /run, etc.
  3. Skips network-mounted filesystems by default (NFS, CIFS, etc.).
  4. Detects manifest files by name (reuses common/scanner/fs_constants.py).
  5. Detects ELF binaries by executable bit (st_mode & 0o111) rather than extension.
  6. Detects shared libraries (.so, .so.N) by extension.
  7. Avoids symlink loops via follow_symlinks=False.
  8. Skips directories unlikely to contain exploitable software.
"""

from __future__ import annotations

import logging
import os
import stat
from enum import Enum, auto
from typing import Generator, FrozenSet, List, Optional, Set, Tuple

from common.scanner.fs_constants import (
    MANIFEST_FILENAMES,
    CONDITIONAL_SKIP_GROUPS,
    MAX_BINARY_SIZE_BYTES,
    MAX_MANIFEST_SIZE_BYTES,
    SKIP_DIR_NAMES_COMMON,
)

logger = logging.getLogger("linux.scanner.fs_walker")


class EntryKind(Enum):
    MANIFEST = auto()   # Text manifest (parse for dependencies)
    BINARY   = auto()   # ELF executable or shared library


# ── Filesystem type constants ─────────────────────────────────────────────────

# Pseudo-filesystems that must NEVER be recursively scanned.
SKIP_FS_TYPES: FrozenSet[str] = frozenset({
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
    "mqueue", "debugfs", "securityfs", "pstore", "bpf", "tracefs",
    "hugetlbfs", "fusectl", "autofs", "rpc_pipefs", "efivarfs",
    "configfs", "ramfs", "squashfs",
})

# Network filesystems skipped by default (no local persistence to scan).
SKIP_NETWORK_FS_TYPES: FrozenSet[str] = frozenset({
    "nfs", "nfs4", "cifs", "smb2", "smbfs", "afs", "ncpfs",
    "davfs", "sshfs", "fuse.sshfs", "fuse.glusterfs",
})

# Absolute path prefixes that must always be excluded regardless of FS type.
SKIP_ABSOLUTE_PREFIXES: FrozenSet[str] = frozenset({
    "/proc", "/sys", "/dev", "/run",
    "/boot", "/lost+found",
    "/snap/core",       # snap base runtimes (not applications)
    "/var/cache",
    "/var/tmp",
    "/tmp",
})

# Linux-specific directory names to skip (merged with common set).
_LINUX_SKIP_DIR_NAMES_EXTRA: FrozenSet[str] = frozenset({
    "lost+found",
    "proc", "sys", "dev", "run",
    "boot",
    "snap_core",
    "containers",
    "overlay",
    ".Trash",
    ".trash",
    "Trash",
})

SKIP_DIR_NAMES: FrozenSet[str] = SKIP_DIR_NAMES_COMMON | _LINUX_SKIP_DIR_NAMES_EXTRA

# Priority scan locations (fast first pass).
PRIORITY_DIRS: List[str] = [
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/bin",
    "/usr/local/lib",
    "/usr/local/sbin",
    "/opt",
    "/var/lib",
    "/snap",
]

# ELF shared library extensions.
_SO_SUFFIX = ".so"


# ── Mount discovery ───────────────────────────────────────────────────────────

def get_local_mounts() -> List[str]:
    """
    Parse /proc/mounts and return mount points of real, local filesystems.
    Excludes pseudo-filesystems, network mounts, and duplicate bind mounts.
    """
    mount_points: List[str] = []
    seen_devs: Set[str] = set()

    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mountpoint, fstype = parts[0], parts[1], parts[2]

                if fstype in SKIP_FS_TYPES:
                    continue
                if fstype in SKIP_NETWORK_FS_TYPES:
                    continue
                if any(mountpoint.startswith(p) for p in SKIP_ABSOLUTE_PREFIXES):
                    continue

                # Avoid counting the same block device twice (bind mounts)
                dev_key = f"{device}:{fstype}"
                if dev_key in seen_devs and device != "overlay":
                    continue
                seen_devs.add(dev_key)

                mount_points.append(mountpoint)
    except OSError as exc:
        logger.warning("Failed to read /proc/mounts: %s — falling back to '/'", exc)
        return ["/"]

    if not mount_points:
        logger.warning("No local mounts found — falling back to '/'")
        return ["/"]

    # Sort by path length so parents come before children
    mount_points.sort(key=len)
    logger.debug("Local mounts (%d): %s", len(mount_points), mount_points)
    return mount_points


def get_priority_scan_dirs(extra_user_dirs: Optional[List[str]] = None) -> List[str]:
    """Return ordered list of priority scan directories."""
    dirs = [d for d in PRIORITY_DIRS if os.path.isdir(d)]

    # Add per-user ~/.local/bin and ~/.local/lib
    home = os.environ.get("HOME") or os.path.expanduser("~")
    for sub in (".local/bin", ".local/lib", ".local/share"):
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            dirs.append(p)

    if extra_user_dirs:
        dirs.extend(d for d in extra_user_dirs if os.path.isdir(d))

    return dirs


# ── Skip logic ────────────────────────────────────────────────────────────────

def _build_conditional_skip_set(file_names: Set[str]) -> FrozenSet[str]:
    skip: Set[str] = set()
    for trigger_manifests, dep_dirs in CONDITIONAL_SKIP_GROUPS:
        if any(
            name in trigger_manifests or name.lower() in {m.lower() for m in trigger_manifests}
            for name in file_names
        ):
            skip.update(name.lower() for name in dep_dirs)
    return frozenset(skip)


def _should_skip_dir(name: str, abs_path: str, conditional_skip: FrozenSet[str]) -> bool:
    name_lower = name.lower()
    if name_lower in SKIP_DIR_NAMES:
        return True
    if conditional_skip and name_lower in conditional_skip:
        return True
    if any(abs_path.startswith(p) for p in SKIP_ABSOLUTE_PREFIXES):
        return True
    return False


# ── Walk logic ────────────────────────────────────────────────────────────────

def _is_elf_binary(entry: os.DirEntry) -> bool:
    """Return True if this file has executable bit set and is not a symlink."""
    try:
        mode = entry.stat(follow_symlinks=False).st_mode
        return bool(mode & 0o111) and stat.S_ISREG(mode)
    except OSError:
        return False


def _is_shared_lib(name: str) -> bool:
    """Return True if file looks like a shared library (.so or .so.N)."""
    lower = name.lower()
    return lower.endswith(".so") or (".so." in lower and lower.split(".so.")[0])


def _walk_dir(
    dirpath: str,
) -> Generator[Tuple[str, EntryKind], None, None]:
    try:
        entries = list(os.scandir(dirpath))
    except (PermissionError, OSError) as exc:
        logger.debug("scandir skipped %s: %s", dirpath, exc)
        return

    file_names: Set[str] = set()
    dir_entries: list = []

    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                dir_entries.append(entry)
            elif entry.is_file(follow_symlinks=False):
                file_names.add(entry.name)
        except (PermissionError, OSError):
            pass

    conditional_skip = _build_conditional_skip_set(file_names)

    # ── Yield files ──────────────────────────────────────────────────────────
    for entry in entries:
        try:
            if entry.is_symlink() or entry.is_dir(follow_symlinks=False):
                continue
            if not entry.is_file(follow_symlinks=False):
                continue

            name = entry.name

            # Manifests (check by name, case-sensitive first then case-insensitive)
            if name in MANIFEST_FILENAMES or name.lower() in MANIFEST_FILENAMES:
                try:
                    st = entry.stat(follow_symlinks=False)
                    if 0 < st.st_size <= MAX_MANIFEST_SIZE_BYTES:
                        yield (entry.path, EntryKind.MANIFEST)
                except OSError:
                    pass
                continue

            # Shared libraries
            if _is_shared_lib(name):
                try:
                    st = entry.stat(follow_symlinks=False)
                    if 0 < st.st_size <= MAX_BINARY_SIZE_BYTES:
                        yield (entry.path, EntryKind.BINARY)
                except OSError:
                    pass
                continue

            # ELF executables (executable bit set)
            if _is_elf_binary(entry):
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

    # ── Recurse into subdirectories ───────────────────────────────────────────
    for entry in dir_entries:
        try:
            abs_path = entry.path
            if _should_skip_dir(entry.name, abs_path, conditional_skip):
                logger.debug("Skipping dir: %s", abs_path)
                continue
            yield from _walk_dir(abs_path)
        except (PermissionError, OSError) as exc:
            logger.debug("Dir error %s: %s", getattr(entry, "path", "?"), exc)
        except Exception as exc:
            logger.warning("Unexpected walk error at %s: %s", dirpath, exc)


def walk_filesystem(
    extra_dirs: Optional[List[str]] = None,
) -> Generator[Tuple[str, EntryKind], None, None]:
    """
    Main entry point. Walks all local, non-pseudo mount points.
    Yields (filepath, EntryKind) tuples.
    """
    roots = get_local_mounts()
    if extra_dirs:
        roots.extend(extra_dirs)

    # De-duplicate while preserving order
    seen_roots: Set[str] = set()
    for root in roots:
        if root not in seen_roots:
            seen_roots.add(root)
            yield from _walk_dir(root)


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
