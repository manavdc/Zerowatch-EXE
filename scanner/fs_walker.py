"""
scanner/fs_walker.py
─────────────────────────────────────────────────────────────────────────────
FORWARDING WRAPPER FOR BACKWARD COMPATIBILITY
Relocated to windows.scanner.fs_walker.
"""

from windows.scanner.fs_walker import (
    EntryKind,
    walk_drives,
    walk_dir_for_manifests,
    walk_specified_dirs,
    get_priority_scan_dirs,
    get_local_fixed_drives,
    BINARY_EXTENSIONS,
    MANIFEST_FILENAMES,
    SKIP_DIR_NAMES,
    SKIP_PATH_PREFIXES,
)

__all__ = [
    "EntryKind",
    "walk_drives",
    "walk_dir_for_manifests",
    "walk_specified_dirs",
    "get_priority_scan_dirs",
    "get_local_fixed_drives",
    "BINARY_EXTENSIONS",
    "MANIFEST_FILENAMES",
    "SKIP_DIR_NAMES",
    "SKIP_PATH_PREFIXES",
]
