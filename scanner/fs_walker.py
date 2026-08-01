"""
scanner/fs_walker.py
─────────────────────────────────────────────────────────────────────────────
FORWARDING WRAPPER FOR BACKWARD COMPATIBILITY

On Windows: re-exports from windows.scanner.fs_walker (full PE + drive walk).
On Linux:   re-exports from linux.scanner.fs_walker (ELF + mount walk).

This shim keeps scanner/orchestrator.py platform-agnostic — it only imports
EntryKind, walk_specified_dirs, get_priority_scan_dirs, BINARY_EXTENSIONS.
All other symbols are platform-specific and are only imported when present.
"""

import sys

if sys.platform == "win32":
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

else:
    # Linux (and any future non-Windows platform)
    from linux.scanner.fs_walker import (
        EntryKind,
        walk_filesystem,
        walk_specified_dirs,
        get_priority_scan_dirs,
        SKIP_DIR_NAMES,
    )
    from common.scanner.fs_constants import (
        MANIFEST_FILENAMES,
        MAX_BINARY_SIZE_BYTES,
    )

    # Provide Windows-compatible stubs for symbols the orchestrator references
    BINARY_EXTENSIONS: frozenset = frozenset()   # Linux detects by exec bit, not extension
    SKIP_PATH_PREFIXES: frozenset = frozenset()

    def walk_drives():
        """Linux stub: use walk_filesystem() instead."""
        return walk_filesystem()

    def walk_dir_for_manifests(path: str):
        """Linux stub: walk_specified_dirs handles this."""
        yield from walk_specified_dirs([path])

    def get_local_fixed_drives():
        """Linux stub: returns root mount point."""
        return ["/"]

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
