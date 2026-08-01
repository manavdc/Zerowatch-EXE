"""
common/scanner package
Platform-independent data models, state cache, manifest parsers, and scanner interfaces.
"""

from .models import SoftwareItem
from .state_cache import ScanCache
from .layer2_manifests import parse_manifest_file
from .interfaces import (
    SoftwareCollector,
    HardwareCollector,
    BinaryInspector,
    FilesystemWalker,
    FileWatcher,
)

__all__ = [
    "SoftwareItem",
    "ScanCache",
    "parse_manifest_file",
    "SoftwareCollector",
    "HardwareCollector",
    "BinaryInspector",
    "FilesystemWalker",
    "FileWatcher",
]
