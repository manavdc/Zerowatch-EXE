"""
scanner/layer1_paths.py
─────────────────────────────────────────────────────────────────────────────
FORWARDING WRAPPER FOR BACKWARD COMPATIBILITY
Relocated to windows.scanner.layer1_paths.
"""

from windows.scanner.layer1_paths import (
    inspect_pe_file,
    process_binary_batch,
)

__all__ = [
    "inspect_pe_file",
    "process_binary_batch",
]
