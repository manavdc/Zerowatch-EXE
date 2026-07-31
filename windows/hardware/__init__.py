"""
windows/hardware package
Windows hardware profiling and fingerprinting implementations.
"""

from .hardware_collector import WindowsHardwareCollector, get_total_ram_bytes
from .fingerprint import get_machine_guid, generate_device_id

__all__ = [
    "WindowsHardwareCollector",
    "get_total_ram_bytes",
    "get_machine_guid",
    "generate_device_id",
]
