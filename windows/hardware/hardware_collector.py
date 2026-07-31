"""
windows/hardware/hardware_collector.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation of HardwareCollector interface.
Uses Win32 registry keys and ctypes GlobalMemoryStatusEx for hardware profiling.
"""

from __future__ import annotations
import ctypes
import ctypes.wintypes as wt
import logging
import os
import winreg
from typing import Any, Dict, List, Optional

from common.scanner.interfaces import HardwareCollector

logger = logging.getLogger("windows.hardware.collector")


def get_total_ram_bytes() -> int:
    """Reads total physical RAM using GlobalMemoryStatusEx."""
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wt.DWORD),
            ("dwMemoryLoad", wt.DWORD),
            ("ullTotalPhys", ctypes.c_uint64),
            ("ullAvailPhys", ctypes.c_uint64),
            ("ullTotalPageFile", ctypes.c_uint64),
            ("ullAvailPageFile", ctypes.c_uint64),
            ("ullTotalVirtual", ctypes.c_uint64),
            ("ullAvailVirtual", ctypes.c_uint64),
            ("ullAvailExtendedVirtual", ctypes.c_uint64),
        ]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        return stat.ullTotalPhys
    return 0


class WindowsHardwareCollector(HardwareCollector):
    """Windows implementation of HardwareCollector interface."""

    def collect_fingerprint(self) -> Dict[str, Any]:
        from .fingerprint import get_machine_guid
        return {"guid": get_machine_guid()}

    def generate_device_id(self, fingerprint: Dict[str, Any]) -> str:
        from .fingerprint import generate_device_id
        return generate_device_id()

    def get_hardware_inventory(self) -> List[Dict[str, Any]]:
        ram_bytes = get_total_ram_bytes()
        return [
            {
                "category": "cpu",
                "name": "Central Processor",
                "vendor": "GenuineIntel/AuthenticAMD",
                "cores": os.cpu_count(),
            },
            {
                "category": "ram",
                "name": "System Memory",
                "capacity_bytes": ram_bytes,
            }
        ]
