"""
linux/hardware/hardware_collector.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of HardwareCollector interface.

Sources:
  CPU    -> /proc/cpuinfo
  RAM    -> /proc/meminfo
  GPU    -> /sys/class/drm/ (lspci fallback)
  Board  -> /sys/class/dmi/id/board_{vendor,name,version}
  BIOS   -> /sys/class/dmi/id/bios_{vendor,version,date}
  OS     -> /etc/os-release
  MACs   -> /sys/class/net/*/address  (loopback excluded)
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from common.scanner.interfaces import HardwareCollector
from linux.hardware.fingerprint import (
    get_machine_id,
    get_dmi_product_uuid,
    generate_device_id,
)

logger = logging.getLogger("linux.hardware.collector")


# ── Proc/sys helpers ─────────────────────────────────────────────────────────

def _read_file(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return default


def _parse_cpuinfo() -> Dict[str, Any]:
    """Parse /proc/cpuinfo and return aggregate CPU info."""
    cpu: Dict[str, Any] = {
        "model_name": "Unknown CPU",
        "physical_ids": set(),
        "cores": 0,
        "max_mhz": "",
        "vendor": "",
    }
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key == "model name" and not cpu["model_name"].startswith("Intel") and not cpu["model_name"].startswith("AMD"):
                    cpu["model_name"] = value
                elif key == "cpu mhz":
                    cpu["max_mhz"] = value
                elif key == "cpu cores":
                    try:
                        cpu["cores"] = max(cpu["cores"], int(value))
                    except ValueError:
                        pass
                elif key == "vendor_id":
                    cpu["vendor"] = value
                elif key == "physical id":
                    cpu["physical_ids"].add(value)
    except OSError as exc:
        logger.debug("Failed reading /proc/cpuinfo: %s", exc)
    cpu["socket_count"] = len(cpu["physical_ids"]) or 1
    return cpu


def _parse_meminfo() -> Dict[str, Any]:
    """Parse /proc/meminfo and return total RAM in kB."""
    mem: Dict[str, Any] = {"total_kb": 0}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            mem["total_kb"] = int(parts[1])
                        except ValueError:
                            pass
                    break
    except OSError as exc:
        logger.debug("Failed reading /proc/meminfo: %s", exc)
    return mem


def _get_ram_modules() -> List[Dict[str, Any]]:
    """
    Enumerate RAM DIMM slots via `dmidecode --type 17`.
    Requires root privileges; returns [] if unavailable or access denied.

    Each returned dict has keys:
        slot, size_gb, type, speed_mhz, manufacturer, part_number
    """
    if not shutil.which("dmidecode"):
        return []
    modules: List[Dict[str, Any]] = []
    try:
        result = subprocess.run(
            ["dmidecode", "--type", "17"],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "LANG": "C"},
        )
        if result.returncode != 0:
            logger.debug("dmidecode --type 17 returned %d", result.returncode)
            return []

        current: Dict[str, Any] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Memory Device"):
                if current:
                    modules.append(current)
                current = {}
            elif ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key == "locator" and "bank" not in key:
                    current["slot"] = val
                elif key == "size" and val not in ("No Module Installed", "Not Installed", ""):
                    # Parse e.g. "16384 MB" or "16 GB"
                    parts = val.split()
                    try:
                        amount = int(parts[0])
                        unit   = parts[1].upper() if len(parts) > 1 else "MB"
                        size_gb = round(amount / 1024, 1) if unit == "MB" else amount
                        current["size_gb"] = size_gb
                    except (ValueError, IndexError):
                        pass
                elif key == "type":
                    current["type"] = val
                elif key == "speed" and "Unknown" not in val:
                    current["speed_mhz"] = val.replace(" MT/s", "").replace(" MHz", "")
                elif key == "manufacturer" and val not in ("Unknown", "", "Not Specified"):
                    current["manufacturer"] = val
                elif key == "part number" and val not in ("Unknown", "", "Not Specified"):
                    current["part_number"] = val.strip()
        if current:
            modules.append(current)
        # Filter out empty / uninstalled slots
        modules = [m for m in modules if "size_gb" in m]
    except Exception as exc:
        logger.debug("dmidecode RAM module enumeration failed: %s", exc)
    return modules


def _get_gpus() -> List[str]:
    """Try to enumerate GPU names from /sys/class/drm or lspci."""
    gpus: List[str] = []

    # Try /sys/class/drm for DRM-based GPUs
    drm_path = "/sys/class/drm"
    if os.path.isdir(drm_path):
        try:
            for entry in os.scandir(drm_path):
                vendor_file = os.path.join(entry.path, "device", "vendor")
                label_file = os.path.join(entry.path, "device", "label")
                uevent_file = os.path.join(entry.path, "device", "uevent")
                name = _read_file(label_file)
                if not name:
                    name = _read_file(uevent_file)
                if name and name not in gpus:
                    gpus.append(name)
        except OSError:
            pass

    # Fallback: lspci
    if not gpus and shutil.which("lspci"):
        try:
            result = subprocess.run(
                ["lspci", "-mm", "-v"],
                capture_output=True, text=True, timeout=10,
                env={**os.environ, "LANG": "C"},
            )
            for line in result.stdout.splitlines():
                if "VGA" in line or "Display" in line or "3D" in line:
                    parts = line.split('"')
                    if len(parts) >= 6:
                        gpus.append(parts[5].strip())
        except Exception:
            pass

    return gpus or ["Unknown"]


def _get_mac_addresses() -> List[str]:
    """Collect non-loopback MAC addresses from /sys/class/net/*/address."""
    macs: List[str] = []
    net_path = "/sys/class/net"
    if not os.path.isdir(net_path):
        return macs
    try:
        for entry in os.scandir(net_path):
            if entry.name == "lo":
                continue
            addr_path = os.path.join(entry.path, "address")
            mac = _read_file(addr_path)
            if mac and mac != "00:00:00:00:00:00":
                macs.append(mac.upper())
    except OSError:
        pass
    return macs


def _get_os_release() -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        key, _, value = line.partition("=")
                        fields[key.strip()] = value.strip().strip('"')
        except OSError:
            continue
        break
    return fields


# ── LinuxHardwareCollector ────────────────────────────────────────────────────

class LinuxHardwareCollector(HardwareCollector):
    """Linux implementation of HardwareCollector interface."""

    def collect_fingerprint(self) -> Dict[str, Any]:
        """
        Collect a full set of hardware identifiers for the GUI DATA INFO panel
        and for device fingerprinting.

        All fields mirror the Windows collect_fingerprint() dict so that the GUI
        _build_data_info_content() can read them with the same keys on every OS.
        """
        import socket

        machine_id  = get_machine_id() or ""
        dmi_uuid    = get_dmi_product_uuid() or ""
        bios_serial = _read_file("/sys/class/dmi/id/product_serial")
        mb_serial   = _read_file("/sys/class/dmi/id/board_serial")
        mb_product  = _read_file("/sys/class/dmi/id/product_name")
        cpu         = _parse_cpuinfo()
        macs        = _get_mac_addresses()
        mac_addr    = macs[0] if macs else ""
        os_rel      = _get_os_release()
        os_serial   = os_rel.get("PRETTY_NAME") or os_rel.get("NAME") or "Linux"
        dev_id      = generate_device_id()
        hostname    = ""
        try:
            hostname = socket.gethostname()
        except Exception:
            pass

        return {
            # Keys that exactly match Windows collect_fingerprint() so the GUI works
            "bios_uuid":          dmi_uuid,
            "bios_serial":        bios_serial or "UNAVAILABLE",
            "motherboard_serial": mb_serial or "UNAVAILABLE",
            "motherboard_product": mb_product or "UNAVAILABLE",
            "cpu_id":             cpu.get("model_name", "Unknown"),
            "machine_guid":       machine_id,   # machine-id is Linux's machine GUID equivalent
            "mac_address":        mac_addr,
            "mac_addresses":      macs,
            "disk_serial":        "UNAVAILABLE",  # Requires root; not collected without sudo
            "os_serial":          os_serial,
            "device_id":          dev_id,
            "hostname":           hostname,
            # Linux-specific extras (read by GUI on linux branch)
            "machine_id":         machine_id,
            "dmi_uuid":           dmi_uuid,
        }

    def generate_device_id(self, fingerprint: Dict[str, Any]) -> str:
        return generate_device_id()

    def get_hardware_inventory(self) -> List[Dict[str, Any]]:
        cpu = _parse_cpuinfo()
        mem = _parse_meminfo()
        return [
            {
                "category": "cpu",
                "name": cpu["model_name"],
                "vendor": cpu.get("vendor", ""),
                "cores": cpu.get("cores", os.cpu_count()),
            },
            {
                "category": "ram",
                "name": "System Memory",
                "capacity_bytes": mem["total_kb"] * 1024,
            },
        ]

    def get_detailed_hardware_profile(self) -> Dict[str, Any]:
        cpu = _parse_cpuinfo()
        mem = _parse_meminfo()
        gpus = _get_gpus()
        macs = _get_mac_addresses()
        os_rel = _get_os_release()
        ram_modules = _get_ram_modules()

        total_kb = mem["total_kb"]
        total_gb = round(total_kb / (1024 * 1024), 2) if total_kb > 0 else 0.0

        return {
            "cpu": cpu["model_name"],
            "cpu_details": {
                "cores": cpu.get("cores") or os.cpu_count() or 0,
                "logical_processors": os.cpu_count() or 0,
                "max_clock_mhz": cpu.get("max_mhz", "Unknown"),
                "manufacturer": cpu.get("vendor", "Unknown"),
                "socket_count": cpu.get("socket_count", 1),
                "processor_id": "ANONYMIZED",
            },
            "ram": {
                "total_kb": str(total_kb),
                "total_gb": total_gb,
                "modules": ram_modules,
                "module_count": len(ram_modules),
            },
            "gpu": gpus[0] if gpus else "Unknown",
            "gpus": [{"name": g} for g in gpus],
            "motherboard": {
                "manufacturer": _read_file("/sys/class/dmi/id/board_vendor"),
                "product": _read_file("/sys/class/dmi/id/board_name"),
                "version": _read_file("/sys/class/dmi/id/board_version"),
            },
            "bios": {
                "manufacturer": _read_file("/sys/class/dmi/id/bios_vendor"),
                "version": _read_file("/sys/class/dmi/id/bios_version"),
                "release_date": _read_file("/sys/class/dmi/id/bios_date"),
            },
            "os_info": {
                "name": os_rel.get("PRETTY_NAME") or os_rel.get("NAME") or "Linux",
                "version": os_rel.get("VERSION") or os_rel.get("VERSION_ID") or "",
                "id": os_rel.get("ID") or "",
                "kernel": _read_file("/proc/version").split()[0:3],
            },
            "mac_addresses": macs or ["ANONYMIZED"],
        }
