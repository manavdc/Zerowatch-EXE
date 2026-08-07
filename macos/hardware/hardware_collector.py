"""
macos/hardware/hardware_collector.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation of HardwareCollector interface.

Sources used (in order of preference for each field):
  CPU/Chip   → sysctl machdep.cpu.brand_string  (Intel)
                sysctl machdep.cpu.brand_string  may be absent on Apple Silicon;
                fall back to sysctl hw.model  (e.g. "Mac14,3")
               'platform.machine()' → "arm64" or "x86_64"
  RAM        → sysctl hw.memsize  (exact bytes, fast)
  GPU        → system_profiler SPDisplaysDataType -json  (only when called)
  Model      → sysctl hw.model  (e.g. "MacBookPro18,3")
  OS         → platform.mac_ver()
  MAC addrs  → ifconfig  (only for detailed profile; kept as ANONYMIZED if needed)

Principles:
  - sysctl calls are cheap syscalls — used without caching.
  - system_profiler is expensive — only called from get_detailed_hardware_profile()
    and only with the specific data type argument.
  - All subprocess calls use arrays (not shell=True), reasonable timeouts,
    and stderr capture.
  - Every source fails independently; the profile is still returned with
    whatever data was obtainable.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from common.scanner.interfaces import HardwareCollector
from macos.hardware.fingerprint import (
    get_primary_identity,
    generate_device_id,
)

logger = logging.getLogger("macos.hardware.collector")

_SUBPROCESS_TIMEOUT = 15  # seconds


# ── subprocess helper ─────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = _SUBPROCESS_TIMEOUT) -> str:
    """
    Run a command, return stdout string on success, empty string on failure.
    Never raises — failures are logged at DEBUG level.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        logger.debug("Command %s exited %d: %s", cmd, result.returncode, result.stderr.strip())
        return ""
    except FileNotFoundError:
        logger.debug("Command not found: %s", cmd[0])
        return ""
    except subprocess.TimeoutExpired:
        logger.debug("Command timed out: %s", cmd)
        return ""
    except OSError as exc:
        logger.debug("Command %s failed: %s", cmd, exc)
        return ""


def _sysctl(name: str) -> str:
    """Read a single sysctl value by name. Returns '' on failure."""
    sysctl = shutil.which("sysctl") or "/usr/sbin/sysctl"
    return _run([sysctl, "-n", name])


# ── CPU ───────────────────────────────────────────────────────────────────────

def _get_cpu_brand() -> str:
    """
    Get CPU / chip brand string.

    On Intel Macs: sysctl machdep.cpu.brand_string returns
        "Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz"

    On Apple Silicon: machdep.cpu.brand_string may be absent or generic;
    sysctl hw.model is the reliable source ("Mac14,3", "MacBookAir10,1", etc.)
    which unambiguously identifies the Apple Silicon SoC family.
    """
    brand = _sysctl("machdep.cpu.brand_string")
    if brand:
        return brand

    # Apple Silicon fallback: hw.model is more useful than an empty string
    model = _sysctl("hw.model")
    if model:
        return model  # e.g. "Mac14,3"

    return "Unknown CPU"


def _get_logical_cpu_count() -> int:
    """hw.logicalcpu is the sysctl preferred over os.cpu_count()."""
    raw = _sysctl("hw.logicalcpu")
    try:
        return int(raw)
    except (ValueError, TypeError):
        return os.cpu_count() or 1


def _get_physical_cpu_count() -> int:
    raw = _sysctl("hw.physicalcpu")
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 0


# ── RAM ───────────────────────────────────────────────────────────────────────

def _get_ram_bytes() -> int:
    """hw.memsize returns total RAM in bytes — fast sysctl."""
    raw = _sysctl("hw.memsize")
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 0


def _get_ram_modules() -> List[Dict[str, Any]]:
    """
    Get detailed RAM modules list via system_profiler SPMemoryDataType -json.
    Falls back to synthesizing a single module from hw.memsize if system_profiler fails
    or if running on Apple Silicon (which uses unified memory and lacks individual DIMM slots).
    """
    sp = shutil.which("system_profiler") or "/usr/sbin/system_profiler"
    raw = _run([sp, "SPMemoryDataType", "-json"], timeout=20)
    
    modules = []
    
    def _parse_size_to_bytes(size_str: str) -> int:
        parts = str(size_str).strip().split()
        if not parts:
            return 0
        try:
            val = float(parts[0])
            unit = parts[1].upper() if len(parts) > 1 else "GB"
            if "GB" in unit:
                return int(val * 1024 * 1024 * 1024)
            elif "MB" in unit:
                return int(val * 1024 * 1024)
            elif "KB" in unit:
                return int(val * 1024)
            return int(val)
        except (ValueError, IndexError):
            return 0

    if raw:
        try:
            data = json.loads(raw)
            memory_data = data.get("SPMemoryDataType", [])
            if memory_data:
                for mem_dict in memory_data:
                    items = mem_dict.get("_items")
                    if isinstance(items, list):
                        for item in items:
                            size = item.get("dimm_size") or ""
                            if not size or "empty" in str(size).lower():
                                continue
                            
                            speed = item.get("dimm_speed") or "Unknown"
                            speed_mhz = speed.replace(" MHz", "").strip() if " MHz" in speed else speed
                            
                            modules.append({
                                "manufacturer": item.get("dimm_manufacturer") or "ANONYMIZED",
                                "part_number":  item.get("dimm_part_number") or "ANONYMIZED",
                                "serial":       item.get("dimm_serial_number") or "ANONYMIZED",
                                "speed_mhz":    speed_mhz,
                                "capacity_bytes": str(_parse_size_to_bytes(size))
                            })
        except Exception as exc:
            logger.debug("system_profiler SPMemoryDataType parse failed: %s", exc)

    # Fallback / Apple Silicon check: If no modules were collected, synthesize a single module
    if not modules:
        ram_bytes = _get_ram_bytes()
        if ram_bytes > 0:
            modules.append({
                "manufacturer": "Apple Inc.",
                "part_number":  "Unified Memory" if _get_arch() == "arm64" else "System RAM",
                "serial":       "ANONYMIZED",
                "speed_mhz":    "Unknown",
                "capacity_bytes": str(ram_bytes)
            })
            
    return modules


# ── Architecture ──────────────────────────────────────────────────────────────

def _get_arch() -> str:
    """
    Return 'arm64' for Apple Silicon, 'x86_64' for Intel.
    platform.machine() is reliable and does not require a subprocess call.
    Under Rosetta 2, it still reports 'arm64' for the native architecture.
    """
    return platform.machine()  # "arm64" or "x86_64"


# ── Model / Board ─────────────────────────────────────────────────────────────

def _get_model_identifier() -> str:
    """hw.model yields the model identifier string, e.g. 'MacBookPro18,3'."""
    return _sysctl("hw.model")


# ── OS info ───────────────────────────────────────────────────────────────────

def _get_os_info() -> Dict[str, str]:
    """
    Uses platform.mac_ver() which reads CoreFoundation and is always reliable
    on macOS without spawning a subprocess.

    Returns dict with keys: name, version, arch.
    """
    release, _versiontuple, machine = platform.mac_ver()
    return {
        "name": "macOS",
        "version": release,          # e.g. "14.5"
        "arch": machine or _get_arch(),
    }


# ── System Firmware (expensive — system_profiler) ─────────────────────────────

def _get_system_firmware() -> str:
    """
    Get Boot ROM / System Firmware Version via system_profiler SPHardwareDataType -json.
    Only called from get_detailed_hardware_profile().
    """
    sp = shutil.which("system_profiler") or "/usr/sbin/system_profiler"
    raw = _run([sp, "SPHardwareDataType", "-json"], timeout=20)
    if not raw:
        return ""
    try:
        data = json.loads(raw)
        hardware = data.get("SPHardwareDataType", [])
        if hardware:
            fw = hardware[0].get("boot_rom_version") or hardware[0].get("system_firmware_version") or ""
            return fw.strip()
    except Exception as exc:
        logger.debug("system_profiler SPHardwareDataType parse failed: %s", exc)
    return ""


# ── GPU (expensive — system_profiler) ─────────────────────────────────────────

def _get_gpus() -> List[str]:
    """
    Get GPU names via system_profiler SPDisplaysDataType -json.
    Only called from get_detailed_hardware_profile().
    """
    sp = shutil.which("system_profiler") or "/usr/sbin/system_profiler"
    raw = _run([sp, "SPDisplaysDataType", "-json"], timeout=20)
    if not raw:
        return []
    try:
        data = json.loads(raw)
        displays = data.get("SPDisplaysDataType", [])
        gpus = []
        for display in displays:
            # Keys vary by macOS version: sppci_model or _sppci_gpuName
            name = (
                display.get("sppci_model")
                or display.get("_sppci_gpuName")
                or display.get("spdisplays_vendor")
                or ""
            )
            if name and name not in gpus:
                gpus.append(name)
        return gpus if gpus else ["Unknown"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        logger.debug("system_profiler SPDisplaysDataType parse failed: %s", exc)
        return []


# ── MAC addresses ─────────────────────────────────────────────────────────────

def _get_mac_addresses() -> List[str]:
    """
    Get non-loopback MAC addresses via ifconfig.
    Falls back to ['ANONYMIZED'] if unavailable.
    """
    ifconfig = shutil.which("ifconfig") or "/sbin/ifconfig"
    output = _run([ifconfig])
    if not output:
        return ["ANONYMIZED"]

    macs = []
    import re
    # Match lines like: ether XX:XX:XX:XX:XX:XX
    for m in re.finditer(r"\bether\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", output):
        mac = m.group(1).upper()
        if mac != "00:00:00:00:00:00" and mac not in macs:
            macs.append(mac)
    return macs if macs else ["ANONYMIZED"]


# ── MacOSHardwareCollector ────────────────────────────────────────────────────

class MacOSHardwareCollector(HardwareCollector):
    """macOS implementation of HardwareCollector interface."""

    def collect_fingerprint(self) -> Dict[str, Any]:
        """
        Collect a full set of hardware identifiers for the GUI DATA INFO panel
        and for device fingerprinting.

        All fields use the same key names as the Windows collect_fingerprint()
        so that the GUI _build_data_info_content() can display them with the
        same field-lookup code on every OS.  macOS-specific extras are also
        included for the GUI's darwin branch.
        """
        import socket as _socket

        identity, source = get_primary_identity()
        arch  = _get_arch()
        model = _get_model_identifier()

        # IOKit serial — also useful to display in GUI
        try:
            from macos.hardware.fingerprint import (
                get_ioreg_uuid, get_ioreg_serial,
            )
            hw_serial       = get_ioreg_serial() or "UNAVAILABLE"
            ioplatform_uuid = get_ioreg_uuid() or identity
        except Exception:
            hw_serial       = identity if source == "ioreg_serial" else "UNAVAILABLE"
            ioplatform_uuid = identity if source == "ioreg_uuid"   else "UNAVAILABLE"

        os_info = _get_os_info()
        macs    = _get_mac_addresses()
        mac_addr = macs[0] if macs else ""
        dev_id  = generate_device_id()
        cpu_brand = _get_cpu_brand()

        hostname = ""
        try:
            hostname = _socket.gethostname()
        except Exception:
            pass

        return {
            # Keys matching Windows collect_fingerprint() — used by GUI
            "bios_uuid":          ioplatform_uuid,    # IOKit UUID (macOS analog of BIOS UUID)
            "bios_serial":        hw_serial,            # IOPlatformSerialNumber
            "motherboard_serial": hw_serial,            # Same serial (no separate mb serial on Mac)
            "motherboard_product": model,               # e.g. "MacBookPro18,3"
            "cpu_id":             cpu_brand,            # CPU/chip brand string
            "machine_guid":       ioplatform_uuid,     # Same as bios_uuid (no separate GUID)
            "mac_address":        mac_addr,
            "mac_addresses":      macs,
            "disk_serial":        "UNAVAILABLE",       # Not exposed without entitlements
            "os_serial":          os_info.get("version", ""),
            "device_id":          dev_id,
            "hostname":           hostname,
            # macOS-specific extras (read by GUI darwin branch)
            "ioplatform_uuid":    ioplatform_uuid,
            "hardware_serial":    hw_serial,
            "model_identifier":   model,
            "cpu_arch":           arch,
            "os_version":         os_info.get("version", ""),
            "identity":           identity,
            "source":             source,
        }

    def generate_device_id(self, fingerprint: Dict[str, Any]) -> str:
        """
        Derive a deterministic device ID from the fingerprint.
        Delegates to fingerprint.generate_device_id() which uses
        the same IOKit identity chain used in collect_fingerprint().
        """
        return generate_device_id()

    def get_hardware_inventory(self) -> List[Dict[str, Any]]:
        """
        Lightweight inventory suitable for quick checks.
        Uses only sysctl calls (no system_profiler).
        """
        ram_bytes = _get_ram_bytes()
        cpu_brand = _get_cpu_brand()
        logical_cpus = _get_logical_cpu_count()

        return [
            {
                "category": "cpu",
                "name": cpu_brand,
                "vendor": "Apple" if _get_arch() == "arm64" else "Intel/AMD",
                "cores": logical_cpus,
            },
            {
                "category": "ram",
                "name": "System Memory",
                "capacity_bytes": ram_bytes,
            },
        ]

    def get_detailed_hardware_profile(self) -> Dict[str, Any]:
        """
        Full structured hardware profile matching the backend schema
        established by Windows and Linux implementations.

        NOTE: Calls system_profiler SPDisplaysDataType for GPU — this is
        the only expensive call. All other sources are lightweight sysctl/platform.
        """
        ram_bytes = _get_ram_bytes()
        ram_kb = str(ram_bytes // 1024) if ram_bytes else "0"
        ram_gb = round(ram_bytes / (1024 ** 3), 2) if ram_bytes else 0.0

        cpu_brand = _get_cpu_brand()
        logical_cpus = _get_logical_cpu_count()
        physical_cpus = _get_physical_cpu_count()
        arch = _get_arch()
        model = _get_model_identifier()
        os_info = _get_os_info()
        gpus = _get_gpus()  # Only expensive call
        macs = _get_mac_addresses()
        ram_modules = _get_ram_modules()

        return {
            "cpu": cpu_brand,
            "cpu_details": {
                "cores": physical_cpus or logical_cpus,
                "logical_processors": logical_cpus,
                "max_clock_mhz": "Unknown",  # sysctl hw.cpufrequency absent on Apple Silicon
                "manufacturer": "Apple" if arch == "arm64" else "Intel/AMD",
                "socket_count": 1,           # macOS always single socket
                "processor_id": "ANONYMIZED",
            },
            "ram": {
                "total_kb": ram_kb,
                "total_gb": ram_gb,
                "modules": ram_modules,
                "module_count": len(ram_modules),
            },
            "gpu": gpus[0] if gpus else "Unknown",
            "gpus": [{"name": g} for g in gpus],
            "motherboard": {
                "manufacturer": "Apple Inc.",
                "product": model,
                "version": "",
            },
            "bios": {
                "manufacturer": "Apple Inc.",
                "version": _get_system_firmware(),
                "release_date": "",
            },
            "os_info": {
                "name": os_info["name"],
                "version": os_info["version"],
                "arch": os_info["arch"],
                "model_id": model,
            },
            "mac_addresses": macs,
        }
