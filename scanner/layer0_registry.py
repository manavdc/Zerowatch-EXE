"""
scanner/layer0_registry.py
─────────────────────────────────────────────────────────────────────────────
FORWARDING WRAPPER FOR BACKWARD COMPATIBILITY
Relocated to windows.scanner.layer0_registry.
"""

from windows.scanner.layer0_registry import (
    get_software_from_registry,
    get_windows_store_apps,
    get_driver_inventory,
    get_os_software_item,
    _read_pe_file_version,
    _read_pe_company_name,
    _read_pe_product_name,
    _read_pe_product_version,
)

__all__ = [
    "get_software_from_registry",
    "get_windows_store_apps",
    "get_driver_inventory",
    "get_os_software_item",
    "_read_pe_file_version",
    "_read_pe_company_name",
    "_read_pe_product_name",
    "_read_pe_product_version",
]
