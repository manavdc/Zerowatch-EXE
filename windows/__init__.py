"""
ZeroWatch Sentinel Agent - Windows Native Implementation Package
Contains Win32 APIs, Registry access, WMI, PE VersionInfo inspection,
DPAPI credential security, Task Scheduler persistence, and Windows Event Logging.
"""

from .platform import WindowsPlatform

__all__ = ["WindowsPlatform"]
