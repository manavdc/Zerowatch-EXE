"""
ZeroWatch Sentinel Agent - Windows Native Implementation Package
Contains Win32 APIs, Registry access, WMI, PE VersionInfo inspection,
DPAPI credential security, Task Scheduler persistence, and Windows Event Logging.

NOTE: Lazy import — do NOT eagerly import WindowsPlatform here.
WindowsPlatform is only constructed by PlatformFactory on Windows.
Top-level import would break Linux/macOS module import chains.
"""

import sys as _sys

if _sys.platform == 'win32':
    from .platform import WindowsPlatform
    __all__ = ["WindowsPlatform"]
else:
    __all__ = []
