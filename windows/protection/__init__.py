"""
windows/protection package
Windows ProcessGuard and EventLogger implementations.
"""

from .process_guard import WindowsProcessGuard, harden_process_acl, install_ctrl_handler
from .event_logger import WindowsEventLogger, log_pin_failure_event

__all__ = [
    "WindowsProcessGuard",
    "harden_process_acl",
    "install_ctrl_handler",
    "WindowsEventLogger",
    "log_pin_failure_event",
]
