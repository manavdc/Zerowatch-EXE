"""
windows/protection/event_logger.py
─────────────────────────────────────────────────────────────────────────────
Windows implementation of EventLogger interface using win32evtlog.
"""

from __future__ import annotations
import logging
from typing import Any, Dict

from common.protection.interfaces import EventLogger

logger = logging.getLogger("windows.protection.event_logger")


def log_pin_failure_event(host: str, error_msg: str) -> None:
    """Log pin verification failure to Windows Event Log."""
    logger.critical("Certificate pinning verification failed for host %s! Details: %s", host, error_msg)
    try:
        import win32evtlog
        import win32evtlogutil
        win32evtlogutil.ReportEvent(
            "ZeroWatchSentinelAgent",
            1001,
            eventCategory=0,
            eventType=win32evtlog.EVENTLOG_ERROR_TYPE,
            strings=[
                "CRITICAL: ZeroWatch Endpoint Agent detected a certificate pinning mismatch (possible Man-in-the-Middle attack).",
                f"Target Host: {host}",
                f"Details: {error_msg}"
            ]
        )
    except Exception as e:
        logger.debug("Failed to write to Windows Event Log: %s", e)


class WindowsEventLogger(EventLogger):
    """Windows implementation of EventLogger interface."""

    def log_event(self, event_type: str, details: Dict[str, Any]) -> bool:
        logger.info("Event logged [%s]: %s", event_type, details)
        return True

    def log_critical(self, source: str, event_id: int, message: str) -> None:
        try:
            import win32evtlog
            import win32evtlogutil
            win32evtlogutil.ReportEvent(
                source,
                event_id,
                eventCategory=0,
                eventType=win32evtlog.EVENTLOG_ERROR_TYPE,
                strings=[message]
            )
        except Exception as e:
            logger.error("Failed writing to Windows Event Log: %s", e)
