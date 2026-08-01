"""
linux/protection/event_logger.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of EventLogger interface.

Primary:  systemd journal (via systemd.journal.send or sd_journal_send)
Fallback: syslog module (always available on Linux)

Critical security events (certificate pinning failures, auth failures)
are logged at LOG_CRIT / LOG_ERR priority so they appear in:
  journalctl -u zerowatch-agent
  /var/log/syslog  (on syslog-enabled systems)
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from common.protection.interfaces import EventLogger

logger = logging.getLogger("linux.protection.event_logger")

# syslog is Linux-only; import lazily so this module parses on Windows
try:
    import syslog as _syslog
except ImportError:
    _syslog = None  # type: ignore[assignment]

_APP_NAME = "zerowatch-agent"


def _try_journal_send(priority: int, _msg: str, **kwargs: Any) -> bool:
    """Try to write to systemd journal; return True on success."""
    try:
        import importlib
        journal = importlib.import_module("systemd.journal")
        journal.send(
            _msg,
            PRIORITY=priority,
            SYSLOG_IDENTIFIER=_APP_NAME,
            **{k.upper(): str(v) for k, v in kwargs.items()},
        )
        return True
    except ImportError:
        return False
    except Exception as exc:
        logger.debug("journal.send failed: %s", exc)
        return False


def _syslog_priority(event_type: str) -> int:
    if _syslog is None:
        return 6  # LOG_INFO fallback value
    et = (event_type or "").upper()
    if "CRITICAL" in et or "FATAL" in et:
        return _syslog.LOG_CRIT
    if "ERROR" in et or "FAIL" in et:
        return _syslog.LOG_ERR
    if "WARN" in et:
        return _syslog.LOG_WARNING
    return _syslog.LOG_INFO


class LinuxEventLogger(EventLogger):
    """Linux implementation of EventLogger using journald / syslog."""

    def log_event(self, event_type: str, details: Dict[str, Any]) -> bool:
        msg = f"[{_APP_NAME}] {event_type}: {details}"
        priority = _syslog_priority(event_type)

        # Try journald first
        if _try_journal_send(priority, msg, event_type=event_type, **{
            k: str(v) for k, v in details.items()
        }):
            return True

        # Fallback: syslog
        if _syslog is None:
            return False
        try:
            _syslog.openlog(_APP_NAME, _syslog.LOG_PID, _syslog.LOG_DAEMON)
            _syslog.syslog(priority, msg)
            _syslog.closelog()
            return True
        except Exception as exc:
            logger.debug("syslog.syslog failed: %s", exc)
            return False

    def log_critical(self, source: str, event_id: int, message: str) -> None:
        msg = f"[{_APP_NAME}] CRITICAL [{source}] event_id={event_id}: {message}"
        priority = _syslog.LOG_CRIT if _syslog is not None else 2

        if _try_journal_send(
            priority, msg,
            source=source,
            event_id=str(event_id),
        ):
            return

        if _syslog is not None:
            try:
                _syslog.openlog(_APP_NAME, _syslog.LOG_PID, _syslog.LOG_DAEMON)
                _syslog.syslog(_syslog.LOG_CRIT, msg)
                _syslog.closelog()
            except Exception as exc:
                logger.error("Event logging failed: %s — message was: %s", exc, msg)
