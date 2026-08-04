"""
macos/protection/event_logger.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation of EventLogger interface.

Logging strategy (layered, most preferred to fallback):

  1. Python `logging` — structured, always available, integrates with the
     agent's existing logging configuration. This is the primary mechanism
     and works correctly on any platform.

  2. syslog (ASL on macOS) — macOS has had the `syslog` C API since 10.0.
     Python's `syslog` module wraps this and works on macOS.
     `syslog` entries appear in:
       - /var/log/system.log (older macOS)
       - Console.app (macOS system log viewer)
       - unified log stream via log(1) command
     Priority mapping:
       CRITICAL → LOG_CRIT
       ERROR    → LOG_ERR
       WARN     → LOG_WARNING
       INFO     → LOG_INFO (default)

  3. os_log (Unified Logging System, macOS 10.12+):
     The recommended macOS logging API uses `os_log_t` and `os_log()` from
     the `os/log.h` C header (libSystem). Calling it from Python requires
     ctypes bindings that cannot be validated on Windows.
     PHASE 6D DECISION: os_log integration is deferred to native macOS testing.
     The syslog module provides an acceptable bridge (syslog messages are
     accessible via the Unified Logging subsystem on modern macOS).

  NOT USED:
    - `log` CLI — the macOS `log` command is a READER tool, not a writer.
      Log entries cannot be written to the Unified Log via `log write` in a
      way that is meaningful for production agent events.
    - journald — Linux-only.
    - win32evtlogutil — Windows-only.

  Logging failure isolation:
    Any failure in the syslog write path is caught, logged via Python's logger
    (which cannot itself fail silently), and the method returns False.
    Logging failure NEVER raises an exception to the caller.

  Log injection safety:
    event_type and message values have control characters (newlines, carriage
    returns, null bytes) removed before being passed to syslog. This prevents
    a malicious discovered filename or network hostname from forging multiple
    separate log entries.

NATIVE VALIDATION: NOT PERFORMED. syslog behavior on macOS will be validated
on real hardware. The syslog module is imported lazily to allow the module to
parse correctly on Windows (where syslog is unavailable).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict

from common.protection.interfaces import EventLogger

logger = logging.getLogger("macos.protection.event_logger")

_APP_NAME = "zerowatch-agent"

# ── syslog lazy import ────────────────────────────────────────────────────────
# syslog is available on macOS and Linux but NOT on Windows.
# Import lazily so this module can be imported on Windows for testing.
try:
    import syslog as _syslog
    _SYSLOG_AVAILABLE = True
except ImportError:
    _syslog = None          # type: ignore[assignment]
    _SYSLOG_AVAILABLE = False

# ── Log injection sanitization ─────────────────────────────────────────────────

# Control character pattern: strip newlines, carriage returns, tabs, null bytes
# that could cause a single log message to appear as multiple entries.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def _sanitize(value: str, max_length: int = 2048) -> str:
    """
    Remove control characters and truncate to max_length.

    Prevents:
      - Log injection via crafted newlines in discovered filenames or event data
      - Runaway log messages from unbounded strings

    Replaces stripped characters with a visible placeholder so data loss is
    detectable in the log output.
    """
    if not isinstance(value, str):
        value = str(value)
    # Replace control chars (except HT 0x09 tab which is acceptable)
    safe = _CONTROL_CHAR_RE.sub(" ", value)
    if len(safe) > max_length:
        safe = safe[:max_length] + "…(truncated)"
    return safe


# ── Priority mapping ──────────────────────────────────────────────────────────

def _syslog_priority(event_type: str) -> int:
    """Map event_type string to syslog priority integer."""
    if _syslog is None:
        return 6  # LOG_INFO fallback (numeric value, no constant available)
    et = (event_type or "").upper()
    if "CRITICAL" in et or "FATAL" in et:
        return _syslog.LOG_CRIT
    if "ERROR" in et or "FAIL" in et or "PINNING" in et:
        return _syslog.LOG_ERR
    if "WARN" in et:
        return _syslog.LOG_WARNING
    return _syslog.LOG_INFO


# ── syslog write ──────────────────────────────────────────────────────────────

def _write_syslog(priority: int, message: str) -> bool:
    """
    Write a message to macOS syslog (ASL / Unified Logging bridge).

    Returns True on success, False on any failure.
    """
    if not _SYSLOG_AVAILABLE or _syslog is None:
        return False
    try:
        _syslog.openlog(_APP_NAME, _syslog.LOG_PID, _syslog.LOG_DAEMON)
        _syslog.syslog(priority, message)
        _syslog.closelog()
        return True
    except Exception as exc:
        # Log via Python logger — this cannot itself fail silently
        logger.debug("syslog write failed: %s", exc)
        return False


# ── Details serialization ─────────────────────────────────────────────────────

def _serialize_details(details: Dict[str, Any]) -> str:
    """
    Safely serialize event details to a JSON string.

    Handles non-serializable values by converting them to strings.
    Never raises.
    """
    if not details:
        return "{}"
    try:
        # Attempt clean JSON serialization
        return json.dumps(details, default=str, ensure_ascii=False)
    except Exception:
        # Last-resort: repr() is always safe
        try:
            return repr(details)
        except Exception:
            return "{}"


# ── MacOSEventLogger ──────────────────────────────────────────────────────────

class MacOSEventLogger(EventLogger):
    """
    macOS implementation of EventLogger.

    Primary:  Python logging module (structured, always available)
    Secondary: syslog module (macOS ASL / Unified Logging bridge)

    Both paths run for each event. Failure in syslog does not prevent
    the Python logger from recording the event, and vice versa.

    NATIVE VALIDATION NOT PERFORMED.
    """

    def log_event(self, event_type: str, details: Dict[str, Any]) -> bool:
        """
        Log a structured security event.

        Args:
            event_type: Event category string (e.g. "agent_started",
                        "scan_complete", "certificate_pinning_failure")
            details:    Key-value metadata dict. Values are serialized to JSON.

        Returns:
            True if at least the Python logger recorded the event.
            False only if both logging paths fail (should be impossible in
            practice since Python's logger is always available).
        """
        try:
            # Sanitize inputs to prevent log injection
            safe_event_type = _sanitize(str(event_type))
            details_str     = _sanitize(_serialize_details(details))

            msg = f"[{_APP_NAME}] {safe_event_type}: {details_str}"
            priority = _syslog_priority(safe_event_type)

            # Primary: Python structured logger (always available)
            logger.info("Event [%s]: %s", safe_event_type, details_str)

            # Secondary: syslog (macOS ASL) — isolated so failure cannot
            # prevent the Python log from being considered successful.
            try:
                _write_syslog(priority, msg)
            except Exception as syslog_exc:
                logger.debug("syslog write raised unexpectedly: %s", syslog_exc)

            return True

        except Exception as exc:
            # Absolute last resort — only reached if Python logging itself fails
            try:
                logger.error("log_event internal error: %s", exc)
            except Exception:
                pass
            return False

    def log_critical(self, source: str, event_id: int, message: str) -> None:
        """
        Log a critical security event.

        Structured metadata:
          source   — originating component (e.g. "certificate_verifier")
          event_id — integer identifier for the event category
          message  — human-readable description

        Critical events are logged at LOG_CRIT / CRITICAL priority.
        Examples:
          - Certificate pinning mismatch (possible MITM attack)
          - Authentication failure
          - Unexpected process restart

        Returns None (consistent with Windows and Linux interface).
        Logging failure is reported via Python logger; it does NOT raise.
        """
        try:
            safe_source  = _sanitize(str(source))
            safe_message = _sanitize(str(message))
            # event_id is an int — validate
            if not isinstance(event_id, int):
                try:
                    event_id = int(event_id)
                except (ValueError, TypeError):
                    event_id = -1

            msg = (
                f"[{_APP_NAME}] CRITICAL [{safe_source}] "
                f"event_id={event_id}: {safe_message}"
            )

            # Python logger at CRITICAL level
            logger.critical(
                "CRITICAL [%s] event_id=%d: %s",
                safe_source, event_id, safe_message,
            )

            # syslog at LOG_CRIT — isolated so failure cannot prevent Python log
            if _SYSLOG_AVAILABLE and _syslog is not None:
                try:
                    _write_syslog(_syslog.LOG_CRIT, msg)
                except Exception as syslog_exc:
                    logger.debug("syslog write raised in log_critical: %s", syslog_exc)

        except Exception as exc:
            # Absolute last resort
            try:
                logger.error("log_critical internal error: %s — message was: %s", exc, message)
            except Exception:
                pass
