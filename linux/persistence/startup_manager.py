"""
linux/persistence/startup_manager.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of PersistenceManager interface.

Uses systemd unit files as the primary persistence mechanism.

Installation:
  - System-wide: /etc/systemd/system/zerowatch-agent.service  (requires root)
  - User-scoped: ~/.config/systemd/user/zerowatch-agent.service  (fallback)

The service is configured to:
  - Start automatically on boot (WantedBy=multi-user.target)
  - Restart on failure with a 15-second backoff
  - Log to journald (StandardOutput=journal)
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import List, Optional

from common.persistence.interfaces import PersistenceManager

logger = logging.getLogger("linux.persistence.startup")

_SERVICE_NAME = "zerowatch-agent.service"
_SYSTEM_UNIT_DIR = "/etc/systemd/system"
_USER_UNIT_DIR_TEMPLATE = os.path.expanduser("~/.config/systemd/user")

_UNIT_TEMPLATE = """\
[Unit]
Description=ZeroWatch Endpoint Agent
Documentation=https://deepcytes.io
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe_path}{args}
{env_line}Restart=on-failure
RestartSec=15s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zerowatch-agent
KillSignal=SIGTERM
TimeoutStopSec=30s

[Install]
WantedBy={wanted_by}
"""


def _systemctl(*args: str, system: bool = True) -> bool:
    if not shutil.which("systemctl"):
        return False
    scope = ["--system"] if system else ["--user"]
    try:
        result = subprocess.run(
            ["systemctl"] + scope + list(args),
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0
    except Exception as exc:
        logger.debug("systemctl %s failed: %s", args, exc)
        return False


def _write_unit(unit_dir: str, exe_path: str, daemon_args: str, wanted_by: str) -> Optional[str]:
    """Write the systemd unit file; return the path on success."""
    try:
        os.makedirs(unit_dir, mode=0o755, exist_ok=True)
        unit_path = os.path.join(unit_dir, _SERVICE_NAME)
        # Prepend a space separator only when args are non-empty so ExecStart
        # does not have a trailing space (which is technically valid for systemd
        # but untidy and may confuse some tooling).
        args_suffix = (" " + daemon_args) if daemon_args.strip() else ""
        # Persist ZEROWATCH_API_URL into the unit so the agent reconnects to
        # the same server after a reboot when the shell env var is gone.
        api_url = os.environ.get("ZEROWATCH_API_URL", "").strip()
        # Place Environment= on its own line before Restart=.
        # When no URL is set (production binary), env_line is empty string.
        env_line = f"Environment=ZEROWATCH_API_URL={api_url}\n" if api_url else ""
        content = _UNIT_TEMPLATE.format(
            exe_path=exe_path,
            args=args_suffix,
            env_line=env_line,
            wanted_by=wanted_by,
        )
        with open(unit_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(unit_path, 0o644)
        logger.info("Wrote systemd unit file: %s", unit_path)
        return unit_path
    except OSError as exc:
        logger.warning("Failed writing unit to %s: %s", unit_dir, exc)
        return None


class LinuxPersistenceManager(PersistenceManager):
    """Linux implementation of PersistenceManager using systemd."""

    def register_startup(
        self,
        exe_path: str,
        daemon_args: Optional[List[str]] = None,
    ) -> bool:
        # The Linux agent binary has no --daemon flag — it always runs its
        # blocking monitor loop directly.  Pass an empty string so ExecStart
        # only contains the binary path.
        args_str = " ".join(daemon_args) if daemon_args else ""

        # If a system-wide unit already exists, do not create a user unit.
        # This prevents duplicate daemon instances across sudo and non-sudo runs.
        system_unit_path = os.path.join(_SYSTEM_UNIT_DIR, _SERVICE_NAME)
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not is_root and os.path.isfile(system_unit_path):
            # Best-effort cleanup of legacy user unit from older builds.
            user_unit_path = os.path.join(_USER_UNIT_DIR_TEMPLATE, _SERVICE_NAME)
            try:
                _systemctl("disable", _SERVICE_NAME, system=False)
            except Exception:
                pass
            try:
                if os.path.isfile(user_unit_path):
                    os.remove(user_unit_path)
                    _systemctl("daemon-reload", system=False)
            except OSError:
                pass
            logger.info(
                "System-wide unit already present (%s). Skipping user unit registration.",
                system_unit_path,
            )
            return True

        # Try system-wide install (requires root)
        unit_path = _write_unit(_SYSTEM_UNIT_DIR, exe_path, args_str, wanted_by="multi-user.target")
        if unit_path:
            _systemctl("daemon-reload", system=True)
            ok = _systemctl("enable", _SERVICE_NAME, system=True)
            if ok:
                logger.info("systemd startup registered (system-wide)")
                return True
            logger.warning("systemctl enable (system) failed — trying user scope")

        # Fallback: user-scope (~/.config/systemd/user/)
        user_unit_dir = _USER_UNIT_DIR_TEMPLATE
        unit_path = _write_unit(user_unit_dir, exe_path, args_str, wanted_by="default.target")
        if unit_path:
            _systemctl("daemon-reload", system=False)
            ok = _systemctl("enable", _SERVICE_NAME, system=False)
            if ok:
                logger.info("systemd startup registered (user-scoped)")
                return True

        logger.warning("All systemd registration attempts failed")
        return False

    def unregister_startup(self) -> bool:
        success = False
        # System-wide
        if _systemctl("disable", _SERVICE_NAME, system=True):
            unit_path = os.path.join(_SYSTEM_UNIT_DIR, _SERVICE_NAME)
            try:
                os.remove(unit_path)
            except OSError:
                pass
            _systemctl("daemon-reload", system=True)
            success = True

        # User-scoped
        if _systemctl("disable", _SERVICE_NAME, system=False):
            unit_path = os.path.join(_USER_UNIT_DIR_TEMPLATE, _SERVICE_NAME)
            try:
                os.remove(unit_path)
            except OSError:
                pass
            success = True

        return success

    def is_persistence_active(self) -> bool:
        """Check whether the systemd unit file is currently installed on disk."""
        system_path = os.path.join(_SYSTEM_UNIT_DIR, _SERVICE_NAME)
        user_path = os.path.join(_USER_UNIT_DIR_TEMPLATE, _SERVICE_NAME)
        return os.path.isfile(system_path) or os.path.isfile(user_path)

