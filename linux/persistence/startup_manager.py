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
ExecStart={exe_path} {args}
Restart=on-failure
RestartSec=15s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zerowatch-agent
KillSignal=SIGTERM
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
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


def _write_unit(unit_dir: str, exe_path: str, daemon_args: str) -> Optional[str]:
    """Write the systemd unit file; return the path on success."""
    try:
        os.makedirs(unit_dir, mode=0o755, exist_ok=True)
        unit_path = os.path.join(unit_dir, _SERVICE_NAME)
        content = _UNIT_TEMPLATE.format(exe_path=exe_path, args=daemon_args)
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
        args_str = " ".join(daemon_args) if daemon_args else "--daemon"

        # Try system-wide install (requires root)
        unit_path = _write_unit(_SYSTEM_UNIT_DIR, exe_path, args_str)
        if unit_path:
            _systemctl("daemon-reload", system=True)
            ok = _systemctl("enable", _SERVICE_NAME, system=True)
            if ok:
                logger.info("systemd startup registered (system-wide)")
                return True
            logger.warning("systemctl enable (system) failed — trying user scope")

        # Fallback: user-scope (~/.config/systemd/user/)
        user_unit_dir = _USER_UNIT_DIR_TEMPLATE
        unit_path = _write_unit(user_unit_dir, exe_path, args_str)
        if unit_path:
            _systemctl("--user", "daemon-reload", system=False)
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
