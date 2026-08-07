"""
macos/persistence/startup_manager.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation of PersistenceManager interface.

Persistence mechanism: launchd LaunchDaemon plist.

Design decisions:

  LaunchDaemon vs LaunchAgent:
    ZeroWatch is an endpoint security agent that must run independently of any
    user session, continue scanning after user logout, and start on boot without
    requiring an interactive login. LaunchDaemons satisfy all of these requirements.
    LaunchAgents run in the user session context and stop on logout — they are NOT
    appropriate for a security daemon.

  Plist location:
    /Library/LaunchDaemons/io.deepcytes.zerowatch.agent.plist
    (requires root/admin privileges to write and manage)

  Label:
    io.deepcytes.zerowatch.agent
    Reverse-DNS identifier following Apple's LaunchDaemon naming convention.

  launchctl strategy:
    Bootstrap domain: system (for LaunchDaemons)
    Modern launchctl verbs used:
      - bootstrap <domain_target> <plist_path>  (load and start)
      - bootout   <domain_target> <plist_path>  (unload and remove from bootstrap)
    The legacy `launchctl load` / `launchctl unload` are avoided because they
    are soft-deprecated in macOS Monterey and later.
    Domain target for system daemons: "system" (equivalent to /System)

  Privilege requirements:
    Installing or removing a LaunchDaemon under /Library/LaunchDaemons requires
    root/Administrator privileges. If insufficient privileges are detected, the
    method fails cleanly with a logged error. No privilege escalation is attempted.

  Plist construction:
    Uses Python's plistlib — NOT string concatenation.
    All values are validated before writing.

  subprocess safety:
    All launchctl invocations use argument arrays (no shell=True).
    Capture_output=True prevents output injection.
    Timeout prevents hangs.

NATIVE VALIDATION: NOT PERFORMED. All launchctl behavior is mocked in tests.
"""

from __future__ import annotations

import logging
import os
import plistlib
import shutil
import subprocess
from typing import List, Optional, Tuple

from common.persistence.interfaces import PersistenceManager

logger = logging.getLogger("macos.persistence.startup")

# ── Constants ─────────────────────────────────────────────────────────────────

LAUNCHD_LABEL = "io.deepcytes.zerowatch.agent"
PLIST_FILENAME = f"{LAUNCHD_LABEL}.plist"
DAEMON_DIR = "/Library/LaunchDaemons"
PLIST_PATH = os.path.join(DAEMON_DIR, PLIST_FILENAME)

# Plist file permissions — must NOT be world-writable for launchd to load it.
PLIST_FILE_MODE = 0o644   # rw-r--r--
PLIST_DIR_MODE  = 0o755   # rwxr-xr-x

_LAUNCHCTL_TIMEOUT = 30   # seconds

# System domain target for launchd bootstrap (system LaunchDaemons)
_SYSTEM_DOMAIN = "system"


# ── plist construction ────────────────────────────────────────────────────────

def _build_plist(
    exe_path: str,
    daemon_args: Optional[List[str]] = None,
    working_dir: Optional[str] = None,
    stdout_path: Optional[str] = None,
    stderr_path: Optional[str] = None,
) -> dict:
    """
    Build the launchd plist dictionary.

    Keys and their justification:
      Label            — required; unique reverse-DNS identifier
      ProgramArguments — required; [exe_path, ...args] as array (NOT a shell string)
      RunAtLoad        — start the daemon immediately when the plist is bootstrapped
      KeepAlive        — launchd respawns the process if it exits unexpectedly
      WorkingDirectory — set to dirname(exe_path) or provided override
      StandardOutPath  — stdout log file (if provided)
      StandardErrorPath — stderr log file (if provided)
    """
    import sys
    if exe_path.endswith('.py'):
        program_arguments = [sys.executable, exe_path]
    else:
        program_arguments = [exe_path]

    if daemon_args:
        # Validate all args are strings
        for arg in daemon_args:
            if not isinstance(arg, str):
                raise ValueError(f"daemon_args must be List[str], got {type(arg)}: {arg!r}")
        program_arguments.extend(daemon_args)
    else:
        program_arguments.append("--daemon")

    plist: dict = {
        "Label":            LAUNCHD_LABEL,
        "ProgramArguments": program_arguments,
        "RunAtLoad":        True,
        "KeepAlive":        True,
        "WorkingDirectory": working_dir or os.path.dirname(exe_path) or "/",
    }

    if stdout_path:
        plist["StandardOutPath"] = stdout_path
    if stderr_path:
        plist["StandardErrorPath"] = stderr_path

    return plist


# ── plist I/O ─────────────────────────────────────────────────────────────────

def _write_plist(plist_data: dict, plist_path: str) -> Optional[str]:
    """
    Write the plist to disk using plistlib (no string concatenation).
    Sets file permissions to 0o644 (required by launchd).
    Returns the path on success, None on failure.
    """
    daemon_dir = os.path.dirname(plist_path)
    try:
        os.makedirs(daemon_dir, mode=PLIST_DIR_MODE, exist_ok=True)
    except PermissionError as exc:
        logger.error(
            "Insufficient privileges to create %s: %s. "
            "Installing a LaunchDaemon requires root/Administrator access.",
            daemon_dir, exc,
        )
        return None
    except OSError as exc:
        logger.error("Failed to create daemon dir %s: %s", daemon_dir, exc)
        return None

    try:
        plist_bytes = plistlib.dumps(plist_data, fmt=plistlib.FMT_XML)
        with open(plist_path, "wb") as fh:
            fh.write(plist_bytes)
        os.chmod(plist_path, PLIST_FILE_MODE)
        logger.info("Wrote launchd plist: %s", plist_path)
        return plist_path
    except PermissionError as exc:
        logger.error(
            "Insufficient privileges to write %s: %s. "
            "Root/Administrator access is required.",
            plist_path, exc,
        )
        return None
    except OSError as exc:
        logger.error("Failed to write plist %s: %s", plist_path, exc)
        return None


# ── launchctl helpers ─────────────────────────────────────────────────────────

def _launchctl_path() -> Optional[str]:
    """Return absolute path to launchctl if available."""
    path = shutil.which("launchctl") or "/bin/launchctl"
    if os.path.isfile(path):
        return path
    logger.warning("launchctl not found — not running on macOS?")
    return None


def _launchctl(
    *args: str,
    timeout: int = _LAUNCHCTL_TIMEOUT,
) -> Tuple[bool, str, str]:
    """
    Execute launchctl with the given argument array.

    Returns:
        (success: bool, stdout: str, stderr: str)

    Never uses shell=True.
    """
    lctl = _launchctl_path()
    if not lctl:
        return False, "", "launchctl not available"

    cmd = [lctl] + list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        ok = result.returncode == 0
        if not ok:
            logger.debug(
                "launchctl %s failed (rc=%d): %s",
                " ".join(args), result.returncode, result.stderr.strip(),
            )
        return ok, result.stdout, result.stderr
    except FileNotFoundError:
        logger.error("launchctl not found at %s", lctl)
        return False, "", "launchctl not found"
    except subprocess.TimeoutExpired:
        logger.error("launchctl timed out after %ds", timeout)
        return False, "", "timeout"
    except OSError as exc:
        logger.error("launchctl OSError: %s", exc)
        return False, "", str(exc)


def _bootstrap(plist_path: str) -> bool:
    """
    Bootstrap a LaunchDaemon into the system domain.
    Equivalent to: launchctl bootstrap system <plist_path>

    Note: the system domain target for LaunchDaemons is simply "system".
    """
    ok, stdout, stderr = _launchctl("bootstrap", _SYSTEM_DOMAIN, plist_path)
    if ok:
        logger.info("launchd bootstrap succeeded: %s", LAUNCHD_LABEL)
    else:
        # "already bootstrapped" is not a fatal error
        if "already" in stderr.lower() or "exists" in stderr.lower():
            logger.info("Service already bootstrapped — treating as success: %s", LAUNCHD_LABEL)
            return True
        logger.error("launchd bootstrap failed: %s", stderr.strip())
    return ok


def _bootout(plist_path: str) -> bool:
    """
    Remove a LaunchDaemon from the system domain.
    Equivalent to: launchctl bootout system <plist_path>

    "service not loaded" is treated as success (idempotent).
    """
    ok, stdout, stderr = _launchctl("bootout", _SYSTEM_DOMAIN, plist_path)
    if ok:
        logger.info("launchd bootout succeeded: %s", LAUNCHD_LABEL)
    else:
        # Not loaded = already unregistered = acceptable
        stderr_lower = stderr.lower()
        if (
            "no such process" in stderr_lower
            or "not loaded" in stderr_lower
            or "does not exist" in stderr_lower
            or "no such file" in stderr_lower
            or "no job" in stderr_lower
        ):
            logger.info("Service not currently loaded — treating bootout as success")
            return True
        logger.warning("launchd bootout returned non-zero: %s", stderr.strip())
    return ok


# ── Path validation ────────────────────────────────────────────────────────────

def _validate_exe_path(exe_path: str) -> bool:
    """Validate that the executable path is safe and absolute."""
    if not exe_path:
        logger.error("exe_path is empty")
        return False
    if not os.path.isabs(exe_path):
        logger.error("exe_path must be absolute, got: %r", exe_path)
        return False
    # Safety: must not contain shell metacharacters (path will be in array, but
    # we sanity-check anyway to catch inadvertent misuse)
    disallowed = {";", "|", "&", "`", "$", ">", "<", "\n", "\r"}
    if any(ch in exe_path for ch in disallowed):
        logger.error("exe_path contains disallowed characters: %r", exe_path)
        return False
    return True


# ── MacOSPersistenceManager ───────────────────────────────────────────────────

class MacOSPersistenceManager(PersistenceManager):
    """
    macOS implementation of PersistenceManager using launchd LaunchDaemon.

    Requires root/Administrator privileges to install or remove a LaunchDaemon.
    If insufficient privileges are detected, operations fail cleanly.

    NATIVE VALIDATION NOT PERFORMED — launchctl calls are mocked in tests.
    """

    def register_startup(
        self,
        exe_path: str,
        daemon_args: Optional[List[str]] = None,
    ) -> bool:
        """
        Install ZeroWatch as a launchd LaunchDaemon.

        Steps:
          1. Validate executable path
          2. Generate plist using plistlib
          3. Write plist to /Library/LaunchDaemons/ (requires root)
          4. Bootstrap service into system domain

        Returns True on success, False on any failure.
        """
        if not _validate_exe_path(exe_path):
            return False

        plist_data = _build_plist(
            exe_path=exe_path,
            daemon_args=daemon_args,
            stdout_path="/var/log/zerowatch-agent.log",
            stderr_path="/var/log/zerowatch-agent-error.log",
        )

        plist_path = _write_plist(plist_data, PLIST_PATH)
        if plist_path is None:
            return False

        return _bootstrap(plist_path)

    def unregister_startup(self) -> bool:
        """
        Remove ZeroWatch LaunchDaemon from launchd.

        Steps:
          1. Bootout from system domain (idempotent — no error if not loaded)
          2. Remove plist file

        Returns True if the agent is no longer registered after this call.
        """
        ok = _bootout(PLIST_PATH)

        # Remove the plist even if bootout failed (cleanup is best-effort)
        if os.path.isfile(PLIST_PATH):
            try:
                os.remove(PLIST_PATH)
                logger.info("Removed plist: %s", PLIST_PATH)
            except PermissionError as exc:
                logger.error(
                    "Insufficient privileges to remove %s: %s. "
                    "Root/Administrator access is required.",
                    PLIST_PATH, exc,
                )
                return False
            except OSError as exc:
                logger.warning("Failed to remove plist %s: %s", PLIST_PATH, exc)

        return ok

    def is_persistence_active(self) -> bool:
        """
        Check whether the ZeroWatch plist is currently installed on disk.
        Does NOT verify whether launchd has the service bootstrapped.
        """
        return os.path.isfile(PLIST_PATH)
