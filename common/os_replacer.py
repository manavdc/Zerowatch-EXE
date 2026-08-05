"""
common/os_replacer.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Platform-specific Atomic Binary Swap & Out-of-Band Watchdog

Implements the OS-specific swap mechanics described in Section 4 of the OTA spec:

  Windows (win32)  → Rename active .exe → .exe.bak, copy new → original path,
                     spawn detached --post-update-check child, exit cleanly.
  Linux            → shutil.copy2 → .bak, os.replace() (POSIX atomic renameat),
                     chmod 755, restorecon (SELinux), systemctl restart.
  macOS (darwin)   → xattr quarantine strip, codesign --verify, os.replace(),
                     launchctl kickstart -k system/{LAUNCHD_LABEL}.

Post-Update Watchdog (self-healing / out-of-band):
  Runs in a SEPARATE THREAD or PROCESS after `--post-update-check` is detected.
  120-second window: verifies the agent sends a successful heartbeat.
    • Heartbeat OK within 120s → remove .bak backup (commit)
    • No heartbeat / crash    → revert .bak → original, restart via native SCM

Service coordination:
  - Windows: sc.exe stop/start "SentinelAgent" (hardened); re-spawn via detached Popen (standard)
  - Linux:   systemctl restart zerowatch-agent.service (system) or user scope
  - macOS:   launchctl kickstart -k system/io.deepcytes.zerowatch.agent
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger("ota.os_replacer")

# ---------------------------------------------------------------------------
# Platform service identifiers (resolved from codebase inspection)
# ---------------------------------------------------------------------------
# Windows: sc.exe service name (register_windows_service in sentinel_agent.py)
_WIN_SERVICE_NAME = "SentinelAgent"

# Linux: systemd unit name (linux/persistence/startup_manager.py line 30)
_LINUX_SERVICE_NAME = "zerowatch-agent.service"

# macOS: launchd label (macos/persistence/startup_manager.py line 66)
_MACOS_LAUNCHD_LABEL = "io.deepcytes.zerowatch.agent"
_MACOS_PLIST_PATH    = f"/Library/LaunchDaemons/{_MACOS_LAUNCHD_LABEL}.plist"

# Watchdog: window within which the updated agent must prove liveness
WATCHDOG_TIMEOUT_SECS: int = 120

# Heartbeat validation poll interval inside watchdog
_WATCHDOG_POLL_SECS: int = 10


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SwapError(Exception):
    """Binary swap operation failed."""


class ServiceRestartError(Exception):
    """Native service restart failed; rollback may be required."""


# ---------------------------------------------------------------------------
# Platform dispatch: perform_update
# ---------------------------------------------------------------------------

def perform_update(
    new_binary_path: str,
    current_exe: str,
    zw_client=None,
) -> bool:
    """
    Atomically swap the new binary into place and kick the native supervisor.

    Args:
        new_binary_path: Absolute path to the verified, downloaded new binary.
        current_exe:     Absolute path to the currently running executable.
        zw_client:       ZeroWatchClient instance (used for watchdog heartbeat check).

    Returns:
        True on success.

    Raises:
        SwapError: if the binary could not be swapped.
        ServiceRestartError: if the native service restart failed.
    """
    platform = sys.platform

    if platform == "win32":
        return _swap_windows(new_binary_path, current_exe, zw_client)
    elif platform == "darwin":
        return _swap_macos(new_binary_path, current_exe, zw_client)
    elif platform.startswith("linux"):
        return _swap_linux(new_binary_path, current_exe, zw_client)
    else:
        raise SwapError(f"Unsupported platform for OTA swap: {platform}")


# ---------------------------------------------------------------------------
# Windows atomic swap (Section 4.1)
# ---------------------------------------------------------------------------

def _swap_windows(new_binary: str, current_exe: str, zw_client=None) -> bool:
    """
    Windows process handshake:
      1. Copy new binary → staging location
      2. Rename running .exe → .exe.bak  (Windows permits renaming open executables)
      3. Copy staging → current_exe path
      4. Spawn detached child: current_exe --post-update-check --parent-pid <PID>
      5. Return True (caller exits cleanly, releasing SCM hooks)

    On failure at step 2 or 3, attempts to restore .bak if it exists.
    """
    bak_path     = current_exe + ".bak"
    staging_path = current_exe + ".new"

    logger.info("[WIN SWAP] Staging new binary: %s → %s", new_binary, staging_path)

    # Stage: copy new binary to .new (keeps the download temp separate from
    # the in-use executable directory in case they are on different volumes)
    try:
        shutil.copy2(new_binary, staging_path)
    except OSError as exc:
        raise SwapError(f"Failed to stage new binary to {staging_path}: {exc}") from exc

    # Backup: rename current .exe → .exe.bak
    # Windows allows renaming a currently-executing binary.
    if os.path.exists(bak_path):
        try:
            os.remove(bak_path)
        except OSError as exc:
            logger.warning("[WIN SWAP] Could not remove stale .bak: %s", exc)

    try:
        os.rename(current_exe, bak_path)
        logger.info("[WIN SWAP] Renamed %s → %s", current_exe, bak_path)
    except OSError as exc:
        # Clean up staging if rename fails
        try:
            os.remove(staging_path)
        except OSError:
            pass
        raise SwapError(
            f"Cannot rename running exe to .bak — admin rights required? {exc}"
        ) from exc

    # Install: move .new → original path
    try:
        shutil.copy2(staging_path, current_exe)
        os.remove(staging_path)
        logger.info("[WIN SWAP] Installed new binary: %s", current_exe)
    except OSError as exc:
        # Rollback the rename immediately
        logger.error("[WIN SWAP] Install failed — restoring .bak: %s", exc)
        try:
            os.rename(bak_path, current_exe)
        except OSError as rb_exc:
            logger.critical("[WIN SWAP] Rollback also failed: %s", rb_exc)
        raise SwapError(f"Failed to copy new binary into place: {exc}") from exc

    # Spawn detached post-update-check child
    _spawn_post_update_check(current_exe)

    logger.info(
        "[WIN SWAP] Swap complete. Post-update watchdog spawned. "
        "Main process will exit to release SCM hooks."
    )
    return True


def _spawn_post_update_check(current_exe: str) -> None:
    """
    Spawn detached child: current_exe --post-update-check --parent-pid <PID>

    The child runs PostUpdateWatchdog which monitors liveness for 120 seconds
    and rolls back if the agent fails to heartbeat.
    """
    import ctypes
    DETACHED    = 0x00000008
    NEW_GROUP   = 0x00000200

    cmd = [current_exe, "--post-update-check", "--parent-pid", str(os.getpid())]

    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE

        subprocess.Popen(
            cmd,
            creationflags = DETACHED | NEW_GROUP | subprocess.CREATE_NO_WINDOW,
            startupinfo   = si,
        )
        logger.info("[WIN SWAP] Detached post-update watchdog spawned.")
    except Exception as exc:
        logger.warning("[WIN SWAP] Failed to spawn post-update check process: %s", exc)


# ---------------------------------------------------------------------------
# Linux atomic swap (Section 4.2)
# ---------------------------------------------------------------------------

def _swap_linux(new_binary: str, current_exe: str, zw_client=None) -> bool:
    """
    Linux POSIX atomic swap:
      1. shutil.copy2 current → .bak
      2. os.replace(new_binary, current_exe)  ← POSIX atomic renameat(2)
      3. chmod 755
      4. restorecon (SELinux context, best-effort)
      5. systemctl restart zerowatch-agent.service (or --user fallback)
      6. Start in-process 120s watchdog thread
    """
    bak_path = current_exe + ".bak"

    # 1. Backup
    try:
        shutil.copy2(current_exe, bak_path)
        logger.info("[LINUX SWAP] Backup: %s → %s", current_exe, bak_path)
    except OSError as exc:
        raise SwapError(f"Failed to create .bak: {exc}") from exc

    # 2. Atomic POSIX replace
    try:
        os.replace(new_binary, current_exe)
        logger.info("[LINUX SWAP] Atomic replace complete: %s", current_exe)
    except OSError as exc:
        logger.error("[LINUX SWAP] Atomic replace failed — restoring .bak: %s", exc)
        try:
            shutil.copy2(bak_path, current_exe)
        except OSError as rb_exc:
            logger.critical("[LINUX SWAP] Rollback failed: %s", rb_exc)
        raise SwapError(f"os.replace failed: {exc}") from exc

    # 3. Set executable permissions
    try:
        os.chmod(current_exe, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                               stat.S_IROTH | stat.S_IXOTH)  # 755
    except OSError as exc:
        logger.warning("[LINUX SWAP] chmod 755 failed: %s", exc)

    # 4. Restore SELinux context (best-effort)
    _restorecon_linux(current_exe)

    # 5. Restart service via systemd
    service_restarted = _systemctl_restart()

    # 6. Launch 120s watchdog thread
    _start_inprocess_watchdog(
        bak_path      = bak_path,
        current_exe   = current_exe,
        zw_client     = zw_client,
        restart_fn    = _systemctl_restart,
    )

    return True


def _restorecon_linux(exe_path: str) -> None:
    """Restore SELinux security context on the replaced binary (best-effort)."""
    if shutil.which("restorecon") is None:
        return
    try:
        subprocess.run(
            ["restorecon", "-v", exe_path],
            capture_output=True, text=True, timeout=10,
        )
        logger.debug("[LINUX SWAP] restorecon applied to %s", exe_path)
    except Exception as exc:
        logger.debug("[LINUX SWAP] restorecon skipped: %s", exc)


def _systemctl_restart() -> bool:
    """
    Restart the ZeroWatch agent service via systemctl.

    Tries system scope first (root context); falls back to user scope.
    Returns True if restart command was accepted.
    """
    if shutil.which("systemctl") is None:
        logger.warning("[LINUX SWAP] systemctl not found — no service restart performed.")
        return False

    for scope_flag in (["--system"], ["--user"]):
        try:
            result = subprocess.run(
                ["systemctl"] + scope_flag + ["restart", _LINUX_SERVICE_NAME],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                logger.info(
                    "[LINUX SWAP] systemctl %s restart %s succeeded.",
                    " ".join(scope_flag), _LINUX_SERVICE_NAME,
                )
                return True
            logger.debug(
                "[LINUX SWAP] systemctl %s restart failed (rc=%d): %s",
                " ".join(scope_flag), result.returncode, result.stderr.strip()
            )
        except Exception as exc:
            logger.debug("[LINUX SWAP] systemctl invocation error: %s", exc)

    logger.warning("[LINUX SWAP] All systemctl restart attempts failed.")
    return False


# ---------------------------------------------------------------------------
# macOS atomic swap (Section 4.3)
# ---------------------------------------------------------------------------

def _swap_macos(new_binary: str, current_exe: str, zw_client=None) -> bool:
    """
    macOS notarization-compliant swap:
      1. xattr -d com.apple.quarantine (strip Gatekeeper quarantine)
      2. codesign --verify --deep --strict (validate Apple code signature)
      3. shutil.copy2 → .bak
      4. os.replace() atomic swap
      5. launchctl kickstart -k system/io.deepcytes.zerowatch.agent
      6. Start in-process 120s watchdog thread
    """
    bak_path = current_exe + ".bak"

    # 1. Strip Gatekeeper quarantine
    _strip_quarantine_macos(new_binary)

    # 2. Validate code signature (advisory — not all builds are notarized)
    _codesign_verify_macos(new_binary)

    # 3. Backup
    try:
        shutil.copy2(current_exe, bak_path)
        logger.info("[MACOS SWAP] Backup: %s → %s", current_exe, bak_path)
    except OSError as exc:
        raise SwapError(f"Backup failed: {exc}") from exc

    # 4. Atomic POSIX replace
    try:
        os.replace(new_binary, current_exe)
        logger.info("[MACOS SWAP] Atomic replace complete: %s", current_exe)
    except OSError as exc:
        logger.error("[MACOS SWAP] Atomic replace failed — restoring .bak: %s", exc)
        try:
            shutil.copy2(bak_path, current_exe)
        except OSError as rb_exc:
            logger.critical("[MACOS SWAP] Rollback failed: %s", rb_exc)
        raise SwapError(f"os.replace failed: {exc}") from exc

    # 5. Kick launchd
    _launchctl_kickstart()

    # 6. Launch 120s watchdog thread
    _start_inprocess_watchdog(
        bak_path    = bak_path,
        current_exe = current_exe,
        zw_client   = zw_client,
        restart_fn  = _launchctl_kickstart,
    )

    return True


def _strip_quarantine_macos(binary_path: str) -> None:
    """Remove Gatekeeper quarantine extended attribute (best-effort)."""
    try:
        subprocess.run(
            ["xattr", "-d", "com.apple.quarantine", binary_path],
            capture_output=True, text=True, timeout=10,
        )
        logger.debug("[MACOS SWAP] Quarantine attribute stripped from %s", binary_path)
    except Exception as exc:
        logger.debug("[MACOS SWAP] xattr -d quarantine skipped: %s", exc)


def _codesign_verify_macos(binary_path: str) -> None:
    """
    Validate Apple code signature.
    Non-fatal: SentinelAgent binaries built with PyInstaller/Nuitka may not
    carry an Apple Developer-signed Designated Requirement in dev/test builds.
    Logs a warning but does not abort — Ed25519 + SHA-256 are authoritative.
    """
    if shutil.which("codesign") is None:
        return
    try:
        result = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", binary_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            logger.debug("[MACOS SWAP] codesign --verify passed.")
        else:
            logger.warning(
                "[MACOS SWAP] codesign --verify returned non-zero (rc=%d). "
                "Binary may lack Apple notarization. Ed25519 trust still valid. "
                "Detail: %s",
                result.returncode, result.stderr.strip()
            )
    except Exception as exc:
        logger.warning("[MACOS SWAP] codesign check skipped: %s", exc)


def _launchctl_kickstart() -> bool:
    """
    Restart the ZeroWatch LaunchDaemon via:
      launchctl kickstart -k system/io.deepcytes.zerowatch.agent
    (-k = kill existing instance before starting fresh)
    """
    if shutil.which("launchctl") is None:
        logger.warning("[MACOS SWAP] launchctl not found.")
        return False
    try:
        result = subprocess.run(
            ["launchctl", "kickstart", "-k",
             f"system/{_MACOS_LAUNCHD_LABEL}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            logger.info("[MACOS SWAP] launchctl kickstart succeeded.")
            return True
        logger.warning(
            "[MACOS SWAP] launchctl kickstart returned rc=%d: %s",
            result.returncode, result.stderr.strip()
        )
        return False
    except Exception as exc:
        logger.warning("[MACOS SWAP] launchctl error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# 120-second Out-of-Band Watchdog (self-healing mechanism)
# ---------------------------------------------------------------------------

def _start_inprocess_watchdog(
    bak_path:    str,
    current_exe: str,
    zw_client,
    restart_fn:  Callable[[], bool],
) -> None:
    """
    Launch the 120-second self-healing watchdog in a daemon thread.

    The watchdog polls for heartbeat success every _WATCHDOG_POLL_SECS.
    If the updated agent proves liveness (heartbeat returns a non-error result)
    within WATCHDOG_TIMEOUT_SECS, the .bak backup is removed.
    Otherwise the backup is restored and the native service is restarted.
    """
    t = threading.Thread(
        target = _watchdog_thread,
        kwargs = dict(
            bak_path    = bak_path,
            current_exe = current_exe,
            zw_client   = zw_client,
            restart_fn  = restart_fn,
        ),
        name   = "ota-watchdog",
        daemon = True,  # Daemon thread: does not block interpreter shutdown
    )
    t.start()
    logger.info(
        "[WATCHDOG] 120-second out-of-band health monitor started (poll every %ds).",
        _WATCHDOG_POLL_SECS,
    )


def _watchdog_thread(
    bak_path:    str,
    current_exe: str,
    zw_client,
    restart_fn:  Callable[[], bool],
) -> None:
    """
    Watchdog body (runs on daemon thread):

    Polls for heartbeat success for up to WATCHDOG_TIMEOUT_SECS (120s).
    On success: commit the update (remove .bak).
    On timeout/failure: revert .bak → current_exe, restart service.
    """
    deadline = time.monotonic() + WATCHDOG_TIMEOUT_SECS
    liveness_confirmed = False

    while time.monotonic() < deadline:
        time.sleep(_WATCHDOG_POLL_SECS)

        if _check_heartbeat(zw_client):
            liveness_confirmed = True
            break

    if liveness_confirmed:
        logger.info(
            "[WATCHDOG] Updated agent proved liveness within %ds. "
            "Committing update — removing .bak.",
            WATCHDOG_TIMEOUT_SECS,
        )
        _commit_update(bak_path)
    else:
        logger.error(
            "[WATCHDOG] Updated agent did NOT prove liveness within %ds. "
            "Initiating automatic rollback.",
            WATCHDOG_TIMEOUT_SECS,
        )
        _rollback(bak_path, current_exe, restart_fn)


def _check_heartbeat(zw_client) -> bool:
    """
    Check whether the agent can successfully heartbeat to the backend.

    Accepts any non-error return from zw_client.heartbeat() as proof of liveness.
    Returns True if heartbeat succeeded, False if it failed or client is unavailable.
    """
    if zw_client is None:
        # No client reference — attempt a simple connectivity probe
        # to localhost instead (the new agent may have restarted the loop)
        return _ping_local_agent()

    try:
        result = zw_client.heartbeat()
        # ZeroWatchClient.heartbeat() returns the server status string or raises
        if result is not None and result != "error":
            logger.debug("[WATCHDOG] Heartbeat OK (status=%s).", result)
            return True
    except Exception as exc:
        logger.debug("[WATCHDOG] Heartbeat check raised: %s", exc)
    return False


def _ping_local_agent() -> bool:
    """
    Fallback liveness check when no ZeroWatchClient is available.
    Attempts to connect to the agent's named mutex (Windows) or lock file (POSIX).
    """
    if sys.platform == "win32":
        try:
            import ctypes
            MUTEX_NAME = "Global\\SentinelAgent_ZeroWatch_4F9A2E1B"
            h = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
            err = ctypes.windll.kernel32.GetLastError()
            if h:
                ctypes.windll.kernel32.CloseHandle(h)
            return err == 183  # ERROR_ALREADY_EXISTS → mutex held by running agent
        except Exception:
            return False
    else:
        # POSIX: check daemon.lock for a live PID
        from common.updater import _PLATFORM_KEY  # just to avoid circular import
        lock_candidates = [
            "/var/lib/zerowatch/state/daemon.lock",
            os.path.expanduser("~/.local/share/zerowatch/state/daemon.lock"),
        ]
        for lock_path in lock_candidates:
            if os.path.exists(lock_path):
                try:
                    with open(lock_path, "r") as fh:
                        pid = int(fh.read().strip())
                    os.kill(pid, 0)  # signal 0: probe, raises OSError if dead
                    return True
                except (OSError, ValueError):
                    continue
        return False


def _commit_update(bak_path: str) -> None:
    """Remove the .bak file to commit the successful update."""
    try:
        if os.path.exists(bak_path):
            os.remove(bak_path)
            logger.info("[WATCHDOG] .bak removed: %s — update committed.", bak_path)
    except OSError as exc:
        logger.warning("[WATCHDOG] Failed to remove .bak: %s", exc)


def _rollback(
    bak_path:    str,
    current_exe: str,
    restart_fn:  Callable[[], bool],
) -> None:
    """
    Restore the .bak binary and restart the service with the previous version.
    """
    if not os.path.exists(bak_path):
        logger.critical(
            "[WATCHDOG] ROLLBACK FAILED — .bak file not found: %s. "
            "Manual recovery required.",
            bak_path,
        )
        return

    try:
        shutil.copy2(bak_path, current_exe)
        logger.info("[WATCHDOG] Rollback: restored %s from .bak.", current_exe)

        # Restore executable permissions on POSIX
        if sys.platform != "win32":
            os.chmod(current_exe, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                                   stat.S_IROTH | stat.S_IXOTH)

        # Restart via native service manager
        ok = restart_fn()
        if ok:
            logger.info("[WATCHDOG] Service restarted with previous version.")
        else:
            logger.error(
                "[WATCHDOG] Service restart failed after rollback. "
                "The agent may require manual restart."
            )

    except OSError as exc:
        logger.critical("[WATCHDOG] Rollback OSError: %s — manual recovery required.", exc)


# ---------------------------------------------------------------------------
# PostUpdateWatchdog — called from main() via --post-update-check flag
# ---------------------------------------------------------------------------

class PostUpdateWatchdog:
    """
    Invoked when the newly updated binary is started with --post-update-check.

    This is the out-of-band watchdog that was spawned by the OLD binary's
    _swap_windows() call. It runs independently from the new binary's process,
    verifying that the new binary is healthy before committing.

    Workflow:
      1. Determine paths (bak, exe)
      2. Wait for the new agent daemon to initialize (15s grace period)
      3. Poll heartbeat / mutex for up to WATCHDOG_TIMEOUT_SECS (120s)
      4. On success: remove .bak
      5. On failure: restore .bak and restart via sc.exe / systemctl / launchctl
    """

    def run(self) -> None:
        """Entry point — called from main() when --post-update-check is in sys.argv."""
        current_exe = self._resolve_current_exe()
        bak_path    = current_exe + ".bak"

        if not os.path.exists(bak_path):
            logger.info(
                "[POST-UPDATE WATCHDOG] No .bak file found at %s — "
                "assuming update was already committed or not applicable.",
                bak_path,
            )
            return

        logger.info(
            "[POST-UPDATE WATCHDOG] Monitoring new agent for %ds liveness...",
            WATCHDOG_TIMEOUT_SECS,
        )

        # Grace period: let the new agent initialize
        time.sleep(15)

        restart_fn = self._get_platform_restart_fn()
        _watchdog_thread(
            bak_path    = bak_path,
            current_exe = current_exe,
            zw_client   = None,    # No client reference in post-update-check mode
            restart_fn  = restart_fn,
        )

    @staticmethod
    def _resolve_current_exe() -> str:
        """Resolve the path of the current executable."""
        if "SENTINEL_EXE_PATH" in os.environ:
            return os.environ["SENTINEL_EXE_PATH"]
        if getattr(sys, "frozen", False) or "__compiled__" in dir(sys.modules.get("__main__", None)):
            return os.path.abspath(sys.executable)
        return os.path.abspath(sys.argv[0])

    @staticmethod
    def _get_platform_restart_fn() -> Callable[[], bool]:
        """Return the appropriate service restart function for the current platform."""
        if sys.platform == "win32":
            def _win_restart() -> bool:
                try:
                    subprocess.run(
                        ["sc", "stop", _WIN_SERVICE_NAME],
                        capture_output=True, text=True, timeout=15,
                    )
                    time.sleep(3)
                    result = subprocess.run(
                        ["sc", "start", _WIN_SERVICE_NAME],
                        capture_output=True, text=True, timeout=15,
                    )
                    return result.returncode == 0
                except Exception as exc:
                    logger.warning("[POST-UPDATE WATCHDOG] sc.exe restart failed: %s", exc)
                    return False
            return _win_restart
        elif sys.platform == "darwin":
            return _launchctl_kickstart
        else:
            return _systemctl_restart
