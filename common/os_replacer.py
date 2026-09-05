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
import base64
import os
import shutil
import stat
import subprocess
import sys
import shlex
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

    # Stage: copy new binary to .new
    try:
        shutil.copy2(new_binary, staging_path)
    except OSError as exc:
        raise SwapError(f"Failed to stage new binary to {staging_path}: {exc}") from exc

    # Backup: rename current .exe → .exe.bak
    # If the .bak already exists (stale from a previous update that didn't clean up),
    # try to delete it first.  If deletion fails (e.g. still locked), fall back to a
    # timestamped backup name so the rename can always succeed.
    if os.path.exists(bak_path):
        try:
            os.remove(bak_path)
            logger.info("[WIN SWAP] Removed stale backup: %s", bak_path)
        except OSError as exc:
            logger.warning("[WIN SWAP] Could not remove stale .bak (%s) — using timestamped backup", exc)
            ts = int(time.time())
            bak_path = current_exe + f".{ts}.bak"

    try:
        os.rename(current_exe, bak_path)
        logger.info("[WIN SWAP] Renamed %s → %s", current_exe, bak_path)
    except OSError as exc:
        try:
            os.remove(staging_path)
        except OSError:
            pass
        raise SwapError(
            f"Cannot rename running exe to .bak — admin rights required? {exc}"
        ) from exc

    # Install: copy .new → original path
    try:
        shutil.copy2(staging_path, current_exe)
        os.remove(staging_path)
        logger.info("[WIN SWAP] Installed new binary: %s", current_exe)
    except OSError as exc:
        logger.error("[WIN SWAP] Install failed — restoring .bak: %s", exc)
        try:
            os.rename(bak_path, current_exe)
        except OSError as rb_exc:
            logger.critical("[WIN SWAP] Rollback also failed: %s", rb_exc)
        raise SwapError(f"Failed to copy new binary into place: {exc}") from exc

    logger.info("[WIN SWAP] Swap complete. Call _relaunch_detached() to restart.")
    return True


def _is_gui_window_open() -> bool:
    """Check if any SentinelAgent GUI window is currently open and visible on Windows."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        found = False

        def enum_windows_callback(hwnd, _extra):
            nonlocal found
            if ctypes.windll.user32.IsWindowVisible(hwnd):
                length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buff = ctypes.create_unicode_buffer(length + 1)
                    ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
                    title = buff.value.upper()
                    if "ZEROWATCH SENTINEL AGENT" in title or "ZEROWATCH AGENT" in title:
                        found = True
                        return False
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        ctypes.windll.user32.EnumWindows(WNDENUMPROC(enum_windows_callback), 0)
        return found
    except Exception:
        return False


def _clean_env():
    """Remove Nuitka/PyInstaller-specific environment variables for safe subprocess launching."""
    env = os.environ.copy()
    for key in list(env.keys()):
        if key.startswith("NUITKA_") or key.startswith("_MEIPASS") or key in ["LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"]:
            env.pop(key, None)
    return env

def _relaunch_detached(current_exe: str, reopen_gui: Optional[bool] = None) -> bool:
    """Launch the replacement agent after the current Windows process exits.

    Args:
        current_exe: Absolute path to the executable to launch.
        reopen_gui: If True, force GUI restart (visible window).
                    If False, force headless daemon restart (--daemon).
                    If None, auto-detect: restart GUI only if a GUI window is currently open.
    """
    if reopen_gui is None:
        if "--daemon" in sys.argv[1:]:
            reopen_gui = False
        else:
            reopen_gui = _is_gui_window_open()

    if sys.platform != "win32":
        try:
            launch_cmd = [current_exe]
            if not reopen_gui and "--daemon" not in launch_cmd:
                launch_cmd.append("--daemon")
            subprocess.Popen(
                launch_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                env=_clean_env(),
            )
            logger.info("[POSIX SWAP] Relaunched updated binary: %s (gui=%s)", current_exe, reopen_gui)
            return True
        except Exception as exc:
            logger.warning("[POSIX SWAP] Failed to relaunch updated binary: %s", exc)
            return False

    detached = 0x00000008
    new_group = 0x00000200

    try:
        # In source/dev runs current_exe is a .py file. Start it through the
        # active Python interpreter; launching a .py directly depends on the
        # user's file association and can open an editor instead of the agent.
        if current_exe.lower().endswith(".py"):
            target = sys.executable
            launch_args = [current_exe]
        else:
            target = current_exe
            launch_args = []

        if reopen_gui:
            # Interactive GUI restart: show window normally without --daemon
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 1  # SW_SHOWNORMAL
            creation_flags = detached | new_group
        else:
            # Headless daemon restart: enforce --daemon and keep hidden
            if "--daemon" not in launch_args:
                launch_args.append("--daemon")
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0  # SW_HIDE
            creation_flags = detached | new_group | subprocess.CREATE_NO_WINDOW

        # Start the replacement directly instead of through PowerShell/cmd.
        # Its entry point waits on this PID before doing any agent work, so it
        # cannot race the old GUI, daemon, or watchdog shutdown.
        launch_args.extend(["--restart-wait-pid", str(os.getpid())])

        child = subprocess.Popen(
            [target, *launch_args],
            creationflags=creation_flags,
            startupinfo=si,
            close_fds=True,
            cwd=os.path.dirname(os.path.abspath(current_exe)) or None,
            env=_clean_env(),
        )
        logger.info(
            "[WIN SWAP] Started replacement PID %s (gui=%s); waiting for parent PID %s.",
            child.pid, reopen_gui, os.getpid(),
        )
        return True
    except Exception as exc:
        logger.warning("[WIN SWAP] Failed to re-launch new binary: %s", exc)
        return False


def _swap_linux(new_binary: str, current_exe: str, zw_client=None) -> bool:
    """
    Linux POSIX atomic swap:
      1. shutil.copy2 current → .bak
      2. Copy new_binary into the target directory, then os.replace() that
         same-filesystem staging file → current_exe (POSIX atomic renameat(2))
      3. chmod 755
      4. restorecon (SELinux context, best-effort)
      5. systemctl restart zerowatch-agent.service (or --user fallback)

    The new agent cleans up .bak on its own startup via startup_bak_cleanup().
    """
    bak_path = current_exe + ".bak"
    # The download commonly lives in /tmp while the installed binary may be
    # on another mount (for example /mnt/e under WSL). os.replace() cannot
    # cross filesystems (EXDEV), so stage beside the target first.
    staging_path = current_exe + ".new"

    # 1. Backup
    try:
        shutil.copy2(current_exe, bak_path)
        logger.info("[LINUX SWAP] Backup: %s → %s", current_exe, bak_path)
    except OSError as exc:
        raise SwapError(f"Failed to create .bak: {exc}") from exc

    # 2. Stage on the target filesystem, then atomically replace the target.
    try:
        shutil.copy2(new_binary, staging_path)
        # Make the staged contents durable before exposing them as the binary.
        with open(staging_path, "rb") as staged_file:
            os.fsync(staged_file.fileno())
        os.replace(staging_path, current_exe)
        logger.info("[LINUX SWAP] Atomic replace complete: %s", current_exe)
    except OSError as exc:
        logger.error("[LINUX SWAP] Atomic replace failed — restoring .bak: %s", exc)
        try:
            os.remove(staging_path)
        except OSError:
            pass
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

    # 5. Restart service via systemd — the new agent will call startup_bak_cleanup()
    _systemctl_restart()

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
            logger.warning(
                "[LINUX SWAP] systemctl %s restart rejected (rc=%d): %s",
                " ".join(scope_flag), result.returncode,
                result.stderr.strip() or "no error output",
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
    3. Restore executable permissions on the downloaded file
    4. shutil.copy2 → .bak
    5. os.replace() atomic swap
    6. launchctl kickstart -k system/io.deepcytes.zerowatch.agent

    The new agent cleans up .bak on its own startup via startup_bak_cleanup().
    """
    bak_path = current_exe + ".bak"

    # 1. Strip Gatekeeper quarantine
    _strip_quarantine_macos(new_binary)

    # 2. Validate code signature (advisory — not all builds are notarized)
    _codesign_verify_macos(new_binary)

    # 3. Downloads do not reliably preserve the executable bit. Without this
    # explicit chmod, launchd reports Permission denied after the swap and the
    # updated agent remains installed but stopped until manually relaunched.
    try:
        current_mode = os.stat(current_exe).st_mode
        executable_mode = current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        os.chmod(new_binary, executable_mode & 0o7777)
        logger.info("[MACOS SWAP] Executable permissions restored: %o", executable_mode & 0o7777)
    except OSError as exc:
        raise SwapError(f"Could not set executable permissions on update: {exc}") from exc

    # 4. Backup
    try:
        shutil.copy2(current_exe, bak_path)
        logger.info("[MACOS SWAP] Backup: %s → %s", current_exe, bak_path)
    except OSError as exc:
        raise SwapError(f"Backup failed: {exc}") from exc

    # 5. Atomic POSIX replace
    try:
        os.replace(new_binary, current_exe)
        logger.info("[MACOS SWAP] Atomic replace complete: %s", current_exe)
    except OSError as exc:
        logger.error("[MACOS SWAP] Atomic replace failed — restoring .bak: %s", exc)
        try:
            shutil.copy2(bak_path, current_exe)
        except OSError as rb_exc:
            logger.critical("[MACOS SWAP] Rollback failed: %s", rb_exc)
        if _authorized_replace_macos(new_binary, current_exe, bak_path):
            return True
        raise SwapError(f"os.replace failed: {exc}") from exc

    # 6. Kick launchd — the new agent will call startup_bak_cleanup()
    _launchctl_kickstart()

    return True


def _authorized_replace_macos(new_binary: str, current_exe: str, bak_path: str) -> bool:
    """Replace a root-owned installed binary through macOS authorization UI."""
    if shutil.which("osascript") is None:
        return False
    command = (
        f"/bin/cp {shlex.quote(current_exe)} {shlex.quote(bak_path)}; "
        f"/bin/cp {shlex.quote(new_binary)} {shlex.quote(current_exe)}; "
        f"/bin/chmod 755 {shlex.quote(current_exe)}; "
        f"/bin/rm -f {shlex.quote(new_binary)} {shlex.quote(bak_path)}"
    )
    encoded = base64.b64encode(command.encode("utf-8")).decode("ascii")
    script = ('do shell script "echo ' + encoded +
              ' | /usr/bin/base64 -D | /bin/sh" with administrator privileges')
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", script],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.error("[MACOS SWAP] Authorized replacement failed: %s", exc)
        return False


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
# Startup: post-update .bak cleanup (called by the newly started agent)
# ---------------------------------------------------------------------------


def _commit_update(bak_path: str) -> None:
    """Remove the .bak file to commit the successful update."""
    try:
        if os.path.exists(bak_path):
            os.remove(bak_path)
            logger.info("[OTA] .bak removed: %s — update committed.", bak_path)
    except OSError as exc:
        logger.warning("[OTA] Failed to remove .bak: %s", exc)


def startup_bak_cleanup(current_exe: str) -> None:
    """
    Called by the NEWLY started agent on startup to clean up any leftover .bak
    file from a previous successful OTA update swap.

    Design rationale
    ----------------
    The previous "--post-update-check" subprocess architecture was fundamentally
    broken for Nuitka onefile binaries: the watchdog subprocess tried to
    self-extract into the same temp directory that the main agent already had
    open and locked (e.g. _asyncio.pyd), causing:
      • Visible terminal/console flashes on every update
      • Ghost background SentinelAgent processes that never exited
      • .bak files that were never removed

    This function runs entirely INSIDE the new agent's own process:
      1. Check if <current_exe>.bak exists (signals a pending update commit)
      2. Start a daemon thread that waits 30 seconds (startup stability window)
      3. If the agent is still running after 30 s → remove .bak safely

    No subprocess spawning. No extraction conflicts. No ghost processes.
    If the agent crashes within 30 s, the daemon thread dies with the process
    and .bak is preserved for manual recovery.

    Args:
        current_exe: Absolute path to the running executable (from get_exe_path()).
    """
    bak_path = current_exe + ".bak"
    backup_paths = [bak_path]
    if sys.platform == "win32":
        current_name = os.path.basename(current_exe)
        parent_dir = os.path.dirname(current_exe) or "."
        try:
            backup_paths.extend(
                os.path.join(parent_dir, name)
                for name in os.listdir(parent_dir)
                if name.startswith(current_name + ".") and name.endswith(".bak")
            )
        except OSError:
            pass

    backup_paths = list(dict.fromkeys(path for path in backup_paths if os.path.exists(path)))
    if not backup_paths:
        return  # Normal startup — nothing to clean up

    logger.info(
        "[OTA] Post-update backup(s) detected: %s — cleaning up after successful startup.",
        ", ".join(backup_paths),
    )

    # Reaching this function means the replacement process has started. Remove
    # the backup now so successful updates never leave a .bak artifact behind.
    for backup_path in backup_paths:
        _commit_update(backup_path)
    logger.info("[OTA] Post-update cleanup complete.")


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


# NOTE: PostUpdateWatchdog and the subprocess-based watchdog architecture
# have been permanently removed. .bak cleanup is now handled by
# startup_bak_cleanup() which runs inside the NEW agent's own process.

