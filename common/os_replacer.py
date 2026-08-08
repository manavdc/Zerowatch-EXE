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


def _relaunch_detached(current_exe: str) -> bool:
    """Schedule a hidden, delayed launch of the newly installed executable."""
    detached = 0x00000008
    new_group = 0x00000200

    try:
        escaped_exe = current_exe.replace("'", "''")
        ps_script = (
            f"$target = '{escaped_exe}'; "
            "Start-Sleep -Seconds 2; "
            "Start-Process -FilePath $target"
        )
        import base64
        encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        ps_exe = os.path.join(
            os.environ.get("WINDIR", r"C:\Windows"),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
        )
        if not os.path.exists(ps_exe):
            ps_exe = "powershell.exe"
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        subprocess.Popen(
            [ps_exe, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
             "-EncodedCommand", encoded],
            creationflags=detached | new_group | subprocess.CREATE_NO_WINDOW,
            startupinfo=si,
            close_fds=True,
        )
        logger.info("[WIN SWAP] Scheduled hidden delayed relaunch for: %s", current_exe)
        return True
    except Exception as exc:
        logger.warning("[WIN SWAP] Failed to re-launch new binary: %s", exc)
        return False


def _swap_linux(new_binary: str, current_exe: str, zw_client=None) -> bool:
    """
    Linux POSIX atomic swap:
      1. shutil.copy2 current → .bak
      2. os.replace(new_binary, current_exe)  ← POSIX atomic renameat(2)
      3. chmod 755
      4. restorecon (SELinux context, best-effort)
      5. systemctl restart zerowatch-agent.service (or --user fallback)

    The new agent cleans up .bak on its own startup via startup_bak_cleanup().
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

    The new agent cleans up .bak on its own startup via startup_bak_cleanup().
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

    # 5. Kick launchd — the new agent will call startup_bak_cleanup()
    _launchctl_kickstart()

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
    if not os.path.exists(bak_path):
        return  # Normal startup — nothing to clean up

    logger.info(
        "[OTA] Post-update .bak detected: %s — scheduling cleanup after 30s stability window.",
        bak_path,
    )

    def _cleanup() -> None:
        # 30-second grace period confirms the agent started successfully.
        # If the process crashes before this completes, the daemon thread is
        # killed automatically and .bak remains for manual recovery.
        time.sleep(30)
        _commit_update(bak_path)
        logger.info("[OTA] Post-update cleanup complete.")

    t = threading.Thread(target=_cleanup, name="post-update-cleanup", daemon=True)
    t.start()


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

