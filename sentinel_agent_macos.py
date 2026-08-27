"""
sentinel_agent_macos.py
─────────────────────────────────────────────────────────────────────────────
ZeroWatch Endpoint Agent — macOS Entry Point

This is the macOS equivalent of sentinel_agent_linux.py.

Differences from Windows agent:
  - No winreg, no ctypes.windll, no Win32 API calls
  - Uses PlatformFactory to obtain MacOS implementations (MacOSPlatform)
  - Shutdown via POSIX SIGTERM/SIGINT → threading.Event (POSIX signal handler)
  - State stored under /var/lib/zerowatch/state → ~/.local/share/zerowatch/state
    → ./state/ (in order of write-access preference)
  - Persistence via launchd LaunchDaemon (MacOSPersistenceManager)
  - Secure storage via macOS Keychain (MacOSSecureStore tagged-reference design)
  - Hardware fingerprint via IOKit IOPlatformUUID (ioreg)
  - Software inventory: app bundles (.app Info.plist), pkgutil receipts,
    Homebrew formulae & casks, MacPorts ports, macOS OS version item

Shared with Windows and Linux agents:
  - ScanOrchestrator (dependency-injected — same code path)
  - cert_pinning.py (certificate pinning — identical SPKI pins)
  - Backend API contract (identical JSON payloads for sync_full / sync_delta)

SIP/TCC Notes:
  - When Full Disk Access (FDA) is not granted, PermissionError hits /Library
    and user subdirectories. The filesystem walker silently skips those paths.
  - L0 (app bundles + pkgutil + OS version) still works without FDA.
  - A startup log message at WARNING level notifies the operator when FDA
    is missing, by detecting PermissionError on the first walk attempt.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import os
import platform
import signal
import socket
import sys
import threading
import time
import uuid

import requests
import socketio
from urllib.parse import urlparse

# ── Certificate pinning (shared with Windows and Linux agents) ────────────────
import cert_pinning
from cert_pinning import (
    PinError,
    SPKIPinningAdapter,
    build_pinning_adapter,
    is_loopback,
    is_pin_failure,
    PinnedSession,
    is_valid_sha256_base64,
)

# ── Platform factory (provides macOS implementations) ────────────────────────
from platforms import PlatformFactory

# ── Scan orchestrator (platform-agnostic) ─────────────────────────────────────
from scanner import ScanOrchestrator
from common.daemon_ota import start_daemon_ota_monitor
from common.state_cleanup import clear_device_state

# ─────────────────────────────────────────────────────────────────────────────
# AGENT CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

AGENT_VERSION      = "1.0.0-macos"
HEARTBEAT_INTERVAL = 30    # seconds between heartbeats
MONITOR_INTERVAL   = 120   # seconds between delta scan checks
RECONNECT_DELAY    = 10    # seconds before reconnect attempt

# Build-time server URL injection (written by run_agent.sh)
_BUILD_CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_build_config.py")
if os.path.exists(_BUILD_CFG_PATH):
    _cfg_ns: dict = {}
    with open(_BUILD_CFG_PATH, "r", encoding="utf-8") as _f:
        exec(compile(_f.read(), _BUILD_CFG_PATH, "exec"), _cfg_ns)
    BASE_API_URL: str = _cfg_ns.get("FORCED_BASE_API_URL", "")
    AGENT_VERSION: str = _cfg_ns.get("FORCED_AGENT_VERSION", AGENT_VERSION)
else:
    BASE_API_URL = os.environ.get("ZEROWATCH_API_URL", "https://zerowatch.deepcytes.io/api")

# ── SPKI pins (identical to Windows and Linux agents) ─────────────────────────
SPKI_PINS = {
    "zerowatch.deepcytes.io": [
        "MZ4Kk+NPs6uc35JlOBNODqa+AZvqgtCq+sSjXx9W/k4=",
        "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4="
    ],
    "zerowatch-testing.eastasia.cloudapp.azure.com": [
        "SOt+phzxLXUaMmNKG6d4kz7QTSoip7zJudN8vGJNdI4=",
        "EzSBE12fT2ZrphmumaBjrpdpXv9G71RhZQHMvuwszI4="
    ],
}

# ── Logging ───────────────────────────────────────────────────────────────────

def _configure_logging() -> None:
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("socketio").setLevel(logging.WARNING)
    logging.getLogger("engineio").setLevel(logging.WARNING)

logger = logging.getLogger("macos.agent")


def _daemonize_if_needed() -> None:
    """Detach the macOS agent from the terminal when launched in daemon mode."""
    if "--daemon" not in sys.argv:
        return
    try:
        if os.getppid() == 1:
            return
        pid = os.fork()
        if pid > 0:
            raise SystemExit(0)
        os.setsid()
        with open(os.devnull, "rb", buffering=0) as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
        log_dir = os.path.join(_get_state_dir(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "agent-daemon.log")
        with open(log_path, "ab", buffering=0) as log_handle:
            os.dup2(log_handle.fileno(), sys.stdout.fileno())
            os.dup2(log_handle.fileno(), sys.stderr.fileno())
    except Exception:
        logger.warning("Daemonization was requested but could not be completed; continuing in foreground.", exc_info=True)


# ── State directory ───────────────────────────────────────────────────────────

# Identity files that must be portable between state directories on Linux/macOS
# so that the device is not re-enrolled when the launch UID changes.
_SHARED_IDENTITY_FILES = (
    "zerowatch_token.dat",       # Legacy JWT
    "zw_team_join_state.dat",    # Legacy join state
    "agent_token.enc",           # Linux/macOS JWT
    "join_state.json",           # Linux/macOS join state
    "consent_accepted.dat",
    "device_fingerprint.json",
    "asset_info.json",
    "dashboard_cache.dat",
)

_SHARED_STATE_FILE_MODE = 0o666

def _get_state_dir() -> str:
    """
    Return the canonical shared state directory for ZeroWatch on macOS.

    Primary path: /Library/Application Support/ZeroWatch/state
    This is the SAME path regardless of whether the agent runs as root (sudo)
    or as a normal user. Using a single shared directory ensures:
      - Only one enrollment ever exists per machine
      - JWT, fingerprint, and join-state are shared between invocations
      - No duplicate device registrations when the user switches between
        `sudo ./agent` and `./agent`

    Permissions:
      On first creation (as root), the directory is set to 0o1777 (sticky,
      world-writable) so non-root users can also read/write their own files.
      This is the same model used by /tmp on macOS.

    Fallback chain (only if /Library/Application Support is not accessible):
      /var/lib/zerowatch/state  → ~/.local/share/zerowatch/state  → ./state/
    """
    # ── Primary: /Library/Application Support/ZeroWatch/state ───────────
    canonical = "/Library/Application Support/ZeroWatch/state"
    try:
        os.makedirs(canonical, mode=0o777, exist_ok=True)
        # Set sticky + world-writable so both root and user can access it.
        # Only try chmod if we own the dir (root context) to avoid
        # unnecessary PermissionErrors.
        try:
            current_mode = os.stat(canonical).st_mode & 0o7777
            if current_mode != 0o1777:
                os.chmod(canonical, 0o777)
        except OSError:
            pass
        # A previous sudo launch may have left identity files owned by root
        # with restrictive modes. Repair them while privileged so later
        # normal-user launches can continue using the same enrollment.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            for name in _SHARED_IDENTITY_FILES:
                path = os.path.join(canonical, name)
                if os.path.isfile(path):
                    try:
                        os.chmod(path, _SHARED_STATE_FILE_MODE)
                    except OSError:
                        pass
        # Verify it's writable
        _probe = os.path.join(canonical, ".write_probe")
        with open(_probe, "w") as _fh:
            _fh.write("x")
        os.remove(_probe)
        return canonical
    except OSError:
        pass  # Fall through to legacy paths

    # ── Legacy fallback chain (maintains backward compat) ───────────────
    base = "/tmp/zerowatch"
    system_dir = "/var/lib/zerowatch/state"
    user_dir   = "/tmp/zerowatch/state"
    local_dir  = os.path.join(base, "state")

    # Try system dir first (consistent across UIDs)
    try:
        os.makedirs(system_dir, mode=0o777, exist_ok=True)
        os.chmod(system_dir, 0o777)
        _probe = os.path.join(system_dir, ".write_probe")
        with open(_probe, "w") as _fh:
            _fh.write("x")
        os.remove(_probe)
        return system_dir
    except OSError:
        pass

    # User-writable fallback
    for fallback in (user_dir, local_dir):
        try:
            os.makedirs(fallback, mode=0o777, exist_ok=True)
            os.chmod(fallback, 0o777)
            _probe = os.path.join(fallback, ".write_probe")
            with open(_probe, "w") as _fh:
                _fh.write("x")
            os.remove(_probe)
        except OSError:
            continue

        # Migrate identity files from system dir if possible
        if os.path.isdir(system_dir):
            migrated = []
            for name in _SHARED_IDENTITY_FILES:
                src = os.path.join(system_dir, name)
                dst = os.path.join(fallback, name)
                if os.path.isfile(src) and not os.path.exists(dst):
                    try:
                        import shutil as _shutil
                        _shutil.copy2(src, dst)
                        migrated.append(name)
                    except OSError:
                        pass
            if migrated:
                logger.warning(
                    "%s is not writable by the current user. "
                    "Identity files migrated to %s (%s). "
                    "To avoid this, run: sudo chmod -R o+rwX %s",
                    system_dir, fallback, ", ".join(migrated), system_dir,
                )
            else:
                logger.info("%s not writable; using %s instead.", system_dir, fallback)

        return fallback

    return local_dir


# ── Single-instance lock ───────────────────────────────────────────────

_LOCK_FILE_PATH = "/Library/Application Support/ZeroWatch/state/.zerowatch.lock"
_lock_fh = None   # module-level handle — keeps fd open for the process lifetime


def _acquire_single_instance_lock() -> bool:
    """
    Acquire an exclusive non-blocking flock on the ZeroWatch lock file.

    Returns True if this process is the only running instance.
    Returns False if another instance already holds the lock — caller should exit.

    The lock is automatically released when the process exits (fd closed by OS).
    Works across both root and normal-user invocations because the lock file
    lives in the shared state directory.
    """
    global _lock_fh
    import fcntl

    lock_path = _LOCK_FILE_PATH
    try:
        os.makedirs(os.path.dirname(lock_path), mode=0o1777, exist_ok=True)
    except OSError:
        pass

    try:
        _lock_fh = open(lock_path, "w")
        # Ensure lock file is readable by any user
        try:
            os.chmod(lock_path, 0o666)
        except OSError:
            pass
        fcntl.flock(_lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Write our PID for diagnostic purposes
        _lock_fh.write(str(os.getpid()) + "\n")
        _lock_fh.flush()
        return True
    except BlockingIOError:
        # Another instance holds the lock
        try:
            pid = open(lock_path).read().strip()
        except OSError:
            pid = "unknown"
        logger.error(
            "ZeroWatch agent is already running (pid=%s). "
            "Only one instance may run at a time. Exiting.",
            pid,
        )
        return False
    except OSError as exc:
        # Lock file not writable (edge case) — log and continue without lock
        logger.warning("Could not acquire instance lock (%s) — proceeding without lock", exc)
        return True


# ── FDA check: detect if Full Disk Access is likely missing ───────────────────

def _check_and_warn_fda() -> None:
    """
    Attempt to list /Library to detect whether Full Disk Access (FDA) is granted.
    Without FDA, scanning /Library, /Applications (deep), and user directories
    will silently skip many paths.
    """
    try:
        os.listdir("/Library/Application Support")
    except PermissionError:
        logger.warning(
            "[ACTION REQUIRED] Full Disk Access (FDA) is NOT granted to this agent.\n"
            "  Software inventory will only include:\n"
            "    • .app bundles in /Applications and /System/Applications\n"
            "    • Package receipts from pkgutil\n"
            "    • Homebrew and MacPorts (if installed)\n"
            "    • macOS version\n"
            "  To enable complete filesystem scanning:\n"
            "    System Settings → Privacy & Security → Full Disk Access\n"
            "    → Click '+' and add this Python interpreter or the agent binary"
        )
    except OSError:
        pass  # Not a PermissionError — another issue; don't warn here


# ── Device ID ─────────────────────────────────────────────────────────────────

def _get_device_id(plat) -> str:
    """Return a stable device ID using the macOS hardware fingerprint (IOKit)."""
    try:
        fingerprint = plat.hardware_collector.collect_fingerprint()
        return plat.hardware_collector.generate_device_id(fingerprint)
    except Exception as exc:
        logger.warning("Hardware fingerprint failed, using hostname fallback: %s", exc)
        return hashlib.sha256(socket.gethostname().encode()).hexdigest()


# ── JWT / session management ──────────────────────────────────────────────────

class MacOSAgentSession:
    """Manages JWT, join state, and HTTP session with certificate pinning."""

    def __init__(self, api_url: str, state_dir: str, plat) -> None:
        self._api_url   = api_url.rstrip("/")
        self._state_dir = state_dir
        self._platform  = plat
        self._jwt: str  = ""
        self._jwt_path  = os.path.join(state_dir, "agent_token.enc")
        self._join_path = os.path.join(state_dir, "join_state.json")
        self._session   = self._build_http_session()

    def _build_http_session(self) -> requests.Session:
        parsed   = urlparse(self._api_url)
        hostname = parsed.hostname or ""
        if is_loopback(self._api_url):
            return requests.Session()
        pins    = SPKI_PINS.get(hostname, [])
        adapter = build_pinning_adapter(pins)
        sess    = requests.Session()
        sess.mount("https://", adapter)
        return sess

    @property
    def headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._jwt:
            h["Authorization"] = f"Bearer {self._jwt}"
        return h

    # ── Secure store wrappers ─────────────────────────────────────────────────

    def _encrypt(self, data: bytes) -> bytes | None:
        """
        Encrypt via MacOSSecureStore (Keychain tagged-reference).
        Falls back to None if Keychain is unavailable (e.g. not on macOS,
        or Keychain locked in daemon context without FDA).

        Always validates the returned token before returning — prevents writing
        corrupt non-token bytes to disk which would cause decrypt failures later.
        """
        try:
            result = self._platform.secure_store.encrypt(data)
            if result is not None:
                # Validate the token is a proper ZW_KC reference or RAW fallback
                if not (result.startswith(b"ZW_KC::") or result.startswith(b"RAW::")):
                    logger.error(
                        "encrypt() returned unexpected token format (len=%d) — "
                        "discarding to prevent corrupt disk state", len(result)
                    )
                    return None
                return result
            # Keychain unavailable — store raw bytes as base64 in state dir
            logger.warning(
                "Keychain unavailable — storing token unprotected in state dir. "
                "This is expected during development on non-macOS hosts."
            )
            import base64
            return b"RAW::" + base64.b64encode(data)
        except Exception as exc:
            # A root LaunchDaemon may not be able to access the logged-in
            # user's Keychain. Keep the agent alive and persist the JWT in the
            # same shared state directory using the explicit RAW:: fallback.
            # The fallback is macOS-only; Linux and Windows use their own
            # session implementations.
            logger.warning(
                "SecureStore encrypt failed: %s; using protected-state fallback.",
                exc,
            )
            import base64
            return b"RAW::" + base64.b64encode(data)

    def _decrypt(self, data: bytes) -> bytes | None:
        """
        Decrypt via MacOSSecureStore, or handle the RAW:: fallback token.
        """
        try:
            if data.startswith(b"RAW::"):
                import base64
                return base64.b64decode(data[5:])
            return self._platform.secure_store.decrypt(data)
        except Exception as exc:
            logger.warning("SecureStore decrypt failed: %s", exc)
            return None

    # ── JWT persistence ───────────────────────────────────────────────────────

    def load_jwt(self) -> bool:
        """Load and decrypt saved JWT. Returns True if valid token found."""
        candidate_paths = [
            self._jwt_path,
            os.path.join(self._state_dir, "zerowatch_token.dat"),
        ]
        for path in candidate_paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "rb") as fh:
                    enc = fh.read()
                raw = self._decrypt(enc)
                if raw:
                    self._jwt = raw.decode("utf-8").strip()
                    if self._jwt:
                        # Synchronize across filenames if loaded from alternate location
                        if path != self._jwt_path:
                            self.save_jwt(self._jwt)
                        return True
            except Exception as exc:
                logger.debug("JWT load failed from %s: %s", path, exc)
        return False

    def save_jwt(self, token: str) -> None:
        """Encrypt and save JWT to disk."""
        self._jwt = token
        enc = self._encrypt(token.encode("utf-8"))
        if enc:
            for path in (self._jwt_path, os.path.join(self._state_dir, "zerowatch_token.dat")):
                try:
                    with open(path, "wb") as fh:
                        fh.write(enc)
                    os.chmod(path, _SHARED_STATE_FILE_MODE)
                except OSError as exc:
                    logger.warning("JWT save failed for %s: %s", path, exc)

    def clear_jwt(self) -> None:
        self._jwt = ""
        for path in (self._jwt_path, os.path.join(self._state_dir, "zerowatch_token.dat")):
            try:
                os.remove(path)
            except OSError:
                pass


    def load_join_state(self) -> dict:
        """Load enrollment state written by the GUI in the shared state dir."""
        for path in (self._join_path, os.path.join(self._state_dir, "zw_team_join_state.dat")):
            if not os.path.exists(path):
                continue
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
                decoded = self._decrypt(raw) or raw
                state = json.loads(decoded.decode("utf-8"))
                if isinstance(state, dict):
                    return state
            except Exception as exc:
                logger.debug("Join state load failed from %s: %s", path, exc)
        return {}

    def save_join_state(self, updates: dict) -> None:
        """Merge *updates* into the persisted join_state.json without overwriting
        fields that are not being changed."""
        existing = self.load_join_state()
        merged   = {**existing, **updates}
        try:
            state_for_check = dict(merged)
            state_for_check.pop("checksum", None)
            canonical = json.dumps(state_for_check, sort_keys=True, separators=(",", ":"))
            device_id = merged.get("deviceId") or _get_device_id(self._platform)
            key = str(device_id or "unknown-device").encode("utf-8")
            merged["checksum"] = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

            data = json.dumps(merged).encode("utf-8")
            enc  = self._encrypt(data)
            payload = enc if enc else data
            for path in (self._join_path, os.path.join(self._state_dir, "zw_team_join_state.dat")):
                try:
                    with open(path, "wb") as fh:
                        fh.write(payload)
                    os.chmod(path, _SHARED_STATE_FILE_MODE)
                except OSError as exc:
                    logger.warning("Join state save failed for %s: %s", path, exc)
        except Exception as exc:
            logger.warning("Join state serialization failed: %s", exc)
    # ── HTTP verbs ────────────────────────────────────────────────────────────

    def post(self, path: str, payload: dict, timeout: int = 30) -> requests.Response:
        url = f"{self._api_url}{path}"
        return self._session.post(url, json=payload, headers=self.headers, timeout=timeout)

    def get(self, path: str, timeout: int = 30) -> requests.Response:
        url = f"{self._api_url}{path}"
        return self._session.get(url, headers=self.headers, timeout=timeout)

    def patch(self, path: str, payload: dict, timeout: int = 30) -> requests.Response:
        url = f"{self._api_url}{path}"
        return self._session.patch(url, json=payload, headers=self.headers, timeout=timeout)


# ── Inventory helpers ─────────────────────────────────────────────────────────

def _build_hardware_profile(plat) -> dict:
    """Build a backend-compatible hardware profile dict from macOS collectors."""
    try:
        hc      = plat.hardware_collector
        profile = hc.get_detailed_hardware_profile()
        inv     = hc.get_hardware_inventory()
        return {
            "hardware": {
                "cpu":   next((x for x in inv if x.get("category") == "cpu"), {}),
                "ram":   next((x for x in inv if x.get("category") == "ram"), {}),
                "gpu":   profile.get("gpus", []),
                "disks": [],
            },
            "os_info":     profile.get("os_info", {}),
            "fingerprint": hc.collect_fingerprint(),
            "profile":     profile,      # Full profile for dashboard display
        }
    except Exception as exc:
        logger.warning("Hardware profile failed: %s", exc)
        return {}


def _items_to_dicts(items) -> list:
    """Convert SoftwareItem list to API-compatible dicts."""
    result = []
    for item in items:
        try:
            if isinstance(item, dict):
                result.append(item)
            elif hasattr(item, "to_api_dict"):
                result.append(item.to_api_dict())
            elif hasattr(item, "to_dict"):
                result.append(item.to_dict())
            else:
                result.append(item.__dict__)
        except Exception:
            pass
    return result


# ── Main agent loop ───────────────────────────────────────────────────────────

class MacOSAgent:
    """
    Main macOS agent class.
    Mirrors the Linux agent flow but uses macOS platform implementations:
      - MacOSHardwareCollector (IOKit fingerprint, sysctl, system_profiler)
      - MacOSSoftwareCollector (app bundles, pkgutil, Homebrew, MacPorts, OS)
      - MacOSBinaryInspector  (static Mach-O ownership resolution)
      - MacOSFilesystemWalker (SIP-aware curated scan roots)
      - MacOSSecureStore      (Keychain tagged-reference)
      - MacOSPersistenceManager (launchd LaunchDaemon)
      - MacOSProcessGuard     (POSIX SIGTERM/SIGINT/SIGHUP)
    """

    def __init__(self) -> None:
        _configure_logging()
        self._stop_event = threading.Event()
        self._state_dir  = _get_state_dir()

        # ── Single-instance guard ─────────────────────────────────────────────
        if not _acquire_single_instance_lock():
            sys.exit(1)

        logger.info("ZeroWatch macOS Agent %s starting", AGENT_VERSION)
        logger.info("API URL:   %s", BASE_API_URL)
        logger.info("State dir: %s", self._state_dir)
        logger.info("Platform:  macOS %s (%s)", platform.mac_ver()[0], platform.machine())

        # Check Full Disk Access early and warn if missing
        _check_and_warn_fda()

        # Build platform (MacOSPlatform via factory)
        self._platform = PlatformFactory.create()
        logger.info("Platform type: %s", type(self._platform).__name__)

        # Device ID via IOKit IOPlatformUUID
        self._device_id = _get_device_id(self._platform)
        logger.info("Device ID: %s", self._device_id)

        # HTTP session with certificate pinning
        self._session = MacOSAgentSession(BASE_API_URL, self._state_dir, self._platform)

        # ScanOrchestrator with macOS implementations injected
        self._orchestrator = ScanOrchestrator(
            base_dir=self._state_dir,
            existing_registry_fn=None,   # macOS: no Windows registry
            agent_version=AGENT_VERSION,
            software_collector=self._platform.software_collector,
            binary_inspector=self._platform.binary_inspector,
            filesystem_walker=self._platform.filesystem_walker,
        )

        # Approval-sync idempotency lock (in-process single-flight guard)
        # The persisted approvalSyncStatus in join_state.json is the cross-restart
        # guard; this threading.Lock() prevents duplicate callbacks within one run.
        self._approval_sync_lock: threading.Lock = threading.Lock()

        # Warm the scan cache from previous session so first delta is minimal
        try:
            self._orchestrator.load_snapshot_from_cache()
            logger.info("Scan cache warmed from previous session.")
        except Exception as exc:
            logger.debug("Scan cache warm failed (cold start): %s", exc)

        # Install POSIX signal handlers (SIGTERM, SIGINT, SIGHUP)
        self._platform.process_guard.register_signal_protection()
        from macos.protection.process_guard import get_shutdown_event
        self._shutdown_event = get_shutdown_event()

        # Register launchd persistence (runs on first boot, idempotent)
        self._register_persistence()

    # ── Persistence ────────────────────────────────────────────────────────────

    def _register_persistence(self) -> None:
        """Install the LaunchDaemon plist so the agent starts on boot."""
        try:
            if not self._platform.persistence_manager.is_persistence_active():
                exe_path = os.path.abspath(sys.argv[0])
                ok = self._platform.persistence_manager.register_startup(
                    exe_path, daemon_args=["--daemon"]
                )
                if ok:
                    logger.info("LaunchDaemon registered: agent will start on boot.")
                else:
                    logger.warning(
                        "LaunchDaemon registration failed — may require root privileges. "
                        "Run with: sudo %s --daemon", exe_path
                    )
            else:
                logger.info("LaunchDaemon already registered.")
        except Exception as exc:
            logger.debug("Persistence registration skipped: %s", exc)

    # ── Authentication ─────────────────────────────────────────────────────────

    # -- Approval-sync idempotency helpers ------------------------------------

    def _claim_approval_sync(self) -> bool:
        """Atomically claim the approval-sync slot. Returns True if this daemon
        should run the full sync; False if already complete or in-progress."""
        with self._approval_sync_lock:
            state = self._session.load_join_state()
            if not isinstance(state, dict) or str(state.get("status") or "").lower() != "approved":
                return False
            sync_status = str(state.get("approvalSyncStatus") or "").lower()
            request_id  = state.get("requestId") or state.get("approvalSyncRequestId") or "approved"
            if sync_status == "complete" and state.get("approvalSyncRequestId") == request_id:
                return False
            if sync_status == "in_progress":
                return False
            self._session.save_join_state({
                "approvalSyncStatus":    "in_progress",
                "approvalSyncRequestId": request_id,
            })
            return True

    def _approval_sync_complete(self) -> bool:
        """Return True if the approval sync already completed for this device."""
        state = self._session.load_join_state()
        return (
            isinstance(state, dict)
            and str(state.get("status") or "").lower() == "approved"
            and state.get("approvalSyncStatus") == "complete"
            and bool(state.get("approvalSyncRequestId"))
        )

    def _finish_approval_sync(self, success: bool) -> None:
        """Persist completion or failure without invalidating enrollment."""
        with self._approval_sync_lock:
            state = self._session.load_join_state()
            if not isinstance(state, dict) or str(state.get("status") or "").lower() != "approved":
                return
            self._session.save_join_state({
                "approvalSyncStatus": "complete" if success else "failed",
            })

    def _register_or_authenticate(self) -> bool:
        """Join the device or authenticate with saved JWT."""
        # Keep authentication independent from the expensive hardware profile.
        # The profile is collected immediately after authentication and sent
        # with the first inventory sync.
        try:
            fingerprint = self._platform.hardware_collector.collect_fingerprint()
        except Exception as exc:
            logger.warning("Fingerprint collection failed during authentication: %s", exc)
            fingerprint = {"device_id": self._device_id}
        hostname    = socket.gethostname()
        username    = os.environ.get("USER", os.environ.get("USERNAME", "root"))

        # Try to load existing JWT first
        if self._session.load_jwt():
            logger.info("Loaded saved JWT — verifying with server")
            try:
                resp = self._session.get("/agent/info")
                if resp.status_code == 200:
                    logger.info("JWT valid — authenticated")
                    return True
                if resp.status_code == 404:
                    self._orchestrator.close()
                    clear_device_state(self._state_dir)
                    self._session.clear_jwt()
                    logger.info("Device was unlinked; local state cleared.")
                logger.info("JWT rejected (HTTP %d) — re-joining", resp.status_code)
                self._session.clear_jwt()
            except Exception as exc:
                logger.warning("Auth check failed: %s", exc)
                self._session.clear_jwt()

        # Persisted-enrollment check (FIXED: no hard deadline)
        # If join_state.json shows pending/approved status, poll indefinitely.
        state = self._session.load_join_state()
        if str(state.get("status") or "").lower() in {"pending", "approved"}:
            logger.info(
                "[PENDING_APPROVAL] Resuming persisted enrollment; "
                "polling indefinitely for administrator approval (device_id=%s).",
                self._device_id,
            )
            consecutive_errors = 0
            while not self._shutdown_event.is_set():
                try:
                    response = self._session.get(
                        f"/agent/join-status?deviceId={self._device_id}"
                    )
                    if response.status_code == 200:
                        data = response.json()
                        status = str(data.get("status") or "").lower()
                        if status == "approved" and data.get("jwt"):
                            self._session.save_jwt(data["jwt"])
                            logger.info(
                                "[APPROVAL_DETECTED] Persisted enrollment approved; "
                                "daemon authenticated (device_id=%s).",
                                self._device_id,
                            )
                            return True
                        if status == "denied":
                            logger.error(
                                "[ENROLLMENT] Persisted enrollment denied by administrator "
                                "(device_id=%s).",
                                self._device_id,
                            )
                            return False
                        consecutive_errors = 0
                    elif response.status_code in (401, 403, 404):
                        logger.warning(
                            "[ENROLLMENT] Join-status returned HTTP %d; clearing pending state.",
                            response.status_code,
                        )
                        return False
                    else:
                        consecutive_errors += 1
                except Exception as exc:
                    consecutive_errors += 1
                    logger.debug(
                        "Persisted enrollment status check failed (attempt %d): %s",
                        consecutive_errors, exc,
                    )
                wait = min(8 * (1 + consecutive_errors // 5), 60)
                self._shutdown_event.wait(timeout=wait)

        # Read enrollment codes from environment
        team_code       = os.environ.get("TEAM_CODE") or os.environ.get("ZEROWATCH_TEAM_CODE")
        individual_code = os.environ.get("INDIVIDUAL_CODE") or os.environ.get("ZEROWATCH_INDIVIDUAL_CODE")

        if not team_code and not individual_code:
            logger.warning(
                "No enrollment code found in environment. "
                "Set TEAM_CODE=<your-team-code> or INDIVIDUAL_CODE=<your-code> "
                "then restart the agent, OR enroll the device from the ZeroWatch dashboard."
            )
            logger.info("Waiting for enrollment code to be set in environment (Ctrl+C to abort)...")
            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(timeout=30)
                team_code = os.environ.get("TEAM_CODE") or os.environ.get("ZEROWATCH_TEAM_CODE")
                individual_code = os.environ.get("INDIVIDUAL_CODE") or os.environ.get("ZEROWATCH_INDIVIDUAL_CODE")
                if team_code or individual_code:
                    logger.info("Enrollment code found. Proceeding with enrollment...")
                    break
            if not team_code and not individual_code:
                return False

        # ── Team Code Join Flow ────────────────────────────────────────────────
        if team_code:
            logger.info("Requesting join for team code: %s", team_code)
            payload = {
                "teamCode":       team_code,
                "device_id":      self._device_id,
                "hostname":       hostname,
                "username":       username,
                "asset_name":     hostname,
                "os_info":        {
                    "name":    "macOS",
                    "version": platform.mac_ver()[0],
                    "arch":    platform.machine(),
                },
                "fingerprint_json": fingerprint,
            }
            try:
                resp = self._session.post("/agent/join-request", payload)
                if resp.status_code in (200, 201):
                    data   = resp.json()
                    status = data.get("status")
                    if status == "approved" and data.get("jwt"):
                        self._session.save_jwt(data.get("jwt"))
                        logger.info("Agent joined and approved immediately.")
                        return True

                    logger.info(
                        "[PENDING_APPROVAL] Join request status: %s. "
                        "Awaiting admin approval indefinitely (device_id=%s)...",
                        status, self._device_id,
                    )
                    # Infinite retry poll -- no hard deadline (fixes the 600s bug)
                    consecutive_errors = 0
                    while not self._shutdown_event.is_set():
                        try:
                            status_resp = self._session.get(
                                f"/agent/join-status?deviceId={self._device_id}"
                            )
                            if status_resp.status_code == 200:
                                status_data = status_resp.json()
                                if status_data.get("status") == "approved":
                                    token = status_data.get("jwt")
                                    if token:
                                        self._session.save_jwt(token)
                                        logger.info(
                                            "[APPROVAL_DETECTED] Device approved! "
                                            "Enrollment complete (device_id=%s).",
                                            self._device_id,
                                        )
                                        return True
                                elif status_data.get("status") == "denied":
                                    logger.error(
                                        "[ENROLLMENT] Device join denied by admin (device_id=%s).",
                                        self._device_id,
                                    )
                                    return False
                                consecutive_errors = 0
                            elif status_resp.status_code in (401, 403, 404):
                                logger.warning(
                                    "[ENROLLMENT] Join-status HTTP %d; enrollment not found.",
                                    status_resp.status_code,
                                )
                                return False
                            else:
                                consecutive_errors += 1
                        except Exception as poll_exc:
                            consecutive_errors += 1
                            logger.debug(
                                "Join status poll error (attempt %d): %s",
                                consecutive_errors, poll_exc,
                            )
                        wait = min(8 * (1 + consecutive_errors // 5), 60)
                        self._shutdown_event.wait(timeout=wait)
                else:
                    logger.error(
                        "Join request failed: HTTP %d — %s",
                        resp.status_code, resp.text[:200],
                    )
            except Exception as exc:
                logger.error("Join request error: %s", exc)

        # ── Individual Code Flow ───────────────────────────────────────────────
        elif individual_code:
            logger.info("Enrolling individual agent with code: %s", individual_code)
            payload = {
                "individualCode": individual_code,
                "device_id":      self._device_id,
                "hostname":       hostname,
                "username":       username,
                "asset_name":     hostname,
                "os_info":        {
                    "name":    "macOS",
                    "version": platform.mac_ver()[0],
                    "arch":    platform.machine(),
                },
                "fingerprint_json": fingerprint,
            }
            try:
                resp = self._session.post("/agent/individual-enroll", payload)
                if resp.status_code in (200, 201):
                    data  = resp.json()
                    token = data.get("jwt")
                    if token:
                        self._session.save_jwt(token)
                        logger.info("Agent enrolled and linked.")
                        return True
                    logger.error("Individual enrollment succeeded but no token returned.")
                else:
                    logger.error(
                        "Individual enrollment failed: HTTP %d — %s",
                        resp.status_code, resp.text[:200],
                    )
            except Exception as exc:
                logger.error("Individual enrollment error: %s", exc)

        return False

    # ── Sync helpers ───────────────────────────────────────────────────────────

    def _sync_full(self, software: list, hardware: dict,
                   inventory_scope: str = "complete") -> bool:
        """Push full software + hardware inventory to backend."""
        payload = {
            "deviceId":  self._device_id,
            "software":  software,
            "hardware":  hardware,
            "inventoryScope": inventory_scope,
            "inventoryRevision": time.time_ns(),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        try:
            resp = self._session.post("/agent/sync/full", payload, timeout=60)
            if resp.status_code in (200, 201, 204):
                logger.info("Full sync: %d software items", len(software))
                return True
            logger.warning("Full sync failed: HTTP %d", resp.status_code)
        except Exception as exc:
            logger.warning("Full sync error: %s", exc)
        return False

    def _sync_full_with_retry(self, software: list, hardware: dict,
                              inventory_scope: str = "complete") -> bool:
        """Push full inventory, retrying up to 3 times on transient failures."""
        for attempt in range(3):
            if self._shutdown_event.is_set():
                return False
            if self._sync_full(software, hardware, inventory_scope):
                return True
            logger.warning("Full sync attempt %d/3 failed. Retrying in 15s...", attempt + 1)
            self._shutdown_event.wait(timeout=15)
        logger.error("Full sync failed after 3 attempts — will retry on next delta.")
        return False

    def _sync_delta(self, added: list, removed: list) -> bool:
        """Push incremental delta to backend."""
        if not added and not removed:
            return True
        payload = {
            "deviceId":  self._device_id,
            "added":     added,
            "removed":   removed,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        try:
            resp = self._session.post("/agent/sync/delta", payload, timeout=60)
            if resp.status_code in (200, 201, 204):
                logger.info("Delta sync: +%d -%d items", len(added), len(removed))
                return True
            logger.warning("Delta sync failed: HTTP %d", resp.status_code)
        except Exception as exc:
            logger.warning("Delta sync error: %s", exc)
        return False

    def _heartbeat(self) -> bool:
        """Send periodic heartbeat to keep the server session alive."""
        if not getattr(self, "_device_id", None):
            logger.debug("Heartbeat skipped until device identity is initialized.")
            return False
        payload = {
            "deviceId":     self._device_id,
            "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
            "agentVersion": AGENT_VERSION,
            "platform":     "macos",
        }
        try:
            resp = self._session.post("/agent/heartbeat", payload, timeout=10)
            ok = resp.status_code in (200, 204)
            if ok:
                logger.info("Heartbeat accepted by server (HTTP %d).", resp.status_code)
            else:
                logger.warning(
                    "Heartbeat rejected by server (HTTP %d): %s",
                    resp.status_code,
                    resp.text[:200],
                )
            return ok
        except Exception as exc:
            logger.warning("Heartbeat error: %s", exc)
            return False

    # ── Scan phases ────────────────────────────────────────────────

    def _initial_scan_and_sync(self, approval_sync_claimed: bool = False) -> None:
        """
        Startup-optimized L0 + priority-path L1/L2 scan.

        Strategy:
          1. run_startup_scan(): L0 synchronous (<1s) + priority L1/L2
             parallelized with 6 workers.
          2. 90-second safety timeout as a defensive backstop.
          3. If exceeded or errored, fall back to L0-only sync.

        The full-disk exhaustive walk is NOT run at startup.
        It runs on the existing 24h cadence via start_periodic_scans().
        """
        _SAFETY_TIMEOUT = 90
        startup_items = []
        scan_done = threading.Event()
        scan_error = []

        def _run_startup():
            try:
                result = self._orchestrator.run_startup_scan(
                    stop_event=self._shutdown_event,
                )
                startup_items.extend(result)
            except Exception as exc:
                scan_error.append(exc)
            finally:
                scan_done.set()

        hardware = {}
        hardware_done = threading.Event()

        def _collect_hardware():
            nonlocal hardware
            try:
                hardware = _build_hardware_profile(self._platform)
            finally:
                hardware_done.set()

        # system_profiler/IOKit can stall under sudo or while TCC prompts are
        # pending. Run it independently so it cannot prevent inventory sync.
        threading.Thread(
            target=_collect_hardware,
            daemon=True,
            name="macos-hardware-profile",
        ).start()

        logger.info(
            "[STARTUP_SCAN_STARTED] macOS initial scan started "
            "(timeout=%ds, device_id=%s, approval_claimed=%s).",
            _SAFETY_TIMEOUT, self._device_id, approval_sync_claimed,
        )
        threading.Thread(
            target=_run_startup, daemon=True, name="initial-startup-scan",
        ).start()
        try:
            completed = scan_done.wait(timeout=_SAFETY_TIMEOUT)
            if not hardware_done.wait(timeout=30):
                logger.warning("Hardware profile timed out; syncing inventory without hardware details.")
            hw = hardware
            if completed and not scan_error:
                logger.info(
                    "[STARTUP_SCAN] Completed within %ds: "
                    "%d software items (device_id=%s).",
                    _SAFETY_TIMEOUT, len(startup_items), self._device_id,
                )
                logger.info("[INVENTORY_UPLOAD_STARTED] device_id=%s items=%d", self._device_id, len(startup_items))
                ok = self._sync_full_with_retry(startup_items, hw, "complete")
                logger.info("[INVENTORY_UPLOAD_COMPLETED] device_id=%s success=%s", self._device_id, ok)
                if approval_sync_claimed:
                    self._finish_approval_sync(ok)
                    logger.info("[FULL_SYNC_COMPLETED] device_id=%s", self._device_id)
            else:
                logger.warning(
                    "[STARTUP_SCAN] Priority scan exceeded %ds or failed; "
                    "syncing L0-only now (device_id=%s).",
                    _SAFETY_TIMEOUT, self._device_id,
                )
                layer0 = self._orchestrator._run_layer0()
                layer0_dicts = _items_to_dicts(self._orchestrator._deduplicate(layer0))
                logger.info(
                    "[INVENTORY_UPLOAD_STARTED] L0 fallback device_id=%s items=%d",
                    self._device_id, len(layer0_dicts),
                )
                self._sync_full_with_retry(layer0_dicts, hw, "partial")
                if approval_sync_claimed:
                    self._finish_approval_sync(False)
        except Exception as exc:
            logger.error("Initial scan failed: %s", exc, exc_info=True)

    def _on_fs_delta(self, added_items: list, removed_items: list) -> None:
        """
        Callback from start_periodic_scans() — push L1/L2 Mach-O deltas to backend.
        NOTE: added_items / removed_items are already List[dict] (converted by
        _emit_fs_delta inside the orchestrator). Do NOT wrap with _items_to_dicts().
        """
        if (added_items or removed_items) and self._session._jwt:
            self._sync_delta(added_items, removed_items)

    # ── Monitor loop ────────────────────────────────────────────────

    def _monitor_loop(self) -> None:
        """
        Background thread: fast L0 delta every 60s (app bundle installs/removals).
        L1/L2 Mach-O filesystem deltas are handled by start_periodic_scans()
        on a 4h priority / 24h deep schedule — identical to Windows pattern.
        """
        last_heartbeat  = time.monotonic()
        last_l0_delta   = time.monotonic()
        L0_INTERVAL     = 60   # seconds between L0 app-bundle delta checks
        logger.info("macOS heartbeat monitor started (interval=%ds).", HEARTBEAT_INTERVAL)

        while not self._shutdown_event.is_set() and not self._stop_event.is_set():
            now = time.monotonic()

            # ── Heartbeat ──────────────────────────────────────────────────
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                self._heartbeat()
                last_heartbeat = now

            # ── Fast L0 delta (app bundles, pkgutil, Homebrew, etc.) ───────
            if now - last_l0_delta >= L0_INTERVAL:
                try:
                    added, removed = self._orchestrator.run_registry_delta()
                    if added or removed:
                        self._sync_delta(
                            _items_to_dicts(added),
                            _items_to_dicts(removed),
                        )
                    last_l0_delta = now
                except Exception as exc:
                    logger.warning("L0 delta scan error: %s", exc)

            self._shutdown_event.wait(timeout=5)

    # ── Main run loop ──────────────────────────────────────────────────────────

    def run(self) -> int:
        """Main blocking run loop. Returns process exit code."""
        # Authenticate / enroll (with retry backoff)
        attempt = 0
        while not self._shutdown_event.is_set():
            if self._shutdown_event.is_set():
                return 0
            if self._register_or_authenticate():
                break
            wait = min(RECONNECT_DELAY * (2 ** min(attempt, 4)), 120)
            attempt += 1
            logger.info("Retrying authentication in %ds (attempt %d; continuing until linked)...", wait, attempt)
            self._shutdown_event.wait(timeout=wait)
        if self._shutdown_event.is_set():
            return 0
        if not self._session._jwt:
            logger.error("Authentication loop ended without a JWT")
            return 1

        # Keep connectivity alive while the initial inventory/deep scan runs.
        logger.info("Sending immediate post-enrollment heartbeat...")
        heartbeat_ok = self._heartbeat()
        logger.info("Immediate post-enrollment heartbeat %s.", "succeeded" if heartbeat_ok else "failed")
        monitor = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="macos-monitor",
        )
        monitor.start()

        # Approval-sync idempotency check
        approval_sync_claimed = self._claim_approval_sync()
        if approval_sync_claimed:
            logger.info(
                "[ENROLLMENT] Approval claimed by macOS daemon; "
                "starting complete inventory sync (device_id=%s).",
                self._device_id,
            )

        # Initial startup scan (L0 + priority L1/L2 within 60s)
        self._initial_scan_and_sync(approval_sync_claimed=approval_sync_claimed)

        # Keep the periodic scanner off the shared cache until the initial
        # deep scan and its follow-up upload have completed.
        self._initial_scan_done.wait()

        # Start periodic filesystem scans (priority + deep) so macOS does a
        # true folder/file deep scan instead of only hardware/software inventory.
        self._orchestrator.start_periodic_scans(on_delta=self._on_fs_delta)
        logger.info("Periodic filesystem scan started (priority every 4h / deep every 24h).")

        ota_monitor = None
        try:
            ota_monitor = start_daemon_ota_monitor(
            os.path.abspath(sys.argv[0]), AGENT_VERSION, self._shutdown_event
            )
        except Exception:
            logger.exception("Failed to start daemon OTA monitor; continuing without OTA")

        logger.info("ZeroWatch macOS Agent running. Press Ctrl+C or send SIGTERM to stop.")

        # Block until shutdown signal (SIGTERM/SIGINT via process_guard)
        self._shutdown_event.wait()

        logger.info("Shutdown signal received — stopping macOS agent")
        self._stop_event.set()
        try:
            self._orchestrator.stop_periodic_scans(timeout=10)
        except Exception as exc:
            logger.debug("Orchestrator stop error (non-fatal): %s", exc)
        monitor.join(timeout=10)
        if ota_monitor is not None:
            ota_monitor.stop()

        # Clean up the build-time config file (written by run_agent.sh)
        try:
            cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_build_config.py")
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except Exception:
            pass

        logger.info("ZeroWatch macOS Agent stopped cleanly.")
        return 0


# Alias for import compatibility from sentinel_agent.py
MacOSSentinelAgent = MacOSAgent


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    if not BASE_API_URL:
        print("[ERROR] No API URL configured.")
        print("        Run via run_agent.sh or set ZEROWATCH_API_URL environment variable.")
        return 1

    _daemonize_if_needed()
    agent = MacOSAgent()
    return agent.run()


if __name__ == "__main__":
    sys.exit(main())
