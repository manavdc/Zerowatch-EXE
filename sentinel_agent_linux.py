"""
sentinel_agent_linux.py
─────────────────────────────────────────────────────────────────────────────
ZeroWatch Endpoint Agent — Linux Entry Point

This is the Linux equivalent of sentinel_agent.py.

Differences from Windows agent:
  - No winreg, no ctypes.wintypes, no Win32 API calls
  - Uses PlatformFactory to obtain Linux implementations
  - Uses systemd-compatible startup/shutdown (SIGTERM/SIGINT)
  - State stored in /var/lib/zerowatch/state (falls back to ./state/)
  - Logging goes to journald (via LinuxEventLogger) or stderr
  - Persistence via systemd unit (LinuxPersistenceManager)

Shared with Windows agent:
  - ScanOrchestrator (dependency injected — same code path)
  - cert_pinning.py (certificate pinning — identical)
  - Backend API contract (identical JSON payloads)
  - SPKI_PINS (identical hardcoded pins)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid

import requests
import socketio  # pyrefly: ignore [missing-import]  # type: ignore[import]
from urllib.parse import urlparse

# ── Certificate pinning (shared with Windows agent) ──────────────────────────
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

# ── Platform factory (provides Linux implementations) ─────────────────────────
from platforms import PlatformFactory

# ── Scan orchestrator (platform-agnostic) ─────────────────────────────────────
from scanner import ScanOrchestrator
from common.daemon_ota import start_daemon_ota_monitor
from common.state_cleanup import clear_device_state

# ─────────────────────────────────────────────────────────────────────────────
# AGENT CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

AGENT_VERSION = "1.0.0-linux"
HEARTBEAT_INTERVAL = 30        # seconds between heartbeats
MONITOR_INTERVAL   = 120       # seconds between delta scan checks
RESTART_CHECK_TIME = 14400  # 4 hours in seconds (OTA update & restart check interval)
RECONNECT_DELAY    = 10        # seconds before reconnect attempt

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

# Automatically resolve WSL localhost loopback gateway to Windows host
if "localhost" in BASE_API_URL or "127.0.0.1" in BASE_API_URL:
    try:
        # Check if running in WSL
        is_wsl = False
        if os.path.exists("/proc/sys/kernel/osrelease"):
            with open("/proc/sys/kernel/osrelease", "r") as f:
                if "wsl" in f.read().lower():
                    is_wsl = True
        if is_wsl:
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        gw_hex = parts[2]
                        gw_bytes = bytes.fromhex(gw_hex)
                        gw_ip = ".".join(str(b) for b in reversed(gw_bytes))
                        BASE_API_URL = BASE_API_URL.replace("localhost", gw_ip).replace("127.0.0.1", gw_ip)
                        break
    except Exception:
        pass

# ── SPKI pins (identical to Windows agent) ────────────────────────────────────
SPKI_PINS = {
    "zerowatch.deepcytes.io": [
        # --- Leaf Public Keys (90-Day Lifespan) ---
        "a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ=",  # Google Trust Services (Active Leaf from 2026-11-03)
        "MZ4Kk+NPs6uc35JlOBNODqa+AZvqgtCq+sSjXx9W/k4=",  # Previous Leaf

        # --- Intermediate CAs (1 to 5-Year Lifespan) ---
        "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",  # Google Trust Services WE1 Intermediate CA
        "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",  # Let's Encrypt R3 Intermediate CA

        # --- Root CAs (10 to 25-Year Lifespan - Immune to 90-Day Rotations) ---
        "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=",  # Google Trust Services GTS Root R1 (RSA 4096)
        "Vfd95BwDeSQo+NUYxVEEIlvkOlWY2SalKK1lPhzOx78=",  # Google Trust Services GTS Root R2 (RSA 4096)
        "QXnt2YHvdHR3tJYmQIr0Paosp6t/nggsEGD4QJZ3Q0g=",  # Google Trust Services GTS Root R3 (ECDSA P-256)
        "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",  # Google Trust Services GTS Root R4 (ECDSA P-384)
        "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",  # Let's Encrypt ISRG Root X1 (RSA 4096, valid to 2035)
        "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",  # Let's Encrypt ISRG Root X2 (ECDSA P-384, valid to 2040)
        "K87oWBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q=",  # GlobalSign Root CA (GTS cross-sign anchor)
        "CLOmM1/OXvSPjw5UOYbAf9GKOxImEp9hhku9W90fHMk=",  # GlobalSign ECC Root R4
        "cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A=",  # GlobalSign Root CA - R3

        # --- Emergency / Rollover Backup Pin ---
        "F9lRuoRnviTJKIdnkPA/fgjKP4lCNbWuIC23cQ7mlJU="   # Rollover backup pin
    ]
}

# ── Logging ───────────────────────────────────────────────────────────────────

def _configure_logging(state_dir: str = "") -> None:
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handlers: list = [logging.StreamHandler(sys.stdout)]

    # Always write to a rotating log file so logs are preserved even when the
    # daemon is spawned with stdout=DEVNULL by the GUI bootstrap.
    if not state_dir:
        # Best-effort early discovery — the real dir is set after _get_state_dir()
        xdg_data_home = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
        state_dir = os.path.join(xdg_data_home, "zerowatch", "state")
    try:
        os.makedirs(state_dir, exist_ok=True)
        log_path = os.path.join(state_dir, "daemon.log")
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
        fh.setFormatter(logging.Formatter(fmt))
        handlers.append(fh)
    except Exception:
        pass  # Never block startup for logging

    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=handlers,
        force=True,
    )
    # Quieten noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("socketio").setLevel(logging.WARNING)
    logging.getLogger("engineio").setLevel(logging.WARNING)

logger = logging.getLogger("linux.agent")

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
    "scan_cache.db",
)

def _get_state_dir() -> str:
    system_parent = "/var/lib/zerowatch"
    system_dir = "/var/lib/zerowatch/state"
    # XDG user dir - MUST match sentinel_agent.py's GUI fallback so the daemon
    # reads the same JWT and join_state.json that the GUI wrote.
    xdg_data_home = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    xdg_dir  = os.path.join(xdg_data_home, "zerowatch", "state")
    user_dir = xdg_dir
    var_tmp_dir = "/var/tmp/zerowatch/state"
    local_dir = "/tmp/zerowatch/state"

    # ── Try system dir first (preferred — consistent across UIDs) ──────
    try:
        os.makedirs(system_dir, mode=0o777, exist_ok=True)
        try:
            os.chmod(system_parent, 0o777)
            os.chmod(system_dir, 0o777)
        except OSError:
            pass
        _probe = os.path.join(system_dir, ".write_probe")
        with open(_probe, "w") as _fh:
            _fh.write("x")
        os.remove(_probe)

        # Privileged repair: ensure all existing files in system dir are world-writable (0666)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            for entry in os.listdir(system_dir):
                fpath = os.path.join(system_dir, entry)
                if os.path.isfile(fpath):
                    try:
                        os.chmod(fpath, 0o666)
                    except OSError:
                        pass

            # If launched via sudo, import any state from the calling user's directory
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user:
                sudo_user_dir = os.path.expanduser(f"~{sudo_user}/.local/share/zerowatch/state")
                if os.path.isdir(sudo_user_dir):
                    for name in _SHARED_IDENTITY_FILES:
                        src = os.path.join(sudo_user_dir, name)
                        dst = os.path.join(system_dir, name)
                        if os.path.isfile(src) and not os.path.exists(dst):
                            try:
                                import shutil as _shutil
                                _shutil.copy2(src, dst)
                                os.chmod(dst, 0o666)
                            except OSError:
                                pass

        return system_dir                          # writable → use it
    except OSError:
        pass  # root-owned or missing; fall through to user-dir

    # ── System dir not writable. Find the first user-writable fallback ─
    for fallback in (var_tmp_dir, user_dir, local_dir):
        try:
            os.makedirs(fallback, mode=0o777, exist_ok=True)
            os.chmod(fallback, 0o777)
            _probe = os.path.join(fallback, ".write_probe")
            with open(_probe, "w") as _fh:
                _fh.write("x")
            os.remove(_probe)
        except OSError:
            continue

        # ── Migrate identity files from the unwritable system dir ───
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
                logger.info(
                    "%s not writable; using %s instead.",
                    system_dir, fallback,
                )

        return fallback

    # Last-resort — return local dir without write verification
    return local_dir


# ── Single-instance lock ─────────────────────────────────────────────────────

_lock_fh = None   # module-level handle — keeps fd open for the process lifetime

def _acquire_single_instance_lock(state_dir: str) -> bool:
    """
    Acquire an exclusive non-blocking flock on the ZeroWatch daemon lock file.

    The daemon uses '.zerowatch-daemon.lock' so it can coexist with a running
    GUI process (which the Windows GUI's _spawn_daemon_process() may launch
    while the user has the GUI open).  The old '.zerowatch.lock' name is kept
    as a compatibility fallback for probing by sentinel_agent.py.
    """
    global _lock_fh
    import fcntl

    # Use a daemon-specific lock file so the GUI and daemon can coexist.
    # sentinel_agent.py's _is_daemon_running() checks both names.
    is_daemon = "--daemon" in sys.argv
    lock_name = ".zerowatch-daemon.lock" if is_daemon else ".zerowatch.lock"
    lock_path = os.path.join(state_dir, lock_name)
    try:
        os.makedirs(os.path.dirname(lock_path), mode=0o700, exist_ok=True)
    except OSError:
        pass

    try:
        _lock_fh = open(lock_path, "a+")
        try:
            os.chmod(lock_path, 0o666)
        except OSError:
            pass
        fcntl.flock(_lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fh.seek(0)
        _lock_fh.truncate()
        _lock_fh.write(str(os.getpid()) + "\n")
        _lock_fh.flush()
        return True
    except BlockingIOError:
        try:
            if _lock_fh:
                _lock_fh.seek(0)
                pid = _lock_fh.read().strip()
            else:
                pid = open(lock_path).read().strip()
        except OSError:
            pid = "unknown"
        logger.error(
            "ZeroWatch daemon is already running (pid=%s). "
            "Only one daemon instance may run at a time. Exiting.",
            pid,
        )
        return False
    except OSError as exc:
        logger.warning("Could not acquire instance lock (%s) — proceeding without lock", exc)
        return True


# ── Device ID ─────────────────────────────────────────────────────────────────


def _get_device_id(platform) -> str:
    """Return a stable device ID using the Linux hardware fingerprint."""
    try:
        fingerprint = platform.hardware_collector.collect_fingerprint()
        return platform.hardware_collector.generate_device_id(fingerprint)
    except Exception as exc:
        logger.warning("Hardware fingerprint failed, using hostname fallback: %s", exc)
        return hashlib.sha256(socket.gethostname().encode()).hexdigest()


# ── JWT / session management ──────────────────────────────────────────────────

class LinuxAgentSession:
    """Manages JWT, join state, and HTTP session with certificate pinning."""

    def __init__(self, api_url: str, state_dir: str, platform):
        self._api_url   = api_url.rstrip("/")
        self._state_dir = state_dir
        self._platform  = platform
        self._jwt: str  = ""
        self._jwt_path  = os.path.join(state_dir, "agent_token.enc")
        self._join_path = os.path.join(state_dir, "join_state.json")
        self._session   = self._build_http_session()

    def _build_http_session(self) -> requests.Session:
        parsed = urlparse(self._api_url)
        hostname = parsed.hostname or ""
        if is_loopback(self._api_url):
            sess = requests.Session()
            return sess
        try:
            from common.updater import load_cached_dynamic_pins
            from common.cert.pinning import register_dynamic_pins
            cached = load_cached_dynamic_pins()
            if cached:
                register_dynamic_pins(cached)
        except Exception:
            pass
        pins = SPKI_PINS.get(hostname, [])
        adapter = build_pinning_adapter(pins)
        sess = PinnedSession()
        sess.mount("https://", adapter)
        return sess

    def heal_certificate_pins(self) -> bool:
        """Forces an immediate out-of-band Ed25519 OTA refresh of dynamic certificate pins."""
        try:
            from common.updater import fetch_dynamic_pins
            updated = fetch_dynamic_pins(timeout=10)
            if updated:
                logging.info(f"[PINNING] Certificate pins manually refreshed: {list(updated.keys())}")
                return True
        except Exception as e:
            logging.warning(f"[PINNING] Manual certificate pin refresh failed: {e}")
        return False

    @property
    def headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._jwt:
            h["Authorization"] = f"Bearer {self._jwt}"
        return h

    def _encrypt(self, data: bytes) -> bytes | None:
        try:
            return self._platform.secure_store.encrypt(data)
        except Exception as exc:
            logger.warning("SecureStore encrypt failed: %s", exc)
            return None

    def _decrypt(self, data: bytes) -> bytes | None:
        try:
            return self._platform.secure_store.decrypt(data)
        except Exception as exc:
            logger.warning("SecureStore decrypt failed: %s", exc)
            return None

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
                    os.chmod(path, 0o666)
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
        """Load enrollment state written by the GUI in the shared state dir.

        Checks both zw_team_join_state.dat (GUI/Windows-compatible DPAPI/AES)
        and join_state.json, sorted by newest mtime, and prioritizes active
        enrollment records ('pending', 'approved').
        """
        candidates = [
            os.path.join(self._state_dir, "zw_team_join_state.dat"),
            self._join_path,
        ]
        existing_paths = [p for p in candidates if os.path.exists(p)]
        existing_paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)

        # 1. Prefer newest active state (pending or approved)
        for path in existing_paths:
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
                decoded = None
                try:
                    decoded = self._decrypt(raw)
                except Exception:
                    pass
                payload = decoded if decoded is not None else raw
                state = json.loads(payload.decode("utf-8"))
                if isinstance(state, dict):
                    status = str(state.get("status") or "").lower()
                    if status in ("pending", "approved"):
                        return state
            except Exception as exc:
                logger.debug("Join state load failed from %s: %s", path, exc)

        # 2. Fall back to any parseable state
        for path in existing_paths:
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
                decoded = None
                try:
                    decoded = self._decrypt(raw)
                except Exception:
                    pass
                payload = decoded if decoded is not None else raw
                state = json.loads(payload.decode("utf-8"))
                if isinstance(state, dict):
                    return state
            except Exception:
                pass
        return {}

    def save_join_state(self, updates: dict) -> None:
        """Merge *updates* into the persisted join_state.json and zw_team_join_state.dat
        without overwriting fields that are not being changed."""
        existing = self.load_join_state()
        merged   = {**existing, **updates}
        dev_id = getattr(self, "_device_id", None)
        if dev_id:
            if "deviceId" not in merged:
                merged["deviceId"] = dev_id
            if "device_id" not in merged:
                merged["device_id"] = dev_id
        try:
            data = json.dumps(merged).encode("utf-8")
            enc  = self._encrypt(data)
            payload = enc if enc else data
            for path in (self._join_path, os.path.join(self._state_dir, "zw_team_join_state.dat")):
                try:
                    with open(path, "wb") as fh:
                        fh.write(payload)
                    os.chmod(path, 0o666)
                except OSError as exc:
                    logger.warning("Join state save failed for %s: %s", path, exc)
        except Exception as exc:
            logger.warning("Join state serialization failed: %s", exc)

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

def _build_hardware_profile(platform) -> dict:
    try:
        hc = platform.hardware_collector
        profile = hc.get_detailed_hardware_profile()
        inv     = hc.get_hardware_inventory()
        return {
            "hardware": {
                "cpu": next((x for x in inv if x.get("category") == "cpu"), {}),
                "ram": next((x for x in inv if x.get("category") == "ram"), {}),
                "gpu": [],
                "disks": [],
            },
            "os_info": profile.get("os_info", {}),
            "fingerprint": hc.collect_fingerprint(),
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
            else:
                result.append(item.to_dict() if hasattr(item, "to_dict") else item.__dict__)
        except Exception:
            pass
    return result


# ── Main agent loop ───────────────────────────────────────────────────────────

class LinuxAgent:
    """
    Main agent class.
    Mirrors the Windows agent daemon flow but uses Linux platform implementations.
    """

    def __init__(self, state_dir: str | None = None):
        self._stop_event = threading.Event()
        self._state_dir  = state_dir if state_dir is not None else _get_state_dir()
        _configure_logging(self._state_dir)

        # ── Single-instance guard ─────────────────────────────────────────────
        if not _acquire_single_instance_lock(self._state_dir):
            sys.exit(1)

        logger.info("ZeroWatch Linux Agent %s starting", AGENT_VERSION)
        logger.info("API URL:    %s", BASE_API_URL)
        logger.info("State dir:  %s", self._state_dir)

        # Build platform (LinuxPlatform via factory)
        self._platform = PlatformFactory.create()
        logger.info("Platform:   %s", type(self._platform).__name__)

        self._device_id = _get_device_id(self._platform)
        logger.info("Device ID:  %s", self._device_id)

        # HTTP session
        self._session = LinuxAgentSession(BASE_API_URL, self._state_dir, self._platform)
        self._session._device_id = self._device_id

        # Build ScanOrchestrator with Linux implementations injected
        self._orchestrator = ScanOrchestrator(
            base_dir=self._state_dir,
            existing_registry_fn=None,   # Linux: no registry
            agent_version=AGENT_VERSION,
            software_collector=self._platform.software_collector,
            binary_inspector=self._platform.binary_inspector,
            filesystem_walker=self._platform.filesystem_walker,
        )

        # ── Approval-sync idempotency lock (in-process single-flight guard) ──
        # The persisted approvalSyncStatus in join_state.json is the cross-restart
        # guard; this threading.Lock() prevents duplicate callbacks within one run.
        self._approval_sync_lock: threading.Lock = threading.Lock()

        # Install signal handlers
        self._platform.process_guard.register_signal_protection()
        from linux.protection.process_guard import get_shutdown_event
        self._shutdown_event = get_shutdown_event()

        # Register systemd persistence (runs on first boot, idempotent)
        self._register_persistence()

        # Socket.IO client
        self._sio = None

    # ── Persistence ────────────────────────────────────────────────────────────

    def _register_persistence(self) -> None:
        """Install the systemd unit so the agent starts on boot."""
        try:
            if not self._platform.persistence_manager.is_persistence_active():
                exe_path = os.path.abspath(sys.argv[0])
                ok = self._platform.persistence_manager.register_startup(
                    exe_path, daemon_args=["--daemon"]
                )
                if ok:
                    logger.info("systemd startup registered: agent will start on boot.")
                else:
                    logger.warning(
                        "systemd startup registration failed — may require root privileges. "
                        "Run with: sudo %s", exe_path
                    )
            else:
                logger.info("systemd startup already registered.")
        except Exception as exc:
            logger.debug("Persistence registration skipped: %s", exc)

    # ── Approval-sync idempotency helpers ──────────────────────────────────────

    def _claim_approval_sync(self) -> bool:
        """Atomically claim the approval-sync slot in the persisted join state.

        Returns True if this daemon invocation should run the full sync.
        Returns False if another invocation already completed or is in progress.

        Uses join_state.json as the cross-process idempotency record so the
        guard survives daemon restarts.
        """
        with self._approval_sync_lock:
            state = self._session.load_join_state()
            if not isinstance(state, dict) or str(state.get("status") or "").lower() != "approved":
                return False
            sync_status = str(state.get("approvalSyncStatus") or "").lower()
            request_id  = state.get("requestId") or state.get("approvalSyncRequestId") or "approved"
            # Already complete for this approval event → skip
            if sync_status == "complete" and state.get("approvalSyncRequestId") == request_id:
                return False
            # Already running (e.g. socket + poll both fired) → skip
            if sync_status == "in_progress":
                return False
            # Claim the slot
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
        hw = _build_hardware_profile(self._platform)
        fingerprint = self._platform.hardware_collector.collect_fingerprint()

        # Try to load existing JWT first
        if self._session.load_jwt():
            logger.info("Loaded saved JWT — attempting re-authentication")
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

        # Check for environment-variable codes (headless / scripted enrollment)
        team_code = os.environ.get("TEAM_CODE") or os.environ.get("ZEROWATCH_TEAM_CODE")
        individual_code = os.environ.get("INDIVIDUAL_CODE") or os.environ.get("ZEROWATCH_INDIVIDUAL_CODE")

        state = self._session.load_join_state()
        has_pending_join = str(state.get("status") or "").lower() in {"pending", "approved"}

        # If not pending and codes are not in environment, wait responsively (5s intervals)
        # matching Windows _wait_for_enrollment without 120-second backoff sleeps.
        if not has_pending_join and not team_code and not individual_code:
            logger.info(
                "[DAEMON_WAITING] Waiting for enrollment: team code in GUI OR "
                "env-var codes (device_id=%s)...",
                self._device_id,
            )
            wait_count = 0
            while not self._shutdown_event.is_set():
                # 1. Check if GUI completed enrollment and wrote a JWT
                if self._session.load_jwt():
                    try:
                        resp = self._session.get("/agent/info")
                        if resp.status_code == 200:
                            logger.info(
                                "[DAEMON_WAITING] JWT detected on disk and verified (device_id=%s).",
                                self._device_id,
                            )
                            return True
                    except Exception:
                        pass

                # 2. Check if GUI submitted a join request and wrote pending join state
                state = self._session.load_join_state()
                if str(state.get("status") or "").lower() in {"pending", "approved"}:
                    logger.info(
                        "[DAEMON_WAITING] Active enrollment detected (status=%s); "
                        "transitioning to approval polling (device_id=%s).",
                        state.get("status"), self._device_id,
                    )
                    has_pending_join = True
                    break

                # 3. Check for runtime env-var codes
                team_code       = os.environ.get("TEAM_CODE") or os.environ.get("ZEROWATCH_TEAM_CODE")
                individual_code = os.environ.get("INDIVIDUAL_CODE") or os.environ.get("ZEROWATCH_INDIVIDUAL_CODE")
                if team_code or individual_code:
                    logger.info("[DAEMON_WAITING] Enrollment code found in environment. Proceeding.")
                    break

                self._shutdown_event.wait(timeout=5)
                wait_count += 1
                if wait_count % 12 == 0:  # Log every ~60 seconds
                    logger.info(
                        "[DAEMON_WAITING] Still waiting for enrollment... (device_id=%s)",
                        self._device_id,
                    )

            if not has_pending_join and not team_code and not individual_code:
                return False

        if has_pending_join:
            logger.info(
                "[PENDING_APPROVAL] Resuming persisted enrollment; "
                "polling for administrator approval (device_id=%s).",
                self._device_id,
            )
            consecutive_errors = 0
            while not self._shutdown_event.is_set():
                # Check if GUI already validated and saved JWT
                if self._session.load_jwt():
                    try:
                        resp = self._session.get("/agent/info")
                        if resp.status_code == 200:
                            logger.info(
                                "[APPROVAL_DETECTED] Valid JWT detected; authenticated (device_id=%s).",
                                self._device_id,
                            )
                            return True
                    except Exception:
                        pass

                try:
                    response = self._session.get(
                        f"/agent/join-status?deviceId={self._device_id}"
                    )
                    if response.status_code == 200:
                        data = response.json()
                        status = str(data.get("status") or "").lower()
                        if status == "approved" and data.get("jwt"):
                            self._session.save_jwt(data["jwt"])
                            
                            # Refresh state from disk to avoid overwriting GUI changes
                            fresh_state = self._session.load_join_state() or {}
                            fresh_state["status"] = "approved"
                            fresh_state["teamCode"] = data.get("teamCode") or fresh_state.get("teamCode")
                            fresh_state["teamName"] = data.get("teamName") or fresh_state.get("teamName")
                            fresh_state["teamId"] = data.get("teamId") or fresh_state.get("teamId")
                            fresh_state["organizationName"] = data.get("organizationName") or fresh_state.get("organizationName")
                            fresh_state["requestId"] = data.get("requestId") or fresh_state.get("requestId")
                            fresh_state["deviceId"] = self._device_id
                            fresh_state["device_id"] = self._device_id
                            self._session.save_join_state(fresh_state)
                            
                            logger.info(
                                "[APPROVAL_DETECTED] Persisted enrollment approved; "
                                "daemon authenticated (device_id=%s).",
                                self._device_id,
                            )
                            consecutive_errors = 0
                            return True
                        if status == "denied":
                            logger.error(
                                "[ENROLLMENT] Persisted enrollment denied by administrator (device_id=%s).",
                                self._device_id,
                            )
                            clear_device_state(self._state_dir)
                            return False
                        # Still pending — reset error counter
                        consecutive_errors = 0
                    elif response.status_code in (401, 403, 404):
                        logger.warning(
                            "[ENROLLMENT] Join-status returned HTTP %d; clearing pending state.",
                            response.status_code,
                        )
                        clear_device_state(self._state_dir)
                        return False
                    else:
                        consecutive_errors += 1
                except Exception as exc:
                    consecutive_errors += 1
                    logger.debug(
                        "Persisted enrollment status check failed (attempt %d): %s",
                        consecutive_errors, exc,
                    )
                # Responsive 5-second polling (same as Windows time.sleep(5)), backed off only on errors
                wait = 5 if consecutive_errors < 3 else min(5 * (1 + consecutive_errors // 3), 30)
                self._shutdown_event.wait(timeout=wait)


        # 1. Team Code Join Flow
        if team_code:
            logger.info(
                "[ENROLLMENT_SUBMITTED] Requesting join for team code: %s (device_id=%s)",
                team_code, self._device_id,
            )
            payload = {
                "teamCode": team_code,
                "device_id": self._device_id,
                "hostname": socket.gethostname(),
                "username": os.environ.get("USER", "root"),
                "asset_name": socket.gethostname(),
                "os_info": {"name": "Linux", "version": AGENT_VERSION},
                "fingerprint_json": fingerprint,
            }
            try:
                resp = self._session.post("/agent/join-request", payload)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    status = data.get("status")
                    if status == "approved" and data.get("jwt"):
                        self._session.save_jwt(data.get("jwt"))
                        logger.info(
                            "[APPROVAL_DETECTED] Agent joined and approved immediately (device_id=%s).",
                            self._device_id,
                        )
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
                                        
                                        # Update join_state.json so _claim_approval_sync works
                                        fresh_state = self._session.load_join_state() or {}
                                        fresh_state["status"] = "approved"
                                        fresh_state["teamCode"] = status_data.get("teamCode") or fresh_state.get("teamCode")
                                        fresh_state["teamName"] = status_data.get("teamName") or fresh_state.get("teamName")
                                        fresh_state["teamId"] = status_data.get("teamId") or fresh_state.get("teamId")
                                        fresh_state["organizationName"] = status_data.get("organizationName") or fresh_state.get("organizationName")
                                        fresh_state["requestId"] = status_data.get("requestId") or fresh_state.get("requestId")
                                        self._session.save_join_state(fresh_state)

                                        logger.info(
                                            "[APPROVAL_DETECTED] Device join approved! "
                                            "Enrollment completed (device_id=%s).",
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
                        "Join request failed: HTTP %d -- %s", resp.status_code, resp.text[:200]
                    )
            except Exception as exc:
                logger.error("Join request error: %s", exc)

        # 2. Individual Code Flow
        elif individual_code:
            logger.info(
                "[ENROLLMENT_SUBMITTED] Enrolling individual agent with code: %s (device_id=%s)",
                individual_code, self._device_id,
            )
            payload = {
                "individualCode": individual_code,
                "device_id": self._device_id,
                "hostname": socket.gethostname(),
                "username": os.environ.get("USER", "root"),
                "asset_name": socket.gethostname(),
                "os_info": {"name": "Linux", "version": AGENT_VERSION},
                "fingerprint_json": fingerprint,
            }
            try:
                resp = self._session.post("/agent/individual-enroll", payload)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    token = data.get("jwt")
                    if token:
                        self._session.save_jwt(token)
                        logger.info(
                            "[APPROVAL_DETECTED] Agent enrolled and linked (device_id=%s).",
                            self._device_id,
                        )
                        return True
                    logger.error("Individual enrollment succeeded but no token returned.")
                else:
                    logger.error(
                        "Individual enrollment failed: HTTP %d -- %s",
                        resp.status_code, resp.text[:200],
                    )
            except Exception as exc:
                logger.error("Individual enrollment error: %s", exc)

        return False

    def _sync_full(self, software: list, hardware: dict | None = None,
                   inventory_scope: str = "complete",
                   batch_index: int = 1, batch_count: int = 1) -> int:
        """Push full software inventory and hardware profile to backend."""
        if hardware is None:
            try:
                hardware = self._platform.hardware_collector.get_detailed_hardware_profile()
            except Exception as hw_exc:
                logger.warning("Hardware profile collection failed: %s", hw_exc)
                hardware = {}

        payload = {
            "deviceId":  self._device_id,
            "device_id": self._device_id,
            "software":  software,
            "inventory": software,
            "hardware":  hardware,
            "inventoryScope": inventory_scope,
            "inventoryRevision": time.time_ns(),
            "batch_index": batch_index,
            "batch_count": batch_count,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        try:
            resp = self._session.post("/agent/sync/full", payload, timeout=60)
            if resp.status_code in (200, 201, 204):
                logger.info("Full sync: %d items and hardware profile synced", len(software))
                return resp.status_code
            logger.warning("Full sync failed: HTTP %d", resp.status_code)
            return resp.status_code
        except Exception as exc:
            logger.warning("Full sync error: %s", exc)
            return 0

    def _sync_complete_inventory(self, software_list: list, hardware: dict | None = None,
                                 inventory_scope: str = "complete") -> bool:
        """Sync complete inventory, falling back to chunked delivery only on HTTP 413.

        Attempts a single sync_full request first (fastest and atomic).
        Only falls back to chunking if the backend or proxy returns HTTP 413
        (Payload Too Large) or connection drops.
        """
        items = list(software_list or [])
        if not items:
            return False

        # Attempt atomic single-request upload first
        status_code = self._sync_full(items, hardware, inventory_scope=inventory_scope)
        if status_code in (200, 201, 204):
            return True
        if status_code not in (413, 0):
            return False

        logger.info("[SYNC] Full sync returned %d; falling back to chunked delivery.", status_code)

        batches = []
        current = []
        current_size = 0
        for item in items:
            item_size = len(json.dumps(item, default=str, separators=(",", ":")))
            if current and (current_size + item_size > 256 * 1024 or len(current) >= 400):
                batches.append(current)
                current, current_size = [], 0
            current.append(item)
            current_size += item_size
        if current:
            batches.append(current)

        batch_count = len(batches)
        logger.info("[SYNC] Chunking inventory (%d items) into %d requests.", len(items), batch_count)
        first_status = self._sync_full(
            batches[0], hardware, inventory_scope=inventory_scope,
            batch_index=1, batch_count=batch_count,
        )
        if first_status not in (200, 201, 204):
            return False

        for index, batch in enumerate(batches[1:], start=2):
            if not self._sync_delta(
                batch, [], inventory_scope=inventory_scope,
                batch_index=index, batch_count=batch_count,
            ):
                logger.warning("[SYNC] Inventory chunk %d/%d failed.", index, batch_count)
                return False
        logger.info("[SYNC] Chunked inventory sync finished: %d items delivered.", len(items))
        return True

    def _sync_delta(self, added: list, removed: list,
                    inventory_scope: str = "delta",
                    batch_index: int = 1, batch_count: int = 1) -> bool:
        """Push incremental delta to backend."""
        if not added and not removed:
            return True
        payload = {
            "deviceId": self._device_id,
            "added":    added,
            "removed":  removed,
            "inventoryScope": inventory_scope,
            "batch_index": batch_index,
            "batch_count": batch_count,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        try:
            resp = self._session.post("/agent/sync/delta", payload, timeout=60)
            if resp.status_code in (200, 201, 204):
                logger.info("Delta sync: +%d -%d items", len(added), len(removed))
                return True
            logger.warning("Delta sync failed: HTTP %d", resp.status_code)
            return resp.status_code in (200, 201, 204)
        except Exception as exc:
            logger.warning("Delta sync error: %s", exc)
            return False

    def _heartbeat(self) -> bool:
        """Send periodic heartbeat."""
        payload = {
            "deviceId":   self._device_id,
            "timestamp":  datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agentVersion": AGENT_VERSION,
            "platform":   "linux",
        }
        try:
            resp = self._session.post("/agent/heartbeat", payload)
            if resp.status_code == 404:
                logger.warning("Heartbeat returned HTTP 404. Device unlinked remotely.")
                self._handle_unlinked()
                return False
            return resp.status_code in (200, 204)
        except Exception as exc:
            logger.debug("Heartbeat error: %s", exc)
            return False

    def _handle_unlinked(self) -> None:
        """Handle backend reporting the device is unlinked."""
        logger.warning("Handling remote unlink. Clearing state...")
        self._orchestrator.close()
        clear_device_state(self._state_dir)
        self._session.clear_jwt()
        # systemd will restart the daemon automatically
        sys.exit(0)

    def _sync_full_with_retry(self, software: list, hardware: dict | None = None,
                              inventory_scope: str = "complete") -> bool:
        """Push full software inventory and hardware profile to backend with 413 chunking fallback, retrying up to 3 times on failure."""
        for attempt in range(3):
            if self._shutdown_event.is_set():
                return False
            if self._sync_complete_inventory(software, hardware, inventory_scope=inventory_scope):
                return True
            logger.warning("Full sync attempt %d/3 failed. Retrying in 15s...", attempt + 1)
            self._shutdown_event.wait(timeout=15)
        logger.error("Full sync failed after 3 attempts — inventory will retry on next delta cycle.")
        return False

    def _initial_scan_and_sync(self, approval_sync_claimed: bool = False) -> None:
        """Run two-stage post-enrollment scan:
        1. Immediate Layer 0 baseline (package managers: dpkg/rpm/pacman/snap/flatpak)
           published to backend immediately within ~10 seconds of joining.
        2. Background Layer 1 + 2 startup scan (priority filesystem, ELF, manifests)
           published to backend as complete inventory within ~1 minute of joining.
        """
        if not hasattr(self, "_initial_scan_done"):
            self._initial_scan_done = threading.Event()

        if not approval_sync_claimed:
            logger.info("[STARTUP_SCAN] Approval sync not claimed; skipping initial scan.")
            self._initial_scan_done.set()
            return

        # Collect full hardware profile
        try:
            hardware = self._platform.hardware_collector.get_detailed_hardware_profile()
        except Exception as hw_exc:
            logger.warning("Hardware collection failed: %s", hw_exc)
            hardware = {}

        # ── Stage 1: Fast Immediate Layer 0 Baseline Sync (<1s collection, immediate send) ──
        raw_items = []
        try:
            raw_items = self._platform.software_collector.collect_software()
            l0_items = []
            for item in raw_items:
                try:
                    if hasattr(item, "to_api_dict"):
                        l0_items.append(item.to_api_dict())
                    elif isinstance(item, dict):
                        l0_items.append(item)
                    else:
                        l0_items.append({
                            "name":     getattr(item, "name", ""),
                            "version":  getattr(item, "version", ""),
                            "vendor":   getattr(item, "vendor", ""),
                            "source":   getattr(item, "source", "package"),
                            "category": getattr(item, "category", "software"),
                        })
                except Exception:
                    pass

            logger.info(
                "[STARTUP_SCAN] Publishing initial Layer 0 baseline (%d items, device_id=%s)...",
                len(l0_items), self._device_id,
            )
            l0_ok = self._sync_full_with_retry(l0_items, hardware, inventory_scope="partial")
            logger.info(
                "[STARTUP_SCAN] Initial Layer 0 baseline synced to backend: %s (%d items).",
                l0_ok, len(l0_items),
            )

            # Seed orchestrator snapshot so subsequent deltas are accurate
            try:
                with self._orchestrator._snapshot_lock:
                    for item in raw_items:
                        if hasattr(item, "dedup_key"):
                            self._orchestrator._last_snapshot[item.dedup_key()] = item
            except Exception as seed_exc:
                logger.debug("Snapshot seed skipped: %s", seed_exc)
        except Exception as l0_exc:
            logger.error("[STARTUP_SCAN] Immediate Layer 0 baseline failed: %s", l0_exc, exc_info=True)

        # ── Stage 2: Background Layer 1 + 2 Priority Startup Scan ──────────
        def _run_deep_startup():
            started = time.perf_counter()
            logger.info(
                "[STARTUP_SCAN] Background priority L1/L2 scan started "
                "(device_id=%s, approval_claimed=%s).",
                self._device_id, approval_sync_claimed,
            )
            sync_ok = False
            try:
                startup_items = self._orchestrator.run_startup_scan(
                    stop_event=self._shutdown_event,
                )
                if startup_items and self._session._jwt:
                    logger.info(
                        "[INVENTORY_UPLOAD_STARTED] device_id=%s items=%d",
                        self._device_id, len(startup_items),
                    )
                    sync_ok = self._sync_full_with_retry(startup_items, hardware, inventory_scope="complete")
                    logger.info(
                        "[STARTUP_SCAN] Complete inventory synced: %d items in %.1fs (device_id=%s, success=%s).",
                        len(startup_items), time.perf_counter() - started, self._device_id, sync_ok,
                    )
                    if approval_sync_claimed:
                        self._finish_approval_sync(sync_ok)
                        logger.info("[FULL_SYNC_COMPLETED] device_id=%s", self._device_id)
            except Exception as exc:
                logger.error(
                    "[STARTUP_SCAN] Background deep scan error (device_id=%s): %s",
                    self._device_id, exc, exc_info=True,
                )
                if approval_sync_claimed:
                    self._finish_approval_sync(False)
            finally:
                self._initial_scan_done.set()
                if self._session._jwt and not self._shutdown_event.is_set():
                    try:
                        self._orchestrator.start_periodic_scans(on_delta=self._on_fs_delta)
                        logger.info("Periodic filesystem scans started after initial deep scan.")
                    except Exception as p_exc:
                        logger.warning("Failed to start periodic filesystem scans: %s", p_exc)

        scan_thread = threading.Thread(
            target=_run_deep_startup, daemon=True, name="initial-startup-scan",
        )
        scan_thread.start()
        logger.info("[STARTUP_SCAN] Background priority scan queued immediately after Layer 0 baseline.")

    def _on_fs_delta(self, added_items: list, removed_items: list) -> None:
        """
        Callback from start_periodic_scans() — push L1/L2 ELF/manifest deltas to backend.
        NOTE: added_items / removed_items are already List[dict] (converted by
        _emit_fs_delta inside the orchestrator). Do NOT wrap with _items_to_dicts().
        """
        if (added_items or removed_items) and self._session._jwt:
            self._sync_delta(added_items, removed_items)

    def _monitor_loop(self) -> None:
        """
        Background thread: fast L0 registry delta every 60s.
        L1/L2 filesystem deltas are handled by start_periodic_scans() (4h priority / 24h deep).
        This mirrors the Windows agent's two-tier scan architecture.
        """
        last_heartbeat  = time.monotonic()
        last_l0_delta   = time.monotonic()
        L0_INTERVAL     = 60   # seconds between L0 (package manager) delta scans

        while not self._shutdown_event.is_set() and not self._stop_event.is_set():
            now = time.monotonic()

            # ── Heartbeat ──────────────────────────────────────────────────
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                self._heartbeat()
                last_heartbeat = now

            # ── Fast L0 delta (dpkg/rpm/pacman/snap/flatpak/etc.) ──────────
            if now - last_l0_delta >= L0_INTERVAL:
                try:
                    added, removed = self._orchestrator.run_registry_delta()
                    if added or removed:
                        self._sync_delta(added, removed)
                    last_l0_delta = now
                except Exception as exc:
                    logger.warning("L0 delta scan error: %s", exc)

            time.sleep(5)

    def run(self) -> int:
        """Main blocking run loop. Returns process exit code."""
        # Register/authenticate
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

        # ── Send immediate heartbeat right after enrollment/auth ──────────────
        # This keeps lastSeen fresh while the initial scan (up to 60s) runs.
        # Without this, the backend marks the device Offline before the first
        # heartbeat from _monitor_loop fires (which starts only after the scan).
        logger.info("Sending immediate post-enrollment heartbeat...")
        self._heartbeat()

        # ── Start monitor thread BEFORE the scan ──────────────────────────────
        # The scan can block for up to 60s. Starting heartbeats early ensures
        # the backend never drops the device to Offline during that window.
        monitor = threading.Thread(target=self._monitor_loop, daemon=True, name="linux-monitor")
        monitor.start()
        logger.info("Heartbeat monitor started (interval=%ds).", HEARTBEAT_INTERVAL)

        # Approval-sync idempotency check (matching Windows behavior)
        approval_sync_claimed = self._claim_approval_sync()
        approval_sync_already_complete = self._approval_sync_complete()

        if approval_sync_already_complete:
            logger.info(
                "[ENROLLMENT] Approval sync already complete; skipping duplicate startup sync (device_id=%s).",
                self._device_id,
            )
        elif not approval_sync_claimed:
            logger.info(
                "[ENROLLMENT] Approval sync claimed by another worker; skipping duplicate startup sync (device_id=%s).",
                self._device_id,
            )
        else:
            logger.info(
                "[ENROLLMENT] Approval claimed by Linux daemon; "
                "starting complete inventory sync (device_id=%s).",
                self._device_id,
            )
            # Initial startup scan (L0 + priority L1/L2 within 60s)
            self._initial_scan_and_sync(approval_sync_claimed=True)
            self._initial_scan_done.wait()

        # Start background L1/L2 filesystem scans (4h priority / 24h deep)
        self._orchestrator.start_periodic_scans(on_delta=self._on_fs_delta)
        logger.info("Periodic filesystem scan started (4h priority / 24h deep).")

        ota_monitor = None
        try:
            ota_monitor = start_daemon_ota_monitor(
                os.path.abspath(sys.argv[0]), AGENT_VERSION, self._shutdown_event,
                check_interval=RESTART_CHECK_TIME
            )
        except Exception:
            logger.exception("Failed to start daemon OTA monitor; continuing without OTA")

        logger.info("ZeroWatch Linux Agent running. Press Ctrl+C to stop.")

        # Block until shutdown signal received
        self._shutdown_event.wait()

        logger.info("Shutdown signal received — stopping agent")
        self._stop_event.set()

        # Stop filesystem scanner before joining monitor thread
        try:
            self._orchestrator.stop_periodic_scans(timeout=10)
        except Exception as exc:
            logger.debug("Orchestrator stop error (non-fatal): %s", exc)

        monitor.join(timeout=10)
        if ota_monitor is not None:
            ota_monitor.stop()

        # Cleanup build-time config
        try:
            cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_build_config.py")
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except Exception:
            pass

        logger.info("ZeroWatch Linux Agent stopped cleanly")
        return 0


# Alias for import compatibility from sentinel_agent.py
LinuxSentinelAgent = LinuxAgent

# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    # Development mode check
    if not BASE_API_URL:
        print("[ERROR] No API URL configured.")
        print("        Run via run_agent.sh or set ZEROWATCH_API_URL environment variable.")
        return 1

    agent = LinuxAgent()
    return agent.run()


if __name__ == "__main__":
    sys.exit(main())
