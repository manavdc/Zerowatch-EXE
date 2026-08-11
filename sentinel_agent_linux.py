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
import socketio
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
    BASE_API_URL = os.environ.get("ZEROWATCH_API_URL", "http://localhost:3001/api")

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
        "MZ4Kk+NPs6uc35JlOBNODqa+AZvqgtCq+sSjXx9W/k4=",
        "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4="
    ],
    "zerowatch-testing.eastasia.cloudapp.azure.com": [
        "SOt+phzxLXUaMmNKG6d4kz7QTSoip7zJudN8vGJNdI4=",
        "EzSBE12fT2ZrphmumaBjrpdpXv9G71RhZQHMvuwszI4="
    ],
}

# ── Logging ───────────────────────────────────────────────────────────────────

def _configure_logging():
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[logging.StreamHandler(sys.stdout)],
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
)

def _get_state_dir() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    system_dir = "/var/lib/zerowatch/state"
    user_dir   = os.path.expanduser("~/.local/share/zerowatch/state")
    local_dir  = os.path.join(base, "state")

    # ── Try system dir first (preferred — consistent across UIDs) ──────
    try:
        os.makedirs(system_dir, mode=0o700, exist_ok=True)
        _probe = os.path.join(system_dir, ".write_probe")
        with open(_probe, "w") as _fh:
            _fh.write("x")
        os.remove(_probe)
        return system_dir                          # writable → use it
    except OSError:
        pass  # root-owned or missing; fall through to user-dir

    # ── System dir not writable. Find the first user-writable fallback ─
    for fallback in (user_dir, local_dir):
        try:
            os.makedirs(fallback, mode=0o700, exist_ok=True)
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
        pins = SPKI_PINS.get(hostname, [])
        adapter = build_pinning_adapter(pins)
        sess = requests.Session()
        sess.mount("https://", adapter)
        return sess

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
        if not os.path.exists(self._jwt_path):
            return False
        try:
            with open(self._jwt_path, "rb") as fh:
                enc = fh.read()
            raw = self._decrypt(enc)
            if raw:
                self._jwt = raw.decode("utf-8").strip()
                return bool(self._jwt)
        except Exception as exc:
            logger.debug("JWT load failed: %s", exc)
        return False

    def save_jwt(self, token: str) -> None:
        """Encrypt and save JWT to disk."""
        self._jwt = token
        enc = self._encrypt(token.encode("utf-8"))
        if enc:
            try:
                with open(self._jwt_path, "wb") as fh:
                    fh.write(enc)
                os.chmod(self._jwt_path, 0o600)
            except OSError as exc:
                logger.warning("JWT save failed: %s", exc)

    def clear_jwt(self) -> None:
        self._jwt = ""
        try:
            os.remove(self._jwt_path)
        except OSError:
            pass

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

    def __init__(self):
        _configure_logging()
        self._stop_event = threading.Event()
        self._state_dir  = _get_state_dir()
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

        # Build ScanOrchestrator with Linux implementations injected
        self._orchestrator = ScanOrchestrator(
            base_dir=self._state_dir,
            existing_registry_fn=None,   # Linux: no registry
            agent_version=AGENT_VERSION,
            software_collector=self._platform.software_collector,
            binary_inspector=self._platform.binary_inspector,
            filesystem_walker=self._platform.filesystem_walker,
        )

        # Install signal handlers
        self._platform.process_guard.register_signal_protection()
        from linux.protection.process_guard import get_shutdown_event
        self._shutdown_event = get_shutdown_event()

        # Socket.IO client
        self._sio = None

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

        # Retrieve codes from environment variables (same as Windows)
        team_code = os.environ.get("TEAM_CODE") or os.environ.get("ZEROWATCH_TEAM_CODE")
        individual_code = os.environ.get("INDIVIDUAL_CODE") or os.environ.get("ZEROWATCH_INDIVIDUAL_CODE")

        if not team_code and not individual_code:
            logger.warning(
                "No enrollment code found in environment. "
                "Set TEAM_CODE=<your-team-code> or INDIVIDUAL_CODE=<your-code> "
                "then restart the agent, OR enroll the device from the ZeroWatch dashboard."
            )
            # Poll every 30s for an env var to appear (e.g. set by a parent wrapper script)
            # This ensures the agent does NOT send a fake "123456" to production.
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

        # 1. Team Code Join Flow
        if team_code:
            logger.info("Requesting join for team code: %s", team_code)
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
                        logger.info("Agent joined and approved immediately.")
                        return True
                    
                    logger.info("Join request status: %s. Awaiting admin approval...", status)
                    # Poll status (same as Windows poll_join_status)
                    start_poll = time.time()
                    while time.time() - start_poll < 600:
                        if self._shutdown_event.is_set():
                            return False
                        time.sleep(8)
                        status_resp = self._session.get(f"/agent/join-status?deviceId={self._device_id}")
                        if status_resp.status_code == 200:
                            status_data = status_resp.json()
                            if status_data.get("status") == "approved":
                                token = status_data.get("jwt")
                                if token:
                                    self._session.save_jwt(token)
                                    logger.info("Device join approved! Enrollment completed.")
                                    return True
                            elif status_data.get("status") == "denied":
                                logger.error("Device join denied by admin.")
                                return False
                else:
                    logger.error("Join request failed: HTTP %d — %s", resp.status_code, resp.text[:200])
            except Exception as exc:
                logger.error("Join request error: %s", exc)

        # 2. Individual Code Flow
        elif individual_code:
            logger.info("Enrolling individual agent with code: %s", individual_code)
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
                        logger.info("Agent successfully enrolled and linked.")
                        return True
                    logger.error("Individual enrollment succeeded but no token returned.")
                else:
                    logger.error("Individual enrollment failed: HTTP %d — %s", resp.status_code, resp.text[:200])
            except Exception as exc:
                logger.error("Individual enrollment error: %s", exc)

        return False

    def _sync_full(self, software: list) -> bool:
        """Push full software inventory to backend."""
        payload = {
            "deviceId": self._device_id,
            "software": software,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        try:
            resp = self._session.post("/agent/sync/full", payload, timeout=60)
            if resp.status_code in (200, 201, 204):
                logger.info("Full sync: %d items synced", len(software))
                return True
            logger.warning("Full sync failed: HTTP %d", resp.status_code)
        except Exception as exc:
            logger.warning("Full sync error: %s", exc)
        return False

    def _sync_delta(self, added: list, removed: list) -> bool:
        """Push incremental delta to backend."""
        if not added and not removed:
            return True
        payload = {
            "deviceId": self._device_id,
            "added":    added,
            "removed":  removed,
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
        """Send periodic heartbeat."""
        payload = {
            "deviceId":   self._device_id,
            "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
            "agentVersion": AGENT_VERSION,
            "platform":   "linux",
        }
        try:
            resp = self._session.post("/agent/heartbeat", payload)
            return resp.status_code in (200, 204)
        except Exception as exc:
            logger.debug("Heartbeat error: %s", exc)
            return False

    def _sync_full_with_retry(self, software: list) -> bool:
        """Push full software inventory to backend, retrying up to 3 times on failure."""
        for attempt in range(3):
            if self._shutdown_event.is_set():
                return False
            if self._sync_full(software):
                return True
            logger.warning("Full sync attempt %d/3 failed. Retrying in 15s...", attempt + 1)
            self._shutdown_event.wait(timeout=15)
        logger.error("Full sync failed after 3 attempts — inventory will retry on next delta cycle.")
        return False

    def _initial_scan_and_sync(self) -> None:
        """Run full L0 scan and push to backend immediately."""
        logger.info("Running initial full scan (L0 — registry/packages)...")
        try:
            items = self._orchestrator.run_full_scan(
                include_filesystem=False,  # L0 only; filesystem handled by start_periodic_scans()
                stop_event=self._shutdown_event,
            )
            logger.info("Initial L0 scan: %d software items", len(items))
            self._sync_full_with_retry(items)
        except Exception as exc:
            logger.error("Initial scan failed: %s", exc, exc_info=True)

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
        max_retries = 5
        for attempt in range(max_retries):
            if self._shutdown_event.is_set():
                return 0
            if self._register_or_authenticate():
                break
            wait = min(RECONNECT_DELAY * (2 ** attempt), 120)
            logger.info("Retrying in %ds (attempt %d/%d)...", wait, attempt + 1, max_retries)
            self._shutdown_event.wait(timeout=wait)
        else:
            logger.error("Could not authenticate after %d attempts — exiting", max_retries)
            return 1

        # Initial L0 scan (fast — package managers only)
        self._initial_scan_and_sync()

        # Start background L1/L2 filesystem scans (4h priority / 24h deep)
        self._orchestrator.start_periodic_scans(on_delta=self._on_fs_delta)
        logger.info("Periodic filesystem scan started (4h priority / 24h deep).")

        ota_monitor = None
        try:
            ota_monitor = start_daemon_ota_monitor(
            os.path.abspath(sys.argv[0]), AGENT_VERSION, self._shutdown_event
            )
        except Exception:
            logger.exception("Failed to start daemon OTA monitor; continuing without OTA")

        # Start background L0 monitor thread (heartbeat + 60s registry delta)
        monitor = threading.Thread(target=self._monitor_loop, daemon=True, name="linux-monitor")
        monitor.start()

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
