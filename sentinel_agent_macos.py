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
else:
    BASE_API_URL = os.environ.get("ZEROWATCH_API_URL", "http://localhost:3001/api")

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


# ── State directory ───────────────────────────────────────────────────────────

def _get_state_dir() -> str:
    """
    Return the best available writable state directory.
    Order: /var/lib/zerowatch/state → ~/.local/share/zerowatch/state → ./state/
    """
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        "/var/lib/zerowatch/state",
        os.path.expanduser("~/.local/share/zerowatch/state"),
        os.path.join(base, "state"),
    ]
    for path in candidates:
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
            test = os.path.join(path, ".write_test")
            with open(test, "w") as fh:
                fh.write("x")
            os.remove(test)
            return path
        except OSError:
            continue
    return os.path.join(base, "state")


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
        """
        try:
            result = self._platform.secure_store.encrypt(data)
            if result is not None:
                return result
            # Keychain unavailable — store raw bytes as base64 in state dir
            logger.warning(
                "Keychain unavailable — storing token unprotected in state dir. "
                "This is expected during development on non-macOS hosts."
            )
            import base64
            return b"RAW::" + base64.b64encode(data)
        except Exception as exc:
            logger.warning("SecureStore encrypt failed: %s", exc)
            return None

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
            if hasattr(item, "to_api_dict"):
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
                ok = self._platform.persistence_manager.register_startup(exe_path)
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

    def _register_or_authenticate(self) -> bool:
        """Join the device or authenticate with saved JWT."""
        hw          = _build_hardware_profile(self._platform)
        fingerprint = self._platform.hardware_collector.collect_fingerprint()
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
                logger.info("JWT rejected (HTTP %d) — re-joining", resp.status_code)
                self._session.clear_jwt()
            except Exception as exc:
                logger.warning("Auth check failed: %s", exc)
                self._session.clear_jwt()

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

                    logger.info("Join request status: %s. Awaiting admin approval...", status)
                    # Poll for admin approval (same pattern as Windows / Linux agents)
                    poll_start = time.time()
                    while time.time() - poll_start < 600:
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
                                    logger.info("Device approved! Enrollment complete.")
                                    return True
                            elif status_data.get("status") == "denied":
                                logger.error("Device join denied by admin.")
                                return False
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

    def _sync_full(self, software: list, hardware: dict) -> bool:
        """Push full software + hardware inventory to backend."""
        payload = {
            "deviceId":  self._device_id,
            "software":  software,
            "hardware":  hardware,
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

    def _sync_full_with_retry(self, software: list, hardware: dict) -> bool:
        """Push full inventory, retrying up to 3 times on transient failures."""
        for attempt in range(3):
            if self._shutdown_event.is_set():
                return False
            if self._sync_full(software, hardware):
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
        payload = {
            "deviceId":     self._device_id,
            "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
            "agentVersion": AGENT_VERSION,
            "platform":     "macos",
        }
        try:
            resp = self._session.post("/agent/heartbeat", payload)
            return resp.status_code in (200, 204)
        except Exception as exc:
            logger.debug("Heartbeat error: %s", exc)
            return False

    # ── Scan phases ────────────────────────────────────────────────

    def _initial_scan_and_sync(self) -> None:
        """
        Fast L0 scan: app bundles, pkgutil, Homebrew, MacPorts, macOS version.
        Completes in < 5s and sends the first inventory to the dashboard immediately.
        L1 (Mach-O filesystem) and L2 (manifests) are handled by start_periodic_scans().
        """
        logger.info("Running initial L0 scan (app bundles, pkgutil, Homebrew, macOS version)...")
        try:
            items = self._orchestrator.run_full_scan(
                include_filesystem=False,   # L0 only on cold start
                stop_event=self._shutdown_event,
            )
            logger.info("Initial L0 scan: %d software items", len(items))
            hw = _build_hardware_profile(self._platform)
            self._sync_full_with_retry(items, hw)
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

        while not self._shutdown_event.is_set() and not self._stop_event.is_set():
            now = time.monotonic()

            # ── Heartbeat ──────────────────────────────────────────────────
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                self._heartbeat()
                last_heartbeat = now

            if now - last_delta >= MONITOR_INTERVAL:
                try:
                    added, removed = self._orchestrator.run_delta_scan()
                    if added or removed:
                        self._sync_delta(
                            _items_to_dicts(added),
                            _items_to_dicts(removed),
                        )
                    last_delta = now
                except Exception as exc:
                    logger.warning("Delta scan error: %s", exc)

            time.sleep(5)

    # ── Main run loop ──────────────────────────────────────────────────────────

    def run(self) -> int:
        """Main blocking run loop. Returns process exit code."""
        # Authenticate / enroll (with retry backoff)
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

        # Initial scan (L0 fast, then L1+L2)
        self._initial_scan_and_sync()

        # Start background monitor thread
        monitor = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="macos-monitor",
        )
        monitor.start()

        logger.info("ZeroWatch macOS Agent running. Press Ctrl+C or send SIGTERM to stop.")

        # Block until shutdown signal (SIGTERM/SIGINT via process_guard)
        self._shutdown_event.wait()

        logger.info("Shutdown signal received — stopping macOS agent")
        self._stop_event.set()
        monitor.join(timeout=10)

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

    agent = MacOSAgent()
    return agent.run()


if __name__ == "__main__":
    sys.exit(main())
