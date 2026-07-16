import requests
import winreg
import uuid
import subprocess
import json
import datetime
import os
import csv
import sys
import time
import getpass
import threading
import hashlib
import hmac
import ctypes
import ctypes.wintypes as wt
import signal
import logging
import re
import socket
import socketio
from urllib.parse import urlparse
import requests

# === CRASH DIAGNOSTICS ===
import traceback

def _global_crash_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    
    # Try to write to Desktop
    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        log_file = os.path.join(desktop, "SentinelAgent_crash.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(msg)
    except Exception:
        pass
        
    # Show MessageBox
    try:
        ctypes.windll.user32.MessageBoxW(
            0,
            f"Failed to start Sentinel Agent:\n{exc_value}\n\nCheck Desktop\\SentinelAgent_crash.log for details.",
            "Error",
            0x10,
        )
    except Exception:
        pass
    
    sys.exit(1)

sys.excepthook = _global_crash_handler
# === END CRASH DIAGNOSTICS ===

def _setup_tcl_tk_paths():
    return # Disabled to let Nuitka plugin handle it!
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if "onefile_" in current_dir and "TEMP" in current_dir:
        tcl86_dir = os.path.join(current_dir, "tcl8.6")
        tcl_dir = os.path.join(current_dir, "tcl")
        tk86_dir = os.path.join(current_dir, "tk8.6")
        tk_dir = os.path.join(current_dir, "tk")
        
        import shutil
        
        # If we have tcl8.6 but not tcl, copy files to tcl
        if os.path.isdir(tcl86_dir) and not os.path.isfile(os.path.join(tcl_dir, "init.tcl")):
            try:
                os.makedirs(tcl_dir, exist_ok=True)
                for item in os.listdir(tcl86_dir):
                    s = os.path.join(tcl86_dir, item)
                    d = os.path.join(tcl_dir, item)
                    if os.path.isdir(s):
                        shutil.copytree(s, d, dirs_exist_ok=True)
                    else:
                        shutil.copy2(s, d)
            except Exception:
                pass
                
        # If we have tk8.6 but not tk, copy files to tk
        if os.path.isdir(tk86_dir) and not os.path.isfile(os.path.join(tk_dir, "tk.tcl")):
            try:
                os.makedirs(tk_dir, exist_ok=True)
                for item in os.listdir(tk86_dir):
                    s = os.path.join(tk86_dir, item)
                    d = os.path.join(tk_dir, item)
                    if os.path.isdir(s):
                        shutil.copytree(s, d, dirs_exist_ok=True)
                    else:
                        shutil.copy2(s, d)
            except Exception:
                pass
                
        # Set environment variables to the 'tcl' and 'tk' folders which the error message looks for
        os.environ["TCL_LIBRARY"] = tcl_dir
        os.environ["TK_LIBRARY"] = tk_dir
        return

    def _has_tcl(path):
        return bool(path) and os.path.isfile(os.path.join(path, "init.tcl"))

    def _has_tk(path):
        return bool(path) and os.path.isfile(os.path.join(path, "tk.tcl"))

    tcl_env = os.environ.get("TCL_LIBRARY")
    tk_env = os.environ.get("TK_LIBRARY")
    if tcl_env and os.path.isdir(tcl_env):
        tcl_candidate = os.path.join(tcl_env, "tcl8.6")
        if _has_tcl(tcl_candidate):
            os.environ["TCL_LIBRARY"] = tcl_candidate
            tcl_env = tcl_candidate
    if (not tk_env) and tcl_env:
        tcl_parent = os.path.dirname(tcl_env)
        tk_candidate = os.path.join(tcl_parent, "tk8.6")
        if _has_tk(tk_candidate):
            os.environ["TK_LIBRARY"] = tk_candidate
            tk_env = tk_candidate

    if tcl_env and not _has_tcl(tcl_env):
        os.environ.pop("TCL_LIBRARY", None)
        tcl_env = None
    if tk_env and not _has_tk(tk_env):
        os.environ.pop("TK_LIBRARY", None)
        tk_env = None
    if tcl_env and tk_env:
        return

    candidates = []
    try:
        candidates.append(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        pass
    try:
        candidates.append(__nuitka_binary_dir)  # noqa: F821
    except NameError:
        pass

    def _first_valid(paths, predicate):
        for path in paths:
            try:
                if predicate(path):
                    return path
            except Exception:
                continue
        return None

    for base in candidates:
        tcl_candidates = [
            os.path.join(base, "tcl"),
            os.path.join(base, "tcl", "tcl8.6"),
            os.path.join(base, "tcl8.6"),
        ]
        tk_candidates = [
            os.path.join(base, "tk"),
            os.path.join(base, "tcl", "tk8.6"),
            os.path.join(base, "tk8.6"),
        ]
        tcl_dir = _first_valid(tcl_candidates, _has_tcl)
        tk_dir = _first_valid(tk_candidates, _has_tk)
        if tcl_dir:
            os.environ["TCL_LIBRARY"] = tcl_dir
        if tk_dir:
            os.environ["TK_LIBRARY"] = tk_dir
        if os.environ.get("TCL_LIBRARY") and os.environ.get("TK_LIBRARY"):
            break

    if not (os.environ.get("TCL_LIBRARY") and os.environ.get("TK_LIBRARY")):
        for base in candidates:
            tcl_root = os.path.join(base, "tcl")
            if not os.path.isdir(tcl_root):
                continue
            found_tcl = None
            found_tk = None
            for root, _, files in os.walk(tcl_root):
                if not found_tcl and "init.tcl" in files:
                    found_tcl = root
                if not found_tk and "tk.tcl" in files:
                    found_tk = root
                if found_tcl and found_tk:
                    break
            if found_tcl:
                os.environ["TCL_LIBRARY"] = found_tcl
            if found_tk:
                os.environ["TK_LIBRARY"] = found_tk
            if os.environ.get("TCL_LIBRARY") and os.environ.get("TK_LIBRARY"):
                break

_setup_tcl_tk_paths()


import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

import math

AGENT_VERSION = "1.1.1"
KILL_PASSWORD = "Pass@123" # Fallback offline password
MUTEX_NAME = "Global\\SentinelAgent_ZeroWatch_4F9A2E1B"
WATCHDOG_MUTEX_NAME = "Global\\SentinelAgent_Watchdog_4F9A2E1B"
PROMPT_MUTEX_NAME = "Global\\SentinelAgent_Prompt_4F9A2E1B"  # Prevents multiple password prompts
HEARTBEAT_INTERVAL = 120  # Reduced from 60 to lower CPU
MONITOR_INTERVAL = 60     # Reduced from 30 to lower CPU
OFFLINE_FLUSH_MIN_INTERVAL = 15
OFFLINE_FLUSH_MAX_INTERVAL = 300
USERNAME_MAX_LENGTH = 20
ASSETNAME_MAX_LENGTH = 20
HOSTNAME_MAX_LENGTH = 64
ORGANIZATION_NAME_MAX_LENGTH = 80
FINGERPRINT_JSON_FILE = "device_fingerprint.json"


def _sanitize_username(value, fallback="Unknown"):
    username = str(value or "").strip()
    if not username:
        username = fallback
    return username[:USERNAME_MAX_LENGTH]


def _sanitize_asset_name(value, fallback="Unknown"):
    asset_name = str(value or "").strip()
    if not asset_name:
        asset_name = fallback
    return asset_name[:ASSETNAME_MAX_LENGTH]


def _sanitize_hostname(value, fallback="Unknown"):
    hostname = str(value or "").strip()
    if not hostname:
        hostname = fallback
    return hostname[:HOSTNAME_MAX_LENGTH]


def _sanitize_organization_name(value, fallback="Unknown"):
    organization_name = str(value or "").strip()
    if not organization_name:
        organization_name = fallback
    return organization_name[:ORGANIZATION_NAME_MAX_LENGTH]


def _secure_state_dir(base_dir):
    program_data = str(os.environ.get("PROGRAMDATA") or "").strip()
    if program_data:
        return os.path.join(program_data, "ZeroWatch", "state")
    return os.path.join(base_dir, "state")


def _state_path(base_dir, filename):
    return os.path.join(_secure_state_dir(base_dir), filename)


def _legacy_state_path(base_dir, filename):
    return os.path.join(base_dir, filename)


def _purge_legacy_build_artifacts(base_dir):
    for file_path in [
        _legacy_state_path(base_dir, "products.csv"),
        _legacy_state_path(base_dir, "sentinel_agent.log"),
    ]:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass


def _windows_hidden_startupinfo():
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return si


def run_hidden(args, timeout=None, shell=False):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=shell,
        startupinfo=_windows_hidden_startupinfo(),
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def check_backend_connectivity():
    """Checks if the configured backend endpoint is reachable before network operations."""
    try:
        parsed = urlparse(BASE_API_URL)
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return False

        if host in {"localhost", "127.0.0.1", "::1"}:
            return True

        port = parsed.port or (443 if (parsed.scheme or "").lower() == "https" else 80)
        with socket.create_connection((host, port), timeout=2):
            return True
    except Exception:
        return False

    return False


def _is_hardened_mode():
    """Hardening is opt-in to reduce AV false positives in standard deployments."""
    env_value = str(os.environ.get("SENTINEL_HARDENED_MODE", "")).strip().lower()
    if env_value in {"1", "true", "yes", "on"}:
        return True
    return "--hardened" in sys.argv


def _daemon_args():
    args = ["--daemon"]
    if _is_hardened_mode():
        args.append("--hardened")
    return args


def _manual_console_args():
    return {"--enroll", "--dashboard", "--password-prompt"}


def ensure_interactive_console():
    """Allocates a console when running as a GUI-subsystem executable."""
    try:
        if ctypes.windll.kernel32.GetConsoleWindow() != 0:
            return
        if ctypes.windll.kernel32.AllocConsole() == 0:
            return
        sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="ignore")
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="ignore")
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="ignore")
    except Exception:
        pass


try:
    # Optional build-time constant generated by build_agent.bat.
    # If present, it pins the EXE to a single backend URL.
    from agent_build_config import FORCED_BASE_API_URL  # type: ignore
except Exception:
    FORCED_BASE_API_URL = None

def _resolve_base_api_url():
    # Priority: env override -> local json config -> baked-in default -> localhost fallback.
    env_url = os.environ.get("ZEROWATCH_API_URL") or os.environ.get("AGENT_SERVER_URL")
    if env_url:
        return env_url.rstrip("/")

    try:
        cfg_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "agent_config.json")
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            cfg_url = cfg.get("api_base_url")
            if cfg_url:
                return str(cfg_url).rstrip("/")
    except Exception:
        pass

    if FORCED_BASE_API_URL:
        return str(FORCED_BASE_API_URL).rstrip("/")

    return "http://localhost:3001/api"


BASE_API_URL = _resolve_base_api_url()
AGENT_API_URL = f"{BASE_API_URL}/agent"
AUTH_API_URL = f"{BASE_API_URL}/auth"
USER_API_URL = f"{BASE_API_URL}/user"

def resolve_api_base_url():
    base = str(BASE_API_URL or "").rstrip("/")
    if base.endswith("/api"):
        base = base[:-4]
    return base

ANSI_COLORS = {
    "reset": "\033[0m",
    "cyan": "\033[96m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "blue": "\033[94m",
    "bold": "\033[1m",
}

def _color(text, color):
    if not sys.stdout.isatty():
        return text
    return f"{ANSI_COLORS.get(color, '')}{text}{ANSI_COLORS['reset']}"

# --- DPAPI Cryptography ---
def encrypt_data(data_bytes):
    # Encrypts data using Windows DPAPI (LocalMachine for cross-user persistence)
    flags = 0x4  # CRYPTPROTECT_LOCAL_MACHINE

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    in_buffer = ctypes.create_string_buffer(data_bytes)
    in_blob = DATA_BLOB(len(data_bytes), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    out_blob = DATA_BLOB()

    try:
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "ZeroWatchAgentCreds",
            None,
            None,
            None,
            flags,
            ctypes.byref(out_blob),
        )
        if not ok:
            return None

        try:
            protected = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return protected
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception as e:
        logging.error(f"DPAPI Encryption failed: {e}")
        return None

def decrypt_data(encrypted_bytes):
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    in_buffer = ctypes.create_string_buffer(encrypted_bytes)
    in_blob = DATA_BLOB(len(encrypted_bytes), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    out_blob = DATA_BLOB()

    try:
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        )
        if not ok:
            return None

        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception as e:
        logging.error(f"DPAPI Decryption failed: {e}")
        return None
# --------------------------


class EncryptedFileHandler(logging.Handler):
    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)

    def emit(self, record):
        try:
            message = self.format(record) + "\n"
            existing = b""
            if os.path.exists(self.filepath):
                with open(self.filepath, "rb") as handle:
                    existing = handle.read()

            plaintext = b""
            if existing:
                decrypted = decrypt_data(existing)
                if decrypted:
                    plaintext = decrypted
                else:
                    try:
                        plaintext = existing.decode("utf-8").encode("utf-8")
                    except Exception:
                        plaintext = b""

            combined = plaintext + message.encode("utf-8", errors="replace")
            encrypted = encrypt_data(combined)
            data_to_write = encrypted if encrypted else combined
            temp_path = f"{self.filepath}.tmp"
            with open(temp_path, "wb") as handle:
                handle.write(data_to_write)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.filepath)
            try:
                subprocess.run(
                    ["attrib", "+H", "+S", self.filepath],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    startupinfo=_windows_hidden_startupinfo(),
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except Exception:
                pass
        except Exception:
            self.handleError(record)


def _configure_logging():
    global LOG_FILE
    early_base_dir = (
        os.path.dirname(os.path.abspath(sys.argv[0]))
        if str(sys.argv[0]).endswith('.exe')
        else os.path.dirname(os.path.abspath(__file__))
    )
    LOG_FILE = _state_path(early_base_dir, "sentinel_agent.log")
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.INFO)
    handler = EncryptedFileHandler(LOG_FILE)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root_logger.addHandler(handler)


_configure_logging()

# ============================================================================
# MODULE 0.5: ZERO-WATCH REST API CLIENT
# ============================================================================

# Offline queue file — DPAPI encrypted, stores pending API calls when offline
OFFLINE_QUEUE_FILE = "zw_offline_queue.dat"
TEAM_JOIN_STATE_FILE = "zw_team_join_state.dat"

class ZeroWatchClient:
    def __init__(self, base_dir, device_id, hostname, fingerprint_data=None, operator_username=None, asset_name=None):
        self.base_dir = base_dir
        self.device_id = device_id
        self.hostname = _sanitize_hostname(hostname)
        self.fingerprint_data = fingerprint_data
        self.operator_username = _sanitize_username(
            operator_username or os.environ.get("USERNAME") or getpass.getuser() or "Unknown"
        )
        self.asset_name = _sanitize_asset_name(asset_name or self.hostname)
        self.token_file = _state_path(base_dir, "zerowatch_token.dat")
        self.queue_file = _state_path(base_dir, OFFLINE_QUEUE_FILE)
        self.state_dir = _secure_state_dir(base_dir)
        self.join_state_file = _state_path(base_dir, TEAM_JOIN_STATE_FILE)
        
        # DEBUG LOGGING
        _append_gui_log(base_dir, f"Client Init: state_dir={self.state_dir}")
        _append_gui_log(base_dir, f"Client Init: token_file={self.token_file}")
        _append_gui_log(base_dir, f"Client Init: PROGRAMDATA={os.environ.get('PROGRAMDATA')}")
        _append_gui_log(base_dir, f"Client Init: device_id={self.device_id}")
        
        self.jwt = self._load_jwt()
        _append_gui_log(base_dir, f"Client Init: JWT loaded={'Yes' if self.jwt else 'No'}")
        self.team_info = None  # Populated after enrollment
        self.last_server_status = None
        self.last_server_message = None
        self.license_active = True
        self.license_reason = None
        self.next_flush_at = 0.0
        self.flush_interval = OFFLINE_FLUSH_MIN_INTERVAL
        self.join_state_tampered = False
        self.join_state = self._load_join_state()
        self.auth_failure_count = 0  # Safety latch for transient auth errors
        identity = _load_identity_from_fingerprint(self.base_dir)
        self.organization_name = _sanitize_organization_name(identity.get("organization_name") or "") if identity.get("organization_name") else "Unknown"
        self.team_info = self._load_team_info_from_state()
        _purge_legacy_build_artifacts(self.base_dir)

        # Real-time WebSocket support
        self.sio = socketio.Client(reconnection=True, reconnection_attempts=0, logger=False, engineio_logger=False)
        self.notification_queue = []
        self._last_approval_sync_at = 0.0
        self._approval_sync_in_flight = False
        self._setup_socket_handlers()
        self.socket_connected = False
        
    def _setup_socket_handlers(self):
        @self.sio.event
        def connect():
            self.socket_connected = True
            logging.info("[WS] Connected to backend")
            # Join device-specific room
            self.sio.emit("join-agent", self.device_id)

        @self.sio.event
        def disconnect():
            self.socket_connected = False
            logging.info("[WS] Disconnected from backend")

        @self.sio.on("feed_ready")
        def on_feed_ready(data):
            logging.info("[WS] Received feed_ready notification")
            self.notification_queue.append({"type": "feed_ready", "data": data})

        @self.sio.on("unlink")
        def on_unlink(data):
            logging.info("[WS] Received unlink notification")
            self.notification_queue.append({"type": "unlink", "data": data})

    def is_enrolled(self):
        """Checks if this device is approved in the join state, independent of JWT."""
        state = self.join_state if isinstance(self.join_state, dict) else self._load_join_state()
        if not state or not isinstance(state, dict):
            return False
            
        status = str(state.get("status") or "").lower()
        team_code = state.get("teamCode")
        device_id = state.get("deviceId")
        
        # Stricter check: Must have status, team, and match current device identity
        is_ok = (status == "approved" and team_code and device_id == self.device_id)
        logging.info(f"Enrollment check: status='{status}', team='{team_code}', match={device_id == self.device_id} => {is_ok}")
        return is_ok

    def connect_socket(self):
        """Connect to WebSocket server in a separate thread if not already connected."""
        if self.socket_connected:
            return
        
        def _target():
            try:
                base_url = resolve_api_base_url()
                # socketio expects the base URL (e.g. http://localhost:5000)
                self.sio.connect(base_url, wait_timeout=10)
            except Exception as e:
                logging.debug(f"[WS] Connection failed: {e}")

        threading.Thread(target=_target, daemon=True).start()

    def disconnect_socket(self):
        try:
            if self.socket_connected:
                self.sio.disconnect()
        except Exception:
            pass

    def poll_notifications(self):
        """Fallback poll for persistent notifications if socket was offline."""
        if not self.jwt:
            return
        
        try:
            url = f"{resolve_api_base_url()}/api/agent/notifications"
            headers = {"Authorization": f"Bearer {self.jwt}"}
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and data.get("notifications"):
                    for notif in data["notifications"]:
                        # Add to queue
                        self.notification_queue.append({
                            "type": notif.get("type"),
                            "data": notif.get("payload"),
                            "id": notif.get("_id")
                        })
                        # Acknowledge immediately so we don't fetch it again
                        self._ack_notification(notif.get("_id"))
        except Exception as e:
            logging.debug(f"[AGENT] Notification poll failed: {e}")

    def _ack_notification(self, notif_id):
        try:
            url = f"{resolve_api_base_url()}/api/agent/notifications/ack"
            headers = {"Authorization": f"Bearer {self.jwt}"}
            requests.post(url, headers=headers, json={"notificationId": notif_id}, timeout=5)
        except Exception:
            pass

    def _load_team_info_from_state(self):
        state = self.join_state if isinstance(self.join_state, dict) else None
        if not state:
            return None
        team_name = str(state.get("teamName") or "").strip()
        team_code = str(state.get("teamCode") or "").strip()
        team_id = str(state.get("teamId") or "").strip()
        if not (team_name or team_code or team_id):
            return None
        return {
            "teamName": team_name or None,
            "teamCode": team_code or None,
            "teamId": team_id or None,
        }

    def _update_team_info_from_payload(self, payload):
        if not isinstance(payload, dict):
            return
        team_name = str(payload.get("teamName") or "").strip()
        team_code = str(payload.get("teamCode") or "").strip()
        team_id = str(payload.get("teamId") or "").strip()
        organization_name = str(payload.get("organizationName") or "").strip()
        if not (team_name or team_code or team_id):
            if organization_name:
                self.organization_name = _sanitize_organization_name(organization_name)
                _save_identity_to_fingerprint(self.base_dir, organization_name=self.organization_name)
            return
        self.team_info = {
            "teamName": team_name or None,
            "teamCode": team_code or None,
            "teamId": team_id or None,
        }
        display_org = organization_name or team_name
        if display_org:
            self.organization_name = _sanitize_organization_name(display_org)
            _save_identity_to_fingerprint(self.base_dir, organization_name=self.organization_name)

    def organization_display_name(self):
        if str(getattr(self, "organization_name", "") or "").strip() and self.organization_name != "Unknown":
            return self.organization_name
        if isinstance(self.team_info, dict):
            team_name = str(self.team_info.get("teamName") or "").strip()
            if team_name:
                return team_name
            team_code = str(self.team_info.get("teamCode") or "").strip()
            if team_code:
                return f"Team {team_code}"
        state = self.join_state if isinstance(self.join_state, dict) else None
        if state:
            team_code = str(state.get("teamCode") or "").strip()
            if team_code:
                return f"Team {team_code}"
        return "Unknown"

    def _secure_state_dir(self):
        return _secure_state_dir(self.base_dir)

    @staticmethod
    def _utc_now_iso():
        return (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    def _join_state_checksum(self, payload):
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        key = str(self.device_id or "unknown-device").encode("utf-8")
        return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def _build_join_state(self, status, team_code=None, request_id=None, team_id=None, team_name=None):
        state = {
            "version": 1,
            "deviceId": self.device_id,
            "teamName": str(team_name or "").strip() or None,
            "teamCode": str(team_code or "").strip() or None,
            "teamId": str(team_id or "").strip() or None,
            "requestId": str(request_id or "").strip() or None,
            "status": str(status or "none").strip().lower(),
            "updatedAt": self._utc_now_iso(),
        }
        state["checksum"] = self._join_state_checksum(state)
        return state

    def _save_join_state(self, status, team_code=None, request_id=None, team_id=None, team_name=None):
        temp_path = f"{self.join_state_file}.tmp"
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            state = self._build_join_state(
                status=status,
                team_code=team_code,
                request_id=request_id,
                team_id=team_id,
                team_name=team_name,
            )
            payload = json.dumps(state, separators=(",", ":")).encode("utf-8")
            encrypted = encrypt_data(payload)
            if not encrypted:
                return False

            with open(temp_path, "wb") as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, self.join_state_file)
            self._protect_file(self.join_state_file)

            try:
                subprocess.run(
                    ["attrib", "+H", "+S", self.join_state_file],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    startupinfo=_windows_hidden_startupinfo(),
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except Exception:
                pass

            self.join_state_tampered = False
            self.join_state = state
            self._update_team_info_from_payload(state)
            return True
        except Exception as e:
            logging.error(f"Failed to save join state: {e}")
            return False
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

    def _load_join_state(self):
        self.join_state_tampered = False
        if not os.path.exists(self.join_state_file):
            return None

        try:
            with open(self.join_state_file, "rb") as f:
                encrypted = f.read()
            decrypted = decrypt_data(encrypted)
            if not decrypted:
                self.join_state_tampered = True
                return None

            state = json.loads(decrypted.decode("utf-8"))
            if not isinstance(state, dict):
                self.join_state_tampered = True
                return None

            persisted_checksum = state.get("checksum")
            state_for_check = dict(state)
            state_for_check.pop("checksum", None)
            expected_checksum = self._join_state_checksum(state_for_check)
            if persisted_checksum != expected_checksum:
                self.join_state_tampered = True
                logging.warning("Join state checksum mismatch detected; treating file as tampered.")
                return None

            self.join_state_tampered = False
            return state
        except Exception as e:
            logging.warning(f"Failed to load join state: {e}")
            self.join_state_tampered = True
            return None

    def clear_join_state(self):
        try:
            if os.path.exists(self.join_state_file):
                os.remove(self.join_state_file)
        except Exception as e:
            logging.warning(f"Failed to remove join state file {self.join_state_file}: {e}")
        self.join_state = None
        self.join_state_tampered = False

    def has_pending_join(self):
        current = self.join_state if isinstance(self.join_state, dict) else self._load_join_state()
        self.join_state = current
        if not current:
            return False
        return str(current.get("status") or "").strip().lower() == "pending"

    def refresh_join_status_once(self):
        """Refreshes join status from backend using deviceId and updates local secure join-state file."""
        try:
            resp = requests.get(
                f"{AGENT_API_URL}/join-status",
                params={"deviceId": self.device_id},
                timeout=10,
            )
            data = resp.json() if resp.content else {}
            if not data.get("success"):
                return {"status": "unknown", "message": data.get("message")}

            status = str(data.get("status") or "").strip().lower()
            current_state = self.join_state if isinstance(self.join_state, dict) else {}
            request_id = data.get("requestId") or current_state.get("requestId")

            if status == "approved":
                if data.get("jwt"):
                    self._save_jwt(data.get("jwt"))
                self._save_join_state(
                    status="approved",
                    team_name=data.get("teamName") or current_state.get("teamName"),
                    team_code=data.get("teamCode") or current_state.get("teamCode"),
                    request_id=request_id,
                    team_id=data.get("teamId") or current_state.get("teamId"),
                )
                self._update_team_info_from_payload(data)
                return {"status": "approved", "jwt": data.get("jwt")}

            if status == "denied":
                self._save_join_state(
                    status="denied",
                    team_name=current_state.get("teamName"),
                    team_code=current_state.get("teamCode"),
                    request_id=request_id,
                    team_id=current_state.get("teamId"),
                )
                return {"status": "denied", "reason": data.get("reason")}

            if status == "pending":
                self._save_join_state(
                    status="pending",
                    team_name=current_state.get("teamName"),
                    team_code=current_state.get("teamCode"),
                    request_id=request_id,
                    team_id=current_state.get("teamId"),
                )
                return {"status": "pending"}

            if status in {"unlinked", "not_linked", "detached"}:
                return {"status": "unlinked", "message": data.get("message")}

            return {"status": "unknown", "message": data.get("message")}
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return {"status": "unreachable"}
        except Exception as e:
            logging.debug(f"Join status refresh failed: {e}")
            return {"status": "unknown"}

    @staticmethod
    def _extract_license_status(payload):
        if not isinstance(payload, dict):
            return None, None

        # Only license-specific response fields are allowed to drive license state.
        has_explicit_license_field = any(
            key in payload for key in ("licenseStatus", "licenseExpired", "licenseValid")
        )
        if not has_explicit_license_field:
            return None, None

        status_value = str(payload.get("licenseStatus") or "").strip().lower()
        message_value = str(payload.get("message") or "").strip()

        if payload.get("licenseExpired") is True:
            return False, message_value or "license expired"
        if payload.get("licenseValid") is False:
            return False, message_value or "license invalid"
        if status_value in {"expired", "inactive", "invalid", "suspended", "blocked"}:
            return False, message_value or status_value

        if payload.get("licenseValid") is True:
            return True, message_value
        if status_value in {"active", "valid", "ok", "renewed"}:
            return True, message_value or status_value

        return None, message_value or None

    def _apply_license_status(self, is_active, reason=None):
        if is_active is None:
            if reason:
                self.last_server_message = reason
            return

        self.license_active = bool(is_active)
        self.license_reason = reason
        self.last_server_message = reason

    def _parse_server_payload(self, resp):
        data = self._parse_json_payload(resp)
        server_asset_name = ""
        if isinstance(data, dict):
            server_asset_name = str(
                data.get("asset_name_update") or data.get("asset_name") or ""
            ).strip()
        if server_asset_name:
            normalized_server_asset_name = _sanitize_asset_name(
                server_asset_name,
                fallback=getattr(self, "asset_name", self.hostname),
            )
            if normalized_server_asset_name != getattr(self, "asset_name", ""):
                self.asset_name = normalized_server_asset_name
                if isinstance(self.fingerprint_data, dict):
                    self.fingerprint_data["asset_name"] = normalized_server_asset_name
                _save_identity_to_fingerprint(
                    self.base_dir,
                    asset_name=normalized_server_asset_name,
                    hostname=self.hostname,
                )
                logging.info(
                    "[SYNC] Applied server asset name update: %s",
                    normalized_server_asset_name,
                )
        is_active, reason = self._extract_license_status(data)
        self._apply_license_status(is_active, reason)
        return data

    def _handle_unlinked_response(self, resp, payload=None):
        if resp is None:
            return False

        data = payload if isinstance(payload, dict) else self._parse_json_payload(resp)
        message = str(data.get("message") or "").strip() if isinstance(data, dict) else ""
        status_text = ""
        if isinstance(data, dict):
            status_text = str(
                data.get("licenseStatus") or data.get("linkStatus") or ""
            ).strip().lower()

        unlink_detected = False
        if isinstance(data, dict) and data.get("linked") is False:
            unlink_detected = True

        if not unlink_detected and status_text in {"unlinked", "not_linked", "detached"}:
            unlink_detected = True

        if not unlink_detected and message:
            lowered_message = message.lower()
            if (
                "no longer linked" in lowered_message
                or "not linked" in lowered_message
                or "device unlinked" in lowered_message
                or "agent not found" in lowered_message
                or "device not found" in lowered_message
            ):
                unlink_detected = True

        if unlink_detected:
            # Proactively verify with a fresh heartbeat if this was just a status code trigger
            if not data or not data.get("unlinked"):
                 _append_gui_log(self.base_dir, "[SECURITY] Verifying unconfirmed unlink signal...")
                 res = self.heartbeat()
                 if res is not None and res != "unlinked":
                     _append_gui_log(self.base_dir, "[SECURITY] Unlink signal was false positive. Staying linked.")
                     return False
            
            _append_gui_log(self.base_dir, f"[SECURITY] Explicit unlink confirmed: {message}")
            self.clear_local_state()
            return True

        return False

    @staticmethod
    def _parse_json_payload(resp):
        data = {}
        if resp.content:
            try:
                data = resp.json()
            except Exception:
                data = {}
        return data

    @staticmethod
    def _is_acknowledged_response(resp):
        """Treats request as delivered only when HTTP is success and backend did not return success=false."""
        if not resp:
            return False
        
        # 5xx means the server is down/restarting. We should NOT treat this as a definitive failure.
        # Returning None tells the caller this is a transient error.
        if resp.status_code >= 500:
            return None

        if not resp.ok:
            return False

        try:
            if not resp.content:
                return True
            payload = resp.json()
            if isinstance(payload, dict):
                return payload.get("success", True) is not False
            return True
        except Exception:
            return True

    def _load_jwt(self):
        _append_gui_log(self.base_dir, f"Attempting to load JWT from {self.token_file}")
        for token_path in [self.token_file, _legacy_state_path(self.base_dir, "zerowatch_token.dat")]:
            if os.path.exists(token_path):
                try:
                    with open(token_path, "rb") as f:
                        encrypted = f.read()
                    _append_gui_log(self.base_dir, f"Found token file: {token_path} (size={len(encrypted)})")
                    decrypted = decrypt_data(encrypted)
                    if decrypted:
                        jwt_str = decrypted.decode("utf-8")
                        _append_gui_log(self.base_dir, "Successfully decrypted JWT")
                        if token_path != self.token_file:
                            _append_gui_log(self.base_dir, "Migrating legacy JWT to new location")
                            self._save_jwt(jwt_str)
                            try:
                                os.remove(token_path)
                            except Exception:
                                pass
                        return jwt_str
                    else:
                        _append_gui_log(self.base_dir, "Failed to decrypt JWT (decrypt_data returned None)")
                except Exception as e:
                    _append_gui_log(self.base_dir, f"Error loading JWT: {e}")
                    logging.error(f"Failed to load JWT: {e}")
            else:
                _append_gui_log(self.base_dir, f"Token file not found: {token_path}")
        return None

    def _save_jwt(self, jwt_str):
        try:
            _append_gui_log(self.base_dir, f"Attempting to save JWT to {self.token_file}")
            os.makedirs(os.path.dirname(self.token_file), exist_ok=True)
            encrypted = encrypt_data(jwt_str.encode("utf-8"))
            if encrypted:
                with open(self.token_file, "wb") as f:
                    f.write(encrypted)
                _append_gui_log(self.base_dir, f"Successfully saved JWT (size={len(encrypted)})")
                self.jwt = jwt_str
                return True
            else:
                _append_gui_log(self.base_dir, "Failed to encrypt JWT (encrypt_data returned None)")
        except Exception as e:
            _append_gui_log(self.base_dir, f"Error saving JWT: {e}")
            logging.error(f"Failed to save JWT: {e}")
        return False

    def clear_local_state(self):
        _append_gui_log(self.base_dir, "clear_local_state() called - DELETING ALL PERSISTENT FILES")
        """Reset local auth/state files so the endpoint behaves like fresh install."""
        files_to_remove = [
            self.token_file,
            self.join_state_file,
            self.queue_file,
            _fingerprint_json_path(self.base_dir),
            _state_path(self.base_dir, "products.csv"),
            _state_path(self.base_dir, "sentinel_agent.log"),
            _state_path(self.base_dir, "dashboard_cache.dat"),
        ]

        for file_path in files_to_remove:
            try:
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                    _append_gui_log(self.base_dir, f"Cleared file: {os.path.basename(file_path)}")
            except Exception as e:
                logging.warning(f"Failed removing local state file {file_path}: {e}")

        self.jwt = None
        self.team_info = None
        self.last_server_status = None
        self.license_active = True
        self.license_reason = None
        self.clear_join_state()

    def request_join(self, team_code):
        """Submit a join request for the given team code."""
        if not team_code:
            return {"success": False, "message": "Team code required"}

        if self.has_pending_join():
            return {
                "success": True,
                "status": "pending",
                "requestId": (self.join_state or {}).get("requestId"),
                "message": "Pending join request already exists for this device.",
            }

        try:
            payload = {
                "teamCode": team_code,
                "device_id": self.device_id,
                "hostname": self.hostname,
                "username": self.operator_username,
                "asset_name": self.asset_name,
                "os_info": f"Windows ({AGENT_VERSION})",
                "fingerprint_json": self.fingerprint_data,
            }
            # Optimistically save state as pending to maintain state across restarts
            self._save_join_state(
                status="pending",
                team_code=team_code,
            )
            
            resp = requests.post(
                f"{AGENT_API_URL}/join-request",
                json=payload,
                timeout=10,
            )
            data = resp.json() if resp.content else {"success": False}
            if data.get("success"):
                result_status = str(data.get("status") or "pending").strip().lower()
                if result_status == "approved":
                    if data.get("jwt"):
                        self._save_jwt(data.get("jwt"))
                    self._save_join_state(
                        status="approved",
                        team_name=data.get("teamName"),
                        team_code=data.get("teamCode") or team_code,
                        request_id=data.get("requestId"),
                        team_id=data.get("teamId"),
                    )
                    self._update_team_info_from_payload(data)
                else:
                    self._save_join_state(
                        status="pending",
                        team_name=data.get("teamName"),
                        team_code=team_code,
                        request_id=data.get("requestId"),
                        team_id=data.get("teamId"),
                    )
                    self._update_team_info_from_payload(data)
            return data
        except Exception as e:
            logging.warning(f"Join request failed: {e}")
            return {"success": False, "message": "Network error"}

    def request_individual_join(self, individual_code):
        """Submit an individual registration request for the given code."""
        if not individual_code:
            return {"success": False, "message": "Registration code required"}

        try:
            payload = {
                "individualCode": individual_code,
                "device_id": self.device_id,
                "hostname": self.hostname,
                "username": self.operator_username,
                "asset_name": self.asset_name,
                "os_info": f"Windows ({AGENT_VERSION})",
                "fingerprint_json": self.fingerprint_data,
            }
            
            resp = requests.post(
                f"{AGENT_API_URL}/individual-enroll",
                json=payload,
                timeout=10,
            )
            data = resp.json() if resp.content else {"success": False}
            if data.get("success") and data.get("jwt"):
                self._save_jwt(data.get("jwt"))
            return data
        except Exception as e:
            logging.warning(f"Individual registration failed: {e}")
            return {"success": False, "message": "Network error"}

    def poll_join_status(self, timeout=600, interval=8):
        """Poll join status until approved, denied, or timed out."""
        start = time.time()
        while time.time() - start < timeout:
            status_data = self.refresh_join_status_once()
            if status_data.get("status") == "approved":
                return {"status": "approved", "jwt": status_data.get("jwt")}
            if status_data.get("status") == "denied":
                return {"status": "denied", "reason": status_data.get("reason")}
            if status_data.get("status") not in {"pending", "unreachable"}:
                logging.debug("Join status check failed: %s", status_data)
            time.sleep(interval)
        return {"status": "timeout"}

    def _auth_headers(self):
        return {"Authorization": f"Bearer {self.jwt}"} if self.jwt else {}

    def _fingerprint_json(self):
        """Serialise the full hardware fingerprint for safe DB storage."""
        if not self.fingerprint_data:
            return self.device_id
        try:
            return json.dumps({
                k: v for k, v in self.fingerprint_data.items()
                if k not in ("collected_at",)
            })
        except Exception:
            return self.device_id

    # ----------------------------------------------------------------
    # OFFLINE QUEUE — DPAPI-encrypted local storage for failed requests
    # ----------------------------------------------------------------
    def _load_queue(self):
        """Loads the offline queue from DPAPI-encrypted file."""
        for queue_path in [self.queue_file, _legacy_state_path(self.base_dir, OFFLINE_QUEUE_FILE)]:
            if not os.path.exists(queue_path):
                continue
            try:
                with open(queue_path, "rb") as f:
                    encrypted = f.read()
                decrypted = decrypt_data(encrypted)
                if decrypted:
                    queue = json.loads(decrypted.decode("utf-8"))
                    if queue_path != self.queue_file:
                        self._save_queue(queue)
                        try:
                            os.remove(queue_path)
                        except Exception:
                            pass
                    return queue
            except Exception as e:
                logging.error(f"Failed to load offline queue: {e}")
        return []

    def _save_queue(self, queue):
        """Saves the offline queue to DPAPI-encrypted file."""
        try:
            data = json.dumps(queue).encode("utf-8")
            encrypted = encrypt_data(data)
            if encrypted:
                with open(self.queue_file, "wb") as f:
                    f.write(encrypted)
                self._protect_file(self.queue_file)
        except Exception as e:
            logging.error(f"Failed to save offline queue: {e}")

    def _enqueue_offline(self, method, url, payload):
        """Adds a request to the offline queue with timestamp."""
        queue = self._load_queue()
        queue.append({
            "method": method,
            "url": url,
            "payload": payload,
            "queued_at": datetime.datetime.now().isoformat(),
            "retry_count": 0,
            "next_retry_at": 0,
            "last_error": None,
        })
        self._save_queue(queue)
        logging.info(f"Offline queued: {method} {url}")

    def _send_queue_item(self, item):
        method = str(item.get("method") or "POST").upper()
        url = item.get("url")
        payload = item.get("payload")

        if method == "POST":
            resp = requests.post(url, headers=self._auth_headers(), json=payload, timeout=15)
        elif method == "GET":
            resp = requests.get(url, headers=self._auth_headers(), timeout=10)
        elif method == "DELETE":
            resp = requests.delete(url, headers=self._auth_headers(), timeout=10)
        else:
            return False, None, f"unsupported method {method}"

        self.last_server_status = resp.status_code
        if self._is_acknowledged_response(resp):
            return True, resp.status_code, None

        return False, resp.status_code, f"http {resp.status_code}"

    def flush_offline_queue(self, network_available=True):
        """Attempts to send queued requests with backoff. Returns summary dict."""
        queue = self._load_queue()
        if not queue:
            return {"flushed": 0, "pending": 0, "attempted": 0}

        if not self.license_active:
            return {"flushed": 0, "pending": len(queue), "attempted": 0}

        now_ts = time.time()
        if not network_available:
            return {"flushed": 0, "pending": len(queue), "attempted": 0}

        if now_ts < self.next_flush_at:
            return {"flushed": 0, "pending": len(queue), "attempted": 0}

        remaining = []
        flushed = 0
        attempted = 0

        for item in queue:
            retry_after = float(item.get("next_retry_at") or 0)
            if retry_after > now_ts:
                remaining.append(item)
                continue

            attempted += 1
            try:
                ok, status_code, error_text = self._send_queue_item(item)
                if ok:
                    flushed += 1
                else:
                    retry_count = int(item.get("retry_count") or 0) + 1
                    backoff = min(900, OFFLINE_FLUSH_MIN_INTERVAL * (2 ** min(retry_count, 6)))
                    item["retry_count"] = retry_count
                    item["next_retry_at"] = now_ts + backoff
                    item["last_error"] = error_text or f"http {status_code}"
                    remaining.append(item)
            except Exception:
                retry_count = int(item.get("retry_count") or 0) + 1
                backoff = min(900, OFFLINE_FLUSH_MIN_INTERVAL * (2 ** min(retry_count, 6)))
                item["retry_count"] = retry_count
                item["next_retry_at"] = now_ts + backoff
                item["last_error"] = "network exception"
                remaining.append(item)

        self._save_queue(remaining)
        if flushed:
            logging.info(f"Offline queue flushed: {flushed} items sent, {len(remaining)} still pending.")

        if attempted > 0 and flushed == 0:
            self.flush_interval = min(self.flush_interval * 2, OFFLINE_FLUSH_MAX_INTERVAL)
        else:
            self.flush_interval = OFFLINE_FLUSH_MIN_INTERVAL

        self.next_flush_at = time.time() + self.flush_interval
        return {"flushed": flushed, "pending": len(remaining), "attempted": attempted}

    def _protect_file(self, filepath):
        """Sets restrictive ACL on a file so only current user, SYSTEM and Administrators can access."""
        try:
            subprocess.run(
                ["icacls", filepath, "/inheritance:r",
                 "/grant:r", f"{os.environ.get('USERNAME', 'SYSTEM')}:(R,W)",
                 "/grant:r", "SYSTEM:(F)",
                 "/grant:r", "Administrators:(F)"],
                capture_output=True, text=True, timeout=5,
                startupinfo=_windows_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass

    # ----------------------------------------------------------------
    # DEVICE LINKING — Team Code Join Requests
    # ----------------------------------------------------------------
    def enroll(self, pin):
        """Legacy no-op retained only for backward compatibility."""
        return False, "Legacy enrollment disabled"

    # ----------------------------------------------------------------
    # SYNC
    # ----------------------------------------------------------------
    def sync_full(self, software_list, hardware_info=None):
        if not self.jwt or not self.license_active: return False
        payload = {
            "device_id": self.device_id,
            "username": self.operator_username,
            "inventory": [],
            "hardware": hardware_info
        }
        try:
            formatted_software = [{
                "name": item.get("name"),
                "version": item.get("version"),
                "vendor": item.get("vendor"),
                "install_date": item.get("install_date"),
                "source": item.get("source")
            } for item in software_list]

            payload["inventory"] = formatted_software
            resp = requests.post(f"{AGENT_API_URL}/sync/full", headers=self._auth_headers(), json=payload, timeout=30)
            self.last_server_status = resp.status_code
            data = self._parse_server_payload(resp)
            if self._handle_unlinked_response(resp, data):
                return False
            logging.info(f"Full sync response: {resp.status_code}")
            if self._is_acknowledged_response(resp):
                return True
            if not self.license_active:
                return False
            self._enqueue_offline("POST", f"{AGENT_API_URL}/sync/full", payload)
            return False
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            logging.warning(f"Full sync failed (offline), queuing: {e}")
            self._enqueue_offline("POST", f"{AGENT_API_URL}/sync/full", payload)
            return False
        except Exception as e:
            logging.error(f"Full sync error: {e}")
            return False

    def sync_delta(self, added, removed, added_hw=None, removed_hw=None, hardware_snapshot=None):
        if not self.jwt or not self.license_active: return False
        payload = {
            "device_id": self.device_id,
            "username": self.operator_username,
            "added": added,
            "removed": removed
        }
        try:
            if added_hw:
                payload["added"] = added + [{"source": "hardware", **h} for h in added_hw]
            if removed_hw:
                payload["removed"] = removed + [{"source": "hardware", **h} for h in removed_hw]

            if hardware_snapshot and isinstance(hardware_snapshot, dict):
                payload["hardware_snapshot"] = hardware_snapshot

            resp = requests.post(f"{AGENT_API_URL}/sync/delta", headers=self._auth_headers(), json=payload, timeout=20)
            self.last_server_status = resp.status_code
            data = self._parse_server_payload(resp)
            if self._handle_unlinked_response(resp, data):
                return False
            logging.info(f"Delta sync response: {resp.status_code}")
            if self._is_acknowledged_response(resp):
                return True
            if not self.license_active:
                return False
            self._enqueue_offline("POST", f"{AGENT_API_URL}/sync/delta", payload)
            return False
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            logging.warning(f"Delta sync failed (offline), queuing: {e}")
            self._enqueue_offline("POST", f"{AGENT_API_URL}/sync/delta", payload)
            return False
        except Exception as e:
            logging.error(f"Delta sync error: {e}")
            return False

    def trigger_approval_sync(self, reason="feed_ready", min_interval=120):
        if not self.jwt or not self.license_active:
            return False
        if self._approval_sync_in_flight:
            return False

        now = time.time()
        if now - self._last_approval_sync_at < float(min_interval):
            return False

        self._last_approval_sync_at = now
        self._approval_sync_in_flight = True

        def _sync_worker():
            try:
                software = get_installed_software_registry()
                hardware_data = get_detailed_hardware_profile()
                sync_ok = self.sync_full(software, hardware_data)
                if sync_ok:
                    logging.info("[AGENT] Approval-triggered full sync completed (reason=%s).", reason)
                else:
                    logging.info(
                        "[AGENT] Approval-triggered full sync did not complete (queued/retry path, reason=%s).",
                        reason,
                    )
            except Exception as exc:
                logging.error("[AGENT] Approval-triggered full sync failed: %s", exc)
            finally:
                self._approval_sync_in_flight = False

        threading.Thread(target=_sync_worker, daemon=True).start()
        return True

    def unlink_self(self):
        """Unlinks this device from the currently linked account using the agent JWT."""
        if not self.jwt:
            return False, "Device is not linked"
        try:
            resp = requests.delete(f"{AGENT_API_URL}/unlink-self", headers=self._auth_headers(), timeout=10)
            self.last_server_status = resp.status_code
            data = resp.json() if resp.content else {}
            if resp.ok and data.get("success"):
                self.clear_local_state()
                return True, None
            return False, data.get("message", "Failed to unlink device")
        except Exception as e:
            return False, str(e)

    # ----------------------------------------------------------------
    # HEARTBEAT / LOGGING
    # ----------------------------------------------------------------
    def heartbeat(self):
        if not self.jwt: return False
        if not self.license_active:
            return "license_expired"
        try:
            payload = {
                "device_id": self.device_id,
                "status": "active",
                "version": AGENT_VERSION,
                "username": self.operator_username,
                "asset_name": self.asset_name,
            }
            resp = requests.post(f"{AGENT_API_URL}/heartbeat", headers=self._auth_headers(), json=payload, timeout=5)
            self.last_server_status = resp.status_code
            
            # 5xx = Server is down/restarting. Treat as "Offline" (None)
            if resp.status_code >= 500:
                return None
                
            data = self._parse_server_payload(resp)
            if self._handle_unlinked_response(resp, data):
                return "unlinked"
            if not self.license_active:
                return "license_expired"
            
            # If 401/403, return False to increment safety latch
            if resp.status_code in {401, 403}:
                return False
                
            return self._is_acknowledged_response(resp)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return None  # None = offline/transient, False = server rejected auth
        except Exception:
            return None # Treat unknown errors as transient to be safe

    def check_license_reactivation(self, force=False):
        """Polls backend for license reactivation using license-status only."""
        if not self.jwt:
            return False
        if self.license_active:
            return True
        try:
            logging.info("[LICENSE] Recheck sent (expired mode) via /license-status.")
            resp = requests.get(
                f"{AGENT_API_URL}/license-status",
                headers=self._auth_headers(),
                timeout=8,
            )
            self.last_server_status = resp.status_code
            logging.info(
                "[LICENSE] Recheck response status=%s (endpoint=/license-status).",
                resp.status_code,
            )

            data = self._parse_server_payload(resp)
            if self._handle_unlinked_response(resp, data):
                return "unlinked"
            if self.license_active:
                logging.info("[LICENSE] Recheck result: renewed (active=true).")
                return True
            logging.info("[LICENSE] Recheck result: still inactive.")
            return False
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            logging.warning("[LICENSE] Recheck failed: backend unreachable during expired mode.")
            return None
        except Exception:
            logging.warning("[LICENSE] Recheck failed: unexpected error during expired mode.")
            return False

    def log_event(self, event_type, details):
        if not self.jwt or not self.license_active: return False
        payload = {
            "device_id": self.device_id,
            "username": self.operator_username,
            "event_type": event_type,
            "details": details,
        }
        try:
            resp = requests.post(f"{AGENT_API_URL}/log", headers=self._auth_headers(), json=payload, timeout=5)
            self.last_server_status = resp.status_code
            data = self._parse_server_payload(resp)
            if self._handle_unlinked_response(resp, data):
                return False
            if self._is_acknowledged_response(resp):
                return True
            if not self.license_active:
                return False
            self._enqueue_offline("POST", f"{AGENT_API_URL}/log", {
                "device_id": self.device_id,
                "username": self.operator_username,
                "event_type": event_type,
                "details": {**details, "original_timestamp": datetime.datetime.now().isoformat()},
            })
            return False
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            self._enqueue_offline("POST", f"{AGENT_API_URL}/log", {
                "device_id": self.device_id,
                "username": self.operator_username,
                "event_type": event_type,
                "details": {**details, "original_timestamp": datetime.datetime.now().isoformat()},
            })
            return False
        except Exception:
            return False

    def verify_kill(self, password):
        if not self.jwt:
            return password == KILL_PASSWORD
        try:
            payload = {"device_id": self.device_id, "password": password}
            resp = requests.post(f"{AGENT_API_URL}/verify-kill", headers=self._auth_headers(), json=payload, timeout=10)
            if resp.ok and resp.json().get("success"):
                return True
            # Backend explicitly denied — also try local fallback password
            return password == KILL_PASSWORD
        except Exception as e:
            logging.error(f"Verify kill error: {e}")
            return password == KILL_PASSWORD

    def get_dashboard_stats(self):
        if not self.jwt: return None
        try:
            resp = requests.get(f"{AGENT_API_URL}/metrics", headers=self._auth_headers(), timeout=10)
            data = self._parse_json_payload(resp)
            if self._handle_unlinked_response(resp, data):
                return "unlinked"
            if resp.ok:
                return data
            return None
        except Exception as e:
            logging.error(f"Failed to fetch dashboard stats: {e}")
            return None

    def get_asset_info(self):
        if not self.jwt:
            cached = self._load_dashboard_cache()
            if cached:
                data = cached.get("data", {})
                data["from_cache"] = True
                return data
            return None
        try:
            resp = requests.get(f"{AGENT_API_URL}/info", headers=self._auth_headers(), timeout=10)
            data = self._parse_json_payload(resp)
            if self._handle_unlinked_response(resp, data):
                return "unlinked"
            if resp.ok:
                asset_data = data.get("data")
                if asset_data:
                    self._save_dashboard_cache({"data": asset_data})
                return asset_data
            
            # Fallback to cache on server error
            cached = self._load_dashboard_cache()
            if cached:
                data = cached.get("data", {})
                data["from_cache"] = True
                return data
            return None
        except Exception as e:
            logging.error(f"Failed to fetch asset info: {e}")
            cached = self._load_dashboard_cache()
            if cached:
                data = cached.get("data", {})
                data["from_cache"] = True
                return data
            return None

    def _save_dashboard_cache(self, data):
        path = _state_path(self.base_dir, "dashboard_cache.dat")
        try:
            serialized = json.dumps(data).encode("utf-8")
            encrypted = encrypt_data(serialized)
            if encrypted:
                with open(path, "wb") as f:
                    f.write(encrypted)
        except Exception:
            pass

    def _load_dashboard_cache(self):
        path = _state_path(self.base_dir, "dashboard_cache.dat")
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                raw = f.read()
            decrypted = decrypt_data(raw)
            if decrypted:
                return json.loads(decrypted.decode("utf-8"))
        except Exception:
            pass
        return None

    def _save_asset_info(self, asset_info):
        path = _state_path(self.base_dir, "asset_info.json")
        try:
            serialized = json.dumps(asset_info, indent=4).encode("utf-8")
            encrypted = encrypt_data(serialized)
            data_to_write = encrypted if encrypted else serialized
            with open(path, "wb") as f:
                f.write(data_to_write)
        except Exception as e:
            logging.error(f"Failed to save asset info: {e}")

    def _load_asset_info(self):
        path = _state_path(self.base_dir, "asset_info.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                raw = f.read()
            decrypted = decrypt_data(raw)
            if decrypted:
                return json.loads(decrypted.decode("utf-8"))
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def get_detailed_stats(self):
        """High-fidelity stats for the new Dashboard GUI."""
        if not self.jwt: return None
        try:
            # We use the /metrics endpoint which returns the full stats object
            resp = requests.get(f"{AGENT_API_URL}/metrics", headers=self._auth_headers(), timeout=10)
            data = self._parse_json_payload(resp)
            if self._handle_unlinked_response(resp, data):
                return None
            if resp.ok and data.get("success"):
                return data
            return None
        except Exception as e:
            logging.error(f"Failed to fetch detailed stats: {e}")
            return None

# ============================================================================

# ---------------------------------------------------------------------------
# Path Resolution: Works for both raw Python AND Nuitka-compiled .exe
# Nuitka does NOT set sys.frozen — it uses __compiled__ at module level.
# For --onefile, sys.executable points to the .exe, but we can also check sys.argv[0]
# ---------------------------------------------------------------------------
def get_base_dir():
    """Returns the directory where the .exe (or .py script) lives on disk."""
    if sys.argv[0].endswith('.exe'):
        return os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.dirname(os.path.abspath(__file__))



def get_exe_path():
    """Returns the absolute path to the current executable."""
    if sys.argv[0].endswith('.exe'):
        return os.path.abspath(sys.argv[0])
    return os.path.abspath(__file__)

# LOG_FILE is initialized in _configure_logging() during module import.

    def _load_asset_info(self):
        path = _state_path(self.base_dir, "asset_info.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                raw = f.read()
            decrypted = decrypt_data(raw)
            if decrypted:
                return json.loads(decrypted.decode("utf-8"))
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

# ============================================================================
# MODULE 1: BOOTSTRAP — Single Instance Mutex
# ============================================================================

def enforce_single_instance():
    """
    Claims a named Windows kernel mutex. If one already exists from another 
    running instance, this process exits silently.
    """
    mutex = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
    last_err = ctypes.windll.kernel32.GetLastError()
    if last_err == 183:  # ERROR_ALREADY_EXISTS
        logging.info("Another instance is already running. Exiting silently.")
        sys.exit(0)
    return mutex  # MUST keep reference alive — releasing frees the mutex


# ============================================================================
# MODULE 2: FINGERPRINT — Device Identity & UID Generation
# ============================================================================

def _read_reg_key(key_path, value_name, hive=winreg.HKEY_LOCAL_MACHINE):
    """Safely reads a string registry value. Spawns zero subprocesses."""
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        value, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return str(value).strip()
    except Exception:
        return None

def _read_reg_subkeys(key_path, hive=winreg.HKEY_LOCAL_MACHINE):
    """Enumerates subkeys of a registry key. Spawns zero subprocesses."""
    subkeys = []
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        num_subkeys, _, _ = winreg.QueryInfoKey(key)
        for i in range(num_subkeys):
            try:
                subkeys.append(winreg.EnumKey(key, i))
            except OSError:
                pass
        winreg.CloseKey(key)
    except Exception:
        pass
    return subkeys

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]

def get_total_ram_bytes():
    """Gets total physical RAM in bytes directly via Win32 API. Spawns zero subprocesses."""
    try:
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(stat)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return stat.ullTotalPhys
    except Exception:
        pass
    return 0

def get_gpus_info():
    """Reads GPU devices from Registry display class. Spawns zero subprocesses."""
    gpus = []
    class_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
    subkeys = _read_reg_subkeys(class_path)
    for sub in subkeys:
        if sub.isdigit():
            path = f"{class_path}\\{sub}"
            name = _read_reg_key(path, "DriverDesc")
            if name:
                vram_raw = _read_reg_key(path, "HardwareInformation.MemorySize")
                vram_bytes = None
                if vram_raw and vram_raw.isdigit():
                    vram_bytes = str(vram_raw)
                driver_version = _read_reg_key(path, "DriverVersion")
                provider = _read_reg_key(path, "ProviderName")
                gpus.append({
                    "name": name,
                    "vram_bytes": vram_bytes or "Unknown",
                    "driver_version": driver_version or "Unknown",
                    "chipset": provider or "Unknown"
                })
    if not gpus:
        gpus.append({
            "name": "Standard Display Adapter",
            "vram_bytes": "Unknown",
            "driver_version": "Unknown",
            "chipset": "Unknown"
        })
    return gpus

def get_disks_info():
    """Reads disk model names from Registry. Spawns zero subprocesses."""
    disks = []
    try:
        scsi_path = r"SYSTEM\CurrentControlSet\Enum\SCSI"
        devices = _read_reg_subkeys(scsi_path)
        for dev in devices:
            instance_path = f"{scsi_path}\\{dev}"
            instances = _read_reg_subkeys(instance_path)
            for inst in instances:
                full_path = f"{instance_path}\\{inst}"
                friendly_name = _read_reg_key(full_path, "FriendlyName")
                mfg = _read_reg_key(full_path, "Mfg")
                if friendly_name:
                    disks.append({
                        "Model": friendly_name,
                        "Manufacturer": mfg or "Unknown",
                        "Size": "Unknown",
                        "InterfaceType": "SCSI"
                    })
    except Exception:
        pass
    if not disks:
        disks.append({
            "Model": "System Disk",
            "Manufacturer": "Generic",
            "Size": "Unknown",
            "InterfaceType": "SATA/NVMe"
        })
    return disks

def get_sound_devices():
    """Reads sound devices from Registry. Spawns zero subprocesses."""
    devices = []
    class_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}"
    subkeys = _read_reg_subkeys(class_path)
    for sub in subkeys:
        if sub.isdigit():
            path = f"{class_path}\\{sub}"
            name = _read_reg_key(path, "DriverDesc")
            provider = _read_reg_key(path, "ProviderName")
            if name:
                devices.append({
                    "Name": name,
                    "Manufacturer": provider or "Unknown"
                })
    return devices

def get_printers():
    """Reads configured printers from Registry. Spawns zero subprocesses."""
    printers = []
    path = r"SYSTEM\CurrentControlSet\Control\Print\Printers"
    subkeys = _read_reg_subkeys(path)
    for sub in subkeys:
        printers.append({
            "Name": sub,
            "DriverName": "Unknown",
            "PortName": "Unknown"
        })
    return printers

def get_bios_info():
    """Reads BIOS details from Registry. Spawns zero subprocesses."""
    path = r"HARDWARE\DESCRIPTION\System\BIOS"
    return {
        "manufacturer": _read_reg_key(path, "BIOSVendor") or "Unknown",
        "name": _read_reg_key(path, "BIOSVersion") or "Unknown",
        "serial": "ANONYMIZED",
        "version": _read_reg_key(path, "BIOSReleaseDate") or "Unknown"
    }

def get_motherboard_info():
    """Reads Motherboard details from Registry. Spawns zero subprocesses."""
    path = r"HARDWARE\DESCRIPTION\System\BIOS"
    return {
        "manufacturer": _read_reg_key(path, "BaseBoardManufacturer") or "Unknown",
        "product": _read_reg_key(path, "BaseBoardProduct") or "Unknown",
        "serial": "ANONYMIZED",
        "version": "Unknown"
    }

def get_os_info():
    """Reads OS version information from Registry. Spawns zero subprocesses."""
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    caption = _read_reg_key(path, "ProductName")
    if not caption:
        caption = "Windows"
    version = _read_reg_key(path, "DisplayVersion") or "Unknown"
    build = _read_reg_key(path, "CurrentBuild") or "Unknown"
    arch = "64-bit" if sys.maxsize > 2**32 else "32-bit"
    return {
        "caption": caption,
        "version": version,
        "build": build,
        "arch": arch
    }

def get_mac_address():
    """Generates a formatted MAC address string using standard library."""
    mac_num = hex(uuid.getnode()).replace('0x', '').upper()
    mac_num = mac_num.zfill(12)
    mac = '-'.join(mac_num[i: i + 2] for i in range(0, 11, 2))
    return mac

def get_machine_guid():
    """Fetches the Windows Machine GUID from the registry."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return str(value).strip()
    except Exception:
        return "UNAVAILABLE"

def get_disk_serial():
    try:
        import wmi
        c = wmi.WMI()
        return c.Win32_DiskDrive()[0].SerialNumber.strip()
    except Exception:
        pass
    return "UNKNOWN_DISK_SERIAL"

def collect_fingerprint():
    """
    Collects a comprehensive device fingerprint from multiple hardware layers.
    Returns a dict with all hardware identifiers and a deterministic computed Device ID.
    """
    import wmi
    try:
        c = wmi.WMI()
    except Exception:
        c = None

    def _get_wmi_val(obj_func, attr):
        if c:
            try:
                objs = obj_func()
                if objs:
                    return str(getattr(objs[0], attr)).strip()
            except Exception:
                pass
        return None

    # 1. Read raw values using WMI with fallback to Registry
    raw_bios_serial = _get_wmi_val(lambda: c.Win32_BIOS(), "SerialNumber") or _clean_hw(_read_reg_key(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemSerialNumber")) or "UNAVAILABLE"
    raw_bios_uuid = _get_wmi_val(lambda: c.Win32_ComputerSystemProduct(), "UUID") or _clean_hw(_read_reg_key(r"SYSTEM\CurrentControlSet\Control\SystemInformation", "SystemUUID")) or "UNAVAILABLE"
    raw_motherboard_serial = _get_wmi_val(lambda: c.Win32_BaseBoard(), "SerialNumber") or _clean_hw(_read_reg_key(r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardSerialNumber")) or "UNAVAILABLE"
    raw_cpu_id = _get_wmi_val(lambda: c.Win32_Processor(), "ProcessorId") or _clean_hw(_read_reg_key(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "Identifier")) or "UNAVAILABLE"
    machine_guid = get_machine_guid()

    raw_fp = {
        "bios_serial": raw_bios_serial,
        "bios_uuid": raw_bios_uuid,
        "cpu_id": raw_cpu_id,
        "machine_guid": machine_guid,
        "motherboard_serial": raw_motherboard_serial
    }
    device_id = generate_device_id(raw_fp)

    fp = {
        "bios_serial":        raw_bios_serial,
        "bios_uuid":          raw_bios_uuid,
        "motherboard_serial": raw_motherboard_serial,
        "motherboard_product":_clean_hw(_read_reg_key(r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardProduct")) or "UNAVAILABLE",
        "cpu_id":             raw_cpu_id,
        "os_serial":          _clean_hw(_read_reg_key(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductId")) or "UNAVAILABLE",
        "machine_guid":       machine_guid,
        "mac_address":        get_mac_address(),
        "mac_addresses":      [get_mac_address()],
        "disk_serial":        get_disk_serial(),
        "collected_at":       datetime.datetime.now().isoformat(),
        "agent_version":      AGENT_VERSION,
        "device_id":          device_id,
    }

    return fp

def generate_device_id(fingerprint):
    """
    Creates a deterministic SHA-256 hash from the 5 most stable hardware identifiers.
    """
    STABLE_KEYS = ["bios_serial", "bios_uuid", "cpu_id", "machine_guid", "motherboard_serial"]
    combined = "|".join(
        str(fingerprint.get(k, "X")).strip().upper()
        for k in sorted(STABLE_KEYS)
    )
    return "SAGT-" + hashlib.sha256(combined.encode()).hexdigest().upper()[:32]


# ============================================================================
# MODULE 3: INVENTORY — Software & Hardware Enumeration
# ============================================================================

def _reg_val(key_handle, value_name):
    """Safely reads a single registry value, returns empty string on failure."""
    try:
        return str(winreg.QueryValueEx(key_handle, value_name)[0]).strip()
    except Exception:
        return ""


def _utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _parse_registry_install_date(raw_value):
    """Parse Windows uninstall key dates to ISO-8601 UTC where possible."""
    raw = str(raw_value or "").strip()
    if not raw:
        return {
            "iso": None,
            "raw": "",
            "source": "missing",
            "confidence": "none",
        }

    # Common Windows uninstall format: YYYYMMDD
    if len(raw) == 8 and raw.isdigit():
        try:
            parsed = datetime.datetime.strptime(raw, "%Y%m%d")
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return {
                "iso": parsed.replace(microsecond=0).isoformat(),
                "raw": raw,
                "source": "registry_yyyymmdd",
                "confidence": "high",
            }
        except ValueError:
            pass

    # Handle unix timestamps sometimes found in custom uninstallers.
    if raw.isdigit():
        try:
            ts_num = int(raw)
            if ts_num > 0:
                if len(raw) >= 13:
                    parsed = datetime.datetime.fromtimestamp(ts_num / 1000, tz=datetime.timezone.utc)
                    source = "registry_unix_ms"
                else:
                    parsed = datetime.datetime.fromtimestamp(ts_num, tz=datetime.timezone.utc)
                    source = "registry_unix_s"
                return {
                    "iso": parsed.replace(microsecond=0).isoformat(),
                    "raw": raw,
                    "source": source,
                    "confidence": "medium",
                }
        except Exception:
            pass

    # Fallback: attempt ISO/date parsing without forcing local timezone assumptions.
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y"):
        try:
            parsed = datetime.datetime.strptime(raw, fmt).replace(tzinfo=datetime.timezone.utc)
            return {
                "iso": parsed.replace(microsecond=0).isoformat(),
                "raw": raw,
                "source": f"registry_{fmt}",
                "confidence": "medium",
            }
        except ValueError:
            continue

    return {
        "iso": None,
        "raw": raw,
        "source": "unparsed",
        "confidence": "low",
    }

def get_installed_software_registry():
    """
    Primary software scanner: reads the Windows Registry Uninstall keys.
    """
    results = []
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]

    for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for path in registry_paths:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub_name = winreg.EnumKey(key, i)
                        sub = winreg.OpenKey(key, sub_name, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                        name = _reg_val(sub, "DisplayName")
                        if name:
                            install_meta = _parse_registry_install_date(
                                _reg_val(sub, "InstallDate")
                            )
                            results.append({
                                "category": "software",
                                "name": name,
                                "vendor": _reg_val(sub, "Publisher"),
                                "version": _reg_val(sub, "DisplayVersion"),
                                "install_date": install_meta["iso"],
                                "install_date_raw": install_meta["raw"],
                                "install_date_source": install_meta["source"],
                                "install_date_confidence": install_meta["confidence"],
                                "install_location": _reg_val(sub, "InstallLocation"),
                                "source": "registry",
                                "last_seen": _utc_now_iso(),
                                "change_type": "initial",
                            })
                        sub.Close()
                    except OSError:
                        pass
                key.Close()
            except OSError:
                pass

    seen = set()
    unique = []
    for app in results:
        ident = f"{app['name']}::{app['version']}"
        if ident not in seen:
            seen.add(ident)
            unique.append(app)
    return unique

def get_hardware_inventory():
    """
    Queries registry and ctypes to build a full hardware profile.
    Each item is returned as a flat dict row for CSV export (legacy format).
    Spawns zero subprocesses and anonymizes serial numbers.
    """
    results = []

    # 1. CPU
    cpu_name = _read_reg_key(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
    cpu_mfg = _read_reg_key(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "VendorIdentifier")
    results.append({
        "category": "cpu",
        "name": cpu_name or "Unknown CPU",
        "vendor": cpu_mfg or "Unknown",
        "version": "",
        "serial_number": "ANONYMIZED",
        "install_date": "",
        "extra_info": json.dumps({"cores": os.cpu_count()}),
        "source": "registry_cpu",
        "last_seen": datetime.datetime.now().isoformat(),
        "change_type": "initial",
    })

    # 2. RAM
    ram_bytes = get_total_ram_bytes()
    results.append({
        "category": "ram",
        "name": "Physical Memory",
        "vendor": "ANONYMIZED",
        "version": "",
        "serial_number": "ANONYMIZED",
        "install_date": "",
        "extra_info": json.dumps({"Capacity": str(ram_bytes)}),
        "source": "ctypes_ram",
        "last_seen": datetime.datetime.now().isoformat(),
        "change_type": "initial",
    })

    # 3. GPU
    for gpu in get_gpus_info():
        results.append({
            "category": "gpu",
            "name": gpu["name"],
            "vendor": gpu["chipset"],
            "version": gpu["driver_version"],
            "serial_number": "ANONYMIZED",
            "install_date": "",
            "extra_info": json.dumps({"vram_bytes": gpu["vram_bytes"]}),
            "source": "registry_gpu",
            "last_seen": datetime.datetime.now().isoformat(),
            "change_type": "initial",
        })

    # 4. Disks
    for disk in get_disks_info():
        results.append({
            "category": "disk",
            "name": disk["Model"],
            "vendor": disk["Manufacturer"],
            "version": "",
            "serial_number": "ANONYMIZED",
            "install_date": "",
            "extra_info": json.dumps({"InterfaceType": disk["InterfaceType"]}),
            "source": "registry_disk",
            "last_seen": datetime.datetime.now().isoformat(),
            "change_type": "initial",
        })

    # 5. Network
    results.append({
        "category": "network",
        "name": "Network Adapter",
        "vendor": "ANONYMIZED",
        "version": "",
        "serial_number": "ANONYMIZED",
        "install_date": "",
        "extra_info": json.dumps({}),
        "source": "uuid_network",
        "last_seen": datetime.datetime.now().isoformat(),
        "change_type": "initial",
    })

    # 6. Motherboard
    mboard = get_motherboard_info()
    results.append({
        "category": "motherboard",
        "name": mboard["product"],
        "vendor": mboard["manufacturer"],
        "version": mboard["version"],
        "serial_number": "ANONYMIZED",
        "install_date": "",
        "extra_info": json.dumps({}),
        "source": "registry_motherboard",
        "last_seen": datetime.datetime.now().isoformat(),
        "change_type": "initial",
    })

    # 7. BIOS
    bios = get_bios_info()
    results.append({
        "category": "bios",
        "name": bios["name"],
        "vendor": bios["manufacturer"],
        "version": bios["version"],
        "serial_number": "ANONYMIZED",
        "install_date": "",
        "extra_info": json.dumps({}),
        "source": "registry_bios",
        "last_seen": datetime.datetime.now().isoformat(),
        "change_type": "initial",
    })

    # 8. OS
    os_info = get_os_info()
    results.append({
        "category": "os",
        "name": os_info["caption"],
        "vendor": "Microsoft",
        "version": os_info["version"],
        "serial_number": "ANONYMIZED",
        "install_date": "",
        "extra_info": json.dumps({"build": os_info["build"], "arch": os_info["arch"]}),
        "source": "registry_os",
        "last_seen": datetime.datetime.now().isoformat(),
        "change_type": "initial",
    })

    # 9. Sound
    for snd in get_sound_devices():
        results.append({
            "category": "sound",
            "name": snd["Name"],
            "vendor": snd["Manufacturer"],
            "version": "",
            "serial_number": "ANONYMIZED",
            "install_date": "",
            "extra_info": json.dumps({}),
            "source": "registry_sound",
            "last_seen": datetime.datetime.now().isoformat(),
            "change_type": "initial",
        })

    # 10. Printer
    for prn in get_printers():
        results.append({
            "category": "printer",
            "name": prn["Name"],
            "vendor": "Generic",
            "version": "",
            "serial_number": "ANONYMIZED",
            "install_date": "",
            "extra_info": json.dumps({}),
            "source": "registry_printer",
            "last_seen": datetime.datetime.now().isoformat(),
            "change_type": "initial",
        })

    return results

def _clean_hw(value):
    """Returns None for missing/unavailable hardware values."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.upper() in ("UNAVAILABLE", "N/A", "NONE", "NULL", "TO BE FILLED BY O.E.M.", "DEFAULT STRING"):
        return None
    return s

def get_detailed_hardware_profile():
    """
    Builds a structured hardware profile object matching the backend schema.
    Uses registry and ctypes to prevent subprocess spawns, and anonymizes serial numbers.
    """
    ram_total_bytes = get_total_ram_bytes()
    ram_total_kb = str(ram_total_bytes // 1024) if ram_total_bytes else "0"

    ram_modules = []
    try:
        ram_modules.append({
            "manufacturer": "ANONYMIZED",
            "part_number":  "ANONYMIZED",
            "serial":       "ANONYMIZED",
            "speed_mhz":    "Unknown",
            "capacity_bytes": str(ram_total_bytes),
            "memory_type":  "DDR",
        })
    except Exception:
        pass

    gpus = get_gpus_info()
    os_info = get_os_info()
    bios_info = get_bios_info()
    motherboard_info = get_motherboard_info()

    cpu_name = _clean_hw(_read_reg_key(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"))
    cpu_mfg = _clean_hw(_read_reg_key(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "VendorIdentifier"))
    logical_proc = os.cpu_count()

    h = {
        "cpu": cpu_name,
        "cpu_details": {
            "cores":               logical_proc,
            "logical_processors":  logical_proc,
            "max_clock_mhz":       "Unknown",
            "manufacturer":        cpu_mfg,
            "processor_id":        "ANONYMIZED",
        },
        "ram": {
            "total_kb": ram_total_kb,
            "total_gb": round((float(ram_total_kb) / (1024 * 1024)), 2) if ram_total_kb != "0" else 0.0,
            "modules": ram_modules,
            "module_count": len(ram_modules),
        },
        "gpu": gpus[0]["name"] if gpus else "Unknown",
        "gpus": gpus,
        "motherboard": motherboard_info,
        "bios": bios_info,
        "os_info": os_info,
        "mac_addresses": ["ANONYMIZED"]
    }
    h["captured_at"] = datetime.datetime.now().isoformat()
    return h

def collect_full_inventory():
    """Combines software and hardware into a single list for CSV export (legacy)."""
    software = get_installed_software_registry()
    hardware = get_hardware_inventory()
    logging.info(f"Inventory: {len(software)} software, {len(hardware)} hardware items")
    return software + hardware


# ============================================================================
# MODULE 4: PROTECTION — Self-Defense Layers
# ============================================================================

def harden_process_acl():
    """
    Denies PROCESS_TERMINATE permission for Everyone on the current process.
    After this, Task Manager's 'End Task' will return ACCESS_DENIED.
    """
    try:
        import win32security
        import ntsecuritycon as con
        import win32api
        import win32con

        handle = win32api.OpenProcess(
            win32con.PROCESS_ALL_ACCESS, False, os.getpid()
        )
        sd = win32security.GetSecurityInfo(
            handle, win32security.SE_KERNEL_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()

        everyone = win32security.CreateWellKnownSid(
            win32security.WinWorldSid, None
        )

        dacl.AddAccessDeniedAce(
            win32security.ACL_REVISION,
            getattr(con, "PROCESS_TERMINATE", 0x0001),
            everyone
        )

        win32security.SetSecurityInfo(
            handle, win32security.SE_KERNEL_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None, None, dacl, None
        )
        logging.info("DACL hardening applied — PROCESS_TERMINATE denied for Everyone.")
        return True
    except ImportError:
        logging.warning("pywin32 not available — DACL hardening SKIPPED.")
        return False
    except Exception as e:
        logging.warning(f"DACL hardening failed: {e}")
        return False

def install_ctrl_handler():
    """
    Intercepts Ctrl+C, Ctrl+Break, console close, logoff, and shutdown events.
    Returning True suppresses the default OS kill behavior.
    """
    HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

    @HandlerRoutine
    def _ctrl_handler(event):
        CTRL_C = 0; CTRL_BREAK = 1; CTRL_CLOSE = 2; CTRL_LOGOFF = 5; CTRL_SHUTDOWN = 6
        if event in (CTRL_C, CTRL_BREAK, CTRL_CLOSE, CTRL_LOGOFF, CTRL_SHUTDOWN):
            logging.info(f"Console control event {event} intercepted. Suppressing.")
            return True
        return False

    ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler, True)
    signal.signal(signal.SIGINT, lambda *_: None)
    signal.signal(signal.SIGTERM, lambda *_: None)
    
    logging.info("Console Ctrl handler and signal handlers installed.")
    return _ctrl_handler

def password_kill_cli():
    """
    Standalone password prompt that runs in its own visible console window.
    Exit code 0 = authorized kill, exit code 1 = denied.
    """
    ensure_interactive_console()
    print()
    print("=" * 62)
    print("  +========================================================+")
    print("  |    SENTINELAGENT - TERMINATION OVERRIDE REQUIRED        |")
    print("  |                                                          |")
    print("  |  An unauthorized attempt to terminate the ZeroWatch      |")
    print("  |  endpoint agent has been detected and blocked.           |")
    print("  |                                                          |")
    print("  |  Enter the administrative kill-code to proceed.          |")
    print("  +========================================================+")
    print("=" * 62)
    print()

    pwd = None
    try:
        pwd = input("  Enter termination password: ")
    except Exception:
        pass

    # Fetch fingerprint purely for device_id
    fingerprint = collect_fingerprint()
    base_dir = get_base_dir()
    hostname = resolve_hostname(base_dir)
    asset_name = resolve_asset_name(base_dir, prompt=False, default_hostname=hostname)
    zw_client = ZeroWatchClient(base_dir, fingerprint['device_id'], hostname, asset_name=asset_name)

    print("\n  [ WAIT ] Verifying kill-code with ZeroWatch Backend...")
    if zw_client.verify_kill(pwd):
        print("  [OK] Authentication successful.")
        print("  [OK] SentinelAgent will terminate in 3 seconds...")
        zw_client.log_event("SHUTDOWN", {"reason": "User provided valid termination key"})
        for i in range(3, 0, -1):
            print(f"      Stopping in {i}...")
            time.sleep(1)
            
        try:
            request_shutdown_signal(base_dir, "watchdog-override")
            unregister_windows_service()
            unregister_task_scheduler()
            unregister_startup_registry()
        except Exception as e:
            logging.error(f"Error during persistent unregistration: {e}")
            
        sys.exit(0)  # Exit code 0 = authorized
    else:
        print("\n  [!!] ERROR: Incorrect kill-code or backend denied access. Access DENIED.")
        print("  [!!] This window will close in 5 seconds. Agent continues running.")
        zw_client.log_event("TERMINATION_ATTEMPT", {"status": "denied"})
        time.sleep(5)
        sys.exit(1)  # Exit code 1 = denied


# ============================================================================
# MODULE 5: PERSISTENCE — Startup Registration
# ============================================================================

def register_startup_registry():
    """Adds SentinelAgent to Run so it starts at every login.

    Tries HKLM first (requires admin) and falls back to HKCU when not elevated.
    """
    exe_path = get_exe_path()

    # Try HKLM (requires admin)
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        daemon_cmd = " ".join(_daemon_args())
        winreg.SetValueEx(
            key,
            "SentinelAgent",
            0,
            winreg.REG_SZ,
            f'"{exe_path}" {daemon_cmd}',
        )
        winreg.CloseKey(key)
        logging.info(f"Registry startup registered (HKLM): {exe_path}")
        return
    except Exception as e:
        logging.warning(f"HKLM startup registration failed (likely non-admin): {e}")

    # Fallback to current user run key
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        daemon_cmd = " ".join(_daemon_args())
        winreg.SetValueEx(
            key,
            "SentinelAgent",
            0,
            winreg.REG_SZ,
            f'"{exe_path}" {daemon_cmd}',
        )
        winreg.CloseKey(key)
        logging.info(f"Registry startup registered (HKCU): {exe_path}")
    except Exception as e:
        logging.warning(f"HKCU startup registration failed: {e}")

def register_task_scheduler():
    """Creates a resilient Task Scheduler setup.

    Strategy:
      1) ONSTART as SYSTEM (best for reboot reliability)
      2) ONLOGON highest privilege
      3) ONLOGON limited privilege
    """
    exe_path = get_exe_path()
    daemon_cmd = " ".join(_daemon_args())
    any_success = False

    def _create_task(task_name, schedule, run_level, run_as=None):
        cmd = [
            "schtasks", "/create", "/tn", task_name,
            "/tr", f'"{exe_path}" {daemon_cmd}',
            "/sc", schedule,
            "/rl", run_level,
            "/f",
        ]
        if run_as:
            cmd.extend(["/ru", run_as])
        result = run_hidden(cmd)
        return result

    def _create_resume_task(task_name, run_level, run_as=None):
        cmd = [
            "schtasks", "/create", "/tn", task_name,
            "/tr", f'"{exe_path}" {daemon_cmd}',
            "/sc", "ONEVENT",
            "/ec", "System",
            "/mo", "*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1]]",
            "/rl", run_level,
            "/f",
        ]
        if run_as:
            cmd.extend(["/ru", run_as])
        return run_hidden(cmd)

    try:
        result = _create_task("SentinelAgentStartup", "ONSTART", "HIGHEST", run_as="SYSTEM")
        if result.returncode == 0:
            logging.info("Startup task created (ONSTART/SYSTEM).")
            any_success = True
        else:
            logging.warning(f"Startup task registration failed: {result.stderr}")

        result = _create_task("SentinelAgent", "ONLOGON", "HIGHEST")
        if result.returncode == 0:
            logging.info("Logon task created (highest privilege).")
            any_success = True
        else:
            logging.warning(f"Logon task (highest) failed: {result.stderr}")

        result = _create_task("SentinelAgent", "ONLOGON", "LIMITED")
        if result.returncode == 0:
            logging.info("Logon task created (limited privilege).")
            any_success = True
        else:
            logging.warning(f"Logon task (limited) failed: {result.stderr}")

        result = _create_resume_task("SentinelAgentResume", "HIGHEST", run_as="SYSTEM")
        if result.returncode == 0:
            logging.info("Resume task created (Power-Troubleshooter event).")
            any_success = True
        else:
            logging.warning(f"Resume task registration failed: {result.stderr}")
    except Exception as e:
        logging.warning(f"Task Scheduler registration failed: {e}")

    return any_success


# ============================================================================
# MODULE 5.5: DEEP SYSTEM INTEGRATION — Anti-Deletion & File Protection
# ============================================================================

def protect_agent_files():
    """
    Protects the agent's executable, data files and directory from deletion.
    Uses NTFS ACLs (icacls) to restrict modification to SYSTEM only.
    """
    base_dir = get_base_dir()
    exe_path = get_exe_path()

    # Files that must be protected
    protected = [exe_path]
    data_files = [
        _state_path(base_dir, "zerowatch_token.dat"),
        _state_path(base_dir, "zw_offline_queue.dat"),
        _fingerprint_json_path(base_dir),
        _state_path(base_dir, "products.csv"),
        _state_path(base_dir, "sentinel_agent.log"),
    ]
    for fp in data_files:
        if os.path.exists(fp):
            protected.append(fp)

    for filepath in protected:
        try:
            # Remove inherited permissions, grant SYSTEM full control
            # and current user full control (F) so the exe can be re-launched.
            # Without Execute permission the user cannot double-click the exe.
            subprocess.run(
                ["icacls", filepath, "/inheritance:r",
                 "/grant:r", "SYSTEM:(F)",
                 "/grant:r", f"{os.environ.get('USERNAME', 'SYSTEM')}:(F)"],
                capture_output=True,
                text=True,
                timeout=5,
                startupinfo=_windows_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception as e:
            logging.warning(f"Failed to protect {filepath}: {e}")

    # Also make the token file hidden
    token_file = _state_path(base_dir, "zerowatch_token.dat")
    if os.path.exists(token_file):
        try:
            subprocess.run(["attrib", "+H", "+S", token_file],
                           capture_output=True,
                           text=True,
                           timeout=3,
                           startupinfo=_windows_hidden_startupinfo(),
                           creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    queue_file = _state_path(base_dir, "zw_offline_queue.dat")
    if os.path.exists(queue_file):
        try:
            subprocess.run(["attrib", "+H", "+S", queue_file],
                           capture_output=True,
                           text=True,
                           timeout=3,
                           startupinfo=_windows_hidden_startupinfo(),
                           creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    logging.info("Agent file protection applied.")


def register_windows_service():
    """
    Registers SentinelAgent as a Windows service for deeper OS integration.
    Uses sc.exe to create a service entry (runs as LocalSystem).
    """
    exe_path = get_exe_path()
    daemon_cmd = " ".join(_daemon_args())
    if not exe_path.endswith('.exe'):
        return  # Only register compiled executables as services

    try:
        # Check if service already exists
        check = subprocess.run(
            ["sc", "query", "SentinelAgent"],
            capture_output=True,
            text=True,
            timeout=5,
            startupinfo=_windows_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if check.returncode == 0:
            logging.info("SentinelAgent service already registered.")
            subprocess.run(
                ["sc", "start", "SentinelAgent"],
                capture_output=True,
                text=True,
                timeout=10,
                startupinfo=_windows_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return

        result = subprocess.run(
            ["sc", "create", "SentinelAgent",
             "binPath=", f'"{exe_path}" {daemon_cmd}',
             "start=", "auto",
             "DisplayName=", "ZeroWatch SentinelAgent"],
            capture_output=True,
            text=True,
            timeout=10,
            startupinfo=_windows_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            logging.info("SentinelAgent Windows service registered.")
            # Set service description
            subprocess.run(
                ["sc", "description", "SentinelAgent",
                 "ZeroWatch endpoint protection and asset monitoring agent."],
                capture_output=True,
                text=True,
                timeout=5,
                startupinfo=_windows_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # Set recovery: restart on failure
            subprocess.run(
                ["sc", "failure", "SentinelAgent",
                 "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/60000"],
                capture_output=True,
                text=True,
                timeout=5,
                startupinfo=_windows_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            subprocess.run(
                ["sc", "config", "SentinelAgent", "start=", "delayed-auto"],
                capture_output=True,
                text=True,
                timeout=5,
                startupinfo=_windows_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            subprocess.run(
                ["sc", "start", "SentinelAgent"],
                capture_output=True,
                text=True,
                timeout=10,
                startupinfo=_windows_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            logging.warning(f"Service registration failed: {result.stderr}")
    except Exception as e:
        logging.warning(f"Service registration failed: {e}")


def unregister_windows_service():
    """Removes the SentinelAgent Windows service."""
    try:
        subprocess.run(
            ["sc", "stop", "SentinelAgent"],
            capture_output=True,
            text=True,
            timeout=10,
            startupinfo=_windows_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        subprocess.run(
            ["sc", "delete", "SentinelAgent"],
            capture_output=True,
            text=True,
            timeout=10,
            startupinfo=_windows_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        logging.info("SentinelAgent Windows service removed.")
    except Exception as e:
        logging.warning(f"Service removal failed: {e}")

def is_inventory_scan_enabled():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Zerowatch\Agent", 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, "InventoryScan")
        winreg.CloseKey(key)
        return val == 1
    except Exception:
        return True # Default to True

def set_inventory_scan_enabled(enabled):
    try:
        import winreg
        try:
            winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Zerowatch")
        except Exception:
            pass
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Zerowatch\Agent")
        winreg.SetValueEx(key, "InventoryScan", 0, winreg.REG_DWORD, 1 if enabled else 0)
        winreg.CloseKey(key)
    except Exception as e:
        logging.error(f"Failed to set InventoryScan registry: {e}")


def is_auto_start_enabled():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, "ZerowatchSentinelAgent")
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

def set_auto_start_enabled(enabled):
    try:
        import winreg
        import sys
        import os
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        if enabled:
            exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])
            winreg.SetValueEx(key, "ZerowatchSentinelAgent", 0, winreg.REG_SZ, f'"{exe_path}"')
        else:
            try:
                winreg.DeleteValue(key, "ZerowatchSentinelAgent")
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
    except Exception as e:
        logging.error(f"Failed to set auto start registry: {e}")


# ============================================================================
# MODULE 6: WATCHER — Change Detection (Safe Registry Polling)
# ============================================================================

def monitor_system_changes(base_dir, fingerprint, zw_client):
    """
    Background thread that polls every MONITOR_INTERVAL seconds.
    Detects software installs/uninstalls/updates AND hardware profile changes.
    Sends only deltas to the backend (no CSV, no full sync).
    """
    # Software snapshot — keyed by "name::version" for accurate update detection
    last_sw_snapshot = {f"{s['name']}::{s['version']}": s for s in get_installed_software_registry()}

    # Hardware snapshot hash for full-profile diffing
    last_hardware_profile = get_detailed_hardware_profile()
    last_hardware_hash = hashlib.sha256(
        json.dumps(last_hardware_profile, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    while True:
        try:
            time.sleep(MONITOR_INTERVAL)
            
            if not is_inventory_scan_enabled():
                continue

            # --- Software delta ---
            current_list = get_installed_software_registry()
            current_sw_snapshot = {f"{s['name']}::{s['version']}": s for s in current_list}

            sw_added   = set(current_sw_snapshot.keys()) - set(last_sw_snapshot.keys())
            sw_removed = set(last_sw_snapshot.keys()) - set(current_sw_snapshot.keys())

            # --- Hardware delta (full-profile hash + key-level diff summary) ---
            current_hardware_profile = get_detailed_hardware_profile()
            current_hardware_hash = hashlib.sha256(
                json.dumps(current_hardware_profile, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()

            hw_added   = []
            hw_removed = []

            if current_hardware_hash != last_hardware_hash:
                old_flat = flatten_hardware_profile(last_hardware_profile)
                new_flat = flatten_hardware_profile(current_hardware_profile)

                for key, value in new_flat.items():
                    if old_flat.get(key) != value:
                        hw_added.append({
                            "name": key,
                            "vendor": "Hardware",
                            "version": value,
                            "category": "profile",
                        })

                for key, value in old_flat.items():
                    if new_flat.get(key) != value:
                        hw_removed.append({
                            "name": key,
                            "vendor": "Hardware",
                            "version": value,
                            "category": "profile",
                        })

            if sw_added or sw_removed or hw_added or hw_removed:
                for key in sw_added:
                    current_sw_snapshot[key]["change_type"] = "added"
                for key in sw_removed:
                    last_sw_snapshot[key]["change_type"] = "removed"

                sw_added_list   = [current_sw_snapshot[k] for k in sw_added]
                sw_removed_list = [last_sw_snapshot[k] for k in sw_removed]

                logging.info(
                    f"System change detected: SW +{len(sw_added)} -{len(sw_removed)} | "
                    f"HW +{len(hw_added)} -{len(hw_removed)}"
                )

                if zw_client:
                    zw_client.sync_delta(
                        sw_added_list, sw_removed_list,
                        added_hw=hw_added if hw_added else None,
                        removed_hw=hw_removed if hw_removed else None,
                        hardware_snapshot=current_hardware_profile if hw_added or hw_removed else None,
                    )
                    event_detail = {"sw_added": len(sw_added), "sw_removed": len(sw_removed)}
                    if hw_added or hw_removed:
                        event_detail["hw_changes"] = len(hw_added) + len(hw_removed)
                    zw_client.log_event("SYSTEM_CHANGE", event_detail)

                # Always update snapshots
                last_sw_snapshot = current_sw_snapshot
                last_hardware_profile = current_hardware_profile
                last_hardware_hash = current_hardware_hash

        except Exception as e:
            logging.error(f"Monitor error: {e}")
            time.sleep(MONITOR_INTERVAL)


def flatten_hardware_profile(data, parent=""):
    """Flattens nested hardware profile for lightweight key-level diff events."""
    flattened = {}

    if isinstance(data, dict):
        for key, value in data.items():
            next_key = f"{parent}.{key}" if parent else key
            flattened.update(flatten_hardware_profile(value, next_key))
        return flattened

    if isinstance(data, list):
        for idx, value in enumerate(data):
            next_key = f"{parent}[{idx}]"
            flattened.update(flatten_hardware_profile(value, next_key))
        return flattened

    flattened[parent] = str(data)
    return flattened


WIDTH = 62
BANNER = r"""
   ___             __  _            __   ___                    __
  / __/__ ___  _  / /_(_)__  ___ _/ /  / _ | ___ ____ ___  __ / /_
 _\ \/ -_) _ \| |/ / / _ \/ -_) / /  / __ |/ _ `/ -_) _ \/ // __/
/___/\__/_//_/|___/_/_//_/\__/_/_/  /_/ |_|\_, /\__/_//_/\_, /\__/
                                           /___/          /___/
"""


class C:
    ACCENT = "\033[1;96m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    SUCCESS = "\033[1;92m"
    WARN = "\033[1;93m"
    ERROR = "\033[1;91m"
    MUTED = "\033[2;37m"
    R = "\033[0m"


ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-9;]*m")


def _visible_len(text):
    return len(ANSI_ESCAPE_RE.sub("", str(text)))


def _clip_ansi(text, max_visible):
    if max_visible <= 0:
        return ""
    src = str(text)
    parts = re.split(r"(\x1B\[[0-9;]*m)", src)
    out = []
    visible = 0
    for part in parts:
        if not part:
            continue
        if ANSI_ESCAPE_RE.fullmatch(part):
            out.append(part)
            continue
        remain = max_visible - visible
        if remain <= 0:
            break
        chunk = part[:remain]
        out.append(chunk)
        visible += len(chunk)
        if visible >= max_visible:
            break
    return "".join(out)


def _align_ansi(text, inner_width, align="left"):
    clipped = _clip_ansi(text, inner_width)
    vis_len = _visible_len(clipped)
    pad = max(0, inner_width - vis_len)
    if align == "center":
        left = pad // 2
        right = pad - left
    elif align == "right":
        left = pad
        right = 0
    else:
        left = 0
        right = pad
    return (" " * left) + clipped + (" " * right)


def _enable_ansi():
    """Enable ANSI output in modern Windows terminals."""
    if os.name != "nt":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        for std_handle in (-11, -12):  # stdout, stderr
            handle = kernel32.GetStdHandle(std_handle)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _cls():
    print("\033[H\033[J", end="")


def _print_banner():
    _cls()
    print(f"{C.ACCENT}{BANNER}{C.R}")


def _top(title=""):
    if title:
        raw_title = f"[ {title} ]"
        pad = max(0, WIDTH - len(raw_title))
        left = pad // 2
        right = pad - left
        print(f"{C.ACCENT}╔{'═' * left}{C.WHITE}{raw_title}{C.ACCENT}{'═' * right}╗{C.R}")
    else:
        print(f"{C.ACCENT}╔{'═' * WIDTH}╗{C.R}")


def _bot():
    print(f"{C.ACCENT}╚{'═' * WIDTH}╝{C.R}")


def _div():
    print(f"{C.ACCENT}╠{'═' * WIDTH}╣{C.R}")


def _row(text="", align="left"):
    inner = WIDTH - 2
    content = _align_ansi(text, inner, align=align)
    print(f"{C.ACCENT}║{C.R} {content} {C.ACCENT}║{C.R}")


def _blank():
    _row()


def _badge(label, value, ok=None):
    color = C.SUCCESS if ok is True else (C.ERROR if ok is False else C.CYAN)
    left = f"{C.WHITE}  {label}:{C.R}"
    right = f" {color}{value}{C.R}"
    composed = f"{left}{right}"
    _row(composed)


def _menu_item(key, label, danger=False):
    color = C.ERROR if danger else C.CYAN
    _row(f"  {color}[ {key} ]{C.R}  {C.WHITE}{label}{C.R}")


def _status_dot(active):
    return f"{C.SUCCESS}● ACTIVE{C.R}" if active else f"{C.ERROR}● INACTIVE{C.R}"


def _refresh_license_state_for_dashboard(zw_client):
    """Refreshes cached license status for interactive dashboard views."""
    if not zw_client or not zw_client.jwt:
        return
    try:
        if zw_client.license_active:
            zw_client.heartbeat()
        else:
            # Force recheck from interactive dashboard so UI reflects renewal immediately.
            zw_client.check_license_reactivation(force=True)
    except Exception:
        pass


def _dashboard_runtime_state(zw_client, service_running):
    has_token = _is_agent_active(zw_client)
    license_active = bool(has_token and zw_client and zw_client.license_active)
    enrolled = bool(has_token and license_active)
    protection_running = bool(service_running and license_active)
    return has_token, license_active, enrolled, protection_running


def _license_badge_text(has_token, license_active):
    if not has_token:
        return "UNLINKED"
    return "ACTIVE" if license_active else "LICENSE EXPIRED"


def _status_dot_text(has_token, license_active, protection_running):
    if not has_token:
        return f"{C.ERROR}● UNLINKED{C.R}"
    if not license_active:
        return f"{C.ERROR}● LICENSE EXPIRED{C.R}"
    if protection_running:
        return f"{C.SUCCESS}● ACTIVE{C.R}"
    return f"{C.WARN}● DEGRADED{C.R}"


def _input_row(prompt):
    print(f"{C.ACCENT}║{C.R}  {C.YELLOW}▶{C.R} {C.WHITE}{prompt}{C.R} ", end="")
    return input().strip()


def _secret_row(prompt):
    print(f"{C.ACCENT}║{C.R}  {C.YELLOW}▶{C.R} {C.WHITE}{prompt}{C.R} ", end="")
    return getpass.getpass("").strip()


def _spinner(message, duration=1.0):
    # Avoid noisy progress output when stdout is redirected/non-interactive.
    if not getattr(sys.stdout, "isatty", lambda: False)():
        time.sleep(duration)
        return

    frames = ["|", "/", "-", "\\"]
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(f"\r{C.CYAN}{frames[i % len(frames)]}{C.R} {C.DIM}{message}{C.R}", end="", flush=True)
        time.sleep(0.08)
        i += 1
    print(f"\r{C.SUCCESS}✔{C.R} {C.DIM}{message}{C.R}   ")


def _validate_team_code(team_code):
    """Validates team code format: 6 digits."""
    if not team_code:
        return False
    normalized = team_code.strip()
    return len(normalized) == 6 and normalized.isdigit()


def _fingerprint_json_path(base_dir):
    return _state_path(base_dir, FINGERPRINT_JSON_FILE)


def _read_fingerprint_json(base_dir):
    try:
        raw = None
        source_path = None
        for path in (
            _fingerprint_json_path(base_dir),
            _legacy_state_path(base_dir, FINGERPRINT_JSON_FILE),
        ):
            if os.path.exists(path):
                with open(path, "rb") as handle:
                    raw = handle.read()
                source_path = path
                if raw:
                    break

        if not raw:
            return {}

        decrypted = decrypt_data(raw)
        if decrypted:
            try:
                data = json.loads(decrypted.decode("utf-8"))
                if source_path and source_path != _fingerprint_json_path(base_dir):
                    _write_fingerprint_json(base_dir, data)
                    try:
                        os.remove(source_path)
                    except Exception:
                        pass
                return data if isinstance(data, dict) else {}
            except Exception:
                pass

        try:
            data = json.loads(raw.decode("utf-8"))
            if source_path and source_path != _fingerprint_json_path(base_dir):
                _write_fingerprint_json(base_dir, data)
                try:
                    os.remove(source_path)
                except Exception:
                    pass
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    except Exception:
        return {}


def _write_fingerprint_json(base_dir, payload):
    path = _fingerprint_json_path(base_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    serialized = json.dumps(payload, indent=4).encode("utf-8")
    encrypted = encrypt_data(serialized)
    data_to_write = encrypted if encrypted else serialized
    temp_path = f"{path}.tmp"
    with open(temp_path, "wb") as handle:
        handle.write(data_to_write)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)
    try:
        subprocess.run(
            ["attrib", "+H", "+S", path],
            capture_output=True,
            text=True,
            timeout=3,
            startupinfo=_windows_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def _save_identity_to_fingerprint(base_dir, username=None, asset_name=None, hostname=None, organization_name=None):
    try:
        payload = _read_fingerprint_json(base_dir)
        if username is not None:
            payload["username"] = _sanitize_username(username)
        if asset_name is not None:
            payload["asset_name"] = _sanitize_asset_name(asset_name)
        if hostname is not None:
            payload["hostname"] = _sanitize_hostname(hostname)
        if organization_name is not None:
            payload["organization_name"] = _sanitize_organization_name(organization_name)
        payload["identity_updated_at"] = datetime.datetime.now().isoformat()
        _write_fingerprint_json(base_dir, payload)
    except Exception as exc:
        logging.warning("Failed writing identity metadata to fingerprint json: %s", exc)


def _load_identity_from_fingerprint(base_dir):
    payload = _read_fingerprint_json(base_dir)
    username = _sanitize_username(payload.get("username") or "") if payload.get("username") else None
    asset_name = _sanitize_asset_name(payload.get("asset_name") or "") if payload.get("asset_name") else None
    hostname = _sanitize_hostname(payload.get("hostname") or "") if payload.get("hostname") else None
    organization_name = _sanitize_organization_name(payload.get("organization_name") or "") if payload.get("organization_name") else None
    return {"username": username, "asset_name": asset_name, "hostname": hostname, "organization_name": organization_name}


def _resolve_default_hostname():
    return _sanitize_hostname(os.environ.get("COMPUTERNAME") or socket.gethostname() or "Unknown")


def resolve_hostname(base_dir):
    identity = _load_identity_from_fingerprint(base_dir)
    if identity.get("hostname"):
        return identity["hostname"]
    default_hostname = _resolve_default_hostname()
    _save_identity_to_fingerprint(base_dir, hostname=default_hostname)
    return default_hostname


def resolve_asset_name(base_dir, prompt=False, default_hostname=None):
    identity = _load_identity_from_fingerprint(base_dir)
    cached = identity.get("asset_name")
    if cached:
        return cached

    default_asset_name = _sanitize_asset_name(default_hostname or resolve_hostname(base_dir))
    if not prompt:
        _save_identity_to_fingerprint(base_dir, asset_name=default_asset_name)
        return default_asset_name

    entered = input(f"{C.CYAN}Asset Name [{default_asset_name}]: {C.R}").strip()
    final_asset_name = _sanitize_asset_name(entered or default_asset_name)
    _save_identity_to_fingerprint(base_dir, asset_name=final_asset_name)
    return final_asset_name


def resolve_agent_username(base_dir, prompt=False):
    identity = _load_identity_from_fingerprint(base_dir)
    cached = identity.get("username")
    if cached:
        return cached

    default_username = _sanitize_username(
        os.environ.get("USERNAME") or getpass.getuser() or "Unknown"
    )
    if not prompt:
        _save_identity_to_fingerprint(base_dir, username=default_username)
        return default_username

    _enable_ansi()
    _print_banner()
    _top("OPERATOR PROFILE")
    _blank()
    _row(f"  {C.GREY}Enter local username for this endpoint registration.{C.R}")
    _row(f"  {C.MUTED}Press ENTER to keep default: {default_username}{C.R}")
    _row(f"  {C.MUTED}Max length: {USERNAME_MAX_LENGTH} characters{C.R}")
    _blank()
    _bot()
    print()
    entered = input(f"{C.CYAN}Username [{default_username}]: {C.R}").strip()
    final_username = _sanitize_username(entered or default_username)
    _save_identity_to_fingerprint(base_dir, username=final_username)
    return final_username


def _is_agent_active(zw_client):
    return bool(zw_client and zw_client.jwt)


def _is_daemon_running():
    probe = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
    err = ctypes.windll.kernel32.GetLastError()
    if probe:
        ctypes.windll.kernel32.CloseHandle(probe)
    return err == 183


def _spawn_daemon_process():
    target_path = get_exe_path()
    if target_path.endswith('.py'):
        daemon_cmd = [sys.executable, target_path, *_daemon_args()]
    else:
        daemon_cmd = [target_path, *_daemon_args()]

    DETACHED = 0x00000008
    NEW_GROUP = 0x00000200
    daemon_proc = subprocess.Popen(
        daemon_cmd,
        creationflags=DETACHED | NEW_GROUP | subprocess.CREATE_NO_WINDOW,
        startupinfo=_windows_hidden_startupinfo(),
    )
    time.sleep(1.5)
    return daemon_proc.poll() is None, daemon_proc.pid


def unregister_startup_registry():
    """Removes SentinelAgent startup entry from the Run key.

    Tries both HKLM and HKCU to match whatever was created.
    """
    # HKLM
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.DeleteValue(key, "SentinelAgent")
        winreg.CloseKey(key)
        logging.info("Registry startup entry removed (HKLM).")
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.warning(f"Failed to remove HKLM startup entry: {e}")

    # HKCU
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.DeleteValue(key, "SentinelAgent")
        winreg.CloseKey(key)
        logging.info("Registry startup entry removed (HKCU).")
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.warning(f"Failed to remove HKCU startup entry: {e}")


def unregister_task_scheduler():
    """Removes the Task Scheduler entry used for startup persistence."""
    try:
        run_hidden(
            ["schtasks", "/delete", "/tn", "SentinelAgent", "/f"],
        )
        run_hidden(
            ["schtasks", "/delete", "/tn", "SentinelAgentStartup", "/f"],
        )
        run_hidden(
            ["schtasks", "/delete", "/tn", "SentinelAgentResume", "/f"],
        )
        logging.info("Task Scheduler entry removed.")
    except Exception as e:
        logging.warning(f"Failed to remove scheduled task: {e}")


def _shutdown_signal_path(base_dir):
    return _state_path(base_dir, "shutdown.signal")


def request_shutdown_signal(base_dir, reason="manual-disable"):
    signal_path = _shutdown_signal_path(base_dir)
    payload = {
        "reason": reason,
        "requested_at": datetime.datetime.now().isoformat(),
    }
    serialized = json.dumps(payload).encode("utf-8")
    encrypted = encrypt_data(serialized)
    data_to_write = encrypted if encrypted else serialized
    temp_path = f"{signal_path}.tmp"
    os.makedirs(os.path.dirname(signal_path), exist_ok=True)
    with open(temp_path, "wb") as handle:
        handle.write(data_to_write)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, signal_path)
    try:
        subprocess.run(
            ["attrib", "+H", "+S", signal_path],
            capture_output=True,
            text=True,
            timeout=3,
            startupinfo=_windows_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def consume_shutdown_signal(base_dir):
    signal_path = _shutdown_signal_path(base_dir)
    try:
        raw = None
        for candidate in [signal_path, _legacy_state_path(base_dir, "shutdown.signal")]:
            if os.path.exists(candidate):
                with open(candidate, "rb") as handle:
                    raw = handle.read()
                signal_path = candidate
                break
        if raw is None:
            return None
        payload = None
        decrypted = decrypt_data(raw)
        if decrypted:
            try:
                payload = json.loads(decrypted.decode("utf-8"))
            except Exception:
                payload = None
        if payload is None:
            payload = json.loads(raw.decode("utf-8"))
    except Exception:
        payload = {"reason": "manual-disable"}
    try:
        os.remove(signal_path)
    except Exception:
        pass
    return payload


def _wait_for_enrollment(zw_client, base_dir):
    if zw_client.jwt:
        return True

    team_code = os.environ.get("TEAM_CODE") or os.environ.get("ZEROWATCH_TEAM_CODE")
    join_state_needs_verification = bool(zw_client.join_state_tampered)

    if zw_client.has_pending_join() or zw_client.join_state_tampered:
        refresh = zw_client.refresh_join_status_once()
        if refresh.get("status") == "approved":
            logging.info("Pending join request approved after refresh; enrollment completed.")
            join_state_needs_verification = False
        elif refresh.get("status") == "denied":
            logging.info("Pending join request denied; resetting to first-run enrollment state.")
            zw_client.clear_join_state()
            join_state_needs_verification = False
        elif refresh.get("status") == "pending":
            logging.info("Pending join request still awaiting admin decision.")
            join_state_needs_verification = False
        elif refresh.get("status") == "unreachable":
            logging.warning("Backend unavailable while pending join exists; keeping request lock active.")

    if join_state_needs_verification and not zw_client.jwt:
        logging.warning("Join-state file requires backend verification; delaying enrollment actions.")
        if team_code:
            return False

    if not team_code:
        logging.warning("No enrollment token found for daemon mode. Waiting for manual enrollment.")
        while not zw_client.jwt:
            shutdown_request = consume_shutdown_signal(base_dir)
            if shutdown_request:
                logging.info("Shutdown signal received while waiting for enrollment.")
                return False

            if zw_client.has_pending_join() or zw_client.join_state_tampered:
                refresh = zw_client.refresh_join_status_once()
                if refresh.get("status") == "approved":
                    logging.info("Pending join approved while waiting; enrollment completed.")
                    join_state_needs_verification = False
                elif refresh.get("status") == "denied":
                    logging.info("Pending join denied while waiting; cleared pending state.")
                    zw_client.clear_join_state()
                    join_state_needs_verification = False
                elif refresh.get("status") == "pending":
                    join_state_needs_verification = False

            time.sleep(60)
            zw_client.jwt = zw_client._load_jwt()

        return True

    if team_code and not zw_client.jwt:
        if zw_client.has_pending_join():
            logging.info("Pending join request already exists; skipping duplicate request creation.")
        else:
            logging.info("Requesting join for team code: %s", team_code)
            join_resp = zw_client.request_join(team_code)
            if not join_resp.get("success"):
                logging.error(
                    "Join request failed: %s",
                    join_resp.get("message", "Unknown error"),
                )
                return False

        logging.info("Join request submitted, awaiting approval...")
        status = zw_client.poll_join_status()
        if status.get("status") == "approved":
            logging.info("Join approved; agent is now enrolled.")
            return True
        if status.get("status") == "denied":
            logging.error("Join denied: %s", status.get("reason"))
            zw_client.clear_join_state()
            return False
        logging.error("Join request timed out waiting for approval.")
        return False

    return bool(zw_client.jwt)


def _append_gui_log(base_dir, message):
    try:
        path = _state_path(base_dir, "gui_startup.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        timestamp = datetime.datetime.now().isoformat()
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} {message}\n")
    except Exception:
        pass


def enrollment_cli(zw_client):
    """First-run flow: team code join request enrollment."""
    if zw_client.join_state_tampered:
        logging.warning("Join-state file appears tampered/corrupt; forcing backend status refresh.")

    if zw_client.has_pending_join() or zw_client.join_state_tampered:
        status = zw_client.refresh_join_status_once()
        if status.get("status") == "approved":
            return True
        if status.get("status") == "denied":
            zw_client.clear_join_state()
        elif status.get("status") in {"pending", "unreachable", "unknown"}:
            wait_interval = 5
            while True:
                _enable_ansi()
                _print_banner()
                _top("WAITING FOR ADMIN APPROVAL")
                _blank()
                if status.get("status") == "pending":
                    _row(f"  {C.WARN}Join request is still pending.{C.R}")
                    _row(f"  {C.MUTED}This window will keep checking automatically.{C.R}")
                elif status.get("status") == "unreachable":
                    _row(f"  {C.WARN}Backend currently unreachable (offline/network).{C.R}")
                    _row(f"  {C.MUTED}Auto-retrying until server is reachable.{C.R}")
                else:
                    _row(f"  {C.WARN}Join state could not be verified yet.{C.R}")
                    _row(f"  {C.MUTED}Auto-retrying backend verification.{C.R}")
                _blank()
                _row(f"  {C.MUTED}Status checks every {wait_interval}s...{C.R}")
                _row(f"  {C.MUTED}Do not enter team code again while this is pending.{C.R}")
                _blank()
                _bot()
                print()

                time.sleep(wait_interval)
                status = zw_client.refresh_join_status_once()

                if status.get("status") == "approved":
                    return True

                if status.get("status") == "denied":
                    zw_client.clear_join_state()
                    _print_banner()
                    _top("REQUEST DENIED")
                    _blank()
                    _row(f"  {C.ERROR}Admin denied the join request.{C.R}")
                    _row(f"  {C.MUTED}You can submit a new team code now.{C.R}")
                    _blank()
                    _bot()
                    print()
                    time.sleep(2)
                    break

                if status.get("status") == "unknown":
                    msg = str(status.get("message") or "").lower()
                    if "not found" in msg:
                        zw_client.clear_join_state()
                        break

    _enable_ansi()
    _print_banner()
    _top("DEVICE ENROLLMENT")
    _blank()
    _row(f"{C.WHITE}Welcome to ZeroWatch SentinelAgent{C.R}", align="center")
    _row(f"{C.MUTED}Enterprise endpoint protection and asset monitoring{C.R}", align="center")
    _blank()
    _div()
    _blank()
    _row(f"  {C.GREY}This device is not yet enrolled.{C.R}")
    _row(f"  {C.GREY}Enter the Team Code provided by your team admin.{C.R}")
    _blank()
    _row(f"  {C.MUTED}Format: {C.CYAN}6 digits{C.R}")
    _blank()
    _bot()
    print()

    max_attempts = 5
    username_captured = False
    for attempt in range(1, max_attempts + 1):
        _top(f"TEAM CODE - Attempt {attempt} of {max_attempts}")
        _blank()
        team_code = _input_row("Enter Team Code:").strip()
        if not _validate_team_code(team_code):
            _blank()
            _row(f"  {C.ERROR}Invalid format. Expected 6 digits.{C.R}")
            _blank()
            _bot()
            print()
            continue

        _blank()
        _bot()
        print()

        # Capture operator username after team code entry (first valid attempt only).
        if not username_captured:
            default_username = _sanitize_username(zw_client.operator_username)
            entered_username = input(f"{C.CYAN}Username [{default_username}]: {C.R}").strip()
            final_username = _sanitize_username(entered_username or default_username)
            zw_client.operator_username = final_username
            _save_identity_to_fingerprint(zw_client.base_dir, username=final_username)

            default_asset_name = _sanitize_asset_name(
                getattr(zw_client, "asset_name", "") or zw_client.hostname
            )
            entered_asset_name = input(f"{C.CYAN}Asset Name [{default_asset_name}]: {C.R}").strip()
            final_asset_name = _sanitize_asset_name(entered_asset_name or default_asset_name)
            zw_client.asset_name = final_asset_name
            _save_identity_to_fingerprint(zw_client.base_dir, asset_name=final_asset_name, hostname=zw_client.hostname)
            username_captured = True

        _spinner("Submitting join request...", duration=0.8)
        join_resp = zw_client.request_join(team_code)
        if not join_resp.get("success"):
            err = join_resp.get("message", "Unknown error")
            print()
            _top("REQUEST FAILED")
            _blank()
            _row(f"  {C.ERROR}Could not submit join request.{C.R}")
            _row(f"  {C.MUTED}{str(err)[:46]}{C.R}")
            _blank()
            _bot()
            print()
            continue

        _spinner("Waiting for admin approval...", duration=0.8)
        status = zw_client.poll_join_status(timeout=900, interval=5)

        if status.get("status") == "approved":
            print()
            _top("ENROLLMENT SUCCESSFUL")
            _blank()
            _row(f"  {C.SUCCESS}Device approved and enrolled successfully.{C.R}")
            _blank()
            _div()
            _badge("Protection", "READY", ok=True)
            _badge("Link State", "ACTIVE", ok=True)
            _blank()
            _bot()
            print()
            return True

        err = status.get("reason")
        if status.get("status") == "timeout":
            err = "Approval timeout. Please ask your admin to approve the request."
        elif status.get("status") == "denied":
            zw_client.clear_join_state()

        print()
        _top("ACTIVATION FAILED")
        _blank()
        _row(f"  {C.ERROR}Could not enroll this device.{C.R}")
        if err:
            _row(f"  {C.MUTED}{str(err)[:46]}{C.R}")
        if attempt < max_attempts:
            _row(f"  {C.GREY}{max_attempts - attempt} attempt(s) remaining.{C.R}")
        _blank()
        _bot()
        print()

    return False


def _show_status_screen(zw_client):
    _print_banner()
    _refresh_license_state_for_dashboard(zw_client)
    service_running = _is_daemon_running()
    has_token, license_active, enrolled, protection_running = _dashboard_runtime_state(zw_client, service_running)
    now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    _top("AGENT STATUS")
    _blank()
    _row(f"  {_status_dot_text(has_token, license_active, protection_running)}")
    _blank()
    _div()
    _badge("License", _license_badge_text(has_token, license_active), ok=(license_active if has_token else None))
    _badge("Protection", "RUNNING" if protection_running else "STOPPED", ok=protection_running)
    _badge("Enrolled", "YES" if enrolled else "NO", ok=enrolled)
    _badge("Organization", zw_client.organization_display_name(), ok=None)
    _badge("Username", _sanitize_username(getattr(zw_client, "operator_username", "Unknown")), ok=None)
    _badge("Asset Name", _sanitize_asset_name(getattr(zw_client, "asset_name", "Unknown")), ok=None)
    _badge("Agent version", AGENT_VERSION, ok=None)
    _badge("Timestamp", now_utc, ok=None)

    stats = zw_client.get_dashboard_stats() if enrolled else None
    asset_info = zw_client._load_asset_info() if enrolled else None
    
    if stats and stats.get("success"):
        totals = stats.get("totals", {})
        _badge("Open CVEs", str(totals.get("open", 0)), ok=None)
        _badge("Resolved", str(totals.get("resolved", 0)), ok=None)
        _badge("Ignored", str(totals.get("ignored", 0)), ok=None)

    if asset_info and "stats" in asset_info:
        a_stats = asset_info["stats"]
        _div()
        _row(f"  {C.CYAN}REAL-TIME ASSET METRICS{C.R}")
        _badge("Top Severe", a_stats.get("topSevere", [{}])[0].get("cveId", "N/A"), ok=None)
        _badge("Most Affected", a_stats.get("mostAffectedProduct", "N/A"), ok=None)
        _badge("Critical", str(a_stats.get("open_critical", 0)), ok=None)

    _blank()
    _div()
    _blank()
    _row(f"  {C.MUTED}Press ENTER to return...{C.R}")
    _blank()
    _bot()
    print()
    input()


def invoke_disable_cli(zw_client):
    _print_banner()
    _top("DISABLE AGENT")
    _blank()
    _row(f"  {C.WARN}WARNING{C.R}")
    _blank()
    _row(f"  {C.GREY}This action stops local background protection.{C.R}")
    _row(f"  {C.MUTED}The action is logged for auditing.{C.R}")
    _blank()
    _div()
    _blank()
    _row(f"  {C.GREY}Enter administrator password to continue.{C.R}")
    _blank()
    _bot()
    print()

    _top("PASSWORD VERIFICATION")
    _blank()
    password = _secret_row("Administrator password:")
    _blank()
    _bot()
    print()

    if not zw_client.verify_kill(password):
        _top("ACCESS DENIED")
        _blank()
        _row(f"  {C.ERROR}Incorrect password. Agent remains active.{C.R}")
        _blank()
        _bot()
        time.sleep(2)
        return

    base_dir = get_base_dir()
    request_shutdown_signal(base_dir)
    unregister_startup_registry()
    unregister_task_scheduler()
    unregister_windows_service()
    zw_client.log_event("DISABLE_REQUESTED", {"reason": "operator-request"})

    _top("DISABLE SCHEDULED")
    _blank()
    _row(f"  {C.SUCCESS}Shutdown approved and queued.{C.R}")
    _row(f"  {C.MUTED}Background process will stop shortly.{C.R}")
    _blank()
    _bot()
    print()
    time.sleep(2)


def main_cli(zw_client):
    """Activated flow: status, start daemon, and disable controls."""
    _enable_ansi()
    while True:
        _print_banner()
        _refresh_license_state_for_dashboard(zw_client)
        service_running = _is_daemon_running()
        has_token, license_active, enrolled, protection_running = _dashboard_runtime_state(zw_client, service_running)

        _top("SENTINEL AGENT")
        _blank()
        _row(f"  {_status_dot_text(has_token, license_active, protection_running)}")
        _blank()
        _div()
        _badge("License", _license_badge_text(has_token, license_active), ok=(license_active if has_token else None))
        _badge("Protection", "RUNNING" if protection_running else "STOPPED", ok=protection_running)
        _badge("Enrolled", "YES" if enrolled else "NO", ok=enrolled)
        _badge("Organization", zw_client.organization_display_name(), ok=None)
        _badge("Username", _sanitize_username(getattr(zw_client, "operator_username", "Unknown")), ok=None)
        _badge("Asset Name", _sanitize_asset_name(getattr(zw_client, "asset_name", "Unknown")), ok=None)
        _badge("Version", AGENT_VERSION, ok=None)
        _div()
        _blank()
        _menu_item("1", "View agent status")
        _menu_item("2", "Start background daemon")
        _menu_item("3", "Disable agent", danger=True)
        _blank()
        _bot()
        print()

        choice = input(f"{C.CYAN}Select option (1-3, Q to exit): {C.R}").strip().lower()
        if choice == "1":
            _show_status_screen(zw_client)
            continue
        if choice == "2":
            if service_running:
                _print_banner()
                _top("DAEMON ALREADY RUNNING")
                _blank()
                _row(f"  {C.SUCCESS}Background protection is already active.{C.R}")
                _blank()
                _bot()
                print()
                time.sleep(1.5)
                continue

            # Start daemon
            _print_banner()
            _top("STARTING DAEMON")
            _blank()
            _row(f"  {C.CYAN}Launching background agent...{C.R}")
            _blank()
            _bot()
            print()
            started, pid = _spawn_daemon_process()
            _print_banner()
            if started:
                _top("DAEMON STARTED")
                _blank()
                _row(f"  {C.SUCCESS}Background agent running (PID {pid}).{C.R}")
            else:
                _top("DAEMON FAILED")
                _blank()
                _row(f"  {C.ERROR}Could not start background agent.{C.R}")
            _blank()
            _bot()
            print()
            time.sleep(2)
            continue
        if choice == "3":
            invoke_disable_cli(zw_client)
            continue
        if choice in ("q", "quit", "x", "exit"):
            break


def run_interactive():
    """Entry point for EXE double-click: strict conditional flow."""
    ensure_interactive_console()
    base_dir = get_base_dir()
    operator_username = resolve_agent_username(base_dir, prompt=False)
    hostname = resolve_hostname(base_dir)
    asset_name = resolve_asset_name(base_dir, prompt=False, default_hostname=hostname)
    identity = _load_identity_from_fingerprint(base_dir)
    fingerprint = collect_fingerprint()
    export_fingerprint_json(
        base_dir,
        fingerprint,
        username=operator_username,
        asset_name=asset_name,
        hostname=hostname,
        organization_name=identity.get("organization_name"),
    )
    zw_client = ZeroWatchClient(
        base_dir,
        fingerprint['device_id'],
        hostname,
        fingerprint_data=fingerprint,
        operator_username=operator_username,
        asset_name=asset_name,
    )

    # If backend rejects local token (unlinked/revoked), wipe state and re-enroll.
    if zw_client.jwt:
        hb = zw_client.heartbeat()
        if hb is False and zw_client.last_server_status in (401, 403, 404) and zw_client.license_active:
            logging.info(
                "Stored local token rejected by backend (%s). Resetting local state.",
                zw_client.last_server_status,
            )
            zw_client.clear_local_state()

    if not _is_agent_active(zw_client):
        enrolled = enrollment_cli(zw_client)
        if not enrolled:
            return

        # ── Immediate post-enrollment sync ──────────────────────────
        # Run a full inventory scan and heartbeat NOW so the dashboard
        # shows the device immediately instead of waiting for the daemon.
        _print_banner()
        _top("INITIALIZING PROTECTION")
        _blank()
        _row(f"  {C.CYAN}Running initial inventory scan...{C.R}")
        _blank()
        _bot()
        print()

        try:
            software = get_installed_software_registry()
            hardware_data = get_detailed_hardware_profile()
            _spinner("Scanning software inventory...", duration=0.5)
            _spinner("Scanning hardware profile...", duration=0.5)

            sync_ok = zw_client.sync_full(software, hardware_data)
            if sync_ok:
                _spinner("Synced inventory to server", duration=0.3)
            else:
                _spinner("Inventory queued (will sync when daemon starts)", duration=0.3)

            zw_client.heartbeat()
            zw_client.log_event("STARTUP", {
                "version": AGENT_VERSION,
                "status": "active",
                "trigger": "post-enrollment",
                "software_count": len(software),
            })
        except Exception as e:
            logging.warning(f"Post-enrollment sync error (non-fatal): {e}")

        # ── Spawn background daemon ─────────────────────────────────
        started, pid = _spawn_daemon_process()
        _print_banner()
        _top("PROTECTION ACTIVE")
        _blank()
        if started:
            _row(f"  {C.SUCCESS}SentinelAgent is running in background (PID {pid}).{C.R}")
        else:
            _row(f"  {C.WARN}Agent was enrolled, but daemon is not running yet.{C.R}")
        _row(f"  {C.MUTED}You may close this window safely.{C.R}")
        _blank()
        _bot()
        print()
        time.sleep(3)
        return

    # Enrolled endpoints should auto-heal daemon state for operator convenience.
    if not _is_daemon_running():
        try:
            started, pid = _spawn_daemon_process()
            if started:
                logging.info("Interactive launch auto-started daemon (pid=%s).", pid)
            else:
                logging.warning("Interactive launch attempted daemon auto-start but process did not stay alive.")
        except Exception as exc:
            logging.warning("Interactive launch failed to auto-start daemon: %s", exc)

    main_cli(zw_client)


# ============================================================================
# MODULE 7: WATCHDOG — Detached Guardian Process (DACL Fallback)
# ============================================================================

def watchdog_process(target_exe_path):
    """
    Silent background guardian. Completely separate process tree from the main agent.
    If the main agent is killed (DACL failed or was bypassed), the watchdog:
      1. Detects the agent is gone within 5 seconds
      2. Acquires PROMPT_MUTEX so only ONE password prompt runs at a time
      3. Spawns a visible password CLI window
      4. If password correct  -> watchdog exits too (full shutdown)
      5. If password wrong    -> watchdog waits 30s cooldown, then revives agent with --no-watchdog
    """
    time.sleep(5)  # Let the main agent finish starting
    executable_name = os.path.basename(target_exe_path)
    
    logging.info(f"[WATCHDOG] Guardian started for '{executable_name}' (PID: {os.getpid()})")

    # Claim the watchdog mutex
    wd_mutex = ctypes.windll.kernel32.CreateMutexW(None, True, WATCHDOG_MUTEX_NAME)

    while True:
        try:
            # Check if main agent holds its mutex
            agent_mutex = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
            last_err = ctypes.windll.kernel32.GetLastError()
            if agent_mutex:
                ctypes.windll.kernel32.CloseHandle(agent_mutex)

            # Normal state: last_err == 183 (ERROR_ALREADY_EXISTS) meaning main agent holds it.
            # If last_err != 183, the watchdog just successfully acquired the vacant mutex, meaning agent is dead!
            if last_err != 183:
                # If the agent was intentionally shut down (via disable/stop), it will
                # create a shutdown signal file. In that case, the watchdog should
                # not pop up a password prompt.
                base_dir = os.path.dirname(target_exe_path)
                shutdown_file = _shutdown_signal_path(base_dir)
                if os.path.exists(shutdown_file):
                    logging.info("[WATCHDOG] Shutdown signal detected; exiting watchdog.")
                    sys.exit(0)

                logging.info("[WATCHDOG] Main agent killed! Attempting to spawn password prompt...")

                # --- ANTI-FORK-BOMB: only ONE password prompt at a time ---
                prompt_mutex = ctypes.windll.kernel32.CreateMutexW(None, True, PROMPT_MUTEX_NAME)
                prompt_err = ctypes.windll.kernel32.GetLastError()
                if prompt_err == 183:  # Another prompt already running
                    logging.info("[WATCHDOG] Another password prompt is already running. Waiting...")
                    if prompt_mutex:
                        ctypes.windll.kernel32.CloseHandle(prompt_mutex)
                    time.sleep(10)
                    continue

                # Spawn a VISIBLE password prompt as a completely separate process
                if target_exe_path.endswith('.py'):
                    prompt_args = [sys.executable, target_exe_path, "--password-prompt"]
                else:
                    prompt_args = [target_exe_path, "--password-prompt"]
                    
                try:
                    exit_code = subprocess.call(
                        prompt_args,
                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                    )
                except Exception as e:
                    logging.error(f"[WATCHDOG] Failed to spawn password prompt: {e}")
                    exit_code = 1  # If prompt itself crashed, treat as denied
                finally:
                    # Release the prompt mutex
                    if prompt_mutex:
                        ctypes.windll.kernel32.CloseHandle(prompt_mutex)

                if exit_code == 0:
                    # Correct password — authorized shutdown
                    logging.info("[WATCHDOG] Authorized shutdown. Exiting watchdog.")
                    sys.exit(0)
                else:
                    # Wrong password or window closed — REVIVE the agent!
                    logging.info("[WATCHDOG] Unauthorized kill. Reviving main agent (no-watchdog mode)...")
                    # Use --no-watchdog to prevent the revived agent from spawning ANOTHER watchdog
                    # (this watchdog is still alive and monitoring)
                    if target_exe_path.endswith('.py'):
                        subprocess.Popen(
                            [sys.executable, target_exe_path, "--no-watchdog"],
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            startupinfo=_windows_hidden_startupinfo(),
                        )
                    else:
                        subprocess.Popen(
                            [target_exe_path, "--no-watchdog"],
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            startupinfo=_windows_hidden_startupinfo(),
                        )
                    # 30-second cooldown to prevent rapid fork cycling
                    time.sleep(30)

            time.sleep(5)  # Reduced polling frequency (was 3s)
        except Exception as e:
            logging.error(f"[WATCHDOG] Error: {e}")
            time.sleep(5)


# ============================================================================
# MODULE 8: FILE EXPORTS
# ============================================================================

def export_fingerprint_json(base_dir, fingerprint, username=None, asset_name=None, hostname=None, organization_name=None):
    """Exports merged fingerprint + identity metadata to device_fingerprint.json."""
    payload = dict(_read_fingerprint_json(base_dir))
    payload.update(fingerprint or {})
    if username is not None:
        payload["username"] = _sanitize_username(username)
    if asset_name is not None:
        payload["asset_name"] = _sanitize_asset_name(asset_name)
    if hostname is not None:
        payload["hostname"] = _sanitize_hostname(hostname)
    if organization_name is not None:
        payload["organization_name"] = _sanitize_organization_name(organization_name)
    payload["identity_updated_at"] = datetime.datetime.now().isoformat()
    filepath = _fingerprint_json_path(base_dir)
    _write_fingerprint_json(base_dir, payload)
    logging.info(f"Fingerprint saved: {filepath}")

def export_products_csv(base_dir, inventory):
    """Exports the full inventory to products.csv."""
    filepath = _state_path(base_dir, "products.csv")
    if not inventory:
        return

    fieldnames = ["category", "name", "vendor", "version", "serial_number",
                  "install_date", "install_location", "extra_info", "source",
                  "last_seen", "change_type"]

    from io import StringIO

    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(inventory)
    serialized = buffer.getvalue().encode("utf-8")
    encrypted = encrypt_data(serialized)
    data_to_write = encrypted if encrypted else serialized
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    temp_path = f"{filepath}.tmp"
    with open(temp_path, "wb") as f:
        f.write(data_to_write)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, filepath)
    try:
        subprocess.run(
            ["attrib", "+H", "+S", filepath],
            capture_output=True,
            text=True,
            timeout=3,
            startupinfo=_windows_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass
    logging.info(f"Products CSV saved: {filepath} ({len(inventory)} items)")


# ============================================================================
# MODULE 9: MAIN ORCHESTRATOR
# ============================================================================

def show_windows_notification(title, message):
    """Shows a native Windows toast notification."""
    try:
        temp_dir = os.environ.get('TEMP', 'C:\\Windows\\Temp')
        ps_script = (
            '[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms");'
            '$objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon;'
            '$objNotifyIcon.Icon = [System.Drawing.SystemIcons]::Information;'
            f'$objNotifyIcon.BalloonTipTitle = "{title}";'
            f'$objNotifyIcon.BalloonTipText = "{message}";'
            '$objNotifyIcon.Visible = $True;'
            '$objNotifyIcon.ShowBalloonTip(5000);'
            'Start-Sleep -Seconds 5;'
            '$objNotifyIcon.Dispose();'
        )
        import shutil
        ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        zw_exe = os.path.join(temp_dir, "SentinelAgent.exe")
        try:
            if not os.path.exists(zw_exe):
                shutil.copy2(ps_exe, zw_exe)
            ps_path = zw_exe
        except Exception:
            ps_path = "powershell"
        
        # Run powershell detached
        subprocess.Popen([ps_path, "-WindowStyle", "Hidden", "-Command", ps_script], 
                         creationflags=subprocess.CREATE_NO_WINDOW)
        
        logging.info(f"Showed notification: {title} - {message}")
    except Exception as e:
        logging.error(f"Failed to show notification: {e}")

def hide_console():
    """Hides the console window so the agent runs invisibly."""
    whnd = ctypes.windll.kernel32.GetConsoleWindow()
    if whnd != 0:
        ctypes.windll.user32.ShowWindow(whnd, 0)  # SW_HIDE

def main_agent():
    """
    The core agent loop. Runs silently in the background.
    """
    # --- Bootstrap ---
    mutex = enforce_single_instance()
    # Console hiding moved down so user can enroll on first run
    
    logging.info("=" * 50)
    logging.info(f"SentinelAgent v{AGENT_VERSION} starting (PID: {os.getpid()})")
    logging.info("=" * 50)

    hardened_mode = _is_hardened_mode()
    logging.info(
        "Hardening profile: %s",
        "enabled (--hardened)" if hardened_mode else "standard (default)",
    )

    # --- Self-Protection ---
    ctrl_handler_ref = install_ctrl_handler()
    if hardened_mode:
        dacl_ok = harden_process_acl()
    else:
        dacl_ok = False
        logging.info("Skipping process ACL hardening in standard profile.")

    # --- Spawn Watchdog (unless --no-watchdog flag is set) ---
    skip_watchdog = "--no-watchdog" in sys.argv
    
    def spawn_watchdog():
        exe_path = get_exe_path()
        if exe_path.endswith('.py'):
            watchdog_args = [sys.executable, exe_path, "--watchdog", exe_path]
        else:
            watchdog_args = [exe_path, "--watchdog", exe_path]
        DETACHED = 0x00000008
        NEW_GROUP = 0x00000200
        subprocess.Popen(
            watchdog_args,
            creationflags=DETACHED | NEW_GROUP | subprocess.CREATE_NO_WINDOW,
            startupinfo=_windows_hidden_startupinfo(),
        )
        logging.info("Watchdog guardian spawned as detached process.")

    if not skip_watchdog:
        spawn_watchdog()
    else:
        logging.info("Skipping watchdog spawn (--no-watchdog mode, existing watchdog is monitoring).")

    # --- Persistence ---
    task_ok = register_task_scheduler()
    if not task_ok:
        logging.warning("Scheduled task setup failed, falling back to Run-key startup registration.")
        register_startup_registry()

    if hardened_mode:
        register_windows_service()
    else:
        logging.info("Skipping Windows service persistence in standard profile.")

    # --- Working directory for output files ---
    base_dir = get_base_dir()
    operator_username = resolve_agent_username(base_dir, prompt=False)
    hostname = resolve_hostname(base_dir)
    asset_name = resolve_asset_name(base_dir, prompt=False, default_hostname=hostname)
    identity = _load_identity_from_fingerprint(base_dir)

    # --- Fingerprint ---
    logging.info("Collecting device fingerprint...")
    cached_fp = _read_fingerprint_json(base_dir)
    if cached_fp.get("device_id"):
        logging.info("Using cached device fingerprint.")
        fingerprint = cached_fp
    else:
        logging.info("No cached fingerprint; collecting fresh hardware ID.")
        fingerprint = collect_fingerprint()

    export_fingerprint_json(
        base_dir,
        fingerprint,
        username=operator_username,
        asset_name=asset_name,
        hostname=hostname,
        organization_name=identity.get("organization_name"),
    )
    logging.info(f"Device ID: {fingerprint['device_id']}")
    _append_gui_log(base_dir, f"Daemon Startup: device_id={fingerprint['device_id']}")

    # --- Initialize API Client ---
    zw_client = ZeroWatchClient(
        base_dir,
        fingerprint['device_id'],
        hostname,
        fingerprint_data=fingerprint,
        operator_username=operator_username,
        asset_name=asset_name,
    )

    # If no JWT, attempt join-request flow (team code based enrollment)
    if not _wait_for_enrollment(zw_client, base_dir):
        return

    # --- Protect agent files on disk ---
    if hardened_mode:
        protect_agent_files()
    else:
        logging.info("Skipping file ACL protection in standard profile.")


    # --- Full Inventory ---
    if is_inventory_scan_enabled():
        show_windows_notification("Zerowatch", "Sentinel Agent running in Background")
        logging.info("Running full software + hardware inventory...")
        # Get software list
        software = get_installed_software_registry()
        
        # Get high-fidelity hardware profile
        hardware_data = get_detailed_hardware_profile()

        logging.info("Syncing full inventory to backend via JSON...")
        zw_client.sync_full(software, hardware_data)
        show_windows_notification("Zerowatch", "Sentinel Agent stopped scanning")
    else:
        logging.info("Inventory scan is disabled in settings. Skipping initial full scan.")
        
    zw_client.log_event("STARTUP", {"version": AGENT_VERSION, "status": "active"})

    # --- Background Monitor ---
    logging.info("Starting background change monitor...")
    monitor = threading.Thread(
        target=monitor_system_changes,
        args=(base_dir, fingerprint, zw_client),
        daemon=True
    )
    monitor.start()

    # --- Heartbeat & Mutual Monitoring Loop ---
    logging.info("Entering heartbeat loop. Agent is fully active.")
    last_heartbeat = 0
    last_watchdog_check = 0
    last_asset_poll = 0
    was_offline = False
    while True:
        try:
            shutdown_request = consume_shutdown_signal(base_dir)
            if shutdown_request:
                reason = shutdown_request.get("reason", "manual-disable")
                logging.info(f"Shutdown signal received. Reason: {reason}")
                zw_client.log_event("SHUTDOWN", {"reason": reason, "source": "shutdown-signal"})
                unregister_startup_registry()
                unregister_task_scheduler()
                unregister_windows_service()
                break

            time.sleep(30)  # Base loop interval
            now = time.time()

            # --- Connectivity-aware offline queue flush ---
            network_ok = check_backend_connectivity()
            if not network_ok:
                if not was_offline:
                    was_offline = True
                    logging.warning("[OFFLINE] Backend network unavailable. Running local collection mode.")
                flush_result = {"flushed": 0, "pending": 0, "attempted": 0}
            else:
                flush_result = zw_client.flush_offline_queue(network_available=True)

            if flush_result.get("flushed", 0) > 0:
                if was_offline:
                    was_offline = False
                    logging.info(
                        "[ONLINE] Connection restored. Flushed %s queued requests.",
                        flush_result.get("flushed", 0),
                    )
                    zw_client.log_event("RECONNECTED", {"flushed_count": flush_result.get("flushed", 0)})
            
            # Check if Watchdog is still alive (every 60s)
            if not skip_watchdog and (now - last_watchdog_check) > 60:
                last_watchdog_check = now
                wd = ctypes.windll.kernel32.CreateMutexW(None, True, WATCHDOG_MUTEX_NAME)
                wd_err = ctypes.windll.kernel32.GetLastError()
                if wd:
                    ctypes.windll.kernel32.CloseHandle(wd)
                
                if wd_err != 183:
                    logging.warning("[MAIN] Watchdog missing! Reviving watchdog...")
                    spawn_watchdog()

            # Poll asset info every 15 minutes
            if (now - last_asset_poll) >= 15 * 60:
                last_asset_poll = now
                logging.info("[MAIN] Polling asset info...")
                asset_info = zw_client.get_asset_info()
                if asset_info:
                    zw_client._save_asset_info(asset_info)
                    logging.info("[MAIN] Asset info updated.")

            # Heartbeat to backend every HEARTBEAT_INTERVAL
            if (now - last_heartbeat) >= HEARTBEAT_INTERVAL:
                last_heartbeat = now
                license_was_active = zw_client.license_active
                if license_was_active:
                    result = zw_client.heartbeat()
                else:
                    result = zw_client.check_license_reactivation()
                license_is_active = zw_client.license_active

                if result is None:
                    if not was_offline:
                        was_offline = True
                        logging.warning("[OFFLINE] Lost connection to backend. Queuing events locally.")
                        zw_client.log_event("DISCONNECTED", {"reason": "heartbeat_failed"})
                elif license_was_active and not license_is_active:
                    logging.info("[LICENSE] License inactive. Pausing telemetry and heartbeat until renewed.")
                elif (not license_was_active) and license_is_active:
                    logging.info("[LICENSE] License renewed. Resuming heartbeat and data collection.")
                    software = get_installed_software_registry()
                    hardware_data = get_detailed_hardware_profile()
                    zw_client.sync_full(software, hardware_data)
                    zw_client.log_event("LICENSE_RENEWED", {"status": "active"})
                elif result is True:
                    logging.info("[HEARTBEAT] Success (status=%s).", zw_client.last_server_status)
                    if was_offline:
                        was_offline = False
                        logging.info("[ONLINE] Reconnected to backend.")
                        zw_client.log_event("RECONNECTED", {"reason": "heartbeat_success"})
                elif result == "unlinked":
                    logging.warning("[LINK] Device was unlinked remotely. Resetting local state.")
                    zw_client.clear_local_state()
                    if not _wait_for_enrollment(zw_client, base_dir):
                        break
                    software = get_installed_software_registry()
                    hardware_data = get_detailed_hardware_profile()
                    zw_client.sync_full(software, hardware_data)
                    zw_client.log_event("REENROLLED", {"status": "active"})
                    last_heartbeat = 0
                    was_offline = False
                elif result is False and zw_client.last_server_status in (401, 403):
                    # SAFETY LATCH: Only clear state if failure is persistent (3+ times)
                    # This prevents nuking enrollment on transient clock skew or proxy errors.
                    zw_client.auth_failure_count += 1
                    logging.warning(
                        "[AUTH] Server returned %s (%d/3). Retrying...",
                        zw_client.last_server_status, zw_client.auth_failure_count
                    )
                    if zw_client.auth_failure_count >= 3:
                        logging.error("[AUTH] Persistent authentication failure. Wiping enrollment for security.")
                        zw_client.clear_local_state()
                        if not _wait_for_enrollment(zw_client, base_dir):
                            break
                        # Reset state after successful re-enrollment
                        zw_client.auth_failure_count = 0
                        software = get_installed_software_registry()
                        hardware_data = get_detailed_hardware_profile()
                        zw_client.sync_full(software, hardware_data)
                        zw_client.log_event("REENROLLED", {"status": "active"})
                        last_heartbeat = 0
                        was_offline = False
                else:
                    # Successful heartbeat or non-auth error (e.g. 500), reset latch
                    if result is True:
                        zw_client.auth_failure_count = 0
        except Exception as e:
            logging.error(f"Heartbeat error: {e}")
            time.sleep(10)

    logging.info("SentinelAgent shutdown completed.")
class EnrollmentFrame(tk.Frame):
    def __init__(self, master, zw_client):
        super().__init__(master)
        self.zw_client = zw_client
        self.configure(bg="#13171d")
        
        # Colors
        self.c_bg_main = "#13171d"
        self.c_cyan = "#00e5ff"
        self.c_cyan_hover = "#00c4db"
        self.c_white = "#ffffff"
        self.c_gray = "#79838c"
        self.c_card_bg = "#181d24"
        self.c_card_border = "#1d333b"
        self.c_input_bg = "#13171d"
        self.c_input_border = "#2a313a"
        
        # Fonts
        self.f_card_header = ("Courier New", 13, "bold")
        self.f_card_title = ("Arial", 16, "bold")
        self.f_card_sub = ("Arial", 12)
        self.f_badge = ("Arial", 14, "bold")
        self.f_btn = ("Arial", 14)
        self.f_input = ("Courier New", 20, "bold")
        self.f_normal = ("Arial", 11)
        
        if self.zw_client.has_pending_join():
            self.state = "PENDING"
            self.team_code = (self.zw_client.join_state or {}).get("teamCode") or ""
        else:
            self.state = "TEAM_CODE" # TEAM_CODE -> METADATA -> PENDING
            
        self.team_code = ""
        self.individual_code = ""
        self.is_individual = False
            
        self._polling_active = False
        self._stop_event = threading.Event()
        self.setup_ui()
        self._start_polling()

    def destroy(self):
        self._stop_event.set()
        super().destroy()
        
    def setup_ui(self):
        # Main Content Area
        main_content = tk.Frame(self, bg=self.c_bg_main)
        main_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        container = tk.Frame(main_content, bg=self.c_bg_main)
        container.place(relx=0.5, rely=0.45, anchor=tk.CENTER)
        
        title_label = tk.Label(container, text="Sentinel Agent", fg=self.c_white, bg=self.c_bg_main, font=("Arial", 36, "bold italic"))
        title_label.pack(pady=(0, 20))
        
        # Center Card
        self.card = tk.Frame(container, bg=self.c_card_bg, highlightbackground=self.c_cyan, highlightcolor=self.c_cyan, highlightthickness=1, padx=60, pady=60)
        self.card.pack()
        
        # Create screens as frames inside self.card
        self.screens = {}
        self.screens["TEAM_CODE"] = self._create_team_code_screen()
        self.screens["INDIVIDUAL_CODE"] = self._create_individual_code_screen()
        self.screens["METADATA"] = self._create_metadata_screen()
        self.screens["PENDING"] = self._create_pending_screen()
        
        settings_btn = tk.Button(main_content, text="⚙ Settings", bg=self.c_bg_main, fg=self.c_cyan, font=self.f_btn, bd=0, activebackground=self.c_bg_main, activeforeground=self.c_cyan_hover, cursor="hand2", command=self.show_settings_popup)
        settings_btn.place(relx=0.98, rely=0.02, anchor=tk.NE)
            
        self.show_screen(self.state)

    def show_settings_popup(self):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
            
        if not is_admin:
            import tkinter.messagebox as mb
            mb.showerror("Access Denied", "This feature can only be accessed with administrator access.")
            return

        popup = tk.Toplevel(self)
        popup.title("SETTINGS")
        popup.geometry("600x400")
        popup.configure(bg=self.c_bg_main)
        popup.resizable(False, False)
        
        header = tk.Frame(popup, bg=self.c_bg_main)
        header.pack(fill=tk.X, pady=(20, 20), padx=20)
        tk.Label(header, text="SETTINGS", fg=self.c_white, bg=self.c_bg_main, font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        
        desc = tk.Label(popup, text="Configure agent system settings. Changes require administrator privileges.", fg=self.c_gray, bg=self.c_bg_main, font=self.f_normal, justify=tk.LEFT)
        desc.pack(anchor="w", pady=(0, 20), padx=20)
        
        container = tk.Frame(popup, bg=self.c_bg_main)
        container.pack(fill=tk.BOTH, expand=True, padx=20)
        
        card = tk.Frame(container, bg=self.c_card_bg, highlightbackground=self.c_card_border, highlightthickness=1, padx=20, pady=15)
        card.pack(fill=tk.X, pady=5)
        
        top = tk.Frame(card, bg=self.c_card_bg)
        top.pack(fill=tk.X)
        tk.Label(top, text="Inventory Scan", fg=self.c_cyan, bg=self.c_card_bg, font=("Arial", 11, "bold")).pack(side=tk.LEFT)
        
        inventory_enabled = tk.BooleanVar()
        inventory_enabled.set(is_inventory_scan_enabled())
            
        def toggle_inventory():
            set_inventory_scan_enabled(inventory_enabled.get())
                
        chk = tk.Checkbutton(top, variable=inventory_enabled, bg=self.c_card_bg, activebackground=self.c_card_bg, command=toggle_inventory)
        chk.pack(side=tk.RIGHT)
        
        tk.Label(card, text="Automatically scan and collect hardware and software inventory.", fg=self.c_gray, bg=self.c_card_bg, font=("Arial", 9), justify=tk.LEFT).pack(anchor="w", pady=(10,0))

    def show_screen(self, state):
        self.state = state
        for name, frame in self.screens.items():
            if name == state:
                frame.pack(fill=tk.BOTH, expand=True)
            else:
                frame.pack_forget()

    def _create_team_code_screen(self):
        frame = tk.Frame(self.card, bg=self.c_card_bg)
        
        # Header
        header_frame = tk.Frame(frame, bg=self.c_card_bg)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        canvas_line = tk.Canvas(header_frame, height=20, width=550, bg=self.c_card_bg, highlightthickness=0)
        canvas_line.pack()
        canvas_line.create_line(50, 10, 180, 10, fill=self.c_card_border)
        canvas_line.create_text(275, 10, text="[ DEVICE ENROLLMENT ]", fill=self.c_white, font=self.f_card_header)
        canvas_line.create_line(370, 10, 500, 10, fill=self.c_card_border)
        
        tk.Label(frame, text="WELCOME TO ZEROWATCH SENTINEL AGENT", fg=self.c_white, bg=self.c_card_bg, font=self.f_card_title).pack()
        tk.Label(frame, text="Enterprise Asset Monitoring", fg=self.c_white, bg=self.c_card_bg, font=self.f_card_sub).pack(pady=(5, 40))
        
        tk.Label(frame, text="ENTER TEAM CODE", fg=self.c_cyan, bg=self.c_card_bg, font=self.f_badge).pack(pady=(0, 18))
        
        input_frame = tk.Frame(frame, bg=self.c_card_bg)
        input_frame.pack(pady=(0, 40))
        
        self.code_entries = []
        for i in range(6):
            f = tk.Frame(input_frame, bg=self.c_input_bg, highlightbackground=self.c_cyan, highlightthickness=1, width=55, height=65)
            f.pack(side=tk.LEFT, padx=(0, 10))
            f.pack_propagate(False)
            entry = tk.Entry(f, fg=self.c_cyan, bg=self.c_input_bg, font=self.f_input, justify='center', bd=0, highlightthickness=0, insertbackground=self.c_cyan)
            entry.pack(expand=True, fill=tk.BOTH, pady=12)
            self.code_entries.append(entry)
            
            def key_release(event, idx=i):
                if event.keysym in ("BackSpace", "Left", "Right", "Tab"): return
                content = self.code_entries[idx].get()
                if len(content) > 0:
                    if len(content) > 1:
                        self.code_entries[idx].delete(0, tk.END)
                        self.code_entries[idx].insert(0, content[-1])
                    if idx < 5: self.code_entries[idx+1].focus_set()

            def key_press(event, idx=i):
                if event.keysym == "BackSpace":
                    if len(self.code_entries[idx].get()) == 0 and idx > 0:
                        self.code_entries[idx-1].focus_set()
                        self.code_entries[idx-1].delete(0, tk.END)
                        
            entry.bind("<KeyRelease>", key_release)
            entry.bind("<KeyPress>", key_press)

        self.code_entries[0].focus_set()
        
        btn_frame = tk.Frame(frame, bg=self.c_cyan, pady=15, cursor="hand2")
        btn_frame.pack(fill=tk.X)
        btn_label = tk.Label(btn_frame, text="◎ NEXT", fg="black", bg=self.c_cyan, font=self.f_btn)
        btn_label.pack()

        link_label = tk.Label(frame, text="Don't have a team? Register your asset here.", fg=self.c_cyan, bg=self.c_card_bg, font=("Arial", 10, "underline"), cursor="hand2")
        link_label.pack(pady=(15, 0))
        def go_to_individual(e): self.show_screen("INDIVIDUAL_CODE")
        link_label.bind("<Button-1>", go_to_individual)

        self.status_label_team = tk.Label(frame, text="", fg=self.c_gray, bg=self.c_card_bg, font=("Arial", 10))
        self.status_label_team.pack(pady=(16, 0))
        
        def on_click(e): self._validate_team_code()
        btn_frame.bind("<Button-1>", on_click)
        btn_label.bind("<Button-1>", on_click)
        
        return frame

    def _create_metadata_screen(self):
        frame = tk.Frame(self.card, bg=self.c_card_bg)
        
        tk.Label(frame, text="DEVICE IDENTITY", fg=self.c_white, bg=self.c_card_bg, font=self.f_card_title).pack()
        tk.Label(frame, text="Configure how this asset appears on your dashboard", fg=self.c_gray, bg=self.c_card_bg, font=self.f_card_sub).pack(pady=(5, 30))
        
        # User Name
        tk.Label(frame, text="USER NAME", fg=self.c_cyan, bg=self.c_card_bg, font=self.f_badge).pack(anchor="w")
        u_frame = tk.Frame(frame, bg=self.c_input_bg, highlightbackground=self.c_input_border, highlightthickness=1)
        u_frame.pack(fill=tk.X, pady=(10, 20))
        self.user_entry = tk.Entry(u_frame, fg=self.c_white, bg=self.c_input_bg, font=self.f_normal, bd=0, highlightthickness=0, insertbackground=self.c_cyan)
        self.user_entry.pack(fill=tk.X, padx=15, pady=10)
        self.user_entry.insert(0, self.zw_client.operator_username)

        # Device Name
        tk.Label(frame, text="DEVICE / ASSET NAME", fg=self.c_cyan, bg=self.c_card_bg, font=self.f_badge).pack(anchor="w")
        d_frame = tk.Frame(frame, bg=self.c_input_bg, highlightbackground=self.c_input_border, highlightthickness=1)
        d_frame.pack(fill=tk.X, pady=(10, 40))
        self.device_entry = tk.Entry(d_frame, fg=self.c_white, bg=self.c_input_bg, font=self.f_normal, bd=0, highlightthickness=0, insertbackground=self.c_cyan)
        self.device_entry.pack(fill=tk.X, padx=15, pady=10)
        self.device_entry.insert(0, self.zw_client.asset_name)

        btn_frame = tk.Frame(frame, bg=self.c_cyan, pady=15, cursor="hand2")
        btn_frame.pack(fill=tk.X)
        btn_label = tk.Label(btn_frame, text="◎ COMPLETE ENROLLMENT", fg="black", bg=self.c_cyan, font=self.f_btn)
        btn_label.pack()

        self.status_label_meta = tk.Label(frame, text="", fg=self.c_gray, bg=self.c_card_bg, font=("Arial", 10))
        self.status_label_meta.pack(pady=(16, 0))

        def on_click(e): self._submit_enrollment()
        btn_frame.bind("<Button-1>", on_click)
        btn_label.bind("<Button-1>", on_click)
        
        return frame

    def _create_pending_screen(self):
        frame = tk.Frame(self.card, bg=self.c_card_bg)
        
        tk.Label(frame, text="ENROLLMENT PENDING", fg=self.c_cyan, bg=self.c_card_bg, font=self.f_card_title).pack()
        tk.Label(frame, text="Waiting for admin approval...", fg=self.c_white, bg=self.c_card_bg, font=self.f_card_sub).pack(pady=(20, 40))
        
        # Loading animation (simulated)
        self.loader = tk.Label(frame, text="⠿", fg=self.c_cyan, bg=self.c_card_bg, font=("Arial", 48))
        self.loader.pack()
        
        self.status_label_pending = tk.Label(frame, text="Your request has been submitted successfully.", fg=self.c_gray, bg=self.c_card_bg, font=self.f_normal)
        self.status_label_pending.pack(pady=(30, 0))
        
        def on_cancel():
            self.zw_client.clear_join_state() # clear state
            self.show_screen("TEAM_CODE")
            
        cancel_btn = tk.Button(frame, text="Cancel Request", bg=self.c_card_bg, fg=self.c_gray, font=self.f_normal, bd=0, activebackground=self.c_card_bg, activeforeground=self.c_white, cursor="hand2", command=on_cancel)
        cancel_btn.pack(pady=(20, 0))
        
        return frame

    def _validate_team_code(self):
        code = "".join(e.get().strip() for e in self.code_entries)
        if len(code) != 6:
            self.status_label_team.config(text="Please enter a 6-digit code", fg="#f87171")
            return
        
        self.team_code = code
        self.show_screen("METADATA")

    def _create_individual_code_screen(self):
        frame = tk.Frame(self.card, bg=self.c_card_bg)
        
        # Header
        header_frame = tk.Frame(frame, bg=self.c_card_bg)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        canvas_line = tk.Canvas(header_frame, height=20, width=550, bg=self.c_card_bg, highlightthickness=0)
        canvas_line.pack()
        canvas_line.create_line(50, 10, 180, 10, fill=self.c_card_border)
        canvas_line.create_text(275, 10, text="[ INDIVIDUAL ENROLLMENT ]", fill=self.c_white, font=self.f_card_header)
        canvas_line.create_line(390, 10, 500, 10, fill=self.c_card_border)
        
        tk.Label(frame, text="WELCOME TO ZEROWATCH SENTINEL AGENT", fg=self.c_white, bg=self.c_card_bg, font=self.f_card_title).pack()
        tk.Label(frame, text="Premium Individual Registration", fg=self.c_white, bg=self.c_card_bg, font=self.f_card_sub).pack(pady=(5, 40))
        
        tk.Label(frame, text="ENTER REGISTRATION CODE", fg=self.c_cyan, bg=self.c_card_bg, font=self.f_badge).pack(pady=(0, 18))
        
        input_frame = tk.Frame(frame, bg=self.c_card_bg)
        input_frame.pack(pady=(0, 40))
        
        self.indiv_entries = []
        for i in range(6):
            f = tk.Frame(input_frame, bg=self.c_input_bg, highlightbackground=self.c_cyan, highlightthickness=1, width=55, height=65)
            f.pack(side=tk.LEFT, padx=(0, 10))
            f.pack_propagate(False)
            entry = tk.Entry(f, fg=self.c_cyan, bg=self.c_input_bg, font=self.f_input, justify='center', bd=0, highlightthickness=0, insertbackground=self.c_cyan)
            entry.pack(expand=True, fill=tk.BOTH, pady=12)
            self.indiv_entries.append(entry)
            
            def key_release(event, idx=i):
                if event.keysym in ("BackSpace", "Left", "Right", "Tab"): return
                content = self.indiv_entries[idx].get()
                if len(content) > 0:
                    if len(content) > 1:
                        self.indiv_entries[idx].delete(0, tk.END)
                        self.indiv_entries[idx].insert(0, content[-1])
                    if idx < 5: self.indiv_entries[idx+1].focus_set()

            def key_press(event, idx=i):
                if event.keysym == "BackSpace":
                    if len(self.indiv_entries[idx].get()) == 0 and idx > 0:
                        self.indiv_entries[idx-1].focus_set()
                        self.indiv_entries[idx-1].delete(0, tk.END)
                        
            entry.bind("<KeyRelease>", key_release)
            entry.bind("<KeyPress>", key_press)

        self.indiv_entries[0].focus_set()
        
        btn_frame = tk.Frame(frame, bg=self.c_cyan, pady=15, cursor="hand2")
        btn_frame.pack(fill=tk.X)
        btn_label = tk.Label(btn_frame, text="◎ NEXT", fg="black", bg=self.c_cyan, font=self.f_btn)
        btn_label.pack()

        link_label = tk.Label(frame, text="Back to Team Registration", fg=self.c_cyan, bg=self.c_card_bg, font=("Arial", 10, "underline"), cursor="hand2")
        link_label.pack(pady=(15, 0))
        def go_to_team(e): self.show_screen("TEAM_CODE")
        link_label.bind("<Button-1>", go_to_team)

        self.status_label_indiv = tk.Label(frame, text="", fg=self.c_gray, bg=self.c_card_bg, font=("Arial", 10))
        self.status_label_indiv.pack(pady=(16, 0))
        
        def on_click(e): self._validate_individual_code()
        btn_frame.bind("<Button-1>", on_click)
        btn_label.bind("<Button-1>", on_click)
        
        return frame

    def _validate_individual_code(self):
        code = "".join(e.get().strip() for e in self.indiv_entries)
        if len(code) != 6:
            self.status_label_indiv.config(text="Please enter a 6-digit code", fg="#f87171")
            return
        
        self.individual_code = code
        self.is_individual = True
        self.show_screen("METADATA")


    def _submit_enrollment(self):
        if getattr(self, "_submitting", False):
            return
            
        u_name = self.user_entry.get().strip()
        d_name = self.device_entry.get().strip()
        
        if not u_name or not d_name:
            self.status_label_meta.config(text="Both names are required", fg="#f87171")
            return

        self.zw_client.operator_username = u_name
        self.zw_client.asset_name = d_name
        
        # Run join request in background
        self.status_label_meta.config(text="Connecting to server...", fg=self.c_cyan)
        self._submitting = True
        threading.Thread(target=self._run_join, daemon=True).start()

    def _run_join(self):
        try:
            if getattr(self, "is_individual", False):
                res = self.zw_client.request_individual_join(self.individual_code)
                if res.get("success") and res.get("jwt"):
                    self.after(0, self._on_success)
                else:
                    msg = res.get("message", "Registration failed")
                    self.after(0, lambda: self.status_label_meta.config(text=msg, fg="#f87171"))
                self._submitting = False
                return

            res = self.zw_client.request_join(self.team_code)
            if res.get("success"):
                if res.get("status") == "approved":
                    self.after(0, self._on_success)
                else:
                    self.after(0, lambda: self._goto_pending())
            else:
                msg = res.get("message", "Network error")
                self.after(0, lambda: self.status_label_meta.config(text=msg, fg="#f87171"))
        finally:
            self._submitting = False

    def _goto_pending(self):
        self.show_screen("PENDING")
        self._start_polling()

    def _start_polling(self):
        if self._polling_active:
            return
        self._polling_active = True
        self._stop_event.clear()

        def poll():
            while not self._stop_event.is_set(): # Keep polling even if not in PENDING, to handle auto-routing if server comes back
                res = self.zw_client.refresh_join_status_once()
                if res.get("status") == "approved":
                    self.after(0, self._on_success)
                    break
                elif res.get("status") == "denied":
                    if self.state == "PENDING":
                        self.after(0, lambda: self._on_denied(res.get("reason")))
                elif res.get("status") == "unknown":
                    pass
                
                # Check sleep in small increments
                for _ in range(20):
                    if self._stop_event.is_set():
                        break
                    time.sleep(0.5)
        threading.Thread(target=poll, daemon=True).start()

    def _on_success(self):
        """Handle successful enrollment: transition to dashboard and setup persistence in background."""
        if getattr(self, "_enrollment_completed", False):
            return
        self._enrollment_completed = True

        # 1. Immediate UI transition to Dashboard
        self.master.show_dashboard()

        # 2. Heavy system tasks in a background thread to prevent UI freeze
        def _post_enrollment_tasks():
            _append_gui_log(self.zw_client.base_dir, "Starting post-enrollment system integration...")
            
            # Register startup persistence so daemon survives reboots
            try:
                task_ok = register_task_scheduler()
                if not task_ok:
                    register_startup_registry()
            except Exception as exc:
                logging.warning("Post-enrollment persistence registration failed: %s", exc)

            # Spawn the background daemon process (detached, survives window close)
            try:
                if not _is_daemon_running():
                    started, pid = _spawn_daemon_process()
                    if started:
                        logging.info("Post-enrollment daemon spawned (pid=%s).", pid)
                    else:
                        logging.warning("Post-enrollment daemon spawn returned no PID.")
            except Exception as exc:
                logging.warning("Post-enrollment daemon spawn failed: %s", exc)
                
            _append_gui_log(self.zw_client.base_dir, "Post-enrollment integration completed.")

        threading.Thread(target=_post_enrollment_tasks, daemon=True).start()

    def _on_denied(self, reason):
        self.show_screen("TEAM_CODE")
        self.status_label_team.config(text=f"Denied: {reason}", fg="#f87171")

class DashboardFrame(tk.Frame):
    def __init__(self, master, zw_client):
        super().__init__(master)
        self.zw_client = zw_client
        
        # Colors based on the ZeroWatch UI
        self.c_bg_base = "#0d0f14"      # Main background
        self.c_bg_sidebar = "#00011e"   # Sidebar background
        self.c_bg_card = "#0d0f14"      # Card background
        self.c_border = "#2a2d3d"       # Borders
        self.c_white = "#ffffff"        # Primary text
        self.c_gray = "#8b949e"         # Secondary text
        self.c_cyan = "#00e5ff"         # Accent cyan
        self.c_cyan_dark = "#005c66"    # Dark cyan for active states
        self.c_red = "#f85149"          # Critical
        self.c_orange = "#d29922"       # High
        self.c_yellow = "#ffd33d"       # Medium
        self.c_green = "#2ea043"        # System online/Resolved
        
        # Fonts
        self.f_menu = ("Arial", 10, "bold")
        self.f_card_sub = ("Arial", 12)
        self.f_metric_val = ("Arial", 22, "bold")
        self.f_metric_label = ("Arial", 9, "bold")
        self.f_normal_bold = ("Arial", 10, "bold")
        self.f_normal = ("Arial", 10)
        self.f_small = ("Arial", 8)
        
        self.metric_labels = {}
        self.metric_cards = {}
        self.cve_tables = {}
        self.bar_chart_widgets = {}
        self.pie_chart_widgets = {}
        self.line_chart_widgets = {}
        self.distribution_chart = {}

        self.setup_layout()
        self.build_sidebar()
        self.build_main_area()
        
        # Responsive binding
        self.bind("<Configure>", self.on_window_resize)
        
        # Load cached data immediately for zero-latency startup
        cached = self.zw_client._load_dashboard_cache()
        if cached:
            info = cached.get("data", {})
            stats = info.get("stats", {}) or {}
            self.after(50, lambda: self._update_ui(info, stats, status="Offline (Cached)"))
        
        # Initial data fetch
        self.after(200, self.fetch_dashboard_data)

    def on_window_resize(self, event):
        if event.widget == self:
            width = event.width
            if width < 800:
                self.sidebar.grid_remove()
            else:
                self.sidebar.grid()
            self.refresh_responsive_layout(width)

    def refresh_responsive_layout(self, width):
        if width < 1000:
            cols_metrics = 3
            cols_charts = 1
        elif width < 1400:
            cols_metrics = 4
            cols_charts = 2
        else:
            cols_metrics = 6
            cols_charts = 2
            
        if hasattr(self, 'metrics_frame'):
            for i in range(6):
                self.metrics_frame.grid_columnconfigure(i, weight=0, uniform="")
            for i in range(cols_metrics):
                self.metrics_frame.grid_columnconfigure(i, weight=1, uniform="metric")
            for i, key in enumerate(["products", "open", "ignored", "resolved", "resolution_spd", "avg_cvss"]):
                card = self.metric_cards.get(key)
                if card:
                    r = i // cols_metrics
                    c = i % cols_metrics
                    card.grid(row=r, column=c, sticky="nsew", padx=5, pady=5)

        self.adjust_chart_rows(cols_charts)

    def adjust_chart_rows(self, cols):
        chart_widgets = [
            getattr(self, 'bar_chart_card', None), 
            getattr(self, 'pie_chart_card', None), 
            getattr(self, 'dist_chart_card', None), 
            getattr(self, 'line_chart_card', None)
        ]
        if cols == 2:
            self.charts_container.grid_columnconfigure(0, weight=1, uniform="group1")
            self.charts_container.grid_columnconfigure(1, weight=1, uniform="group1")
        else:
            self.charts_container.grid_columnconfigure(0, weight=1, uniform="")
            self.charts_container.grid_columnconfigure(1, weight=0, uniform="")

        for i, card in enumerate(chart_widgets):
            if card:
                r = i // cols
                c = i % cols
                card.grid(row=r, column=c, sticky="nsew", padx=5, pady=5)
                
        list_widgets = [
            getattr(self, 'recent_list_card', None), 
            getattr(self, 'severe_list_card', None)
        ]
        if cols == 2:
            self.lists_container.grid_columnconfigure(0, weight=1, uniform="group1")
            self.lists_container.grid_columnconfigure(1, weight=1, uniform="group1")
        else:
            self.lists_container.grid_columnconfigure(0, weight=1, uniform="")
            self.lists_container.grid_columnconfigure(1, weight=0, uniform="")

        for i, card in enumerate(list_widgets):
            if card:
                r = i // cols
                c = i % cols
                card.grid(row=r, column=c, sticky="nsew", padx=5, pady=5)

    def setup_layout(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.sidebar = tk.Frame(self, bg=self.c_bg_sidebar, width=220)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        middle_wrapper = tk.Frame(self, bg=self.c_bg_base)
        middle_wrapper.grid(row=0, column=1, sticky="nsew")
        middle_wrapper.grid_rowconfigure(0, weight=1)
        middle_wrapper.grid_columnconfigure(0, weight=1)
        
        self.main_canvas = tk.Canvas(middle_wrapper, bg=self.c_bg_base, highlightthickness=0)
        self.main_scrollbar = tk.Scrollbar(middle_wrapper, orient="vertical", command=self.main_canvas.yview)
        
        self.main_area = tk.Frame(self.main_canvas, bg=self.c_bg_base, padx=20, pady=20)
        self.main_area.bind("<Configure>", lambda e: self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all")))
        
        canvas_window = self.main_canvas.create_window((0, 0), window=self.main_area, anchor="nw")
        
        def on_canvas_configure(event):
            self.main_canvas.itemconfig(canvas_window, width=event.width)
            
        self.main_canvas.bind("<Configure>", on_canvas_configure)
        self.main_canvas.configure(yscrollcommand=self.main_scrollbar.set)
        
        self.main_canvas.grid(row=0, column=0, sticky="nsew")
        self.main_scrollbar.grid(row=0, column=1, sticky="ns")
        
        def _on_mousewheel(event):
            if event.delta:
                self.main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        self.main_canvas.bind_all("<MouseWheel>", _on_mousewheel)

    def build_sidebar(self):
        tk.Frame(self.sidebar, bg=self.c_bg_sidebar, height=20).pack()
        self.sidebar_items = {}
        
        def switch_page(page_name):
            if page_name == "settings":
                try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except Exception:
                    is_admin = False
                if not is_admin:
                    import tkinter.messagebox as mb
                    mb.showerror("Access Denied", "This feature can only be accessed with administrator access.")
                    return
            
            for name, (item_frame, indicator, label) in self.sidebar_items.items():
                if name == page_name:
                    item_frame.config(bg=self.c_cyan_dark, highlightthickness=1)
                    indicator.place(relheight=1.0, x=0, y=0)
                    label.config(fg=self.c_cyan, bg=self.c_cyan_dark)
                else:
                    item_frame.config(bg=self.c_bg_sidebar, highlightthickness=0)
                    indicator.place_forget()
                    label.config(fg=self.c_gray, bg=self.c_bg_sidebar)
            
            if page_name == "dashboard":
                self.page_info.pack_forget()
                if hasattr(self, 'page_settings'):
                    self.page_settings.pack_forget()
                self.page_dashboard.pack(fill=tk.BOTH, expand=True)
            elif page_name == "settings":
                self.page_dashboard.pack_forget()
                self.page_info.pack_forget()
                if hasattr(self, 'page_settings'):
                    self.page_settings.pack(fill=tk.BOTH, expand=True)
            else:
                self.page_dashboard.pack_forget()
                if hasattr(self, 'page_settings'):
                    self.page_settings.pack_forget()
                self.page_info.pack(fill=tk.BOTH, expand=True)
                
            self.main_canvas.yview_moveto(0)
            self.update_idletasks()
            self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))

        def create_menu_item(name, text, is_active=False):
            bg_col = self.c_cyan_dark if is_active else self.c_bg_sidebar
            fg_col = self.c_cyan if is_active else self.c_gray
            hl = 1 if is_active else 0
            
            item = tk.Frame(self.sidebar, bg=bg_col, pady=12, padx=20, highlightbackground=self.c_cyan, highlightthickness=hl, cursor="hand2")
            item.pack(fill=tk.X, pady=2)
            
            indicator = tk.Frame(item, bg=self.c_cyan, width=4)
            if is_active:
                indicator.place(relheight=1.0, x=0, y=0)
                
            label = tk.Label(item, text=text, fg=fg_col, bg=bg_col, font=self.f_menu, cursor="hand2")
            label.pack(anchor="w", padx=(10, 0))
            
            item.bind("<Button-1>", lambda e: switch_page(name))
            label.bind("<Button-1>", lambda e: switch_page(name))
            
            self.sidebar_items[name] = (item, indicator, label)
            
        create_menu_item("dashboard", "DASHBOARD", is_active=True)
        create_menu_item("info", "DATA INFO", is_active=False)
        create_menu_item("settings", "SETTINGS", is_active=False)

    def build_main_area(self):
        self.page_dashboard = tk.Frame(self.main_area, bg=self.c_bg_base)
        self.page_info = tk.Frame(self.main_area, bg=self.c_bg_base)
        self.page_dashboard.pack(fill=tk.BOTH, expand=True)
        
        self._build_dashboard_content(self.page_dashboard)
        self._build_data_info_content(self.page_info)
        
        self.page_settings = tk.Frame(self.main_area, bg=self.c_bg_base)
        self._build_settings_content(self.page_settings)

    def _build_settings_content(self, parent_frame):
        header = tk.Frame(parent_frame, bg=self.c_bg_base)
        header.pack(fill=tk.X, pady=(0, 20))
        tk.Label(header, text="SETTINGS", fg=self.c_white, bg=self.c_bg_base, font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        
        desc = tk.Label(parent_frame, text="Configure agent system settings. Changes require administrator privileges.", fg=self.c_gray, bg=self.c_bg_base, font=self.f_normal, justify=tk.LEFT)
        desc.pack(anchor="w", pady=(0, 20))
        
        container = tk.Frame(parent_frame, bg=self.c_bg_base)
        container.pack(fill=tk.BOTH, expand=True)
        
        card = tk.Frame(container, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=15)
        card.pack(fill=tk.X, pady=5)
        
        top = tk.Frame(card, bg=self.c_bg_card)
        top.pack(fill=tk.X)
        tk.Label(top, text="Inventory Scan", fg=self.c_cyan, bg=self.c_bg_card, font=self.f_normal_bold).pack(side=tk.LEFT)
        
        inventory_enabled = tk.BooleanVar()
        inventory_enabled.set(is_inventory_scan_enabled())
            
        def toggle_inventory():
            enabled = inventory_enabled.get()
            set_inventory_scan_enabled(enabled)
            if enabled:
                show_windows_notification("Zerowatch", "Sentinel Agent running in Background")
            else:
                show_windows_notification("Zerowatch", "Sentinel Agent stopped scanning")
                
        chk = tk.Checkbutton(top, variable=inventory_enabled, bg=self.c_bg_card, activebackground=self.c_bg_card, command=toggle_inventory)
        chk.pack(side=tk.RIGHT)
        
        tk.Label(card, text="Automatically scan and collect hardware and software inventory.", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small, justify=tk.LEFT).pack(anchor="w", pady=(10,0))
        
        card2 = tk.Frame(container, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=15)
        card2.pack(fill=tk.X, pady=5)
        
        top2 = tk.Frame(card2, bg=self.c_bg_card)
        top2.pack(fill=tk.X)
        tk.Label(top2, text="Auto Start Agent", fg=self.c_cyan, bg=self.c_bg_card, font=self.f_normal_bold).pack(side=tk.LEFT)
        
        auto_start_enabled = tk.BooleanVar()
        auto_start_enabled.set(is_auto_start_enabled())
            
        def toggle_auto_start():
            enabled = auto_start_enabled.get()
            set_auto_start_enabled(enabled)
            if enabled:
                show_windows_notification("Zerowatch", "Agent will now auto start on boot")
            else:
                show_windows_notification("Zerowatch", "Auto start on boot disabled")
                
        chk2 = tk.Checkbutton(top2, variable=auto_start_enabled, bg=self.c_bg_card, activebackground=self.c_bg_card, command=toggle_auto_start)
        chk2.pack(side=tk.RIGHT)
        
        tk.Label(card2, text="Automatically start the agent when the computer boots.", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small, justify=tk.LEFT).pack(anchor="w", pady=(10,0))

        card3 = tk.Frame(container, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=15)
        card3.pack(fill=tk.X, pady=5)
        
        top3 = tk.Frame(card3, bg=self.c_bg_card)
        top3.pack(fill=tk.X)
        tk.Label(top3, text="Unlink Device", fg=self.c_red, bg=self.c_bg_card, font=self.f_normal_bold).pack(side=tk.LEFT)
        
        def on_unlink_click():
            import tkinter.messagebox as messagebox
            if messagebox.askyesno("Confirm Unlink", "Are you sure you want to unlink this device from the team? This action cannot be undone."):
                res = self.zw_client.unlink_self()
                # unlink_self returns a tuple (bool, str) usually or "unlinked"
                success = False
                msg = ""
                if isinstance(res, tuple):
                    success, msg = res
                elif res == "unlinked":
                    success = True
                
                if success:
                    show_windows_notification("Zerowatch", "Device successfully unlinked.")
                    if hasattr(self.winfo_toplevel(), 'show_enrollment'):
                        self.winfo_toplevel().show_enrollment()
                    else:
                        sys.exit(0)
                else:
                    messagebox.showerror("Unlink Failed", f"Failed to unlink device: {msg}")

        unlink_btn = tk.Button(top3, text="Unlink", bg=self.c_red, fg=self.c_white, font=self.f_normal_bold, bd=0, activebackground=self.c_bg_card, activeforeground=self.c_red, cursor="hand2", command=on_unlink_click)
        unlink_btn.pack(side=tk.RIGHT)
        
        tk.Label(card3, text="Disconnect this device from the currently linked team.", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small, justify=tk.LEFT).pack(anchor="w", pady=(10,0))


    def _build_data_info_content(self, parent_frame):
        header = tk.Frame(parent_frame, bg=self.c_bg_base)
        header.pack(fill=tk.X, pady=(0, 20))
        tk.Label(header, text="COLLECTED DATA", fg=self.c_white, bg=self.c_bg_base, font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        
        desc = tk.Label(parent_frame, text="The following are collected from your device to provide security analytics and vulnerability matching.", fg=self.c_gray, bg=self.c_bg_base, font=self.f_normal, justify=tk.LEFT)
        desc.pack(anchor="w", pady=(0, 20))
        
        container = tk.Frame(parent_frame, bg=self.c_bg_base)
        container.pack(fill=tk.BOTH, expand=True)
        
        fp = getattr(self.zw_client, "fingerprint_data", {}) or {}
        
        fields = [
            ("MAC Address", fp.get("mac_address", "Unknown"), "Network interface unique hardware address used for device fingerprinting."),
            ("BIOS UUID", fp.get("bios_uuid", "Unknown"), "Motherboard firmware unique identifier."),
            ("Motherboard Serial", fp.get("motherboard_serial", "Unknown"), "Factory serial number of the motherboard."),
            ("Machine GUID", fp.get("machine_guid", "Unknown"), "Windows OS unique identifier generated during installation."),
            ("CPU ID", fp.get("cpu_id", "Unknown"), "Processor unique hardware identifier."),
            ("Disk Serial", fp.get("disk_serial", "Unknown"), "Primary storage drive serial number.")
        ]
        
        for i, (title, val, explanation) in enumerate(fields):
            card = tk.Frame(container, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=15)
            card.pack(fill=tk.X, pady=5)
            
            top = tk.Frame(card, bg=self.c_bg_card)
            top.pack(fill=tk.X)
            tk.Label(top, text=title, fg=self.c_cyan, bg=self.c_bg_card, font=self.f_normal_bold).pack(side=tk.LEFT)
            tk.Label(top, text=str(val), fg=self.c_white, bg=self.c_bg_card, font=self.f_normal_bold).pack(side=tk.RIGHT)
            
            tk.Label(card, text=explanation, fg=self.c_gray, bg=self.c_bg_card, font=self.f_small, justify=tk.LEFT).pack(anchor="w", pady=(10,0))

    def _build_dashboard_content(self, parent_frame):
        header_frame = tk.Frame(parent_frame, bg=self.c_bg_base)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header_frame, text="ENDPOINT SECURITY MONITOR", fg=self.c_white, bg=self.c_bg_base, font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        
        self.data_status_label = tk.Label(header_frame, text="Loading...", fg=self.c_gray, bg=self.c_bg_base, font=self.f_normal_bold)
        self.data_status_label.pack(side=tk.RIGHT)

        # Row 1: Top Metrics (6 cards)
        self.metrics_frame = tk.Frame(parent_frame, bg=self.c_bg_base)
        self.metrics_frame.pack(fill=tk.X, pady=(0, 20))
        self.metric_cards = {}

        self.create_mini_metric(self.metrics_frame, 0, "PRODUCTS", "0", self.c_cyan, key="products")
        self.create_mini_metric(self.metrics_frame, 1, "OPEN CVES", "0", self.c_red, key="open")
        self.create_mini_metric(self.metrics_frame, 2, "IGNORED CVES", "0", self.c_gray, key="ignored")
        self.create_mini_metric(self.metrics_frame, 3, "RESOLVED CVES", "0", self.c_green, key="resolved")
        self.create_mini_metric(self.metrics_frame, 4, "RESOLUTION SPD", "N/A", self.c_cyan, key="resolution_spd")
        self.create_mini_metric(self.metrics_frame, 5, "AVG CVSS SCORE", "N/A", self.c_orange, key="avg_cvss")

        # Container for Charts
        self.charts_container = tk.Frame(parent_frame, bg=self.c_bg_base)
        self.charts_container.pack(fill=tk.X, expand=True, pady=(0, 20))
        self.charts_container.grid_columnconfigure(0, weight=1)
        self.charts_container.grid_columnconfigure(1, weight=1)

        self.bar_chart_card = self.build_bar_chart(self.charts_container, 0, 0)
        self.pie_chart_card = self.build_pie_chart(self.charts_container, 0, 1)
        self.dist_chart_card = self.build_distribution_chart(self.charts_container, 1, 0)
        self.line_chart_card = self.build_line_chart(self.charts_container, 1, 1)

        # Container for Lists
        self.lists_container = tk.Frame(parent_frame, bg=self.c_bg_base)
        self.lists_container.pack(fill=tk.X, expand=True)
        self.lists_container.grid_columnconfigure(0, weight=1)
        self.lists_container.grid_columnconfigure(1, weight=1)

        self.recent_list_card = self.build_cve_list(self.lists_container, 0, 0, "Top 5 Recent CVEs", key="recent")
        self.severe_list_card = self.build_cve_list(self.lists_container, 0, 1, "Most Affected CVEs", key="severe")

    def create_mini_metric(self, parent, col, title, val, color, key=None):
        card = tk.Frame(parent, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=15, pady=15)
        card.grid(row=0, column=col, sticky="nsew", padx=5, pady=5)
        
        tk.Label(card, text=title, fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).pack(anchor="w")
        value_label = tk.Label(card, text=val, fg=color, bg=self.c_bg_card, font=self.f_metric_val)
        value_label.pack(anchor="w", pady=(5,0))
        if key:
            self.metric_labels[key] = value_label
            self.metric_cards[key] = card

    def refresh_data(self):
        """Manual trigger to refresh data immediately."""
        self._fetch_worker()

    def fetch_dashboard_data(self):
        """Background poll loop."""
        self._fetch_worker()
        # Reschedule next poll
        self.after(30000, self.fetch_dashboard_data)

    def _fetch_worker(self):
        """Internal threaded data fetch."""
        def _worker():
            try:
                info = self.zw_client.get_asset_info()
                if info == "unlinked":
                    logging.warning("Device unlinked by admin. Redirecting to enrollment.")
                    self.zw_client.clear_local_state()
                    self.after(0, self.master.show_enrollment)
                    return

                # Fallback sync if daemon is not running
                if not getattr(self, "inventory_synced", False):
                    if not _is_daemon_running():
                        logging.info("GUI: Daemon not running. Triggering fallback full sync...")
                        software = get_installed_software_registry()
                        hardware_data = get_detailed_hardware_profile()
                        self.zw_client.sync_full(software, hardware_data)
                        self.inventory_synced = True
                    else:
                        logging.info("GUI: Daemon is running. Skipping fallback sync.")
                        self.inventory_synced = True

                if info:
                    stats = info.get("stats", {}) or {}
                    status = "Offline (Cached)" if info.get("from_cache") else "Live"
                    self.after(0, lambda: self._update_ui(info, stats, status=status))
                else:
                    self.after(0, lambda: self.data_status_label.config(text="Loading...", fg=self.c_gray))
            except Exception as e:
                logging.error(f"Dashboard fetch error: {e}")
        
        threading.Thread(target=_worker, daemon=True).start()

    def _update_ui(self, info, stats, status="Live"):
        fg = self.c_green if status == "Live" else self.c_gray
        self.data_status_label.config(text=status, fg=fg)
        
        product_count = stats.get("productCount")
        if product_count is None:
            product_count = info.get("softwareCount", 0)

        self._update_metric("products", product_count)
        self._update_metric("open", stats.get("open", 0))
        self._update_metric("ignored", stats.get("ignored", 0))
        self._update_metric("resolved", stats.get("resolved", 0))

        avg_cvss = stats.get("avgCvssOpen", 0)
        resolution_spd = stats.get("resolutionSpeedHours", 0)
        self._update_metric("avg_cvss", f"{float(avg_cvss):.2f}")
        self._update_metric("resolution_spd", f"{float(resolution_spd):.1f} hrs")

        self._update_bar_chart(stats)
        self._update_distribution_chart(stats)
        self._update_line_chart(stats)
        self._update_pie_chart(stats)
        self._update_cve_list("recent", stats.get("topRecent", []))
        self._update_cve_list("severe", stats.get("topSevere", []))

    def _update_metric(self, key, value):
        label = self.metric_labels.get(key)
        if label:
            label.config(text=str(value))

    def _update_bar_chart(self, stats):
        widgets = self.bar_chart_widgets
        if not widgets: return

        product = stats.get("mostAffectedProduct") or "--"
        count = stats.get("mostAffectedCount") or 0
        top_cve = "--"
        top_score = "0.0"
        top_severe = stats.get("topSevere") or []
        if top_severe:
            top = top_severe[0]
            top_cve = top.get("cveId") or "--"
            score = top.get("score")
            if score is not None:
                top_score = f"{float(score):.1f}"

        widgets["vendor_label"].config(text=product)
        widgets["product_label"].config(text=product)
        widgets["total_label"].config(text=str(count))
        widgets["total_sub_label"].config(text=f"{count} total")
        widgets["top_cve_label"].config(text=top_cve)
        widgets["cvss_label"].config(text=f"CVSS {top_score}")

        bg_width = widgets["bar_bg"].winfo_width() or 1
        bar_width = min(bg_width, max(0, int(bg_width * min(count / 10, 1))))
        widgets["bar_fg"].config(width=bar_width)

    def _update_distribution_chart(self, stats):
        top_products = stats.get("topProducts") or []
        data = []
        for entry in top_products[:5]:
            name = entry.get("name") or "Unknown"
            count = entry.get("count") or 0
            data.append((name, count, "")) 

        self.distribution_chart["data"] = data
        draw = self.distribution_chart.get("draw")
        if draw: draw()

    def _update_pie_chart(self, stats):
        widgets = self.pie_chart_widgets
        if not widgets: return

        counts = stats.get("attackVectorCounts") or {}
        total = sum(counts.values()) or 0
        primary_key = max(counts.keys(), key=lambda k: counts.get(k, 0)) if total else "AV:N"
        primary_count = counts.get(primary_key, 0)
        percent = int((primary_count / total) * 100) if total else 0

        canvas = widgets["canvas"]
        canvas.delete("slices")
        canvas.create_oval(10, 10, 150, 150, outline=self.c_border, width=12, tags="slices")

        start_angle = 90
        for key, color in [("AV:R", "#3b82f6"), ("AV:N", "#a855f7"), ("AV:AN", "#10b981"), ("AV:L", "#64748b")]:
            value = counts.get(key, 0)
            extent = int((value / total) * 360) if total else 0
            if extent > 0:
                canvas.create_arc(10, 10, 150, 150, start=start_angle, extent=-extent, style=tk.ARC, outline=color, width=12, tags="slices")
                start_angle -= extent

        canvas.itemconfig(widgets["percent_label"], text=f"{percent}%")
        canvas.itemconfig(widgets["vector_label"], text=primary_key)
        widgets["total_label"].config(text=str(total))

        for key, row in widgets["rows"].items():
            value = counts.get(key, 0)
            row["count_label"].config(text=str(value))
            relwidth = value / total if total else 0
            row["bar_fg"].place(relx=0, rely=0, relwidth=relwidth, relheight=1)

    def _update_cve_list(self, key, items):
        rows = self.cve_tables.get(key) or []
        severity_colors = {"CRITICAL": self.c_red, "HIGH": self.c_orange, "MEDIUM": self.c_yellow, "LOW": self.c_green}

        for idx, row in enumerate(rows):
            entry = items[idx] if idx < len(items) else {}
            cve_id = entry.get("cveId") or "--"
            severity = (entry.get("severity") or "--").upper()
            score = entry.get("score")
            score_text = f"{float(score):.1f}" if score is not None else "--"
            affected = entry.get("affectedProduct") or "--"
            color = severity_colors.get(severity, self.c_gray)

            row["cve_label"].config(text=cve_id)
            row["sev_label"].config(text=score_text, fg=color)
            row["aff_label"].config(text=affected)

    def build_line_chart(self, parent, row, col):
        card = tk.Frame(parent, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=20)
        card.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        tk.Label(card, text="CVE Discovery vs Resolution", fg=self.c_white, bg=self.c_bg_card, font=("Arial", 14, "bold")).pack(anchor="w")
        tk.Label(card, text="Open vs Resolved", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).pack(anchor="w", pady=(0, 20))
        
        canvas = tk.Canvas(card, bg=self.c_bg_card, highlightthickness=0, height=200)
        canvas.pack(fill=tk.BOTH, expand=True)
        
        status_label = tk.Label(card, text="Waiting for data...", fg=self.c_white, bg=self.c_bg_card, font=self.f_normal_bold, justify=tk.LEFT)
        status_label.pack(anchor="w", pady=(10, 0))
        
        self.line_chart_widgets["status_label"] = status_label
        
        def draw():
            w, h = canvas.winfo_width(), canvas.winfo_height()
            if h < 50:
                self.after(200, draw)
                return
            canvas.delete("all")
            
            pad_left, pad_right, pad_top, pad_bottom = 20, 20, 10, 30
            chart_w, chart_h = w - pad_left - pad_right, h - pad_top - pad_bottom
            
            labels = ["Dec", "Jan", "Feb", "Mar", "Apr", "May"]
            dx = chart_w / (len(labels) - 1)
            for i, lbl in enumerate(labels):
                x = pad_left + i * dx
                canvas.create_text(x, h - pad_bottom + 15, text=lbl, fill=self.c_gray, font=self.f_small)
            
            discovery_timeline = self.line_chart_widgets.get("discovery_timeline") or [0, 0, 0, 0, 0, 0]
            resolution_timeline = self.line_chart_widgets.get("resolution_timeline") or [0, 0, 0, 0, 0, 0]
            max_val = max(max(discovery_timeline, default=0), max(resolution_timeline, default=0), 1)
            
            def get_y(val): return h - pad_bottom - (val / max_val) * chart_h
            
            disc_coords, res_coords = [], []
            for i in range(len(discovery_timeline)):
                x = pad_left + (i / (len(discovery_timeline) - 1)) * chart_w if len(discovery_timeline) > 1 else pad_left
                disc_coords.extend([x, get_y(discovery_timeline[i])])
            for i in range(len(resolution_timeline)):
                x = pad_left + (i / (len(resolution_timeline) - 1)) * chart_w if len(resolution_timeline) > 1 else pad_left
                res_coords.extend([x, get_y(resolution_timeline[i])])
            
            for coords, color, fill_color, is_filled in [(disc_coords, self.c_red, "#300a0a", True), (res_coords, self.c_green, "#0a2010", False)]:
                if is_filled and len(coords) >= 4:
                    poly_coords = [pad_left, h-pad_bottom] + coords + [w-pad_right, h-pad_bottom]
                    canvas.create_polygon(poly_coords, fill=fill_color, outline="")
                if len(coords) >= 4:
                    canvas.create_line(coords, fill=color, width=2)
            
            discovered, resolved = self.line_chart_widgets.get("discovered", 0), self.line_chart_widgets.get("resolved", 0)
            status_label.config(text=f"May: {discovered} discovered, {resolved} resolved in managed scope.")
            
        self.after(200, draw)
        self.line_chart_widgets["draw"] = draw
        return card

    def _update_line_chart(self, stats):
        discovered, resolved = stats.get("open", 0) or 0, stats.get("resolved", 0) or 0
        self.line_chart_widgets["discovered"] = discovered
        self.line_chart_widgets["resolved"] = resolved
        self.line_chart_widgets["discovery_timeline"] = stats.get("discoveryTimeline") or [0, 0, 0, 0, 0, discovered]
        self.line_chart_widgets["resolution_timeline"] = stats.get("resolutionTimeline") or [0, 0, 0, 0, 0, resolved]
        draw = self.line_chart_widgets.get("draw")
        if draw: draw()

    def build_distribution_chart(self, parent, row, col):
        card = tk.Frame(parent, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=20)
        card.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        tk.Label(card, text="CVE Distribution Amongst Products", fg=self.c_white, bg=self.c_bg_card, font=("Arial", 14, "bold")).pack(anchor="w")
        tk.Label(card, text="Top 5 products by open CVE count", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).pack(anchor="w", pady=(0, 20))
        
        canvas = tk.Canvas(card, bg=self.c_bg_card, highlightthickness=0, height=200)
        canvas.pack(fill=tk.BOTH, expand=True)
        tk.Label(card, text="Visualized from scoped managed analytics.", fg=self.c_white, bg=self.c_bg_card, font=self.f_normal_bold, justify=tk.LEFT).pack(anchor="w", pady=(10, 0))

        self.distribution_chart["canvas"] = canvas
        self.distribution_chart["data"] = []
        
        def right_round_rect(x1, y1, x2, y2, color):
            r = (y2 - y1) / 2
            canvas.create_line(x1, y1, x2-r, y1, fill=color, width=2)
            canvas.create_line(x1, y2, x2-r, y2, fill=color, width=2)
            canvas.create_line(x1, y1, x1, y2+1, fill=color, width=2)
            canvas.create_arc(x2-2*r, y1, x2, y2, start=-90, extent=180, style=tk.ARC, outline=color, width=2)
        
        def draw():
            w, h = canvas.winfo_width(), canvas.winfo_height()
            if h < 50:
                self.after(200, draw)
                return
            canvas.delete("all")

            data = self.distribution_chart.get("data", [])
            if not data:
                canvas.create_text(w/2, h/2, text="No product CVE data", fill=self.c_gray, font=self.f_small)
                return

            max_val = max((item[1] for item in data), default=1)
            pad_left, pad_right, pad_top, pad_bottom = 120, 40, 10, 30
            chart_w, chart_h = w - pad_left - pad_right, h - pad_top - pad_bottom
            
            for i in range(5):
                x = pad_left + i * (chart_w / 4)
                canvas.create_line(x, pad_top, x, h - pad_bottom, fill=self.c_border)
                canvas.create_text(x, h - pad_bottom + 15, text=str(i), fill=self.c_gray, font=self.f_small)
            
            bar_h, colors = 16, [self.c_yellow] * 4 + [self.c_green]
            gap = (chart_h - (len(data) * bar_h)) / (len(data) + 1)
            y = pad_top + gap
            for i, (name, val, _) in enumerate(data):
                color = colors[i] if i < len(colors) else self.c_gray
                canvas.create_text(pad_left - 10, y + bar_h/2, text=name, fill=self.c_gray, font=self.f_small, anchor="e")
                bw = (val / max_val) * chart_w
                right_round_rect(pad_left, y, pad_left + bw, y + bar_h, color)
                canvas.create_text(pad_left + bw + 10, y + bar_h/2, text=str(val), fill=self.c_white, font=self.f_normal_bold, anchor="w")
                y += bar_h + gap
                
        self.after(200, draw)
        self.distribution_chart["draw"] = draw
        return card

    def build_bar_chart(self, parent, row, col):
        card = tk.Frame(parent, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=20)
        card.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        tk.Label(card, text="Most Affected Product", fg=self.c_white, bg=self.c_bg_card, font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 15))
        
        content = tk.Frame(card, bg=self.c_bg_card)
        content.pack(fill=tk.BOTH, expand=True)
        content.grid_columnconfigure(0, weight=1); content.grid_columnconfigure(1, weight=0); content.grid_columnconfigure(2, weight=1)
        
        left_top = tk.Frame(content, bg=self.c_bg_card); left_top.grid(row=0, column=0, sticky="nw")
        tk.Label(left_top, text="VENDOR", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).pack(anchor="w")
        vendor_label = tk.Label(left_top, text="--", fg="#3b82f6", bg=self.c_bg_card, font=("Arial", 18, "bold")); vendor_label.pack(anchor="w")
        
        right_top = tk.Frame(content, bg=self.c_bg_card); right_top.grid(row=0, column=2, sticky="new")
        tk.Label(right_top, text="TOTAL CVES", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).pack(anchor="w")
        total_label = tk.Label(right_top, text="0", fg=self.c_yellow, bg=self.c_bg_card, font=("Arial", 20, "bold")); total_label.pack(anchor="w", pady=(2, 2))
        
        bar_bg = tk.Frame(right_top, bg=self.c_border, height=4, width=150); bar_bg.pack(anchor="w", pady=(0, 5)); bar_bg.pack_propagate(False)
        bar_fg = tk.Frame(bar_bg, bg=self.c_yellow, width=0); bar_fg.pack(side=tk.LEFT, fill=tk.Y)
        total_sub_label = tk.Label(right_top, text="0 total", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small); total_sub_label.pack(anchor="w", pady=(0, 15))
        
        left_bot = tk.Frame(content, bg=self.c_bg_card); left_bot.grid(row=1, column=0, sticky="nw")
        tk.Label(left_bot, text="PRODUCT", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).pack(anchor="w")
        product_label = tk.Label(left_bot, text="--", fg=self.c_white, bg=self.c_bg_card, font=("Arial", 18, "bold")); product_label.pack(anchor="w")

        right_bot = tk.Frame(content, bg=self.c_bg_card); right_bot.grid(row=1, column=2, sticky="new")
        tk.Label(right_bot, text="TOP CVE", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).pack(anchor="w", pady=(0, 5))
        pill1 = tk.Frame(right_bot, bg="#112435", highlightbackground="#1b3f60", highlightthickness=1, padx=10, pady=5); pill1.pack(anchor="w", fill=tk.X, pady=(0, 5))
        top_cve_label = tk.Label(pill1, text="--", fg="#3b82f6", bg="#112435", font=self.f_normal_bold); top_cve_label.pack(anchor="w")
        pill2 = tk.Frame(right_bot, bg="#361718", highlightbackground="#592022", highlightthickness=1, padx=10, pady=5); pill2.pack(anchor="w", fill=tk.X)
        cvss_label = tk.Label(pill2, text="CVSS 0.0", fg=self.c_red, bg="#361718", font=self.f_normal_bold); cvss_label.pack(anchor="w")

        tk.Frame(content, bg=self.c_border, width=1).grid(row=0, column=1, rowspan=2, sticky="ns", padx=30)

        self.bar_chart_widgets = {"vendor_label": vendor_label, "total_label": total_label, "total_sub_label": total_sub_label, "product_label": product_label, "top_cve_label": top_cve_label, "cvss_label": cvss_label, "bar_fg": bar_fg, "bar_bg": bar_bg}
        return card

    def build_pie_chart(self, parent, row, col):
        card = tk.Frame(parent, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=20)
        card.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        tk.Label(card, text="Attack Vector Distribution", fg=self.c_white, bg=self.c_bg_card, font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 25))
        
        content = tk.Frame(card, bg=self.c_bg_card); content.pack(fill=tk.BOTH, expand=True)
        left_frame = tk.Frame(content, bg=self.c_bg_card); left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 30))
        donut_canvas = tk.Canvas(left_frame, width=160, height=160, bg=self.c_bg_card, highlightthickness=0); donut_canvas.pack(pady=(10, 0))
        donut_canvas.create_oval(10, 10, 150, 150, outline=self.c_border, width=12)
        percent_label = donut_canvas.create_text(80, 70, text="0%", fill="#a855f7", font=("Arial", 22, "bold"))
        vector_label = donut_canvas.create_text(80, 100, text="AV:N", fill=self.c_gray, font=self.f_small)
        
        right_frame = tk.Frame(content, bg=self.c_bg_card); right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        row_widgets = {}
        for name, key, color in [("AV:R", "AV:R", "#3b82f6"), ("AV:N", "AV:N", "#a855f7"), ("AV:AN", "AV:AN", "#10b981"), ("AV:L", "AV:L", "#64748b")]:
            row_f = tk.Frame(right_frame, bg=self.c_bg_card); row_f.pack(fill=tk.X, pady=(0, 12))
            top_row = tk.Frame(row_f, bg=self.c_bg_card); top_row.pack(fill=tk.X)
            tk.Frame(top_row, bg=color, width=10, height=10).pack(side=tk.LEFT, pady=5)
            tk.Label(top_row, text=name, fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).pack(side=tk.LEFT, padx=(10, 0))
            cl = tk.Label(top_row, text="0", fg=self.c_white, bg=self.c_bg_card, font=self.f_normal_bold); cl.pack(side=tk.RIGHT)
            bb = tk.Frame(row_f, bg=self.c_border, height=6); bb.pack(fill=tk.X, pady=(5, 0), padx=(20, 0))
            bf = tk.Frame(bb, bg=color); bf.place(relx=0, rely=0, relwidth=0, relheight=1)
            row_widgets[key] = {"count_label": cl, "bar_fg": bf}
                
        total_label = tk.Label(right_frame, text="0", fg=self.c_white, bg=self.c_bg_card, font=("Arial", 12, "bold"))
        self.pie_chart_widgets = {"canvas": donut_canvas, "percent_label": percent_label, "vector_label": vector_label, "rows": row_widgets, "total_label": total_label}
        return card

    def build_cve_list(self, parent, row, col, title, key):
        card = tk.Frame(parent, bg=self.c_bg_card, highlightbackground=self.c_border, highlightthickness=1, padx=20, pady=20)
        card.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        tk.Label(card, text=title, fg=self.c_white, bg=self.c_bg_card, font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 15))
        table = tk.Frame(card, bg=self.c_bg_card); table.pack(fill=tk.BOTH, expand=True)
        table.grid_columnconfigure(0, weight=3); table.grid_columnconfigure(1, weight=2); table.grid_columnconfigure(2, weight=3)
        tk.Label(table, text="CVE ID", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).grid(row=0, column=0, sticky="w")
        tk.Label(table, text="SCORE", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).grid(row=0, column=1, sticky="w")
        tk.Label(table, text="AFFECTED", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small).grid(row=0, column=2, sticky="w")
        rows = []
        for r in range(1, 6):
            cl = tk.Label(table, text="--", fg="#3b82f6", bg=self.c_bg_card, font=self.f_normal_bold, anchor="w"); cl.grid(row=r, column=0, sticky="w", pady=8)
            sl = tk.Label(table, text="--", fg=self.c_gray, bg=self.c_bg_card, font=self.f_small, anchor="w"); sl.grid(row=r, column=1, sticky="w", pady=8)
            al = tk.Label(table, text="--", fg=self.c_gray, bg=self.c_bg_card, font=self.f_normal, anchor="w"); al.grid(row=r, column=2, sticky="w", pady=8)
            rows.append({"cve_label": cl, "sev_label": sl, "aff_label": al})
        self.cve_tables[key] = rows
        return card

class UnifiedSentinelGUI(tk.Tk):
    def __init__(self, zw_client, force_frame=None):
        try:
            import os
            base_dir = get_base_dir()
            _append_gui_log(base_dir, f"GUI init: before tk.Tk")
            _append_gui_log(base_dir, f"GUI init: __file__ is {__file__}")
            _append_gui_log(base_dir, f"GUI init: TCL_LIBRARY is {os.environ.get('TCL_LIBRARY')}")
            _append_gui_log(base_dir, f"GUI init: TK_LIBRARY is {os.environ.get('TK_LIBRARY')}")
        except Exception as e:
            _append_gui_log(get_base_dir(), f"GUI init: logging failed: {e}")
        super().__init__()
        self.withdraw()  # Hide window during construction to prevent flickering/jumping
        self.zw_client = zw_client
        try:
            _append_gui_log(get_base_dir(), "GUI init: tk.Tk initialized")
        except Exception:
            pass
        self.title("ZEROWATCH SENTINEL AGENT")
        self.geometry("1200x800")
        self.minsize(800, 600)
        self.resizable(True, True) # Allow resizing and maximizing
        self.configure(bg="#0d0f14")
        
        # Set icon if available
        try:
            import os
            import sys
            
            # Possible locations for the icon file
            possible_icon_paths = [
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "favicon.ico"),
                os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "favicon.ico"),
                os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "favicon.ico"),
                os.path.join(get_base_dir(), "favicon.ico"),
            ]
            
            icon_loaded = False
            for icon_path in possible_icon_paths:
                if os.path.exists(icon_path):
                    try:
                        # Try iconbitmap first for taskbar grouping
                        self.iconbitmap(icon_path)
                        # Also set iconphoto for broader support
                        img = tk.PhotoImage(file=icon_path)
                        self.iconphoto(True, img)
                        icon_loaded = True
                        break
                    except Exception:
                        try:
                            img = tk.PhotoImage(file=icon_path)
                            self.iconphoto(True, img)
                            icon_loaded = True
                            break
                        except Exception:
                            continue
        except Exception as e:
            _append_gui_log(get_base_dir(), f"GUI icon load failed: {e}")

        # Final Taskbar Icon Force (Windows OS level)
        try:
            icon_path = self._resolve_icon_path()
            if icon_path:
                from ctypes import windll
                hwnd = windll.user32.GetParent(self.winfo_id())
                # Load icon using shell32 to ensure it is handled as a proper HICON
                hicon = windll.user32.LoadImageW(0, icon_path, 1, 0, 0, 0x00000010)
                if hicon:
                    windll.user32.SendMessageW(hwnd, 0x0080, 1, hicon) # ICON_BIG
                    windll.user32.SendMessageW(hwnd, 0x0080, 0, hicon) # ICON_SMALL
        except Exception:
            pass

        self.current_frame = None
        
        if force_frame == "enroll":
            self.show_enrollment()
        elif force_frame == "dashboard":
            self.show_dashboard()
        else:
            # Default routing logic: strictly check enrollment status
            if self.zw_client.is_enrolled():
                self.show_dashboard()
            else:
                self.show_enrollment()

        # Start notification listener and socket
        self.zw_client.connect_socket()
        self.process_notifications()

        self.after(50, self._bring_to_front)
        self.after(200, self._force_show_window)

    def _bring_to_front(self):
        try:
            self.deiconify()
            self.lift()
            self.attributes("-topmost", True)
            self.focus_force()
            self.after(150, lambda: self.attributes("-topmost", False))
        except Exception:
            pass

    def _force_show_window(self):
        try:
            hwnd = self.winfo_id()
            ctypes.windll.user32.ShowWindow(hwnd, 9)
            ctypes.windll.user32.SetForegroundWindow(hwnd)
            _append_gui_log(get_base_dir(), f"GUI init: forced show hwnd={hwnd}")
        except Exception:
            pass

    def report_callback_exception(self, exc, val, tb):
        try:
            _append_gui_log(get_base_dir(), f"GUI callback exception: {val}")
        except Exception:
            pass
        logging.error("GUI callback exception", exc_info=(exc, val, tb))

    def process_notifications(self):
        """Check the client's notification queue and react."""
        try:
            # Periodic fallback poll
            if hasattr(self.zw_client, "last_poll_at"):
                if time.time() - self.zw_client.last_poll_at > 30:
                    self.zw_client.poll_notifications()
                    self.zw_client.last_poll_at = time.time()
            else:
                self.zw_client.last_poll_at = time.time()
                self.zw_client.poll_notifications()

            while self.zw_client.notification_queue:
                notif = self.zw_client.notification_queue.pop(0)
                ntype = notif.get("type")
                data = notif.get("data")
                
                logging.info(f"[GUI] Processing notification: {ntype}")
                
                if ntype == "unlink":
                    # Proactive verification
                    _append_gui_log(self.zw_client.base_dir, "[GUI] Real-time unlink signal received. Verifying...")
                    if self.zw_client.heartbeat() == "unlinked":
                         _append_gui_log(self.zw_client.base_dir, "[GUI] Remote unlink VERIFIED by server.")
                         self.zw_client.clear_local_state()
                         from tkinter import messagebox
                         messagebox.showwarning(
                             "Security Update",
                             "This device has been unlinked by the administrator.\n\n"
                             "Local security data has been wiped and enrollment reset."
                         )
                         self.show_enrollment()
                    else:
                         _append_gui_log(self.zw_client.base_dir, "[GUI] Unlink signal could not be verified (Spoof?). Ignoring.")
                
                elif ntype == "feed_ready":
                    # Debounce: don't refresh more than once every 5 seconds from notifications
                    now = time.time()
                    last_refresh = getattr(self, "_last_notif_refresh", 0)
                    payload_status = ""
                    if isinstance(data, dict):
                        payload_status = str(data.get("status") or "").strip().lower()

                    if payload_status == "approved":
                        # Ensure first inventory reaches backend immediately after admin approval.
                        self.zw_client.trigger_approval_sync(
                            reason="feed_ready_approved",
                            min_interval=90,
                        )
                    
                    if now - last_refresh > 5:
                        self._last_notif_refresh = now
                        # If we are in enrollment waiting, switch to dashboard
                        if isinstance(self.current_frame, EnrollmentFrame):
                            status = self.zw_client.refresh_join_status_once()
                            if status.get("status") == "approved" and self.zw_client.jwt:
                                self.zw_client.trigger_approval_sync(
                                    reason="enrollment_approved",
                                    min_interval=90,
                                )
                                self.show_dashboard()
                        elif isinstance(self.current_frame, DashboardFrame):
                            # Just refresh the dashboard data
                            self.current_frame.refresh_data()
                    else:
                        logging.info("[GUI] Coalesced redundant feed_ready notification")
        except Exception as exc:
            logging.error("[GUI] Notification processing failed: %s", exc)
        self.after(2000, self.process_notifications)

    def show_enrollment(self):
        if isinstance(self.current_frame, EnrollmentFrame):
            return
        self.title("ZEROWATCH SENTINEL AGENT — ENROLLMENT")
        self._switch_frame(EnrollmentFrame)

    def show_dashboard(self):
        if isinstance(self.current_frame, DashboardFrame):
            return
        self.title("ZEROWATCH SENTINEL AGENT — DASHBOARD")
        self._switch_frame(DashboardFrame)

    def _switch_frame(self, frame_class):
        new_frame = frame_class(self, self.zw_client)
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = new_frame
        self.current_frame.pack(fill=tk.BOTH, expand=True)

def _is_daemon_running():
    mutex = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
    err = ctypes.windll.kernel32.GetLastError()
    if mutex:
        ctypes.windll.kernel32.CloseHandle(mutex)
    return err == 183 # ERROR_ALREADY_EXISTS

def _spawn_daemon_process():
    exe_path = get_exe_path()
    args = [exe_path] + _daemon_args()
    try:
        DETACHED = 0x00000008
        NEW_GROUP = 0x00000200
        p = subprocess.Popen(
            args,
            creationflags=DETACHED | NEW_GROUP | subprocess.CREATE_NO_WINDOW,
            startupinfo=_windows_hidden_startupinfo(),
        )
        return True, p.pid
    except Exception as e:
        logging.error(f"Failed to spawn daemon: {e}")
        return False, None

def _daemon_args():
    args = ["--daemon"]
    if "--hardened" in sys.argv:
        args.append("--hardened")
    return args

def prompt_consent(base_dir):
    consent_file = os.path.join(_secure_state_dir(base_dir), "consent_accepted.dat")
    if os.path.exists(consent_file):
        return True

    root = tk.Tk()
    root.title("ZeroWatch Agent - Consent Required")
    root.geometry("600x400")
    root.configure(bg="#0d0f14")
    
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (600 // 2)
    y = (root.winfo_screenheight() // 2) - (400 // 2)
    root.geometry(f"600x400+{x}+{y}")

    result = [False]

    def on_accept():
        try:
            os.makedirs(os.path.dirname(consent_file), exist_ok=True)
            with open(consent_file, "w") as f:
                f.write("1")
        except Exception:
            pass
        result[0] = True
        root.destroy()

    def on_decline():
        root.destroy()
        sys.exit(0)

    root.protocol("WM_DELETE_WINDOW", on_decline)

    tk.Label(root, text="DATA COLLECTION CONSENT", fg="#ffffff", bg="#0d0f14", font=("Arial", 16, "bold")).pack(pady=20)
    
    info_text = (
        "ZeroWatch Sentinel Agent collects the following data points to secure your endpoint:\n\n"
        "- Hostname & Username\n"
        "- MAC Address & IP Address\n"
        "- Hardware Identifiers (CPU ID, Disk Serial, BIOS UUID, Motherboard Serial)\n"
        "- Installed Software & Versions (via Registry)\n\n"
        "This data is securely transmitted to your organization's ZeroWatch dashboard.\n"
        "By clicking Accept, you consent to this data collection."
    )
    tk.Label(root, text=info_text, fg="#8b949e", bg="#0d0f14", font=("Arial", 10), justify=tk.LEFT).pack(padx=20, pady=10)

    btn_frame = tk.Frame(root, bg="#0d0f14")
    btn_frame.pack(side=tk.BOTTOM, pady=30)

    btn_accept = tk.Button(btn_frame, text="Accept & Continue", fg="#ffffff", bg="#2ea043", font=("Arial", 10, "bold"), width=15, command=on_accept)
    btn_accept.pack(side=tk.LEFT, padx=10)

    btn_decline = tk.Button(btn_frame, text="Decline & Exit", fg="#ffffff", bg="#f85149", font=("Arial", 10, "bold"), width=15, command=on_decline)
    btn_decline.pack(side=tk.LEFT, padx=10)

    # Load icon if possible
    try:
        possible_icon_paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "favicon.ico"),
            os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "favicon.ico"),
            os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "favicon.ico"),
            os.path.join(base_dir, "favicon.ico"),
        ]
        for icon_path in possible_icon_paths:
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
                break
    except:
        pass

    root.mainloop()

    if not result[0]:
        sys.exit(0)
    return True


def run_interactive():
    """Redesigned interactive entry point."""
    try:
        # Set AppUserModelID to ensure the taskbar icon matches the window icon
        # Use a unique but descriptive string
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ZeroWatch.SentinelAgent.v2")
    except Exception:
        pass

    # CLI Reset Flag: Allows users to force-clear local state for re-enrollment
    if "--reset" in sys.argv:
        print("Resetting local state as requested...")
        base_dir = get_base_dir()
        # Create a minimal client to clear state
        client = ZeroWatchClient(base_dir, "reset-temp", "reset-temp")
        client.clear_local_state()
        # Also purge any cached dashboard data
        cache_path = os.path.join(_secure_state_dir(base_dir), "dashboard_cache.dat")
        if os.path.exists(cache_path):
            try: os.remove(cache_path)
            except: pass
        print("Local state cleared. Please restart the agent.")
        sys.exit(0)

    try:
        base_dir = get_base_dir()
        prompt_consent(base_dir)
        _append_gui_log(base_dir, "GUI startup: begin")
        hostname = resolve_hostname(base_dir)
        operator_username = resolve_agent_username(base_dir, prompt=False)
        asset_name = resolve_asset_name(base_dir, prompt=False, default_hostname=hostname)
        identity = _load_identity_from_fingerprint(base_dir)
        cached_fp = _read_fingerprint_json(base_dir)
        fingerprint = cached_fp if cached_fp.get("device_id") else collect_fingerprint()
        _append_gui_log(base_dir, "GUI startup: fingerprint ready")
        export_fingerprint_json(
            base_dir,
            fingerprint,
            username=operator_username,
            asset_name=asset_name,
            hostname=hostname,
            organization_name=identity.get("organization_name"),
        )
        zw_client = ZeroWatchClient(
            base_dir,
            fingerprint["device_id"],
            hostname,
            fingerprint_data=fingerprint,
            operator_username=operator_username,
            asset_name=asset_name,
        )
        _append_gui_log(base_dir, "GUI startup: client initialized")

        # Ensure a daemon is running so background monitoring persists.
        try:
            if not _is_daemon_running():
                _spawn_daemon_process()
        except Exception:
            pass

        # Default routing logic with a 2-second "Server Veto"
        is_enrolled_locally = zw_client.is_enrolled()
        
        if is_enrolled_locally:
            logging.info("Startup: Device enrolled locally. Verifying with server (2s timeout)...")
            # Perform a quick synchronous check to see if we should auto-reset
            verify_res = zw_client.refresh_join_status_once() # This has a timeout
            
            # If server explicitly says we are NOT approved, wipe and show enrollment
            if verify_res.get("status") in {"denied", "unknown", "unlinked"}:
                logging.info("Startup: Server rejected enrollment. Wiping local state.")
                zw_client.clear_local_state()
                is_enrolled_locally = False
            else:
                logging.info(f"Startup: Server verification result: {verify_res.get('status')}")

        if is_enrolled_locally:
            logging.info("Startup: Proceeding to Dashboard.")
            app = UnifiedSentinelGUI(zw_client, force_frame="dashboard")
        else:
            logging.info("Startup: Proceeding to Enrollment.")
            app = UnifiedSentinelGUI(zw_client, force_frame="enroll")
        
        _append_gui_log(base_dir, f"GUI startup: {'Dashboard' if is_enrolled_locally else 'Enrollment'} routing decided")
        _append_gui_log(base_dir, "GUI startup: window created")
        try:
            app.update_idletasks()
            app.update()
            _append_gui_log(
                base_dir,
                f"GUI startup: viewable={app.winfo_viewable()} state={app.state()}"
            )
        except Exception as exc:
            _append_gui_log(base_dir, f"GUI startup: update failed: {exc}")
        app.mainloop()
        _append_gui_log(base_dir, "GUI startup: mainloop exited")
    except Exception as e:
        try:
            _append_gui_log(get_base_dir(), f"GUI startup failed: {e}")
        except Exception:
            pass
        logging.error(f"Failed to start interactive mode: {e}", exc_info=True)
        # Show a message box if possible
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, f"Failed to start Sentinel Agent:\n{e}\n\nCheck logs for details.", "Error", 0x10)
        except Exception:
            pass
        sys.exit(1)

def main():
    """
    Entry point resolver. The same binary serves multiple purposes:
      --enroll            -> Force Enrollment screen
      --dashboard         -> Force Dashboard screen
      --daemon            -> Silent background agent (detached)
      --password-prompt   -> Show the visible kill CLI
      --watchdog          -> Internal watchdog process
      (default)           -> Interactive routing (Enroll -> Dashboard)
    """
    # 1. Immediate Console Hiding
    if "--password-prompt" not in sys.argv and "--reset" not in sys.argv:
        hide_console()

    # 2. Force enrollment (CLI flag)
    if "--enroll" in sys.argv:
        base_dir = get_base_dir()
        fp = collect_fingerprint()
        hn = resolve_hostname(base_dir)
        client = ZeroWatchClient(base_dir, fp['device_id'], hn)
        app = UnifiedSentinelGUI(client, force_frame="enroll")
        app.mainloop()
        return

    # 2. Force dashboard (CLI flag)
    if "--dashboard" in sys.argv:
        base_dir = get_base_dir()
        fp = collect_fingerprint()
        hn = resolve_hostname(base_dir)
        client = ZeroWatchClient(base_dir, fp['device_id'], hn)
        if not client.jwt:
            logging.error("Agent not enrolled. Use --enroll first.")
            return
        app = UnifiedSentinelGUI(client, force_frame="dashboard")
        app.mainloop()
        return

    # 3. Visible kill utility
    if "--password-prompt" in sys.argv:
        password_kill_cli()
        return

    # 4. Internal watchdog
    if "--watchdog" in sys.argv:
        wd_idx = sys.argv.index("--watchdog")
        target_exe = sys.argv[wd_idx + 1] if len(sys.argv) > wd_idx + 1 else sys.executable
        watchdog_process(target_exe)
        return
          
    # 5. Background Daemon Mode (The real 'Agent')
    if "--daemon" in sys.argv:
        base_dir = get_base_dir()
        consent_file = os.path.join(_secure_state_dir(base_dir), "consent_accepted.dat")
        if not os.path.exists(consent_file):
            logging.info("Daemon blocked: Consent not accepted yet.")
            sys.exit(0)
        logging.info("Starting background daemon agent.")
        main_agent()
        return

    # Default interactive routing
    run_interactive()

if __name__ == "__main__":
    main()