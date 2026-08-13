# SentinelAgent Endpoint Sensor Documentation

This document provides a comprehensive, in‑depth overview of the cross-platform endpoint agent code located in `Endpoint-Agent/`. The primary platform entry points are [sentinel_agent.py](file:///e:/Deepcytes/Endpoint-Agent/sentinel_agent.py) (Windows), [sentinel_agent_linux.py](file:///e:/Deepcytes/Endpoint-Agent/sentinel_agent_linux.py) (Linux), and [sentinel_agent_macos.py](file:///e:/Deepcytes/Endpoint-Agent/sentinel_agent_macos.py) (macOS). A lightweight prototype (`agent.py`) is also included but is no longer used by the build pipeline.

> **Note:** build artifacts (`.exe`, build directories) are not documented here; they are generated automatically by the build script and are implicit from the source code.

---

## 1. Purpose & High-Level Flow

SentinelAgent is a self‑protecting, persistent Windows “sensor” that
fingerprints the host, inventories installed software/hardware, and
synchronises that information to a ZeroWatch backend over a REST API.
It runs in two modes:

1. **Interactive Command Center** (default) – used for initial
   enrollment, linking to an account, manual syncs, and launching the
   daemon.
2. **Daemon Mode** (`--daemon`) – background service performing full
   inventory, periodic delta monitoring, heartbeats, and self‑defense.

A detached **watchdog** process guards against termination, and a
password CLI is spawned if a kill attempt is detected.

The agent communicates with a local server (default `http://localhost:3001`)
using JSON over HTTP. All device‑specific requests require a JWT that is
stored encrypted by DPAPI in `zerowatch_token.dat` beside the
executable.

---

## 2. Files & Structure

```
endpoint_agent/
├── sentinel_agent.py   # Main agent implementation
├── agent.py            # Legacy/prototype script
├── build_agent.bat     # Nuitka build pipeline (not covered here)
└── build/              # Temporary build output
```

The bulk of the logic lives in `sentinel_agent.py`; the remainder of
this document focuses on that file.

---

## 3. Dependencies & Libraries

The agent uses only standard library modules except where noted:

| Module                                                                               | Purpose                                      |
| ------------------------------------------------------------------------------------ | -------------------------------------------- |
| `os`, `sys`, `time`, `datetime`, `threading`, `subprocess`, `json`, `csv`, `hashlib` | general utilities                            |
| `uuid`, `ctypes`, `ctypes.wintypes`, `signal`                                        | low‑level Windows APIs                       |
| `winreg`                                                                             | registry access                              |
| `logging`                                                                            | file logging to `sentinel_agent.log`         |
| `requests`                                                                           | HTTP client (third‑party, bundled by Nuitka) |
| `win32crypt`                                                                         | DPAPI encryption (from `pywin32`)            |

Additional `pywin32` modules such as `win32security`, `ntsecuritycon`,
`win32api`, and `win32con` are imported on demand for ACL hardening
(protection module); if they are missing, the agent logs a warning and
continues.

The build pipeline uses Nuitka + Zig to freeze this script into a
standalone exe, but no build‑time artifacts appear in the repository.

---

## 4. ZeroWatch REST API Client

A helper class encapsulates all server communication. It handles
JWT loading/saving, header management, serialization and automatic
invalid‑token cleanup.

```python
class ZeroWatchClient:
    def __init__(self, base_dir, device_id, hostname, fingerprint_data=None):
        ...
    # JWT persistence
    def _load_jwt(self): ...
    def _save_jwt(self, jwt_str): ...
    def _auth_headers(self): ...

    # Authentication endpoints
    def login_user(self, email, password): ...
    def request_otp(self, email): ...
    def register_user(self, name, email, password, otp): ...
    def get_device_status(self, user_jwt): ...

    # Device linking
    def enroll(self, pin): ...
    def link_direct(self, user_jwt): ...

    # Inventory sync
    def sync_full(self, software_list, hardware_info=None): ...
    def sync_delta(self, added, removed, added_hw=None, removed_hw=None, hardware_snapshot=None): ...
    def unlink_self(self): ...

    # Heartbeat & logging
    def heartbeat(self): ...
    def log_event(self, event_type, details): ...

    # Kill verification & metrics
    def verify_kill(self, password): ...
    def get_dashboard_stats(self): ...
```

### Server endpoints used

All URLs are relative to `BASE_API_URL = "http://localhost:3001/api"`.

| Method | Path                        | Purpose                            |
| ------ | --------------------------- | ---------------------------------- |
| POST   | `/auth/login`               | Authenticate user, obtain JWT      |
| POST   | `/auth/request-otp`         | Send OTP email for registration    |
| POST   | `/auth/register`            | Create user account                |
| GET    | `/agent/device`             | Get linked device for current user |
| POST   | `/agent/enroll`             | Link via 6‑digit PIN (public)      |
| POST   | `/agent/link-authenticated` | Link device after user login       |
| POST   | `/agent/sync/full`          | Upload entire inventory            |
| POST   | `/agent/sync/delta`         | Upload incremental changes         |
| DELETE | `/agent/unlink-self`        | Unlink this device                 |
| POST   | `/agent/heartbeat`          | Periodic alive signal              |
| POST   | `/agent/log`                | Generic event logging              |
| POST   | `/agent/verify-kill`        | Validate termination password      |
| GET    | `/agent/metrics`            | Retrieve dashboard statistics      |

Responses with `401` or `404` trigger local JWT/token deletion so the
agent returns to the linking state.

---

## 5. Module Breakdown

The file is organised into numbered modules with clear boundaries.

### 5.1 Module 0.5 – API Client (covered above)

### 5.2 Bootstrap – single‑instance mutex

```python
def enforce_single_instance():
    mutex = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
    last_err = ctypes.windll.kernel32.GetLastError()
    if last_err == 183:  # ERROR_ALREADY_EXISTS
        logging.info("Another instance is already running. Exiting silently.")
        sys.exit(0)
    return mutex
```

Prevents multiple copies of the agent/daemon from running.

### 5.3 Fingerprint & Device ID

Collection functions use WMIC and the registry to gather persistent
device identifiers. A deterministic SHA‑256 hash (prefixed `SAGT-`)
is used as the `device_id`.
Key functions:

- `_wmi_query`, `_wmi_query_all`, `_wmi_query_rows` – helpers for WMIC
- `get_mac_address`, `get_machine_guid` – simple helpers
- `collect_fingerprint()` – returns full fingerprint dict
- `generate_device_id(fingerprint)` – returns the stable ID

### 5.4 Inventory

Software scanning occurs via the registry uninstall keys. Hardware
scanning uses WMIC commands to enumerate CPU, RAM, GPU, disks, network,
motherboard, BIOS, OS, etc. Snapshots are returned either as flat lists
(for delta reporting) or as structured profiles (`get_detailed_hardware_profile`).

### 5.5 Protection

To impede termination the agent applies a DACL denying
`PROCESS_TERMINATE` to Everyone (if `pywin32` is installed) and installs
a console control handler to intercept Ctrl+C/close events. A
separate password‑based kill CLI (`password_kill_cli`) verifies input
with the backend before allowing termination.

### 5.6 Persistence

Two mechanisms ensure startup persistence:

- `register_startup_registry()` places the daemon command in
  `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`.
- `register_task_scheduler()` creates a scheduled task that runs
  at logon with highest privileges.

Both entries run the executable with the `--daemon` flag.

### 5.7 Watcher (change monitor)

`monitor_system_changes` runs in a background thread during daemon mode.
It polls the software registry and hardware profile every
`MONITOR_INTERVAL` seconds, diffs against the last snapshot, and calls
`zw_client.sync_delta` with the added/removed items. Deltas are logged
via `zw_client.log_event("SYSTEM_CHANGE", …)`.

### 5.8 Watchdog

A completely detached guardian process monitors the main agent. If the
agent mutex disappears (i.e. the agent is killed), the watchdog
acquires a prompt mutex and spawns a visible password CLI. Correct
password → both processes exit. Incorrect password → watchdog revives
the agent (using `--no-watchdog` to avoid recursive spawning) after a
30‑second cooldown.

### 5.9 File exports

Utility functions dump the fingerprint and inventory to
`device_fingerprint.json` and `products.csv` respectively for forensic
review.

### 5.10 Main orchestrator & CLI code

`main_agent()` implements daemon behaviour:

1. Enforce single instance
2. Apply protection (ACL + control handler)
3. Optionally spawn watchdog
4. Register persistence
5. Collect fingerprint and export JSON
6. Initialize `ZeroWatchClient`; if no JWT, exit requiring manual link
7. Run full software+hardware inventory and upload via `sync_full`
8. Start watcher thread
9. Enter heartbeat loop, revive watchdog if necessary

The CLI functions (`command_center_cli`, `login_cli`, `register_cli`,
`enroll_cli`) provide interactive menus for linking and manual actions.
`main()` dispatches based on command‑line arguments; the same binary
handles:

- `--enroll` / `--login` / `--register` / `--dashboard` – various
  interactive menus
- `--password-prompt` – password CLI invoked by watchdog
- `--watchdog <exe>` – run watchdog logic
- `--daemon` – run daemon
- default – run command center

A typical user flow: double‑click `SentinelAgent.exe` → command center →
Link device → choose "Start background protection mode" → daemon
launches (or runs automatically at startup) and closes the menu.

## 6. agent.py (Legacy Prototype)

The earlier `agent.py` contains simplified fingerprinting, registry
scraping, and change monitoring code used when the project was first
being prototyped. It exports fingerprint and software lists to local
files and includes a minimal watchdog mechanism. It is kept mostly for
reference only and is not built into an executable.

Key functions:

- `get_fingerprint()` – gathers MAC, BIOS UUID, motherboard serial,
  machine GUID, CPU ID, disk serial
- `get_installed_software()` – registry scanner (deduplicated)
- `export_to_readable_files()` – write JSON + CSV
- `monitor_software_changes()` – poll every 20s and export on count
  change
- `prompt_password_to_quit()` – simple password prompt (no network)

## 7. Communication & API Details

All network activity is synchronous `requests` calls with short timeouts.
Payload formats are simple JSON and mirror the backend schema for
inventory items. When the agent detects a server error or an invalid
token (401/404), it deletes the local JWT file and returns to the
unlinked state – the next interactive run will prompt the user to relink.

### Typical inventory payload (`sync_full`)

```json
{
  "device_id": "SAGT-...",
  "inventory": [
    {"name": "App", "version": "1.2", "vendor": "Corp", "install_date": "20230201", "source": "registry"},
    ...
  ],
  "hardware": {
     "cpu": "Intel ...",
     "ram": {"total_kb": "...", "modules": [...]},
     ...
  }
}
```

### Delta payload (`sync_delta`)

```json
{
  "device_id": "SAGT-...",
  "added": [...],
  "removed": [...],
  // optional "hardware_snapshot" when hardware changed
}
```

Other endpoints use minimal JSON fields as shown in the `ZeroWatchClient`
methods above.

---

## 8. Execution Flow Summary

1. **Install/extract**: user obtains `SentinelAgent.exe` on a Windows
   machine.
2. **Initial run**: double‑clicking invokes `main()` with no args,
   showing the command center. The user either registers a new
   ZeroWatch account, logs in, or enters an enrollment PIN.
3. **Link**: the agent obtains a JWT (saved encrypted) and returns to the
   menu where the user may launch the daemon.
4. **Daemon startup**: on `--daemon`, the agent enforces single instance,
   hardens itself, spawns a watchdog, registers persistence, fingerprints
   the device, uploads a full inventory, and begins periodic monitoring
   and heartbeats.
5. **Background operation**: the agent runs invisibly, syncing changes
   and reporting health. The watchdog ensures the agent restarts after
   unauthorized kills.
6. **User interaction after link**: running the exe again (or using
   `--dashboard`) brings up status or allows manual syncs/unlinking.
7. **Unlink**: the user can unlink from the command center; the agent
   deletes its local JWT and on next daemon run will prompt for linking.

---

## 9. Notes & Extension Points

- **Token invalidation**: `sync_full`, `sync_delta`, and `heartbeat` all
  clear the local token on 401/404 response codes.
- **DAE**: DACL hardening is optional; the agent will still run without
  `pywin32`.
- **Persistence**: two mechanisms are used to survive reboots and UAC
  prompts. The build script now defaults to a non‑elevated build; UAC
  elevation is only required when `--admin` is passed.
- **Watchdog**: the guardian offers an offline kill password
  (`Pass@123`) and prevents fork bombs via mutexes.
- **Logging**: all operations write to `sentinel_agent.log` in the base
  directory. The CLI prints coloured output when attached to a TTY.

---

## 10. Cross-Platform Support (Linux & macOS)

To support non-Windows endpoints, the agent includes dedicated entry points and platform compositions for Linux and macOS. The core orchestrator (`scanner/fs_walker.py`, `scanner/orchestrator.py`) remains platform-agnostic, while platform-specific behaviors are composed via a `PlatformFactory`.

### 10.1 Platform Entry Points
- **Linux (`sentinel_agent_linux.py`)**: Designed for modern Linux distributions. It uses systemd-compatible signals (SIGTERM/SIGINT) for clean shutdowns.
- **macOS (`sentinel_agent_macos.py`)**: Tailored for macOS (supporting both Intel and Apple Silicon), handling Full Disk Access (FDA) verification and Keychain access.

### 10.2 Single-Instance Locks
Unlike the Windows agent which uses named mutexes, Linux and macOS employ POSIX file locks via `fcntl.flock` on `.zerowatch.lock` located inside the active state directory:
- It attempts to open and acquire an exclusive, non-blocking lock (`LOCK_EX | LOCK_NB`).
- If successful, it writes the current PID to the file and continues.
- If it fails due to `BlockingIOError`, it logs the PID of the existing running process and exits cleanly.
- The lock file descriptor is kept open for the process lifetime and released automatically by the OS upon process exit.

### 10.3 Persistence Managers
- **Linux (`LinuxPersistenceManager`)**: Registers a systemd unit (`zerowatch-agent.service`). If run as root, it registers system-wide under `/etc/systemd/system/`. If run as a standard user, it falls back to a user-level service under `~/.config/systemd/user/`.
- **macOS (`MacOSPersistenceManager`)**: Registers a launchd plist (`io.deepcytes.zerowatch.agent.plist`) under `/Library/LaunchDaemons/` and bootstraps it into the system domain using `launchctl bootstrap`.

### 10.4 Environment Propagation
When persistence is registered, if `ZEROWATCH_API_URL` is set in the current shell, it is dynamically baked into the persistence configuration (`Environment=` directive for systemd, or `EnvironmentVariables` dictionary for launchd plist). This ensures the agent maintains connection to custom or local server URLs across system reboots or crash restarts.

---

The above description should provide exhaustive insight into every function, flow control decision, and interaction within the endpoint agent codebase. Use this as reference when debugging, extending, or integrating the agent with the backend.
