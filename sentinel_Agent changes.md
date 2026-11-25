# SentinelAgent Optimization & Architecture Remediation Plan
**Target:** ZeroWatch Windows Sentinel Agent (`sentinel_agent.py`)  
**Objective:** Deliver on the "Lightweight Endpoint Agent" claim by reducing process count from 5 to 1–2, slashing memory footprint by ~60%, and eliminating duplicate concurrent instances.

---

## 1. Executive Summary & Current Condition Analysis

In the current live deployment, Windows Task Manager displays **5 running processes** grouped under two process trees:
* **Tree 1:** `SentinelAgent-windows-x64 (2)` consuming ~53.4 MB RAM
* **Tree 2:** `SentinelAgent-windows-x64 (3)` consuming ~24.5 MB RAM
* **Total Resource Usage:** ~78 MB RAM, 5 processes, dual concurrent WebSocket/HTTPS connections to backend port 443, and competing writes to local SQLite caches.

```
Task Manager View:
┌── SentinelAgent-windows-x64 (2) ───────── 0% CPU ── 53.4 MB RAM
│   ├── PID 15008 (Nuitka Launcher / Medium Integrity)
│   └── PID 15100 (Duplicate Daemon / Medium Integrity / Established Port 443)
│
└── SentinelAgent-windows-x64 (3) ───────── 0% CPU ── 24.5 MB RAM
    ├── PID 7440  (Nuitka Launcher / Task Scheduler / High Integrity)
    ├── PID 13264 (Primary Daemon / High Integrity / Established Port 443)
    └── PID 12664 (Watchdog Guardian / High Integrity)
```

### The Problem
An endpoint security agent claiming to be **lightweight** should maintain a minimal OS footprint:
* **Target Process Count:** 1 process (or 1 daemon + 1 watchdog in standalone mode).
* **Target Memory Footprint:** < 25 MB in background idle mode.
* **Target Concurrency:** Strict single-instance guarantee across all Windows user sessions and privilege boundaries.

---

## 2. Root Cause Analysis

### 2.1 Cross-Privilege Mutex Collision Bug (Duplicate Daemons)
* **Location:** [`sentinel_agent.py` line 2924–2936](file:///e:/Deepcytes/Endpoint-Agent/sentinel_agent.py#L2924-L2936) (`enforce_single_daemon_instance()`)
* **Mechanism:**
  1. Windows Task Scheduler executes the agent at logon with **RunLevel: Highest** (`Administrator`).
  2. PID 13264 creates named mutex `Global\SentinelAgent_Daemon_4F9A2E1B` with default security attributes (`None`), giving full control only to the elevated token.
  3. When an interactive user starts the application or secondary startup trigger fires at medium integrity, PID 15100 calls `CreateMutexW`.
  4. Windows denies access with `GetLastError() == ERROR_ACCESS_DENIED` (`5`), returning a `NULL` handle.
  5. The existing code checks:
     ```python
     if last_err != 183:  # 183 is ERROR_ALREADY_EXISTS
         return mutex
     ```
  6. Since `5 != 183`, the function erroneously assumes it acquired the mutex, returns `None`, and enters the daemon loop!
  7. **Result:** Two full background daemons run simultaneously, duplicate telemetry is transmitted, and SQLite locking errors occur on `scan_cache.db`.

### 2.2 Process Multiplication via Nuitka Onefile Architecture
* **Location:** [`build_agent.bat` lines 218–228](file:///e:/Deepcytes/Endpoint-Agent/build_agent.bat#L218-L228) (`--onefile`)
* **Mechanism:**
  * Nuitka's `--onefile` packaging works by keeping a bootstrap parent stub running while executing the extracted binary in `%TEMP%\onefile_...`.
  * Every invocation creates **2 OS processes** by design (1 parent bootstrap + 1 child worker).
  * Spawning `--watchdog` as a separate onefile invocation adds another process pair.
  * 1 Daemon + 1 Watchdog = 3 to 4 processes before any UI is even opened.

### 2.3 Unconditional Tkinter & UI Import Overhead in Headless Daemon
* **Location:** [`sentinel_agent.py` lines 150–259](file:///e:/Deepcytes/Endpoint-Agent/sentinel_agent.py#L150-L259)
* **Mechanism:**
  * `_setup_tcl_tk_paths()` runs full recursive directory sweeps (`os.walk`) during top-level module import.
  * `import tkinter as tk` and `ttk` are imported unconditionally at the root of `sentinel_agent.py`.
  * Even when launched with `--daemon` or `--watchdog`, every headless background process initializes the Win32 GUI subsystem, Tcl/Tk interpreter, and font caches, unnecessarily consuming 15–30 MB RAM per process.

### 2.4 The Auto-Update (OTA) Spawning Chain & Missing Watchdog Stand-Down Signal
* **Location:** [`common/daemon_ota.py` lines 42–74](file:///e:/Deepcytes/Endpoint-Agent/common/daemon_ota.py#L42-L74) vs [`sentinel_agent.py` lines 8287–8298](file:///e:/Deepcytes/Endpoint-Agent/sentinel_agent.py#L8287-L8298)
* **Mechanism:**
  1. **User Observation Confirmed:** The extra 3 instances spawn precisely when the background agent performs an OTA auto-update.
  2. When an update is ready, `daemon_ota.py` downloads the new binary, performs the swap, and calls:
     ```python
     relaunched = _relaunch_detached(self.current_exe, reopen_gui=False)
     ...
     self.shutdown_event.set()
     ```
  3. **Critical Bug in Headless OTA:**
     In the GUI update path (`sentinel_agent.py` line 8291), the author specifically documented:
     ```python
     # 0. Signal the watchdog guardian to exit gracefully.
     #    Without this, the watchdog detects the mutex release from os._exit(0)
     #    and RESPAWNS the agent — causing 4+ ghost processes every update.
     request_shutdown_signal(get_base_dir(), reason="ota-restart")
     _wait_for_auxiliary_processes()
     ```
     However, **in `common/daemon_ota.py`, this entire stand-down signal sequence was omitted!**
  4. **The Cascade:**
     * `_relaunch_detached()` spawns the new binary. Because it is a Nuitka onefile executable, it immediately spawns:
       - **Process 1:** New Nuitka parent unpacker stub.
       - **Process 2:** New Sentinel daemon worker.
       - **Process 3:** New Watchdog guardian process (spawned by the new daemon via `spawn_watchdog()`).
     * Meanwhile, the **old daemon** exits via `self.shutdown_event.set()`, releasing `DAEMON_MUTEX_NAME`.
     * The **old watchdog** is still alive! Because `daemon_ota.py` never wrote `request_shutdown_signal(..., "ota-restart")`, the old watchdog detects the daemon is dead. It waits, fails to see the new mutex (or gets `ERROR_ACCESS_DENIED`), and attempts its own recovery relaunch via `_relaunch_detached()` or leaves orphaned processes behind.
     * The result: 1 old tree + 1 new tree = **5 running processes** (2 from one tree, 3 from the other).

### 2.5 Synchronous Network Call During Module Import
* **Location:** [`sentinel_agent.py` lines 270–282](file:///e:/Deepcytes/Endpoint-Agent/sentinel_agent.py#L270-L282)
* **Mechanism:**
  * If `agent_build_config.py` is absent, `_fetch_github_release_version()` executes a blocking HTTP request to `api.github.com` inside the import path. This stalls daemon bootstrap and increases CPU wakeups.

---

## 3. Required Remediation & Architecture Changes

### Change 1: Universal Low-Integrity / Permissive DACL Mutex Guard
Ensure non-elevated processes can properly inspect elevated mutexes across Windows integrity levels.

```python
# Fix in sentinel_agent.py: enforce_single_daemon_instance()
import win32security
import ntsecuritycon

def _create_permissive_mutex(mutex_name: str):
    """
    Creates a named Global mutex with a NULL DACL so medium-integrity
    processes can detect an existing high-integrity instance without
    receiving ERROR_ACCESS_DENIED.
    """
    if sys.platform != "win32":
        return None
    
    # Security Descriptor with empty DACL (grants Everyone access to probe)
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.Initialize()
    sd.SetSecurityDescriptorDacl(True, None, False)
    
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.bInheritHandle = False
    sa.SECURITY_DESCRIPTOR = sd
    
    mutex = ctypes.windll.kernel32.CreateMutexW(sa, True, mutex_name)
    last_err = ctypes.windll.kernel32.GetLastError()
    
    # 183 = ERROR_ALREADY_EXISTS, 5 = ERROR_ACCESS_DENIED
    if last_err in (183, 5):
        if mutex:
            ctypes.windll.kernel32.CloseHandle(mutex)
        return None
    return mutex
```

Additionally, add a file-lock fallback on Windows in `%PROGRAMDATA%\ZeroWatch\state\daemon.lock` using `msvcrt.locking` to ensure double-guaranteed single-instance enforcement.

---

### Change 2: Lazy-Load Tkinter and GUI Libraries
Move all GUI imports out of the global module scope into `run_interactive()`, `enroll()`, and `dashboard()` entry points:

1. **Delete** global `_setup_tcl_tk_paths()` call from line 248.
2. **Delete** global `import tkinter as tk` from line 252.
3. **Move** inside `UnifiedSentinelGUI.__init__` or `run_interactive()`:
   ```python
   def run_interactive():
       _setup_tcl_tk_paths()
       import tkinter as tk
       from tkinter import ttk, font as tkfont
       ...
   ```
* **Immediate Impact:** Cuts ~20 MB RAM from each background daemon and watchdog process.

---

### Change 3: Transition from `--onefile` to Directory/Installer Distribution
Nuitka's `--onefile` flag is the direct cause of the parent wrapper processes (`PID 7440` and `PID 15008`).

| Packaging Format | Process Count per Daemon | RAM per Process | Startup Latency | Temp Disk Overhead |
| :--- | :--- | :--- | :--- | :--- |
| **Current (`--onefile`)** | **2 processes** (Parent + Child) | ~50–100 MB | 2–5 sec (unpack) | Unpacks 100MB+ in `%TEMP%` |
| **Recommended (`--standalone` + Inno Setup / MSI)** | **1 process** | **~20–30 MB** | **Instant (< 100ms)** | Zero temp unpacking |

#### Update `build_agent.bat`:
Switch the production target from `/onefile` to `/standalone` and bundle the output folder using standard Inno Setup or WiX MSI. The executable will run as a native single process with no parent stub.

---

### Change 4: Lightweight Watchdog Architecture
Currently, the watchdog executes another copy of the entire agent binary (`--watchdog`).

**Options to reduce footprint:**
1. **Windows Service Recovery (Preferred for Enterprise):**
   * Register `ZeroWatch Sentinel` as a Windows Service (`sc.exe create ZeroWatchService ...`).
   * Configure service failure recovery:
     ```cmd
     sc.exe failure ZeroWatchService reset= 86400 actions= restart/5000/restart/10000/restart/60000
     ```
   * **Result:** Eliminates the watchdog process entirely (0 MB overhead, handled natively by Windows Service Control Manager).
2. **Minimalist Watchdog Executable (If Standalone):**
   * If an anti-kill watchdog process is mandatory, compile a tiny standalone C/Rust watchdog binary (`watchdog.exe`, < 1 MB disk, < 3 MB RAM) instead of spawning a full Python/Nuitka runtime.

---

### Change 5: Fix Headless OTA Watchdog Stand-Down Signal
In [`common/daemon_ota.py`](file:///e:/Deepcytes/Endpoint-Agent/common/daemon_ota.py#L42-L74), replicate the watchdog stand-down signal sequence that was implemented in the GUI path:

```python
# Fix in common/daemon_ota.py: _apply_update()
if perform_update(dest, self.current_exe):
    if os.name == "nt":
        from common.os_replacer import (
            _relaunch_detached,
            _trigger_windows_daemon_task,
        )
        # CRITICAL: Signal the active watchdog to stand down and expect an OTA restart
        # Without this, the old watchdog detects daemon termination and spawns a recovery process!
        from common.os_replacer import request_shutdown_signal, _wait_for_auxiliary_processes
        try:
            base_dir = os.path.dirname(os.path.abspath(self.current_exe))
            request_shutdown_signal(base_dir, reason="ota-restart")
            logger.info("[OTA] Shutdown signal written for watchdog stand-down.")
        except Exception as sig_err:
            logger.warning("[OTA] Could not write shutdown signal: %s", sig_err)

        _wait_for_auxiliary_processes(timeout=10)
        relaunched = _relaunch_detached(self.current_exe, reopen_gui=False)
        ...
```

---

### Change 6: Active Orphan Process Cleanup on Startup
Add an active cleanup routine in `main_agent()` to kill any stale duplicate daemons from previous runs:

```python
def cleanup_duplicate_sentinels(current_pid: int):
    """Ensure no duplicate sentinel agent daemons are running."""
    import win32process
    # Enumerate processes with same image path, terminate duplicates if not watchdog
```

---

## 4. Expected Results After Remediation

| Metric | Current State | Target State | Improvement |
| :--- | :--- | :--- | :--- |
| **Total Processes in Background** | **5 processes** | **1 process** (or 2 with standalone watchdog) | **60% to 80% reduction** |
| **Total Memory Consumption** | **~78 MB – 120 MB** | **< 25 MB** | **~70% memory reduction** |
| **Network Sockets to Backend** | Dual parallel sockets | Single socket | Eliminates duplicate telemetry |
| **Startup / Disk Behavior** | Unpacks to `%TEMP%` on boot | Native execution from disk | Instant boot, zero temp clutter |

---

## 5. Implementation Roadmap

1. [ ] **Phase 1 (Immediate Hotfix):** Patch `enforce_single_daemon_instance()` in [`sentinel_agent.py`](file:///e:/Deepcytes/Endpoint-Agent/sentinel_agent.py) to check `ERROR_ACCESS_DENIED` and prevent duplicate daemons.
2. [ ] **Phase 2 (OTA Restart Hotfix):** Add `request_shutdown_signal(..., reason="ota-restart")` and `_wait_for_auxiliary_processes()` to [`common/daemon_ota.py`](file:///e:/Deepcytes/Endpoint-Agent/common/daemon_ota.py) so old watchdogs exit cleanly on update.
3. [ ] **Phase 3 (Memory Optimization):** Move Tkinter and Tcl/Tk initialization to lazy loads inside interactive GUI blocks.
4. [ ] **Phase 4 (Build Pipeline):** Switch [`build_agent.bat`](file:///e:/Deepcytes/Endpoint-Agent/build_agent.bat) to standalone distribution packaged in an installer or Windows Service.
5. [ ] **Phase 5 (Supervision):** Replace python-based watchdog with Windows Service Recovery or a lightweight native guardian.

