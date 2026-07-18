# ZeroWatch SentinelAgent

SentinelAgent is a self-protecting, persistent Windows endpoint sensor designed for the ZeroWatch platform. It fingerprints the host, inventories installed software and hardware, and synchronizes that information to a ZeroWatch backend over a REST API.

## Features

- **Inventory Management**: Automatically scans and inventories hardware profiles and installed software using Windows APIs and registry.
- **Dual Modes**:
  - **Interactive Command Center**: Used for initial enrollment, linking to an account, manual syncs, and launching the daemon.
  - **Daemon Mode**: Runs as a background service performing full inventory, periodic delta monitoring, heartbeats, and self-defense.
- **Self-Protection & Watchdog**: Employs DACL hardening (preventing unauthorized process termination) and a detached watchdog process to restart the agent if killed. Attempts to kill the agent require a password via a spawned CLI prompt.
- **Persistence**: Ensures startup persistence by registering via the Windows Registry (`Run` keys) and Task Scheduler.
- **Delta Syncing**: Monitors system changes continuously and synchronizes only added or removed items to reduce overhead.
- **API Integration**: Communicates with the ZeroWatch backend (default `http://localhost:3001`) via JSON over HTTP using JWT authentication.

## Project Structure

- `sentinel_agent.py`: The main agent implementation containing all orchestrator logic, hardware/software inventory modules, network communication, and self-protection logic.
- `agent.py`: A legacy prototype script kept for reference purposes.
- `build_agent.bat`: Nuitka build pipeline script to compile the agent into a standalone executable.
- `AGENT_DOCUMENTATION.md`: Comprehensive internal documentation detailing the architecture, API client, and module breakdown.

## Prerequisites

- **OS**: Windows (requires low-level Windows APIs and registry access)
- **Python**: 3.x
- **Dependencies**: Included in `requirements.txt`. Notable external modules include `requests` and `pywin32` (specifically for DPAPI encryption and ACL hardening).
- **Build Tools**: Nuitka and Zig (if compiling to a standalone executable).

## Installation & Build

To compile the SentinelAgent into a standalone Windows executable (`.exe`), you can use the provided build script:

```cmd
build_agent.bat
```
This uses Nuitka to freeze the Python script into an executable that can be deployed onto endpoints.

## Usage

**Interactive Mode:**
Simply run the compiled executable to open the command center. You can enroll, link an account, or perform manual synchronizations.
```cmd
SentinelAgent.exe
```

**Daemon Mode:**
To run the agent continuously in the background, use the `--daemon` flag.
```cmd
SentinelAgent.exe --daemon
```

For more detailed information regarding the implementation and architecture, refer to `AGENT_DOCUMENTATION.md`.
