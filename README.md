# ZeroWatch SentinelAgent (Cross-Platform Endpoint Sensor)

[![Platform: Windows | Linux | macOS](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)](https://deepcytes.io)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://python.org)
[![Security: SPKI Pinning + DPAPI/Keychain](https://img.shields.io/badge/Security-SPKI%20Pinning%20%7C%20Encrypted%20Store-red.svg)](https://deepcytes.io)

**SentinelAgent** is a persistent, self-protecting endpoint sensor designed for the **ZeroWatch** cyber-risk and vulnerability management platform. It fingerprints host hardware, inventories installed software across multiple operational layers, monitors system deltas in real time, and synchronizes inventory and security posture to the ZeroWatch backend over encrypted, certificate-pinned communication channels.

---

## Key Features

- **Multi-Platform Native Support**:
  - **Windows**: Deep Win32/WMI integration, DPAPI credential protection, DACL process hardening, Windows Registry & Task Scheduler persistence.
  - **Linux**: Systemd background service & XDG autostart, SecretService / machine-bound AES-256-GCM vault, POSIX signal defense, and native package manager integration (`dpkg`, `rpm`, `pacman`, `apk`, `flatpak`, `snap`).
  - **macOS**: Native Keychain Services (`Security.framework`), LaunchDaemon lifecycle management, Mach-O binary parsing, and package receipt parsing (`pkgutil`, Homebrew, MacPorts).
- **3-Layer Scanning Engine (`ScanOrchestrator`)**:
  - **Layer 0 (OS Packages & Registry)**: Fast enumeration of installed applications via OS-level package managers and registry hives.
  - **Layer 1 (Deep Binary Inspection)**: High-speed filesystem walker (`fs_walker.py`) and static metadata inspectors for PE (`.exe`, `.dll`, `.sys`), ELF, and Mach-O binaries.
  - **Layer 2 (Dependency Manifests & Lockfiles)**: Automatic discovery of nested project dependencies (`package.json`, `requirements.txt`, `Cargo.lock`, `go.mod`, `pom.xml`, `Pipfile.lock`, `poetry.lock`, `composer.lock`, etc.).
  - **Syft Deep Scan / SBOM**: Bundled Syft engine integration (`resources/syft.exe`) for on-demand full-system Software Bill of Materials generation.
  - **SQLite State Caching (`ScanCache`)**: Local cache tracking file modification timestamps (`mtime`) and cryptographic hashes to minimize I/O overhead during delta evaluations.
- **Dual Operating Modes**:
  - **Unified Desktop GUI (`UnifiedSentinelGUI`)**: Dark-themed Tkinter GUI for interactive device enrollment, user consent onboarding, team pairing, live metric display, and manual trigger controls.
  - **Silent Background Daemon (`--daemon`)**: Headless background service running with console window suppression, low CPU footprint, scheduled delta synchronization, and periodic heartbeats.
- **Self-Defense & Resilience**:
  - **Process Protection**: Windows DACL modification denying `PROCESS_TERMINATE` access to unauthorized users and intercepting console termination events.
  - **Guardian Watchdog**: Detached watchdog process monitoring agent health. In case of termination, an authenticated password prompt (`--password-prompt`) is required before allowing process exit, otherwise the agent automatically revives.
- **Real-Time Bidirectional Communication**:
  - **Socket.IO Eventing**: Real-time WebSocket connection to the ZeroWatch backend joining device-specific rooms (`join-agent`) with handlers for instant unlinking (`unlink`), real-time feeds (`feed_ready`), and remote deep scans (`deep_scan`).
- **Resilient Offline Spooling**:
  - Network requests, synchronization deltas, and audit logs are queued on disk when offline and automatically replayed with exponential backoff when connectivity is restored.
- **Hardened Security & Cryptography**:
  - **SPKI Certificate Pinning**: Strict SHA-256 Subject Public Key Info pinning against backend endpoints to protect against TLS proxying and MITM attacks.
  - **Encrypted Local Storage**: Encrypted token storage (DPAPI / Keychain / AES-GCM) and encrypted audit event logs (`EncryptedFileHandler`).
  - **Mandatory Consent Gate**: Requires explicit operator consent (`consent_accepted.dat`) before enabling background synchronization.

---

## Directory Structure

```
Zerowatch-EXE/
├── common/                        # Cross-platform abstract interfaces and core utilities
│   ├── cert/                      # SPKI certificate pinning engine & verification
│   ├── crypto/                    # Abstract SecureStore interfaces
│   ├── persistence/               # Abstract PersistenceManager interfaces
│   ├── protection/                # Abstract ProcessGuard and EventLogger interfaces
│   ├── scanner/                   # Models, cache abstractions, and manifest definitions
│   ├── utils/                     # Sanitizers, formatting, and time helpers
│   └── platform.py                # Abstract Platform container class
├── platforms/                     # Platform factory for runtime OS dispatch
│   └── factory.py                 # PlatformFactory (instantiates Windows/Linux/macOS)
├── windows/                       # Windows-specific native implementations
│   ├── crypto/                    # Windows DPAPI credential store (CryptProtectData)
│   ├── hardware/                  # WMI hardware collector & machine GUID fingerprinting
│   ├── persistence/               # Registry 'Run' keys and Task Scheduler (schtasks)
│   ├── protection/                # Win32 DACL process guard, console handlers, Event Log
│   ├── scanner/                   # PE binary inspector, registry collector, FS walker
│   └── platform.py                # WindowsPlatform composition
├── linux/                         # Linux-specific native implementations
│   ├── crypto/                    # SecretService & AES-256-GCM file vault
│   ├── hardware/                  # /etc/machine-id, DMI, /proc, and lshw collectors
│   ├── persistence/               # Systemd unit & XDG autostart manager
│   ├── protection/                # POSIX signal guard, watchdog, syslog/journald logger
│   ├── scanner/                   # dpkg/rpm/pacman/apk/snap/flatpak collectors, ELF inspector
│   └── platform.py                # LinuxPlatform composition
├── macos/                         # macOS-specific native implementations
│   ├── crypto/                    # Keychain Services & Security.framework bindings
│   ├── hardware/                  # sysctl, system_profiler, and IOKit collectors
│   ├── persistence/               # LaunchDaemon plist generator (launchctl)
│   ├── protection/                # POSIX signal protection & ASL/syslog logger
│   ├── scanner/                   # App bundle parser, Mach-O inspector, pkgutil/brew
│   ├── validation/                # Native macOS diagnostic validation harness & README
│   └── platform.py                # MacOSPlatform composition
├── scanner/                       # 3-Layer Scanning Orchestrator
│   ├── orchestrator.py            # ScanOrchestrator (coordinates L0, L1, L2 + deduplication)
│   ├── state_cache.py             # SQLite scan cache with mtime & hash validation
│   ├── fs_walker.py               # Fast directory traversal engine
│   ├── layer0_registry.py         # Layer 0 registry adapter
│   ├── layer1_paths.py            # Layer 1 binary scanning
│   ├── layer2_manifests.py        # Layer 2 dependency manifest & lockfile parsers
│   └── models.py                  # SoftwareItem data schemas
├── resources/                     # Embedded resources (icons, Syft binary)
│   ├── favicon.ico                # Windows application icon
│   ├── favicon.png                # Linux/macOS icon
│   └── syft.exe                   # Syft CLI binary for SBOM generation
├── sentinel_agent.py              # Main Windows entry point, GUI, & daemon orchestrator
├── sentinel_agent_linux.py        # Linux entry point & background daemon
├── build_agent.bat                # Windows Nuitka + Zig compilation pipeline
├── build_agent_pyinstaller_enc.bat# Windows PyInstaller compilation with AES-256 encryption
├── run_agent.sh                   # Linux environment launcher & daemon runner
├── validate_macos.sh              # macOS native diagnostic validation harness launcher
├── cert_pinning.py                # Certificate pinning module export adapter
├── verify_pins.py                 # Build-time SPKI pin format & integrity verifier
├── test_cert_pinning.py           # Unit tests for SSL pinning context and SPKI hashes
├── requirements-common.txt        # Shared runtime dependencies (requests, socketio, cryptography)
├── requirements-windows.txt       # Windows dependencies (pywin32, wmi, nuitka)
├── requirements-linux.txt         # Linux dependencies & optional bindings
└── requirements.txt               # Aggregated requirements file
```

---

## Installation & Prerequisites

### 1. Requirements

- **Python**: Version 3.10 or higher.
- **C Compiler (for Nuitka)**: MSVC or Zig (Windows), GCC/Clang (Linux/macOS).

Install dependencies according to your host operating system:

**Windows:**
```powershell
pip install -r requirements-windows.txt
```

**Linux:**
```bash
pip install -r requirements-linux.txt

# Optional system packages for enhanced Linux integration:
sudo apt install python3-inotify python3-secretstorage python3-systemd
```

---

## Building Executables

### Windows Compilation

#### Option A: Nuitka Compiler (Recommended for Performance)
Compile into a standalone executable using `build_agent.bat`:
```cmd
build_agent.bat [OPTIONS]
```

**Supported Options:**
- `/prod` — Pre-configures production backend (`https://zerowatch.deepcytes.io`).
- `/demo` — Pre-configures demo/testing backend (`https://zerowatch-testing.eastasia.cloudapp.azure.com`).
- `/dev` — Pre-configures local development backend (`http://localhost:3001`).
- `/server <URL>` — Points agent to a custom ZeroWatch backend URL.
- `/admin` — Embeds administrative UAC manifest (requests elevation on launch).
- `/onefile` — Bundles everything into a single self-extracting `.exe` (default).
- `/standalone` — Generates an unpacked distribution folder with standalone dependencies.

*Example:*
```cmd
build_agent.bat /prod /onefile
```

#### Option B: PyInstaller with Bytecode Encryption
Compile using `build_agent_pyinstaller_enc.bat` to encrypt embedded Python bytecode via AES-256 and bundle `syft.exe`:
```cmd
build_agent_pyinstaller_enc.bat /prod /onefile
```

---

## Running the Agent

### Windows

#### 1. Interactive Desktop GUI (Default)
Double-click `SentinelAgent.exe` or execute from terminal without arguments:
```cmd
SentinelAgent.exe
```
This launches the dark-themed **Unified Sentinel GUI** for enrollment, account pairing, and live system status inspection.

#### 2. Background Daemon Mode
To execute continuously as a persistent background sensor:
```cmd
SentinelAgent.exe --daemon
```
*(Note: Initial enrollment and consent acceptance via the GUI is required before the daemon will synchronize).*

#### 3. CLI Helper Commands
- `SentinelAgent.exe --enroll` — Forces opening directly to the Enrollment screen.
- `SentinelAgent.exe --dashboard` — Opens directly to the Dashboard screen.
- `SentinelAgent.exe --password-prompt` — Launches the authenticated termination prompt.
- `SentinelAgent.exe --watchdog <exe>` — Spawns the detached guardian watchdog process.

---

### Linux

Use the provided shell wrapper [`run_agent.sh`](file:///c:/Users/admin/Desktop/deepcytes/zerowatch-site/Zerowatch-EXE/run_agent.sh) to run or deploy the Linux sensor:

```bash
chmod +x run_agent.sh

# Interactive development run
./run_agent.sh --dev

# Production background daemon
./run_agent.sh --prod --daemon

# Connect to custom server
./run_agent.sh --server https://custom-backend.internal --daemon
```

---

### macOS Validation Harness

To validate all macOS platform features (Keychain, LaunchDaemon, Mach-O parser, signal handling) on native hardware:

```bash
chmod +x validate_macos.sh
sudo ./validate_macos.sh
```
Refer to [`macos/validation/README.md`](file:///c:/Users/admin/Desktop/deepcytes/zerowatch-site/Zerowatch-EXE/macos/validation/README.md) for full remote QA and validation instructions.

---

## Security Verification & Testing

Verify that your SPKI certificate pins match target servers prior to deployment:
```bash
python verify_pins.py prod
python verify_pins.py demo
```

Run certificate pinning unit tests:
```bash
python -m unittest test_cert_pinning.py
```

For complete technical architecture, API schema reference, and security internals, see [`AGENT_DOCUMENTATION.md`](file:///c:/Users/admin/Desktop/deepcytes/zerowatch-site/Zerowatch-EXE/AGENT_DOCUMENTATION.md).
