# ZeroWatch SentinelAgent

ZeroWatch SentinelAgent is a secure, persistent, and self-protecting endpoint security sensor. It executes deep software and hardware asset discovery, monitors system changes, and maintains a secure connection to a ZeroWatch server to log delta variations and telemetry events in real-time.

Designed for enterprise threat management, the agent is engineered to prevent unauthorized termination, securely store authentication secrets in OS-native secure stores, verify backend identities via cryptographic pinning, and survive system reboots through native daemon mechanisms.

---

## 🔍 Core Architectures & Features

### 1. Dual-Engine Software & Hardware Discovery
To establish a version-exact record of every piece of software on the host without causing CPU or disk I/O spikes, the agent operates a multi-tiered inspection pipeline:
* **L0: Fast Package & Registry Monitor (Continuous)**
  * **Windows**: Real-time polling of Windows Registry `Uninstall` hives (both 64-bit and 32-bit `Wow6432Node` paths).
  * **Linux**: Native queries to distribution package databases (`dpkg`, `rpm`, `pacman`) and sandbox container layers (`snap`, `flatpak`).
  * **macOS**: Scans system application bundle registers (`/Applications` and `~/Applications`) and registers with Apple package database utilities (`pkgutil`).
  * *Runs periodically with local caching to detect instant software additions or removals.*
* **L1 & L2: Deep Filesystem & Binary Inspection (Scheduled)**
  * **Path Walks**: Recursively inspects binary files in standard executable search paths (such as `/bin`, `/usr/bin`, `/sbin` on Linux; `/usr/local/bin` and system locations on macOS).
  * **Format-Aware Parsing**: Parses binary layouts directly—Portable Executable (PE) on Windows, Executable and Linkable Format (ELF) on Linux, and Mach-O on macOS—to read internal product version blocks, static manifest declarations, and dynamic dependency configurations.
  * **Delta Walkers**: Uses cached file hashes and write-timestamps to inspect only modified or newly created files, ensuring zero performance impact on the host.

### 2. Transport Hardening & Cryptographic Pinning
To prevent Man-in-the-Middle (MitM) attacks, SSL interception, or rogue server redirection:
* **Subject Public Key Info (SPKI) Pinning**: The agent's custom HTTP sessions enforce strict certificate pinning by validating the SHA-256 fingerprint of the backend server's public key.
* **Enrollment Guards**: Limits device enrollment to verified team and individual join codes, refusing to initiate default parameters or fake state information.
* **Auto-Purge**: If the backend returns a `401 Unauthorized` or `404 Not Found` response code during synchronization or heartbeats, the local token is instantly purged, putting the agent back into a secure, unlinked state.

### 3. OS-Native Secure Credential Storage
Authentication JWT tokens are never stored in plain text. Instead, the agent wraps credentials inside OS-native cryptographic vaults:
* **Windows**: Protected using DPAPI (Data Protection API) via `CryptProtectData` (user-scoped encryption).
* **Linux**: Secured using encrypted storage modules mapping to platform keyrings or user-specific state folders locked with `0o600` (read/write only by owner) permissions.
* **macOS**: Uses macOS Keychain Services to register and secure the device authentication secrets.

### 4. Self-Protection & Tamper Resistance
* **Process ACL Hardening (Windows)**: Denies `PROCESS_TERMINATE` access rights to Everyone (via custom DACLs) on Windows console processes.
* **Console Controls**: Intercepts shutdown, close, and Ctrl+C console signals.
* **Watchdog Supervisor**: Spawns a separate guardian process. If the main agent process disappears, the watchdog triggers a password validation dialog. A correct security password halts both; an incorrect password instantly respawns the main agent.
* **Single-Instance Guards**: Uses exclusive named Mutexes (Windows) and POSIX file locks via `fcntl.flock` (Linux & macOS) to prevent multiple concurrent agents from running and corrupting cache databases.

---

## 💻 Windows Setup & Execution

### Interactive Mode
Double-click `SentinelAgent.exe` or execute it from Command Prompt / PowerShell. This runs the text-based command center interface where users can enroll new devices, log in, view status, or execute manual inventories.
```cmd
SentinelAgent.exe
```

### Setup Demo Video
Below is a demonstration of installing, configuring, and running the Windows endpoint agent:

https://github.com/user-attachments/assets/77a62549-01ed-4cab-a0dd-2f37109f0a86

---

## 🐧 Linux Setup & Execution

### 1. Make the Binary Executable
```bash
chmod +x SentinelAgent-linux-x64
```

### 2. Launch the GUI and Enroll
Run the binary as the logged-in desktop user. This opens the ZeroWatch GUI:
```bash
./zerowatch-agent-linux-x64
```
Complete enrollment in the GUI. After enrollment, the GUI starts the detached background agent automatically. Closing the GUI or terminal does not stop it.

For a system-wide service installation, run the daemon setup with administrator privileges after enrollment:
```bash
sudo ./zerowatch-agent-linux-x64 --daemon
```
For a normal user installation, the background process can be started directly:
```bash
./zerowatch-agent-linux-x64 --daemon
```

### Service Control Commands
* **Status**: `sudo systemctl status zerowatch-agent` (system install)
* **User status**: `systemctl --user status zerowatch-agent`
* **Live logs**: `sudo journalctl -u zerowatch-agent -f` (system install)
* **Stop daemon**: `sudo systemctl stop zerowatch-agent`

---

## 🍎 macOS Setup & Execution


### 1. Make the Binary Executable
```bash
chmod +x SentinelAgent-macos-arm64
```

### 2. Launch the GUI and Enroll
Run the binary as the logged-in macOS user. This opens the ZeroWatch GUI:
```bash
./zerowatch-agent-macos
```
Complete enrollment in the GUI. The GUI then starts the detached background agent; closing the GUI or terminal does not stop it.

For LaunchDaemon installation and startup across reboots, run the daemon once with administrator privileges after enrollment:
```bash
sudo ./zerowatch-agent-macos --daemon
```
`tail -f agent_output.log`
