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

### Background Daemon Mode
To start the agent in headless background mode and register it as an auto-starting service (via UAC Registry Run key or Task Scheduler):
```cmd
SentinelAgent.exe --daemon
```

### Setup Demo Video
Below is a demonstration of installing, configuring, and running the Windows endpoint agent:

https://github.com/user-attachments/assets/77a62549-01ed-4cab-a0dd-2f37109f0a86

---

## 🐧 Linux Setup & Execution

### 1. Set the Server Connection (Optional)
If connecting to a custom local or private ZeroWatch instance, export the environment variable (production releases default automatically to the cloud platform):
```bash
export ZEROWATCH_API_URL=http://<your-server-ip>:3001
```

### 2. Make the Binary Executable
```bash
chmod +x SentinelAgent-linux-x64
```

### 3. Run Once to Enroll & Register
Run the binary once as `sudo` to complete initial device enrollment and automatically install the systemd unit file:
```bash
sudo ./SentinelAgent-linux-x64
```
*Note: If run without `sudo` (standard user), it will write a user-scoped service unit under `~/.config/systemd/user/` instead.*

Look for the log output: `systemd startup registered: agent will start on boot.` 
Once you see this, you can terminate the interactive screen with `Ctrl+C`.

### 4. Start the Background Service
Kick off the background execution thread immediately (the terminal can now be safely closed):
```bash
sudo systemctl start zerowatch-agent
```
*(Or use `systemctl --user start zerowatch-agent` if registered as a standard user.)*

### Service Control Commands
* **Status**: `sudo systemctl status zerowatch-agent`
* **Live Logs**: `sudo journalctl -u zerowatch-agent -f`
* **Stop Daemon**: `sudo systemctl stop zerowatch-agent`

---

## 🍎 macOS Setup & Execution

### 1. Set the Server Connection (Optional)
Export the backend URL if running a custom local deployment:
```bash
export ZEROWATCH_API_URL=http://<your-server-ip>:3001
```

### 2. Make the Binary Executable
```bash
chmod +x SentinelAgent-macos-arm64
```

### 3. Run and Bootstrap LaunchDaemon
Run the agent once using `sudo` to register the launchd LaunchDaemon plist:
```bash
sudo ./SentinelAgent-macos-arm64
```
This automatically:
1. Validates macOS Full Disk Access (FDA) permissions.
2. Registers a LaunchDaemon plist under `/Library/LaunchDaemons/io.deepcytes.zerowatch.agent.plist`.
3. Bootstraps it immediately with `RunAtLoad` and `KeepAlive` parameters.

The agent is now detached and running. You can close your terminal window.

### Service Control Commands
* **Logs**: `tail -f /var/log/zerowatch-agent.log`
* **Stop**: `sudo launchctl bootout system /Library/LaunchDaemons/io.deepcytes.zerowatch.agent.plist`
* **Uninstall**:
  ```bash
  sudo launchctl bootout system /Library/LaunchDaemons/io.deepcytes.zerowatch.agent.plist
  sudo rm /Library/LaunchDaemons/io.deepcytes.zerowatch.agent.plist
  ```

---

## 🛠️ CLI Alternative: Process Detachment (Linux / macOS)

If you do not want to install native system startup utilities (systemd or launchd), you can run the binary directly and detach it from your shell session using `nohup`:

```bash
export ZEROWATCH_API_URL=http://<your-server-ip>:3001
nohup ./SentinelAgent-linux-x64 > agent_output.log 2>&1 &
```
* **Stop Process**: `pkill -f SentinelAgent-linux-x64`
* **Read Logs**: `tail -f agent_output.log`
