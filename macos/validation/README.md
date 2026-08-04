# ZeroWatch macOS One-Shot Validation Harness

This validation harness is designed for remote QA / native validation on macOS hardware when development is performed on Windows and access to real macOS devices is limited.

## Instructions for Friend / Tester

1. **Open Terminal** on your Mac.
2. Navigate to the `Endpoint-Agent` directory:
   ```bash
   cd Endpoint-Agent
   ```
3. Make the launcher script executable and run it with `sudo`:
   ```bash
   chmod +x validate_macos.sh
   sudo ./validate_macos.sh
   ```
4. Wait for the validation to finish (typically 1–3 minutes).
5. At completion, terminal will display:
   ```text
   ==========================================
   ZeroWatch macOS Validation Complete
   ==========================================
   Report Archive:
     /path/to/zerowatch_macos_validation_<timestamp>.zip

   Please send this file to Jatin:
     /path/to/zerowatch_macos_validation_<timestamp>.zip
   ```
6. Send the generated `.zip` file back to Jatin.

---

## What the Harness Does

- **Preflight**: Checks macOS version, architecture (Apple Silicon vs Intel), Python version, SIP status, Homebrew/MacPorts availability.
- **Software Inventory**: Tests `.app` bundle parsing, `pkgutil` receipts, Homebrew, MacPorts, and OS version detection.
- **Hardware Inventory**: Tests `sysctl` hardware collection, GPU profiling, anonymized device fingerprint generation.
- **Filesystem & Mach-O Detection**: Performs a bounded scan of macOS software directories to test Mach-O static header parsing.
- **Dependency Manifests**: Parses temporary test project manifests (`package.json`, `requirements.txt`).
- **Scan Cache**: Tests SQLite state cache cold storage, warm lookups, and mtime invalidation.
- **Keychain Storage (`Security.framework`)**: Tests native Keychain `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete` operations with arbitrary binary data in user, root, and LaunchDaemon execution contexts.
- **LaunchDaemon Lifecycle**: Temporarily installs a non-destructive test LaunchDaemon (`io.deepcytes.zerowatch.validation.plist`), verifies background execution and Keychain access under launchd, then cleanly uninstalls it.
- **Process Guard**: Tests POSIX signal handler installation (`SIGTERM`, `SIGINT`, `SIGHUP`) and graceful shutdown triggering.
- **Event Logger**: Tests structured security event logging and `syslog` / Unified Logging interaction.
- **Unit Test Suite**: Executes the complete `macos/tests/` unit suite natively.
- **Platform & Agent Integration**: Direct smoke-test of `MacOSPlatform` and `ScanOrchestrator` full scan pipeline.

---

## Safety & Cleanup Guarantee

- **Non-Destructive**: Does NOT alter system settings, disable SIP, modify user keychains, or touch user files.
- **Temporary Key Identifiers**: Keychain tests use isolated validation service identifiers (`io.deepcytes.zerowatch.validation`) and clean up all test entries.
- **Temporary LaunchDaemon**: Uses a dedicated test label (`io.deepcytes.zerowatch.validation`) and automatically uninstalls the daemon and plist file upon test completion.
- **Automatic Diagnostics**: All logs, stack traces, and test results are packaged into a single timestamped ZIP file. Sensitive device serials and UUIDs are anonymized before inclusion in the report.
