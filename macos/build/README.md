# ZeroWatch macOS Agent — Build & Signing Architecture (Phase 6A Research)

This document outlines the build, packaging, code signing, notarization, and runtime security model required for the native macOS ZeroWatch Endpoint Agent.

---

## 1. Compiler & Standalone Executable Strategy (Nuitka)

### Build Script (`macos/build/build_agent.sh`)
The macOS agent is compiled using the unified build script `macos/build/build_agent.sh` which mirrors the Linux (`linux/build/build_agent.sh`) and Windows (`build_agent.bat`) build pipelines.

#### Usage:
```bash
chmod +x macos/build/build_agent.sh
./macos/build/build_agent.sh [--prod | --demo | --dev | --server URL]
```

### Features included in `build_agent.sh`:
- **Server Selection**: Command-line flags (`--prod`, `--demo`, `--dev`, `--server URL`) or interactive terminal prompt.
- **Tkinter GUI Support**: Invokes Nuitka with `--enable-plugin=tk-inter` to ensure the Tkinter GUI consent interface displays properly.
- **Certificate Pinning Validation**: Runs `verify_pins.py` prior to compilation.
- **Cross-Platform Modules**: Includes all required modules (`common`, `linux`, `macos`, `windows`, `platforms`, `scanner`, `cert_pinning`).
- **Data Resources**: Bundles icon and data resources (`--include-data-dir=resources=resources`).
- **Output Binary**: Outputted to `dist/macos/zerowatch-agent-macos`.

### Universal Binary Targets (Optional Multi-Arch)
- **`arm64` (Apple Silicon — M1/M2/M3/M4)**: Primary target architecture for modern macOS devices.
- **`x86_64` (Intel Mac)**: Secondary target for legacy Intel hardware.
- **Universal 2 Binary**: Combine `arm64` + `x86_64` binaries into a single universal binary using Apple's `lipo` tool:
  ```bash
  lipo -create -output dist/macos/zerowatch-agent dist/macos/zerowatch-agent-arm64 dist/macos/zerowatch-agent-x86_64
  ```

---

## 2. Code Signing, Developer ID & Entitlements

macOS Gatekeeper blocks un-signed binaries or binaries signed with ad-hoc certificates.

### Prerequisites
1. **Apple Developer Program Account** ($99/year).
2. **Developer ID Application Certificate**: Used for signing binaries distributed outside the Mac App Store.

### Entitlements (`entitlements.plist`)
For hardened runtime compatibility and low-level system access:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
```

### Signing Command (`codesign`)
```bash
codesign --force --options runtime --deep \
    --sign "Developer ID Application: Your Organization Name (TEAMID)" \
    --entitlements entitlements.plist \
    dist/macos/zerowatch-agent
```

---

## 3. Notarization & Gatekeeper Compliance

Apple requires all macOS software distributed outside the Mac App Store to be notarized by Apple's Notary Service.

### Step 1: Zip the Signed Binary / Package
```bash
ditto -c -k --keepParent dist/macos/zerowatch-agent dist/macos/zerowatch-agent.zip
```

### Step 2: Submit for Notarization (`xcrun notarytool`)
```bash
xcrun notarytool submit dist/macos/zerowatch-agent.zip \
    --apple-id "developer@organization.com" \
    --team-id "TEAMID" \
    --password "app-specific-password" \
    --wait
```

### Step 3: Staple the Ticket
```bash
xcrun stapler staple dist/macos/zerowatch-agent
```

### Step 4: Verify Gatekeeper Approval (`spctl`)
```bash
spctl --assess --type execute -v dist/macos/zerowatch-agent
```

---

## 4. System Integrity Protection (SIP) & Privacy / TCC Considerations

### System Integrity Protection (SIP)
- SIP restricts modification to root-owned system directories (`/System`, `/usr`, `/bin`, `/sbin`).
- **Scan Access**: SIP does NOT prevent read-only filesystem traversal by root, but standard POSIX read permissions still apply.

### Transparency, Consent, and Control (TCC / Privacy Settings)
- Accessing user data directories (`~/Documents`, `~/Desktop`, `~/Downloads`) or Full Disk Access requires explicit system privacy permissions.
- ZeroWatch agent deployed as a background daemon via `launchd` (`/Library/LaunchDaemons`) running as `root` can be granted **Full Disk Access** (FDA) in macOS System Settings → Privacy & Security → Full Disk Access.

---

## 5. Phase 6B Implementation Roadmap
- Test and validate Nuitka build pipeline on native macOS hardware (M-series & Intel).
- Implement Keychain integration for secret storage.
- Implement native launchd plist generator for boot persistence.
- Implement Mach-O binary inspector & `pkgutil` software collector.
