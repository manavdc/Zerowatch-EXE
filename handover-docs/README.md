# SentinelAgent (Zerowatch-EXE) Master Handover Documentation

Welcome to the engineer handover documentation suite for **SentinelAgent (`Zerowatch-EXE` / `Endpoint-Agent`)**.

This folder contains comprehensive architectural overviews, cross-platform specifications, operational runbooks, and strategic decision records for engineering successors.

---

## 🧭 Documentation Index

### 1. Platform Implementation Guides
- **[Windows Sentinel Agent](platforms/windows-agent.md)**: Architecture, Tkinter Command Center, headless daemon mode, DPAPI key storage, Layer 0 Registry + Layer 1 Authenticode scanning, persistence, watchdog self-defense, and DEV-OTA auto-updates.
- **[Linux Sentinel Agent](platforms/linux-agent.md)**: Architecture, systemd service units, multi-distro package managers (`dpkg`, `rpm`, `pacman`, `apk`), `inotify` dynamic file monitoring, Secret Service encryption, and Linux capabilities.
- **[macOS Agent Status & Security Blockers](decisions/01-macos-agent-status-and-security-blockers.md)**: Exhaustive analysis of why macOS agent distribution is currently on hold (Gatekeeper code signing, Apple Notary Service, Apple Developer Program requirements, TCC permissions, SIP, LaunchDaemons), what works today, and the exact step-by-step resumption roadmap once Apple Developer credentials are provided.

---

### 2. Core Protocol & Security Specifications
- **[Certificate Pinning & Dual-Pin Rotation](01-certificate-pinning.md)**: Client-side SPKI SHA-256 certificate pinning with dual-pin failover and Ed25519-signed OTA updates.
- **[SBOM Generation & Syft/Grype Pipeline](03-sbom-generation-analysis.md)**: Local software bill-of-materials generation and vulnerability scoring.
- **[Endpoint Desktop Agent & DEV-OTA Specification](07-endpoint-desktop-agent.md)**: Fleet enrollment, delta sync payloads, and signed background auto-updater protocol.
- **[Headless Silent Enrollment Spec](HEADLESS_ENROLLMENT_SPEC.md)**: Enterprise silent enrollment protocol via command-line flags and pre-shared provisioning tokens.
- **[OTA Update Industry Standards](OTA_UPDATE_INDUSTRY_STANDARD.md)**: Dual-key Ed25519 signature verification, rollback prevention, and CDN failover handling.
- **[Agent Architecture & Reference Guide](AGENT_DOCUMENTATION.md)**: In-depth reference for all classes, methods, and thread loops in `sentinel_agent.py`.
- **[ZeroWatch Backend Performance Audit](ZEROWATCH_BACKEND_PERFORMANCE_AUDIT.md)**: Fleet scale testing, delta compression, and backend load profiling.
