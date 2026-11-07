# ZeroWatch 3-Layer Scanning Engine

This directory contains the core multi-layer scanning engine and orchestration logic for the ZeroWatch endpoint sensor.

---

## Architecture Overview

The scanner coordinates software discovery across three complementary operational layers to build a unified, deduplicated software and vulnerability inventory:

```
┌───────────────────────────────────────────────────────────┐
│                    ScanOrchestrator                       │
├─────────────────────────────┬─────────────────────────────┤
│ Synchronous (Fast path)     │ Parallel (ThreadPoolExecutor)│
│ ┌─────────────────────────┐ │ ┌─────────────────────────┐ │
│ │ Layer 0: Registry / DB  │ │ │ Layer 1: PE/ELF/Mach-O  │ │
│ │ Authoritative OS data   │ │ │ Deep binary inspection  │ │
│ └─────────────────────────┘ │ └─────────────────────────┘ │
│                             │ ┌─────────────────────────┐ │
│                             │ │ Layer 2: Lockfiles      │ │
│                             │ │ Language ecosystems     │ │
│                             │ └─────────────────────────┘ │
└─────────────────────────────┴─────────────────────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
    Deduplication Engine            SQLite StateCache
  (L0 > L0_driver > L1 > L2)        (mtime & SHA-256)
```

---

## Layer Definitions

### Layer 0: Native OS Package Databases & Registry
- **Source**: Native operating system stores (Windows Registry `Uninstall` keys and drivers; Linux `dpkg`, `rpm`, `pacman`, `apk`, `flatpak`, `snap`; macOS `.app` bundles, `pkgutil`, Homebrew, MacPorts).
- **Execution**: Runs **synchronously** on the main scan thread.
- **Latency**: Very fast (< 500ms).
- **Authority**: Highest precedence. If an application is found in Layer 0, its version and vendor metadata supersede inferred data from file paths.

### Layer 1: Filesystem Walker & Static Binary Inspector
- **Source**: Traversal of executable and shared library directories (`Program Files`, `/usr/bin`, `/opt`, `/Applications`).
- **Inspection**: Static header inspection without execution:
  - **PE (Windows)**: Inspects `VS_FIXEDFILEINFO`, `StringFileInfo`, `CompanyName`, `FileDescription`, `FileVersion`.
  - **ELF (Linux)**: Reads ELF headers, `.comment`, `.note` sections, and version strings.
  - **Mach-O (macOS)**: Parses Mach-O load commands (`LC_LOAD_DYLIB`, `LC_BUILD_VERSION`, bundle identifiers).
- **Execution**: Runs in parallel via `ThreadPoolExecutor(max_workers=4)`.

### Layer 2: Ecosystem Manifests & Lockfiles
- **Source**: Traversal of developer workspaces and application folders for dependency lockfiles:
  - **Node.js**: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - **Python**: `requirements.txt`, `Pipfile.lock`, `poetry.lock`
  - **Rust**: `Cargo.lock`
  - **Go**: `go.mod`
  - **Java / JVM**: `pom.xml`, `build.gradle`
  - **PHP / Ruby**: `composer.lock`, `Gemfile.lock`
  - **C / C++**: `conan.lock`
- **Execution**: Runs in parallel alongside Layer 1.

---

## Deduplication & Priority Rules

Different layers frequently discover the same software component (e.g. OpenSSL in registry, `libssl.so` via binary inspection, and `openssl` in a lockfile).

Components are normalized into a deduplication key:
```python
dedup_key = f"{item.name.lower()}::{item.version.lower()}"
```

When duplicates exist across layers, metadata is merged according to priority:
$$\text{Layer 0 (Registry/Package DB)} > \text{Layer 0 (Driver)} > \text{Layer 1 (PE/ELF/Mach-O)} > \text{Layer 2 (Manifest)}$$

---

## Incremental State Cache (`ScanCache`)

[`state_cache.py`](file:///c:/Users/admin/Desktop/deepcytes/zerowatch-site/Zerowatch-EXE/scanner/state_cache.py) manages a local SQLite database (`state/scan_cache.db`).

- Records `(filepath, mtime, size, sha256, layer, item_json)`.
- During delta scans, files whose `mtime` and size have not changed are skipped without re-reading or re-parsing.
- Allows continuous delta monitoring in daemon mode with minimal CPU utilization (< 1%).

---

## Usage Example

```python
from scanner import ScanOrchestrator
from platforms import PlatformFactory

# 1. Instantiate the platform container
platform = PlatformFactory.create()

# 2. Initialize the orchestrator
orchestrator = ScanOrchestrator(
    base_dir="./",
    agent_version="2.0.0",
    software_collector=platform.software_collector,
    binary_inspector=platform.binary_inspector,
    filesystem_walker=platform.filesystem_walker,
)

# 3. Perform a full scan
inventory = orchestrator.run_full_scan()

# 4. Perform subsequent delta scans
added, removed = orchestrator.run_delta_scan()
```

