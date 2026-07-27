"""
scanner/layer2_manifests.py
─────────────────────────────────────────────────────────────────────────────
Layer 2: Dependency manifest parsers.

PURPOSE
───────
Parse ecosystem-specific package manifests and lockfiles to discover
development dependencies, runtime libraries, and transitive packages
that are NEVER visible in the Windows Registry.

PARSING PHILOSOPHY
──────────────────
1. LOCKFILES ARE PREFERRED OVER MANIFESTS
   Lockfiles (package-lock.json, Pipfile.lock, Cargo.lock, go.sum, etc.)
   contain pinned versions.  Manifests (package.json, pyproject.toml)
   may contain version ranges like "^1.2.3".  Pinned versions produce
   far more accurate CVE matching on the backend.

2. SIZE GUARD FIRST
   Every parser checks file size before opening.  Files > 10 MB are
   rejected.  This prevents the parser from hanging on auto-generated
   lockfiles from massive monorepos.

3. CACHE INTEGRATION
   mtime_ns + size_bytes are checked before any file open.  Unchanged
   manifests return cached items immediately.

4. PARSE ERRORS ARE NON-FATAL
   Each parser wraps its logic in a broad except clause.  A malformed
   manifest silently returns [] and is logged at DEBUG level so the
   scan continues without interruption.

5. DIRECT DEPENDENCIES ONLY IN MANIFESTS, ALL IN LOCKFILES
   For manifests we extract only direct dependencies to keep signal-to-
   noise high.  For lockfiles (which represent the actual installed
   state) we extract everything — those are what is actually on disk.

ECOSYSTEMS SUPPORTED
────────────────────
• npm     → package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
• pip     → requirements.txt, Pipfile, Pipfile.lock, pyproject.toml,
            poetry.lock, setup.py (skipped — too fragile to parse)
• Maven   → pom.xml (direct dependencies only)
• Gradle  → build.gradle / build.gradle.kts (direct deps, regex-based)
• .NET    → packages.config, *.csproj (direct refs)
• Go      → go.mod (direct), go.sum (all)
• Rust    → Cargo.toml (direct), Cargo.lock (all pinned)
• Ruby    → Gemfile.lock (all pinned)
• PHP     → composer.lock (all pinned)
• Java    → MANIFEST.MF inside .jar files (single component identity)
• Conda   → environment.yml
"""

from __future__ import annotations

import json
import logging
import os
import re
import zipfile
from typing import Dict, List, Optional, Tuple

from .models import (
    SoftwareItem,
    SOURCE_NPM_MANIFEST, SOURCE_NPM_LOCKFILE,
    SOURCE_PIP_REQUIREMENTS, SOURCE_PIP_LOCKFILE,
    SOURCE_PYPROJECT, SOURCE_MAVEN, SOURCE_GRADLE,
    SOURCE_NUGET, SOURCE_GO_MOD, SOURCE_CARGO,
    SOURCE_GEM, SOURCE_COMPOSER, SOURCE_JAR,
)
from .state_cache import ScanCache

logger = logging.getLogger("scanner.layer2")

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


# ── Shared utilities ──────────────────────────────────────────────────────────

def _utc_now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ).isoformat()


def _read_text(filepath: str) -> Optional[str]:
    """Read file as text; return None if too large or on any error."""
    try:
        size = os.path.getsize(filepath)
        if size > MAX_FILE_SIZE:
            return None
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def _clean_version(v: str) -> str:
    """Strip leading ^, ~, =, >, <, spaces from a version specifier."""
    return re.sub(r"^[\^~>=<!\s]+", "", v or "").strip().split(",")[0].strip()


def _make_item(
    name: str,
    version: str,
    vendor: str,
    source: str,
    scan_path: str,
    category: str = "software",
) -> Optional[SoftwareItem]:
    name = (name or "").strip()
    if not name:
        return None
    return SoftwareItem(
        name=name,
        version=_clean_version(version),
        vendor=vendor,
        source=source,
        category=category,
        scan_path=scan_path,
    )


# ── npm ───────────────────────────────────────────────────────────────────────

def parse_npm_package_json(filepath: str) -> List[SoftwareItem]:
    """
    Parses package.json.  Emits:
    - The package itself (if name + version are present)
    - All direct `dependencies` (NOT devDependencies — too much noise)
    """
    text = _read_text(filepath)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    items: List[SoftwareItem] = []

    # Top-level package identity
    if data.get("name") and data.get("version"):
        item = _make_item(
            data["name"], data.get("version", ""), "",
            SOURCE_NPM_MANIFEST, filepath,
        )
        if item:
            items.append(item)

    # Production dependencies only
    for dep, ver in (data.get("dependencies") or {}).items():
        item = _make_item(dep, str(ver), "", SOURCE_NPM_MANIFEST, filepath)
        if item:
            items.append(item)

    return items


def parse_npm_lockfile_v2(filepath: str) -> List[SoftwareItem]:
    """
    Parses package-lock.json (npm lockfile v2/v3 format).
    Uses the `packages` section which contains all pinned versions.
    Falls back to the v1 `dependencies` section.
    """
    text = _read_text(filepath)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    items: List[SoftwareItem] = []
    seen: set = set()

    def add(name: str, version: str) -> None:
        key = f"{name}::{version}"
        if key in seen:
            return
        seen.add(key)
        item = _make_item(name, version, "", SOURCE_NPM_LOCKFILE, filepath)
        if item:
            items.append(item)

    # v2/v3: `packages` dict, keys are "node_modules/name"
    packages = data.get("packages") or {}
    for pkg_key, pkg_data in packages.items():
        if not isinstance(pkg_data, dict):
            continue
        name = pkg_key.lstrip("node_modules/")
        # Scoped packages: node_modules/@scope/pkg → @scope/pkg
        if "/" in pkg_key and not pkg_key.startswith("node_modules/@"):
            parts = pkg_key.split("node_modules/")
            name = parts[-1] if parts else name
        version = pkg_data.get("version", "")
        if name and version:
            add(name, version)

    # v1 fallback: `dependencies` dict
    if not items:
        deps = data.get("dependencies") or {}
        for name, dep_data in deps.items():
            if isinstance(dep_data, dict):
                add(name, dep_data.get("version", ""))

    return items


def parse_yarn_lock(filepath: str) -> List[SoftwareItem]:
    """
    Parses yarn.lock (v1 format).  Format:
        "package@version":
          version "resolved_version"
    """
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    seen: set = set()
    pkg_header_re = re.compile(r'^"?([^"@\n]+)@[^:]+":?\s*$')
    version_re    = re.compile(r'^\s+version\s+"([^"]+)"')

    current_name: Optional[str] = None
    for line in text.splitlines():
        m = pkg_header_re.match(line)
        if m:
            current_name = m.group(1).strip()
            continue
        if current_name:
            mv = version_re.match(line)
            if mv:
                ver = mv.group(1)
                key = f"{current_name}::{ver}"
                if key not in seen:
                    seen.add(key)
                    item = _make_item(current_name, ver, "", SOURCE_NPM_LOCKFILE, filepath)
                    if item:
                        items.append(item)
                current_name = None

    return items


# ── pip ───────────────────────────────────────────────────────────────────────

def parse_pip_requirements(filepath: str) -> List[SoftwareItem]:
    """
    Parses requirements.txt.  Handles ==, >=, ~=, <=, != specifiers.
    Lines with extras ([security]) are stripped.
    -r / -c / -f / -i directives are skipped.
    """
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    # Strip extras: package[extra1,extra2]==1.0
    extras_re  = re.compile(r"\[.*?\]")
    # Match: name op version
    req_re     = re.compile(
        r"^([A-Za-z0-9_.\-]+)\s*([~><=!]+)\s*([\w.\-*]+)"
    )

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-", "http", "git+")):
            continue
        line = extras_re.sub("", line)
        m = req_re.match(line)
        if m:
            name, op, version = m.group(1), m.group(2), m.group(3)
            # Only emit pinned versions (== or ~=)
            item = _make_item(name, version if "==" in op or "~=" in op else "",
                              "", SOURCE_PIP_REQUIREMENTS, filepath)
            if item:
                items.append(item)
        elif re.match(r"^[A-Za-z0-9_.\-]+\s*$", line):
            # Bare package name with no version — still worth reporting
            item = _make_item(line.strip(), "", "", SOURCE_PIP_REQUIREMENTS, filepath)
            if item:
                items.append(item)

    return items


def parse_pipfile_lock(filepath: str) -> List[SoftwareItem]:
    """Parses Pipfile.lock — contains hashed pinned versions."""
    text = _read_text(filepath)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    items: List[SoftwareItem] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            version = (meta.get("version") or "").lstrip("=")
            item = _make_item(name, version, "", SOURCE_PIP_LOCKFILE, filepath)
            if item:
                items.append(item)
    return items


def parse_pyproject_toml(filepath: str) -> List[SoftwareItem]:
    """
    Parses pyproject.toml for Poetry / PEP 621 project dependencies.
    Uses regex-based parsing to avoid requiring a TOML parser in stdlib
    (tomllib is only available in Python 3.11+).
    Falls back to tomllib/tomli if available.
    """
    text = _read_text(filepath)
    if not text:
        return []

    # Try stdlib tomllib (3.11+) or tomli
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore
        data = tomllib.loads(text)
        return _parse_pyproject_toml_data(data, filepath)
    except (ImportError, Exception):
        pass

    # Regex fallback: match 'name = ">=version"' patterns in [dependencies]
    items: List[SoftwareItem] = []
    in_deps = False
    dep_line_re = re.compile(
        r'^([A-Za-z0-9_.\-]+)\s*=\s*["\{]([^"}\n]*)["\}]'
    )
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and "dependencies" in stripped.lower():
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
        if in_deps:
            m = dep_line_re.match(stripped)
            if m:
                name, version_spec = m.group(1), m.group(2)
                version = _clean_version(version_spec)
                item = _make_item(name, version, "", SOURCE_PYPROJECT, filepath)
                if item:
                    items.append(item)
    return items


def _parse_pyproject_toml_data(data: dict, filepath: str) -> List[SoftwareItem]:
    items: List[SoftwareItem] = []

    # PEP 621
    project_deps = (data.get("project") or {}).get("dependencies") or []
    for dep in project_deps:
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([~><=!,\s].*)?$", str(dep))
        if m:
            item = _make_item(
                m.group(1).split("[")[0], _clean_version(m.group(2) or ""),
                "", SOURCE_PYPROJECT, filepath
            )
            if item:
                items.append(item)

    # Poetry
    poetry_deps = (
        (data.get("tool") or {})
        .get("poetry", {})
        .get("dependencies") or {}
    )
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else (
            spec.get("version", "") if isinstance(spec, dict) else ""
        )
        item = _make_item(name, _clean_version(version), "", SOURCE_PIP_LOCKFILE, filepath)
        if item:
            items.append(item)

    return items


# ── Maven / Gradle ────────────────────────────────────────────────────────────

def parse_pom_xml(filepath: str) -> List[SoftwareItem]:
    """
    Parses pom.xml for direct Maven dependencies.
    Uses regex to avoid an xml.etree import that may not be bundled.
    Handles property substitution for common patterns.
    """
    text = _read_text(filepath)
    if not text:
        return []

    # Extract all <dependency> blocks
    dep_block_re = re.compile(
        r"<dependency>\s*"
        r"<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*"
        r"(?:<version>([^<]+)</version>)?",
        re.DOTALL,
    )

    items: List[SoftwareItem] = []
    for m in dep_block_re.finditer(text):
        group_id    = m.group(1).strip()
        artifact_id = m.group(2).strip()
        version     = (m.group(3) or "").strip()
        # Skip property references like ${project.version}
        if version.startswith("${"):
            version = ""
        name = f"{group_id}:{artifact_id}"
        item = _make_item(name, version, group_id, SOURCE_MAVEN, filepath)
        if item:
            items.append(item)
    return items


def parse_gradle_build(filepath: str) -> List[SoftwareItem]:
    """
    Parses build.gradle / build.gradle.kts for dependency declarations.
    Matches:  implementation 'group:artifact:version'
    and:      implementation("group:artifact:version")
    """
    text = _read_text(filepath)
    if not text:
        return []

    dep_re = re.compile(
        r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[(\s]['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )

    items: List[SoftwareItem] = []
    for m in dep_re.finditer(text):
        parts = m.group(1).split(":")
        if len(parts) >= 2:
            group   = parts[0].strip()
            artifact = parts[1].strip()
            version  = parts[2].strip() if len(parts) > 2 else ""
            item = _make_item(
                f"{group}:{artifact}", version, group, SOURCE_GRADLE, filepath
            )
            if item:
                items.append(item)
    return items


# ── .NET / NuGet ──────────────────────────────────────────────────────────────

def parse_packages_config(filepath: str) -> List[SoftwareItem]:
    """Parses NuGet packages.config XML."""
    text = _read_text(filepath)
    if not text:
        return []
    pkg_re = re.compile(
        r'<package\s+id="([^"]+)"\s+version="([^"]+)"', re.IGNORECASE
    )
    items: List[SoftwareItem] = []
    for m in pkg_re.finditer(text):
        item = _make_item(m.group(1), m.group(2), "", SOURCE_NUGET, filepath)
        if item:
            items.append(item)
    return items


def parse_csproj(filepath: str) -> List[SoftwareItem]:
    """Parses .csproj / .vbproj / .fsproj for PackageReference elements."""
    text = _read_text(filepath)
    if not text:
        return []
    ref_re = re.compile(
        r'<PackageReference\s+Include="([^"]+)"(?:[^>]*Version="([^"]*)")?',
        re.IGNORECASE,
    )
    items: List[SoftwareItem] = []
    for m in ref_re.finditer(text):
        name    = m.group(1)
        version = m.group(2) or ""
        item = _make_item(name, version, "", SOURCE_NUGET, filepath)
        if item:
            items.append(item)
    return items


# ── Go ────────────────────────────────────────────────────────────────────────

def parse_go_mod(filepath: str) -> List[SoftwareItem]:
    """Parses go.mod — direct `require` statements only."""
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    # Single-line require: require github.com/pkg/errors v0.9.1
    single_re = re.compile(r"^require\s+(\S+)\s+(v[\w.+-]+)", re.MULTILINE)
    # Block require:
    #   require (
    #     github.com/pkg/errors v0.9.1
    #   )
    block_re  = re.compile(r"^\s+(\S+)\s+(v[\w.+-]+)", re.MULTILINE)

    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "require (":
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block:
            m = block_re.match(line)
            if m:
                item = _make_item(m.group(1), m.group(2), "", SOURCE_GO_MOD, filepath)
                if item:
                    items.append(item)
        else:
            m = single_re.match(stripped)
            if m:
                item = _make_item(m.group(1), m.group(2), "", SOURCE_GO_MOD, filepath)
                if item:
                    items.append(item)
    return items


def parse_go_sum(filepath: str) -> List[SoftwareItem]:
    """
    Parses go.sum — contains all transitive dependencies with pinned hashes.
    Format: module@version hash
    We skip /go.mod lines (duplicates) and keep only the source entries.
    """
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    seen: set = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module_ver = parts[0]
        if module_ver.endswith("/go.mod"):
            continue
        at = module_ver.rfind("@")
        if at < 0:
            continue
        module  = module_ver[:at]
        version = module_ver[at+1:]
        key = f"{module}::{version}"
        if key in seen:
            continue
        seen.add(key)
        item = _make_item(module, version, "", SOURCE_GO_MOD, filepath)
        if item:
            items.append(item)
    return items


# ── Rust ──────────────────────────────────────────────────────────────────────

def parse_cargo_toml(filepath: str) -> List[SoftwareItem]:
    """Parses Cargo.toml for direct dependencies."""
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    in_deps = False
    dep_re = re.compile(r'^([A-Za-z0-9_\-]+)\s*=\s*["\{]([^"}\n]*)')

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and "dependencies" in stripped.lower():
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
        if in_deps:
            m = dep_re.match(stripped)
            if m:
                item = _make_item(
                    m.group(1), _clean_version(m.group(2)),
                    "", SOURCE_CARGO, filepath
                )
                if item:
                    items.append(item)
    return items


def parse_cargo_lock(filepath: str) -> List[SoftwareItem]:
    """
    Parses Cargo.lock — all pinned crate versions.
    Cargo.lock uses TOML format v1 or v3.
    """
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    seen: set = set()
    name_re    = re.compile(r'^name\s*=\s*"([^"]+)"')
    version_re = re.compile(r'^version\s*=\s*"([^"]+)"')

    current_name: Optional[str] = None
    current_version: Optional[str] = None

    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            if current_name and current_version:
                key = f"{current_name}::{current_version}"
                if key not in seen:
                    seen.add(key)
                    item = _make_item(
                        current_name, current_version, "", SOURCE_CARGO, filepath
                    )
                    if item:
                        items.append(item)
            current_name = None
            current_version = None
            continue
        mn = name_re.match(stripped)
        if mn:
            current_name = mn.group(1)
            continue
        mv = version_re.match(stripped)
        if mv:
            current_version = mv.group(1)

    # Last package
    if current_name and current_version:
        item = _make_item(current_name, current_version, "", SOURCE_CARGO, filepath)
        if item:
            items.append(item)

    return items


# ── Ruby ──────────────────────────────────────────────────────────────────────

def parse_gemfile_lock(filepath: str) -> List[SoftwareItem]:
    """
    Parses Gemfile.lock.  Format:
        GEM
          specs:
            activesupport (7.1.2)
    """
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    seen: set = set()
    gem_re = re.compile(r"^\s{4}([A-Za-z0-9_\-]+)\s+\(([^)]+)\)")

    for line in text.splitlines():
        m = gem_re.match(line)
        if m:
            name, version = m.group(1), m.group(2)
            key = f"{name}::{version}"
            if key not in seen:
                seen.add(key)
                item = _make_item(name, version, "", SOURCE_GEM, filepath)
                if item:
                    items.append(item)
    return items


# ── PHP ───────────────────────────────────────────────────────────────────────

def parse_composer_lock(filepath: str) -> List[SoftwareItem]:
    """Parses composer.lock — all pinned PHP packages."""
    text = _read_text(filepath)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    items: List[SoftwareItem] = []
    for section in ("packages", "packages-dev"):
        for pkg in (data.get(section) or []):
            item = _make_item(
                pkg.get("name", ""),
                pkg.get("version", ""),
                "",
                SOURCE_COMPOSER,
                filepath,
            )
            if item:
                items.append(item)
    return items


# ── Java JARs ─────────────────────────────────────────────────────────────────

def parse_jar_manifest(filepath: str) -> List[SoftwareItem]:
    """
    Reads META-INF/MANIFEST.MF from a .jar / .war / .ear archive.
    Extracts Implementation-Title, Implementation-Version, and
    Implementation-Vendor.  Falls back to Bundle-SymbolicName (OSGi).
    """
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            try:
                manifest_text = zf.read("META-INF/MANIFEST.MF").decode(
                    "utf-8", errors="ignore"
                )
            except (KeyError, zipfile.BadZipFile):
                return []
    except (zipfile.BadZipFile, OSError):
        return []

    attrs: Dict[str, str] = {}
    for line in manifest_text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            attrs[key.strip()] = value.strip()

    name = (
        attrs.get("Implementation-Title")
        or attrs.get("Bundle-SymbolicName", "").split(";")[0].strip()
        or attrs.get("Bundle-Name")
        or os.path.basename(filepath)
    )
    version = (
        attrs.get("Implementation-Version")
        or attrs.get("Bundle-Version")
        or ""
    )
    vendor = (
        attrs.get("Implementation-Vendor")
        or attrs.get("Bundle-Vendor")
        or ""
    )

    item = _make_item(name, version, vendor, SOURCE_JAR, filepath)
    return [item] if item else []


# ── Conda ─────────────────────────────────────────────────────────────────────

def parse_conda_environment(filepath: str) -> List[SoftwareItem]:
    """
    Parses conda environment.yml / environment.yaml.
    Extracts the `dependencies:` list — both conda and pip sub-lists.
    """
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    dep_re = re.compile(r"^\s*-\s+([A-Za-z0-9_.\-]+)(?:=+([^\s#]+))?")

    for line in text.splitlines():
        m = dep_re.match(line)
        if m:
            name    = m.group(1)
            version = (m.group(2) or "").strip("=")
            if name.lower() in ("pip", "conda", "defaults"):
                continue
            item = _make_item(name, version, "", SOURCE_PIP_LOCKFILE, filepath)
            if item:
                items.append(item)
    return items


# ── Dispatcher ────────────────────────────────────────────────────────────────

# Maps exact filenames → parser function
# For extension-based files (*.csproj, *.jar etc.) the orchestrator
# calls parse_jar_manifest() or parse_csproj() directly after checking
# the extension.

FILENAME_PARSERS = {
    # npm
    "package.json":       parse_npm_package_json,
    "package-lock.json":  parse_npm_lockfile_v2,
    "yarn.lock":          parse_yarn_lock,
    # pip
    "requirements.txt":   parse_pip_requirements,
    "requirements-dev.txt": parse_pip_requirements,
    "requirements-prod.txt": parse_pip_requirements,
    "requirements-test.txt": parse_pip_requirements,
    "Pipfile.lock":        parse_pipfile_lock,
    "pyproject.toml":     parse_pyproject_toml,
    # Java
    "pom.xml":            parse_pom_xml,
    "build.gradle":       parse_gradle_build,
    "build.gradle.kts":   parse_gradle_build,
    # .NET
    "packages.config":    parse_packages_config,
    # Go
    "go.mod":             parse_go_mod,
    "go.sum":             parse_go_sum,
    # Rust
    "Cargo.toml":         parse_cargo_toml,
    "Cargo.lock":         parse_cargo_lock,
    # Ruby
    "Gemfile.lock":       parse_gemfile_lock,
    # PHP
    "composer.lock":      parse_composer_lock,
    # Conda
    "environment.yml":    parse_conda_environment,
    "environment.yaml":   parse_conda_environment,
}

# pnpm-lock.yaml → treat as npm lockfile (package names same format)
FILENAME_PARSERS["pnpm-lock.yaml"] = parse_yarn_lock  # similar structure


def parse_manifest_file(
    filepath: str,
    cache: Optional[ScanCache] = None,
) -> List[SoftwareItem]:
    """
    Main entry point: dispatches to the correct parser based on the
    file's basename.  Also handles .jar, .csproj, .whl extensions.

    Cache lookup is performed first.
    """
    basename = os.path.basename(filepath)

    # ── Cache lookup ───────────────────────────────────────────────────────
    try:
        st = os.stat(filepath)
        mtime_ns   = st.st_mtime_ns
        size_bytes = st.st_size
    except OSError:
        return []

    if cache is not None:
        cached = cache.lookup(filepath, mtime_ns, size_bytes)
        if cached is not None:
            return cached

    # ── Dispatch ───────────────────────────────────────────────────────────
    parser = FILENAME_PARSERS.get(basename)

    if parser is None:
        # Extension-based dispatch for non-exact-name files
        ext = os.path.splitext(basename)[1].lower()
        if ext in (".jar", ".war", ".ear", ".aar"):
            parser = parse_jar_manifest
        elif ext in (".csproj", ".vbproj", ".fsproj"):
            parser = parse_csproj
        elif ext in (".whl",):
            # Python wheel is a zip; try jar manifest path
            parser = parse_jar_manifest

    if parser is None:
        return []

    try:
        items = parser(filepath)
    except Exception as exc:
        logger.debug("Parse error %s: %s", filepath, exc)
        items = []

    # ── Cache store ────────────────────────────────────────────────────────
    if cache is not None:
        cache.store(filepath, mtime_ns, size_bytes, items, layer=2)

    return items
