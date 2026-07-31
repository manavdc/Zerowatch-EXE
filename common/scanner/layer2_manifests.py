"""
common/scanner/layer2_manifests.py
─────────────────────────────────────────────────────────────────────────────
Layer 2: Dependency manifest parsers.
"""

from __future__ import annotations

import json
import logging
import os
import re
import zipfile
from typing import Dict, List, Optional, Tuple

from common.scanner.models import (
    SoftwareItem,
    SOURCE_NPM_MANIFEST, SOURCE_NPM_LOCKFILE,
    SOURCE_PIP_REQUIREMENTS, SOURCE_PIP_LOCKFILE,
    SOURCE_PYPROJECT, SOURCE_MAVEN, SOURCE_GRADLE,
    SOURCE_NUGET, SOURCE_GO_MOD, SOURCE_CARGO,
    SOURCE_GEM, SOURCE_COMPOSER, SOURCE_JAR,
)
from common.scanner.state_cache import ScanCache
from common.utils.time_ import utc_now_iso

logger = logging.getLogger("scanner.layer2")

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


# ── Shared utilities ──────────────────────────────────────────────────────────

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
    text = _read_text(filepath)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    items: List[SoftwareItem] = []

    if data.get("name") and data.get("version"):
        item = _make_item(
            data["name"], data.get("version", ""), "",
            SOURCE_NPM_MANIFEST, filepath,
        )
        if item:
            items.append(item)

    for dep, ver in (data.get("dependencies") or {}).items():
        item = _make_item(dep, str(ver), "", SOURCE_NPM_MANIFEST, filepath)
        if item:
            items.append(item)

    return items


def parse_npm_lockfile_v2(filepath: str) -> List[SoftwareItem]:
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

    packages = data.get("packages") or {}
    for pkg_key, pkg_data in packages.items():
        if not isinstance(pkg_data, dict):
            continue
        name = pkg_key.lstrip("node_modules/")
        if "/" in pkg_key and not pkg_key.startswith("node_modules/@"):
            parts = pkg_key.split("node_modules/")
            name = parts[-1] if parts else name
        version = pkg_data.get("version", "")
        if name and version:
            add(name, version)

    if not items:
        deps = data.get("dependencies") or {}
        for name, dep_data in deps.items():
            if isinstance(dep_data, dict):
                add(name, dep_data.get("version", ""))

    return items


def parse_yarn_lock(filepath: str) -> List[SoftwareItem]:
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
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    extras_re  = re.compile(r"\[.*?\]")
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
            item = _make_item(name, version if "==" in op or "~=" in op else "",
                              "", SOURCE_PIP_REQUIREMENTS, filepath)
            if item:
                items.append(item)
        elif re.match(r"^[A-Za-z0-9_.\-]+\s*$", line):
            item = _make_item(line.strip(), "", "", SOURCE_PIP_REQUIREMENTS, filepath)
            if item:
                items.append(item)

    return items


def parse_pipfile_lock(filepath: str) -> List[SoftwareItem]:
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
    text = _read_text(filepath)
    if not text:
        return []

    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore
        data = tomllib.loads(text)
        return _parse_pyproject_toml_data(data, filepath)
    except (ImportError, Exception):
        pass

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
    text = _read_text(filepath)
    if not text:
        return []

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
        if version.startswith("${"):
            version = ""
        name = f"{group_id}:{artifact_id}"
        item = _make_item(name, version, group_id, SOURCE_MAVEN, filepath)
        if item:
            items.append(item)
    return items


def parse_gradle_build(filepath: str) -> List[SoftwareItem]:
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
    text = _read_text(filepath)
    if not text:
        return []

    items: List[SoftwareItem] = []
    single_re = re.compile(r"^require\s+(\S+)\s+(v[\w.+-]+)", re.MULTILINE)
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

    if current_name and current_version:
        item = _make_item(current_name, current_version, "", SOURCE_CARGO, filepath)
        if item:
            items.append(item)

    return items


# ── Ruby ──────────────────────────────────────────────────────────────────────

def parse_gemfile_lock(filepath: str) -> List[SoftwareItem]:
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

FILENAME_PARSERS["pnpm-lock.yaml"] = parse_yarn_lock


def parse_manifest_file(
    filepath: str,
    cache: Optional[ScanCache] = None,
) -> List[SoftwareItem]:
    basename = os.path.basename(filepath)

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

    parser = FILENAME_PARSERS.get(basename)

    if parser is None:
        ext = os.path.splitext(basename)[1].lower()
        if ext in (".jar", ".war", ".ear", ".aar"):
            parser = parse_jar_manifest
        elif ext in (".csproj", ".vbproj", ".fsproj"):
            parser = parse_csproj
        elif ext in (".whl",):
            parser = parse_jar_manifest

    if parser is None:
        return []

    try:
        items = parser(filepath)
    except Exception as exc:
        logger.debug("Parse error %s: %s", filepath, exc)
        items = []

    if cache is not None:
        cache.store(filepath, mtime_ns, size_bytes, items, layer=2)

    return items
