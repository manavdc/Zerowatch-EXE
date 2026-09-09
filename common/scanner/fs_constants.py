"""
common/scanner/fs_constants.py
─────────────────────────────────────────────────────────────────────────────
Shared filesystem scanning constants used by both the Windows and Linux
filesystem walkers.
"""

from __future__ import annotations
from typing import FrozenSet, Tuple

# ── Manifest file names (cross-platform) ─────────────────────────────────────

MANIFEST_FILENAMES: FrozenSet[str] = frozenset({
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    ".yarn-integrity",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "requirements-test.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "packages.config",
    "project.json",
    "project.assets.json",
    "nuget.config",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "Podfile.lock",
    "Package.swift",
    "Package.resolved",
    "environment.yml",
    "environment.yaml",
    "conda-lock.yml",
    "apk.installed",
    "dpkg.installed",
})

# ── Conditional skip groups (cross-platform) ──────────────────────────────────
# If any of the trigger_manifests are in the current directory,
# skip the dep_dirs subdirectories during deep scan (they contain
# already-catalogued dependencies, not the project manifest itself).

_ConditionalSkipGroup = Tuple[FrozenSet[str], FrozenSet[str]]

CONDITIONAL_SKIP_GROUPS: Tuple[_ConditionalSkipGroup, ...] = (
    # NOTE: node_modules moved to unconditional SKIP_DIR_NAMES_COMMON.
    # Orphaned node_modules (no parent manifest) are a rare edge case,
    # and the time savings from unconditional skip are large on dev machines.
    (
        frozenset({
            "requirements.txt", "requirements-dev.txt",
            "requirements-prod.txt", "requirements-test.txt",
            "Pipfile", "Pipfile.lock",
            "pyproject.toml", "setup.py", "setup.cfg",
            "poetry.lock", "pdm.lock", "uv.lock",
        }),
        frozenset({"venv", ".venv", "env", ".env"}),
    ),
    (
        frozenset({
            "pom.xml", "build.gradle", "build.gradle.kts",
            "settings.gradle", "settings.gradle.kts",
        }),
        frozenset({"target", "out", "build", "dist"}),
    ),
    (
        frozenset({"composer.json", "composer.lock"}),
        frozenset({"vendor"}),
    ),
    (
        frozenset({"Cargo.toml", "Cargo.lock"}),
        frozenset({"target"}),
    ),
    (
        frozenset({"go.mod", "go.sum"}),
        frozenset({"vendor"}),
    ),
)

# ── Universal skip directory names (cross-platform) ──────────────────────────

SKIP_DIR_NAMES_COMMON: FrozenSet[str] = frozenset({
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".eggs",
    ".tox",
    ".yarn",
    ".gradle",
    ".cargo",
    ".rustup",
    "cmake-build-debug",
    "cmake-build-release",
    ".git", ".svn", ".hg", ".bzr",
    ".idea", ".vscode",
    ".sonarwork",
    "cache", "caches", ".cache",
    "tmp", "temp",
    "node_modules",
    "crashreports",
    "logs",
    "docker",
    ".docker",
})

# ── Size limits ───────────────────────────────────────────────────────────────

MAX_BINARY_SIZE_BYTES: int = 200 * 1024 * 1024   # 200 MiB
MAX_MANIFEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MiB
