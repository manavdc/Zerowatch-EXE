"""
scanner/layer2_manifests.py (Forwarding adapter to common.scanner.layer2_manifests)
─────────────────────────────────────────────────────────────────────────────
Preserves backward compatibility for legacy imports while using the portable
common.scanner.layer2_manifests package.
"""

from common.scanner.layer2_manifests import (
    FILENAME_PARSERS,
    parse_manifest_file,
    parse_npm_package_json,
    parse_npm_lockfile_v2,
    parse_yarn_lock,
    parse_pip_requirements,
    parse_pipfile_lock,
    parse_pyproject_toml,
    parse_pom_xml,
    parse_gradle_build,
    parse_packages_config,
    parse_csproj,
    parse_go_mod,
    parse_go_sum,
    parse_cargo_toml,
    parse_cargo_lock,
    parse_gemfile_lock,
    parse_composer_lock,
    parse_jar_manifest,
    parse_conda_environment,
)

__all__ = [
    "FILENAME_PARSERS",
    "parse_manifest_file",
    "parse_npm_package_json",
    "parse_npm_lockfile_v2",
    "parse_yarn_lock",
    "parse_pip_requirements",
    "parse_pipfile_lock",
    "parse_pyproject_toml",
    "parse_pom_xml",
    "parse_gradle_build",
    "parse_packages_config",
    "parse_csproj",
    "parse_go_mod",
    "parse_go_sum",
    "parse_cargo_toml",
    "parse_cargo_lock",
    "parse_gemfile_lock",
    "parse_composer_lock",
    "parse_jar_manifest",
    "parse_conda_environment",
]
