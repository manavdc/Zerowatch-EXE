"""
tests/test_linux_persistence.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive tests for LinuxPersistenceManager to verify headless daemon
persistence under systemd.
"""

import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from linux.persistence.startup_manager import (
    LinuxPersistenceManager,
    _SERVICE_NAME,
    _write_unit,
)


class TestLinuxPersistenceManager:
    """Test suite for Linux persistence manager and systemd unit generation."""

    def test_write_unit_always_includes_daemon_flag(self):
        """Verifies that generated systemd unit contains --daemon in ExecStart."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            unit_path = _write_unit(
                unit_dir=tmp_dir,
                exe_path="/usr/local/bin/SentinelAgent",
                daemon_args="--daemon",
                wanted_by="multi-user.target",
            )
            assert unit_path is not None
            assert os.path.isfile(unit_path)

            with open(unit_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "ExecStart=/usr/local/bin/SentinelAgent --daemon" in content
            assert "Restart=on-failure" in content
            assert "WantedBy=multi-user.target" in content

    def test_write_unit_quotes_executable_with_spaces(self):
        """Verifies that executables with spaces are quoted in ExecStart."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            unit_path = _write_unit(
                unit_dir=tmp_dir,
                exe_path="/opt/Zero Watch/SentinelAgent",
                daemon_args="--daemon",
                wanted_by="multi-user.target",
            )
            assert unit_path is not None

            with open(unit_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert 'ExecStart="/opt/Zero Watch/SentinelAgent" --daemon' in content

    def test_write_unit_handles_python_script_path(self):
        """Verifies that .py scripts invoke sys.executable for headless execution."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            unit_path = _write_unit(
                unit_dir=tmp_dir,
                exe_path="/home/user/agent/sentinel_agent.py",
                daemon_args="--daemon",
                wanted_by="multi-user.target",
            )
            assert unit_path is not None

            with open(unit_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert f"{sys.executable}" in content
            assert "/home/user/agent/sentinel_agent.py --daemon" in content

    def test_register_startup_defaults_none_args_to_daemon(self):
        """When daemon_args is None, --daemon must be present."""
        manager = LinuxPersistenceManager()
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("linux.persistence.startup_manager._SYSTEM_UNIT_DIR", tmp_dir), \
                 patch("linux.persistence.startup_manager._systemctl", return_value=True), \
                 patch("os.geteuid", return_value=0, create=True):

                ok = manager.register_startup("/usr/local/bin/SentinelAgent", daemon_args=None)
                assert ok is True

                unit_file = os.path.join(tmp_dir, _SERVICE_NAME)
                assert os.path.isfile(unit_file)
                with open(unit_file, "r", encoding="utf-8") as f:
                    content = f.read()

                assert "ExecStart=/usr/local/bin/SentinelAgent --daemon" in content

    def test_register_startup_empty_list_does_not_generate_empty_args(self):
        """When daemon_args is [], --daemon must still be added (never empty arguments)."""
        manager = LinuxPersistenceManager()
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("linux.persistence.startup_manager._SYSTEM_UNIT_DIR", tmp_dir), \
                 patch("linux.persistence.startup_manager._systemctl", return_value=True), \
                 patch("os.geteuid", return_value=0, create=True):

                ok = manager.register_startup("/usr/local/bin/SentinelAgent", daemon_args=[])
                assert ok is True

                unit_file = os.path.join(tmp_dir, _SERVICE_NAME)
                assert os.path.isfile(unit_file)
                with open(unit_file, "r", encoding="utf-8") as f:
                    content = f.read()

                assert "ExecStart=/usr/local/bin/SentinelAgent --daemon" in content

    def test_register_startup_empty_string_does_not_generate_empty_args(self):
        """When daemon_args is '', --daemon must still be added."""
        manager = LinuxPersistenceManager()
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("linux.persistence.startup_manager._SYSTEM_UNIT_DIR", tmp_dir), \
                 patch("linux.persistence.startup_manager._systemctl", return_value=True), \
                 patch("os.geteuid", return_value=0, create=True):

                ok = manager.register_startup("/usr/local/bin/SentinelAgent", daemon_args="")
                assert ok is True

                unit_file = os.path.join(tmp_dir, _SERVICE_NAME)
                assert os.path.isfile(unit_file)
                with open(unit_file, "r", encoding="utf-8") as f:
                    content = f.read()

                assert "ExecStart=/usr/local/bin/SentinelAgent --daemon" in content

    def test_register_startup_custom_args_preserves_and_ensures_daemon(self):
        """When daemon_args is ['--dev', '--no-hide'], --daemon is prepended."""
        manager = LinuxPersistenceManager()
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("linux.persistence.startup_manager._SYSTEM_UNIT_DIR", tmp_dir), \
                 patch("linux.persistence.startup_manager._systemctl", return_value=True), \
                 patch("os.geteuid", return_value=0, create=True):

                ok = manager.register_startup(
                    "/usr/local/bin/SentinelAgent",
                    daemon_args=["--dev", "--no-hide"]
                )
                assert ok is True

                unit_file = os.path.join(tmp_dir, _SERVICE_NAME)
                with open(unit_file, "r", encoding="utf-8") as f:
                    content = f.read()

                assert "ExecStart=/usr/local/bin/SentinelAgent --daemon --dev --no-hide" in content

    def test_register_startup_already_has_daemon_avoids_duplicate(self):
        """When daemon_args already includes --daemon, it should not duplicate --daemon."""
        manager = LinuxPersistenceManager()
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("linux.persistence.startup_manager._SYSTEM_UNIT_DIR", tmp_dir), \
                 patch("linux.persistence.startup_manager._systemctl", return_value=True), \
                 patch("os.geteuid", return_value=0, create=True):

                ok = manager.register_startup(
                    "/usr/local/bin/SentinelAgent",
                    daemon_args=["--daemon", "--hardened"]
                )
                assert ok is True

                unit_file = os.path.join(tmp_dir, _SERVICE_NAME)
                with open(unit_file, "r", encoding="utf-8") as f:
                    content = f.read()

                assert "ExecStart=/usr/local/bin/SentinelAgent --daemon --hardened" in content
                assert "--daemon --daemon" not in content

    def test_is_persistence_active_detects_missing_daemon_flag(self):
        """Legacy unit files without --daemon must be reported as inactive to trigger auto-healing."""
        manager = LinuxPersistenceManager()
        with tempfile.TemporaryDirectory() as tmp_dir:
            unit_file = os.path.join(tmp_dir, _SERVICE_NAME)
            # Write a legacy broken unit file without --daemon
            with open(unit_file, "w", encoding="utf-8") as f:
                f.write("[Service]\nExecStart=/usr/local/bin/SentinelAgent\n")

            with patch("linux.persistence.startup_manager._SYSTEM_UNIT_DIR", tmp_dir), \
                 patch("linux.persistence.startup_manager._USER_UNIT_DIR_TEMPLATE", "/nonexistent"):

                assert manager.is_persistence_active() is False

            # Add --daemon to unit file
            with open(unit_file, "w", encoding="utf-8") as f:
                f.write("[Service]\nExecStart=/usr/local/bin/SentinelAgent --daemon\n")

            with patch("linux.persistence.startup_manager._SYSTEM_UNIT_DIR", tmp_dir), \
                 patch("linux.persistence.startup_manager._USER_UNIT_DIR_TEMPLATE", "/nonexistent"):

                assert manager.is_persistence_active() is True
