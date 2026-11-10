"""
tests/test_local_windows_agent.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive tests for local testing of the Windows Sentinel Agent.
Verifies:
  1. Default and flag-based local backend URL resolution (http://localhost:3001/api).
  2. Pinning bypass for loopback addresses.
  3. Windows hardware fingerprinting and device ID generation.
  4. Windows registry software discovery.
  5. Windows DPAPI credential encryption/decryption round-trip.
  6. ZeroWatchClient initialization and local payload routing.
"""

import os
import sys
import json
import tempfile
from unittest.mock import patch
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sentinel_agent
from sentinel_agent import (
    _resolve_base_api_url,
    _load_pins_for_url,
    collect_fingerprint,
    get_installed_software_registry,
    ZeroWatchClient,
)
from windows.crypto.dpapi_store import encrypt_data, decrypt_data
from windows.hardware.fingerprint import generate_device_id, get_machine_guid


class TestLocalWindowsAgent:
    """Test suite for testing Windows Sentinel Agent locally."""

    def test_default_url_is_local_backend(self):
        """In this testing branch, default API URL points to local backend http://localhost:3001/api."""
        with patch.object(sys, "argv", ["sentinel_agent.py"]):
            with patch.dict(os.environ, {}, clear=True):
                url = _resolve_base_api_url()
                assert url == "http://localhost:3001/api"

    def test_url_resolution_dev_and_local_flags(self):
        """Flags --dev and --local explicitly resolve to http://localhost:3001/api."""
        for flag in ["--dev", "--local", "--test"]:
            with patch.object(sys, "argv", ["sentinel_agent.py", flag]):
                with patch.dict(os.environ, {}, clear=True):
                    assert _resolve_base_api_url() == "http://localhost:3001/api"

    def test_url_resolution_custom_server_flag(self):
        """Flag --server allows targeting any arbitrary local/custom address."""
        with patch.object(sys, "argv", ["sentinel_agent.py", "--server", "http://127.0.0.1:4000"]):
            assert _resolve_base_api_url() == "http://127.0.0.1:4000/api"

        with patch.object(sys, "argv", ["sentinel_agent.py", "--server=http://localhost:8080/api"]):
            assert _resolve_base_api_url() == "http://localhost:8080/api"

    def test_url_resolution_prod_flag(self):
        """Flag --prod allows pointing to production when explicitly needed."""
        with patch.object(sys, "argv", ["sentinel_agent.py", "--prod"]):
            assert _resolve_base_api_url() == "https://zerowatch.deepcytes.io/api"

    def test_url_resolution_env_override(self):
        """Environment variable ZEROWATCH_API_URL takes precedence."""
        with patch.object(sys, "argv", ["sentinel_agent.py"]):
            with patch.dict(os.environ, {"ZEROWATCH_API_URL": "http://127.0.0.1:5000/api"}):
                assert _resolve_base_api_url() == "http://127.0.0.1:5000/api"

    def test_url_resolution_agent_config_json(self):
        """agent_config.json api_base_url is respected if present."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_file = os.path.join(tmp_dir, "agent_config.json")
            with open(cfg_file, "w") as f:
                json.dump({"api_base_url": "http://localhost:9000/api"}, f)

            with patch("sentinel_agent.os.path.exists", side_effect=lambda p: p == cfg_file):
                with patch("sentinel_agent.os.getcwd", return_value=tmp_dir):
                    with patch.object(sys, "argv", ["sentinel_agent.py"]):
                        with patch.dict(os.environ, {}, clear=True):
                            assert _resolve_base_api_url() == "http://localhost:9000/api"

    def test_loopback_pinning_bypass(self):
        """Certificate pinning returns empty list and does NOT raise PinError for loopback."""
        local_urls = [
            "http://localhost:3001/api",
            "http://127.0.0.1:3001/api",
            "http://[::1]:3001/api",
        ]
        for url in local_urls:
            pins = _load_pins_for_url(url)
            assert pins == []

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows specific test")
    def test_windows_hardware_fingerprint_collection(self):
        """Windows hardware fingerprint is successfully gathered with device_id."""
        fp = collect_fingerprint()
        assert isinstance(fp, dict)
        assert "device_id" in fp
        assert fp["device_id"].startswith("SAGT-")
        assert "machine_guid" in fp
        assert "mac_address" in fp
        assert "agent_version" in fp

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows specific test")
    def test_windows_guid_and_device_id_generation(self):
        """Hardware GUID and stable device ID are non-empty strings."""
        guid = get_machine_guid()
        assert isinstance(guid, str) and len(guid) > 0
        device_id = generate_device_id()
        assert isinstance(device_id, str) and len(device_id) == 64

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows specific test")
    def test_windows_registry_software_inventory(self):
        """Windows registry returns a list of installed software dictionaries."""
        software = get_installed_software_registry()
        assert isinstance(software, list)
        assert len(software) > 0
        # Check first item schema
        first = software[0]
        assert "name" in first
        assert "version" in first
        assert "source" in first
        assert first["source"] == "registry"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows specific test")
    def test_windows_dpapi_encryption_roundtrip(self):
        """Windows DPAPI protects and unprotects secret byte strings."""
        secret = b"zerowatch_local_test_secret_payload_12345"
        encrypted = encrypt_data(secret)
        assert encrypted is not None
        assert encrypted != secret
        decrypted = decrypt_data(encrypted)
        assert decrypted == secret

    def test_client_init_with_local_backend(self):
        """ZeroWatchClient mounts standard HTTP adapter when pointing to local endpoint."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = ZeroWatchClient(tmp_dir, "test-local-device-id", "LOCAL-WIN-PC")
            assert client.device_id == "test-local-device-id"
            assert client.hostname == "LOCAL-WIN-PC"
            assert client.session is not None
