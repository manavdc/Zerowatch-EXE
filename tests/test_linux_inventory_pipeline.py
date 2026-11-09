"""
tests/test_linux_inventory_pipeline.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive tests for Linux inventory scanning, chunking, and sync pipeline.
Verifies:
  1. Two-phase sync: immediate L0 baseline ('partial') followed by background
     L1+L2 startup scan ('complete').
  2. Single-request atomic delivery (no premature proactive chunking at 400 items).
  3. Proper HTTP 413 fallback chunking with scope preservation.
  4. Streamlined PRIORITY_DIRS excluding heavy system library directories.
"""

import sys
import threading
import time
from unittest.mock import MagicMock, patch, call
import pytest

from linux.scanner.fs_walker import PRIORITY_DIRS


class TestLinuxInventoryPipeline:
    """Test suite for Linux agent inventory collection and synchronization."""

    def test_priority_dirs_streamlined(self):
        """PRIORITY_DIRS must only contain binary execution roots, not 100k+ system libs."""
        assert "/usr/lib" not in PRIORITY_DIRS
        assert "/usr/lib64" not in PRIORITY_DIRS
        assert "/var/lib" not in PRIORITY_DIRS
        assert "/usr/bin" in PRIORITY_DIRS
        assert "/opt" in PRIORITY_DIRS

    @patch("sentinel_agent_linux.LinuxAgentSession")
    def test_sync_complete_inventory_single_request_for_large_payload(self, mock_session_cls):
        """Inventories >= 400 items must attempt a single sync_full request first (no proactive chunking)."""
        from sentinel_agent_linux import LinuxAgent

        agent = LinuxAgent.__new__(LinuxAgent)
        agent._device_id = "test-device-1"
        agent._sync_full = MagicMock(return_value=200)
        agent._sync_delta = MagicMock(return_value=True)

        items = [{"name": f"pkg_{i}", "version": "1.0"} for i in range(500)]
        res = agent._sync_complete_inventory(items, hardware={"cpu": "x86"}, inventory_scope="complete")

        assert res is True
        agent._sync_full.assert_called_once_with(items, {"cpu": "x86"}, inventory_scope="complete")
        agent._sync_delta.assert_not_called()

    @patch("sentinel_agent_linux.LinuxAgentSession")
    def test_sync_complete_inventory_falls_back_to_chunking_on_413(self, mock_session_cls):
        """HTTP 413 triggers bounded chunking and preserves inventory_scope."""
        from sentinel_agent_linux import LinuxAgent

        agent = LinuxAgent.__new__(LinuxAgent)
        agent._device_id = "test-device-2"
        # First call (full payload) returns 413, subsequent calls (chunk 1) return 200
        agent._sync_full = MagicMock(side_effect=[413, 200])
        agent._sync_delta = MagicMock(return_value=True)

        items = [{"name": f"pkg_{i}", "version": "1.0"} for i in range(450)]
        res = agent._sync_complete_inventory(items, hardware={}, inventory_scope="complete")

        assert res is True
        assert agent._sync_full.call_count == 2
        # Check that the first batch of chunks preserves inventory_scope="complete"
        assert agent._sync_full.call_args_list[1][1]["inventory_scope"] == "complete"
        assert agent._sync_delta.call_count >= 1

    @patch("sentinel_agent_linux.LinuxAgentSession")
    def test_initial_scan_and_sync_two_stage_ordering(self, mock_session_cls):
        """_initial_scan_and_sync must sync L0 'partial' immediately, then L1+L2 'complete' in background."""
        from sentinel_agent_linux import LinuxAgent

        agent = LinuxAgent.__new__(LinuxAgent)
        agent._device_id = "test-device-3"
        agent._shutdown_event = threading.Event()
        agent._initial_scan_done = threading.Event()

        # Mock platform collectors
        mock_l0_item = MagicMock()
        mock_l0_item.to_api_dict.return_value = {"name": "dpkg_app", "version": "1.0", "source": "dpkg"}
        mock_l0_item.dedup_key.return_value = "dpkg_app:1.0"

        agent._platform = MagicMock()
        agent._platform.software_collector.collect_software.return_value = [mock_l0_item]
        agent._platform.hardware_collector.get_detailed_hardware_profile.return_value = {"cores": 4}

        # Mock orchestrator
        agent._orchestrator = MagicMock()
        agent._orchestrator._snapshot_lock = threading.Lock()
        agent._orchestrator._last_snapshot = {}
        deep_items = [
            {"name": "dpkg_app", "version": "1.0", "source": "dpkg"},
            {"name": "custom_binary", "version": "2.0", "source": "elf"},
        ]
        agent._orchestrator.run_startup_scan.return_value = deep_items

        # Mock sync tracking
        sync_calls = []
        def track_sync(items, hw, inventory_scope="complete"):
            sync_calls.append((inventory_scope, len(items)))
            return True

        agent._sync_full_with_retry = MagicMock(side_effect=track_sync)
        agent._finish_approval_sync = MagicMock()
        agent._session = MagicMock()
        agent._session._jwt = "valid-token"

        # Execute
        agent._initial_scan_and_sync(approval_sync_claimed=True)

        # Stage 1 (L0 baseline) must be executed immediately
        assert len(sync_calls) >= 1
        assert sync_calls[0] == ("partial", 1)

        # Wait for Stage 2 background thread to complete
        finished = agent._initial_scan_done.wait(timeout=5.0)
        assert finished is True

        # Stage 2 must have synced complete inventory with 2 items
        assert len(sync_calls) == 2
        assert sync_calls[1] == ("complete", 2)
        agent._finish_approval_sync.assert_called_once_with(True)

    @patch("sentinel_agent_linux.LinuxAgentSession")
    def test_initial_scan_skipped_when_not_claimed(self, mock_session_cls):
        """When approval sync is not claimed (e.g. already complete or claimed by another worker),
        _initial_scan_and_sync must skip both Stage 1 and Stage 2 completely."""
        from sentinel_agent_linux import LinuxAgent

        agent = LinuxAgent.__new__(LinuxAgent)
        agent._device_id = "test-device-4"
        agent._shutdown_event = threading.Event()
        agent._sync_full_with_retry = MagicMock()
        agent._finish_approval_sync = MagicMock()

        agent._initial_scan_and_sync(approval_sync_claimed=False)

        assert agent._sync_full_with_retry.call_count == 0
        assert agent._finish_approval_sync.call_count == 0
        assert agent._initial_scan_done.is_set() is True

    def test_load_join_state_prefers_active_pending_state(self, tmp_path):
        """load_join_state must prioritize active 'pending'/'approved' state across dat/json files."""
        import json
        from sentinel_agent_linux import LinuxAgentSession

        state_dir = str(tmp_path)
        # Old json file with status "none"
        old_json = tmp_path / "join_state.json"
        old_json.write_text(json.dumps({"status": "none"}), encoding="utf-8")

        # Newer dat file with status "pending"
        new_dat = tmp_path / "zw_team_join_state.dat"
        new_dat.write_text(json.dumps({"status": "pending", "teamCode": "ABCDEF"}), encoding="utf-8")

        mock_plat = MagicMock()
        mock_plat.secure_store.decrypt.side_effect = lambda b: b
        session = LinuxAgentSession("http://127.0.0.1:8000", state_dir, mock_plat)

        loaded = session.load_join_state()
        assert loaded.get("status") == "pending"
        assert loaded.get("teamCode") == "ABCDEF"

    @patch("sentinel_agent_linux.LinuxAgentSession")
    def test_register_or_authenticate_polls_and_detects_approval(self, mock_session_cls):
        """_register_or_authenticate must poll join-status and return True upon approval."""
        from sentinel_agent_linux import LinuxAgent

        agent = LinuxAgent.__new__(LinuxAgent)
        agent._device_id = "test-device-5"
        agent._state_dir = "/tmp/test"
        agent._shutdown_event = threading.Event()
        agent._platform = MagicMock()
        agent._platform.hardware_collector.collect_fingerprint.return_value = {}

        mock_session = MagicMock()
        mock_session.load_jwt.side_effect = [False, False]  # no initial JWT
        mock_session.load_join_state.return_value = {"status": "pending", "teamCode": "ABC"}

        # Simulate join-status returning approved on poll
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "approved",
            "jwt": "approved-jwt-token-123",
            "teamCode": "ABC",
            "requestId": "req-999",
        }
        mock_session.get.return_value = mock_resp
        agent._session = mock_session

        res = agent._register_or_authenticate()

        assert res is True
        mock_session.save_jwt.assert_called_once_with("approved-jwt-token-123")
        mock_session.save_join_state.assert_called()

