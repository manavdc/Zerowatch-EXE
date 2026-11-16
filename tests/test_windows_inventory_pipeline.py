"""
tests/test_windows_inventory_pipeline.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive tests for Windows agent inventory collection and synchronization.
Verifies:
  1. Single-request atomic delivery for complete inventories.
  2. Bounded fallback chunking on HTTP 413 with batch_index/batch_count headers.
  3. Preservation of inventory_scope="complete" across all chunked requests.
"""

from unittest.mock import MagicMock, patch
import pytest

from sentinel_agent import ZeroWatchClient


class TestWindowsInventoryPipeline:
    """Test suite for Windows agent inventory synchronization."""

    def test_sync_complete_inventory_single_request_success(self):
        """Standard complete inventories are delivered atomically via sync_full in a single request."""
        client = ZeroWatchClient.__new__(ZeroWatchClient)
        client.jwt = "test-token"
        client.device_id = "test-win-dev-1"
        client.sync_full = MagicMock(return_value=True)
        client.sync_delta = MagicMock(return_value=True)

        items = [{"name": f"win_app_{i}", "version": "1.0"} for i in range(350)]
        res = client.sync_complete_inventory(items, hardware_info={"os": "Windows 11"})

        assert res is True
        client.sync_full.assert_called_once_with(items, {"os": "Windows 11"}, inventory_scope="complete")
        client.sync_delta.assert_not_called()

    def test_sync_complete_inventory_chunking_on_413(self):
        """HTTP 413 triggers fallback chunking with batch_index, batch_count, and scope='complete'."""
        client = ZeroWatchClient.__new__(ZeroWatchClient)
        client.jwt = "test-token"
        client.device_id = "test-win-dev-2"
        client.last_server_status = 413

        # First call (atomic single request) fails with 413; chunk 1 call succeeds
        client.sync_full = MagicMock(side_effect=[False, True])
        client.sync_delta = MagicMock(return_value=True)

        # Create enough items to generate multiple chunks (> 512KB)
        large_desc = "x" * 2000
        items = [{"name": f"win_app_{i}", "version": "1.0", "description": large_desc} for i in range(300)]

        res = client.sync_complete_inventory(items, hardware_info={"os": "Windows 11"})

        assert res is True
        assert client.sync_full.call_count == 2
        # Verify chunk 1 was sent with inventory_scope="complete" and batch_index=1
        first_chunk_call = client.sync_full.call_args_list[1]
        assert first_chunk_call[1]["inventory_scope"] == "complete"
        assert first_chunk_call[1]["batch_index"] == 1
        assert first_chunk_call[1]["batch_count"] > 1

        # Verify subsequent chunks sent via sync_delta had scope="complete" and incrementing batch_index
        assert client.sync_delta.call_count >= 1
        delta_call = client.sync_delta.call_args_list[0]
        assert delta_call[1]["inventory_scope"] == "complete"
        assert delta_call[1]["batch_index"] == 2

    def test_sync_full_payload_structure(self):
        """sync_full builds request payload containing batch_index, batch_count, and inventoryScope."""
        client = ZeroWatchClient.__new__(ZeroWatchClient)
        client.jwt = "test-token"
        client.device_id = "test-win-dev-3"
        client.operator_username = "admin"
        client.license_active = True
        client.session = MagicMock()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True}
        client.session.post.return_value = mock_resp
        client._auth_headers = MagicMock(return_value={"Authorization": "Bearer test-token"})
        client._parse_server_payload = MagicMock(return_value={"success": True})
        client._handle_unlinked_response = MagicMock(return_value=False)
        client._is_acknowledged_response = MagicMock(return_value=True)

        items = [{"name": "app1", "version": "1.0"}]
        ok = client.sync_full(items, hardware_info={"cpu": "Intel"}, inventory_scope="complete", batch_index=2, batch_count=5)

        assert ok is True
        call_json = client.session.post.call_args[1]["json"]
        assert call_json["inventoryScope"] == "complete"
        assert call_json["batch_index"] == 2
        assert call_json["batch_count"] == 5
        assert len(call_json["software"]) == 1

    def test_sync_delta_payload_structure(self):
        """sync_delta builds request payload containing batch_index, batch_count, and inventoryScope."""
        client = ZeroWatchClient.__new__(ZeroWatchClient)
        client.jwt = "test-token"
        client.device_id = "test-win-dev-4"
        client.operator_username = "admin"
        client.license_active = True
        client.session = MagicMock()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True}
        client.session.post.return_value = mock_resp
        client._auth_headers = MagicMock(return_value={"Authorization": "Bearer test-token"})
        client._parse_server_payload = MagicMock(return_value={"success": True})
        client._handle_unlinked_response = MagicMock(return_value=False)
        client._is_acknowledged_response = MagicMock(return_value=True)

        added = [{"name": "new_app", "version": "2.0"}]
        ok = client.sync_delta(added, [], inventory_scope="complete", batch_index=3, batch_count=5)

        assert ok is True
        call_json = client.session.post.call_args[1]["json"]
        assert call_json["inventoryScope"] == "complete"
        assert call_json["batch_index"] == 3
        assert call_json["batch_count"] == 5
        assert len(call_json["added"]) == 1

    def test_orchestrator_deduplicates_sub_binaries(self):
        """Orchestrator must not create duplicate software items from sub-binaries in registered app paths."""
        from scanner.orchestrator import ScanOrchestrator
        from common.scanner.models import SoftwareItem

        reg_chrome = SoftwareItem(
            name="Google Chrome",
            version="157.0.8103.51",
            vendor="Google LLC",
            source="registry",
            install_location=r"C:\Program Files\Google\Chrome\Application"
        )
        pe_chrome_helper = SoftwareItem(
            name="Google Chrome",
            version="153.0.8002.0",
            vendor="Google LLC",
            source="pe_binary",
            scan_path=r"C:\Program Files\Google\Chrome\Application\PlatformExperienceHelper\platform_experience_helper.exe"
        )

        deduped = ScanOrchestrator._deduplicate([reg_chrome, pe_chrome_helper])
        assert len(deduped) == 1
        assert deduped[0].version == "157.0.8103.51"
        assert deduped[0].source == "registry"

    def test_fs_walker_skips_ide_internal_extensions(self):
        """fs_walker must skip internal IDE language grammar directories."""
        from windows.scanner.fs_walker import _should_skip_dir
        import os

        class MockDirEntry:
            def __init__(self, name):
                self.name = name

        # Path inside IDE resources/app/extensions
        entry = MockDirEntry("python")
        path = r"c:\users\admin\appdata\local\programs\antigravity ide\resources\app\extensions\python"
        assert _should_skip_dir(entry, path) is True

        # Normal project directory
        entry_proj = MockDirEntry("myproject")
        path_proj = r"c:\projects\myproject"
        assert _should_skip_dir(entry_proj, path_proj) is False


