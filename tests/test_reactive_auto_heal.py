"""
tests/test_reactive_auto_heal.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive tests for Phase 3: Reactive Auto-Healing Loop in PinnedSession.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.cert.pinning import (
    PinnedSession,
    build_pinning_adapter,
    clear_dynamic_pins,
    reset_pin_mismatch,
    reset_emergency_ota_cooldown,
    set_pin_mismatch_detected,
    get_pin_mismatch_detected,
    PinError,
)


class TestReactiveAutoHeal(unittest.TestCase):
    """Tests the autonomous auto-healing and retry loop in PinnedSession."""

    def setUp(self):
        clear_dynamic_pins()
        reset_pin_mismatch()
        reset_emergency_ota_cooldown()
        self.prod_host = "zerowatch.deepcytes.io"
        self.active_leaf = "a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ="
        self.bogus_pin = "SOt+phzxLXUaMmNKG6d4kz7QTSoip7zJudN8vGJNdI4="

    def tearDown(self):
        clear_dynamic_pins()
        reset_pin_mismatch()
        reset_emergency_ota_cooldown()

    def test_autonomous_recovery_on_pin_error(self):
        """
        Tests that when a PinError occurs, PinnedSession intercepts it,
        triggers emergency OTA recovery, registers the refreshed pin,
        and seamlessly retries and returns the valid response.
        """
        sess = PinnedSession()
        sess.mount("https://", build_pinning_adapter([self.bogus_pin]))

        # Mock fetch_dynamic_pins to simulate receiving the valid leaf pin via OTA
        mock_ota_response = {self.prod_host: [self.active_leaf]}

        with patch("common.updater.fetch_dynamic_pins", return_value=mock_ota_response) as mock_fetch:
            resp = sess.get(f"https://{self.prod_host}", timeout=6)

            # 1. Assert mock was called during reactive recovery
            mock_fetch.assert_called_once()

            # 2. Assert connection completed with HTTP 200 without throwing PinError
            self.assertEqual(resp.status_code, 200)

            # 3. Assert pin mismatch latch was reset on successful recovery
            self.assertFalse(get_pin_mismatch_detected())

    def test_unrecoverable_pin_error_raises_and_latches(self):
        """
        Tests that if OTA recovery returns no valid pin for the host,
        PinError is raised and the mismatch cooldown is latched.
        """
        sess = PinnedSession()
        sess.mount("https://", build_pinning_adapter([self.bogus_pin]))

        # OTA returns empty or irrelevant domain
        with patch("common.updater.fetch_dynamic_pins", return_value={"other.domain.com": ["pin"]}) as mock_fetch:
            with self.assertRaises(PinError):
                sess.get(f"https://{self.prod_host}", timeout=6)

            mock_fetch.assert_called_once()
            self.assertTrue(get_pin_mismatch_detected())

    def test_emergency_recovery_throttling(self):
        """
        Tests that emergency OTA checks are throttled to at most once per 60 seconds
        to prevent hammering the CDN on repeated failures.
        """
        sess = PinnedSession()
        sess.mount("https://", build_pinning_adapter([self.bogus_pin]))

        with patch("common.updater.fetch_dynamic_pins", return_value={}) as mock_fetch:
            # First attempt: calls fetch_dynamic_pins
            with self.assertRaises(PinError):
                sess.get(f"https://{self.prod_host}", timeout=6)
            self.assertEqual(mock_fetch.call_count, 1)

            # Reset mismatch latch to simulate another attempt within cooldown window
            reset_pin_mismatch()

            # Second immediate attempt: throttled, should NOT call fetch_dynamic_pins again
            with self.assertRaises(PinError):
                sess.get(f"https://{self.prod_host}", timeout=6)
            self.assertEqual(mock_fetch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
