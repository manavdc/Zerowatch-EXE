"""
tests/test_cert_pinning_ota.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive unit tests for Phase 2:
Ed25519-Signed Dynamic Pin Manifest Engine & OTA Fallback.
"""

import sys
import os
import json
import base64
import socket
import ssl
import unittest
import tempfile
import shutil
from datetime import datetime, timezone, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common.updater import (
    verify_and_extract_pins,
    save_dynamic_pins,
    load_cached_dynamic_pins,
    normalize_ed25519_signature,
    ManifestVerificationError,
    TimestampExpiredError,
    OTAError,
)
from common.cert.pinning import (
    register_dynamic_pins,
    get_dynamic_pins_for_host,
    clear_dynamic_pins,
    PinnedSSLContext,
    PinError,
)


class TestCertPinningOTA(unittest.TestCase):
    """Tests Ed25519-signed dynamic pin manifest parsing, verification, and caching."""

    def setUp(self):
        # Generate a fresh ephemeral Ed25519 keypair for test signing
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.pub_key_b64 = base64.b64encode(self.pub_key.public_bytes_raw()).decode("ascii")

        # Temp directory for testing persistent caching
        self.test_dir = tempfile.mkdtemp(prefix="zw_ota_test_")
        clear_dynamic_pins()

    def tearDown(self):
        clear_dynamic_pins()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_signed_manifest(self, payload: dict, mutate_sig: bool = False, mutate_bytes: bool = False):
        manifest_bytes = json.dumps(payload, indent=2).encode("utf-8")
        sig = self.priv_key.sign(manifest_bytes)
        if mutate_sig:
            sig = bytes([b ^ 0xFF for b in sig])
        if mutate_bytes:
            manifest_bytes = manifest_bytes + b" "
        return manifest_bytes, sig

    def test_valid_manifest_pin_extraction(self):
        """Verifies that a validly signed manifest extracts all valid SPKI pins."""
        payload = {
            "version": "1.0.8",
            "released_at": datetime.now(timezone.utc).isoformat(),
            "spki_pins": {
                "zerowatch.deepcytes.io": [
                    "a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ=",
                    "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4="
                ],
                "custom.server.com": [
                    "K87oWBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q="
                ]
            }
        }
        manifest_bytes, sig = self._create_signed_manifest(payload)

        extracted = verify_and_extract_pins(
            manifest_bytes,
            sig,
            public_key_b64=self.pub_key_b64,
            enforce_timestamp=True,
        )

        self.assertIn("zerowatch.deepcytes.io", extracted)
        self.assertEqual(len(extracted["zerowatch.deepcytes.io"]), 2)
        self.assertIn("custom.server.com", extracted)
        self.assertEqual(len(extracted["custom.server.com"]), 1)

    def test_tampered_manifest_rejected(self):
        """Verifies that an adversary modifying 1 byte in the manifest causes ManifestVerificationError."""
        payload = {
            "version": "1.0.8",
            "released_at": datetime.now(timezone.utc).isoformat(),
            "spki_pins": {
                "zerowatch.deepcytes.io": ["a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ="]
            }
        }
        manifest_bytes, sig = self._create_signed_manifest(payload, mutate_bytes=True)

        with self.assertRaises(ManifestVerificationError):
            verify_and_extract_pins(
                manifest_bytes,
                sig,
                public_key_b64=self.pub_key_b64,
                enforce_timestamp=True,
            )

    def test_tampered_signature_rejected(self):
        """Verifies that an invalid signature causes ManifestVerificationError."""
        payload = {
            "version": "1.0.8",
            "released_at": datetime.now(timezone.utc).isoformat(),
            "spki_pins": {
                "zerowatch.deepcytes.io": ["a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ="]
            }
        }
        manifest_bytes, sig = self._create_signed_manifest(payload, mutate_sig=True)

        with self.assertRaises(ManifestVerificationError):
            verify_and_extract_pins(
                manifest_bytes,
                sig,
                public_key_b64=self.pub_key_b64,
                enforce_timestamp=True,
            )

    def test_stale_manifest_timestamp_rejected(self):
        """Verifies that a manifest older than 3 days is rejected (freeze attack guard)."""
        four_days_ago = datetime.now(timezone.utc) - timedelta(days=4)
        payload = {
            "version": "1.0.8",
            "released_at": four_days_ago.isoformat(),
            "spki_pins": {
                "zerowatch.deepcytes.io": ["a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ="]
            }
        }
        manifest_bytes, sig = self._create_signed_manifest(payload)

        with self.assertRaises(TimestampExpiredError):
            verify_and_extract_pins(
                manifest_bytes,
                sig,
                public_key_b64=self.pub_key_b64,
                enforce_timestamp=True,
            )

    def test_atomic_persistence_and_cache_loading(self):
        """Verifies saving dynamic pins to disk and reloading them across sessions."""
        test_pins = {
            "zerowatch.deepcytes.io": [
                "a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ=",
                "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4="
            ]
        }

        # 1. Save dynamic pins to test directory
        success = save_dynamic_pins(test_pins, target_dir=self.test_dir)
        self.assertTrue(success)

        # 2. Check memory registration
        in_memory = get_dynamic_pins_for_host("zerowatch.deepcytes.io")
        self.assertEqual(len(in_memory), 2)

        # 3. Clear memory and reload from disk
        clear_dynamic_pins()
        self.assertEqual(len(get_dynamic_pins_for_host("zerowatch.deepcytes.io")), 0)

        reloaded = load_cached_dynamic_pins(target_dir=self.test_dir)
        self.assertIn("zerowatch.deepcytes.io", reloaded)
        self.assertEqual(len(reloaded["zerowatch.deepcytes.io"]), 2)

    def test_dynamic_pin_enables_connection_recovery(self):
        """
        End-to-End Dynamic Pin Recovery Test:
        Initial state: Connection configured with NO valid pins (would fail).
        Dynamic update: Verified Ed25519 pin is ingested.
        Final state: Connection immediately succeeds via dynamic pin!
        """
        prod_host = "zerowatch.deepcytes.io"
        active_leaf = "a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ="
        bogus_pin = "SOt+phzxLXUaMmNKG6d4kz7QTSoip7zJudN8vGJNdI4="

        # Initially, with only bogus pin, connection must fail
        ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT, [bogus_pin])
        ctx.load_default_certs()

        with socket.create_connection((prod_host, 443), timeout=6) as sock:
            with self.assertRaises(PinError):
                ctx.wrap_socket(sock, server_hostname=prod_host)

        # Now simulate OTA receiving the valid pin
        register_dynamic_pins({prod_host: [active_leaf]})

        # Now, connecting with the same context immediately succeeds because dynamic pins are evaluated!
        with socket.create_connection((prod_host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=prod_host) as ssock:
                self.assertIsNotNone(ssock.getpeercert(binary_form=True))


if __name__ == "__main__":
    unittest.main()
