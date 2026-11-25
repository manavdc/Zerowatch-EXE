"""
tests/test_cert_pinning_hierarchical.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive unit and integration tests for Hierarchical Certificate Pinning
(Leaf, Intermediate CA, and Root CA validation).
"""

import sys
import os
import unittest
import socket
import ssl

# Add parent directory to path so common and sentinel_agent can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.cert.pinning import (
    PinError,
    get_spki_sha256,
    is_valid_sha256_base64,
    _verify_socket_pins,
    _verify_pin,
    _extract_spki_from_cert,
    _resolve_aia_issuers,
    PinnedSSLContext,
    build_pinning_adapter
)
from sentinel_agent import SPKI_PINS


class TestCertPinningHierarchical(unittest.TestCase):
    """Tests hierarchical pinning across Leaf, Intermediate, and Root CAs."""

    @classmethod
    def setUpClass(cls):
        cls.prod_host = "zerowatch.deepcytes.io"
        cls.prod_pins = SPKI_PINS.get(cls.prod_host, [])
        # Known fingerprints for zerowatch.deepcytes.io
        cls.active_leaf_pin = "a6WoJxzcp0Im4dXEiaHUcio3U8wbbRWdVyaWoqsIlGQ="
        cls.intermediate_we1_pin = "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4="
        cls.root_globalsign_pin = "K87oWBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q="
        cls.root_gts_r4_pin = "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c="
        cls.bogus_pin = "SOt+phzxLXUaMmNKG6d4kz7QTSoip7zJudN8vGJNdI4="

    def test_pin_format_validity(self):
        """Ensures all configured production pins are valid SHA-256 base64 digests."""
        self.assertGreater(len(self.prod_pins), 5)
        for pin in self.prod_pins:
            self.assertTrue(is_valid_sha256_base64(pin), f"Invalid pin: {pin}")

    def test_leaf_pin_only_connection(self):
        """Verifies successful connection when only the Leaf pin is configured."""
        ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT, [self.active_leaf_pin])
        ctx.load_default_certs()

        with socket.create_connection((self.prod_host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.prod_host) as ssock:
                self.assertIsNotNone(ssock.getpeercert(binary_form=True))

    def test_intermediate_ca_only_connection(self):
        """
        Simulates 90-day leaf certificate renewal:
        Connection MUST succeed if leaf changed but Intermediate CA pin matches.
        """
        ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT, [self.intermediate_we1_pin])
        ctx.load_default_certs()

        with socket.create_connection((self.prod_host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.prod_host) as ssock:
                self.assertIsNotNone(ssock.getpeercert(binary_form=True))

    def test_root_ca_only_connection(self):
        """
        Simulates renewal with new leaf AND new intermediate:
        Connection MUST succeed if Root CA pin matches.
        """
        ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT, [self.root_globalsign_pin])
        ctx.load_default_certs()

        with socket.create_connection((self.prod_host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.prod_host) as ssock:
                self.assertIsNotNone(ssock.getpeercert(binary_form=True))

    def test_all_configured_prod_pins_connection(self):
        """Verifies connection with the full production pin set."""
        ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT, self.prod_pins)
        ctx.load_default_certs()

        with socket.create_connection((self.prod_host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.prod_host) as ssock:
                self.assertIsNotNone(ssock.getpeercert(binary_form=True))

    def test_untrusted_bogus_pin_fails(self):
        """Verifies that an unlisted/bogus pin strictly raises PinError."""
        ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT, [self.bogus_pin])
        ctx.load_default_certs()

        with socket.create_connection((self.prod_host, 443), timeout=6) as sock:
            with self.assertRaises(PinError) as cm:
                ctx.wrap_socket(sock, server_hostname=self.prod_host)
            self.assertIn("Pin verification failed", str(cm.exception))

    def test_empty_or_whitespace_pins_fail(self):
        """Verifies that empty pin configuration safely rejects."""
        with self.assertRaises(PinError):
            _verify_pin(self.prod_host, b"", [])


if __name__ == "__main__":
    unittest.main()

