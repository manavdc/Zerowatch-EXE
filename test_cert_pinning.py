import unittest
from unittest.mock import MagicMock, patch
import base64
import datetime
import os
import json
import requests
import socket
from urllib3.exceptions import ProtocolError

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import cert_pinning
import sentinel_agent

def generate_self_signed_cert():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"test-server.local"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)

class TestCertPinning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_der = generate_self_signed_cert()
        cls.expected_spki = cert_pinning.get_spki_sha256(cls.cert_der)

    def test_spki_extraction_known_cert(self):
        # Verify that SPKI extraction is consistent and returns a base64 string
        spki = cert_pinning.get_spki_sha256(self.cert_der)
        self.assertEqual(spki, self.expected_spki)
        self.assertTrue(len(spki) > 0)
        # Verify it is valid base64
        base64.b64decode(spki)

    def test_pin_match_succeeds(self):
        # _verify_pin should run silently on match
        try:
            cert_pinning._verify_pin("test-server.local", self.cert_der, [self.expected_spki])
        except cert_pinning.PinError:
            self.fail("_verify_pin raised PinError unexpectedly on matching pin")

    def test_pin_mismatch_raises(self):
        # _verify_pin should raise PinError on mismatch
        wrong_pin = "WRONG_PIN_HASH_BASE64_VALUE="
        with self.assertRaises(cert_pinning.PinError):
            cert_pinning._verify_pin("test-server.local", self.cert_der, [wrong_pin])

    def test_loopback_bypass_localhost(self):
        self.assertTrue(cert_pinning.is_loopback("http://localhost:3001"))
        self.assertTrue(cert_pinning.is_loopback("https://127.0.0.1:3001"))
        self.assertTrue(cert_pinning.is_loopback("http://[::1]:3001"))
        self.assertFalse(cert_pinning.is_loopback("https://zerowatch.deepcytes.io"))

    def test_load_pins_prod(self):
        pins = sentinel_agent._load_pins_for_url("https://zerowatch.deepcytes.io/api")
        self.assertIn("PLACEHOLDER_PROD_PRIMARY_SPKI_HASH", pins)

    def test_load_pins_demo(self):
        pins = sentinel_agent._load_pins_for_url("https://zerowatch-testing.eastasia.cloudapp.azure.com/api")
        self.assertIn("PLACEHOLDER_DEMO_PRIMARY_SPKI_HASH", pins)

    def test_load_pins_localhost_empty(self):
        pins = sentinel_agent._load_pins_for_url("http://localhost:3001/api")
        self.assertEqual(pins, [])

    def test_load_pins_unknown_https_raises(self):
        with self.assertRaises(RuntimeError):
            sentinel_agent._load_pins_for_url("https://unknown-secure-endpoint.io/api")

    def test_load_pins_custom_config(self):
        # Test loading custom pins from agent_config.json
        config_data = {
            "api_base_url": "https://custom-staging.local/api",
            "custom_pins": [
                "dK85yRZtQWIab16/niIHoJelcw85aRSZHmkiMhgN3WY=",
                "EzSBE12fT2ZrphmumaBjrpdpXv9G71RhZQHMvuwszI4="
            ]
        }
        
        # Patch os.path.exists and open to simulate config file presence
        original_exists = os.path.exists
        def mock_exists(path):
            if str(path).endswith("agent_config.json"):
                return True
            return original_exists(path)

        import io
        original_open = open
        def mock_open_func(file, mode='r', *args, **kwargs):
            if str(file).endswith("agent_config.json"):
                return io.StringIO(json.dumps(config_data))
            return original_open(file, mode, *args, **kwargs)

        with patch("os.path.exists", mock_exists), \
             patch("builtins.open", mock_open_func):
            pins = sentinel_agent._load_pins_for_url("https://custom-staging.local/api")
            self.assertEqual(pins, [
                "dK85yRZtQWIab16/niIHoJelcw85aRSZHmkiMhgN3WY=",
                "EzSBE12fT2ZrphmumaBjrpdpXv9G71RhZQHMvuwszI4="
            ])

    def test_is_pin_failure_helper(self):
        # Simulate normal ConnectionError
        normal_err = requests.exceptions.ConnectionError("Network down")
        self.assertFalse(cert_pinning.is_pin_failure(normal_err))

        # Simulate PinError wrapped in urllib3 ProtocolError
        pin_err = cert_pinning.PinError("mismatch")
        protocol_err = ProtocolError("Connection aborted.", pin_err)
        wrapped_err = requests.exceptions.ConnectionError(protocol_err)
        self.assertTrue(cert_pinning.is_pin_failure(wrapped_err))

    def test_pinned_session_blocks_after_failure(self):
        # Set global flag
        cert_pinning.PIN_MISMATCH_DETECTED = True
        session = cert_pinning.PinnedSession()
        
        with self.assertRaises(cert_pinning.PinError) as context:
            session.get("https://google.com")
        self.assertIn("previous certificate pinning mismatch", str(context.exception))
        
        # Reset global flag
        cert_pinning.PIN_MISMATCH_DETECTED = False

    def test_socketio_http_session_setup(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        client = sentinel_agent.ZeroWatchClient(
            base_dir=base_dir,
            device_id="test_device",
            hostname="test_host"
        )
        self.assertIsInstance(client.session, cert_pinning.PinnedSession)
        self.assertEqual(client.sio.eio.http, client.session)

    def test_custom_pins_cannot_override_production_by_default(self):
        config_data = {
            "api_base_url": "https://zerowatch.deepcytes.io/api",
            "custom_pins": ["dK85yRZtQWIab16/niIHoJelcw85aRSZHmkiMhgN3WY="]
        }
        original_exists = os.path.exists
        def mock_exists(path):
            if str(path).endswith("agent_config.json"):
                return True
            return original_exists(path)

        import io
        original_open = open
        def mock_open_func(file, mode='r', *args, **kwargs):
            if str(file).endswith("agent_config.json"):
                return io.StringIO(json.dumps(config_data))
            return original_open(file, mode, *args, **kwargs)

        with patch("os.path.exists", mock_exists), \
             patch("builtins.open", mock_open_func), \
             patch("sys.argv", ["sentinel_agent.py"]): # No --dev flag
            pins = sentinel_agent._load_pins_for_url("https://zerowatch.deepcytes.io/api")
            self.assertEqual(pins, [
                "PLACEHOLDER_PROD_PRIMARY_SPKI_HASH",
                "PLACEHOLDER_PROD_BACKUP_SPKI_HASH"
            ])

    def test_custom_pins_can_override_production_in_dev_mode(self):
        config_data = {
            "api_base_url": "https://zerowatch.deepcytes.io/api",
            "custom_pins": ["dK85yRZtQWIab16/niIHoJelcw85aRSZHmkiMhgN3WY="]
        }
        original_exists = os.path.exists
        def mock_exists(path):
            if str(path).endswith("agent_config.json"):
                return True
            return original_exists(path)

        import io
        original_open = open
        def mock_open_func(file, mode='r', *args, **kwargs):
            if str(file).endswith("agent_config.json"):
                return io.StringIO(json.dumps(config_data))
            return original_open(file, mode, *args, **kwargs)

        with patch("os.path.exists", mock_exists), \
             patch("builtins.open", mock_open_func), \
             patch("sys.argv", ["sentinel_agent.py", "--dev"]):
            pins = sentinel_agent._load_pins_for_url("https://zerowatch.deepcytes.io/api")
            self.assertEqual(pins, ["dK85yRZtQWIab16/niIHoJelcw85aRSZHmkiMhgN3WY="])

if __name__ == "__main__":
    unittest.main()
