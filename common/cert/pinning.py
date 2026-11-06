"""
common/cert/pinning.py
─────────────────────────────────────────────────────────────────────────────
Platform-independent Subject Public Key Info (SPKI) Certificate Pinning module.
Supports full certificate chain pinning (Leaf, Issuing Intermediate CAs, and
Root CAs) with non-latching resilient backoff recovery.
"""

from __future__ import annotations

import ssl
import time
import base64
import logging
from urllib.parse import urlparse
import urllib.request
import urllib3
from urllib3.exceptions import ProtocolError
import requests
from requests.adapters import HTTPAdapter
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

logger = logging.getLogger("ZeroWatch.CertPinning")


class PinError(requests.exceptions.SSLError):
    """Raised when certificate pin verification fails."""
    pass


def get_spki_sha256(der_cert: bytes) -> str:
    """Extracts the SPKI block from a DER certificate and returns its SHA-256 hash in base64."""
    cert = x509.load_der_x509_certificate(der_cert)
    public_key = cert.public_key()
    spki_bytes = public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    sha256_hash = hashes.Hash(hashes.SHA256())
    sha256_hash.update(spki_bytes)
    digest = sha256_hash.finalize()
    return base64.b64encode(digest).decode('ascii')


def is_loopback(url: str) -> bool:
    """Checks if the URL points to a loopback/localhost address."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname = hostname.lower()
        return hostname in ("localhost", "127.0.0.1", "::1")
    except Exception:
        return False


def is_pin_failure(exc: Exception) -> bool:
    """Detects if a requests ConnectionError was caused by a PinError."""
    if not isinstance(exc, requests.exceptions.ConnectionError):
        return False
    if not exc.args:
        return False
    underlying = exc.args[0]
    args = getattr(underlying, 'args', None)
    if args and len(args) > 1:
        err = args[1]
        if isinstance(err, PinError) or (hasattr(err, '__class__') and err.__class__.__name__ == 'PinError'):
            return True
    return False


def is_valid_sha256_base64(pin: str) -> bool:
    """Validates that a pin is a SHA-256 base64-encoded string."""
    if not isinstance(pin, str) or len(pin) != 44 or not pin.endswith('='):
        return False
    try:
        return len(base64.b64decode(pin)) == 32
    except Exception:
        return False


# In-memory cache for AIA-fetched intermediate certificates to avoid repeated network roundtrips
_CA_ISSUER_CACHE: dict[str, bytes] = {}


def _verify_pin(hostname: str, der_cert: bytes, allowed_pins: list[str]):
    """
    Verifies that the SPKI hash of the certificate matches one of the allowed pins.
    Preserved for backwards compatibility with single-cert callers.
    """
    valid_pins = [p for p in allowed_pins if is_valid_sha256_base64(p)]
    if not valid_pins:
        raise PinError(f"No valid SPKI pins configured for validation against {hostname}")

    if not der_cert:
        raise PinError("No certificate presented by peer")

    spki_hash = get_spki_sha256(der_cert)

    if spki_hash in valid_pins:
        logger.debug("SPKI pin verified successfully against leaf certificate.")
        return

    # Leaf did not match directly; check if AIA intermediate matches an allowed pin
    try:
        leaf_cert = x509.load_der_x509_certificate(der_cert)
        try:
            aia = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ca_issuers = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
        except Exception:
            ca_issuers = []

        for issuer_url in ca_issuers:
            try:
                if issuer_url not in _CA_ISSUER_CACHE:
                    req = urllib.request.Request(issuer_url, headers={"User-Agent": "ZeroWatch-Pinning/1.0"})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        _CA_ISSUER_CACHE[issuer_url] = resp.read()

                issuer_der = _CA_ISSUER_CACHE.get(issuer_url)
                if issuer_der:
                    issuer_cert = x509.load_der_x509_certificate(issuer_der)
                    leaf_cert.verify_directly_issued_by(issuer_cert)
                    issuer_spki = get_spki_sha256(issuer_der)
                    if issuer_spki in valid_pins:
                        logger.info(f"SPKI pin verified successfully via issuing intermediate ({issuer_url}).")
                        return
            except Exception as _aia_err:
                logger.debug(f"AIA issuer validation check failed for {issuer_url}: {_aia_err}")
    except Exception:
        pass

    try:
        cert = x509.load_der_x509_certificate(der_cert)
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = "Unknown"

    msg = (
        f"Pin verification failed for {hostname}! "
        f"Server presented SPKI hash {spki_hash}, which is not in the allowed list. "
        f"Presented Certificate Issuer: {issuer}."
    )
    if any(term in issuer.lower() for term in ["proxy", "zscaler", "fortinet", "bluecoat", "kaspersky", "firewall", "inspection", "security"]):
        msg += " (Possible enterprise TLS decryption/inspection proxy detected)"

    logger.critical(msg)
    raise PinError(msg)


def _verify_socket_pins(hostname: str, wrapped_sock, allowed_pins: list[str]):
    """
    Verifies that at least one certificate in the TLS peer chain (leaf, intermediate, or root)
    matches one of the allowed SPKI pins.
    """
    valid_pins = [p for p in allowed_pins if is_valid_sha256_base64(p)]
    if not valid_pins:
        raise PinError(f"No valid SPKI pins configured for validation against {hostname}")

    presented_spkis: list[str] = []
    leaf_cert = None

    # 1. Extract leaf certificate DER
    try:
        leaf_der = wrapped_sock.getpeercert(binary_form=True)
        if leaf_der:
            leaf_cert = x509.load_der_x509_certificate(leaf_der)
            leaf_spki = get_spki_sha256(leaf_der)
            presented_spkis.append(leaf_spki)
            if leaf_spki in valid_pins:
                logger.debug(f"SPKI pin verified successfully (leaf match: {leaf_spki}).")
                return
    except Exception as e:
        logger.debug(f"Failed extracting leaf cert SPKI: {e}")

    # 2. Extract full verified/unverified certificate chain from SSLSocket
    sslobj = getattr(wrapped_sock, '_sslobj', None)
    if sslobj is not None:
        for getter_name in ('get_verified_chain', 'get_unverified_chain'):
            getter = getattr(sslobj, getter_name, None)
            if callable(getter):
                try:
                    chain = getter() or []
                    for depth, cert_obj in enumerate(chain):
                        pem = cert_obj.public_bytes()
                        pem_bytes = pem.encode('ascii') if isinstance(pem, str) else pem
                        chain_cert = x509.load_pem_x509_certificate(pem_bytes)
                        chain_spki_bytes = chain_cert.public_key().public_bytes(
                            encoding=Encoding.DER,
                            format=PublicFormat.SubjectPublicKeyInfo
                        )
                        h = hashes.Hash(hashes.SHA256())
                        h.update(chain_spki_bytes)
                        chain_spki = base64.b64encode(h.finalize()).decode('ascii')
                        if chain_spki not in presented_spkis:
                            presented_spkis.append(chain_spki)
                        if chain_spki in valid_pins:
                            logger.info(f"SPKI pin verified successfully (matched at chain depth {depth}: {chain_spki}).")
                            return
                except Exception as _chain_err:
                    logger.debug(f"{getter_name} extraction error: {_chain_err}")

    # 3. Fallback: check leaf AIA issuer
    if leaf_cert is not None:
        try:
            aia = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ca_issuers = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
            for issuer_url in ca_issuers:
                try:
                    if issuer_url not in _CA_ISSUER_CACHE:
                        req = urllib.request.Request(issuer_url, headers={"User-Agent": "ZeroWatch-Pinning/1.0"})
                        with urllib.request.urlopen(req, timeout=3) as resp:
                            _CA_ISSUER_CACHE[issuer_url] = resp.read()

                    issuer_der = _CA_ISSUER_CACHE.get(issuer_url)
                    if issuer_der:
                        issuer_cert = x509.load_der_x509_certificate(issuer_der)
                        leaf_cert.verify_directly_issued_by(issuer_cert)
                        issuer_spki = get_spki_sha256(issuer_der)
                        if issuer_spki not in presented_spkis:
                            presented_spkis.append(issuer_spki)
                        if issuer_spki in valid_pins:
                            logger.info(f"SPKI pin verified successfully via AIA intermediate ({issuer_url}: {issuer_spki}).")
                            return
                except Exception as _aia_err:
                    logger.debug(f"AIA issuer validation error for {issuer_url}: {_aia_err}")
        except Exception:
            pass

    # If no certificate in the chain matched allowed pins, fail
    issuer_desc = "Unknown"
    if leaf_cert:
        try:
            issuer_desc = leaf_cert.issuer.rfc4514_string()
        except Exception:
            pass

    msg = (
        f"Pin verification failed for {hostname}! "
        f"Presented SPKI chain {presented_spkis} contains no keys in the allowed list. "
        f"Presented Certificate Issuer: {issuer_desc}."
    )
    if any(term in issuer_desc.lower() for term in ["proxy", "zscaler", "fortinet", "bluecoat", "kaspersky", "firewall", "inspection", "security"]):
        msg += " (Possible enterprise TLS decryption/inspection proxy detected)"

    logger.critical(msg)
    raise PinError(msg)


class PinnedSSLContext(ssl.SSLContext):
    def __init__(self, protocol, pins, hostname_target=None):
        self.pins = pins
        self.hostname_target = hostname_target

    def wrap_socket(self, sock, *args, **kwargs):
        wrapped = super().wrap_socket(sock, *args, **kwargs)

        if not self.pins:
            return wrapped

        hostname = kwargs.get('server_hostname') or self.hostname_target or ""
        try:
            _verify_socket_pins(hostname, wrapped, self.pins)
        except PinError:
            try:
                wrapped.close()
            except Exception:
                pass
            raise
        except Exception as e:
            try:
                wrapped.close()
            except Exception:
                pass
            logger.error(f"Error during certificate pin verification: {e}")
            raise PinError(f"Pin verification error: {e}")

        return wrapped


class SPKIPinningAdapter(HTTPAdapter):
    def __init__(self, pins, **kwargs):
        self.pins = pins
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **pool_kwargs):
        ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT, self.pins)
        ctx.load_default_certs()
        pool_kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **pool_kwargs)

    def proxy_manager_for(self, *args, **pool_kwargs):
        ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT, self.pins)
        ctx.load_default_certs()
        pool_kwargs['ssl_context'] = ctx
        return super().proxy_manager_for(*args, **pool_kwargs)


def build_pinning_adapter(pins: list[str]) -> SPKIPinningAdapter:
    return SPKIPinningAdapter(pins)


# ─────────────────────────────────────────────────────────────────────────────
# Resilient Non-Latching Pin Mismatch State & Backoff Management
# ─────────────────────────────────────────────────────────────────────────────
PIN_MISMATCH_DETECTED = False
_LAST_PIN_FAILURE_TIME = 0.0
_PIN_MISMATCH_BACKOFF_SECONDS = 30.0  # Cooldown before automatically attempting fresh connection


def get_pin_mismatch_detected() -> bool:
    """
    Returns True if a pin mismatch was detected AND the backoff cooldown is active.
    If the cooldown window has elapsed, the latch automatically resets to False
    to allow recovery attempts.
    """
    global PIN_MISMATCH_DETECTED, _LAST_PIN_FAILURE_TIME
    try:
        import cert_pinning
        if hasattr(cert_pinning, "_LAST_PIN_FAILURE_TIME"):
            _LAST_PIN_FAILURE_TIME = cert_pinning._LAST_PIN_FAILURE_TIME
    except Exception:
        pass

    if not PIN_MISMATCH_DETECTED:
        return False

    elapsed = time.time() - _LAST_PIN_FAILURE_TIME
    if elapsed >= _PIN_MISMATCH_BACKOFF_SECONDS:
        logger.info(f"[PINNING] Pin mismatch backoff cooldown expired ({elapsed:.1f}s elapsed). Resetting latch for retry.")
        reset_pin_mismatch()
        return False

    return True


def get_pin_mismatch_remaining_cooldown() -> float:
    """Returns remaining seconds in current cooldown window, or 0.0 if not throttled."""
    if not PIN_MISMATCH_DETECTED:
        return 0.0
    remaining = _PIN_MISMATCH_BACKOFF_SECONDS - (time.time() - _LAST_PIN_FAILURE_TIME)
    return max(0.0, remaining)


def set_pin_mismatch_detected(value: bool):
    """Sets pin mismatch state with timestamped backoff tracking."""
    global PIN_MISMATCH_DETECTED, _LAST_PIN_FAILURE_TIME
    PIN_MISMATCH_DETECTED = value
    if value:
        _LAST_PIN_FAILURE_TIME = time.time()
    else:
        _LAST_PIN_FAILURE_TIME = 0.0

    try:
        import cert_pinning
        cert_pinning.PIN_MISMATCH_DETECTED = value
        if hasattr(cert_pinning, "_LAST_PIN_FAILURE_TIME"):
            cert_pinning._LAST_PIN_FAILURE_TIME = _LAST_PIN_FAILURE_TIME
    except Exception:
        pass


def reset_pin_mismatch():
    """Immediately resets the pin mismatch latch to allow connections without waiting."""
    set_pin_mismatch_detected(False)


def log_pin_failure_event(host: str, error_msg: str):
    """Log pin verification failure to system logging and OS event log if available."""
    logger.critical(f"Certificate pinning verification failed for host {host}! Details: {error_msg}")
    try:
        import win32evtlog
        import win32evtlogutil
        win32evtlogutil.ReportEvent(
            "ZeroWatchSentinelAgent",
            1001,
            eventCategory=0,
            eventType=win32evtlog.EVENTLOG_ERROR_TYPE,
            strings=[
                "CRITICAL: ZeroWatch Endpoint Agent detected a certificate pinning mismatch (possible Man-in-the-Middle attack).",
                f"Target Host: {host}",
                f"Details: {error_msg}"
            ]
        )
    except Exception as e:
        logger.debug(f"OS Event log writing unavailable or failed: {e}")


class PinnedSession(requests.Session):
    def request(self, method, url, *args, **kwargs):
        # Sovereign unlinking requests must never be blocked by pin cooldown
        is_unlink_call = "/unlink" in str(url).lower()

        if not is_unlink_call and get_pin_mismatch_detected():
            remaining = get_pin_mismatch_remaining_cooldown()
            raise PinError(f"Connection temporarily throttled due to recent certificate pinning mismatch (cooldown remaining: {int(remaining)}s).")

        try:
            resp = super().request(method, url, *args, **kwargs)
            # If the request succeeds, ensure failure latch is cleared
            if resp.ok and PIN_MISMATCH_DETECTED:
                reset_pin_mismatch()
            return resp
        except Exception as e:
            if is_pin_failure(e):
                set_pin_mismatch_detected(True)
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or url
                except Exception:
                    host = url
                log_pin_failure_event(host, str(e))
                raise PinError(f"Certificate pinning verification failed for {host}") from e
            raise
