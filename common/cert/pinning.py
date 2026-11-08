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


# Base64-encoded raw Ed25519 public key (32 bytes) used as trust anchor for OTA updates
OTA_ED25519_PUBLIC_KEY_B64 = "uJ7OJWcMDHdkshzP38SpOh57/pX7vqku80HC8Yx7ZLk="

# Dynamic in-memory SPKI pins received via verified Ed25519 OTA updates
_DYNAMIC_PINS_CACHE: dict[str, list[str]] = {}


def register_dynamic_pins(pins: dict[str, list[str]]) -> None:
    """
    Registers cryptographically verified dynamic SPKI pins into memory for immediate use.
    Merges with existing pins without discarding valid pins.
    """
    global _DYNAMIC_PINS_CACHE
    if not isinstance(pins, dict):
        return
    for host, host_pins in pins.items():
        if not isinstance(host, str) or not isinstance(host_pins, list):
            continue
        valid = [p for p in host_pins if is_valid_sha256_base64(str(p))]
        if valid:
            existing = _DYNAMIC_PINS_CACHE.get(host, [])
            merged = list(dict.fromkeys(existing + valid))
            _DYNAMIC_PINS_CACHE[host] = merged
            logger.info(f"[PINNING] Registered {len(valid)} dynamic SPKI pin(s) for host {host}")


def get_dynamic_pins_for_host(hostname: str) -> list[str]:
    """Returns runtime-registered dynamic pins for the given hostname."""
    if not hostname:
        return []
    return list(_DYNAMIC_PINS_CACHE.get(hostname.lower(), []))


def clear_dynamic_pins() -> None:
    """Clears dynamic in-memory pins (primarily used for testing)."""
    global _DYNAMIC_PINS_CACHE
    _DYNAMIC_PINS_CACHE.clear()


# In-memory cache for AIA-fetched intermediate certificates to avoid repeated network roundtrips
_CA_ISSUER_CACHE: dict[str, bytes] = {}


def _extract_spki_from_cert(cert_input) -> str | None:
    """
    Safely extracts the SHA-256 SPKI base64 string from:
      - x509.Certificate
      - _ssl.Certificate (or any object implementing public_bytes)
      - raw DER bytes
      - raw PEM string or bytes
    """
    try:
        if isinstance(cert_input, x509.Certificate):
            cert = cert_input
        elif hasattr(cert_input, "public_bytes"):
            raw = cert_input.public_bytes()
            if isinstance(raw, str):
                raw = raw.encode("ascii", errors="replace")
            if b"BEGIN CERTIFICATE" in raw:
                cert = x509.load_pem_x509_certificate(raw)
            else:
                cert = x509.load_der_x509_certificate(raw)
        elif isinstance(cert_input, (bytes, bytearray)):
            if b"BEGIN CERTIFICATE" in cert_input:
                cert = x509.load_pem_x509_certificate(cert_input)
            else:
                cert = x509.load_der_x509_certificate(cert_input)
        elif isinstance(cert_input, str):
            cert = x509.load_pem_x509_certificate(cert_input.encode("ascii", errors="replace"))
        else:
            return None

        spki_bytes = cert.public_key().public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        h = hashes.Hash(hashes.SHA256())
        h.update(spki_bytes)
        return base64.b64encode(h.finalize()).decode("ascii")
    except Exception as e:
        logger.debug(f"Failed extracting SPKI from cert input: {e}")
        return None


def _resolve_aia_issuers(cert: x509.Certificate, max_depth: int = 2) -> list[tuple[str, x509.Certificate]]:
    """
    Follows Authority Information Access (AIA) caIssuers URLs up to max_depth
    to discover intermediate and root CA certificates not included directly in the TLS handshake.
    Returns list of (spki_hash, x509.Certificate).
    """
    discovered: list[tuple[str, x509.Certificate]] = []
    current_cert = cert

    for _ in range(max_depth):
        try:
            aia = current_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ca_issuers = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
        except Exception:
            break

        next_cert = None
        for issuer_url in ca_issuers:
            try:
                if issuer_url not in _CA_ISSUER_CACHE:
                    req = urllib.request.Request(issuer_url, headers={"User-Agent": "ZeroWatch-Pinning/1.0"})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        _CA_ISSUER_CACHE[issuer_url] = resp.read()

                issuer_der = _CA_ISSUER_CACHE.get(issuer_url)
                if issuer_der:
                    parsed_issuer = x509.load_der_x509_certificate(issuer_der)
                    issuer_spki = get_spki_sha256(issuer_der)
                    discovered.append((issuer_spki, parsed_issuer))
                    next_cert = parsed_issuer
                    break
            except Exception as e:
                logger.debug(f"AIA resolution failed for {issuer_url}: {e}")

        if next_cert is None:
            break
        current_cert = next_cert

    return discovered


def _verify_pin(hostname: str, der_cert: bytes, allowed_pins: list[str]):
    """
    Verifies that the SPKI hash of the certificate (or any discovered issuing CA in its chain)
    matches one of the allowed pins (hardcoded or OTA dynamic).
    Preserved for backwards compatibility with single-cert callers.
    """
    dynamic = get_dynamic_pins_for_host(hostname)
    combined = list(dict.fromkeys(allowed_pins + dynamic))
    valid_pins = [p for p in combined if is_valid_sha256_base64(p)]
    if not valid_pins:
        raise PinError(f"No valid SPKI pins configured for validation against {hostname}")

    if not der_cert:
        raise PinError("No certificate presented by peer")

    spki_hash = get_spki_sha256(der_cert)

    if spki_hash in valid_pins:
        logger.debug("SPKI pin verified successfully against leaf certificate.")
        return

    # Leaf did not match directly; traverse AIA chain (intermediate & root CAs)
    try:
        leaf_cert = x509.load_der_x509_certificate(der_cert)
        aia_chain = _resolve_aia_issuers(leaf_cert, max_depth=2)
        for depth, (issuer_spki, issuer_cert) in enumerate(aia_chain, start=1):
            if issuer_spki in valid_pins:
                issuer_name = issuer_cert.subject.rfc4514_string()
                logger.info(f"SPKI pin verified successfully via AIA CA (depth {depth}, {issuer_name}: {issuer_spki}).")
                return
    except Exception as _aia_err:
        logger.debug(f"AIA issuer traversal error: {_aia_err}")

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
    Verifies that at least one certificate in the TLS peer chain (leaf, intermediate CA, or root CA)
    matches one of the allowed SPKI pins (hardcoded or OTA dynamic).
    """
    dynamic = get_dynamic_pins_for_host(hostname)
    combined = list(dict.fromkeys(allowed_pins + dynamic))
    valid_pins = [p for p in combined if is_valid_sha256_base64(p)]
    if not valid_pins:
        raise PinError(f"No valid SPKI pins configured for validation against {hostname}")

    presented_spkis: list[str] = []
    leaf_cert = None

    # 1. Check leaf certificate
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

    # 2. Check full certificate chain from SSLSocket (verified chain from OpenSSL)
    sslobj = getattr(wrapped_sock, '_sslobj', None)
    if sslobj is not None:
        for getter_name in ('get_verified_chain', 'get_unverified_chain'):
            getter = getattr(sslobj, getter_name, None)
            if callable(getter):
                try:
                    chain = getter() or []
                    for depth, cert_obj in enumerate(chain):
                        chain_spki = _extract_spki_from_cert(cert_obj)
                        if not chain_spki:
                            continue
                        if chain_spki not in presented_spkis:
                            presented_spkis.append(chain_spki)
                        if chain_spki in valid_pins:
                            logger.info(f"SPKI pin verified successfully (matched at chain depth {depth}: {chain_spki}).")
                            return
                except Exception as _chain_err:
                    logger.debug(f"{getter_name} extraction error: {_chain_err}")

    # 3. Fallback: Traverse Authority Information Access (AIA) caIssuers
    if leaf_cert is not None:
        try:
            aia_chain = _resolve_aia_issuers(leaf_cert, max_depth=2)
            for depth, (issuer_spki, issuer_cert) in enumerate(aia_chain, start=1):
                if issuer_spki not in presented_spkis:
                    presented_spkis.append(issuer_spki)
                if issuer_spki in valid_pins:
                    issuer_name = issuer_cert.subject.rfc4514_string()
                    logger.info(f"SPKI pin verified successfully via AIA CA (depth {depth}, {issuer_name}: {issuer_spki}).")
                    return
        except Exception as _aia_err:
            logger.debug(f"AIA issuer validation error: {_aia_err}")

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


_LAST_EMERGENCY_OTA_TIME = 0.0


def reset_emergency_ota_cooldown() -> None:
    """Resets the emergency OTA throttling cooldown (used in testing and explicit recovery)."""
    global _LAST_EMERGENCY_OTA_TIME
    _LAST_EMERGENCY_OTA_TIME = 0.0


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
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or url
                except Exception:
                    host = url

                # Reactive OTA Auto-Healing:
                # Attempt to fetch latest Ed25519-signed pins out-of-band before hard-failing
                if self._attempt_emergency_ota_recovery(host):
                    logger.info(f"[PINNING] Emergency OTA recovery refreshed pins for {host}. Retrying request...")
                    try:
                        reset_pin_mismatch()
                        resp = super().request(method, url, *args, **kwargs)
                        if resp.ok and PIN_MISMATCH_DETECTED:
                            reset_pin_mismatch()
                        return resp
                    except Exception as retry_err:
                        logger.warning(f"[PINNING] Request retry after emergency OTA update still failed: {retry_err}")

                set_pin_mismatch_detected(True)
                log_pin_failure_event(host, str(e))
                raise PinError(f"Certificate pinning verification failed for {host}") from e
            raise

    def _attempt_emergency_ota_recovery(self, host: str) -> bool:
        """
        Attempts to fetch out-of-band Ed25519-signed pins via OTA.
        Throttled to at most once per 60 seconds to prevent connection storms.
        """
        global _LAST_EMERGENCY_OTA_TIME
        now = time.time()
        if (now - _LAST_EMERGENCY_OTA_TIME) < 60.0:
            logger.debug(f"[PINNING] Emergency OTA check throttled (last attempt {now - _LAST_EMERGENCY_OTA_TIME:.1f}s ago).")
            return False

        _LAST_EMERGENCY_OTA_TIME = now
        try:
            logger.info(f"[PINNING] Pin mismatch on {host}. Triggering emergency Ed25519 OTA pin sync...")
            from common.updater import fetch_dynamic_pins
            updated = fetch_dynamic_pins(timeout=10)
            if updated and any(h.lower() == host.lower() for h in updated):
                register_dynamic_pins(updated)
                return True
        except Exception as ota_err:
            logger.warning(f"[PINNING] Emergency OTA recovery attempt failed: {ota_err}")
        return False
