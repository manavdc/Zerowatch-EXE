import ssl
import base64
import logging
from urllib.parse import urlparse
import urllib3
from urllib3.exceptions import ProtocolError
import requests
from requests.adapters import HTTPAdapter
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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

def _verify_pin(hostname: str, der_cert: bytes, allowed_pins: list[str]):
    """Verifies that the SPKI hash of the certificate matches one of the allowed pins."""
    valid_pins = [p for p in allowed_pins if is_valid_sha256_base64(p)]
    if not valid_pins:
        raise PinError(f"No valid SPKI pins configured for validation against {hostname}")

    if not der_cert:
        raise PinError("No certificate presented by peer")
        
    spki_hash = get_spki_sha256(der_cert)
    
    if spki_hash not in valid_pins:
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
        # Check for common keywords used by enterprise firewalls / decryption proxies
        if any(term in issuer.lower() for term in ["proxy", "zscaler", "fortinet", "bluecoat", "kaspersky", "firewall", "inspection", "security"]):
            msg += " (Possible enterprise TLS decryption/inspection proxy detected)"
            
        logger.critical(msg)
        raise PinError(msg)
        
    logger.debug("SPKI pin verified successfully.")

class PinnedSSLContext(ssl.SSLContext):
    """Custom SSLContext that intercepts wrap_socket to perform SPKI pin validation.
    
    WARNING:
    This class subclasses and overrides `ssl.SSLContext.wrap_socket()`. While highly effective,
    this hook is not an officially documented Python extension point and relies on current CPython
    implementation behaviors. 
    - Future changes to Python's standard library `ssl` module internals could alter how sockets are wrapped,
      requiring maintainers to revisit this pinning implementation.
    - This mechanism must be thoroughly regression-tested during any future Python runtime version upgrades.
    """
    def __init__(self, protocol, pins, hostname_target=None):
        # We do not call super().__init__(protocol) because ssl.SSLContext.__init__ resolves
        # to object.__init__, which does not accept any arguments.
        self.pins = pins
        self.hostname_target = hostname_target

    def wrap_socket(self, sock, *args, **kwargs):
        wrapped = super().wrap_socket(sock, *args, **kwargs)
        
        # If we have no pins configured, do not validate (e.g., localhost/dev)
        if not self.pins:
            return wrapped
            
        # Resolve hostname from SNI arguments or stored target
        hostname = kwargs.get('server_hostname') or self.hostname_target or ""
        try:
            cert_der = wrapped.getpeercert(binary_form=True)
            _verify_pin(hostname, cert_der, self.pins)
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
    """Requests HTTPAdapter that mounts our custom PinnedSSLContext."""
    def __init__(self, pins, **kwargs):
        self.pins = pins
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **pool_kwargs):
        # Create custom SSLContext for connection pooling
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
    """Factory function to build and return an SPKIPinningAdapter."""
    return SPKIPinningAdapter(pins)

# Global state flag for pin failure
PIN_MISMATCH_DETECTED = False

def log_pin_failure_event(host: str, error_msg: str):
    """Log pin verification failure to Windows Event Log and logging subsystem."""
    logger.critical(f"Certificate pinning verification failed for host {host}! Details: {error_msg}")
    try:
        import win32evtlog
        import win32evtlogutil
        win32evtlogutil.ReportEvent(
            "ZeroWatchSentinelAgent",
            1001,  # Event ID for Pinning Mismatch
            eventCategory=0,
            eventType=win32evtlog.EVENTLOG_ERROR_TYPE,
            strings=[
                "CRITICAL: ZeroWatch Endpoint Agent detected a certificate pinning mismatch (possible Man-in-the-Middle attack).",
                f"Target Host: {host}",
                f"Details: {error_msg}"
            ]
        )
    except Exception as e:
        logger.error(f"Failed to write to Windows Event Log: {e}")

class PinnedSession(requests.Session):
    """Subclass of requests.Session that intercepts and handles pinning failures centrally."""
    def request(self, method, url, *args, **kwargs):
        global PIN_MISMATCH_DETECTED
        if PIN_MISMATCH_DETECTED:
            # Block any further requests if we previously detected a MITM attack
            raise PinError("Connection blocked due to previous certificate pinning mismatch.")

        try:
            return super().request(method, url, *args, **kwargs)
        except Exception as e:
            if is_pin_failure(e):
                PIN_MISMATCH_DETECTED = True
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or url
                except Exception:
                    host = url
                log_pin_failure_event(host, str(e))
                raise PinError(f"Certificate pinning verification failed for {host}") from e
            raise
