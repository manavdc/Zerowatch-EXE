"""
macos/crypto/keychain_backend.py
─────────────────────────────────────────────────────────────────────────────
Internal Keychain backend abstraction for MacOSSecureStore.

This module is INTERNAL to macos/crypto/ and must NOT be imported by any
other package. It is not part of the shared SecureStore interface.

Architecture:
    MacOSSecureStore
           ↓
    KeychainBackend      ← this module
           ↓
    concrete implementation (currently: security CLI prototype)

Purpose of this abstraction:
    Allow the concrete Keychain implementation to be swapped — from security
    CLI (current, prototype) to Security.framework ctypes (recommended for
    production) — without modifying MacOSSecureStore or any caller.

    The backend contract is simple:
        store(service, account, secret_bytes) → bool
        retrieve(service, account) → Optional[bytes]
        update(service, account, secret_bytes) → bool
        delete(service, account) → bool
        available() → bool

─────────────────────────────────────────────────────────────────────────────
Implementation: security CLI (current prototype)
─────────────────────────────────────────────────────────────────────────────

macOS ships the `security` command-line tool which provides read/write access
to the Keychain from the terminal. This is used as the Phase 6E prototype
implementation for several reasons:

  1. No external Python dependency
  2. No ctypes/PyObjC complexity
  3. Allows native validation without a frozen binary

Critically important: SECRET BYTES NEVER APPEAR IN ARGV

The security CLI's `-w` flag writes the secret as a command-line argument,
which is observable via `ps -ax` or `/proc/*/cmdline` while the command is
executing. This is a known exposure vector.

Mitigations used here:
  a) Secrets are written via `-w -` (stdin pipe) where the CLI supports it.
     This is NOT supported by `security add-generic-password -w` for the
     write value; `-w` takes a positional value only.

  b) For the write case: The security CLI does NOT support piping the secret
     via stdin for `add-generic-password`. The `-w` flag requires the value
     inline.

  SECURITY LIMITATION REPORT — Security CLI Write Path:
  ┌─────────────────────────────────────────────────────────────────────┐
  │ The `security add-generic-password -w <value>` call exposes the     │
  │ secret in argv for the brief duration of the subprocess.            │
  │ This is a known, documented limitation of the security CLI.         │
  │                                                                     │
  │ On macOS, argv is visible to processes running as the same user     │
  │ (or root) for approximately the duration of subprocess startup.     │
  │ For a root LaunchDaemon, only other root processes can observe it.  │
  │                                                                     │
  │ RECOMMENDATION: The production implementation should replace this   │
  │ with Security.framework ctypes calls (SecItemAdd / SecItemUpdate)   │
  │ which do not expose secrets through argv.                           │
  │                                                                     │
  │ This backend is explicitly labeled PROTOTYPE.                       │
  └─────────────────────────────────────────────────────────────────────┘

─────────────────────────────────────────────────────────────────────────────
Implementation: Security.framework (recommended for production)
─────────────────────────────────────────────────────────────────────────────

Production should use SecItemAdd / SecItemCopyMatching / SecItemUpdate /
SecItemDelete from Security.framework via ctypes. This avoids all argv
exposure and is the native Keychain API.

These calls cannot be validated on Windows. When native macOS hardware is
available, the Security.framework backend should be implemented and validated
before production release.

─────────────────────────────────────────────────────────────────────────────
LaunchDaemon Keychain Context (critical, requires native validation)
─────────────────────────────────────────────────────────────────────────────

A LaunchDaemon runs as root in the System context (not the user session).
This has critical implications for Keychain behavior:

  Interactive user process:
    - Accesses the user's login keychain (~/.keychains/login.keychain-db)
    - Login keychain is unlocked on login, locked on logout
    - User may see UI prompts for access approval

  LaunchAgent (user context):
    - Similar to interactive; runs in user session
    - Can access login keychain

  LaunchDaemon (root, no session):
    - The user's login keychain is NOT automatically available
    - The System keychain (/Library/Keychains/System.keychain) is accessible
    - Access control behavior differs from interactive context
    - UI prompts CANNOT appear (no user session)
    - The security CLI `add-generic-password` with `-T ""` grants access to
      any application; without it, prompts may appear

    RECOMMENDATION: Use the System keychain for the agent credential.
    Target: /Library/Keychains/System.keychain
    Accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    (unlocked after system boot, device-specific, survives reboot)

    ALL of the above must be validated on real macOS hardware with the
    daemon running under launchd.

─────────────────────────────────────────────────────────────────────────────
NATIVE VALIDATION NOT PERFORMED.
All behavior described above is based on macOS documentation and must be
confirmed on real hardware before production use.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger("macos.crypto.keychain_backend")

# ── Backend constants ─────────────────────────────────────────────────────────
# The System keychain is used because the agent runs as a LaunchDaemon.
# User keychains are not reliably accessible without a user session.
_SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
_SECURITY_TIMEOUT = 10   # seconds; Keychain operations should be near-instant
_SECURITY_CMD = "/usr/bin/security"


# ── CliKeychainBackend (PROTOTYPE/DEBUG only) ────────────────────────────────
# Renamed from KeychainBackend in Phase 6F-A.
# The production default is now SecurityFrameworkBackend.
# CliKeychainBackend is retained for:
#   1. Native validation comparison (run both backends side-by-side)
#   2. Debug Keychain state via standard `security` commands
#   3. Fallback investigation if Security.framework load fails
# DO NOT use CliKeychainBackend in production (argv exposure on write path).

class CliKeychainBackend:
    """
    PROTOTYPE/DEBUG backend using the macOS `security` CLI.

    NOT for production use. See module docstring for security limitation.
    SecurityFrameworkBackend is the production implementation.

    Retained for native validation comparison and debugging.
    """

    def __init__(self) -> None:
        # Check at instantiation whether security is available
        self._security_path = shutil.which("security") or _SECURITY_CMD
        self._available = self._check_available()
        if self._available:
            logger.info(
                "KeychainBackend: security CLI available at %s",
                self._security_path,
            )
        else:
            logger.warning(
                "KeychainBackend: security CLI not found — Keychain unavailable. "
                "Likely running on non-macOS platform (Windows CI)."
            )

    def _check_available(self) -> bool:
        """Check whether the security binary exists and is executable."""
        import os
        return bool(self._security_path) and os.path.isfile(self._security_path)

    def available(self) -> bool:
        """Return True if the Keychain backend can be used."""
        return self._available

    def _run_security(self, *args: str, input_bytes: Optional[bytes] = None) -> tuple[bool, str, str]:
        """
        Execute security(1) with the given arguments.

        Rules:
          - Never uses shell=True
          - Captures stdout and stderr (no secret leakage to terminal)
          - Enforces timeout
          - Returns (success, stdout, stderr)
        """
        cmd = [self._security_path] + list(args)
        try:
            result = subprocess.run(
                cmd,
                input=input_bytes,
                capture_output=True,
                timeout=_SECURITY_TIMEOUT,
                # NO shell=True
            )
            ok = result.returncode == 0
            stdout = result.stdout.decode("utf-8", errors="replace").strip()
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            return ok, stdout, stderr
        except FileNotFoundError:
            logger.error("security binary not found at %s", self._security_path)
            return False, "", "security not found"
        except subprocess.TimeoutExpired:
            logger.error("security CLI timed out after %ds", _SECURITY_TIMEOUT)
            return False, "", "timeout"
        except OSError as exc:
            logger.error("security CLI OSError: %s", exc)
            return False, "", str(exc)

    def store(self, service: str, account: str, secret_bytes: bytes) -> bool:
        """
        Store a secret in the Keychain.

        Uses `security add-generic-password` targeting the System keychain.

        ── SECURITY NOTE ──────────────────────────────────────────────────────
        The -w flag passes the secret as a command-line argument. This is
        observable via ps(1) for the brief duration of subprocess execution.
        For a root LaunchDaemon, this window is exposed only to other root
        processes. This is a KNOWN LIMITATION of the security CLI and is
        documented in keychain_backend.py module docstring.
        The production replacement uses Security.framework directly (no argv).
        ───────────────────────────────────────────────────────────────────────

        The secret is passed as a hex-encoded value to avoid encoding
        issues with arbitrary binary bytes (the security CLI treats -w as
        a UTF-8 string argument; hex avoids any null/encoding issues).
        decode is done in retrieve().

        Returns True on success (including if update was needed).
        """
        if not self._available:
            logger.warning("store: Keychain backend not available")
            return False

        if not secret_bytes:
            logger.warning("store: empty secret bytes — rejecting")
            return False

        # Encode as hex to safely pass arbitrary bytes through the CLI's -w flag
        hex_secret = secret_bytes.hex()

        # Try add first
        ok, stdout, stderr = self._run_security(
            "add-generic-password",
            "-s", service,
            "-a", account,
            "-w", hex_secret,
            "-T", "",                  # Allow access without UI prompt
            _SYSTEM_KEYCHAIN,
        )

        if ok:
            logger.info("Keychain store succeeded [service=%s]", service)
            return True

        # If duplicate: update instead
        if "already" in stderr.lower() or "duplicate" in stderr.lower():
            logger.info("Keychain item exists — updating [service=%s]", service)
            return self.update(service, account, secret_bytes)

        logger.error("Keychain store failed [service=%s]: %s", service, stderr)
        return False

    def retrieve(self, service: str, account: str) -> Optional[bytes]:
        """
        Retrieve a secret from the Keychain.

        Uses `security find-generic-password -w` which prints the password
        to stdout. This does NOT expose the secret in argv.

        Returns the original bytes on success, None on failure.
        """
        if not self._available:
            logger.warning("retrieve: Keychain backend not available")
            return None

        ok, stdout, stderr = self._run_security(
            "find-generic-password",
            "-s", service,
            "-a", account,
            "-w",                      # Print password to stdout (not argv)
            _SYSTEM_KEYCHAIN,
        )

        if not ok:
            stderr_lower = stderr.lower()
            if "could not find" in stderr_lower or "no such" in stderr_lower:
                logger.debug("Keychain item not found [service=%s]", service)
            else:
                logger.error(
                    "Keychain retrieve failed [service=%s]: %s", service, stderr
                )
            return None

        # Decode hex back to bytes
        hex_value = stdout.strip()
        if not hex_value:
            logger.error("Keychain retrieve returned empty value [service=%s]", service)
            return None

        try:
            return bytes.fromhex(hex_value)
        except ValueError as exc:
            logger.error(
                "Keychain retrieve: hex decode failed [service=%s]: %s",
                service, exc,
            )
            return None

    def update(self, service: str, account: str, secret_bytes: bytes) -> bool:
        """
        Update an existing Keychain item.

        Uses delete + add (the security CLI does not have a standalone
        update subcommand for generic passwords).

        Returns True if the item is updated successfully.
        """
        if not self._available:
            return False

        if not secret_bytes:
            logger.warning("update: empty secret bytes — rejecting")
            return False

        # Delete existing (ignore errors — it might not exist)
        self._run_security(
            "delete-generic-password",
            "-s", service,
            "-a", account,
            _SYSTEM_KEYCHAIN,
        )

        # Re-add
        hex_secret = secret_bytes.hex()
        ok, stdout, stderr = self._run_security(
            "add-generic-password",
            "-s", service,
            "-a", account,
            "-w", hex_secret,
            "-T", "",
            _SYSTEM_KEYCHAIN,
        )

        if ok:
            logger.info("Keychain update succeeded [service=%s]", service)
        else:
            logger.error("Keychain update failed [service=%s]: %s", service, stderr)
        return ok

    def delete(self, service: str, account: str) -> bool:
        """
        Delete a Keychain item.

        Returns True if deleted or if it didn't exist (idempotent).
        """
        if not self._available:
            return False

        ok, stdout, stderr = self._run_security(
            "delete-generic-password",
            "-s", service,
            "-a", account,
            _SYSTEM_KEYCHAIN,
        )

        if ok:
            logger.info("Keychain delete succeeded [service=%s]", service)
            return True

        if "could not find" in stderr.lower() or "no such" in stderr.lower():
            # Already gone — idempotent success
            return True

        logger.warning("Keychain delete failed [service=%s]: %s", service, stderr)
        return False

# ── Backward-compatibility alias ──────────────────────────────────────────────
# KeychainBackend is now CliKeychainBackend. The alias keeps any existing
# internal references working without a rename sweep.
KeychainBackend = CliKeychainBackend


# ── InMemoryKeychainBackend (test/mock only) ──────────────────────────────────

class InMemoryKeychainBackend(CliKeychainBackend):
    """
    Deterministic in-memory backend for testing.

    Replaces all subprocess calls with a simple dict.
    MUST NOT be used in production.

    Usage:
        from macos.crypto.keychain_backend import InMemoryKeychainBackend
        store = MacOSSecureStore(backend=InMemoryKeychainBackend())
    """

    def __init__(self) -> None:
        # Deliberately DO NOT call super().__init__() to avoid subprocess checks
        self._store: dict[tuple[str, str], bytes] = {}
        self._available_flag = True
        logger.debug("InMemoryKeychainBackend initialized")

    def available(self) -> bool:
        return self._available_flag

    def set_available(self, value: bool) -> None:
        """Allow tests to simulate backend unavailability."""
        self._available_flag = value

    def store(self, service: str, account: str, secret_bytes: bytes) -> bool:
        if not self._available_flag:
            return False
        if not secret_bytes:
            return False
        self._store[(service, account)] = secret_bytes
        logger.debug("InMemory: stored [%s:%s]", service, account)
        return True

    def retrieve(self, service: str, account: str) -> Optional[bytes]:
        if not self._available_flag:
            return None
        val = self._store.get((service, account))
        if val is None:
            logger.debug("InMemory: not found [%s:%s]", service, account)
        return val

    def update(self, service: str, account: str, secret_bytes: bytes) -> bool:
        if not self._available_flag:
            return False
        if not secret_bytes:
            return False
        self._store[(service, account)] = secret_bytes
        logger.debug("InMemory: updated [%s:%s]", service, account)
        return True

    def delete(self, service: str, account: str) -> bool:
        if not self._available_flag:
            return False
        existed = (service, account) in self._store
        self._store.pop((service, account), None)
        logger.debug("InMemory: deleted [%s:%s] (existed=%s)", service, account, existed)
        return True
