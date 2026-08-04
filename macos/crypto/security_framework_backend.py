"""
macos/crypto/security_framework_backend.py
─────────────────────────────────────────────────────────────────────────────
Production macOS Keychain backend using Apple Security.framework via ctypes.

This module is INTERNAL to macos/crypto/ and must NOT be imported by any
package outside this directory. It is not part of the SecureStore interface.

─────────────────────────────────────────────────────────────────────────────
Architecture
─────────────────────────────────────────────────────────────────────────────

    MacOSSecureStore
          ↓
    KeychainBackend  (abstract contract: store/retrieve/update/delete)
          ↓
    SecurityFrameworkBackend   ← this module
          ↓
    _NativeSecurityBindings    ← ctypes bridge (mockable for CI)
          ↓
    /System/Library/Frameworks/Security.framework/Security

─────────────────────────────────────────────────────────────────────────────
Security.framework APIs used
─────────────────────────────────────────────────────────────────────────────

    SecItemAdd           — store a new Keychain item
    SecItemCopyMatching  — retrieve a Keychain item
    SecItemUpdate        — update an existing Keychain item
    SecItemDelete        — delete a Keychain item

All calls go through NativeSecurityBindings which is swappable for testing.

─────────────────────────────────────────────────────────────────────────────
Binary secret safety
─────────────────────────────────────────────────────────────────────────────

Secrets are stored as binary CFData. No hex encoding, no UTF-8 conversion,
no subprocess boundary. The exact bytes passed to store() are the exact bytes
returned from retrieve().

Python bytes → CFDataCreate → SecItemAdd → Keychain
Keychain → SecItemCopyMatching → CFDataGetBytePtr → Python bytes

─────────────────────────────────────────────────────────────────────────────
No secret in argv — Security Review
─────────────────────────────────────────────────────────────────────────────

    Secret in argv:        NOT POSSIBLE — no subprocess used
    Secret in logs:        No — only metadata (slot_id, OSStatus) logged
    Secret in temp files:  Not possible — no file I/O
    shell=True:            Not used — ctypes only
    Plaintext fallback:    Not implemented — fail-closed
    Custom crypto:         Not implemented

─────────────────────────────────────────────────────────────────────────────
OSStatus constants (Security.framework)
─────────────────────────────────────────────────────────────────────────────

OSStatus is a 32-bit signed integer (c_int32 / c_long on Darwin).
Documented at:
  https://developer.apple.com/documentation/security/1542001-security_framework_result_codes

─────────────────────────────────────────────────────────────────────────────
Keychain accessibility
─────────────────────────────────────────────────────────────────────────────

Target: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
  - Available after first boot unlock (not before)
  - Device-specific (not transferable via backup)
  - Survives reboot (item persists while device is locked after first unlock)

For a root LaunchDaemon:
  - The System keychain is the target
  - kSecUseKeychain must specify the System keychain explicitly
  - kSecAttrAccessGroup may be needed for signed binaries

ALL of the above requires native validation on real macOS hardware.
The implementation uses documented APIs only.

─────────────────────────────────────────────────────────────────────────────
LaunchDaemon Keychain context (requires native validation)
─────────────────────────────────────────────────────────────────────────────

LaunchDaemon runs as root in the System context with no user session.
The login keychain is NOT accessible. The System keychain is the correct
target. See keychain_backend.py for full context documentation.

─────────────────────────────────────────────────────────────────────────────
NATIVE VALIDATION NOT PERFORMED.
All behavior described above is based on Apple documentation and must be
confirmed on real macOS hardware before production use.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import sys
from typing import Optional

logger = logging.getLogger("macos.crypto.security_framework_backend")

# ── OSStatus constants ────────────────────────────────────────────────────────
# Documented: https://developer.apple.com/documentation/security/keychain_services

class OSStatus:
    """Security.framework OSStatus result codes."""
    errSecSuccess            = 0          # Operation succeeded
    errSecItemNotFound       = -25300     # Item not found
    errSecDuplicateItem      = -25299     # Duplicate item already exists
    errSecInteractionNotAllowed = -25308  # No UI allowed; interaction needed
    errSecAuthFailed         = -25293     # Authorization/authentication failed
    errSecParam              = -50        # Invalid parameter
    errSecAllocate           = -108       # Memory allocation failure
    errSecNotAvailable       = -25291     # No keychain is available
    errSecUserCanceled       = -128       # User cancelled operation

    # Human-readable mapping for logging (metadata only, no secrets)
    _NAMES: dict[int, str] = {
        0:       "errSecSuccess",
        -25300:  "errSecItemNotFound",
        -25299:  "errSecDuplicateItem",
        -25308:  "errSecInteractionNotAllowed",
        -25293:  "errSecAuthFailed",
        -50:     "errSecParam",
        -108:    "errSecAllocate",
        -25291:  "errSecNotAvailable",
        -128:    "errSecUserCanceled",
    }

    @classmethod
    def name(cls, code: int) -> str:
        return cls._NAMES.get(code, f"OSStatus({code})")


# ── CoreFoundation / Security.framework framework path ───────────────────────

_SECURITY_FW_PATH  = "/System/Library/Frameworks/Security.framework/Security"
_CF_FW_PATH        = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

# Keychain attribute / query key CFString values (kSec* constants).
# These are the raw CFStringRef values exposed by Security.framework.
# We access them by name via ctypes.CDLL + ctypes.c_void_p to avoid
# depending on PyObjC.
#
# kSec* constant names used:
#   kSecClass                 — item class (kSecClassGenericPassword)
#   kSecAttrService           — service name
#   kSecAttrAccount           — account name
#   kSecValueData             — the secret data
#   kSecReturnData            — whether to return the data
#   kSecMatchLimit            — how many results to return
#   kSecMatchLimitOne         — match exactly one
#   kSecAttrAccessible        — accessibility constant
#   kSecAttrSynchronizable    — iCloud sync (disabled)
#   kSecAttrSynchronizableAny — match any sync state

# ── _NativeSecurityBindings ───────────────────────────────────────────────────

class _NativeSecurityBindings:
    """
    ctypes bridge to Security.framework and CoreFoundation.

    This class is instantiated LAZILY: framework loading happens only when
    an instance is first created, not at module import time. Importing
    macos.crypto.security_framework_backend on Windows CI never attempts to
    load Security.framework.

    This class is INTERNAL and mockable. Tests replace it with
    _MockSecurityBindings to avoid needing macOS frameworks.

    All CoreFoundation references (CFDictionaryRef, CFDataRef, etc.) are
    opaque c_void_p values. We do not attempt to wrap the full CF type system.

    Memory management:
      - CFRelease is called on all CF objects created here.
      - Python bytes created from CFData are independent of the CF lifetime.
      - All CF objects are released in finally blocks.

    NATIVE VALIDATION NOT PERFORMED.
    """

    def __init__(self) -> None:
        """Load Security.framework and CoreFoundation. Raises on non-macOS."""
        if sys.platform != "darwin":
            raise RuntimeError(
                "_NativeSecurityBindings: not on macOS — cannot load Security.framework"
            )
        self._sec  = self._load_framework(_SECURITY_FW_PATH,  "Security.framework")
        self._cf   = self._load_framework(_CF_FW_PATH,         "CoreFoundation.framework")
        self._setup_function_signatures()
        self._constants = self._load_constants()
        logger.debug("_NativeSecurityBindings: Security.framework loaded")

    # ── Framework loading ─────────────────────────────────────────────────────

    @staticmethod
    def _load_framework(path: str, name: str) -> ctypes.CDLL:
        try:
            lib = ctypes.CDLL(path)
            logger.debug("Loaded %s from %s", name, path)
            return lib
        except OSError as exc:
            raise RuntimeError(f"Cannot load {name}: {exc}") from exc

    # ── Function signatures ───────────────────────────────────────────────────

    def _setup_function_signatures(self) -> None:
        """
        Set argtypes and restype for all Security.framework and CoreFoundation
        functions used. This is required for correct argument marshalling on
        64-bit Darwin (arm64 and x86_64).

        All SecItem* functions:
          argtypes: (CFDictionaryRef,) or (CFDictionaryRef, CFTypeRef*)
          restype:  OSStatus (c_int32)
        """
        cf = self._cf
        sec = self._sec

        # ── CoreFoundation ─────────────────────────────────────────────────────

        # CFDataCreate(allocator, bytes, length) → CFDataRef
        cf.CFDataCreate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long]
        cf.CFDataCreate.restype  = ctypes.c_void_p

        # CFDataGetLength(CFDataRef) → CFIndex (c_long)
        cf.CFDataGetLength.argtypes = [ctypes.c_void_p]
        cf.CFDataGetLength.restype  = ctypes.c_long

        # CFDataGetBytePtr(CFDataRef) → const UInt8*
        cf.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
        cf.CFDataGetBytePtr.restype  = ctypes.c_char_p

        # CFDictionaryCreate(alloc, keys, values, count, keyCallbacks, valueCallbacks) → CFDictionaryRef
        cf.CFDictionaryCreate.argtypes = [
            ctypes.c_void_p,                       # allocator (kCFAllocatorDefault = NULL)
            ctypes.POINTER(ctypes.c_void_p),       # keys
            ctypes.POINTER(ctypes.c_void_p),       # values
            ctypes.c_long,                         # numValues
            ctypes.c_void_p,                       # keyCallBacks
            ctypes.c_void_p,                       # valueCallBacks
        ]
        cf.CFDictionaryCreate.restype = ctypes.c_void_p

        # CFDictionaryCreateMutable(alloc, capacity, keyCallbacks, valueCallbacks) → CFMutableDictionaryRef
        cf.CFDictionaryCreateMutable.argtypes = [
            ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p,
        ]
        cf.CFDictionaryCreateMutable.restype = ctypes.c_void_p

        # CFDictionaryAddValue(dict, key, value)
        cf.CFDictionaryAddValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        cf.CFDictionaryAddValue.restype  = None

        # CFStringCreateWithCString(alloc, cStr, encoding) → CFStringRef
        cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFStringCreateWithCString.restype  = ctypes.c_void_p

        # CFBooleanRef: kCFBooleanTrue / kCFBooleanFalse are exported globals
        # No function signature needed; accessed as c_void_p globals.

        # CFRelease(CFTypeRef)
        cf.CFRelease.argtypes = [ctypes.c_void_p]
        cf.CFRelease.restype  = None

        # ── Security.framework ─────────────────────────────────────────────────

        # SecItemAdd(attributes, result) → OSStatus
        sec.SecItemAdd.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        sec.SecItemAdd.restype  = ctypes.c_int32

        # SecItemCopyMatching(query, result) → OSStatus
        sec.SecItemCopyMatching.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        sec.SecItemCopyMatching.restype  = ctypes.c_int32

        # SecItemUpdate(query, attributesToUpdate) → OSStatus
        sec.SecItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        sec.SecItemUpdate.restype  = ctypes.c_int32

        # SecItemDelete(query) → OSStatus
        sec.SecItemDelete.argtypes = [ctypes.c_void_p]
        sec.SecItemDelete.restype  = ctypes.c_int32

    # ── Constant loading ──────────────────────────────────────────────────────

    def _load_constants(self) -> dict[str, int]:
        """
        Load kSec* and kCF* constant pointers from the frameworks.

        These are CFStringRef / CFTypeRef / CFBooleanRef globals exported by
        the framework dylib. We read them as c_void_p (pointer-sized integers)
        because CFDictionary uses void* for keys and values.

        CFString kCFStringEncodingUTF8 = 0x08000100
        """
        sec = self._sec
        cf  = self._cf

        def load(lib: ctypes.CDLL, name: str) -> int:
            """Load a framework global constant (a pointer) by name."""
            try:
                ref = ctypes.c_void_p.in_dll(lib, name)
                val = ref.value
                if val is None:
                    logger.warning("Constant %s resolved to None — framework issue?", name)
                    return 0
                return val
            except AttributeError as exc:
                raise RuntimeError(f"Cannot find {name} in framework: {exc}") from exc

        constants = {
            # Security.framework class
            "kSecClass":                    load(sec, "kSecClass"),
            "kSecClassGenericPassword":     load(sec, "kSecClassGenericPassword"),
            # Attributes
            "kSecAttrService":              load(sec, "kSecAttrService"),
            "kSecAttrAccount":              load(sec, "kSecAttrAccount"),
            "kSecAttrAccessible":           load(sec, "kSecAttrAccessible"),
            "kSecAttrSynchronizable":       load(sec, "kSecAttrSynchronizable"),
            "kSecAttrSynchronizableAny":    load(sec, "kSecAttrSynchronizableAny"),
            # kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            # Available after boot unlock; device-specific; survives reboot.
            # Appropriate for a root LaunchDaemon credential.
            "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly":
                                            load(sec, "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"),
            # Data / result keys
            "kSecValueData":                load(sec, "kSecValueData"),
            "kSecReturnData":               load(sec, "kSecReturnData"),
            "kSecMatchLimit":               load(sec, "kSecMatchLimit"),
            "kSecMatchLimitOne":            load(sec, "kSecMatchLimitOne"),
            # CoreFoundation booleans
            "kCFBooleanTrue":               load(cf,  "kCFBooleanTrue"),
            "kCFBooleanFalse":              load(cf,  "kCFBooleanFalse"),
        }
        logger.debug("Loaded %d Security.framework constants", len(constants))
        return constants

    # ── CoreFoundation helpers ────────────────────────────────────────────────

    _CF_UTF8 = 0x08000100  # kCFStringEncodingUTF8

    def _cf_string(self, s: str) -> int:
        """
        Create a CFStringRef from a Python str (UTF-8).
        Caller is responsible for CFRelease.
        """
        encoded = s.encode("utf-8")
        ref = self._cf.CFStringCreateWithCString(None, encoded, self._CF_UTF8)
        if not ref:
            raise RuntimeError(f"CFStringCreateWithCString failed for {s!r}")
        return ref

    def _cf_data(self, data: bytes) -> int:
        """
        Create a CFDataRef from Python bytes.
        Caller is responsible for CFRelease.
        Binary-safe: handles null bytes and arbitrary binary.
        """
        ref = self._cf.CFDataCreate(None, data, len(data))
        if not ref:
            raise RuntimeError("CFDataCreate failed")
        return ref

    def _cf_bytes(self, data_ref: int) -> bytes:
        """
        Extract Python bytes from a CFDataRef.
        Does NOT CFRelease — caller manages lifetime.
        Binary-safe.
        """
        length = self._cf.CFDataGetLength(data_ref)
        if length == 0:
            return b""
        ptr = self._cf.CFDataGetBytePtr(data_ref)
        if not ptr:
            return b""
        return ctypes.string_at(ptr, length)

    def _build_query(self, service: str, account: str) -> int:
        """
        Build a CFMutableDictionaryRef query for service+account lookup.

        Keys:
          kSecClass             = kSecClassGenericPassword
          kSecAttrService       = service string
          kSecAttrAccount       = account string

        Caller is responsible for CFRelease on the returned dictionary
        AND on the CFStrings used as values.
        """
        c = self._constants
        cf = self._cf

    def _cf_dict_callbacks(self) -> tuple[ctypes.c_void_p, ctypes.c_void_p]:
        """
        Return pointers (&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks).

        kCFTypeDictionaryKeyCallBacks and kCFTypeDictionaryValueCallBacks are struct
        globals in CoreFoundation (not pointer variables). We use ctypes.addressof()
        to pass their memory addresses to CFDictionaryCreateMutable.
        """
        key_ref = ctypes.c_void_p.in_dll(self._cf, "kCFTypeDictionaryKeyCallBacks")
        val_ref = ctypes.c_void_p.in_dll(self._cf, "kCFTypeDictionaryValueCallBacks")
        return ctypes.c_void_p(ctypes.addressof(key_ref)), ctypes.c_void_p(ctypes.addressof(val_ref))

    def _build_query(self, service: str, account: str) -> int:
        """
        Build a CFMutableDictionaryRef query for service+account lookup.

        Keys:
          kSecClass             = kSecClassGenericPassword
          kSecAttrService       = service string
          kSecAttrAccount       = account string

        Caller is responsible for CFRelease on the returned dictionary.
        """
        c = self._constants
        cf = self._cf

        key_cbs, val_cbs = self._cf_dict_callbacks()
        d = cf.CFDictionaryCreateMutable(None, 0, key_cbs, val_cbs)
        if not d:
            raise RuntimeError("CFDictionaryCreateMutable failed")

        svc_ref  = self._cf_string(service)
        acct_ref = self._cf_string(account)

        cf.CFDictionaryAddValue(d, ctypes.c_void_p(c["kSecClass"]),
                                   ctypes.c_void_p(c["kSecClassGenericPassword"]))
        cf.CFDictionaryAddValue(d, ctypes.c_void_p(c["kSecAttrService"]),  ctypes.c_void_p(svc_ref))
        cf.CFDictionaryAddValue(d, ctypes.c_void_p(c["kSecAttrAccount"]),  ctypes.c_void_p(acct_ref))
        # Disable iCloud sync — agent credentials are device-specific
        cf.CFDictionaryAddValue(d, ctypes.c_void_p(c["kSecAttrSynchronizable"]),
                                   ctypes.c_void_p(c["kCFBooleanFalse"]))

        # Note: svc_ref and acct_ref are retained by the dict (CF retain semantics)
        # We release our own references now that the dict holds them.
        cf.CFRelease(svc_ref)
        cf.CFRelease(acct_ref)

        return d

    # ── Public SecItem operations ─────────────────────────────────────────────

    def sec_item_add(self, service: str, account: str, data: bytes) -> int:
        """
        Call SecItemAdd. Returns OSStatus.

        secret is stored as binary CFData. No hex encoding.
        """
        c = self._constants
        cf = self._cf
        sec = self._sec

        query = self._build_query(service, account)
        data_ref = self._cf_data(data)
        # Set accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        cf.CFDictionaryAddValue(query,
                                ctypes.c_void_p(c["kSecAttrAccessible"]),
                                ctypes.c_void_p(c["kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"]))
        cf.CFDictionaryAddValue(query,
                                ctypes.c_void_p(c["kSecValueData"]),
                                ctypes.c_void_p(data_ref))
        try:
            status = sec.SecItemAdd(ctypes.c_void_p(query), None)
            return int(status)
        finally:
            cf.CFRelease(ctypes.c_void_p(data_ref))
            cf.CFRelease(ctypes.c_void_p(query))

    def sec_item_copy_matching(self, service: str, account: str) -> tuple[int, Optional[bytes]]:
        """
        Call SecItemCopyMatching. Returns (OSStatus, bytes_or_None).

        Requests exactly one item (kSecMatchLimitOne) with data returned.
        """
        c = self._constants
        cf = self._cf
        sec = self._sec

        query = self._build_query(service, account)
        cf.CFDictionaryAddValue(query,
                                ctypes.c_void_p(c["kSecReturnData"]),
                                ctypes.c_void_p(c["kCFBooleanTrue"]))
        cf.CFDictionaryAddValue(query,
                                ctypes.c_void_p(c["kSecMatchLimit"]),
                                ctypes.c_void_p(c["kSecMatchLimitOne"]))
        # Match any synchronizable state to find daemon-stored items
        cf.CFDictionaryAddValue(query,
                                ctypes.c_void_p(c["kSecAttrSynchronizable"]),
                                ctypes.c_void_p(c["kSecAttrSynchronizableAny"]))

        result_ref = ctypes.c_void_p(None)
        try:
            status = sec.SecItemCopyMatching(
                ctypes.c_void_p(query),
                ctypes.byref(result_ref),
            )
            status = int(status)
            if status != OSStatus.errSecSuccess or not result_ref.value:
                return status, None
            # Extract bytes from returned CFDataRef
            result_bytes = self._cf_bytes(result_ref.value)
            return status, result_bytes
        finally:
            if result_ref.value:
                cf.CFRelease(result_ref)
            cf.CFRelease(ctypes.c_void_p(query))

    def sec_item_update(self, service: str, account: str, data: bytes) -> int:
        """
        Call SecItemUpdate. Returns OSStatus.

        query: identifies the existing item (service + account)
        attributesToUpdate: {kSecValueData: new_data}
        """
        c = self._constants
        cf = self._cf
        sec = self._sec

        query = self._build_query(service, account)
        data_ref = self._cf_data(data)

        key_cbs, val_cbs = self._cf_dict_callbacks()
        attrs = cf.CFDictionaryCreateMutable(None, 0, key_cbs, val_cbs)
        if not attrs:
            cf.CFRelease(ctypes.c_void_p(query))
            cf.CFRelease(ctypes.c_void_p(data_ref))
            raise RuntimeError("CFDictionaryCreateMutable failed for update attrs")

        cf.CFDictionaryAddValue(attrs,
                                ctypes.c_void_p(c["kSecValueData"]),
                                ctypes.c_void_p(data_ref))
        try:
            status = sec.SecItemUpdate(ctypes.c_void_p(query), ctypes.c_void_p(attrs))
            return int(status)
        finally:
            cf.CFRelease(ctypes.c_void_p(data_ref))
            cf.CFRelease(ctypes.c_void_p(attrs))
            cf.CFRelease(ctypes.c_void_p(query))

    def sec_item_delete(self, service: str, account: str) -> int:
        """
        Call SecItemDelete. Returns OSStatus.
        """
        query = self._build_query(service, account)
        try:
            status = self._sec.SecItemDelete(ctypes.c_void_p(query))
            return int(status)
        finally:
            self._cf.CFRelease(ctypes.c_void_p(query))


# ── _MockSecurityBindings (test/CI use only) ──────────────────────────────────

class _MockSecurityBindings:
    """
    In-memory mock of _NativeSecurityBindings for CI testing.

    Does NOT load Security.framework. Does NOT require macOS.

    Simulates OSStatus return codes and binary data storage.
    Allows testing of SecurityFrameworkBackend logic without real Keychain.

    DO NOT use in production.
    """

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], bytes] = {}
        # Allow tests to inject failures
        self._next_add_status:    int = OSStatus.errSecSuccess
        self._next_copy_status:   int = OSStatus.errSecSuccess
        self._next_update_status: int = OSStatus.errSecSuccess
        self._next_delete_status: int = OSStatus.errSecSuccess

    def _key(self, service: str, account: str) -> tuple[str, str]:
        return (service, account)

    def sec_item_add(self, service: str, account: str, data: bytes) -> int:
        status = self._next_add_status
        self._next_add_status = OSStatus.errSecSuccess  # reset

        if status != OSStatus.errSecSuccess:
            return status

        key = self._key(service, account)
        if key in self._store:
            return OSStatus.errSecDuplicateItem
        self._store[key] = data
        return OSStatus.errSecSuccess

    def sec_item_copy_matching(self, service: str, account: str) -> tuple[int, Optional[bytes]]:
        status = self._next_copy_status
        self._next_copy_status = OSStatus.errSecSuccess

        if status != OSStatus.errSecSuccess:
            return status, None

        key = self._key(service, account)
        if key not in self._store:
            return OSStatus.errSecItemNotFound, None
        return OSStatus.errSecSuccess, self._store[key]

    def sec_item_update(self, service: str, account: str, data: bytes) -> int:
        status = self._next_update_status
        self._next_update_status = OSStatus.errSecSuccess

        if status != OSStatus.errSecSuccess:
            return status

        key = self._key(service, account)
        if key not in self._store:
            return OSStatus.errSecItemNotFound
        self._store[key] = data
        return OSStatus.errSecSuccess

    def sec_item_delete(self, service: str, account: str) -> int:
        status = self._next_delete_status
        self._next_delete_status = OSStatus.errSecSuccess

        if status != OSStatus.errSecSuccess:
            return status

        key = self._key(service, account)
        if key not in self._store:
            return OSStatus.errSecItemNotFound
        del self._store[key]
        return OSStatus.errSecSuccess

    # ── Test control helpers ──────────────────────────────────────────────────

    def inject_add_status(self, status: int) -> None:
        """Force the next sec_item_add to return a specific OSStatus."""
        self._next_add_status = status

    def inject_copy_status(self, status: int) -> None:
        """Force the next sec_item_copy_matching to return a specific OSStatus."""
        self._next_copy_status = status

    def inject_update_status(self, status: int) -> None:
        """Force the next sec_item_update to return a specific OSStatus."""
        self._next_update_status = status

    def inject_delete_status(self, status: int) -> None:
        """Force the next sec_item_delete to return a specific OSStatus."""
        self._next_delete_status = status


# ── SecurityFrameworkBackend ──────────────────────────────────────────────────

class SecurityFrameworkBackend:
    """
    Production macOS Keychain backend using Security.framework via ctypes.

    Implements the same contract as KeychainBackend:
        store(service, account, secret_bytes) → bool
        retrieve(service, account) → Optional[bytes]
        update(service, account, secret_bytes) → bool
        delete(service, account) → bool
        available() → bool

    NEVER exposes secrets through:
        subprocess argv
        log output
        temporary files
        exception messages

    Default bindings: _NativeSecurityBindings (loads Security.framework lazily).
    Test bindings:    _MockSecurityBindings (injected via constructor).

    NATIVE VALIDATION NOT PERFORMED.
    """

    def __init__(
        self,
        bindings: Optional[_NativeSecurityBindings | _MockSecurityBindings] = None,
    ) -> None:
        """
        Initialize SecurityFrameworkBackend.

        Args:
            bindings: Optional Security.framework bindings. If None, attempts
                      to load _NativeSecurityBindings (macOS only). Tests
                      inject _MockSecurityBindings to avoid framework loading.
        """
        self._bindings = bindings
        self._available_flag: bool = False

        if bindings is not None:
            # Injected (test) bindings — always "available"
            self._available_flag = True
            logger.debug("SecurityFrameworkBackend: using injected bindings")
            return

        # Lazy-load native bindings (only on macOS)
        if sys.platform != "darwin":
            logger.warning(
                "SecurityFrameworkBackend: not on macOS — backend unavailable. "
                "Windows CI: this is expected."
            )
            return

        try:
            self._bindings = _NativeSecurityBindings()
            self._available_flag = True
            logger.info("SecurityFrameworkBackend: Security.framework loaded successfully")
        except Exception as exc:
            logger.error(
                "SecurityFrameworkBackend: failed to load Security.framework: %s", exc
            )
            self._available_flag = False

    def available(self) -> bool:
        """Return True if Security.framework is available and loaded."""
        return self._available_flag and self._bindings is not None

    # ── store ─────────────────────────────────────────────────────────────────

    def store(self, service: str, account: str, secret_bytes: bytes) -> bool:
        """
        Store secret_bytes in the Keychain under (service, account).

        Uses SecItemAdd. If the item already exists (errSecDuplicateItem),
        falls through to SecItemUpdate.

        Binary-safe: secret_bytes is passed directly as CFData.
        No hex encoding. No subprocess.

        Returns True on success, False on failure.
        """
        if not self.available():
            logger.warning("store: SecurityFrameworkBackend not available")
            return False

        if not secret_bytes:
            logger.warning("store: empty secret bytes — rejecting")
            return False

        status = self._bindings.sec_item_add(service, account, secret_bytes)

        if status == OSStatus.errSecSuccess:
            logger.info("Keychain SecItemAdd succeeded [service=%s]", service)
            return True

        if status == OSStatus.errSecDuplicateItem:
            logger.info("Keychain item exists (errSecDuplicateItem) — updating [service=%s]", service)
            return self.update(service, account, secret_bytes)

        logger.error(
            "Keychain SecItemAdd failed [service=%s]: %s",
            service, OSStatus.name(status),
        )
        return False

    # ── retrieve ──────────────────────────────────────────────────────────────

    def retrieve(self, service: str, account: str) -> Optional[bytes]:
        """
        Retrieve secret from the Keychain under (service, account).

        Uses SecItemCopyMatching. Returns binary CFData as Python bytes.
        Returns None if item not found or on error.

        Binary-safe: handles null bytes and arbitrary binary data.
        """
        if not self.available():
            logger.warning("retrieve: SecurityFrameworkBackend not available")
            return None

        status, data = self._bindings.sec_item_copy_matching(service, account)

        if status == OSStatus.errSecSuccess and data is not None:
            logger.info(
                "Keychain SecItemCopyMatching succeeded [service=%s, len=%d]",
                service, len(data),
            )
            return data

        if status == OSStatus.errSecItemNotFound:
            logger.debug("Keychain item not found [service=%s]", service)
            return None

        if status == OSStatus.errSecInteractionNotAllowed:
            logger.error(
                "Keychain retrieve: interaction not allowed [service=%s] — "
                "likely running headless (LaunchDaemon) with a locked keychain",
                service,
            )
            return None

        if status == OSStatus.errSecAuthFailed:
            logger.error(
                "Keychain retrieve: authorization failed [service=%s]", service
            )
            return None

        logger.error(
            "Keychain SecItemCopyMatching failed [service=%s]: %s",
            service, OSStatus.name(status),
        )
        return None

    # ── update ────────────────────────────────────────────────────────────────

    def update(self, service: str, account: str, secret_bytes: bytes) -> bool:
        """
        Update an existing Keychain item with new secret_bytes.

        Uses SecItemUpdate. If the item is not found, returns False.

        Binary-safe.
        """
        if not self.available():
            return False

        if not secret_bytes:
            logger.warning("update: empty secret bytes — rejecting")
            return False

        status = self._bindings.sec_item_update(service, account, secret_bytes)

        if status == OSStatus.errSecSuccess:
            logger.info("Keychain SecItemUpdate succeeded [service=%s]", service)
            return True

        if status == OSStatus.errSecItemNotFound:
            logger.warning(
                "Keychain SecItemUpdate: item not found [service=%s] — cannot update",
                service,
            )
            return False

        logger.error(
            "Keychain SecItemUpdate failed [service=%s]: %s",
            service, OSStatus.name(status),
        )
        return False

    # ── delete ────────────────────────────────────────────────────────────────

    def delete(self, service: str, account: str) -> bool:
        """
        Delete a Keychain item.

        Uses SecItemDelete. Returns True if deleted or not found (idempotent).
        """
        if not self.available():
            return False

        status = self._bindings.sec_item_delete(service, account)

        if status == OSStatus.errSecSuccess:
            logger.info("Keychain SecItemDelete succeeded [service=%s]", service)
            return True

        if status == OSStatus.errSecItemNotFound:
            # Already gone — idempotent success
            logger.debug("Keychain SecItemDelete: item not found (idempotent) [service=%s]", service)
            return True

        logger.warning(
            "Keychain SecItemDelete failed [service=%s]: %s",
            service, OSStatus.name(status),
        )
        return False
