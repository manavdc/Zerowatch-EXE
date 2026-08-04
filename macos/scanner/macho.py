"""
macos/scanner/macho.py
─────────────────────────────────────────────────────────────────────────────
Static Mach-O binary detection and classification.

Reads only the first 8 bytes (the minimum needed to identify Mach-O magic
and CPU type). The file is never executed, loaded, or fully parsed.

Supported magic values:
  0xFEEDFACE  Mach-O 32-bit little-endian
  0xCEFAEDFE  Mach-O 32-bit big-endian (byte-swapped on disk)
  0xFEEDFACF  Mach-O 64-bit little-endian
  0xCFFAEDFE  Mach-O 64-bit big-endian
  0xCAFEBABE  Universal / Fat binary (multi-arch)
  0xBEBAFECA  Universal binary big-endian

Reference: mach-o/loader.h — Apple OSS
"""

from __future__ import annotations

import struct
from enum import Enum, auto
from typing import Optional

# ── Mach-O magic constants ────────────────────────────────────────────────────

_MH_MAGIC       = 0xFEEDFACE   # 32-bit LE
_MH_CIGAM       = 0xCEFAEDFE   # 32-bit BE (byte-swapped)
_MH_MAGIC_64    = 0xFEEDFACF   # 64-bit LE
_MH_CIGAM_64    = 0xCFFAEDFE   # 64-bit BE (byte-swapped)
_FAT_MAGIC      = 0xCAFEBABE   # Fat / Universal LE
_FAT_CIGAM      = 0xBEBAFECA   # Fat / Universal BE

_MACHO_MAGICS = frozenset({
    _MH_MAGIC, _MH_CIGAM, _MH_MAGIC_64, _MH_CIGAM_64, _FAT_MAGIC, _FAT_CIGAM,
})

_FAT_MAGICS = frozenset({_FAT_MAGIC, _FAT_CIGAM})

# Mach-O filetype constants (from mach-o/loader.h)
_MH_EXECUTE  = 0x00000002  # executable
_MH_DYLIB    = 0x00000006  # shared library
_MH_BUNDLE   = 0x00000008  # loadable bundle (plug-in)
_MH_DYLINKER = 0x00000007  # dynamic linker

_HEADER_READ_SIZE = 32  # bytes — enough for magic + cputype + cpusubtype + filetype


class MachOKind(Enum):
    """Classification of a detected Mach-O binary."""
    EXECUTABLE  = auto()   # MH_EXECUTE — standalone program
    DYLIB       = auto()   # MH_DYLIB   — dynamic library
    BUNDLE      = auto()   # MH_BUNDLE  — plug-in / loadable bundle
    FAT         = auto()   # Universal binary (contains multiple arch slices)
    GENERIC     = auto()   # Other Mach-O (dylinker, core, etc.)


def detect_macho(filepath: str) -> Optional[MachOKind]:
    """
    Read the first few bytes of a file and determine if it is Mach-O.

    Returns:
        MachOKind if the file starts with a recognised Mach-O magic value.
        None if the file is not Mach-O, cannot be read, or is empty.

    Never executes the binary.
    """
    try:
        with open(filepath, "rb") as fh:
            header = fh.read(_HEADER_READ_SIZE)
    except (PermissionError, OSError, IsADirectoryError):
        return None

    if len(header) < 4:
        return None

    # Read magic as both big-endian and little-endian 4-byte uint
    magic_le = struct.unpack_from("<I", header, 0)[0]
    magic_be = struct.unpack_from(">I", header, 0)[0]

    # Use whichever interpretation is a known Mach-O magic
    if magic_le in _MACHO_MAGICS:
        magic = magic_le
        is_le = True
    elif magic_be in _MACHO_MAGICS:
        magic = magic_be
        is_le = False
    else:
        return None

    # Universal / Fat binaries — contain multiple arch slices
    if magic in _FAT_MAGICS:
        return MachOKind.FAT

    # For single-arch, read filetype from offset 12 (mach_header.filetype)
    # mach_header layout (LE): magic(4) + cputype(4) + cpusubtype(4) + filetype(4)
    # mach_header_64 layout:   magic(4) + cputype(4) + cpusubtype(4) + filetype(4) ...same offset
    if len(header) < 16:
        return MachOKind.GENERIC

    fmt = "<I" if is_le else ">I"
    filetype = struct.unpack_from(fmt, header, 12)[0]

    if filetype == _MH_EXECUTE:
        return MachOKind.EXECUTABLE
    if filetype == _MH_DYLIB:
        return MachOKind.DYLIB
    if filetype == _MH_BUNDLE:
        return MachOKind.BUNDLE
    return MachOKind.GENERIC


def is_macho(filepath: str) -> bool:
    """Return True if filepath is any kind of Mach-O file."""
    return detect_macho(filepath) is not None


def is_dylib(name: str) -> bool:
    """
    Return True if a filename matches dynamic library conventions.
    Covers:
      *.dylib                  Standard macOS dynamic library
      *.dylib.N.N.N            Versioned library (com.apple convention)
    """
    lower = name.lower()
    return lower.endswith(".dylib") or ".dylib." in lower
