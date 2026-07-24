# SPDX-License-Identifier: Apache-2.0
"""Checksums used by ESE compression headers.

Two non-stdlib CRCs are required, and both are implemented here from their literal
parameters. Python's :func:`zlib.crc32` uses a different polynomial and must not be
substituted for either.

* :func:`crc32c_ese` -- CRC-32C / Castagnoli (reflected polynomial ``0x82F63B78``,
  normal form ``0x1EDC6F41``; init/xorout ``0xFFFFFFFF``): the "SSE 4.2 compatible" CRC
  computed over the XPRESS10 plaintext. Verified check value
  ``crc32c_ese(b"123456789") == 0xE3069283``.
* :func:`crc64_ese` -- reflected polynomial ``0x9A6C9329AC4BC9B5``, init/xorout
  all-ones: the "Corsica compatible" CRC computed over the XPRESS10 compressed
  payload. Verified check value ``crc64_ese(b"123456789") == 0xAE8B14860A799888``.
  This parameterization is **CRC-64/NVME** (RevEng catalogue: normal polynomial
  ``0xAD93D23594C93659``, reflected ``0x9A6C9329AC4BC9B5``, init/xorout all-ones,
  refin/refout, check ``0xAE8B14860A799888``). It is NOT CRC-64/XZ (reflected poly
  ``0xC96C5795D7870F42``); do not use a library preset named ``crc64('xz')``.

Both are little-endian / reflected CRCs, so a right-shifting byte-wise table drives
them. The polynomials are already given in reflected form.

Authority: ``dev/ese/src/_xpress10/xpress10sw.cxx:34-59`` (the CRC-64 bit loop, poly
``CORSICA_CRC64_POLY``) and ESE ``Crc32Checksum`` in ``dev/ese/src/os/encrypt.cxx``
(CRC-32C).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from ntcompress._types import Buffer

# --- Polynomials (reflected / LSB-first form) ---

CRC32C_POLY: Final = 0x82F63B78
"""Reflected CRC-32C (Castagnoli) polynomial (normal form 0x1EDC6F41)."""

CRC64_ESE_POLY: Final = 0x9A6C9329AC4BC9B5
"""Reflected CRC-64/NVME polynomial (xpress10sw.cxx:35, ``CORSICA_CRC64_POLY``). Not CRC-64/XZ."""

_MASK32: Final = 0xFFFFFFFF
_MASK64: Final = 0xFFFFFFFFFFFFFFFF


def _make_table(poly: int, mask: int) -> tuple[int, ...]:
    """Build a 256-entry byte-wise lookup table for a reflected (right-shifting) CRC."""
    table: list[int] = []
    for index in range(256):
        crc = index
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
            crc &= mask
        table.append(crc)
    return tuple(table)


_CRC32C_TABLE: Final = _make_table(CRC32C_POLY, _MASK32)
_CRC64_TABLE: Final = _make_table(CRC64_ESE_POLY, _MASK64)


def crc32c_ese(data: Buffer) -> int:
    """Return the CRC-32C (Castagnoli) of ``data``, as ESE stores it in headers.

    Reflected, init/xorout ``0xFFFFFFFF``. This is the "SSE 4.2 compatible" checksum
    ESE computes over uncompressed data (``Crc32Checksum``); the XPRESS10 header
    stores it over the plaintext.

    Args:
        data: The bytes to checksum.

    Returns:
        The 32-bit CRC-32C. ``crc32c_ese(b"123456789") == 0xE3069283``.
    """
    crc = _MASK32
    for byte in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ _MASK32


def crc64_ese(data: Buffer) -> int:
    """Return the ESE/Corsica CRC-64 of ``data``.

    Reflected poly ``0x9A6C9329AC4BC9B5``, init/xorout all-ones -- the CRC-64/NVME
    parameterization. The XPRESS10 header stores this over the compressed payload
    (``UtilGenCorsicaCrc64``, ``xpress10sw.cxx:34-59``).

    Args:
        data: The bytes to checksum.

    Returns:
        The 64-bit CRC. ``crc64_ese(b"123456789") == 0xAE8B14860A799888``.
    """
    crc = _MASK64
    for byte in data:
        crc = (crc >> 8) ^ _CRC64_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ _MASK64
