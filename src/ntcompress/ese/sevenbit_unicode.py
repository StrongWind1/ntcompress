# SPDX-License-Identifier: Apache-2.0
"""COMPRESS_7BITUNICODE (0x2) -- 7-bit Unicode packing for ESE records.

Identical bitstream to 7BITASCII; only the source stride (2 bytes) and the
``0x00`` high-byte re-emission on decode differ. Authority:
``ErrCompress7BitUnicode_`` (compression.cxx:1390-1504) and
``ErrDecompress7BitUnicode_`` (:2188-2272).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ntcompress.ese._sevenbit import (
    _BYTE_BITS,
    UNIT_BITS,
    UNIT_MASK,
    _check_padding,
    _frame,
    _parse_header,
    _unpack_units,
)
from ntcompress.exceptions import CompressionError, IncompressibleError

if TYPE_CHECKING:
    from ntcompress._types import Buffer

_WIDE_STRIDE: Final = 2
"""Bytes per UTF-16LE code unit (sizeof(WORD), compression.cxx:1002)."""


def decompress(blob: Buffer) -> bytes:
    """Unpack a 7BITUNICODE cell to UTF-16LE plaintext bytes.

    Per ``ErrDecompress7BitUnicode_`` (compression.cxx:2188-2272): emit each
    unpacked 7-bit value followed by a ``0x00`` high byte (:2251-2255) to
    reconstruct the little-endian code units.
    """
    from ntcompress.ese import Format

    data = bytes(blob)
    header = _parse_header(data, Format.SEVEN_BIT_UNICODE)
    _check_padding(data, header)
    out = bytearray(header.unit_count * _WIDE_STRIDE)
    out[::_WIDE_STRIDE] = _unpack_units(data[1:], header.unit_count)
    return bytes(out)


def compress(data: Buffer) -> bytes:
    """Pack 7-bit-clean UTF-16LE text into a framed 7BITUNICODE cell.

    Per ``ErrCompress7BitUnicode_`` (compression.cxx:1390-1504), with the
    applicability rules of ``Calculate7BitCompressionScheme_`` (:1007-1118):
    the input must be an even number of bytes, every code unit must be
    ``<= 0x007f``, and the result must beat the plaintext.
    """
    from ntcompress.ese import Format

    raw = bytes(data)
    if len(raw) % _WIDE_STRIDE:
        msg = f"7BITUNICODE input must be whole UTF-16LE code units, got {len(raw)} byte(s)"
        raise CompressionError(msg)
    units = raw[::_WIDE_STRIDE]
    if any(raw[1::_WIDE_STRIDE]) or any(byte > UNIT_MASK for byte in units):
        msg = "7BITUNICODE requires every UTF-16LE code unit <= 0x007f"
        raise CompressionError(msg)
    # CbCompressed7BitUnicode_ (compression.cxx:1002), accepted only if < cbData (:1109).
    compressed_size = (len(units) * UNIT_BITS + _BYTE_BITS - 1) // _BYTE_BITS + 1
    if compressed_size >= len(raw):
        msg = f"7BITUNICODE would pack {len(raw)} byte(s) into {compressed_size}; ESE stores such cells uncompressed"
        raise IncompressibleError(msg)
    return _frame(Format.SEVEN_BIT_UNICODE, units)


def decompressed_size(blob: Buffer) -> int:
    """Return the plaintext byte length of a 7BITUNICODE cell without decoding.

    The exact ESE formula: ``cwTotal = ((Cb - 2) * 8 + cbitFinal) // 7`` code
    units, times ``sizeof(WORD)`` (compression.cxx:2210-2216).
    """
    from ntcompress.ese import Format

    return _parse_header(bytes(blob), Format.SEVEN_BIT_UNICODE).unit_count * _WIDE_STRIDE
