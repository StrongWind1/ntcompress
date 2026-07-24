# SPDX-License-Identifier: Apache-2.0
"""COMPRESS_7BITASCII (0x1) -- 7-bit ASCII packing for ESE records.

Authority: ``ErrCompress7BitAscii_`` (compression.cxx:1168-1387) and
``ErrDecompress7BitAscii_`` (:2113-2185).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

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


def decompress(blob: Buffer) -> bytes:
    """Unpack a 7BITASCII cell to plaintext bytes."""
    from ntcompress.ese import Format

    data = bytes(blob)
    header = _parse_header(data, Format.SEVEN_BIT_ASCII)
    _check_padding(data, header)
    return bytes(_unpack_units(data[1:], header.unit_count))


def compress(data: Buffer) -> bytes:
    """Pack 7-bit-clean bytes into a framed 7BITASCII cell."""
    from ntcompress.ese import Format

    units = bytes(data)
    if any(byte > UNIT_MASK for byte in units):
        msg = "7BITASCII requires every byte <= 0x7f"
        raise CompressionError(msg)
    compressed_size = (len(units) * UNIT_BITS + _BYTE_BITS - 1) // _BYTE_BITS + 1
    if compressed_size >= len(units):
        msg = f"7BITASCII would pack {len(units)} byte(s) into {compressed_size}; ESE stores such cells uncompressed"
        raise IncompressibleError(msg)
    return _frame(Format.SEVEN_BIT_ASCII, units)


def decompressed_size(blob: Buffer) -> int:
    """Return the plaintext byte length of a 7BITASCII cell without decoding."""
    from ntcompress.ese import Format

    return _parse_header(bytes(blob), Format.SEVEN_BIT_ASCII).unit_count
