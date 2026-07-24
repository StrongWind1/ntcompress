# SPDX-License-Identifier: Apache-2.0
"""ESE (Extensible Storage Engine) record-compression formats.

Provides both Shape A (enum dispatch) and Shape B (direct module import) APIs for
every ESE record-compression scheme. The ``Format`` enum values are the 5-bit scheme
IDs extracted from the first byte of a compressed ESE cell, matching the
``CDataCompressor::COMPRESSION_SCHEME`` constants in the MIT ESE source.

Shape A (enum dispatch)::

    import ntcompress.ese
    compressed = ntcompress.ese.compress(data, ntcompress.ese.Format.XPRESS)
    plain = ntcompress.ese.decompress(compressed)  # auto-detects format

Shape B (direct module)::

    from ntcompress.ese import xpress
    compressed = xpress.compress(data)
    plain = xpress.decompress(compressed)
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Final

from ntcompress.ese._registry import _get, _register
from ntcompress.exceptions import (
    CompressionError,
    DecompressionError,
    FormatUnavailableError,
    ScrubDetectedError,
)

if TYPE_CHECKING:
    from ntcompress._types import Buffer


# --- Header bit layout ---

_SCHEME_SHIFT: Final = 3
"""Bit offset of the 5-bit format id within the header byte (compression.cxx:2003)."""

_FLAG_MASK: Final = 0b0000_0111
"""Mask selecting the low 3 format-specific flag bits of the header byte."""


class Format(IntEnum):
    """ESE record-compression format identifiers.

    Values are the 5-bit scheme IDs extracted from the first byte of a compressed
    ESE cell. See ``CDataCompressor::COMPRESSION_SCHEME`` in the MIT-licensed ESE
    source (``compression.cxx:504-512``).
    """

    NONE = 0x00
    """Sentinel -- uncompressed cell, no compression header."""

    SEVEN_BIT_ASCII = 0x01
    """7-bit ASCII packing (compression.cxx:1168-1387)."""

    SEVEN_BIT_UNICODE = 0x02
    """7-bit Unicode packing over UTF-16LE code units (compression.cxx:1390-1504)."""

    XPRESS = 0x03
    """Plain LZ77 ([MS-XCA] §2.1) with 3-byte ESE frame (compression.cxx:1507-1568)."""

    SCRUB = 0x04
    """Erase marker -- not a compression format. Use :mod:`ntcompress.ese.scrub`."""

    XPRESS9 = 0x05
    """LZ77+Huffman9 with ESE frame (compression.cxx:1686-1759)."""

    XPRESS10 = 0x06
    """LZ4 block + CRC-32C/CRC-64 integrity (compression.cxx:1935-2064)."""

    LZ4 = 0x07
    """Raw LZ4 block with 3-byte ESE frame (compression.cxx:2070-2109)."""

    MAXIMUM = 0x1F
    """Sentinel -- upper bound of the 5-bit scheme space, not a real format."""


# --- First-byte helpers ---


def format_id(first_byte: int) -> int:
    """Extract the 5-bit format ID from an ESE cell's header byte.

    Returns ``first_byte >> 3`` (0-31). Callers map this to a :class:`Format` member.
    """
    return first_byte >> _SCHEME_SHIFT


def format_flags(first_byte: int) -> int:
    """Extract the 3 format-specific flag bits from an ESE cell's header byte.

    Returns ``first_byte & 0x7``. Meaning is format-specific.
    """
    return first_byte & _FLAG_MASK


def header_byte(fmt: Format, flags: int = 0) -> int:
    """Build a record header byte from a format id and optional flag bits.

    Returns ``(fmt << 3) | (flags & 0x7)``.
    """
    return (fmt << _SCHEME_SHIFT) | (flags & _FLAG_MASK)


# --- Shape A dispatch ---


def _format_of(blob: Buffer) -> Format:
    """Resolve a buffer's leading byte to a :class:`Format`, or raise."""
    if len(blob) == 0:
        msg = "cannot read a compression format from an empty buffer"
        raise DecompressionError(msg)
    raw = format_id(blob[0])
    try:
        fmt = Format(raw)
    except ValueError:
        msg = f"unknown ESE compression format id 0x{raw:x}"
        raise DecompressionError(msg) from None
    if fmt is Format.MAXIMUM:
        msg = f"Format.MAXIMUM (0x{raw:x}) is a sentinel value, not a compression format"
        raise DecompressionError(msg)
    return fmt


def compress(data: Buffer, fmt: Format) -> bytes:
    """Encode plaintext into a framed ESE cell using the specified format.

    Args:
        data: The plaintext to compress.
        fmt: The ESE compression format to use.

    Raises:
        CompressionError: The format is a sentinel (NONE, SCRUB, MAXIMUM), or the
            input cannot be encoded by the requested format.
        FormatUnavailableError: No codec is registered, or the codec does not
            support compression (decode-only).
    """
    if fmt is Format.NONE:
        msg = "Format.NONE is not a compression format"
        raise CompressionError(msg)
    if fmt is Format.SCRUB:
        msg = "Format.SCRUB is not a compression format — use ntcompress.ese.scrub"
        raise CompressionError(msg)
    if fmt is Format.MAXIMUM:
        msg = "Format.MAXIMUM is a sentinel value, not a compression format"
        raise CompressionError(msg)
    module = _get(fmt)
    if not hasattr(module, "compress"):
        msg = f"format {fmt.name} (0x{fmt.value:x}) is decode-only; no encoder is available"
        raise FormatUnavailableError(msg)
    return module.compress(data)


def decompress(blob: Buffer, fmt: Format | None = None) -> bytes:
    """Decode a framed ESE cell.

    When ``fmt`` is None, the format is auto-detected from the header byte.

    Args:
        blob: The framed cell, including the header byte.
        fmt: The format to use, or None for auto-detection.

    Raises:
        DecompressionError: Empty buffer, unknown format id, or decode failure.
        ScrubDetectedError: The record is a SCRUB (0x4) erase marker.
        FormatUnavailableError: The format is known but no codec is registered.
    """
    if fmt is None:
        fmt = _format_of(blob)
    if fmt is Format.NONE:
        msg = "Format.NONE has no compression header; pass the raw cell body instead"
        raise DecompressionError(msg)
    if fmt is Format.SCRUB:
        msg = "record is a SCRUB erase marker; no plaintext is recoverable — use ntcompress.ese.scrub"
        raise ScrubDetectedError(msg)
    if fmt is Format.MAXIMUM:
        msg = "Format.MAXIMUM is a sentinel value, not a compression format"
        raise DecompressionError(msg)
    return _get(fmt).decompress(blob)


def decompressed_size(blob: Buffer) -> int:
    """Return a framed cell's recorded plaintext length without decoding.

    Auto-detects the format from the header byte.

    Raises:
        DecompressionError: Empty buffer or unknown format id.
        ScrubDetectedError: The record is a SCRUB erase marker.
        FormatUnavailableError: The format is known but no codec is registered.
    """
    fmt = _format_of(blob)
    if fmt is Format.NONE:
        msg = "Format.NONE has no compression header; the size is the raw body length"
        raise DecompressionError(msg)
    if fmt is Format.SCRUB:
        msg = "record is a SCRUB erase marker; it has no decompressed size — use ntcompress.ese.scrub"
        raise ScrubDetectedError(msg)
    return _get(fmt).decompressed_size(blob)


# --- Auto-registration of codec modules ---

from ntcompress.ese import lz4, sevenbit_ascii, sevenbit_unicode, xpress, xpress9, xpress10  # noqa: E402

_register(Format.SEVEN_BIT_ASCII, sevenbit_ascii)
_register(Format.SEVEN_BIT_UNICODE, sevenbit_unicode)
_register(Format.XPRESS, xpress)
_register(Format.XPRESS9, xpress9)
_register(Format.XPRESS10, xpress10)
_register(Format.LZ4, lz4)
