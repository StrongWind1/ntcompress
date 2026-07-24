# SPDX-License-Identifier: Apache-2.0
"""ntdll.dll ``RtlCompressBuffer`` / ``RtlDecompressBuffer`` compression formats.

Provides both Shape A (enum dispatch) and Shape B (direct module import) APIs for
every raw stream compression format exposed by Windows ntdll.dll. The ``Format``
enum values are the actual ``CompressionFormatAndEngine`` constants from ``ntifs.h``
(values 0x0002--0x0008).

Shape A (enum dispatch)::

    import ntcompress.ntdll
    compressed = ntcompress.ntdll.compress(data, ntcompress.ntdll.Format.LZNT1)
    plain = ntcompress.ntdll.decompress(compressed, ntcompress.ntdll.Format.LZNT1)

Shape B (direct module)::

    from ntcompress.ntdll import lznt1
    compressed = lznt1.compress(data)
    plain = lznt1.decompress(compressed)
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING

from ntcompress.ntdll._registry import _get, _register

if TYPE_CHECKING:
    from ntcompress._types import Buffer


class Format(IntEnum):
    """Compression format identifiers for ntdll.dll RtlCompressBuffer/RtlDecompressBuffer.

    Values 0x0002--0x0008 are the ``CompressionFormatAndEngine`` base-format constants
    from ``ntifs.h``. Not all formats are available on all Windows builds; see the
    per-member docstrings for minimum build numbers.
    """

    LZNT1 = 0x0002
    """``COMPRESSION_FORMAT_LZNT1`` -- chunk-based LZ77 ([MS-XCA] §2.5). XP+."""

    XPRESS = 0x0003
    """``COMPRESSION_FORMAT_XPRESS`` -- Plain LZ77 ([MS-XCA] §2.1). Win8.1+."""

    XPRESS_HUFF = 0x0004
    """``COMPRESSION_FORMAT_XPRESS_HUFF`` -- LZ77+Huffman ([MS-XCA] §2.2). Win8.1+."""

    XPRESS9 = 0x0005
    """Compact XPRESS9 -- canonical Huffman LZ77, magic ``0xC039E510``. Server 2022+ (Build 20348+)."""

    XP10 = 0x0006
    """XP10 -- raw LZ4 block format. Win11 / Server 2025 (Build 26100+)."""

    DEFLATE = 0x0007
    """Raw DEFLATE (RFC 1951, wbits=-15). Win11 / Server 2025 (Build 26100+)."""

    ZLIB = 0x0008
    """ZLIB wrapper (RFC 1950, wbits=15). Win11 / Server 2025 (Build 26100+)."""


# --- Windows constant aliases ---

COMPRESSION_FORMAT_LZNT1 = Format.LZNT1
"""Alias for ``Format.LZNT1`` (0x0002), matching the ``ntifs.h`` constant name."""

COMPRESSION_FORMAT_XPRESS = Format.XPRESS
"""Alias for ``Format.XPRESS`` (0x0003), matching the ``ntifs.h`` constant name."""

COMPRESSION_FORMAT_XPRESS_HUFF = Format.XPRESS_HUFF
"""Alias for ``Format.XPRESS_HUFF`` (0x0004), matching the ``ntifs.h`` constant name."""


# --- Shape A dispatch ---


def compress(data: Buffer, fmt: Format) -> bytes:
    """Compress plaintext using the specified ntdll format.

    Dispatches to the per-format ``compress()`` function.

    Args:
        data: The plaintext to compress.
        fmt: The compression format to use.

    Returns:
        The compressed stream.

    Raises:
        FormatUnavailableError: No codec is registered for the format.
    """
    return _get(fmt).compress(data)


def decompress(blob: Buffer, fmt: Format) -> bytes:
    """Decompress a raw stream using the specified ntdll format.

    Unlike ESE dispatch, there is no auto-detection -- raw ntdll streams carry no
    format header, so the caller must specify which format was used.

    Args:
        blob: The compressed stream.
        fmt: The compression format that was used to produce the stream.

    Returns:
        The decompressed plaintext.

    Raises:
        FormatUnavailableError: No codec is registered for the format.
    """
    return _get(fmt).decompress(blob)


# --- Auto-registration of codec modules ---

from ntcompress.ntdll import deflate, lznt1, xp10, xpress, xpress9, xpress_huff, zlib  # noqa: E402

_register(Format.LZNT1, lznt1)
_register(Format.XPRESS, xpress)
_register(Format.XPRESS_HUFF, xpress_huff)
_register(Format.XPRESS9, xpress9)
_register(Format.XP10, xp10)
_register(Format.DEFLATE, deflate)
_register(Format.ZLIB, zlib)
