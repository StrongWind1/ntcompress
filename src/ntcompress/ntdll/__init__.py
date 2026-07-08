"""ntdll.dll ``RtlCompressBuffer`` / ``RtlDecompressBuffer`` compression formats.

Provides both Shape A (enum dispatch) and Shape B (direct module import) APIs for
every raw stream compression format exposed by Windows ntdll.dll. The ``Format``
enum values are the actual ``COMPRESSION_FORMAT_*`` constants from ``ntifs.h``
(values 0x0002--0x0004), plus library extensions for related MS-XCA codecs at
0x0100+.

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

    Values 0x0002--0x0004 are the ``COMPRESSION_FORMAT_*`` constants from ``ntifs.h``.
    Values 0x0100+ are library extensions for related MS-XCA codecs not exposed
    through the ``RtlCompressBuffer`` API.
    """

    LZNT1 = 0x0002
    """``COMPRESSION_FORMAT_LZNT1`` -- chunk-based LZ77 ([MS-XCA] §2.5)."""

    XPRESS = 0x0003
    """``COMPRESSION_FORMAT_XPRESS`` -- Plain LZ77 ([MS-XCA] §2.1)."""

    XPRESS_HUFF = 0x0004
    """``COMPRESSION_FORMAT_XPRESS_HUFF`` -- LZ77+Huffman ([MS-XCA] §2.2)."""

    DEFLATE = 0x0100
    """Extension -- raw DEFLATE (RFC 1951). Not a Windows constant."""

    ZLIB = 0x0101
    """Extension -- ZLIB wrapper (RFC 1950). Not a Windows constant."""


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

from ntcompress.ntdll import deflate, lznt1, xpress, xpress_huff, zlib  # noqa: E402

_register(Format.LZNT1, lznt1)
_register(Format.XPRESS, xpress)
_register(Format.XPRESS_HUFF, xpress_huff)
_register(Format.DEFLATE, deflate)
_register(Format.ZLIB, zlib)
