"""Raw DEFLATE codec (ntdll format 0x0007, library extension ``Format.DEFLATE``).

Windows ntdll.dll exposes raw DEFLATE as ``CompressionFormatAndEngine`` 0x0007
(default engine) and 0x0107 (ENGINE_MAXIMUM). The bitstream is RFC 1951 raw
deflate with no zlib or gzip wrapper. Available on Win11 / Server 2025
(Build 26100+).

Thin wrapper over Python's ``zlib`` module with ``wbits=-15`` (raw deflate).
"""

from __future__ import annotations

import zlib as _zlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ntcompress._types import Buffer


def decompress(data: Buffer, /, *, max_size: int | None = None) -> bytes:
    """Decompress a raw DEFLATE stream (RFC 1951, no zlib/gzip wrapper).

    Args:
        data: The compressed DEFLATE bitstream.
        max_size: Optional output size limit. If the decompressed output would
            exceed this, a ``zlib.error`` is raised.

    Returns:
        The decompressed bytes.
    """
    if max_size is not None:
        dc = _zlib.decompressobj(wbits=-15)
        result = dc.decompress(bytes(data), max_size)
        if dc.unconsumed_tail:
            msg = "DEFLATE output exceeds max_size"
            raise _zlib.error(msg)
        return result
    return _zlib.decompress(bytes(data), -15)


def compress(data: Buffer, /, *, level: int = 1) -> bytes:
    """Compress data into a raw DEFLATE stream (RFC 1951, no wrapper).

    The default level (1) matches Windows ntdll.dll ``RtlCompressBuffer(0x0007)``
    byte-for-byte. Level 7 matches ENGINE_MAXIMUM (0x0107).

    Args:
        data: The plaintext to compress.
        level: Compression level 0-9 (default 1, matching ntdll default engine).

    Returns:
        The compressed raw DEFLATE bitstream.
    """
    c = _zlib.compressobj(level, _zlib.DEFLATED, -15)
    return c.compress(bytes(data)) + c.flush()
