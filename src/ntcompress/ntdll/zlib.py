# SPDX-License-Identifier: Apache-2.0
"""ZLIB codec (ntdll format 0x0008, library extension ``Format.ZLIB``).

Windows ntdll.dll exposes ZLIB as ``CompressionFormatAndEngine`` 0x0008
(default engine) and 0x0108 (ENGINE_MAXIMUM). The bitstream is RFC 1950 ZLIB
(DEFLATE with a 2-byte header and 4-byte Adler-32 trailer). Available on
Win11 / Server 2025 (Build 26100+).

Thin wrapper over Python's ``zlib`` module with default ``wbits=15``.
"""

from __future__ import annotations

import zlib as _zlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ntcompress._types import Buffer


def decompress(data: Buffer, /) -> bytes:
    """Decompress a ZLIB stream (RFC 1950 header + DEFLATE + Adler-32).

    Args:
        data: The compressed ZLIB stream.

    Returns:
        The decompressed bytes.
    """
    return _zlib.decompress(bytes(data))


def compress(data: Buffer, /, *, level: int = 1) -> bytes:
    """Compress data into a ZLIB stream (RFC 1950).

    The default level (1) matches Windows ntdll.dll ``RtlCompressBuffer(0x0008)``
    byte-for-byte. Level 7 matches ENGINE_MAXIMUM (0x0108).

    Args:
        data: The plaintext to compress.
        level: Compression level 0-9 (default 1, matching ntdll default engine).

    Returns:
        The compressed ZLIB stream (2-byte header + DEFLATE + Adler-32).
    """
    return _zlib.compress(bytes(data), level)
