# SPDX-License-Identifier: Apache-2.0
"""XP10 raw LZ4 block codec (``COMPRESSION_FORMAT_XP10``, 0x0006).

Windows ntdll.dll exposes raw LZ4 block compression as ``CompressionFormatAndEngine``
0x0006 (default engine) and 0x0106 (ENGINE_MAXIMUM). Available on Win11 / Server 2025
(Build 26100+).

The bitstream is the standard LZ4 *block* format -- the same codec used by ESE
XPRESS10 (scheme 0x06), but without the 15-byte ESE header. The uncompressed size
is not stored in the stream; the caller must supply it.

Thin wrapper over :mod:`ntcompress.ese.lz4` block-level functions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ntcompress.ese.lz4 import compress_block, decompress_block

if TYPE_CHECKING:
    from ntcompress._types import Buffer


def decompress(data: Buffer, /, uncompressed_size: int = 0) -> bytes:
    """Decompress a raw LZ4 block.

    Args:
        data: The compressed LZ4 block payload.
        uncompressed_size: Expected decompressed size. Required because the LZ4
            block format does not store the original size.

    Returns:
        The decompressed bytes.
    """
    return decompress_block(data, uncompressed_size)


def compress(data: Buffer, /) -> bytes:
    """Compress data into a raw LZ4 block.

    Produces byte-identical output to ``RtlCompressBuffer(0x0006)`` on Windows.

    Args:
        data: The plaintext to compress.

    Returns:
        The compressed LZ4 block.
    """
    return compress_block(data)
