"""COMPRESS_XPRESS10 (0x6) -- ESE framing over the LZ4 block payload format.

The XPRESS10 record carries a packed 15-byte header (scheme byte, u16 LE
uncompressed size, u32 LE CRC-32C over the plaintext, u64 LE CRC-64/NVME over
the compressed payload) with the raw XP10 payload starting at offset 15.

The XP10 payload is the standard LZ4 *block* format -- the same codec used by ESE
scheme 0x7 (COMPRESS_LZ4) and by ``RtlCompressBufferXp10`` / ``RtlDecompressBufferXp10``
in ``ntdll.dll``. Verified by decoding the ntdll format 0x0006 gold vector (52 bytes
for a 4096-byte A-Z pattern) with :func:`~ntcompress.ese.lz4.decompress_block`,
producing byte-identical plaintext. The only differences from COMPRESS_LZ4 are the
header size (15 vs 3 bytes), the presence of CRC-32C over plaintext AND CRC-64/NVME
over the compressed payload, and the scheme id (0x6 vs 0x7).

Authority: ``compression.cxx:523-532`` (packed ``Xpress10Header``, ``C_ASSERT``
size 15 at ``:1940``/``:2503``); scheme check ``(byte >> 3) == COMPRESS_XPRESS10``
(``compression.cxx:2513``); CRC-32C over plaintext (``os/encrypt.cxx:147-184``);
CRC-64/NVME over payload, reflected poly ``0x9A6C9329AC4BC9B5``
(``_xpress10/xpress10sw.cxx:34-59``). [MS-XCA] does not cover XPRESS10.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ntcompress.ese.checksums import crc32c_ese, crc64_ese
from ntcompress.ese.lz4 import compress_block, decompress_block
from ntcompress.exceptions import (
    CompressionError,
    DecompressionError,
    IncompressibleError,
    IntegrityError,
)

if TYPE_CHECKING:
    from ntcompress._types import Buffer

HEADER_SIZE: Final = 15
"""Size of the packed ``Xpress10Header`` (``C_ASSERT`` at compression.cxx:1940)."""

MAX_UNCOMPRESSED: Final = 0xFFFF
"""Maximum plaintext size for a single XPRESS10 cell (u16 ceiling)."""

_HEADER = struct.Struct("<BHIQ")
"""Little-endian packed layout of ``Xpress10Header`` (compression.cxx:523-532)."""


def _signature() -> int:
    """Compute the XPRESS10 scheme byte (deferred to avoid circular import at module level)."""
    from ntcompress.ese import Format, header_byte

    return header_byte(Format.XPRESS10)


@dataclass(frozen=True)
class Xpress10Header:
    """Parsed 15-byte ``Xpress10Header`` (compression.cxx:523-532).

    Attributes:
        uncompressed_size: ``mle_cbUncompressed`` -- plaintext length, u16 LE, so an
            XPRESS10 cell holds at most 65535 plaintext bytes (cc.hxx:246, ``wMax``).
        plaintext_crc32c: ``mle_ulUncompressedChecksum`` -- CRC-32C (Castagnoli) of
            the plaintext.
        payload_crc64: ``mle_ullCompressedChecksum`` -- "Corsica compatible"
            CRC-64/NVME of the compressed payload (the bytes from offset 15).
    """

    uncompressed_size: int
    plaintext_crc32c: int
    payload_crc64: int


def parse_header(blob: Buffer) -> Xpress10Header:
    """Parse and validate the leading 15-byte XPRESS10 header of a framed cell.

    Mirrors the entry checks of ``ErrDecompressXpress10_`` (compression.cxx:2503,
    :2513): the buffer must hold the full header, and the top five bits of byte 0
    must carry COMPRESS_XPRESS10.

    Raises:
        DecompressionError: The buffer is shorter than 15 bytes, or its format id
            is not XPRESS10.
    """
    from ntcompress.ese import Format, format_id

    if len(blob) < HEADER_SIZE:
        msg = f"XPRESS10 cell is {len(blob)} bytes; the header alone is {HEADER_SIZE}"
        raise DecompressionError(msg)
    scheme_byte, size, crc32, crc64 = _HEADER.unpack_from(blob)
    if format_id(scheme_byte) != Format.XPRESS10:
        msg = f"expected format XPRESS10 (0x{Format.XPRESS10:x}) but header byte 0x{scheme_byte:02x} carries format 0x{format_id(scheme_byte):x}"
        raise DecompressionError(msg)
    return Xpress10Header(uncompressed_size=size, plaintext_crc32c=crc32, payload_crc64=crc64)


def decompress(blob: Buffer, *, verify: bool = True) -> bytes:
    """Decompress an XPRESS10-framed cell.

    Strips the 15-byte header, optionally verifies both CRC checksums, and
    decodes the LZ4 block payload.

    Args:
        blob: The framed cell, including the 15-byte header.
        verify: When True, validate the CRC-32C over plaintext and CRC-64/NVME
            over the compressed payload.

    Raises:
        DecompressionError: Truncated buffer, wrong scheme byte, or LZ4 decode failure.
        IntegrityError: ``verify`` is True and either CRC does not match.
    """
    header = parse_header(blob)
    payload = memoryview(blob)[HEADER_SIZE:]
    if verify:
        actual_crc64 = crc64_ese(payload)
        if actual_crc64 != header.payload_crc64:
            msg = f"XPRESS10 payload CRC-64 mismatch: header says 0x{header.payload_crc64:016x}, payload hashes to 0x{actual_crc64:016x}"
            raise IntegrityError(msg)
    plaintext = decompress_block(payload, header.uncompressed_size)
    if verify:
        actual_crc32 = crc32c_ese(plaintext)
        if actual_crc32 != header.plaintext_crc32c:
            msg = f"XPRESS10 plaintext CRC-32C mismatch: header says 0x{header.plaintext_crc32c:08x}, plaintext hashes to 0x{actual_crc32:08x}"
            raise IntegrityError(msg)
    return plaintext


def compress(data: Buffer) -> bytes:
    """Compress data into an XPRESS10-framed cell.

    Encodes the plaintext as an LZ4 block, computes both CRC checksums, and
    prepends the 15-byte header.

    Raises:
        CompressionError: Plaintext exceeds the u16 size limit (65535 bytes).
        IncompressibleError: Compressed cell is not strictly smaller than plaintext.
    """
    size = len(data)
    if size > MAX_UNCOMPRESSED:
        msg = f"XPRESS10 plaintext ({size} bytes) exceeds the u16 limit ({MAX_UNCOMPRESSED})"
        raise CompressionError(msg)
    payload = compress_block(data)
    if len(payload) + HEADER_SIZE >= size:
        msg = f"XPRESS10 compressed cell ({len(payload) + HEADER_SIZE} bytes) is not smaller than plaintext ({size} bytes)"
        raise IncompressibleError(msg)
    plain_crc = crc32c_ese(data)
    pay_crc = crc64_ese(payload)
    sig = _signature()
    return _HEADER.pack(sig, size, plain_crc, pay_crc) + payload


def decompressed_size(blob: Buffer) -> int:
    """Return ``mle_cbUncompressed`` from the header (compression.cxx:2518-2524)."""
    return parse_header(blob).uncompressed_size
