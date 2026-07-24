# SPDX-License-Identifier: Apache-2.0
"""COMPRESS_XPRESS (0x3) -- ESE record framing over MS-XCA Plain LZ77.

Implements the ESE scheme ``COMPRESS_XPRESS``: a 3-byte header (scheme byte + u16
little-endian uncompressed size) wrapping a raw MS-XCA Plain LZ77 stream. The raw
codec itself lives in :mod:`ntcompress.ntdll.xpress` so it can be reused outside ESE;
this module only adds and strips the ESE frame.

Frame layout, per the MIT ESE source (``ErrCompressXpress_``,
``compression.cxx:1507-1568``; ``ErrDecompressXpress_``, ``:2275-2347``)::

    offset 0:     u8   scheme byte = COMPRESS_XPRESS << 3 = 0x18   (compression.cxx:1551)
    offset 1..2:  u16  uncompressed size, little-endian            (compression.cxx:1549-1552)
    offset 3..:   raw Plain LZ77 stream ([MS-XCA] §2.3 / §2.4)

The u16 size field caps a single cell's plaintext at 65535 bytes
(``Assert( data.Cb() <= wMax )``, compression.cxx:1518), and ESE stores a compressed
cell only when it is strictly smaller than the plaintext (``errRECCannotCompress``
otherwise, compression.cxx:1541-1545). Dispatch is on the top 5 bits of byte 0
(``bIdentifier = bHeader >> 3``, compression.cxx:2294), not the whole byte, so a
hypothetical nonzero flag bit does not misroute.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ntcompress.exceptions import CompressionError, DecompressionError, IncompressibleError
from ntcompress.ntdll import xpress as lzxpress

if TYPE_CHECKING:
    from ntcompress._types import Buffer

HEADER_SIZE: Final = 3
"""ESE XPRESS frame size: ``sizeof(BYTE) + sizeof(WORD)`` (compression.cxx:1528, :2300)."""

MAX_UNCOMPRESSED: Final = 0xFFFF
"""Largest plaintext one cell can record in its u16 size field (compression.cxx:1518)."""


def _signature() -> int:
    """Compute the XPRESS scheme byte (deferred to avoid circular import at module level)."""
    from ntcompress.ese import Format, header_byte

    return header_byte(Format.XPRESS)


def _uncompressed_size(blob: Buffer) -> int:
    """Validate the 3-byte frame and read its u16 LE uncompressed size.

    Ports the entry checks of ``ErrDecompressXpress_`` (compression.cxx:2290-2301):
    the cell must hold the full header, and byte 0's top 5 bits must carry
    COMPRESS_XPRESS. The low 3 flag bits are ignored, matching ESE's own
    ``bHeader >> 3`` dispatch.

    Raises:
        DecompressionError: The buffer is shorter than 3 bytes or carries a
            different format id.
    """
    from ntcompress.ese import Format, format_id

    if len(blob) < HEADER_SIZE:
        msg = f"an XPRESS cell needs the {HEADER_SIZE}-byte header, got {len(blob)} byte(s)"
        raise DecompressionError(msg)
    raw = format_id(blob[0])
    if raw != Format.XPRESS:
        msg = f"cell header carries format id 0x{raw:x}, not XPRESS (0x{Format.XPRESS:x})"
        raise DecompressionError(msg)
    return int.from_bytes(blob[1:HEADER_SIZE], "little")


def decompress(blob: Buffer, *, verify: bool = True) -> bytes:
    """Decode an XPRESS (0x3) cell to plaintext.

    Strips the 3-byte frame and decodes the remainder per [MS-XCA] §2.4, the
    Python equivalent of ``ErrDecompressXpress_`` handing ``pb + cbHeader`` to
    ``XpressDecode`` (compression.cxx:2301, :2316-2322).

    Args:
        blob: The framed cell, scheme byte included.
        verify: When True, require the decoded length to equal the header's
            declared size. The declared size always caps the decode regardless
            of this flag.

    Raises:
        DecompressionError: Truncated or mis-schemed frame, an invalid payload
            stream, a decode that overruns the declared size, or (with
            ``verify``) a decoded-size mismatch.
    """
    declared = _uncompressed_size(blob)
    plaintext = lzxpress.decompress(blob[HEADER_SIZE:], max_size=declared)
    if verify and len(plaintext) != declared:
        msg = f"header declares {declared} plaintext byte(s) but the stream decoded to {len(plaintext)}"
        raise DecompressionError(msg)
    return plaintext


def compress(data: Buffer) -> bytes:
    """Encode plaintext into an XPRESS (0x3) cell.

    Mirrors ``ErrCompressXpress_`` (compression.cxx:1507-1568): encode the
    payload per [MS-XCA] §2.3, prepend the 0x18 scheme byte and the u16 LE
    plaintext size, and refuse to "compress" unless that saves space.

    Raises:
        CompressionError: The plaintext exceeds the 65535 bytes the u16 size
            field can record (compression.cxx:1518).
        IncompressibleError: The framed cell would not be strictly smaller than
            the plaintext -- ESE's ``errRECCannotCompress`` policy
            (compression.cxx:1541-1545).
    """
    size = len(data)
    if size > MAX_UNCOMPRESSED:
        msg = f"an XPRESS cell records its plaintext size in a u16, so at most {MAX_UNCOMPRESSED} bytes fit; got {size}"
        raise CompressionError(msg)
    payload = lzxpress.compress(data)
    if HEADER_SIZE + len(payload) >= size:
        msg = f"compressed cell would be {HEADER_SIZE + len(payload)} byte(s), not smaller than the {size}-byte plaintext"
        raise IncompressibleError(msg)
    sig = _signature()
    return sig.to_bytes(1, "little") + size.to_bytes(2, "little") + payload


def decompressed_size(blob: Buffer) -> int:
    """Return the u16 uncompressed size from the frame, without decoding (compression.cxx:2290-2291)."""
    return _uncompressed_size(blob)
