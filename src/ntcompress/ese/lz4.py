"""COMPRESS_LZ4 (0x7) -- ESE record framing over the standard LZ4 block format.

ESE does not define its own codec here: it links the reference liblz4 and calls
``LZ4_compress_default`` (compression.cxx:2085) / ``LZ4_decompress_safe_partial``
(compression.cxx:2677), so the payload is the standard LZ4 *block* format -- no LZ4
frame, no magic, no checksum, and no stored size. The plaintext length lives
out-of-band in the 3-byte ESE ``Lz4Header`` (compression.cxx:534-539): scheme byte
``COMPRESS_LZ4 << 3`` = ``0x38``, then a u16 little-endian uncompressed size. This
module implements the block format directly in Python -- no ``lz4`` dependency.

Block format (lz4_Block_format.md): each sequence is a token byte (high nibble =
literal length, low nibble = match length), optional ``0xFF``-continuation length
bytes, the literals, a 2-byte little-endian match offset, and optional match-length
continuation bytes. ``minmatch`` is 4 (the stored nibble is ``length - 4``), offset 0
is invalid, the maximum offset is 65535, matches may overlap their own output
(RLE-style), the last sequence is literals only, the last 5 bytes of a block are
literals, and the last match starts at least 12 bytes before the end.

The encoder is a greedy hash-table matcher that honours those end-of-block
invariants; it produces valid blocks that any conformant decoder (including liblz4)
accepts, but not necessarily the byte-identical output of ``LZ4_compress_default``.

Authority: ESE ``compression.cxx:2070-2109`` (``ErrCompressLz4_``) and ``:2643-2699``
(``ErrDecompressLz4_``) for the framing; ``lz4/lz4 doc/lz4_Block_format.md`` for the
payload. [MS-XCA] does not cover LZ4.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ntcompress.exceptions import CompressionError, DecompressionError, IncompressibleError

if TYPE_CHECKING:
    from ntcompress._types import Buffer

# --- ESE framing constants ---

HEADER_SIZE: Final = 3
"""Size of the packed ``Lz4Header`` (``C_ASSERT`` at compression.cxx:2083 / :2654)."""

_HEADER = struct.Struct("<BH")
"""Packed ``Lz4Header``: scheme byte, then u16 LE uncompressed size (compression.cxx:534-539)."""

MAX_UNCOMPRESSED: Final = 0xFFFF
"""``mle_cbUncompressed`` is a WORD, and ESE routes only cells of at most ``wMax`` bytes to LZ4 (compression.cxx:2080, :2761)."""

# --- LZ4 block-format constants (lz4_Block_format.md) ---

MIN_MATCH: Final = 4
"""``minmatch``: the low token nibble stores ``match_length - 4`` (lz4_Block_format.md)."""

MAX_OFFSET: Final = 0xFFFF
"""Largest encodable back-reference distance; "65536 and beyond cannot be coded" (lz4_Block_format.md)."""

_TOKEN_MAX = 15
"""Nibble value meaning "length continues in extra bytes" (lz4_Block_format.md)."""

_LENGTH_CONTINUE = 0xFF
"""Extension byte value meaning "one more length byte follows" (lz4_Block_format.md)."""

_LAST_LITERALS = 5
"""End-of-block invariant: the last 5 bytes of a block are always literals (lz4_Block_format.md)."""

_MF_LIMIT = 12
"""End-of-block invariant: the last match starts at least 12 bytes before the end (lz4_Block_format.md)."""


# --- ESE header ---


@dataclass(frozen=True)
class Lz4Header:
    """Parsed 3-byte ``Lz4Header`` (compression.cxx:534-539).

    Attributes:
        uncompressed_size: ``mle_cbUncompressed`` -- plaintext length, u16 LE. This
            is the out-of-band size channel the LZ4 block format requires but does
            not itself store (the block has no header of its own).
    """

    uncompressed_size: int


def parse_header(blob: Buffer) -> Lz4Header:
    """Parse and validate the leading 3-byte LZ4 header of a framed cell.

    Mirrors the entry checks of ``ErrDecompressLz4_``: a cell shorter than the
    header is rejected (compression.cxx:2656-2660), and the top five bits of byte 0
    must carry COMPRESS_LZ4 (compression.cxx:2664-2667).

    Raises:
        DecompressionError: The buffer is shorter than 3 bytes, or its format id is
            not LZ4.
    """
    from ntcompress.ese import Format, format_id

    if len(blob) < HEADER_SIZE:
        msg = f"LZ4 cell is {len(blob)} bytes; the header alone is {HEADER_SIZE}"
        raise DecompressionError(msg)
    scheme_byte, size = _HEADER.unpack_from(blob)
    if format_id(scheme_byte) != Format.LZ4:
        msg = f"expected format LZ4 (0x{Format.LZ4:x}) but header byte 0x{scheme_byte:02x} carries format 0x{format_id(scheme_byte):x}"
        raise DecompressionError(msg)
    return Lz4Header(uncompressed_size=size)


# --- LZ4 block decoder ---


def _read_length(src: bytes, pos: int) -> tuple[int, int]:
    """Read the ``0xFF``-continuation extension of a length nibble equal to 15.

    Per lz4_Block_format.md every extra byte (0-255) is added to the running
    length, and a byte of 255 means one more byte follows (unbounded run).

    Returns:
        The total length (starting from the nibble value 15) and the new position.

    Raises:
        DecompressionError: The block ends in the middle of the extension.
    """
    length = _TOKEN_MAX
    while True:
        if pos >= len(src):
            msg = "LZ4 block truncated inside a length extension"
            raise DecompressionError(msg)
        extra = src[pos]
        pos += 1
        length += extra
        if extra != _LENGTH_CONTINUE:
            return length, pos


def _copy_match(dst: bytearray, offset: int, length: int) -> None:
    """Append ``length`` bytes copied from ``offset`` bytes back in ``dst``.

    Matches may overlap their own output when ``length > offset``
    (lz4_Block_format.md); copying in chunks of at most ``offset`` bytes reproduces
    the RLE-style overlap semantics. Each iteration copies one ``offset``-sized chunk,
    so a wide offset copies in bulk while ``offset == 1`` degenerates to one byte per
    iteration.
    """
    while length > 0:
        start = len(dst) - offset
        chunk = min(length, offset)
        dst += dst[start : start + chunk]
        length -= chunk


def _decode_match(src: bytes, pos: int, token: int, dst: bytearray, target: int) -> int:
    """Decode one sequence's match part (offset + length) and append the copy.

    Split from :func:`decompress_block` purely to keep each function readable; the
    checks are the block-format validity rules for the offset field.

    Returns:
        The position of the next sequence's token.

    Raises:
        DecompressionError: Truncated offset, zero offset, or an offset reaching
            before the start of the output.
    """
    if pos + 2 > len(src):
        msg = "LZ4 block truncated inside a match offset"
        raise DecompressionError(msg)
    # Offset: 2 bytes little-endian; 0 is invalid (lz4_Block_format.md).
    offset = src[pos] | (src[pos + 1] << 8)
    pos += 2
    if offset == 0:
        msg = "LZ4 match offset 0 denotes a corrupted block"
        raise DecompressionError(msg)
    if offset > len(dst):
        msg = f"LZ4 match offset {offset} reaches before the start of the output ({len(dst)} bytes decoded)"
        raise DecompressionError(msg)
    # Match length: low nibble + minmatch of 4, same continuation scheme.
    match_len = token & 0xF
    if match_len == _TOKEN_MAX:
        match_len, pos = _read_length(src, pos)
    match_len += MIN_MATCH
    _copy_match(dst, offset, min(match_len, target - len(dst)))
    return pos


def decompress_block(payload: Buffer, uncompressed_size: int, /) -> bytes:
    """Decode a headerless LZ4 block to exactly ``uncompressed_size`` bytes.

    The block format carries no size, so the target must be supplied out-of-band --
    for an ESE cell it comes from ``Lz4Header.mle_cbUncompressed``. Matching ESE's
    ``LZ4_decompress_safe_partial(..., targetOutputSize=cbDataMax,
    dstCapacity=cbDataMax)`` call (compression.cxx:2677-2682), decoding stops the
    moment the target size has been produced, even mid-sequence; any further payload
    bytes are ignored. Unlike ESE release builds (which only ``Assert`` the decoded
    count, compression.cxx:2688), a block that runs out of input *before* reaching
    the target is rejected here rather than returned short.

    Args:
        payload: The raw LZ4 block bytes (for an ESE cell, the bytes from offset 3).
        uncompressed_size: Exact plaintext length to produce.

    Raises:
        DecompressionError: Truncated or corrupt block (EOF mid-sequence, zero
            offset, offset pointing before the start of the output, or the block
            ending before ``uncompressed_size`` bytes were produced).
    """
    src = bytes(payload)
    if uncompressed_size <= 0:
        return b""
    dst = bytearray()
    pos = 0
    while True:
        if pos >= len(src):
            msg = f"LZ4 block ended after {len(dst)} of {uncompressed_size} bytes"
            raise DecompressionError(msg)
        token = src[pos]
        pos += 1
        # Literals: high nibble, 15 => 0xFF-continuation extension.
        literal_len = token >> 4
        if literal_len == _TOKEN_MAX:
            literal_len, pos = _read_length(src, pos)
        take = min(literal_len, uncompressed_size - len(dst))
        if pos + take > len(src):
            msg = "LZ4 block truncated inside a literal run"
            raise DecompressionError(msg)
        dst += src[pos : pos + take]
        pos += literal_len
        if len(dst) >= uncompressed_size:
            return bytes(dst)
        pos = _decode_match(src, pos, token, dst, uncompressed_size)
        if len(dst) >= uncompressed_size:
            return bytes(dst)


# --- LZ4 block encoder ---


def _emit_length_extension(out: bytearray, remainder: int) -> None:
    """Emit the ``0xFF``-continuation bytes for a length whose nibble was 15.

    ``remainder`` is ``length - 15``; per lz4_Block_format.md each byte 0-255 adds
    to the length and a 255 byte forces another, so an exact multiple of 255 is
    terminated by an explicit 0 byte.
    """
    while remainder >= _LENGTH_CONTINUE:
        out.append(_LENGTH_CONTINUE)
        remainder -= _LENGTH_CONTINUE
    out.append(remainder)


def _emit_sequence(out: bytearray, literals: bytes, offset: int, match_len: int) -> None:
    """Emit one full sequence: token, literal run, offset, match length.

    ``match_len`` of 0 marks the final literals-only sequence (no offset field) --
    the block-format end condition that the last sequence contains only literals.
    """
    literal_len = len(literals)
    literal_nibble = min(literal_len, _TOKEN_MAX)
    # The stored match nibble is match_length - minmatch (lz4_Block_format.md).
    match_nibble = 0 if match_len == 0 else min(match_len - MIN_MATCH, _TOKEN_MAX)
    out.append((literal_nibble << 4) | match_nibble)
    if literal_nibble == _TOKEN_MAX:
        _emit_length_extension(out, literal_len - _TOKEN_MAX)
    out += literals
    if match_len == 0:
        return
    out += offset.to_bytes(2, "little")
    if match_nibble == _TOKEN_MAX:
        _emit_length_extension(out, match_len - MIN_MATCH - _TOKEN_MAX)


def compress_block(data: Buffer, /) -> bytes:
    """Encode ``data`` as a headerless LZ4 block.

    Greedy matcher over a hash table of 4-byte substrings, honouring every
    end-of-block invariant from lz4_Block_format.md: matches are at least
    ``MIN_MATCH`` bytes, reach back at most ``MAX_OFFSET``, start at least 12 bytes
    before the end, and stop 5 bytes short of it so the block ends in a
    literals-only sequence. The output decodes with any conformant LZ4 block
    decoder; it is not guaranteed byte-identical to ``LZ4_compress_default``.
    """
    src = bytes(data)
    n = len(src)
    out = bytearray()
    if n == 0:
        # A single zero token: empty final literal run (what liblz4 emits too).
        return b"\x00"
    table: dict[bytes, int] = {}
    match_limit = n - _LAST_LITERALS
    anchor = 0
    pos = 0
    while pos <= n - _MF_LIMIT:
        key = src[pos : pos + MIN_MATCH]
        candidate = table.get(key)
        table[key] = pos
        if candidate is None or pos - candidate > MAX_OFFSET:
            pos += 1
            continue
        # dict key equality already guarantees the first MIN_MATCH bytes match.
        match_len = MIN_MATCH
        while pos + match_len < match_limit and src[candidate + match_len] == src[pos + match_len]:
            match_len += 1
        _emit_sequence(out, src[anchor:pos], pos - candidate, match_len)
        pos += match_len
        anchor = pos
    _emit_sequence(out, src[anchor:], 0, 0)
    return bytes(out)


# --- ESE framed codec (module-level Shape B functions) ---


def decompress(blob: Buffer, *, verify: bool = True) -> bytes:
    """Decode an LZ4 (0x7) cell to its plaintext.

    Port of ``ErrDecompressLz4_`` (compression.cxx:2643-2699): validate the
    header, then decode the block at offset 3 up to the out-of-band
    ``mle_cbUncompressed`` target.

    Args:
        blob: The framed cell, including the 3-byte header.
        verify: Accepted for interface consistency; the LZ4 frame carries no
            checksum, so there is nothing extra to verify.

    Raises:
        DecompressionError: Truncated buffer, wrong scheme byte, or a corrupt
            block payload.
    """
    del verify
    head = parse_header(blob)
    return decompress_block(memoryview(blob)[HEADER_SIZE:], head.uncompressed_size)


def compress(data: Buffer) -> bytes:
    """Encode plaintext into a framed LZ4 (0x7) cell.

    Port of ``ErrCompressLz4_`` (compression.cxx:2070-2109): compress into a
    standard LZ4 block behind a 3-byte header carrying ``0x38`` and the u16 LE
    plaintext size (compression.cxx:2104-2105).

    Raises:
        CompressionError: ``data`` exceeds 65535 bytes, the u16 size field's
            capacity (ESE gates LZ4 on ``data.Cb() <= wMax``, compression.cxx:2761).
        IncompressibleError: The compressed payload plus the 3-byte header would
            not be smaller than the plaintext -- ESE refuses to store such cells
            (``( cbCompressedActual + 3 ) >= data.Cb()``, compression.cxx:2090-2095).
    """
    from ntcompress.ese import Format, header_byte

    size = len(data)
    if size > MAX_UNCOMPRESSED:
        msg = f"LZ4 cells hold at most {MAX_UNCOMPRESSED} plaintext bytes (u16 size field); got {size}"
        raise CompressionError(msg)
    block = compress_block(data)
    if len(block) + HEADER_SIZE >= size:
        msg = f"LZ4 output ({len(block) + HEADER_SIZE} bytes framed) would not shrink the {size}-byte input"
        raise IncompressibleError(msg)
    return _HEADER.pack(header_byte(Format.LZ4), size) + block


def decompressed_size(blob: Buffer) -> int:
    """Return ``mle_cbUncompressed`` from the header (compression.cxx:2669-2670)."""
    return parse_header(blob).uncompressed_size
