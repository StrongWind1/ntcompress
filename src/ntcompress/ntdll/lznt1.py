# SPDX-License-Identifier: Apache-2.0
"""MS-XCA LZNT1 raw codec (``COMPRESSION_FORMAT_LZNT1``, 0x0002).

Standalone MS-XCA codec operating on a bare stream. An LZNT1 buffer is a series of
independently decompressible chunks, each beginning with a 16-bit little-endian
header: bit 15 is the compressed flag, bits [14:12] are a signature that MUST be 3,
and bits [11:0] hold the total chunk size minus three bytes ([MS-XCA] §2.5.1.2). A
header of 0x0000 is the optional *End_of_buffer* terminal. Compressed chunks hold
flag groups: one flag byte followed by up to eight data elements, where a clear bit
means a literal byte and a set bit means a 16-bit compressed word ([MS-XCA] §2.5.1.3).
A compressed word packs a D-bit displacement (high bits) and an L-bit length (low
bits) with D + L = 16; D grows with the amount of chunk-relative uncompressed data
already processed ([MS-XCA] §2.5.1.4). Stored displacement is actual minus 1; stored
length is actual minus 3 (minimum match 3).

Input is compressed in units of 4096 bytes per chunk ([MS-XCA] §2.5.3), and matches
that overlap the write cursor MUST be copied front to back so a word may reference
bytes it is itself producing.

Authority: ``[MS-XCA] §2.5`` (algorithm details), ``§2.5.3`` (processing rules),
``§3.3`` (worked example, used as the pinned test vector).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ntcompress.exceptions import DecompressionError

if TYPE_CHECKING:
    from ntcompress._types import Buffer

# --- Wire constants ([MS-XCA] §2.5.1.2, §2.5.1.4, §2.5.3) ---

_CHUNK_INPUT_SIZE = 4096
"""Uncompressed bytes consumed per chunk; [MS-XCA] §2.5.3 mandates 4096-byte units."""

_HEADER_COMPRESSED = 0x8000
"""Chunk-header bit 15: set when the chunk body is flag groups, clear for raw data."""

_HEADER_SIGNATURE_MASK = 0x7000
"""Chunk-header bits [14:12]: the signature field."""

_HEADER_SIGNATURE = 0x3000
"""The signature value 3 required by [MS-XCA] §2.5.1.2 for every non-terminal chunk."""

_HEADER_SIZE_MASK = 0x0FFF
"""Chunk-header bits [11:0]: total chunk size (header included) minus 3 bytes."""

_WORD_SIZE = 2
"""Bytes per chunk header and per compressed word ([MS-XCA] §2.5.1.2, §2.5.1.4)."""

_FLAG_GROUP_ELEMENTS = 8
"""Data elements per flag group, one per bit of the flag byte ([MS-XCA] §2.5.1.3)."""

_MIN_MATCH = 3
"""Minimum match length; stored length is actual minus 3 ([MS-XCA] §2.5.1.4)."""

_MIN_DISPLACEMENT_BITS = 4
_MAX_DISPLACEMENT_BITS = 12
"""Bounds of the D (displacement) bit width: 4 <= D <= 12 ([MS-XCA] §2.5.1.4)."""

_MAX_MATCH_CANDIDATES = 256
"""Encoder-only cap on hash-chain probes per position; bounds worst-case time."""


def _displacement_bits(chunk_position: int) -> int:
    """Return D, the displacement bit width of a compressed word at this position.

    Per [MS-XCA] §2.5.1.4: with U the amount of chunk-relative uncompressed data
    already processed, D is the largest M in [4..12] such that 2**(M-1) < U (or 4 if
    no such M exists); the length then occupies the remaining L = 16 - D low bits.
    """
    bits = _MIN_DISPLACEMENT_BITS
    while bits < _MAX_DISPLACEMENT_BITS and (1 << bits) < chunk_position:
        bits += 1
    return bits


# --- Decompression ([MS-XCA] §2.5.1, §2.5.3) ---


def _decompress_chunk_body(src: bytes, pos: int, chunk_end: int, out: bytearray, chunk_start: int) -> None:
    """Decode one compressed chunk's flag groups into ``out``."""
    while pos < chunk_end:
        flags = src[pos]
        pos += 1
        for bit in range(_FLAG_GROUP_ELEMENTS):
            if pos >= chunk_end:
                break
            if not flags >> bit & 1:
                out.append(src[pos])
                pos += 1
                continue
            if chunk_end - pos < _WORD_SIZE:
                msg = f"LZNT1 compressed word truncated at offset {pos}"
                raise DecompressionError(msg)
            word = src[pos] | src[pos + 1] << 8
            pos += 2
            disp_bits = _displacement_bits(len(out) - chunk_start)
            displacement = (word >> (16 - disp_bits)) + 1
            length = (word & (1 << (16 - disp_bits)) - 1) + _MIN_MATCH
            copy_from = len(out) - displacement
            if copy_from < 0:
                msg = f"LZNT1 match displacement {displacement} reaches before the start of the output at offset {pos - 2}"
                raise DecompressionError(msg)
            for i in range(length):
                out.append(out[copy_from + i])


def decompress(data: Buffer, /) -> bytes:
    """Decode a raw MS-XCA LZNT1 buffer to plaintext.

    Walks the chunk sequence of [MS-XCA] §2.5.1.2: a 0x0000 header is the optional
    End_of_buffer terminal, an uncompressed chunk carries raw literal data, and a
    compressed chunk carries flag groups.

    Raises:
        DecompressionError: Bad signature, truncated chunk, or a match that reaches
            before the start of the output.
    """
    src = bytes(data)
    out = bytearray()
    pos = 0
    end = len(src)
    while pos < end:
        if end - pos < _WORD_SIZE:
            msg = f"LZNT1 chunk header truncated at offset {pos}"
            raise DecompressionError(msg)
        header = src[pos] | src[pos + 1] << 8
        if header == 0:
            break
        if header & _HEADER_SIGNATURE_MASK != _HEADER_SIGNATURE:
            msg = f"LZNT1 chunk header 0x{header:04x} at offset {pos} has bad signature (bits [14:12] must be 3)"
            raise DecompressionError(msg)
        chunk_end = pos + (header & _HEADER_SIZE_MASK) + 3
        if chunk_end > end:
            msg = f"LZNT1 chunk at offset {pos} claims {chunk_end - pos} bytes but only {end - pos} remain"
            raise DecompressionError(msg)
        if header & _HEADER_COMPRESSED:
            _decompress_chunk_body(src, pos + 2, chunk_end, out, chunk_start=len(out))
        else:
            out += src[pos + 2 : chunk_end]
        pos = chunk_end
    return bytes(out)


# --- Compression ([MS-XCA] §2.5.2-2.5.4) ---


def _find_match(chunk: bytes, pos: int, table: dict[bytes, list[int]]) -> tuple[int, int]:
    """Return ``(length, displacement)`` of the best match at ``pos`` (0, 0 if none)."""
    if len(chunk) - pos < _MIN_MATCH:
        return 0, 0
    disp_bits = _displacement_bits(pos)
    max_displacement = min(pos, 1 << disp_bits)
    max_length = min(len(chunk) - pos, (1 << (16 - disp_bits)) - 1 + _MIN_MATCH)
    best_length = 0
    best_displacement = 0
    candidates = table.get(chunk[pos : pos + _MIN_MATCH], [])
    for candidate in reversed(candidates[-_MAX_MATCH_CANDIDATES:]):
        if pos - candidate > max_displacement:
            break
        length = _MIN_MATCH
        while length < max_length and chunk[candidate + length] == chunk[pos + length]:
            length += 1
        if length > best_length:
            best_length = length
            best_displacement = pos - candidate
            if length == max_length:
                break
    return best_length, best_displacement


def _compress_chunk(chunk: bytes) -> bytes:
    """Encode one chunk's worth of plaintext into an LZNT1 flag-group body."""
    body = bytearray()
    table: dict[bytes, list[int]] = {}
    group_flags = 0
    group_items = bytearray()
    group_count = 0
    pos = 0
    while pos < len(chunk):
        length, displacement = _find_match(chunk, pos, table)
        if length >= _MIN_MATCH:
            disp_bits = _displacement_bits(pos)
            word = (displacement - 1) << (16 - disp_bits) | (length - _MIN_MATCH)
            group_items += word.to_bytes(2, "little")
            group_flags |= 1 << group_count
        else:
            length = 1
            group_items.append(chunk[pos])
        for indexed in range(pos, min(pos + length, len(chunk) - _MIN_MATCH + 1)):
            table.setdefault(chunk[indexed : indexed + _MIN_MATCH], []).append(indexed)
        pos += length
        group_count += 1
        if group_count == _FLAG_GROUP_ELEMENTS:
            body.append(group_flags)
            body += group_items
            group_flags = 0
            group_items.clear()
            group_count = 0
    if group_count:
        body.append(group_flags)
        body += group_items
    return bytes(body)


def compress(data: Buffer, /) -> bytes:
    """Encode plaintext into a raw MS-XCA LZNT1 buffer.

    Consumes the input in 4096-byte units per [MS-XCA] §2.5.3, emitting one chunk
    each: a compressed chunk when the flag-group body is smaller than the raw data,
    otherwise an uncompressed chunk.
    """
    src = bytes(data)
    out = bytearray()
    for start in range(0, len(src), _CHUNK_INPUT_SIZE):
        chunk = src[start : start + _CHUNK_INPUT_SIZE]
        body = _compress_chunk(chunk)
        if len(body) < len(chunk):
            header = _HEADER_COMPRESSED | _HEADER_SIGNATURE | len(body) + 2 - 3
            out += header.to_bytes(2, "little")
            out += body
        else:
            header = _HEADER_SIGNATURE | len(chunk) + 2 - 3
            out += header.to_bytes(2, "little")
            out += chunk
    return bytes(out)
