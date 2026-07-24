# SPDX-License-Identifier: Apache-2.0
"""MS-XCA Plain LZ77 (LZXPRESS) raw stream codec (``COMPRESSION_FORMAT_XPRESS``, 0x0003).

This is the canonical home for the raw Plain LZ77 codec. The ESE XPRESS (scheme 0x3)
module imports from here and adds ESE framing on top.

Wire format ([MS-XCA] §2.3.4 encode / §2.4.4 decode):

- Literal/match flags are packed in 32-bit little-endian words, consumed MSB-first
  (1 = match, 0 = literal); the final partial word is padded with 1-bits.
- A match is a 16-bit little-endian token: high 13 bits = offset - 1 (so the largest
  offset is 8192), low 3 bits = length - 3. A low-bits value of 7 escapes to the
  extended-length ladder: a 4-bit nibble (two consecutive long matches share one
  byte, low nibble first), then if 15 an 8-bit byte, then if 255 a 16-bit word, then
  (v10.0) if that word is 0 a 32-bit dword.
- Match copies run one byte at a time because a match may overlap its own output
  (length > offset), [MS-XCA] §2.4.4.

Authority: ``[MS-XCA] §2.3`` (compression), ``§2.4`` (decompression), ``§3.1``
(worked examples).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, NoReturn

from ntcompress.exceptions import DecompressionError

if TYPE_CHECKING:
    from ntcompress._types import Buffer

# --- Wire constants ---

MIN_MATCH: Final = 3
"""Smallest encodable match ([MS-XCA] §2.3.4 "length of at least 3")."""

MAX_OFFSET: Final = 8192
"""Largest encodable match distance, 2^13 ([MS-XCA] §2.3.4)."""

MAX_MATCH_LENGTH: Final = 0xFFFF_FFFF
"""MatchLength is a ULONG, so 4,294,967,295 at most ([MS-XCA] §2.3.4)."""

_FLAG_BITS: Final = 32
"""Flags travel in 32-bit words ([MS-XCA] §2.4.4)."""

_TOKEN_LENGTH_LIMIT: Final = 7
"""Low-3-bits escape sentinel of the match token."""

_NIBBLE_LIMIT: Final = 15
"""Escape sentinel of the 4-bit ladder step."""

_BYTE_LIMIT: Final = 255
"""Escape sentinel of the 8-bit ladder step."""

_WORD_LIMIT: Final = 1 << 16
"""First length needing the v10.0 32-bit escape."""

_LADDER_FLOOR: Final = _NIBBLE_LIMIT + _TOKEN_LENGTH_LIMIT
"""Smallest length-minus-3 reaching the word/dword steps."""

# --- Decompression ([MS-XCA] §2.4.4) ---


def _truncated(needed: str) -> NoReturn:
    """Reject a read past the end of the compressed buffer."""
    msg = f"compressed stream truncated: expected {needed}"
    raise DecompressionError(msg)


def _extra_length(src: bytes, pos: int) -> tuple[int, int]:
    """Decode the byte -> word -> dword tail of the length ladder."""
    if pos >= len(src):
        _truncated("an extended-length byte")
    length = src[pos]
    pos += 1
    if length == _BYTE_LIMIT:
        if pos + 2 > len(src):
            _truncated("a 16-bit extended length")
        length = int.from_bytes(src[pos : pos + 2], "little")
        pos += 2
        if length == 0:
            if pos + 4 > len(src):
                _truncated("a 32-bit extended length")
            length = int.from_bytes(src[pos : pos + 4], "little")
            pos += 4
        if length < _LADDER_FLOOR:
            msg = f"extended match length {length} is below the ladder floor {_LADDER_FLOOR} ([MS-XCA] §2.4.4)"
            raise DecompressionError(msg)
        length -= _LADDER_FLOOR
    return length, pos


def _long_length(src: bytes, pos: int, nibble_pos: int) -> tuple[int, int, int]:
    """Decode the extended-length ladder entered when the token's low 3 bits are 7."""
    if nibble_pos < 0:
        if pos >= len(src):
            _truncated("a length nibble")
        length = src[pos] & 0xF
        nibble_pos = pos
        pos += 1
    else:
        length = src[nibble_pos] >> 4
        nibble_pos = -1
    if length == _NIBBLE_LIMIT:
        length, pos = _extra_length(src, pos)
        length += _NIBBLE_LIMIT
    return length + _TOKEN_LENGTH_LIMIT, pos, nibble_pos


def _copy_match(src: bytes, pos: int, nibble_pos: int, out: bytearray, max_size: int | None) -> tuple[int, int]:
    """Decode one match token and copy it into the output."""
    if pos + 2 > len(src):
        _truncated("a 16-bit match token")
    token = int.from_bytes(src[pos : pos + 2], "little")
    pos += 2
    length = token & 0x7
    offset = (token >> 3) + 1
    if length == _TOKEN_LENGTH_LIMIT:
        length, pos, nibble_pos = _long_length(src, pos, nibble_pos)
    length += MIN_MATCH
    if offset > len(out):
        msg = f"match reaches {offset} bytes back with only {len(out)} bytes decoded"
        raise DecompressionError(msg)
    if max_size is not None and len(out) + length > max_size:
        msg = f"match writes {len(out) + length} bytes into a {max_size}-byte output ([MS-XCA] §2.4.4)"
        raise DecompressionError(msg)
    for _ in range(length):
        out.append(out[-offset])
    return pos, nibble_pos


def decompress(data: Buffer, /, *, max_size: int | None = None) -> bytes:
    """Decode a raw MS-XCA Plain LZ77 stream to plaintext.

    Direct port of [MS-XCA] §2.4.4: flag words are read 4 bytes at a time and
    consumed MSB-first; a 0 bit copies one literal byte, a 1 bit decodes a match.

    Args:
        data: The compressed stream.
        max_size: Size of the caller's output buffer, when one is known. ``None``
            leaves the output unbounded.

    Raises:
        DecompressionError: Any read outside the input, a match reaching before the
            start of the output, or a write past ``max_size``.
    """
    src = bytes(data)
    size = len(src)
    out = bytearray()
    pos = 0
    flags = 0
    flag_count = 0
    nibble_pos = -1
    while True:
        if flag_count == 0:
            if pos + 4 > size:
                _truncated("a 32-bit flag word")
            flags = int.from_bytes(src[pos : pos + 4], "little")
            pos += 4
            flag_count = _FLAG_BITS
        flag_count -= 1
        if (flags >> flag_count) & 1 == 0:
            if pos >= size:
                _truncated("a literal byte")
            if max_size is not None and len(out) >= max_size:
                msg = f"literal writes past the {max_size}-byte output ([MS-XCA] §2.4.4)"
                raise DecompressionError(msg)
            out.append(src[pos])
            pos += 1
        else:
            if pos == size:
                return bytes(out)
            pos, nibble_pos = _copy_match(src, pos, nibble_pos, out, max_size)


# --- Compression ([MS-XCA] §2.3.4) ---

_MAX_CHAIN: Final = 64
"""Candidates examined per match search."""

_CHAIN_PRUNE: Final = 256
"""Chain length that triggers dropping the oldest candidates."""


class _Encoder:
    """Mutable output side of the [MS-XCA] §2.3.4 encoder."""

    def __init__(self) -> None:
        self.out = bytearray(4)
        self.flags = 0
        self.flag_count = 0
        self.flag_pos = 0
        self.nibble_pos = -1

    def _push_flag(self, bit: int) -> None:
        """Append one literal/match flag bit; on the 32nd, flush the word."""
        self.flags = self.flags << 1 | bit
        self.flag_count += 1
        if self.flag_count == _FLAG_BITS:
            self.out[self.flag_pos : self.flag_pos + 4] = self.flags.to_bytes(4, "little")
            self.flags = 0
            self.flag_count = 0
            self.flag_pos = len(self.out)
            self.out += b"\x00\x00\x00\x00"

    def emit_literal(self, byte: int) -> None:
        """Copy one raw byte to the output under a 0 flag bit."""
        self.out.append(byte)
        self._push_flag(0)

    def _emit_long_length(self, extra: int) -> None:
        """Encode ``length - 3 - 7`` through the nibble/byte/word/dword ladder."""
        if self.nibble_pos < 0:
            self.nibble_pos = len(self.out)
            self.out.append(min(extra, _NIBBLE_LIMIT))
        else:
            self.out[self.nibble_pos] |= min(extra, _NIBBLE_LIMIT) << 4
            self.nibble_pos = -1
        if extra < _NIBBLE_LIMIT:
            return
        extra -= _NIBBLE_LIMIT
        if extra < _BYTE_LIMIT:
            self.out.append(extra)
            return
        self.out.append(_BYTE_LIMIT)
        extra += _LADDER_FLOOR
        if extra < _WORD_LIMIT:
            self.out += extra.to_bytes(2, "little")
        else:
            self.out += b"\x00\x00" + extra.to_bytes(4, "little")

    def emit_match(self, offset: int, length: int) -> None:
        """Encode one match as a 16-bit LE token under a 1 flag bit."""
        token = (offset - 1) << 3
        extra = length - MIN_MATCH
        if extra < _TOKEN_LENGTH_LIMIT:
            self.out += (token | extra).to_bytes(2, "little")
        else:
            self.out += (token | _TOKEN_LENGTH_LIMIT).to_bytes(2, "little")
            self._emit_long_length(extra - _TOKEN_LENGTH_LIMIT)
        self._push_flag(1)

    def finish(self) -> bytes:
        """Pad the pending flag word with 1-bits and flush it."""
        pad = _FLAG_BITS - self.flag_count
        self.out[self.flag_pos : self.flag_pos + 4] = (self.flags << pad | (1 << pad) - 1).to_bytes(4, "little")
        return bytes(self.out)


def _index(table: dict[bytes, list[int]], src: bytes, pos: int) -> None:
    """Record ``pos`` as a future match candidate for its 3-byte prefix."""
    key = src[pos : pos + MIN_MATCH]
    chain = table.get(key)
    if chain is None:
        table[key] = [pos]
        return
    chain.append(pos)
    if len(chain) > _CHAIN_PRUNE:
        del chain[:-_MAX_CHAIN]


def _match_length(src: bytes, candidate: int, pos: int, limit: int) -> int:
    """Extend a guaranteed 3-byte prefix match as far as it goes."""
    length = MIN_MATCH
    while length < limit and src[candidate + length] == src[pos + length]:
        length += 1
    return length


def _find_match(src: bytes, pos: int, table: dict[bytes, list[int]]) -> tuple[int, int]:
    """Find the longest match for ``pos`` within the last 8192 bytes.

    Returns ``(offset, length)``, or ``(0, 0)`` when no match exists.
    """
    if pos + MIN_MATCH > len(src):
        return 0, 0
    chain = table.get(src[pos : pos + MIN_MATCH])
    if chain is None:
        return 0, 0
    limit = min(len(src) - pos, MAX_MATCH_LENGTH)
    best_offset = 0
    best_length = 0
    for candidate in reversed(chain[-_MAX_CHAIN:]):
        if pos - candidate > MAX_OFFSET:
            break
        length = _match_length(src, candidate, pos, limit)
        if length > best_length:
            best_offset = pos - candidate
            best_length = length
            if length == limit:
                break
    return best_offset, best_length


def compress(data: Buffer, /) -> bytes:
    """Encode plaintext into a raw MS-XCA Plain LZ77 stream.

    Direct port of [MS-XCA] §2.3.4 with a greedy hash-chain match finder.
    """
    src = bytes(data)
    size = len(src)
    encoder = _Encoder()
    table: dict[bytes, list[int]] = {}
    last_key_pos = size - MIN_MATCH
    pos = 0
    while pos < size:
        offset, length = _find_match(src, pos, table)
        if length:
            for covered in range(pos, min(pos + length, last_key_pos + 1)):
                _index(table, src, covered)
            encoder.emit_match(offset, length)
            pos += length
        else:
            if pos <= last_key_pos:
                _index(table, src, pos)
            encoder.emit_literal(src[pos])
            pos += 1
    return encoder.finish()
