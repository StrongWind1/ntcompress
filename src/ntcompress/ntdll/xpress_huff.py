# SPDX-License-Identifier: Apache-2.0
"""MS-XCA LZ77+Huffman raw codec (``COMPRESSION_FORMAT_XPRESS_HUFF``, 0x0004).

Standalone MS-XCA codec operating on a bare stream. Data is processed in 64 KiB
blocks; each block begins with a 256-byte table giving the 4-bit code length of all
512 Huffman symbols (0-255 literals, 256 EOF, 257-511 matches), followed by the
Huffman-coded literals and matches read as 16-bit little-endian chunks through a
32-bit register. The whole stream ends with the EOF symbol (256).

This targets ``[MS-XCA]`` v10.0: the match-length continuation is nibble -> byte ->
``uint16`` -> (v10.0) ``uint32``, removing the old 65,538-byte cap.

Authority: ``[MS-XCA] §2.1`` (compression), ``§2.2`` (decompression), ``§3.2``
(worked example).
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Final

from ntcompress.exceptions import DecompressionError

if TYPE_CHECKING:
    from ntcompress._types import Buffer

# --- Format constants ([MS-XCA] §2.1) ---

BLOCK_SIZE: Final = 65536
"""Each block decodes to at most 64 KiB of output ([MS-XCA] §2.1)."""

TABLE_SIZE: Final = 256
"""The per-block Huffman code-length table is 512 symbols x 4 bits = 256 bytes (§2.1.4.3)."""

SYMBOL_COUNT: Final = 512
"""Huffman alphabet size: 0-255 literals, 256 EOF, 257-511 matches (§2.1)."""

EOF_SYMBOL: Final = 256
"""End-of-file marker symbol, encoded after the final block (§2.1)."""

MIN_MATCH: Final = 3
"""Minimum match length; 3 is subtracted before length encoding (§3.2)."""

MAX_CODE_LENGTH: Final = 15
"""A code length is stored in 4 bits, so no Huffman code may exceed 15 bits (§2.1.4.2)."""

_LEN_BYTE_MAX: Final = 0xFF
"""Sentinel byte in the match-length ladder: 0xFF escapes to a wider field (§2.1.4.3)."""

_LEN_U16_LIMIT: Final = 0x10000
"""Match lengths at or above this take the v10.0 uint16(0)+uint32 escape (§2.1.4.3)."""

_MIN_SYMBOLS: Final = 2
"""A complete binary prefix code needs at least two symbols; blocks below this get a filler."""

_ROOT_BITS: Final = 15
"""The decode table is indexed by the top 15 bits of the register (§2.2.4)."""


# --- Bit / byte helpers ---


def _read16(data: bytes, pos: int) -> int:
    """Read a little-endian ``uint16`` at ``pos``, or raise if it runs past the end."""
    if pos + 2 > len(data):
        msg = "compressed stream truncated: expected a 16-bit chunk"
        raise DecompressionError(msg)
    return data[pos] | (data[pos + 1] << 8)


def _read32(data: bytes, pos: int) -> int:
    """Read a little-endian ``uint32`` at ``pos`` (the v10.0 long-match escape, §2.1.4.3)."""
    if pos + 4 > len(data):
        msg = "compressed stream truncated: expected a 32-bit match length"
        raise DecompressionError(msg)
    return int.from_bytes(data[pos : pos + 4], "little")


def _high_bit(value: int) -> int:
    """Return the index of the highest set bit of ``value`` (``GetHighBit``, §2.1.4.1)."""
    return value.bit_length() - 1


# --- Decode ([MS-XCA] §2.2) ---


def _lengths_from_table(table: bytes) -> list[int]:
    """Expand the 256-byte code-length table to 512 per-symbol bit lengths (§2.1.4.3)."""
    lengths = [0] * SYMBOL_COUNT
    for i, byte in enumerate(table):
        lengths[2 * i] = byte & 0x0F
        lengths[2 * i + 1] = byte >> 4
    return lengths


def _build_decode_table(lengths: list[int]) -> list[int]:
    """Build the canonical 2**15-entry Huffman decode table (§2.2.4)."""
    table = [0] * (1 << _ROOT_BITS)
    entry = 0
    for bit_length in range(1, MAX_CODE_LENGTH + 1):
        span = 1 << (_ROOT_BITS - bit_length)
        for symbol in range(SYMBOL_COUNT):
            if lengths[symbol] != bit_length:
                continue
            end = entry + span
            if end > (1 << _ROOT_BITS):
                msg = "invalid Huffman table: code lengths overflow the 15-bit code space"
                raise DecompressionError(msg)
            for slot in range(entry, end):
                table[slot] = symbol
            entry = end
    if entry != (1 << _ROOT_BITS):
        msg = "invalid Huffman table: code lengths do not form a complete prefix code"
        raise DecompressionError(msg)
    return table


class _BitReader:
    """The §2.2.4 input register: a 32-bit window refilled 16 bits at a time."""

    __slots__ = ("data", "extra", "pos", "register")

    def __init__(self, data: bytes, pos: int) -> None:
        self.data = data
        self.register = (_read16(data, pos) << 16) | _read16(data, pos + 2)
        self.pos = pos + 4
        self.extra = 16

    def peek15(self) -> int:
        """Return the top 15 bits of the register without consuming them."""
        return self.register >> (32 - _ROOT_BITS)

    def take(self, count: int) -> int:
        """Consume ``count`` bits (MSB-first) and return them, refilling as needed."""
        if count == 0:
            return 0
        value = self.register >> (32 - count)
        self.register = (self.register << count) & 0xFFFFFFFF
        self.extra -= count
        if self.extra < 0:
            self.register |= _read16(self.data, self.pos) << (-self.extra)
            self.pos += 2
            self.extra += 16
        return value

    def read_byte(self) -> int:
        """Read one raw byte from the shared cursor."""
        if self.pos >= len(self.data):
            msg = "compressed stream truncated: expected an extra match-length byte"
            raise DecompressionError(msg)
        byte = self.data[self.pos]
        self.pos += 1
        return byte

    def read_u16(self) -> int:
        """Read a raw little-endian ``uint16`` from the shared cursor."""
        value = _read16(self.data, self.pos)
        self.pos += 2
        return value

    def read_u32(self) -> int:
        """Read a raw little-endian ``uint32`` from the shared cursor (v10.0 escape)."""
        value = _read32(self.data, self.pos)
        self.pos += 4
        return value


def _decode_match_length(reader: _BitReader, nibble: int) -> int:
    """Return a match's full length from its 4-bit nibble and any continuation (§2.2.4)."""
    if nibble < MAX_CODE_LENGTH:
        return nibble + MIN_MATCH
    byte = reader.read_byte()
    if byte < _LEN_BYTE_MAX:
        return byte + MAX_CODE_LENGTH + MIN_MATCH
    word = reader.read_u16()
    if word == 0:
        return reader.read_u32() + MIN_MATCH
    if word < MAX_CODE_LENGTH:
        msg = "invalid Xpress Huffman match length continuation"
        raise DecompressionError(msg)
    return word + MIN_MATCH


def _copy_match(out: bytearray, offset: int, length: int) -> None:
    """Append an overlapping back-reference one byte at a time (§2.2.4 note)."""
    if offset <= 0 or offset > len(out):
        msg = f"invalid match offset {offset} into {len(out)} decoded bytes"
        raise DecompressionError(msg)
    start = len(out) - offset
    for i in range(length):
        out.append(out[start + i])


def decompress(data: Buffer, /, *, max_size: int | None = None) -> bytes:
    """Decode a raw MS-XCA LZ77+Huffman stream to plaintext (per [MS-XCA] §2.2).

    Processes 64 KiB blocks in order, each led by its own 256-byte Huffman table,
    until the EOF symbol (256) is decoded.

    Args:
        data: The raw LZ77+Huffman stream.
        max_size: Optional ceiling on the decoded length.

    Raises:
        DecompressionError: Any read past the end, malformed Huffman table, or output
            exceeding ``max_size``.
    """
    data = bytes(data)
    out = bytearray()
    pos = 0
    total = len(data)
    while pos < total:
        if total - pos < TABLE_SIZE:
            if not out:
                msg = "compressed stream ends before any block table or EOF symbol"
                raise DecompressionError(msg)
            break
        lengths = _lengths_from_table(data[pos : pos + TABLE_SIZE])
        table = _build_decode_table(lengths)
        pos += TABLE_SIZE
        reader = _BitReader(data, pos)
        block_end = len(out) + BLOCK_SIZE
        while len(out) < block_end:
            symbol = table[reader.peek15()]
            reader.take(lengths[symbol])
            if symbol < EOF_SYMBOL:
                if max_size is not None and len(out) >= max_size:
                    msg = f"decoded output would exceed the {max_size}-byte limit"
                    raise DecompressionError(msg)
                out.append(symbol)
                continue
            if symbol == EOF_SYMBOL:
                return bytes(out)
            match = symbol - EOF_SYMBOL
            length = _decode_match_length(reader, match & 0x0F)
            offset_bits = match >> 4
            offset = reader.take(offset_bits) + (1 << offset_bits)
            if max_size is not None and len(out) + length > max_size:
                msg = f"decoded output would exceed the {max_size}-byte limit"
                raise DecompressionError(msg)
            _copy_match(out, offset, length)
        pos = reader.pos
    return bytes(out)


# --- Encode ([MS-XCA] §2.1) ---

MAX_OFFSET: Final = 65535
"""Largest encodable match distance."""

_MAX_CHAIN: Final = 64
"""Hash-chain search depth."""

_Token = tuple[str, int, int]


def _lz77(data: bytes) -> list[_Token]:
    """Greedy LZ77 factorization with a 3-byte hash chain ([MS-XCA] §2.1.4.1)."""
    tokens: list[_Token] = []
    heads: dict[int, int] = {}
    chain: list[int] = [-1] * len(data)
    n = len(data)
    pos = 0
    while pos < n:
        best_len = 0
        best_dist = 0
        if pos + MIN_MATCH <= n:
            key = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
            candidate = heads.get(key, -1)
            depth = 0
            while candidate >= 0 and depth < _MAX_CHAIN:
                distance = pos - candidate
                if distance > MAX_OFFSET:
                    break
                length = 0
                limit = n - pos
                while length < limit and data[candidate + length] == data[pos + length]:
                    length += 1
                if length > best_len:
                    best_len = length
                    best_dist = distance
                candidate = chain[candidate]
                depth += 1
        if best_len >= MIN_MATCH and _match_symbol(best_len, best_dist) > EOF_SYMBOL:
            tokens.append(("M", best_len, best_dist))
            advance = best_len
        else:
            tokens.append(("L", data[pos], 0))
            advance = 1
        end = pos + advance
        while pos < end and pos + MIN_MATCH <= n:
            key = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
            chain[pos] = heads.get(key, -1)
            heads[key] = pos
            pos += 1
        pos = end
    return tokens


def _match_symbol(length: int, distance: int) -> int:
    """Return the Huffman symbol for a match (256-511), per [MS-XCA] §2.1.4.1."""
    return EOF_SYMBOL + min(length - MIN_MATCH, MAX_CODE_LENGTH) + 16 * _high_bit(distance)


def _limited_lengths(freqs: Counter[int]) -> dict[int, int]:
    """Compute canonical Huffman code lengths capped at 15 bits via package-merge."""
    items = sorted((count, symbol) for symbol, count in freqs.items())
    n = len(items)
    lengths = {symbol: 0 for _, symbol in items}
    if n == 1:
        lengths[items[0][1]] = 1
        return lengths
    base = sorted((items[i][0], (i,)) for i in range(n))
    current = list(base)
    for _ in range(MAX_CODE_LENGTH - 1):
        packaged = [(current[j][0] + current[j + 1][0], current[j][1] + current[j + 1][1]) for j in range(0, len(current) - 1, 2)]
        current = sorted(base + packaged)
    counts = [0] * n
    for _weight, indices in current[: 2 * n - 2]:
        for i in indices:
            counts[i] += 1
    for i in range(n):
        lengths[items[i][1]] = counts[i]
    return lengths


def _canonical_codes(lengths: dict[int, int]) -> dict[int, int]:
    """Assign canonical Huffman codes from bit lengths ([MS-XCA] §2.2.4 ordering)."""
    ordered = sorted(symbol for symbol, length in lengths.items() if length > 0)
    ordered.sort(key=lambda symbol: (lengths[symbol], symbol))
    codes: dict[int, int] = {}
    code = 0
    prev_length = 0
    for symbol in ordered:
        code <<= lengths[symbol] - prev_length
        codes[symbol] = code
        code += 1
        prev_length = lengths[symbol]
    return codes


def _pack_table(lengths: dict[int, int]) -> bytearray:
    """Pack 512 bit lengths into the 256-byte table (§2.1.4.3)."""
    table = bytearray(TABLE_SIZE)
    for symbol, length in lengths.items():
        if symbol % 2 == 0:
            table[symbol // 2] |= length & 0x0F
        else:
            table[symbol // 2] |= (length & 0x0F) << 4
    return table


class _BitWriter:
    """The §2.1.4.3 output engine: 16-bit words with two deferred slots."""

    __slots__ = ("buf", "free", "pos", "pos1", "pos2", "word")

    def __init__(self, table: bytearray) -> None:
        self.buf = bytearray(table)
        self.buf += b"\x00\x00\x00\x00"
        self.pos1 = TABLE_SIZE
        self.pos2 = TABLE_SIZE + 2
        self.pos = TABLE_SIZE + 4
        self.free = 16
        self.word = 0

    def _emit_word(self) -> None:
        """Write the completed 16-bit word to ``pos1`` and rotate."""
        self.buf[self.pos1] = self.word & 0xFF
        self.buf[self.pos1 + 1] = (self.word >> 8) & 0xFF
        self.pos1 = self.pos2
        self.pos2 = self.pos
        self.buf += b"\x00\x00"
        self.pos += 2

    def write_bits(self, count: int, bits: int) -> None:
        """Append ``count`` bits (MSB-first) to the deferred bit stream."""
        if count == 0:
            return
        if self.free >= count:
            self.free -= count
            self.word = (self.word << count) + bits
        else:
            self.word = (self.word << self.free) + (bits >> (count - self.free))
            self.free -= count
            self._emit_word()
            self.free += 16
            self.word = bits

    def write_byte(self, value: int) -> None:
        """Write a raw extra-length byte at the current cursor."""
        self.buf.append(value & 0xFF)
        self.pos += 1

    def write_u16(self, value: int) -> None:
        """Write a raw little-endian ``uint16`` extra-length value."""
        self.buf += value.to_bytes(2, "little")
        self.pos += 2

    def write_u32(self, value: int) -> None:
        """Write a raw little-endian ``uint32`` extra-length value (v10.0 escape)."""
        self.buf += value.to_bytes(4, "little")
        self.pos += 4

    def finish(self) -> bytes:
        """Flush the pending bits and a trailing zero word."""
        self.word <<= self.free
        self.buf[self.pos1] = self.word & 0xFF
        self.buf[self.pos1 + 1] = (self.word >> 8) & 0xFF
        self.buf[self.pos2] = 0
        self.buf[self.pos2 + 1] = 0
        return bytes(self.buf[: self.pos])


def _write_length_extra(writer: _BitWriter, length: int) -> None:
    """Emit any bytes past the 4-bit match-length nibble (§2.1.4.3 v10.0 ladder)."""
    value = length - MIN_MATCH
    if value < MAX_CODE_LENGTH:
        return
    value -= MAX_CODE_LENGTH
    if value < _LEN_BYTE_MAX:
        writer.write_byte(value)
        return
    writer.write_byte(_LEN_BYTE_MAX)
    value += MAX_CODE_LENGTH
    if value < _LEN_U16_LIMIT:
        writer.write_u16(value)
    else:
        writer.write_u16(0)
        writer.write_u32(value)


def _encode_block(tokens: list[_Token], *, is_last: bool) -> bytes:
    """Huffman-encode one block's tokens into a table + bit stream ([MS-XCA] §2.1)."""
    freqs: Counter[int] = Counter()
    for token in tokens:
        if token[0] == "L":
            freqs[token[1]] += 1
        else:
            freqs[_match_symbol(token[1], token[2])] += 1
    if is_last:
        freqs[EOF_SYMBOL] += 1
    filler = 0
    while len(freqs) < _MIN_SYMBOLS:
        if filler not in freqs:
            freqs[filler] = 1
        filler += 1
    lengths = _limited_lengths(freqs)
    codes = _canonical_codes(lengths)
    writer = _BitWriter(_pack_table(lengths))
    for token in tokens:
        if token[0] == "L":
            writer.write_bits(lengths[token[1]], codes[token[1]])
            continue
        length, distance = token[1], token[2]
        symbol = _match_symbol(length, distance)
        writer.write_bits(lengths[symbol], codes[symbol])
        _write_length_extra(writer, length)
        high = _high_bit(distance)
        writer.write_bits(high, distance - (1 << high))
    if is_last:
        writer.write_bits(lengths[EOF_SYMBOL], codes[EOF_SYMBOL])
    return writer.finish()


def compress(data: Buffer, /) -> bytes:
    """Encode plaintext into a raw MS-XCA LZ77+Huffman stream (per [MS-XCA] §2.1).

    Runs a greedy LZ77 pass, segments the tokens into 64 KiB output blocks each with
    its own canonical Huffman table, and appends the EOF symbol after the final block.
    """
    data = bytes(data)
    tokens = _lz77(data)
    out = bytearray()
    index = 0
    produced = 0
    count = len(tokens)
    while True:
        block: list[_Token] = []
        base = produced
        while index < count and produced < base + BLOCK_SIZE:
            token = tokens[index]
            block.append(token)
            produced += 1 if token[0] == "L" else token[1]
            index += 1
        is_last = index >= count
        out += _encode_block(block, is_last=is_last)
        if is_last:
            break
    return bytes(out)
