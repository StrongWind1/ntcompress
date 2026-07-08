"""COMPRESS_XPRESS9 (0x5) -- pure-Python XPRESS9 codec.

XPRESS9 has no public byte-format specification: ``[MS-XCA]`` does not cover it, and
the authority is the MIT-licensed ESE C codec in ``dev/ese/src/_xpress9/``. This
module is an ATTRIBUTED PORT of that codec (see ``THIRD-PARTY-NOTICES.md``), not
clean-room work, so every constant and rule below cites its C ``file:line``.

The on-disk layout has two layers:

1. ESE outer record header (``Xpress9Header``, compression.cxx:515-521, 5 bytes):
   scheme byte ``(COMPRESS_XPRESS9 << 3) == 0x28`` (compression.cxx:1757) followed by
   a u32 LE CRC-32C of the *plaintext* (compression.cxx:1758, verified after
   decompression at compression.cxx:2461-2462).
2. One or more Xpress9 blocks, each a 32-byte header (``LZ77_BLOCK_HEADER``,
   Xpress9Internal.h:972-984, magic ``0x4E86D72A``, itself CRC-32C protected) followed
   by a single LSB-first bitstream holding: optional MTF (repeated-offset) initial
   state, two serialized canonical-Huffman code-length tables (short-symbol alphabet
   of 704, long-length alphabet of 256), and the LZ77 token stream with Elias-gamma
   offset coding (Xpress9Lz77Dec.i). ESE always writes the fixed "Cosmos Level 6"
   parameters MTF=4 / PtrMin=4 / MtfMin=2 / window 2**16 (compression.cxx:1696-1706),
   but this port handles every legal parameter combination like the C decoder does.

The encoder is a port of the C codec's lazy match finder (``Xpress9Lz77EncPass1.i``
with ``LAZY_MATCH_EVALUATION``, ``DEEP_LOOKUP=1``): hash-chain LZ77 with 4-entry MTF
support, 2-position lookahead, and Mode 0/1 Huffman table selection. The encoder
produces byte-identical output to the MIT ESE C reference encoder, excluding only
the non-deterministic session signature (``CRC32(__rdtsc())``, Xpress9EncLz77.c:1128).

Note: ntdll format 0x0005 is NOT XPRESS9 -- it has block magic ``0xC039E510`` (vs
XPRESS9's ``0x4E86D72A``) and is an entirely different, undocumented algorithm.

Known deviations from the C decoder, all only reachable with corrupt input:
* Match offsets are validated against the bytes decoded so far in the session
  (Xpress9Lz77Dec.i:248), not additionally against the C decoder's internal buffer
  geometry of about 1.5x the window size (Xpress9DecLz77.c:223), so a hand-crafted
  stream may reference slightly further back than a real decoder buffer would allow.
* A degenerate single-symbol Huffman table whose codeword is longer than 15 bits is
  decoded arithmetically here, where the C table builder's 4-bit skip field would
  silently overflow (Xpress9DecHuffman.c:360-372). The encoder emits neither case.
* ESE's ``ErrDecompressXpress9_`` performs a single fetch (compression.cxx:2437-2449),
  so it decodes the first block and silently ignores any trailing bytes; this port
  walks the whole session, so trailing bytes must parse as further valid blocks or the
  cell is rejected. ESE itself never writes trailing bytes (compression.cxx:1759).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ntcompress.ese.checksums import crc32c_ese
from ntcompress.exceptions import CompressionError, DecompressionError, IncompressibleError, IntegrityError

if TYPE_CHECKING:
    from ntcompress._types import Buffer

# --- ESE outer framing (compression.cxx) ---

HEADER_SIZE: Final = 5
"""Size of the packed ``Xpress9Header``: scheme byte + u32 LE plaintext CRC-32C ("Reserve 5 bytes for the header", compression.cxx:1691)."""

# --- Block format constants (Xpress9Internal.h) ---

BLOCK_HEADER_SIZE: Final = 32
"""Size of ``LZ77_BLOCK_HEADER``: 8 x u32 LE (Xpress9Internal.h:972-984)."""

XPRESS9_MAGIC: Final = 0x4E86D72A
"""``XPRESS9_MAGIC``, word [0] of every block header (Xpress9Internal.h:970)."""

_MAX_SHORT_LENGTH_LOG: Final = 4  # LZ77_MAX_SHORT_LENGTH_LOG (Xpress9Internal.h:769)
_MAX_SHORT_LENGTH: Final = 1 << _MAX_SHORT_LENGTH_LOG  # LZ77_MAX_SHORT_LENGTH = 16 (Xpress9Internal.h:770)
_MAX_WINDOW_SIZE_LOG: Final = 24  # LZ77_MAX_WINDOW_SIZE_LOG (Xpress9Internal.h:772)
_MAX_MTF: Final = 4  # LZ77_MAX_MTF (Xpress9Internal.h:767)
_LONG_LENGTH_ALPHABET_SIZE: Final = 256  # LZ77_LONG_LENGTH_ALPHABET_SIZE = 1 << (9 - 1) (Xpress9Internal.h:775-776)
_MAX_LONG_LENGTH: Final = _LONG_LENGTH_ALPHABET_SIZE - _MAX_WINDOW_SIZE_LOG  # LZ77_MAX_LONG_LENGTH = 232 (Xpress9Internal.h:777)
_SHORT_SYMBOL_ALPHABET_SIZE: Final = 256 + ((_MAX_WINDOW_SIZE_LOG + _MAX_MTF) << _MAX_SHORT_LENGTH_LOG)  # 704 (Xpress9Internal.h:779)
_MAX_CODEWORD_LENGTH: Final = 27  # HUFFMAN_MAX_CODEWORD_LENGTH (Xpress9Internal.h:500)

# Serialized code-length table opcodes (Xpress9Internal.h:604-611). Symbols 0..27 are
# literal codeword lengths; 28..32 are the RLE/copy opcodes decoded by
# HuffmanDecodeLengthTable (Xpress9DecHuffman.c:511-615).
_TABLE_FILL: Final = _MAX_CODEWORD_LENGTH + 1  # zeros up to the fill boundary
_TABLE_ZERO_REPT: Final = _MAX_CODEWORD_LENGTH + 2  # explicit run of zeros
_TABLE_PREV: Final = _MAX_CODEWORD_LENGTH + 3  # repeat previous non-zero length
_TABLE_ROW_0: Final = _MAX_CODEWORD_LENGTH + 4  # copy length[i - 16]
_TABLE_ROW_1: Final = _MAX_CODEWORD_LENGTH + 5  # copy length[i - 16] + 1
_TABLE_ALPHABET_SIZE: Final = _MAX_CODEWORD_LENGTH + 6  # HUFFMAN_ENCODED_TABLE_SIZE = 33
_TABLE_ZERO_REPT_MIN_COUNT: Final = 5  # HUFFMAN_ENCODED_TABLE_ZERO_REPT_MIN_COUNT
_TABLE_FILL_BOUNDARY: Final = 16  # HUFFMAN_ENCODED_TABLE_FILL_BOUNDARY

# Table-serialization framing values (Xpress9DecHuffman.c).
_TABLE_ENCODING_STORED: Final = 0  # 3-bit mode 0: computed 9/10-bit lengths (Xpress9DecHuffman.c:431-452)
_TABLE_ENCODING_HUFFMAN: Final = 1  # 3-bit mode 1: Huffman-coded length table (Xpress9DecHuffman.c:456-460)
_SMALL_TABLE_MAX_LENGTH: Final = 8  # small-table lengths are capped at 8 bits (Xpress9DecHuffman.c:481)
_SMALL_TABLE_INITIAL_PREV: Final = 4  # uPrevSymbol seed while reading the small table (Xpress9DecHuffman.c:465)
_MAIN_TABLE_INITIAL_PREV: Final = 8  # uPrevSymbol seed for the main loop (Xpress9DecHuffman.c:510)
_ZERO_REPT_EXTEND: Final = 3  # 2-bit count of 3 starts the extension loop (Xpress9DecHuffman.c:545)
_ZERO_REPT_CONTINUE: Final = 7  # 3-bit extension of 7 keeps extending (Xpress9DecHuffman.c:558)

_BLOCK_HEADER: Final = struct.Struct("<8I")
"""Little-endian layout of ``LZ77_BLOCK_HEADER`` (Xpress9Internal.h:972-984)."""

_FLAGS_HUFFMAN_TABLE_BITS_MASK: Final = 0x1FFF  # flags bits 0..12 (Xpress9DecLz77.c:656)
_FLAGS_RESERVED_SHIFT: Final = 20  # flags bits 20..31 must be zero (Xpress9DecLz77.c:698)

# Safety ceiling on the plaintext one cell may decode to. Each block's u32 orig_size
# is attacker-controlled, and a single Elias-escaped match can encode a length near
# 2**30 from a few bytes of input, so an unbounded decode is a classic decompression
# bomb. ESE bounds its own decode by the caller's output buffer (cbDataMax, returning
# JET_wrnBufferTruncated on overflow, compression.cxx:2452-2454); this whole-buffer API
# has no caller budget, so it substitutes a fixed limit far above any real ESE cell.
# This is a library safety limit, not an XPRESS9 format constraint.
_MAX_DECODED_SIZE: Final = 1 << 30

# --- Bit input ---


class _BitReader:
    """LSB-first bit reader over one block's payload bitstream.

    Port of the ``BIORD_*`` macro family (Xpress9Internal.h:390-472): the encoder
    packs values least-significant-bit first into a shift register flushed as
    little-endian half-words (``BIOWR``, Xpress9Internal.h:313-361), which makes the
    byte stream a plain LSB-first bitstream regardless of word size. Like the C shift
    register, which preloads ``sizeof(BIO_FULL)`` bytes at a time and is allowed a
    small overrun past the block end (Xpress9DecLz77.c:940-950), this reader serves
    up to 8 phantom zero bytes past the end before treating a read as corrupt; the
    caller's exact bits-consumed checks reject any stream that relied on them.
    """

    __slots__ = ("_acc", "_data", "_navail", "_pos", "_size")

    _OVERRUN_BYTES: Final = 8  # sizeof(BIO_FULL) on 64-bit builds (Xpress9Internal.h:253)

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._size = len(data)
        self._pos = 0
        self._acc = 0
        self._navail = 0

    @property
    def bits_consumed(self) -> int:
        """Bits consumed so far, as measured by ``BIORD_TELL_CONSUMED_BITS_STATE`` (Xpress9Internal.h:471-472)."""
        return (self._pos << 3) - self._navail

    def read(self, count: int) -> int:
        """Return the next ``count`` bits as an integer, first stream bit in the LSB (``BIORD_LOAD``)."""
        while self._navail < count:
            if self._pos < self._size:
                self._acc |= self._data[self._pos] << self._navail
            elif self._pos >= self._size + self._OVERRUN_BYTES:
                msg = "XPRESS9 bitstream exhausted: the block needs more bits than its declared compressed size holds"
                raise DecompressionError(msg)
            self._pos += 1
            self._navail += 8
        value = self._acc & ((1 << count) - 1)
        self._acc >>= count
        self._navail -= count
        return value


# --- Canonical Huffman ---


class _CanonicalHuffman:
    """Canonical-Huffman decoder over a code-length table.

    Equivalent to ``HuffmanCreateDecodeTables`` + ``HUFFMAN_DECODE_SYMBOL``
    (Xpress9DecHuffman.c:154-321, Xpress9Internal.h:581-601) without the multi-level
    lookup tables: the C builder assigns each symbol a contiguous interval of the
    code space in descending (length, symbol) order from the top, which is exactly
    the standard canonical code over ascending (length, symbol) order, transmitted
    bit-reversed (``HuffmanReverseMask``, Xpress9Misc.c:123-149) so codewords are
    read MSB-first from the LSB-first stream one bit at a time.
    """

    __slots__ = ("_base_index", "_counts", "_first_code", "_max_length", "_single", "_symbols")

    def __init__(self, lengths: list[int]) -> None:
        """Build the decoder, validating the tree like ``HuffmanDecodeVerifyTree`` (Xpress9DecHuffman.c:108-143).

        Raises:
            DecompressionError: No symbol has a codeword, or the codeword lengths do
                not describe a full binary tree (Kraft sum exactly one).
        """
        present = sorted((length, symbol) for symbol, length in enumerate(lengths) if length)
        if not present:
            msg = "XPRESS9 Huffman code-length table has no symbols"
            raise DecompressionError(msg)
        self._max_length = present[-1][0]
        self._single: tuple[int, int] | None = None
        if len(present) == 1:
            # Single-symbol special case (Xpress9DecHuffman.c:354-375): the whole
            # lookup table maps to one symbol, so a decode just skips the codeword
            # bits (their values are ignored) and returns the symbol.
            self._single = (present[0][1], present[0][0])
            self._counts, self._first_code, self._base_index, self._symbols = [], [], [], []
            return
        counts = [0] * (self._max_length + 1)
        for length, _ in present:
            counts[length] += 1
        # Full-tree (Kraft) check, ported from HuffmanDecodeVerifyTree: walking from
        # the deepest level up, each level must pair all its nodes.
        nodes = 0
        for length in range(self._max_length, 0, -1):
            nodes += counts[length]
            if nodes & 1:
                msg = f"XPRESS9 Huffman code lengths do not form a full tree at depth {length}"
                raise DecompressionError(msg)
            nodes >>= 1
        if nodes != 1:
            msg = "XPRESS9 Huffman code lengths do not form a full tree"
            raise DecompressionError(msg)
        first_code = [0] * (self._max_length + 1)
        base_index = [0] * (self._max_length + 1)
        code = 0
        index = 0
        for length in range(1, self._max_length + 1):
            first_code[length] = code
            base_index[length] = index
            code = (code + counts[length]) << 1
            index += counts[length]
        self._counts = counts
        self._first_code = first_code
        self._base_index = base_index
        self._symbols = [symbol for _, symbol in present]

    def decode(self, reader: _BitReader) -> int:
        """Decode one symbol from the stream (``HUFFMAN_DECODE_SYMBOL``, Xpress9Internal.h:581-601)."""
        if self._single is not None:
            symbol, skip = self._single
            reader.read(skip)
            return symbol
        code = 0
        for length in range(1, self._max_length + 1):
            code = (code << 1) | reader.read(1)
            delta = code - self._first_code[length]
            if delta < self._counts[length]:
                return self._symbols[self._base_index[length] + delta]
        # Unreachable for a full tree (every bit path terminates), kept as a guard.
        msg = "XPRESS9 Huffman codeword exceeds the table's maximum length"
        raise DecompressionError(msg)


def _decode_zero_run(reader: _BitReader, position: int, alphabet_size: int, fill_boundary: int) -> int:
    """Read a ``HUFFMAN_ENCODED_TABLE_ZERO_REPT`` run length (Xpress9DecHuffman.c:541-564).

    The run is 5..8 from a 2-bit count, open-ended via 3-bit extensions when the
    2-bit count saturates; it may neither pass the end of the alphabet nor cross a
    fill boundary (the ``(i ^ (i + run)) >= uFillBoundary`` check).
    """
    count = reader.read(2)
    run = count + _TABLE_ZERO_REPT_MIN_COUNT
    if count == _ZERO_REPT_EXTEND:
        while True:
            count = reader.read(3)
            run += count
            if position + run > alphabet_size or (position ^ (position + run)) >= fill_boundary:
                msg = f"XPRESS9 encoded Huffman table: zero run of {run} at index {position} overflows the alphabet or crosses a fill boundary"
                raise DecompressionError(msg)
            if count != _ZERO_REPT_CONTINUE:
                break
    if position + run > alphabet_size or (position ^ (position + run)) >= fill_boundary:
        msg = f"XPRESS9 encoded Huffman table: zero run of {run} at index {position} overflows the alphabet or crosses a fill boundary"
        raise DecompressionError(msg)
    return run


def _decode_small_table(reader: _BitReader) -> _CanonicalHuffman:
    """Read the 33-symbol "small" code that compresses the length table itself (Xpress9DecHuffman.c:462-508).

    Each small-table length is either "same as previous" (1 flag bit) or a 3-bit
    value, biased by one when it collides with the previous value; lengths above 8
    bits are corrupt.
    """
    prev = _SMALL_TABLE_INITIAL_PREV
    lengths: list[int] = []
    for _ in range(_TABLE_ALPHABET_SIZE):
        if reader.read(1) == 0:
            lengths.append(prev)
            continue
        value = reader.read(3)
        if value >= prev:
            value += 1
            if value > _SMALL_TABLE_MAX_LENGTH:
                msg = f"XPRESS9 encoded Huffman table: small-table codeword length {value} exceeds {_SMALL_TABLE_MAX_LENGTH}"
                raise DecompressionError(msg)
        lengths.append(value)
        prev = value
    return _CanonicalHuffman(lengths)


def _apply_fill(lengths: list[int], position: int, fill_boundary: int) -> int:
    """Apply a ``HUFFMAN_ENCODED_TABLE_FILL`` opcode (Xpress9DecHuffman.c:531-539): at least one zero, up to the next boundary."""
    alphabet_size = len(lengths)
    while True:  # do-while in the C
        lengths[position] = 0
        position += 1
        if position & (fill_boundary - 1) == 0 or position >= alphabet_size:
            return position


def _apply_row(lengths: list[int], position: int, symbol: int, fill_boundary: int) -> int:
    """Apply a ``HUFFMAN_ENCODED_TABLE_ROW_0/ROW_1`` opcode (Xpress9DecHuffman.c:581-613): copy the length one boundary back, ROW_1 plus one.

    Returns the copied length (which also becomes the new "previous" length).
    """
    if position < fill_boundary:
        msg = f"XPRESS9 encoded Huffman table: ROW opcode at index {position} has no previous row"
        raise DecompressionError(msg)
    value = lengths[position - fill_boundary] + (1 if symbol == _TABLE_ROW_1 else 0)
    if value == 0 or value > _MAX_CODEWORD_LENGTH:
        msg = f"XPRESS9 encoded Huffman table: ROW opcode yields invalid codeword length {value}"
        raise DecompressionError(msg)
    lengths[position] = value
    return value


def _decode_coded_lengths(reader: _BitReader, alphabet_size: int, fill_boundary: int) -> list[int]:
    """Read a mode-1 (Huffman-coded) code-length table body (Xpress9DecHuffman.c:462-615)."""
    small = _decode_small_table(reader)
    lengths = [0] * alphabet_size
    prev = _MAIN_TABLE_INITIAL_PREV
    position = 0
    while position < alphabet_size:
        symbol = small.decode(reader)
        if symbol < _TABLE_FILL:
            # Plain codeword length 0..27 (the C also re-checks uMaxCodewordLength
            # here, Xpress9DecHuffman.c:517; symbol values are already <= 27).
            lengths[position] = symbol
            position += 1
            if symbol:
                prev = symbol
        elif symbol == _TABLE_FILL:
            position = _apply_fill(lengths, position, fill_boundary)
        elif symbol == _TABLE_ZERO_REPT:
            position += _decode_zero_run(reader, position, alphabet_size, fill_boundary)
        elif symbol == _TABLE_PREV:
            lengths[position] = prev
            position += 1
        else:  # _TABLE_ROW_0 or _TABLE_ROW_1
            prev = _apply_row(lengths, position, symbol, fill_boundary)
            position += 1
    return lengths


def _decode_length_table(reader: _BitReader, alphabet_size: int, fill_boundary: int) -> list[int]:
    """Deserialize one canonical-Huffman code-length table (``HuffmanDecodeLengthTable``, Xpress9DecHuffman.c:405-622).

    A 3-bit mode selects "stored" (mode 0: the first ``2**(M+1) - |A|`` symbols get
    ``M = floor(log2 |A|)`` bits, the rest ``M + 1``, Xpress9DecHuffman.c:431-452) or
    a Huffman-coded table (mode 1: lengths 0..27 plus the FILL/ZERO_REPT/PREV/ROW_0/
    ROW_1 opcodes decoded through the small table). Both main alphabets use fill
    boundary 16 (``LZ77_MAX_SHORT_LENGTH``, Xpress9DecLz77.c:386-419).
    """
    mode = reader.read(3)
    if mode == _TABLE_ENCODING_STORED:
        msb = alphabet_size.bit_length() - 1  # GET_MSB (Xpress9Internal.h:654)
        short_count = (1 << (msb + 1)) - alphabet_size
        return [msb] * short_count + [msb + 1] * (alphabet_size - short_count)
    if mode != _TABLE_ENCODING_HUFFMAN:
        msg = f"XPRESS9 encoded Huffman table: unknown table encoding {mode}"
        raise DecompressionError(msg)
    return _decode_coded_lengths(reader, alphabet_size, fill_boundary)


# --- Block header ---


@dataclass(frozen=True)
class Xpress9BlockHeader:
    """Parsed and validated 32-byte ``LZ77_BLOCK_HEADER`` (Xpress9Internal.h:972-995).

    Attributes:
        orig_size: ``m_uOrigSizeBytes`` -- uncompressed size of this block.
        comp_size_bits: ``m_uCompSizeBits`` -- exact compressed size in bits,
            *including* the 256 header bits (Xpress9EncLz77.c:1452-1462); the block
            occupies ``ceil(comp_size_bits / 8)`` bytes on disk.
        huffman_table_bits: flags bits 0..12 -- bits spent on the MTF initial state
            plus both serialized Huffman tables (Xpress9DecLz77.c:656, :797-802).
        window_size_log2: flags bits 13..15 plus 16 (Xpress9DecLz77.c:665).
        mtf_entry_count: flags bits 16..17 doubled: 0, 2 or 4 (Xpress9DecLz77.c:659).
        ptr_min_match_length: flags bit 18 plus 3 (Xpress9DecLz77.c:666).
        mtf_min_match_length: flags bit 19 plus 2 (Xpress9DecLz77.c:667).
        session_signature: ``m_uSessionSignature`` -- captured from the first block,
            identical on every later block (Xpress9DecLz77.c:616, :625).
        block_index: ``m_uBlockSignature`` -- sequential block number starting at 0
            (Xpress9DecLz77.c:619).
    """

    orig_size: int
    comp_size_bits: int
    huffman_table_bits: int
    window_size_log2: int
    mtf_entry_count: int
    ptr_min_match_length: int
    mtf_min_match_length: int
    session_signature: int
    block_index: int


def parse_block_header(payload: Buffer, offset: int = 0) -> Xpress9BlockHeader:
    """Parse and validate one block header, mirroring ``Xpress9DecoderFetchDecompressedData`` (Xpress9DecLz77.c:607-716).

    Checks, in the C decoder's order: magic, reserved word zero, header CRC-32C over
    the first seven words seeded by the (zero) reserved word (Xpress9DecLz77.c:638;
    ``Xpress9Crc32`` in Xpress9Misc.c:229-247 is plain CRC-32C for a zero seed),
    reserved flag bits, MTF entry count, and that the compressed bit size exceeds
    the header-plus-tables overhead.

    Raises:
        DecompressionError: The buffer is too short or any header check fails.
    """
    if len(payload) - offset < BLOCK_HEADER_SIZE:
        msg = f"XPRESS9 block header truncated: need {BLOCK_HEADER_SIZE} bytes, have {len(payload) - offset}"
        raise DecompressionError(msg)
    words = _BLOCK_HEADER.unpack_from(payload, offset)
    if words[0] != XPRESS9_MAGIC:
        msg = f"bad XPRESS9 block magic 0x{words[0]:08x}, expected 0x{XPRESS9_MAGIC:08x}"
        raise DecompressionError(msg)
    if words[4] != 0:
        msg = f"XPRESS9 block header reserved word is 0x{words[4]:08x}, must be 0"
        raise DecompressionError(msg)
    actual_crc = crc32c_ese(memoryview(payload)[offset : offset + BLOCK_HEADER_SIZE - 4])
    if words[7] != actual_crc:
        msg = f"XPRESS9 block header CRC-32C mismatch: header says 0x{words[7]:08x}, first seven words hash to 0x{actual_crc:08x}"
        raise DecompressionError(msg)
    flags = words[3]
    if flags >> _FLAGS_RESERVED_SHIFT:
        msg = f"XPRESS9 block flags reserved bits are non-zero: 0x{flags:08x}"
        raise DecompressionError(msg)
    mtf_entry_count = ((flags >> 16) & 3) << 1
    if mtf_entry_count > _MAX_MTF:
        # The 2-bit field value 3 encodes the reserved MTF count 6 (Xpress9DecLz77.c:660-664).
        msg = f"XPRESS9 block declares reserved MTF entry count {mtf_entry_count}"
        raise DecompressionError(msg)
    huffman_table_bits = flags & _FLAGS_HUFFMAN_TABLE_BITS_MASK
    if words[2] <= huffman_table_bits + BLOCK_HEADER_SIZE * 8:
        # Xpress9DecLz77.c:712: the bitstream must hold more than header + tables.
        msg = f"XPRESS9 block compressed size of {words[2]} bits does not exceed its header and Huffman tables"
        raise DecompressionError(msg)
    return Xpress9BlockHeader(
        orig_size=words[1],
        comp_size_bits=words[2],
        huffman_table_bits=huffman_table_bits,
        window_size_log2=((flags >> 13) & 7) + 16,
        mtf_entry_count=mtf_entry_count,
        ptr_min_match_length=((flags >> 18) & 1) + 3,
        mtf_min_match_length=((flags >> 19) & 1) + 2,
        session_signature=words[5],
        block_index=words[6],
    )


# --- LZ77 token stream ---


def _read_mtf_initial_state(reader: _BitReader, header: Xpress9BlockHeader) -> tuple[int, list[int]]:
    """Read the block's MTF seed: the last-was-pointer flag and the initial offsets (Xpress9DecodeState, Xpress9DecLz77.c:362-383).

    Each offset is Elias-gamma-style: a 5-bit MSB position (which must lie inside
    the window) followed by that many low bits, decoding to ``low + 2**msb``.
    """
    last_was_ptr = reader.read(1)
    offsets: list[int] = []
    for _ in range(header.mtf_entry_count):
        msb = reader.read(5)
        if msb >= header.window_size_log2:
            msg = f"XPRESS9 MTF initial offset MSB {msb} is outside the {header.window_size_log2}-bit window"
            raise DecompressionError(msg)
        offsets.append(reader.read(msb) + (1 << msb))
    return last_was_ptr, offsets


def _take_mtf_offset(mtf: list[int], symbol: int, *, last_was_ptr: bool) -> int:
    """Pick and reorder the MTF (repeated-offset) list for one MTF match (Xpress9Lz77Dec.i:143-220).

    When the previous emission was also a pointer, slot 0 is skipped (it would just
    repeat that pointer, which the encoder would have merged), so symbol ``k`` means
    slot ``k + 1`` and the top two valid symbols collapse; after a literal, symbol
    ``k`` means slot ``k``. Either way the chosen offset moves to the front, except
    that re-using slot 0 after a literal leaves the list untouched.
    """
    if last_was_ptr:
        if symbol >= len(mtf) - 1:
            msg = f"XPRESS9 MTF symbol {symbol} is invalid directly after a pointer"
            raise DecompressionError(msg)
        offset = mtf.pop(symbol + 1)
        mtf.insert(0, offset)
        return offset
    offset = mtf[symbol]
    if symbol:
        del mtf[symbol]
        mtf.insert(0, offset)
    return offset


def _read_match_length(reader: _BitReader, long_table: _CanonicalHuffman) -> int:
    """Read an escaped (>= 15) match-length base value (Xpress9Lz77Dec.i:128-141).

    Long lengths come from the second Huffman alphabet; values past 232
    (``LZ77_MAX_LONG_LENGTH``) are a further Elias-gamma escape where the symbol
    encodes the extra bit count. The returned value still excludes the per-kind
    minimum match length.
    """
    length = long_table.decode(reader)
    if length >= _MAX_LONG_LENGTH:
        extra_bits = length - _MAX_LONG_LENGTH
        length = reader.read(extra_bits) + (1 << extra_bits) + (_MAX_LONG_LENGTH - 1)
    return length + _MAX_SHORT_LENGTH - 1


def _copy_match(out: bytearray, offset: int, length: int) -> None:
    """Append ``length`` bytes copied from ``offset`` bytes back, LZ77-overlap semantics (Xpress9Lz77Dec.i:246-291).

    The C copies byte-by-byte so an offset smaller than the length replicates the
    trailing pattern; slicing reproduces that by repeating the source chunk.
    """
    start = len(out) - offset
    if length <= offset:
        out += out[start : start + length]
    else:
        repeats = -(-length // offset)
        out += (out[start:] * repeats)[:length]


def _read_block_prelude(reader: _BitReader, header: Xpress9BlockHeader) -> tuple[int, list[int], _CanonicalHuffman, _CanonicalHuffman]:
    """Read everything before the token stream: MTF seed and both Huffman tables (Xpress9DecodeState, Xpress9DecLz77.c:346-442).

    Returns ``(last_was_ptr, mtf_offsets, short_table, long_table)`` and enforces
    that the prelude consumed exactly ``huffman_table_bits`` (Xpress9DecLz77.c:797-802).
    """
    last_was_ptr = 0
    mtf: list[int] = []
    if header.mtf_entry_count:
        last_was_ptr, mtf = _read_mtf_initial_state(reader, header)
    short_table = _CanonicalHuffman(_decode_length_table(reader, _SHORT_SYMBOL_ALPHABET_SIZE, _MAX_SHORT_LENGTH))
    long_table = _CanonicalHuffman(_decode_length_table(reader, _LONG_LENGTH_ALPHABET_SIZE, _MAX_SHORT_LENGTH))
    if reader.bits_consumed != header.huffman_table_bits:
        msg = f"XPRESS9 Huffman tables consumed {reader.bits_consumed} bits but the header declares {header.huffman_table_bits}"
        raise DecompressionError(msg)
    return last_was_ptr, mtf, short_table, long_table


def _decode_block(reader: _BitReader, header: Xpress9BlockHeader, out: bytearray) -> None:
    """Decode one block's bitstream into ``out`` (Xpress9Lz77Dec.i:101-293 plus the driver's end-of-block checks).

    ``out`` holds the whole session so far: match offsets may reach back into
    previous blocks of the same session (the C decoder keeps its window across
    blocks, Xpress9DecLz77.c:707-708 resets only per-block byte counters).
    """
    last_was_ptr, mtf, short_table, long_table = _read_block_prelude(reader, header)
    target = len(out) + header.orig_size
    while len(out) < target:
        symbol = short_table.decode(reader)
        if symbol < 256:
            out.append(symbol)
            last_was_ptr = 0
            continue
        symbol -= 256
        length = symbol & (_MAX_SHORT_LENGTH - 1)
        symbol >>= _MAX_SHORT_LENGTH_LOG
        if length == _MAX_SHORT_LENGTH - 1:
            length = _read_match_length(reader, long_table)
        if symbol < header.mtf_entry_count:
            length += header.mtf_min_match_length
            offset = _take_mtf_offset(mtf, symbol, last_was_ptr=bool(last_was_ptr))
        else:
            length += header.ptr_min_match_length
            msb = symbol - header.mtf_entry_count
            offset = reader.read(msb) + (1 << msb)
            if mtf:
                mtf.insert(0, offset)
                mtf.pop()
        if offset > len(out):
            # Xpress9Lz77Dec.i:248-252: the match may not reach before the session start.
            msg = f"XPRESS9 match offset {offset} reaches before the start of the data at position {len(out)}"
            raise DecompressionError(msg)
        if length > target - len(out):
            # Xpress9DecLz77.c:837-844: a token whose copy would pass the block's
            # declared orig_size is corrupt. Rejecting before the copy (rather than
            # after, as the C driver's end-of-block check does) means a forged length
            # can never allocate past the declared bound.
            msg = f"XPRESS9 match of length {length} overruns the block's declared {header.orig_size}-byte size"
            raise DecompressionError(msg)
        last_was_ptr = 1
        _copy_match(out, offset, length)
    if len(out) != target:
        # Xpress9DecLz77.c:842-861: a match overshooting the declared size is corrupt.
        msg = f"XPRESS9 block decoded {len(out) - target + header.orig_size} bytes but the header declares {header.orig_size}"
        raise DecompressionError(msg)
    if reader.bits_consumed != header.comp_size_bits - BLOCK_HEADER_SIZE * 8:
        # Xpress9DecLz77.c:843-845: the stream must consume exactly m_uCompSizeBits.
        msg = f"XPRESS9 block consumed {reader.bits_consumed + BLOCK_HEADER_SIZE * 8} bits but the header declares {header.comp_size_bits}"
        raise DecompressionError(msg)


# --- Session (block sequence) ---


def _session_blocks(payload: bytes) -> list[tuple[Xpress9BlockHeader, int, int]]:
    """Split a codec payload into validated, byte-aligned blocks.

    Returns ``(header, body_start, body_end)`` per block. Consecutive blocks must
    share the first block's session signature and coding parameters and carry
    sequential block indices (Xpress9DecLz77.c:613-696). ESE cells hold exactly one
    block (``ErrDecompressXpress9_`` fetches once, compression.cxx:2437-2449); the
    multi-block walk matches the codec's own session semantics.

    Raises:
        DecompressionError: Empty payload, truncated block, or any header check fails.
    """
    blocks: list[tuple[Xpress9BlockHeader, int, int]] = []
    first: Xpress9BlockHeader | None = None
    offset = 0
    while offset < len(payload):
        header = parse_block_header(payload, offset)
        if first is None:
            first = header
        elif header.session_signature != first.session_signature:
            msg = f"XPRESS9 block {len(blocks)} session signature 0x{header.session_signature:08x} does not match the session's 0x{first.session_signature:08x}"
            raise DecompressionError(msg)
        elif (header.window_size_log2, header.mtf_entry_count, header.ptr_min_match_length, header.mtf_min_match_length) != (first.window_size_log2, first.mtf_entry_count, first.ptr_min_match_length, first.mtf_min_match_length):
            msg = f"XPRESS9 block {len(blocks)} changes the session's coding parameters"
            raise DecompressionError(msg)
        if header.block_index != len(blocks):
            msg = f"XPRESS9 block carries index {header.block_index}, expected {len(blocks)}"
            raise DecompressionError(msg)
        end = offset + ((header.comp_size_bits + 7) >> 3)
        if end > len(payload):
            msg = f"XPRESS9 block truncated: needs {end - offset} bytes, only {len(payload) - offset} remain"
            raise DecompressionError(msg)
        blocks.append((header, offset + BLOCK_HEADER_SIZE, end))
        offset = end
    if not blocks:
        msg = "XPRESS9 cell has no block after the 5-byte record header"
        raise DecompressionError(msg)
    return blocks


def _parse_outer(blob: Buffer) -> tuple[int, bytes]:
    """Split a framed cell into the stored plaintext CRC-32C and the codec payload.

    Mirrors the entry of ``ErrDecompressXpress9_`` (compression.cxx:2411-2426): the
    5-byte header is reserved and the identifier is the top five bits of byte 0.
    """
    from ntcompress.ese import Format, format_id  # deferred to avoid circular

    if len(blob) < HEADER_SIZE:
        msg = f"XPRESS9 cell is {len(blob)} bytes; the record header alone is {HEADER_SIZE}"
        raise DecompressionError(msg)
    view = memoryview(blob)
    scheme_byte = view[0]
    if format_id(scheme_byte) != Format.XPRESS9:
        msg = f"expected format XPRESS9 (0x{Format.XPRESS9:x}) but header byte 0x{scheme_byte:02x} carries format 0x{format_id(scheme_byte):x}"
        raise DecompressionError(msg)
    (stored_crc,) = struct.unpack_from("<I", view, 1)
    return stored_crc, bytes(view[HEADER_SIZE:])


# --- Bit output (encoder) ---

# ESE fixed "Cosmos Level 6" parameters (compression.cxx:1696-1706).
_ENC_WINDOW_SIZE_LOG2: Final = 16
_ENC_WINDOW_SIZE: Final = 1 << _ENC_WINDOW_SIZE_LOG2  # 64 KB
_ENC_MTF_ENTRY_COUNT: Final = 4
_ENC_PTR_MIN_MATCH_LENGTH: Final = 4
_ENC_MTF_MIN_MATCH_LENGTH: Final = 2
_ENC_SESSION_SIGNATURE: Final = 0x12345678

# Minimum input size: a block must have at least one token, plus header overhead.
_MIN_COMPRESS_INPUT: Final = 1

# Hash table sizing follows the C encoder's StartSession logic
# (Xpress9EncLz77.c:1062-1102): uMsb = window_log2 - 1, then capped by
# lookup depth.  The oracle binary uses LookupDepth=1 and window 2^16,
# giving uMsb = 16-1 = 15, capped to 12 (case 1), so hash table = 2^12.
_HASH_TABLE_SIZE_LOG2: Final = 12
_HASH_TABLE_SIZE: Final = 1 << _HASH_TABLE_SIZE_LOG2  # 4096
_HASH_MASK: Final = _HASH_TABLE_SIZE - 1

# The oracle binary sets LookupDepth=1 and OptimizationLevel=1 (lazy match
# evaluation).  The C encoder adds 1 to LookupDepth before the lookup loop
# (Xpress9Lz77EncPass1.i:65), giving uMaxDepth = 2.
_ENC_LOOKUP_DEPTH: Final = 1
_ENC_MAX_DEPTH: Final = _ENC_LOOKUP_DEPTH + 1  # 2

# IR buffer chunk size (Xpress9EncLz77.c:926,1570-1581): the C encoder's
# intermediate representation buffer limits how many input bytes can be
# processed per insert+pass1 iteration.  The IR buffer is twice the window
# size; usable capacity is one third of that minus 256 bytes of headroom.
_IR_BUFFER_SIZE: Final = 2 * _ENC_WINDOW_SIZE  # 131072
_IR_CHUNK_SIZE: Final = _IR_BUFFER_SIZE // 3 - 256  # 43434

# Maximum-offset-by-length table (Xpress9EncLz77.c:297-310).  Matches
# shorter than len(table) are rejected when the (negative) offset is not
# large enough (i.e. too far away).  Signed 32-bit values.
_MAX_OFFSET_BY_LENGTH: Final[tuple[int, ...]] = (
    0,  # length 0 -- unused
    0,  # length 1 -- unused
    -(1 << 6),  # length 2: -64
    -(1 << 10),  # length 3: -1024
    -(1 << 13),  # length 4: -8192
    -(1 << 16),  # length 5: -65536
)


class _BitWriter:
    """LSB-first bit writer, the encoding counterpart of ``_BitReader``.

    Port of the ``BIOWR`` macro family (Xpress9Internal.h:313-372): values are
    accumulated into a shift register and flushed to a ``bytearray`` as complete
    bytes. The ``flush`` call writes any remaining partial byte.
    """

    __slots__ = ("_acc", "_buf", "_navail")

    def __init__(self) -> None:
        self._buf = bytearray()
        self._acc = 0
        self._navail = 0

    @property
    def bits_written(self) -> int:
        """Total bits written so far, including unflushed accumulator bits."""
        return len(self._buf) * 8 + self._navail

    def write(self, value: int, count: int) -> None:
        """Write ``count`` bits of ``value``, LSB first (``BIOWR``)."""
        self._acc |= value << self._navail
        self._navail += count
        while self._navail >= 8:
            self._buf.append(self._acc & 0xFF)
            self._acc >>= 8
            self._navail -= 8

    def flush(self) -> None:
        """Write any remaining partial byte (``BIOWR_FLUSH``)."""
        if self._navail > 0:
            self._buf.append(self._acc & 0xFF)
            self._acc = 0
            self._navail = 0

    def getvalue(self) -> bytes:
        """Return the written bytes. Must call ``flush`` first."""
        return bytes(self._buf)


# --- Canonical Huffman encoder ---


def _reverse_mask(value: int, bits: int) -> int:
    """Reverse the lowest ``bits`` bits of ``value`` (HuffmanReverseMask, Xpress9Misc.c:123-149).

    The C codec writes codewords bit-reversed so the decoder can read them MSB-first
    from the LSB-first bitstream. This is the same bit-reversal used during tree
    construction in ``HuffmanCreateCodewords`` (Xpress9EncHuffman.c:624-665).
    """
    result = 0
    for _ in range(bits):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def _build_huffman_codes(counts: list[int], alphabet_size: int, max_codeword_length: int) -> list[tuple[int, int]]:
    """Build canonical Huffman codewords from frequency counts.

    Port of ``Xpress9HuffmanCreateTree`` (Xpress9EncHuffman.c:673-797): build a tree,
    compute bit-lengths, truncate to ``max_codeword_length``, canonize, and create
    bit-reversed codewords. Returns ``(reversed_codeword, length)`` per symbol; symbols
    with zero count get ``(0, 0)``.
    """
    # Collect symbols that have non-zero counts.
    present = sorted(
        ((counts[i], i) for i in range(alphabet_size) if counts[i] > 0),
        key=lambda x: (x[0], x[1]),
    )
    n = len(present)

    result: list[tuple[int, int]] = [(0, 0)] * alphabet_size

    if n == 0:
        return result

    if n == 1:
        # Single-symbol special case: one-bit codeword (Xpress9EncHuffman.c:698-712).
        sym = present[0][1]
        result[sym] = (0, 1)
        return result

    # Build Huffman tree using a two-queue approach (equivalent to the C merge-sort
    # based tree builder). We only need the bit-lengths, not the tree structure.
    # Use the standard "package merge" / tree-from-queues approach.
    queue_leaf = list(present)  # (count, symbol)
    queue_node: list[tuple[int, list[int]]] = []  # (count, [symbols...])
    li = 0
    ni = 0

    def _pop_min() -> tuple[int, list[int]]:
        nonlocal li, ni
        lv = queue_leaf[li][0] if li < len(queue_leaf) else float("inf")
        nv = queue_node[ni][0] if ni < len(queue_node) else float("inf")
        if lv <= nv:
            c, s = queue_leaf[li]
            li += 1
            return (c, [s])
        r = queue_node[ni]
        ni += 1
        return r

    # Build n-1 internal nodes.
    for _ in range(n - 1):
        left_c, left_s = _pop_min()
        right_c, right_s = _pop_min()
        queue_node.append((left_c + right_c, left_s + right_s))

    # The last node is the root. Assign depths.
    depths = [0] * alphabet_size
    # BFS from root: root is at depth 0, children at depth+1. We track depth via the
    # tree structure implicitly: we built it bottom-up, so the root's symbol list has
    # all symbols. Instead, recompute depths by walking the merge history.
    # Simpler: we have n leaves, n-1 internal nodes. Walk from root.
    # Actually, the simplest correct approach: use the standard bit-length algorithm.
    # Count how many nodes at each depth.
    # First, compute raw depths from the tree structure.
    _compute_depths_from_tree(queue_leaf, queue_node, depths, li, ni, n)

    # Count symbols at each depth.
    bit_length_count = [0] * 65
    for d in depths:
        if d > 0:
            bit_length_count[d] += 1

    # Truncate tree to max_codeword_length (HuffmanTruncateTree, Xpress9EncHuffman.c:460-508).
    for i in range(64, max_codeword_length, -1):
        while bit_length_count[i] > 0:
            # Find deepest level j < max_codeword_length with a leaf.
            j = max_codeword_length - 1
            while j > 0 and bit_length_count[j] == 0:
                j -= 1
            bit_length_count[j] -= 1
            bit_length_count[j + 1] += 2
            bit_length_count[i - 1] += 1
            bit_length_count[i] -= 2

    # Assign final lengths: sort symbols by (count, symbol) ascending, assign longest
    # codewords to least frequent (HuffmanCanonizeTree, Xpress9EncHuffman.c:514-617).
    sorted_symbols = [s for _, s in present]
    sym_lengths = [0] * alphabet_size
    idx = 0
    for length in range(max_codeword_length, 0, -1):
        for _ in range(bit_length_count[length]):
            sym_lengths[sorted_symbols[idx]] = length
            idx += 1

    # Build canonical codewords sorted by (length, symbol) ascending.
    # (HuffmanCreateCodewords, Xpress9EncHuffman.c:624-665).
    by_length_symbol = sorted(
        ((sym_lengths[s], s) for s in range(alphabet_size) if sym_lengths[s] > 0),
        key=lambda x: (x[0], x[1]),
    )
    code = 0
    prev_len = 0
    for length, sym in by_length_symbol:
        code <<= length - prev_len
        result[sym] = (_reverse_mask(code, length), length)
        code += 1
        prev_len = length

    return result


def _compute_depths_from_tree(
    queue_leaf: list[tuple[int, int]],
    _queue_node: list[tuple[int, list[int]]],
    depths: list[int],
    _li: int,
    _ni: int,
    n: int,
) -> None:
    """Compute symbol depths by walking the merged node structure.

    Each internal node in ``queue_node`` stores a list of the leaf symbols in its
    subtree. The root (last node) is at depth 0. For each internal node, we
    reconstruct the depth by tracking how the tree was built bottom-up.
    """
    if n <= 1:
        if n == 1:
            depths[queue_leaf[0][1]] = 1
        return

    # Rebuild: each internal node was formed by merging its two children. We need to
    # assign depths. The root is the last node in queue_node; its depth is 0. Walking
    # backward, each node's children are at parent_depth + 1. But we don't store the
    # tree edges. So: re-derive depths from scratch using the bit-length count method.
    #
    # Standard approach: sort symbols by count ascending, use the well-known algorithm
    # that computes optimal code lengths in O(n) given sorted input.
    sorted_symbols = [s for _, s in sorted(queue_leaf, key=lambda x: (x[0], x[1]))]
    sorted_counts = [c for c, _ in sorted(queue_leaf, key=lambda x: (x[0], x[1]))]

    # Kraft-optimal lengths via the in-place algorithm (similar to what the C code
    # does with its tree walker). We'll use a simple simulation.
    # Merge two queues to build the tree, tracking depth.
    node_counts: list[int] = []
    node_depths: list[int] = []
    si = 0
    ndi = 0

    def _get_min_count() -> tuple[int, int]:
        """Return (count, depth) of the minimum-count item from either queue."""
        nonlocal si, ndi
        sc = sorted_counts[si] if si < n else float("inf")
        nc = node_counts[ndi] if ndi < len(node_counts) else float("inf")
        if sc <= nc:  # type: ignore[operator]
            c = sorted_counts[si]
            si += 1
            return (c, 0)
        c = node_counts[ndi]
        d = node_depths[ndi]
        ndi += 1
        return (c, d)

    for _ in range(n - 1):
        c1, d1 = _get_min_count()
        c2, d2 = _get_min_count()
        parent_depth = max(d1, d2) + 1
        node_counts.append(c1 + c2)
        node_depths.append(parent_depth)

    # The root depth tells us the max depth from root. But we need per-symbol depths.
    # Instead, let's use the well-known algorithm that operates on the bit-length
    # count array derived from the tree. We'll redo this properly.
    # Reset and use a direct tree depth computation.
    # Build the actual tree to get depths.
    class _Node:
        __slots__ = ("count", "depth", "left", "right", "symbol")

        def __init__(self, *, count: int, symbol: int = -1) -> None:
            self.count = count
            self.symbol = symbol
            self.depth = 0
            self.left: _Node | None = None
            self.right: _Node | None = None

    leaves = [_Node(count=sorted_counts[i], symbol=sorted_symbols[i]) for i in range(n)]
    internals: list[_Node] = []
    ssi = 0
    isi = 0

    def _pop_min_node() -> _Node:
        nonlocal ssi, isi
        sv = leaves[ssi].count if ssi < n else float("inf")
        iv = internals[isi].count if isi < len(internals) else float("inf")
        if sv <= iv:  # type: ignore[operator]
            nd = leaves[ssi]
            ssi += 1
            return nd
        nd = internals[isi]
        isi += 1
        return nd

    for _ in range(n - 1):
        left = _pop_min_node()
        right = _pop_min_node()
        parent = _Node(count=left.count + right.count)
        parent.left = left
        parent.right = right
        internals.append(parent)

    root = internals[-1] if internals else leaves[0]

    # BFS to assign depths.
    stack: list[tuple[_Node, int]] = [(root, 0)]
    while stack:
        node, d = stack.pop()
        if node.symbol >= 0:
            depths[node.symbol] = max(d, 1)  # at least 1 for single-symbol case
        else:
            if node.left is not None:
                stack.append((node.left, d + 1))
            if node.right is not None:
                stack.append((node.right, d + 1))


# --- Huffman table serialization (encoder) ---


def _encode_small_table(writer: _BitWriter, code_lengths: list[tuple[int, int]]) -> None:
    """Write the 33-symbol "small" code-length table for the Huffman-coded table encoding.

    Port of the small table writer in ``Xpress9HuffmanEncodeTable`` (Xpress9EncHuffman.c:941-964):
    each symbol's codeword length is delta-coded against the previous, with a 1-bit
    flag for "same as previous" and a 3-bit value otherwise (biased by 1 when it
    collides with previous).
    """
    prev = _SMALL_TABLE_INITIAL_PREV
    for sym in range(_TABLE_ALPHABET_SIZE):
        length = code_lengths[sym][1]
        if length == prev:
            writer.write(0, 1)
        else:
            writer.write(1, 1)
            if length > prev:
                writer.write(length - 1, 3)
            else:
                writer.write(length, 3)
            prev = length


def _write_length_sequence(writer: _BitWriter, lengths: list[int], symbols: list[int], meta_codes: list[tuple[int, int]], alphabet_size: int, fill_boundary: int) -> None:
    """Write the Mode 1 encoded length sequence into ``writer``.

    Extracted from the Mode 1 path of ``_encode_huffman_table`` so that it can
    be called twice: once into a scratch writer (for cost measurement, matching
    the C encoder's approach at Xpress9EncHuffman.c:1129-1141) and once into
    the real output writer.
    """
    prev_sym = _MAIN_TABLE_INITIAL_PREV
    sym_idx = 0
    i = 0
    while i < alphabet_size:
        k = lengths[i]
        if k != 0:
            meta_sym = symbols[sym_idx]
            sym_idx += 1
            cw, cl = meta_codes[meta_sym]
            writer.write(cw, cl)
            if k != prev_sym:
                prev_sym = k
            i += 1
        else:
            zero_start = i
            while i < alphabet_size and lengths[i] == 0:
                i += 1
            k_pos = zero_start
            while (k_pos ^ i) >= fill_boundary:
                cw, cl = meta_codes[_TABLE_FILL]
                writer.write(cw, cl)
                sym_idx += 1
                k_pos = (k_pos & ~(fill_boundary - 1)) + fill_boundary
            remaining = i - k_pos
            if remaining > 0:
                if remaining < _TABLE_ZERO_REPT_MIN_COUNT:
                    for _ in range(remaining):
                        cw, cl = meta_codes[0]
                        writer.write(cw, cl)
                        sym_idx += 1
                else:
                    cw, cl = meta_codes[_TABLE_ZERO_REPT]
                    writer.write(cw, cl)
                    sym_idx += 1
                    run = remaining - _TABLE_ZERO_REPT_MIN_COUNT
                    if run < 3:
                        writer.write(run, 2)
                    else:
                        writer.write(3, 2)
                        run -= 3
                        while run >= 7:
                            writer.write(7, 3)
                            run -= 7
                        writer.write(run, 3)


def _encode_huffman_table(writer: _BitWriter, codes: list[tuple[int, int]], counts: list[int], alphabet_size: int, fill_boundary: int) -> list[tuple[int, int]]:
    """Serialize one canonical-Huffman code-length table into the bitstream.

    Port of ``Xpress9HuffmanCreateAndEncodeTable`` (Xpress9EncHuffman.c:1078-1222):
    compare mode 0 (stored/uniform) vs mode 1 (Huffman-coded) and pick the cheaper one.
    Returns the final codes used (may be uniform if mode 0 was chosen).
    """
    lengths = [c[1] for c in codes]

    # Mode 0 (stored/uniform) cost: all data encoded with near-uniform codes.
    msb = alphabet_size.bit_length() - 1
    threshold = (1 << (msb + 1)) - alphabet_size
    freq0 = sum(counts[i] for i in range(threshold))
    freq1 = sum(counts[i] for i in range(threshold, alphabet_size))
    mode0_cost = (freq0 + freq1) * msb + freq1 + 3

    # Mode 1 (Huffman-coded) data cost: frequency-weighted codeword lengths.
    huffman_data_cost = sum(counts[i] * lengths[i] for i in range(alphabet_size) if lengths[i] > 0)

    # Build Mode 1 opcode sequence and compute table overhead.
    symbols: list[int] = []
    meta_counts = [0] * _TABLE_ALPHABET_SIZE
    prev_sym = _MAIN_TABLE_INITIAL_PREV
    i = 0
    while i < alphabet_size:
        k = lengths[i]
        if k != 0:
            sym: int
            if k == prev_sym:
                sym = _TABLE_PREV
            else:
                prev_sym = k
                if i >= fill_boundary:
                    row_val = lengths[i - fill_boundary]
                    if k == row_val:
                        sym = _TABLE_ROW_0
                    elif k == row_val + 1:
                        sym = _TABLE_ROW_1
                    else:
                        sym = k
                else:
                    sym = k
            meta_counts[sym] += 1
            symbols.append(sym)
            i += 1
        else:
            zero_start = i
            while i < alphabet_size and lengths[i] == 0:
                i += 1
            k_pos = zero_start
            while (k_pos ^ i) >= fill_boundary:
                symbols.append(_TABLE_FILL)
                meta_counts[_TABLE_FILL] += 1
                k_pos = (k_pos & ~(fill_boundary - 1)) + fill_boundary
            remaining = i - k_pos
            if remaining > 0:
                if remaining < _TABLE_ZERO_REPT_MIN_COUNT:
                    for _ in range(remaining):
                        symbols.append(0)
                        meta_counts[0] += 1
                else:
                    symbols.append(_TABLE_ZERO_REPT)
                    meta_counts[_TABLE_ZERO_REPT] += 1

    meta_codes = _build_huffman_codes(meta_counts, _TABLE_ALPHABET_SIZE, _SMALL_TABLE_MAX_LENGTH)

    # Measure Mode 1 cost exactly by writing to a scratch writer, matching
    # the C encoder's approach (Xpress9EncHuffman.c:1129-1141) which writes
    # the table to a temporary bitstream and measures the actual bits rather
    # than estimating the overhead.
    scratch = _BitWriter()
    scratch.write(_TABLE_ENCODING_HUFFMAN, 3)
    _encode_small_table(scratch, meta_codes)
    _write_length_sequence(scratch, lengths, symbols, meta_codes, alphabet_size, fill_boundary)
    mode1_cost = huffman_data_cost + scratch.bits_written

    # Xpress9EncHuffman.c:1143: choose mode 0 if it's cheaper or equal.
    if mode0_cost <= mode1_cost:
        writer.write(_TABLE_ENCODING_STORED, 3)
        # Build uniform codes (Xpress9EncHuffman.c:1149-1160).
        uniform = [(0, 0)] * alphabet_size
        for j in range(threshold):
            uniform[j] = (_reverse_mask(j, msb), msb)
        base = threshold << 1
        for j in range(threshold, alphabet_size):
            uniform[j] = (_reverse_mask(base, msb + 1), msb + 1)
            base += 1
        return uniform

    # Mode 1: write Huffman-coded length table (already measured above
    # via the scratch writer; now write to the real writer).
    writer.write(_TABLE_ENCODING_HUFFMAN, 3)
    _encode_small_table(writer, meta_codes)
    _write_length_sequence(writer, lengths, symbols, meta_codes, alphabet_size, fill_boundary)

    return codes


# --- LZ77 match finder and encoder ---


def _hash4(data: bytes | bytearray, pos: int) -> int:
    """Hash 4 bytes at ``pos`` using the C encoder's non-SSE2 hash function.

    Port of Xpress9Lz77EncInsert.i:212-225 (``LZ77_MIN_PTR_MATCH_LENGTH == 4``
    scalar path).  The SSE2 insert path adds an extra ``^= >>17`` step, but
    ESE on Linux (the oracle) compiles without SSE2 intrinsics, so we omit it.
    """
    if pos + 4 > len(data):
        return 0
    v = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24)
    v = ((v ^ 0xDEADBEEF) + (v >> 5)) & 0xFFFFFFFF
    v = (v ^ (v >> 11)) & 0xFFFFFFFF
    return v & _HASH_MASK


def _hash_insert(data: bytes | bytearray, pos: int, hash_table: list[int], p_next: list[int]) -> None:
    """Insert ``pos`` into the hash chain, mirroring Xpress9Lz77EncInsert.i:226-229.

    Sets ``p_next[pos]`` to the previous chain head and updates the hash table
    to point to ``pos``.
    """
    h = _hash4(data, pos)
    p_next[pos] = hash_table[h]
    hash_table[h] = pos


def _hash_insert_range(data: bytes | bytearray, start: int, end: int, hash_table: list[int], p_next: list[int], data_size: int) -> None:
    """Insert all positions in ``[start, end)`` into the hash chain.

    Mirrors the C encoder's bulk insertion in Xpress9Lz77EncInsert.i:210-232.
    Positions within the last 3 bytes of the data cannot form a 4-byte hash
    and are assigned ``p_next[pos] = 0`` (Xpress9Lz77EncInsert.i:241-245).
    """
    hashable_limit = data_size - 4 if data_size >= 4 else 0
    for pos in range(start, end):
        if pos < hashable_limit:
            _hash_insert(data, pos, hash_table, p_next)
        else:
            p_next[pos] = 0


def _chain_lookup(data: bytes | bytearray, pos: int, data_size: int, p_next: list[int], max_depth: int, best_len: int) -> tuple[int, int]:
    """Walk the hash chain from ``pos`` looking for the longest match.

    Port of the Xpress9Lookup.i inner loop (DEEP_LOOKUP=1, TAIL_T=UInt16).
    Returns ``(best_offset_neg, best_length)`` where the offset is negative
    (candidate - position) matching the C convention, or ``(0, best_len)``
    unchanged if nothing better was found.

    The ``s_iMaxOffsetByLength`` table rejects short matches at large distances
    (Xpress9EncLz77.c:297-310).
    """
    candidate = p_next[pos]
    # Sentinel: pNext[0] = position, so walking into 0 terminates.
    saved_next_0 = p_next[0]
    p_next[0] = pos

    best_offset = 0
    depth_remaining = max_depth
    max_offset_table = _MAX_OFFSET_BY_LENGTH
    max_offset_len = len(max_offset_table) - 1  # last valid index

    while True:
        # --- Inner loop: check tail bytes for early-out (unrolled 8 per depth tick) ---
        # With TAIL_T = UInt16, the tail comperand is the 2 bytes at
        # data[pos + best_len - 1 .. pos + best_len].  We compare the same
        # window at each candidate for a quick reject before extending.
        tail_pos = pos + best_len - 1
        if tail_pos + 1 >= data_size:
            break  # can't form tail comperand at end of data
        tail0 = data[tail_pos]
        tail1 = data[tail_pos + 1]

        # Walk up to 8 candidates per depth tick (Xpress9Lookup.i unrolls 4 pairs).
        found_candidate = -1
        checks_in_block = 0
        cur = candidate
        while checks_in_block < 8:
            # Even iteration: cur is _uCandidate, peek at _uCandidate2.
            next_cur = p_next[cur]
            if cur + best_len - 1 + 1 < data_size and data[cur + best_len - 1] == tail0 and data[cur + best_len] == tail1:
                found_candidate = cur
                candidate = next_cur  # resume point for DEEP_LOOKUP continuation
                break
            checks_in_block += 1

            # Odd iteration: next_cur is _uCandidate2.
            cur2 = p_next[next_cur]
            if next_cur + best_len - 1 + 1 < data_size and data[next_cur + best_len - 1] == tail0 and data[next_cur + best_len] == tail1:
                found_candidate = next_cur
                candidate = cur2
                break
            checks_in_block += 1
            cur = cur2

        if found_candidate < 0:
            # Exhausted this 8-candidate block without a tail match.
            depth_remaining -= 1
            if depth_remaining == 0:
                break
            candidate = cur  # continue from where we left off
            continue

        # Tail matched -- check if this is a valid forward reference (sentinel guard).
        if found_candidate >= pos:
            break

        # Extend the match byte-by-byte (Xpress9Lookup.i:97-106).
        i_offset = found_candidate - pos  # negative
        ml = 0
        while pos + ml < data_size and data[pos + ml] == data[found_candidate + ml]:
            ml += 1

        # Accept only if longer than current best AND passes the
        # max-offset-by-length filter (Xpress9Lookup.i:112-119).
        if ml > best_len and (ml > max_offset_len or i_offset > max_offset_table[ml]):
            best_len = ml
            best_offset = i_offset

        # DEEP_LOOKUP: follow to next candidate in chain.
        candidate = p_next[found_candidate]

    p_next[0] = saved_next_0
    return best_offset, best_len


def _check_mtf(data: bytes | bytearray, pos: int, i_offset: int, data_size: int) -> int:
    """Check an MTF match at ``pos`` and return its length.

    Port of the CHECK_MTF macro (Xpress9EncLz77.c:42-66).  Checks the first
    ``_ENC_MTF_MIN_MATCH_LENGTH`` bytes, then extends byte-by-byte.  Returns 0
    if the minimum match fails, otherwise the full match length.
    """
    # Validity: position + offset must be > 0 (in-bounds backward reference).
    if pos + i_offset <= 0:
        return 0
    src = pos + i_offset  # i_offset is negative
    # Quick check of the first LZ77_MIN_MTF_MATCH_LENGTH (=2) bytes.
    if data[pos] != data[src] or data[pos + 1] != data[src + 1]:
        return 0
    # Extend past the minimum.
    ml = _ENC_MTF_MIN_MATCH_LENGTH
    while pos + ml < data_size and data[pos + ml] == data[src + ml]:
        ml += 1
    return ml


# Token types used in the intermediate representation.
_TOKEN_LIT: Final = 0
_TOKEN_PTR: Final = 1
_TOKEN_MTF: Final = 2


def _emit_mtf(tokens: list[tuple[int, ...]], encode_idx: int, offset_neg: int, length: int, mtf_slot: int, mtf_0: int, mtf_1: int, mtf_2: int, mtf_3: int) -> tuple[int, int, int, int]:
    """Emit an MTF token and perform UPDATE_MTF, returning the updated MTF state.

    Factored out because both the main path and the LOOKAHEAD paths need
    identical MTF-emit + UPDATE_MTF logic (Xpress9EncLz77.c:42-66,
    Xpress9Lz77EncPass1.i:15-21).
    """
    tokens.append((_TOKEN_MTF, encode_idx, -offset_neg, length))
    if mtf_slot >= 3:
        mtf_3 = mtf_2
    if mtf_slot >= 2:
        mtf_2 = mtf_1
    mtf_1 = mtf_0
    mtf_0 = offset_neg
    return mtf_0, mtf_1, mtf_2, mtf_3


def _check_all_mtf(data: bytes | bytearray, pos: int, data_size: int, mtf_last_ptr: int, mtf_0: int, mtf_1: int, mtf_2: int, mtf_3: int) -> tuple[int, int, int]:
    """Check all 4 MTF slots at ``pos`` in the order the C encoder does.

    Returns ``(match_len, encode_idx, slot)`` for the first matching slot, or
    ``(0, 0, 0)`` if none.  Port of the CHECK_MTF cascade in
    Xpress9Lz77EncPass1.i:80-93.
    """
    if mtf_last_ptr == 0:
        ml = _check_mtf(data, pos, mtf_0, data_size)
        if ml >= _ENC_MTF_MIN_MATCH_LENGTH:
            return ml, 0, 0
    ml = _check_mtf(data, pos, mtf_1, data_size)
    if ml >= _ENC_MTF_MIN_MATCH_LENGTH:
        return ml, 1 + mtf_last_ptr, 1
    ml = _check_mtf(data, pos, mtf_2, data_size)
    if ml >= _ENC_MTF_MIN_MATCH_LENGTH:
        return ml, 2 + mtf_last_ptr, 2
    ml = _check_mtf(data, pos, mtf_3, data_size)
    if ml >= _ENC_MTF_MIN_MATCH_LENGTH:
        return ml, 3 + mtf_last_ptr, 3
    return 0, 0, 0


def _lookahead_check_mtf(data: bytes | bytearray, pos: int, data_size: int, threshold: int, mtf_0: int, mtf_1: int, mtf_2: int, mtf_3: int) -> tuple[int, int, int]:
    """Check all 4 MTF slots for the lookahead paths (P+1 or P+2).

    Port of LOOKAHEAD_CHECK_MTF / LOOKAHEAD2_CHECK_MTF macros
    (Xpress9EncLz77.c:71-136).  After a literal, ``iMtfLastPtr`` is 0 so the
    encode indices are un-shifted (0,1,2,3).

    Returns ``(match_len, encode_idx, slot)`` for the first slot whose match
    length >= ``threshold`` (= saved_best - 3), or ``(0, 0, 0)`` if none.
    """
    for slot, off in enumerate((mtf_0, mtf_1, mtf_2, mtf_3)):
        ml = _check_mtf(data, pos, off, data_size)
        if ml >= threshold:
            return ml, slot, slot
    return 0, 0, 0


def _lz77_tokenize(data: bytes | bytearray) -> list[tuple[int, ...]]:
    """LZ77 tokenizer with lazy match evaluation matching the C reference encoder.

    Port of Xpress9Lz77EncPass1.i instantiated with DEEP_LOOKUP=1, LZ77_MTF=4,
    LZ77_MIN_MTF_MATCH_LENGTH=2, LZ77_MIN_PTR_MATCH_LENGTH=4, and
    LAZY_MATCH_EVALUATION -- the variant selected by the oracle binary's
    parameters (OptimizationLevel=1, LookupDepth=1).

    Two-phase approach matching the C encoder:

    1. **Insert phase** (Xpress9Lz77EncInsert.i): all positions in the input
       are inserted into the hash chain BEFORE the match-finding pass.

    2. **Encode phase** (Xpress9Lz77EncPass1.i): walk the data linearly,
       checking MTF matches first, then hash-chain lookup.  When a match is
       found at position P, the LAZY_MATCH_EVALUATION block
       (Xpress9Lz77EncPass1.i:110-227) checks P+1 and P+2 for longer matches
       before committing.

    Produces the same token types as before so downstream ``_collect_frequencies``
    and ``_encode_tokens`` remain unchanged.
    """
    data_size = len(data)
    tokens: list[tuple[int, ...]] = []
    if data_size == 0:
        return tokens

    # --- Allocate hash table and chain array (Xpress9EncLz77.c:1102-1104) ---
    hash_table = [0] * _HASH_TABLE_SIZE
    p_next = [0] * data_size

    # --- Chunked insert+encode (Xpress9EncLz77.c:1548-1656) ---
    # The C encoder copies data in chunks limited by the IR buffer capacity,
    # then inserts and encodes each chunk.  Match extensions are bounded by
    # the end of the currently-inserted data (``chunk_data_size``), not the
    # full input.
    hash_insert_pos = 0  # how far we've inserted into the hash table

    # --- MTF state (Xpress9Lz77EncPass1.i:40-47) ---
    mtf_0 = -1
    mtf_1 = -1
    mtf_2 = -1
    mtf_3 = -1
    mtf_last_ptr = 0  # 0 after literal, -1 after ptr/MTF

    max_depth = _ENC_MAX_DEPTH
    pos = 0
    bytes_copied = 0

    while bytes_copied < data_size:
        # Determine the next chunk size (Xpress9EncLz77.c:1600-1604).
        remaining = data_size - bytes_copied
        chunk = min(_IR_CHUNK_SIZE, remaining)
        bytes_copied += chunk
        chunk_data_size = bytes_copied  # pEndData = pData + uDataSize after this copy

        # Insert new positions into the hash chain (Xpress9Lz77EncInsert.i).
        _hash_insert_range(data, hash_insert_pos, bytes_copied, hash_table, p_next, data_size)
        # The hashable limit is chunk_data_size - 4; the insert function
        # handles the boundary.  Update the insertion cursor.
        hash_insert_pos = min(bytes_copied, max(data_size - 4, 0)) if data_size >= 4 else 0
        # stop_position = hash_insert_pos for this chunk's Pass1 run.
        stop_position = hash_insert_pos

        # --- Pass1 encode loop (Xpress9Lz77EncPass1.i) ---
        while pos < stop_position:
            # --- MTF checks ---
            mtf_ml, mtf_ei, mtf_sl = _check_all_mtf(data, pos, chunk_data_size, mtf_last_ptr, mtf_0, mtf_1, mtf_2, mtf_3)
            if mtf_ml > 0:
                offset_neg = (mtf_0, mtf_1, mtf_2, mtf_3)[mtf_sl]
                mtf_0, mtf_1, mtf_2, mtf_3 = _emit_mtf(tokens, mtf_ei, offset_neg, mtf_ml, mtf_sl, mtf_0, mtf_1, mtf_2, mtf_3)
                mtf_last_ptr = -1
                pos += mtf_ml
                continue

            # --- Hash chain lookup ---
            if p_next[pos] == 0:
                pass
            else:
                best_len = _ENC_PTR_MIN_MATCH_LENGTH - 1
                best_offset, best_len = _chain_lookup(data, pos, chunk_data_size, p_next, max_depth, best_len)

                if best_len >= _ENC_PTR_MIN_MATCH_LENGTH:
                    # --- LAZY_MATCH_EVALUATION ---
                    if pos + 2 < stop_position and p_next[pos + 1] != 0:
                        saved_best_len = best_len
                        saved_best_offset = best_offset

                        la_threshold = max(saved_best_len - 3, _ENC_MTF_MIN_MATCH_LENGTH)
                        la_ml, la_ei, la_sl = _lookahead_check_mtf(data, pos + 1, chunk_data_size, la_threshold, mtf_0, mtf_1, mtf_2, mtf_3)
                        if la_ml >= la_threshold:
                            tokens.append((_TOKEN_LIT, data[pos]))
                            offset_neg = (mtf_0, mtf_1, mtf_2, mtf_3)[la_sl]
                            mtf_0, mtf_1, mtf_2, mtf_3 = _emit_mtf(tokens, la_ei, offset_neg, la_ml, la_sl, mtf_0, mtf_1, mtf_2, mtf_3)
                            mtf_last_ptr = -1
                            pos += 1 + la_ml
                            continue

                        la1_best_len = best_len
                        la1_best_offset, la1_best_len = _chain_lookup(data, pos + 1, chunk_data_size, p_next, max(max_depth // 2, 1), la1_best_len)

                        if la1_best_len > saved_best_len:
                            if p_next[pos + 2] != 0:
                                saved_best_len2 = la1_best_len
                                saved_best_offset2 = la1_best_offset

                                la2_threshold = max(saved_best_len2 - 3, _ENC_MTF_MIN_MATCH_LENGTH)
                                la2_ml, la2_ei, la2_sl = _lookahead_check_mtf(data, pos + 2, chunk_data_size, la2_threshold, mtf_0, mtf_1, mtf_2, mtf_3)
                                if la2_ml >= la2_threshold:
                                    tokens.append((_TOKEN_LIT, data[pos]))
                                    tokens.append((_TOKEN_LIT, data[pos + 1]))
                                    offset_neg = (mtf_0, mtf_1, mtf_2, mtf_3)[la2_sl]
                                    mtf_0, mtf_1, mtf_2, mtf_3 = _emit_mtf(tokens, la2_ei, offset_neg, la2_ml, la2_sl, mtf_0, mtf_1, mtf_2, mtf_3)
                                    mtf_last_ptr = -1
                                    pos += 2 + la2_ml
                                    continue

                                la2_best_len = la1_best_len
                                la2_best_offset, la2_best_len = _chain_lookup(data, pos + 2, chunk_data_size, p_next, max(max_depth // 4, 1), la2_best_len)

                                if la2_best_len > saved_best_len2:
                                    tokens.append((_TOKEN_LIT, data[pos]))
                                    tokens.append((_TOKEN_LIT, data[pos + 1]))
                                    pos += 2
                                    best_offset = la2_best_offset
                                    best_len = la2_best_len
                                else:
                                    tokens.append((_TOKEN_LIT, data[pos]))
                                    pos += 1
                                    best_offset = saved_best_offset2
                                    best_len = saved_best_len2
                            else:
                                tokens.append((_TOKEN_LIT, data[pos]))
                                pos += 1
                                best_offset = la1_best_offset
                                best_len = la1_best_len
                        else:
                            la2_threshold = max(saved_best_len - 3, _ENC_MTF_MIN_MATCH_LENGTH)
                            la2_ml, la2_ei, la2_sl = _lookahead_check_mtf(data, pos + 2, chunk_data_size, la2_threshold, mtf_0, mtf_1, mtf_2, mtf_3)
                            if la2_ml >= la2_threshold:
                                tokens.append((_TOKEN_LIT, data[pos]))
                                tokens.append((_TOKEN_LIT, data[pos + 1]))
                                offset_neg = (mtf_0, mtf_1, mtf_2, mtf_3)[la2_sl]
                                mtf_0, mtf_1, mtf_2, mtf_3 = _emit_mtf(tokens, la2_ei, offset_neg, la2_ml, la2_sl, mtf_0, mtf_1, mtf_2, mtf_3)
                                mtf_last_ptr = -1
                                pos += 2 + la2_ml
                                continue

                            best_offset = saved_best_offset
                            best_len = saved_best_len

                    # Emit pointer match.
                    tokens.append((_TOKEN_PTR, -best_offset, best_len))
                    mtf_3 = mtf_2
                    mtf_2 = mtf_1
                    mtf_1 = mtf_0
                    mtf_0 = best_offset
                    mtf_last_ptr = -1
                    pos += best_len
                    continue

            # --- Literal loop (Xpress9Lz77EncPass1.i:243-267) ---
            mtf_last_ptr = 0
            while True:
                tokens.append((_TOKEN_LIT, data[pos]))
                pos += 1
                if pos >= stop_position:
                    break
                candidate = p_next[pos]
                if candidate == 0:
                    continue
                if pos + 3 < chunk_data_size and candidate + 3 < chunk_data_size and data[pos] == data[candidate] and data[pos + 1] == data[candidate + 1] and data[pos + 2] == data[candidate + 2] and data[pos + 3] == data[candidate + 3]:
                    break

    # --- Flush trailing unhashed positions as literals (Xpress9EncLz77.c:1680-1686) ---
    while pos < data_size:
        tokens.append((_TOKEN_LIT, data[pos]))
        mtf_last_ptr = 0
        pos += 1

    return tokens


def _collect_frequencies(tokens: list[tuple[int, ...]]) -> tuple[list[int], list[int], int]:
    """Collect Huffman frequency tables from the token stream (pass 1).

    Returns ``(short_counts, long_counts, extra_bits_total)`` matching the C encoder's
    ``m_uShortSymbolCount``, ``m_uLongLengthCount``, and ``m_uStoredBitCount``
    (Xpress9EncLz77.c ENCODE_PTR/ENCODE_MTF/ENCODE_LIT macros).
    """
    short_counts = [0] * _SHORT_SYMBOL_ALPHABET_SIZE
    long_counts = [0] * _LONG_LENGTH_ALPHABET_SIZE
    extra_bits = 0

    for token in tokens:
        if token[0] == _TOKEN_LIT:
            short_counts[token[1]] += 1
        elif token[0] == _TOKEN_PTR:
            offset, length = token[1], token[2]
            msb_offset = offset.bit_length() - 1
            extra_bits += msb_offset
            sym_base = (msb_offset + 16 + _ENC_MTF_ENTRY_COUNT) << _MAX_SHORT_LENGTH_LOG
            adj_length = length - _ENC_PTR_MIN_MATCH_LENGTH
            if adj_length < _MAX_SHORT_LENGTH - 1:
                sym = sym_base + adj_length
                short_counts[sym] += 1
            else:
                sym = sym_base + _MAX_SHORT_LENGTH - 1
                short_counts[sym] += 1
                long_length = adj_length - (_MAX_SHORT_LENGTH - 1)
                if long_length <= _MAX_LONG_LENGTH - 1:
                    long_counts[long_length] += 1
                else:
                    escaped = long_length - (_MAX_LONG_LENGTH - 1)
                    msb_len = escaped.bit_length() - 1
                    extra_bits += msb_len
                    long_sym = msb_len + _MAX_LONG_LENGTH
                    long_counts[long_sym] += 1
        else:  # _TOKEN_MTF
            mtf_index, _offset, length = token[1], token[2], token[3]
            sym_base = (mtf_index + 16) << _MAX_SHORT_LENGTH_LOG
            adj_length = length - _ENC_MTF_MIN_MATCH_LENGTH
            if adj_length < _MAX_SHORT_LENGTH - 1:
                sym = sym_base + adj_length
                short_counts[sym] += 1
            else:
                sym = sym_base + _MAX_SHORT_LENGTH - 1
                short_counts[sym] += 1
                long_length = adj_length - (_MAX_SHORT_LENGTH - 1)
                if long_length <= _MAX_LONG_LENGTH - 1:
                    long_counts[long_length] += 1
                else:
                    escaped = long_length - (_MAX_LONG_LENGTH - 1)
                    msb_len = escaped.bit_length() - 1
                    extra_bits += msb_len
                    long_sym = msb_len + _MAX_LONG_LENGTH
                    long_counts[long_sym] += 1

    return short_counts, long_counts, extra_bits


def _encode_tokens(writer: _BitWriter, tokens: list[tuple[int, ...]], short_codes: list[tuple[int, int]], long_codes: list[tuple[int, int]]) -> None:
    """Encode the LZ77 token stream using Huffman codes (pass 2).

    Port of ``Xpress9Lz77EncPass2`` (Xpress9Lz77EncPass2.i:1-107): writes each token
    as a short-symbol Huffman codeword, optionally followed by a long-length codeword
    and/or raw offset bits.
    """
    for token in tokens:
        if token[0] == _TOKEN_LIT:
            cw, cl = short_codes[token[1]]
            writer.write(cw, cl)
        elif token[0] == _TOKEN_PTR:
            offset, length = token[1], token[2]
            msb_offset = offset.bit_length() - 1
            low_offset = offset - (1 << msb_offset)
            sym_base = (msb_offset + 16 + _ENC_MTF_ENTRY_COUNT) << _MAX_SHORT_LENGTH_LOG
            adj_length = length - _ENC_PTR_MIN_MATCH_LENGTH

            if adj_length < _MAX_SHORT_LENGTH - 1:
                sym = sym_base + adj_length
                cw, cl = short_codes[sym]
                writer.write(cw, cl)
            else:
                sym = sym_base + _MAX_SHORT_LENGTH - 1
                cw, cl = short_codes[sym]
                writer.write(cw, cl)
                long_length = adj_length - (_MAX_SHORT_LENGTH - 1)
                if long_length <= _MAX_LONG_LENGTH - 1:
                    cw, cl = long_codes[long_length]
                    writer.write(cw, cl)
                else:
                    escaped = long_length - (_MAX_LONG_LENGTH - 1)
                    msb_len = escaped.bit_length() - 1
                    low_len = escaped - (1 << msb_len)
                    long_sym = msb_len + _MAX_LONG_LENGTH
                    cw, cl = long_codes[long_sym]
                    writer.write(cw, cl)
                    writer.write(low_len, msb_len)

            # Write raw offset low bits.
            writer.write(low_offset, msb_offset)

        else:  # _TOKEN_MTF
            mtf_index, _offset, length = token[1], token[2], token[3]
            sym_base = (mtf_index + 16) << _MAX_SHORT_LENGTH_LOG
            adj_length = length - _ENC_MTF_MIN_MATCH_LENGTH

            if adj_length < _MAX_SHORT_LENGTH - 1:
                sym = sym_base + adj_length
                cw, cl = short_codes[sym]
                writer.write(cw, cl)
            else:
                sym = sym_base + _MAX_SHORT_LENGTH - 1
                cw, cl = short_codes[sym]
                writer.write(cw, cl)
                long_length = adj_length - (_MAX_SHORT_LENGTH - 1)
                if long_length <= _MAX_LONG_LENGTH - 1:
                    cw, cl = long_codes[long_length]
                    writer.write(cw, cl)
                else:
                    escaped = long_length - (_MAX_LONG_LENGTH - 1)
                    msb_len = escaped.bit_length() - 1
                    low_len = escaped - (1 << msb_len)
                    long_sym = msb_len + _MAX_LONG_LENGTH
                    cw, cl = long_codes[long_sym]
                    writer.write(cw, cl)
                    writer.write(low_len, msb_len)
            # MTF matches have no explicit offset bits (offset comes from MTF list).


def _encode_block(data: bytes | bytearray, block_index: int) -> bytes:
    """Encode one XPRESS9 block: 32-byte header followed by bitstream.

    Implements the C encoder's block assembly (Xpress9EncLz77.c:1367-1512): MTF initial
    state, two Huffman tables, the LZ77 token stream, and the 8-word block header with
    CRC-32C.
    """
    # Tokenize the data.
    tokens = _lz77_tokenize(data)

    # Pass 1: collect frequency counts.
    short_counts, long_counts, _extra_bits = _collect_frequencies(tokens)

    # Ensure every alphabet has at least one symbol with a non-zero count.
    # The decoder requires a valid Huffman tree for both alphabets.
    if sum(short_counts) == 0:
        short_counts[0] = 1  # at least one literal
    # For the long-length alphabet, if no long lengths occur, we still need a valid
    # tree. Give a dummy count to two symbols to form a full binary tree.
    if sum(long_counts) == 0:
        long_counts[0] = 1
        long_counts[1] = 1
    elif sum(1 for c in long_counts if c > 0) == 1:
        # Single-symbol trees work for decoding but we need to be careful.
        # Add a dummy second symbol to ensure a proper tree.
        for j in range(_LONG_LENGTH_ALPHABET_SIZE):
            if long_counts[j] == 0:
                long_counts[j] = 1
                break

    # Build Huffman codes.
    short_codes = _build_huffman_codes(short_counts, _SHORT_SYMBOL_ALPHABET_SIZE, _MAX_CODEWORD_LENGTH)
    long_codes = _build_huffman_codes(long_counts, _LONG_LENGTH_ALPHABET_SIZE, _MAX_CODEWORD_LENGTH)

    # Build the bitstream: MTF initial state + Huffman tables + token stream.
    writer = _BitWriter()

    # MTF initial state (Xpress9EncLz77.c:1393-1410).
    # Write the last-was-ptr flag (0 = no, start of block) and the initial MTF offsets.
    # At the start of the block, we set last_was_ptr = 0 and all offsets to 1 (the
    # smallest valid offset).
    writer.write(0, 1)  # iMtfLastPtr
    for _ in range(_ENC_MTF_ENTRY_COUNT):
        # Offset 1 encoded as Elias-gamma: msb = 0, then 0 low bits.
        writer.write(0, 5)  # msb = 0
        # No low bits since msb = 0.

    # Write Huffman tables (may switch to uniform codes if Mode 0 is cheaper).
    short_codes = _encode_huffman_table(writer, short_codes, short_counts, _SHORT_SYMBOL_ALPHABET_SIZE, _MAX_SHORT_LENGTH)
    long_codes = _encode_huffman_table(writer, long_codes, long_counts, _LONG_LENGTH_ALPHABET_SIZE, _MAX_SHORT_LENGTH)

    huffman_table_bits = writer.bits_written  # includes MTF state + tables

    # Write token stream using the final codes (Huffman or uniform).
    _encode_tokens(writer, tokens, short_codes, long_codes)

    # Capture exact bit count before flush pads the partial byte.
    exact_bits = writer.bits_written
    writer.flush()
    bitstream = writer.getvalue()

    # Compute compressed size in bits (including the 32-byte header = 256 bits).
    comp_size_bits = BLOCK_HEADER_SIZE * 8 + exact_bits

    # Build flags (Xpress9EncLz77.c:1464-1483).
    flags = huffman_table_bits & 0x1FFF
    flags |= ((_ENC_WINDOW_SIZE_LOG2 - 16) & 7) << 13
    flags |= (_ENC_MTF_ENTRY_COUNT >> 1) << 16
    flags |= ((_ENC_PTR_MIN_MATCH_LENGTH - 3) & 1) << 18
    flags |= ((_ENC_MTF_MIN_MATCH_LENGTH - 2) & 1) << 19

    # Build block header (Xpress9Internal.h:972-984).
    header_words = struct.pack(
        "<7I",
        XPRESS9_MAGIC,
        len(data),
        comp_size_bits,
        flags,
        0,  # reserved
        _ENC_SESSION_SIGNATURE,
        block_index,
    )
    header_crc = crc32c_ese(header_words)
    header = header_words + struct.pack("<I", header_crc)

    return header + bitstream


def _compress_xpress9(data: Buffer) -> bytes:
    """Compress data into a single XPRESS9 block, with no ESE outer header.

    The C encoder processes the entire input as one block regardless of size;
    the window size (64KB) limits match distances, not the block boundary.
    """
    raw = bytes(data)
    size = len(raw)
    if size == 0:
        msg = "cannot compress empty input"
        raise CompressionError(msg)

    return _encode_block(raw, 0)


# --- Public API ---


def compress(data: Buffer) -> bytes:
    """Encode plaintext into a framed XPRESS9 cell.

    Mirrors ``ErrCompressXpress9_`` (compression.cxx:1686-1759): encode the
    payload as XPRESS9 block(s), prepend the 0x28 scheme byte and a u32 LE
    CRC-32C of the plaintext, and refuse to "compress" unless that saves space.

    Raises:
        CompressionError: The input is empty.
        IncompressibleError: The framed cell would not be strictly smaller than
            the plaintext -- ESE's ``errRECCannotCompress`` policy.
    """
    from ntcompress.ese import Format  # deferred to avoid circular

    raw = bytes(data)
    plaintext_crc = crc32c_ese(raw)
    payload = _compress_xpress9(raw)
    framed_size = HEADER_SIZE + len(payload)
    if framed_size >= len(raw):
        msg = f"compressed cell would be {framed_size} byte(s), not smaller than the {len(raw)}-byte plaintext"
        raise IncompressibleError(msg)
    scheme_byte = Format.XPRESS9 << 3
    return struct.pack("<BI", scheme_byte, plaintext_crc) + payload


def decompress(blob: Buffer, *, verify: bool = True) -> bytes:
    """Decode a framed XPRESS9 cell to its plaintext.

    Args:
        blob: The framed cell: scheme byte 0x28, u32 LE plaintext CRC-32C, then
            the raw Xpress9 block(s).
        verify: When True, check the header's plaintext CRC-32C against the
            decoded output, as ``ErrDecompressXpress9_`` does
            (compression.cxx:2461-2467). The per-block header CRCs are
            structural and always checked.

    Raises:
        DecompressionError: Truncated or corrupt frame, block header, Huffman
            table, or token stream.
        IntegrityError: ``verify`` is True and the plaintext CRC does not match.
    """
    stored_crc, payload = _parse_outer(blob)
    blocks = _session_blocks(payload)
    declared_total = sum(header.orig_size for header, _, _ in blocks)
    if declared_total > _MAX_DECODED_SIZE:
        # Reject an implausibly large declared size before allocating anything; see
        # _MAX_DECODED_SIZE. decompressed_size() still reports the raw declared
        # value, so callers can inspect it without triggering a decode.
        msg = f"XPRESS9 cell declares {declared_total} plaintext bytes, over the {_MAX_DECODED_SIZE}-byte safety limit"
        raise DecompressionError(msg)
    out = bytearray()
    for header, body_start, body_end in blocks:
        _decode_block(_BitReader(payload[body_start:body_end]), header, out)
    plain = bytes(out)
    if verify:
        actual = crc32c_ese(plain)
        if actual != stored_crc:
            msg = f"XPRESS9 plaintext CRC-32C mismatch: header says 0x{stored_crc:08x}, decoded data hashes to 0x{actual:08x}"
            raise IntegrityError(msg)
    return plain


def decompressed_size(blob: Buffer) -> int:
    """Return the plaintext size recorded in the block header(s), without decoding.

    The 5-byte record header carries no size (unlike XPRESS10 and LZ4), so the
    size comes from ``m_uOrigSizeBytes`` -- the C decoder's fast path for a
    zero-length fetch (Xpress9DecLz77.c:718-726), summed across blocks.
    """
    _, payload = _parse_outer(blob)
    return sum(header.orig_size for header, _, _ in _session_blocks(payload))
