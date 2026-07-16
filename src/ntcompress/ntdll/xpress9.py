"""Compact XPRESS9 codec (``COMPRESSION_FORMAT_XPRESS9``, 0x0005).

Undocumented ntdll.dll compression format introduced in Windows Server 2022
(Build 20348). Uses the same canonical-Huffman LZ77 engine as the ESE XPRESS9
codec (``ntcompress.ese.xpress9``) but with a streamlined 10-byte header instead
of XPRESS9's 32-byte block header.

Reverse-engineered from ``ntdll.dll`` Build 20348 (decompressor at RVA 0x111810,
Huffman builder at 0x114DA8, header parser at 0x115AB0). The header magic is
``0xC039E510``; the bitstream after the header is identical to XPRESS9's token
format: canonical Huffman short-symbol table (704 entries for window_log=24) for
literals (0-255) and match tokens (256+), a second long-length table (256 entries)
for escaped match lengths, and an LZ77 token stream with 4-entry MTF support.

On-disk layout:

  bytes 0-3:   magic ``0xC039E510`` (LE u32)
  bytes 4-5:   params (LE u16) -- bits 0-2: window_log index; bit 3: mode
  bytes 6-9:   control (LE u32) -- bits 0-27: payload bit count (comp_data + 32-bit CRC);
               bit 29: compressed flag; bit 31: end-of-stream
  bytes 10+:   payload data (ceil(payload_bits / 8) bytes)
  trailing:    CRC-32C of the original plaintext (32 bits, inside the payload area)
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Final

from ntcompress.ese.checksums import crc32c_ese
from ntcompress.ese.xpress9 import (
    _LONG_LENGTH_ALPHABET_SIZE,
    _MAX_LONG_LENGTH,
    _MAX_MTF,
    _MAX_SHORT_LENGTH,
    _MAX_SHORT_LENGTH_LOG,
    _BitReader,
    _CanonicalHuffman,
    _copy_match,
    _decode_length_table,
    _read_match_length,
    _take_mtf_offset,
)
from ntcompress.exceptions import DecompressionError, IntegrityError

if TYPE_CHECKING:
    from ntcompress._types import Buffer

MAGIC: Final = 0xC039E510
"""Block magic -- distinct from XPRESS9's ``0x4E86D72A``."""

HEADER_SIZE: Final = 10
"""Fixed header size: 4 (magic) + 2 (params) + 4 (control)."""

_WINDOW_LOG_TABLE: Final = (12, 13, 14, 16, 18, 20, 22, 24)
"""Maps the 3-bit index in ``params & 0x07`` to the window size exponent (from header parser at RVA 0x115AB0)."""

_PTR_MIN_MATCH: Final = 3
"""Minimum match length for explicit-pointer matches (verified empirically)."""

_MTF_MIN_MATCH: Final = 2
"""Minimum match length for MTF (repeated-offset) matches."""


def _parse_header(data: Buffer) -> tuple[int, int, bool, int]:
    """Parse the 10-byte header and return ``(window_log, payload_bits, compressed, comp_bits)``.

    Raises:
        DecompressionError: Bad magic, reserved bits set, or truncated input.
    """
    if len(data) < HEADER_SIZE:
        msg = f"compact XPRESS9 stream is {len(data)} bytes; the header alone is {HEADER_SIZE}"
        raise DecompressionError(msg)

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MAGIC:
        msg = f"bad compact XPRESS9 magic 0x{magic:08x}, expected 0x{MAGIC:08x}"
        raise DecompressionError(msg)

    params = struct.unpack_from("<H", data, 4)[0]
    control = struct.unpack_from("<I", data, 6)[0]

    window_log = _WINDOW_LOG_TABLE[params & 0x07]
    payload_bits = control & 0x0FFF_FFFF
    compressed = bool(control & (1 << 29))
    comp_bits = payload_bits - 32 if compressed else 0

    return window_log, payload_bits, compressed, comp_bits


def _short_alphabet_size(window_log: int) -> int:
    """Compute the short-symbol alphabet size: ``(window_log + 20) << 4``."""
    return (window_log + 16 + _MAX_MTF) << _MAX_SHORT_LENGTH_LOG


def _long_alphabet_size(window_log: int) -> int:
    """Compute the long-length alphabet size (always 256 for window_log <= 24)."""
    n = (1 << window_log) - 3 - (_LONG_LENGTH_ALPHABET_SIZE - _MAX_LONG_LENGTH)
    msb = n.bit_length() - 1
    extra = 1 if (n & (n - 1)) else 0
    return msb + extra + _LONG_LENGTH_ALPHABET_SIZE - _MAX_LONG_LENGTH


def _decode_table_2bit(reader: _BitReader, alphabet_size: int) -> _CanonicalHuffman:
    """Decode a Huffman table with the compact 2-bit mode prefix (vs XPRESS9's 3-bit).

    Modes: 0 = stored (flat code lengths), 2 = Huffman-coded, 1/3 = error.
    """
    mode = reader.read(2)
    if mode == 0:
        msb = alphabet_size.bit_length() - 1
        short_count = (1 << (msb + 1)) - alphabet_size
        lengths = [msb] * short_count + [msb + 1] * (alphabet_size - short_count)
        return _CanonicalHuffman(lengths)
    if mode == 2:
        lengths = _decode_length_table.__wrapped__(reader, alphabet_size, _MAX_SHORT_LENGTH) if hasattr(_decode_length_table, "__wrapped__") else _decode_coded_lengths_via_xpress9(reader, alphabet_size)
        return _CanonicalHuffman(lengths)
    msg = f"compact XPRESS9: unsupported Huffman table mode {mode}"
    raise DecompressionError(msg)


def _decode_coded_lengths_via_xpress9(reader: _BitReader, alphabet_size: int) -> list[int]:
    """Use XPRESS9's Huffman-coded length table decoder for mode 2."""
    from ntcompress.ese.xpress9 import _decode_coded_lengths

    return _decode_coded_lengths(reader, alphabet_size, _MAX_SHORT_LENGTH)


def decompress(data: Buffer, /, *, verify: bool = True) -> bytes:
    """Decompress a compact XPRESS9 stream (ntdll format 0x0005).

    Args:
        data: The compressed stream including the 10-byte header.
        verify: If True (default), verify the trailing CRC-32C against the
            decompressed plaintext. Set to False to skip verification.

    Returns:
        The decompressed plaintext.

    Raises:
        DecompressionError: The stream is corrupt or truncated.
        IntegrityError: CRC-32C mismatch (only when ``verify=True``).
    """
    raw = bytes(data)
    window_log, payload_bits, compressed, comp_bits = _parse_header(raw)

    payload_bytes = -(-payload_bits // 8)
    if len(raw) < HEADER_SIZE + payload_bytes:
        msg = f"compact XPRESS9 stream truncated: need {HEADER_SIZE + payload_bytes} bytes, have {len(raw)}"
        raise DecompressionError(msg)

    payload = raw[HEADER_SIZE : HEADER_SIZE + payload_bytes]

    if not compressed:
        data_bits = payload_bits - 32
        if data_bits & 7:
            msg = f"compact XPRESS9 uncompressed payload has non-byte-aligned bit count {data_bits}"
            raise DecompressionError(msg)
        data_bytes = data_bits >> 3
        plain = payload[:data_bytes]
    else:
        short_alpha = _short_alphabet_size(window_log)
        long_alpha = _LONG_LENGTH_ALPHABET_SIZE

        reader = _BitReader(payload)

        short_table = _decode_table_2bit(reader, short_alpha)
        long_table = _decode_table_2bit(reader, long_alpha)

        out = bytearray()
        mtf: list[int] = []
        last_was_ptr = 0

        while reader.bits_consumed < comp_bits:
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

            if symbol < _MAX_MTF:
                length += _MTF_MIN_MATCH
                offset = _take_mtf_offset(mtf, symbol, last_was_ptr=bool(last_was_ptr))
            else:
                length += _PTR_MIN_MATCH
                msb = symbol - _MAX_MTF
                offset = reader.read(msb) + (1 << msb) if msb > 0 else 1
                if len(mtf) < _MAX_MTF:
                    mtf.insert(0, offset)
                else:
                    mtf.insert(0, offset)
                    mtf.pop()

            if offset > len(out):
                msg = f"compact XPRESS9 match offset {offset} reaches before start at position {len(out)}"
                raise DecompressionError(msg)
            last_was_ptr = 1
            _copy_match(out, offset, length)

        plain = bytes(out)

    if verify:
        crc_offset_bits = payload_bits - 32
        crc_byte_start = crc_offset_bits >> 3
        if crc_offset_bits & 7:
            crc_byte_start += 1
        expected_crc = struct.unpack_from("<I", payload, crc_byte_start)[0] if crc_byte_start + 4 <= len(payload) else 0
        actual_crc = crc32c_ese(plain)
        if expected_crc != actual_crc:
            msg = f"compact XPRESS9 CRC-32C mismatch: stream says 0x{expected_crc:08x}, plaintext hashes to 0x{actual_crc:08x}"
            raise IntegrityError(msg)

    return plain


def compress(data: Buffer, /) -> bytes:
    """Compress data into a compact XPRESS9 stream (ntdll format 0x0005).

    Uses flat (stored) Huffman tables for simplicity. Produces valid streams that
    ``RtlDecompressBufferEx(0x0005)`` accepts, but not necessarily byte-identical
    to ``RtlCompressBuffer(0x0005)`` output.

    Args:
        data: The plaintext to compress.

    Returns:
        The compressed stream including header and CRC-32C trailer.
    """
    plain = bytes(data)
    crc = crc32c_ese(plain)
    crc_bytes = struct.pack("<I", crc)

    if len(plain) <= 13:
        payload = plain + crc_bytes
        payload_bits = len(payload) * 8
        control = payload_bits | (1 << 31)
        header = struct.pack("<IHI", MAGIC, 0x4007, control)
        return header + payload

    window_log = 24
    short_alpha = _short_alphabet_size(window_log)
    long_alpha = _LONG_LENGTH_ALPHABET_SIZE

    short_msb = short_alpha.bit_length() - 1
    short_short_count = (1 << (short_msb + 1)) - short_alpha
    long_msb = long_alpha.bit_length() - 1

    bits: list[int] = []

    def write_bits(value: int, count: int) -> None:
        bits.extend((value >> i) & 1 for i in range(count))

    def write_huffman_code(symbol: int, msb_val: int, short_count: int) -> None:
        if symbol < short_count:
            code_len = msb_val
            code = symbol
        else:
            code_len = msb_val + 1
            first_long_code = short_count << 1
            code = first_long_code + (symbol - short_count)
        bits.extend((code >> i) & 1 for i in range(code_len - 1, -1, -1))

    write_bits(0, 2)
    write_bits(0, 2)

    pos = 0
    mtf: list[int] = []
    while pos < len(plain):
        best_offset = 0
        best_length = 0

        for mtf_idx in range(min(len(mtf), _MAX_MTF)):
            off = mtf[mtf_idx]
            if off > pos:
                continue
            ml = 0
            while pos + ml < len(plain) and plain[pos + ml] == plain[pos + ml - off]:
                ml += 1
            if ml >= _MTF_MIN_MATCH and ml > best_length:
                best_length = ml
                best_offset = off

        if best_offset == 0:
            for off in range(1, min(pos + 1, 1 << window_log)):
                if off in mtf:
                    continue
                ml = 0
                while pos + ml < len(plain) and plain[pos + ml] == plain[pos + ml - off]:
                    ml += 1
                if ml >= _PTR_MIN_MATCH and ml > best_length:
                    best_length = ml
                    best_offset = off

        if best_length == 0:
            write_huffman_code(plain[pos], short_msb, short_short_count)
            pos += 1
            continue

        is_mtf = best_offset in mtf[:_MAX_MTF]
        if is_mtf:
            mtf_idx = mtf.index(best_offset)
            min_match = _MTF_MIN_MATCH
            offset_slot = mtf_idx
        else:
            min_match = _PTR_MIN_MATCH
            msb_off = best_offset.bit_length() - 1
            offset_slot = msb_off + _MAX_MTF

        adj_length = best_length - min_match
        short_length = min(adj_length, _MAX_SHORT_LENGTH - 1)
        symbol = 256 + (offset_slot << _MAX_SHORT_LENGTH_LOG) + short_length
        write_huffman_code(symbol, short_msb, short_short_count)

        if short_length == _MAX_SHORT_LENGTH - 1:
            remaining = adj_length - (_MAX_SHORT_LENGTH - 1)
            if remaining < _MAX_LONG_LENGTH:
                long_symbol = remaining
                bits.extend((long_symbol >> i) & 1 for i in range(long_msb - 1, -1, -1))
            else:
                extra_val = remaining - (_MAX_LONG_LENGTH - 1)
                extra_bits_count = extra_val.bit_length()
                base = 1 << extra_bits_count
                long_symbol = _MAX_LONG_LENGTH + extra_bits_count
                bits.extend((long_symbol >> i) & 1 for i in range(long_msb - 1, -1, -1))
                write_bits(extra_val - base // 2, extra_bits_count)

        if not is_mtf:
            msb_off = best_offset.bit_length() - 1
            if msb_off > 0:
                write_bits(best_offset - (1 << msb_off), msb_off)
            if len(mtf) < _MAX_MTF:
                mtf.insert(0, best_offset)
            else:
                mtf.insert(0, best_offset)
                mtf.pop()

        pos += best_length

    comp_bits = len(bits)

    out_bytes = bytearray((comp_bits + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out_bytes[i >> 3] |= 1 << (i & 7)

    payload = bytes(out_bytes) + crc_bytes
    payload_bits = comp_bits + 32
    control = payload_bits | (1 << 29) | (1 << 31)
    header = struct.pack("<IHI", MAGIC, 0x4007, control)
    return header + payload
