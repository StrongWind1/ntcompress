"""Tests for the MS-XCA LZ77+Huffman (Xpress Huffman) raw codec.

Pins the [MS-XCA] §3.2 worked example and exercises round-trips, the v10.0 long-match
escape, multi-block streams, and corruption rejection.
"""

from __future__ import annotations

import os

import pytest

from ntcompress.ese import Format
from ntcompress.ese._registry import _CODECS
from ntcompress.exceptions import DecompressionError
from ntcompress.ntdll import xpress_huff


def _msxca_3_2_vector() -> bytes:
    # [MS-XCA] §3.2: 256-byte Huffman length table (four nonzero bytes) + 7-byte stream.
    table = bytearray(256)
    table[48] = 0x30  # symbol 97 'a' length 3
    table[49] = 0x23  # symbol 98 'b' length 3, symbol 99 'c' length 2
    table[128] = 0x02  # symbol 256 EOF length 2
    table[143] = 0x20  # symbol 287 (match nibble 15, offset-bits 1) length 2
    return bytes(table) + bytes([0xA8, 0xDC, 0x00, 0x00, 0xFF, 0x26, 0x01])


# --- Windows RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS_HUFF) vector ---
# Compressed by ntdll.dll 10.0.20348.4050. Our compressor produces byte-identical output.
_RTL_XPHUFF_REP4K_PLAIN = bytes(0x41 + (i % 26) for i in range(1, 4097))
_RTL_XPHUFF_REP4K_COMP = bytes.fromhex(
    "000000000000000000000000000000000000000000000000000000000000000050555555555555555555555545040000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000964ab9c68cf04aa7f8dab7cefbce28e0203a0000ffe30f"
)


# Format 0x0104: COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_MAXIMUM.
# Slightly different Huffman table choices; decompresses correctly but our compressor
# produces different (equally valid) output.
_RTL_XPHUFF_MAX_COMP = bytes.fromhex(
    "000000000000000000000000000000000000000000000000000000000000000050545555555555555555555555040000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000a9046b6c089f74caafadeb8cef7c28bea2030000ffe20f"
)


def test_rtl_xpress_huffman_default_decompress():
    assert xpress_huff.decompress(_RTL_XPHUFF_REP4K_COMP) == _RTL_XPHUFF_REP4K_PLAIN


def test_rtl_xpress_huffman_max_decompress():
    assert xpress_huff.decompress(_RTL_XPHUFF_MAX_COMP) == _RTL_XPHUFF_REP4K_PLAIN


def test_rtl_xpress_huffman_default_byte_identical():
    assert xpress_huff.compress(_RTL_XPHUFF_REP4K_PLAIN) == _RTL_XPHUFF_REP4K_COMP


def test_msxca_3_2_worked_example() -> None:
    # Decodes to abc[match distance=3 length=297][EOF] == "abc" * 100.
    assert xpress_huff.decompress(_msxca_3_2_vector()) == b"abc" * 100


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"A",
        b"abc" * 100,
        b"the quick brown fox jumps over the lazy dog. " * 40,
        b"a" * 501,  # overlapping match, length >> offset
        bytes(range(256)) * 20,  # every byte value
        b"Hi " * 3 + b"ZZZ" * 80,
    ],
)
def test_roundtrip(data: bytes) -> None:
    assert xpress_huff.decompress(xpress_huff.compress(data)) == data


def test_roundtrip_incompressible() -> None:
    # Random data cannot shrink but must still round-trip exactly.
    data = os.urandom(8192)
    assert xpress_huff.decompress(xpress_huff.compress(data)) == data


def test_multi_block_roundtrip() -> None:
    # >64 KiB forces multiple 64 KiB blocks, each with its own Huffman table.
    data = (b"multi-block payload " * 4000)[:80000]
    assert len(data) > 65536
    assert xpress_huff.decompress(xpress_huff.compress(data)) == data


def test_long_match_uint32_escape() -> None:
    # A single match longer than 65538 bytes drives the v10.0 uint16(0)+uint32 escape.
    data = b"x" * 300000
    compressed = xpress_huff.compress(data)
    assert xpress_huff.decompress(compressed) == data


def test_empty_encodes_single_eof_block() -> None:
    # Empty input still produces a valid, decodable block ending in the EOF symbol.
    compressed = xpress_huff.compress(b"")
    assert xpress_huff.decompress(compressed) == b""


@pytest.mark.parametrize("data", [b"AAAA", b"aaaa", b"1234123", b"xyxyxyx", b"ababab", b"AAAAB"])
def test_roundtrip_short_repeats_no_eof_collision(data: bytes) -> None:
    # A (length 3, distance 1) match encodes to _match_symbol == EOF_SYMBOL (256), which
    # the decoder reads as end-of-stream. The encoder must emit a literal for that case,
    # or these short repeats decode to a truncated prefix (e.g. b"AAAA" -> b"A").
    assert xpress_huff.decompress(xpress_huff.compress(data)) == data


def test_no_match_symbol_collides_with_eof() -> None:
    # Exhaustive guard on the encoder's match-symbol space: only (3, 1) hits 256, and
    # _lz77 must never emit it as a match.
    assert xpress_huff._match_symbol(3, 1) == xpress_huff.EOF_SYMBOL
    for length in range(3, 300):
        for distance in (1, 2, 3, 255, 8192, 65535):
            symbol = xpress_huff._match_symbol(length, distance)
            assert (length, distance) == (3, 1) or symbol > xpress_huff.EOF_SYMBOL


def test_decompress_max_size_rejects_bomb() -> None:
    # A forged or highly compressible stream must not expand past max_size: the check
    # fires before the offending bytes are materialised.
    data = b"x" * 50000
    compressed = xpress_huff.compress(data)
    with pytest.raises(DecompressionError):
        xpress_huff.decompress(compressed, max_size=1000)
    # An exact or ample ceiling, or none at all, still decodes fully.
    assert xpress_huff.decompress(compressed, max_size=len(data)) == data
    assert xpress_huff.decompress(compressed) == data


def test_decompress_max_size_rejects_literal_overflow() -> None:
    # The bound also covers pure-literal (incompressible) streams, byte by byte.
    data = os.urandom(2048)
    compressed = xpress_huff.compress(data)
    with pytest.raises(DecompressionError):
        xpress_huff.decompress(compressed, max_size=len(data) - 1)
    assert xpress_huff.decompress(compressed, max_size=len(data)) == data


def test_truncated_stream_rejected() -> None:
    # A table with no following bit stream must raise, not read past the buffer.
    with pytest.raises(DecompressionError):
        xpress_huff.decompress(bytes(256))


def test_truncated_below_table_with_no_output_rejected() -> None:
    # Fewer than 256 leading bytes with no output yet is a stream that ended before a
    # single decodable block: it must raise, not silently return empty (§2.2.4).
    with pytest.raises(DecompressionError):
        xpress_huff.decompress(b"\x00\x00\x00")


def test_invalid_huffman_table_rejected() -> None:
    # An all-length-1 table (every symbol length 1) cannot form a complete 15-bit code.
    bad = bytes([0x11] * 256) + bytes(8)
    with pytest.raises(DecompressionError):
        xpress_huff.decompress(bad)


def test_not_registered_as_ese_codec() -> None:
    # Xpress Huffman is an MS-XCA sibling, not an ESE record scheme: never dispatched.
    assert Format.XPRESS not in {type(c).__module__ for c in _CODECS.values()}
    registered_modules = {type(codec).__module__ for codec in _CODECS.values()}
    assert not any(module.endswith("xpress_huff") for module in registered_modules)
