"""Tests for the LZ4 (0x7) ESE codec and the standalone LZ4 block encoder/decoder."""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ntcompress.ese import Format, header_byte
from ntcompress.ese._registry import _CODECS
from ntcompress.ese.lz4 import HEADER_SIZE, Lz4Header, compress_block, decompress_block, parse_header
from ntcompress.ese import lz4
from ntcompress.exceptions import CompressionError, DecompressionError, IncompressibleError


def pseudo_random(size: int) -> bytes:
    # Deterministic high-entropy bytes (chained sha256) -- reproducible across runs.
    out = bytearray()
    seed = b"lz4-test-seed"
    while len(out) < size:
        seed = hashlib.sha256(seed).digest()
        out += seed
    return bytes(out[:size])


# Hand-crafted vectors, decoded independently against a reference LZ4 decoder.
# Vector A: a single literals-only sequence (token high nibble = literal count).
LITERAL_PLAIN = b"0123456789"
LITERAL_BLOCK = bytes([0xA0]) + LITERAL_PLAIN
LITERAL_CELL = bytes.fromhex("380a00") + LITERAL_BLOCK

# Vector B: overlapping match. Sequence 1: 4 literals "abcd", then offset 4 with
# match length 12 (nibble 8 + minmatch 4) -- the match overlaps its own output,
# expanding "abcd" RLE-style; sequence 2: the mandatory 5 trailing literals.
OVERLAP_PLAIN = b"abcd" * 4 + b"XYZWV"
OVERLAP_BLOCK = bytes([0x48]) + b"abcd" + b"\x04\x00" + bytes([0x50]) + b"XYZWV"
OVERLAP_CELL = bytes([0x38, 0x15, 0x00]) + OVERLAP_BLOCK

# Vector C: both 0xFF-continuation paths. Sequence 1: literal nibble 15 + extension
# byte 5 (= 20 literals), offset 20, match nibble 15 + extension byte 7
# (= 15 + 7 + minmatch 4 = 26 bytes, again overlapping); sequence 2: 5 literals.
EXTENSION_PLAIN = bytes(range(20)) + (bytes(range(20)) * 2)[:26] + b"QWERT"
EXTENSION_BLOCK = bytes([0xFF, 0x05]) + bytes(range(20)) + b"\x14\x00" + bytes([0x07, 0x50]) + b"QWERT"
EXTENSION_CELL = bytes([0x38, 0x33, 0x00]) + EXTENSION_BLOCK

# Vector D: emitted by the reference liblz4 LZ4_compress_default -- the exact
# function ESE calls (compression.cxx:2085) -- framed with the 3-byte Lz4Header.
# Exercises a 45-literal 0xFF extension (15 + 30), offset 45, and a two-byte match
# extension 0xFF 0x24 (15 + 255 + 36 + minmatch 4 = 310, overlapping x6).
LIBLZ4_PLAIN = b"Extensible Storage Engine stores LZ4 blocks. " * 8
LIBLZ4_CELL = bytes.fromhex("386801ff1e457874656e7369626c652053746f7261676520456e67696e652073746f726573204c5a3420626c6f636b732e202d00ff2450636b732e20")

# Vector E: liblz4 output for an RLE run -- offset 1 self-copy with a two-byte match
# extension 0xFF 0x7D (15 + 255 + 125 + minmatch 4 = 399 bytes of "c").
RLE_PLAIN = b"ab" + b"c" * 400 + b"final"
RLE_BLOCK = bytes.fromhex("3f6162630100ff7d5066696e616c")


# --- ESE framing ---


def test_header_constants() -> None:
    # C_ASSERT( sizeof(Lz4Header) == 3 ) and byte0 = COMPRESS_LZ4 << 3 = 0x38.
    assert HEADER_SIZE == 3
    assert header_byte(Format.LZ4) == 0x38


def test_parse_header_pinned_bytes() -> None:
    assert parse_header(bytes.fromhex("38e803") + b"payload") == Lz4Header(uncompressed_size=0x03E8)


@pytest.mark.parametrize("scheme_byte", [0x00, 0x08, 0x30, 0x40, 0xFF])
def test_wrong_scheme_byte_rejected(scheme_byte: int) -> None:
    with pytest.raises(DecompressionError):
        parse_header(bytes([scheme_byte, 0x0A, 0x00]) + LITERAL_BLOCK)


def test_low_flag_bits_do_not_change_scheme() -> None:
    # ESE only compares byte0 >> 3 (compression.cxx:2664); low bits are flags.
    cell = bytes([0x3F]) + LITERAL_CELL[1:]
    assert lz4.decompress(cell) == LITERAL_PLAIN


@pytest.mark.parametrize("length", [0, 1, 2])
def test_truncated_header_rejected(length: int) -> None:
    blob = LITERAL_CELL[:length]
    with pytest.raises(DecompressionError):
        lz4.decompressed_size(blob)
    with pytest.raises(DecompressionError):
        lz4.decompress(blob)


def test_decompressed_size() -> None:
    assert lz4.decompressed_size(LITERAL_CELL) == 10
    assert lz4.decompressed_size(OVERLAP_CELL) == 21
    assert lz4.decompressed_size(EXTENSION_CELL) == 51


# --- Pinned decode vectors ---


def test_decode_all_literals_vector() -> None:
    assert lz4.decompress(LITERAL_CELL) == LITERAL_PLAIN


def test_decode_overlapping_match_vector() -> None:
    assert lz4.decompress(OVERLAP_CELL) == OVERLAP_PLAIN


def test_decode_length_extension_vector() -> None:
    assert lz4.decompress(EXTENSION_CELL) == EXTENSION_PLAIN


def test_decode_liblz4_reference_vector() -> None:
    # Cell whose payload was produced by LZ4_compress_default itself -- byte-for-byte
    # what ErrCompressLz4_ persists (compression.cxx:2085, 2104-2105).
    assert lz4.decompress(LIBLZ4_CELL) == LIBLZ4_PLAIN
    assert lz4.decompressed_size(LIBLZ4_CELL) == len(LIBLZ4_PLAIN)


def test_decode_liblz4_rle_vector() -> None:
    # Offset-1 self-overlap with a multi-byte (0xFF 0x7D) match-length extension.
    assert decompress_block(RLE_BLOCK, len(RLE_PLAIN)) == RLE_PLAIN


def test_trailing_payload_bytes_ignored() -> None:
    # LZ4_decompress_safe_partial stops once targetOutputSize bytes are out
    # (compression.cxx:2677-2682); bytes past the block's end are never read.
    assert lz4.decompress(LITERAL_CELL + b"\xde\xad\xbe\xef") == LITERAL_PLAIN


def test_decode_stops_at_target_size() -> None:
    # LZ4_decompress_safe_partial semantics (compression.cxx:2677-2682): output
    # stops at the out-of-band target, even mid-literal-run or mid-match.
    assert decompress_block(LITERAL_BLOCK, 4) == b"0123"
    assert decompress_block(OVERLAP_BLOCK, 10) == b"abcdabcdab"


def test_decode_empty() -> None:
    assert decompress_block(b"", 0) == b""
    assert lz4.decompress(bytes([0x38, 0x00, 0x00])) == b""
    assert lz4.decompressed_size(bytes([0x38, 0x00, 0x00])) == 0


# --- Corrupt payload rejection ---


def test_offset_zero_rejected() -> None:
    # lz4_Block_format.md: "The presence of a 0 offset value denotes an invalid (corrupted) block".
    block = bytes([0x14]) + b"A" + b"\x00\x00"
    with pytest.raises(DecompressionError):
        decompress_block(block, 9)


def test_offset_before_output_start_rejected() -> None:
    block = bytes([0x14]) + b"A" + b"\x05\x00"
    with pytest.raises(DecompressionError):
        decompress_block(block, 9)


def test_truncated_literal_run_rejected() -> None:
    with pytest.raises(DecompressionError):
        decompress_block(bytes([0x50]) + b"AB", 5)


def test_truncated_match_offset_rejected() -> None:
    with pytest.raises(DecompressionError):
        decompress_block(bytes([0x10]) + b"A" + b"\x04", 9)


def test_eof_inside_length_extension_rejected() -> None:
    with pytest.raises(DecompressionError):
        decompress_block(bytes([0xF0, 0xFF]), 600)


def test_payload_shorter_than_target_rejected() -> None:
    # Header claims 10 bytes but the block cleanly produces only 2.
    cell = bytes([0x38, 0x0A, 0x00, 0x20]) + b"AB"
    with pytest.raises(DecompressionError):
        lz4.decompress(cell)


def test_empty_payload_with_nonzero_size_rejected() -> None:
    with pytest.raises(DecompressionError):
        lz4.decompress(bytes([0x38, 0x05, 0x00]))


# --- Encoder ---


def test_compress_pinned_output() -> None:
    # Pins THIS greedy encoder's output (the block format does not mandate encoder
    # bytes): "abc" literals, match offset 3 length 9, then 5 trailing literals.
    data = b"abcabcabcabcXXXXX"
    cell = lz4.compress(data)
    assert cell == bytes.fromhex("381100") + bytes([0x35]) + b"abc" + b"\x03\x00" + bytes([0x50]) + b"XXXXX"
    assert lz4.decompress(cell) == data


def test_compress_header_fields() -> None:
    data = b"the quick brown fox " * 100
    cell = lz4.compress(data)
    assert cell[0] == 0x38
    assert int.from_bytes(cell[1:3], "little") == len(data)
    assert len(cell) < len(data)
    assert lz4.decompress(cell) == data
    assert lz4.decompressed_size(cell) == len(data)


def test_compress_block_empty() -> None:
    # A lone zero token: empty final literal run (matches liblz4 for srcSize=0).
    assert compress_block(b"") == b"\x00"


@pytest.mark.parametrize("data", [b"", b"a", b"0123456789", b"abcabcabc"])
def test_compress_small_input_incompressible(data: bytes) -> None:
    # compression.cxx:2090-2095: reject unless compressed + 3 < original.
    with pytest.raises(IncompressibleError):
        lz4.compress(data)


def test_compress_random_input_incompressible() -> None:
    data = pseudo_random(2000)
    with pytest.raises(IncompressibleError):
        lz4.compress(data)


def test_compress_oversized_input_rejected() -> None:
    # mle_cbUncompressed is a u16; ESE gates on data.Cb() <= wMax (compression.cxx:2761).
    with pytest.raises(CompressionError):
        lz4.compress(b"\x00" * 65536)


def test_compress_max_size_round_trip() -> None:
    data = b"\xab" * 65535
    assert lz4.decompress(lz4.compress(data)) == data


# --- Round trips ---


@pytest.mark.parametrize(
    "data",
    [
        b"abc" * 1000,
        b"\x00" * 300,
        b"The quick brown fox jumps over the lazy dog. " * 40,
        bytes(b & 3 for b in pseudo_random(3000)),
        b"a" * 12 + b"b" * 12 + b"a" * 12,
    ],
)
def test_cell_round_trip(data: bytes) -> None:
    cell = lz4.compress(data)
    assert len(cell) < len(data)
    assert lz4.decompress(cell) == data


@given(st.binary(max_size=2048))
def test_block_round_trip_arbitrary(data: bytes) -> None:
    assert decompress_block(compress_block(data), len(data)) == data


@given(st.binary(min_size=1, max_size=48), st.integers(min_value=2, max_value=64))
def test_block_round_trip_repetitive(unit: bytes, repeats: int) -> None:
    data = unit * repeats
    assert decompress_block(compress_block(data), len(data)) == data


# --- Interface ---


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview])
def test_accepts_bytes_like(wrap: type) -> None:
    cell = wrap(OVERLAP_CELL)
    assert lz4.decompress(cell) == OVERLAP_PLAIN
    assert lz4.decompressed_size(cell) == len(OVERLAP_PLAIN)
    assert lz4.decompress(lz4.compress(wrap(b"abc" * 1000))) == b"abc" * 1000


def test_registered_in_registry() -> None:
    assert Format.LZ4 in _CODECS


# --- esent.dll byte-identical vectors ---
# Captured from Win11 (Build 26100) ESE database with EFV 9420 / 8KB pages.
# Cells are 3-byte Lz4Header + raw LZ4 block, byte-for-byte as esent.dll wrote them.


def _highbit_rep(size: int) -> bytes:
    """0xC0..0xCF repeating pattern (ese_targeted.ps1 "highbit_rep")."""
    return bytes(0xC0 + (i % 16) for i in range(size))


def _highbit_mod64(size: int) -> bytes:
    """0x80..0xBF repeating pattern (ese_targeted.ps1 "highbit_mod64")."""
    return bytes(0x80 + (i % 64) for i in range(size))


def _mixed_high(size: int) -> bytes:
    """0xFF every 4th byte, else 0x80+(i%32) (ese_targeted.ps1 "mixed_high")."""
    return bytes(0xFF if i % 4 == 0 else 0x80 + (i % 32) for i in range(size))


@pytest.mark.parametrize(
    ("label", "plain_fn", "size", "esent_cell_hex"),
    [
        ("highbit_rep_1024", _highbit_rep, 1024, "380004ff01c0c1c2c3c4c5c6c7c8c9cacbcccdcecf1000ffffffdb50cbcccdcecf"),
        ("highbit_mod64_1024", _highbit_mod64, 1024, "380004ff31808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf4000ffffffab50bbbcbdbebf"),
        ("mixed_high_1024", _mixed_high, 1024, "380004ff11ff818283ff858687ff898a8bff8d8e8fff919293ff959697ff999a9bff9d9e9f2000ffffffcb509bff9d9e9f"),
        ("highbit_rep_2048", _highbit_rep, 2048, "380008ff01c0c1c2c3c4c5c6c7c8c9cacbcccdcecf1000ffffffffffffffdf50cbcccdcecf"),
        ("highbit_mod64_2048", _highbit_mod64, 2048, "380008ff31808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf4000ffffffffffffffaf50bbbcbdbebf"),
        ("mixed_high_2048", _mixed_high, 2048, "380008ff11ff818283ff858687ff898a8bff8d8e8fff919293ff959697ff999a9bff9d9e9f2000ffffffffffffffcf509bff9d9e9f"),
        ("highbit_rep_4096", _highbit_rep, 4096, "380010ff01c0c1c2c3c4c5c6c7c8c9cacbcccdcecf1000ffffffffffffffffffffffffffffffe750cbcccdcecf"),
        ("highbit_mod64_4096", _highbit_mod64, 4096, "380010ff31808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf4000ffffffffffffffffffffffffffffffb750bbbcbdbebf"),
        ("mixed_high_4096", _mixed_high, 4096, "380010ff11ff818283ff858687ff898a8bff8d8e8fff919293ff959697ff999a9bff9d9e9f2000ffffffffffffffffffffffffffffffd7509bff9d9e9f"),
        ("zeros_1024", lambda n: b"\x00" * n, 1024, "3800041f000100ffffffea500000000000"),
        ("zeros_2048", lambda n: b"\x00" * n, 2048, "3800081f000100ffffffffffffffee500000000000"),
        ("zeros_4096", lambda n: b"\x00" * n, 4096, "3800101f000100fffffffffffffffffffffffffffffff6500000000000"),
        ("allA_1024", lambda n: b"\x41" * n, 1024, "3800041f410100ffffffea504141414141"),
        ("allA_2048", lambda n: b"\x41" * n, 2048, "3800081f410100ffffffffffffffee504141414141"),
        ("allA_4096", lambda n: b"\x41" * n, 4096, "3800101f410100fffffffffffffffffffffffffffffff6504141414141"),
    ],
    ids=lambda x: x if isinstance(x, str) else "",
)
def test_esent_lz4_byte_identical(label, plain_fn, size, esent_cell_hex):  # noqa: ARG001
    """Our LZ4 compressor matches esent.dll output byte-for-byte (Win11 EFV 9420)."""
    plain = plain_fn(size)
    esent_cell = bytes.fromhex(esent_cell_hex)
    assert lz4.decompress(esent_cell) == plain
    assert lz4.compress(plain) == esent_cell
