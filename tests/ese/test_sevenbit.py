"""Tests for the 7-bit ASCII (0x1) and 7-bit Unicode (0x2) codecs."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ntcompress.ese import Format
from ntcompress.ese._registry import _CODECS
from ntcompress.exceptions import CompressionError, DecompressionError, IncompressibleError
from ntcompress.ese import sevenbit_ascii, sevenbit_unicode

ASCII = sevenbit_ascii
UNICODE = sevenbit_unicode

# ESE unit-test vector (compression.cxx:3298-3312): 16 bytes -> 15, header 0x0F.
ASCII_PLAINTEXT = b"1234567890ABCDEF"
ASCII_CELL = bytes.fromhex("0f31d98c56b3dd703958503824168d")

# ESE unit-test vector (compression.cxx:3349-3363): L"12" (4 bytes) -> 3, header 0x15.
UNICODE_PLAINTEXT = "12".encode("utf-16-le")
UNICODE_CELL = bytes.fromhex("153119")

# libesedb tests/esedb_test_compression.c:39-65: 50-byte Exchange cell, header 0x10
# (scheme id 2 = 7BITUNICODE, final-byte bit count 1).
EXCHANGE_CELL = bytes.fromhex("10d2a20e0442bd82f2313a5d36b7c37078d9fdb296e5f7b49a5c9693cba034bddc9ebfac65b9feed2697dda034bddc9ea700")
EXCHANGE_TEXT = "RE:  (/Archiefmappen/Verwijderde items/Verzonden items)"

# ese-rs src/utils.rs:142-157: 10-byte CA RequestOSVersion cell, header 0x15 (scheme id 2).
CA_CELL = bytes([0x15, 0x36, 0x57, 0xCC, 0x75, 0xB3, 0xC1, 0x62, 0x38, 0x38])
CA_TEXT = "6.1.76018p"


# --- ESE unit-test vectors ---


def test_ascii_ese_vector_compress():
    cell = ASCII.compress(ASCII_PLAINTEXT)
    assert len(cell) == 15  # CHECK( 15 == cbDataActual ), compression.cxx:3304
    assert cell == ASCII_CELL
    assert cell[0] == 0x0F  # scheme 0x1 << 3, final byte fully valid (count 7 = 8 bits)


def test_ascii_ese_vector_decompress():
    assert ASCII.decompress(ASCII_CELL) == ASCII_PLAINTEXT
    assert ASCII.decompressed_size(ASCII_CELL) == 16


def test_unicode_ese_vector_compress():
    cell = UNICODE.compress(UNICODE_PLAINTEXT)
    assert len(cell) == 3  # CHECK( 3 == cbDataActual ), compression.cxx:3355
    assert cell == UNICODE_CELL
    assert cell[0] == 0x15  # scheme 0x2 << 3 | 5 (6 valid bits: 14 bits in 2 bytes)


def test_unicode_ese_vector_decompress():
    assert UNICODE.decompress(UNICODE_CELL) == UNICODE_PLAINTEXT
    assert UNICODE.decompressed_size(UNICODE_CELL) == 4


# --- Real-world vectors ---


def test_exchange_vector_shape():
    # The dossier-cited leading bytes of the libesedb vector.
    assert len(EXCHANGE_CELL) == 50
    assert EXCHANGE_CELL[:8] == bytes([0x10, 0xD2, 0xA2, 0x0E, 0x04, 0x42, 0xBD, 0x82])


def test_exchange_vector_decompress():
    # (50 - 2) * 8 + 1 = 385 bits = exactly 55 units -> 110 UTF-16LE bytes.
    assert UNICODE.decompressed_size(EXCHANGE_CELL) == 110
    assert UNICODE.decompress(EXCHANGE_CELL) == EXCHANGE_TEXT.encode("utf-16-le")


def test_exchange_vector_recompress():
    # Our encoder reproduces the on-disk cell byte for byte, header included.
    assert UNICODE.compress(EXCHANGE_TEXT.encode("utf-16-le")) == EXCHANGE_CELL


def test_ca_vector_decompress():
    # (10 - 2) * 8 + 6 = 70 bits = exactly 10 units -> 20 UTF-16LE bytes.
    assert UNICODE.decompressed_size(CA_CELL) == 20
    assert UNICODE.decompress(CA_CELL) == CA_TEXT.encode("utf-16-le")


def test_ese_parser_alternate_header_vectors():
    # ese_parser decomp.rs:48-91 carries the same Exchange payload with header 0x0E
    # (scheme id 1, bit count 6): (50-2)*8 + 7 = 391 bits, NOT a multiple of 7, so the
    # retail floor division must yield exactly 55 ASCII bytes. The test then flips the
    # header to 0x16 (scheme id 2, same count) and expects 110 UTF-16LE bytes.
    ascii_cell = bytes([0x0E]) + EXCHANGE_CELL[1:]
    assert ASCII.decompressed_size(ascii_cell) == 55  # decomp.rs asserts get_size == 55
    assert ASCII.decompress(ascii_cell) == EXCHANGE_TEXT.encode("ascii")
    unicode_cell = bytes([0x16]) + EXCHANGE_CELL[1:]
    assert UNICODE.decompressed_size(unicode_cell) == 110
    assert UNICODE.decompress(unicode_cell) == EXCHANGE_TEXT.encode("utf-16-le")


# --- Real esent.dll vectors (Server 2022 Build 20348, EFV 8920, PS 8192) ---

# ascii7_rand_16: 16 random 7-bit-clean bytes, scheme chosen by Calculate7BitCompressionScheme_.
_ESENT_ASCII_RAND_16_CELL = bytes.fromhex("0fb151efea0649d967a24b44526f55")
_ESENT_ASCII_RAND_16_PLAIN = bytes.fromhex("31233d576e20526c67442e22246a5b2a")

# ascii_text_16: "The quick brown " (first 16 bytes of repeating sentence).
_ESENT_ASCII_TEXT_16_CELL = bytes.fromhex("0f54741914afa7c76b9058febebb41")
_ESENT_ASCII_TEXT_16_PLAIN = bytes.fromhex("54686520717569636b2062726f776e20")

# single_0x41_16: 16 * b'\x41'.
_ESENT_SINGLE_41_16_CELL = bytes.fromhex("0fc16030180c0683c16030180c0683")
_ESENT_SINGLE_41_16_PLAIN = b"\x41" * 16

# gradient_16: bytes 0x00-0x0F (all 7-bit clean, so ESE picks 7BITASCII).
_ESENT_GRADIENT_16_CELL = bytes.fromhex("0f8080604028180e888462c168381e")
_ESENT_GRADIENT_16_PLAIN = bytes(range(16))

# zeros_8: 8 null bytes -- ESE picks 7BITUNICODE (every byte < 0x80).
_ESENT_ZEROS_8_CELL = bytes.fromhex("1300000000")
_ESENT_ZEROS_8_PLAIN = b"\x00" * 8

# zeros_16: 16 null bytes -- 7BITUNICODE.
_ESENT_ZEROS_16_CELL = bytes.fromhex("1700000000000000")
_ESENT_ZEROS_16_PLAIN = b"\x00" * 16

# zeros_64: 64 null bytes -- 7BITUNICODE.
_ESENT_ZEROS_64_CELL = bytes.fromhex("1700000000000000000000000000000000000000000000000000000000")
_ESENT_ZEROS_64_PLAIN = b"\x00" * 64


@pytest.mark.parametrize(
    ("cell", "plain"),
    [
        (_ESENT_ASCII_RAND_16_CELL, _ESENT_ASCII_RAND_16_PLAIN),
        (_ESENT_ASCII_TEXT_16_CELL, _ESENT_ASCII_TEXT_16_PLAIN),
        (_ESENT_SINGLE_41_16_CELL, _ESENT_SINGLE_41_16_PLAIN),
        (_ESENT_GRADIENT_16_CELL, _ESENT_GRADIENT_16_PLAIN),
    ],
    ids=["ascii7_rand_16", "ascii_text_16", "single_0x41_16", "gradient_16"],
)
def test_esent_ascii_vectors(cell, plain):
    assert ASCII.decompress(cell) == plain
    assert ASCII.decompressed_size(cell) == len(plain)
    assert ASCII.compress(plain) == cell


@pytest.mark.parametrize(
    ("cell", "plain"),
    [
        (_ESENT_ZEROS_8_CELL, _ESENT_ZEROS_8_PLAIN),
        (_ESENT_ZEROS_16_CELL, _ESENT_ZEROS_16_PLAIN),
        (_ESENT_ZEROS_64_CELL, _ESENT_ZEROS_64_PLAIN),
    ],
    ids=["zeros_8", "zeros_16", "zeros_64"],
)
def test_esent_unicode_vectors(cell, plain):
    assert UNICODE.decompress(cell) == plain
    assert UNICODE.decompressed_size(cell) == len(plain)
    assert UNICODE.compress(plain) == cell


# --- decompressed_size formula ---


def test_size_uses_final_byte_bit_count():
    # Same 3-byte cell, varying only the low-3-bit count: (3-2)*8 + cbitFinal bits.
    # count 5 -> 14 bits -> 2 units; count 0 -> 9 bits -> 1 unit (floor division).
    assert UNICODE.decompressed_size(bytes([0x15, 0x31, 0x19])) == 4
    assert UNICODE.decompressed_size(bytes([0x10, 0x31, 0x01])) == 2
    assert ASCII.decompressed_size(bytes([0x0F, *([0] * 14)])) == 16


# --- Round trips ---


@given(st.binary(min_size=16, max_size=1024).map(lambda raw: bytes(byte & 0x7F for byte in raw)))
def test_ascii_roundtrip(data):
    cell = ASCII.compress(data)
    assert len(cell) < len(data)
    assert ASCII.decompressed_size(cell) == len(data)
    assert ASCII.decompress(cell) == data


@given(st.text(alphabet=st.characters(max_codepoint=0x7F), min_size=2, max_size=512))
def test_unicode_roundtrip(text):
    data = text.encode("utf-16-le")
    cell = UNICODE.compress(data)
    assert len(cell) < len(data)
    assert UNICODE.decompressed_size(cell) == len(data)
    assert UNICODE.decompress(cell) == data


def test_roundtrip_every_final_bit_count():
    # Sweep unit counts so the stored final-byte bit count takes all 8 values.
    for length in range(16, 32):
        data = bytes(range(length))
        assert ASCII.decompress(ASCII.compress(data)) == data


# --- Compression thresholds and applicability ---


def test_ascii_minimum_input_is_16_bytes():
    with pytest.raises(IncompressibleError):
        ASCII.compress(b"foo")  # errRECCannotCompress, compression.cxx:3291-3296
    with pytest.raises(IncompressibleError):
        ASCII.compress(b"A" * 15)  # packs to 15: not strictly smaller
    assert len(ASCII.compress(b"A" * 16)) == 15


def test_unicode_minimum_input_is_4_bytes():
    with pytest.raises(IncompressibleError):
        UNICODE.compress("f".encode("utf-16-le"))  # errRECCannotCompress, compression.cxx:3342-3347
    assert len(UNICODE.compress("fo".encode("utf-16-le"))) == 3


def test_empty_input_incompressible():
    with pytest.raises(IncompressibleError):
        ASCII.compress(b"")
    with pytest.raises(IncompressibleError):
        UNICODE.compress(b"")


def test_ascii_rejects_non_seven_bit_bytes():
    with pytest.raises(CompressionError):
        ASCII.compress(b"\x80" + b"A" * 30)


def test_unicode_rejects_wide_code_units():
    with pytest.raises(CompressionError):
        UNICODE.compress("café latte".encode("utf-16-le"))  # combining accent > 0x7F


def test_unicode_rejects_high_byte_and_odd_length():
    with pytest.raises(CompressionError):
        UNICODE.compress(b"a\x01" * 10)  # code unit 0x0161 has a non-zero high byte
    with pytest.raises(CompressionError):
        UNICODE.compress(b"abc")


# --- Decode error handling ---


def test_decompress_rejects_empty_and_header_only():
    for fmt, codec in [(Format.SEVEN_BIT_ASCII, ASCII), (Format.SEVEN_BIT_UNICODE, UNICODE)]:
        with pytest.raises(DecompressionError):
            codec.decompress(b"")
        with pytest.raises(DecompressionError):
            codec.decompressed_size(b"")
        with pytest.raises(DecompressionError):
            codec.decompress(bytes([fmt << 3]))


def test_decompress_rejects_wrong_format_id():
    with pytest.raises(DecompressionError):
        ASCII.decompress(EXCHANGE_CELL)  # header 0x10 is 7BITUNICODE
    with pytest.raises(DecompressionError):
        UNICODE.decompress(ASCII_CELL)  # header 0x0F is 7BITASCII
    with pytest.raises(DecompressionError):
        ASCII.decompressed_size(EXCHANGE_CELL)


def test_verify_rejects_nonzero_padding():
    # UNICODE_CELL declares 6 valid bits in its final byte 0x19; setting bit 7
    # corrupts the padding region without changing the decoded units.
    corrupt = UNICODE_CELL[:-1] + bytes([UNICODE_CELL[-1] | 0x80])
    with pytest.raises(DecompressionError):
        UNICODE.decompress(corrupt)


def test_two_byte_cell_with_zero_units_decodes_empty():
    # (2-2)*8 + 1 = 1 bit -> 0 whole units: degenerate but well-defined.
    assert ASCII.decompress(bytes([0x08, 0x00])) == b""
    assert ASCII.decompressed_size(bytes([0x08, 0x00])) == 0


# --- Input types and registration ---


def test_accepts_bytearray_and_memoryview():
    assert ASCII.decompress(bytearray(ASCII_CELL)) == ASCII_PLAINTEXT
    assert ASCII.decompress(memoryview(ASCII_CELL)) == ASCII_PLAINTEXT
    assert UNICODE.compress(memoryview(UNICODE_PLAINTEXT)) == UNICODE_CELL


def test_codecs_are_registered():
    assert _CODECS[Format.SEVEN_BIT_ASCII] is sevenbit_ascii
    assert _CODECS[Format.SEVEN_BIT_UNICODE] is sevenbit_unicode
