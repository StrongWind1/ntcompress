"""Tests for the raw Plain LZ77 codec (ntdll xpress) and the ESE XPRESS (0x3) frame."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ntcompress.ese import Format, compress, decompress, decompressed_size
from ntcompress.ese import xpress as ese_xpress
from ntcompress.ese._registry import _CODECS
from ntcompress.ese.xpress import HEADER_SIZE, MAX_UNCOMPRESSED
from ntcompress.exceptions import CompressionError, DecompressionError, IncompressibleError
from ntcompress.ntdll import xpress as lzxpress

# [MS-XCA] §3.1 worked examples (raw Plain LZ77 payloads, MS-XCA.md:933-958).
ALPHABET = b"abcdefghijklmnopqrstuvwxyz"
ALPHABET_RAW = bytes.fromhex("3f000000") + ALPHABET
ABC300 = b"abc" * 100
ABC300_RAW = bytes.fromhex("ffffff1f61626317000fff2601")

# Framed ESE cells: 0x18 scheme byte + u16 LE uncompressed size + raw payload.
ABC300_CELL = bytes.fromhex("182c01") + ABC300_RAW
ALPHABET_CELL = bytes.fromhex("181a00") + ALPHABET_RAW


# --- Raw lzxpress: [MS-XCA] §3.1 vectors ---


def test_spec_alphabet_decompress():
    assert lzxpress.decompress(ALPHABET_RAW) == ALPHABET


def test_spec_alphabet_compress():
    # 26 literals -> flag word = 26 zero bits then 6 one-bit pads = 0x0000003F.
    assert lzxpress.compress(ALPHABET) == ALPHABET_RAW


def test_spec_abc300_decompress():
    assert lzxpress.decompress(ABC300_RAW) == ABC300


def test_spec_abc300_compress():
    # "abc" + match(offset=3, length=297): token 0x0017, nibble 15, byte 255, word 0x0126.
    assert lzxpress.compress(ABC300) == ABC300_RAW


# --- Raw lzxpress: Windows RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS) vectors ---
# Compressed by ntdll.dll 10.0.20348.4050 on Server 2022. Our compressor produces
# byte-identical output for all four, confirming interoperability.

# 4096 bytes of repeating A-Z pattern
_RTL_REP4K_PLAIN = bytes(0x41 + (i % 26) for i in range(1, 4097))
_RTL_REP4K_COMP = bytes.fromhex("3f00000042434445464748494a4b4c4d4e4f505152535455565758595a41cf000fffe30f")

# 4096 bytes of repeating "The quick brown fox..." sentence
_RTL_TEXT_PLAIN = (b"The quick brown fox jumps over the lazy dog. " * 92)[:4096]
_RTL_TEXT_COMP = bytes.fromhex("0000000054686520717569636b2062726f776e20666f78206a756d7073206f7665722074ffff1f80f0006c617a7920646f672e2067010fffd00f")

# 4096 null bytes
_RTL_ZEROS_COMP = bytes.fromhex("ffffff7f0007000ffffc0f")

# 1024 random bytes (seed 42) — incompressible, expands to 1156 bytes
_RTL_RAND_PLAIN_LEN = 1024


@pytest.mark.parametrize(
    ("compressed", "plain"),
    [
        (_RTL_REP4K_COMP, _RTL_REP4K_PLAIN),
        (_RTL_TEXT_COMP, _RTL_TEXT_PLAIN),
        (_RTL_ZEROS_COMP, b"\x00" * 4096),
    ],
    ids=["rtl_rep4k", "rtl_text", "rtl_zeros"],
)
def test_rtl_compress_buffer_decompress(compressed, plain):
    assert lzxpress.decompress(compressed) == plain


@pytest.mark.parametrize(
    ("plain", "expected_compressed"),
    [
        (_RTL_REP4K_PLAIN, _RTL_REP4K_COMP),
        (_RTL_TEXT_PLAIN, _RTL_TEXT_COMP),
        (b"\x00" * 4096, _RTL_ZEROS_COMP),
    ],
    ids=["rtl_rep4k", "rtl_text", "rtl_zeros"],
)
def test_rtl_compress_buffer_byte_identical(plain, expected_compressed):
    assert lzxpress.compress(plain) == expected_compressed


# --- Raw lzxpress: hand-derived vectors ---


def test_shared_nibble_vector():
    # Two long matches share one length byte: the first takes the low nibble, the
    # second ORs into the high nibble ([MS-XCA] §2.3.4/§2.4.4 LastLengthHalfByte).
    # b"x"*15 + b"y"*15 -> lit 'x', match(1,14), lit 'y', match(1,14); both lengths
    # 14 -> extra nibble 4, shared byte 0x44; flags 0101 + pad = 0x5FFFFFFF.
    data = b"x" * 15 + b"y" * 15
    raw = bytes.fromhex("ffffff5f78070044790700")
    assert lzxpress.decompress(raw) == data
    assert lzxpress.compress(data) == raw


def test_saturated_shared_nibble_vector():
    # First long match saturates its nibble at 15 (spec's goto EncodeExtraLen path)
    # yet still leaves LastLengthHalfByte set, so the next long match ORs into the
    # high half of the same byte: b"x"*30 + b"y"*15 -> lit x, match(1,29) [nibble 15,
    # byte 4], lit y, match(1,14) [nibble 4] -> shared byte 0x4F.
    data = b"x" * 30 + b"y" * 15
    raw = bytes.fromhex("ffffff5f7807004f04790700")
    assert lzxpress.decompress(raw) == data
    assert lzxpress.compress(data) == raw


def test_max_offset_decode():
    # A match at the full 8192-byte window: token 0xFFF8 = offset bits 8191 ->
    # MatchOffset 8192, length bits 0 -> length 3 ([MS-XCA] §2.3.4 MatchOffset <= 2^13).
    literals = bytes(range(256)) * 32  # 8192 literal bytes
    raw = b"".join(b"\x00\x00\x00\x00" + literals[i * 32 : (i + 1) * 32] for i in range(256))
    raw += b"\xff\xff\xff\xff\xf8\xff"
    assert lzxpress.decompress(raw) == literals + literals[:3]


def test_overlapping_match_vector():
    # b"a"*10 -> lit 'a', match(offset=1, length=9): length may exceed offset, so the
    # copy must run one byte at a time ([MS-XCA] MS-XCA.md:562).
    data = b"a" * 10
    raw = bytes.fromhex("ffffff7f610600")
    assert lzxpress.decompress(raw) == data
    assert lzxpress.compress(data) == raw


def test_u32_length_ladder_vector():
    # b"a"*70000 -> lit 'a', match(1, 69999). extra = 69996 >= 2^16 so the v10.0
    # ladder bottoms out: nibble 15, byte 255, word 0, dword 69996 (0x0001116C).
    data = b"a" * 70000
    raw = bytes.fromhex("ffffff7f6107000fff00006c110100")
    assert lzxpress.compress(data) == raw
    assert lzxpress.decompress(raw) == data


def test_empty_input_compresses_to_padded_flag_word():
    # §2.3.4's final flush always writes a flag word; with no items it is all 1-pad.
    assert lzxpress.compress(b"") == b"\xff\xff\xff\xff"
    assert lzxpress.decompress(b"\xff\xff\xff\xff") == b""


def test_exact_32_items_gets_trailing_flag_word():
    # 32 literals flush the first flag word (all zeros) and reserve a second slot,
    # which the final flush fills with all ones.
    data = bytes(range(32))
    raw = lzxpress.compress(data)
    assert raw == bytes(4) + data + b"\xff\xff\xff\xff"
    assert lzxpress.decompress(raw) == data


def test_single_literal_then_terminating_match_flag():
    # Flag word 0x40000000: bit 31 = 0 (literal), bit 30 = 1 (match) hit with the
    # input exhausted, which is the §2.4.4 success exit.
    assert lzxpress.decompress(bytes.fromhex("0000004041")) == b"A"


def test_decompress_accepts_bytearray_and_memoryview():
    assert lzxpress.decompress(bytearray(ABC300_RAW)) == ABC300
    assert lzxpress.decompress(memoryview(ABC300_RAW)) == ABC300


# --- Raw lzxpress: corrupt/truncated streams rejected ---


def test_decompress_empty_rejected():
    with pytest.raises(DecompressionError):
        lzxpress.decompress(b"")


def test_truncated_flag_word_rejected():
    with pytest.raises(DecompressionError):
        lzxpress.decompress(b"\x3f\x00")


def test_literal_past_end_rejected():
    # 32 literal flags but no literal bytes.
    with pytest.raises(DecompressionError):
        lzxpress.decompress(bytes.fromhex("00000000"))


def test_truncated_match_token_rejected():
    # Match flag (bit 31 of 0x80000000) with only 1 payload byte left.
    with pytest.raises(DecompressionError):
        lzxpress.decompress(bytes.fromhex("0000008061"))


def test_match_before_output_start_rejected():
    # First item is a match token (offset 1) with nothing decoded yet.
    with pytest.raises(DecompressionError):
        lzxpress.decompress(bytes.fromhex("ffffffff0700"))


def test_extended_length_below_ladder_floor_rejected():
    # lit 'a', then match with nibble 15, byte 255, word 5 < 22 ([MS-XCA] §2.4.4
    # "If MatchLength < 15 + 7 Return error").
    with pytest.raises(DecompressionError):
        lzxpress.decompress(bytes.fromhex("ffffff7f6107000fff0500"))


def test_truncated_length_ladder_rejected():
    # lit 'a', match escaping to the ladder, but the stream ends before the nibble.
    with pytest.raises(DecompressionError):
        lzxpress.decompress(bytes.fromhex("ffffff7f610700"))


def test_dword_length_below_ladder_floor_rejected():
    # The floor check also guards the v10.0 dword path: word 0 escapes to a dword
    # of 21 < 22 ([MS-XCA] §2.4.4 "If MatchLength < 15 + 7 Return error").
    with pytest.raises(DecompressionError):
        lzxpress.decompress(bytes.fromhex("ffffff7f6107000fff000015000000"))


# --- Raw lzxpress: max_size output cap ([MS-XCA] §2.4.4 out-of-buffer writes) ---


def test_max_size_allows_exact_fit():
    assert lzxpress.decompress(ALPHABET_RAW, max_size=26) == ALPHABET
    assert lzxpress.decompress(ABC300_RAW, max_size=300) == ABC300


def test_max_size_rejects_literal_overflow():
    with pytest.raises(DecompressionError):
        lzxpress.decompress(ALPHABET_RAW, max_size=25)


def test_max_size_rejects_match_overflow():
    with pytest.raises(DecompressionError):
        lzxpress.decompress(ABC300_RAW, max_size=299)


# --- Raw lzxpress: round trips ---


@given(st.binary(max_size=1024))
def test_raw_roundtrip_arbitrary(data):
    assert lzxpress.decompress(lzxpress.compress(data)) == data


@given(st.binary(min_size=1, max_size=48), st.integers(min_value=2, max_value=64))
def test_raw_roundtrip_repetitive(pattern, repeats):
    # Repetitive data exercises overlapping copies and every length-ladder tier.
    data = pattern * repeats
    assert lzxpress.decompress(lzxpress.compress(data)) == data


@pytest.mark.parametrize("length", [3, 9, 10, 24, 25, 279, 280, 65537, 65538, 65539, 70000])
def test_raw_roundtrip_ladder_boundaries(length):
    # One literal + one match of (length - 1): crosses the 3-bit (<=9), nibble
    # (<=24), byte (<=279), word (<=65538 historically), and dword tiers.
    data = b"q" * length
    assert lzxpress.decompress(lzxpress.compress(data)) == data


# --- Framed ESE xpress: spec vectors ---


def test_framed_abc300_decompress():
    assert ese_xpress.decompress(ABC300_CELL) == ABC300


def test_framed_abc300_compress():
    assert ese_xpress.compress(ABC300) == ABC300_CELL


def test_framed_alphabet_decompress():
    # The alphabet is incompressible so ESE would never write this cell, but the
    # decoder must still handle a well-formed one.
    assert ese_xpress.decompress(ALPHABET_CELL) == ALPHABET


def test_decompressed_size():
    assert ese_xpress.decompressed_size(ABC300_CELL) == 300
    assert ese_xpress.decompressed_size(ALPHABET_CELL) == 26
    assert ese_xpress.decompressed_size(bytes.fromhex("18ffff")) == MAX_UNCOMPRESSED


def test_header_size_constant():
    assert HEADER_SIZE == 3
    assert ABC300_CELL[0] == 0x18  # COMPRESS_XPRESS << 3, compression.cxx:1551


def test_nonzero_flag_bits_still_dispatch():
    # ESE dispatches on byte0 >> 3, not the whole byte; flags 0x03 must not misroute.
    cell = bytes([0x1B]) + ABC300_CELL[1:]
    assert ese_xpress.decompress(cell) == ABC300


# --- Framed ESE xpress: real esent.dll vectors (Server 2022 Build 20348, EFV 8920) ---

# zeros_1024: 1024 null bytes compressed by esent.dll.
_ESENT_ZEROS_1024_CELL = bytes.fromhex("180004ffffff3f000007000ffffb03")
_ESENT_ZEROS_1024_PLAIN = b"\x00" * 1024

# single_0x41_1024: 1024 * b'\x41'.
_ESENT_SINGLE_41_1024_CELL = bytes.fromhex("180004ffffff3f414107000ffffb03")
_ESENT_SINGLE_41_1024_PLAIN = b"\x41" * 1024

# highbit_rep_1024: repeating 0xC0-0xCF pattern (16-byte cycle).
_ESENT_HIGHBIT_REP_1024_CELL = bytes.fromhex("180004ff7f0000c0c1c2c3c4c5c6c7c8c9cacbcccdcecfc07f000fffec03")
_ESENT_HIGHBIT_REP_1024_PLAIN = bytes(0xC0 + (i % 16) for i in range(1024))

# alt_aa55_1024: alternating 0xAA/0x55 pattern.
_ESENT_ALT_AA55_1024_CELL = bytes.fromhex("180004ffffff1faa55aa0f000ffffa03")
_ESENT_ALT_AA55_1024_PLAIN = bytes(0xAA if i % 2 == 0 else 0x55 for i in range(1024))

# ascii_text_1024: "The quick brown fox..." repeating, 1024 bytes.
_ESENT_ASCII_TEXT_1024_CELL = bytes.fromhex("1800040000000054686520717569636b2062726f776e20666f78206a756d7073206f7665722074ffff0f80f0006c617a7920646f672e2054680067010fffcc03")
_ESENT_ASCII_TEXT_1024_PLAIN = (b"The quick brown fox jumps over the lazy dog. " * 23)[:1024]

# runlength_1024: 256-byte runs of 0x80, 0x81, 0x82, 0x83.
_ESENT_RUNLENGTH_1024_CELL = bytes.fromhex("180004ffffff2a80800700ffe5810700e6820700ffe6830700e6")
_ESENT_RUNLENGTH_1024_PLAIN = b"".join(bytes([0x80 + i]) * 256 for i in range(4))


@pytest.mark.parametrize(
    ("cell", "plain"),
    [
        (_ESENT_ZEROS_1024_CELL, _ESENT_ZEROS_1024_PLAIN),
        (_ESENT_SINGLE_41_1024_CELL, _ESENT_SINGLE_41_1024_PLAIN),
        (_ESENT_HIGHBIT_REP_1024_CELL, _ESENT_HIGHBIT_REP_1024_PLAIN),
        (_ESENT_ALT_AA55_1024_CELL, _ESENT_ALT_AA55_1024_PLAIN),
        (_ESENT_ASCII_TEXT_1024_CELL, _ESENT_ASCII_TEXT_1024_PLAIN),
        (_ESENT_RUNLENGTH_1024_CELL, _ESENT_RUNLENGTH_1024_PLAIN),
    ],
    ids=["zeros_1024", "single_0x41_1024", "highbit_rep_1024", "alt_aa55_1024", "ascii_text_1024", "runlength_1024"],
)
def test_esent_xpress_vectors(cell, plain):
    assert ese_xpress.decompress(cell) == plain
    assert ese_xpress.decompressed_size(cell) == len(plain)


# --- Framed ESE xpress: error cases ---


def test_framed_empty_and_short_rejected():
    for blob in (b"", b"\x18", b"\x18\x2c"):
        with pytest.raises(DecompressionError):
            ese_xpress.decompress(blob)
        with pytest.raises(DecompressionError):
            ese_xpress.decompressed_size(blob)


def test_framed_wrong_format_rejected():
    cell = bytes([Format.LZ4 << 3]) + ABC300_CELL[1:]
    with pytest.raises(DecompressionError):
        ese_xpress.decompress(cell)


def test_framed_size_mismatch_rejected():
    # Declares 301 but the stream decodes 300: the size-equality check catches this.
    cell = bytes.fromhex("182d01") + ABC300_RAW  # declares 301, stream decodes 300
    with pytest.raises(DecompressionError):
        ese_xpress.decompress(cell)


def test_framed_corrupt_payload_rejected():
    cell = ABC300_CELL[:-2]  # truncate the extended-length word
    with pytest.raises(DecompressionError):
        ese_xpress.decompress(cell)


def test_framed_forged_giant_match_fails_fast():
    # Cell declares 10 bytes but its dword-escape match claims ~4 GB (lit 'a', then
    # match(1, 4_000_000_000)). The declared size bounds the decode as it runs
    # ([MS-XCA] §2.4.4 out-of-buffer write), so this must raise without first
    # materializing a multi-gigabyte buffer.
    cell = bytes.fromhex("180a00") + bytes.fromhex("ffffff7f6107000fff0000fd276bee")
    with pytest.raises(DecompressionError):
        ese_xpress.decompress(cell)


def test_framed_forged_giant_match_fails_fast_second_vector():
    # The declared size caps the decode: the same forged ~4 GB match must raise. This
    # is a duplicate of the above to confirm the running bound catches both paths.
    cell = bytes.fromhex("180a00") + bytes.fromhex("ffffff7f6107000fff0000fd276bee")
    with pytest.raises(DecompressionError):
        ese_xpress.decompress(cell)


def test_compress_incompressible_rejected():
    # Frame (3) + flag words make small/high-entropy input larger, ESE's
    # errRECCannotCompress case.
    for data in (b"", b"a", ALPHABET):
        with pytest.raises(IncompressibleError):
            ese_xpress.compress(data)


def test_compress_oversized_rejected():
    with pytest.raises(CompressionError):
        ese_xpress.compress(b"a" * (MAX_UNCOMPRESSED + 1))


# --- Framed ESE xpress: round trips and registration ---


def test_framed_roundtrip_max_size():
    data = (b"0123456789abcdef" * 4096)[:MAX_UNCOMPRESSED]
    cell = ese_xpress.compress(data)
    assert len(cell) < len(data)
    assert ese_xpress.decompressed_size(cell) == MAX_UNCOMPRESSED
    assert ese_xpress.decompress(cell) == data


@given(st.binary(min_size=1, max_size=32), st.integers(min_value=8, max_value=64))
def test_framed_roundtrip_repetitive(pattern, repeats):
    data = pattern * repeats
    try:
        cell = ese_xpress.compress(data)
    except IncompressibleError:
        return
    assert len(cell) < len(data)
    assert ese_xpress.decompress(cell) == data
    assert ese_xpress.decompressed_size(cell) == len(data)


def test_registered_and_dispatchable():
    assert Format.XPRESS in _CODECS
    assert decompress(ABC300_CELL) == ABC300
    assert decompressed_size(ABC300_CELL) == 300
