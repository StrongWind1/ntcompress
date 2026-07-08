"""Tests for the raw MS-XCA LZNT1 codec ([MS-XCA] §2.5, worked example §3.3)."""

from __future__ import annotations

import hashlib
import itertools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ntcompress.exceptions import DecompressionError
from ntcompress.ntdll import lznt1

# [MS-XCA] §3.3 worked example: 59-byte compressed buffer (single compressed chunk,
# header 0xB038) and its 142-byte ANSI plaintext including the terminal NUL.
SPEC_COMPRESSED = bytes.fromhex("38b08846232000204720410010a24701a045204400084501507900c045200524138805b4024a44ef0358028c091601484500be009e000401189000")
SPEC_PLAINTEXT = b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E F# D E F# G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D\x00"


def test_spec_vector_shape():
    # §3.3: compressed length 59, plaintext length 142, header 0xB038.
    assert len(SPEC_COMPRESSED) == 59
    assert len(SPEC_PLAINTEXT) == 142
    assert SPEC_COMPRESSED[0] | SPEC_COMPRESSED[1] << 8 == 0xB038


def test_spec_vector_decompress():
    assert lznt1.decompress(SPEC_COMPRESSED) == SPEC_PLAINTEXT


def test_spec_vector_decompress_with_terminal():
    # The End_of_buffer terminal (0x0000) is optional; when present it stops the
    # walk and anything after it is ignored ([MS-XCA] §2.5.1.2).
    assert lznt1.decompress(SPEC_COMPRESSED + b"\x00\x00") == SPEC_PLAINTEXT
    assert lznt1.decompress(SPEC_COMPRESSED + b"\x00\x00" + b"trailing junk") == SPEC_PLAINTEXT


def test_overlap_copy_vector():
    # Hand-built chunk (cross-checked against a reference LZNT1 decoder): header
    # 0xB003, flag byte 0x02 -> literal 'A' then word 0x0007 (displacement 1,
    # length 10), an overlapping copy that self-extends to eleven 'A's.
    assert lznt1.decompress(bytes.fromhex("03b0024107 00".replace(" ", ""))) == b"A" * 11


# --- Windows RtlCompressBuffer gold-standard vectors ---
# All compressed by ntdll.dll 10.0.20348.4050 on Server 2022 via format sweep
# (RtlCompressBuffer → RtlDecompressBuffer(Ex) round-trip verified on Windows).
# Plaintext: 4096 bytes of repeating A-Z pattern (0x42..0x5A,0x41,0x42...).

_RTL_PLAIN = bytes(0x41 + (i % 26) for i in range(1, 4097))

# Format 0x0002: COMPRESSION_FORMAT_LZNT1 (default engine).
# Decompresses correctly via our lznt1.decompress; our compressor picks different
# (equally valid) matches, so the compressed bytes differ while the plaintext matches.
_RTL_0x0002 = bytes.fromhex(
    "0fb1004243444546474849004a4b4c4d4e4f5051005253545556575859fc5a41ffcf5f80ff819f839f833f85ffdf86df867f881f8abf8bbf8b5f8dff8e"
    "ff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e"
    "9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff"
    "9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f"
    "0e9f0e9f0e9f0eff9f0e9f0e9f0e9f0e9f0e9f0e9f0e9f0e0f9f0e9f0e9f0e910e"
)

# Format 0x0102: COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM.
# Our compressor produces BYTE-IDENTICAL output to Windows' maximum-compression LZNT1.
_RTL_0x0102 = bytes.fromhex(
    "0fb1004243444546474849004a4b4c4d4e4f5051005253545556575859fc5a41ffcf9f019f019f019f019f01ff9f019f019f019f019f019f019f019f01ff"
    "9f019f019f019f019f019f019f019f01ff9f019f019f019f019f019f019f019f01ff9f019f019f019f019f019f019f019f01ff9f019f019f019f019f019f01"
    "9f019f01ff9f019f019f019f019f019f019f019f01ff9f019f019f019f019f019f019f019f01ff9f019f019f019f019f019f019f019f01ff9f019f019f019f"
    "019f019f019f019f01ff9f019f019f019f019f019f019f019f01ff9f019f019f019f019f019f019f019f01ff9f019f019f019f019f019f019f019f01ff9f01"
    "9f019f019f019f019f019f019f010f9f019f019f019101"
)


def test_rtl_lznt1_default_decompress():
    assert lznt1.decompress(_RTL_0x0002) == _RTL_PLAIN


def test_rtl_lznt1_max_decompress():
    assert lznt1.decompress(_RTL_0x0102) == _RTL_PLAIN


def test_rtl_lznt1_max_byte_identical():
    assert lznt1.compress(_RTL_PLAIN) == _RTL_0x0102


def test_uncompressed_chunk_decode():
    raw = b"hello world"
    header = (0x3000 | len(raw) - 1).to_bytes(2, "little")
    assert lznt1.decompress(header + raw) == raw


def test_multiple_chunks_decode():
    raw = b"independent chunks"
    header = (0x3000 | len(raw) - 1).to_bytes(2, "little")
    assert lznt1.decompress((header + raw) * 3) == raw * 3


def test_decompress_empty():
    assert lznt1.decompress(b"") == b""


def test_compress_empty():
    assert lznt1.compress(b"") == b""


def test_buffer_types_accepted():
    assert lznt1.decompress(bytearray(SPEC_COMPRESSED)) == SPEC_PLAINTEXT
    assert lznt1.decompress(memoryview(SPEC_COMPRESSED)) == SPEC_PLAINTEXT
    assert lznt1.decompress(lznt1.compress(bytearray(b"abc" * 100))) == b"abc" * 100
    assert lznt1.decompress(lznt1.compress(memoryview(b"abc" * 100))) == b"abc" * 100


def test_round_trip_spec_plaintext():
    encoded = lznt1.compress(SPEC_PLAINTEXT)
    assert lznt1.decompress(encoded) == SPEC_PLAINTEXT
    assert len(encoded) < len(SPEC_PLAINTEXT)


def test_round_trip_repetitive_multi_chunk():
    data = b"abc" * 5000  # 15000 bytes -> 4 chunks
    encoded = lznt1.compress(data)
    assert len(encoded) < len(data)
    # Every chunk header has the compressed bit (15) set and signature 3.
    header = encoded[0] | encoded[1] << 8
    assert header & 0x8000
    assert header & 0x7000 == 0x3000
    assert lznt1.decompress(encoded) == data


def test_round_trip_incompressible():
    # Deterministic high-entropy stream: chained SHA-256 digests.
    digests = itertools.accumulate(range(313), lambda acc, _: hashlib.sha256(acc).digest(), initial=b"seed")
    data = b"".join(digests)[:10000]
    encoded = lznt1.compress(data)
    # Three uncompressed chunks (4096 + 4096 + 1808): 2 header bytes each.
    assert len(encoded) == len(data) + 6
    header = encoded[0] | encoded[1] << 8
    assert not header & 0x8000
    assert header & 0x7000 == 0x3000
    assert lznt1.decompress(encoded) == data


def test_round_trip_single_byte():
    encoded = lznt1.compress(b"A")
    assert encoded == b"\x00\x30A"  # uncompressed chunk, stored size 0
    assert lznt1.decompress(encoded) == b"A"


def test_round_trip_chunk_boundaries():
    for size in (4095, 4096, 4097, 8192, 8193):
        data = b"\xaa" * size
        assert lznt1.decompress(lznt1.compress(data)) == data


def test_round_trip_long_overlap_run():
    data = b"xy" + b"z" * 8191
    encoded = lznt1.compress(data)
    assert len(encoded) < 32
    assert lznt1.decompress(encoded) == data


def test_bad_signature_rejected():
    # Bits [14:12] must be 3 for any non-terminal header ([MS-XCA] §2.5.1.2).
    with pytest.raises(DecompressionError):
        lznt1.decompress(b"\x0a\x80\x41\x42")


def test_truncated_header_rejected():
    with pytest.raises(DecompressionError):
        lznt1.decompress(b"\x38")


def test_truncated_chunk_rejected():
    # Header claims a 59-byte chunk but the body is cut short.
    with pytest.raises(DecompressionError):
        lznt1.decompress(SPEC_COMPRESSED[:20])


def test_truncated_uncompressed_chunk_rejected():
    header = (0x3000 | 9).to_bytes(2, "little")  # claims 10 data bytes
    with pytest.raises(DecompressionError):
        lznt1.decompress(header + b"short")


def test_truncated_compressed_word_rejected():
    # Chunk of stored size 1 (4 bytes total): flag byte 0x01 marks a compressed
    # word, but only one byte remains inside the chunk.
    with pytest.raises(DecompressionError):
        lznt1.decompress(b"\x01\xb0\x01\x00")


def test_match_before_output_start_rejected():
    # First element is a match (word 0x0000 -> displacement 1) with no output yet.
    with pytest.raises(DecompressionError):
        lznt1.decompress(b"\x02\xb0\x01\x00\x00")


@given(st.binary(max_size=20000))
@settings(max_examples=50, deadline=None)
def test_round_trip_random(data):
    assert lznt1.decompress(lznt1.compress(data)) == data


@given(st.binary(max_size=3000).map(lambda chunk: chunk * 4))
@settings(max_examples=50, deadline=None)
def test_round_trip_low_entropy(data):
    assert lznt1.decompress(lznt1.compress(data)) == data
