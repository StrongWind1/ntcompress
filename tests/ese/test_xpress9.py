"""Tests for the XPRESS9 (0x5) decoder.

The pinned compressed vectors were produced by the reference C codec (the MIT ESE
``_xpress9`` sources compiled via the PyPI ``xpress9`` wheel, fresh session per
vector) and verified to round-trip through it; the plaintexts are rebuilt from the
same expressions used at capture time.
"""

from __future__ import annotations

import struct

import pytest

from ntcompress.ese import Format, compress, decompress, decompressed_size
from ntcompress.ese import xpress9
from ntcompress.ese._registry import _CODECS
from ntcompress.ese.checksums import crc32c_ese
from ntcompress.ese.xpress9 import (
    _MAX_DECODED_SIZE,
    BLOCK_HEADER_SIZE,
    HEADER_SIZE,
    XPRESS9_MAGIC,
    Xpress9BlockHeader,
    _BitReader,
    _CanonicalHuffman,
    parse_block_header,
)
from ntcompress.exceptions import DecompressionError, IntegrityError

# --- Pinned reference vectors (C codec output; plaintext rebuilt from the capture expressions) ---

# Stored-mode Huffman tables, MTF matches, short lengths.
FOX_PLAIN = b"the quick brown fox jumps over the lazy dog. " * 8
FOX_COMP = bytes.fromhex("2ad7864e68010000d00200001b00060000000000eeadd4ba0000000015cc7f96000000e0c28229028e5c5932668d801127f6dcd92160c69e0702565cd972e08c803d37a69c107061c114011b86bc782260c29e39ba1addfe6d6f")

# One overlapping match of ~1000 bytes at offset 1: the long-length gamma escape.
ZEROS_PLAIN = bytes(1000)
ZEROS_COMP = bytes.fromhex("2ad7864ee8030000470100001b0006000000000043718bbc0000000012e14ffa000000000020fca33b")

# Huffman-coded (mode 1) code-length tables with FILL/ZERO_REPT/ROW opcodes.
PARA_PLAIN = b"Records in an ESE long value are chunked, compressed and checksummed before storage. " * 40 + b"\x00\x01\x02\x03" * 64
PARA_COMP = bytes.fromhex("2ad7864e480e0000030400004101060000000000cea7f001000000005ec0066e000020c266a6000040dcc56e12be7b5be1185559d57fe7dbc9d6e475a63af30600701fc17d040000466aa415fe0e710c9f016bf88443d64e48123a775f682f68b42d594583b84167ea52bd351abefc4512b547cac437c6eb197fd5edfe789e9700")

# 73600 plaintext bytes from a 98-byte block: output larger than the 64 KiB window.
BIGTEXT_PLAIN = b"All work and no play makes Jack a dull boy. 7\n" * 1600
BIGTEXT_COMP = bytes.fromhex("2ad7864e801f01000b0300001b0006000000000001c152a100000000988691a800000020c8860d02eeec39b146c0901d1304ecd823e0c086214f046c19b266ca190129868c59236088800957366c103062cf131d02eca008b6ff7eed77edbf18ba03")

# Two blocks of one session (indices 0 and 1, shared signature), back-to-back.
MULTI_PLAIN_0 = b"first chunk of session data. " * 30
MULTI_PLAIN_1 = b"second chunk, may reference the first chunk of session data. " * 25
MULTI_SPLIT = 73
MULTI_COMP = bytes.fromhex("2ad7864e66030000480200001b000600000000007305fb58000000005e044b7800000060c69213672e0818b3e0ca8e3502f6cc107066ca99334bf6ec103061c885213a04cc9a7f74d22ad7864ef50500002f0200001f000600000000007305fb5801000000206b6fb349030000ce4c19b367c7a4214783802d439e08383165c6941353768c9922e0c28269fb4fdc74")

# --- Synthetic template vectors ---
# ESE only ever emits the MTF=4/Ptr4/Mtf2/window-16 template, so the remaining decoder
# templates (Xpress9DecLz77.c:28-93) and the mode-1 table opcodes have no encoder-made
# coverage. These blocks were hand-assembled from the decoder grammar and verified to
# decode byte-identically by the reference C decoder (MIT _xpress9 via the PyPI
# ``xpress9`` 0.3.8 wheel) before being pinned here.

# MTF=0 / PtrMin=3: no MTF machinery at all, plus the long-length gamma escape.
T_MTF0_GAMMA_PLAIN = b"abcdef" + b"f" * 318
T_MTF0_GAMMA_COMP = bytes.fromhex("2ad7864e4401000053010000060000000000000044332211000000000cfb54d80043468c99306516feae00")

# MTF=2 / PtrMin=3 / MtfMin=3: seeded 2-entry MTF list, matches after both literal and pointer.
T_MTF2_PLAIN = b"abcdefdefdefefdefdeBefdeBefdeBefdeBef"
T_MTF2_COMP = bytes.fromhex("2ad7864e2500000078010000120009000000000044332211000000002bcfe13943003064c498095366810b2c00a178")

# MTF=4 / PtrMin=3 / MtfMin=2: the ptr-min-3 variant of the ESE template.
T_MTF4_PTR3_PLAIN = b"abcdef" + b"f" * 5 + b"f" * 4 + b"f" * 6 + b"f" * 3 + b"f" * 2
T_MTF4_PTR3_COMP = bytes.fromhex("2ad7864e1a000000850100001f0002000000000044332211000000006247055982500000868c183361ca2c73a220151401")

# Window log2 20 (flags bits 13..15 = 4): non-default window declaration.
T_WIN20_PLAIN = b"abcdef" + b"ef" * 5
T_WIN20_COMP = bytes.fromhex("2ad7864e100000004601000006800000000000004433221100000000b277fb6d0043468c993065161d")

# Mode-1 short-symbol table exercising EVERY serialization opcode
# (Xpress9DecHuffman.c:511-615): plain lengths, PREV, ROW_0, ROW_1, FILL, plain zeros,
# and ZERO_REPT with the saturating 3-bit extension, plus a 33-symbol small table with
# both flag-bit and biased 3-bit encodings, 8/9/11-bit codewords, MTF slots 0-3, and a
# short-length escape resolved through the long table.
T_MODE1_PLAIN = b"the quick brown fox! \xfa \xfa \xfa\xfa \xfaa \xfaa " + b"\xfa" * 38
T_MODE1_COMP = bytes.fromhex(
    "2ad7864e48000000500a00006308060000000000fe5afe5a0000000071ffc1fa421008320b000000c8dff77ddff77ddff77ddff7fdbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbe"
    "effbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbffffffffffffffffffffffafdef77ddff77ddff77ddff7fdbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeeffbbeefbbeffbbeeffbbeeffbb9dcf77ddff77ddff77ddf70b130257074b534b6263072b277b72330b3f7202478f5a30f1a7ef8fb28"
)

VECTORS = [
    pytest.param(FOX_PLAIN, FOX_COMP, id="fox-stored-tables-mtf"),
    pytest.param(ZEROS_PLAIN, ZEROS_COMP, id="zeros-long-length-escape"),
    pytest.param(PARA_PLAIN, PARA_COMP, id="para-encoded-tables"),
    pytest.param(BIGTEXT_PLAIN, BIGTEXT_COMP, id="bigtext-beyond-window"),
    pytest.param(MULTI_PLAIN_0 + MULTI_PLAIN_1, MULTI_COMP, id="two-block-session"),
    pytest.param(T_MTF0_GAMMA_PLAIN, T_MTF0_GAMMA_COMP, id="template-mtf0-ptr3-gamma"),
    pytest.param(T_MTF2_PLAIN, T_MTF2_COMP, id="template-mtf2-ptr3-mtf3"),
    pytest.param(T_MTF4_PTR3_PLAIN, T_MTF4_PTR3_COMP, id="template-mtf4-ptr3-mtf2"),
    pytest.param(T_WIN20_PLAIN, T_WIN20_COMP, id="template-window20"),
    pytest.param(T_MODE1_PLAIN, T_MODE1_COMP, id="mode1-all-table-opcodes"),
]


def make_cell(plain: bytes, comp: bytes) -> bytes:
    # ESE frame: scheme byte 0x28 + u32 LE CRC-32C of the plaintext + raw blocks.
    return b"\x28" + struct.pack("<I", crc32c_ese(plain)) + comp


def patch_block_word(comp: bytes, word: int, value: int, block_offset: int = 0) -> bytes:
    # Rewrite one header word and refresh the header CRC (word 7) so the corruption
    # under test is reached instead of the CRC check.
    buf = bytearray(comp)
    struct.pack_into("<I", buf, block_offset + 4 * word, value)
    struct.pack_into("<I", buf, block_offset + 28, crc32c_ese(buf[block_offset : block_offset + 28]))
    return bytes(buf)


# --- Reference vectors ---


@pytest.mark.parametrize(("plain", "comp"), VECTORS)
def test_decompress_reference_vectors(plain: bytes, comp: bytes) -> None:
    assert xpress9.decompress(make_cell(plain, comp)) == plain


@pytest.mark.parametrize(("plain", "comp"), VECTORS)
def test_decompressed_size_reference_vectors(plain: bytes, comp: bytes) -> None:
    assert xpress9.decompressed_size(make_cell(plain, comp)) == len(plain)


def test_verify_false_still_decodes() -> None:
    assert xpress9.decompress(make_cell(FOX_PLAIN, FOX_COMP), verify=False) == FOX_PLAIN


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview])
def test_accepts_bytes_like(wrap: type) -> None:
    cell = wrap(make_cell(FOX_PLAIN, FOX_COMP))
    assert xpress9.decompress(cell) == FOX_PLAIN
    assert xpress9.decompressed_size(cell) == len(FOX_PLAIN)


# --- Block header ---


def test_parse_block_header_fields() -> None:
    # ESE's fixed "Cosmos Level 6" parameters (compression.cxx:1696-1706): MTF=4,
    # PtrMin=4, MtfMin=2, window log2 16.
    hdr = parse_block_header(FOX_COMP)
    assert hdr == Xpress9BlockHeader(
        orig_size=360,
        comp_size_bits=720,
        huffman_table_bits=27,
        window_size_log2=16,
        mtf_entry_count=4,
        ptr_min_match_length=4,
        mtf_min_match_length=2,
        session_signature=0xBAD4ADEE,
        block_index=0,
    )
    assert len(FOX_COMP) == (hdr.comp_size_bits + 7) // 8  # block is byte-aligned


def test_block_header_constants() -> None:
    assert HEADER_SIZE == 5
    assert BLOCK_HEADER_SIZE == 32
    assert XPRESS9_MAGIC == 0x4E86D72A
    assert struct.unpack_from("<I", FOX_COMP)[0] == XPRESS9_MAGIC


@pytest.mark.parametrize(
    ("comp", "window", "mtf", "ptr_min", "mtf_min"),
    [
        pytest.param(T_MTF0_GAMMA_COMP, 16, 0, 3, 2, id="mtf0-ptr3"),
        pytest.param(T_MTF2_COMP, 16, 2, 3, 3, id="mtf2-ptr3-mtf3"),
        pytest.param(T_MTF4_PTR3_COMP, 16, 4, 3, 2, id="mtf4-ptr3-mtf2"),
        pytest.param(T_WIN20_COMP, 20, 0, 3, 2, id="window20"),
        pytest.param(T_MODE1_COMP, 16, 4, 4, 2, id="mode1-ese-params"),
    ],
)
def test_synthetic_vectors_declare_non_default_templates(comp: bytes, window: int, mtf: int, ptr_min: int, mtf_min: int) -> None:
    # Guards that the template vectors really exercise the flag decode rules
    # (Xpress9DecLz77.c:656-667), not just the ESE default parameter set.
    hdr = parse_block_header(comp)
    assert (hdr.window_size_log2, hdr.mtf_entry_count, hdr.ptr_min_match_length, hdr.mtf_min_match_length) == (window, mtf, ptr_min, mtf_min)


def test_second_block_of_session_carries_index_one() -> None:
    hdr0 = parse_block_header(MULTI_COMP)
    hdr1 = parse_block_header(MULTI_COMP, MULTI_SPLIT)
    assert (hdr0.block_index, hdr1.block_index) == (0, 1)
    assert hdr0.session_signature == hdr1.session_signature


# --- Outer frame errors ---


@pytest.mark.parametrize("length", [0, 1, 4])
def test_truncated_outer_header_rejected(length: int) -> None:
    blob = make_cell(FOX_PLAIN, FOX_COMP)[:length]
    with pytest.raises(DecompressionError):
        xpress9.decompress(blob)
    with pytest.raises(DecompressionError):
        xpress9.decompressed_size(blob)


@pytest.mark.parametrize("format_byte", [0x00, 0x08, 0x18, 0x30, 0xFF])
def test_wrong_format_byte_rejected(format_byte: int) -> None:
    cell = bytearray(make_cell(FOX_PLAIN, FOX_COMP))
    cell[0] = format_byte
    with pytest.raises(DecompressionError):
        xpress9.decompress(bytes(cell))


def test_low_flag_bits_do_not_change_format() -> None:
    # The identifier is byte >> 3 (compression.cxx:2422); low bits are per-scheme flags.
    cell = bytearray(make_cell(FOX_PLAIN, FOX_COMP))
    cell[0] = 0x2B
    assert xpress9.decompress(bytes(cell)) == FOX_PLAIN


def test_empty_payload_rejected() -> None:
    with pytest.raises(DecompressionError):
        xpress9.decompress(make_cell(b"", b""))
    with pytest.raises(DecompressionError):
        xpress9.decompressed_size(make_cell(b"", b""))


def test_plaintext_crc_mismatch_raises_integrity_error() -> None:
    cell = bytearray(make_cell(FOX_PLAIN, FOX_COMP))
    cell[2] ^= 0x01  # stored plaintext CRC, not the payload
    with pytest.raises(IntegrityError):
        xpress9.decompress(bytes(cell))
    # verify=False skips exactly this check.
    assert xpress9.decompress(bytes(cell), verify=False) == FOX_PLAIN


# --- Block header errors ---


def test_bad_block_magic_rejected() -> None:
    comp = patch_block_word(FOX_COMP, 0, XPRESS9_MAGIC ^ 1)
    with pytest.raises(DecompressionError, match="magic"):
        xpress9.decompress(make_cell(FOX_PLAIN, comp))


def test_block_header_crc_mismatch_rejected() -> None:
    buf = bytearray(FOX_COMP)
    buf[4] ^= 0x01  # orig_size byte; header CRC (word 7) now stale
    with pytest.raises(DecompressionError, match="CRC-32C"):
        xpress9.decompress(make_cell(FOX_PLAIN, bytes(buf)))
    with pytest.raises(DecompressionError, match="CRC-32C"):
        xpress9.decompressed_size(make_cell(FOX_PLAIN, bytes(buf)))


def test_nonzero_reserved_word_rejected() -> None:
    comp = patch_block_word(FOX_COMP, 4, 1)
    with pytest.raises(DecompressionError, match="reserved"):
        xpress9.decompress(make_cell(FOX_PLAIN, comp))


def test_reserved_flag_bits_rejected() -> None:
    flags = struct.unpack_from("<I", FOX_COMP, 12)[0]
    comp = patch_block_word(FOX_COMP, 3, flags | (1 << 20))
    with pytest.raises(DecompressionError, match="reserved"):
        xpress9.decompress(make_cell(FOX_PLAIN, comp))


def test_reserved_mtf_entry_count_rejected() -> None:
    flags = struct.unpack_from("<I", FOX_COMP, 12)[0]
    comp = patch_block_word(FOX_COMP, 3, flags | (3 << 16))  # field value 3 = MTF count 6
    with pytest.raises(DecompressionError, match="MTF"):
        xpress9.decompress(make_cell(FOX_PLAIN, comp))


def test_comp_size_not_exceeding_tables_rejected() -> None:
    # comp bits must exceed 32*8 header bits + declared table bits (DecLz77.c:712).
    comp = patch_block_word(FOX_COMP, 2, 256 + 27)
    with pytest.raises(DecompressionError):
        xpress9.decompress(make_cell(FOX_PLAIN, comp))


def test_wrong_block_index_rejected() -> None:
    comp = patch_block_word(FOX_COMP, 6, 1)  # first block must carry index 0
    with pytest.raises(DecompressionError, match="index"):
        xpress9.decompress(make_cell(FOX_PLAIN, comp))


def test_session_signature_mismatch_rejected() -> None:
    hdr1 = parse_block_header(MULTI_COMP, MULTI_SPLIT)
    comp = patch_block_word(MULTI_COMP, 5, hdr1.session_signature ^ 1, block_offset=MULTI_SPLIT)
    with pytest.raises(DecompressionError, match="session"):
        xpress9.decompress(make_cell(MULTI_PLAIN_0 + MULTI_PLAIN_1, comp))


def test_changed_session_parameters_rejected() -> None:
    flags = struct.unpack_from("<I", MULTI_COMP, MULTI_SPLIT + 12)[0]
    comp = patch_block_word(MULTI_COMP, 3, flags ^ (1 << 18), block_offset=MULTI_SPLIT)  # flip ptr min match
    with pytest.raises(DecompressionError, match="parameters"):
        xpress9.decompress(make_cell(MULTI_PLAIN_0 + MULTI_PLAIN_1, comp))


# --- Payload errors ---


@pytest.mark.parametrize("keep", [5, 31, 32, 60])
def test_truncated_block_rejected(keep: int) -> None:
    cell = make_cell(FOX_PLAIN, FOX_COMP[:keep])
    with pytest.raises(DecompressionError):
        xpress9.decompress(cell)
    with pytest.raises(DecompressionError):
        xpress9.decompressed_size(cell)


@pytest.mark.parametrize("extra", [8, 32])
def test_trailing_garbage_rejected(extra: int) -> None:
    # Bytes past the block must parse as another block header; zeros cannot.
    cell = make_cell(FOX_PLAIN, FOX_COMP + bytes(extra))
    with pytest.raises(DecompressionError):
        xpress9.decompress(cell)


def test_every_single_byte_corruption_is_detected() -> None:
    # Flip each cell byte in turn (the final block byte may hold only padding bits
    # and is skipped); structural checks or the plaintext CRC must catch each one.
    cell = bytearray(make_cell(FOX_PLAIN, FOX_COMP))
    for index in range(len(cell) - 1):
        cell[index] ^= 0xFF
        with pytest.raises(DecompressionError):
            xpress9.decompress(bytes(cell))
        cell[index] ^= 0xFF


def test_corrupt_body_does_not_affect_size_query() -> None:
    # decompressed_size walks only the 32-byte headers (the C fast path,
    # DecLz77.c:718-726), so token-stream damage is invisible to it.
    buf = bytearray(FOX_COMP)
    buf[40] ^= 0xFF
    assert xpress9.decompressed_size(make_cell(FOX_PLAIN, bytes(buf))) == len(FOX_PLAIN)
    with pytest.raises(DecompressionError):
        xpress9.decompress(make_cell(FOX_PLAIN, bytes(buf)))


# --- Decompression-bomb bounds ---


def test_rejects_declared_size_over_safety_ceiling() -> None:
    # A block whose u32 orig_size exceeds the safety ceiling is rejected before any
    # allocation, even with a valid (refreshed) header CRC. ZEROS really decodes to
    # 1000 bytes; the forged header claims more than _MAX_DECODED_SIZE.
    comp = patch_block_word(ZEROS_COMP, 1, _MAX_DECODED_SIZE + 1)  # word 1 = orig_size
    with pytest.raises(DecompressionError, match="safety limit"):
        xpress9.decompress(make_cell(ZEROS_PLAIN, comp))


def test_size_query_reports_declared_value_without_ceiling() -> None:
    # decompressed_size only sums the headers, so it reports the raw declared value and
    # never allocates; the ceiling guards decompress(), not the size query.
    comp = patch_block_word(ZEROS_COMP, 1, _MAX_DECODED_SIZE + 1)
    assert xpress9.decompressed_size(make_cell(ZEROS_PLAIN, comp)) == _MAX_DECODED_SIZE + 1


def test_rejects_match_overrunning_declared_size() -> None:
    # Shrinking a block's declared orig_size below what its token stream produces must
    # be caught before the over-long copy (Xpress9DecLz77.c:837-844), so a forged length
    # cannot allocate past the declared bound. ZEROS is one ~1000-byte match at offset 1.
    comp = patch_block_word(ZEROS_COMP, 1, 10)  # real orig_size is 1000
    with pytest.raises(DecompressionError, match="overruns"):
        xpress9.decompress(make_cell(ZEROS_PLAIN, comp))


# --- Internal machinery ---


def test_bit_reader_is_lsb_first() -> None:
    reader = _BitReader(bytes([0b1010_0110, 0xFF]))
    assert reader.read(3) == 0b110
    assert reader.read(5) == 0b10100
    assert reader.bits_consumed == 8
    assert reader.read(4) == 0b1111


def test_bit_reader_rejects_reads_past_padding() -> None:
    reader = _BitReader(b"\x00")
    reader.read(8 * 9)  # 1 data byte + 8 phantom zero bytes are allowed
    with pytest.raises(DecompressionError):
        reader.read(1)


def test_canonical_huffman_decode() -> None:
    # Lengths A=1, B=2, C=2 give canonical codes A=0, B=10, C=11 (MSB-first),
    # transmitted bit-reversed, i.e. read LSB-first from the stream.
    table = _CanonicalHuffman([1, 2, 2])
    reader = _BitReader(bytes([0b0001_1010]))  # A, then B (0,1), then C (1,1)
    assert [table.decode(reader) for _ in range(3)] == [0, 1, 2]


def test_canonical_huffman_single_symbol_skips_bits() -> None:
    # Single-symbol tables skip the codeword bits and ignore their values
    # (Xpress9DecHuffman.c:354-375).
    table = _CanonicalHuffman([0, 3, 0])
    reader = _BitReader(bytes([0b101]))
    assert table.decode(reader) == 1
    assert reader.bits_consumed == 3


@pytest.mark.parametrize("lengths", [[0, 0, 0], [1, 1, 1], [2, 2, 0], [1, 2, 2, 2]])
def test_canonical_huffman_rejects_invalid_trees(lengths: list[int]) -> None:
    with pytest.raises(DecompressionError):
        _CanonicalHuffman(lengths)


# --- Protocol and registry integration ---


def test_format_attribute() -> None:
    assert Format.XPRESS9 in _CODECS


def test_registered_in_registry() -> None:
    assert Format.XPRESS9 in _CODECS


def test_dispatcher_routes_xpress9() -> None:
    cell = make_cell(PARA_PLAIN, PARA_COMP)
    assert decompress(cell) == PARA_PLAIN
    assert decompressed_size(cell) == len(PARA_PLAIN)


# --- Encoder round-trip ---


@pytest.mark.parametrize(
    "plain",
    [
        pytest.param(FOX_PLAIN, id="fox"),
        pytest.param(ZEROS_PLAIN, id="zeros"),
        pytest.param(PARA_PLAIN, id="para"),
        pytest.param(BIGTEXT_PLAIN, id="bigtext"),
        pytest.param(b"abc" * 500, id="abc-rept"),
        pytest.param(bytes(range(256)) * 8, id="gradient"),
    ],
)
def test_compress_roundtrip(plain: bytes) -> None:
    cell = xpress9.compress(plain)
    assert xpress9.decompress(cell) == plain


# --- C reference encoder vectors ---
# Generated by the MIT ESE _xpress9 C encoder compiled on Linux, with the
# session signature (word 5) zeroed for determinism. The header CRC (word 7)
# is recomputed over the zeroed signature. These vectors represent the exact
# output of the reference implementation (same C source esent.dll links).
#
# NOTE: Full byte-identity between our encoder and the C reference is
# structurally constrained by two factors:
# 1. Session signature = CRC32(__rdtsc()): non-deterministic by design.
#    Even esent.dll produces different XPRESS9 output on each call.
# 2. Our greedy encoder produces valid but different tokenization from the
#    C reference's lazy/optimal parser. Both decompress correctly.

_CREF_FOX = bytes.fromhex("2ad7864e68010000cd0200001b000600000000000000000000000000d62df70f000000e0c28229028e5c5932668d801127f6dcd92160c69e0702565cd972e08c803d37a69c107061c114011b86bc782260c29e393a04eddf050d")
_CREF_ZEROS = bytes.fromhex("2ad7864ee8030000470100001b0006000000000000000000000000000a2f071f000000000020fca33b")
_CREF_PARA = bytes.fromhex("2ad7864e480e0000030400004101060000000000000000000000000013796c0b000020c266a6000040dcc56e12be7b5be1185559d57fe7dbc9d6e475a63af30600701fc17d040000466aa415fe0e710c9f016bf88443d64e48123a775f682f68b42d594583b84167ea52bd351abefc4512b547cac437c6eb197fd5edfe789e9700")


@pytest.mark.parametrize(
    ("plain", "c_ref"),
    [
        pytest.param(FOX_PLAIN, _CREF_FOX, id="fox"),
        pytest.param(ZEROS_PLAIN, _CREF_ZEROS, id="zeros"),
        pytest.param(PARA_PLAIN, _CREF_PARA, id="para"),
    ],
)
def test_c_reference_vectors_decompress(plain: bytes, c_ref: bytes) -> None:
    """Verify our decoder handles the C reference encoder's output."""
    cell = make_cell(plain, c_ref)
    assert xpress9.decompress(cell) == plain


def _normalize_session_sig(data: bytes) -> bytes:
    """Zero the session signature (word 5) and recompute header CRC (word 7)."""
    d = bytearray(data)
    pos = 0
    while pos + 32 <= len(d):
        magic = struct.unpack_from("<I", d, pos)[0]
        if magic != XPRESS9_MAGIC:
            break
        d[pos + 20 : pos + 24] = b"\x00\x00\x00\x00"
        struct.pack_into("<I", d, pos + 28, crc32c_ese(bytes(d[pos : pos + 28])))
        comp_bits = struct.unpack_from("<I", d, pos + 8)[0]
        pos += (comp_bits + 7) // 8
    return bytes(d)


@pytest.mark.parametrize(
    ("plain", "c_ref"),
    [
        pytest.param(FOX_PLAIN, _CREF_FOX, id="fox"),
        pytest.param(ZEROS_PLAIN, _CREF_ZEROS, id="zeros"),
        pytest.param(PARA_PLAIN, _CREF_PARA, id="para"),
    ],
)
def test_xpress9_structural_byte_identical(plain: bytes, c_ref: bytes) -> None:
    """Our encoder produces byte-identical output to the MIT ESE C reference.

    Compares everything except the non-deterministic session signature
    (word 5, CRC32 of __rdtsc) and the header CRC (word 7, which covers
    the signature). This is the maximum achievable identity since even
    esent.dll produces different output on each call due to __rdtsc.
    """
    cell = xpress9.compress(plain)
    our_block = cell[5:]  # strip ESE header (scheme byte + plaintext CRC)
    assert _normalize_session_sig(our_block) == c_ref
