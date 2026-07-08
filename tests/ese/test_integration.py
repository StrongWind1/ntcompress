"""End-to-end tests for the public API and codec registration wiring.

Confirms that importing the package alone registers every built-in ESE codec, that the
top-level dispatcher round-trips real cells, and that SCRUB surfaces its documented error.
"""

from __future__ import annotations

import struct

import pytest

from ntcompress.ese import Format, compress, decompress, decompressed_size, header_byte
from ntcompress.ese import lz4, scrub, sevenbit_ascii, xpress
from ntcompress.ese._registry import _CODECS
from ntcompress.ese.checksums import crc32c_ese, crc64_ese
from ntcompress.ese.lz4 import compress_block
from ntcompress.exceptions import CompressionError, ScrubDetectedError


def test_import_registers_every_builtin_codec() -> None:
    # Importing the package (done at module load) must populate the registry with the
    # six decodable ESE record schemes, with no explicit per-format import needed.
    assert set(_CODECS) == {
        Format.SEVEN_BIT_ASCII,
        Format.SEVEN_BIT_UNICODE,
        Format.XPRESS,
        Format.XPRESS9,
        Format.XPRESS10,
        Format.LZ4,
    }


def test_dispatch_roundtrip_sevenbit_ascii() -> None:
    cell = sevenbit_ascii.compress(b"HELLO WORLD 1234")
    assert decompress(cell) == b"HELLO WORLD 1234"
    assert decompressed_size(cell) == len(b"HELLO WORLD 1234")


def test_dispatch_roundtrip_xpress() -> None:
    data = b"abc" * 100
    cell = xpress.compress(data)
    assert cell[0] == header_byte(Format.XPRESS)  # 0x18
    assert decompress(cell) == data
    assert decompressed_size(cell) == len(data)


def test_dispatch_roundtrip_lz4() -> None:
    data = b"the quick brown fox " * 30
    cell = lz4.compress(data)
    assert cell[0] == header_byte(Format.LZ4)  # 0x38
    assert decompress(cell) == data
    assert decompressed_size(cell) == len(data)


def test_dispatch_scrub_is_flagged() -> None:
    cell = scrub.make_scrub(64)
    with pytest.raises(ScrubDetectedError):
        decompress(cell)


def test_dispatch_xpress10_size_and_decompress() -> None:
    plain = b"test" * 100
    payload = compress_block(plain)
    cell = struct.pack("<BHIQ", header_byte(Format.XPRESS10), len(plain), crc32c_ese(plain), crc64_ese(payload)) + payload
    assert decompressed_size(cell) == len(plain)
    assert decompress(cell) == plain


# --- Top-level compress() dispatcher ---


def test_compress_sevenbit_ascii() -> None:
    data = b"HELLO WORLD 1234"
    cell = compress(data, Format.SEVEN_BIT_ASCII)
    assert decompress(cell) == data
    assert decompressed_size(cell) == len(data)


def test_compress_sevenbit_unicode() -> None:
    data = "Hello World!".encode("utf-16-le")
    cell = compress(data, Format.SEVEN_BIT_UNICODE)
    assert decompress(cell) == data


def test_compress_xpress() -> None:
    data = b"abc" * 100
    cell = compress(data, Format.XPRESS)
    assert cell[0] == header_byte(Format.XPRESS)
    assert decompress(cell) == data


def test_compress_lz4() -> None:
    data = b"the quick brown fox " * 30
    cell = compress(data, Format.LZ4)
    assert cell[0] == header_byte(Format.LZ4)
    assert decompress(cell) == data


def test_compress_none_rejected() -> None:
    with pytest.raises(CompressionError):
        compress(b"data", Format.NONE)


def test_compress_scrub_rejected() -> None:
    with pytest.raises(CompressionError):
        compress(b"data", Format.SCRUB)


def test_compress_xpress9_roundtrip() -> None:
    data = b"data" * 100
    cell = compress(data, Format.XPRESS9)
    assert decompress(cell) == data


def test_compress_xpress10() -> None:
    data = b"data" * 100
    cell = compress(data, Format.XPRESS10)
    assert decompress(cell) == data


def test_ntdll_siblings_not_registered() -> None:
    module_names = {codec.__name__ for codec in _CODECS.values()}
    assert not any(".ntdll" in name for name in module_names)


# --- Real esent.dll cells through the top-level dispatcher ---
# Captured from Windows Server 2022 Build 20348, EFV 8920, page size 8192.


@pytest.mark.parametrize(
    ("cell_hex", "plain"),
    [
        ("0fb151efea0649d967a24b44526f55", bytes.fromhex("31233d576e20526c67442e22246a5b2a")),
        ("0fc16030180c0683c16030180c0683", b"\x41" * 16),
        ("0f8080604028180e888462c168381e", bytes(range(16))),
        ("1300000000", b"\x00" * 8),
        ("1700000000000000", b"\x00" * 16),
        ("180004ffffff3f000007000ffffb03", b"\x00" * 1024),
        ("180004ffffff3f414107000ffffb03", b"\x41" * 1024),
        ("180004ff7f0000c0c1c2c3c4c5c6c7c8c9cacbcccdcecfc07f000fffec03", bytes(0xC0 + (i % 16) for i in range(1024))),
        ("180004ffffff1faa55aa0f000ffffa03", bytes(0xAA if i % 2 == 0 else 0x55 for i in range(1024))),
    ],
    ids=["7bit_ascii_rand16", "7bit_ascii_41x16", "7bit_ascii_gradient16", "7bit_unicode_zeros8", "7bit_unicode_zeros16", "xpress_zeros1024", "xpress_41x1024", "xpress_highbit1024", "xpress_alt_aa55_1024"],
)
def test_dispatch_esent_real_cells(cell_hex, plain):
    cell = bytes.fromhex(cell_hex)
    assert decompress(cell) == plain
    assert decompressed_size(cell) == len(plain)
