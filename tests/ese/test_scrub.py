"""Tests for the SCRUB (0x4) erase-marker helpers."""

from __future__ import annotations

import pytest

from ntcompress import ese
from ntcompress.exceptions import CompressionError, DecompressionError, ScrubDetectedError
from ntcompress.ese import Format, header_byte
from ntcompress.ese.scrub import (
    ScrubFill,
    ScrubRecord,
    is_scrub,
    make_scrub,
    parse_scrub,
    scrub_fill_byte,
)


def test_format_constant():
    assert header_byte(Format.SCRUB) == 0x20


def test_fill_constants_match_daedef():
    # daedef.hxx:1064 and :1069
    assert ScrubFill.LEGACY_LV_CHUNK == 0x6C == ord("l")
    assert ScrubFill.DB_MAINT_LV_CHUNK == 0x4C == ord("L")


def test_make_scrub_layout():
    cell = make_scrub(8)
    assert cell == b"\x20" + b"L" * 7
    assert cell[0] == 0x20
    assert len(cell) == 8


def test_make_scrub_legacy_fill():
    cell = make_scrub(5, fill=ScrubFill.LEGACY_LV_CHUNK)
    assert cell == b"\x20llll"


def test_make_scrub_one_byte_cell():
    # compression.cxx:3556-3561 -- a 1-byte chunk is legal: header only, no fill.
    cell = make_scrub(1)
    assert cell == b"\x20"
    assert is_scrub(cell)
    assert scrub_fill_byte(cell) is None


def test_make_scrub_rejects_bad_args():
    with pytest.raises(CompressionError):
        make_scrub(0)
    with pytest.raises(CompressionError):
        make_scrub(-3)
    with pytest.raises(CompressionError):
        make_scrub(4, fill=0x100)
    with pytest.raises(CompressionError):
        make_scrub(4, fill=-1)


@pytest.mark.parametrize("fill", [ScrubFill.LEGACY_LV_CHUNK, ScrubFill.DB_MAINT_LV_CHUNK])
@pytest.mark.parametrize("length", [1, 2, 3, 17, 4096])
def test_make_scrub_round_trips(length, fill):
    cell = make_scrub(length, fill=int(fill))
    assert is_scrub(cell)
    expected_fill = None if length == 1 else int(fill)
    assert scrub_fill_byte(cell) == expected_fill


def test_is_scrub_edge_cases():
    assert not is_scrub(b"")
    assert not is_scrub(b"\x18\x00\x00")  # XPRESS (0x3 << 3), not SCRUB
    assert not is_scrub(b"\x08abc")  # 7-bit ASCII
    assert is_scrub(bytearray(b"\x20LL"))
    assert is_scrub(memoryview(b"\x20"))
    # Any of the low 3 flag bits set still resolves format id 0x4.
    assert is_scrub(b"\x27LL")


def test_scrub_fill_byte_non_uniform():
    assert scrub_fill_byte(b"\x20LLl") is None
    assert scrub_fill_byte(b"\x20") is None
    assert scrub_fill_byte(b"") is None
    assert scrub_fill_byte(b"\x20\x00\x00") == 0x00


def test_parse_scrub_known_fills():
    rec = parse_scrub(make_scrub(10, fill=ScrubFill.LEGACY_LV_CHUNK))
    assert rec == ScrubRecord(erased_length=10, fill_byte=0x6C, known_fill=True)
    rec = parse_scrub(make_scrub(10, fill=ScrubFill.DB_MAINT_LV_CHUNK))
    assert rec == ScrubRecord(erased_length=10, fill_byte=0x4C, known_fill=True)


def test_parse_scrub_unknown_fill_and_one_byte():
    rec = parse_scrub(make_scrub(6, fill=0xAA))
    assert rec.fill_byte == 0xAA
    assert not rec.known_fill
    rec = parse_scrub(b"\x20")
    assert rec.erased_length == 1
    assert rec.fill_byte is None
    assert not rec.known_fill


def test_parse_scrub_non_uniform_fill():
    # A tampered cell whose fill region is not one repeated byte: recognized as
    # SCRUB (format id only), but no single fill byte can be reported.
    rec = parse_scrub(b"\x20LLl")
    assert rec == ScrubRecord(erased_length=4, fill_byte=None, known_fill=False)


def test_scrub_unit_test_vector():
    # JETUNITTEST(CDataCompressor, Scrub), compression.cxx:3523-3574: scrub a
    # 2048-byte chunk with chSCRUBDBMaintLVChunkFill in place; byte 0 becomes
    # the signature and bytes 1..2047 the fill; decompress must only signal.
    cell = make_scrub(2048, fill=ScrubFill.DB_MAINT_LV_CHUNK)
    assert len(cell) == 2048
    assert cell[0] == 0x20
    assert cell[1:] == b"L" * 2047
    with pytest.raises(ScrubDetectedError):
        ese.decompress(cell)


def test_parse_scrub_rejects_non_scrub():
    with pytest.raises(DecompressionError):
        parse_scrub(b"")
    with pytest.raises(DecompressionError):
        parse_scrub(b"\x18\x01\x02")


def test_dispatcher_raises_scrub_detected():
    cell = make_scrub(32)
    with pytest.raises(ScrubDetectedError):
        ese.decompress(cell)
    with pytest.raises(ScrubDetectedError):
        ese.decompressed_size(cell)
    # A 1-byte cell (header only) must dispatch the same way (compression.cxx:3556-3574).
    with pytest.raises(ScrubDetectedError):
        ese.decompress(make_scrub(1))


def test_scrub_never_registered():
    from ntcompress.ese._registry import _CODECS

    assert Format.SCRUB not in _CODECS
