"""Smoke tests for every public function in ntcompress.

One test per public function, exercising the happy path. These verify
that the API surface described in the plan actually exists and works.
"""

from __future__ import annotations

import pytest

# --- Test data ---

DATA = b"ABCDEFGHIJKLMNOP" * 10  # 160 bytes, compressible
SEVENBIT_DATA = b"Hello, World! This is a test of seven-bit ASCII packing."
UNICODE_DATA = "Hello World Test".encode("utf-16-le")


# ============================================================
# ntcompress (root)
# ============================================================


def test_root_version():
    import ntcompress

    assert isinstance(ntcompress.__version__, str)
    assert len(ntcompress.__version__) > 0


# ============================================================
# ntcompress.exceptions
# ============================================================


def test_exception_hierarchy():
    from ntcompress.exceptions import (
        CompressionError,
        CompressionLibError,
        DecompressionError,
        FormatUnavailableError,
        IncompressibleError,
        IntegrityError,
        ScrubDetectedError,
    )

    assert issubclass(CompressionError, CompressionLibError)
    assert issubclass(DecompressionError, CompressionLibError)
    assert issubclass(IncompressibleError, CompressionError)
    assert issubclass(IntegrityError, DecompressionError)
    assert issubclass(ScrubDetectedError, DecompressionError)
    assert issubclass(FormatUnavailableError, CompressionLibError)


# ============================================================
# ntcompress.ese — Shape A dispatch
# ============================================================


class TestEseShapeA:
    def test_compress(self):
        import ntcompress.ese as ese

        cell = ese.compress(DATA, ese.Format.XPRESS)
        assert isinstance(cell, bytes)
        assert len(cell) < len(DATA)

    def test_decompress_auto_detect(self):
        import ntcompress.ese as ese

        cell = ese.compress(DATA, ese.Format.XPRESS)
        assert ese.decompress(cell) == DATA

    def test_decompress_explicit_format(self):
        import ntcompress.ese as ese

        cell = ese.compress(DATA, ese.Format.LZ4)
        assert ese.decompress(cell, fmt=ese.Format.LZ4) == DATA

    def test_decompressed_size(self):
        import ntcompress.ese as ese

        cell = ese.compress(DATA, ese.Format.LZ4)
        assert ese.decompressed_size(cell) == len(DATA)

    def test_format_id(self):
        import ntcompress.ese as ese

        assert ese.format_id(0x18) == ese.Format.XPRESS

    def test_format_flags(self):
        import ntcompress.ese as ese

        assert ese.format_flags(0x1F) == 0x7

    def test_header_byte(self):
        import ntcompress.ese as ese

        assert ese.header_byte(ese.Format.XPRESS) == 0x18

    def test_format_enum_values(self):
        import ntcompress.ese as ese

        assert ese.Format.NONE == 0x00
        assert ese.Format.SEVEN_BIT_ASCII == 0x01
        assert ese.Format.SEVEN_BIT_UNICODE == 0x02
        assert ese.Format.XPRESS == 0x03
        assert ese.Format.SCRUB == 0x04
        assert ese.Format.XPRESS9 == 0x05
        assert ese.Format.XPRESS10 == 0x06
        assert ese.Format.LZ4 == 0x07
        assert ese.Format.MAXIMUM == 0x1F


# ============================================================
# ntcompress.ese — sentinel errors
# ============================================================


class TestEseSentinelErrors:
    def test_compress_none_raises(self):
        import ntcompress.ese as ese
        from ntcompress.exceptions import CompressionError

        with pytest.raises(CompressionError, match="Format.NONE"):
            ese.compress(DATA, ese.Format.NONE)

    def test_compress_scrub_raises(self):
        import ntcompress.ese as ese
        from ntcompress.exceptions import CompressionError

        with pytest.raises(CompressionError, match="ntcompress.ese.scrub"):
            ese.compress(DATA, ese.Format.SCRUB)

    def test_compress_maximum_raises(self):
        import ntcompress.ese as ese
        from ntcompress.exceptions import CompressionError

        with pytest.raises(CompressionError, match="Format.MAXIMUM"):
            ese.compress(DATA, ese.Format.MAXIMUM)

    def test_decompress_scrub_raises(self):
        import ntcompress.ese as ese
        from ntcompress.exceptions import ScrubDetectedError

        cell = bytes([ese.header_byte(ese.Format.SCRUB)]) + b"\x4c" * 10
        with pytest.raises(ScrubDetectedError, match="ntcompress.ese.scrub"):
            ese.decompress(cell)


# ============================================================
# ntcompress.ese — Shape B modules
# ============================================================


class TestEseSevenbitAscii:
    def test_compress(self):
        from ntcompress.ese import sevenbit_ascii

        cell = sevenbit_ascii.compress(SEVENBIT_DATA)
        assert isinstance(cell, bytes)

    def test_decompress(self):
        from ntcompress.ese import sevenbit_ascii

        cell = sevenbit_ascii.compress(SEVENBIT_DATA)
        assert sevenbit_ascii.decompress(cell) == SEVENBIT_DATA

    def test_decompressed_size(self):
        from ntcompress.ese import sevenbit_ascii

        cell = sevenbit_ascii.compress(SEVENBIT_DATA)
        assert sevenbit_ascii.decompressed_size(cell) == len(SEVENBIT_DATA)


class TestEseSevenbitUnicode:
    def test_compress(self):
        from ntcompress.ese import sevenbit_unicode

        cell = sevenbit_unicode.compress(UNICODE_DATA)
        assert isinstance(cell, bytes)

    def test_decompress(self):
        from ntcompress.ese import sevenbit_unicode

        cell = sevenbit_unicode.compress(UNICODE_DATA)
        assert sevenbit_unicode.decompress(cell) == UNICODE_DATA

    def test_decompressed_size(self):
        from ntcompress.ese import sevenbit_unicode

        cell = sevenbit_unicode.compress(UNICODE_DATA)
        assert sevenbit_unicode.decompressed_size(cell) == len(UNICODE_DATA)


class TestEseXpress:
    def test_compress(self):
        from ntcompress.ese import xpress

        cell = xpress.compress(DATA)
        assert isinstance(cell, bytes)

    def test_decompress(self):
        from ntcompress.ese import xpress

        cell = xpress.compress(DATA)
        assert xpress.decompress(cell) == DATA

    def test_decompress_verify_false(self):
        from ntcompress.ese import xpress

        cell = xpress.compress(DATA)
        assert xpress.decompress(cell, verify=False) == DATA

    def test_decompressed_size(self):
        from ntcompress.ese import xpress

        cell = xpress.compress(DATA)
        assert xpress.decompressed_size(cell) == len(DATA)


class TestEseXpress9:
    def test_compress(self):
        from ntcompress.ese import xpress9

        cell = xpress9.compress(DATA)
        assert isinstance(cell, bytes)

    def test_decompress(self):
        from ntcompress.ese import xpress9

        cell = xpress9.compress(DATA)
        assert xpress9.decompress(cell) == DATA

    def test_decompress_verify_false(self):
        from ntcompress.ese import xpress9

        cell = xpress9.compress(DATA)
        assert xpress9.decompress(cell, verify=False) == DATA

    def test_decompressed_size(self):
        from ntcompress.ese import xpress9

        cell = xpress9.compress(DATA)
        assert xpress9.decompressed_size(cell) == len(DATA)

    def test_parse_block_header(self):
        from ntcompress.ese import xpress9

        cell = xpress9.compress(DATA)
        payload = cell[5:]
        header = xpress9.parse_block_header(payload)
        assert header.orig_size == len(DATA)
        assert isinstance(header, xpress9.Xpress9BlockHeader)


class TestEseXpress10:
    def test_compress(self):
        from ntcompress.ese import xpress10

        cell = xpress10.compress(DATA)
        assert isinstance(cell, bytes)

    def test_decompress(self):
        from ntcompress.ese import xpress10

        cell = xpress10.compress(DATA)
        assert xpress10.decompress(cell) == DATA

    def test_decompress_verify_false(self):
        from ntcompress.ese import xpress10

        cell = xpress10.compress(DATA)
        assert xpress10.decompress(cell, verify=False) == DATA

    def test_decompressed_size(self):
        from ntcompress.ese import xpress10

        cell = xpress10.compress(DATA)
        assert xpress10.decompressed_size(cell) == len(DATA)

    def test_parse_header(self):
        from ntcompress.ese import xpress10

        cell = xpress10.compress(DATA)
        header = xpress10.parse_header(cell)
        assert header.uncompressed_size == len(DATA)
        assert isinstance(header, xpress10.Xpress10Header)


class TestEseLz4:
    def test_compress(self):
        from ntcompress.ese import lz4

        cell = lz4.compress(DATA)
        assert isinstance(cell, bytes)

    def test_decompress(self):
        from ntcompress.ese import lz4

        cell = lz4.compress(DATA)
        assert lz4.decompress(cell) == DATA

    def test_decompress_verify_false(self):
        from ntcompress.ese import lz4

        cell = lz4.compress(DATA)
        assert lz4.decompress(cell, verify=False) == DATA

    def test_decompressed_size(self):
        from ntcompress.ese import lz4

        cell = lz4.compress(DATA)
        assert lz4.decompressed_size(cell) == len(DATA)

    def test_parse_header(self):
        from ntcompress.ese import lz4

        cell = lz4.compress(DATA)
        header = lz4.parse_header(cell)
        assert header.uncompressed_size == len(DATA)
        assert isinstance(header, lz4.Lz4Header)

    def test_compress_block(self):
        from ntcompress.ese import lz4

        block = lz4.compress_block(DATA)
        assert isinstance(block, bytes)

    def test_decompress_block(self):
        from ntcompress.ese import lz4

        block = lz4.compress_block(DATA)
        assert lz4.decompress_block(block, len(DATA)) == DATA


class TestEseScrub:
    def test_is_scrub(self):
        from ntcompress.ese import scrub

        cell = scrub.make_scrub(10)
        assert scrub.is_scrub(cell) is True
        assert scrub.is_scrub(b"\x00") is False

    def test_scrub_fill_byte(self):
        from ntcompress.ese import scrub

        cell = scrub.make_scrub(10, fill=0x4C)
        assert scrub.scrub_fill_byte(cell) == 0x4C

    def test_parse_scrub(self):
        from ntcompress.ese import scrub

        cell = scrub.make_scrub(10, fill=scrub.ScrubFill.LEGACY_LV_CHUNK)
        record = scrub.parse_scrub(cell)
        assert isinstance(record, scrub.ScrubRecord)
        assert record.erased_length == 10
        assert record.fill_byte == 0x6C
        assert record.known_fill is True

    def test_make_scrub(self):
        from ntcompress.ese import scrub

        cell = scrub.make_scrub(5)
        assert len(cell) == 5
        assert isinstance(cell, bytes)

    def test_scrub_fill_enum(self):
        from ntcompress.ese.scrub import ScrubFill

        assert ScrubFill.LEGACY_LV_CHUNK == 0x6C
        assert ScrubFill.DB_MAINT_LV_CHUNK == 0x4C


class TestEseChecksums:
    def test_crc32c_ese(self):
        from ntcompress.ese.checksums import crc32c_ese

        assert crc32c_ese(b"123456789") == 0xE3069283

    def test_crc64_ese(self):
        from ntcompress.ese.checksums import crc64_ese

        assert crc64_ese(b"123456789") == 0xAE8B14860A799888


# ============================================================
# ntcompress.ntdll — Shape A dispatch
# ============================================================


class TestNtdllShapeA:
    def test_compress(self):
        import ntcompress.ntdll as ntdll

        compressed = ntdll.compress(DATA, ntdll.Format.LZNT1)
        assert isinstance(compressed, bytes)

    def test_decompress(self):
        import ntcompress.ntdll as ntdll

        compressed = ntdll.compress(DATA, ntdll.Format.LZNT1)
        assert ntdll.decompress(compressed, ntdll.Format.LZNT1) == DATA

    def test_format_enum_values(self):
        import ntcompress.ntdll as ntdll

        assert ntdll.Format.LZNT1 == 0x0002
        assert ntdll.Format.XPRESS == 0x0003
        assert ntdll.Format.XPRESS_HUFF == 0x0004
        assert ntdll.Format.XPRESS9 == 0x0005
        assert ntdll.Format.XP10 == 0x0006
        assert ntdll.Format.DEFLATE == 0x0007
        assert ntdll.Format.ZLIB == 0x0008

    def test_compression_format_aliases(self):
        import ntcompress.ntdll as ntdll

        assert ntdll.COMPRESSION_FORMAT_LZNT1 == ntdll.Format.LZNT1
        assert ntdll.COMPRESSION_FORMAT_XPRESS == ntdll.Format.XPRESS
        assert ntdll.COMPRESSION_FORMAT_XPRESS_HUFF == ntdll.Format.XPRESS_HUFF

    def test_alias_dispatch(self):
        import ntcompress.ntdll as ntdll

        compressed = ntdll.compress(DATA, ntdll.COMPRESSION_FORMAT_XPRESS)
        assert ntdll.decompress(compressed, ntdll.COMPRESSION_FORMAT_XPRESS) == DATA


# ============================================================
# ntcompress.ntdll — Shape B modules
# ============================================================


class TestNtdllLznt1:
    def test_compress(self):
        from ntcompress.ntdll import lznt1

        compressed = lznt1.compress(DATA)
        assert isinstance(compressed, bytes)

    def test_decompress(self):
        from ntcompress.ntdll import lznt1

        compressed = lznt1.compress(DATA)
        assert lznt1.decompress(compressed) == DATA


class TestNtdllXpress:
    def test_compress(self):
        from ntcompress.ntdll import xpress

        compressed = xpress.compress(DATA)
        assert isinstance(compressed, bytes)

    def test_decompress(self):
        from ntcompress.ntdll import xpress

        compressed = xpress.compress(DATA)
        assert xpress.decompress(compressed) == DATA

    def test_decompress_max_size(self):
        from ntcompress.ntdll import xpress

        compressed = xpress.compress(DATA)
        assert xpress.decompress(compressed, max_size=len(DATA)) == DATA


class TestNtdllXpressHuff:
    def test_compress(self):
        from ntcompress.ntdll import xpress_huff

        compressed = xpress_huff.compress(DATA)
        assert isinstance(compressed, bytes)

    def test_decompress(self):
        from ntcompress.ntdll import xpress_huff

        compressed = xpress_huff.compress(DATA)
        assert xpress_huff.decompress(compressed) == DATA

    def test_decompress_max_size(self):
        from ntcompress.ntdll import xpress_huff

        compressed = xpress_huff.compress(DATA)
        assert xpress_huff.decompress(compressed, max_size=len(DATA)) == DATA


class TestNtdllDeflate:
    def test_compress(self):
        from ntcompress.ntdll import deflate

        compressed = deflate.compress(DATA)
        assert isinstance(compressed, bytes)

    def test_compress_level(self):
        from ntcompress.ntdll import deflate

        compressed = deflate.compress(DATA, level=9)
        assert deflate.decompress(compressed) == DATA

    def test_decompress(self):
        from ntcompress.ntdll import deflate

        compressed = deflate.compress(DATA)
        assert deflate.decompress(compressed) == DATA

    def test_decompress_max_size(self):
        from ntcompress.ntdll import deflate

        compressed = deflate.compress(DATA)
        assert deflate.decompress(compressed, max_size=len(DATA)) == DATA


class TestNtdllZlib:
    def test_compress(self):
        from ntcompress.ntdll import zlib

        compressed = zlib.compress(DATA)
        assert isinstance(compressed, bytes)

    def test_compress_level(self):
        from ntcompress.ntdll import zlib

        compressed = zlib.compress(DATA, level=9)
        assert zlib.decompress(compressed) == DATA

    def test_decompress(self):
        from ntcompress.ntdll import zlib

        compressed = zlib.compress(DATA)
        assert zlib.decompress(compressed) == DATA


# ============================================================
# Cross-subpackage: ESE xpress delegates to ntdll xpress
# ============================================================


class TestCrossImport:
    def test_ese_xpress_uses_ntdll_xpress(self):
        from ntcompress.ese import xpress as ese_xpress
        from ntcompress.ntdll import xpress as ntdll_xpress

        raw = ntdll_xpress.compress(DATA)
        cell = ese_xpress.compress(DATA)
        assert raw == cell[3:]


# ============================================================
# All ESE formats roundtrip via Shape A
# ============================================================


@pytest.mark.parametrize(
    "fmt_name",
    ["SEVEN_BIT_ASCII", "XPRESS", "XPRESS9", "XPRESS10", "LZ4"],
)
def test_ese_shape_a_roundtrip(fmt_name):
    import ntcompress.ese as ese

    fmt = ese.Format[fmt_name]
    data = SEVENBIT_DATA if "SEVEN_BIT" in fmt_name else DATA
    cell = ese.compress(data, fmt)
    assert ese.decompress(cell) == data


@pytest.mark.parametrize("fmt_name", ["SEVEN_BIT_UNICODE"])
def test_ese_shape_a_roundtrip_unicode(fmt_name):
    import ntcompress.ese as ese

    fmt = ese.Format[fmt_name]
    cell = ese.compress(UNICODE_DATA, fmt)
    assert ese.decompress(cell) == UNICODE_DATA


# ============================================================
# All ntdll formats roundtrip via Shape A
# ============================================================


@pytest.mark.parametrize(
    "fmt_name",
    ["LZNT1", "XPRESS", "XPRESS_HUFF", "DEFLATE", "ZLIB"],
)
def test_ntdll_shape_a_roundtrip(fmt_name):
    import ntcompress.ntdll as ntdll

    fmt = ntdll.Format[fmt_name]
    compressed = ntdll.compress(DATA, fmt)
    assert ntdll.decompress(compressed, fmt) == DATA
