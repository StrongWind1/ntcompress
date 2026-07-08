"""Tests for the format dispatch and the ESE/ntdll registration boundary."""

from __future__ import annotations

import struct

import pytest

from ntcompress.ese import Format, decompress, decompressed_size, header_byte
from ntcompress.ese._registry import _CODECS
from ntcompress.exceptions import (
    DecompressionError,
    ScrubDetectedError,
)


def test_empty_buffer_rejected() -> None:
    with pytest.raises(DecompressionError):
        decompress(b"")


def test_unknown_format_id_rejected() -> None:
    # 0xF0 >> 3 == 0x1E, which is unassigned.
    with pytest.raises(DecompressionError):
        decompress(bytes([0xF0]))


def test_none_format_has_no_frame() -> None:
    with pytest.raises(DecompressionError):
        decompress(bytes([header_byte(Format.NONE)]))


def test_scrub_is_flagged() -> None:
    with pytest.raises(ScrubDetectedError):
        decompress(bytes([header_byte(Format.SCRUB)]))
    with pytest.raises(ScrubDetectedError):
        decompressed_size(bytes([header_byte(Format.SCRUB)]))


def test_xpress10_full_roundtrip_via_registry() -> None:
    from ntcompress.ese.checksums import crc32c_ese, crc64_ese
    from ntcompress.ese.lz4 import compress_block

    plain = b"roundtrip " * 50
    payload = compress_block(plain)
    cell = struct.pack("<BHIQ", header_byte(Format.XPRESS10), len(plain), crc32c_ese(plain), crc64_ese(payload)) + payload
    assert decompress(cell) == plain


def test_registry_holds_only_ese_format_ids() -> None:
    # The dispatch boundary: only ESE record-format ids (0x0-0x7) may ever register.
    assert all(0x0 <= fmt <= 0x7 for fmt in _CODECS)


def test_ntdll_codecs_are_never_registered() -> None:
    # ntdll standalone codecs (Xpress Huffman, LZNT1) must not enter the ESE registry.
    registered_modules = {type(codec).__name__ for codec in _CODECS.values()}
    assert not any("ntdll" in mod for mod in registered_modules)
