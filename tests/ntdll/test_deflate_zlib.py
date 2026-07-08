"""Tests for the raw DEFLATE and ZLIB standalone codecs (ntdll 0x0007/0x0008)."""

from __future__ import annotations

import os
import sys

import pytest

from ntcompress.ntdll import deflate
from ntcompress.ntdll import zlib as ntdll_zlib

PLAIN = bytes(0x41 + (i % 26) for i in range(1, 4097))

# --- ntdll gold vectors from test_ntdll_gold.py ---

_DEFLATE_DEFAULT = bytes.fromhex("737276717573f7f0f4f2f6f1f5f30f080c0a0e090d0b8f888c72741a95190d83d174309a1746cb83d13271b45e18ad1b47db07a36da4d176e2685b79b4bf30da331aed190d939e1100")

_DEFLATE_MAX = bytes.fromhex("edc9c71180200000c1dac812140425d87f21f6c1dc7e572a6dac3b7c88e9bc72b96b7bde3ee6fa8464188661188661188661186693f901")

_ZLIB_DEFAULT = bytes.fromhex("7801737276717573f7f0f4f2f6f1f5f30f080c0a0e090d0b8f888c72741a95190d83d174309a1746cb83d13271b45e18ad1b47db07a36da4d176e2685b79b4bf30da331aed190d939e110004d2d7f7")

_ZLIB_MAX = bytes.fromhex("78daedc9c71180200000c1dac812140425d87f21f6c1dc7e572a6dac3b7c88e9bc72b96b7bde3ee6fa8464188661188661188661186693f90104d2d7f7")


# --- DEFLATE tests ---


def test_deflate_decompress_ntdll_default() -> None:
    assert deflate.decompress(_DEFLATE_DEFAULT) == PLAIN


def test_deflate_decompress_ntdll_max() -> None:
    assert deflate.decompress(_DEFLATE_MAX) == PLAIN


def test_deflate_roundtrip() -> None:
    assert deflate.decompress(deflate.compress(PLAIN)) == PLAIN


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"A",
        b"hello world",
        b"abc" * 1000,
        os.urandom(4096),
    ],
)
def test_deflate_roundtrip_various(data: bytes) -> None:
    assert deflate.decompress(deflate.compress(data)) == data


def test_deflate_compress_level_0() -> None:
    data = b"test" * 100
    stored = deflate.compress(data, level=0)
    assert deflate.decompress(stored) == data


def test_deflate_compress_level_9() -> None:
    data = b"test" * 100
    fast = deflate.compress(data, level=1)
    best = deflate.compress(data, level=9)
    assert deflate.decompress(fast) == data
    assert deflate.decompress(best) == data
    assert len(best) <= len(fast)


def test_deflate_max_size_rejects_bomb() -> None:
    import zlib

    compressed = deflate.compress(b"x" * 50000)
    with pytest.raises(zlib.error):
        deflate.decompress(compressed, max_size=1000)


# --- ZLIB tests ---


def test_zlib_decompress_ntdll_default() -> None:
    assert ntdll_zlib.decompress(_ZLIB_DEFAULT) == PLAIN


def test_zlib_decompress_ntdll_max() -> None:
    assert ntdll_zlib.decompress(_ZLIB_MAX) == PLAIN


def test_zlib_roundtrip() -> None:
    assert ntdll_zlib.decompress(ntdll_zlib.compress(PLAIN)) == PLAIN


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"A",
        b"hello world",
        b"abc" * 1000,
        os.urandom(4096),
    ],
)
def test_zlib_roundtrip_various(data: bytes) -> None:
    assert ntdll_zlib.decompress(ntdll_zlib.compress(data)) == data


def test_zlib_header_bytes() -> None:
    compressed = ntdll_zlib.compress(b"test" * 100)
    assert compressed[0] == 0x78


# --- Cross-format consistency ---


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="Python 3.14+ zlib changed wbits initialization")
def test_zlib_wraps_deflate() -> None:
    """ZLIB stream = 2-byte header + raw DEFLATE + 4-byte Adler-32."""
    data = b"consistency check " * 50
    zlib_out = ntdll_zlib.compress(data)
    defl_out = deflate.compress(data)
    assert zlib_out[2:-4] == defl_out


def test_not_registered_in_ese_registry() -> None:
    from ntcompress.ese._registry import _CODECS

    modules = {type(codec).__module__ for codec in _CODECS.values()}
    assert not any("deflate" in m for m in modules)
    assert not any("zlib" in m for m in modules)
