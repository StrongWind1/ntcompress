"""Tests for the ESE header checksums, pinned to Microsoft's published check values."""

from __future__ import annotations

import zlib

import pytest

from ntcompress.ese.checksums import crc32c_ese, crc64_ese


def test_crc32c_check_value() -> None:
    # Standard CRC-32C / Castagnoli check value, confirming poly + init/xorout.
    assert crc32c_ese(b"123456789") == 0xE3069283


def test_crc64_ese_check_value() -> None:
    # Verified against the ESE/Corsica CRC-64 (UtilGenCorsicaCrc64).
    assert crc64_ese(b"123456789") == 0xAE8B14860A799888


def test_empty_input_is_zero() -> None:
    # init ^ xorout == 0 for both.
    assert crc32c_ese(b"") == 0
    assert crc64_ese(b"") == 0


@pytest.mark.parametrize("factory", [bytes, bytearray, lambda d: memoryview(bytes(d))])
def test_accepts_bytes_like(factory: object) -> None:
    build = factory  # type: ignore[operator]
    assert crc32c_ese(build(b"123456789")) == 0xE3069283
    assert crc64_ese(build(b"123456789")) == 0xAE8B14860A799888


def test_single_byte_differs_from_zlib() -> None:
    # Sanity: CRC-32C is not zlib's CRC-32, so results must differ on real input.
    assert crc32c_ese(b"The quick brown fox") != zlib.crc32(b"The quick brown fox")
