"""Tests for the format enum and first-byte header helpers."""

from __future__ import annotations

import pytest

from ntcompress.ese import Format, format_flags, format_id, header_byte


def test_format_ids_match_ese_source() -> None:
    # Values are pinned to compression.cxx:504-512.
    assert Format.NONE == 0x0
    assert Format.SEVEN_BIT_ASCII == 0x1
    assert Format.SEVEN_BIT_UNICODE == 0x2
    assert Format.XPRESS == 0x3
    assert Format.SCRUB == 0x4
    assert Format.XPRESS9 == 0x5
    assert Format.XPRESS10 == 0x6
    assert Format.LZ4 == 0x7
    assert Format.MAXIMUM == 0x1F


@pytest.mark.parametrize(
    ("fmt", "first_byte"),
    [
        (Format.XPRESS, 0x18),
        (Format.SCRUB, 0x20),
        (Format.XPRESS9, 0x28),
        (Format.XPRESS10, 0x30),
        (Format.LZ4, 0x38),
    ],
)
def test_header_byte_round_trips(fmt: Format, first_byte: int) -> None:
    assert header_byte(fmt) == first_byte
    assert format_id(first_byte) == fmt
    assert format_flags(first_byte) == 0


def test_seven_bit_flags_live_in_low_three_bits() -> None:
    # The 7-bit formats store a final-bit count in the low 3 bits of byte 0.
    hb = header_byte(Format.SEVEN_BIT_ASCII, flags=0b101)
    assert format_id(hb) == Format.SEVEN_BIT_ASCII
    assert format_flags(hb) == 0b101
