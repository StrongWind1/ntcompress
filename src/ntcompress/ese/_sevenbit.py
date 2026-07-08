"""Internal shared helpers for 7-bit ASCII and Unicode codecs.

These two schemes share their framing and packer, so the common infrastructure lives
here. Each packs 7 significant bits per source unit LSB-first into a continuous
bitstream: 7BITASCII over bytes, 7BITUNICODE over UTF-16LE code units whose high byte
is zero (so the wide scheme differs only in its 2-byte source stride and in re-emitting
the ``0x00`` high byte on decode). The low 3 bits of the header byte hold the number of
valid bits in the final packed byte, stored biased as 0-7 meaning 1-8.

There is no public specification -- [MS-XCA] scopes only the Xpress family -- so the
authority is the MIT-licensed ESE source: ``compression.cxx:985-1004`` (size math),
``:1168-1387`` / ``:1390-1504`` (ASCII/Unicode writers), ``:2113-2185`` /
``:2188-2272`` (ASCII/Unicode readers).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ntcompress.exceptions import DecompressionError

if TYPE_CHECKING:
    from ntcompress.ese import Format

# --- Constants ---

UNIT_BITS: Final = 7
"""Packed bits per source unit; the writers' fixed ``cbits = 7`` (compression.cxx:1310)."""

UNIT_MASK: Final = 0x7F
"""Mask of one packed unit; both readers extract ``(x >> ibit) & 0x7F`` (compression.cxx:2166, 2243)."""

_BYTE_BITS: Final = 8
_WIDE_STRIDE: Final = 2  # bytes per UTF-16LE code unit (sizeof(WORD), compression.cxx:1002)

MIN_CELL_SIZE: Final = 2
"""Smallest well-formed cell: header byte + one packed byte, which the readers' ``Cb - 2`` size math presumes (compression.cxx:2135)."""


# --- Shared framing ---


@dataclass(frozen=True)
class SevenBitHeader:
    """A parsed 7-bit cell header, per ``ErrDecompress7Bit*_`` (compression.cxx:2127-2137).

    Captures the two facts the readers derive before unpacking: how many bits of
    the last packed byte are valid, and hence exactly how many 7-bit units the
    stream holds.
    """

    fmt: Format
    """The format id from the header's top 5 bits (SEVEN_BIT_ASCII or SEVEN_BIT_UNICODE)."""

    final_byte_bits: int
    """Valid bits in the last packed byte, 1-8: ``(bHeader & 0x7) + 1`` (compression.cxx:2131)."""

    unit_count: int
    """Number of 7-bit units in the stream: ``((Cb - 2) * 8 + final_byte_bits) // 7`` (compression.cxx:2135-2137)."""


def _parse_header(blob: bytes, expected: Format) -> SevenBitHeader:
    """Validate a framed 7-bit cell and derive its unit count.

    Ports the size prologue shared by both readers (compression.cxx:2127-2137).
    ESE only *asserts* ``cbitTotal % 7 == 0`` in DEBUG builds and floor-divides in
    retail; real-world producers do emit non-canonical bit counts (the same
    Exchange payload circulates with header ``0x10`` and ``0x0e``), so this port
    keeps the retail floor-division behavior.

    Args:
        blob: The framed cell, header byte included.
        expected: The format the calling codec owns.

    Returns:
        The parsed header.

    Raises:
        DecompressionError: The cell is shorter than header + one stream byte, or
            its format id is not ``expected``.
    """
    from ntcompress.ese import format_flags, format_id

    if len(blob) < MIN_CELL_SIZE:
        msg = f"a 7-bit cell needs a header byte plus at least one packed byte, got {len(blob)} byte(s)"
        raise DecompressionError(msg)
    raw = format_id(blob[0])
    if raw != expected:
        msg = f"cell header carries format id 0x{raw:x}, not {expected.name} (0x{expected.value:x})"
        raise DecompressionError(msg)
    final_byte_bits = format_flags(blob[0]) + 1
    total_bits = (len(blob) - 2) * _BYTE_BITS + final_byte_bits
    return SevenBitHeader(fmt=expected, final_byte_bits=final_byte_bits, unit_count=total_bits // UNIT_BITS)


def _check_padding(blob: bytes, header: SevenBitHeader) -> None:
    """Reject a cell whose declared-invalid final-byte bits are non-zero.

    ESE's writers flush from a zero-initialized accumulator, so the padding bits
    above ``final_byte_bits`` are always zero in a well-formed cell. This checks only
    those high bits of the final packed byte; libesedb performs a comparable (not
    identical) padding-rejection check on corrupt streams (cf. ``value_16bit != 0``,
    libesedb_compression.c:220). Gated on ``verify`` by the callers.
    """
    if blob[-1] >> header.final_byte_bits:
        msg = f"non-zero padding above the {header.final_byte_bits} declared valid bit(s) of the final packed byte"
        raise DecompressionError(msg)


def _unpack_units(stream: bytes, count: int) -> bytearray:
    """Unpack ``count`` LSB-first 7-bit units from a packed stream.

    Accumulator port of the readers' inner loop (compression.cxx:2154-2180): the C
    code re-reads a byte or little-endian WORD at each bit offset, which is exactly
    equivalent to draining 7-bit units off a little-endian accumulator. ``count``
    comes from :func:`_parse_header`, which guarantees the stream holds enough bits.
    """
    out = bytearray()
    accumulator = 0
    bits = 0
    for byte in stream:
        accumulator |= byte << bits
        bits += _BYTE_BITS
        while bits >= UNIT_BITS:
            if len(out) == count:
                return out
            out.append(accumulator & UNIT_MASK)
            accumulator >>= UNIT_BITS
            bits -= UNIT_BITS
    return out


def _pack_units(units: bytes) -> bytearray:
    """Pack 7-bit values LSB-first into a byte stream.

    Accumulator port of the writers' slow path (compression.cxx:1298-1348 ASCII,
    :1413-1464 Unicode): OR each unit's 7 bits at the current bit offset and flush
    whole bytes. The final partial byte is always written, zero-padded high --
    matching ESE's ``(ibitOutputCurr + 7) / 8`` trailing flush (:1354-1362).
    """
    out = bytearray()
    accumulator = 0
    bits = 0
    for value in units:
        accumulator |= value << bits
        bits += UNIT_BITS
        if bits >= _BYTE_BITS:
            out.append(accumulator & 0xFF)
            accumulator >>= _BYTE_BITS
            bits -= _BYTE_BITS
    if bits:
        out.append(accumulator)
    return out


def _frame(fmt: Format, units: bytes) -> bytes:
    """Build a framed cell: header byte + packed stream.

    The stored bit count is ``(ibitOutputCurr - 1) % 8`` (compression.cxx:1379,
    :1497), which for ``n`` units reduces to ``(7n - 1) % 8`` -- the writers' 0->32
    fixup for an exactly-full final DWORD (:1374-1378) folds into the same formula.
    """
    from ntcompress.ese import header_byte

    final_bits_biased = (len(units) * UNIT_BITS - 1) % _BYTE_BITS
    return bytes([header_byte(fmt, final_bits_biased)]) + bytes(_pack_units(units))
