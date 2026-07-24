# SPDX-License-Identifier: Apache-2.0
"""COMPRESS_SCRUB (0x4) -- a data-erasure marker, not a codec.

SCRUB does not compress anything: database maintenance and repair overwrite an
orphaned long-value chunk with a known fill pattern and tag it with this scheme so
later reads can detect the erasure instead of mis-decoding it. There is no plaintext
to recover, so this module is never registered as a codec -- the dispatcher raises
:class:`~ntcompress.exceptions.ScrubDetectedError` for scheme 0x4. What lives
here are helpers to *recognize* a scrub cell (:func:`is_scrub`,
:func:`scrub_fill_byte`, :func:`parse_scrub`) and to *produce* one
(:func:`make_scrub`), mirroring ``CDataCompressor::ErrScrub``.

Authority: ESE ``compression.cxx:1571-1590`` (write) and ``:2350-2391`` (recognize);
fill-pattern constants in ``dev/ese/src/inc/daedef.hxx:1063-1072``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Final

from ntcompress.exceptions import CompressionError, DecompressionError

if TYPE_CHECKING:
    from ntcompress._types import Buffer


def _scrub_header() -> int:
    """Compute the fixed SCRUB header byte (deferred to avoid circular import at module level)."""
    from ntcompress.ese import Format, header_byte

    return header_byte(Format.SCRUB)


_MAX_FILL: Final = 0xFF
"""Upper bound of a single fill byte; ErrScrub memsets one CHAR (compression.cxx:1587)."""


class ScrubFill(IntEnum):
    """The two ``chSCRUB*`` fill bytes that reach a 0x4 compression cell.

    Only long-value-chunk scrubbing writes through the compression-cell path
    (``ErrRECScrubLVChunk``, compression.cxx:3007-3014); the other ``chSCRUB*``
    page/record fills are written directly into page bytes and never appear here.
    Values from ``daedef.hxx:1064`` and ``:1069``.
    """

    LEGACY_LV_CHUNK = 0x6C
    """``chSCRUBLegacyLVChunkFill`` ``'l'`` -- legacy (OLDv1 / ``eseutil /z``) LV scrubbing (lv.cxx:7228)."""

    DB_MAINT_LV_CHUNK = 0x4C
    """``chSCRUBDBMaintLVChunkFill`` ``'L'`` -- DB Maintenance LV scrubbing (node.cxx:2778)."""


@dataclass(frozen=True)
class ScrubRecord:
    """A recognized SCRUB cell, described for forensic reporting.

    Captures what ``ErrDecompressScrub_`` (compression.cxx:2350-2391) inspects:
    the erased length (scrubbing is in place, so it equals the original chunk
    length) and the uniform fill byte, flagged when it matches a known
    ``chSCRUB*`` LV-chunk value. Retail ESE accepts any fill, so ``known_fill``
    is informational, not a validity gate.
    """

    erased_length: int
    """Total cell length in bytes, header included; the original chunk length."""

    fill_byte: int | None
    """The uniform fill after the header, or None if absent (1-byte cell) or non-uniform."""

    known_fill: bool
    """True when ``fill_byte`` is one of the two documented :class:`ScrubFill` values."""


# --- Recognition ---


def is_scrub(blob: Buffer) -> bool:
    """Report whether a cell's leading byte carries the SCRUB format id.

    Exists so callers can screen cells before dispatching, instead of catching
    :class:`~ntcompress.exceptions.ScrubDetectedError`. Matches the decode
    dispatch test ``bIdentifier == COMPRESS_SCRUB`` (compression.cxx:2852, 2865).

    Args:
        blob: A (possibly empty) framed ESE cell.

    Returns:
        True iff the buffer is non-empty and ``blob[0] >> 3 == 0x4``.
    """
    from ntcompress.ese import Format, format_id

    return len(blob) > 0 and format_id(blob[0]) == Format.SCRUB


def scrub_fill_byte(blob: Buffer) -> int | None:
    """Return the uniform fill byte of a scrub cell's erased region.

    ``ErrScrub`` memsets everything after the header to one byte
    (compression.cxx:1587), so a well-formed cell has a single fill value. This
    surfaces it for forensic reporting (which scrubber wrote the cell).

    Args:
        blob: A framed cell; typically one for which :func:`is_scrub` is True.

    Returns:
        The fill byte repeated over ``blob[1:]``, or None when that region is
        empty (a 1-byte cell, legal per compression.cxx:3556-3561) or not uniform.
    """
    body = bytes(memoryview(blob)[1:])
    if not body:
        return None
    fill = body[0]
    if body.count(fill) != len(body):
        return None
    return fill


def parse_scrub(blob: Buffer) -> ScrubRecord:
    """Describe a SCRUB cell as a :class:`ScrubRecord`.

    The read-side counterpart of :func:`make_scrub`. ``ErrDecompressScrub_`` runs its
    checks only in DEBUG builds (compression.cxx:2361-2389); this bundles the scheme-id
    check and the uniform-fill read into one immutable record for callers that want
    more than a boolean. It deliberately does not enforce the low-3-flag-bits-zero
    condition, which ESE states as a soft ``Expected`` it tolerates (:2370), not an
    assert, so a cell with nonzero flag bits still parses.

    Args:
        blob: A framed cell whose format id must be SCRUB.

    Returns:
        The erased length, fill byte, and whether the fill is a known
        :class:`ScrubFill` value.

    Raises:
        DecompressionError: The buffer is empty or not a SCRUB cell.
    """
    if not is_scrub(blob):
        msg = "buffer is not a SCRUB (0x4) erase-marker cell"
        raise DecompressionError(msg)
    fill = scrub_fill_byte(blob)
    return ScrubRecord(
        erased_length=len(blob),
        fill_byte=fill,
        known_fill=fill in tuple(ScrubFill),
    )


# --- Production ---


def make_scrub(length: int, fill: int = ScrubFill.DB_MAINT_LV_CHUNK) -> bytes:
    """Build a scrub cell of a given total length, as ``ErrScrub`` would in place.

    Mirrors ``CDataCompressor::ErrScrub`` (compression.cxx:1571-1590): byte 0 is
    ``COMPRESS_SCRUB << 3 = 0x20`` and the remaining ``length - 1`` bytes are the
    fill. A 1-byte cell is legal and is just the header.

    Args:
        length: Total cell size in bytes (the chunk length being erased), >= 1.
        fill: The fill byte, 0-255; defaults to ``chSCRUBDBMaintLVChunkFill``
            (``'L'``), the fill modern DB maintenance writes (node.cxx:2778).

    Returns:
        The framed scrub cell.

    Raises:
        CompressionError: ``length`` < 1, or ``fill`` is not a byte value. Deviation:
            ``ErrScrub`` has no such guard -- it scrubs a caller-sized buffer in place
            and always returns success (compression.cxx:1571-1590) -- so this
            minimum-length check is a library-side precondition, not an ESE error path.
    """
    if length < 1:
        msg = f"a scrub cell needs at least 1 byte for its header, got length {length}"
        raise CompressionError(msg)
    if not 0 <= fill <= _MAX_FILL:
        msg = f"scrub fill must be a byte value 0-255, got {fill}"
        raise CompressionError(msg)
    scrub_header = _scrub_header()
    return bytes([scrub_header]) + bytes([fill]) * (length - 1)
