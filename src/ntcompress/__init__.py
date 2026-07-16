"""Pure-Python codecs for Microsoft ESE record-compression and Windows ntdll compression formats.

``ntcompress`` compresses and decompresses all ESE record schemes (7-bit ASCII/Unicode,
XPRESS, SCRUB, XPRESS9, XPRESS10, LZ4) and all ntdll ``RtlCompressBuffer`` formats
(LZNT1, XPRESS, XPRESS_HUFF, Compact XPRESS9, XP10, DEFLATE, ZLIB). Compress output is
verified byte-identical to ``esent.dll`` and ``ntdll.dll`` across 16 Windows builds. No
runtime dependencies beyond the standard library.

ESE codecs live under :mod:`ntcompress.ese`; ntdll standalone codecs under
:mod:`ntcompress.ntdll`.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ntcompress")
except PackageNotFoundError:  # pragma: no cover - source checkout without install metadata
    __version__ = "0.0.0"
