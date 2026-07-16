# Spec traceability

Every wire constant, flag, offset, and polynomial in `ntcompress` is traceable to a normative source. Two kinds of authority are used:

## Published specifications

Formats covered by `[MS-XCA]` (Plain LZ77, LZ77+Huffman, LZNT1) cite section numbers from the published Microsoft Open Specification. The library implements against **v10.0** (document date 2024-04-23). The v10.0 revision adds the 32-bit extended-length escape to both Plain LZ77 and LZ77+Huffman; the v2.1 (2014-05-15) revision caps match lengths at 65538. Both revisions are vendored under `research/spec/`.

Citation format: `[MS-XCA] §x.y` (e.g., `[MS-XCA] §2.4.4` for the Plain LZ77 decompression pseudocode).

## Source code

Formats with no published specification (7-bit ASCII/Unicode, SCRUB, XPRESS9, XPRESS10, LZ4) cite the MIT-licensed Microsoft ESE source at `dev/ese/src/ese/compression.cxx` and related files. These citations are `file:line` references (e.g., `compression.cxx:1551`).

The `min(Length - 3, 15)` versus `min(Length, 15)` difference between [MS-XCA] revisions is a pseudocode refactor (v10.0 redefines `Length` as `Length - 3` first); the emitted match symbol is identical.

## Per-format authority

| Format | Authority |
|--------|-----------|
| 7-bit ASCII (0x1) | `compression.cxx:1168-1387, :2113-2185` |
| 7-bit Unicode (0x2) | `compression.cxx:1390-1504, :2188-2272` |
| XPRESS (0x3) | `[MS-XCA] §2.3/§2.4`; ESE frame `compression.cxx:1507-1568` |
| SCRUB (0x4) | `compression.cxx:1571-1590, :2350-2391`; `daedef.hxx:1063-1072` |
| XPRESS9 (0x5) | `dev/ese/src/_xpress9/` (MIT port); frame `compression.cxx:1686-1759` |
| XPRESS10 (0x6) | `compression.cxx:523-532, :1935-2064`; CRC `os/encrypt.cxx`, `_xpress10/xpress10sw.cxx` |
| LZ4 (0x7) | `compression.cxx:2070-2109`; payload `lz4_Block_format.md` |
| LZNT1 (0x0002) | `[MS-XCA] §2.5` |
| XPRESS (0x0003) | `[MS-XCA] §2.3/§2.4` |
| XPRESS_HUFF (0x0004) | `[MS-XCA] §2.1/§2.2` |
| Compact XPRESS9 (0x0005) | Reverse-engineered from `ntdll.dll` Build 20348 (RVA 0x111810, 0x114DA8, 0x115AB0) |
| XP10 (0x0006) | `lz4_Block_format.md` (same payload as ESE 0x6/0x7) |
| DEFLATE (0x0007) | RFC 1951 |
| ZLIB (0x0008) | RFC 1950 |

## Windows binary verification

PE export and strings analysis of the shipping Windows binaries (Server 2025 Build 26100) confirms the internal structure of the compression pipeline:

| Binary | Compression exports | Internal strings |
|--------|-------------------|------------------|
| `ntdll.dll` | `RtlCompressBuffer`, `RtlDecompressBuffer`, `RtlDecompressBufferEx`, `RtlDecompressFragment`, `RtlGetCompressionWorkSpaceSize` | `unknown compression method`. Format dispatch tables at RVA 0x173F30 (compress), 0x173F80 (decompress), 0x173FE0 (workspace) on Build 26100; 0x128088, 0x128028, 0x128058 on Build 20348. |
| `esent.dll` | *(none)* | `JET_paramFlight_EnableXpress10Compression`, `JET_paramMinDataForXpress`, `Lz4CompressionVerificationFailed`, `onecore\ds\esent\src\ese\compression.cxx` |

All format-specific codecs (LZNT1, XPRESS, XPRESS_HUFF, XP10, XPRESS9) are dispatched internally by numeric format ID. No format-specific function names appear in the export tables or string tables of either DLL. The XPRESS9 functions (`Xpress9DecoderCreate`, `Xpress9EncoderCreate`, etc.) are statically linked inside `esent.dll` and not exported.

## Attribution

The XPRESS9 module is an attributed port of Microsoft's MIT-licensed C reference implementation. See `THIRD-PARTY-NOTICES.md` for full license text and provenance details.
