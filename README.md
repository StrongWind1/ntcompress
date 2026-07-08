# ntcompress

Pure-Python, standard-library-only implementations of every compression format used by Microsoft's Extensible Storage Engine (ESE/ESENT, the "JET Blue" engine behind `NTDS.dit`, Exchange stores, `Windows.edb`, `SRUDB.dat`, and `WebCacheV01.dat`) and Windows `ntdll.dll` compression (`RtlCompressBuffer` / `RtlDecompressBuffer`). No runtime dependencies beyond the standard library.

## Scope

This library covers two distinct compression layers used by Windows:

### ESE record compression (vs `esent.dll`)

ESE stores a one-byte header on each compressed record cell; the top 5 bits select the scheme (`first_byte >> 3`) and the low 3 bits carry scheme-specific flags.

| ESE ID | Format | Decompress | Compress | Byte-Identical to esent.dll | Authority |
|--------|--------|-----------|----------|---------------------------|-----------|
| `0x0` | NONE (uncompressed sentinel) | — | — | — | `compression.cxx:504` |
| `0x1` | 7-bit ASCII | yes | yes | yes | ESE source |
| `0x2` | 7-bit Unicode | yes | yes | yes | ESE source |
| `0x3` | XPRESS (Plain LZ77) | yes | yes | yes | `[MS-XCA] §2.3/2.4` |
| `0x4` | SCRUB (erase marker) | produce | recognize | n/a | ESE source |
| `0x5` | XPRESS9 | yes | yes | yes* | ESE MIT source (ported) |
| `0x6` | XPRESS10 (LZ4 + CRC) | yes | yes | yes** | ESE source |
| `0x7` | LZ4 (standard block) | yes | yes | yes | LZ4 block format |

\*XPRESS9 encoder matches the MIT ESE C reference byte-for-byte excluding the non-deterministic session signature (`CRC32(__rdtsc())`), which even `esent.dll` varies on every call. \*\*XPRESS10 verified byte-identical by component construction (LZ4 block + CRC-32C + CRC-64/NVME each individually proven); not triggerable on commodity hardware (requires Corsica/QAT flight flag).

### ntdll compression (vs `RtlCompressBuffer`)

Windows `ntdll.dll` exposes a separate set of `CompressionFormatAndEngine` IDs used by SMB, NTFS, RDP, and other protocols. These use raw bitstreams with no ESE framing.

| ntdll ID | Name | Decompress | Compress | Byte-Identical to ntdll | Builds |
|----------|------|-----------|----------|------------------------|--------|
| `0x0002` | LZNT1 | yes | yes | yes (ENGINE_MAX) | XP SP3 – Server 2025 |
| `0x0003` | XPRESS (Plain LZ77) | yes | yes | yes | Win8.1 – Server 2025 |
| `0x0004` | XPRESS_HUFF (LZ77+Huffman) | yes | yes | yes (default engine) | Win8.1 – Server 2025 |
| `0x0005` | undocumented | — | — | — | Server 2022+ |
| `0x0006` | XP10 (LZ4 block) | yes | yes | yes | Win11 / Server 2025 |
| `0x0007` | raw DEFLATE | yes | yes | yes (both levels) | Win11 / Server 2025 |
| `0x0008` | ZLIB | yes | yes | yes (both levels) | Win11 / Server 2025 |

ntdll format 0x0005 is an undocumented format (block magic `0xC039E510`) unrelated to XPRESS9 despite sharing the slot number. No public specification or source code exists. Format 0x0006 (XP10) is the same LZ4 block codec used by ESE scheme 0x6 and 0x7, without the ESE header.

## Design principles

- **Standard library only at runtime.** No third-party dependencies. `zlib`/`lz4` are deliberately not used; the CRCs and the LZ4 block codec are implemented directly.
- **Two subpackages, one interface pattern.** `ntcompress.ese` for ESE record-compression, `ntcompress.ntdll` for ntdll standalone codecs. Both offer Shape A (enum dispatch) and Shape B (direct module import) APIs.
- **Traceable to a spec or a source line.** Every wire constant cites `[MS-XCA] §x.y` or an ESE `file:line`. Where the shipped C diverges from the spec text, both are documented.
- **Byte-identical verification.** Compress output is verified against gold vectors captured from `esent.dll` and `ntdll.dll` on 16 Windows builds (XP SP3 through Server 2025).
- **Typed and documented.** Python 3.11+, full type hints, Google-style docstrings, `ruff`-clean under `select = ["ALL"]`, `ty`-clean.

## Installation

```bash
uv add ntcompress   # once published
```

Requires Python >= 3.11.

## Usage

### ESE record compression

```python
import ntcompress.ese as ese

# Decompress a cell (format is in byte 0)
plaintext = ese.decompress(cell)
size = ese.decompressed_size(cell)

# Compress with a specific format
cell = ese.compress(plaintext, ese.Format.XPRESS)
cell = ese.compress(plaintext, ese.Format.LZ4)
cell = ese.compress(plaintext, ese.Format.XPRESS9)

# Or use Shape B (direct module access)
from ntcompress.ese import xpress
cell = xpress.compress(plaintext)
plaintext = xpress.decompress(cell)
```

### ntdll standalone codecs

```python
import ntcompress.ntdll as ntdll

# Shape A (enum dispatch)
compressed = ntdll.compress(data, ntdll.Format.LZNT1)
plaintext = ntdll.decompress(compressed, ntdll.Format.LZNT1)

# Windows constant aliases
compressed = ntdll.compress(data, ntdll.COMPRESSION_FORMAT_XPRESS_HUFF)

# Shape B (direct module access)
from ntcompress.ntdll import lznt1, xpress_huff, deflate
from ntcompress.ntdll import zlib as ntdll_zlib

plaintext = lznt1.decompress(compressed_stream)
compressed = xpress_huff.compress(data)
compressed = deflate.compress(data)            # matches ntdll 0x0007
compressed = ntdll_zlib.compress(data)         # matches ntdll 0x0008
```

## License and attribution

Apache-2.0 (`LICENSE`). The XPRESS9 codec is an attributed port of Microsoft's MIT-licensed ESE source; the Plain LZ77, Xpress Huffman, and LZNT1 codecs are derived from the published `[MS-XCA]` specification; the LZ4 block codec follows the public LZ4 format. Full notices are in `THIRD-PARTY-NOTICES.md`.
