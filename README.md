<h1 align="center">ntcompress</h1>

<p align="center"><strong>Every ESE and ntdll compression format in pure Python. No Windows, no dependencies.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/ntcompress/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/ntcompress/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ntcompress/"><img src="https://img.shields.io/pypi/v/ntcompress.svg" alt="PyPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/ntcompress/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/ntcompress/getting-started/#installation">Installation</a> &bull;
  <a href="https://strongwind.dev/ntcompress/getting-started/#ese-quickstart">Quick start</a> &bull;
  <a href="https://strongwind.dev/ntcompress/user-guide/ese/">Usage</a> &bull;
  <a href="https://strongwind.dev/ntcompress/reference/formats/">Format details</a> &bull;
  <a href="https://strongwind.dev/ntcompress/">Documentation</a>
</p>

---

ntcompress compresses and decompresses every record-compression format of Microsoft's Extensible Storage Engine (ESE, the "JET Blue" engine behind `NTDS.dit`, Exchange stores, `Windows.edb`, `SRUDB.dat`, and `WebCacheV01.dat`) and every `ntdll.dll` `RtlCompressBuffer` / `RtlDecompressBuffer` format. Use it when a parser for one of those databases, or for an ntdll-compressed stream, runs into compressed data and you cannot call `esent.dll` or `ntdll.dll`, or are not on Windows at all. It is pure Python with no dependencies outside the standard library.

## Example

Decompress an XPRESS cell written by `esent.dll` on Windows Server 2022 (one of the real cells in the test suite):

```python
import ntcompress.ese as ese

cell = bytes.fromhex("180004ffffff3f414107000ffffb03")
assert ese.decompress(cell) == b"A" * 1024
assert ese.decompressed_size(cell) == 1024
```

## Features

- **ESE record compression**: 7-bit ASCII, 7-bit Unicode, XPRESS, XPRESS9, XPRESS10, and LZ4, plus SCRUB (erase marker) cells. `ese.decompress()` reads the format from the cell's header byte.
- **ntdll compression**: LZNT1, XPRESS, XPRESS_HUFF, compact XPRESS9, XP10, raw DEFLATE, and ZLIB, the raw streams behind `RtlCompressBuffer` / `RtlDecompressBuffer`.
- **Standard library only**: no third-party runtime dependencies. The CRCs and the LZ4 block codec are implemented directly; DEFLATE and ZLIB wrap the standard `zlib` module.
- **Byte-identical to Windows**: compress output is verified against gold vectors captured from `esent.dll` and `ntdll.dll` on 16 Windows builds, XP SP3 through Server 2025.
- **Traceable to a spec or a source line**: every wire constant cites `[MS-XCA] §x.y` or an ESE `file:line`. Where the shipped C diverges from the spec text, both are documented.
- **One interface pattern**: `ntcompress.ese` and `ntcompress.ntdll` both offer enum dispatch (Shape A) and direct module import (Shape B).
- **Typed**: full type hints, Google-style docstrings, `ruff`-clean under `select = ["ALL"]`, and `ty`-clean.

## Installation

```sh
uv add ntcompress        # recommended
pip install ntcompress   # or with pip
```

From source:

```sh
uv add git+https://github.com/StrongWind1/ntcompress
```

Requires Python 3.11 or newer.

## Quick start

```python
import ntcompress.ese as ese
import ntcompress.ntdll as ntdll

plaintext = ese.decompress(cell)  # format comes from the header byte
cell = ese.compress(plaintext, ese.Format.XPRESS)

compressed = ntdll.compress(data, ntdll.Format.LZNT1)
plaintext = ntdll.decompress(compressed, ntdll.Format.LZNT1)
```

Direct module imports, the Windows `COMPRESSION_FORMAT_*` aliases, and per-format options such as `level` and `max_size` are in the [ESE](https://strongwind.dev/ntcompress/user-guide/ese/) and [ntdll](https://strongwind.dev/ntcompress/user-guide/ntdll/) user guides.

## Supported formats

### ESE record compression

| ESE ID | Format | Decompress | Compress | Byte-identical to esent.dll | Authority |
| --- | --- | --- | --- | --- | --- |
| `0x0` | NONE (uncompressed sentinel) | n/a | n/a | n/a | `compression.cxx:504` |
| `0x1` | 7-bit ASCII | yes | yes | yes | ESE source |
| `0x2` | 7-bit Unicode | yes | yes | yes | ESE source |
| `0x3` | XPRESS (Plain LZ77) | yes | yes | yes | `[MS-XCA] §2.3/2.4` |
| `0x4` | SCRUB (erase marker) | produce | recognize | n/a | ESE source |
| `0x5` | XPRESS9 | yes | yes | yes* | ESE MIT source (ported) |
| `0x6` | XPRESS10 (LZ4 + CRC) | yes | yes | yes** | ESE source |
| `0x7` | LZ4 (standard block) | yes | yes | yes | LZ4 block format |

\*The XPRESS9 encoder matches the MIT ESE C reference byte-for-byte, excluding the non-deterministic session signature (`CRC32(__rdtsc())`), which even `esent.dll` varies on every call. \*\*XPRESS10 is verified byte-identical by component construction (LZ4 block, CRC-32C, and CRC-64/NVME, each proven on its own); it cannot be triggered on commodity hardware (it requires the Corsica/QAT flight flag).

### ntdll compression

`ntdll.dll` numbers its formats separately (`CompressionFormatAndEngine` IDs). SMB, NTFS, RDP, and other protocols use them as raw bitstreams with no ESE framing.

| ntdll ID | Name | Decompress | Compress | Byte-identical to ntdll | Builds |
| --- | --- | --- | --- | --- | --- |
| `0x0002` | LZNT1 | yes | yes | yes (ENGINE_MAX) | XP SP3 to Server 2025 |
| `0x0003` | XPRESS (Plain LZ77) | yes | yes | yes | Win8.1 to Server 2025 |
| `0x0004` | XPRESS_HUFF (LZ77+Huffman) | yes | yes | yes (default engine) | Win8.1 to Server 2025 |
| `0x0005` | Compact XPRESS9 | yes | yes | not verified | Server 2022+ |
| `0x0006` | XP10 (LZ4 block) | yes | yes | yes | Win11 / Server 2025 |
| `0x0007` | raw DEFLATE | yes | yes | yes (both levels) | Win11 / Server 2025 |
| `0x0008` | ZLIB | yes | yes | yes (both levels) | Win11 / Server 2025 |

Format 0x0005 is an undocumented XPRESS9-family Huffman LZ77 codec (magic `0xC039E510`, 10-byte header), reverse-engineered from `ntdll.dll` Build 20348. It shares its core algorithm with ESE XPRESS9 (magic `0x4E86D72A`) but not the outer framing.

Header layouts and per-format wire details are in [Format details](https://strongwind.dev/ntcompress/reference/formats/); spec and source citations are in [Spec traceability](https://strongwind.dev/ntcompress/reference/spec-traceability/).

## Credits

- [`[MS-XCA]` Xpress Compression Algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8): the Microsoft Open Specification the Plain LZ77, LZ77+Huffman, and LZNT1 codecs are written from.
- [Microsoft Extensible Storage Engine](https://github.com/microsoft/Extensible-Storage-Engine) (MIT): the XPRESS9 codec and the CRC-32C / CRC-64 routines are ports of its source, and the other ESE formats cite its `compression.cxx`.
- [LZ4 block format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md) (Yann Collet): the payload format of ESE LZ4, XPRESS10, and ntdll XP10.

## Related tools

- [**CredWolf**](https://github.com/StrongWind1/CredWolf): Validate AD passwords, hashes, keys, and tickets over NTLM and Kerberos
- [**KerbWolf**](https://github.com/StrongWind1/KerbWolf): Kerberos roasting and TGT attack toolkit for Active Directory
- [**NTDSWolf**](https://github.com/StrongWind1/NTDSWolf): Offline NTDS.dit parser and credential extractor for NT/LM hashes, Kerberos keys, LAPS, and gMSA
- [**PassWolf**](https://github.com/StrongWind1/PassWolf): Spec-compliant AD password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, LDAP
- [**AD-SecretGen**](https://github.com/StrongWind1/AD-SecretGen): Derive every password-derived AD secret (NT/LM, Kerberos keys, WDigest) from a password
- [**Kerberos**](https://github.com/StrongWind1/Kerberos): Protocol internals, security configuration, and attack techniques for Kerberos in Active Directory

All tools: [strongwind.dev](https://strongwind.dev)

## License

[Apache License 2.0](LICENSE)

The XPRESS9 codec is an attributed port of Microsoft's MIT-licensed ESE source; the Plain LZ77, Xpress Huffman, and LZNT1 codecs are derived from the published `[MS-XCA]` specification; the LZ4 block codec follows the public LZ4 format. Full notices are in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
