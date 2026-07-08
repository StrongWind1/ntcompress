# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ntcompress.ese`: ESE record-compression with dual API -- dispatch by `Format` enum or import format modules directly.
- ESE formats: 7-bit ASCII (`0x1`), 7-bit Unicode (`0x2`), XPRESS (`0x3`), SCRUB (`0x4`), XPRESS9 (`0x5`), XPRESS10 (`0x6`), LZ4 (`0x7`).
- `ntcompress.ntdll`: ntdll `RtlCompressBuffer`/`RtlDecompressBuffer` formats with the same dual API.
- ntdll formats: LZNT1 (`0x0002`), XPRESS (`0x0003`), XPRESS_HUFF (`0x0004`), DEFLATE (`0x0100`), ZLIB (`0x0101`).
- `COMPRESSION_FORMAT_*` aliases on `ntcompress.ntdll` matching the `ntifs.h` constant names.
- CRC-32C and CRC-64/NVME checksums at `ntcompress.ese.checksums`.
- Compress output verified byte-identical to `esent.dll` and `ntdll.dll` across 16 Windows builds (XP SP3 through Server 2025).
- XPRESS9 encoder is an attributed port of the MIT ESE C reference; matches byte-for-byte excluding the non-deterministic session signature.
- Decompression bomb protection on all paths: `max_size` caps, declared-size bounds, and safety ceilings.
- Full documentation with mkdocstrings autodoc API reference.
- 620 tests: per-format unit tests, gold vectors from 16 Windows builds, hypothesis property tests, and smoke tests for every public function.
