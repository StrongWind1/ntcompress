# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-15

### Added

- `ntcompress.ntdll.xpress9`: Compact XPRESS9 decompressor and compressor for ntdll format `0x0005` (magic `0xC039E510`). Reverse-engineered from `ntdll.dll` Build 20348. Uses the same canonical-Huffman LZ77 engine as ESE XPRESS9 with a streamlined 10-byte header. Verified against 11 test vectors from Server 2022 and Server 2025.
- `ntcompress.ntdll.xp10`: XP10 codec for ntdll format `0x0006` -- thin wrapper over `ese.lz4` block functions. Byte-identical to `RtlCompressBuffer` output on Build 26100.
- `Format.XPRESS9 = 0x0005` and `Format.XP10 = 0x0006` enum members.

### Changed

- **Breaking:** `Format.DEFLATE` changed from `0x0100` to `0x0007` (the real Windows `CompressionFormatAndEngine` constant). Code that compared `Format.DEFLATE == 0x0100` will break.
- **Breaking:** `Format.ZLIB` changed from `0x0101` to `0x0008` (the real Windows constant). Same migration as DEFLATE.
- All seven ntdll format IDs (`0x0002`--`0x0008`) now match the actual Windows constants. The library extension IDs `0x0100`/`0x0101` are removed.

## [0.2.0] - 2026-07-08

### Changed

- Minimum Python version lowered from 3.11 to 3.10.

## [0.1.0] - 2026-07-08

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

[Unreleased]: https://github.com/StrongWind1/ntcompress/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/StrongWind1/ntcompress/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/StrongWind1/ntcompress/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/StrongWind1/ntcompress/releases/tag/v0.1.0
