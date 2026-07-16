# Format details

## ESE record compression (0x0--0x7)

Every compressed ESE record cell starts with a header byte. The top 5 bits select the format (`byte >> 3`), the low 3 bits carry format-specific flags.

### NONE (0x0)

Uncompressed sentinel. No header is stored; the raw cell body is the plaintext.

### 7-bit ASCII (0x1)

Packs each byte's low 7 bits LSB-first into a continuous bitstream. Header byte low 3 bits store `(final_byte_valid_bits - 1)`. Minimum cell size: 2 bytes (header + one packed byte). Input must be 7-bit clean and at least 16 bytes to beat the plaintext size.

Authority: `compression.cxx:1168-1387` (writer), `:2113-2185` (reader).

### 7-bit Unicode (0x2)

Identical bitstream to 7-bit ASCII over UTF-16LE code units whose high byte is zero. The 2-byte source stride and `0x00` high-byte reconstruction on decode are the only differences. Input must be even-length and at least 4 bytes.

Authority: `compression.cxx:1390-1504` (writer), `:2188-2272` (reader).

### XPRESS (0x3)

3-byte header: scheme byte (`0x18`) + u16 LE uncompressed size. Payload is a raw MS-XCA Plain LZ77 stream ([MS-XCA] §2.3/§2.4). Maximum plaintext: 65535 bytes.

Authority: `compression.cxx:1507-1568` (writer), `:2275-2347` (reader). Wire format: `[MS-XCA]` v10.0.

### SCRUB (0x4)

Not a compression format. Database maintenance overwrites orphaned long-value chunks with a known fill byte (`0x4C` for DB maintenance, `0x6C` for legacy) and tags them with this format ID. No plaintext is recoverable.

Authority: `compression.cxx:1571-1590` (writer), `:2350-2391` (reader). Fill constants: `daedef.hxx:1063-1072`.

### XPRESS9 (0x5)

5-byte header: scheme byte (`0x28`) + u32 LE CRC-32C of plaintext. Payload is one or more 32-byte block headers followed by LSB-first bitstreams encoding canonical Huffman tables, MTF (repeated-offset) state, and LZ77 tokens with Elias-gamma offset coding.

No public specification exists. Authority: MIT ESE source `dev/ese/src/_xpress9/`.

### XPRESS10 (0x6)

15-byte header: scheme byte (`0x30`) + u16 LE uncompressed size + u32 LE CRC-32C of plaintext + u64 LE CRC-64/NVME of compressed payload. Payload is a standard LZ4 block (same format as scheme 0x7 and ntdll format 0x0006). Maximum plaintext: 65535 bytes.

Authority: `compression.cxx:523-532` (header struct), `:1935-2064` (writer), `:2481-2626` (reader). CRC-32C: `os/encrypt.cxx:147-184`. CRC-64/NVME: `_xpress10/xpress10sw.cxx:34-59`.

### LZ4 (0x7)

3-byte header: scheme byte (`0x38`) + u16 LE uncompressed size. Payload is a standard LZ4 block (no LZ4 frame, no magic, no checksum). Maximum plaintext: 65535 bytes. ESE links the reference liblz4 and calls `LZ4_compress_default`/`LZ4_decompress_safe_partial`.

Authority: `compression.cxx:2070-2109` (writer), `:2643-2699` (reader). Payload format: `lz4/lz4 doc/lz4_Block_format.md`. `[MS-XCA]` does not cover LZ4.

---

## ntdll compression (0x0002--0x0008)

Windows `ntdll.dll` exposes a separate numbering space through `RtlCompressBuffer`/`RtlDecompressBuffer`. These are raw bitstreams with no ESE framing. The `CompressionFormatAndEngine` USHORT low byte selects the format; bit 8 selects ENGINE_MAXIMUM.

### LZNT1 (0x0002)

Chunk-based LZ77. Input is processed in 4096-byte units. Each chunk has a 16-bit header (bit 15 = compressed flag, bits [14:12] = signature 3, bits [11:0] = size - 3). Compressed chunks use flag groups with position-dependent displacement/length field widths.

Authority: `[MS-XCA] §2.5`. Available: XP SP3 through Server 2025.

### XPRESS / Plain LZ77 (0x0003)

Flag words are 32-bit LE, consumed MSB-first. Matches are 16-bit tokens (13-bit offset, 3-bit length) with a nibble/byte/word/dword extended-length ladder (v10.0). Match copies are byte-by-byte for overlap semantics.

Authority: `[MS-XCA] §2.3/§2.4` v10.0. Available: Win8.1 through Server 2025.

### XPRESS_HUFF / LZ77+Huffman (0x0004)

64 KiB blocks, each with a 256-byte canonical Huffman code-length table (512 symbols x 4 bits). Symbols 0--255 are literals, 256 is EOF, 257--511 are matches. Match-length ladder: nibble -> byte -> uint16 -> uint32 (v10.0).

Authority: `[MS-XCA] §2.1/§2.2` v10.0. Available: Win8.1 through Server 2025.

### Compact XPRESS9 (0x0005)

10-byte header: u32 LE magic (`0xC039E510`) + u16 LE params (window log index and mode) + u32 LE control word (payload bit count, compressed flag, end-of-stream flag). Payload is a canonical-Huffman LZ77 bitstream (same algorithm as ESE XPRESS9) with a trailing 32-bit CRC-32C of the original plaintext. Uses a 2-bit Huffman table mode prefix (0 = stored flat lengths, 2 = Huffman-coded) instead of XPRESS9's 3-bit mode. Window sizes from 4 KB to 16 MB, controlled by the params field. DEFAULT and ENGINE_MAXIMUM produce identical output.

No public specification exists. Reverse-engineered from `ntdll.dll` Build 20348 (decompressor at RVA 0x111810, Huffman builder at 0x114DA8, header parser at 0x115AB0). Available: Server 2022+.

### XP10 (0x0006)

Standard LZ4 block format. Same payload as ESE scheme 0x6 and 0x7, without ESE framing. Available: Win11 / Server 2025.

### Raw DEFLATE (0x0007)

RFC 1951 raw DEFLATE bitstream, no zlib or gzip wrapper. Default engine matches level 1; ENGINE_MAXIMUM matches level 7. Available: Win11 / Server 2025.

### ZLIB (0x0008)

RFC 1950 ZLIB stream (2-byte header + DEFLATE + Adler-32 trailer). Default engine matches level 1; ENGINE_MAXIMUM matches level 7. Available: Win11 / Server 2025.
