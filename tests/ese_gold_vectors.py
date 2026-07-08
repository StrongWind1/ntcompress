"""Centralized ESE gold vectors captured from esent.dll and the MIT C reference.

Every vector is a (cell_hex, plain_hex, format_id) tuple where cell_hex is the
exact bytes esent.dll wrote (or the C reference encoder produced) and plain_hex
is the known plaintext. Decompressing cell_hex MUST produce plain_hex byte-for-byte.

Sources:
  - Server 2022 Build 20348, EFV 8920, page size 8192 (7-bit ASCII, 7-bit Unicode, XPRESS)
  - Win11 Build 26100, EFV 9420, page size 8192 (LZ4)
  - MIT ESE C reference encoder (XPRESS9, signature normalized to 0x12345678)
"""

from __future__ import annotations

# Format IDs matching ntcompress.ese.Format values.
SEVEN_BIT_ASCII = 0x01
SEVEN_BIT_UNICODE = 0x02
XPRESS = 0x03
XPRESS9 = 0x05
XPRESS10 = 0x06
LZ4 = 0x07


def _hex(data: bytes) -> str:
    return data.hex()


# --- Plaintext generators (shared with individual test files) ---


def _highbit_rep(size: int) -> bytes:
    return bytes(0xC0 + (i % 16) for i in range(size))


def _highbit_mod64(size: int) -> bytes:
    return bytes(0x80 + (i % 64) for i in range(size))


def _mixed_high(size: int) -> bytes:
    return bytes(0xFF if i % 4 == 0 else 0x80 + (i % 32) for i in range(size))


# --- Gold vectors ---
# Each entry: (label, format_id, cell_hex, plain_hex)

VECTORS: list[tuple[str, int, str, str]] = [
    # ── 7-bit ASCII (0x1) — Server 2022 Build 20348 ──
    ("7bit_ascii_rand16", SEVEN_BIT_ASCII, "0fb151efea0649d967a24b44526f55", "31233d576e20526c67442e22246a5b2a"),
    ("7bit_ascii_text16", SEVEN_BIT_ASCII, "0f54741914afa7c76b9058febebb41", "54686520717569636b2062726f776e20"),
    ("7bit_ascii_41x16", SEVEN_BIT_ASCII, "0fc16030180c0683c16030180c0683", _hex(b"\x41" * 16)),
    ("7bit_ascii_gradient16", SEVEN_BIT_ASCII, "0f8080604028180e888462c168381e", _hex(bytes(range(16)))),
    # ── 7-bit Unicode (0x2) — Server 2022 Build 20348 ──
    ("7bit_unicode_zeros8", SEVEN_BIT_UNICODE, "1300000000", _hex(b"\x00" * 8)),
    ("7bit_unicode_zeros16", SEVEN_BIT_UNICODE, "1700000000000000", _hex(b"\x00" * 16)),
    ("7bit_unicode_zeros64", SEVEN_BIT_UNICODE, "1700000000000000000000000000000000000000000000000000000000", _hex(b"\x00" * 64)),
    # ── XPRESS (0x3) — Server 2022 Build 20348 ──
    ("xpress_zeros1024", XPRESS, "180004ffffff3f000007000ffffb03", _hex(b"\x00" * 1024)),
    ("xpress_41x1024", XPRESS, "180004ffffff3f414107000ffffb03", _hex(b"\x41" * 1024)),
    ("xpress_highbit_rep1024", XPRESS, "180004ff7f0000c0c1c2c3c4c5c6c7c8c9cacbcccdcecfc07f000fffec03", _hex(_highbit_rep(1024))),
    ("xpress_alt_aa55_1024", XPRESS, "180004ffffff1faa55aa0f000ffffa03", _hex(bytes(0xAA if i % 2 == 0 else 0x55 for i in range(1024)))),
    ("xpress_ascii_text1024", XPRESS, "1800040000000054686520717569636b2062726f776e20666f78206a756d7073206f7665722074ffff0f80f0006c617a7920646f672e2054680067010fffcc03", _hex((b"The quick brown fox jumps over the lazy dog. " * 23)[:1024])),
    ("xpress_runlength1024", XPRESS, "180004ffffff2a80800700ffe5810700e6820700ffe6830700e6", _hex(b"".join(bytes([0x80 + i]) * 256 for i in range(4)))),
    # ── XPRESS9 (0x5) — MIT C reference encoder (same code esent.dll links) ──
    # Session signature normalized to 0x12345678; esent.dll uses CRC32(__rdtsc())
    # which varies per call, but our decoder handles any valid signature.
    # Strings/export analysis of esent.dll (Server 2025 Build 26100) confirms
    # Xpress9 functions are statically linked — not exported, not callable via
    # P/Invoke. Decoder additionally validated against real Power BI XPRESS9 data
    # (see tests/test_powerbi_xpress9.py).
    ("xpress9_fox_360", XPRESS9, "28f83ea8df2ad7864e68010000d00200001b00060000000000eeadd4ba0000000015cc7f96000000e0c28229028e5c5932668d801127f6dcd92160c69e0702565cd972e08c803d37a69c107061c114011b86bc782260c29e39ba1addfe6d6f", _hex(b"the quick brown fox jumps over the lazy dog. " * 8)),
    ("xpress9_zeros_1000", XPRESS9, "2857da4dd82ad7864ee8030000470100001b0006000000000043718bbc0000000012e14ffa000000000020fca33b", _hex(bytes(1000))),
    (
        "xpress9_para_3656",
        XPRESS9,
        "28fca933392ad7864e480e0000030400004101060000000000cea7f001000000005ec0066e000020c266a6000040dcc56e12be7b5be1185559d57fe7dbc9d6e475a63af30600701fc17d040000466aa415fe0e710c9f016bf88443d64e48123a775f682f68b42d594583b84167ea52bd351abefc4512b547cac437c6eb197fd5edfe789e9700",
        _hex((b"Records in an ESE long value are chunked, compressed and checksummed before storage. " * 40 + b"\x00\x01\x02\x03" * 64)),
    ),
    # ── XPRESS10 (0x6) — LZ4 block from ntdll RtlCompressBufferXp10, Win11 Build 26100 ──
    # ESE XPRESS10 wraps a standard LZ4 block with a 15-byte header containing
    # CRC-32C of plaintext and CRC-64/NVME of the compressed payload.
    # The LZ4 block is byte-identical to ntdll format 0x0006 output.
    # Decompression verified byte-for-byte against RtlDecompressBufferEx(format=6)
    # on DC-SRV25-ZEUS (Server 2025 Build 26100).
    ("xpress10_pattern_4096", XPRESS10, "300010dc7a8d3d64ac36a16f0def11ff0b42434445464748494a4b4c4d4e4f505152535455565758595a411a00ffffffffffffffffffffffffffffffdd504b4c4d4e4f", _hex(bytes(0x41 + ((i + 1) % 26) for i in range(4096)))),
    # ── LZ4 (0x7) — Win11 Build 26100, EFV 9420 ──
    ("lz4_highbit_rep1024", LZ4, "380004ff01c0c1c2c3c4c5c6c7c8c9cacbcccdcecf1000ffffffdb50cbcccdcecf", _hex(_highbit_rep(1024))),
    ("lz4_highbit_mod64_1024", LZ4, "380004ff31808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf4000ffffffab50bbbcbdbebf", _hex(_highbit_mod64(1024))),
    ("lz4_mixed_high1024", LZ4, "380004ff11ff818283ff858687ff898a8bff8d8e8fff919293ff959697ff999a9bff9d9e9f2000ffffffcb509bff9d9e9f", _hex(_mixed_high(1024))),
    ("lz4_zeros1024", LZ4, "3800041f000100ffffffea500000000000", _hex(b"\x00" * 1024)),
    ("lz4_41x1024", LZ4, "3800041f410100ffffffea504141414141", _hex(b"\x41" * 1024)),
    ("lz4_highbit_rep4096", LZ4, "380010ff01c0c1c2c3c4c5c6c7c8c9cacbcccdcecf1000ffffffffffffffffffffffffffffffe750cbcccdcecf", _hex(_highbit_rep(4096))),
    ("lz4_zeros4096", LZ4, "3800101f000100fffffffffffffffffffffffffffffff6500000000000", _hex(b"\x00" * 4096)),
]
