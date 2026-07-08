# ntcompress

Pure-Python implementations of every Microsoft ESE record-compression format and Windows `ntdll.dll` `RtlCompressBuffer`/`RtlDecompressBuffer` format. No runtime dependencies beyond the standard library.

Every decompress function is validated byte-identical against real Windows output. The test suite carries **107 gold vectors** captured from `esent.dll` and `ntdll.dll` across **16 Windows builds** (XP SP3 through Server 2025). Decompressing any gold vector produces the exact same bytes as the Windows API.

## ESE record compression

| ESE ID | Format | Decompress | Compress | Verified against | Gold vectors |
|--------|--------|-----------|----------|-----------------|--------------|
| `0x0` | NONE | -- | -- | -- | -- |
| `0x1` | 7-bit ASCII | yes | yes | esent.dll Server 2022 | 4 |
| `0x2` | 7-bit Unicode | yes | yes | esent.dll Server 2022 | 3 |
| `0x3` | XPRESS (Plain LZ77) | yes | yes | esent.dll Server 2022 | 6 |
| `0x4` | SCRUB (erase marker) | produce | recognize | n/a | -- |
| `0x5` | XPRESS9 | yes | yes | MIT C reference + Power BI* | 3 + fixture |
| `0x6` | XPRESS10 (LZ4 + CRC) | yes | yes | ntdll.dll Server 2025** | 1 |
| `0x7` | LZ4 (standard block) | yes | yes | esent.dll Win11 26100 | 7 |

\*XPRESS9 vectors come from the MIT-licensed C reference encoder — the same source code that `esent.dll` statically links. PE export and strings analysis of `esent.dll` (Server 2025 Build 26100) confirms the XPRESS9 functions (`Xpress9DecoderCreate`, `Xpress9EncoderCreate`, etc.) are statically linked and not exported — no public Windows API can invoke the codec directly. The decoder is additionally validated against a 2 MB real-world XPRESS9 stream from a Power BI DataModel file (Microsoft Analysis Services, `Hugoberry/pbixray` on GitHub). The public ESE API never enables XPRESS9 compression (`compressXpress9` is defined but never set in `fldmod.cxx:CalculateCompressFlags`); XPRESS9 cells in the wild originate from internal Microsoft code paths.

\*\*XPRESS10 decompression is verified byte-for-byte against `RtlDecompressBufferEx(format=0x0006)` on Server 2025 Build 26100 (DC-SRV25-ZEUS). The gold vector uses a real LZ4 block compressed by `RtlCompressBufferXp10` on the same build, wrapped with the ESE 15-byte header (CRC-32C + CRC-64/NVME). ESE-side XPRESS10 compression requires Corsica/QAT hardware (`g_fAllowXpress10SoftwareCompression = fFalse` in production).

## ntdll compression

| ntdll ID | Format | Decompress | Compress | Verified against | Gold vectors | Windows builds |
|----------|--------|-----------|----------|-----------------|--------------|----------------|
| `0x0002` | LZNT1 | yes | yes | ntdll.dll | 27 | 14 (XP SP3 -- Server 2025) |
| `0x0003` | XPRESS (Plain LZ77) | yes | yes | ntdll.dll | 18 | 8 (Win8.1 -- Server 2025) |
| `0x0004` | XPRESS_HUFF (LZ77+Huffman) | yes | yes | ntdll.dll | 18 | 8 (Win8.1 -- Server 2025) |
| `0x0006` | XP10 (LZ4 block) | yes | yes | ntdll.dll | 4 | 2 (Win11 / Server 2025) |
| `0x0007` | raw DEFLATE | yes | yes | ntdll.dll | 4 | 2 (Win11 / Server 2025) |
| `0x0008` | ZLIB | yes | yes | ntdll.dll | 4 | 2 (Win11 / Server 2025) |

Each ntdll format is tested with output from both `COMPRESSION_ENGINE_DEFAULT` and `COMPRESSION_ENGINE_MAXIMUM` where available, proving the decoder handles every compression level the Windows API produces.

## Install

```bash
uv add ntcompress
```

```bash
pip install ntcompress
```

Requires Python >= 3.11.

## Quick example

```python
import ntcompress.ese as ese

cell = ese.compress(b"Hello, World! " * 100, ese.Format.XPRESS)
plaintext = ese.decompress(cell)
```

```python
import ntcompress.ntdll as ntdll

compressed = ntdll.compress(b"Hello, World! " * 100, ntdll.Format.LZNT1)
plaintext = ntdll.decompress(compressed, ntdll.Format.LZNT1)
```
