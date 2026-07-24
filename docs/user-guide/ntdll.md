# ntdll compression

`ntcompress.ntdll` implements the compression formats exposed by Windows `ntdll.dll` through `RtlCompressBuffer` and `RtlDecompressBuffer`. These are raw bitstreams with no ESE framing.

## Dispatch API

Both `compress()` and `decompress()` require an explicit format -- raw ntdll streams have no format header:

```python
import ntcompress.ntdll as ntdll

compressed = ntdll.compress(data, ntdll.Format.LZNT1)
plaintext = ntdll.decompress(compressed, ntdll.Format.LZNT1)
```

The `Format` enum values match the `COMPRESSION_FORMAT_*` constants from `ntifs.h`:

| Member | Value | Constant | Description |
|--------|-------|----------|-------------|
| `LZNT1` | `0x0002` | `COMPRESSION_FORMAT_LZNT1` | Chunk-based LZ77 |
| `XPRESS` | `0x0003` | `COMPRESSION_FORMAT_XPRESS` | Plain LZ77 |
| `XPRESS_HUFF` | `0x0004` | `COMPRESSION_FORMAT_XPRESS_HUFF` | LZ77+Huffman |
| `XPRESS9` | `0x0005` | *(undocumented)* | Compact XPRESS9 (Huffman LZ77) |
| `XP10` | `0x0006` | *(undocumented)* | Raw LZ4 block |
| `DEFLATE` | `0x0007` | *(undocumented)* | Raw DEFLATE (RFC 1951) |
| `ZLIB` | `0x0008` | *(undocumented)* | ZLIB wrapper (RFC 1950) |

All values are the real `CompressionFormatAndEngine` base-format constants from Windows. Formats 0x0005--0x0008 are not documented in `ntifs.h` but are implemented in `ntdll.dll` on the builds listed above.

## Windows constant aliases

```python
import ntcompress.ntdll as ntdll

compressed = ntdll.compress(data, ntdll.COMPRESSION_FORMAT_LZNT1)
compressed = ntdll.compress(data, ntdll.COMPRESSION_FORMAT_XPRESS)
compressed = ntdll.compress(data, ntdll.COMPRESSION_FORMAT_XPRESS_HUFF)
```

## Direct module access

```python
from ntcompress.ntdll import lznt1

compressed = lznt1.compress(data)
plaintext = lznt1.decompress(compressed)

from ntcompress.ntdll import xpress_huff

compressed = xpress_huff.compress(data)
plaintext = xpress_huff.decompress(compressed)
```

Available modules: `lznt1`, `xpress`, `xpress_huff`, `xpress9`, `xp10`, `deflate`, `zlib`.

## Format-specific parameters

Some formats accept additional parameters:

```python
from ntcompress.ntdll import xpress, deflate
from ntcompress.ntdll import zlib as ntdll_zlib

# max_size limits decoded output (prevents decompression bombs)
plaintext = xpress.decompress(compressed, max_size=65536)
plaintext = deflate.decompress(compressed, max_size=65536)

# level controls compression effort (default 1 matches ntdll default engine)
compressed = deflate.compress(data, level=7)  # matches ntdll ENGINE_MAXIMUM
compressed = ntdll_zlib.compress(data, level=7)
```

There is no `decompressed_size()` on the ntdll side -- raw streams do not encode the output length.
