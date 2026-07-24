# Getting started

## Installation

```bash
uv add ntcompress
```

```bash
pip install ntcompress
```

## ESE quickstart

ESE cells carry the compression format in the header byte. Decompression auto-detects:

```python
import ntcompress.ese as ese

plaintext = ese.decompress(cell)
size = ese.decompressed_size(cell)
```

Compression requires an explicit format:

```python
cell = ese.compress(plaintext, ese.Format.XPRESS)
cell = ese.compress(plaintext, ese.Format.LZ4)
cell = ese.compress(plaintext, ese.Format.XPRESS9)
```

Or use a format module directly:

```python
from ntcompress.ese import xpress

cell = xpress.compress(plaintext)
plaintext = xpress.decompress(cell)
size = xpress.decompressed_size(cell)
```

Read the format ID from a cell's header byte without decompressing:

```python
fmt_id = ese.format_id(cell[0])  # 5-bit format ID (0--31)
flags = ese.format_flags(cell[0])  # 3-bit format-specific flags
```

## ntdll quickstart

ntdll streams have no header. The caller must specify the format for both directions:

```python
import ntcompress.ntdll as ntdll

compressed = ntdll.compress(data, ntdll.Format.LZNT1)
plaintext = ntdll.decompress(compressed, ntdll.Format.LZNT1)
```

Windows `COMPRESSION_FORMAT_*` constant aliases are available:

```python
compressed = ntdll.compress(data, ntdll.COMPRESSION_FORMAT_XPRESS_HUFF)
plaintext = ntdll.decompress(compressed, ntdll.COMPRESSION_FORMAT_XPRESS_HUFF)
```

Or use a format module directly:

```python
from ntcompress.ntdll import lznt1, xpress9, xp10

compressed = lznt1.compress(data)
plaintext = lznt1.decompress(compressed)

plaintext = xpress9.decompress(stream)  # format 0x0005 (compact XPRESS9)
compressed = xp10.compress(data)  # format 0x0006 (LZ4 block)
```

Some ntdll formats accept additional parameters:

```python
from ntcompress.ntdll import deflate
from ntcompress.ntdll import zlib as ntdll_zlib

# level controls compression effort (default 1 matches ntdll default engine)
compressed = deflate.compress(data, level=7)  # matches ntdll ENGINE_MAXIMUM
compressed = ntdll_zlib.compress(data, level=7)

# max_size limits decoded output
plaintext = deflate.decompress(compressed, max_size=65536)
```
