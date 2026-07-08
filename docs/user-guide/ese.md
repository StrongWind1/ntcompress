# ESE compression

`ntcompress.ese` implements every ESE record-compression format (schemes 0x0--0x7).

## Dispatch API

Compress and decompress ESE cells by format enum:

```python
import ntcompress.ese as ese

cell = ese.compress(data, ese.Format.XPRESS)
plaintext = ese.decompress(cell)                    # auto-detects format
plaintext = ese.decompress(cell, ese.Format.XPRESS) # explicit format
size = ese.decompressed_size(cell)
```

The `Format` enum carries the wire values from the ESE header byte:

| Member | Value | Description |
|--------|-------|-------------|
| `NONE` | `0x00` | Uncompressed sentinel |
| `SEVEN_BIT_ASCII` | `0x01` | 7-bit ASCII packing |
| `SEVEN_BIT_UNICODE` | `0x02` | 7-bit Unicode packing |
| `XPRESS` | `0x03` | Plain LZ77 with ESE frame |
| `SCRUB` | `0x04` | Erase marker (not a compression format) |
| `XPRESS9` | `0x05` | LZ77+Huffman9 with ESE frame |
| `XPRESS10` | `0x06` | LZ4 block + CRC integrity |
| `LZ4` | `0x07` | LZ4 block with ESE frame |
| `MAXIMUM` | `0x1F` | Sentinel (upper bound of 5-bit space) |

`NONE`, `SCRUB`, and `MAXIMUM` raise errors when passed to `compress()` or `decompress()`. The SCRUB error message points to `ntcompress.ese.scrub`.

## Direct module access

Each format is a separate module with `compress()`, `decompress()`, and `decompressed_size()`:

```python
from ntcompress.ese import xpress
cell = xpress.compress(data)
plaintext = xpress.decompress(cell)
size = xpress.decompressed_size(cell)
```

Available modules: `sevenbit_ascii`, `sevenbit_unicode`, `xpress`, `xpress9`, `xpress10`, `lz4`.

Formats with integrity checksums accept a `verify` parameter on `decompress()`:

```python
from ntcompress.ese import xpress10
plaintext = xpress10.decompress(cell, verify=True)   # default
plaintext = xpress10.decompress(cell, verify=False)  # skip CRC checks
```

## Format detection

Read format information from an ESE cell's header byte:

```python
import ntcompress.ese as ese

fmt_id = ese.format_id(cell[0])     # 5-bit format ID
flags = ese.format_flags(cell[0])   # 3-bit format-specific flags
header = ese.header_byte(ese.Format.XPRESS, flags=0)  # build a header byte
```

## SCRUB handling

SCRUB (0x4) is an erase marker, not a compression format. Use the `scrub` module directly:

```python
from ntcompress.ese import scrub

if scrub.is_scrub(cell):
    record = scrub.parse_scrub(cell)
    print(record.erased_length, record.fill_byte, record.known_fill)

cell = scrub.make_scrub(length=256, fill=scrub.ScrubFill.DB_MAINT_LV_CHUNK)
```

## Checksums

ESE XPRESS10 cells use CRC-32C and CRC-64/NVME checksums:

```python
from ntcompress.ese.checksums import crc32c_ese, crc64_ese

crc32 = crc32c_ese(data)   # CRC-32C (Castagnoli)
crc64 = crc64_ese(data)    # CRC-64/NVME
```
