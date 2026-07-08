# ESE format modules

## 7-bit ASCII (0x1)

::: ntcompress.ese.sevenbit_ascii

## 7-bit Unicode (0x2)

::: ntcompress.ese.sevenbit_unicode

## XPRESS (0x3)

::: ntcompress.ese.xpress

## XPRESS9 (0x5)

::: ntcompress.ese.xpress9
    options:
      members:
        - compress
        - decompress
        - decompressed_size
        - parse_block_header
        - Xpress9BlockHeader
        - HEADER_SIZE
        - BLOCK_HEADER_SIZE
        - XPRESS9_MAGIC

## XPRESS10 (0x6)

::: ntcompress.ese.xpress10

## LZ4 (0x7)

::: ntcompress.ese.lz4

## SCRUB (0x4)

::: ntcompress.ese.scrub
