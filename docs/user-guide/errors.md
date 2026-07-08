# Error handling

All exceptions inherit from `CompressionLibError`:

```
CompressionLibError
├── CompressionError
│   └── IncompressibleError
├── DecompressionError
│   ├── IntegrityError
│   └── ScrubDetectedError
└── FormatUnavailableError
```

All exceptions are importable from `ntcompress.exceptions`.

## CompressionLibError

Base class. Catch this to handle any error from the library:

```python
from ntcompress.exceptions import CompressionLibError

try:
    plaintext = ese.decompress(cell)
except CompressionLibError as e:
    print(e)
```

## DecompressionError

Raised when a compressed buffer cannot be decoded (truncated input, corrupt payload, unknown format ID):

```python
from ntcompress.exceptions import DecompressionError

try:
    plaintext = ese.decompress(cell)
except DecompressionError:
    print("corrupt or unrecognized cell")
```

## IntegrityError

Subclass of `DecompressionError`. Raised when a stored checksum does not match the decoded data. Applies to XPRESS9 (CRC-32C over plaintext) and XPRESS10 (CRC-32C over plaintext + CRC-64/NVME over payload):

```python
from ntcompress.exceptions import IntegrityError

try:
    plaintext = ese.decompress(cell)
except IntegrityError:
    print("checksum mismatch -- data is corrupt")
```

## ScrubDetectedError

Subclass of `DecompressionError`. Raised when the dispatcher encounters a SCRUB (0x4) erase marker. Use `ntcompress.ese.scrub` to inspect SCRUB cells:

```python
from ntcompress.exceptions import ScrubDetectedError
from ntcompress.ese import scrub

try:
    plaintext = ese.decompress(cell)
except ScrubDetectedError:
    record = scrub.parse_scrub(cell)
```

## CompressionError

Raised when input cannot be encoded (non-7-bit bytes for a 7-bit format, input exceeds the u16 size limit):

```python
from ntcompress.exceptions import CompressionError

try:
    cell = ese.compress(data, ese.Format.SEVEN_BIT_ASCII)
except CompressionError:
    print("input contains bytes > 0x7F")
```

## IncompressibleError

Subclass of `CompressionError`. Raised when the compressed output would not be smaller than the input. ESE stores such cells uncompressed:

```python
from ntcompress.exceptions import IncompressibleError

try:
    cell = ese.compress(data, ese.Format.XPRESS)
except IncompressibleError:
    pass  # store uncompressed
```

## FormatUnavailableError

Raised when a format is recognized but the requested operation is not supported:

```python
from ntcompress.exceptions import FormatUnavailableError

try:
    cell = ese.compress(data, ese.Format.NONE)
except FormatUnavailableError:
    pass
```
