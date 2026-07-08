"""Exception hierarchy for :mod:`ntcompress`.

All errors derive from :class:`CompressionLibError`, so callers can catch the whole
library with a single ``except``. The hierarchy separates decode-time from encode-time
failures and carries semantically meaningful leaf types: checksum mismatches, the SCRUB
erase marker, incompressible input, and formats that are recognized but not implemented.
"""

from __future__ import annotations


class CompressionLibError(Exception):
    """Base class for every error raised by :mod:`ntcompress`."""


class DecompressionError(CompressionLibError):
    """Raised when a compressed buffer cannot be decoded."""


class CompressionError(CompressionLibError):
    """Raised when input cannot be encoded by the requested format."""


class IntegrityError(DecompressionError):
    """Raised when a stored checksum does not match the decoded data.

    Applies to formats that carry checksums in their header, for example the
    XPRESS10 CRC-32C over the plaintext and CRC-64 over the payload.
    """


class ScrubDetectedError(DecompressionError):
    """Raised when a record uses the SCRUB (0x4) format.

    SCRUB is not a codec: it marks a long-value chunk that database maintenance or
    repair has overwritten with a known fill pattern, so there is no original
    plaintext to recover. Callers should handle this case explicitly.
    """


class IncompressibleError(CompressionError):
    """Raised when a compressor cannot shrink the input below the ESE threshold.

    ESE stores a compressed cell only when the compressed payload plus its header
    is strictly smaller than the original; otherwise the cell is stored
    uncompressed. Encoders surface that policy through this error.
    """


class FormatUnavailableError(CompressionLibError):
    """Raised when a format is recognized but cannot be decoded.

    Either no codec is registered for the format, or a registered codec does not
    support the requested operation (e.g. a decode-only format asked to compress).
    """
