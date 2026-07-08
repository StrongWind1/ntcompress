"""Verify XPRESS9 decompression against a real Power BI DataModel.

The fixture is a raw XPRESS9 block extracted from a Power BI .pbix file
(Hugoberry/pbixray ``ols-sample-report.pbix``, DataModel entry). Power BI's
Analysis Services engine uses the same XPRESS9 codec as esent.dll — same block
magic (0x4E86D72A), same header structure, same Huffman+LZ77 encoding.

Strings and PE export analysis of esent.dll (Server 2025 Build 26100) confirms
XPRESS9 functions (Xpress9DecoderCreate, Xpress9EncoderCreate, etc.) are
statically linked — not exported, not callable via P/Invoke. No ntdll.dll
equivalent exists either. The codec cannot be invoked directly through any
public Windows API, so this Power BI fixture is the strongest available
real-world validation outside the MIT C reference vectors.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from ntcompress.ese import xpress9
from ntcompress.ese.checksums import crc32c_ese

FIXTURE = Path(__file__).parent / "fixtures" / "powerbi_xpress9_block.bin"

EXPECTED_BLOCK_SHA256 = "bd799f556155f35573a1a541aaf13615f8f26169dab6c20f975382256da337f3"
EXPECTED_PLAIN_SHA256 = "afdda4a7bba2b50a2af6807280be932ffff1204cd8d2ce1d24100aad5ef84aff"
EXPECTED_PLAIN_CRC32C = 0x6444EBA9
EXPECTED_PLAIN_SIZE = 2015232


@pytest.fixture()
def xpress9_block() -> bytes:
    """Load the Power BI XPRESS9 block fixture."""
    if not FIXTURE.exists():
        pytest.skip("Power BI XPRESS9 fixture not found")
    return FIXTURE.read_bytes()


def test_fixture_integrity(xpress9_block: bytes) -> None:
    """The fixture file has not been corrupted since capture."""
    assert hashlib.sha256(xpress9_block).hexdigest() == EXPECTED_BLOCK_SHA256


def test_decompress(xpress9_block: bytes) -> None:
    """Our decoder decompresses a real Power BI XPRESS9 stream correctly."""
    cell = b"\x28" + struct.pack("<I", 0) + xpress9_block
    result = xpress9.decompress(cell, verify=False)
    assert len(result) == EXPECTED_PLAIN_SIZE


def test_decompress_crc_verified(xpress9_block: bytes) -> None:
    """Decompressed plaintext CRC-32C matches the independently computed value."""
    cell = b"\x28" + struct.pack("<I", 0) + xpress9_block
    result = xpress9.decompress(cell, verify=False)
    crc = crc32c_ese(result)
    assert crc == EXPECTED_PLAIN_CRC32C

    proper_cell = b"\x28" + struct.pack("<I", crc) + xpress9_block
    result2 = xpress9.decompress(proper_cell, verify=True)
    assert result2 == result


def test_plaintext_sha256(xpress9_block: bytes) -> None:
    """Decompressed plaintext SHA-256 matches the pinned hash."""
    cell = b"\x28" + struct.pack("<I", 0) + xpress9_block
    result = xpress9.decompress(cell, verify=False)
    assert hashlib.sha256(result).hexdigest() == EXPECTED_PLAIN_SHA256


def test_decompressed_size(xpress9_block: bytes) -> None:
    """decompressed_size() returns the correct value for a real XPRESS9 stream."""
    cell = b"\x28" + struct.pack("<I", 0) + xpress9_block
    assert xpress9.decompressed_size(cell) == EXPECTED_PLAIN_SIZE
