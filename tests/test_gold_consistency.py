"""Cross-function gold-standard consistency tests.

Every gold vector from both ESE and ntdll is run through ALL applicable public
API functions (Shape A dispatch, Shape B direct module, decompressed_size) to
prove they agree. A single test failure means two public functions disagree on
the same input.
"""

from __future__ import annotations

import pytest

from tests.ese_gold_vectors import VECTORS as ESE_VECTORS
from tests.gold_vectors import OS_META, PLAIN_HEX, VECTORS as NTDLL_VECTORS

# --- ESE cross-function tests ---

import ntcompress.ese as ese
from ntcompress.ese import lz4, sevenbit_ascii, sevenbit_unicode, xpress, xpress9, xpress10

_ESE_MODULES = {
    0x01: sevenbit_ascii,
    0x02: sevenbit_unicode,
    0x03: xpress,
    0x05: xpress9,
    0x06: xpress10,
    0x07: lz4,
}


@pytest.mark.parametrize(
    ("label", "fmt_id", "cell_hex", "plain_hex"),
    ESE_VECTORS,
    ids=[v[0] for v in ESE_VECTORS],
)
def test_ese_gold_shape_a_decompress(label, fmt_id, cell_hex, plain_hex):
    """Shape A dispatch decompresses every ESE gold vector correctly."""
    cell = bytes.fromhex(cell_hex)
    expected = bytes.fromhex(plain_hex)
    assert ese.decompress(cell) == expected


@pytest.mark.parametrize(
    ("label", "fmt_id", "cell_hex", "plain_hex"),
    ESE_VECTORS,
    ids=[v[0] for v in ESE_VECTORS],
)
def test_ese_gold_shape_a_decompressed_size(label, fmt_id, cell_hex, plain_hex):
    """Shape A decompressed_size matches plaintext length for every ESE gold vector."""
    cell = bytes.fromhex(cell_hex)
    expected_len = len(bytes.fromhex(plain_hex))
    assert ese.decompressed_size(cell) == expected_len


@pytest.mark.parametrize(
    ("label", "fmt_id", "cell_hex", "plain_hex"),
    [v for v in ESE_VECTORS if v[1] in _ESE_MODULES],
    ids=[v[0] for v in ESE_VECTORS if v[1] in _ESE_MODULES],
)
def test_ese_gold_shape_b_decompress(label, fmt_id, cell_hex, plain_hex):
    """Shape B direct module decompresses every ESE gold vector correctly."""
    cell = bytes.fromhex(cell_hex)
    expected = bytes.fromhex(plain_hex)
    module = _ESE_MODULES[fmt_id]
    assert module.decompress(cell) == expected


@pytest.mark.parametrize(
    ("label", "fmt_id", "cell_hex", "plain_hex"),
    [v for v in ESE_VECTORS if v[1] in _ESE_MODULES],
    ids=[v[0] for v in ESE_VECTORS if v[1] in _ESE_MODULES],
)
def test_ese_gold_shape_b_decompressed_size(label, fmt_id, cell_hex, plain_hex):
    """Shape B decompressed_size matches plaintext length for every ESE gold vector."""
    cell = bytes.fromhex(cell_hex)
    expected_len = len(bytes.fromhex(plain_hex))
    module = _ESE_MODULES[fmt_id]
    assert module.decompressed_size(cell) == expected_len


@pytest.mark.parametrize(
    ("label", "fmt_id", "cell_hex", "plain_hex"),
    [v for v in ESE_VECTORS if v[1] in _ESE_MODULES],
    ids=[v[0] for v in ESE_VECTORS if v[1] in _ESE_MODULES],
)
def test_ese_gold_shape_a_and_b_agree(label, fmt_id, cell_hex, plain_hex):
    """Shape A and Shape B produce identical output for every ESE gold vector."""
    cell = bytes.fromhex(cell_hex)
    module = _ESE_MODULES[fmt_id]
    assert ese.decompress(cell) == module.decompress(cell)
    assert ese.decompressed_size(cell) == module.decompressed_size(cell)


@pytest.mark.parametrize(
    ("label", "fmt_id", "cell_hex", "plain_hex"),
    [v for v in ESE_VECTORS if v[1] in _ESE_MODULES],
    ids=[v[0] for v in ESE_VECTORS if v[1] in _ESE_MODULES],
)
def test_ese_gold_compress_roundtrip(label, fmt_id, cell_hex, plain_hex):
    """Compressing the gold plaintext and decompressing produces the original."""
    plain = bytes.fromhex(plain_hex)
    module = _ESE_MODULES[fmt_id]
    recompressed = module.compress(plain)
    assert module.decompress(recompressed) == plain


# --- ntdll cross-function tests ---

import ntcompress.ntdll as ntdll
from ntcompress.ntdll import deflate, lznt1, xpress as ntdll_xpress, xpress_huff
from ntcompress.ntdll import zlib as ntdll_zlib

_NTDLL_DECODERS = {
    0x0002: (ntdll.Format.LZNT1, lznt1),
    0x0102: (ntdll.Format.LZNT1, lznt1),
    0x0003: (ntdll.Format.XPRESS, ntdll_xpress),
    0x0103: (ntdll.Format.XPRESS, ntdll_xpress),
    0x0004: (ntdll.Format.XPRESS_HUFF, xpress_huff),
    0x0104: (ntdll.Format.XPRESS_HUFF, xpress_huff),
    0x0007: (ntdll.Format.DEFLATE, deflate),
    0x0107: (ntdll.Format.DEFLATE, deflate),
    0x0008: (ntdll.Format.ZLIB, ntdll_zlib),
    0x0108: (ntdll.Format.ZLIB, ntdll_zlib),
}

PLAIN = bytes.fromhex(PLAIN_HEX)


def _ntdll_cases():
    cases = []
    for os_slug, fmts in sorted(NTDLL_VECTORS.items()):
        meta = OS_META[os_slug]
        for fmt_id, vec in sorted(fmts.items()):
            if fmt_id in _NTDLL_DECODERS:
                label = f"{meta['description']}_Build{meta['build']}_0x{fmt_id:04X}"
                cases.append((label, fmt_id, vec["comp_hex"]))
    return cases


@pytest.mark.parametrize(
    ("label", "fmt_id", "comp_hex"),
    _ntdll_cases(),
    ids=[c[0] for c in _ntdll_cases()],
)
def test_ntdll_gold_shape_a_decompress(label, fmt_id, comp_hex):
    """Shape A dispatch decompresses every ntdll gold vector correctly."""
    fmt, _ = _NTDLL_DECODERS[fmt_id]
    assert ntdll.decompress(bytes.fromhex(comp_hex), fmt) == PLAIN


@pytest.mark.parametrize(
    ("label", "fmt_id", "comp_hex"),
    _ntdll_cases(),
    ids=[c[0] for c in _ntdll_cases()],
)
def test_ntdll_gold_shape_b_decompress(label, fmt_id, comp_hex):
    """Shape B direct module decompresses every ntdll gold vector correctly."""
    _, module = _NTDLL_DECODERS[fmt_id]
    assert module.decompress(bytes.fromhex(comp_hex)) == PLAIN


@pytest.mark.parametrize(
    ("label", "fmt_id", "comp_hex"),
    _ntdll_cases(),
    ids=[c[0] for c in _ntdll_cases()],
)
def test_ntdll_gold_shape_a_and_b_agree(label, fmt_id, comp_hex):
    """Shape A and Shape B produce identical output for every ntdll gold vector."""
    fmt, module = _NTDLL_DECODERS[fmt_id]
    comp = bytes.fromhex(comp_hex)
    assert ntdll.decompress(comp, fmt) == module.decompress(comp)
