"""Per-OS gold-standard decompression and cross-build identity tests.

Verifies that every compressed vector captured from each Windows build
decompresses to the expected plaintext, and that all builds sharing a
format produce byte-identical compressed output.
"""

from __future__ import annotations

from collections import defaultdict

import pytest

from ntcompress.ntdll import deflate, lznt1, xpress, xpress_huff
from ntcompress.ntdll import zlib as ntdll_zlib
from tests.gold_vectors import OS_META, PLAIN_HEX, VECTORS

PLAIN = bytes.fromhex(PLAIN_HEX)

DECODERS: dict[int, object] = {
    0x0002: lznt1.decompress,
    0x0102: lznt1.decompress,
    0x0003: xpress.decompress,
    0x0103: xpress.decompress,
    0x0004: xpress_huff.decompress,
    0x0104: xpress_huff.decompress,
    0x0007: deflate.decompress,
    0x0107: deflate.decompress,
    0x0008: ntdll_zlib.decompress,
    0x0108: ntdll_zlib.decompress,
}


def _all_cases() -> list[tuple[str, int, str, bytes]]:
    """Build (os_slug, format_id, label, compressed_bytes) for every decodable vector."""
    cases = []
    for os_slug, fmts in sorted(VECTORS.items()):
        meta = OS_META[os_slug]
        for fmt_id, vec in sorted(fmts.items()):
            if fmt_id in DECODERS:
                label = f"{meta['description']}_Build{meta['build']}_0x{fmt_id:04X}"
                cases.append((os_slug, fmt_id, label, bytes.fromhex(vec["comp_hex"])))
    return cases


@pytest.mark.parametrize(
    ("os_slug", "fmt_id", "label", "comp"),
    _all_cases(),
    ids=lambda x: x if isinstance(x, str) else "",
)
def test_per_os_decompress(os_slug: str, fmt_id: int, label: str, comp: bytes) -> None:  # noqa: ARG001
    """Every per-OS vector decompresses to the exact plaintext."""
    decoder = DECODERS[fmt_id]
    assert decoder(comp) == PLAIN


def test_per_os_roundtrip_decomp_matches_plain() -> None:
    """Every stored decomp_hex matches the stored plain_hex exactly."""
    for os_slug, fmts in VECTORS.items():
        for fmt_id, vec in fmts.items():
            assert vec["decomp_hex"] == PLAIN_HEX, f"{os_slug} 0x{fmt_id:04X}: decomp_hex != plain_hex"


def test_cross_build_identity() -> None:
    """All builds sharing a format produce byte-identical compressed output."""
    by_fmt: dict[int, dict[str, str]] = defaultdict(dict)
    for os_slug, fmts in VECTORS.items():
        for fmt_id, vec in fmts.items():
            by_fmt[fmt_id][os_slug] = vec["comp_hex"]

    for fmt_id, os_map in sorted(by_fmt.items()):
        hexes = set(os_map.values())
        assert len(hexes) == 1, f"Format 0x{fmt_id:04X} has {len(hexes)} distinct outputs across {list(os_map.keys())}"


def test_vector_count() -> None:
    """Sanity check: we have the expected number of per-OS vectors."""
    total = sum(len(fmts) for fmts in VECTORS.values())
    assert total == 83
    assert len(VECTORS) == 15


def test_plaintext_matches() -> None:
    """The stored PLAIN_HEX matches the computed A-Z pattern."""
    assert bytes(0x41 + (i % 26) for i in range(1, 4097)) == PLAIN
