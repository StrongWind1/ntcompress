"""Internal dispatch table for ESE compression formats.

Maps :class:`Format` enum members to the modules that implement them. Each codec
module is imported and registered when :mod:`ntcompress.ese` is first loaded.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ntcompress.exceptions import FormatUnavailableError

if TYPE_CHECKING:
    from types import ModuleType

    from ntcompress.ese import Format

_CODECS: dict[Format, ModuleType] = {}


def _register(fmt: Format, module: ModuleType) -> None:
    """Register a codec module for a given format."""
    _CODECS[fmt] = module


def _get(fmt: Format) -> ModuleType:
    """Look up the codec module for a format, or raise."""
    module = _CODECS.get(fmt)
    if module is None:
        msg = f"no codec registered for ESE format {fmt.name} (0x{fmt.value:x})"
        raise FormatUnavailableError(msg)
    return module
