# SPDX-License-Identifier: Apache-2.0
"""Shared type aliases used across both the ESE and ntdll subpackages."""

from __future__ import annotations

from typing import TypeAlias

Buffer: TypeAlias = bytes | bytearray | memoryview
"""Any read-only bytes-like input accepted by the codecs."""
