"""Safe evasion / HBX1 authenticated packaging tool.

Public API re-exported for convenience and backwards compatibility with the
previous single-module layout.
"""

from __future__ import annotations

# ``time`` is re-exported so tests can monkeypatch
# ``hidden_bytes.evasion.time.sleep``; crypto.py imports the same module object.
import time

from .constants import (
    GCM_TAG_SIZE,
    HEADER_SIZE,
    KEY_SIZE,
    MAGIC,
    MAX_HEADER_SIZE,
    MIB,
    NONCE_SIZE,
)
from .container import inspect_file, read_container, validate_header
from .crypto import decrypt_file, encrypt_file, load_key
from .cli import build_parser, main

__all__ = [
    "GCM_TAG_SIZE",
    "HEADER_SIZE",
    "KEY_SIZE",
    "MAGIC",
    "MAX_HEADER_SIZE",
    "MIB",
    "NONCE_SIZE",
    "build_parser",
    "decrypt_file",
    "encrypt_file",
    "inspect_file",
    "load_key",
    "main",
    "read_container",
    "time",
    "validate_header",
]
