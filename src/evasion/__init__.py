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
    RUNNER_CONTAINER_NAME,
    RUNNER_MAGIC,
)
from .container import (
    inspect_file,
    parse_container,
    read_container_header,
    validate_header,
)
from .crypto import (
    build_payload,
    decrypt_file,
    decrypt_payload,
)
from .runner import (
    build_executable,
    build_executable_from_source,
    build_runner_file,
    is_runner,
    read_runner_container,
    read_runner_header,
    read_runner_key,
    render_runner,
    write_launcher,
)
from .cli import build_parser, main

__all__ = [
    "GCM_TAG_SIZE",
    "HEADER_SIZE",
    "KEY_SIZE",
    "MAGIC",
    "MAX_HEADER_SIZE",
    "MIB",
    "NONCE_SIZE",
    "RUNNER_CONTAINER_NAME",
    "RUNNER_MAGIC",
    "build_executable",
    "build_executable_from_source",
    "build_parser",
    "build_payload",
    "build_runner_file",
    "decrypt_file",
    "decrypt_payload",
    "inspect_file",
    "is_runner",
    "main",
    "parse_container",
    "read_container_header",
    "read_runner_container",
    "read_runner_header",
    "read_runner_key",
    "render_runner",
    "time",
    "validate_header",
    "write_launcher",
]
