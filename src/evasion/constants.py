"""Shared constants for the HBX1 container and runner formats.

``KEY_SIZE`` and ``NONCE_SIZE`` are re-exported from ``common`` so the rest of
the package can import every size from one place.
"""

from __future__ import annotations

import struct

from ..common import KEY_SIZE, NONCE_SIZE

# Container format identifier. Also used as AES-GCM associated data so that
# tampering with the magic bytes makes authentication fail.
MAGIC = b"HBX1"

# Header length is stored as an unsigned big-endian 32-bit integer.
HEADER_SIZE = struct.Struct(">I")

# One mebibyte, in bytes.
MIB = 1024 * 1024

# Protect the parser from allocating/reading unreasonable metadata.
MAX_HEADER_SIZE = 1 * MIB

# GCM authentication tag size, included in AESGCM.encrypt() output.
GCM_TAG_SIZE = 16

# Identifier written in the header of the generated self-extracting runner.
RUNNER_MAGIC = b"HBX-RUNNER-V1"

# Name of the container file when the runner is packaged as a single
# executable (PyInstaller one-file mode).
RUNNER_CONTAINER_NAME = "payload.hbx"

__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "MAGIC",
    "HEADER_SIZE",
    "MIB",
    "MAX_HEADER_SIZE",
    "GCM_TAG_SIZE",
    "RUNNER_MAGIC",
    "RUNNER_CONTAINER_NAME",
]

