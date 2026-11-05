

from __future__ import annotations

import struct

from ..common import KDF_ITERATIONS, KDF_NAME, KEY_SIZE, NONCE_SIZE, SALT_SIZE

# Container format identifier. Also used as AES-GCM associated data so that
# tampering with the magic bytes makes authentication fail.
MAGIC = b"HBX1"

# Header length is stored as an unsigned big-endian 32-bit integer.
HEADER_SIZE = struct.Struct(">I")

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

MAX_KDF_ITERATIONS = 1_000_000


