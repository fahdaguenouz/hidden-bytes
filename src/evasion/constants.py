"""Shared constants for the HBX1 container format."""

from __future__ import annotations

import struct

# Container format identifier. Also used as AES-GCM associated data so that
# tampering with the magic bytes makes authentication fail.
MAGIC = b"HBX1"

# Header length is stored as an unsigned big-endian 32-bit integer.
HEADER_SIZE = struct.Struct(">I")

MIB = 1024 * 1024

# Protect the parser from allocating/reading unreasonable metadata.
MAX_HEADER_SIZE = 1 * MIB

# AES-GCM uses a 12-byte nonce (standard recommended size).
NONCE_SIZE = 12

# AES-256 key size in bytes.
KEY_SIZE = 32

# GCM authentication tag size, included in AESGCM.encrypt() output.
GCM_TAG_SIZE = 16

# Key derivation used when a passphrase protects a container instead of a
# separate key file. PBKDF2-HMAC-SHA256 is available in the standard library,
# so the generated runner can derive the key without any third-party package.
KDF_NAME = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 200_000
SALT_SIZE = 16

# Identifier written in the header of the generated self-extracting runner.
RUNNER_MAGIC = b"HBX-RUNNER-V1"

# Name of the container file when the runner is packaged as a single
# executable (PyInstaller one-file mode).
RUNNER_CONTAINER_NAME = "payload.hbx"
