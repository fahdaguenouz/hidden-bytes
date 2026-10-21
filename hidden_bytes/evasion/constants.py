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
