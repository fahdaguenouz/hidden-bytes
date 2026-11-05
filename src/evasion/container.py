"""HBX1 container parsing, validation, and inspection.

An HBX1 container is laid out as::

    MAGIC (4 bytes) | header length (>I) | JSON header | ciphertext | padding

The JSON header carries the metadata required to recover the payload; the
ciphertext is AES-256-GCM output; the trailing padding is random filler used
for file-size manipulation and is ignored on read.

The header may also carry a ``kdf`` section. When present, the container key
is derived from a passphrase instead of being read from a sidecar key file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import BinaryIO
import math

from .constants import (
    GCM_TAG_SIZE,
    HEADER_SIZE,
    KDF_NAME,
    MAGIC,
    MAX_HEADER_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    MAX_KDF_ITERATIONS,
    MAX_DELAY_SECONDS,
)
from .encoding import b64_decode

REQUIRED_FIELDS = frozenset(
    {
        "algorithm",
        "ciphertext_length",
        "delay_seconds",
        "original_name",
        "original_size",
        "nonce",
    }
)

OPTIONAL_FIELDS = frozenset({"kdf"})


def _validate_kdf(kdf: object) -> None:
    """Validate the key-derivation metadata of a container header."""

    if not isinstance(kdf, dict):
        raise ValueError("kdf metadata must be a JSON object")

    if kdf.get("name") != KDF_NAME:
        raise ValueError(f"unsupported key derivation function: {kdf.get('name')!r}")

    
    iterations = kdf.get("iterations")
    
    if type(iterations) is not int:
        raise ValueError("kdf iteration count must be an integer")

    if not 1 <= iterations <= MAX_KDF_ITERATIONS:
        raise ValueError(
            f"kdf iteration count must be between 1 and {MAX_KDF_ITERATIONS}"
        )

    salt = b64_decode(kdf.get("salt", ""), "kdf salt")
    if len(salt) != SALT_SIZE:
        raise ValueError(
            f"invalid kdf salt length: expected {SALT_SIZE} bytes, got {len(salt)}"
        )


def validate_header(header: dict) -> None:
    """Validate the metadata required by an HBX1 container."""
    missing = REQUIRED_FIELDS - header.keys()
    if missing:
        raise ValueError(
            "container header is missing fields: " + ", ".join(sorted(missing))
        )

    unknown = header.keys() - REQUIRED_FIELDS - OPTIONAL_FIELDS
    if unknown:
        raise ValueError(
            "container header has unknown fields: " + ", ".join(sorted(unknown))
        )

    if header["algorithm"] != "AES-256-GCM":
        raise ValueError(
            f"unsupported encryption algorithm: {header['algorithm']!r}"
        )

    try:
        ciphertext_length = header["ciphertext_length"]
        original_size = header["original_size"]
        delay_seconds = header["delay_seconds"]
        
        if type(ciphertext_length) is not int:
             raise ValueError("ciphertext_length must be an integer")

        if type(original_size) is not int:
            raise ValueError("original_size must be an integer")

        if type(delay_seconds) not in (int, float):
            raise ValueError("delay_seconds must be a number")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid numeric value in container header") from exc

    if ciphertext_length < GCM_TAG_SIZE:
        raise ValueError(
            "ciphertext is too short to contain a GCM authentication tag"
        )
    if original_size < 0:
        raise ValueError("original_size cannot be negative")
    
    if delay_seconds < 0:
        raise ValueError("delay_seconds cannot be negative")
    
    if delay_seconds > MAX_DELAY_SECONDS:
        raise ValueError(
            f"delay_seconds cannot exceed {MAX_DELAY_SECONDS} seconds"
        )
    
    if not math.isfinite(delay_seconds):
        raise ValueError("delay_seconds must be finite")

    nonce = b64_decode(header["nonce"], "nonce")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"invalid nonce length: expected {NONCE_SIZE} bytes, "
            f"got {len(nonce)}"
        )

    if not isinstance(header["original_name"], str):
        raise ValueError("original_name must be a string")

    if "kdf" in header:
        _validate_kdf(header["kdf"])


def _decode_header(raw_header: bytes) -> dict:
    """Decode and validate the JSON header of a container."""

    try:
        header = json.loads(raw_header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON header") from exc

    if not isinstance(header, dict):
        raise ValueError("container header must be a JSON object")

    validate_header(header)

    return header


def parse_container(data: bytes) -> tuple[dict, bytes]:
    """Parse an HBX1 container held in memory and return ``(header, ciphertext)``."""

    if len(data) < len(MAGIC) + HEADER_SIZE.size:
        raise ValueError("invalid HBX1 container: truncated header")
    
    if data[:len(MAGIC)] != MAGIC:   
        raise ValueError("invalid HBX1 container: incorrect magic bytes")

    offset = len(MAGIC)
    header_length = HEADER_SIZE.unpack(
        data[offset:offset + HEADER_SIZE.size]
    )[0]
    offset += HEADER_SIZE.size

    if header_length > MAX_HEADER_SIZE:
        raise ValueError(f"header is too large: {header_length} bytes")

    raw_header = data[offset:offset + header_length]
    if len(raw_header) != header_length:
        raise EOFError("unexpected end of file: truncated header")

    header = _decode_header(raw_header)

    offset += header_length
    ciphertext_length = header["ciphertext_length"]
    ciphertext = data[offset:offset + ciphertext_length]
    if len(ciphertext) != ciphertext_length:
        raise EOFError(
            f"unexpected end of file: expected {ciphertext_length} bytes, "
            f"received {len(ciphertext)}"
        )

    return header, ciphertext


def _read_exact(handle: BinaryIO, size: int) -> bytes:
    """Read exactly ``size`` bytes or raise EOFError."""
    if size < 0:
        raise ValueError("size cannot be negative")

    data = handle.read(size)
    if len(data) != size:
        raise EOFError(
            f"unexpected end of file: expected {size} bytes, "
            f"received {len(data)}"
        )
    return data


def read_container(source: Path) -> tuple[dict, bytes]:
    """Read an HBX1 container and return ``(header, ciphertext)``."""
    if not source.is_file():
        raise ValueError(f"input file does not exist: {source}")

    with source.open("rb") as handle:
        if _read_exact(handle, len(MAGIC)) != MAGIC:
            raise ValueError("invalid HBX1 container: incorrect magic bytes")

        header_length = HEADER_SIZE.unpack(
            _read_exact(handle, HEADER_SIZE.size)
        )[0]

        if header_length > MAX_HEADER_SIZE:
            raise ValueError(f"header is too large: {header_length} bytes")

        raw_header = _read_exact(handle, header_length)
        header = _decode_header(raw_header)

        ciphertext = _read_exact(handle, header["ciphertext_length"])

    return header, ciphertext


def read_container_header(source: Path) -> dict:
    from .runner import is_runner, read_runner_header

    if is_runner(source):
        return read_runner_header(source)

    if not source.is_file():
        raise ValueError(f"input file does not exist: {source}")

    with source.open("rb") as handle:
        if _read_exact(handle, len(MAGIC)) != MAGIC:
            raise ValueError("invalid HBX1 container: incorrect magic bytes")

        header_length = HEADER_SIZE.unpack(
            _read_exact(handle, HEADER_SIZE.size)
        )[0]

        if header_length > MAX_HEADER_SIZE:
            raise ValueError(f"header is too large: {header_length} bytes")

        raw_header = _read_exact(handle, header_length)

    return _decode_header(raw_header)


def inspect_file(source: Path) -> dict:
    header = read_container_header(source)

    result = dict(header)
    result["artifact_type"] = "container"
    result["container_magic"] = MAGIC.decode("ascii")
    result["container_ciphertext_bytes"] = header["ciphertext_length"]
    result["container_size_bytes"] = source.stat().st_size

    return result
