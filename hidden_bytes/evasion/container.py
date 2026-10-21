"""HBX1 container parsing, validation, and inspection.

An HBX1 container is laid out as::

    MAGIC (4 bytes) | header length (>I) | JSON header | ciphertext | padding

The JSON header carries the metadata required to recover the payload; the
ciphertext is AES-256-GCM output; the trailing padding is random filler used
for file-size manipulation and is ignored on read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import BinaryIO

from .constants import (
    GCM_TAG_SIZE,
    HEADER_SIZE,
    MAGIC,
    MAX_HEADER_SIZE,
    NONCE_SIZE,
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


def validate_header(header: dict) -> None:
    """Validate the metadata required by an HBX1 container."""
    missing = REQUIRED_FIELDS - header.keys()
    if missing:
        raise ValueError(
            "container header is missing fields: " + ", ".join(sorted(missing))
        )

    if header["algorithm"] != "AES-256-GCM":
        raise ValueError(
            f"unsupported encryption algorithm: {header['algorithm']!r}"
        )

    try:
        ciphertext_length = int(header["ciphertext_length"])
        original_size = int(header["original_size"])
        delay_seconds = float(header["delay_seconds"])
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

    nonce = b64_decode(header["nonce"], "nonce")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"invalid nonce length: expected {NONCE_SIZE} bytes, "
            f"got {len(nonce)}"
        )

    if not isinstance(header["original_name"], str):
        raise ValueError("original_name must be a string")


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
        try:
            header = json.loads(raw_header.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON header") from exc

        if not isinstance(header, dict):
            raise ValueError("container header must be a JSON object")

        validate_header(header)

        ciphertext = _read_exact(handle, int(header["ciphertext_length"]))

    return header, ciphertext


def inspect_file(source: Path) -> dict:
    """Return HBX1 metadata without decrypting the payload."""
    header, ciphertext = read_container(source)

    result = dict(header)
    result["container_magic"] = MAGIC.decode("ascii")
    result["container_ciphertext_bytes"] = len(ciphertext)
    result["container_size_bytes"] = source.stat().st_size
    return result
