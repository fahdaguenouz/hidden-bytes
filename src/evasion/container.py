"""HBX1 container parsing, validation, and inspection.

An HBX1 container is laid out as::

    MAGIC (4 bytes) | header length (>I) | JSON header | ciphertext | padding

The JSON header carries the metadata required to recover the payload; the
ciphertext is AES-256-GCM output; the trailing padding is random filler used
for file-size manipulation and is ignored on read.

Each container is protected by a randomly generated 256-bit AES key. The key
is never stored inside the container itself: a self-extracting runner embeds it
in its launcher, while a standalone ``.hbx`` container keeps it in a sidecar
``.key`` file. Either way the key is required to recover the payload.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import BinaryIO
import math

from .constants import (
    GCM_TAG_SIZE,
    HEADER_SIZE,
    MAGIC,
    MAX_HEADER_SIZE,
    NONCE_SIZE,
)
from .encoding import b64_decode

from ..common import MAX_DELAY_SECONDS

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

    unknown = header.keys() - REQUIRED_FIELDS
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


    if not math.isfinite(delay_seconds):
        raise ValueError("delay_seconds must be finite")

    if delay_seconds < 0:
        raise ValueError("delay_seconds cannot be negative")

    if delay_seconds > MAX_DELAY_SECONDS:
        raise ValueError(
            f"delay_seconds cannot exceed {MAX_DELAY_SECONDS} seconds"
        )

    nonce = b64_decode(header["nonce"], "nonce")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"invalid nonce length: expected {NONCE_SIZE} bytes, "
            f"got {len(nonce)}"
        )

    if not isinstance(header["original_name"], str):
        raise ValueError("original_name must be a string")


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


def _read_header_from_handle(handle: BinaryIO) -> dict:
    """Read, size-guard and validate the HBX1 header from an open handle.

    This is the single place the magic check, the big-endian length field and
    the ``MAX_HEADER_SIZE`` guard live, shared by the in-memory parser and the
    file readers so the rules cannot drift apart between them.
    """

    if _read_exact(handle, len(MAGIC)) != MAGIC:
        raise ValueError("invalid HBX1 container: incorrect magic bytes")

    header_length = HEADER_SIZE.unpack(_read_exact(handle, HEADER_SIZE.size))[0]

    if header_length > MAX_HEADER_SIZE:
        raise ValueError(f"header is too large: {header_length} bytes")

    raw_header = _read_exact(handle, header_length)
    return _decode_header(raw_header)


def parse_container(data: bytes) -> tuple[dict, bytes]:
    """Parse an HBX1 container held in memory and return ``(header, ciphertext)``."""

    handle = io.BytesIO(data)
    header = _read_header_from_handle(handle)
    ciphertext = _read_exact(handle, header["ciphertext_length"])

    return header, ciphertext


def read_container(source: Path) -> tuple[dict, bytes]:
    """Read an HBX1 container and return ``(header, ciphertext)``."""
    if not source.is_file():
        raise ValueError(f"input file does not exist: {source}")

    with source.open("rb") as handle:
        header = _read_header_from_handle(handle)
        ciphertext = _read_exact(handle, header["ciphertext_length"])

    return header, ciphertext


def read_container_header(source: Path) -> dict:
    from .runner import is_runner, read_runner_header

    if is_runner(source):
        return read_runner_header(source)

    if not source.is_file():
        raise ValueError(f"input file does not exist: {source}")

    with source.open("rb") as handle:
        return _read_header_from_handle(handle)


def inspect_file(source: Path) -> dict:
    from .runner import is_runner

    header = read_container_header(source)

    result = dict(header)
    result["container_ciphertext_bytes"] = header["ciphertext_length"]

    if is_runner(source):
        result["artifact_type"] = "runner"
        result["artifact_size_bytes"] = source.stat().st_size
    else:
        result["artifact_type"] = "container"
        result["container_magic"] = MAGIC.decode("ascii")
        result["container_size_bytes"] = source.stat().st_size

    return result
