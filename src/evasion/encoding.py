"""Base64 encoding helpers with strict validation."""

from __future__ import annotations

import base64
import binascii


def b64_encode(value: bytes) -> str:
    """Encode bytes as ASCII Base64."""
    return base64.b64encode(value).decode("ascii")


def b64_decode(value: str, field_name: str) -> bytes:
    """Decode Base64 metadata safely, naming the field on failure."""
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"invalid Base64 value for {field_name}") from exc
