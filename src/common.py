"""Shared utilities for Hidden-Bytes tools."""

from __future__ import annotations

import argparse
import math

KEY_SIZE = 32
NONCE_SIZE = 12
MAX_DELAY_SECONDS = 86400


def positive_number(value: str) -> float:
    """Argparse type for finite, non-negative numbers."""
    try:
        num = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid number: {value}"
        ) from exc

    if not math.isfinite(num):
        raise argparse.ArgumentTypeError(
            "value must be a finite number"
        )

    if num < 0:
        raise argparse.ArgumentTypeError(
            "value must be non-negative"
        )

    return num


def delay_number(value: str) -> float:
    """Argparse type for a valid recovery delay."""
    num = positive_number(value)

    if num > MAX_DELAY_SECONDS:
        raise argparse.ArgumentTypeError(
            f"delay cannot exceed {MAX_DELAY_SECONDS} seconds"
        )

    return num


__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "MAX_DELAY_SECONDS",
    "positive_number",
    "delay_number",
]
