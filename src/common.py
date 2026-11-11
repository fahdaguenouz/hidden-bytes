"""Shared utilities for Hidden-Bytes tools."""

from __future__ import annotations

import argparse
import math

KEY_SIZE = 32
NONCE_SIZE = 12
MAX_DELAY_SECONDS = 86400

# Upper bound on --add-size, in MiB. The subject only asks for ~101 MB; this
# 2 GiB ceiling is generous (20x the subject) while staying within what the
# tool can build: a .pyz runner is assembled in memory, so an unbounded value
# would otherwise exhaust RAM, and a .exe would fill the disk, before failing.
MAX_ADD_SIZE_MB = 2 * 1024


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


def add_size_number(value: str) -> float:
    """Argparse type for a valid ``--add-size`` value (in MiB).

    Bounded above so an absurd value fails with a clear message instead of
    exhausting memory (``.pyz``) or filling the disk (``.exe``).
    """
    num = positive_number(value)

    if num > MAX_ADD_SIZE_MB:
        raise argparse.ArgumentTypeError(
            f"add-size cannot exceed {MAX_ADD_SIZE_MB} MB"
        )

    return num


__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "MAX_DELAY_SECONDS",
    "MAX_ADD_SIZE_MB",
    "positive_number",
    "delay_number",
    "add_size_number",
]
