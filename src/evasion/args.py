"""argparse type validators."""

from __future__ import annotations

import argparse
import math


def positive_number(value: str) -> float:
    """Parse a finite, non-negative floating-point number."""
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from exc

    if not math.isfinite(number):
        raise argparse.ArgumentTypeError("value must be finite")

    if number < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")

    return number


def positive_integer(value: str) -> int:
    """Parse a non-negative integer."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc

    if number < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")

    return number
