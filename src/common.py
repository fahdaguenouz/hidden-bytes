"""Shared utilities for Hidden-Bytes tools."""

from __future__ import annotations

import getpass
import hashlib
import os
import sys
from pathlib import Path
from typing import Any
import argparse

KDF_NAME = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 200_000
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
DEFAULT_PASSPHRASE_ENV = "HBX_PASSPHRASE"


def derive_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS, length: int = KEY_SIZE) -> bytes:
    """Derive an encryption key from a passphrase using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=length)


def read_passphrase(
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    env_var: str = DEFAULT_PASSPHRASE_ENV,
) -> tuple[str, dict[str, str]]:
    """Resolve passphrase from explicit value, file, env var, or prompt.

    Returns (passphrase, source_dict) where source_dict describes where
    the passphrase came from so it can be recorded in container metadata.
    """
    if passphrase is not None:
        return passphrase, {}

    if passphrase_file is not None:
        if not passphrase_file.is_file():
            raise ValueError(f"passphrase file does not exist: {passphrase_file}")
        content = passphrase_file.read_text(encoding="utf-8").splitlines()[0]
        return content, {"file": str(passphrase_file.resolve())}

    env_value = os.environ.get(env_var)
    if env_value:
        return env_value, {"env": env_var}

    if not sys.stdin.isatty():
        raise ValueError(
            f"no passphrase available: use --passphrase, --passphrase-file or set the {env_var} environment variable"
        )

    return getpass.getpass("Passphrase: "), {"env": env_var}


def resolve_passphrase_for_decrypt(
    header: dict[str, Any],
    passphrase: str | None = None,
    passphrase_file: Path | None = None,
    env_var: str = DEFAULT_PASSPHRASE_ENV,
) -> str:
    """Resolve passphrase for decryption, checking header kdf metadata first."""
    if passphrase is not None or passphrase_file is not None or os.environ.get(env_var):
        return read_passphrase(passphrase, passphrase_file, env_var)[0]

    kdf = header.get("kdf")
    if not isinstance(kdf, dict):
        raise ValueError("container has no passphrase metadata")

    env_name = kdf.get("env")
    if env_name:
        value = os.environ.get(env_name)
        if value:
            return value

    file_name = kdf.get("file")
    if file_name:
        try:
            return Path(file_name).read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            pass

    if not sys.stdin.isatty():
        raise ValueError("no passphrase available and no passphrase source recorded in container")

    return getpass.getpass("Passphrase: ")


def positive_number(value: str) -> float:
    """Argparse type for positive float/int values."""
    try:
        num = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value}") from exc
    if num < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return num





def add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add common passphrase-related arguments to a parser."""
    parser.add_argument(
        "--passphrase",
        help="passphrase protecting the payload/container. The key is derived with PBKDF2-HMAC-SHA256.",
    )
    parser.add_argument(
        "--passphrase-file",
        type=Path,
        help="read the passphrase from the first line of this file",
    )


def build_passphrase_source(passphrase: str | None, passphrase_file: Path | None, env_var: str = DEFAULT_PASSPHRASE_ENV) -> dict[str, str]:
    """Build the passphrase source dict for recording in metadata."""
    if passphrase is not None:
        return {}
    if passphrase_file is not None:
        return {"file": str(passphrase_file.resolve())}
    return {"env": env_var}


__all__ = [
    "KDF_NAME",
    "KDF_ITERATIONS",
    "SALT_SIZE",
    "KEY_SIZE",
    "NONCE_SIZE",
    "DEFAULT_PASSPHRASE_ENV",
    "derive_key",
    "read_passphrase",
    "resolve_passphrase_for_decrypt",
    "positive_number",
    "add_common_args",
    "build_passphrase_source",
]