#!/usr/bin/env python3
"""
Hidden-Bytes — Safe Evasion / Binary Packaging Demonstration

This module demonstrates concepts commonly discussed when studying
binary obfuscation and defensive analysis:

    - AES-256-GCM authenticated encryption
    - Binary container construction
    - Random padding / file-size manipulation
    - Metadata embedded in a binary container
    - Delayed recovery
    - Integrity verification
    - Tamper detection

IMPORTANT:
    This implementation deliberately DOES NOT:

    - execute encrypted/recovered binaries
    - bypass Microsoft Defender
    - bypass VirusTotal or other security products
    - modify security-product behavior
    - provide payload execution
    - provide persistence
    - provide command-and-control
    - provide reverse shells

The encrypted output is an HBX1 DATA CONTAINER, not a Windows PE loader.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import struct
import sys
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC = b"HBX1"

# Header length is stored as an unsigned big-endian 32-bit integer.
HEADER_SIZE = struct.Struct(">I")

MIB = 1024 * 1024

# Protect the parser from accidentally allocating/reading unreasonable
# metadata.
MAX_HEADER_SIZE = 1 * MIB

# AES-GCM uses a 12-byte nonce as the standard recommended size.
NONCE_SIZE = 12

# AES-256 key size.
KEY_SIZE = 32

# GCM authentication tag is included in AESGCM.encrypt() output.
GCM_TAG_SIZE = 16


# ---------------------------------------------------------------------------
# Argument helpers
# ---------------------------------------------------------------------------

def _positive_number(value: str) -> float:
    """
    Parse a non-negative floating-point number.
    """
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid number: {value!r}"
        ) from exc

    if number < 0:
        raise argparse.ArgumentTypeError(
            "value must be zero or greater"
        )

    if not number == number or number in (float("inf"), float("-inf")):
        raise argparse.ArgumentTypeError(
            "value must be finite"
        )

    return number


def _positive_integer(value: str) -> int:
    """
    Parse a non-negative integer.
    """
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid integer: {value!r}"
        ) from exc

    if number < 0:
        raise argparse.ArgumentTypeError(
            "value must be zero or greater"
        )

    return number


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _b64_encode(value: bytes) -> str:
    """
    Encode bytes as ASCII Base64.
    """
    return base64.b64encode(value).decode("ascii")


def _b64_decode(value: str, field_name: str) -> bytes:
    """
    Decode Base64 metadata safely.
    """
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(
            f"invalid Base64 value for {field_name}"
        ) from exc


# ---------------------------------------------------------------------------
# Header validation
# ---------------------------------------------------------------------------

def _validate_header(header: dict) -> None:
    """
    Validate the metadata required by an HBX1 container.
    """

    required_fields = {
        "algorithm",
        "ciphertext_length",
        "delay_seconds",
        "original_name",
        "original_size",
        "nonce",
    }

    missing = required_fields - set(header)

    if missing:
        raise ValueError(
            "container header is missing fields: "
            + ", ".join(sorted(missing))
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
        raise ValueError(
            "invalid numeric value in container header"
        ) from exc

    if ciphertext_length < GCM_TAG_SIZE:
        raise ValueError(
            "ciphertext is too short to contain a GCM authentication tag"
        )

    if original_size < 0:
        raise ValueError(
            "original_size cannot be negative"
        )

    if delay_seconds < 0:
        raise ValueError(
            "delay_seconds cannot be negative"
        )

    nonce = _b64_decode(header["nonce"], "nonce")

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"invalid nonce length: expected {NONCE_SIZE} bytes, "
            f"got {len(nonce)}"
        )

    if not isinstance(header["original_name"], str):
        raise ValueError(
            "original_name must be a string"
        )


# ---------------------------------------------------------------------------
# Container parsing
# ---------------------------------------------------------------------------

def _read_exact(handle, size: int) -> bytes:
    """
    Read exactly 'size' bytes or raise EOFError.
    """
    if size < 0:
        raise ValueError("size cannot be negative")

    data = handle.read(size)

    if len(data) != size:
        raise EOFError(
            f"unexpected end of file: expected {size} bytes, "
            f"received {len(data)}"
        )

    return data


def _read_container(source: Path) -> tuple[dict, bytes]:
    """
    Read an HBX1 container.

    Returns:
        (header, ciphertext)
    """

    if not source.is_file():
        raise ValueError(
            f"input file does not exist: {source}"
        )

    with source.open("rb") as handle:

        magic = _read_exact(handle, len(MAGIC))

        if magic != MAGIC:
            raise ValueError(
                "invalid HBX1 container: incorrect magic bytes"
            )

        raw_header_size = _read_exact(
            handle,
            HEADER_SIZE.size,
        )

        header_length = HEADER_SIZE.unpack(
            raw_header_size
        )[0]

        if header_length > MAX_HEADER_SIZE:
            raise ValueError(
                f"header is too large: {header_length} bytes"
            )

        raw_header = _read_exact(
            handle,
            header_length,
        )

        try:
            header = json.loads(
                raw_header.decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "invalid JSON header"
            ) from exc

        if not isinstance(header, dict):
            raise ValueError(
                "container header must be a JSON object"
            )

        _validate_header(header)

        ciphertext_length = int(
            header["ciphertext_length"]
        )

        ciphertext = _read_exact(
            handle,
            ciphertext_length,
        )

    return header, ciphertext


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def encrypt_file(
    source: Path,
    output: Path,
    add_size_mb: float,
    delay: float,
) -> Path:
    """
    Encrypt a file into an HBX1 container.

    The final container size is:

        original_size + round(add_size_mb * 1024 * 1024)

    Random padding is used to reach the requested final size.

    Returns:
        Path to the generated key file.
    """

    source = source.resolve()
    output = output.resolve()

    if not source.is_file():
        raise ValueError(
            f"source file does not exist: {source}"
        )

    if source == output:
        raise ValueError(
            "source and output cannot be the same file"
        )

    if add_size_mb < 0:
        raise ValueError(
            "add_size_mb cannot be negative"
        )

    if delay < 0:
        raise ValueError(
            "delay cannot be negative"
        )

    plaintext = source.read_bytes()
    original_size = len(plaintext)

    # Generate a fresh 256-bit AES key for every encryption.
    key = AESGCM.generate_key(
        bit_length=256
    )

    # Fresh 96-bit nonce for every encryption.
    nonce = os.urandom(
        NONCE_SIZE
    )

    # Authenticate the container format identifier as AAD.
    #
    # This means changing HBX1 -> something else will cause GCM
    # authentication to fail during decryption.
    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        MAGIC,
    )

    header = {
        "algorithm": "AES-256-GCM",
        "ciphertext_length": len(ciphertext),
        "delay_seconds": delay,
        "original_name": source.name,
        "original_size": original_size,
        "nonce": _b64_encode(nonce),
    }

    raw_header = json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(raw_header) > MAX_HEADER_SIZE:
        raise ValueError(
            "generated header is unexpectedly large"
        )

    body = (
        MAGIC
        + HEADER_SIZE.pack(len(raw_header))
        + raw_header
        + ciphertext
    )

    requested_additional_size = round(
        add_size_mb * MIB
    )

    requested_size = (
        original_size
        + requested_additional_size
    )

    if requested_size < len(body):
        raise ValueError(
            "requested final size is too small for the encrypted "
            "container metadata and ciphertext. "
            f"Minimum required: {len(body)} bytes; "
            f"requested: {requested_size} bytes."
        )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    remaining = requested_size - len(body)

    with output.open("wb") as handle:
        handle.write(body)

        # Fill the remaining space with cryptographically random bytes.
        while remaining:
            chunk_size = min(
                remaining,
                MIB,
            )

            handle.write(
                os.urandom(chunk_size)
            )

            remaining -= chunk_size

    actual_size = output.stat().st_size

    if actual_size != requested_size:
        raise RuntimeError(
            "internal size verification failed: "
            f"expected {requested_size}, got {actual_size}"
        )

    # Store the key separately.
    key_path = Path(
        str(output) + ".key"
    )

    key_path.write_text(
        _b64_encode(key) + "\n",
        encoding="ascii",
    )

    # On Unix-like systems, attempt to restrict the key file.
    # Windows may ignore this permission model.
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    return key_path


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def _load_key(key_path: Path) -> bytes:
    """
    Read and validate a Base64 encoded AES-256 key.
    """

    if not key_path.is_file():
        raise ValueError(
            f"key file does not exist: {key_path}"
        )

    encoded = key_path.read_text(
        encoding="ascii"
    ).strip()

    key = _b64_decode(
        encoded,
        "key",
    )

    if len(key) != KEY_SIZE:
        raise ValueError(
            f"invalid AES-256 key length: "
            f"expected {KEY_SIZE} bytes, got {len(key)}"
        )

    return key


# ---------------------------------------------------------------------------
# Decryption / recovery
# ---------------------------------------------------------------------------

def decrypt_file(
    source: Path,
    output: Path,
    key_path: Path,
    no_delay: bool = False,
) -> None:
    """
    Recover the original plaintext from an HBX1 container.

    IMPORTANT:
        The recovered file is written to disk only.
        It is NEVER executed by this program.
    """

    source = source.resolve()
    output = output.resolve()
    key_path = key_path.resolve()

    if source == output:
        raise ValueError(
            "source and output cannot be the same file"
        )

    header, ciphertext = _read_container(
        source
    )

    delay = float(
        header["delay_seconds"]
    )

    if delay and not no_delay:
        print(
            f"[INFO] Recovery delayed for "
            f"{delay:g} second(s)...",
            flush=True,
        )

        time.sleep(delay)

    key = _load_key(
        key_path
    )

    nonce = _b64_decode(
        header["nonce"],
        "nonce",
    )

    try:
        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext,
            MAGIC,
        )
    except InvalidTag as exc:
        raise ValueError(
            "authentication failed: wrong key or "
            "container data was modified"
        ) from exc

    expected_size = int(
        header["original_size"]
    )

    if len(plaintext) != expected_size:
        raise ValueError(
            "recovered plaintext size does not match "
            f"metadata: expected {expected_size}, "
            f"got {len(plaintext)}"
        )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_bytes(
        plaintext
    )

    actual_size = output.stat().st_size

    if actual_size != expected_size:
        raise RuntimeError(
            "recovered file size verification failed"
        )


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------

def inspect_file(source: Path) -> dict:
    """
    Read and return HBX1 metadata without decrypting the payload.
    """

    header, ciphertext = _read_container(
        source
    )

    result = dict(header)

    result["container_magic"] = MAGIC.decode(
        "ascii"
    )

    result["container_ciphertext_bytes"] = len(
        ciphertext
    )

    result["container_size_bytes"] = source.stat().st_size

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evasion",
        description=(
            "Safe authenticated binary packaging demonstration. "
            "The tool encrypts data into an HBX1 container and never "
            "executes recovered files."
        ),
    )

    operation = parser.add_mutually_exclusive_group(
        required=True
    )

    operation.add_argument(
        "--encrypt",
        action="store_true",
        help="encrypt/package a file into an HBX1 container",
    )

    operation.add_argument(
        "--decrypt",
        action="store_true",
        help="recover a file from an HBX1 container",
    )

    operation.add_argument(
        "--inspect",
        action="store_true",
        help="inspect HBX1 metadata without decrypting",
    )

    parser.add_argument(
        "source",
        type=Path,
        help="input file/container",
    )

    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "output file path. Required for --encrypt and --decrypt."
        ),
    )

    parser.add_argument(
        "--add-size",
        type=_positive_number,
        default=0.01,
        metavar="MB",
        help=(
            "additional size to add to the original file "
            "during encryption (default: 0.01 MB)"
        ),
    )

    parser.add_argument(
        "--delay",
        type=_positive_number,
        default=101.0,
        metavar="SECONDS",
        help=(
            "recovery delay stored in the container "
            "(default: 101 seconds)"
        ),
    )

    parser.add_argument(
        "--key",
        type=Path,
        help=(
            "AES key file used with --decrypt. "
            "For encryption the key is generated automatically."
        ),
    )

    parser.add_argument(
        "--no-delay",
        action="store_true",
        help=(
            "skip the stored recovery delay. "
            "Useful for controlled testing."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:

        # ---------------------------------------------------------------
        # ENCRYPT
        # ---------------------------------------------------------------

        if args.encrypt:

            if args.output is None:
                parser.error(
                    "--output is required with --encrypt"
                )

            key_path = encrypt_file(
                source=args.source,
                output=args.output,
                add_size_mb=args.add_size,
                delay=args.delay,
            )

            original_size = args.source.stat().st_size
            final_size = args.output.stat().st_size

            print(
                "[OK] Encryption completed."
            )
            print(
                f"[INFO] Input:       {args.source}"
            )
            print(
                f"[INFO] Container:   {args.output}"
            )
            print(
                f"[INFO] Key:         {key_path}"
            )
            print(
                f"[INFO] Original:    {original_size} bytes"
            )
            print(
                f"[INFO] Container:   {final_size} bytes"
            )
            print(
                f"[INFO] Added:       "
                f"{final_size - original_size} bytes"
            )
            print(
                f"[INFO] Delay:       {args.delay:g} second(s)"
            )
            print(
                "[INFO] The container is data only; "
                "nothing is executed."
            )

            return 0

        # ---------------------------------------------------------------
        # DECRYPT
        # ---------------------------------------------------------------

        if args.decrypt:

            if args.output is None:
                parser.error(
                    "--output is required with --decrypt"
                )

            if args.key is None:
                parser.error(
                    "--key is required with --decrypt"
                )

            decrypt_file(
                source=args.source,
                output=args.output,
                key_path=args.key,
                no_delay=args.no_delay,
            )

            print(
                "[OK] Recovery completed."
            )
            print(
                f"[INFO] Recovered file: {args.output}"
            )
            print(
                "[INFO] The recovered file was written to disk "
                "but was NOT executed."
            )

            return 0

        # ---------------------------------------------------------------
        # INSPECT
        # ---------------------------------------------------------------

        if args.inspect:

            header = inspect_file(
                args.source
            )

            print(
                json.dumps(
                    header,
                    indent=2,
                    sort_keys=True,
                )
            )

            return 0

        parser.error(
            "no operation selected"
        )

    except KeyboardInterrupt:
        print(
            "\n[ERROR] Operation cancelled.",
            file=sys.stderr,
        )
        return 130

    except (OSError, ValueError, EOFError) as exc:
        print(
            f"[ERROR] {exc}",
            file=sys.stderr,
        )
        return 1

    except Exception as exc:
        print(
            f"[ERROR] Unexpected failure: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )