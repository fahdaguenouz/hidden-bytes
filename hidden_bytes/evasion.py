"""Authenticated binary packaging demo.

This module deliberately does not execute packaged files or attempt to evade
security products.  It demonstrates encryption, padding and delayed recovery.
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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


MAGIC = b"HBX1"
HEADER_SIZE = struct.Struct(">I")
MIB = 1024 * 1024


def _positive_number(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def encrypt_file(source: Path, output: Path, add_size_mb: float, delay: float) -> Path:
    if not source.is_file():
        raise ValueError(f"input file does not exist: {source}")
    if source.resolve() == output.resolve():
        raise ValueError("input and output must be different files")

    plaintext = source.read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
    header = json.dumps(
        {
            "algorithm": "AES-256-GCM",
            "ciphertext_length": len(ciphertext),
            "delay_seconds": delay,
            "original_name": source.name,
            "original_size": len(plaintext),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    body = MAGIC + HEADER_SIZE.pack(len(header)) + header + ciphertext
    requested_size = len(plaintext) + round(add_size_mb * MIB)
    if requested_size < len(body):
        raise ValueError(
            "requested size increase is too small for the authenticated container "
            f"(need at least {len(body) - len(plaintext)} bytes)"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        handle.write(body)
        remaining = requested_size - len(body)
        while remaining:
            chunk_size = min(remaining, MIB)
            handle.write(os.urandom(chunk_size))
            remaining -= chunk_size

    key_path = Path(str(output) + ".key")
    key_path.write_text(base64.b64encode(key).decode("ascii") + "\n", encoding="ascii")
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    return key_path


def _read_container(source: Path) -> tuple[dict[str, object], bytes]:
    with source.open("rb") as handle:
        if handle.read(len(MAGIC)) != MAGIC:
            raise ValueError("not a Hidden-Bytes HBX1 container")
        packed_length = handle.read(HEADER_SIZE.size)
        if len(packed_length) != HEADER_SIZE.size:
            raise ValueError("truncated container header")
        header_length = HEADER_SIZE.unpack(packed_length)[0]
        if header_length > MIB:
            raise ValueError("invalid container header length")
        header = json.loads(handle.read(header_length).decode("utf-8"))
        ciphertext_length = int(header["ciphertext_length"])
        ciphertext = handle.read(ciphertext_length)
        if len(ciphertext) != ciphertext_length:
            raise ValueError("truncated encrypted content")
    return header, ciphertext


def decrypt_file(source: Path, output: Path, key_path: Path, no_delay: bool = False) -> None:
    header, ciphertext = _read_container(source)
    delay = float(header["delay_seconds"])
    if delay and not no_delay:
        print(f"[INFO] Recovery delayed by {delay:g} seconds...", flush=True)
        time.sleep(delay)
    key = base64.b64decode(key_path.read_text(encoding="ascii").strip(), validate=True)
    nonce = base64.b64decode(str(header["nonce"]), validate=True)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    if len(plaintext) != int(header["original_size"]):
        raise ValueError("recovered size does not match metadata")
    output.write_bytes(plaintext)


def inspect_file(source: Path) -> dict[str, object]:
    header, _ = _read_container(source)
    return header


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evasion",
        description="Safe authenticated binary-packaging demonstration (never executes payloads).",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--encrypt", metavar="TARGET")
    action.add_argument("--decrypt", metavar="CONTAINER")
    action.add_argument("--inspect", metavar="CONTAINER")
    parser.add_argument("--output", metavar="FILE")
    parser.add_argument("--add-size", type=_positive_number, default=0.01, metavar="MB")
    parser.add_argument("--delay", type=_positive_number, default=101.0, metavar="SECONDS")
    parser.add_argument("--key", metavar="KEY_FILE")
    parser.add_argument(
        "--no-delay",
        action="store_true",
        help="skip delay during recovery (intended only for automated tests)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.encrypt:
            if not args.output:
                raise ValueError("--output is required with --encrypt")
            key_path = encrypt_file(Path(args.encrypt), Path(args.output), args.add_size, args.delay)
            print(f'Encryption successful. Container saved as "{args.output}".')
            print(f'Key saved separately as "{key_path}". Keep it private.')
        elif args.decrypt:
            if not args.output or not args.key:
                raise ValueError("--output and --key are required with --decrypt")
            decrypt_file(Path(args.decrypt), Path(args.output), Path(args.key), args.no_delay)
            print(f'Recovery successful. File saved as "{args.output}" (not executed).')
        else:
            print(json.dumps(inspect_file(Path(args.inspect)), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, binascii.Error, InvalidTag) as error:
        print(f"evasion: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
