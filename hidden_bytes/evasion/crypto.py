"""AES-256-GCM encryption and recovery for HBX1 containers.

The recovered file is written to disk only; it is never executed by this
program.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import HEADER_SIZE, KEY_SIZE, MAGIC, MAX_HEADER_SIZE, MIB, NONCE_SIZE
from .container import read_container
from .encoding import b64_decode, b64_encode


def encrypt_file(
    source: Path,
    output: Path,
    add_size_mb: float,
    delay: float,
) -> Path:
    """Encrypt a file into an HBX1 container.

    The final container size is ``original_size + round(add_size_mb * MIB)``,
    reached by appending cryptographically random padding.

    Returns the path to the generated key file.
    """
    source = source.resolve()
    output = output.resolve()

    if not source.is_file():
        raise ValueError(f"source file does not exist: {source}")
    if source == output:
        raise ValueError("source and output cannot be the same file")
    if add_size_mb < 0:
        raise ValueError("add_size_mb cannot be negative")
    if delay < 0:
        raise ValueError("delay cannot be negative")

    plaintext = source.read_bytes()
    original_size = len(plaintext)

    # Fresh 256-bit key and 96-bit nonce for every encryption.
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_SIZE)

    # Authenticate the format identifier as AAD: altering MAGIC breaks auth.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)

    header = {
        "algorithm": "AES-256-GCM",
        "ciphertext_length": len(ciphertext),
        "delay_seconds": delay,
        "original_name": source.name,
        "original_size": original_size,
        "nonce": b64_encode(nonce),
    }
    raw_header = json.dumps(
        header, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    if len(raw_header) > MAX_HEADER_SIZE:
        raise ValueError("generated header is unexpectedly large")

    body = MAGIC + HEADER_SIZE.pack(len(raw_header)) + raw_header + ciphertext

    requested_size = original_size + round(add_size_mb * MIB)
    if requested_size < len(body):
        raise ValueError(
            "requested final size is too small for the encrypted container "
            f"metadata and ciphertext. Minimum required: {len(body)} bytes; "
            f"requested: {requested_size} bytes."
        )

    output.parent.mkdir(parents=True, exist_ok=True)

    remaining = requested_size - len(body)
    with output.open("wb") as handle:
        handle.write(body)
        while remaining:
            chunk_size = min(remaining, MIB)
            handle.write(os.urandom(chunk_size))
            remaining -= chunk_size

    actual_size = output.stat().st_size
    if actual_size != requested_size:
        raise RuntimeError(
            "internal size verification failed: "
            f"expected {requested_size}, got {actual_size}"
        )

    key_path = output.with_name(output.name + ".key")
    key_path.write_text(b64_encode(key) + "\n", encoding="ascii")

    # Best-effort restriction on Unix; Windows may ignore this.
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    return key_path


def load_key(key_path: Path) -> bytes:
    """Read and validate a Base64-encoded AES-256 key."""
    if not key_path.is_file():
        raise ValueError(f"key file does not exist: {key_path}")

    key = b64_decode(key_path.read_text(encoding="ascii").strip(), "key")
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"invalid AES-256 key length: expected {KEY_SIZE} bytes, "
            f"got {len(key)}"
        )
    return key


def decrypt_file(
    source: Path,
    output: Path,
    key_path: Path,
    no_delay: bool = False,
) -> None:
    """Recover the original plaintext from an HBX1 container (write-only)."""
    source = source.resolve()
    output = output.resolve()
    key_path = key_path.resolve()

    if source == output:
        raise ValueError("source and output cannot be the same file")

    header, ciphertext = read_container(source)

    delay = float(header["delay_seconds"])
    if delay and not no_delay:
        print(f"[INFO] Recovery delayed for {delay:g} second(s)...", flush=True)
        time.sleep(delay)

    key = load_key(key_path)
    nonce = b64_decode(header["nonce"], "nonce")

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag as exc:
        raise ValueError(
            "authentication failed: wrong key or container data was modified"
        ) from exc

    expected_size = int(header["original_size"])
    if len(plaintext) != expected_size:
        raise ValueError(
            "recovered plaintext size does not match metadata: "
            f"expected {expected_size}, got {len(plaintext)}"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(plaintext)

    if output.stat().st_size != expected_size:
        raise RuntimeError("recovered file size verification failed")
